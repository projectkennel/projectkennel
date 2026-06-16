//! Terminal-escape filtering for the workload→operator PTY stream.
//!
//! A confined workload writes to the operator's real terminal through the PTY
//! proxy. Hostile escape sequences in that stream are an exfil/injection channel:
//! **OSC 52** writes the clipboard (poison a payload the operator later pastes into
//! a trusted shell, or harvest it — `T2.6`); **OSC 9 / 777** raise desktop
//! notifications; the **DCS / APC / PM / SOS** string bands are opaque
//! device/application commands with no legitimate use from an untrusted workload.
//!
//! [`Filter`] runs the stream through the vetted `vte` ANSI state machine (Paul
//! Williams' parser — the correct reference; hand-rolling is what desync attacks
//! exploit) and **drops** the dangerous set while **passing** benign sequences
//! (window title OSC 0/1/2, hyperlinks OSC 8, palette OSC 4/104, CSI, print, C0).
//!
//! It is **best-effort, not a proof**: a terminal-specific desync may slip past a
//! standard parser. It shuts down the low-effort 99% of payloads (the `echo -e
//! '\e]52;c;…'` scripts), not a determined attacker crafting against one terminal's
//! quirks. The structural defences (constructed view, no clipboard grant) remain the
//! real boundary; this closes the terminal-escape path that was an open `T2.6`
//! residual for a TTY workload.
//!
//! Enforcement lives at the single point where the workload's output flows toward
//! any attached client (kenneld's PTY-master read), so every attach/reattach is
//! filtered identically and no client can opt itself out.

#![forbid(unsafe_code)]

use vte::{Params, Parser, Perform};

/// Which dangerous escape classes to neutralise. All default **on** (the policy
/// default is filtering enabled); a policy may relax individual classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterPolicy {
    /// Drop OSC 52 (clipboard set/query) — the clipboard-poisoning / exfil vector.
    pub drop_clipboard: bool,
    /// Drop OSC 9 and OSC 777 (desktop notifications).
    pub drop_notifications: bool,
    /// Drop the DCS / APC / PM / SOS string bands (opaque app/device commands).
    pub drop_opaque_bands: bool,
}

impl Default for FilterPolicy {
    /// The secure default: every dangerous class neutralised.
    fn default() -> Self {
        Self {
            drop_clipboard: true,
            drop_notifications: true,
            drop_opaque_bands: true,
        }
    }
}

impl FilterPolicy {
    /// A pass-everything policy (filtering disabled) — what a relaxed `[tty]` resolves to.
    #[must_use]
    pub const fn passthrough() -> Self {
        Self {
            drop_clipboard: false,
            drop_notifications: false,
            drop_opaque_bands: false,
        }
    }

    /// Whether this policy drops anything at all.
    #[must_use]
    pub const fn filters_anything(&self) -> bool {
        self.drop_clipboard || self.drop_notifications || self.drop_opaque_bands
    }
}

/// A streaming terminal-escape filter: feed it chunks, collect filtered output.
///
/// One instance per session — the `vte` parser carries state across chunk boundaries,
/// so a sequence split across two reads is still recognised (the desync the request
/// worried about is bounded by the parser's own state machine).
pub struct Filter {
    parser: Parser,
    perform: FilterPerform,
}

impl Filter {
    /// A filter applying `policy`.
    #[must_use]
    pub fn new(policy: FilterPolicy) -> Self {
        Self {
            parser: Parser::new(),
            perform: FilterPerform {
                policy,
                out: Vec::new(),
                dropped: 0,
            },
        }
    }

    /// Feed a chunk of workload output; returns the filtered bytes to write to the
    /// terminal. Bytes mid-sequence at the end of a chunk are held in the parser
    /// until the rest arrives (they appear in a later call's output).
    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.perform.out.clear();
        self.parser.advance(&mut self.perform, input);
        std::mem::take(&mut self.perform.out)
    }

    /// Total dropped sequences over this filter's lifetime (for the one-time
    /// "filtered an escape" operator notice).
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.perform.dropped
    }
}

/// One-shot convenience: filter a complete buffer (tests, non-streaming callers).
#[must_use]
pub fn filter(input: &[u8], policy: FilterPolicy) -> Vec<u8> {
    let mut f = Filter::new(policy);
    f.feed(input)
}

/// The `vte::Perform` that re-serialises passed actions and drops the dangerous set.
struct FilterPerform {
    policy: FilterPolicy,
    out: Vec<u8>,
    dropped: u64,
}

/// The OSC final byte: a sequence is `ESC ] params ST`, terminated by BEL (`0x07`)
/// or ST (`ESC \`). We re-emit BEL-terminated for compactness; terminals accept either.
const BEL: u8 = 0x07;

impl FilterPerform {
    /// Re-emit a passed-through OSC: `ESC ] p1 ; p2 ; … BEL`.
    fn emit_osc(&mut self, params: &[&[u8]]) {
        self.out.push(0x1b);
        self.out.push(b']');
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                self.out.push(b';');
            }
            self.out.extend_from_slice(p);
        }
        self.out.push(BEL);
    }
}

/// Parse the leading OSC parameter (the command number) as a `u16`.
fn osc_number(params: &[&[u8]]) -> Option<u16> {
    let first = params.first()?;
    std::str::from_utf8(first).ok()?.parse::<u16>().ok()
}

impl Perform for FilterPerform {
    fn print(&mut self, c: char) {
        let mut buf = [0u8; 4];
        self.out
            .extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }

    fn execute(&mut self, byte: u8) {
        // C0/C1 control (newline, tab, CR, …) — passed verbatim.
        self.out.push(byte);
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        let drop = match osc_number(params) {
            Some(52) => self.policy.drop_clipboard,
            Some(9 | 777) => self.policy.drop_notifications,
            _ => false,
        };
        if drop {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.emit_osc(params);
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        // Re-emit `ESC [ params intermediates final`. CSI is cursor movement, colour,
        // erase — benign rendering control, passed through.
        self.out.push(0x1b);
        self.out.push(b'[');
        let mut first = true;
        for group in params {
            if !first {
                self.out.push(b';');
            }
            first = false;
            for (j, sub) in group.iter().enumerate() {
                if j > 0 {
                    self.out.push(b':');
                }
                push_u16(&mut self.out, *sub);
            }
        }
        self.out.extend_from_slice(intermediates);
        let mut buf = [0u8; 4];
        self.out
            .extend_from_slice(action.encode_utf8(&mut buf).as_bytes());
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        // A plain ESC sequence (`ESC <intermediates> <byte>`): charset selection,
        // keypad mode, etc. Benign; passed verbatim.
        self.out.push(0x1b);
        self.out.extend_from_slice(intermediates);
        self.out.push(byte);
    }

    // --- the opaque string bands: DCS (hook/put/unhook), and APC/PM/SOS ----------
    // vte routes DCS through hook/put/unhook; APC/PM/SOS it consumes without a
    // dispatch callback. For DCS we drop the whole string when drop_opaque_bands is
    // set (emit nothing in hook/put/unhook); otherwise we cannot faithfully re-emit
    // a DCS without a terminator API, so the safe default (drop) is also the only
    // honest behaviour — documented: opaque bands are dropped, not passed.
    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {
        if self.policy.drop_opaque_bands {
            self.dropped = self.dropped.saturating_add(1);
        }
        // Whether dropping or not, we do not re-emit DCS (see note above).
    }

    fn put(&mut self, _byte: u8) {
        // DCS payload byte — never re-emitted (the band is dropped).
    }

    fn unhook(&mut self) {}
}

/// Append a `u16`'s decimal ASCII to `out` (no per-call allocation; `u16` max is 5
/// digits, written into a small stack buffer then copied). Uses checked/`div_euclid`
/// arithmetic to satisfy the workspace `arithmetic_side_effects` lint.
fn push_u16(out: &mut Vec<u8>, mut n: u16) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 5];
    let mut i = buf.len();
    while n > 0 {
        i = i.saturating_sub(1);
        let digit = u8::try_from(n.rem_euclid(10)).unwrap_or(0);
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0'.saturating_add(digit);
        }
        n = n.div_euclid(10);
    }
    out.extend_from_slice(buf.get(i..).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dropped(input: &[u8]) -> Vec<u8> {
        filter(input, FilterPolicy::default())
    }

    #[test]
    fn osc52_clipboard_is_dropped() {
        // ESC ] 52 ; c ; <base64> BEL
        let payload = b"\x1b]52;c;cHduCg==\x07";
        let out = dropped(payload);
        assert!(
            !out.windows(4).any(|w| w == b"]52;"),
            "OSC52 must not survive: {out:?}"
        );
        assert!(out.is_empty(), "nothing but the dropped OSC: {out:?}");
    }

    #[test]
    fn window_title_osc_is_passed() {
        // ESC ] 0 ; title BEL  — benign, must survive.
        let title = b"\x1b]0;my-title\x07";
        let out = dropped(title);
        assert!(
            out.windows(2).any(|w| w == b"]0"),
            "title OSC kept: {out:?}"
        );
        assert!(out.ends_with(&[BEL]));
    }

    #[test]
    fn hyperlink_osc8_is_passed() {
        let link = b"\x1b]8;;https://example.com\x07link\x1b]8;;\x07";
        let out = dropped(link);
        assert!(
            out.windows(2).any(|w| w == b"]8"),
            "hyperlink kept: {out:?}"
        );
        assert!(out.windows(4).any(|w| w == b"link"), "link text kept");
    }

    #[test]
    fn plain_text_and_csi_colour_pass_verbatim() {
        let s = b"hello \x1b[31mred\x1b[0m world\n";
        let out = dropped(s);
        assert!(out.windows(5).any(|w| w == b"hello"));
        assert!(out.windows(3).any(|w| w == b"red"));
        assert!(out.windows(5).any(|w| w == b"world"));
        // the colour CSI is re-emitted
        assert!(
            out.windows(5).any(|w| w == b"\x1b[31m"),
            "colour kept: {out:?}"
        );
    }

    #[test]
    fn dcs_band_is_dropped() {
        // ESC P … ST  (DCS). Surrounding text must survive; the DCS body must not.
        let s = b"before\x1bPq#0;2;0;0;0\x1b\\after";
        let out = dropped(s);
        assert!(out.windows(6).any(|w| w == b"before"));
        assert!(out.windows(5).any(|w| w == b"after"));
        assert!(
            !out.windows(2).any(|w| w == b"#0"),
            "DCS body dropped: {out:?}"
        );
    }

    #[test]
    fn osc52_split_across_chunks_still_dropped() {
        let mut f = Filter::new(FilterPolicy::default());
        let mut out = f.feed(b"\x1b]52;c;cHdu");
        out.extend(f.feed(b"Cg==\x07"));
        assert!(
            !out.windows(4).any(|w| w == b"]52;"),
            "split OSC52 still dropped: {out:?}"
        );
        assert_eq!(f.dropped(), 1);
    }

    #[test]
    fn passthrough_policy_keeps_clipboard() {
        let out = filter(b"\x1b]52;c;cHduCg==\x07", FilterPolicy::passthrough());
        assert!(
            out.windows(4).any(|w| w == b"]52;"),
            "passthrough keeps OSC52: {out:?}"
        );
    }

    #[test]
    fn push_u16_round_trips() {
        for n in [0u16, 7, 31, 255, 777, 65535] {
            let mut v = Vec::new();
            push_u16(&mut v, n);
            assert_eq!(
                std::str::from_utf8(&v).expect("ascii digits"),
                n.to_string()
            );
        }
    }
}
