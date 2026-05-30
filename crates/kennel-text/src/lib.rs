//! Project Kennel text sanitisation.
//!
//! # Purpose
//!
//! The helpers wherever untrusted bytes might enter a context that interprets
//! formatting (CODING-STANDARDS.md §10.3, §10.4): a terminal, a log line, or an
//! audit JSONL field. Untrusted strings — paths, hostnames, D-Bus member names,
//! `argv`, command names, `reason` fields — pass through here on the way out so
//! that a terminal control sequence, a bidi-override spoof, or a stray
//! non-printable becomes visible, escaped text rather than an executed escape.
//!
//! # What is neutralised
//!
//! - **C0/C1 control characters and DEL** (`is_control()`): the ESC that starts
//!   an ANSI sequence, carriage return, backspace, NUL, and friends. These are
//!   the terminal-injection vector named in §10.3.
//! - **Bidi and zero-width formatting characters**: the "Trojan Source" set
//!   (CVE-2021-42574) — `U+202A‥E`, `U+2066‥9`, the directional marks, the
//!   zero-width joiners, and the BOM — which reorder or hide text in a terminal
//!   or editor without being control characters.
//! - **The backslash** itself, so the escapes we introduce are unambiguous.
//!
//! Ordinary printable Unicode (accented letters, CJK, emoji) is preserved: the
//! goal is to defang formatting, not to mangle legitimate text.
//!
//! # Threat bearing
//!
//! T9 and the audit-integrity goals: an attacker who controls a string that
//! reaches an operator's terminal (directly, via a log, or via a rendered audit
//! record) must not thereby control the terminal. "It is only an error message"
//! is not a defence — error messages are exactly where attacker strings land
//! (§10.4).
//!
//! # Owed
//!
//! A `fuzz/text_sanitise` target is required by §10.6 / `06-build-and-test.md`
//! but depends on a fuzzing harness crate (external), which lands with the §5.5
//! supply-chain procedure. Until then the contract is held by the unit tests
//! below.

#![forbid(unsafe_code)]

use std::fmt;

/// How many characters of an untrusted value [`Untrusted`] renders before
/// truncating. Bounds the size an error message can reach (§10.4: "Truncates
/// absurdly long values … so the error message itself does not become a
/// denial-of-service vector").
const DISPLAY_MAX_CHARS: usize = 256;

/// Sanitise a string destined for an audit JSONL field.
///
/// Control and spoofing characters are rendered as visible escapes so that the
/// stored value, once decoded and possibly printed to a terminal downstream,
/// carries no live escape. Structural JSON escaping (quotes, the outer string)
/// is the serialiser's job and is not done here; this is the content pass that
/// the serialiser cannot substitute (§10.3, `02-3-audit-schema.md`).
#[must_use]
pub fn sanitise_for_audit(s: &str) -> String {
    let _ = s;
    todo!("implemented in the feat: phase")
}

/// Sanitise a string destined for a terminal-attached log (stdout, stderr).
///
/// Neutralises the ANSI/control and bidi vectors of §10.3 so that an untrusted
/// substring in a log line cannot move the cursor, clear the screen, or reorder
/// the line.
#[must_use]
pub fn sanitise_for_log(s: &str) -> String {
    let _ = s;
    todo!("implemented in the feat: phase")
}

/// Wrap an untrusted string for safe `Display` in an error or diagnostic.
///
/// Per §10.4, rendering escapes control/spoofing characters, escapes the `"`
/// delimiter, marks the value's provenance, delimits its boundaries, and
/// truncates absurdly long values with an explicit marker. The wrapper borrows;
/// rendering is lazy and allocates at most [`DISPLAY_MAX_CHARS`] characters'
/// worth of escaped text regardless of input size.
#[must_use]
pub const fn display_untrusted(s: &str) -> Untrusted<'_> {
    Untrusted { inner: s }
}

/// A borrowed untrusted string whose `Display` impl renders it safely. Produced
/// by [`display_untrusted`].
#[derive(Debug, Clone, Copy)]
pub struct Untrusted<'a> {
    inner: &'a str,
}

impl fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        todo!("implemented in the feat: phase")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the headline guarantee: no live escape survives ----

    #[test]
    fn esc_byte_never_survives_log_sanitisation() {
        let evil = "\u{1b}[2J\u{1b}[1;1H"; // clear screen, home cursor
        let out = sanitise_for_log(evil);
        assert!(!out.contains('\u{1b}'), "raw ESC leaked: {out:?}");
    }

    #[test]
    fn esc_byte_never_survives_audit_sanitisation() {
        let out = sanitise_for_audit("\u{1b}]0;title\u{7}");
        assert!(!out.contains('\u{1b}'));
        assert!(!out.contains('\u{7}'));
    }

    // ---- exact escape forms ----

    #[test]
    fn control_char_becomes_hex_escape() {
        assert_eq!(sanitise_for_log("a\u{1b}b"), "a\\x1bb");
    }

    #[test]
    fn named_escapes_for_common_controls() {
        assert_eq!(sanitise_for_log("a\nb\rc\td"), "a\\nb\\rc\\td");
    }

    #[test]
    fn nul_is_escaped() {
        assert_eq!(sanitise_for_log("a\0b"), "a\\0b");
    }

    #[test]
    fn del_is_escaped() {
        assert_eq!(sanitise_for_log("a\u{7f}b"), "a\\x7fb");
    }

    #[test]
    fn backslash_is_doubled_so_escapes_are_unambiguous() {
        assert_eq!(sanitise_for_log("a\\b"), "a\\\\b");
    }

    // ---- bidi / zero-width spoofing ----

    #[test]
    fn bidi_override_is_escaped() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — the Trojan Source vector.
        assert_eq!(sanitise_for_log("a\u{202e}b"), "a\\u{202e}b");
    }

    #[test]
    fn zero_width_space_is_escaped() {
        assert_eq!(sanitise_for_log("a\u{200b}b"), "a\\u{200b}b");
    }

    #[test]
    fn bom_is_escaped() {
        assert_eq!(sanitise_for_log("\u{feff}x"), "\\u{feff}x");
    }

    // ---- legitimate text is preserved ----

    #[test]
    fn printable_unicode_is_preserved() {
        assert_eq!(
            sanitise_for_log("café—naïve—日本語—🦀"),
            "café—naïve—日本語—🦀"
        );
    }

    #[test]
    fn ordinary_ascii_is_unchanged() {
        assert_eq!(
            sanitise_for_audit("/usr/bin/node --version"),
            "/usr/bin/node --version"
        );
    }

    // ---- display_untrusted ----

    #[test]
    fn display_marks_delimits_and_escapes() {
        let rendered = format!("{}", display_untrusted("a\u{1b}b"));
        assert_eq!(rendered, "untrusted\"a\\x1bb\"");
    }

    #[test]
    fn display_escapes_the_quote_delimiter() {
        let rendered = format!("{}", display_untrusted("a\"b"));
        assert_eq!(rendered, "untrusted\"a\\\"b\"");
    }

    #[test]
    fn display_truncates_absurdly_long_values() {
        let long = "a".repeat(DISPLAY_MAX_CHARS + 100);
        let rendered = format!("{}", display_untrusted(&long));
        let expected = format!(
            "untrusted\"{}\"...(truncated)",
            "a".repeat(DISPLAY_MAX_CHARS)
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn display_does_not_truncate_at_the_boundary() {
        let exact = "a".repeat(DISPLAY_MAX_CHARS);
        let rendered = format!("{}", display_untrusted(&exact));
        assert!(!rendered.contains("truncated"));
    }

    #[test]
    fn display_truncation_counts_characters_not_bytes() {
        // Multi-byte chars: 300 of them exceed the char cap though byte length
        // is far larger; truncation must trigger on the char count.
        let long = "é".repeat(DISPLAY_MAX_CHARS + 10);
        let rendered = format!("{}", display_untrusted(&long));
        assert!(rendered.ends_with("...(truncated)"));
    }
}
