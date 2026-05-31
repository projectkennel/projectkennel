//! The per-user allocation file — Project Kennel's analogue of `/etc/subuid`.
//!
//! `/etc/kennel/subkennel` is root-owned and admin-managed (like `/etc/subuid`,
//! written by `useradd`/an admin tool), one line per user:
//!
//! ```text
//! uid:tag:gid:namespace          # e.g. 1000:42:0000000001:kennel-alice
//! ```
//!
//! - `uid` — the user's numeric UID. The privhelper looks up the **caller's real
//!   UID** (kernel-trusted), so no NSS/`getpwuid` runs in the setuid helper — a
//!   deliberate hardening (NSS in a setuid binary is a classic footgun).
//! - `tag` — the per-user tag byte (decimal).
//! - `gid` — the 40-bit ULA global ID as exactly 10 hex characters.
//! - `namespace` — the user's resource namespace (e.g. `kennel-alice`), stored
//!   rather than derived so the helper needs no username lookup.
//!
//! Blank lines and `#` comments are ignored.

use crate::validate::ReservedScope;

/// The system allocation file.
const ALLOCATION_FILE: &str = "/etc/kennel/subkennel";

/// Load the reserved scope allocated to `uid`, if present and well-formed.
#[must_use]
pub fn load(uid: u32) -> Option<ReservedScope> {
    let text = std::fs::read_to_string(ALLOCATION_FILE).ok()?;
    parse(&text, uid)
}

/// Find and parse the allocation line for `uid` in `text`.
fn parse(text: &str, uid: u32) -> Option<ReservedScope> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        if fields.next()?.parse::<u32>().ok()? != uid {
            continue;
        }
        let tag = fields.next()?.parse::<u8>().ok()?;
        let gid = parse_gid(fields.next()?)?;
        let namespace = fields.next()?;
        if namespace.is_empty() {
            return None;
        }
        return Some(ReservedScope::new(tag, gid, namespace));
    }
    None
}

/// Parse a 40-bit ULA global ID from exactly 10 hex characters into 5 bytes.
fn parse_gid(hex: &str) -> Option<[u8; 5]> {
    if hex.len() != 10 {
        return None;
    }
    let value = u64::from_str_radix(hex, 16).ok()?;
    // The 40-bit GID occupies the low 5 bytes of the big-endian u64.
    let mut gid = [0u8; 5];
    for (dst, byte) in gid.iter_mut().zip(value.to_be_bytes().into_iter().skip(3)) {
        *dst = byte;
    }
    Some(gid)
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_gid};

    const SAMPLE: &str = "\
# allocation file
1000:42:0000000001:kennel-alice
1001:43:00000000ff:kennel-bob
";

    #[test]
    fn parses_an_allocated_user() {
        let scope = parse(SAMPLE, 1000).expect("alice present");
        assert_eq!(scope.namespace(), "kennel-alice");
    }

    #[test]
    fn unallocated_user_is_none() {
        assert!(parse(SAMPLE, 1234).is_none());
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        assert!(parse("\n# only comments\n\n", 1000).is_none());
    }

    #[test]
    fn malformed_lines_do_not_match() {
        // Wrong field count / bad hex length must not yield a scope.
        assert!(parse("1000:42:01:kennel-alice", 1000).is_none());
        assert!(parse("1000:notanumber:0000000001:ns", 1000).is_none());
    }

    #[test]
    fn gid_decodes_low_five_bytes() {
        assert_eq!(parse_gid("00000000ff"), Some([0, 0, 0, 0, 0xff]));
        assert_eq!(parse_gid("0102030405"), Some([1, 2, 3, 4, 5]));
        assert_eq!(parse_gid("123"), None); // wrong length
    }
}
