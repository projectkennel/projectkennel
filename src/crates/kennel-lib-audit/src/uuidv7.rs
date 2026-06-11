//! `UUIDv7` rendering for the per-instance `kennel_uuid` envelope field.
//!
//! `UUIDv7` (RFC 9562) is a 48-bit Unix-millisecond timestamp followed by random
//! bits, so the IDs sort by creation time — useful for grouping one kennel's
//! lifetime of events. This module only *formats* a UUID from a timestamp and
//! caller-supplied random bytes; the randomness comes from the OS CSPRNG via
//! `kennel-lib-syscall` at the call site (kenneld), keeping this crate free of both
//! `unsafe` and a randomness dependency.

use std::fmt::Write as _;

/// Low 48 bits: the millisecond timestamp field width.
const TS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Format a `UUIDv7` from a Unix-millisecond timestamp and ten random bytes.
///
/// Layout (RFC 9562 §5.7): 48-bit big-endian `unix_ts_ms`, the 4-bit version
/// `0b0111`, 12 random bits, the 2-bit variant `0b10`, then 62 random bits.
#[must_use]
pub fn format_uuid_v7(unix_ms: u64, rand: [u8; 10]) -> String {
    let [_, _, m0, m1, m2, m3, m4, m5] = (unix_ms & TS_MASK).to_be_bytes();
    let [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9] = rand;
    // Version 7 in the high nibble of byte 6; variant 0b10 in the top bits of
    // byte 8. Bitwise ops, so no arithmetic-overflow lint to satisfy.
    let version_byte = 0x70 | (r0 & 0x0F);
    let variant_byte = 0x80 | (r2 & 0x3F);
    let bytes: [u8; 16] = [
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
        version_byte,
        r1,
        variant_byte,
        r3,
        r4,
        r5,
        r6,
        r7,
        r8,
        r9,
    ];

    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        // 8-4-4-4-12 grouping: a dash precedes bytes 4, 6, 8, and 10.
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_is_canonical_v7_nil_timestamp() {
        assert_eq!(
            format_uuid_v7(0, [0; 10]),
            "00000000-0000-7000-8000-000000000000"
        );
    }

    #[test]
    fn version_and_variant_nibbles_are_set() {
        // Random bytes all 0xFF must not disturb version (7) or variant (8/9/a/b).
        let s = format_uuid_v7(0, [0xFF; 10]);
        let version = s.chars().nth(14);
        let variant = s.chars().nth(19);
        assert_eq!(version, Some('7'), "version nibble in {s}");
        assert!(
            matches!(variant, Some('8' | '9' | 'a' | 'b')),
            "variant nibble in {s}"
        );
    }

    #[test]
    fn timestamp_is_big_endian_in_the_first_octets() {
        // 0x0102_0304_0506 ms → first six octets 01 02 03 04 05 06.
        let s = format_uuid_v7(0x0001_0203_0405, [0; 10]);
        assert!(s.starts_with("00010203-0405-7000-"), "{s}");
    }

    #[test]
    fn shape_is_36_chars_with_four_dashes() {
        let s = format_uuid_v7(1_700_000_000_000, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(s.len(), 36);
        assert_eq!(s.matches('-').count(), 4);
    }
}
