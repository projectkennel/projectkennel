//! Standard Base64 (RFC 4648) encode/decode, std-only.
//!
//! The signature envelope carries the Ed25519 signature as Base64, and public
//! keys in the trust store are Base64. This is *encoding*, not cryptography —
//! the bytes are public and the real gate is the Ed25519 verification — so a
//! small hand-rolled codec is appropriate (it keeps `kennel-policy` off a
//! base64 crate dependency). Decoding is lenient about padding; malformed input
//! that happens to decode yields wrong bytes, which the signature check rejects.

/// Map a Base64 alphabet character to its 6-bit value, or `None` if invalid.
const fn value_of(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(c.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Map a 6-bit value (0..=63) to its Base64 alphabet character.
const fn char_of(v: u8) -> u8 {
    match v {
        0..=25 => b'A'.wrapping_add(v),
        26..=51 => b'a'.wrapping_add(v.wrapping_sub(26)),
        52..=61 => b'0'.wrapping_add(v.wrapping_sub(52)),
        62 => b'+',
        // 63 (the only remaining value, since callers mask to 6 bits)
        _ => b'/',
    }
}

/// Decode a Base64 string into bytes. `=` padding is skipped. Returns `None` if
/// any non-alphabet, non-padding byte is present.
#[must_use]
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len().wrapping_mul(3).wrapping_div(4));
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in input {
        if c == b'=' {
            continue;
        }
        let v = value_of(c)?;
        acc = acc.wrapping_shl(6) | u32::from(v);
        nbits = nbits.wrapping_add(6);
        if nbits >= 8 {
            nbits = nbits.wrapping_sub(8);
            let byte = acc.wrapping_shr(nbits) & 0xff;
            out.push(byte as u8);
        }
    }
    Some(out)
}

/// Encode bytes as a Base64 string (with `=` padding).
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().wrapping_add(2).wrapping_div(3).wrapping_mul(4));
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in input {
        acc = acc.wrapping_shl(8) | u32::from(b);
        nbits = nbits.wrapping_add(8);
        while nbits >= 6 {
            nbits = nbits.wrapping_sub(6);
            let v = (acc.wrapping_shr(nbits) & 0x3f) as u8;
            out.push(char_of(v) as char);
        }
    }
    if nbits > 0 {
        // Pad the final partial group up to a 6-bit boundary, then to 4 chars.
        let v = (acc.wrapping_shl(6u32.wrapping_sub(nbits)) & 0x3f) as u8;
        out.push(char_of(v) as char);
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn rfc4648_vectors() {
        // The canonical RFC 4648 §10 test vectors.
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, b64) in cases {
            assert_eq!(encode(plain.as_bytes()), *b64, "encode {plain:?}");
            assert_eq!(
                decode(b64.as_bytes()).as_deref(),
                Some(plain.as_bytes()),
                "decode {b64:?}"
            );
        }
    }

    #[test]
    fn round_trip_all_byte_values() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let encoded = encode(&bytes);
        assert_eq!(decode(encoded.as_bytes()).as_deref(), Some(bytes.as_slice()));
    }

    #[test]
    fn rejects_invalid_characters() {
        assert!(decode(b"Zm9v!").is_none());
        assert!(decode(b"not base64 *").is_none());
    }
}
