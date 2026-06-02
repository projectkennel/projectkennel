//! Front-door protocol detection: which handshake a fresh connection speaks.
//!
//! One listener serves SOCKS5 and HTTP-proxy clients alike. The first byte of
//! the stream disambiguates them with no ambiguity, so the server peers a single
//! byte (`MSG_PEEK`, leaving it in the stream for the chosen handler to read):
//!
//! - **SOCKS5** opens with the version byte `0x05` — a control byte.
//! - **SOCKS4/4a** opens with `0x04`. We detect it only to refuse it with a
//!   clear reason; SOCKS4 cannot carry a name in the base protocol (4a can, but
//!   the family is obsolete and we do not implement it).
//! - **HTTP** (`CONNECT host:port`, or an absolute-form `GET http://...`) always
//!   opens with an uppercase ASCII method letter, `A`..=`Z` (`0x41`..=`0x5a`).
//!
//! Any other leading byte is not a protocol we serve; the connection is refused.
//! This is a classifier only — it does not parse the handshake, so it reads
//! nothing an attacker controls beyond one byte, and it never blocks waiting for
//! more than that byte.
//!
//! # Threat bearing
//!
//! Fail-closed front door (T1.8 and the general "only talk to the proxy" thesis):
//! an unrecognised leading byte is refused rather than guessed at, so a
//! malformed or hostile client cannot coax the proxy into a handler it did not
//! intend.

/// Transports a peeked connection's protocol can be served as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// SOCKS5 (leading byte `0x05`).
    Socks5,
    /// HTTP proxy: `CONNECT` tunnel or absolute-form forward (leading uppercase
    /// ASCII method letter).
    Http,
}

/// The reason a leading byte was not a protocol the proxy serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// SOCKS4/4a (leading byte `0x04`): obsolete, not implemented.
    Socks4,
    /// The connection carried no bytes to classify.
    Empty,
    /// A leading byte matching no protocol the proxy serves.
    Unknown(u8),
}

/// Classify a connection from the byte(s) peeked at its head.
///
/// `head` is what a single peek returned; only the first byte is consulted, but
/// an empty slice (peer sent nothing / half-closed) is itself a classification
/// outcome.
///
/// # Errors
///
/// Returns [`Unsupported`] when the leading byte is SOCKS4, when `head` is
/// empty, or when the byte matches no served protocol.
pub const fn detect(head: &[u8]) -> Result<Protocol, Unsupported> {
    match head.first() {
        None => Err(Unsupported::Empty),
        Some(0x05) => Ok(Protocol::Socks5),
        Some(0x04) => Err(Unsupported::Socks4),
        // Uppercase ASCII letter: an HTTP method (CONNECT, GET, POST, ...).
        Some(&b) if b.is_ascii_uppercase() => Ok(Protocol::Http),
        Some(&b) => Err(Unsupported::Unknown(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_version_byte_is_socks5() {
        assert_eq!(detect(&[0x05, 0x01, 0x00]), Ok(Protocol::Socks5));
    }

    #[test]
    fn http_methods_are_http() {
        for method in [
            "CONNECT example:443",
            "GET http://h/ HTTP/1.1",
            "POST ",
            "HEAD ",
            "PUT ",
        ] {
            assert_eq!(
                detect(method.as_bytes()),
                Ok(Protocol::Http),
                "method {method:?}"
            );
        }
    }

    #[test]
    fn socks4_is_refused_distinctly() {
        assert_eq!(detect(&[0x04, 0x01]), Err(Unsupported::Socks4));
    }

    #[test]
    fn empty_head_is_refused() {
        assert_eq!(detect(&[]), Err(Unsupported::Empty));
    }

    #[test]
    fn lowercase_or_binary_lead_is_unknown() {
        // A lowercase method (clients always send uppercase) and a stray binary
        // byte both fail closed rather than being guessed.
        assert_eq!(detect(b"get "), Err(Unsupported::Unknown(b'g')));
        assert_eq!(detect(&[0x16, 0x03, 0x01]), Err(Unsupported::Unknown(0x16)));
        // a TLS ClientHello
    }

    #[test]
    fn only_the_first_byte_matters() {
        // A SOCKS5 greeting and a longer buffer classify the same.
        assert_eq!(detect(&[0x05]), Ok(Protocol::Socks5));
        assert_eq!(detect(&[0x05, 0xff, 0xff, 0xff]), Ok(Protocol::Socks5));
    }
}
