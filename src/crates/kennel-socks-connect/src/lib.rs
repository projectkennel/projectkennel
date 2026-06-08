//! `kennel-socks-connect`: a minimal SOCKS5 CONNECT stdio proxy.
//!
//! # Why this exists
//!
//! A confined kennel can `connect()` only to its egress proxy (cgroup BPF denies
//! everything else, `docs/design/07-5-network.md` §7.5.2); all egress is SOCKS5. To
//! reach the SSH re-origination bastion (`07-10-ssh.md` §7.10.4), the kennel's `ssh`
//! must go through that proxy — but OpenSSH has no built-in SOCKS client, only an
//! external `ProxyCommand`. Rather than depend on `nc`/`ncat` being present in the
//! workload image, Project Kennel ships this tiny connector and the synthetic
//! `~/.ssh/config` names it:
//!
//! ```text
//! ProxyCommand /opt/kennel/bin/kennel-socks-connect %h %p
//! ```
//!
//! It speaks SOCKS5 CONNECT to the kennel's proxy (`$KENNEL_SOCKS_PROXY`) for the
//! requested host/port and splices `stdin`/`stdout` to the established stream — so
//! `ssh` talks to the bastion as if directly connected, with the proxy enforcing the
//! allowlist (the bastion is one allowlisted host-loopback service, §7.5 host
//! services). No DNS happens kennel-side: a name is sent as a SOCKS5 domain address
//! and the proxy resolves it (`socks5h` semantics).
//!
//! The wire encoding/decoding is pure and unit-tested; `main` does the TCP + splice.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A SOCKS5 protocol or usage error. Every variant is fatal — the connector exits
/// non-zero and `ssh` sees a closed `ProxyCommand`, so it fails closed.
#[derive(Debug, PartialEq, Eq)]
pub enum SocksError {
    /// A destination host name longer than SOCKS5's single-byte length field allows.
    HostTooLong(usize),
    /// The proxy selected an auth method other than "no authentication required".
    BadMethod(u8),
    /// The proxy's reply was malformed or too short.
    BadReply,
    /// The proxy refused the CONNECT (the SOCKS5 reply code, e.g. 0x02 = not allowed).
    Refused(u8),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostTooLong(n) => {
                write!(f, "destination host is {n} bytes, exceeds SOCKS5's 255")
            }
            Self::BadMethod(m) => write!(
                f,
                "proxy selected unsupported auth method 0x{m:02x} (want no-auth)"
            ),
            Self::BadReply => write!(f, "malformed SOCKS5 reply from the proxy"),
            Self::Refused(c) => write!(f, "proxy refused CONNECT with SOCKS5 reply code 0x{c:02x}"),
        }
    }
}

impl std::error::Error for SocksError {}

/// The version-identifier/method-selection greeting: SOCKS5, one method, "no auth".
pub const GREETING: [u8; 3] = [0x05, 0x01, 0x00];

/// Build the SOCKS5 CONNECT request for `host:port`.
///
/// An IPv4/IPv6 literal is sent as the matching address type; anything else is sent
/// as a domain name (`ATYP=0x03`) for the proxy to resolve (`socks5h` — the kennel
/// never resolves DNS itself, §7.5.2).
///
/// # Errors
///
/// [`SocksError::HostTooLong`] if a domain name exceeds 255 bytes.
pub fn connect_request(host: &str, port: u16) -> Result<Vec<u8>, SocksError> {
    // VER=5, CMD=1 (CONNECT), RSV=0.
    let mut b = vec![0x05, 0x01, 0x00];
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        b.push(0x01);
        b.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        b.push(0x04);
        b.extend_from_slice(&v6.octets());
    } else {
        let bytes = host.as_bytes();
        let len = u8::try_from(bytes.len()).map_err(|_| SocksError::HostTooLong(bytes.len()))?;
        b.push(0x03);
        b.push(len);
        b.extend_from_slice(bytes);
    }
    b.extend_from_slice(&port.to_be_bytes());
    Ok(b)
}

/// Validate the proxy's 2-byte method-selection reply: must be `05 00` (no-auth).
///
/// # Errors
///
/// [`SocksError::BadReply`] if not SOCKS5, [`SocksError::BadMethod`] if the proxy
/// chose any method other than no-auth (this connector offers no credentials).
pub const fn check_method_selection(reply: [u8; 2]) -> Result<(), SocksError> {
    let [ver, method] = reply;
    if ver != 0x05 {
        return Err(SocksError::BadReply);
    }
    if method != 0x00 {
        return Err(SocksError::BadMethod(method));
    }
    Ok(())
}

/// The number of bytes following the 4-byte CONNECT-reply header for `atyp`, so the
/// caller knows how much of the bound-address tail to drain. `None` for an unknown
/// address type (a malformed reply).
#[must_use]
pub const fn reply_tail_len(atyp: u8, domain_len_byte: u8) -> Option<usize> {
    match atyp {
        0x01 => Some(6),                                            // IPv4 (4) + port (2)
        0x04 => Some(18),                                           // IPv6 (16) + port (2)
        0x03 => Some((domain_len_byte as usize).saturating_add(3)), // len byte + domain + port
        _ => None,
    }
}

/// Interpret the first 4 bytes of a CONNECT reply (`VER REP RSV ATYP`): `Ok(atyp)`
/// on success (`REP == 0x00`), else an error.
///
/// # Errors
///
/// [`SocksError::BadReply`] if too short or not SOCKS5; [`SocksError::Refused`] with
/// the reply code otherwise.
pub fn check_reply_header(header: &[u8]) -> Result<u8, SocksError> {
    let &[ver, rep, _rsv, atyp, ..] = header else {
        return Err(SocksError::BadReply);
    };
    if ver != 0x05 {
        return Err(SocksError::BadReply);
    }
    if rep != 0x00 {
        return Err(SocksError::Refused(rep));
    }
    Ok(atyp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_encodes_an_ipv4_literal() {
        let r = connect_request("127.0.0.1", 7022).expect("encode");
        assert_eq!(r, vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1b, 0x6e]); // 7022 = 0x1b6e
    }

    #[test]
    fn connect_request_encodes_an_ipv6_literal() {
        let r = connect_request("::1", 22).expect("encode");
        assert_eq!(r.get(3), Some(&0x04), "ATYP IPv6");
        assert_eq!(r.len(), 3 + 1 + 16 + 2);
        assert_eq!(r.get(r.len() - 2..), Some(&[0x00, 0x16][..]), "port 22");
    }

    #[test]
    fn connect_request_sends_a_name_as_a_domain_for_the_proxy_to_resolve() {
        let r = connect_request("github.com", 22).expect("encode");
        assert_eq!(r.get(3), Some(&0x03), "ATYP domain (socks5h)");
        assert_eq!(r.get(4), Some(&10), "len of github.com");
        assert_eq!(r.get(5..15), Some(&b"github.com"[..]));
        assert_eq!(r.get(15..), Some(&[0x00, 0x16][..]));
    }

    #[test]
    fn an_overlong_host_is_rejected() {
        let long = "a".repeat(256);
        assert_eq!(
            connect_request(&long, 22),
            Err(SocksError::HostTooLong(256))
        );
        // 255 is the boundary that still fits.
        assert!(connect_request(&"a".repeat(255), 22).is_ok());
    }

    #[test]
    fn method_selection_requires_no_auth() {
        assert!(check_method_selection([0x05, 0x00]).is_ok());
        assert_eq!(
            check_method_selection([0x05, 0x02]),
            Err(SocksError::BadMethod(0x02))
        );
        assert_eq!(
            check_method_selection([0x05, 0xff]),
            Err(SocksError::BadMethod(0xff))
        );
        assert_eq!(
            check_method_selection([0x04, 0x00]),
            Err(SocksError::BadReply)
        );
    }

    #[test]
    fn reply_header_distinguishes_success_refusal_and_garbage() {
        assert_eq!(
            check_reply_header(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0]),
            Ok(0x01)
        );
        assert_eq!(
            check_reply_header(&[0x05, 0x02, 0x00, 0x01]),
            Err(SocksError::Refused(0x02))
        );
        assert_eq!(
            check_reply_header(&[0x04, 0x00, 0x00, 0x01]),
            Err(SocksError::BadReply)
        );
        assert_eq!(check_reply_header(&[0x05]), Err(SocksError::BadReply));
    }

    #[test]
    fn reply_tail_len_covers_each_address_type() {
        assert_eq!(reply_tail_len(0x01, 0), Some(6));
        assert_eq!(reply_tail_len(0x04, 0), Some(18));
        assert_eq!(reply_tail_len(0x03, 10), Some(13));
        assert_eq!(reply_tail_len(0x09, 0), None);
    }
}
