//! SOCKS5 wire parsing (RFC 1928), server side.
//!
//! Pure, allocation-light parsing of the two messages a SOCKS5 client sends —
//! the method greeting and the request — plus the encoders for the two replies
//! the proxy sends back. No I/O: the server (`src/server.rs`) reads bytes into a
//! bounded buffer and hands slices here, so every parse is unit-testable against
//! constructed and adversarial input.
//!
//! # Incremental parsing
//!
//! SOCKS5 messages are self-framing but variable-length, and the server reads
//! from a stream. Each parser returns [`Socks5Error::Incomplete`] when the slice
//! is a valid but truncated prefix; the server reads more and retries.
//! `Incomplete` is therefore *not* a malformed-input error — it is the "need more
//! bytes" signal. Every other error variant is a definite protocol violation and
//! fails the connection closed.
//!
//! # Input handling
//!
//! Every field read is bounds-checked against the slice with `.get()` (never
//! indexing); a domain name is validated as UTF-8 before a `String` exists; the
//! reserved byte is checked to be zero. The longest possible request is bounded
//! (`4 + 1 + 255 + 2` bytes), and the server caps its read buffer accordingly, so
//! the parser cannot be driven to allocate without limit.
//!
//! # Threat bearing
//!
//! Trust boundary 5 (network bytes -> handler, CODING-STANDARDS.md §10): the
//! SOCKS5 client is inside the kennel and is exactly the untrusted workload this
//! project confines. A parse error is an expected outcome, not an exceptional
//! one; the connection is refused and the event is auditable.
//!
//! # Owed
//!
//! A `fuzz/socks5_parse` target (§10.6) is required for this parser; like the
//! `kennel-text` fuzz target it waits on the fuzzing-harness crate crossing the
//! §5.5 supply-chain gate. Until then the contract is held by the adversarial
//! unit tests below.

use std::net::{IpAddr, SocketAddr};

use crate::allow::Destination;

/// The SOCKS protocol version byte this parser accepts.
const VERSION: u8 = 0x05;

/// The "no authentication required" method, the only one the proxy offers.
const METHOD_NO_AUTH: u8 = 0x00;

/// A SOCKS5 request command (RFC 1928 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `CONNECT` (0x01): open a TCP connection to the destination.
    Connect,
    /// `BIND` (0x02): accept an inbound connection. Not supported by the proxy.
    Bind,
    /// `UDP ASSOCIATE` (0x03): relay UDP datagrams.
    UdpAssociate,
}

/// A parsed SOCKS5 request: what the client wants the proxy to do, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The command.
    pub command: Command,
    /// The destination (a literal address or a name to resolve).
    pub dest: Destination,
    /// The destination port (host order, decoded from the wire's network order).
    pub port: u16,
}

/// The parsed method greeting, plus how many bytes it consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Greeting {
    /// Whether the client offered the no-authentication method (the only one the
    /// proxy accepts).
    pub offers_no_auth: bool,
    /// Bytes consumed from the input by the greeting.
    pub consumed: usize,
}

/// A parsed request, plus how many bytes it consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRequest {
    /// The request.
    pub request: Request,
    /// Bytes consumed from the input by the request.
    pub consumed: usize,
}

/// A reply code the proxy returns in a request reply (RFC 1928 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `succeeded` (0x00).
    Success,
    /// `general SOCKS server failure` (0x01).
    GeneralFailure,
    /// `connection not allowed by ruleset` (0x02).
    NotAllowed,
    /// `host unreachable` (0x04) — used for a name that does not resolve.
    HostUnreachable,
    /// `connection refused` (0x05) — the upstream refused the connection.
    ConnectionRefused,
    /// `command not supported` (0x07) — BIND/UDP ASSOCIATE.
    CommandNotSupported,
    /// `address type not supported` (0x08).
    AddrTypeNotSupported,
}

impl Reply {
    /// The wire byte for this reply code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddrTypeNotSupported => 0x08,
        }
    }
}

/// A SOCKS5 parse outcome that is not a successful parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5Error {
    /// The slice is a valid but truncated prefix; read more and retry. Not a
    /// protocol violation.
    Incomplete,
    /// The version byte was not `0x05`.
    BadVersion(u8),
    /// The reserved byte was not zero.
    BadReserved(u8),
    /// The command byte was not 1, 2, or 3.
    BadCommand(u8),
    /// The address-type byte was not 1, 3, or 4.
    BadAddrType(u8),
    /// A domain-name request carried a zero-length name.
    DomainEmpty,
    /// A domain name was not valid UTF-8.
    DomainNotUtf8,
}

/// Parse a SOCKS5 method greeting: `VER NMETHODS METHODS...`.
///
/// # Errors
///
/// [`Socks5Error::Incomplete`] if the slice is a truncated greeting;
/// [`Socks5Error::BadVersion`] if the version byte is not `0x05`.
pub fn parse_greeting(buf: &[u8]) -> Result<Greeting, Socks5Error> {
    let &ver = buf.first().ok_or(Socks5Error::Incomplete)?;
    if ver != VERSION {
        return Err(Socks5Error::BadVersion(ver));
    }
    let &nmethods = buf.get(1).ok_or(Socks5Error::Incomplete)?;
    // Methods are the `nmethods` bytes after the 2-byte header. Slicing from the
    // header offset, then to the count, avoids any index arithmetic.
    let after_header = buf.get(2..).ok_or(Socks5Error::Incomplete)?;
    let methods = after_header
        .get(..usize::from(nmethods))
        .ok_or(Socks5Error::Incomplete)?;
    let offers_no_auth = methods.contains(&METHOD_NO_AUTH);
    let rest = after_header
        .get(usize::from(nmethods)..)
        .ok_or(Socks5Error::Incomplete)?;
    Ok(Greeting {
        offers_no_auth,
        consumed: buf.len().saturating_sub(rest.len()),
    })
}

/// Encode the method-selection reply: `VER METHOD`, choosing no-auth (`0x00`) if
/// the client offered it, else `0xFF` (no acceptable methods).
#[must_use]
pub const fn method_reply(no_auth: bool) -> [u8; 2] {
    [VERSION, if no_auth { METHOD_NO_AUTH } else { 0xFF }]
}

/// Parse a SOCKS5 request: `VER CMD RSV ATYP DST.ADDR DST.PORT`.
///
/// # Errors
///
/// [`Socks5Error::Incomplete`] for a truncated request; otherwise the specific
/// protocol-violation variant (bad version, reserved byte, command, address
/// type, or domain name).
pub fn parse_request(buf: &[u8]) -> Result<ParsedRequest, Socks5Error> {
    let &ver = buf.first().ok_or(Socks5Error::Incomplete)?;
    if ver != VERSION {
        return Err(Socks5Error::BadVersion(ver));
    }
    let &cmd = buf.get(1).ok_or(Socks5Error::Incomplete)?;
    let command = match cmd {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UdpAssociate,
        other => return Err(Socks5Error::BadCommand(other)),
    };
    let &rsv = buf.get(2).ok_or(Socks5Error::Incomplete)?;
    if rsv != 0x00 {
        return Err(Socks5Error::BadReserved(rsv));
    }
    let &atyp = buf.get(3).ok_or(Socks5Error::Incomplete)?;
    // The address (and the bytes after it) start at offset 4.
    let body = buf.get(4..).ok_or(Socks5Error::Incomplete)?;
    let (dest, after_addr) = parse_addr(atyp, body)?;
    // Two-byte port in network order follows the address.
    let port_bytes: [u8; 2] = after_addr
        .get(..2)
        .ok_or(Socks5Error::Incomplete)?
        .try_into()
        .map_err(|_| Socks5Error::Incomplete)?;
    let port = u16::from_be_bytes(port_bytes);
    let rest = after_addr.get(2..).ok_or(Socks5Error::Incomplete)?;
    Ok(ParsedRequest {
        request: Request {
            command,
            dest,
            port,
        },
        consumed: buf.len().saturating_sub(rest.len()),
    })
}

/// Parse the `ATYP`-tagged destination address out of `body` (the bytes after
/// the 4-byte request header). Returns the destination and the bytes following
/// the address (where the port begins).
fn parse_addr(atyp: u8, body: &[u8]) -> Result<(Destination, &[u8]), Socks5Error> {
    match atyp {
        // IPv4: four octets.
        0x01 => {
            let octets: [u8; 4] = body
                .get(..4)
                .ok_or(Socks5Error::Incomplete)?
                .try_into()
                .map_err(|_| Socks5Error::Incomplete)?;
            let rest = body.get(4..).ok_or(Socks5Error::Incomplete)?;
            Ok((Destination::Addr(IpAddr::from(octets)), rest))
        }
        // Domain name: one length byte, then that many bytes.
        0x03 => {
            let &len = body.first().ok_or(Socks5Error::Incomplete)?;
            if len == 0 {
                return Err(Socks5Error::DomainEmpty);
            }
            let after_len = body.get(1..).ok_or(Socks5Error::Incomplete)?;
            let name_bytes = after_len
                .get(..usize::from(len))
                .ok_or(Socks5Error::Incomplete)?;
            let name = std::str::from_utf8(name_bytes).map_err(|_| Socks5Error::DomainNotUtf8)?;
            let rest = after_len
                .get(usize::from(len)..)
                .ok_or(Socks5Error::Incomplete)?;
            Ok((Destination::Name(name.to_owned()), rest))
        }
        // IPv6: sixteen octets.
        0x04 => {
            let octets: [u8; 16] = body
                .get(..16)
                .ok_or(Socks5Error::Incomplete)?
                .try_into()
                .map_err(|_| Socks5Error::Incomplete)?;
            let rest = body.get(16..).ok_or(Socks5Error::Incomplete)?;
            Ok((Destination::Addr(IpAddr::from(octets)), rest))
        }
        other => Err(Socks5Error::BadAddrType(other)),
    }
}

/// Encode a request reply: `VER REP RSV ATYP BND.ADDR BND.PORT`, where the bound
/// address is the proxy-side socket the upstream connection was made from (or a
/// zero address on failure).
#[must_use]
pub fn encode_reply(reply: Reply, bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![VERSION, reply.code(), 0x00];
    match bound {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // ---- greeting ----

    #[test]
    fn greeting_with_no_auth_offered() {
        // VER=5, NMETHODS=2, methods = [0x00, 0x02]
        let g = parse_greeting(&[0x05, 0x02, 0x00, 0x02]).expect("greeting");
        assert!(g.offers_no_auth);
        assert_eq!(g.consumed, 4);
    }

    #[test]
    fn greeting_without_no_auth() {
        // only GSSAPI(0x01) and user/pass(0x02) offered
        let g = parse_greeting(&[0x05, 0x02, 0x01, 0x02]).expect("greeting");
        assert!(!g.offers_no_auth);
        assert_eq!(g.consumed, 4);
    }

    #[test]
    fn greeting_truncated_is_incomplete() {
        assert_eq!(parse_greeting(&[]), Err(Socks5Error::Incomplete));
        assert_eq!(parse_greeting(&[0x05]), Err(Socks5Error::Incomplete));
        // says 3 methods but only 1 present
        assert_eq!(
            parse_greeting(&[0x05, 0x03, 0x00]),
            Err(Socks5Error::Incomplete)
        );
    }

    #[test]
    fn greeting_bad_version() {
        assert_eq!(
            parse_greeting(&[0x04, 0x01, 0x00]),
            Err(Socks5Error::BadVersion(0x04))
        );
    }

    #[test]
    fn greeting_zero_methods() {
        let g = parse_greeting(&[0x05, 0x00]).expect("greeting");
        assert!(!g.offers_no_auth);
        assert_eq!(g.consumed, 2);
    }

    // ---- method reply ----

    #[test]
    fn method_reply_encodes() {
        assert_eq!(method_reply(true), [0x05, 0x00]);
        assert_eq!(method_reply(false), [0x05, 0xFF]);
    }

    // ---- request: ipv4 ----

    #[test]
    fn request_connect_ipv4() {
        // VER CMD RSV ATYP=1 1.2.3.4 :443
        let buf = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB];
        let p = parse_request(&buf).expect("request");
        assert_eq!(p.request.command, Command::Connect);
        assert_eq!(
            p.request.dest,
            Destination::Addr(IpAddr::from(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(p.request.port, 443);
        assert_eq!(p.consumed, 10);
    }

    // ---- request: ipv6 ----

    #[test]
    fn request_connect_ipv6() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let mut buf = vec![0x05, 0x01, 0x00, 0x04];
        buf.extend_from_slice(&addr.octets());
        buf.extend_from_slice(&80u16.to_be_bytes());
        let p = parse_request(&buf).expect("request");
        assert_eq!(p.request.dest, Destination::Addr(IpAddr::from(addr)));
        assert_eq!(p.request.port, 80);
        assert_eq!(p.consumed, 22);
    }

    // ---- request: domain ----

    #[test]
    fn request_connect_domain() {
        // ATYP=3, len=11, "example.com", :443
        let name = b"example.com";
        let len = u8::try_from(name.len()).expect("name fits a length byte");
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, len];
        buf.extend_from_slice(name);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let p = parse_request(&buf).expect("request");
        assert_eq!(p.request.dest, Destination::Name("example.com".to_owned()));
        assert_eq!(p.request.port, 443);
        assert_eq!(p.consumed, buf.len());
    }

    #[test]
    fn request_udp_associate_command_parses() {
        let buf = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let p = parse_request(&buf).expect("request");
        assert_eq!(p.request.command, Command::UdpAssociate);
    }

    // ---- request: adversarial ----

    #[test]
    fn request_truncated_is_incomplete() {
        // header only, no address
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x01]),
            Err(Socks5Error::Incomplete)
        );
        // ipv4 address but missing port
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4]),
            Err(Socks5Error::Incomplete)
        );
        // domain length says 5 but only 3 bytes present
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x03, 0x05, b'a', b'b', b'c']),
            Err(Socks5Error::Incomplete)
        );
    }

    #[test]
    fn request_bad_version() {
        assert_eq!(
            parse_request(&[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]),
            Err(Socks5Error::BadVersion(0x04))
        );
    }

    #[test]
    fn request_bad_reserved() {
        assert_eq!(
            parse_request(&[0x05, 0x01, 0xFF, 0x01, 1, 2, 3, 4, 0, 80]),
            Err(Socks5Error::BadReserved(0xFF))
        );
    }

    #[test]
    fn request_bad_command() {
        assert_eq!(
            parse_request(&[0x05, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0, 80]),
            Err(Socks5Error::BadCommand(0x09))
        );
    }

    #[test]
    fn request_bad_addr_type() {
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4]),
            Err(Socks5Error::BadAddrType(0x02))
        );
    }

    #[test]
    fn request_empty_domain() {
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x03, 0x00, 0, 80]),
            Err(Socks5Error::DomainEmpty)
        );
    }

    #[test]
    fn request_domain_not_utf8() {
        // ATYP=3, len=2, invalid UTF-8 bytes, port
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x03, 0x02, 0xFF, 0xFE, 0, 80]),
            Err(Socks5Error::DomainNotUtf8)
        );
    }

    // ---- request reply ----

    #[test]
    fn encode_reply_ipv4() {
        let bound = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080));
        let out = encode_reply(Reply::Success, bound);
        // VER REP RSV ATYP=1 127.0.0.1 1080
        assert_eq!(out, vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn encode_reply_ipv6() {
        let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let bound = SocketAddr::V6(SocketAddrV6::new(ip, 1080, 0, 0));
        let out = encode_reply(Reply::NotAllowed, bound);
        let mut want = vec![0x05, 0x02, 0x00, 0x04];
        want.extend_from_slice(&ip.octets());
        want.extend_from_slice(&1080u16.to_be_bytes());
        assert_eq!(out, want);
    }

    #[test]
    fn encode_reply_carries_the_code() {
        let bound = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        assert_eq!(
            encode_reply(Reply::CommandNotSupported, bound).get(1),
            Some(&0x07)
        );
    }
}
