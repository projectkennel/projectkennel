//! HTTP-proxy request parsing, server side.
//!
//! The second protocol the one listener serves (`src/protocol.rs` routes here on
//! a leading uppercase method letter). Two request forms reach an HTTP proxy:
//!
//! - **`CONNECT host:port HTTP/1.1`** (authority-form) — the client wants a raw
//!   tunnel, used for HTTPS (`HTTPS_PROXY`). The proxy connects, replies
//!   `200 Connection Established`, and relays bytes blind.
//! - **`GET http://host/path HTTP/1.1`** (absolute-form) — a plaintext forward
//!   proxy request (`HTTP_PROXY`). The proxy connects, rewrites the request
//!   target to origin-form (`GET /path HTTP/1.1`), forwards the head verbatim
//!   otherwise, and relays.
//!
//! This module is parsing only: it turns the request head into a destination and
//! a classification. The tunnelling / forwarding I/O lives in `src/server.rs`.
//! Both forms collapse to the same `(Destination, port)` the allowlist evaluator
//! consumes, so egress policy is enforced identically regardless of protocol.
//!
//! # Input handling
//!
//! The head is read up to the terminating `CRLF CRLF`, bounded by
//! [`MAX_HEAD`]; a head that reaches the cap without terminating is rejected
//! rather than buffered without limit (§10.2). The request line is validated as
//! UTF-8; header bytes are preserved verbatim for forwarding and are never
//! interpreted by this proxy. A truncated head returns [`HttpError::Incomplete`]
//! so the server can read more.
//!
//! # Threat bearing
//!
//! Trust boundary 5 (network bytes -> handler, §10), same as `src/socks5.rs`: the
//! HTTP client is the confined workload. The destination is extracted and handed
//! to the allowlist; nothing in the head influences where the proxy connects
//! except the parsed host and port.
//!
//! # Owed
//!
//! A `fuzz/http_parse` target (§10.6) once the fuzzing harness crosses the §5.5
//! gate; the adversarial unit tests hold the contract until then.

use crate::allow::Destination;

/// Maximum request-head size the proxy buffers before the terminating
/// `CRLF CRLF`.
///
/// A head that reaches this without terminating is refused
/// ([`HttpError::HeadTooLarge`]); 8 KiB comfortably fits real request heads while
/// bounding the per-connection buffer.
pub const MAX_HEAD: usize = 8 * 1024;

/// How the proxy must service a parsed HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `CONNECT`: open a tunnel, reply `200`, relay bytes blind.
    Connect,
    /// Absolute-form: forward as a plaintext HTTP proxy using `upstream_head`.
    Forward,
}

/// A parsed HTTP-proxy request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// How to service it.
    pub kind: Kind,
    /// The destination (a literal address or a name to resolve).
    pub dest: Destination,
    /// The destination port (mandatory for `CONNECT`; defaulted to 80 for an
    /// absolute-form request that omits it).
    pub port: u16,
    /// Bytes consumed by the request head (through the terminating `CRLF CRLF`).
    pub head_len: usize,
    /// For [`Kind::Forward`], the head to send upstream: the request line
    /// rewritten to origin-form, followed by the original header bytes verbatim.
    /// Empty for [`Kind::Connect`] (the server tunnels, it does not forward).
    pub upstream_head: Vec<u8>,
}

/// A parse outcome that is not a successful parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// The head is not yet terminated by `CRLF CRLF`; read more and retry.
    Incomplete,
    /// The head reached [`MAX_HEAD`] without terminating.
    HeadTooLarge,
    /// The request line was not valid UTF-8.
    RequestLineNotUtf8,
    /// The request line was not `METHOD SP TARGET SP VERSION`.
    MalformedRequestLine,
    /// A non-`CONNECT` request whose target was not absolute-form (origin-form or
    /// asterisk-form is meaningless to a forward proxy).
    NotAbsoluteForm,
    /// A `CONNECT` target that was not a valid `host:port` authority.
    BadAuthority,
    /// An absolute-form target whose scheme was not `http://`.
    UnsupportedScheme,
    /// A port that was absent where required, zero, or out of range.
    BadPort,
}

/// Parse an HTTP-proxy request head from `buf`.
///
/// # Errors
///
/// [`HttpError::Incomplete`] if the head is not yet fully present;
/// [`HttpError::HeadTooLarge`] if it exceeds [`MAX_HEAD`] without terminating;
/// otherwise the specific malformed-input variant.
pub fn parse_request(buf: &[u8]) -> Result<HttpRequest, HttpError> {
    // allow: structure-phase stub; the implementing commit's body is not const.
    #[allow(clippy::missing_const_for_fn)]
    fn stub(buf: &[u8]) -> Result<HttpRequest, HttpError> {
        let _ = buf;
        Err(HttpError::Incomplete)
    }
    stub(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn name(s: &str) -> Destination {
        Destination::Name(s.to_owned())
    }

    // ---- CONNECT (authority-form) ----

    #[test]
    fn connect_host_port() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let p = parse_request(req).expect("connect");
        assert_eq!(p.kind, Kind::Connect);
        assert_eq!(p.dest, name("example.com"));
        assert_eq!(p.port, 443);
        assert_eq!(p.head_len, req.len());
        assert!(p.upstream_head.is_empty());
    }

    #[test]
    fn connect_ipv4_literal() {
        let req = b"CONNECT 10.0.0.1:8443 HTTP/1.1\r\n\r\n";
        let p = parse_request(req).expect("connect");
        assert_eq!(
            p.dest,
            Destination::Addr(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(p.port, 8443);
    }

    #[test]
    fn connect_ipv6_bracketed() {
        let req = b"CONNECT [fd00::1]:443 HTTP/1.1\r\n\r\n";
        let p = parse_request(req).expect("connect");
        assert_eq!(
            p.dest,
            Destination::Addr(IpAddr::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(p.port, 443);
    }

    #[test]
    fn connect_without_port_is_bad_authority() {
        let req = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(req), Err(HttpError::BadAuthority));
    }

    #[test]
    fn connect_port_zero_is_bad_port() {
        let req = b"CONNECT example.com:0 HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(req), Err(HttpError::BadPort));
    }

    // ---- absolute-form (forward) ----

    #[test]
    fn absolute_form_get_default_port() {
        let req =
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let p = parse_request(req).expect("forward");
        assert_eq!(p.kind, Kind::Forward);
        assert_eq!(p.dest, name("example.com"));
        assert_eq!(p.port, 80);
        // The request line is rewritten to origin-form, headers kept verbatim.
        let upstream = String::from_utf8(p.upstream_head).expect("utf8");
        assert!(
            upstream.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "got {upstream:?}"
        );
        assert!(upstream.contains("Host: example.com\r\n"));
        assert!(upstream.ends_with("\r\n\r\n"));
    }

    #[test]
    fn absolute_form_explicit_port() {
        let req = b"POST http://h.example:8080/api HTTP/1.1\r\nHost: h.example:8080\r\n\r\n";
        let p = parse_request(req).expect("forward");
        assert_eq!(p.dest, name("h.example"));
        assert_eq!(p.port, 8080);
        let upstream = String::from_utf8(p.upstream_head).expect("utf8");
        assert!(upstream.starts_with("POST /api HTTP/1.1\r\n"));
    }

    #[test]
    fn absolute_form_root_path_when_empty() {
        let req = b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let p = parse_request(req).expect("forward");
        assert_eq!(p.dest, name("example.com"));
        let upstream = String::from_utf8(p.upstream_head).expect("utf8");
        assert!(
            upstream.starts_with("GET / HTTP/1.1\r\n"),
            "got {upstream:?}"
        );
    }

    #[test]
    fn origin_form_target_is_rejected() {
        // A bare path (origin-form) is what a server expects, not a proxy.
        let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_request(req), Err(HttpError::NotAbsoluteForm));
    }

    #[test]
    fn non_http_scheme_rejected() {
        let req = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_request(req), Err(HttpError::UnsupportedScheme));
    }

    // ---- adversarial ----

    #[test]
    fn truncated_head_is_incomplete() {
        assert_eq!(
            parse_request(b"CONNECT example.com:443 HTTP/1.1\r\n"),
            Err(HttpError::Incomplete)
        );
        assert_eq!(parse_request(b"GET htt"), Err(HttpError::Incomplete));
        assert_eq!(parse_request(b""), Err(HttpError::Incomplete));
    }

    #[test]
    fn malformed_request_line_rejected() {
        // Only two tokens.
        let req = b"CONNECT HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(req), Err(HttpError::MalformedRequestLine));
    }

    #[test]
    fn oversize_head_without_terminator_is_rejected() {
        let mut req = b"GET http://example.com/".to_vec();
        req.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        assert_eq!(parse_request(&req), Err(HttpError::HeadTooLarge));
    }

    #[test]
    fn request_line_not_utf8_rejected() {
        let mut req = vec![0xFF, 0xFE, b' ', b'x', b' ', b'y'];
        req.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse_request(&req), Err(HttpError::RequestLineNotUtf8));
    }
}
