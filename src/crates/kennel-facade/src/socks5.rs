//! The egress front-door parsers: protocol classification and the HTTP-proxy head.
//!
//! `facade-socks5` serves SOCKS5 and HTTP-proxy clients on one listener. Two pieces
//! of that handshake are pure functions over workload-controlled bytes — the
//! leading-byte [`protocol::detect`] classifier and the [`http::parse_request`]
//! request-head parser — so they live here, fuzzed by `kennel-fuzz` and run by the
//! binary alike. The SOCKS5 request reader itself is stream-coupled (`Read`-driven)
//! and stays in the binary.

pub mod http;
pub mod protocol;
