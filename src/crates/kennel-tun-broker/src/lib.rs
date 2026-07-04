//! The W2 UDP-egress fenced flow broker: a per-kennel, host-mode leaf.
//!
//! # Purpose
//!
//! The broker is the trusted operator-context half of UDP egress (Kennel book Vol 2 ch.8). kenneld
//! is **absent from the per-flow path**; the broker is spawned at construction when `[net.udp]` is
//! enabled, handed the allowlist once, and fate-shared with the kennel. It owns two halves over the
//! `facade-tun` channel: the **DNS naming shim** — a query is checked against the allowlist and, if
//! approved, a `name → synthetic-IPv6` mapping is minted (persistent for the kennel's life) and
//! answered **AAAA**; everything else (denied, or A/CNAME/…) is **NODATA**, with zero wire activity
//! — and the **flow forwarder**, which reads an L3 datagram's synthetic dst back to its mapped name
//! ([`forward`]) and dials it directly from the host stack over a per-flow connected socket
//! ([`flow`]). The broker runs host-side, so it resolves and dials itself; kenneld is not on the
//! path. Its cgroup `net.bpf` deny-first floor is the IP-layer fence that closes DNS rebinding at
//! `connect()`, belt-and-suspenders with the [`flow`] gate's resolved-address re-check.
//!
//! This module carries the shim's query read; [`shim`] mints and answers, [`forward`] reads and
//! builds frames, and [`flow`] re-vets and dials. The event loop that binds them lands in the
//! broker binary.

#![forbid(unsafe_code)]

pub mod flow;
pub mod forward;
pub mod icmp;
pub mod poll;
pub mod serve;
pub mod shim;
pub mod table;

use simple_dns::Packet;

/// The `AAAA` record type number (RFC 3596) — the only type the shim answers with an address.
pub const QTYPE_AAAA: u16 = 28;

/// Lowercase-hex encode `bytes`.
///
/// The tun-broker passes the small `DELIVER_TUN_SESSION` grant payload to each per-session mediator
/// process on its argv; argv is text and the payload is binary, so it rides as hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        // `b >> 4` and `b & 0x0f` are each 0..=15, so `from_digit(_, 16)` is always `Some`.
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// Decode a hex string produced by [`to_hex`], or `None` if it is malformed (odd length or a
/// non-hex digit).
#[must_use]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if (bytes.len() & 1) == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() >> 1);
    for pair in bytes.chunks_exact(2) {
        let hi = char::from(*pair.first()?).to_digit(16)?;
        let lo = char::from(*pair.get(1)?).to_digit(16)?;
        out.push(u8::try_from(hi.checked_shl(4)?.checked_add(lo)?).ok()?);
    }
    Some(out)
}

/// The queried name and record type of a DNS query's first question, or `None` if the packet does
/// not parse or carries no question.
///
/// The name is normalised to its dotted form; `qtype` is the raw numeric QTYPE. This reads fully
/// workload-controlled bytes through `simple-dns` (the hostile-input parser the no-hand-roll rule
/// delegates, §5.1); the shim never resolves — it checks the name against the allowlist and mints a
/// synthetic — so only the question is needed here.
#[must_use]
pub fn query_question(packet: &[u8]) -> Option<(String, u16)> {
    let parsed = Packet::parse(packet).ok()?;
    let question = parsed.questions.first()?;
    Some((question.qname.to_string(), u16::from(question.qtype)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{RData, A};
    use simple_dns::{Name, Packet, Question, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE};

    /// Build a real DNS query for `name`/`qtype` via `simple-dns`, so the parse runs against
    /// genuine wire bytes (not a hand-forged buffer).
    fn query(name: &str, qtype: QTYPE) -> Vec<u8> {
        let mut p = Packet::new_query(0x1234);
        p.questions.push(Question::new(
            Name::new(name).expect("name"),
            qtype,
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.build_bytes_vec().expect("build query")
    }

    #[test]
    fn extracts_the_first_question() {
        let bytes = query("example.com", QTYPE::TYPE(TYPE::AAAA));
        assert_eq!(
            query_question(&bytes),
            Some(("example.com".to_owned(), QTYPE_AAAA))
        );
    }

    #[test]
    fn distinguishes_aaaa_from_other_types() {
        let a = query("host.example", QTYPE::TYPE(TYPE::A));
        let (name, qtype) = query_question(&a).expect("parsed");
        assert_eq!(name, "host.example");
        assert_ne!(qtype, QTYPE_AAAA, "an A query is not AAAA");
    }

    #[test]
    fn rejects_junk_and_empty() {
        assert_eq!(query_question(&[]), None);
        assert_eq!(query_question(&[0xff; 3]), None);
    }

    /// A response packet (not a query) still parses; the shim only ever *receives* queries, but the
    /// parser must not panic on one — it simply reads whatever first question is present.
    #[test]
    fn a_response_still_parses_without_panic() {
        let mut p = Packet::new_reply(0x1);
        p.answers.push(ResourceRecord::new(
            Name::new("x.example").expect("name"),
            CLASS::IN,
            300,
            RData::A(A {
                address: 0x7f00_0001,
            }),
        ));
        let bytes = p.build_bytes_vec().expect("build reply");
        // No question in this reply → None, no panic.
        assert_eq!(query_question(&bytes), None);
    }
}
