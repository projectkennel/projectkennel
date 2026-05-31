//! Hand-rolled DNS resolution under policy (`docs/07-3-network.md` §7.3.2/§7.3.3).
//!
//! The kennel never resolves names itself — it holds names, the proxy resolves
//! them. This module is that resolver: a minimal RFC 1035 query encoder and
//! response decoder for `A`/`AAAA` records, plus a UDP round-trip against the
//! policy-configured resolver. DNS rebinding is structurally defeated by this
//! arrangement (the workload never sees an address it could pin), and the
//! allowlist evaluator re-checks every resolved address against the deny rules
//! ([`crate::allow::Ruleset::decide_resolved`]) before the proxy connects.
//!
//! We hand-roll the wire format rather than take a resolver dependency: the
//! subset we need (one question, `A`/`AAAA` answers, compression-pointer
//! skipping) is small, and a parser of attacker-adjacent bytes is exactly the
//! kind of code this project keeps in-tree and reviews itself (§5.1).
//!
//! # Input handling
//!
//! The response comes from the configured resolver, which is outside the
//! kennel but still untrusted (it may be hostile or compromised — hence the
//! resolved-address deny re-check upstream). Every field is bounds-checked with
//! `.get()`; name fields (including compression pointers) are skipped without
//! following pointers, so a crafted pointer cannot loop the parser; offsets use
//! `checked_add`. A response is read into a fixed-size datagram buffer, so it
//! cannot drive unbounded allocation.
//!
//! # Threat bearing
//!
//! T8 and the DNS-rebinding class: resolution happens here under policy, not in
//! the workload. The query ID is matched on the response, and the resolver
//! address is fixed by policy (not discoverable or selectable by the workload).
//!
//! # Owed
//!
//! A `fuzz/dns_parse` target (§10.6) once the fuzzing harness crosses the §5.5
//! gate; the adversarial unit tests hold the contract until then.

use std::net::IpAddr;

/// The DNS record types the proxy queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// `A` (IPv4), QTYPE 1.
    A,
    /// `AAAA` (IPv6), QTYPE 28.
    Aaaa,
}

impl RecordType {
    /// The wire QTYPE value.
    #[must_use]
    pub const fn qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// A DNS encode/decode failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// A name (or label) was empty, contained an empty label, had a label longer
    /// than 63 bytes, or exceeded 255 bytes encoded.
    InvalidName,
    /// The response was shorter than its structure requires.
    Truncated,
    /// The response ID did not match the query ID.
    BadId,
    /// The response did not have the QR (response) bit set.
    NotResponse,
    /// The response carried a non-zero RCODE (the byte is the RCODE).
    ServerFailure(u8),
    /// The response was well-formed with RCODE 0 but carried no `A`/`AAAA`
    /// address of the queried type.
    NoAddresses,
}

/// Encode a standard recursive query for `name` of type `rtype` with id `id`.
///
/// # Errors
///
/// [`DnsError::InvalidName`] if `name` is not a valid DNS name (empty, an empty
/// label, a label over 63 bytes, or over 255 bytes encoded).
pub fn encode_query(id: u16, name: &str, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
    // allow: structure-phase stub; the implementing commit's body is not const.
    #[allow(clippy::missing_const_for_fn)]
    fn stub(id: u16, name: &str, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
        let _ = (id, name, rtype);
        Err(DnsError::InvalidName)
    }
    stub(id, name, rtype)
}

/// Parse a DNS response, returning the `A`/`AAAA` addresses it carries.
///
/// # Errors
///
/// [`DnsError::Truncated`] for a short/malformed response; [`DnsError::BadId`]
/// if the id does not match; [`DnsError::NotResponse`] if the QR bit is unset;
/// [`DnsError::ServerFailure`] for a non-zero RCODE; [`DnsError::NoAddresses`]
/// if RCODE is zero but no address records are present.
pub fn parse_response(query_id: u16, buf: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
    // allow: structure-phase stub; the implementing commit's body is not const.
    #[allow(clippy::missing_const_for_fn)]
    fn stub(query_id: u16, buf: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
        let _ = (query_id, buf);
        Err(DnsError::Truncated)
    }
    stub(query_id, buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- query encoding ----

    #[test]
    fn encodes_a_query_for_example_com() {
        let q = encode_query(0x1234, "example.com", RecordType::A).expect("query");
        // Header: id, flags(RD=1), qd=1, an/ns/ar=0
        assert_eq!(q.get(..2), Some([0x12, 0x34].as_slice()));
        assert_eq!(q.get(2..4), Some([0x01, 0x00].as_slice()));
        assert_eq!(q.get(4..6), Some([0x00, 0x01].as_slice()));
        assert_eq!(q.get(6..12), Some([0, 0, 0, 0, 0, 0].as_slice()));
        // QNAME: 7"example" 3"com" 0
        let mut want = vec![7u8];
        want.extend_from_slice(b"example");
        want.push(3);
        want.extend_from_slice(b"com");
        want.push(0);
        // QTYPE=1 (A), QCLASS=1 (IN)
        want.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(q.get(12..), Some(want.as_slice()));
    }

    #[test]
    fn encodes_aaaa_qtype() {
        let q = encode_query(1, "h", RecordType::Aaaa).expect("query");
        // last four bytes: QTYPE=28, QCLASS=1
        assert_eq!(
            q.get(q.len().saturating_sub(4)..),
            Some([0x00, 0x1C, 0x00, 0x01].as_slice())
        );
    }

    #[test]
    fn trailing_dot_is_accepted() {
        let a = encode_query(1, "example.com", RecordType::A).expect("a");
        let b = encode_query(1, "example.com.", RecordType::A).expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_names_rejected() {
        assert_eq!(
            encode_query(1, "", RecordType::A),
            Err(DnsError::InvalidName)
        );
        assert_eq!(
            encode_query(1, "a..b", RecordType::A),
            Err(DnsError::InvalidName)
        );
        let too_long_label = "x".repeat(64);
        assert_eq!(
            encode_query(1, &too_long_label, RecordType::A),
            Err(DnsError::InvalidName)
        );
        let too_long_name = std::iter::repeat_n("abcdefgh", 40)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(
            encode_query(1, &too_long_name, RecordType::A),
            Err(DnsError::InvalidName)
        );
    }

    // ---- response decoding ----

    /// Build a minimal response: one question (name compressed away in answers
    /// via a pointer to offset 12), `addrs` answer records of `rtype`.
    fn response(id: u16, rcode: u8, qr: bool, rtype: RecordType, addrs: &[IpAddr]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = (u16::from(qr) << 15) | u16::from(rcode);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        let ancount = u16::try_from(addrs.len()).expect("few answers");
        buf.extend_from_slice(&ancount.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
                                              // Question: QNAME "h" 0, QTYPE, QCLASS
        buf.push(1);
        buf.push(b'h');
        buf.push(0);
        buf.extend_from_slice(&rtype.qtype().to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        // Answers
        for addr in addrs {
            buf.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to offset 12
            buf.extend_from_slice(&rtype.qtype().to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            buf.extend_from_slice(&300u32.to_be_bytes()); // TTL
            match addr {
                IpAddr::V4(a) => {
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    buf.extend_from_slice(&16u16.to_be_bytes());
                    buf.extend_from_slice(&a.octets());
                }
            }
        }
        buf
    }

    #[test]
    fn parses_a_records() {
        let addrs = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        let buf = response(0x1234, 0, true, RecordType::A, &addrs);
        assert_eq!(parse_response(0x1234, &buf), Ok(addrs.to_vec()));
    }

    #[test]
    fn parses_multiple_aaaa_records() {
        let addrs = [
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 2)),
        ];
        let buf = response(7, 0, true, RecordType::Aaaa, &addrs);
        assert_eq!(parse_response(7, &buf), Ok(addrs.to_vec()));
    }

    #[test]
    fn id_mismatch_rejected() {
        let buf = response(
            0x1234,
            0,
            true,
            RecordType::A,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        assert_eq!(parse_response(0x9999, &buf), Err(DnsError::BadId));
    }

    #[test]
    fn missing_qr_bit_rejected() {
        let buf = response(
            1,
            0,
            false,
            RecordType::A,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        assert_eq!(parse_response(1, &buf), Err(DnsError::NotResponse));
    }

    #[test]
    fn nonzero_rcode_is_server_failure() {
        let buf = response(1, 3, true, RecordType::A, &[]); // NXDOMAIN
        assert_eq!(parse_response(1, &buf), Err(DnsError::ServerFailure(3)));
    }

    #[test]
    fn rcode_zero_no_answers_is_no_addresses() {
        let buf = response(1, 0, true, RecordType::A, &[]);
        assert_eq!(parse_response(1, &buf), Err(DnsError::NoAddresses));
    }

    #[test]
    fn truncated_response_rejected() {
        let buf = response(
            1,
            0,
            true,
            RecordType::A,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        // Lop off the last RDATA byte.
        let short = buf.get(..buf.len().saturating_sub(1)).expect("slice");
        assert_eq!(parse_response(1, short), Err(DnsError::Truncated));
        // A header-only buffer.
        assert_eq!(parse_response(1, &[0, 1]), Err(DnsError::Truncated));
    }
}
