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

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

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
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1 (recursion desired)
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT
    encode_name(name, &mut out)?;
    out.extend_from_slice(&rtype.qtype().to_be_bytes()); // QTYPE
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(out)
}

/// The largest legal encoded DNS name (RFC 1035 §3.1).
const MAX_NAME_LEN: usize = 255;
/// The largest legal label (the length is a 6-bit count; the top two bits are
/// the compression-pointer marker).
const MAX_LABEL_LEN: usize = 63;

/// Append `name` as a sequence of length-prefixed labels terminated by a zero
/// byte. A single trailing dot (the fully-qualified form) is accepted.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DnsError::InvalidName);
    }
    // Encoded length is the running total of (1 length byte + label) plus the
    // final zero byte; reject before it can exceed the wire maximum.
    let mut encoded_len = 1usize;
    for label in name.split('.') {
        let label_len = label.len();
        if label_len == 0 || label_len > MAX_LABEL_LEN {
            return Err(DnsError::InvalidName);
        }
        encoded_len = encoded_len
            .checked_add(label_len)
            .and_then(|n| n.checked_add(1))
            .filter(|&n| n <= MAX_NAME_LEN)
            .ok_or(DnsError::InvalidName)?;
        // label_len <= 63, so the cast is exact; try_from keeps it lint-clean.
        out.push(u8::try_from(label_len).map_err(|_| DnsError::InvalidName)?);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
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
    let (id, _) = read_u16(buf, 0)?;
    if id != query_id {
        return Err(DnsError::BadId);
    }
    let (flags, _) = read_u16(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotResponse);
    }
    // The low four bits of the flags word are the RCODE.
    let rcode = u8::try_from(flags & 0x000F).map_err(|_| DnsError::Truncated)?;
    if rcode != 0 {
        return Err(DnsError::ServerFailure(rcode));
    }
    let (qdcount, _) = read_u16(buf, 4)?;
    let (ancount, _) = read_u16(buf, 6)?;

    // Skip the question section: each is a name then QTYPE+QCLASS (4 bytes).
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = advance(pos, 4, buf)?;
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let (rtype, after_type) = read_u16(buf, pos)?;
        let (_class, after_class) = read_u16(buf, after_type)?;
        // Skip the 4-byte TTL, then read RDLENGTH.
        let after_ttl = advance(after_class, 4, buf)?;
        let (rdlength, rdata_start) = read_u16(buf, after_ttl)?;
        let rdlen = usize::from(rdlength);
        let rdata = buf
            .get(rdata_start..)
            .and_then(|s| s.get(..rdlen))
            .ok_or(DnsError::Truncated)?;
        match rtype {
            t if t == RecordType::A.qtype() && rdlen == 4 => {
                let octets: [u8; 4] = rdata.try_into().map_err(|_| DnsError::Truncated)?;
                addrs.push(IpAddr::from(octets));
            }
            t if t == RecordType::Aaaa.qtype() && rdlen == 16 => {
                let octets: [u8; 16] = rdata.try_into().map_err(|_| DnsError::Truncated)?;
                addrs.push(IpAddr::from(octets));
            }
            // Some other record type (CNAME, etc.) or a mismatched length: skip it.
            _ => {}
        }
        pos = advance(rdata_start, rdlen, buf)?;
    }

    if addrs.is_empty() {
        Err(DnsError::NoAddresses)
    } else {
        Ok(addrs)
    }
}

/// Read a big-endian `u16` at `pos`, returning it and the offset just past it.
fn read_u16(buf: &[u8], pos: usize) -> Result<(u16, usize), DnsError> {
    let end = pos.checked_add(2).ok_or(DnsError::Truncated)?;
    let bytes: [u8; 2] = buf
        .get(pos..end)
        .ok_or(DnsError::Truncated)?
        .try_into()
        .map_err(|_| DnsError::Truncated)?;
    Ok((u16::from_be_bytes(bytes), end))
}

/// Advance `pos` by `n`, checking the result stays within `buf`.
fn advance(pos: usize, n: usize, buf: &[u8]) -> Result<usize, DnsError> {
    let next = pos.checked_add(n).ok_or(DnsError::Truncated)?;
    if next > buf.len() {
        return Err(DnsError::Truncated);
    }
    Ok(next)
}

/// Skip a name field at `pos`, returning the offset just past it. Labels are
/// skipped by length; a compression pointer (top two bits set) ends the name in
/// two bytes and is *not* followed — we only need to reach the fields after the
/// name, and refusing to follow pointers makes a crafted pointer unable to loop
/// the parser.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let &len = buf.get(pos).ok_or(DnsError::Truncated)?;
        if len == 0 {
            return advance(pos, 1, buf);
        }
        if len & 0xC0 == 0xC0 {
            // Two-byte pointer; the second byte must be present.
            return advance(pos, 2, buf);
        }
        if len & 0xC0 != 0 {
            // Reserved label-type bits: malformed.
            return Err(DnsError::Truncated);
        }
        // A normal label: one length byte plus `len` bytes.
        pos = advance(pos, 1, buf)?;
        pos = advance(pos, usize::from(len), buf)?;
    }
}

/// Resolve `name` to addresses by querying `resolver` over UDP for each of
/// `types` (typically `A` and `AAAA`).
///
/// The socket is `connect()`ed to the resolver so the kernel drops datagrams
/// from any other source (basic spoof resistance), and the query id is the
/// ephemeral local port. A type that yields no answer (timeout, empty, or a
/// server failure) contributes nothing rather than failing the whole call; the
/// returned vector is the union across `types` and may be empty (the caller
/// treats an empty result as "host unreachable"). The resolved addresses are
/// still untrusted — the caller re-checks each against the deny rules.
///
/// # Errors
///
/// An [`io::Error`] if the socket cannot be created, connected, or written, or
/// if a name is invalid. A per-type read timeout is not an error; it simply
/// contributes no addresses for that type.
pub fn resolve(
    resolver: SocketAddr,
    name: &str,
    types: &[RecordType],
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    // Bind in the resolver's address family, then connect so the kernel drops
    // datagrams from any source other than the resolver (basic spoof defence).
    let bind: SocketAddr = match resolver {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(resolver)?;
    sock.set_read_timeout(Some(timeout))?;
    // The query id is the ephemeral local port: OS-assigned, varies per call,
    // and matched against on the response.
    let id = sock.local_addr()?.port();

    let mut addrs = Vec::new();
    for &rtype in types {
        let query = encode_query(id, name, rtype).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS name: {e:?}"),
            )
        })?;
        sock.send(&query)?;
        let mut buf = [0u8; UDP_BUF];
        let datagram = match sock.recv(&mut buf) {
            Ok(n) => buf.get(..n).unwrap_or(&[]),
            // A per-type timeout is not fatal: this type simply has no answer.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        // No addresses of this type (empty, NXDOMAIN/SERVFAIL), or a malformed
        // answer: contribute nothing rather than failing the whole call.
        if let Ok(found) = parse_response(id, datagram) {
            addrs.extend(found);
        }
    }
    Ok(addrs)
}

/// The receive buffer for a DNS-over-UDP response. 1500 bytes is one Ethernet
/// MTU; the proxy asks for small `A`/`AAAA` answers and does not set EDNS0, so a
/// response that does not fit is one we would refuse anyway.
const UDP_BUF: usize = 1500;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

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

    // ---- resolve (UDP round-trip against a loopback fake resolver) ----

    #[test]
    fn resolves_over_loopback_udp() {
        // A fake resolver on loopback: read one query, reply with a canned A
        // record for whatever id the query carried. No external network.
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind fake resolver");
        // Bound the server's wait so the thread (and join below) cannot block
        // forever if no query arrives — e.g. against an unimplemented resolve.
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("server timeout");
        let resolver = server.local_addr().expect("resolver addr");
        let want = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let Ok((n, from)) = server.recv_from(&mut buf) else {
                return; // no query arrived within the timeout
            };
            assert!(n >= 12, "query has a header");
            let id_bytes: [u8; 2] = buf.get(..2).expect("id").try_into().expect("2 bytes");
            let id = u16::from_be_bytes(id_bytes);
            let reply = response(id, 0, true, RecordType::A, &[want]);
            server.send_to(&reply, from).expect("send reply");
        });

        let got = resolve(
            resolver,
            "example.com",
            &[RecordType::A],
            Duration::from_secs(2),
        )
        .expect("resolve");
        handle.join().expect("resolver thread");
        assert_eq!(got, vec![want]);
    }

    #[test]
    fn resolve_timeout_yields_no_addresses() {
        // A resolver socket that never replies: resolve times out per type and
        // returns an empty vector, not an error.
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let resolver = server.local_addr().expect("addr");
        let got = resolve(
            resolver,
            "example.com",
            &[RecordType::A],
            Duration::from_millis(150),
        )
        .expect("resolve ok");
        assert!(got.is_empty(), "no reply -> no addresses, got {got:?}");
    }
}
