//! `facade-tun`'s L3 shape predicate: the pure, workload-facing parser (W2 Part C).
//!
//! `facade-tun` copies whole IPv6 L3 frames between the kennel's tun and the flow broker behind a
//! symmetric shape check, originating nothing and keeping no flow state. The check is a pure
//! function over fully workload-controlled bytes — the **egress** direction parses genuinely
//! hostile input — so it lives here, fuzzed by `kennel-fuzz` and run by the binary alike. A frame
//! that fails is dropped (a counter, never an ICMP).
//!
//! The predicate is a *shape* check, not the policy: it pins the transport, the version, and the
//! endpoints to the kennel's own tun `/64`. Which synthetic addresses are live (the pool vs the
//! resolver, the name behind each) is the broker's mapping, not the facade's — the facade is
//! stateless by construction.

use std::net::Ipv6Addr;

/// The fixed IPv6 header length. Extension headers are not accepted — `next_header` must be the
/// transport directly, so a hop-by-hop/fragment/etc. header fails the check (drop).
const IPV6_HEADER: usize = 40;
/// The UDP header length (src/dst port, length, checksum).
const UDP_HEADER: usize = 8;
/// The `ICMPv6` header length (type, code, checksum) that must be present to read type+code.
const ICMPV6_HEADER: usize = 4;
/// IPv6 `next_header`: UDP.
const NEXT_UDP: u8 = 17;
/// IPv6 `next_header`: `ICMPv6`.
const NEXT_ICMPV6: u8 = 58;
/// `ICMPv6` type 1 = Destination Unreachable — the only `ICMPv6` the broker relays inbound.
const ICMPV6_DEST_UNREACH: u8 = 1;
/// The Destination-Unreachable codes the broker may relay: 1 = communication administratively
/// prohibited (a denial), 4 = port unreachable (translated from `ECONNREFUSED`).
const ICMPV6_RELAYED_CODES: [u8; 2] = [1, 4];

/// The IPv6 header fields the predicate needs.
struct Ipv6Header {
    payload_len: usize,
    next_header: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
}

/// Parse the fixed IPv6 header, or `None` on any malformation — too short, not version 6, or a
/// stated payload length that does not match the frame (the tun delivers exactly one IP packet).
/// Fully bounds-checked; never panics on hostile input.
fn parse_ipv6(frame: &[u8]) -> Option<Ipv6Header> {
    // Version is the high nibble of the first byte.
    if *frame.first()? >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(
        frame.get(4..6).and_then(|b| <[u8; 2]>::try_from(b).ok())?,
    ));
    // The frame is exactly one packet: the header's stated length must account for every byte.
    if IPV6_HEADER.checked_add(payload_len)? != frame.len() {
        return None;
    }
    let next_header = *frame.get(6)?;
    let src = Ipv6Addr::from(
        frame
            .get(8..24)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())?,
    );
    let dst = Ipv6Addr::from(
        frame
            .get(24..40)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())?,
    );
    Some(Ipv6Header {
        payload_len,
        next_header,
        src,
        dst,
    })
}

/// The `/64` prefix (first eight octets) of an address.
const fn prefix64(addr: Ipv6Addr) -> [u8; 8] {
    let o = addr.octets();
    [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
}

/// Does an **egress** frame (workload → broker) pass the shape check?
///
/// `version 6 ∧ next_header == UDP ∧ src == kennel_addr ∧ dst ∈ the tun /64 (a pool or resolver
/// address, never the interface itself) ∧ a UDP header fits`. Any deviation ⇒ `false` (drop);
/// workload `ICMPv6` and any non-UDP transport are dropped here. `kennel_addr` is the tun's own
/// address; `prefix` is the tun's `/64` (the pool and resolver both live in it).
#[must_use]
pub fn egress_ok(frame: &[u8], kennel_addr: Ipv6Addr, prefix: [u8; 8]) -> bool {
    let Some(h) = parse_ipv6(frame) else {
        return false;
    };
    h.next_header == NEXT_UDP
        && h.src == kennel_addr
        && prefix64(h.dst) == prefix
        && h.dst != kennel_addr
        && h.payload_len >= UDP_HEADER
}

/// Does an **ingress** frame (broker → workload) pass the shape check?
///
/// `dst == kennel_addr ∧ src ∈ the tun /64 ∧ (UDP ∨ ICMPv6 Destination-Unreachable code 1|4)`.
/// Any deviation ⇒ `false` (drop).
#[must_use]
pub fn ingress_ok(frame: &[u8], kennel_addr: Ipv6Addr, prefix: [u8; 8]) -> bool {
    let Some(h) = parse_ipv6(frame) else {
        return false;
    };
    if h.dst != kennel_addr || prefix64(h.src) != prefix {
        return false;
    }
    match h.next_header {
        NEXT_UDP => h.payload_len >= UDP_HEADER,
        NEXT_ICMPV6 => {
            h.payload_len >= ICMPV6_HEADER
                && frame.get(IPV6_HEADER) == Some(&ICMPV6_DEST_UNREACH)
                && frame
                    .get(IPV6_HEADER + 1)
                    .is_some_and(|c| ICMPV6_RELAYED_CODES.contains(c))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KENNEL: &str = "fd6b:6e9c:691c:8001::1";
    fn kennel() -> Ipv6Addr {
        KENNEL.parse().expect("kennel addr")
    }
    fn prefix() -> [u8; 8] {
        prefix64(kennel())
    }
    fn addr(s: &str) -> Ipv6Addr {
        s.parse().expect("addr")
    }

    /// Build a bare IPv6 frame (as the `IFF_NO_PI` tun delivers): 40-byte header + payload, with a
    /// correct stated payload length.
    fn frame(next: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(IPV6_HEADER.saturating_add(payload.len()));
        f.push(0x60); // version 6, traffic class 0
        f.extend_from_slice(&[0, 0, 0]); // flow label
        f.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("payload len")
                .to_be_bytes(),
        );
        f.push(next);
        f.push(64); // hop limit
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(payload);
        f
    }
    /// A minimal UDP payload (header only).
    fn udp() -> Vec<u8> {
        vec![0u8; UDP_HEADER]
    }

    #[test]
    fn egress_accepts_udp_to_the_pool() {
        let f = frame(
            NEXT_UDP,
            kennel(),
            addr("fd6b:6e9c:691c:8001::abcd"),
            &udp(),
        );
        assert!(egress_ok(&f, kennel(), prefix()));
    }

    #[test]
    fn egress_accepts_udp_to_the_resolver() {
        let f = frame(NEXT_UDP, kennel(), addr("fd6b:6e9c:691c:8001::2"), &udp());
        assert!(egress_ok(&f, kennel(), prefix()));
    }

    #[test]
    fn egress_rejects_the_hostile_shapes() {
        let dst = addr("fd6b:6e9c:691c:8001::abcd");
        // wrong transport (workload `ICMPv6`, TCP), wrong src, dst outside the /64, dst == interface.
        assert!(!egress_ok(
            &frame(NEXT_ICMPV6, kennel(), dst, &udp()),
            kennel(),
            prefix()
        ));
        assert!(!egress_ok(
            &frame(6, kennel(), dst, &udp()),
            kennel(),
            prefix()
        ));
        assert!(!egress_ok(
            &frame(NEXT_UDP, addr("fd6b:6e9c:691c:8001::99"), dst, &udp()),
            kennel(),
            prefix()
        ));
        assert!(!egress_ok(
            &frame(NEXT_UDP, kennel(), addr("2001:db8::1"), &udp()),
            kennel(),
            prefix()
        ));
        assert!(!egress_ok(
            &frame(NEXT_UDP, kennel(), kennel(), &udp()),
            kennel(),
            prefix()
        ));
    }

    #[test]
    fn egress_rejects_malformed_frames() {
        // empty, too short, not v6, a UDP payload shorter than a UDP header.
        assert!(!egress_ok(&[], kennel(), prefix()));
        assert!(!egress_ok(&[0x60; 20], kennel(), prefix()));
        let mut not_v6 = frame(NEXT_UDP, kennel(), addr("fd6b:6e9c:691c:8001::5"), &udp());
        *not_v6.first_mut().expect("frame has bytes") = 0x40; // version 4
        assert!(!egress_ok(&not_v6, kennel(), prefix()));
        let short = frame(
            NEXT_UDP,
            kennel(),
            addr("fd6b:6e9c:691c:8001::5"),
            &[0u8; 4],
        );
        assert!(!egress_ok(&short, kennel(), prefix()));
        // stated payload length longer than the frame.
        let mut lying = frame(NEXT_UDP, kennel(), addr("fd6b:6e9c:691c:8001::5"), &udp());
        *lying.get_mut(4).expect("payload-len high byte") = 0xff;
        assert!(!egress_ok(&lying, kennel(), prefix()));
    }

    #[test]
    fn ingress_accepts_udp_and_relayed_icmpv6() {
        let src = addr("fd6b:6e9c:691c:8001::abcd");
        assert!(ingress_ok(
            &frame(NEXT_UDP, src, kennel(), &udp()),
            kennel(),
            prefix()
        ));
        // `ICMPv6` Dest-Unreach, code 1 (admin prohibited) and code 4 (port unreachable).
        for code in [1u8, 4] {
            let icmp = vec![ICMPV6_DEST_UNREACH, code, 0, 0];
            assert!(ingress_ok(
                &frame(NEXT_ICMPV6, src, kennel(), &icmp),
                kennel(),
                prefix()
            ));
        }
    }

    #[test]
    fn ingress_rejects_the_hostile_shapes() {
        let src = addr("fd6b:6e9c:691c:8001::abcd");
        // dst not the kennel, src outside the /64, a non-relayed `ICMPv6` type/code, other transport.
        assert!(!ingress_ok(
            &frame(NEXT_UDP, src, addr("2001:db8::1"), &udp()),
            kennel(),
            prefix()
        ));
        assert!(!ingress_ok(
            &frame(NEXT_UDP, addr("2001:db8::5"), kennel(), &udp()),
            kennel(),
            prefix()
        ));
        let echo = vec![128u8, 0, 0, 0]; // `ICMPv6` Echo Request (type 128) — not an error, drop.
        assert!(!ingress_ok(
            &frame(NEXT_ICMPV6, src, kennel(), &echo),
            kennel(),
            prefix()
        ));
        let wrong_code = vec![ICMPV6_DEST_UNREACH, 2, 0, 0]; // code 2 not relayed.
        assert!(!ingress_ok(
            &frame(NEXT_ICMPV6, src, kennel(), &wrong_code),
            kennel(),
            prefix()
        ));
        assert!(!ingress_ok(
            &frame(6, src, kennel(), &udp()),
            kennel(),
            prefix()
        ));
    }
}
