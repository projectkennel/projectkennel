//! The broker's flow forwarder (W2 Part D, half 2): the pure wire half.
//!
//! Route between the tun's L3 frames and the host-side UDP dial. `facade-tun` hands the broker
//! whole, already-shape-checked L3 frames. Outbound, [`route`] reads
//! the datagram's synthetic destination back to its mapped name (via the [`Pool`]) plus the UDP
//! ports and payload — everything the dialer needs to open a connected UDP socket to the real host
//! (`host-netproxy`'s UDP mode). Inbound, [`build_udp_datagram`] wraps a datagram the host returned
//! back into an L3 frame the workload's kernel accepts — same synthetic as source, so the flow the
//! workload opened is the flow it hears back from.
//!
//! This module is the pure wire half: parsing the egress frame and building the ingress one,
//! including the mandatory IPv6 UDP checksum. The sockets, the flow table, and the dial live in the
//! broker binary; the shape guarantees come from `facade-tun` (this re-reads bounds, not policy).

use std::net::Ipv6Addr;

use crate::shim::Pool;

/// Fixed IPv6 header length.
const IPV6_HEADER: usize = 40;
/// UDP header length (src port, dst port, length, checksum).
const UDP_HEADER: usize = 8;
/// IPv6 `next_header` for UDP.
const NEXT_UDP: u8 = 17;
/// Offsets of the UDP fields, measured from the start of the frame (after the IPv6 header).
const SRC_PORT: usize = IPV6_HEADER;
const DST_PORT: usize = IPV6_HEADER + 2;
const PAYLOAD: usize = IPV6_HEADER + UDP_HEADER;

/// An egress datagram routed to its dialled host: the mapped `name`, the destination `dst_port` to
/// dial, the workload's `src_port` (where the reply must return), and the UDP `payload`.
pub struct Route<'d> {
    /// The name the synthetic destination maps to — what `host-netproxy` dials.
    pub name: String,
    /// The destination port the workload addressed (the service port to dial).
    pub dst_port: u16,
    /// The workload's source port — the reply datagram's destination port.
    pub src_port: u16,
    /// The UDP payload to send.
    pub payload: &'d [u8],
}

/// Route an egress L3 frame to its dialled host, or `None` if its destination is not a live
/// synthetic (the caller answers ICMP-unreach) or the frame is too short / not UDP.
///
/// `facade-tun` already shape-checked the frame (v6, UDP, src == kennel, dst ∈ the tun `/64`); this
/// extracts the routing fields rather than re-validating policy, but stays fully bounds-checked.
#[must_use]
pub fn route<'d>(frame: &'d [u8], pool: &Pool) -> Option<Route<'d>> {
    if *frame.get(6)? != NEXT_UDP {
        return None;
    }
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(frame.get(24..IPV6_HEADER)?).ok()?);
    let name = pool.name_of(dst)?.to_owned();
    let src_port = be16(frame, SRC_PORT)?;
    let dst_port = be16(frame, DST_PORT)?;
    let payload = frame.get(PAYLOAD..)?;
    Some(Route {
        name,
        dst_port,
        src_port,
        payload,
    })
}

/// Read a big-endian `u16` at byte `off`, bounds-checked.
fn be16(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    Some(u16::from_be_bytes(
        buf.get(off..end)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())?,
    ))
}

/// Build an ingress L3 frame the workload's kernel will accept, with a valid UDP checksum.
///
/// `src` → `dst`, UDP `src_port` → `dst_port`, carrying `payload`; hop limit 64 and the mandatory
/// IPv6 UDP checksum computed. Returns `None` if the total length overflows the 16-bit UDP length.
#[must_use]
pub fn build_udp_datagram(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(UDP_HEADER.checked_add(payload.len())?).ok()?;
    let mut udp = Vec::with_capacity(UDP_HEADER.saturating_add(payload.len()));
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    let checksum = udp_checksum_v6(src, dst, &udp);
    // A computed checksum of 0 is transmitted as 0xffff (RFC 768 / 8200) so it is never mistaken
    // for "no checksum".
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    if let Some(field) = udp.get_mut(6..8) {
        field.copy_from_slice(&checksum.to_be_bytes());
    }

    let mut frame = Vec::with_capacity(IPV6_HEADER.saturating_add(udp.len()));
    frame.push(0x60); // version 6, traffic class 0
    frame.extend_from_slice(&[0, 0, 0]); // flow label
    frame.extend_from_slice(&udp_len.to_be_bytes()); // payload length = the UDP datagram
    frame.push(NEXT_UDP);
    frame.push(64); // hop limit
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&udp);
    Some(frame)
}

/// The IPv6 UDP checksum: [`checksum_v6`] over the UDP datagram with next-header 17.
fn udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    checksum_v6(src, dst, NEXT_UDP, udp)
}

/// The IPv6 upper-layer checksum (RFC 8200 §8.1): the one's-complement sum over the pseudo-header
/// (`src` | `dst` | u32 upper-layer length | 3 zero bytes | `next_header`) and the upper-layer
/// `payload` (its own checksum field zeroed), folded and complemented.
///
/// Shared by the UDP datagram builder and the `ICMPv6` error builder — the same algorithm keyed only
/// by the `next_header` byte (17 for UDP, 58 for `ICMPv6`).
pub(crate) fn checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            if let [a, b] = pair {
                sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*a, *b])));
            }
        }
        if let [last] = chunks.remainder() {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
        }
    };
    add(&src.octets());
    add(&dst.octets());
    // Upper-layer length as a 32-bit pseudo-header field, then 3 zero bytes + the next-header byte.
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    add(&len.to_be_bytes());
    add(&[0, 0, 0, next_header]);
    add(payload);
    // Fold carries into 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)] // folded to 16 bits above
    let folded = sum as u16;
    !folded
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: [u8; 8] = [0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01];
    fn kennel() -> Ipv6Addr {
        "fd6b:6e9c:691c:8001::1".parse().expect("kennel")
    }

    /// Mint a synthetic for `name` and build an egress frame from the kennel to the `synthetic:dst_port`.
    fn egress(
        pool: &mut Pool,
        name: &str,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let synth = pool.mint(name, 0).expect("mint");
        build_udp_datagram(kennel(), synth, src_port, dst_port, payload).expect("frame")
    }

    #[test]
    fn route_maps_the_synthetic_back_to_its_name_and_ports() {
        let mut pool = Pool::new(PREFIX);
        let frame = egress(&mut pool, "example.com", 5353, 443, b"hello");
        let r = route(&frame, &pool).expect("routed");
        assert_eq!(r.name, "example.com");
        assert_eq!(r.src_port, 5353);
        assert_eq!(r.dst_port, 443);
        assert_eq!(r.payload, b"hello");
    }

    #[test]
    fn route_misses_an_unminted_destination() {
        let pool = Pool::new(PREFIX);
        // A frame to a /64 address never minted → no name → None (caller sends ICMP-unreach).
        let frame = build_udp_datagram(
            kennel(),
            "fd6b:6e9c:691c:8001::dead".parse().expect("addr"),
            1,
            2,
            b"x",
        )
        .expect("frame");
        assert!(route(&frame, &pool).is_none());
    }

    #[test]
    fn route_rejects_short_and_non_udp() {
        let pool = Pool::new(PREFIX);
        assert!(route(&[], &pool).is_none());
        assert!(route(&[0x60; 20], &pool).is_none());
    }

    #[test]
    fn checksum_is_correct_and_verifies_to_zero() {
        // A receiver sums the whole datagram (checksum field included) + pseudo-header; a valid
        // datagram folds to 0xffff (the one's-complement of 0), i.e. `!sum == 0`.
        let src: Ipv6Addr = "fd6b:6e9c:691c:8001::abcd".parse().expect("addr");
        let dst = kennel();
        let frame = build_udp_datagram(src, dst, 443, 5353, b"pong").expect("frame");
        let udp = frame.get(IPV6_HEADER..).expect("udp");
        // Recomputing over the on-wire datagram (checksum field in place) yields 0: the receiver's
        // sum folds to 0xffff and this returns its one's-complement.
        assert_eq!(udp_checksum_v6(src, dst, udp), 0, "checksum verifies");
    }

    #[test]
    fn round_trip_egress_then_reply() {
        // Build an egress frame, route it, then build the reply the workload would receive: the
        // reply's src is the synthetic and its dst_port is the workload's original src_port.
        let mut pool = Pool::new(PREFIX);
        let frame = egress(&mut pool, "api.example", 40000, 53, b"query");
        let r = route(&frame, &pool).expect("routed");
        let synth = pool.mint("api.example", 0).expect("mint"); // stable
        let reply = build_udp_datagram(synth, kennel(), r.dst_port, r.src_port, b"answer")
            .expect("reply frame");
        let back = route(&reply, &pool); // the reply's dst is the kennel, not a synthetic → no route
        assert!(
            back.is_none(),
            "the reply is inbound, not a routable egress frame"
        );
        // The reply is well-formed: v6, UDP, to the kennel, from the synthetic.
        assert_eq!(reply.get(6), Some(&NEXT_UDP));
        assert_eq!(&reply.get(8..24).expect("octets"), &synth.octets());
        assert_eq!(&reply.get(24..40).expect("octets"), &kennel().octets());
    }
}
