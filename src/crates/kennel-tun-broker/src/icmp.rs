//! `ICMPv6` Destination Unreachable synthesis (W2 Part D): the broker's local error replies.
//!
//! When a flow cannot proceed the broker answers **locally**, with the triggering packet in hand —
//! it never retains state for this. Two codes, both accepted by `facade-tun`'s ingress predicate
//! (type 1, codes {1, 4}):
//!
//! - **admin prohibited** (code 1) for a policy denial: the workload addressed a synthetic whose
//!   name/port no grant covers, or that resolves into denied space. This is the fast-fail this
//!   workstream exists for — a client looping against a dead destination learns it is refused
//!   instead of retrying forever.
//! - **port unreachable** (code 4) translated from a real host's `ECONNREFUSED` (recovered from the
//!   connected socket's error queue): the destination is reachable but nothing listens.
//!
//! The error's source is the **synthetic** the workload addressed, so the workload's kernel matches
//! the error to the socket that sent the datagram. RFC 4443 §3.1: the body quotes as much of the
//! invoking packet as fits under the pinned 1280-byte MTU, after a 4-byte unused field.

use std::net::Ipv6Addr;

use crate::forward::checksum_v6;

/// IPv6 `next_header` for `ICMPv6`.
const NEXT_ICMPV6: u8 = 58;
/// `ICMPv6` type 1: Destination Unreachable.
const DEST_UNREACH: u8 = 1;
/// Code 1: communication with the destination is administratively prohibited (a policy denial).
pub const CODE_ADMIN_PROHIBITED: u8 = 1;
/// Code 4: the destination port is unreachable (translated from `ECONNREFUSED`).
pub const CODE_PORT_UNREACHABLE: u8 = 4;

/// Fixed IPv6 header length.
const IPV6_HEADER: usize = 40;
/// `ICMPv6` Destination Unreachable header: type, code, checksum (2), unused (4).
const ICMP6_HEADER: usize = 8;
/// The pinned path MTU. A synthesized error, like any frame the broker emits, must fit it.
const MIN_MTU: usize = 1280;
/// Room for the quoted invoking packet: the MTU less the outer IPv6 header and the `ICMPv6` header.
const QUOTE_ROOM: usize = MIN_MTU - IPV6_HEADER - ICMP6_HEADER;

/// Build an `ICMPv6` Destination Unreachable (type 1) frame with `code`, from `src` (the synthetic
/// the workload addressed) to `dst` (the kennel), quoting the head of `invoking`.
///
/// The quote is truncated so the whole frame fits the pinned 1280-byte MTU. The `ICMPv6` checksum is
/// mandatory and computed over the pseudo-header; a computed 0 is written verbatim (unlike UDP,
/// `ICMPv6` has no "no checksum" sentinel).
#[must_use]
pub fn build_dest_unreachable(src: Ipv6Addr, dst: Ipv6Addr, code: u8, invoking: &[u8]) -> Vec<u8> {
    let quote = invoking.get(..QUOTE_ROOM).unwrap_or(invoking);

    let mut icmp = Vec::with_capacity(ICMP6_HEADER.saturating_add(quote.len()));
    icmp.push(DEST_UNREACH);
    icmp.push(code);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&[0, 0, 0, 0]); // unused (RFC 4443 §3.1)
    icmp.extend_from_slice(quote);
    let checksum = checksum_v6(src, dst, NEXT_ICMPV6, &icmp);
    if let Some(field) = icmp.get_mut(2..4) {
        field.copy_from_slice(&checksum.to_be_bytes());
    }

    // The upper-layer length never exceeds the MTU, so the u16 conversion cannot truncate.
    let payload_len = u16::try_from(icmp.len()).unwrap_or(u16::MAX);
    let mut frame = Vec::with_capacity(IPV6_HEADER.saturating_add(icmp.len()));
    frame.push(0x60); // version 6, traffic class 0
    frame.extend_from_slice(&[0, 0, 0]); // flow label
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(NEXT_ICMPV6);
    frame.push(64); // hop limit
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&icmp);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth() -> Ipv6Addr {
        "fd6b:6e9c:691c:8001::10".parse().expect("synth")
    }
    fn kennel() -> Ipv6Addr {
        "fd6b:6e9c:691c:8001::1".parse().expect("kennel")
    }

    #[test]
    fn admin_prohibited_is_a_well_formed_type1_code1_frame() {
        let frame = build_dest_unreachable(synth(), kennel(), CODE_ADMIN_PROHIBITED, b"invoking");
        assert_eq!(frame.get(6), Some(&NEXT_ICMPV6), "next-header ICMPv6");
        assert_eq!(&frame.get(8..24).expect("src"), &synth().octets());
        assert_eq!(&frame.get(24..40).expect("dst"), &kennel().octets());
        assert_eq!(frame.get(40), Some(&DEST_UNREACH), "type 1");
        assert_eq!(frame.get(41), Some(&CODE_ADMIN_PROHIBITED), "code 1");
    }

    #[test]
    fn the_checksum_verifies() {
        let frame = build_dest_unreachable(synth(), kennel(), CODE_PORT_UNREACHABLE, b"hello");
        let icmp = frame.get(IPV6_HEADER..).expect("icmp");
        // Recomputing over the on-wire ICMP message (checksum field in place) folds to 0.
        assert_eq!(checksum_v6(synth(), kennel(), NEXT_ICMPV6, icmp), 0);
    }

    #[test]
    fn the_quote_is_truncated_to_the_mtu() {
        // An oversized invoking packet is truncated so the whole frame fits 1280 bytes.
        let big = vec![0xabu8; 4000];
        let frame = build_dest_unreachable(synth(), kennel(), CODE_ADMIN_PROHIBITED, &big);
        assert!(frame.len() <= MIN_MTU, "frame fits the pinned MTU");
        assert_eq!(frame.len(), MIN_MTU, "a large quote fills the MTU exactly");
    }

    #[test]
    fn a_short_invoking_packet_is_quoted_whole() {
        let frame = build_dest_unreachable(synth(), kennel(), CODE_ADMIN_PROHIBITED, b"abc");
        // 40 (IPv6) + 8 (ICMP header) + 3 (quote) = 51.
        assert_eq!(frame.len(), IPV6_HEADER + ICMP6_HEADER + 3);
    }
}
