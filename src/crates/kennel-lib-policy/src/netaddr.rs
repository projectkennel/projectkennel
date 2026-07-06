//! Special-use IP classification — the rebinding / SSRF-to-internal predicate.
//!
//! Shared by every egress decision point so the classification cannot drift between them: the TCP
//! CONNECT decision in `kenneld` (`inet::allow`) and the UDP flow dial in the tun broker
//! (`kennel-tun-broker`) both refuse a *resolved* address in this space, so a public name that
//! resolves into private/loopback/link-local space — through a hostile resolver or system DNS
//! answering for an internal zone — never becomes a reachable internal destination.

#![allow(clippy::doc_markdown)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `addr` is in special-use / non-public space.
///
/// IPv4: RFC1918 private, CGNAT (`100.64.0.0/10`), loopback, link-local, multicast, broadcast,
/// documentation, and unspecified. IPv6: loopback, unspecified, multicast, ULA (`fc00::/7`), and
/// link-local (`fe80::/10`).
///
/// A resolved address in this space is refused by default; a policy that genuinely needs private
/// space opts in explicitly (the TCP proxy's `accept_private_resolved`, or `net.mode = host`). The
/// classification is a set of explicit range checks (no DNS or other footgun parsing); the bit
/// checks for CGNAT, ULA, and IPv6 link-local use the octets directly because the corresponding
/// `std` predicates are unstable.
#[must_use]
pub const fn is_special_use(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || is_cgnat(a)
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || is_ula(a)
                || is_v6_link_local(a)
        }
    }
}

/// Whether `addr` is never a legitimate unicast **egress** destination for a resolved name.
///
/// The set: loopback, link-local, unspecified, multicast, broadcast. A public/enterprise name
/// pointed at one of these (through a hostile or misconfigured DNS zone) is refused at the dial.
///
/// Deliberately NARROWER than [`is_special_use`]: it does **not** include RFC1918 / CGNAT / ULA,
/// which are real internal-unicast destinations that constrained UDP (enterprise data-sync, QUIC to
/// a private endpoint) legitimately reaches. Those are dropped only when a policy asks
/// (`[net.bpf].connect.deny`), not by default. (The DNS-exfil axis is closed separately, by the
/// broker's port-53/5353 deny, so a resolver on a reachable internal address is still refused.)
#[must_use]
pub const fn is_nonroutable_egress(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
        }
        IpAddr::V6(a) => {
            a.is_loopback() || a.is_unspecified() || a.is_multicast() || is_v6_link_local(a)
        }
    }
}

/// Whether `a` is in the carrier-grade NAT range `100.64.0.0/10` (RFC 6598).
const fn is_cgnat(a: Ipv4Addr) -> bool {
    let [first, second, ..] = a.octets();
    first == 100 && matches!(second, 64..=127)
}

/// Whether `a` is a unique-local address `fc00::/7` (RFC 4193): the top 7 bits are `1111110`,
/// i.e. the first octet is `0xfc` or `0xfd`.
const fn is_ula(a: Ipv6Addr) -> bool {
    let [first, ..] = a.octets();
    first & 0xfe == 0xfc
}

/// Whether `a` is a link-local unicast address `fe80::/10`: the first ten bits are `1111111010`.
const fn is_v6_link_local(a: Ipv6Addr) -> bool {
    let [first, second, ..] = a.octets();
    first == 0xfe && second & 0xc0 == 0x80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("v4 literal"))
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("v6 literal"))
    }

    #[test]
    fn special_use_v4_ranges() {
        for s in [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ] {
            assert!(is_special_use(v4(s)), "{s} should be special-use");
        }
    }

    #[test]
    fn public_v4_is_not_special_use() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
        ] {
            assert!(!is_special_use(v4(s)), "{s} should be public");
        }
    }

    #[test]
    fn special_use_v6_ranges() {
        for s in ["::1", "::", "fd00::1", "fc00::1", "fe80::1", "ff02::1"] {
            assert!(is_special_use(v6(s)), "{s} should be special-use");
        }
    }

    #[test]
    fn public_v6_is_not_special_use() {
        for s in ["2606:4700:4700::1111", "2620:fe::fe"] {
            assert!(!is_special_use(v6(s)), "{s} should be public");
        }
    }

    #[test]
    fn nonroutable_egress_is_loopback_linklocal_and_the_non_unicast_set() {
        for s in [
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            assert!(is_nonroutable_egress(v4(s)), "{s} is non-routable");
        }
        for s in ["::1", "::", "fe80::1", "ff02::1"] {
            assert!(is_nonroutable_egress(v6(s)), "{s} is non-routable");
        }
        // RFC1918 / CGNAT / ULA are reachable by default (dropped only by policy), so NOT here —
        // and public addresses are never here.
        for s in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.5.5",
            "100.64.0.1",
            "8.8.8.8",
        ] {
            assert!(
                !is_nonroutable_egress(v4(s)),
                "{s} is a reachable/real dest"
            );
        }
        for s in ["fd00::1", "fc00::1", "2606:4700:4700::1111"] {
            assert!(
                !is_nonroutable_egress(v6(s)),
                "{s} is a reachable/real dest"
            );
        }
    }
}
