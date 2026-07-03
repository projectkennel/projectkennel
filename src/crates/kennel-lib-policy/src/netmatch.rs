//! Address matching for egress: CIDR containment and special-use classification.
//!
//! The two address primitives every egress gate re-checks a *resolved* address against, in one
//! place so they cannot drift between enforcers. The egress proxy (`kenneld`'s `NetRuntime`) and
//! the UDP-egress broker (`kennel-udp-broker`) each resolve a policy-permitted name and must then
//! re-vet the answer against the categorical deny CIDRs and the non-public ranges — the rebinding /
//! SSRF-to-internal defence. That vetting is byte-for-byte identical wherever it runs, so it lives
//! here (the sibling of [`name_matches`](crate::name_matches), which shares names the same way).
//!
//! This module is pure and network-free: given an address, decide containment or classification.
//! It shares no arithmetic with the BPF LPM encoder in `kennel-lib-spawn`; the BPF map and these
//! checks are independent enforcers of the same notion and must each be correct on their own.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP network: a base address and a prefix length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix_len: u8,
}

/// Error constructing a [`Cidr`]: the prefix length exceeds the address family's
/// maximum (32 for IPv4, 128 for IPv6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixTooLong {
    /// The maximum prefix length for the address family.
    pub max: u8,
    /// The prefix length that was supplied.
    pub got: u8,
}

impl std::fmt::Display for PrefixTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prefix length {} exceeds the maximum {} for the address family",
            self.got, self.max
        )
    }
}

impl std::error::Error for PrefixTooLong {}

impl Cidr {
    /// Construct a CIDR from a base address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixTooLong`] if `prefix_len` exceeds 32 for an IPv4 base or
    /// 128 for an IPv6 base.
    pub const fn new(base: IpAddr, prefix_len: u8) -> Result<Self, PrefixTooLong> {
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(PrefixTooLong {
                max,
                got: prefix_len,
            });
        }
        Ok(Self { base, prefix_len })
    }

    /// Whether `addr` falls within this network. A family mismatch (v4 address
    /// against a v6 network, or vice versa) is never a match.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(base), IpAddr::V4(other)) => {
                octets_match(&base.octets(), &other.octets(), self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(other)) => {
                octets_match(&base.octets(), &other.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Whether the top `prefix_len` bits of `base` and `addr` are equal. The two
/// slices must be the same length (both 4 or both 16 octets); a length mismatch
/// compares only the shared prefix and is never reached for real addresses.
fn octets_match(base: &[u8], addr: &[u8], prefix_len: u8) -> bool {
    let mut bits_remaining = u32::from(prefix_len);
    for (b, a) in base.iter().zip(addr.iter()) {
        if bits_remaining == 0 {
            return true;
        }
        if bits_remaining >= 8 {
            if b != a {
                return false;
            }
            bits_remaining = bits_remaining.saturating_sub(8);
        } else {
            let mask = top_bits_mask(bits_remaining);
            return (b & mask) == (a & mask);
        }
    }
    true
}

/// A byte mask selecting the top `n` bits, for `n` in `1..=7`. Built by lookup
/// rather than by shifting, so the function shares no arithmetic that the
/// `arithmetic_side_effects` lint would flag.
const fn top_bits_mask(n: u32) -> u8 {
    match n {
        1 => 0b1000_0000,
        2 => 0b1100_0000,
        3 => 0b1110_0000,
        4 => 0b1111_0000,
        5 => 0b1111_1000,
        6 => 0b1111_1100,
        7 => 0b1111_1110,
        _ => 0b0000_0000,
    }
}

/// Whether `addr` is in special-use / non-public space.
///
/// IPv4: RFC1918 private, CGNAT (`100.64.0.0/10`), loopback, link-local,
/// multicast, broadcast, documentation, and unspecified. IPv6: loopback,
/// unspecified, multicast, ULA (`fc00::/7`), and link-local (`fe80::/10`).
///
/// An egress gate refuses to connect to a *resolved* address in this space unless the policy opts
/// in. The point is the rebinding / SSRF-to-internal defence: a public name that resolves into
/// private space — whether through a hostile resolver or system DNS answering for an internal zone
/// — must not become a reachable internal destination by default.
///
/// The classification is a set of explicit, well-defined range checks (no DNS or
/// other footgun parsing); the bit checks for CGNAT, ULA, and IPv6 link-local use
/// the octets directly because the corresponding `std` predicates are unstable.
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

/// Whether `a` is in the carrier-grade NAT range `100.64.0.0/10` (RFC 6598).
const fn is_cgnat(a: Ipv4Addr) -> bool {
    let [first, second, ..] = a.octets();
    first == 100 && matches!(second, 64..=127)
}

/// Whether `a` is a unique-local address `fc00::/7` (RFC 4193): the top 7 bits
/// are `1111110`, i.e. the first octet is `0xfc` or `0xfd`.
const fn is_ula(a: Ipv6Addr) -> bool {
    let [first, ..] = a.octets();
    first & 0xfe == 0xfc
}

/// Whether `a` is a link-local unicast address `fe80::/10`: the first ten bits
/// are `1111111010`.
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

    fn cidr(addr: &str, prefix: u8) -> Cidr {
        Cidr::new(addr.parse::<IpAddr>().expect("addr literal"), prefix).expect("valid cidr")
    }

    // ---- is_special_use ----

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
        // A global unicast address and a Quad9/Cloudflare-style public resolver.
        for s in ["2606:4700:4700::1111", "2620:fe::fe"] {
            assert!(!is_special_use(v6(s)), "{s} should be public");
        }
    }

    // ---- Cidr (structure) ----

    #[test]
    fn cidr_rejects_overlong_prefix() {
        assert_eq!(
            Cidr::new(v4("10.0.0.0"), 33),
            Err(PrefixTooLong { max: 32, got: 33 })
        );
        assert_eq!(
            Cidr::new(v6("fd00::"), 129),
            Err(PrefixTooLong { max: 128, got: 129 })
        );
    }

    #[test]
    fn cidr_accepts_boundary_prefixes() {
        assert!(Cidr::new(v4("10.0.0.0"), 32).is_ok());
        assert!(Cidr::new(v4("0.0.0.0"), 0).is_ok());
        assert!(Cidr::new(v6("fd00::"), 128).is_ok());
    }

    #[test]
    fn cidr_v4_contains_within_and_excludes_outside() {
        let net = cidr("10.1.2.0", 24);
        assert!(net.contains(v4("10.1.2.0")));
        assert!(net.contains(v4("10.1.2.255")));
        assert!(!net.contains(v4("10.1.3.0")));
        assert!(!net.contains(v4("10.1.1.255")));
    }

    #[test]
    fn cidr_host_route_matches_only_itself() {
        let net = cidr("169.254.169.254", 32);
        assert!(net.contains(v4("169.254.169.254")));
        assert!(!net.contains(v4("169.254.169.253")));
    }

    #[test]
    fn cidr_default_route_matches_everything_in_family() {
        let net = cidr("0.0.0.0", 0);
        assert!(net.contains(v4("8.8.8.8")));
        assert!(net.contains(v4("192.168.0.1")));
        // ...but not the other family.
        assert!(!net.contains(v6("fd00::1")));
    }

    #[test]
    fn cidr_v6_prefix_matches() {
        let net = cidr("fd00:ec2::", 32);
        assert!(net.contains(v6("fd00:ec2::254")));
        assert!(!net.contains(v6("fd00:ec3::1")));
    }

    #[test]
    fn cidr_family_mismatch_never_matches() {
        assert!(!cidr("10.0.0.0", 8).contains(v6("fd00::1")));
        assert!(!cidr("fd00::", 8).contains(v4("10.0.0.1")));
    }
}
