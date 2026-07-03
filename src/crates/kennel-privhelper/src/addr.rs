//! Forward construction of a kennel's IPv6 loopback address.
//!
//! The privhelper [`validate`](crate::validate)s an address by taking it apart
//! (extracting the embedded fixed prefix / uid subnet / `ctx` and comparing to
//! the caller's kernel-trusted uid); `kenneld` needs the inverse — given a uid
//! and a context, *build* the address to ask the helper to add. The bit layout
//! here is the exact mirror of `validate::validate_addr`, and a round-trip test
//! pins them together.
//!
//! IPv6 `/64`: `0xfd | KENNEL(16) | uid_subnet(24) | ctx(16) | host(64)`. The
//! fixed [`KENNEL_ULA`] 16-bit constant makes the prefix a standard, greppable
//! Kennel ULA space (`fd6b:6e00::/24`); the 24-bit [`uid_subnet`] isolates each
//! user; `ctx` gives each kennel its own `/64`. There is no IPv4: a kennel's
//! loopback and inbound-mirror addressing is v6-only (the same posture as the
//! UDP-egress work), so a v4-only inbound service is an accepted non-goal.
//!
//! The per-user subnet is *derived from the kernel-trusted uid*, not an admin
//! allocation: both sides recompute it from the same uid, so the "add only your
//! own subnet" capability holds with no `/etc` file.

use std::net::Ipv6Addr;

/// The fixed prefix length of a per-kennel IPv6 ULA subnet.
pub const V6_PREFIX: u8 = 64;

/// The fixed 16-bit Kennel ULA identifier, following `0xfd`.
///
/// Arbitrary constant, chosen once (RFC 4193 permits any global ID); Kennel's
/// host-local loopback ULA space is `fd6b:6e00::/24`, never routed off the host.
pub const KENNEL_ULA: [u8; 2] = [0x6b, 0x6e];

/// The 24-bit per-user subnet, an FNV-1a hash of the uid.
///
/// FNV-1a is a tiny, std-only non-cryptographic hash (no dependency): this is
/// collision-avoidance for host-local loopback addresses, not a security
/// primitive. A 24-bit space makes a collision between two co-located users
/// astronomically unlikely on any realistic host.
#[must_use]
pub fn uid_subnet(uid: u32) -> [u8; 3] {
    let mut h: u32 = 0x811c_9dc5;
    for b in uid.to_le_bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    // The low 24 bits: the three least-significant bytes of the big-endian hash.
    let [_, a, b, c] = h.to_be_bytes();
    [a, b, c]
}

/// Build the IPv6 loopback address `0xfd | KENNEL(16) | uid_subnet(24) | ctx(16) | host(64)`.
#[must_use]
pub fn loopback_v6(uid: u32, ctx: u16, host: u64) -> Ipv6Addr {
    let [k0, k1] = KENNEL_ULA;
    let [s0, s1, s2] = uid_subnet(uid);
    let [c0, c1] = ctx.to_be_bytes();
    let [h0, h1, h2, h3, h4, h5, h6, h7] = host.to_be_bytes();
    Ipv6Addr::from([
        0xfd, k0, k1, s0, s1, s2, c0, c1, h0, h1, h2, h3, h4, h5, h6, h7,
    ])
}

/// The tun `/64` ctx offset: the kennel ctx's high bit flipped, so the tun's connected `/64` never
/// collides with the loopback `/64` in the kennel's net-ns (W2).
pub const TUN_CTX_FLIP: u16 = 0x8000;
/// The tun interface address's host suffix within its `/64` (`::1`); `::2` is the broker resolver
/// and the rest is the synthetic pool.
pub const TUN_HOST: u64 = 1;

/// The tun's reserved resolver host suffix within its `/64` (`::2`): where the tun broker's DNS
/// naming shim answers, and where a `[net.udp]` kennel's `resolv.conf` points.
pub const TUN_RESOLVER_HOST: u64 = 2;

/// The kennel's tun interface address (`::1` in its ULA `/64`), from the operator uid and kennel ctx.
///
/// The single source both the privileged constructor (which addresses the tun) and kenneld (which
/// tells the tun broker the consumer's `/64` over `ACCEPT_SESSION`) derive it from, so the two can
/// never disagree on where a kennel's synthetics live.
#[must_use]
pub fn tun_addr(op_uid: u32, kennel_ctx: u16) -> Ipv6Addr {
    loopback_v6(op_uid, kennel_ctx ^ TUN_CTX_FLIP, TUN_HOST)
}

/// The tun's reserved resolver address (`::2` in the tun `/64`), where the broker's DNS shim answers.
#[must_use]
pub fn tun_resolver(op_uid: u32, kennel_ctx: u16) -> Ipv6Addr {
    loopback_v6(op_uid, kennel_ctx ^ TUN_CTX_FLIP, TUN_RESOLVER_HOST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{validate_addr, AddrRequest, ReservedScope};
    use std::net::IpAddr;

    #[test]
    fn v6_layout_matches_validation() {
        let uid = 1000;
        let addr = loopback_v6(uid, 0x0102, 1);
        let o = addr.octets();
        assert_eq!(o[0], 0xfd);
        assert_eq!(&o[1..3], &KENNEL_ULA);
        assert_eq!(&o[3..6], &uid_subnet(uid));
        assert_eq!(&o[6..8], &[0x01, 0x02]);

        // The address the forward builder produces must pass reverse validation
        // against the same uid.
        let req = AddrRequest {
            ctx: 0x0102,
            interface: "lo".to_owned(),
            addr: IpAddr::V6(addr),
            prefix: V6_PREFIX,
        };
        assert!(validate_addr(&req, &ReservedScope::new(uid)).is_ok());
    }

    #[test]
    fn different_uids_land_in_different_subnets() {
        // The whole point: two users get distinct /64s for the same ctx.
        assert_ne!(uid_subnet(1000), uid_subnet(1001));
        assert_ne!(loopback_v6(1000, 5, 1), loopback_v6(1001, 5, 1));
    }

    #[test]
    fn a_foreign_uids_address_fails_validation() {
        // An address built for uid 1001 must not validate against uid 1000's scope.
        let addr = loopback_v6(1001, 7, 1);
        let req = AddrRequest {
            ctx: 7,
            interface: "lo".to_owned(),
            addr: IpAddr::V6(addr),
            prefix: V6_PREFIX,
        };
        assert!(validate_addr(&req, &ReservedScope::new(1000)).is_err());
    }
}
