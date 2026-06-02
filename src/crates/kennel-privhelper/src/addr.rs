//! Forward construction of a kennel's loopback addresses.
//!
//! The privhelper [`validate`](crate::validate)s addresses by taking them apart
//! (extracting the embedded `tag`/`ctx` and comparing to the caller's scope);
//! `kenneld` needs the inverse — given a scope and a context, *build* the
//! addresses to ask the helper to add. The bit layout here is the exact mirror
//! of `validate::validate_addr`, and a round-trip test pins them together.
//!
//! - IPv4 `/28`: `127 | tag(12) | ctx(8) | host(4)`. A v4-enabled kennel is
//!   limited to `ctx <= 255` (the 8-bit field); the 4-bit host selects an
//!   address within the kennel's 16-address subnet (offset 1 is the proxy).
//! - IPv6 `/64`: `0xfd | gid(40) | ctx(16) | host(64)`. The per-user 40-bit
//!   `gid` provides isolation, so there is no `tag`; `ctx` is a full 16 bits.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The fixed prefix length of a per-kennel IPv4 loopback subnet (16 addresses).
pub const V4_PREFIX: u8 = 28;
/// The fixed prefix length of a per-kennel IPv6 ULA subnet.
pub const V6_PREFIX: u8 = 64;

/// Build the IPv4 loopback address `127 | tag(12) | ctx(8) | host(4)`.
///
/// `tag` is masked to 12 bits and `host` to 4; `ctx` occupies the full 8-bit
/// field. The result is in the kennel's `/28`.
#[must_use]
pub fn loopback_v4(tag: u16, ctx: u8, host: u8) -> Ipv4Addr {
    let tag = u32::from(tag) & 0x0FFF;
    let host = u32::from(host) & 0x0F;
    let full = (127u32 << 24) | tag.wrapping_shl(12) | u32::from(ctx).wrapping_shl(4) | host;
    Ipv4Addr::from(full)
}

/// Build the IPv6 loopback address `0xfd | gid(40) | ctx(16) | host(64)`.
#[must_use]
pub fn loopback_v6(gid: [u8; 5], ctx: u16, host: u64) -> Ipv6Addr {
    let [g0, g1, g2, g3, g4] = gid;
    let [c0, c1] = ctx.to_be_bytes();
    let [h0, h1, h2, h3, h4, h5, h6, h7] = host.to_be_bytes();
    Ipv6Addr::from([0xfd, g0, g1, g2, g3, g4, c0, c1, h0, h1, h2, h3, h4, h5, h6, h7])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{validate_addr, AddrRequest, ReservedScope};
    use std::net::IpAddr;

    #[test]
    fn v4_layout_matches_validation() {
        // tag 9, ctx 5, host 1 -> 127.0.144.81 (the proxy address of that kennel).
        let addr = loopback_v4(9, 5, 1);
        assert_eq!(addr, Ipv4Addr::new(127, 0, 144, 81));

        // The address the forward builder produces must pass reverse validation.
        let scope = ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-x");
        let req = AddrRequest { ctx: 5, interface: "lo".to_owned(), addr: IpAddr::V4(addr), prefix: V4_PREFIX };
        assert!(validate_addr(&req, &scope).is_ok());
    }

    #[test]
    fn v6_layout_matches_validation() {
        let gid = [0x01, 0x02, 0x03, 0x04, 0x05];
        let addr = loopback_v6(gid, 0x0102, 1);
        // fd | gid | ctx | host
        assert_eq!(addr.octets()[0], 0xfd);
        assert_eq!(&addr.octets()[1..6], &gid);
        assert_eq!(&addr.octets()[6..8], &[0x01, 0x02]);

        let scope = ReservedScope::new(9, gid, "kennel-x");
        let req = AddrRequest { ctx: 0x0102, interface: "lo".to_owned(), addr: IpAddr::V6(addr), prefix: V6_PREFIX };
        assert!(validate_addr(&req, &scope).is_ok());
    }

    #[test]
    fn v4_high_bits_are_masked() {
        // tag and host beyond their fields must not bleed into neighbours.
        let addr = loopback_v4(0xFFFF, 0, 0xFF);
        let scope = ReservedScope::new(0x0FFF, [0; 5], "k");
        let req = AddrRequest { ctx: 0, interface: "lo".to_owned(), addr: IpAddr::V4(addr), prefix: V4_PREFIX };
        assert!(validate_addr(&req, &scope).is_ok(), "masked tag should match TAG_MAX scope");
    }
}
