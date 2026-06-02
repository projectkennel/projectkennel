//! Request validation: the security core of the privileged helper.
//!
//! # Purpose
//!
//! Decide whether a privileged request falls within Project Kennel's reserved
//! scope, *before* any privileged syscall runs. A compromised or hostile
//! caller (`kenneld` itself, in the threat model) must not be able to direct
//! the helper to touch anything outside that scope.
//!
//! # Invariants
//!
//! - Address requests are confined to the per-kennel allocation. The bit layout
//!   packs more users into the cramped IPv4 loopback space and gives each kennel
//!   only the addresses it needs (a /28 — 16 — rather than a wasteful /24):
//!   - **IPv4**: `127 | tag(12) | ctx(8) | host(4)` → a **/28** per kennel. A
//!     user owns the /20 selected by their 12-bit `tag` (4096 users, 256
//!     v4-enabled kennels each).
//!   - **IPv6**: `fd | gid(40) | ctx(16) | host(64)` → a **/64** per kennel. The
//!     user is isolated by their 40-bit random ULA `gid` (no `tag` needed in v6);
//!     `ctx` is 16-bit, and its low 8 bits coincide with the v4 `ctx` so a
//!     dual-stack kennel shares one context number.
//!
//!   `tag`/`gid` are per-user (the allocation); `ctx` is supplied by the request.
//!   The prefix length is fixed (28 / 64); anything else is refused.
//! - The interface is `lo` or a dummy named `<namespace>-<id>` for the calling
//!   user, within the kernel's 15-character interface-name limit.
//!
//! cgroups are no longer validated here: kenneld creates and manages them
//! unprivileged within its systemd-delegated subtree, and the egress op gates
//! its target cgroup by **directory ownership** (`exec::attach_egress_programs`),
//! not by a namespace path.
//!
//! # Threat bearing
//!
//! Defends against T1.6 (lateral movement) and the cloud-metadata case in
//! particular: a request to add `169.254.169.254` is refused because it is not
//! in the reserved loopback block. This module is pure and platform-
//! independent; it is exercised by the unit tests below on any host.

use std::net::IpAddr;

/// The kernel interface-name length limit (`IFNAMSIZ - 1`).
const IFNAME_MAX: usize = 15;

/// The fixed prefix length for a per-kennel IPv4 loopback subnet (16 addresses).
const V4_PREFIX: u8 = 28;

/// The largest `tag` value (12 bits).
pub const TAG_MAX: u16 = 0x0FFF;

/// The fixed prefix length for a per-kennel IPv6 ULA subnet.
const V6_PREFIX: u8 = 64;

/// The **per-user** reserved scope to validate against.
///
/// Project Kennel's analogue of `/etc/subuid`: each user is allocated a `tag`, a
/// 40-bit ULA global ID, and a resource `namespace` (e.g. `kennel-alice`) so
/// co-located users' kennels cannot collide or touch one another's. The
/// privhelper derives this from the caller's real UID via the allocation file
/// ([`crate::alloc`]), never from the (untrusted) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedScope {
    tag: u16,
    ula_gid: [u8; 5],
    namespace: String,
}

impl ReservedScope {
    /// Construct a reserved scope from a user's 12-bit tag, 40-bit ULA global ID,
    /// and resource namespace. `tag` above [`TAG_MAX`] is clamped (the allocation
    /// loader validates it).
    #[must_use]
    pub fn new(tag: u16, ula_gid: [u8; 5], namespace: impl Into<String>) -> Self {
        Self { tag: tag & TAG_MAX, ula_gid, namespace: namespace.into() }
    }

    /// The user's resource namespace (the cgroup/interface name prefix).
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The user's 12-bit tag (selects their IPv4 loopback `/20`).
    #[must_use]
    pub const fn tag(&self) -> u16 {
        self.tag
    }

    /// The user's 40-bit IPv6 ULA global ID (the five bytes after `0xfd`).
    #[must_use]
    pub const fn ula_gid(&self) -> [u8; 5] {
        self.ula_gid
    }
}

/// A request to add or remove a per-kennel loopback address.
#[derive(Debug, Clone)]
pub struct AddrRequest {
    /// The per-kennel context assigned by `kenneld` (16-bit; a v4-enabled kennel
    /// uses `ctx <= 255`, the low 8 bits that the IPv4 layout can carry).
    pub ctx: u16,
    /// The interface to operate on (`lo` or `kennel-<id>`).
    pub interface: String,
    /// The address to add or remove.
    pub addr: IpAddr,
    /// The subnet prefix length.
    pub prefix: u8,
}

/// Why a request was refused. Each variant names a specific out-of-scope
/// condition so the refusal is actionable in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The prefix length is not the fixed value for the address family.
    BadPrefix {
        /// The required prefix length.
        expected: u8,
        /// The prefix length the request carried.
        got: u8,
    },
    /// The address is not within the per-kennel reserved subnet.
    AddrOutOfScope,
    /// The interface is neither `lo` nor a well-formed `<namespace>-<id>` name.
    InterfaceNotAllowed,
    /// The interface name exceeds the kernel's 15-character limit.
    InterfaceNameTooLong,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPrefix { expected, got } => {
                write!(f, "prefix length must be {expected}, got {got}")
            }
            Self::AddrOutOfScope => {
                write!(
                    f,
                    "address is outside Project Kennel's reserved per-kennel subnet"
                )
            }
            Self::InterfaceNotAllowed => {
                write!(
                    f,
                    "interface must be `lo` or a `<namespace>-<id>` dummy interface"
                )
            }
            Self::InterfaceNameTooLong => {
                write!(
                    f,
                    "interface name exceeds the {IFNAME_MAX}-character kernel limit"
                )
            }
        }
    }
}

impl std::error::Error for Refusal {}

/// Validate an address request against the reserved scope.
///
/// # Errors
///
/// Returns a [`Refusal`] if the prefix length is wrong for the family, the
/// address falls outside the per-kennel `127.<tag>.<ctx>.0/24` (IPv4) or
/// `fd<gid>:<tag>:<ctx>::/64` (IPv6) subnet, or the interface name is not
/// permitted.
pub fn validate_addr(req: &AddrRequest, scope: &ReservedScope) -> Result<(), Refusal> {
    validate_interface(&req.interface, scope)?;
    match req.addr {
        IpAddr::V4(v4) => {
            if req.prefix != V4_PREFIX {
                return Err(Refusal::BadPrefix {
                    expected: V4_PREFIX,
                    got: req.prefix,
                });
            }
            // 127 | tag(12) | ctx(8) | host(4); the 4-bit host is free.
            let full = u32::from_be_bytes(v4.octets());
            let in_loopback = full.wrapping_shr(24) == 127;
            let suffix = full & 0x00FF_FFFF;
            let addr_tag = u16::try_from(suffix.wrapping_shr(12) & 0x0FFF).unwrap_or(u16::MAX);
            let addr_ctx = suffix.wrapping_shr(4) & 0xFF; // 0..=255
            // A v4-enabled kennel has ctx <= 255; a larger ctx can have no v4
            // address, so the comparison against the 8-bit field fails it.
            if in_loopback && addr_tag == scope.tag && u32::from(req.ctx) == addr_ctx {
                Ok(())
            } else {
                Err(Refusal::AddrOutOfScope)
            }
        }
        IpAddr::V6(v6) => {
            if req.prefix != V6_PREFIX {
                return Err(Refusal::BadPrefix {
                    expected: V6_PREFIX,
                    got: req.prefix,
                });
            }
            // 0xfd | gid(40) | ctx(16) | host(64). The user is isolated by gid.
            let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = v6.octets();
            let addr_ctx = u16::from(b6).wrapping_shl(8) | u16::from(b7);
            if b0 == 0xfd && [b1, b2, b3, b4, b5] == scope.ula_gid && addr_ctx == req.ctx {
                Ok(())
            } else {
                Err(Refusal::AddrOutOfScope)
            }
        }
    }
}

/// Check that an interface name is `lo` or a well-formed `<namespace>-<id>`
/// dummy for the calling user.
fn validate_interface(interface: &str, scope: &ReservedScope) -> Result<(), Refusal> {
    if interface == "lo" {
        return Ok(());
    }
    let dash_prefix = format!("{}-", scope.namespace);
    if let Some(id) = interface.strip_prefix(&dash_prefix) {
        if interface.len() > IFNAME_MAX {
            return Err(Refusal::InterfaceNameTooLong);
        }
        if id.is_empty() {
            return Err(Refusal::InterfaceNotAllowed);
        }
        if id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Ok(());
        }
        return Err(Refusal::InterfaceNotAllowed);
    }
    Err(Refusal::InterfaceNotAllowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TAG: u16 = 42;
    const GID: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x01];

    fn scope() -> ReservedScope {
        // Namespace "kennel" keeps the historical /sys/fs/cgroup/kennel/ and
        // kennel-<id> conventions, so the cgroup/interface tests are unchanged.
        ReservedScope::new(TAG, GID, "kennel")
    }

    /// Build a v4 loopback address: `127 | tag(12) | ctx(8) | host(4)`.
    fn v4(tag: u16, ctx: u16, host: u8) -> IpAddr {
        let suffix =
            u32::from(tag).wrapping_shl(12) | u32::from(ctx).wrapping_shl(4) | u32::from(host);
        IpAddr::V4(Ipv4Addr::from(0x7F00_0000 | suffix))
    }

    /// Build a v6 ULA address: `fd | gid(40) | ctx(16) | host(64)`.
    fn v6(gid: [u8; 5], ctx: u16, host_lo: u16) -> IpAddr {
        let [g0, g1, g2, g3, g4] = gid;
        let [c0, c1] = ctx.to_be_bytes();
        let [h0, h1] = host_lo.to_be_bytes();
        IpAddr::V6(Ipv6Addr::from([
            0xfd, g0, g1, g2, g3, g4, c0, c1, 0, 0, 0, 0, 0, 0, h0, h1,
        ]))
    }

    fn addr_req(ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> AddrRequest {
        AddrRequest {
            ctx,
            interface: interface.to_owned(),
            addr,
            prefix,
        }
    }

    // ---- validate_addr: success ----

    #[test]
    fn v4_in_scope_on_lo_is_ok() {
        assert!(validate_addr(&addr_req(5, "lo", v4(TAG, 5, 1), 28), &scope()).is_ok());
    }

    #[test]
    fn v4_in_scope_on_kennel_dummy_is_ok() {
        assert!(validate_addr(&addr_req(5, "kennel-ai", v4(TAG, 5, 1), 28), &scope()).is_ok());
    }

    #[test]
    fn v4_any_host_in_the_slash28_is_ok() {
        // host 15 is the top of the /28; still in the kennel's subnet.
        assert!(validate_addr(&addr_req(5, "lo", v4(TAG, 5, 15), 28), &scope()).is_ok());
    }

    #[test]
    fn v6_in_scope_is_ok() {
        assert!(validate_addr(&addr_req(5, "lo", v6(GID, 5, 1), 64), &scope()).is_ok());
    }

    #[test]
    fn v6_high_ctx_beyond_v4_range_is_ok() {
        // ctx 300 has no v4 address but is a valid 16-bit v6 context.
        assert!(validate_addr(&addr_req(300, "lo", v6(GID, 300, 1), 64), &scope()).is_ok());
    }

    // ---- validate_addr: prefix ----

    #[test]
    fn v4_wrong_prefix_is_refused() {
        assert_eq!(
            validate_addr(&addr_req(5, "lo", v4(TAG, 5, 1), 24), &scope()),
            Err(Refusal::BadPrefix { expected: 28, got: 24 })
        );
    }

    #[test]
    fn v6_wrong_prefix_is_refused() {
        assert_eq!(
            validate_addr(&addr_req(5, "lo", v6(GID, 5, 1), 128), &scope()),
            Err(Refusal::BadPrefix { expected: 64, got: 128 })
        );
    }

    // ---- validate_addr: out of scope ----

    #[test]
    fn v4_wrong_tag_is_out_of_scope() {
        assert_eq!(
            validate_addr(&addr_req(5, "lo", v4(99, 5, 1), 28), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v4_ctx_mismatch_is_out_of_scope() {
        // addr encodes ctx 6, request says ctx 5
        assert_eq!(
            validate_addr(&addr_req(5, "lo", v4(TAG, 6, 1), 28), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v4_high_ctx_has_no_v4_address() {
        // A v4-enabled kennel is capped at ctx 255; a request for ctx 300 cannot
        // match any v4 address (the 8-bit field tops out at 255).
        assert_eq!(
            validate_addr(&addr_req(300, "lo", v4(TAG, 44, 1), 28), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v4_non_loopback_is_out_of_scope() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 28), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn cloud_metadata_addr_is_out_of_scope() {
        // The headline threat: a hostile caller must not get 169.254.169.254 added.
        let a = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 28), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_wrong_gid_is_out_of_scope() {
        let IpAddr::V6(v6addr) = v6(GID, 5, 1) else { unreachable!() };
        let mut o = v6addr.octets();
        o[3] = 0xff; // corrupt a gid byte
        let a = IpAddr::V6(Ipv6Addr::from(o));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_ctx_mismatch_is_out_of_scope() {
        // ctx 6 in addr, request ctx 5
        assert_eq!(
            validate_addr(&addr_req(5, "lo", v6(GID, 6, 1), 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_non_ula_is_out_of_scope() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    // ---- validate_addr: interface ----

    #[test]
    fn arbitrary_interface_is_refused() {
        assert_eq!(
            validate_addr(&addr_req(5, "eth0", v4(TAG, 5, 1), 28), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn empty_kennel_interface_id_is_refused() {
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-", v4(TAG, 5, 1), 28), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn overlong_interface_is_refused() {
        // "kennel-" (7) + 9 chars = 16 > 15
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-toolongid", v4(TAG, 5, 1), 28), &scope()),
            Err(Refusal::InterfaceNameTooLong)
        );
    }

}
