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
//! - Address requests are confined to the per-kennel allocation, which is
//!   **v6-only**: `fd | KENNEL(16) | uid_subnet(24) | ctx(16) | host(64)` → a
//!   `/64` per kennel within the fixed Kennel ULA space `fd6b:6e00::/24`
//!   ([`crate::addr`]). The per-user 24-bit subnet is derived from the caller's
//!   **kernel-trusted real uid**, not an admin allocation, so the "add only your
//!   own subnet" capability holds with no `/etc` file; `ctx` is supplied by the
//!   request. The prefix length is fixed (64); anything else is refused. There is
//!   no IPv4 loopback addressing (a v4-only inbound service is an accepted
//!   non-goal, the same posture as UDP egress).
//! - The interface is `lo` or a dummy named `kennel-<id>` (each kennel's own
//!   net namespace isolates the name, so the prefix is fixed, not per-user),
//!   within the kernel's 15-character interface-name limit.
//!
//! cgroups are not validated here: kenneld creates and manages them unprivileged
//! within its systemd-delegated subtree, and the egress op gates its target
//! cgroup by **directory ownership** (`exec::attach_egress_programs`), not by a
//! namespace path.
//!
//! # Threat bearing
//!
//! Defends against T1.6 (lateral movement) and the cloud-metadata case in
//! particular: a request to add `169.254.169.254` is refused because it is not a
//! v6 address in the reserved ULA block. This module is pure and platform-
//! independent; it is exercised by the unit tests below on any host.

use std::net::IpAddr;

use crate::addr::{uid_subnet, KENNEL_ULA};

/// The kernel interface-name length limit (`IFNAMSIZ - 1`).
const IFNAME_MAX: usize = 15;

/// The fixed prefix length for a per-kennel IPv6 ULA subnet.
const V6_PREFIX: u8 = 64;

/// The fixed dummy-interface name prefix (each kennel's net namespace isolates
/// the name, so it need not be per-user).
const IFACE_PREFIX: &str = "kennel-";

/// The **per-user** reserved scope to validate against — the caller's real uid.
///
/// The ULA subnet and the resource namespace are *derived* from the uid; there is
/// no admin allocation file. The uid is the whole trust anchor, and both the
/// helper (validate) and `kenneld` (build) recompute the same subnet from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedScope {
    uid: u32,
}

impl ReservedScope {
    /// Construct a reserved scope from the caller's real uid.
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        Self { uid }
    }

    /// The caller's uid.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The resource namespace label (topology display) derived from the uid.
    #[must_use]
    pub fn namespace(&self) -> String {
        format!("kennel-{}", self.uid)
    }
}

/// A request to add or remove a per-kennel loopback address.
#[derive(Debug, Clone)]
pub struct AddrRequest {
    /// The per-kennel context assigned by `kenneld` (16-bit).
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
    /// The address is not within the per-kennel reserved subnet (or is not v6).
    AddrOutOfScope,
    /// The interface is neither `lo` nor a well-formed `kennel-<id>` name.
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
                    "address is outside Project Kennel's reserved per-kennel v6 subnet"
                )
            }
            Self::InterfaceNotAllowed => {
                write!(
                    f,
                    "interface must be `lo` or a `kennel-<id>` dummy interface"
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
/// Returns a [`Refusal`] if the address is not IPv6, the prefix length is not
/// 64, the address falls outside the caller's per-kennel
/// `fd6b:6e00:<uid_subnet>:<ctx>::/64`, or the interface name is not permitted.
pub fn validate_addr(req: &AddrRequest, scope: &ReservedScope) -> Result<(), Refusal> {
    validate_interface(&req.interface)?;
    let IpAddr::V6(v6) = req.addr else {
        // IPv4 loopback addressing was retired; only v6 ULA is in scope.
        return Err(Refusal::AddrOutOfScope);
    };
    if req.prefix != V6_PREFIX {
        return Err(Refusal::BadPrefix {
            expected: V6_PREFIX,
            got: req.prefix,
        });
    }
    // fd | KENNEL(16) | uid_subnet(24) | ctx(16) | host(64).
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = v6.octets();
    let addr_ctx = u16::from_be_bytes([b6, b7]);
    if b0 == 0xfd
        && [b1, b2] == KENNEL_ULA
        && [b3, b4, b5] == uid_subnet(scope.uid)
        && addr_ctx == req.ctx
    {
        Ok(())
    } else {
        Err(Refusal::AddrOutOfScope)
    }
}

/// Check that an interface name is `lo` or a well-formed `kennel-<id>` dummy.
fn validate_interface(interface: &str) -> Result<(), Refusal> {
    if interface == "lo" {
        return Ok(());
    }
    let Some(id) = interface.strip_prefix(IFACE_PREFIX) else {
        return Err(Refusal::InterfaceNotAllowed);
    };
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
        Ok(())
    } else {
        Err(Refusal::InterfaceNotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::loopback_v6;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const UID: u32 = 1000;

    fn scope() -> ReservedScope {
        ReservedScope::new(UID)
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
    fn v6_in_scope_on_lo_is_ok() {
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert!(validate_addr(&addr_req(5, "lo", a, 64), &scope()).is_ok());
    }

    #[test]
    fn v6_in_scope_on_kennel_dummy_is_ok() {
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert!(validate_addr(&addr_req(5, "kennel-ai", a, 64), &scope()).is_ok());
    }

    #[test]
    fn v6_high_ctx_is_ok() {
        let a = IpAddr::V6(loopback_v6(UID, 300, 1));
        assert!(validate_addr(&addr_req(300, "lo", a, 64), &scope()).is_ok());
    }

    // ---- validate_addr: prefix ----

    #[test]
    fn v6_wrong_prefix_is_refused() {
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 128), &scope()),
            Err(Refusal::BadPrefix {
                expected: 64,
                got: 128
            })
        );
    }

    // ---- validate_addr: out of scope ----

    #[test]
    fn a_foreign_uid_subnet_is_out_of_scope() {
        // An address built for uid 1001 must not validate against uid 1000.
        let a = IpAddr::V6(loopback_v6(1001, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_ctx_mismatch_is_out_of_scope() {
        let a = IpAddr::V6(loopback_v6(UID, 6, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
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

    #[test]
    fn any_v4_is_out_of_scope() {
        // IPv4 addressing was retired: no v4 address is ever in scope.
        let a = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn cloud_metadata_addr_is_out_of_scope() {
        // The headline threat: a hostile caller must not get 169.254.169.254 added.
        let a = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    // ---- validate_addr: interface ----

    #[test]
    fn arbitrary_interface_is_refused() {
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "eth0", a, 64), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn empty_kennel_interface_id_is_refused() {
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-", a, 64), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn overlong_interface_is_refused() {
        // "kennel-" (7) + 9 chars = 16 > 15
        let a = IpAddr::V6(loopback_v6(UID, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-toolongid", a, 64), &scope()),
            Err(Refusal::InterfaceNameTooLong)
        );
    }
}
