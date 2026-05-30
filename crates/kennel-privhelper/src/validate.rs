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
//! - Address requests are confined to the per-kennel allocation: IPv4
//!   `127.<tag>.<ctx>.0/24` and IPv6 `fd<gid>:<tag>:<ctx>::/64`, where `<tag>`
//!   and `<gid>` are installation constants and `<ctx>` is supplied by the
//!   request. The prefix length is fixed (24 / 64); anything else is refused.
//! - The interface is `lo` or a per-kennel dummy named `kennel-<id>`, within
//!   the kernel's 15-character interface-name limit.
//! - cgroup paths are absolute, free of `..` traversal, and strictly under
//!   `/sys/fs/cgroup/kennel/`. The check is path-component aware, not a string
//!   prefix, so `/sys/fs/cgroup/kennel-evil/...` is refused.
//!
//! # Threat bearing
//!
//! Defends against T6 (lateral movement) and the cloud-metadata case in
//! particular: a request to add `169.254.169.254` is refused because it is not
//! in the reserved loopback block. This module is pure and platform-
//! independent; it is exercised by the unit tests below on any host.

use std::net::IpAddr;
use std::path::{Component, Path};

/// The cgroup hierarchy root that the helper is permitted to manage. A valid
/// cgroup request names a path strictly beneath this.
const CGROUP_PREFIX: [&str; 4] = ["sys", "fs", "cgroup", "kennel"];

/// The kernel interface-name length limit (`IFNAMSIZ - 1`).
const IFNAME_MAX: usize = 15;

/// The fixed prefix length for a per-kennel IPv4 loopback subnet.
const V4_PREFIX: u8 = 24;

/// The fixed prefix length for a per-kennel IPv6 ULA subnet.
const V6_PREFIX: u8 = 64;

/// The installation-constant reserved address scope to validate against.
///
/// `tag` is the per-installation byte; `ula_gid` is the 40-bit ULA global ID.
/// The full IPv6 ULA prefix is `0xfd` followed by `ula_gid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedScope {
    tag: u8,
    ula_gid: [u8; 5],
}

impl ReservedScope {
    /// Construct a reserved scope from the installation's tag byte and 40-bit
    /// ULA global ID.
    #[must_use]
    pub const fn new(tag: u8, ula_gid: [u8; 5]) -> Self {
        Self { tag, ula_gid }
    }
}

/// A request to add or remove a per-kennel loopback address.
#[derive(Debug, Clone)]
pub struct AddrRequest {
    /// The per-kennel context byte assigned by `kenneld`.
    pub ctx: u8,
    /// The interface to operate on (`lo` or `kennel-<id>`).
    pub interface: String,
    /// The address to add or remove.
    pub addr: IpAddr,
    /// The subnet prefix length.
    pub prefix: u8,
}

/// A request to create or delete a per-kennel cgroup.
#[derive(Debug, Clone)]
pub struct CgroupRequest {
    /// The cgroup path to operate on.
    pub path: std::path::PathBuf,
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
    /// The interface is neither `lo` nor a well-formed `kennel-<id>` name.
    InterfaceNotAllowed,
    /// The interface name exceeds the kernel's 15-character limit.
    InterfaceNameTooLong,
    /// The cgroup path is not absolute.
    CgroupPathNotAbsolute,
    /// The cgroup path contains a `..` traversal component.
    CgroupPathTraversal,
    /// The cgroup path is not strictly beneath `/sys/fs/cgroup/kennel/`.
    CgroupPathOutsidePrefix,
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
                    "interface must be `lo` or a `kennel-<id>` dummy interface"
                )
            }
            Self::InterfaceNameTooLong => {
                write!(
                    f,
                    "interface name exceeds the {IFNAME_MAX}-character kernel limit"
                )
            }
            Self::CgroupPathNotAbsolute => write!(f, "cgroup path must be absolute"),
            Self::CgroupPathTraversal => {
                write!(f, "cgroup path must not contain `..` components")
            }
            Self::CgroupPathOutsidePrefix => {
                write!(
                    f,
                    "cgroup path must be strictly beneath /sys/fs/cgroup/kennel/"
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
    validate_interface(&req.interface)?;
    match req.addr {
        IpAddr::V4(v4) => {
            if req.prefix != V4_PREFIX {
                return Err(Refusal::BadPrefix {
                    expected: V4_PREFIX,
                    got: req.prefix,
                });
            }
            // Per-kennel subnet 127.<tag>.<ctx>.0/24; the host octet is free.
            let [a, b, c, _host] = v4.octets();
            if a == 127 && b == scope.tag && c == req.ctx {
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
            // Per-kennel /64: 0xfd | gid(40) | tag(8) | ctx(8) | host(64).
            let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = v6.octets();
            if b0 == 0xfd
                && [b1, b2, b3, b4, b5] == scope.ula_gid
                && b6 == scope.tag
                && b7 == req.ctx
            {
                Ok(())
            } else {
                Err(Refusal::AddrOutOfScope)
            }
        }
    }
}

/// Validate a cgroup request: absolute, traversal-free, strictly beneath
/// `/sys/fs/cgroup/kennel/`.
///
/// # Errors
///
/// Returns a [`Refusal`] if the path is relative, contains a `..` component,
/// or does not name a location strictly beneath the kennel cgroup root.
pub fn validate_cgroup(req: &CgroupRequest) -> Result<(), Refusal> {
    cgroup_path_ok(&req.path)
}

/// Check that an interface name is `lo` or a well-formed `kennel-<id>` dummy.
fn validate_interface(interface: &str) -> Result<(), Refusal> {
    if interface == "lo" {
        return Ok(());
    }
    if let Some(id) = interface.strip_prefix("kennel-") {
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

/// Check that a path's components begin exactly with the cgroup prefix and
/// name at least one location beneath it. Component-aware, not string-prefix,
/// so `/sys/fs/cgroup/kennel-evil/...` is refused.
fn cgroup_path_ok(path: &Path) -> Result<(), Refusal> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(Refusal::CgroupPathNotAbsolute);
    }
    let mut normals: Vec<&str> = Vec::new();
    for component in components {
        match component {
            Component::ParentDir => return Err(Refusal::CgroupPathTraversal),
            Component::CurDir => {}
            Component::Normal(part) => match part.to_str() {
                Some(part) => normals.push(part),
                // Non-UTF-8 cannot match our ASCII prefix; out of scope.
                None => return Err(Refusal::CgroupPathOutsidePrefix),
            },
            // A second root or a Windows prefix mid-path is not ours.
            Component::RootDir | Component::Prefix(_) => {
                return Err(Refusal::CgroupPathOutsidePrefix);
            }
        }
    }
    let begins_with_prefix = normals
        .iter()
        .take(CGROUP_PREFIX.len())
        .eq(CGROUP_PREFIX.iter());
    if normals.len() > CGROUP_PREFIX.len() && begins_with_prefix {
        Ok(())
    } else {
        Err(Refusal::CgroupPathOutsidePrefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    // tag = 42, gid = 00:00:00:00:01 → ULA prefix fd00:0000:0001 ... ; the
    // per-kennel /64 base is fd00:0:1:<tag><ctx>:: with tag=0x2a.
    const TAG: u8 = 42;
    const GID: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x01];

    fn scope() -> ReservedScope {
        ReservedScope::new(TAG, GID)
    }

    fn v6_in_scope(ctx: u8, host_low: u16) -> Ipv6Addr {
        // [0xfd, gid(5), tag, ctx, 0,0,0,0,0,0, host_hi, host_lo]
        let h = host_low.to_be_bytes();
        Ipv6Addr::from([
            0xfd, GID[0], GID[1], GID[2], GID[3], GID[4], TAG, ctx, 0, 0, 0, 0, 0, 0, h[0], h[1],
        ])
    }

    fn addr_req(ctx: u8, interface: &str, addr: IpAddr, prefix: u8) -> AddrRequest {
        AddrRequest {
            ctx,
            interface: interface.to_owned(),
            addr,
            prefix,
        }
    }

    fn cg(path: &str) -> CgroupRequest {
        CgroupRequest {
            path: PathBuf::from(path),
        }
    }

    // ---- validate_addr: success ----

    #[test]
    fn v4_in_scope_on_lo_is_ok() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        assert!(validate_addr(&addr_req(5, "lo", a, 24), &scope()).is_ok());
    }

    #[test]
    fn v4_in_scope_on_kennel_dummy_is_ok() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        assert!(validate_addr(&addr_req(5, "kennel-ai", a, 24), &scope()).is_ok());
    }

    #[test]
    fn v4_any_host_in_the_slash24_is_ok() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 200));
        assert!(validate_addr(&addr_req(5, "lo", a, 24), &scope()).is_ok());
    }

    #[test]
    fn v6_in_scope_is_ok() {
        let a = IpAddr::V6(v6_in_scope(5, 1));
        assert!(validate_addr(&addr_req(5, "lo", a, 64), &scope()).is_ok());
    }

    // ---- validate_addr: prefix ----

    #[test]
    fn v4_wrong_prefix_is_refused() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 25), &scope()),
            Err(Refusal::BadPrefix {
                expected: 24,
                got: 25
            })
        );
    }

    #[test]
    fn v6_wrong_prefix_is_refused() {
        let a = IpAddr::V6(v6_in_scope(5, 1));
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
    fn v4_wrong_tag_is_out_of_scope() {
        let a = IpAddr::V4(Ipv4Addr::new(127, 99, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 24), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v4_ctx_mismatch_is_out_of_scope() {
        // addr says ctx 6, request says ctx 5
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 6, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 24), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v4_non_loopback_is_out_of_scope() {
        let a = IpAddr::V4(Ipv4Addr::new(10, TAG, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 24), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn cloud_metadata_addr_is_out_of_scope() {
        // The headline threat: a hostile caller must not get 169.254.169.254 added.
        let a = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 24), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_wrong_gid_is_out_of_scope() {
        let mut o = v6_in_scope(5, 1).octets();
        o[3] = 0xff; // corrupt a gid byte
        let a = IpAddr::V6(Ipv6Addr::from(o));
        assert_eq!(
            validate_addr(&addr_req(5, "lo", a, 64), &scope()),
            Err(Refusal::AddrOutOfScope)
        );
    }

    #[test]
    fn v6_ctx_mismatch_is_out_of_scope() {
        let a = IpAddr::V6(v6_in_scope(6, 1)); // ctx 6 in addr, request ctx 5
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

    // ---- validate_addr: interface ----

    #[test]
    fn arbitrary_interface_is_refused() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "eth0", a, 24), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn empty_kennel_interface_id_is_refused() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-", a, 24), &scope()),
            Err(Refusal::InterfaceNotAllowed)
        );
    }

    #[test]
    fn overlong_interface_is_refused() {
        let a = IpAddr::V4(Ipv4Addr::new(127, TAG, 5, 1));
        // "kennel-" (7) + 9 chars = 16 > 15
        assert_eq!(
            validate_addr(&addr_req(5, "kennel-toolongid", a, 24), &scope()),
            Err(Refusal::InterfaceNameTooLong)
        );
    }

    // ---- validate_cgroup: success ----

    #[test]
    fn cgroup_under_prefix_is_ok() {
        assert!(validate_cgroup(&cg("/sys/fs/cgroup/kennel/ai-coding")).is_ok());
    }

    #[test]
    fn nested_cgroup_is_ok() {
        assert!(validate_cgroup(&cg("/sys/fs/cgroup/kennel/ai-coding/npm")).is_ok());
    }

    // ---- validate_cgroup: refusals ----

    #[test]
    fn relative_cgroup_is_refused() {
        assert_eq!(
            validate_cgroup(&cg("sys/fs/cgroup/kennel/x")),
            Err(Refusal::CgroupPathNotAbsolute)
        );
    }

    #[test]
    fn cgroup_outside_prefix_is_refused() {
        assert_eq!(
            validate_cgroup(&cg("/etc/passwd")),
            Err(Refusal::CgroupPathOutsidePrefix)
        );
    }

    #[test]
    fn cgroup_prefix_confusion_is_refused() {
        // String-prefix bug bait: starts with the prefix string but is a
        // different directory.
        assert_eq!(
            validate_cgroup(&cg("/sys/fs/cgroup/kennel-evil/x")),
            Err(Refusal::CgroupPathOutsidePrefix)
        );
    }

    #[test]
    fn bare_prefix_with_no_child_is_refused() {
        assert_eq!(
            validate_cgroup(&cg("/sys/fs/cgroup/kennel")),
            Err(Refusal::CgroupPathOutsidePrefix)
        );
    }

    #[test]
    fn cgroup_traversal_is_refused() {
        assert_eq!(
            validate_cgroup(&cg("/sys/fs/cgroup/kennel/../../../etc")),
            Err(Refusal::CgroupPathTraversal)
        );
    }
}
