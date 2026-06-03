//! Request dispatch: validate, then perform the one privileged operation.
//!
//! This is the privileged side of the trust boundary
//! (`docs/architecture/04-trust-boundaries.md`, boundary 1): every request is
//! validated against the reserved scope *before* any privileged syscall. The
//! privileged work routes through `kennel-syscall` (netlink for addresses) and
//! `std::fs` (cgroup directories); this crate stays `#![forbid(unsafe_code)]`.

use std::ffi::CString;

use crate::validate::{validate_addr, validate_gid_map, AddrRequest, Refusal, ReservedScope};
use crate::wire::{EgressPayload, GidMapPayload, Op, Request, Response};

/// Stable refusal codes carried on the wire (`Response::refusal`).
const fn refusal_code(r: &Refusal) -> u8 {
    match r {
        Refusal::BadPrefix { .. } => 1,
        Refusal::AddrOutOfScope => 2,
        Refusal::InterfaceNotAllowed => 3,
        Refusal::InterfaceNameTooLong => 4,
        Refusal::GidNotMember { .. } => 5,
        Refusal::EmptyGidMap => 6,
    }
}

/// A refusal code for "this helper has no configured reserved scope, so it
/// cannot service an address request". Distinct from the validation refusals.
pub const REFUSAL_NO_SCOPE: u8 = 100;

/// A refusal code for "the target cgroup directory is not owned by the caller".
///
/// Under the delegated-subtree model (`08-enforcement-architecture.md` §8.5),
/// kenneld creates kennel cgroups inside the user's systemd-delegated subtree,
/// so a legitimate kennel cgroup is owned by the caller's uid. This rejects
/// attaching BPF to another user's or a system cgroup.
pub const REFUSAL_CGROUP_NOT_OWNED: u8 = 101;

/// A refusal code for "the target process of a `gid_map` request is not owned by
/// the caller" — a user may only write the `gid_map` of its own process's userns.
pub const REFUSAL_PID_NOT_OWNED: u8 = 102;

/// `ENOSYS` on Linux — returned when a [`Op::SetupEgress`] request reaches a
/// helper built without the `bpf-egress` feature.
const ENOSYS: i32 = 38;

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Validate and perform `req`.
///
/// Every operation is confined to the caller's allocation (`scope`), so a user
/// with no allocation can do nothing. A [`Op::SetupEgress`] request additionally
/// carries an `egress` payload (the BPF map contents); the other ops ignore it.
/// Returns the [`Response`] to send back.
#[must_use]
pub fn perform(
    req: &Request,
    egress: Option<&EgressPayload>,
    gidmap: Option<&GidMapPayload>,
    scope: Option<&ReservedScope>,
) -> Response {
    let Some(scope) = scope else {
        return Response::refused(REFUSAL_NO_SCOPE);
    };
    match req.op {
        Op::AddAddr | Op::DelAddr => perform_addr(req, scope),
        // SetupEgress needs the variable payload; without it the request is malformed.
        // The scope still gates *whether* the caller may act (the None check above);
        // the cgroup itself is gated by directory ownership inside perform_egress.
        Op::SetupEgress => egress.map_or_else(Response::protocol, |payload| perform_egress(req, payload)),
        // SetGidMap likewise carries a variable payload. The scope gates *whether*
        // the caller may act; the gids are gated by membership and the pid by
        // ownership, inside perform_set_gid_map.
        Op::SetGidMap => gidmap.map_or_else(Response::protocol, perform_set_gid_map),
    }
}

/// Write a workload's user-namespace `gid_map` so it keeps specific supplementary
/// groups (§7.2.8). The security gates, in order:
///
/// 1. **Membership** — every gid must be one the caller already holds (its own gid
///    set, which the helper inherits from `kenneld` = the user). Mapping a gid the
///    user is not in would let the workload act as that group (the map is identity).
/// 2. **Ownership** — `/proc/<pid>` must be owned by the caller's real uid, so a
///    user can only write the `gid_map` of its own process's namespace.
///
/// Only then is the map written: one identity line (`<gid> <gid> 1`) per gid. The
/// helper holds `CAP_SETGID` in the parent (init) user namespace, which is what
/// lets it write a multi-gid map an unprivileged process could not.
fn perform_set_gid_map(payload: &GidMapPayload) -> Response {
    use std::fmt::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    // The caller's group set: real gid + supplementary groups. The helper is a
    // child of kenneld (the user), and setuid/file-caps leave the gid set untouched.
    let mut caller_groups = kennel_syscall::unistd::supplementary_groups();
    caller_groups.push(kennel_syscall::unistd::real_gid());
    if let Err(r) = validate_gid_map(&payload.gids, &caller_groups) {
        return Response::refused(refusal_code(&r));
    }

    // The target process must belong to the caller.
    let proc_dir = format!("/proc/{}", payload.pid);
    let owner = match std::fs::metadata(&proc_dir) {
        Ok(m) => m.uid(),
        Err(e) => return Response::internal(errno_of(&e)),
    };
    if owner != kennel_syscall::unistd::real_uid() {
        return Response::refused(REFUSAL_PID_NOT_OWNED);
    }

    // Identity-map each gid (`<gid> <gid> 1`). The kernel accepts multiple lines
    // because the helper has CAP_SETGID in the parent user namespace.
    let mut map = String::new();
    for g in &payload.gids {
        let _ = writeln!(map, "{g} {g} 1");
    }
    match std::fs::write(format!("{proc_dir}/gid_map"), map) {
        Ok(()) => Response::ok(),
        Err(e) => Response::internal(errno_of(&e)),
    }
}

/// Load, populate, and attach the egress BPF programs to the target cgroup.
///
/// The cross-user boundary is **directory ownership**: the caller must own the
/// cgroup directory (`attach_egress_programs` checks `st_uid`). The map contents
/// are not checked — they only shape the kennel's own egress, which the user
/// already controls.
fn perform_egress(req: &Request, payload: &EgressPayload) -> Response {
    attach_egress_programs(&req.cgroup_path, payload)
}

/// Load every egress program, populate its maps from `payload`, and attach it to
/// the cgroup at `path`. `BPF_PROG_ATTACH` outlives this process, so the
/// programs stay attached after the helper exits even though the program/map fds
/// close when each `Loaded` drops.
///
/// The caller must own the cgroup directory (the delegation boundary): the fd is
/// opened once and `fstat`ed, so the ownership check and the attach use the same
/// inode (no TOCTOU).
#[cfg(feature = "bpf-egress")]
fn attach_egress_programs(path: &std::path::Path, payload: &EgressPayload) -> Response {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let dir = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    let owner = match dir.metadata() {
        Ok(m) => m.uid(),
        Err(e) => return Response::internal(errno_of(&e)),
    };
    if owner != kennel_syscall::unistd::real_uid() {
        return Response::refused(REFUSAL_CGROUP_NOT_OWNED);
    }
    let cgroup_fd = dir.as_fd();

    for spec in kennel_bpf::KENNEL_PROGRAMS {
        let Some(elf) = kennel_bpf::programs::object(spec.name) else {
            // The binary was built without this program embedded — treat as unsupported.
            return Response::internal(ENOSYS);
        };
        let loaded = match kennel_bpf::load_program(elf, spec, kennel_bpf::KENNEL_MAPS) {
            Ok(l) => l,
            Err(e) => return Response::internal(errno_of(&e)),
        };
        if let Err(e) = populate_maps(&loaded, payload) {
            return Response::internal(errno_of(&e));
        }
        if let Err(e) = loaded.attach(cgroup_fd, spec.attach_type) {
            return Response::internal(errno_of(&e));
        }
        // `loaded` drops here: its fds close, but the cgroup keeps the attachment.
    }
    Response::ok()
}

/// Write `payload` into whichever of a loaded program's egress maps it declares.
#[cfg(feature = "bpf-egress")]
fn populate_maps(loaded: &kennel_bpf::Loaded, payload: &EgressPayload) -> std::io::Result<()> {
    use kennel_bpf::sys::BPF_ANY;

    if loaded.maps.contains_key("kennel_meta_map") {
        loaded.update_map("kennel_meta_map", &0u32.to_ne_bytes(), &payload.meta, BPF_ANY)?;
    }
    if loaded.maps.contains_key("allow_v4") {
        for (key, value) in &payload.allow_v4 {
            loaded.update_map("allow_v4", key, value, BPF_ANY)?;
        }
    }
    if loaded.maps.contains_key("deny_v4") {
        for (key, value) in &payload.deny_v4 {
            loaded.update_map("deny_v4", key, value, BPF_ANY)?;
        }
    }
    if loaded.maps.contains_key("allow_v6") {
        for (key, value) in &payload.allow_v6 {
            loaded.update_map("allow_v6", key, value, BPF_ANY)?;
        }
    }
    if loaded.maps.contains_key("deny_v6") {
        for (key, value) in &payload.deny_v6 {
            loaded.update_map("deny_v6", key, value, BPF_ANY)?;
        }
    }
    Ok(())
}

/// Built without egress support: the helper cannot honour `SetupEgress`.
#[cfg(not(feature = "bpf-egress"))]
const fn attach_egress_programs(_path: &std::path::Path, _payload: &EgressPayload) -> Response {
    Response::internal(ENOSYS)
}

fn perform_addr(req: &Request, scope: &ReservedScope) -> Response {
    let areq = AddrRequest {
        ctx: req.ctx,
        interface: req.interface.clone(),
        addr: req.addr,
        prefix: req.prefix,
    };
    if let Err(r) = validate_addr(&areq, scope) {
        return Response::refused(refusal_code(&r));
    }
    // Validation passed; resolve the interface and perform the netlink op.
    let Ok(cname) = CString::new(req.interface.clone()) else {
        return Response::protocol();
    };
    let ifindex = match kennel_syscall::netlink::if_index(&cname) {
        Ok(i) => i,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    let result = match req.op {
        Op::AddAddr => kennel_syscall::netlink::add_address(ifindex, req.addr, req.prefix),
        _ => kennel_syscall::netlink::del_address(ifindex, req.addr, req.prefix),
    };
    match result {
        Ok(()) => Response::ok(),
        Err(e) => Response::internal(errno_of(&e)),
    }
}

