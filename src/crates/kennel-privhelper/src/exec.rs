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

/// A short, stable description of a wire refusal code.
///
/// For the `message` field of a `priv.refuse` audit event (`02-3`). Mirrors the
/// `refusal_code` table and the scope/ownership constants so the audit and the
/// helper share one source of truth; an unrecognised code (a future helper
/// version) maps to `"refused"`.
#[must_use]
pub const fn refusal_message(code: u8) -> &'static str {
    match code {
        1 => "prefix length is wrong for the address family",
        2 => "address is outside the reserved per-kennel subnet",
        3 => "interface is not `lo` or a `<namespace>-<id>` dummy",
        4 => "interface name exceeds the kernel length limit",
        5 => "caller is not a member of a requested gid",
        6 => "gid_map request carried no gids",
        REFUSAL_NO_SCOPE => "helper has no configured reserved scope for this user",
        REFUSAL_CGROUP_NOT_OWNED => "target cgroup is not owned by the caller",
        REFUSAL_PID_NOT_OWNED => "target process is not owned by the caller",
        _ => "refused",
    }
}

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
        Op::SetupEgress => {
            egress.map_or_else(Response::protocol, |payload| perform_egress(req, payload))
        }
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

/// Load every egress program against ONE shared map set, populate it from
/// `payload`, attach each program to the cgroup at `path`, then pin the shared
/// maps for inspection and the audit-ringbuf drain.
///
/// `BPF_PROG_ATTACH` outlives this process, so the programs stay attached after
/// the helper exits even though the program/map fds close on drop. Pinning the
/// maps under `/run/kennel/bpf/<id>/` keeps them alive (and reachable) for the
/// unprivileged kenneld to drain — see [`pin_kennel_maps`].
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

    // One shared map set for the whole kennel: every program references the same
    // maps (so there is one `audit_ringbuf` to drain and one coherent set to pin).
    let maps = match kennel_bpf::create_maps(kennel_bpf::KENNEL_MAPS) {
        Ok(m) => m,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    if let Err(e) = populate_maps(&maps, payload) {
        return Response::internal(errno_of(&e));
    }

    for spec in kennel_bpf::KENNEL_PROGRAMS {
        let Some(elf) = kennel_bpf::programs::object(spec.name) else {
            // The binary was built without this program embedded — treat as unsupported.
            return Response::internal(ENOSYS);
        };
        let prog = match kennel_bpf::load_program_against(elf, spec, &maps) {
            Ok(p) => p,
            Err(e) => return Response::internal(errno_of(&e)),
        };
        if let Err(e) =
            kennel_bpf::sys::prog_attach_cgroup(cgroup_fd, prog.as_fd(), spec.attach_type)
        {
            return Response::internal(errno_of(&e));
        }
        // `prog` drops here: its fd closes, but the cgroup keeps the attachment.
        // The shared `maps` stay open (owned by `maps`) for pinning below.
    }

    // Pin the shared maps so they outlive the helper and the unprivileged kenneld
    // can reopen the audit ringbuf to drain it. Best-effort: a pin failure degrades
    // to "no BPF audit drain / no map inspection" but never fails egress setup, which
    // is already in force (the programs are attached).
    pin_kennel_maps(&maps, &payload.pin_id);

    Response::ok()
}

/// Pin this kennel's shared BPF maps under `/run/kennel/bpf/<pin_id>/`.
///
/// The pins keep the maps alive after the helper exits and reachable by the
/// unprivileged kenneld (which `BPF_OBJ_GET`s `audit_ringbuf` to drain, and which
/// the owning user inspects with `bpftool`). Kennel is a **per-user** tool: the
/// pin dir and pins are chowned to the **caller** and made owner-only (dir `0700`,
/// pins `0600`) — no shared OS group. Other users cannot read them, and the shared
/// bpffs root is mode `0711` (traverse-only), so they cannot even enumerate another
/// user's kennels.
///
/// All steps are best-effort: any failure simply leaves the drain/inspection
/// unavailable for this kennel; egress enforcement is unaffected. `pin_id` empty
/// (an older kenneld, or pinning disabled) skips pinning entirely.
#[cfg(feature = "bpf-egress")]
fn pin_kennel_maps(maps: &std::collections::BTreeMap<String, std::os::fd::OwnedFd>, pin_id: &str) {
    use std::os::fd::AsFd as _;

    if pin_id.is_empty() || !valid_pin_id(pin_id) {
        return;
    }
    let base = std::path::Path::new(PIN_ROOT);
    if ensure_bpffs(base).is_err() {
        return;
    }
    let dir = base.join(pin_id);
    // Clear any stale pins from a prior kennel of the same id before re-pinning.
    let _ = clear_pin_dir(&dir);
    if std::fs::create_dir(&dir).is_err() {
        return;
    }
    // Owner-only, owned by the caller (the user kenneld runs as): chown the uid and
    // leave the group untouched — there is no kennel-wide OS group by design.
    let caller_uid = kennel_syscall::unistd::real_uid();
    let _ = std::os::unix::fs::chown(&dir, Some(caller_uid), None);
    let _ = set_mode(&dir, 0o700);

    for (name, fd) in maps {
        let pin = dir.join(name);
        let Ok(cpin) = std::ffi::CString::new(pin.as_os_str().as_encoded_bytes()) else {
            continue;
        };
        if kennel_bpf::sys::obj_pin(fd.as_fd(), &cpin).is_err() {
            continue;
        }
        let _ = std::os::unix::fs::chown(&pin, Some(caller_uid), None);
        let _ = set_mode(&pin, 0o600);
    }
}

/// The bpffs mount root for per-kennel BPF pins (`07-paths.md`). One bpffs serves
/// all kennels; per-kennel pins live in `<PIN_ROOT>/<id>/`.
#[cfg(feature = "bpf-egress")]
const PIN_ROOT: &str = "/run/kennel/bpf";

/// Whether `id` is a safe single path component for a pin dir: the kennel-name
/// grammar `[a-z0-9][a-z0-9-]{0,63}` (so never `..`, never containing `/`).
#[cfg(feature = "bpf-egress")]
fn valid_pin_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let mut chars = id.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Ensure a bpffs is mounted at `base` (idempotent), mode `0711` — traverse-only,
/// so the unprivileged kenneld of any user can reach *its own* per-kennel pin dir
/// but no user can list (and thereby discover) another user's kennels.
#[cfg(feature = "bpf-egress")]
fn ensure_bpffs(base: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(base)?;
    if !kennel_syscall::mount::is_bpffs(base).unwrap_or(false) {
        kennel_syscall::mount::mount_bpffs(base)?;
    }
    // Enforce traverse-only every time (cheap, root-only): self-heals a stale mode
    // and keeps one user from listing another's pin dirs.
    set_mode(base, 0o711)?;
    Ok(())
}

/// Remove a per-kennel pin dir and its pinned-map files (unlinking a pin detaches
/// that reference). Missing is success.
#[cfg(feature = "bpf-egress")]
fn clear_pin_dir(dir: &std::path::Path) -> std::io::Result<()> {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
            std::fs::remove_dir(dir)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Set `path`'s permission bits to `mode` (octal).
#[cfg(feature = "bpf-egress")]
fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Build the `struct bind_subnet` (44 bytes) the `bind4`/`bind6` programs read, from
/// the kennel's own loopback addresses carried in `meta` (the `kennel_meta` layout:
/// `proxy_addr_v4` at offset 8, `proxy_addr_v6` at 16) plus the bind-port allowlist.
/// The prefixes are the per-kennel allocation widths (v4 `/28`, v6 `/64`). Layout
/// matches `struct bind_subnet` in `bpf/maps.h`: addrs/prefixes, then `n_ports` (u8 at
/// offset 25) and `allowed_ports[8]` (host-order u16 at offset 26). At most 8 ports
/// are written. Returns `None` only if the meta is too short (never, for a well-formed
/// payload).
#[cfg(feature = "bpf-egress")]
fn bind_subnet_value(meta: &[u8], allowed_ports: &[u16]) -> Option<[u8; 44]> {
    let v4_addr = meta.get(8..12)?;
    let v6_addr = meta.get(16..32)?;
    let mut value = [0u8; 44];
    value.get_mut(0..4)?.copy_from_slice(v4_addr);
    value.get_mut(4..8)?.copy_from_slice(&28u32.to_ne_bytes());
    value.get_mut(8..24)?.copy_from_slice(v6_addr);
    *value.get_mut(24)? = 64;
    let n = allowed_ports.len().min(8);
    *value.get_mut(25)? = u8::try_from(n).unwrap_or(0);
    for (i, port) in allowed_ports.iter().take(8).enumerate() {
        let off = 26usize.checked_add(i.checked_mul(2)?)?;
        let end = off.checked_add(2)?;
        value
            .get_mut(off..end)?
            .copy_from_slice(&port.to_ne_bytes());
    }
    Some(value)
}

/// Write `payload` into the shared egress map set (from `kennel_bpf::create_maps`).
#[cfg(feature = "bpf-egress")]
fn populate_maps(
    maps: &std::collections::BTreeMap<String, std::os::fd::OwnedFd>,
    payload: &EgressPayload,
) -> std::io::Result<()> {
    use kennel_bpf::sys::{map_update, BPF_ANY};
    use std::os::fd::AsFd as _;

    let update = |name: &str, key: &[u8], value: &[u8]| -> std::io::Result<()> {
        if let Some(fd) = maps.get(name) {
            map_update(fd.as_fd(), key, value, BPF_ANY)?;
        }
        Ok(())
    };

    update("kennel_meta_map", &0u32.to_ne_bytes(), &payload.meta)?;
    // Per-kennel bind subnet (§7.3): the INADDR_ANY/in6addr_any rewrite target
    // for dev-server binds. The bind4/bind6 programs fail closed without it, so
    // a workload inside the kennel cannot bind a listening socket. The kennel's
    // own loopback addresses are already in the meta, so it derives from there.
    if let Some(value) = bind_subnet_value(&payload.meta, &payload.bind_allowed_ports) {
        update("bind_subnet_map", &0u32.to_ne_bytes(), &value)?;
    }
    for (key, value) in &payload.allow_v4 {
        update("allow_v4", key, value)?;
    }
    for (key, value) in &payload.deny_v4 {
        update("deny_v4", key, value)?;
    }
    for (key, value) in &payload.allow_v6 {
        update("allow_v6", key, value)?;
    }
    for (key, value) in &payload.deny_v6 {
        update("deny_v6", key, value)?;
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

#[cfg(all(test, feature = "bpf-egress"))]
mod tests {
    use super::bind_subnet_value;

    #[test]
    fn bind_subnet_is_derived_from_the_meta_loopback_addresses() {
        // kennel_meta layout: proxy_addr_v4 @8..12 (net order), proxy_addr_v6 @16..32.
        let mut meta = [0u8; 64];
        meta.get_mut(8..12)
            .expect("v4 range")
            .copy_from_slice(&[127, 42, 7, 1]);
        meta.get_mut(16..32)
            .expect("v6 range")
            .copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 0, 0, 0, 1]);

        let v = bind_subnet_value(&meta, &[8080, 9090]).expect("meta long enough");
        assert_eq!(v.get(0..4), Some(&[127u8, 42, 7, 1][..]), "v4_addr");
        assert_eq!(v.get(4..8), Some(&28u32.to_ne_bytes()[..]), "v4_prefix /28");
        assert_eq!(v.get(8..24), meta.get(16..32), "v6_addr");
        assert_eq!(v.get(24), Some(&64u8), "v6_prefix /64");
        assert_eq!(v.get(25), Some(&2u8), "n_ports");
        assert_eq!(
            v.get(26..28),
            Some(&8080u16.to_ne_bytes()[..]),
            "allowed_ports[0]"
        );
        assert_eq!(
            v.get(28..30),
            Some(&9090u16.to_ne_bytes()[..]),
            "allowed_ports[1]"
        );
    }
}
