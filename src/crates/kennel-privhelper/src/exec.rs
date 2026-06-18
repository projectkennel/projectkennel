//! Request dispatch: validate, then perform the one privileged operation.
//!
//! This is the privileged side of the trust boundary
//! (`docs/architecture/04-trust-boundaries.md`, boundary 1): every request is
//! validated against the reserved scope *before* any privileged syscall. The
//! privileged work routes through `kennel-lib-syscall` (netlink for addresses) and
//! `std::fs` (cgroup directories); this crate stays `#![forbid(unsafe_code)]`.

use std::ffi::CString;

use crate::validate::{validate_addr, AddrRequest, Refusal, ReservedScope};
use crate::wire::{EgressPayload, Op, Request, Response};

/// Stable refusal codes carried on the wire (`Response::refusal`).
const fn refusal_code(r: &Refusal) -> u8 {
    match r {
        Refusal::BadPrefix { .. } => 1,
        Refusal::AddrOutOfScope => 2,
        Refusal::InterfaceNotAllowed => 3,
        Refusal::InterfaceNameTooLong => 4,
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
        REFUSAL_NO_SCOPE => "helper has no configured reserved scope for this user",
        REFUSAL_CGROUP_NOT_OWNED => "target cgroup is not owned by the caller",
        _ => "refused",
    }
}

/// `ENOSYS` on Linux — returned by [`attach_egress_programs`] when the egress-BPF attach
/// (folded into the factory's construct op) reaches a helper built without the `bpf-egress`
/// feature.
const ENOSYS: i32 = 38;

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Validate and perform `req` — the one remaining standalone op, `Op::DelAddr` (teardown).
///
/// (The address *add* and the egress-BPF *attach* are folded into the factory's
/// `construct_kennel` op — see `construct.rs`.) Confined to the caller's allocation (`scope`),
/// so a user with no allocation can do nothing. Returns the [`Response`] to send back.
#[must_use]
pub fn perform(req: &Request, scope: Option<&ReservedScope>) -> Response {
    let Some(scope) = scope else {
        return Response::refused(REFUSAL_NO_SCOPE);
    };
    match req.op {
        Op::DelAddr => perform_addr(req, scope),
    }
}

/// Load every egress program against ONE shared map set, populate it from
/// `payload`, attach each program to the cgroup at `path`, then pin the shared
/// maps for inspection and the audit-ringbuf drain.
///
/// `BPF_PROG_ATTACH` outlives this process, so the programs stay attached after
/// the helper exits even though the program/map fds close on drop. Pinning the
/// maps under `/run/user/<uid>/kennel/bpf/<id>/` keeps them alive (and reachable)
/// for the unprivileged kenneld to drain — see `pin_kennel_maps`.
///
/// The caller must own the cgroup directory (the delegation boundary): the fd is
/// opened once and `fstat`ed, so the ownership check and the attach use the same
/// inode (no TOCTOU).
#[cfg(feature = "bpf-egress")]
#[must_use]
pub fn attach_egress_programs(path: &std::path::Path, payload: &EgressPayload) -> Response {
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
    if owner != kennel_lib_syscall::unistd::real_uid() {
        return Response::refused(REFUSAL_CGROUP_NOT_OWNED);
    }
    let cgroup_fd = dir.as_fd();

    // One shared map set for the whole kennel: every program references the same
    // maps (so there is one `audit_ringbuf` to drain and one coherent set to pin).
    let maps = match kennel_lib_bpf::create_maps(kennel_lib_bpf::KENNEL_MAPS) {
        Ok(m) => m,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    if let Err(e) = populate_maps(&maps, payload) {
        return Response::internal(errno_of(&e));
    }

    for spec in kennel_lib_bpf::KENNEL_PROGRAMS {
        let Some(elf) = kennel_lib_bpf::programs::object(spec.name) else {
            // The binary was built without this program embedded — treat as unsupported.
            return Response::internal(ENOSYS);
        };
        let prog = match kennel_lib_bpf::load_program_against(elf, spec, &maps) {
            Ok(p) => p,
            Err(e) => return Response::internal(errno_of(&e)),
        };
        if let Err(e) =
            kennel_lib_bpf::sys::prog_attach_cgroup(cgroup_fd, prog.as_fd(), spec.attach_type)
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

/// Pin this kennel's shared BPF maps under `/run/user/<uid>/kennel/bpf/<pin_id>/`.
///
/// The pins keep the maps alive after the helper exits and reachable by the
/// unprivileged kenneld (which `BPF_OBJ_GET`s `audit_ringbuf` to drain, and which
/// the owning user inspects with `bpftool`).
///
/// Kennel is a **per-user** tool, so the pins live in the caller's own
/// `$XDG_RUNTIME_DIR` (`/run/user/<uid>/`, which systemd creates `0700`, owned by
/// the user). Isolation is therefore *structural* — the whole tree is already
/// unreachable by other users — rather than permission gymnastics in a shared
/// directory: no cross-user collision (the uid is in the path), no clobber (this
/// root helper only ever writes under the caller's own `/run/user/<uid>/`), and no
/// existence disclosure. The uid is the helper's **real** uid (it is setuid-root
/// but runs for the caller), never the wire. The bpffs, the per-kennel dir, and the
/// pins are all owner-only (`0700`/`0700`/`0600`, no OS group).
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
    let caller_uid = kennel_lib_syscall::unistd::real_uid();
    let base = pin_root(caller_uid);
    if ensure_bpffs(&base, caller_uid).is_err() {
        return;
    }
    let dir = base.join(pin_id);
    // Clear any stale pins from a prior kennel of the same name (this user's own).
    let _ = clear_pin_dir(&dir);
    if std::fs::create_dir(&dir).is_err() {
        return;
    }
    let _ = std::os::unix::fs::chown(&dir, Some(caller_uid), None);
    let _ = set_mode(&dir, 0o700);

    for (name, fd) in maps {
        let pin = dir.join(name);
        let Ok(cpin) = std::ffi::CString::new(pin.as_os_str().as_encoded_bytes()) else {
            continue;
        };
        if kennel_lib_bpf::sys::obj_pin(fd.as_fd(), &cpin).is_err() {
            continue;
        }
        let _ = std::os::unix::fs::chown(&pin, Some(caller_uid), None);
        let _ = set_mode(&pin, 0o600);
    }
}

/// The bpffs mount root for a user's BPF pins: `/run/user/<uid>/kennel/bpf`.
///
/// uid-derived (matching `kenneld::bpf_audit::pin_dir_for`) so the privileged helper
/// and the unprivileged daemon agree without passing a path over the wire. This is
/// `$XDG_RUNTIME_DIR/kennel/bpf` in the standard systemd case; we resolve it from
/// the uid rather than the (scrubbed, untrusted) environment.
#[cfg(feature = "bpf-egress")]
fn pin_root(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/kennel/bpf"))
}

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

/// Ensure a bpffs is mounted at `base` (idempotent) and owned by the caller,
/// owner-only `0700`. `base` lives inside the user's `0700` `/run/user/<uid>/`, so
/// other users cannot reach it regardless; the chown lets the unprivileged owner
/// reopen the pins and clean them up.
#[cfg(feature = "bpf-egress")]
fn ensure_bpffs(base: &std::path::Path, caller_uid: u32) -> std::io::Result<()> {
    std::fs::create_dir_all(base)?;
    if !kennel_lib_syscall::mount::is_bpffs(base).unwrap_or(false) {
        kennel_lib_syscall::mount::mount_bpffs(base)?;
    }
    // Hand the bpffs root to the owning user, owner-only. Enforced every time
    // (cheap, root-only) so it self-heals a stale owner/mode.
    let _ = std::os::unix::fs::chown(base, Some(caller_uid), None);
    set_mode(base, 0o700)?;
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

/// Write `payload` into the shared egress map set (from `kennel_lib_bpf::create_maps`).
#[cfg(feature = "bpf-egress")]
fn populate_maps(
    maps: &std::collections::BTreeMap<String, std::os::fd::OwnedFd>,
    payload: &EgressPayload,
) -> std::io::Result<()> {
    use kennel_lib_bpf::sys::BPF_ANY;

    // The safe `update_kennel_map` validates each (key, value) against the named map's
    // KENNEL_MAPS geometry and does the unsafe `map_update` internally — so this
    // `#![forbid(unsafe_code)]` crate needs no unsafe block of its own.
    let update = |name: &str, key: &[u8], value: &[u8]| -> std::io::Result<()> {
        kennel_lib_bpf::update_kennel_map(maps, name, key, value, BPF_ANY)
    };

    update("kennel_meta_map", &0u32.to_ne_bytes(), &payload.meta)?;
    // Per-kennel bind subnet (§7.5): the INADDR_ANY/in6addr_any rewrite target
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
    // The inbound BIND ACL (§7.5.7): the bind4/bind6 programs gate every bind deny-first
    // against these dedicated maps. Default-deny — an empty allow set denies every bind.
    for (key, value) in &payload.bind_allow_v4 {
        update("bind_allow_v4", key, value)?;
    }
    for (key, value) in &payload.bind_deny_v4 {
        update("bind_deny_v4", key, value)?;
    }
    for (key, value) in &payload.bind_allow_v6 {
        update("bind_allow_v6", key, value)?;
    }
    for (key, value) in &payload.bind_deny_v6 {
        update("bind_deny_v6", key, value)?;
    }
    Ok(())
}

/// Built without egress support: the factory cannot attach the egress BPF.
#[cfg(not(feature = "bpf-egress"))]
#[must_use]
pub const fn attach_egress_programs(_path: &std::path::Path, _payload: &EgressPayload) -> Response {
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
    let ifindex = match kennel_lib_syscall::netlink::if_index(&cname) {
        Ok(i) => i,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    // The only standalone address op is the teardown delete; the add is folded into construct.
    match kennel_lib_syscall::netlink::del_address(ifindex, req.addr, req.prefix) {
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
