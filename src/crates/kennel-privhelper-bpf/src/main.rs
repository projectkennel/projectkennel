//! `kennel-privhelper-bpf` — the host-mode egress sub-helper.
//!
//! Loads the per-kennel cgroup egress BPF programs against one shared map set,
//! populates the maps from the operator-supplied allow/deny ruleset, attaches each
//! program to the kennel's cgroup, and pins the maps so the unprivileged `kenneld`
//! can drain the audit ringbuf. This is the **only** construction step that needs
//! `CAP_BPF`, and it runs **only** for `net.mode = host` (the rare, `reason`-required
//! mode where there is no net-ns boundary and the cgroup BPF is the primary egress
//! gate) — so `CAP_BPF`, a verifier-bug LPE surface, never sits on the common factory.
//!
//! Invoked **only** by the main `kennel-privhelper`'s construct orchestration (never
//! by `kenneld` directly). It carries its own `cap_bpf,cap_net_admin` file caps, so
//! the orchestrator gains them across the `exec` without holding them.
//!
//! Gating (boundary 1, `04-trust-boundaries.md`): the caller must hold a
//! `/etc/kennel/subkennel` allocation, and the attach is performed only on a cgroup
//! the **caller owns** (the delegation boundary, `REFUSAL_CGROUP_NOT_OWNED`) — the fd
//! is opened once and `fstat`ed, so the ownership check and the attach use the same
//! inode (no TOCTOU).
//!
//! Usage: `kennel-privhelper-bpf attach <cgroup-path>` with the `EgressPayload` bytes
//! on stdin.

#![forbid(unsafe_code)]

use std::io::Read as _;
use std::process::ExitCode;

use kennel_privhelper::wire::{EgressPayload, Response, Status};

/// `ENOSYS` on Linux — a program was not embedded (built without `embed-programs`).
const ENOSYS: i32 = 38;

/// Refusal code for "the target cgroup directory is not owned by the caller"
/// (mirrors `kennel-privhelper`'s `exec::REFUSAL_CGROUP_NOT_OWNED`).
const REFUSAL_CGROUP_NOT_OWNED: u8 = 101;

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

fn main() -> ExitCode {
    // Scrub the inherited environment: privileged, takes no decision from the
    // environment; identity is the kernel-stamped real uid and trust comes from
    // root-owned config. `vars_os` is a snapshot, so removing during iteration is sound.
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }

    // Gate on the caller's subkennel allocation, exactly as every privileged op is
    // gated — an unallocated user performs nothing.
    if kennel_privhelper::alloc::load(kennel_lib_syscall::unistd::real_uid()).is_none() {
        eprintln!("kennel-privhelper-bpf: caller has no /etc/kennel/subkennel allocation");
        return ExitCode::from(1);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("attach") {
        eprintln!("usage: kennel-privhelper-bpf attach <cgroup-path>  (EgressPayload on stdin)");
        return ExitCode::from(2);
    }
    let Some(cgroup) = args.get(2) else {
        eprintln!("kennel-privhelper-bpf: attach needs a cgroup path");
        return ExitCode::from(2);
    };

    // The egress payload (the maps' allow/deny ruleset) arrives on stdin — too large
    // and binary for argv.
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        eprintln!("kennel-privhelper-bpf: could not read the egress payload from stdin");
        return ExitCode::from(2);
    }
    let payload = match EgressPayload::decode(&buf) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kennel-privhelper-bpf: egress payload decode: {e:?}");
            return ExitCode::from(2);
        }
    };

    let resp = attach_egress_programs(std::path::Path::new(cgroup), &payload);
    ExitCode::from(match resp.status {
        Status::Ok => 0,
        Status::Refused => 1,
        Status::Protocol => 2,
        Status::Internal => 3,
    })
}

/// Load every egress program against ONE shared map set, populate it from `payload`,
/// attach each program to the cgroup at `path`, then pin the shared maps for
/// inspection and the audit-ringbuf drain.
///
/// `BPF_PROG_ATTACH` outlives this process, so the programs stay attached after the
/// helper exits even though the program/map fds close on drop.
///
/// The caller must own the cgroup directory (the delegation boundary): the fd is
/// opened once and `fstat`ed, so the ownership check and the attach use the same inode
/// (no TOCTOU).
#[must_use]
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
    if owner != kennel_lib_syscall::unistd::real_uid() {
        return Response::refused(REFUSAL_CGROUP_NOT_OWNED);
    }
    let cgroup_fd = dir.as_fd();

    // One shared map set for the whole kennel: every program references the same maps
    // (so there is one `audit_ringbuf` to drain and one coherent set to pin).
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
        // `prog` drops here: its fd closes, but the cgroup keeps the attachment. The
        // shared `maps` stay open (owned by `maps`) for pinning below.
    }

    // Pin the shared maps so they outlive the helper and the unprivileged kenneld can
    // reopen the audit ringbuf to drain it. Best-effort: a pin failure degrades to "no
    // BPF audit drain / no map inspection" but never fails egress setup.
    pin_kennel_maps(&maps, &payload.pin_id);

    Response::ok()
}

/// Pin this kennel's shared BPF maps under `/run/user/<uid>/kennel/bpf/<pin_id>/`.
///
/// The pins keep the maps alive after the helper exits and reachable by the
/// unprivileged kenneld (which `BPF_OBJ_GET`s `audit_ringbuf` to drain). Kennel is a
/// per-user tool, so the pins live in the caller's own `$XDG_RUNTIME_DIR`
/// (`/run/user/<uid>/`, systemd-created `0700`); isolation is structural. The uid is
/// the helper's **real** uid, never the wire. All steps are best-effort.
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
/// and the unprivileged daemon agree without passing a path over the wire.
fn pin_root(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/kennel/bpf"))
}

/// Whether `id` is a safe single path component for a pin dir: the kennel-name grammar
/// `[a-z0-9][a-z0-9-]{0,63}` (so never `..`, never containing `/`).
fn valid_pin_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let first_ok = id
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Ensure a bpffs is mounted at `base` (idempotent) and owned by the caller, owner-only
/// `0700`. `base` lives inside the user's `0700` `/run/user/<uid>/`, so other users
/// cannot reach it regardless; the chown lets the unprivileged owner reopen the pins.
fn ensure_bpffs(base: &std::path::Path, caller_uid: u32) -> std::io::Result<()> {
    std::fs::create_dir_all(base)?;
    if !kennel_lib_syscall::mount::is_bpffs(base).unwrap_or(false) {
        kennel_lib_syscall::mount::mount_bpffs(base)?;
    }
    let _ = std::os::unix::fs::chown(base, Some(caller_uid), None);
    set_mode(base, 0o700)?;
    Ok(())
}

/// Remove a per-kennel pin dir and its pinned-map files (unlinking a pin detaches that
/// reference). Missing is success.
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
fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Build the `struct bind_subnet` (44 bytes) the `bind4`/`bind6` programs read, from
/// the kennel's own loopback addresses carried in `meta` plus the bind-port allowlist.
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
fn populate_maps(
    maps: &std::collections::BTreeMap<String, std::os::fd::OwnedFd>,
    payload: &EgressPayload,
) -> std::io::Result<()> {
    use kennel_lib_bpf::sys::BPF_ANY;

    let update = |name: &str, key: &[u8], value: &[u8]| -> std::io::Result<()> {
        kennel_lib_bpf::update_kennel_map(maps, name, key, value, BPF_ANY)
    };

    update("kennel_meta_map", &0u32.to_ne_bytes(), &payload.meta)?;
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
