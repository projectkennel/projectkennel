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
//! The pins land in the per-user bpffs at [`kennel_privhelper::bpf_pin_root`]. This helper
//! does **not** mount that bpffs — the mount is the one egress step that needs `CAP_SYS_ADMIN`,
//! which the factory holds and this sub-helper does not; the factory mounts it before delegating,
//! and this helper pins into it (`CAP_BPF`). If it is absent, pinning is skipped (no audit drain).
//!
//! Invoked **only** by the main `kennel-privhelper`'s construct orchestration (never
//! by `kenneld` directly). It carries its own `cap_bpf,cap_net_admin,cap_perfmon` file caps, so
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
    // Seal the write-once meta map (02-7-bpf-abi.md): BPF_F_RDONLY_PROG (set at creation)
    // prevents BPF-program writes; BPF_MAP_FREEZE prevents userspace writes. Frozen after
    // populate (which writes it once) and before the programs attach.
    if let Err(e) = kennel_lib_bpf::freeze_maps(&maps, &["kennel_meta_map"]) {
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
    let base = kennel_privhelper::bpf_pin_root(caller_uid);
    // The bpffs is mounted by the factory (it holds `CAP_SYS_ADMIN`; this sub-helper does not).
    // Without it there is nowhere to pin — degrade to "no audit drain".
    if !kennel_lib_syscall::mount::is_bpffs(&base).unwrap_or(false) {
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

#[cfg(all(test, feature = "e2e"))]
mod tests {
    use super::{attach_egress_programs, REFUSAL_CGROUP_NOT_OWNED};
    use kennel_privhelper::wire::{EgressPayload, Status, V4Entry, META_LEN};

    /// Skip a root-only test with cause on an unprivileged runner (a skip is not a proof), so
    /// `cargo test --all-features` is green for any runner while `sudo … --features e2e` runs it.
    fn skip_if_unprivileged(test: &str) -> bool {
        let euid = kennel_lib_syscall::unistd::effective_uid();
        if euid != 0 {
            eprintln!("skipping {test}: requires root (euid={euid}) for the egress attach");
            return true;
        }
        false
    }

    /// An `allow_v4` entry matching any port/protocol for `addr/32`.
    const fn allow_v4_any(addr: [u8; 4]) -> V4Entry {
        let [a, b, c, d] = addr;
        let [p0, p1, p2, p3] = 32u32.to_ne_bytes(); // prefixlen
        let key = [p0, p1, p2, p3, a, b, c, d];
        let [lo0, lo1] = 0u16.to_ne_bytes();
        let [hi0, hi1] = u16::MAX.to_ne_bytes();
        let value = [lo0, lo1, hi0, hi1, 0, 0, 0, 0];
        (key, value)
    }

    /// An `EgressPayload` with the given `pin_id` and `allow_v4` set, everything else empty.
    fn payload(pin_id: &str, allow_v4: Vec<V4Entry>) -> EgressPayload {
        EgressPayload {
            meta: [0u8; META_LEN],
            allow_v4,
            deny_v4: Vec::new(),
            allow_v6: Vec::new(),
            deny_v6: Vec::new(),
            bind_allow_v4: Vec::new(),
            bind_deny_v4: Vec::new(),
            bind_allow_v6: Vec::new(),
            bind_deny_v6: Vec::new(),
            bind_allowed_ports: Vec::new(),
            pin_id: pin_id.to_owned(),
        }
    }

    #[test]
    fn loads_and_attaches_egress_to_an_owned_cgroup() {
        if skip_if_unprivileged("loads_and_attaches_egress_to_an_owned_cgroup") {
            return;
        }
        // Delegated-subtree flow: the caller (here, root) creates the cgroup, so it owns it.
        let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-egress-test");
        let _ = std::fs::remove_dir(&cgroup);
        std::fs::create_dir(&cgroup).expect("create cgroup");
        let resp =
            attach_egress_programs(&cgroup, &payload("", vec![allow_v4_any([127, 0, 0, 1])]));
        assert_eq!(
            resp.status,
            Status::Ok,
            "egress setup should load+attach all programs (errno {})",
            resp.errno
        );
        std::fs::remove_dir(&cgroup).expect("remove cgroup");
    }

    /// With a `pin_id`, the helper pins the shared maps under `/run/user/<uid>/kennel/bpf/<id>/`.
    ///
    /// The **factory** mounts that bpffs in production (it holds `CAP_SYS_ADMIN`; this helper does
    /// not); here the test (root) mounts it first, then proves the pins land owner-only with the
    /// right modes — `obj_pin` only succeeds on a bpffs, so their presence proves the pin worked.
    #[test]
    fn pins_the_shared_maps_in_the_xdg_runtime_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        if skip_if_unprivileged("pins_the_shared_maps_in_the_xdg_runtime_dir") {
            return;
        }
        let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-egress-pin-test");
        let _ = std::fs::remove_dir(&cgroup);
        std::fs::create_dir(&cgroup).expect("create cgroup");

        let uid = kennel_lib_syscall::unistd::real_uid();
        let base = kennel_privhelper::bpf_pin_root(uid);
        std::fs::create_dir_all(&base).expect("mkdir pin root");
        if !kennel_lib_syscall::mount::is_bpffs(&base).unwrap_or(false) {
            kennel_lib_syscall::mount::mount_bpffs(&base).expect("mount bpffs (the factory's job)");
        }
        let pin_id = "kennel-pintest";
        let pin_dir = base.join(pin_id);
        let _ = std::fs::remove_dir_all(&pin_dir);

        let resp = attach_egress_programs(
            &cgroup,
            &payload(pin_id, vec![allow_v4_any([127, 0, 0, 1])]),
        );
        assert_eq!(
            resp.status,
            Status::Ok,
            "egress setup (errno {})",
            resp.errno
        );

        for map in [
            "audit_ringbuf",
            "kennel_meta_map",
            "allow_v4",
            "bind_subnet_map",
        ] {
            let pin = pin_dir.join(map);
            assert!(pin.exists(), "expected pinned map at {}", pin.display());
            let mode = std::fs::metadata(&pin)
                .expect("stat pin")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "pin {map} should be mode 0600, got {mode:o}");
        }
        let dir_mode = std::fs::metadata(&pin_dir)
            .expect("stat pin dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "pin dir should be owner-only 0700, got {dir_mode:o}"
        );

        let _ = std::fs::remove_dir_all(&pin_dir);
        std::fs::remove_dir(&cgroup).expect("remove cgroup");
    }

    #[test]
    fn egress_to_a_cgroup_not_owned_by_caller_is_refused() {
        if skip_if_unprivileged("egress_to_a_cgroup_not_owned_by_caller_is_refused") {
            return;
        }
        // A cgroup owned by a *different* uid must be refused before any BPF syscall — the
        // delegation boundary. (Run as root, so chowning to a foreign uid is possible.)
        let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-foreign-test");
        let _ = std::fs::remove_dir(&cgroup);
        std::fs::create_dir(&cgroup).expect("create cgroup");
        std::os::unix::fs::chown(&cgroup, Some(12345), None).expect("chown to foreign uid");
        let resp = attach_egress_programs(&cgroup, &payload("", Vec::new()));
        assert_eq!(
            resp.status,
            Status::Refused,
            "a cgroup not owned by the caller must be refused"
        );
        assert_eq!(
            resp.refusal, REFUSAL_CGROUP_NOT_OWNED,
            "refusal should name the ownership boundary"
        );
        std::fs::remove_dir(&cgroup).expect("remove cgroup");
    }
}
