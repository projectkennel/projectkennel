//! `kennel-privhelper-mounts` — the exclusive-bind over-mount sub-helper.
//!
//! While a kennel runs, an `fs.exclusive` path is shadowed on the **host** side by an
//! opaque sentinel `tmpfs`, so the operator and the workload cannot use the path
//! concurrently — this severs the live confused-deputy channel (a workload planting
//! "run this" content the operator then acts on, §2.7 / T2.8). The kennel keeps the real
//! inode through its own already-constructed, rec-private view; the over-mount lands only
//! in the operator's session mount namespace. The release (`unmount`) happens at teardown.
//!
//! This over-mount must run in the operator's host mount namespace, so it is the one
//! construction step that needs `CAP_SYS_ADMIN` — which this helper carries and the common
//! factory does not. It is invoked **only** by the main `kennel-privhelper`'s construct
//! orchestration (the over-mount lands after the child has built its view and `pivot_root`ed
//! away, a sequence point only the orchestrator holds); the orchestrator gains the capability
//! across the `exec` without holding it itself.
//!
//! Gating: the caller must hold a `/etc/kennel/subkennel` allocation, and the over-mount is
//! refused over any path the **caller does not own** (`check_owned_dir`, the authoritative
//! overreach gate — the helper trusts only the kernel-stamped real uid). The release unmounts
//! only a mount carrying this helper's own sentinel.
//!
//! Usage: `kennel-privhelper-mounts {mount|unmount} <host-path>`.

#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::ExitCode;

use kennel_lib_syscall::mount;

/// The sentinel marker dropped into the over-mounted tmpfs, naming the lock for an operator
/// who finds a directory shadowed (and a recovery hint for a leaked lock).
const SENTINEL: &str = "KENNEL-EXCLUSIVE-LOCK";
const SENTINEL_BODY: &[u8] = b"This directory is held by a Project Kennel exclusive bind \
(fs.exclusive) while a kennel is running, so the host and the workload do not use it \
concurrently. It is released (unmounted) at teardown. If a kennel crashed and left this behind, \
run `kennel release <name>` or restart kenneld to clear the leaked lock.\n";

fn main() -> ExitCode {
    // Scrub the inherited environment: privileged, takes no decision from the environment;
    // identity is the kernel-stamped real uid. `vars_os` is a snapshot, so removing during
    // iteration is sound.
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }

    // Gate on the caller's subkennel allocation, like every privileged op.
    let uid = kennel_lib_syscall::unistd::real_uid();
    if kennel_privhelper::alloc::load(uid).is_none() {
        eprintln!("kennel-privhelper-mounts: caller has no /etc/kennel/subkennel allocation");
        return ExitCode::from(1);
    }

    let args: Vec<String> = std::env::args().collect();
    let Some(host) = args.get(2) else {
        eprintln!("usage: kennel-privhelper-mounts {{mount|unmount}} <host-path>");
        return ExitCode::from(2);
    };
    let host = Path::new(host);
    match args.get(1).map(String::as_str) {
        // The over-mount: the caller (this helper's real uid) must own the path.
        Some("mount") => match mount_exclusive(host, uid) {
            Ok(()) => ExitCode::from(0),
            Err(reason) => {
                eprintln!("kennel-privhelper-mounts: {reason}");
                ExitCode::from(1)
            }
        },
        Some("unmount") => unmount_exclusive(host),
        _ => {
            eprintln!("usage: kennel-privhelper-mounts {{mount|unmount}} <host-path>");
            ExitCode::from(2)
        }
    }
}

/// Over-mount an opaque sentinel on `host` (an owned writable-bind path).
///
/// Refuses a path `owner_uid` does not own (the authoritative overreach gate). A small,
/// `nosuid+nodev` tmpfs shadows the real dir; the kennel keeps the real inode through its own
/// already-built view.
///
/// # Errors
/// A human-readable reason if `host` is not a directory owned by `owner_uid`, or the over-mount
/// fails.
fn mount_exclusive(host: &Path, owner_uid: u32) -> Result<(), String> {
    check_owned_dir(host, owner_uid)?;
    // mode 0755 so the operator can see the sentinel.
    mount::mount_tmpfs(host, Some(1), Some("0755"), false, false)
        .map_err(|e| format!("exclusive over-mount of {} failed: {e}", host.display()))?;
    // Drop the sentinel, then seal the over-mount read-only (best-effort — the shadow itself is
    // the control; the read-only remount is hardening).
    let _ = std::fs::write(host.join(SENTINEL), SENTINEL_BODY);
    if let Err(e) = mount::remount_readonly(host) {
        eprintln!(
            "kennel-privhelper-mounts: sealing exclusive over-mount of {} read-only failed: {e}",
            host.display()
        );
    }
    Ok(())
}

/// Release the exclusive over-mount at teardown / `kennel release`.
///
/// Gated on the over-mount carrying our sentinel (so the helper unmounts only mounts it created,
/// never an arbitrary host mount). Exit code: 0 ok, 1 refused (not our sentinel), 3 internal.
fn unmount_exclusive(host: &Path) -> ExitCode {
    if !host.join(SENTINEL).is_file() {
        eprintln!(
            "kennel-privhelper-mounts: refusing release: {} is not a kennel exclusive over-mount",
            host.display()
        );
        return ExitCode::from(1);
    }
    match mount::unmount_detach(host) {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!(
                "kennel-privhelper-mounts: releasing exclusive over-mount of {} failed: {e}",
                host.display()
            );
            ExitCode::from(3)
        }
    }
}

/// The ownership predicate (parameterised by `uid` for testability): `Ok` iff `host` exists, is
/// a directory, and is owned by `uid`. A non-owned path is the overreach case.
fn check_owned_dir(host: &Path, uid: u32) -> Result<(), String> {
    match std::fs::symlink_metadata(host) {
        Ok(meta) if !meta.file_type().is_dir() => {
            Err(format!("{} is not a directory", host.display()))
        }
        Ok(meta) if meta.uid() != uid => Err(format!(
            "{} is not owned by uid {uid} (an exclusive blind-mount over a path you do not own \
             would be overreach)",
            host.display()
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("cannot stat {}: {e}", host.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_an_exclusive_over_mount_of_a_path_you_do_not_own() {
        let dir = std::env::temp_dir().join(format!("kennel-excl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let me = kennel_lib_syscall::unistd::real_uid();
        // A directory the caller owns is accepted; the same path under a foreign uid is refused.
        assert!(check_owned_dir(&dir, me).is_ok(), "owned dir accepted");
        let other = me.wrapping_add(1);
        assert!(
            check_owned_dir(&dir, other).is_err(),
            "a path not owned by the (pretend) caller is overreach"
        );
        // A regular file is not a valid exclusive target.
        let file = dir.join("f");
        std::fs::write(&file, b"x").expect("write");
        assert!(
            check_owned_dir(&file, me).is_err(),
            "a file is not a directory"
        );
        // A missing path is refused (cannot own what is not there).
        assert!(
            check_owned_dir(&dir.join("nope"), me).is_err(),
            "absent path refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
