//! Mount-namespace construction primitives.
//!
//! Safe wrappers (over nix) for the mount operations the spawn sequence uses to
//! build the workload's filesystem view inside a fresh mount namespace
//! (`docs/design/07-2`, `docs/design/08` §spawn): make the tree private, bind paths in,
//! remount read-only, mount `proc`/`tmpfs`, then `pivot_root` into the new root
//! and detach the old one. Flags are hidden behind named functions and bool
//! parameters, so callers do not touch nix's `MsFlags`. No `unsafe` of ours.
//!
//! Every operation requires `CAP_SYS_ADMIN` in the current user namespace and
//! only makes sense after [`crate::namespace::unshare`] of the mount namespace —
//! otherwise it mutates the host. Tests run inside a private mount namespace for
//! exactly this reason.

use std::io;
use std::path::Path;

use nix::mount::{MntFlags, MsFlags};

fn map_err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Make the entire mount tree private (`MS_REC | MS_PRIVATE` on `/`).
///
/// The first step in a new mount namespace: it stops later mount/unmount events
/// from propagating back to the parent namespace (and vice versa).
///
/// # Errors
///
/// Returns the OS error if the remount fails (e.g. without `CAP_SYS_ADMIN`).
pub fn make_root_private() -> io::Result<()> {
    nix::mount::mount(
        None::<&Path>,
        Path::new("/"),
        None::<&Path>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&Path>,
    )
    .map_err(map_err)
}

/// Bind-mount `source` onto `target` (`MS_BIND`; `MS_REC` when `recursive`).
///
/// # Errors
///
/// Returns the OS error if the bind fails (missing target, permission, …).
pub fn bind(source: &Path, target: &Path, recursive: bool) -> io::Result<()> {
    let mut flags = MsFlags::MS_BIND;
    if recursive {
        flags |= MsFlags::MS_REC;
    }
    nix::mount::mount(Some(source), target, None::<&Path>, flags, None::<&Path>).map_err(map_err)
}

/// Remount an existing (bind) mount read-only
/// (`MS_BIND | MS_REMOUNT | MS_RDONLY`), **preserving the mount's locked flags**.
///
/// A bind mount must be remounted to apply `MS_RDONLY`; bind + this is the
/// read-only-grant idiom. Inside an unprivileged user namespace the kernel
/// forbids a remount from *clearing* the `nosuid`/`nodev`/`noexec` flags that are
/// locked on the underlying superblock — a bind of a file from a `nosuid,nodev`
/// mount (e.g. `$XDG_RUNTIME_DIR`, a systemd `tmpfs`) would otherwise fail with
/// `EPERM`. We therefore read the target's current flags (`statvfs`) and carry the
/// locked ones into the remount. This both fixes the unprivileged case and is
/// strictly more restrictive (a read-only grant never wants `suid`/`dev`); a
/// source without those flags (e.g. the root fs under `/usr`) is unaffected, so an
/// executable bind stays executable.
///
/// # Errors
///
/// Returns the OS error if `target` is not a mount point, its flags cannot be
/// read, or the remount fails.
pub fn remount_readonly(target: &Path) -> io::Result<()> {
    use nix::sys::statvfs::{statvfs, FsFlags};

    let current = statvfs(target).map_err(map_err)?.flags();
    let mut flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    // Preserve the flags the kernel locks on a userns-visible mount; clearing any
    // of them in a remount is EPERM inside an unprivileged user namespace.
    flags.set(MsFlags::MS_NOSUID, current.contains(FsFlags::ST_NOSUID));
    flags.set(MsFlags::MS_NODEV, current.contains(FsFlags::ST_NODEV));
    flags.set(MsFlags::MS_NOEXEC, current.contains(FsFlags::ST_NOEXEC));
    nix::mount::mount(None::<&Path>, target, None::<&Path>, flags, None::<&Path>).map_err(map_err)
}

/// Mount a special filesystem (`proc`, `sysfs`, `tmpfs`, …) at `target` with the
/// safe baseline `nosuid,nodev`.
///
/// # Errors
///
/// Returns the OS error if the mount fails (unknown fstype, permission, …).
pub fn mount_special(fstype: &str, target: &Path) -> io::Result<()> {
    nix::mount::mount(
        Some(fstype),
        target,
        Some(fstype),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&Path>,
    )
    .map_err(map_err)
}

/// Mount a fresh `tmpfs` at `target` with `nosuid` (and `nodev` unless
/// `allow_dev`), an optional `size_mib` cap (mebibytes) and octal `mode`.
///
/// `allow_dev` exists for the constructed `/dev`, whose bind-mounted device nodes
/// must function; every other tmpfs (`/tmp`, the new root) forbids devices.
/// `mode` must be octal digits — the caller validates it (it flows into the
/// comma-separated mount data string, so a stray comma would inject an option).
///
/// # Errors
///
/// Returns the OS error if the mount fails.
pub fn mount_tmpfs(target: &Path, size_mib: Option<u32>, mode: Option<&str>, allow_dev: bool) -> io::Result<()> {
    let mut opts: Vec<String> = Vec::new();
    if let Some(s) = size_mib {
        opts.push(format!("size={s}M"));
    }
    if let Some(m) = mode {
        opts.push(format!("mode={m}"));
    }
    let data = opts.join(",");
    let mut flags = MsFlags::MS_NOSUID;
    if !allow_dev {
        flags |= MsFlags::MS_NODEV;
    }
    nix::mount::mount(Some("tmpfs"), target, Some("tmpfs"), flags, Some(data.as_str())).map_err(map_err)
}

/// Mount a fresh `proc` at `target` (`nosuid,nodev`), with `hidepid=2` when
/// `hidepid` so `/proc/<pid>` is owner-only even within the PID namespace
/// (§7.2.7, belt-and-braces atop the namespace).
///
/// # Errors
///
/// Returns the OS error if the mount fails.
pub fn mount_proc(target: &Path, hidepid: bool) -> io::Result<()> {
    let data = if hidepid { "hidepid=2" } else { "" };
    nix::mount::mount(Some("proc"), target, Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some(data))
        .map_err(map_err)
}

/// `pivot_root(new_root, put_old)`: make `new_root` the process's root,
/// relocating the old root under `put_old` (which must be beneath `new_root`).
///
/// `new_root` must be a mount point distinct from its parent. After a successful
/// call, `chdir("/")` and [`unmount_detach`] the old root.
///
/// # Errors
///
/// Returns the OS error if the preconditions are unmet or the call fails.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> io::Result<()> {
    nix::unistd::pivot_root(new_root, put_old).map_err(map_err)
}

/// Lazily unmount `target` (`umount2(MNT_DETACH)`): detaches it now and frees it
/// once no longer busy. Used to drop the old root after `pivot_root`.
///
/// # Errors
///
/// Returns the OS error if the unmount fails.
pub fn unmount_detach(target: &Path) -> io::Result<()> {
    nix::mount::umount2(target, MntFlags::MNT_DETACH).map_err(map_err)
}

#[cfg(all(test, feature = "root-tests"))]
mod root_tests {
    //! Run via `sudo -E cargo test --features root-tests`. Each test runs inside
    //! a forked child that unshares a private mount namespace first, so nothing
    //! touches the host mount table.

    use super::*;

    /// Run `body` in a child with a private mount namespace; assert it exits 0.
    /// `body` returns the child exit code (0 = success).
    fn in_private_mount_ns(body: impl FnOnce() -> i32) {
        // SAFETY: fork(); the child runs `body` (mount syscalls + fs ops) and
        // _exit()s, never returning to the harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if crate::namespace::unshare(crate::namespace::Namespaces::MOUNT)
                    .is_err()
                    || make_root_private().is_err()
                {
                    90
                } else {
                    body()
                };
                // SAFETY: _exit without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "child failed (90 = ns/private setup): {status:?}"
                );
            }
        }
    }

    #[test]
    fn tmpfs_mounts_and_is_writable_then_detaches() {
        in_private_mount_ns(|| {
            let dir = Path::new("/tmp/kennel-mnt-tmpfs");
            if std::fs::create_dir_all(dir).is_err() {
                return 1;
            }
            if mount_special("tmpfs", dir).is_err() {
                return 2;
            }
            // tmpfs is writable
            if std::fs::write(dir.join("probe"), b"x").is_err() {
                return 3;
            }
            if unmount_detach(dir).is_err() {
                return 4;
            }
            0
        });
    }

    #[test]
    fn bind_then_remount_readonly_blocks_writes() {
        in_private_mount_ns(|| {
            // A tmpfs we can write, bind it elsewhere, remount the bind RO.
            let src = Path::new("/tmp/kennel-mnt-src");
            let dst = Path::new("/tmp/kennel-mnt-ro");
            for d in [src, dst] {
                if std::fs::create_dir_all(d).is_err() {
                    return 1;
                }
            }
            if mount_special("tmpfs", src).is_err() {
                return 2;
            }
            if bind(src, dst, false).is_err() {
                return 3;
            }
            if remount_readonly(dst).is_err() {
                return 4;
            }
            // Writing through the read-only bind must fail (EROFS).
            match std::fs::write(dst.join("probe"), b"x") {
                Ok(()) => 5, // should have been denied
                Err(_) => 0,
            }
        });
    }

    #[test]
    fn tmpfs_with_size_and_mode_mounts_and_is_writable() {
        in_private_mount_ns(|| {
            let dir = Path::new("/tmp/kennel-mnt-tmpfs-opts");
            if std::fs::create_dir_all(dir).is_err() {
                return 1;
            }
            if mount_tmpfs(dir, Some(8), Some("0700"), false).is_err() {
                return 2;
            }
            if std::fs::write(dir.join("probe"), b"x").is_err() {
                return 3;
            }
            if unmount_detach(dir).is_err() {
                return 4;
            }
            0
        });
    }

    #[test]
    fn proc_with_hidepid_mounts() {
        in_private_mount_ns(|| {
            let dir = Path::new("/tmp/kennel-mnt-proc-hidepid");
            if std::fs::create_dir_all(dir).is_err() {
                return 1;
            }
            if mount_proc(dir, true).is_err() {
                return 2;
            }
            // A freshly-mounted proc exposes /proc/self.
            if std::fs::metadata(dir.join("self")).is_err() {
                return 3;
            }
            if unmount_detach(dir).is_err() {
                return 4;
            }
            0
        });
    }

    #[test]
    fn pivot_root_into_a_fresh_tmpfs_root() {
        in_private_mount_ns(|| {
            let new_root = Path::new("/tmp/kennel-newroot");
            if std::fs::create_dir_all(new_root).is_err() {
                return 1;
            }
            // new_root must be a mount point: mount a tmpfs there.
            if mount_special("tmpfs", new_root).is_err() {
                return 2;
            }
            let put_old = new_root.join(".old-root");
            if std::fs::create_dir_all(&put_old).is_err() {
                return 3;
            }
            if pivot_root(new_root, &put_old).is_err() {
                return 4;
            }
            if std::env::set_current_dir("/").is_err() {
                return 5;
            }
            // The old root is now under /.old-root; detach it.
            if unmount_detach(Path::new("/.old-root")).is_err() {
                return 6;
            }
            // We are in the fresh tmpfs root: it is empty apart from .old-root.
            match std::fs::metadata("/.old-root") {
                Ok(_) => 0,
                Err(_) => 7,
            }
        });
    }
}
