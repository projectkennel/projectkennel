//! File-descriptor helpers: flag manipulation and `openat2` path resolution.
//!
//! The `openat2` wrapper (`open_no_symlinks`) is an `unsafe` site — the fourth in
//! this crate — documented per §4 (SAFETY / INVARIANTS UPHELD / FAILURE MODE).
//! It uses the raw `openat2(2)` syscall (Linux 5.6+, `__NR_openat2 = 437`) because
//! neither `libc` nor `nix` wrap it. The pattern matches the existing `clone3`
//! wrapper in `namespace.rs`: a `#[repr(C)]` kernel struct and a raw
//! `libc::syscall`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};

// ─── openat2(2) — RESOLVE_NO_SYMLINKS ────────────────────────────────────────

/// The kernel's `struct open_how` (v0, `OPEN_HOW_SIZE_VER0 = 24`).
///
/// All fields are `__u64`; the kernel reads exactly `size_of::<OpenHow>()` bytes
/// and retains no pointer. Defined in `<linux/openat2.h>`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `RESOLVE_NO_SYMLINKS` (`<linux/openat2.h>`, kernel 5.6+).
///
/// If any path component (including the final one) is a symbolic link, the
/// `openat2` call fails with `ELOOP`.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// `__NR_openat2` — syscall 437 on x86-64 / aarch64 / riscv64.
const SYS_OPENAT2: libc::c_long = 437;

/// Open `path` relative to `dir_fd` with `RESOLVE_NO_SYMLINKS`, returning an
/// `O_PATH` fd.
///
/// If any component of `path` is a symbolic link the call fails with `ELOOP`,
/// closing the writable-bind-source symlink-aliasing class (W3, 0.4.0 F1
/// residual). The returned fd is safe to use as `/proc/self/fd/N` — its target
/// is the inode the path resolved to without following any symlink.
///
/// `dir_fd` follows the kernel's `int dfd` semantics: pass `libc::AT_FDCWD` to
/// resolve relative to the current directory, or an open directory fd for
/// anchored resolution. For absolute paths the kernel ignores it.
///
/// # Errors
///
/// - `ELOOP`: a path component is a symlink.
/// - `ENOSYS`: kernel < 5.6 (does not support `openat2`).
/// - Any other `openat2` error (`ENOENT`, `EACCES`, …).
pub fn open_no_symlinks(dir_fd: RawFd, path: &Path) -> io::Result<OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let how = OpenHow {
        flags: libc::O_PATH as u64, // fd-only, no read/write capability
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `openat2` with a valid `dir_fd` (or `AT_FDCWD`), a NUL-terminated
    // `path`, and a correctly sized, stack-local `open_how` is a pure open-path
    // call — no pointer is retained, no aliasing concern. `O_PATH` means no I/O
    // capability is granted, only an fd for `/proc/self/fd/N` resolution. The
    // returned descriptor is fresh and owned by us.
    //
    // INVARIANTS UPHELD: `how` is stack-local, correctly sized (24 bytes,
    // `OPEN_HOW_SIZE_VER0`), zeroed in unused fields. `c_path` lives until
    // the syscall returns. `SYS_OPENAT2` is the correct syscall number for
    // all supported architectures (verified against `<asm/unistd.h>`).
    //
    // FAILURE MODE: -1 + errno → `Err`. The caller must not proceed with
    // the bind mount — a symlink in the path is a potential escape.
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dir_fd,
            c_path.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat2` returned a non-negative descriptor that we are the
    // sole owner of; wrapping it transfers that ownership for RAII close.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

// ─── FD flag helpers ─────────────────────────────────────────────────────────

/// Set the close-on-exec flag (`FD_CLOEXEC`) on `fd`.
///
/// The privhelper factory uses this on the privileged kenneld↔helper control socket (the
/// helper's stdin): `clone` copies the fd table into the construction child, and `dup2`
/// onto stdin clears `O_CLOEXEC`, so without this the channel would survive the child's
/// `fexecve` into `kennel-bin-init` and leak a handle to the privileged factory transport into
/// the kennel (`07-2`; sec review: fd hygiene). Re-getting the existing flags first keeps
/// any other descriptor flags intact.
///
/// # Errors
/// An OS error if `fcntl(F_GETFD/F_SETFD)` fails.
pub fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    let current =
        fcntl(fd, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    let flags = FdFlag::from_bits_truncate(current) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Duplicate `src` onto descriptor number `dst` (`dup2(2)`).
///
/// `dup2` installs `src`'s open file at the exact number `dst` (closing any prior `dst`) and
/// the new descriptor is **not** close-on-exec — so it survives a subsequent `fexecve`. The
/// privhelper factory uses this to place the interactive pty return socket at the fixed
/// [`crate::pty::PTY_RETURN_FD`] the argv-less `kennel-bin-init` reads.
///
/// # Errors
/// The OS error if `dup2(2)` fails (e.g. `dst` is out of range).
pub fn dup_onto(src: BorrowedFd<'_>, dst: RawFd) -> io::Result<()> {
    // `dup2(fd, fd)` is a no-op that does NOT clear close-on-exec, so when `src` already sits
    // at `dst` we must clear it explicitly — otherwise the descriptor would not survive the
    // intended `fexecve`.
    if src.as_raw_fd() == dst {
        let flags =
            fcntl(src, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let cleared = FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC;
        fcntl(src, FcntlArg::F_SETFD(cleared))
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        return Ok(());
    }
    // SAFETY: a plain dup2 of a valid borrowed descriptor onto a raw target number. We work
    // in descriptor numbers, not `OwnedFd`, so there is no Rust ownership/aliasing concern;
    // the kernel closes any file previously at `dst` and the new `dst` is not close-on-exec.
    let rc = unsafe { libc::dup2(src.as_raw_fd(), dst) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Duplicate `src` to the lowest free descriptor `>= base`, close-on-exec (`F_DUPFD_CLOEXEC`),
/// returned as an [`OwnedFd`].
///
/// Used to move the descriptors a process will place at fixed low numbers (via [`dup_onto`]) up
/// out of that range first, so the placements cannot clobber one another or another descriptor
/// the process still needs (e.g. the factory relocates the init-binary fd, the pty socket, and
/// the boot-sync socket above `PTY_RETURN_FD`/`BOOT_SYNC_FD` before `dup2`-ing them down).
///
/// # Errors
/// The OS error if `fcntl(F_DUPFD_CLOEXEC)` fails (e.g. the fd table is full).
pub fn dup_above(src: BorrowedFd<'_>, base: RawFd) -> io::Result<OwnedFd> {
    let raw = fcntl(src, FcntlArg::F_DUPFD_CLOEXEC(base))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    // SAFETY: `F_DUPFD_CLOEXEC` returned a fresh, owned descriptor we are the sole holder of;
    // wrapping it transfers that ownership for RAII close.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn set_cloexec_marks_the_descriptor_close_on_exec() {
        // A pipe read end starts without FD_CLOEXEC (nix `pipe` is plain); setting it must
        // make F_GETFD report the flag.
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        let before = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            !FdFlag::from_bits_truncate(before).contains(FdFlag::FD_CLOEXEC),
            "plain pipe is not close-on-exec to begin with"
        );
        set_cloexec(r.as_fd()).expect("set_cloexec");
        let after = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            FdFlag::from_bits_truncate(after).contains(FdFlag::FD_CLOEXEC),
            "the flag is set after set_cloexec"
        );
    }

    #[test]
    fn dup_onto_self_clears_cloexec() {
        // The subtle case: `dup_onto(fd, fd)` must NOT be a no-op — `dup2(fd, fd)` leaves
        // close-on-exec set, so the descriptor would not survive the factory's fexecve. Mark a
        // pipe end close-on-exec, dup it onto itself, and confirm the flag is now clear.
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        set_cloexec(r.as_fd()).expect("set_cloexec");
        dup_onto(r.as_fd(), r.as_raw_fd()).expect("dup_onto self");
        let flags = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC),
            "dup_onto(fd, fd) clears close-on-exec so it survives fexecve"
        );
    }

    // ─── W3: open_no_symlinks (openat2 RESOLVE_NO_SYMLINKS) ──────────────────

    #[test]
    fn open_no_symlinks_succeeds_on_a_real_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("kennel-test-openat2-real");
        std::fs::write(&path, b"ok").expect("create");
        let fd = open_no_symlinks(libc::AT_FDCWD, &path);
        let _ = std::fs::remove_file(&path);
        let fd = fd.expect("open_no_symlinks on a real file should succeed");
        // The fd is O_PATH — we can stat through /proc/self/fd/N.
        let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        assert!(
            std::fs::symlink_metadata(&proc_path).is_ok(),
            "/proc/self/fd/N must be resolvable"
        );
    }

    #[test]
    fn open_no_symlinks_rejects_a_symlink_target() {
        let dir = std::env::temp_dir();
        let real = dir.join("kennel-test-openat2-target");
        let link = dir.join("kennel-test-openat2-link");
        std::fs::write(&real, b"ok").expect("create");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let result = open_no_symlinks(libc::AT_FDCWD, &link);
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_file(&link);
        let err = result.expect_err("open_no_symlinks on a symlink target must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP, got: {err}"
        );
    }

    #[test]
    fn open_no_symlinks_rejects_a_symlink_component() {
        let dir = std::env::temp_dir();
        let real_dir = dir.join("kennel-test-openat2-realdir");
        let link_dir = dir.join("kennel-test-openat2-linkdir");
        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&link_dir);
        std::fs::create_dir_all(&real_dir).expect("mkdir");
        let target = real_dir.join("file");
        std::fs::write(&target, b"ok").expect("create");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("symlink");
        // Try to open link_dir/file — the link_dir component is a symlink.
        let via_link = link_dir.join("file");
        let result = open_no_symlinks(libc::AT_FDCWD, &via_link);
        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&link_dir);
        let err = result.expect_err("open_no_symlinks with a symlink component must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP for symlink component, got: {err}"
        );
    }
}
