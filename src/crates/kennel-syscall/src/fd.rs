//! File-descriptor flag helpers.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, FdFlag};

/// Set the close-on-exec flag (`FD_CLOEXEC`) on `fd`.
///
/// The privhelper factory uses this on the privileged kenneld↔helper control socket (the
/// helper's stdin): `clone` copies the fd table into the construction child, and `dup2`
/// onto stdin clears `O_CLOEXEC`, so without this the channel would survive the child's
/// `fexecve` into `kennel-init` and leak a handle to the privileged factory transport into
/// the kennel (`07-2`; sec review: fd hygiene). Re-getting the existing flags first keeps
/// any other descriptor flags intact.
///
/// # Errors
/// An OS error if `fcntl(F_GETFD/F_SETFD)` fails.
pub fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    let current = fcntl(fd, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    let flags = FdFlag::from_bits_truncate(current) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Duplicate `src` onto descriptor number `dst` (`dup2(2)`).
///
/// `dup2` installs `src`'s open file at the exact number `dst` (closing any prior `dst`) and
/// the new descriptor is **not** close-on-exec — so it survives a subsequent `fexecve`. The
/// privhelper factory uses this to place the interactive pty return socket at the fixed
/// [`crate::pty::PTY_RETURN_FD`] the argv-less `kennel-init` reads.
///
/// # Errors
/// The OS error if `dup2(2)` fails (e.g. `dst` is out of range).
pub fn dup_onto(src: BorrowedFd<'_>, dst: RawFd) -> io::Result<()> {
    // `dup2(fd, fd)` is a no-op that does NOT clear close-on-exec, so when `src` already sits
    // at `dst` we must clear it explicitly — otherwise the descriptor would not survive the
    // intended `fexecve`.
    if src.as_raw_fd() == dst {
        let flags = fcntl(src, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let cleared = FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC;
        fcntl(src, FcntlArg::F_SETFD(cleared)).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
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
}
