//! File-descriptor flag helpers.

use std::io;
use std::os::fd::BorrowedFd;

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
}
