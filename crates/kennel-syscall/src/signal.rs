//! Sending signals to a process by pid.
//!
//! kenneld stops a kennel from a *different* thread than the one that owns the
//! workload's `Child`, so it cannot use `std`'s `Child::kill` (which needs `&mut
//! Child`); it signals the pid directly. `kill(2)` takes two integers and touches
//! no memory, so this is a trivial reviewed `unsafe` over libc rather than a
//! reason to widen nix's feature set.

use std::io;

/// Send `SIGTERM` to `pid` (a graceful request to terminate).
///
/// # Errors
/// An OS error if the signal cannot be sent (e.g. `ESRCH` if `pid` is gone, or
/// `EPERM`), or `InvalidInput` if `pid` does not fit a `pid_t`.
pub fn terminate(pid: u32) -> io::Result<()> {
    send(pid, libc::SIGTERM)
}

/// Send `SIGKILL` to `pid` (forced, uncatchable termination).
///
/// # Errors
/// As [`terminate`].
pub fn kill(pid: u32) -> io::Result<()> {
    send(pid, libc::SIGKILL)
}

fn send(pid: u32, signal: i32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: kill(2) sends `signal` to `pid`; both are plain integers and no
    // memory is read or written. FAILURE MODE: -1 -> last_os_error.
    let result = unsafe { libc::kill(pid, signal) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn terminate_stops_a_child() {
        let mut child = Command::new("/bin/sleep").arg("60").spawn().expect("spawn sleep");
        terminate(child.id()).expect("send SIGTERM");
        let status = child.wait().expect("wait");
        assert!(!status.success(), "the signalled sleep should not exit successfully");
    }

    #[test]
    fn signalling_a_missing_pid_errors() {
        // pid 0x7FFF_FFFE is almost certainly not a live process.
        let err = kill(0x7FFF_FFFE).expect_err("no such process");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }
}
