//! A wake eventfd polled alongside a primary fd.
//!
//! A poll loop that waits on a primary fd with a timeout (a binder looper on the
//! device fd, the BPF-audit drain on its ring buffer) checks its stop flag only
//! between polls, so teardown would otherwise wait out a whole timeout cycle. A
//! never-drained wake eventfd, polled alongside the primary fd, lets a single
//! [`signal_wake`] return every waiter at once.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Create a wake eventfd (`EFD_CLOEXEC | EFD_NONBLOCK`, initial count 0).
///
/// Level-triggered and never drained: [`signal_wake`] raises its count once and it
/// stays readable, so every waiter in [`poll_in_or_wake`] returns together.
///
/// # Errors
///
/// Returns the OS error if `eventfd(2)` fails.
pub fn make_wake_eventfd() -> io::Result<OwnedFd> {
    // SAFETY: `eventfd` takes a count and flags and returns a fresh owned fd or -1; no pointers.
    let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, exclusively-owned, open fd from a successful `eventfd`.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Fire the wake eventfd: raise its count so every waiter returns at once.
///
/// # Errors
///
/// Returns the OS error if the `write(2)` fails; a saturated counter (`EAGAIN` on the
/// non-blocking fd) is reported as success — it is already signalled.
pub fn signal_wake(wake: BorrowedFd<'_>) -> io::Result<()> {
    let one: u64 = 1;
    let buf = one.to_ne_bytes();
    // SAFETY: `buf` is a live 8-byte buffer; `write` reads exactly its length and retains nothing.
    let ret = unsafe { libc::write(wake.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(()); // counter already saturated — already signalled
        }
        return Err(err);
    }
    Ok(())
}

/// Wait up to `timeout_ms` for `primary` to become readable, returning early if `wake` does.
///
/// The return reflects only `primary` (whether it has work): a wake-only return is `false`, so the
/// caller loops to re-check its stop flag.
///
/// # Errors
///
/// Returns the OS error if `poll(2)` fails for a reason other than `EINTR` (reported as "not
/// readable" so the caller loops).
pub fn poll_in_or_wake(
    primary: BorrowedFd<'_>,
    wake: BorrowedFd<'_>,
    timeout_ms: i32,
) -> io::Result<bool> {
    let mut pfds = [
        libc::pollfd {
            fd: primary.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: `pfds` is two live, initialised pollfds; `poll` reads/writes them and the count (2)
    // matches the array length. No pointer is retained past the call.
    //
    // INVARIANTS UPHELD: exactly two pollfds are described to the kernel.
    //
    // FAILURE MODE: -1 + errno; EINTR is mapped to "not ready" so the caller retries.
    let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(pfds[0].revents & libc::POLLIN != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn wake_breaks_the_poll() {
        let wake = make_wake_eventfd().expect("eventfd");
        // Unsignalled: not readable, so a 0ms poll returns false (primary == wake here).
        assert!(!poll_in_or_wake(wake.as_fd(), wake.as_fd(), 0).expect("poll"));
        // Signalled: readable, so the poll returns true.
        signal_wake(wake.as_fd()).expect("signal");
        assert!(poll_in_or_wake(wake.as_fd(), wake.as_fd(), 100).expect("poll"));
        // Level-triggered: a second signal on the never-drained counter still succeeds.
        signal_wake(wake.as_fd()).expect("signal again");
    }
}
