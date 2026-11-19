//! Facade readiness: a one-byte-per-facade signal from each socket-serving facade to
//! `kennel-bin-init`, so the workload starts only once every facade is listening.
//!
//! # Purpose
//!
//! `kennel-bin-init` forks the facades and then the workload. A workload that connects to a facade
//! socket at once (a D-Bus client, a brokered AF_UNIX socket) must not beat the facade's bind. Init
//! cannot simply check that the socket path exists: it is the kennel's uid 0, mapped to host root
//! only, so the operator-owned `0700` `/tmp` is not even searchable to it (`CAP_DAC_OVERRIDE` in a
//! user namespace covers only inodes whose owner is mapped there). So the facade reports readiness
//! itself: init hands each gated facade the write end of one pipe at [`READY_FD`] (named in the
//! facade's environment as [`READY_ENV`]); the facade writes one byte once every listener is bound;
//! init [`wait`]s for one byte per gated facade, bounded.
//!
//! # Why nix here
//!
//! `pipe2`/`dup2`/`poll`/`read` via nix's safe wrappers: this module is `unsafe`-free.

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::time::Duration;

/// The fixed fd a gated facade inherits the readiness pipe's write end at. 3–9 are taken by the
/// other boot fds (`PTY_RETURN_FD` … `TUN_FD`).
pub const READY_FD: RawFd = 10;

/// The environment variable that tells a facade it is gated and which fd to signal on.
pub const READY_ENV: &str = "KENNEL_READY_FD";

/// Create the readiness pipe, close-on-exec, as `(read end, write end)`. Close-on-exec so the
/// workload never inherits either end; a gated facade gets its own copy at [`READY_FD`] via
/// [`place_write_end`].
///
/// # Errors
///
/// The OS error if `pipe2(2)` fails.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    todo!("facade readiness (D-Bus race)")
}

/// In the forked facade child, before `execve`: duplicate `write` onto [`READY_FD`] *without*
/// close-on-exec, so the facade program inherits it. Async-signal-safe (`dup2` only).
///
/// # Errors
///
/// The OS error if `dup2(2)` fails.
pub fn place_write_end(write: BorrowedFd<'_>) -> io::Result<()> {
    let _ = write;
    todo!("facade readiness (D-Bus race)")
}

/// Read readiness bytes from `read` until `expected` have arrived, every writer has closed (EOF:
/// the gated facades exited), or `timeout` elapses. Returns how many arrived.
///
/// # Errors
///
/// The OS error if `poll(2)` or `read(2)` fails for a reason other than an interrupt.
pub fn wait(read: BorrowedFd<'_>, expected: usize, timeout: Duration) -> io::Result<usize> {
    let _ = (read, expected, timeout);
    todo!("facade readiness (D-Bus race)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::time::Instant;

    fn signal(write: &OwnedFd) {
        nix::unistd::write(write, &[1]).expect("write a readiness byte");
    }

    #[test]
    fn returns_once_every_expected_byte_arrives() {
        let (r, w) = pipe().expect("pipe");
        signal(&w);
        signal(&w);
        assert_eq!(wait(r.as_fd(), 2, Duration::from_secs(5)).expect("wait"), 2);
    }

    #[test]
    fn waits_for_a_late_signal() {
        let (r, w) = pipe().expect("pipe");
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            signal(&w);
        });
        let start = Instant::now();
        assert_eq!(wait(r.as_fd(), 1, Duration::from_secs(5)).expect("wait"), 1);
        assert!(
            start.elapsed() >= Duration::from_millis(40),
            "it waited for the byte"
        );
        t.join().expect("join");
    }

    #[test]
    fn gives_up_at_the_deadline_with_the_partial_count() {
        let (r, w) = pipe().expect("pipe");
        signal(&w);
        let start = Instant::now();
        assert_eq!(
            wait(r.as_fd(), 3, Duration::from_millis(60)).expect("wait"),
            1
        );
        assert!(start.elapsed() >= Duration::from_millis(60));
        assert!(start.elapsed() < Duration::from_secs(2), "bounded");
        drop(w);
    }

    #[test]
    fn returns_early_when_every_writer_has_closed() {
        let (r, w) = pipe().expect("pipe");
        signal(&w);
        drop(w); // the gated facades exited
        let start = Instant::now();
        assert_eq!(wait(r.as_fd(), 3, Duration::from_secs(5)).expect("wait"), 1);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "EOF ends the wait early"
        );
    }

    #[test]
    fn zero_expected_means_no_wait() {
        let (r, _w) = pipe().expect("pipe");
        assert_eq!(wait(r.as_fd(), 0, Duration::from_secs(5)).expect("wait"), 0);
    }

    #[test]
    fn the_pipe_ends_are_close_on_exec() {
        let (r, w) = pipe().expect("pipe");
        for fd in [r.as_fd(), w.as_fd()] {
            let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "the workload must not inherit it"
            );
        }
    }
}
