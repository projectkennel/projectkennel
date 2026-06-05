//! A tiny anonymous-pipe handshake for the spawn-time `gid_map` exchange.
//!
//! # Purpose
//!
//! The unprivileged spawn re-grants a supplementary group by deferring the
//! workload userns `gid_map` to the privhelper (§7.2.8): the spawn child (A)
//! establishes its user namespace, then must pause until a privileged helper
//! (running in the init userns, where it holds `CAP_SETGID`) writes A's
//! `gid_map`, before A proceeds to fork the PID-1 grandchild and exec. Because
//! `Command::spawn` blocks the parent until A execs, kenneld services the pause
//! on a separate thread (`gid-map-handshake-design`, design (a)). This module is
//! the two-pipe primitive that carries the exchange:
//!
//! * A → servicer: a 4-byte **ready** signal carrying A's pid.
//! * servicer → A: a 1-byte **ack** (proceed / abort).
//!
//! # Why nix here
//!
//! These are four trivial syscalls (`pipe2`/`poll`/`read`/`write`). Rather than
//! own the `unsafe` for them, this module uses nix's safe wrappers
//! (`nix::unistd::{pipe2, read, write}` and `nix::poll`) — the §4 "prefer a vetted
//! crate to our own `unsafe`" rule. The cancellable wait genuinely needs `poll`,
//! so the crate enables nix's `poll` feature (it pulls no new dependency); the
//! module is itself `unsafe`-free, which keeps `kennel-spawn`
//! `#![forbid(unsafe_code)]` for free.
//!
//! # Threat bearing
//!
//! Indirect: the handshake is what lets the `gid_map` write happen in the
//! privileged helper rather than by relaxing the spawn's privilege (§7.2.8,
//! T1.6). This module carries no policy; it only moves bytes between two
//! cooperating local processes that already share a trust domain (kenneld and
//! its own spawn child).

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};

/// The ack byte the servicer sends when the privileged step succeeded and A may
/// proceed.
pub const ACK_PROCEED: u8 = 1;

/// The ack byte the servicer sends when the privileged step failed and A must
/// abort the spawn fail-closed.
pub const ACK_ABORT: u8 = 0;

/// Create a close-on-exec anonymous pipe, returned as `(read end, write end)`.
///
/// Close-on-exec so the fds never leak into the execed workload: A (which holds
/// the ends through the handshake) never execs — it becomes the tiny init — and
/// the PID-1 grandchild that does exec drops them on `execve`.
///
/// # Errors
///
/// The OS error if `pipe2(2)` fails (e.g. the process fd table is full).
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    // nix::unistd::pipe2 hands back the two ends as `OwnedFd`s already (RAII close),
    // so there is no raw fd to adopt — the whole call is safe.
    Ok(nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?)
}

/// Send a 4-byte native-endian `pid` (the ready signal) on `fd`.
///
/// # Errors
///
/// The OS error if the write fails (e.g. the peer closed the read end).
pub fn send_ready(fd: BorrowedFd<'_>, pid: u32) -> io::Result<()> {
    write_all(fd, &pid.to_ne_bytes())
}

/// Send a single ack `byte` on `fd` ([`ACK_PROCEED`] or [`ACK_ABORT`]).
///
/// # Errors
///
/// The OS error if the write fails.
pub fn send_ack(fd: BorrowedFd<'_>, byte: u8) -> io::Result<()> {
    write_all(fd, &[byte])
}

/// Wait for the 1-byte ack on `fd`.
///
/// Returns `Ok(Some(byte))` with the ack, or `Ok(None)` if the peer closed the
/// write end without sending one (EOF) — which the caller treats as an aborted
/// handshake (fail-closed), the same as [`ACK_ABORT`].
///
/// # Errors
///
/// The OS error if the read fails for a reason other than EOF.
pub fn recv_ack(fd: BorrowedFd<'_>) -> io::Result<Option<u8>> {
    let mut buf = [0u8; 1];
    if read_exact(fd, &mut buf)? {
        Ok(Some(buf[0]))
    } else {
        Ok(None)
    }
}

/// Wait for the 4-byte ready signal (a pid) on `fd`, waking every `tick_ms`
/// milliseconds to check `cancel`.
///
/// Returns `Ok(Some(pid))` once the signal arrives. Returns `Ok(None)` if
/// `cancel` is observed set first, or if the peer closes the pipe before sending
/// the full signal (EOF). The cancellable poll exists because the parent keeps a
/// copy of the *write* end alive (inside `Command`'s stored `pre_exec` closure),
/// so the servicer cannot rely on EOF to wake it if the spawn child dies before
/// signalling; the caller sets `cancel` once `Command::spawn` has returned an
/// error. The tick also bounds the wait against a hung privileged step.
///
/// # Errors
///
/// The OS error if `poll`/`read` fails for a reason other than `EINTR` or EOF.
pub fn recv_ready_cancellable(
    fd: BorrowedFd<'_>,
    cancel: &AtomicBool,
    tick_ms: i32,
) -> io::Result<Option<u32>> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
        // A negative tick means "block indefinitely" (libc poll convention), which
        // PollTimeout spells `NONE`; any value >= -1 converts infallibly.
        let timeout = PollTimeout::try_from(tick_ms.max(-1)).unwrap_or(PollTimeout::NONE);
        let ready = match nix::poll::poll(&mut fds, timeout) {
            Ok(ready) => ready,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        if ready == 0 {
            // Timeout: re-check `cancel` and poll again.
            continue;
        }
        let mut buf = [0u8; 4];
        return if read_exact(fd, &mut buf)? {
            Ok(Some(u32::from_ne_bytes(buf)))
        } else {
            // Readable but EOF before a full signal: the peer is gone.
            Ok(None)
        };
    }
}

/// Write the whole of `buf` to `fd`, retrying short writes and `EINTR`.
fn write_all(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<()> {
    let mut rest = buf;
    while !rest.is_empty() {
        match nix::unistd::write(fd, rest) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => rest = rest.get(written..).unwrap_or(&[]),
            Err(Errno::EINTR) => {} // interrupted before any byte moved: retry
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes from `fd`. Returns `Ok(true)` when the buffer
/// was filled, `Ok(false)` on EOF before it could be (peer closed the pipe).
fn read_exact(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let dst = buf.get_mut(filled..).unwrap_or(&mut []);
        match nix::unistd::read(fd, dst) {
            Ok(0) => return Ok(false), // EOF before the buffer was filled
            Ok(got) => filled = filled.saturating_add(got),
            Err(Errno::EINTR) => {} // interrupted before any byte moved: retry
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn ready_and_ack_round_trip_across_two_pipes() {
        // The real shape: A signals ready+pid on one pipe and waits for the ack on
        // the other; the servicer reads the pid and acks. Exercised here with a
        // thread standing in for A, in one process (no privilege needed).
        let (ready_r, ready_w) = pipe_cloexec().expect("ready pipe");
        let (proceed_r, proceed_w) = pipe_cloexec().expect("proceed pipe");

        let a = std::thread::spawn(move || {
            send_ready(ready_w.as_fd(), 4242).expect("send ready");
            recv_ack(proceed_r.as_fd()).expect("recv ack")
        });

        let cancel = AtomicBool::new(false);
        let pid = recv_ready_cancellable(ready_r.as_fd(), &cancel, 50).expect("recv ready");
        assert_eq!(pid, Some(4242), "the servicer reads A's pid");
        send_ack(proceed_w.as_fd(), ACK_PROCEED).expect("send ack");

        assert_eq!(
            a.join().expect("join"),
            Some(ACK_PROCEED),
            "A receives the proceed ack"
        );
    }

    #[test]
    fn recv_ready_returns_none_when_cancelled() {
        // With the write end held open (no EOF) and no pid ever sent, a set cancel
        // flag is what wakes the servicer — proving it does not rely on EOF.
        let (ready_r, _ready_w) = pipe_cloexec().expect("pipe");
        let cancel = AtomicBool::new(true);
        let got = recv_ready_cancellable(ready_r.as_fd(), &cancel, 50).expect("recv");
        assert_eq!(got, None, "a set cancel flag aborts the wait");
    }

    #[test]
    fn recv_ready_returns_none_on_eof() {
        // Peer closes the write end without signalling: EOF surfaces as None.
        let (ready_r, ready_w) = pipe_cloexec().expect("pipe");
        drop(ready_w);
        let cancel = AtomicBool::new(false);
        let got = recv_ready_cancellable(ready_r.as_fd(), &cancel, 50).expect("recv");
        assert_eq!(got, None, "EOF before a full ready signal is None");
    }

    #[test]
    fn recv_ack_returns_none_on_eof() {
        // Peer closes the proceed end without acking: EOF surfaces as None, which
        // the caller treats as abort.
        let (proceed_r, proceed_w) = pipe_cloexec().expect("pipe");
        drop(proceed_w);
        assert_eq!(
            recv_ack(proceed_r.as_fd()).expect("recv"),
            None,
            "EOF is a None ack"
        );
    }
}
