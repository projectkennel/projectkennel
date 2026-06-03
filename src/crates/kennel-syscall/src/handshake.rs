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
//! # Why libc here
//!
//! `kennel-syscall` is the designated `unsafe` crate (§4); these are four trivial
//! syscalls (`pipe2`/`poll`/`read`/`write`) wrapped with the mandated `SAFETY:`
//! comments, exactly as [`crate::netlink`] does for its sockets. nix does not
//! enable its `poll` module under our feature set, and the cancellable wait
//! genuinely needs `poll`, so owning these here keeps `kennel-spawn`
//! `#![forbid(unsafe_code)]` without widening the nix feature surface.
//!
//! # Threat bearing
//!
//! Indirect: the handshake is what lets the `gid_map` write happen in the
//! privileged helper rather than by relaxing the spawn's privilege (§7.2.8,
//! T1.6). This module carries no policy; it only moves bytes between two
//! cooperating local processes that already share a trust domain (kenneld and
//! its own spawn child).

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

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
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` writes exactly two fds into the 2-element array and returns
    // 0 on success / -1 on error (writing nothing on error). `O_CLOEXEC` is a
    // valid flag. No aliasing: `fds` is a fresh local.
    //
    // INVARIANTS UPHELD: on success the two ints are fresh kernel fds we then take
    // sole ownership of via `OwnedFd`; on failure we own nothing and return early.
    //
    // FAILURE MODE: rc < 0 → return the errno; the array is untouched, no fd leaks.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let [rfd, wfd] = fds;
    // SAFETY: `pipe2` returned 0, so `rfd`/`wfd` are open, owned fds; we transfer
    // ownership to the two `OwnedFd`s, which close them on drop. They are distinct.
    let read = unsafe { OwnedFd::from_raw_fd(rfd) };
    let write = unsafe { OwnedFd::from_raw_fd(wfd) };
    Ok((read, write))
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
pub fn recv_ready_cancellable(fd: BorrowedFd<'_>, cancel: &AtomicBool, tick_ms: i32) -> io::Result<Option<u32>> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: `&mut pfd` points at one valid, initialised `pollfd`; `nfds = 1`
        // matches the single element. `poll` only reads `fd`/`events` and writes
        // `revents`. `tick_ms` is a plain timeout.
        //
        // FAILURE MODE: rc < 0 → errno; `EINTR` retries, anything else propagates.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, tick_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
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
        // SAFETY: `rest` is a valid initialised slice of `rest.len()` bytes; we
        // pass its pointer and length to `write`, which only reads from it. `fd`
        // is a borrowed, open fd for the lifetime of the call.
        //
        // FAILURE MODE: n < 0 → errno (EINTR retries); n == 0 → WriteZero.
        let n = unsafe { libc::write(fd.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let written = usize::try_from(n).unwrap_or(0);
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        rest = rest.get(written..).unwrap_or(&[]);
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes from `fd`. Returns `Ok(true)` when the buffer
/// was filled, `Ok(false)` on EOF before it could be (peer closed the pipe).
fn read_exact(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let dst = buf.get_mut(filled..).unwrap_or(&mut []);
        // SAFETY: `dst` is a valid initialised mutable slice of `dst.len()` bytes;
        // `read` writes at most that many. `fd` is a borrowed, open fd.
        //
        // FAILURE MODE: n < 0 → errno (EINTR retries); n == 0 → EOF (return false).
        let n = unsafe { libc::read(fd.as_raw_fd(), dst.as_mut_ptr().cast(), dst.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let got = usize::try_from(n).unwrap_or(0);
        if got == 0 {
            return Ok(false);
        }
        filled = filled.saturating_add(got);
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

        assert_eq!(a.join().expect("join"), Some(ACK_PROCEED), "A receives the proceed ack");
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
        assert_eq!(recv_ack(proceed_r.as_fd()).expect("recv"), None, "EOF is a None ack");
    }
}
