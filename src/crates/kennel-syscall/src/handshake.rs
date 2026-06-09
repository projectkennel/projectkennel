//! A tiny anonymous-pipe **ready/ack** handshake between two cooperating local processes.
//!
//! # Purpose
//!
//! The live user is the privhelper **factory**'s clone sequence (`kennel-privhelper`'s
//! `construct.rs`): the construction child is `clone(CLONE_NEWUSER|…)`'d with **no** identity
//! map yet, so it cannot `set_uid(0)` into the kennel's uid 0 until the parent has written its
//! `/proc/<pid>/uid_map` + `gid_map` (you cannot become a uid the user namespace has not mapped).
//! The parent writes the maps, then sends `ACK_PROCEED`; the child blocks on the read until then
//! — the canonical bubblewrap/runc map-write handshake. This module is that one-byte ack carried
//! over a close-on-exec pipe.
//!
//! It was originally written for the deferred-`gid_map` exchange of the legacy unprivileged
//! spawn (§7.4.8) — which had a richer servicer side (a pid "ready" signal + a cancellable
//! `poll` wait). That path is **gone** (the factory now writes the full identity map, granted
//! groups included, in one shot), and the servicer machinery with it; the plain ack primitive is
//! reused, unchanged, for the maps-written handshake above.
//!
//! # Why nix here
//!
//! These are three trivial syscalls (`pipe2`/`read`/`write`). Rather than own the `unsafe` for
//! them, this module uses nix's safe wrappers — the §4 "prefer a vetted crate to our own
//! `unsafe`" rule. The module is itself `unsafe`-free.
//!
//! # Threat bearing
//!
//! Indirect: it carries no policy, only bytes between two processes that already share a trust
//! domain. The map-write sync it gates is what lets the privileged map write and the child's
//! drop into the kennel's uid 0 happen in the right order.

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

use nix::errno::Errno;

/// The ack byte the parent sends once the privileged step (writing the child's userns identity
/// maps) succeeded and the child may proceed to `set_uid(0)`.
pub const ACK_PROCEED: u8 = 1;

/// Create a close-on-exec anonymous pipe, returned as `(read end, write end)`.
///
/// Close-on-exec so the fds never leak into the execed workload: the construction child holds
/// the ends through the handshake and then `fexecve`s `kennel-init`, which drops them.
///
/// # Errors
///
/// The OS error if `pipe2(2)` fails (e.g. the process fd table is full).
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    // nix::unistd::pipe2 hands back the two ends as `OwnedFd`s already (RAII close),
    // so there is no raw fd to adopt — the whole call is safe.
    Ok(nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?)
}

/// Send a single ack `byte` on `fd` (the parent sends [`ACK_PROCEED`]; any other byte, or EOF,
/// the child reads as abort).
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
/// handshake (fail-closed).
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
    fn ack_round_trips_across_a_pipe() {
        // The maps-written handshake's shape: the parent writes the child's identity maps, then
        // sends ACK_PROCEED; the child blocks in recv_ack until then. One process, no privilege.
        let (proceed_r, proceed_w) = pipe_cloexec().expect("proceed pipe");
        let child = std::thread::spawn(move || recv_ack(proceed_r.as_fd()).expect("recv ack"));
        send_ack(proceed_w.as_fd(), ACK_PROCEED).expect("send ack");
        assert_eq!(
            child.join().expect("join"),
            Some(ACK_PROCEED),
            "the child receives the proceed ack"
        );
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
