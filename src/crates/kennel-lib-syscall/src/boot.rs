//! The kennel **boot-sync** socket: a one-byte handshake that makes the binder bus startup
//! deterministic, with no retry loops.
//!
//! # Why
//!
//! `kennel-bin-init` pulls its supervision-half over binder node 0, which `kenneld` claims by opening
//! the kennel's binderfs via `/proc/<init>/root`. That open only succeeds once `kennel-bin-init` has
//! actually `fexecve`'d (a blocked, pre-exec construction child is not reachable that way), so the
//! claim cannot precede the exec — yet the pull must not precede the claim. The factory therefore
//! cannot gate the *exec*; it gates the *pull*, from inside `kennel-bin-init`, over a socket the
//! factory hands it at [`BOOT_SYNC_FD`]:
//!
//! 1. `kennel-bin-init` execs, then sends `READY` and **blocks** before opening the bus.
//! 2. `kenneld` (holding the other end) sees `READY`, opens the now-reachable binderfs, claims
//!    node 0, then sends `GO`.
//! 3. `kennel-bin-init` wakes and pulls — the context manager is already serving (first-try success).
//!
//! Both ends ship from one release, so this module is the single source of the convention.

use std::io;
use std::os::fd::{BorrowedFd, RawFd};

use nix::errno::Errno;

/// Borrow a raw descriptor for the duration of one sync call. Safe for our callers: `kennel-bin-init`
/// passes [`BOOT_SYNC_FD`] (a live inherited fd) and `kenneld` passes a fd it owns.
const fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: the caller guarantees `fd` is open for the duration of the call (an inherited or
    // owned descriptor); we only borrow it for the single write/read below.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// The fixed descriptor for the boot-sync socket.
///
/// The factory places `kennel-bin-init`'s end of the boot-sync socket (a `SOCK_SEQPACKET` pair)
/// here, inherited across the `fexecve` — the sibling of [`crate::pty::PTY_RETURN_FD`].
pub const BOOT_SYNC_FD: RawFd = 4;

/// The fixed descriptor for the **sha256-pinned workload binary** (`07-4` §7.4).
///
/// When the policy pins the workload's digest, kenneld opens the resolved binary, hashes it
/// via `/proc/self/fd`, and passes that exact fd through the construction channel; the factory
/// places it here, inherited across the `fexecve` of `kennel-bin-init`, which `fexecve`s it for
/// the workload — so the bytes that run are the bytes that were hashed (no path relookup, no
/// TOCTOU). Absent when the policy carries no digest pin. Sibling of [`BOOT_SYNC_FD`] /
/// [`crate::pty::PTY_RETURN_FD`].
pub const WORKLOAD_FD: RawFd = 5;

/// The fixed descriptors for **injected workload stdio** (`02-10` §7.12, the non-interactive
/// counterpart of [`crate::pty::PTY_RETURN_FD`]).
///
/// For a non-interactive run, the workload's stdin/stdout/stderr are passed fds — the controller's
/// three stdio fds for a piped `kennel run`, or the spawned-kennel ends of a `SPAWN` channel (the
/// JSON-RPC socketpair, duplicated for stdin+stdout, and the stderr pipe). kenneld passes them
/// through the construction channel; the factory places them here, inherited across the `fexecve`;
/// `kennel-bin-init` `dup2`s them onto 0/1/2 as the final pre-exec step (after the seal, so init's
/// own diagnostics never ride the channel). A pty would impose terminal semantics the byte channel
/// must not have, so this is raw, not a pty. Absent for the interactive (pty) path.
pub const INJECT_STDIN_FD: RawFd = 6;
/// See [`INJECT_STDIN_FD`].
pub const INJECT_STDOUT_FD: RawFd = 7;
/// See [`INJECT_STDIN_FD`].
pub const INJECT_STDERR_FD: RawFd = 8;

/// `kennel-bin-init` → `kenneld`: "I have `fexecve`'d; my binderfs is reachable via `/proc/<me>/root`."
const READY: u8 = 1;
/// `kenneld` → `kennel-bin-init`: "node 0 is claimed and serving — pull now."
const GO: u8 = 2;

/// `kennel-bin-init` side: announce we are up (`READY`) and block until `kenneld` confirms the bus
/// is live (`GO`). Call this after `fexecve` and before opening the binder connection.
///
/// # Errors
///
/// The OS error if the send/recv fails, or other-kind if `kenneld` closed the socket or replied
/// with an unexpected byte (treat as fail-closed — do not pull a bus that may not be there).
pub fn init_await_bus(fd: RawFd) -> io::Result<()> {
    let fd = borrow(fd);
    write_byte(fd, READY)?;
    match read_byte(fd)? {
        Some(GO) => Ok(()),
        _ => Err(io::Error::other(
            "boot-sync: kenneld did not confirm the binder bus is live",
        )),
    }
}

/// `kenneld` side: wait for `kennel-bin-init` to announce it is up (`READY`).
///
/// # Errors
///
/// The OS error if the recv fails, or other-kind on EOF / an unexpected byte.
pub fn await_init_ready(fd: RawFd) -> io::Result<()> {
    match read_byte(borrow(fd))? {
        Some(READY) => Ok(()),
        _ => Err(io::Error::other(
            "boot-sync: kennel-bin-init did not report ready",
        )),
    }
}

/// `kenneld` side: tell `kennel-bin-init` the bus is live (`GO`) — call after claiming node 0.
///
/// # Errors
///
/// The OS error if the send fails.
pub fn signal_bus_live(fd: RawFd) -> io::Result<()> {
    write_byte(borrow(fd), GO)
}

fn write_byte(fd: BorrowedFd<'_>, byte: u8) -> io::Result<()> {
    loop {
        match nix::unistd::write(fd, &[byte]) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn read_byte(fd: BorrowedFd<'_>) -> io::Result<Option<u8>> {
    let mut buf = [0u8; 1];
    loop {
        match nix::unistd::read(fd, &mut buf) {
            Ok(0) => return Ok(None), // EOF: the peer closed without a byte
            Ok(_) => return Ok(Some(buf[0])),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Place the injected-stdio fds onto the workload's 0/1/2.
///
/// The three fds parked at [`INJECT_STDIN_FD`]/[`INJECT_STDOUT_FD`]/[`INJECT_STDERR_FD`] by the
/// factory are `dup3`'d onto 0/1/2, then the source slots are closed so the workload inherits no
/// duplicate channel ends.
///
/// `kennel-bin-init`'s final pre-exec step for a **non-interactive** run — the raw-channel
/// counterpart of the interactive pty setup (`02-10` §7.12). The spawn-template seccomp must permit
/// the `dup3` this performs.
///
/// # Errors
///
/// The OS error if a `dup3` fails.
pub fn place_injected_stdio() -> io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    for (slot, target) in [
        (INJECT_STDIN_FD, 0),
        (INJECT_STDOUT_FD, 1),
        (INJECT_STDERR_FD, 2),
    ] {
        crate::fd::dup_onto(borrow(slot), target)?;
    }
    for slot in [INJECT_STDIN_FD, INJECT_STDOUT_FD, INJECT_STDERR_FD] {
        // SAFETY: the factory placed a live fd at `slot` with no other owner in this process; take
        // ownership to close it (the workload keeps only the 0/1/2 copies). Dropping closes it.
        drop(unsafe { OwnedFd::from_raw_fd(slot) });
    }
    Ok(())
}
