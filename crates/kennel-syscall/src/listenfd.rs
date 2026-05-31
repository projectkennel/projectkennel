//! Adopting a socket-activated listener fd (systemd `sd_listen_fds`).
//!
//! When kenneld is started by socket activation, systemd has already created and
//! bound the listening socket and passes it as fd `SD_LISTEN_FDS_START` (3),
//! setting `LISTEN_PID`/`LISTEN_FDS`. Adopting a numbered fd needs one reviewed
//! `unsafe` (`OwnedFd::from_raw_fd`); the rest is environment parsing.

use std::os::fd::{FromRawFd, OwnedFd};

/// The first fd systemd passes for socket activation.
const SD_LISTEN_FDS_START: i32 = 3;

/// Take the socket-activation listener fd, if this process was socket-activated
/// (`LISTEN_PID` names us and `LISTEN_FDS >= 1`). Returns the single passed
/// listener; multiple passed fds are not used.
///
/// Consumes the `LISTEN_*` environment so descendants do not inherit it. Returns
/// `None` when not socket-activated, so the caller falls back to binding its own.
#[must_use]
pub fn take_listener() -> Option<OwnedFd> {
    let listen_pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if listen_pid != std::process::id() {
        return None;
    }
    let listen_fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if listen_fds < 1 {
        return None;
    }
    // Clear so spawned workloads do not see a stale activation environment.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    // SAFETY: under socket activation systemd guarantees fd SD_LISTEN_FDS_START
    // is an open listening socket transferred to us; we take ownership exactly
    // once (this function clears the environment so it cannot run twice).
    Some(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) })
}
