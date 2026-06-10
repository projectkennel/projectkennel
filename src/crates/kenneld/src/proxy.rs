//! Launching the per-kennel egress dial delegate.
//!
//! kenneld owns the egress decision (`crate::inet`): it resolves names under policy, re-checks the
//! resolved address, pins the vetted IPs, and emits the `net.egress` audit record itself. The
//! `kennel-netproxy` delegate is a glorified `netcat(1)` — it binds one owner-only `AF_UNIX` command
//! socket (path supplied here) and, per command kenneld sends, dials a pinned address and splices.
//! No config file: the socket path is the binary's sole argument.

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Launch the netproxy `binary` to serve the conduit command socket at `command_socket`.
///
/// Spawns it as a per-kennel child with no inherited stdio (its stderr goes to the daemon's). The
/// caller owns the returned [`Child`] and must reap/kill it on teardown.
///
/// # Errors
///
/// An OS error if the delegate process cannot be spawned.
pub fn spawn(binary: &Path, command_socket: &Path) -> std::io::Result<Child> {
    Command::new(binary)
        .arg(command_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
}
