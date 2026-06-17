//! `host-netproxy`: the per-kennel egress **dial delegate**.
//!
//! `kenneld` owns the egress decision (allow/deny, DNS resolution, address pinning —
//! `docs/design/07-5-network.md` §7.5). This binary is what's left after that: a glorified
//! `netcat(1)`. It binds one owner-only `AF_UNIX` command socket — whose path is the sole argument,
//! supplied by `kenneld` — and for each command `kenneld` sends `(port, pinned IPs)` plus a conduit
//! fd over `SCM_RIGHTS`, it dials the pinned address from the host stack and splices the conduit to
//! it. No TCP listener, no SOCKS5/HTTP server, no resolver, no policy, no config file.
//!
//! All the logic is in the library (`kennel_host_delegate::netproxy::conduit`); `main` binds the socket and serves.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: host-netproxy <command-socket-path>");
        return ExitCode::from(2);
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("host-netproxy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Bind the owner-only command socket and serve the conduit.
///
/// Returns only on a fatal error; `serve_conduit` loops until the listener fails.
fn run(sock: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(sock); // clear a stale socket from a prior run
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    kennel_host_delegate::netproxy::conduit::serve_conduit(&listener);
    Ok(())
}
