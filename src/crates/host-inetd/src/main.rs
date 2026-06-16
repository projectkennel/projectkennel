//! `host-inetd`: the per-kennel inbound **BIND delegate** (the reverse of `host-netproxy`).
//!
//! `kenneld` owns the bind decision (`docs/design/07-5-network.md` §7.5.7): the `[net.bpf].bind`
//! cgroup ACL already gated the workload's `bind()`. This binary binds one owner-only `AF_UNIX`
//! command socket — whose path is the sole argument, supplied by `kenneld` — and for each
//! registration `kenneld` sends `(ip, port)`, it binds that `ip:port` on the host loopback,
//! `accept()`s, and pushes each accepted connection's fd back to `kenneld` over the same socket. No
//! TCP dialer, no resolver, no policy, no config file.
//!
//! All the logic is in the library (`host_inetd::listen`); `main` binds the socket and serves.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: host-inetd <command-socket-path>");
        return ExitCode::from(2);
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("host-inetd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Bind the owner-only command socket and serve inbound registrations.
///
/// Returns only on a fatal error; `serve` loops until the listener fails.
fn run(sock: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(sock); // clear a stale socket from a prior run
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    host_inetd::listen::serve(&listener);
    Ok(())
}
