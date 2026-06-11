//! `kennel-akc` — the bastion's root-owned `AuthorizedKeysCommand` (§7.10.7).
//!
//! OpenSSH `sshd` invokes this on every bastion authentication, passing the offered
//! public key as `%t %k` (its type and base64 blob). The helper asks the **running**
//! `kenneld` — over the per-user control socket — for the forced-command
//! `authorized_keys` line(s) bound to that key, and prints them on stdout for sshd.
//!
//! The answer is the daemon's live, verified edge state, never a file the
//! unprivileged bastion user could rewrite. That is the whole point of the design:
//! the binary is installed **root-owned** so OpenSSH's safe-path check accepts it,
//! and the bindings exist only in `kenneld`'s memory, sourced from signed policy.
//! Treating the running daemon as the source of truth is the matching posture — it
//! is the same trusted process that builds and seals every kennel.
//!
//! Fail-closed: any error — no daemon, missing/garbled arguments, a protocol
//! failure, an unexpected response — prints nothing and exits non-zero, so sshd
//! sees no authorised key and refuses the login.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use kenneld::control::{self, Request, Response};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        // Fail closed and silent: no line on stdout ⇒ sshd authorises nothing.
        Err(_) => ExitCode::FAILURE,
    }
}

fn run() -> io::Result<()> {
    // sshd passes the offered key as `%t %k` (type then base64 blob). Rejoin whatever
    // argv we were handed into the canonical "<type> <base64>" line kenneld matches on
    // — robust whether configured as `%t %k` (two args) or a single combined token.
    let offered = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if offered.trim().is_empty() {
        return Err(io::Error::other("no key offered"));
    }

    let mut conn = UnixStream::connect(socket_path())?;
    control::send_request(&mut conn, &Request::AuthorizedKeys { key: offered })?;
    // Any reply other than AuthorizedKeys (e.g. an Error) ⇒ refuse the key.
    let Response::AuthorizedKeys { lines } = control::recv_response(&mut conn)? else {
        return Err(io::Error::other("unexpected control response"));
    };

    let mut out = io::stdout().lock();
    for line in &lines {
        out.write_all(line.as_bytes())?;
        if !line.ends_with('\n') {
            out.write_all(b"\n")?;
        }
    }
    out.flush()
}

/// kenneld's control socket: the `KENNEL_CONTROL_SOCK` override (tests / non-standard
/// layouts), else the per-user default under `$XDG_RUNTIME_DIR` ([`kenneld::socket`]).
fn socket_path() -> PathBuf {
    std::env::var_os("KENNEL_CONTROL_SOCK").map_or_else(kenneld::socket::socket_path, PathBuf::from)
}
