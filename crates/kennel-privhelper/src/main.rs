//! Project Kennel privileged-operation helper — binary entry point.
//!
//! Reads one fixed-layout [`Request`](kennel_privhelper::wire::Request) from
//! stdin, validates it, performs the single privileged operation, writes a
//! [`Response`](kennel_privhelper::wire::Response) to stdout, and exits. The
//! helper is invoked per operation and never persists privilege.
//!
//! Address operations need the installation's reserved scope (the `tag` and
//! 40-bit ULA GID). These are read from a **root-owned** file at
//! `/etc/kennel/scope` (6 bytes: `tag` then 5 GID bytes) — a trusted source
//! independent of the (unprivileged) caller, never from the request or the
//! caller-controlled environment. Cgroup operations do not need it.

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use kennel_privhelper::exec;
use kennel_privhelper::validate::ReservedScope;
use kennel_privhelper::wire::{Request, Response, Status};

/// The trusted file the installation's reserved scope is read from.
const SCOPE_PATH: &str = "/etc/kennel/scope";

fn main() -> ExitCode {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return respond(Response::protocol());
    }
    let Ok(request) = Request::decode(&buf) else {
        return respond(Response::protocol());
    };
    let scope = load_scope();
    respond(exec::perform(&request, scope.as_ref()))
}

/// Load the reserved scope from the trusted file, if present and well-formed.
fn load_scope() -> Option<ReservedScope> {
    let bytes = std::fs::read(SCOPE_PATH).ok()?;
    if bytes.len() != 6 {
        return None;
    }
    let tag = bytes.first().copied()?;
    let gid: [u8; 5] = bytes.get(1..6).and_then(|s| s.try_into().ok())?;
    Some(ReservedScope::new(tag, gid))
}

/// Write the response and map its status to the process exit code (matching the
/// wire contract: 0 ok, 1 refused, 2 protocol, 3 internal).
fn respond(response: Response) -> ExitCode {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(&response.encode());
    let _ = stdout.flush();
    ExitCode::from(match response.status {
        Status::Ok => 0,
        Status::Refused => 1,
        Status::Protocol => 2,
        Status::Internal => 3,
    })
}
