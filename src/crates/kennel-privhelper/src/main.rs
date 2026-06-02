//! Project Kennel privileged-operation helper — binary entry point.
//!
//! Reads one fixed-layout [`Request`](kennel_privhelper::wire::Request) from
//! stdin, validates it, performs the single privileged operation, writes a
//! [`Response`](kennel_privhelper::wire::Response) to stdout, and exits. The
//! helper is invoked per operation and never persists privilege.
//!
//! The reserved scope (tag, ULA GID, resource namespace) is **per user**, the
//! way `/etc/subuid` allocates subordinate ranges. The helper looks up the
//! caller's **real UID** (kernel-trusted; setuid leaves it as the invoking user)
//! in the root-owned `/etc/kennel/subkennel` allocation file — never trusting the
//! request or the caller-controlled environment. A user with no allocation can
//! perform no operation.

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use kennel_privhelper::{alloc, exec};
use kennel_privhelper::wire::{EgressPayload, Op, Request, Response, Status, REQUEST_LEN};

fn main() -> ExitCode {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return respond(Response::protocol());
    }
    // The fixed request is always the first REQUEST_LEN bytes.
    let head = buf.get(..REQUEST_LEN).unwrap_or(&buf);
    let Ok(request) = Request::decode(head) else {
        return respond(Response::protocol());
    };
    // SetupEgress carries a variable-length payload appended after the request.
    let egress = if request.op == Op::SetupEgress {
        match EgressPayload::decode(buf.get(REQUEST_LEN..).unwrap_or(&[])) {
            Ok(p) => Some(p),
            Err(_) => return respond(Response::protocol()),
        }
    } else {
        None
    };
    // The caller's real UID is the trusted identity; look up its allocation.
    let scope = alloc::load(kennel_syscall::unistd::real_uid());
    respond(exec::perform(&request, egress.as_ref(), scope.as_ref()))
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
