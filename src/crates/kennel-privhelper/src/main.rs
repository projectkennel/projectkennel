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
use std::os::fd::AsFd as _;
use std::process::ExitCode;

use kennel_privhelper::wire::{
    EgressPayload, Op, Request, Response, Status, REQUEST_LEN,
};
use kennel_privhelper::{alloc, construct, exec};

fn main() -> ExitCode {
    // Scrub the inherited environment before anything else. The helper runs privileged and
    // takes no decision from the environment — identity is the kernel-stamped real uid and
    // trust comes from root-owned config/allocation files — so a caller-controlled variable
    // must not steer its runtime (panic verbosity, allocator tuning) nor leak onward (sec
    // review: ambient environment). The kernel already strips LD_*; this clears the rest.
    // `vars_os` is a snapshot, so removing during iteration is sound.
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }

    // The factory mode (`07-2`): kenneld invokes `kennel-privhelper construct` with a
    // SOCK_SEQPACKET socket as stdin. It is long-lived (stays as the construction child's
    // parent) and passes fds, so it does not use the one-shot stdin/stdout framing below.
    if std::env::args().nth(1).as_deref() == Some("construct") {
        // Gate the factory on the caller holding a subkennel allocation, exactly as every
        // one-shot op is gated below: an unallocated user performs no privileged operation
        // (module docs). The factory replies over the SEQPACKET, not the stdout framing, so a
        // refusal is a non-zero exit — kenneld sees the helper die without sending a pid.
        if alloc::load(kennel_syscall::unistd::real_uid()).is_none() {
            eprintln!(
                "kennel-privhelper: refusing `construct`: caller has no /etc/kennel/subkennel allocation"
            );
            return ExitCode::from(1);
        }
        construct::run_construct(std::io::stdin().as_fd());
    }
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return respond(Response::protocol());
    }
    // The fixed request is always the first REQUEST_LEN bytes.
    let head = buf.get(..REQUEST_LEN).unwrap_or(&buf);
    let Ok(request) = Request::decode(head) else {
        return respond(Response::protocol());
    };
    // SetupEgress carries a variable-length payload appended after the fixed request.
    let tail = buf.get(REQUEST_LEN..).unwrap_or(&[]);
    let egress = if request.op == Op::SetupEgress {
        match EgressPayload::decode(tail) {
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
