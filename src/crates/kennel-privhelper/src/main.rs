//! Project Kennel privileged-operation helper — binary entry point.
//!
//! Reads one fixed-layout [`Request`](kennel_privhelper::wire::Request) from
//! stdin, validates it, performs the single privileged operation, writes a
//! [`Response`](kennel_privhelper::wire::Response) to stdout, and exits. The
//! helper is invoked per operation and never persists privilege.
//!
//! The reserved scope is **per user**, *derived from the caller's kernel-trusted
//! real UID* (setuid leaves it as the invoking user) — the v6 loopback subnet is
//! a hash of the uid ([`kennel_privhelper::addr`]), never trusting the request or
//! the caller-controlled environment. There is no allocation file: who may run
//! the helper at all is governed by its binary permissions, as for any setcap
//! binary.

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::process::ExitCode;

use kennel_privhelper::validate::ReservedScope;
use kennel_privhelper::wire::{Request, Response, Status, REQUEST_LEN};
use kennel_privhelper::{construct, exec};

fn main() -> ExitCode {
    // Scrub the inherited environment before anything else. The helper runs privileged and
    // takes no decision from the environment — identity is the kernel-stamped real uid and
    // trust comes from root-owned config files — so a caller-controlled variable
    // must not steer its runtime (panic verbosity, allocator tuning) nor leak onward (sec
    // review: ambient environment). The kernel already strips LD_*; this clears the rest.
    // `vars_os` is a snapshot, so removing during iteration is sound.
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }

    // The factory mode (`07-2`): kenneld invokes `kennel-privhelper construct` with a
    // SOCK_SEQPACKET socket as stdin. It passes fds (so not the one-shot stdin/stdout framing
    // below) and exits as soon as it has built the kennel and reported the init pid — it is not
    // a reaper proxy; kenneld (a subreaper) adopts and waits the orphaned `kennel-bin-init`.
    if std::env::args().nth(1).as_deref() == Some("construct") {
        construct::run_construct(std::io::stdin().as_fd());
    }

    // Release an exclusive host-bind over-mount (§2.7): `exclusive-unmount <host>`. The over-mount
    // is performed during construction; only the *release* is a standalone op, because it happens
    // at a different time — teardown, or `kennel release` recovery after a crash. Both are delegated
    // to the `{sys_admin}` kennel-privhelper-mounts sub-helper (the factory holds no
    // `CAP_SYS_ADMIN`); this op forwards to its `unmount` and passes its exit code through.
    let arg1 = std::env::args().nth(1);
    if arg1.as_deref() == Some("exclusive-unmount") {
        let Some(path) = std::env::args().nth(2) else {
            eprintln!("kennel-privhelper: `exclusive-unmount` needs a host path argument");
            return ExitCode::from(2);
        };
        let helper = match kennel_lib_config::Deployment::load() {
            Ok(d) => d.privhelper_mounts(),
            Err(e) => {
                eprintln!("kennel-privhelper: resolve kennel-privhelper-mounts: {e}");
                return ExitCode::from(3);
            }
        };
        return ExitCode::from(
            match std::process::Command::new(helper)
                .arg("unmount")
                .arg(&path)
                .status()
            {
                Ok(s) => u8::try_from(s.code().unwrap_or(3)).unwrap_or(3),
                Err(e) => {
                    eprintln!("kennel-privhelper: exec kennel-privhelper-mounts: {e}");
                    3
                }
            },
        );
    }

    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return respond(Response::protocol());
    }
    // The one-shot path serves a single fixed-size request — the teardown `DelAddr` (the
    // address add + egress attach are folded into the `construct` op above).
    let head = buf.get(..REQUEST_LEN).unwrap_or(&buf);
    let Ok(request) = Request::decode(head) else {
        return respond(Response::protocol());
    };
    // The caller's real UID is the trusted identity; the reserved scope derives from it.
    let scope = ReservedScope::new(kennel_lib_syscall::unistd::real_uid());
    respond(exec::perform(&request, Some(&scope)))
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
