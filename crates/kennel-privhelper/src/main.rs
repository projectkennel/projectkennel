//! Project Kennel privileged-operation helper — binary entry point.
//!
//! The library core ([`kennel_privhelper`]) holds the platform-independent
//! logic. This binary will, on Linux, frame stdin/stdout IPC and perform the
//! privileged syscalls. Those layers are not yet implemented; `main` reports
//! that honestly rather than pretending to service a request.

#![forbid(unsafe_code)]

use std::process::ExitCode;

/// Exit codes, matching the privhelper wire contract
/// (architecture/02-4-ipc.md): 0 ok, 1 refused, 2 protocol error, 3 internal.
const EXIT_PROTOCOL_ERROR: u8 = 2;

fn main() -> ExitCode {
    eprintln!(
        "kennel-privhelper: the IPC and privileged-execution layers are not yet \
         implemented; this binary cannot service a request. The validation core \
         is implemented and tested (cargo test -p kennel-privhelper)."
    );
    ExitCode::from(EXIT_PROTOCOL_ERROR)
}
