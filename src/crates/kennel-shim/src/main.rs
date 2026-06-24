//! `kennel` — the unified command shim (W10).
//!
//! The one name a user or agent types, in either context. It holds **no authority** and does no
//! work of its own: it detects context and `exec`s the right execution unit, replacing itself.
//!
//! - **`/usr/libexec/kennel/host`** — the dynamically-linked host execution unit (the operator
//!   surface: `run` a first kennel, `policy`, `list`, `oci`, …).
//! - **`/usr/libexec/kennel-facades/spawn`** — the statically-linked in-cage spawn-requester (`run` a
//!   sibling over Node 0 `SPAWN`, `caps`).
//!
//! Context is **construction, not a flag**, and detection is **try-then-fall-back**: the shim execs
//! the host unit first; in a constructed kennel that exec fails — the host unit is unreachable
//! (absent from the view and/or not in `exec.allow`, §4.2 construction-by-absence) — so the shim
//! falls through to the in-cage spawn unit. Host-side the host unit execs and replaces the shim, so
//! the spawn unit is never reached.
//!
//! The failure *is* the signal, which makes correctness independent of how the host unit is kept out
//! of a cage (unallowed today; absent once the host-side `/usr/libexec/kennel` tree is blacklisted
//! from views). Dispatch correctness is therefore **ergonomic**, not a security boundary: a wrong
//! guess cannot reach host authority, because the host unit is unreachable from inside regardless.
//! The shim is built static so the single artifact runs host-side and in-cage alike.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitCode};

/// The dynamically-linked host execution unit — reachable host-side, unreachable from a cage (the
/// host `/usr/libexec/kennel` tree is blacklisted from constructed views, W10).
const HOST_UNIT: &str = "/usr/libexec/kennel/host";
/// The statically-linked in-cage spawn-requester execution unit, in the in-cage facade directory.
const SPAWN_UNIT: &str = "/usr/libexec/kennel-facades/spawn";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // `exec` replaces this process on success and only returns on failure. Try the host unit; in a
    // cage it is unreachable (unallowed/absent), so the exec fails and we fall through to the spawn
    // unit. A wrong guess cannot reach host authority — the failure to exec it is exactly the point.
    let host_err = Command::new(HOST_UNIT).args(&args).exec();
    let spawn_err = Command::new(SPAWN_UNIT).args(&args).exec();
    eprintln!("kennel: no execution unit reachable (host: {host_err}; spawn: {spawn_err})");
    ExitCode::FAILURE
}
