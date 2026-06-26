//! `kennel` — the unified command shim (W10).
//!
//! The one name a user or agent types, in either context. It holds **no authority** and does no
//! work of its own: it detects context and `exec`s the right execution unit, replacing itself.
//!
//! ## Host-side keyword dispatch (W10)
//!
//! On the host side, the first argument (keyword) selects the sub-binary:
//!
//! - `kennel run|attach|stop|list|review|release|daemon-reload` → `/usr/libexec/kennel/run`
//! - `kennel policy <verb>` → `/usr/libexec/kennel/policy`
//! - `kennel oci <verb>` → `/usr/libexec/kennel/oci`
//! - `kennel keygen|subkennel|audit` → `/usr/libexec/kennel/misc`
//! - no keyword / `--help` → the shim prints help and exits
//!
//! ## In-cage fallback
//!
//! In a constructed kennel the host units are unreachable (absent from the view and/or not in
//! `exec.allow`, §4.2 construction-by-absence), so the shim falls through to the in-cage spawn
//! unit (`/usr/libexec/kennel-facades/spawn`).
//!
//! Context is **construction, not a flag**, and detection is **try-then-fall-back**: the shim execs
//! the sub-binary first; in a constructed kennel that exec fails — the failure *is* the signal.
//! Host-side the sub-binary execs and replaces the shim, so the spawn unit is never reached.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitCode};

/// The sub-binary directory on the host side.
const HOST_DIR: &str = "/usr/libexec/kennel";
/// The legacy monolith host unit (transition — kept during 0.5.0).
const HOST_UNIT: &str = "/usr/libexec/kennel/host";
/// The statically-linked in-cage spawn-requester execution unit.
const SPAWN_UNIT: &str = "/usr/libexec/kennel-facades/spawn";

/// Map a keyword to the sub-binary name within `HOST_DIR`.
fn keyword_binary(keyword: &str) -> &'static str {
    match keyword {
        // Runtime verbs → kennel-run.
        "run" | "attach" | "stop" | "list" | "review" | "release" | "daemon-reload" => "run",
        // Policy-authoring verbs → kennel-policy.
        "policy" => "policy",
        // OCI substrate verbs → kennel-oci.
        "oci" => "oci",
        // Misc verbs → kennel-misc.
        "keygen" | "subkennel" | "audit" => "misc",
        // Unknown keywords → try the legacy host unit for forward compatibility.
        _ => "host",
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    // No arguments or help request → the shim prints its own help (no exec needed).
    if args.is_empty() {
        print_help();
        return ExitCode::SUCCESS;
    }
    let first = args[0].to_str().unwrap_or("");
    if first == "--help" || first == "-h" || first == "help" {
        print_help();
        return ExitCode::SUCCESS;
    }

    // --- Host-side keyword dispatch ---
    // Try the keyword-specific sub-binary first. If it exists and execs, we're replaced.
    let sub = keyword_binary(first);
    let sub_path = format!("{HOST_DIR}/{sub}");
    let _sub_err = Command::new(&sub_path).args(&args).exec();

    // Sub-binary not found (not yet installed, or wrong platform) → fall back to the
    // monolith host unit (transition path).
    let _host_err = Command::new(HOST_UNIT).args(&args).exec();

    // Host side unreachable → we're in a cage. Try the spawn unit.
    let spawn_err = Command::new(SPAWN_UNIT).args(&args).exec();
    eprintln!("kennel: no execution unit reachable (spawn: {spawn_err})");
    ExitCode::FAILURE
}

/// Print the shim's help — the unified command list. This is the only output the shim
/// produces itself; every verb is dispatched to a sub-binary.
fn print_help() {
    eprintln!("usage: kennel <command> [args...]\n");
    eprintln!("commands:");
    eprintln!("  run               run a command confined by a policy");
    eprintln!("  attach            reattach a terminal to a running kennel");
    eprintln!("  stop              stop a running kennel");
    eprintln!("  list              list running kennels and the service mesh");
    eprintln!("  review            review a workspace's trust manifest");
    eprintln!("  release           release a leaked exclusive over-mount");
    eprintln!("  daemon-reload     re-derive the service catalogue");
    eprintln!("  policy            author, inspect, sign, and check policies");
    eprintln!("  keygen            generate a policy-signing key");
    eprintln!("  subkennel         manage /etc/kennel/subkennel allocations");
    eprintln!("  audit             show a kennel's audit log");
    eprintln!("  oci               build and run OCI image substrates");
    eprintln!("\nrun `kennel <command> --help` for a command's usage.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_dispatch_maps_to_the_right_binary() {
        assert_eq!(keyword_binary("run"), "run");
        assert_eq!(keyword_binary("attach"), "run");
        assert_eq!(keyword_binary("stop"), "run");
        assert_eq!(keyword_binary("list"), "run");
        assert_eq!(keyword_binary("review"), "run");
        assert_eq!(keyword_binary("release"), "run");
        assert_eq!(keyword_binary("daemon-reload"), "run");
        assert_eq!(keyword_binary("policy"), "policy");
        assert_eq!(keyword_binary("oci"), "oci");
        assert_eq!(keyword_binary("keygen"), "misc");
        assert_eq!(keyword_binary("subkennel"), "misc");
        assert_eq!(keyword_binary("audit"), "misc");
        // Unknown → host (forward-compatible fallback).
        assert_eq!(keyword_binary("future-verb"), "host");
    }
}
