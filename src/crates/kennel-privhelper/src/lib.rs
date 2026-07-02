//! Project Kennel privileged-operation helper — library core.
//!
//! # Purpose
//!
//! The single privileged component of Project Kennel. Invoked per operation
//! (never long-lived), it reads a request, validates that the request falls
//! within Project Kennel's reserved scope, performs the privileged operation,
//! and exits. The privileged operations are: adding and removing per-kennel
//! loopback addresses, and creating and deleting per-kennel cgroups
//! (Kennel book Vol 2 ch.2 (Process and Privilege Model), 02-6-ipc.md).
//!
//! This library holds the parts that are platform-independent and fully
//! testable on any host: principally the request *validation* core
//! ([`validate`]). The privileged-syscall execution and the stdin/stdout IPC
//! framing are Linux-only and live in the binary (`main.rs`); they are not yet
//! implemented.
//!
//! # Invariants
//!
//! - Every field of every request is validated before any privileged syscall
//!   (Kennel book Vol 1 ch.14 (Trust and Consent), boundary 1). The helper does not
//!   trust the caller's claim that a request is in scope.
//! - Requests outside the reserved address ranges or the `kennel/` cgroup
//!   hierarchy are refused with a structured error; no privileged syscall runs.
//!
//! # Threat bearing
//!
//! Defends against T1.6 (lateral movement: a hostile caller cannot direct the
//! helper outside the reserved scope) and T3.1 (setuid escalation: the helper
//! is small, refuses out-of-scope requests, and bounds the privileged surface
//! to one validated operation).
//!
//! # Non-goals
//!
//! Does not resolve policy, manage daemons, or run as a daemon. Privilege is
//! transient: one validated operation per invocation.

#![forbid(unsafe_code)]

/// The bpffs mount root for a user's egress-BPF map pins: `/run/user/<uid>/kennel/bpf`.
///
/// Shared by the factory (which mounts the bpffs here, holding `cap_sys_admin`) and the
/// `kennel-privhelper-bpf` sub-helper (which pins into it), and matching `kenneld`'s
/// `bpf_audit::pin_dir_for`, so all three agree on the path without it crossing the wire.
#[must_use]
pub fn bpf_pin_root(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/kennel/bpf"))
}

pub mod addr;
pub mod client;
pub mod construct;
pub mod exec;
pub mod validate;
pub mod wire;
