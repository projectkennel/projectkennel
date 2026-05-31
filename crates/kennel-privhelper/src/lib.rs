//! Project Kennel privileged-operation helper — library core.
//!
//! # Purpose
//!
//! The single privileged component of Project Kennel. Invoked per operation
//! (never long-lived), it reads a request, validates that the request falls
//! within Project Kennel's reserved scope, performs the privileged operation,
//! and exits. The privileged operations are: adding and removing per-kennel
//! loopback addresses, and creating and deleting per-kennel cgroups
//! (architecture/01-process-model.md, 02-4-ipc.md).
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
//!   (architecture/04-trust-boundaries.md, boundary 1). The helper does not
//!   trust the caller's claim that a request is in scope.
//! - Requests outside the reserved address ranges or the `kennel/` cgroup
//!   hierarchy are refused with a structured error; no privileged syscall runs.
//!
//! # Threat bearing
//!
//! Defends against T6 (lateral movement: a hostile caller cannot direct the
//! helper outside the reserved scope) and T19 (setuid escalation: the helper
//! is small, refuses out-of-scope requests, and bounds the privileged surface
//! to one validated operation).
//!
//! # Non-goals
//!
//! Does not resolve policy, manage daemons, or run as a daemon. Privilege is
//! transient: one validated operation per invocation.

#![forbid(unsafe_code)]

pub mod alloc;
pub mod exec;
pub mod validate;
pub mod wire;
