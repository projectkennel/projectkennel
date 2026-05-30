//! Project Kennel low-level system primitives.
//!
//! # Purpose
//!
//! `kennel-syscall` is, by architecture (`architecture/02-6-internal-api.md`,
//! `03-crate-decomposition.md`), the *single* crate in the workspace permitted
//! to contain `unsafe`: it will wrap raw Linux syscalls, namespace operations,
//! Landlock and seccomp primitives, capability manipulation, and the libbpf
//! FFI behind safe APIs. Everything else in the workspace links it and stays
//! `#![forbid(unsafe_code)]`.
//!
//! # `unsafe`
//!
//! The crate carries `#![allow(unsafe_code)]` (the workspace default is
//! `#![forbid(unsafe_code)]`; this crate is the documented exception in
//! `UNSAFE-CRATES.md`). The pure-`std` part — the path-canonicalisation helper
//! of CODING-STANDARDS.md §10.3 / §11.3 ([`path::canonicalise_path`]) — uses no
//! `unsafe`; the FFI part ([`unistd`] and the syscall wrappers to follow) wraps
//! raw libc calls, every block carrying the §4 `SAFETY:` / `INVARIANTS UPHELD:`
//! / `FAILURE MODE:` comment. `libc` is vendored under §5.5; `nix` /
//! `libbpf-sys` arrive the same way as their wrappers land.
//!
//! # Invariants
//!
//! - Path validation is the *only* place in the workspace that performs
//!   `realpath`-equivalent resolution (§11.3). Callers compare canonicalised
//!   values, never raw strings.
//! - A canonicalised path is evidence it was proven to lie within an explicit
//!   allowed prefix; the type carries no such guarantee on its own, so the
//!   helper returns the resolved `PathBuf` only on success.
//!
//! # Threat bearing
//!
//! Defends against path-traversal and symlink-escape (the T6 lateral-movement
//! and T2 confused-deputy classes): an untrusted path that resolves outside the
//! allowed prefix — directly, via `..`, or via a symlink — is refused rather
//! than silently accepted.

#![allow(unsafe_code)]

pub mod path;
pub mod unistd;
