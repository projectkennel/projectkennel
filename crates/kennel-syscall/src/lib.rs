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
//! # Staging
//!
//! The portable, dependency-free part lands first: the path-canonicalisation
//! helper of CODING-STANDARDS.md §10.3 / §11.3 ([`path::canonicalise_path`]),
//! which is pure `std` and fully testable on any host. While only that part
//! exists the crate carries `#![forbid(unsafe_code)]` below — there is no
//! `unsafe` yet, so we take the stronger guarantee. The forbid flips to
//! `#![allow(unsafe_code)]` when the first syscall wrapper lands (with its
//! `UNSAFE-CRATES.md` and `CHANGELOG.md` entries and the §4 `SAFETY:` comment
//! discipline), and the `nix` / `libc` / `libbpf-sys` dependencies arrive then
//! through the §5.5 supply-chain procedure.
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

#![forbid(unsafe_code)]

pub mod path;
