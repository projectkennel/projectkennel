//! Project Kennel low-level system primitives.
//!
//! # Purpose
//!
//! `kennel-syscall` is the workspace's single point for low-level system
//! operations (`architecture/02-6-internal-api.md`, `03-crate-decomposition.md`):
//! namespaces, mounts, Landlock and seccomp, capability manipulation, path
//! resolution, and the credential calls. It presents one curated, safe API so
//! the rest of the workspace does not depend on the underlying syscall crates
//! directly. It is also the *designated* place for `unsafe` should any be
//! unavoidable — but it prefers vetted crates over owning `unsafe` (see below).
//! Everything else in the workspace stays `#![forbid(unsafe_code)]`.
//!
//! # `unsafe`
//!
//! This crate is the workspace's *designated* `unsafe` crate (`UNSAFE-CRATES.md`)
//! and owns as little `unsafe` as possible. Following "don't roll your own
//! `unsafe`" (CODING-STANDARDS.md §4) it prefers vetted crates: nix for the
//! general syscalls ([`unistd`], and the namespace/mount wrappers to follow),
//! and `seccompiler` for the seccomp-BPF filter (hand-rolling BPF bytecode is
//! the dangerous case).
//!
//! The one deliberate exception is [`landlock`]: the `landlock` crate would pull
//! `syn` and the first proc-macros into the privileged dependency tree, whereas
//! the Landlock ABI is three syscalls and a few packed structs from the kernel
//! UAPI — small enough to own. So this crate carries `#![allow(unsafe_code)]`,
//! with the `unsafe` confined to [`landlock`]'s three raw syscall wrappers, each
//! carrying the §4 `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment.
//! Dependencies are vendored under §5.5.
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

pub mod landlock;
pub mod mount;
pub mod namespace;
pub mod path;
pub mod process;
pub mod unistd;
