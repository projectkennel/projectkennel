//! Project Kennel low-level system primitives.
//!
//! # Purpose
//!
//! `kennel-syscall` is the workspace's single point for low-level system
//! operations (`docs/architecture/02-8-internal-api.md`, `03-crate-decomposition.md`):
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
//! Two sites carry our own `unsafe`, each with the §4 `SAFETY:` /
//! `INVARIANTS UPHELD:` / `FAILURE MODE:` comment:
//!
//! - [`landlock`]'s three raw syscall wrappers. The `landlock` crate would pull
//!   `syn` and the first proc-macros into the privileged dependency tree,
//!   whereas the Landlock ABI is three syscalls and a few packed structs from
//!   the kernel UAPI — small enough to own.
//! - [`spawn`]'s one `CommandExt::pre_exec` call, which registers the
//!   post-`fork`/pre-`execve` seal hook the spawn sequence installs confinement
//!   in. Wrapping it here keeps `kennel-spawn` `#![forbid(unsafe_code)]`.
//! - [`netlink`]'s three socket syscalls (`socket`/`sendto`/`recv`) for
//!   interface-address management. The `rtnetlink` crate is a large async tree
//!   (MIT-only) and `ioctl` cannot add a secondary/IPv6 address; the message is
//!   built as a plain byte buffer (no `transmute`), so only the syscalls are
//!   `unsafe`.
//!
//! So this crate carries `#![allow(unsafe_code)]`. Dependencies are vendored
//! under §5.5.
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
//! Defends against path-traversal and symlink-escape (the T1.6 lateral-movement
//! and T1.2 confused-deputy classes): an untrusted path that resolves outside the
//! allowed prefix — directly, via `..`, or via a symlink — is refused rather
//! than silently accepted.

#![allow(unsafe_code)]

pub mod boot;
pub mod fd;
#[cfg(feature = "audit-journald")]
pub mod journal;
pub mod landlock;
pub mod listenfd;
pub mod mount;
pub mod namespace;
pub mod process;
pub mod pty;
pub mod random;
pub mod scm;
pub mod seccomp;
pub mod signal;
pub mod spawn;

// The safe (no-`unsafe`) primitives live in `kennel-os` so this crate carries only genuinely
// unsafe code (CODING-STANDARDS §4). Re-exported so existing `kennel_syscall::{path, unistd,
// netlink, handshake}` paths keep resolving unchanged.
pub use kennel_os::{handshake, netlink, path, unistd};
