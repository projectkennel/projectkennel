// SPDX-License-Identifier: Apache-2.0

//! Project Kennel low-level system primitives.
//!
//! # Purpose
//!
//! `kennel-lib-syscall` is the workspace's single point for low-level system
//! operations (Kennel book Vol 2 ch.4 (The Trusted Base); `docs/reference/03-crate-decomposition.md`):
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
//! Our own `unsafe` is where no vetted wrapper fits, each site with a `SAFETY:` comment (the
//! full §4 `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` form is not yet on every one):
//!
//! - [`namespace`]: raw `clone`/`clone3`/`fork` for the kennel's PID 1 and the mesh mount
//!   holder, and what their children do before `exec`. The largest share by far.
//! - [`spawn`]: the post-`fork` drop, seal and `execve` of a facade or the workload. Wrapping it
//!   here keeps `kennel-lib-spawn` `#![forbid(unsafe_code)]`.
//! - [`pty`], [`boot`], [`fd`]: adopting or borrowing descriptors that arrive as bare numbers
//!   (inherited at a fixed fd, or named in a message), and the controlling-terminal ioctls.
//! - [`wake`], [`signal`], [`process`], [`random`], [`tun`], [`listenfd`] and (behind its
//!   feature) `journal`: one to four sites each around a single syscall or fd adoption.
//!
//! The Landlock bindings are in `kennel-lib-landlock`, not here.
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
pub mod inotify;
#[cfg(feature = "audit-journald")]
pub mod journal;
pub mod listenfd;
pub mod mount;
pub mod namespace;
pub mod process;
pub mod pty;
pub mod random;
pub mod seccomp;
pub mod signal;
pub mod spawn;
pub mod sysinfo;
pub mod tun;
pub mod wake;

// The safe (no-`unsafe`) primitives live in `kennel-lib-os` so this crate carries only genuinely
// unsafe code (CODING-STANDARDS §4). Re-exported so existing `kennel_lib_syscall::{path, unistd,
// netlink, handshake}` paths keep resolving unchanged.
pub use kennel_lib_os::{handshake, net, netlink, path, ready, unistd};

// SCM_RIGHTS fd-passing is its own small unsafe-bearing crate (parallel to kennel-lib-landlock), so
// dumb delegates can use it without the whole unsafe crate; re-exported so `kennel_lib_syscall::scm::…`
// keeps resolving unchanged.
pub use kennel_lib_scm as scm;

// The hand-rolled Landlock ABI is its own unsafe-bearing crate (parallel to kennel-lib-bpf/binder),
// re-exported so `kennel_lib_syscall::landlock::…` keeps resolving unchanged.
pub use kennel_lib_landlock as landlock;
