//! Project Kennel binder IPC — a hand-rolled `binder(7)`/binderfs loader.
//!
//! # Purpose
//!
//! Provides the two halves of Project Kennel's binder use, over the stable
//! `binder` ioctl ABI (`<linux/android/binder.h>`) with **no** libbinder /
//! libbinder-ndk: the context-manager state machine ([`ctxmgr`]) that `kenneld`
//! runs as node 0 of each kennel's binderfs instance, and the consumer client
//! ([`client`]) that a workload-side process (a service, or — with §7.10 — the
//! `kennel-netshim`) uses to register and look up services. The wire codec for
//! the `BC_*`/`BR_*` command stream lives in [`proto`]; the raw ioctl/`mmap` FFI
//! is quarantined to [`sys`]; binderfs mount + device allocation is [`binderfs`].
//!
//! # Invariants
//!
//! - The `unsafe` surface is confined to [`sys`] (raw `ioctl`/`mmap`) per
//!   CODING-STANDARDS.md §4; every other module is safe Rust over it.
//! - The `BC_*`/`BR_*` codec ([`proto`]) treats the kernel-supplied read buffer
//!   as untrusted bytes: every field is bounds-checked, never indexed.
//! - Binder protocol version is pinned: a device whose `BINDER_VERSION` is not
//!   [`proto::PROTOCOL_VERSION`] is refused at open.
//!
//! # Threat bearing
//!
//! Implements the kernel-enforced IPC chokepoint of `07-9-ipc.md` (§7.9): the
//! context manager is the per-call policy decision point, and binder node
//! references are unforgeable kernel objects with no path to enumerate. Bears on
//! the ambient-authority threats §7.9.1 catalogues (T1.6 and the D-Bus/Wayland
//! residuals) by moving enforcement from connect-time to call-time.
//!
//! # Non-goals
//!
//! This crate does not own policy (which services a kennel may register or look
//! up — that is `kenneld`'s `binder` module against the settled policy), does not
//! mount the kennel's namespaces (`kennel-spawn`), and does not implement the
//! cross-instance relay (`kenneld`).

#![allow(unsafe_code)]

pub mod binderfs;
pub mod client;
pub mod ctxmgr;
pub mod proto;
pub mod service;
pub mod sys;
