//! Project Kennel control-plane wire protocol.
//!
//! # Purpose
//!
//! The framed [`Request`](control::Request)/[`Response`](control::Response)
//! messages the unprivileged `kennel` CLI and the `kenneld` daemon exchange over
//! the per-user control socket, plus the [`socket`] path/listener resolver. This
//! crate is the *bytes and the path*, nothing else — no policy, no spawn, no
//! enforcement.
//!
//! # Invariants
//!
//! - The framing is the hand-rolled length-prefixed encoding of [`control`]
//!   (native-endian, same-host CLI and daemon); it is not a serialisation
//!   language and pulls in no `serde`/`serde_json`.
//! - A decoder bounds every read by a fixed maximum-message size before
//!   allocating, so a malformed length prefix cannot exhaust memory (the control
//!   socket is a trust boundary, §10).
//!
//! # Threat bearing
//!
//! The control socket is the CLI→daemon trust boundary. Keeping the protocol in
//! its own crate lets the CLI link the wire types **without** linking the daemon's
//! enforcement code (spawn, privhelper glue, BPF) — the dependency-graph half of
//! keeping the daemon's TCB minimal (CODING-STANDARDS.md §3, §5).
//!
//! # Non-goals
//!
//! This crate does not transfer the workload's stdio (those fds ride as
//! `SCM_RIGHTS` alongside the frame, handled by the daemon's server layer), does
//! not make policy decisions, and does not serve the socket — it only frames the
//! messages and resolves where the socket lives.

#![forbid(unsafe_code)]

pub mod control;
pub mod socket;
