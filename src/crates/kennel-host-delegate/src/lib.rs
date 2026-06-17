//! Project Kennel host-side conduit delegates.
//!
//! # Purpose
//!
//! The two "glorified netcat" delegates that put a connected socket on a file
//! descriptor across the kennel's network-namespace boundary — the one thing
//! `kenneld` cannot do in-process. Each is a tiny binary over an owner-only
//! `AF_UNIX` command socket; all policy lives in `kenneld`, never here.
//!
//! - [`netproxy`] — the egress **dial** delegate (`host-netproxy` binary): receives
//!   a pinned address + a conduit fd, dials from the host stack, and splices
//!   (`07-5-network.md` §7.5.2).
//! - [`inetd`] — the inbound **BIND** delegate (`host-inetd` binary, the mirror of
//!   `netproxy`): binds a policy-mirrored `ip:port` on the host loopback, accepts,
//!   and hands each accepted connection's kennel-side fd back to `kenneld`
//!   (`07-5-network.md` §7.5.7).
//!
//! # Invariants
//!
//! Neither delegate makes a policy decision: `kenneld` resolves, pins, and gates
//! before any command reaches these processes. The net-ns boundary is the gate;
//! these are the only path across it.
//!
//! # Threat bearing
//!
//! Kept small and `kennel-lib-scm`-only (not the whole `kennel-lib-syscall` unsafe
//! surface) so each delegate's own TCB stays minimal.
//!
//! # Non-goals
//!
//! No TCP listener of its own (the in-kennel facades do that), no resolver, no
//! allowlist, no config file — `kenneld` owns all of it.

#![forbid(unsafe_code)]

pub mod inetd;
pub mod netproxy;
