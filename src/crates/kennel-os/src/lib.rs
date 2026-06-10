//! Project Kennel **safe** OS primitives.
//!
//! These are the helpers that wrap the operating system without needing `unsafe`: they go
//! through `std` and nix's safe API. They were split out of `kennel-syscall` (the one crate
//! permitted `unsafe`) so that crate carries *only* genuinely-unsafe code and stays reviewable in
//! one sitting (CODING-STANDARDS §4). `kennel-syscall` re-exports these modules, so callers may
//! continue to reach them as `kennel_syscall::{path, unistd, netlink, handshake}` unchanged.
//!
//! - [`path`] — portable, std-only path canonicalisation.
//! - [`unistd`] — uid/gid identity (the masked-identity reads, group set).
//! - [`netlink`] — per-kennel loopback address management over a netlink socket.
//! - [`handshake`] — the one-byte pipe ack the factory uses while writing a child's userns maps.
#![forbid(unsafe_code)]

pub mod handshake;
pub mod net;
pub mod netlink;
pub mod path;
pub mod unistd;
