//! `kennel-cli` — the library crate backing the host-side `kennel` CLI.
//!
//! Provides the shared helpers (daemon connection, key loading, policy resolution, trust
//! store) and the verb modules (`run`, `policy`, `key`, `oci`, `review`, `runtime`, `misc`). The
//! `kennel-host` execution unit dispatches them; the `kennel` shim execs it host-side.

#![forbid(unsafe_code)]

// The verb modules — the `kennel-host` unit dispatches into these.
pub mod key;
pub mod misc;
pub mod oci;
pub mod policy;
pub mod review;
pub mod run;
pub mod runtime;

// Re-export the shared helpers that were in main.rs. These are now in `shared.rs`
// so the binary entry points and the verb modules can both reach them.
mod shared;
pub use shared::*;
