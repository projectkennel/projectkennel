//! `kennel-cli` — the library crate backing all host-side CLI binaries.
//!
//! After the W10 split, this crate provides:
//! - Shared helpers: daemon connection, key loading, policy resolution, trust store
//! - Verb modules: `run`, `policy`, `oci`, `review`, `runtime`, `misc`
//!
//! Each sub-binary (`kennel-run`, `kennel-policy`, `kennel-oci`, `kennel-misc`) imports
//! from this crate and dispatches its subset of verbs.

#![forbid(unsafe_code)]

// The verb modules — each sub-binary dispatches into these.
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
