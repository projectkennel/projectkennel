//! Project Kennel policy-schema generator (library half).
//!
//! Emits a JSON Schema (draft-07) for the authored policy TOML from an in-repo data
//! table ([`model`]) that mirrors the `kennel-lib-compile` source structs. The emitted
//! `schema/policy.toml.schema` is what host editors read for completion and inline
//! validation. The schema↔parser agreement is enforced by a cross-check test in
//! `kennel-lib-compile` (which dev-depends on this crate's [`model`]), so the schema
//! cannot silently drift from the parser.
//!
//! Std-only by design (CODING-STANDARDS §5.1): no `schemars`, no `serde_json` — a small
//! hand-rolled JSON writer ([`json`]) emits the document.

#![forbid(unsafe_code)]

pub mod emit;
pub mod json;
pub mod model;

pub use emit::{schema_document, SCHEMA_ID};
