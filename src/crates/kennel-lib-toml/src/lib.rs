//! Project Kennel's TOML (de)serializer for [Serde].
//!
//! This is [basic-toml] 0.1.10 by Alex Crichton and David Tolnay, brought in-tree as a
//! first-party crate when upstream was archived (RUSTSEC-2026-0374, projectkennel#221). It
//! parses the signed settled policy on the TCB path, so it has an owner here rather than an
//! unmaintained upstream, and it keeps the dependency graph at `serde` alone (the maintained
//! `toml` crate would pull a chain of new external crates into the TCB).
//!
//! The API is upstream's: [`from_str`], [`from_slice`], [`to_string`] and [`Error`].
//!
//! ```
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize, Serialize, PartialEq, Debug)]
//! struct Package {
//!     name: String,
//!     version: String,
//! }
//!
//! let pkg: Package = kennel_lib_toml::from_str("name = \"kennel\"\nversion = \"0.7.1\"\n").unwrap();
//! assert_eq!(pkg.name, "kennel");
//! assert_eq!(kennel_lib_toml::to_string(&pkg).unwrap(), "name = \"kennel\"\nversion = \"0.7.1\"\n");
//! ```
//!
//! # Spec compatibility
//!
//! TOML v0.5.0. TOML's date and time syntax are not supported.
//!
//! [Serde]: https://serde.rs
//! [basic-toml]: https://github.com/dtolnay/basic-toml

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::bool_to_int_with_if,
    clippy::elidable_lifetime_names,
    clippy::let_underscore_untyped,
    clippy::manual_let_else,
    clippy::manual_range_contains,
    clippy::match_like_matches_macro,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_doctest_main,
    clippy::needless_lifetimes,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::type_complexity,
    clippy::uninlined_format_args,
    clippy::unnecessary_box_returns,
    clippy::unwrap_or_default
)]

mod de;
mod error;
mod ser;
mod tokens;

pub use crate::de::{from_slice, from_str};
pub use crate::error::Error;
pub use crate::ser::to_string;
