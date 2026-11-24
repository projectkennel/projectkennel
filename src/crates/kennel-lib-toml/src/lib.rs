// SPDX-License-Identifier: Apache-2.0

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

mod de;
mod error;
mod ser;
mod tokens;

pub use crate::de::{from_slice, from_str};
pub use crate::error::Error;
pub use crate::ser::to_string;
