// SPDX-License-Identifier: Apache-2.0

//! Project Kennel facade library: the pure, untrusted-input parsers the facade
//! binaries share.
//!
//! # Purpose
//!
//! The facade binaries (`facade-socks5`, …) are otherwise I/O loops with no shared
//! library, but their *parsers* read fully workload-controlled bytes and so must
//! carry fuzz targets (CODING-STANDARDS §10.6). Keeping those parsers here — out
//! of the bin roots, which a separate workspace cannot link — lets the `kennel-fuzz`
//! harness exercise them directly. The binaries `use kennel_facade::…` for the same
//! code they run in production, so the fuzzed parser and the served parser are one.
//!
//! # Non-goals
//!
//! No policy, and no I/O beyond [`listen::bind_ready`] — the one readiness-atomic socket bind the
//! path-serving facades share (it decides when the workload may start, so it lives in one place).
//! Otherwise this is the parse surface only; the connect/splice loops stay in each binary.

#![forbid(unsafe_code)]

pub mod listen;
pub mod socks5;
pub mod tun;
