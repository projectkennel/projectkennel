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
//! No I/O, no policy, no sockets: this is the parse surface only. The connect/splice
//! loops stay in each binary.

#![forbid(unsafe_code)]

pub mod socks5;
