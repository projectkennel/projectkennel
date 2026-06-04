//! Project Kennel unified audit writer.
//!
//! This crate is the seam between audit *sources* (the BPF programs drained by
//! kenneld, the netproxy, the privhelper, the spawn wrapper, kenneld itself) and
//! audit *sinks* (the JSONL file, stdout, syslog, and optional journald). A
//! source builds an [`Event`]; the [`Writer`] stamps the envelope, runs one
//! content-sanitisation pass, applies the per-class audit [`Level`], and fans
//! the rendered record out to every configured [`Sink`]. The event schema is the
//! durable contract — see `docs/architecture/02-3-audit-schema.md`.
//!
//! # Why a hand-rolled JSON/timestamp/UUID path
//!
//! The serialiser escapes (it does not parse), the timestamp is calendar
//! arithmetic, and the `UUIDv7` is bit-packing: none is the crypto/DNS/`unsafe`
//! that the no-hand-roll rule reserves for vetted crates (CODING-STANDARDS.md
//! §4). Randomness for the UUID and the journald FFI are the parts that *do*
//! need privilege/`unsafe`, so they live in `kennel-syscall`.

#![forbid(unsafe_code)]

pub mod event;
pub mod render;
pub mod sinks;
pub mod time;
pub mod timeout;
pub mod uuidv7;
pub mod writer;

#[cfg(feature = "audit-journald")]
pub mod journald;
#[cfg(feature = "audit-journald")]
pub mod message_ids;

pub use event::{Event, Level, Outcome, Resource, Source, Value};
pub use render::{Record, Rendered};
pub use sinks::{FileSink, StdoutSink, SyslogSink};
pub use time::{format_rfc3339_micros, Clock, SystemClock};
pub use timeout::TimeoutSink;
pub use uuidv7::format_uuid_v7;
pub use writer::{Levels, Sink, SinkError, Writer, WriterContext, MAX_EVENT_BYTES, SCHEMA_VERSION};

#[cfg(feature = "audit-journald")]
pub use journald::JournaldSink;
