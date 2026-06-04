//! The systemd-journald sink (feature `audit-journald`).
//!
//! Each canonical field becomes a `KENNEL_<UPPER>` journal field; the writer's
//! human message becomes `MESSAGE`, the outcome severity becomes `PRIORITY`, and
//! `SYSLOG_IDENTIFIER` is `kennel-audit`. Submission goes through
//! `kennel_syscall::journal::sendv` (the `sd_journal_sendv` FFI — the one crate
//! permitted `unsafe`). journald owns the realtime timestamp and `_HOSTNAME`;
//! the canonical `ts`/`host` are still emitted as `KENNEL_TS`/`KENNEL_HOST` for
//! sub-microsecond precision and round-tripping (`02-3` §Sink: systemd-journald).

use std::fmt::Write as _;

use crate::render::{Record, Rendered};
use crate::writer::{Sink, SinkError};

/// Emits events to systemd-journald via `sd_journal_sendv`.
#[derive(Default)]
pub struct JournaldSink;

impl JournaldSink {
    /// Construct the sink. Submission is per-event; there is no persistent
    /// connection to fail at construction.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Sink for JournaldSink {
    fn name(&self) -> &'static str {
        "journald"
    }

    fn write(&self, record: &Record) -> Result<(), SinkError> {
        let mut fields: Vec<String> = Vec::with_capacity(record.fields.len().saturating_add(3));
        for (key, value) in &record.fields {
            append_journal_fields(&mut fields, key, value);
        }
        // journald-required extras.
        fields.push(format!("MESSAGE={}", record.message()));
        fields.push("SYSLOG_IDENTIFIER=kennel-audit".to_owned());
        fields.push(format!("PRIORITY={}", record.outcome.severity()));
        // MESSAGE_ID for journalctl filtering by event kind, when registered.
        if let Some(id) = crate::message_ids::for_event(record.event_type) {
            fields.push(format!("MESSAGE_ID={id}"));
        }

        kennel_syscall::journal::sendv(&fields).map_err(|e| SinkError {
            sink: "journald",
            message: format!("sd_journal_sendv: {e}"),
        })
    }
}

/// Append one canonical field as one or more `KENNEL_<UPPER>=value` entries.
/// Arrays become repeated keys (journald allows multi-valued fields); nested
/// values are unused by the current schema.
fn append_journal_fields(out: &mut Vec<String>, key: &str, value: &Rendered) {
    let name = journal_name(key);
    match value {
        Rendered::Str(s) => out.push(format!("{name}={s}")),
        Rendered::Int(i) => out.push(format!("{name}={i}")),
        Rendered::Uint(u) => out.push(format!("{name}={u}")),
        Rendered::Bool(b) => out.push(format!("{name}={b}")),
        Rendered::Null => {}
        Rendered::Array(items) => {
            for item in items {
                append_journal_fields(out, key, item);
            }
        }
    }
}

/// `KENNEL_` + the upper-cased key. Keys are `[a-z0-9_]`, so the result matches
/// journald's required `[A-Z0-9_]+`.
fn journal_name(key: &str) -> String {
    let mut name = String::with_capacity(key.len().saturating_add(7));
    name.push_str("KENNEL_");
    for ch in key.chars() {
        let _ = write!(name, "{}", ch.to_ascii_uppercase());
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Outcome, Resource};

    fn rec() -> Record {
        Record {
            resource: Resource::Net,
            event_type: "net.connect-deny",
            outcome: Outcome::Deny,
            fields: vec![
                ("schema_version", Rendered::Uint(1)),
                ("event", Rendered::Str("net.connect-deny".to_owned())),
                ("addr", Rendered::Str("169.254.169.254".to_owned())),
                (
                    "template_chain",
                    Rendered::Array(vec![
                        Rendered::Str("base".to_owned()),
                        Rendered::Str("strict".to_owned()),
                    ]),
                ),
            ],
        }
    }

    #[test]
    fn fields_are_kennel_prefixed_and_uppercased() {
        let mut out = Vec::new();
        for (k, v) in &rec().fields {
            append_journal_fields(&mut out, k, v);
        }
        assert!(out.contains(&"KENNEL_SCHEMA_VERSION=1".to_owned()));
        assert!(out.contains(&"KENNEL_ADDR=169.254.169.254".to_owned()));
        assert!(out.contains(&"KENNEL_EVENT=net.connect-deny".to_owned()));
    }

    #[test]
    fn arrays_become_repeated_keys() {
        let mut out = Vec::new();
        append_journal_fields(
            &mut out,
            "template_chain",
            &Rendered::Array(vec![
                Rendered::Str("base".to_owned()),
                Rendered::Str("strict".to_owned()),
            ]),
        );
        assert_eq!(
            out,
            vec![
                "KENNEL_TEMPLATE_CHAIN=base".to_owned(),
                "KENNEL_TEMPLATE_CHAIN=strict".to_owned(),
            ]
        );
    }
}
