//! The rendered record and its sink encodings.
//!
//! A [`Record`] is the canonical, ordered, already-sanitised field list the
//! writer hands to every sink, plus the JSON Lines encoding and the
//! human-readable `MESSAGE` synthesis the journald and syslog sinks reuse.
//!
//! By the time a [`Record`] exists, the single content-sanitisation pass has run
//! (untrusted strings carry only visible escapes), so each sink does its own
//! *structural* encoding only: JSON escaping here, journald field naming, syslog
//! SD-PARAM escaping. Field order is the §Common-envelope order then
//! event-specific declared order, deterministic for diff-friendliness.

use std::fmt::Write as _;

use crate::event::{Outcome, Resource};

/// A field value after sanitisation, ready for structural encoding by a sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rendered {
    /// A string with no live control bytes (sanitised if it was untrusted).
    Str(String),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer.
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// JSON `null`.
    Null,
    /// An ordered array.
    Array(Vec<Self>),
    /// An ordered object of named sub-values.
    Object(Vec<(&'static str, Self)>),
}

/// One fully-rendered audit event: ordered canonical fields plus the metadata a
/// sink needs to route and summarise it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Resource class (routes the JSONL file sink to `<stem>.jsonl`).
    pub resource: Resource,
    /// The event-type identifier.
    pub event_type: &'static str,
    /// The outcome (drives syslog/journald severity).
    pub outcome: Outcome,
    /// Canonical ordered fields: envelope first, then event-specific, then a
    /// trailing `sanitised` flag when sanitisation altered anything.
    pub fields: Vec<(&'static str, Rendered)>,
}

impl Record {
    /// Render this record as a single JSON Lines entry (no trailing newline).
    ///
    /// Always well-formed JSON: every string is structurally escaped, so a
    /// sanitised-but-still-arbitrary value cannot break the object.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        let mut first = true;
        for (key, value) in &self.fields {
            if first {
                first = false;
            } else {
                out.push(',');
            }
            push_json_string(&mut out, key);
            out.push(':');
            push_value(&mut out, value);
        }
        out.push('}');
        out
    }

    /// A human-readable one-line summary for the journald/syslog `MESSAGE`.
    /// Consumers read the structured fields; this is for eyeballing.
    #[must_use]
    pub fn message(&self) -> String {
        let mut out = String::with_capacity(64);
        let _ = write!(out, "{} {}", self.outcome.token(), self.event_type);
        // Append the event-specific scalar fields (skip the envelope, which the
        // sink already carries structurally).
        let mut shown = 0_u32;
        for (key, value) in &self.fields {
            if is_envelope_key(key) {
                continue;
            }
            if let Some(scalar) = scalar_text(value) {
                out.push_str(if shown == 0 { ": " } else { ", " });
                let _ = write!(out, "{key}={scalar}");
                shown = shown.saturating_add(1);
            }
        }
        out
    }
}

/// The envelope keys, in canonical order. The writer emits them in this order
/// ahead of any event-specific fields.
pub(crate) const ENVELOPE_KEYS: [&str; 11] = [
    "schema_version",
    "ts",
    "kennel",
    "kennel_uuid",
    "event",
    "resource",
    "outcome",
    "source",
    "host",
    "pid",
    "comm",
];

fn is_envelope_key(key: &str) -> bool {
    ENVELOPE_KEYS.contains(&key) || key == "sanitised"
}

/// A short text form of a scalar value for the human message, or `None` for
/// arrays/null (which the message omits).
fn scalar_text(value: &Rendered) -> Option<String> {
    match value {
        Rendered::Str(s) => Some(s.clone()),
        Rendered::Int(i) => Some(i.to_string()),
        Rendered::Uint(u) => Some(u.to_string()),
        Rendered::Bool(b) => Some(b.to_string()),
        Rendered::Null | Rendered::Array(_) | Rendered::Object(_) => None,
    }
}

fn push_value(out: &mut String, value: &Rendered) {
    match value {
        Rendered::Str(s) => push_json_string(out, s),
        Rendered::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Rendered::Uint(u) => {
            let _ = write!(out, "{u}");
        }
        Rendered::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Rendered::Null => out.push_str("null"),
        Rendered::Array(items) => {
            out.push('[');
            let mut first = true;
            for item in items {
                if first {
                    first = false;
                } else {
                    out.push(',');
                }
                push_value(out, item);
            }
            out.push(']');
        }
        Rendered::Object(entries) => {
            out.push('{');
            let mut first = true;
            for (key, val) in entries {
                if first {
                    first = false;
                } else {
                    out.push(',');
                }
                push_json_string(out, key);
                out.push(':');
                push_value(out, val);
            }
            out.push('}');
        }
    }
}

/// Append `s` as a quoted, JSON-escaped string. Quote and backslash are escaped;
/// any residual C0 control becomes `\u00XX`. Content sanitisation has already
/// run upstream, so this is the structural layer only.
pub(crate) fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Record {
        Record {
            resource: Resource::Net,
            event_type: "net.connect-deny",
            outcome: Outcome::Deny,
            fields: vec![
                ("schema_version", Rendered::Uint(1)),
                ("event", Rendered::Str("net.connect-deny".to_owned())),
                ("resource", Rendered::Str("net".to_owned())),
                ("outcome", Rendered::Str("deny".to_owned())),
                ("pid", Rendered::Uint(12_345)),
                ("addr", Rendered::Str("169.254.169.254".to_owned())),
                ("port", Rendered::Uint(80)),
                ("reason", Rendered::Str("cloud metadata".to_owned())),
            ],
        }
    }

    #[test]
    fn jsonl_is_one_object_per_line() {
        let line = sample().to_jsonl();
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains(r#""schema_version":1"#));
        assert!(line.contains(r#""addr":"169.254.169.254""#));
        assert!(line.contains(r#""port":80"#));
    }

    #[test]
    fn strings_are_structurally_escaped() {
        let r = Record {
            resource: Resource::Fs,
            event_type: "fs.access-deny",
            outcome: Outcome::Deny,
            fields: vec![("path", Rendered::Str("a\"b\\c".to_owned()))],
        };
        let line = r.to_jsonl();
        assert!(line.contains(r#""path":"a\"b\\c""#), "{line}");
    }

    #[test]
    fn arrays_render() {
        let r = Record {
            resource: Resource::Lifecycle,
            event_type: "lifecycle.kennel-start",
            outcome: Outcome::Info,
            fields: vec![(
                "template_chain",
                Rendered::Array(vec![
                    Rendered::Str("base".to_owned()),
                    Rendered::Str("ai-coding-strict".to_owned()),
                ]),
            )],
        };
        assert!(r
            .to_jsonl()
            .contains(r#""template_chain":["base","ai-coding-strict"]"#));
    }

    #[test]
    fn objects_render_as_nested_json() {
        let r = Record {
            resource: Resource::Priv,
            event_type: "priv.invoke",
            outcome: Outcome::Allow,
            fields: vec![(
                "params",
                Rendered::Object(vec![
                    ("ctx", Rendered::Uint(7)),
                    ("addr", Rendered::Str("127.0.144.81".to_owned())),
                ]),
            )],
        };
        assert!(
            r.to_jsonl()
                .contains(r#""params":{"ctx":7,"addr":"127.0.144.81"}"#),
            "{}",
            r.to_jsonl()
        );
    }

    #[test]
    fn message_summarises_event_specific_scalars() {
        let m = sample().message();
        assert!(m.starts_with("deny net.connect-deny:"), "{m}");
        assert!(m.contains("addr=169.254.169.254"));
        assert!(m.contains("port=80"));
        // Envelope keys are not repeated in the message body.
        assert!(!m.contains("schema_version="));
    }
}
