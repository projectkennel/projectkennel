//! Structured audit records for proxied requests (CODING-STANDARDS.md §9.2).
//!
//! Every request the proxy handles — allowed or denied — produces one audit
//! event. This is the security-relevant stream (§9.2), distinct from developer
//! logging: it is what a SIEM consumes to see where confined workloads tried to
//! reach. The proxy *is* the policy decision, so the record is authoritative —
//! no correlation with kernel events is needed (`docs/design/07-3-network.md` §7.3.2).
//!
//! # Delivery
//!
//! A [`Record`] is the proxy's internal shape for one request. [`Record::to_event`]
//! turns it into a canonical [`kennel_audit::Event`] (a `net.egress` event); the
//! `kennel-audit` [`Writer`](kennel_audit::Writer) the server holds sanitises it,
//! applies the audit level, and fans it out to every configured sink (the
//! per-kennel `network.jsonl` file, and any others the policy selected). The
//! requested host is attacker-controlled, so it is emitted as a
//! [`Value::untrusted`] field — the writer runs the single sanitisation pass.
//!
//! This module does not write anywhere; it formats. The server owns the writer.
//! It carries no payload bytes (§9.3): only the destination, byte counts, and
//! the policy outcome.

use kennel_audit::{Event, Outcome as AuditOutcome, Resource, Source, Value};

/// The protocol a request arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// SOCKS5.
    Socks5,
    /// HTTP `CONNECT` tunnel.
    HttpConnect,
    /// HTTP absolute-form forward.
    HttpForward,
}

impl Wire {
    /// The stable token used in the audit record.
    const fn token(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::HttpConnect => "http-connect",
            Self::HttpForward => "http-forward",
        }
    }
}

/// The policy outcome recorded for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed and connected; carries the byte counts.
    Allowed {
        /// Bytes relayed from the client to the upstream.
        bytes_up: u64,
        /// Bytes relayed from the upstream back to the client.
        bytes_down: u64,
    },
    /// Refused by policy, with a stable reason token.
    Denied(&'static str),
    /// Allowed by policy but the connection failed (DNS empty, connect refused),
    /// with a stable reason token.
    Failed(&'static str),
}

impl Outcome {
    /// The canonical envelope outcome (`allowed` → allow, `denied` → deny,
    /// `failed` → error).
    const fn audit_outcome(self) -> AuditOutcome {
        match self {
            Self::Allowed { .. } => AuditOutcome::Allow,
            Self::Denied(_) => AuditOutcome::Deny,
            Self::Failed(_) => AuditOutcome::Error,
        }
    }

    /// The egress-specific outcome token, retained for human triage.
    const fn token(self) -> &'static str {
        match self {
            Self::Allowed { .. } => "allowed",
            Self::Denied(_) => "denied",
            Self::Failed(_) => "failed",
        }
    }
}

/// One audit record for a single proxied request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The protocol the request arrived on.
    pub wire: Wire,
    /// The host the workload asked for (a name or a literal address). Untrusted.
    pub host: String,
    /// The destination port.
    pub port: u16,
    /// The address the name resolved to and the proxy connected to, if any.
    pub resolved: Option<std::net::IpAddr>,
    /// The policy outcome.
    pub outcome: Outcome,
}

impl Record {
    /// Render this record as a canonical `net.egress` [`Event`] for the unified
    /// writer. The untrusted host rides a [`Value::untrusted`] field so the
    /// writer's single sanitisation pass neutralises it before any sink.
    #[must_use]
    pub fn to_event(&self) -> Event {
        let resolved = self
            .resolved
            .map_or(Value::Null, |addr| Value::str(addr.to_string()));
        let base = Event::new(
            "net.egress",
            Resource::Net,
            self.outcome.audit_outcome(),
            Source::Proxy,
        )
        .target(format!("{}:{}", self.host, self.port))
        .field("wire", Value::str(self.wire.token()))
        .field("egress_outcome", Value::str(self.outcome.token()))
        .field("host", Value::untrusted(self.host.clone()))
        .field("port", Value::Uint(u64::from(self.port)))
        .field("resolved", resolved);
        match self.outcome {
            Outcome::Allowed {
                bytes_up,
                bytes_down,
            } => base
                .field("bytes_up", Value::Uint(bytes_up))
                .field("bytes_down", Value::Uint(bytes_down)),
            Outcome::Denied(reason) | Outcome::Failed(reason) => {
                base.field("reason", Value::str(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_audit::{Sink, SinkError, Writer, WriterContext};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    fn allowed(host: &str, port: u16, resolved: Option<IpAddr>) -> Record {
        Record {
            wire: Wire::Socks5,
            host: host.to_owned(),
            port,
            resolved,
            outcome: Outcome::Allowed {
                bytes_up: 10,
                bytes_down: 200,
            },
        }
    }

    /// A sink that records each event's rendered JSONL, so the test can assert on
    /// what the writer produced from a `Record`.
    #[derive(Default)]
    struct CaptureSink(Mutex<Vec<String>>);
    impl Sink for CaptureSink {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, record: &kennel_audit::Record) -> Result<(), SinkError> {
            if let Ok(mut v) = self.0.lock() {
                v.push(record.to_jsonl());
            }
            Ok(())
        }
    }
    struct Shared(Arc<CaptureSink>);
    impl Sink for Shared {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, record: &kennel_audit::Record) -> Result<(), SinkError> {
            self.0.write(record)
        }
    }

    fn emit(record: &Record) -> String {
        let cap = Arc::new(CaptureSink::default());
        let ctx = WriterContext {
            kennel: "k".to_owned(),
            kennel_uuid: "u".to_owned(),
            host: "h".to_owned(),
        };
        let w = Writer::new(
            ctx,
            kennel_audit::Levels {
                net: kennel_audit::Level::Full,
                ..kennel_audit::Levels::default()
            },
            vec![Box::new(Shared(Arc::clone(&cap)))],
        );
        w.emit(&record.to_event());
        cap.0
            .lock()
            .ok()
            .and_then(|v| v.last().cloned())
            .unwrap_or_default()
    }

    #[test]
    fn allowed_record_shape() {
        let line = emit(&allowed(
            "example.com",
            443,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        assert!(line.contains(r#""event":"net.egress""#), "{line}");
        assert!(line.contains(r#""resource":"net""#));
        assert!(line.contains(r#""outcome":"allow""#));
        assert!(line.contains(r#""source":"proxy""#));
        assert!(line.contains(r#""wire":"socks5""#));
        assert!(line.contains(r#""egress_outcome":"allowed""#));
        assert!(line.contains(r#""host":"example.com""#));
        assert!(line.contains(r#""port":443"#));
        assert!(line.contains(r#""resolved":"93.184.216.34""#));
        assert!(line.contains(r#""bytes_up":10"#));
        assert!(line.contains(r#""bytes_down":200"#));
    }

    #[test]
    fn unresolved_deny_is_null_with_reason() {
        let r = Record {
            wire: Wire::HttpConnect,
            host: "blocked.example".to_owned(),
            port: 80,
            resolved: None,
            outcome: Outcome::Denied("not-allowed"),
        };
        let line = emit(&r);
        assert!(line.contains(r#""wire":"http-connect""#));
        assert!(line.contains(r#""resolved":null"#));
        assert!(line.contains(r#""outcome":"deny""#));
        assert!(line.contains(r#""reason":"not-allowed""#));
    }

    #[test]
    fn hostile_host_is_sanitised_by_the_writer() {
        // A host carrying a quote, a backslash, a newline, and an ESC.
        let line = emit(&allowed("a\"b\\c\nd\u{1b}e", 443, None));
        assert!(!line.contains('\n'), "no raw newline, got {line}");
        assert!(!line.contains('\u{1b}'), "no raw ESC, got {line}");
        // The writer flags that sanitisation altered an untrusted field.
        assert!(line.contains(r#""sanitised":true"#), "{line}");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn failed_outcome_maps_to_error_with_reason() {
        let r = Record {
            wire: Wire::Socks5,
            host: "h".to_owned(),
            port: 443,
            resolved: None,
            outcome: Outcome::Failed("connect-refused"),
        };
        let line = emit(&r);
        assert!(line.contains(r#""outcome":"error""#));
        assert!(line.contains(r#""egress_outcome":"failed""#));
        assert!(line.contains(r#""reason":"connect-refused""#));
    }
}
