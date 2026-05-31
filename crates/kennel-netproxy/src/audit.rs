//! Structured audit records for proxied requests (CODING-STANDARDS.md §9.2).
//!
//! Every request the proxy handles — allowed or denied — produces one JSON Lines
//! record. This is the security-relevant stream (§9.2), distinct from developer
//! logging: it is what a SIEM consumes to see where confined workloads tried to
//! reach. The proxy *is* the policy decision, so the record is authoritative —
//! no correlation with kernel events is needed (`docs/07-3-network.md` §7.3.2).
//!
//! # Input handling
//!
//! The requested host is attacker-controlled (it came from the confined
//! workload). It is emitted as a JSON string value through a serialiser that
//! escapes every control character and the JSON metacharacters (§10.3: JSON is
//! never built by raw concatenation of untrusted bytes). A consumer rendering
//! the record to a terminal still applies its own sanitisation, but the record
//! itself is always well-formed JSON with no raw control bytes.
//!
//! # Non-goals
//!
//! This module does not write the records anywhere — it formats them. The server
//! owns the sink (a file under the kennel's state dir, or an fd kenneld passed).
//! It does not carry payload bytes (§9.3): only the destination, byte counts,
//! and the policy outcome.

use std::fmt::Write as _;
use std::net::IpAddr;

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
    pub resolved: Option<IpAddr>,
    /// The policy outcome.
    pub outcome: Outcome,
}

impl Record {
    /// Render this record as a single JSON Lines entry (no trailing newline).
    ///
    /// The output is always well-formed JSON: every string value is escaped, so
    /// an attacker-controlled host cannot break the structure or inject control
    /// bytes.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push('{');
        push_str_field(&mut out, "event", "egress");
        out.push(',');
        push_str_field(&mut out, "wire", self.wire.token());
        out.push(',');
        push_key(&mut out, "host");
        push_json_string(&mut out, &self.host);
        out.push(',');
        push_key(&mut out, "port");
        // A u16 is plain ASCII digits; no escaping needed.
        let _ = write!(out, "{}", self.port);
        out.push(',');
        push_key(&mut out, "resolved");
        match self.resolved {
            Some(addr) => push_json_string(&mut out, &addr.to_string()),
            None => out.push_str("null"),
        }
        out.push(',');
        match self.outcome {
            Outcome::Allowed {
                bytes_up,
                bytes_down,
            } => {
                push_str_field(&mut out, "outcome", "allowed");
                let _ = write!(out, ",\"bytes_up\":{bytes_up},\"bytes_down\":{bytes_down}");
            }
            Outcome::Denied(reason) => {
                push_str_field(&mut out, "outcome", "denied");
                out.push(',');
                push_str_field(&mut out, "reason", reason);
            }
            Outcome::Failed(reason) => {
                push_str_field(&mut out, "outcome", "failed");
                out.push(',');
                push_str_field(&mut out, "reason", reason);
            }
        }
        out.push('}');
        out
    }
}

/// Append `"key":` to `out`. Keys here are all internal string literals.
fn push_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

/// Append `"key":"value"` for an internal (trusted) string value.
fn push_str_field(out: &mut String, key: &str, value: &str) {
    push_key(out, key);
    push_json_string(out, value);
}

/// Append `s` as a quoted, escaped JSON string. Control characters become the
/// short escapes or `\u00XX`, and `"` and `\` are escaped, so the result is
/// valid JSON regardless of `s`'s contents.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Other C0 control characters: \u00XX.
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
    use std::net::Ipv4Addr;

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

    #[test]
    fn allowed_record_shape() {
        let r = allowed(
            "example.com",
            443,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        );
        let line = r.to_jsonl();
        let expected = concat!(
            r#"{"event":"egress","wire":"socks5","host":"example.com","port":443,"#,
            r#""resolved":"93.184.216.34","outcome":"allowed","bytes_up":10,"bytes_down":200}"#
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn unresolved_is_null() {
        let r = Record {
            wire: Wire::HttpConnect,
            host: "blocked.example".to_owned(),
            port: 80,
            resolved: None,
            outcome: Outcome::Denied("not-allowed"),
        };
        let line = r.to_jsonl();
        assert!(line.contains(r#""wire":"http-connect""#));
        assert!(line.contains(r#""resolved":null"#));
        assert!(line.contains(r#""outcome":"denied","reason":"not-allowed""#));
    }

    #[test]
    fn hostile_host_cannot_break_json_or_inject_control_bytes() {
        // A host carrying a quote, a backslash, a newline, and an ESC.
        let r = allowed("a\"b\\c\nd\u{1b}e", 443, None);
        let line = r.to_jsonl();
        // No raw control bytes survive into the record.
        assert!(!line.contains('\n'), "no raw newline, got {line}");
        assert!(!line.contains('\u{1b}'), "no raw ESC, got {line}");
        // Quote and backslash are escaped; the ESC becomes its \u00XX escape.
        assert!(line.contains("\\\""), "escaped quote present, got {line}");
        assert!(
            line.contains("\\\\"),
            "escaped backslash present, got {line}"
        );
        assert!(
            line.contains("\\u001b"),
            "ESC escaped as \\u001b, got {line}"
        );
        // The whole record is still a single line.
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn failed_outcome_carries_reason() {
        let r = Record {
            wire: Wire::Socks5,
            host: "h".to_owned(),
            port: 443,
            resolved: None,
            outcome: Outcome::Failed("connect-refused"),
        };
        assert!(r
            .to_jsonl()
            .contains(r#""outcome":"failed","reason":"connect-refused""#));
    }
}
