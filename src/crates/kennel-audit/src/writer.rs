//! The unified writer: the seam between event sources and sinks.
//!
//! A source builds an [`Event`]; [`Writer::emit`] stamps the envelope fields the
//! writer owns, runs the one content-sanitisation pass, applies the per-class
//! audit level (including `summary` first-allow dedup), and fans the rendered
//! record out to every configured [`Sink`]. A sink that fails is reported to the
//! *other* sinks as a `lifecycle.audit-drop`, never to itself, so a wholly-down
//! sink degrades to a stderr self-diagnostic rather than a loop.

use std::collections::HashSet;
use std::sync::Mutex;

use crate::event::{Event, Level, Outcome, Resource, Source, Value};
use crate::render::{Record, Rendered, ENVELOPE_KEYS};
use crate::time::{Clock, SystemClock};

/// The current audit schema version (`02-3` §Stability commitment).
pub const SCHEMA_VERSION: u64 = 1;

/// The maximum rendered size of a single event for the line-oriented sinks.
///
/// A `write()` of at most `PIPE_BUF` bytes is atomic on Linux; the file sink
/// rejects anything larger (a longer event is a bug, not a runtime case).
pub const MAX_EVENT_BYTES: usize = 4096;

/// Per-kennel context the writer stamps onto every event.
#[derive(Clone, Debug)]
pub struct WriterContext {
    /// The kennel name (operator-set and policy-validated).
    pub kennel: String,
    /// The per-instance `UUIDv7`, grouping one kennel lifetime's events.
    pub kennel_uuid: String,
    /// The hostname at writer-construction time.
    pub host: String,
}

/// The per-class audit levels (`02-3` §Audit levels). Lifecycle and privileged
/// events ignore these and are always emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    /// `net` class level.
    pub net: Level,
    /// `fs` class level.
    pub fs: Level,
    /// `exec` class level.
    pub exec: Level,
    /// `unix` class level.
    pub unix: Level,
    /// `dbus` class level.
    pub dbus: Level,
}

impl Default for Levels {
    fn default() -> Self {
        // Defaults per 02-3: summary everywhere except filesystem (high-volume),
        // which is denies-only.
        Self {
            net: Level::Summary,
            fs: Level::DeniesOnly,
            exec: Level::Summary,
            unix: Level::Summary,
            dbus: Level::Summary,
        }
    }
}

impl Levels {
    const fn for_resource(self, resource: Resource) -> Level {
        match resource {
            Resource::Net => self.net,
            Resource::Fs => self.fs,
            Resource::Exec => self.exec,
            Resource::Unix => self.unix,
            Resource::Dbus => self.dbus,
            // Always-emitted classes: treated as Full so they never filter.
            Resource::Priv | Resource::Lifecycle => Level::Full,
        }
    }
}

/// An error from one sink's emit.
#[derive(Debug)]
pub struct SinkError {
    /// The sink that failed.
    pub sink: &'static str,
    /// A human-readable cause.
    pub message: String,
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit sink {}: {}", self.sink, self.message)
    }
}

impl std::error::Error for SinkError {}

/// An output target for the canonical event stream.
pub trait Sink: Send + Sync {
    /// The stable sink name, for diagnostics and drop records.
    fn name(&self) -> &'static str;
    /// Emit one rendered record.
    ///
    /// # Errors
    /// Returns a [`SinkError`] if the sink cannot emit the record; the writer
    /// reports it to the other sinks.
    fn write(&self, record: &Record) -> Result<(), SinkError>;
}

/// The unified audit writer.
pub struct Writer {
    ctx: WriterContext,
    levels: Levels,
    sinks: Vec<Box<dyn Sink>>,
    clock: Box<dyn Clock>,
    /// `(resource\0target)` keys already emitted, for `summary` first-allow dedup.
    seen: Mutex<HashSet<String>>,
}

impl Writer {
    /// Construct a writer over the real system clock.
    #[must_use]
    pub fn new(ctx: WriterContext, levels: Levels, sinks: Vec<Box<dyn Sink>>) -> Self {
        Self::with_clock(ctx, levels, sinks, Box::new(SystemClock))
    }

    /// Construct a writer with an explicit clock (tests).
    #[must_use]
    pub fn with_clock(
        ctx: WriterContext,
        levels: Levels,
        sinks: Vec<Box<dyn Sink>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            ctx,
            levels,
            sinks,
            clock,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Emit one event: filter by level, render, and fan out. Returns whether the
    /// event passed the level filter (useful in tests; callers ignore it).
    pub fn emit(&self, event: &Event) -> bool {
        if !self.should_emit(event) {
            return false;
        }
        let record = self.render(event);
        self.fan_out(&record);
        true
    }

    /// Apply the per-class level. May record a `(resource, target)` pair so the
    /// next matching allow is suppressed under `summary`.
    fn should_emit(&self, event: &Event) -> bool {
        if event.resource.always_emitted() {
            return true;
        }
        match self.levels.for_resource(event.resource) {
            Level::Off => false,
            Level::DeniesOnly => event.outcome == Outcome::Deny,
            Level::Full => true,
            Level::Summary => {
                if event.outcome != Outcome::Allow {
                    // Denies, errors, and info always pass under summary.
                    return true;
                }
                // First allow per (resource, target) only.
                let key = match &event.target {
                    Some(t) => format!("{}\0{t}", event.resource.token()),
                    // No target: every allow is "first"; emit it.
                    None => return true,
                };
                // A poisoned lock must not silently drop audit, so emit on Err.
                self.seen.lock().map_or(true, |mut seen| seen.insert(key))
            }
        }
    }

    /// Build the canonical, sanitised, ordered record.
    fn render(&self, event: &Event) -> Record {
        let (secs, micros) = self.clock.now_unix_micros();
        let ts = crate::time::format_rfc3339_micros(secs, micros);

        let mut sanitised = false;
        let mut fields: Vec<(&'static str, Rendered)> =
            Vec::with_capacity(ENVELOPE_KEYS.len().saturating_add(event.fields.len()));

        fields.push(("schema_version", Rendered::Uint(SCHEMA_VERSION)));
        fields.push(("ts", Rendered::Str(ts)));
        fields.push(("kennel", Rendered::Str(self.ctx.kennel.clone())));
        fields.push(("kennel_uuid", Rendered::Str(self.ctx.kennel_uuid.clone())));
        fields.push(("event", Rendered::Str(event.event.to_owned())));
        fields.push(("resource", Rendered::Str(event.resource.token().to_owned())));
        fields.push(("outcome", Rendered::Str(event.outcome.token().to_owned())));
        fields.push(("source", Rendered::Str(event.source.token().to_owned())));
        fields.push(("host", Rendered::Str(self.ctx.host.clone())));
        if let Some(pid) = event.pid {
            fields.push(("pid", Rendered::Uint(u64::from(pid))));
        }
        if let Some(comm) = &event.comm {
            fields.push(("comm", Rendered::Str(sanitise(comm, &mut sanitised))));
        }
        for (key, value) in &event.fields {
            fields.push((key, render_value(value, &mut sanitised)));
        }
        if sanitised {
            fields.push(("sanitised", Rendered::Bool(true)));
        }

        Record {
            resource: event.resource,
            event_type: event.event,
            outcome: event.outcome,
            fields,
        }
    }

    fn fan_out(&self, record: &Record) {
        for (index, sink) in self.sinks.iter().enumerate() {
            if let Err(err) = sink.write(record) {
                self.report_drop(&err, index);
            }
        }
    }

    /// Record a sink failure in the *other* sinks (never the one that failed,
    /// and without a level check), falling back to stderr if none take it.
    fn report_drop(&self, err: &SinkError, failed_index: usize) {
        let drop = Record {
            resource: Resource::Lifecycle,
            event_type: "lifecycle.audit-drop",
            outcome: Outcome::Error,
            fields: vec![
                ("schema_version", Rendered::Uint(SCHEMA_VERSION)),
                ("event", Rendered::Str("lifecycle.audit-drop".to_owned())),
                ("resource", Rendered::Str("lifecycle".to_owned())),
                ("outcome", Rendered::Str("error".to_owned())),
                ("source", Rendered::Str(Source::Kenneld.token().to_owned())),
                ("kennel", Rendered::Str(self.ctx.kennel.clone())),
                ("failed_sink", Rendered::Str(err.sink.to_owned())),
                (
                    "reason",
                    Rendered::Str(kennel_text::sanitise_for_audit(&err.message)),
                ),
            ],
        };
        let mut delivered = false;
        for (index, sink) in self.sinks.iter().enumerate() {
            if index == failed_index {
                continue;
            }
            if sink.write(&drop).is_ok() {
                delivered = true;
            }
        }
        if !delivered {
            eprintln!(
                "kennel-audit: sink {} failed and no other sink accepted the drop record: {}",
                err.sink, err.message
            );
        }
    }
}

fn sanitise(s: &str, changed: &mut bool) -> String {
    let clean = kennel_text::sanitise_for_audit(s);
    if clean != s {
        *changed = true;
    }
    clean
}

fn render_value(value: &Value, sanitised: &mut bool) -> Rendered {
    match value {
        Value::Str(s) => Rendered::Str(s.clone()),
        Value::Untrusted(s) => Rendered::Str(sanitise(s, sanitised)),
        Value::Int(i) => Rendered::Int(*i),
        Value::Uint(u) => Rendered::Uint(*u),
        Value::Bool(b) => Rendered::Bool(*b),
        Value::Null => Rendered::Null,
        Value::Array(items) => {
            Rendered::Array(items.iter().map(|v| render_value(v, sanitised)).collect())
        }
        Value::Object(entries) => Rendered::Object(
            entries
                .iter()
                .map(|(k, v)| (*k, render_value(v, sanitised)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that records the JSONL of every record it receives.
    #[derive(Default)]
    struct CaptureSink {
        lines: Mutex<Vec<String>>,
    }
    impl CaptureSink {
        fn lines(&self) -> Vec<String> {
            self.lines.lock().map(|v| v.clone()).unwrap_or_default()
        }
    }
    impl Sink for CaptureSink {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, record: &Record) -> Result<(), SinkError> {
            if let Ok(mut v) = self.lines.lock() {
                v.push(record.to_jsonl());
            }
            Ok(())
        }
    }

    // A capture sink behind an Arc so the test keeps a handle while the writer
    // owns a Box pointing at the same data.
    use std::sync::Arc;
    struct Shared(Arc<CaptureSink>);
    impl Sink for Shared {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, record: &Record) -> Result<(), SinkError> {
            self.0.write(record)
        }
    }

    fn writer_with(levels: Levels) -> (Writer, Arc<CaptureSink>) {
        let cap = Arc::new(CaptureSink::default());
        let ctx = WriterContext {
            kennel: "ai-coding".to_owned(),
            kennel_uuid: "01HZX".to_owned(),
            host: "workstation".to_owned(),
        };
        let w = Writer::with_clock(
            ctx,
            levels,
            vec![Box::new(Shared(Arc::clone(&cap)))],
            Box::new(crate::time::SystemClock),
        );
        (w, cap)
    }

    #[test]
    fn envelope_is_stamped_in_canonical_order() {
        let (w, cap) = writer_with(Levels::default());
        let e = Event::new(
            "net.connect-deny",
            Resource::Net,
            Outcome::Deny,
            Source::Bpf,
        )
        .pid(12_345)
        .field("addr", Value::str("169.254.169.254"))
        .field("port", Value::Uint(80));
        assert!(w.emit(&e));
        let line = cap.lines().pop().unwrap_or_default();
        assert!(line.contains(r#""schema_version":1"#), "{line}");
        assert!(line.contains(r#""kennel":"ai-coding""#));
        assert!(line.contains(r#""source":"bpf""#));
        assert!(line.contains(r#""pid":12345"#));
        // schema_version precedes kennel precedes addr (canonical order).
        let sv = line.find("schema_version").unwrap_or(usize::MAX);
        let kn = line.find("\"kennel\"").unwrap_or(0);
        let ad = line.find("addr").unwrap_or(0);
        assert!(sv < kn && kn < ad, "order wrong: {line}");
    }

    #[test]
    fn denies_only_drops_allows() {
        let levels = Levels {
            fs: Level::DeniesOnly,
            ..Levels::default()
        };
        let (w, cap) = writer_with(levels);
        let allow = Event::new(
            "fs.access-allow",
            Resource::Fs,
            Outcome::Allow,
            Source::Kernel,
        );
        let deny = Event::new(
            "fs.access-deny",
            Resource::Fs,
            Outcome::Deny,
            Source::Kernel,
        );
        assert!(!w.emit(&allow));
        assert!(w.emit(&deny));
        assert_eq!(cap.lines().len(), 1);
    }

    #[test]
    fn summary_dedups_allows_by_target() {
        let (w, cap) = writer_with(Levels::default());
        let mk = || {
            Event::new(
                "net.connect-allow",
                Resource::Net,
                Outcome::Allow,
                Source::Bpf,
            )
            .target("example.com:443")
        };
        assert!(w.emit(&mk()), "first allow passes");
        assert!(!w.emit(&mk()), "second identical allow is deduped");
        // A deny to the same target still passes.
        let deny = Event::new(
            "net.connect-deny",
            Resource::Net,
            Outcome::Deny,
            Source::Bpf,
        )
        .target("example.com:443");
        assert!(w.emit(&deny));
        assert_eq!(cap.lines().len(), 2);
    }

    #[test]
    fn off_emits_nothing_for_the_class() {
        let levels = Levels {
            net: Level::Off,
            ..Levels::default()
        };
        let (w, cap) = writer_with(levels);
        let deny = Event::new(
            "net.connect-deny",
            Resource::Net,
            Outcome::Deny,
            Source::Bpf,
        );
        assert!(!w.emit(&deny));
        assert!(cap.lines().is_empty());
    }

    #[test]
    fn lifecycle_ignores_level_off() {
        let levels = Levels {
            net: Level::Off,
            ..Levels::default()
        };
        let (w, cap) = writer_with(levels);
        let life = Event::new(
            "lifecycle.kennel-start",
            Resource::Lifecycle,
            Outcome::Info,
            Source::Kenneld,
        );
        assert!(w.emit(&life));
        assert_eq!(cap.lines().len(), 1);
    }

    #[test]
    fn untrusted_fields_are_sanitised_and_flagged() {
        let (w, cap) = writer_with(Levels::default());
        let e = Event::new("exec.deny", Resource::Exec, Outcome::Deny, Source::Kernel)
            .field("binary", Value::untrusted("/bin/\u{1b}[2Jevil"));
        assert!(w.emit(&e));
        let line = cap.lines().pop().unwrap_or_default();
        assert!(!line.contains('\u{1b}'), "raw ESC leaked: {line}");
        assert!(line.contains(r#""sanitised":true"#), "{line}");
    }
}
