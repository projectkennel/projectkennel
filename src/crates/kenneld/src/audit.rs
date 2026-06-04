//! The per-kennel audit writer kenneld builds, and the events it emits.
//!
//! kenneld constructs the `kennel-audit` writer from the settled
//! [`AuditRuntime`] and records lifecycle events through it (`02-3`).
//! kenneld is one userspace audit *source* (daemon and kennel lifecycle); the
//! netproxy is the other. Sink/writer assembly is shared via
//! [`kennel_audit::build`]; kenneld maps the settled runtime onto it.

use std::path::Path;

use kennel_audit::build::{writer, SinkConfig};
use kennel_audit::{
    Event, Level, Levels, Outcome, Resource, SinkKind, Source, Value, Writer, WriterContext,
};
use kennel_policy::{AuditRuntime, AuditSinkKind};

/// Generate a per-kennel `kennel_uuid` (a `UUIDv7`).
///
/// The current Unix-millisecond time plus ten CSPRNG bytes. A best-effort
/// fallback (zero timestamp / zero randomness) keeps a running kennel observable
/// even if the clock or `getrandom` misbehaves.
#[must_use]
pub fn kennel_uuid() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let rand = kennel_syscall::random::bytes::<10>().unwrap_or([0_u8; 10]);
    kennel_audit::format_uuid_v7(ms, rand)
}

/// Build the writer for a kennel from the settled `runtime`.
///
/// Its sinks and per-class levels come from `runtime`, its file sink is rooted at
/// `state_dir`, and it is stamped with `name` and `kennel_uuid`. The caller
/// supplies `kennel_uuid` so the per-kennel egress proxy (a separate process) can
/// be given the same id and its events correlate with these.
#[must_use]
pub fn build_writer(
    name: &str,
    state_dir: &Path,
    runtime: &AuditRuntime,
    kennel_uuid: String,
) -> Writer {
    let ctx = WriterContext {
        kennel: name.to_owned(),
        kennel_uuid,
        host: kennel_audit::hostname(),
    };
    let cfg = SinkConfig {
        kinds: runtime.sinks.iter().map(|k| sink_kind(*k)).collect(),
        dir: state_dir.to_path_buf(),
        rotate_at_bytes: runtime.file.rotate_at_bytes,
        retain_count: runtime
            .file
            .retain_count
            .and_then(|n| usize::try_from(n).ok()),
        syslog_facility: runtime.syslog_facility.clone(),
    };
    writer(ctx, levels_from(runtime), &cfg)
}

const fn sink_kind(kind: AuditSinkKind) -> SinkKind {
    match kind {
        AuditSinkKind::File => SinkKind::File,
        AuditSinkKind::Stdout => SinkKind::Stdout,
        AuditSinkKind::Syslog => SinkKind::Syslog,
        AuditSinkKind::Journald => SinkKind::Journald,
    }
}

fn levels_from(runtime: &AuditRuntime) -> Levels {
    let mut levels = Levels::default();
    if let Some(l) = parse_level(runtime.network_level.as_deref()) {
        levels.net = l;
    }
    if let Some(l) = parse_level(runtime.filesystem_level.as_deref()) {
        levels.fs = l;
    }
    if let Some(l) = parse_level(runtime.exec_level.as_deref()) {
        levels.exec = l;
    }
    if let Some(l) = parse_level(runtime.unix_level.as_deref()) {
        levels.unix = l;
    }
    if let Some(l) = parse_level(runtime.dbus_level.as_deref()) {
        levels.dbus = l;
    }
    levels
}

fn parse_level(token: Option<&str>) -> Option<Level> {
    token.and_then(Level::parse)
}

/// `lifecycle.kennel-start`: the workload was spawned (`started_pid`).
#[must_use]
pub fn kennel_start(pid: u32, ctx: u16) -> Event {
    Event::new(
        "lifecycle.kennel-start",
        Resource::Lifecycle,
        Outcome::Info,
        Source::Kenneld,
    )
    .pid(pid)
    .field("ctx", Value::Uint(u64::from(ctx)))
    .field("started_pid", Value::Uint(u64::from(pid)))
}

/// `lifecycle.workload-exit`: the workload exited with `exit_code`.
#[must_use]
pub fn workload_exit(pid: u32, exit_code: i32) -> Event {
    Event::new(
        "lifecycle.workload-exit",
        Resource::Lifecycle,
        Outcome::Info,
        Source::Kenneld,
    )
    .pid(pid)
    .field("exit_code", Value::Int(i64::from(exit_code)))
}

/// `lifecycle.kennel-exit`: the kennel was torn down.
#[must_use]
pub fn kennel_exit(reason: &'static str) -> Event {
    Event::new(
        "lifecycle.kennel-exit",
        Resource::Lifecycle,
        Outcome::Info,
        Source::Kenneld,
    )
    .field("reason", Value::str(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_is_v7_shaped() {
        let id = kennel_uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().nth(14), Some('7'));
    }

    #[test]
    fn levels_default_when_unset_and_override_when_set() {
        let mut rt = AuditRuntime::default();
        assert_eq!(levels_from(&rt).fs, Level::DeniesOnly);
        rt.filesystem_level = Some("full".to_owned());
        rt.network_level = Some("off".to_owned());
        let l = levels_from(&rt);
        assert_eq!(l.fs, Level::Full);
        assert_eq!(l.net, Level::Off);
    }

    #[test]
    fn writer_emits_a_lifecycle_event_to_a_file_sink() {
        let dir = std::env::temp_dir().join(format!("kenneld-audit-life-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let writer = build_writer(
            "ai-coding",
            &dir,
            &AuditRuntime::default(),
            "test-uuid".to_owned(),
        );
        assert!(writer.emit(&kennel_start(4242, 7)));
        // Sinks are buffered (TimeoutSink); dropping the writer joins the worker
        // so the event is flushed to the file before we read it.
        drop(writer);
        let body = std::fs::read_to_string(dir.join("lifecycle.jsonl")).expect("lifecycle log");
        assert!(
            body.contains(r#""event":"lifecycle.kennel-start""#),
            "{body}"
        );
        assert!(body.contains(r#""kennel":"ai-coding""#));
        assert!(body.contains(r#""kennel_uuid":"test-uuid""#));
        assert!(body.contains(r#""started_pid":4242"#));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
