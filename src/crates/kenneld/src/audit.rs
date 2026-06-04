//! The per-kennel audit writer kenneld builds, and the events it emits.
//!
//! kenneld constructs the `kennel-audit` writer from the settled
//! [`AuditRuntime`] and records lifecycle events through it (`02-3`).
//! kenneld is one audit *source* (daemon and kennel lifecycle); the netproxy,
//! the privhelper, and the BPF programs are the others. The writer applies the
//! sinks and per-class levels the policy selected, falling back to the `02-3`
//! defaults (file sink, summary/denies-only levels) for anything the policy left
//! unset.

use std::path::Path;

use kennel_audit::{
    Event, FileSink, Level, Levels, Outcome, Resource, Sink, Source, StdoutSink, SyslogSink, Value,
    Writer, WriterContext,
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

/// Build the writer for a kennel: its sinks and per-class levels from `runtime`,
/// its file sink rooted at `state_dir`, stamped with `name` and a fresh
/// `kennel_uuid`.
#[must_use]
pub fn build_writer(name: &str, state_dir: &Path, runtime: &AuditRuntime) -> Writer {
    let ctx = WriterContext {
        kennel: name.to_owned(),
        kennel_uuid: kennel_uuid(),
        host: hostname(),
    };
    Writer::new(ctx, levels_from(runtime), sinks_from(runtime, state_dir))
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

fn sinks_from(runtime: &AuditRuntime, state_dir: &Path) -> Vec<Box<dyn Sink>> {
    // An unset sink list means the 02-3 default: the file sink.
    let kinds = if runtime.sinks.is_empty() {
        vec![AuditSinkKind::File]
    } else {
        runtime.sinks.clone()
    };
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    for kind in kinds {
        match kind {
            AuditSinkKind::File => {
                let retain = runtime
                    .file
                    .retain_count
                    .and_then(|n| usize::try_from(n).ok());
                match FileSink::new(
                    state_dir.to_path_buf(),
                    runtime.file.rotate_at_bytes,
                    retain,
                ) {
                    Ok(sink) => sinks.push(Box::new(sink)),
                    Err(e) => eprintln!("kennel-audit: file sink unavailable: {e}"),
                }
            }
            AuditSinkKind::Stdout => sinks.push(Box::new(StdoutSink)),
            AuditSinkKind::Syslog => {
                let facility = facility_code(runtime.syslog_facility.as_deref());
                match SyslogSink::new(std::path::PathBuf::from("/dev/log"), facility) {
                    Ok(sink) => sinks.push(Box::new(sink)),
                    Err(e) => eprintln!("kennel-audit: syslog sink unavailable: {e}"),
                }
            }
            AuditSinkKind::Journald => push_journald(&mut sinks),
        }
    }
    sinks
}

#[cfg(feature = "audit-journald")]
fn push_journald(sinks: &mut Vec<Box<dyn Sink>>) {
    sinks.push(Box::new(kennel_audit::JournaldSink::new()));
}

#[cfg(not(feature = "audit-journald"))]
fn push_journald(_sinks: &mut [Box<dyn Sink>]) {
    eprintln!("kennel-audit: journald sink requested but kenneld was built without audit-journald");
}

/// Map an RFC 5424 facility name to its code; default `user` (1).
fn facility_code(name: Option<&str>) -> u8 {
    match name {
        Some("kern") => 0,
        Some("mail") => 2,
        Some("daemon") => 3,
        Some("auth") => 4,
        Some("syslog") => 5,
        Some("lpr") => 6,
        Some("news") => 7,
        Some("uucp") => 8,
        Some("cron") => 9,
        Some("authpriv") => 10,
        Some("ftp") => 11,
        Some("local0") => 16,
        Some("local1") => 17,
        Some("local2") => 18,
        Some("local3") => 19,
        Some("local4") => 20,
        Some("local5") => 21,
        Some("local6") => 22,
        Some("local7") => 23,
        // "user" and anything unrecognised (already validated at compile time).
        _ => 1,
    }
}

/// The machine hostname for the envelope `host` field, from
/// `/proc/sys/kernel/hostname`; `localhost` if unreadable.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_or_else(|_| "localhost".to_owned(), |s| s.trim().to_owned())
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
    fn empty_runtime_yields_the_file_sink() {
        let dir = std::env::temp_dir().join(format!("kenneld-audit-{}", std::process::id()));
        let sinks = sinks_from(&AuditRuntime::default(), &dir);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks.first().map(|s| s.name()), Some("file"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn facilities_map_to_codes() {
        assert_eq!(facility_code(Some("local0")), 16);
        assert_eq!(facility_code(Some("daemon")), 3);
        assert_eq!(facility_code(None), 1);
        assert_eq!(facility_code(Some("nonsense")), 1);
    }

    #[test]
    fn writer_emits_a_lifecycle_event_to_a_file_sink() {
        let dir = std::env::temp_dir().join(format!("kenneld-audit-life-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let writer = build_writer("ai-coding", &dir, &AuditRuntime::default());
        assert!(writer.emit(&kennel_start(4242, 7)));
        let body = std::fs::read_to_string(dir.join("lifecycle.jsonl")).expect("lifecycle log");
        assert!(
            body.contains(r#""event":"lifecycle.kennel-start""#),
            "{body}"
        );
        assert!(body.contains(r#""kennel":"ai-coding""#));
        assert!(body.contains(r#""started_pid":4242"#));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
