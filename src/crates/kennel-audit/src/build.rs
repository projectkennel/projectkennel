//! Assembling a [`Writer`] with the standard sink set and the per-sink timeout.
//!
//! Sink construction lives here so the two writer-building call sites — kenneld
//! (from the settled `AuditRuntime`) and the netproxy (from its TOML config) —
//! share one implementation. Each constructed sink is wrapped in a
//! [`TimeoutSink`] so a stuck backend cannot block the writer.

use std::path::PathBuf;

use crate::sinks::{FileSink, StdoutSink, SyslogSink};
use crate::timeout::TimeoutSink;
use crate::writer::{Levels, Sink, Writer, WriterContext};

/// A sink to activate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkKind {
    /// Per-class JSONL files under the state dir (the default).
    File,
    /// JSONL on stdout.
    Stdout,
    /// RFC 5424 syslog to `/dev/log`.
    Syslog,
    /// systemd-journald (only emits when built with `audit-journald`).
    Journald,
}

impl SinkKind {
    /// Parse a sink token (`file`/`stdout`/`syslog`/`journald`).
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "file" => Some(Self::File),
            "stdout" => Some(Self::Stdout),
            "syslog" => Some(Self::Syslog),
            "journald" => Some(Self::Journald),
            _ => None,
        }
    }
}

/// How to build the sink set.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// The active sinks. Empty means the default: the file sink.
    pub kinds: Vec<SinkKind>,
    /// The per-kennel state directory the file sink writes its `<class>.jsonl` to.
    pub dir: PathBuf,
    /// Rotate a class file once it would exceed this many bytes (file sink).
    pub rotate_at_bytes: Option<u64>,
    /// Gzip a rotated file once it is at least this many seconds old (file sink).
    pub compress_after_seconds: Option<u64>,
    /// Keep at most this many rotated files per class (file sink).
    pub retain_count: Option<usize>,
    /// The syslog facility name (default `user`).
    pub syslog_facility: Option<String>,
}

/// Build a [`Writer`] over `ctx`, `levels`, and the sinks `cfg` selects.
///
/// Each sink is wrapped in a [`TimeoutSink`]. A sink that cannot be constructed
/// (a missing state dir, no `/dev/log`) is logged to stderr and skipped.
#[must_use]
pub fn writer(ctx: WriterContext, levels: Levels, cfg: &SinkConfig) -> Writer {
    let kinds = if cfg.kinds.is_empty() {
        vec![SinkKind::File]
    } else {
        cfg.kinds.clone()
    };
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    for kind in kinds {
        match kind {
            SinkKind::File => {
                match FileSink::new(
                    cfg.dir.clone(),
                    cfg.rotate_at_bytes,
                    cfg.compress_after_seconds,
                    cfg.retain_count,
                ) {
                    Ok(sink) => push_buffered(&mut sinks, Box::new(sink)),
                    Err(e) => eprintln!("kennel-audit: file sink unavailable: {e}"),
                }
            }
            SinkKind::Stdout => push_buffered(&mut sinks, Box::new(StdoutSink)),
            SinkKind::Syslog => {
                let facility = facility_code(cfg.syslog_facility.as_deref());
                match SyslogSink::new(PathBuf::from("/dev/log"), facility) {
                    Ok(sink) => push_buffered(&mut sinks, Box::new(sink)),
                    Err(e) => eprintln!("kennel-audit: syslog sink unavailable: {e}"),
                }
            }
            SinkKind::Journald => push_journald(&mut sinks),
        }
    }
    Writer::new(ctx, levels, sinks)
}

fn push_buffered(sinks: &mut Vec<Box<dyn Sink>>, inner: Box<dyn Sink>) {
    sinks.push(Box::new(TimeoutSink::new(inner)));
}

#[cfg(feature = "audit-journald")]
fn push_journald(sinks: &mut Vec<Box<dyn Sink>>) {
    push_buffered(sinks, Box::new(crate::journald::JournaldSink::new()));
}

#[cfg(not(feature = "audit-journald"))]
fn push_journald(_sinks: &mut Vec<Box<dyn Sink>>) {
    eprintln!("kennel-audit: journald sink requested but built without audit-journald");
}

/// The machine hostname for the envelope `host` field, from
/// `/proc/sys/kernel/hostname`; `localhost` if unreadable.
#[must_use]
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_or_else(|_| "localhost".to_owned(), |s| s.trim().to_owned())
}

/// Map an RFC 5424 facility name to its code; default `user` (1).
#[must_use]
pub fn facility_code(name: Option<&str>) -> u8 {
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
        // "user" and anything unrecognised.
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_known_sinks() {
        assert_eq!(SinkKind::parse("file"), Some(SinkKind::File));
        assert_eq!(SinkKind::parse("journald"), Some(SinkKind::Journald));
        assert_eq!(SinkKind::parse("nope"), None);
    }

    #[test]
    fn empty_kinds_default_to_file() {
        let dir = std::env::temp_dir().join(format!("kennel-audit-build-{}", std::process::id()));
        let cfg = SinkConfig {
            kinds: Vec::new(),
            dir: dir.clone(),
            rotate_at_bytes: None,
            compress_after_seconds: None,
            retain_count: None,
            syslog_facility: None,
        };
        let ctx = WriterContext {
            kennel: "k".to_owned(),
            kennel_uuid: "u".to_owned(),
            host: "h".to_owned(),
        };
        // Builds without panicking and creates the state dir for the file sink.
        let _writer = writer(ctx, Levels::default(), &cfg);
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn facilities_map_to_codes() {
        assert_eq!(facility_code(Some("local0")), 16);
        assert_eq!(facility_code(Some("daemon")), 3);
        assert_eq!(facility_code(None), 1);
        assert_eq!(facility_code(Some("nonsense")), 1);
    }
}
