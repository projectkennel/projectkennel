//! The dependency-free sinks: JSONL file (the default), stdout, and RFC 5424
//! syslog. The journald sink lives in the `journald` module behind a feature
//! flag because it alone needs FFI.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::event::Resource;
use crate::render::{Record, Rendered};
use crate::time::{Clock, SystemClock};
use crate::writer::{Sink, SinkError, MAX_EVENT_BYTES};

fn oversize(sink: &'static str, len: usize) -> SinkError {
    SinkError {
        sink,
        message: format!("event of {len} bytes exceeds the {MAX_EVENT_BYTES}-byte atomic limit"),
    }
}

fn io_err(sink: &'static str, context: &str, err: &std::io::Error) -> SinkError {
    SinkError {
        sink,
        message: format!("{context}: {err}"),
    }
}

// ---------------------------------------------------------------------------
// File sink
// ---------------------------------------------------------------------------

/// The default sink: one append-only JSONL file per resource class.
///
/// Files live under the per-kennel state directory. Each write is a single
/// `open(O_APPEND)` + `write` of at most [`MAX_EVENT_BYTES`], so it is atomic
/// and safe for the concurrent writers (kenneld and the netproxy both append to
/// `network.jsonl`).
pub struct FileSink {
    dir: PathBuf,
    rotate_at_bytes: Option<u64>,
    compress_after_seconds: Option<u64>,
    retain_count: Option<usize>,
    clock: Box<dyn Clock>,
    // Serialises this process's rotation so a size-check and rename do not race
    // within the process; cross-process rotation is benign (append handles
    // follow the renamed inode).
    rotate_lock: Mutex<()>,
}

impl FileSink {
    /// Create a file sink writing under `dir` (created if absent).
    ///
    /// `rotate_at_bytes` rotates a class file once it would exceed that size;
    /// `compress_after_seconds` gzips a rotated file once it is at least that
    /// old (lazily, at the next rotation); `retain_count` keeps at most that
    /// many rotated files per class. `None` for any disables that behaviour.
    ///
    /// # Errors
    /// Returns the underlying error if `dir` cannot be created.
    pub fn new(
        dir: PathBuf,
        rotate_at_bytes: Option<u64>,
        compress_after_seconds: Option<u64>,
        retain_count: Option<usize>,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            rotate_at_bytes,
            compress_after_seconds,
            retain_count,
            clock: Box::new(SystemClock),
            rotate_lock: Mutex::new(()),
        })
    }

    /// As [`FileSink::new`] but with an explicit clock for the rotation suffix
    /// (tests).
    ///
    /// # Errors
    /// Returns the underlying error if `dir` cannot be created.
    pub fn with_clock(
        dir: PathBuf,
        rotate_at_bytes: Option<u64>,
        compress_after_seconds: Option<u64>,
        retain_count: Option<usize>,
        clock: Box<dyn Clock>,
    ) -> std::io::Result<Self> {
        let mut sink = Self::new(dir, rotate_at_bytes, compress_after_seconds, retain_count)?;
        sink.clock = clock;
        Ok(sink)
    }

    fn path_for(&self, resource: Resource) -> PathBuf {
        self.dir.join(format!("{}.jsonl", resource.file_stem()))
    }

    /// Rotate `path` if appending `incoming` bytes would cross the threshold.
    fn maybe_rotate(&self, resource: Resource, path: &Path, incoming: usize) {
        let Some(limit) = self.rotate_at_bytes else {
            return;
        };
        // Scope the rotation lock: the rename and retention sweep are serialised,
        // but the (slower, fork-exec) compression sweep runs after it is dropped.
        let rotated = {
            let Ok(_guard) = self.rotate_lock.lock() else {
                return;
            };
            let current = std::fs::metadata(path).map_or(0, |m| m.len());
            if current.saturating_add(incoming as u64) <= limit {
                return;
            }
            let (secs, _) = self.clock.now_unix_micros();
            let dest = self
                .dir
                .join(format!("{}.{secs}.jsonl", resource.file_stem()));
            // A failed rename just means we keep appending to the live file; not
            // fatal for audit integrity.
            if std::fs::rename(path, &dest).is_ok() {
                self.enforce_retention(resource);
                true
            } else {
                false
            }
        };
        if rotated {
            self.maybe_compress(resource);
        }
    }

    /// Gzip rotated files for a class that are at least `compress_after_seconds`
    /// old. Best-effort: shells out to the system `gzip(1)` on the closed,
    /// already-rotated file (never the live append target), and degrades to
    /// leaving the file uncompressed if `gzip` is missing, denied, or fails.
    fn maybe_compress(&self, resource: Resource) {
        let Some(after) = self.compress_after_seconds else {
            return;
        };
        let after = i64::try_from(after).unwrap_or(i64::MAX);
        let (now, _) = self.clock.now_unix_micros();
        let prefix = format!("{}.", resource.file_stem());
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Only uncompressed rotated files: "<stem>.<digits>.jsonl".
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            let Some(stamp) = rest.strip_suffix(".jsonl") else {
                continue;
            };
            let Ok(ts) = stamp.parse::<i64>() else {
                continue;
            };
            if now.saturating_sub(ts) < after {
                continue;
            }
            let path = entry.path();
            // Skip if a prior run already produced the .gz (gzip would refuse).
            let mut gz = path.clone().into_os_string();
            gz.push(".gz");
            if Path::new(&gz).exists() {
                continue;
            }
            gzip_file(&path);
        }
    }

    /// Delete the oldest rotated files for a class beyond `retain_count`,
    /// counting compressed (`.jsonl.gz`) and uncompressed rotations alike.
    fn enforce_retention(&self, resource: Resource) {
        let Some(keep) = self.retain_count else {
            return;
        };
        let prefix = format!("{}.", resource.file_stem());
        let mut rotated: Vec<(i64, PathBuf)> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Match "<stem>.<digits>.jsonl[.gz]"; skip the live "<stem>.jsonl".
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            let stamp = rest
                .strip_suffix(".jsonl.gz")
                .or_else(|| rest.strip_suffix(".jsonl"));
            let Some(stamp) = stamp else { continue };
            if let Ok(ts) = stamp.parse::<i64>() {
                rotated.push((ts, entry.path()));
            }
        }
        if rotated.len() <= keep {
            return;
        }
        rotated.sort_by_key(|(ts, _)| *ts);
        let surplus = rotated.len().saturating_sub(keep);
        for (_, path) in rotated.into_iter().take(surplus) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Compress one closed, rotated file in place with the system `gzip(1)`,
/// producing `<path>.gz` and removing the original on success.
///
/// `-n` omits the original name/timestamp from the gzip header (reproducible
/// output, no mtime leak). A spawn/exec failure or a non-zero exit leaves the
/// file untouched and is reported once to stderr — the audit data is intact
/// either way.
fn gzip_file(path: &Path) {
    match std::process::Command::new("gzip")
        .arg("-n")
        .arg(path)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!(
            "kennel-audit: gzip of {} exited {}; left uncompressed",
            path.display(),
            status.code().unwrap_or(-1)
        ),
        Err(e) => eprintln!(
            "kennel-audit: gzip of {} could not run ({e}); left uncompressed",
            path.display()
        ),
    }
}

impl Sink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    fn write(&self, record: &Record) -> Result<(), SinkError> {
        let mut line = record.to_jsonl();
        line.push('\n');
        if line.len() > MAX_EVENT_BYTES {
            return Err(oversize("file", line.len()));
        }
        let path = self.path_for(record.resource);
        self.maybe_rotate(record.resource, &path, line.len());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_err("file", "open", &e))?;
        file.write_all(line.as_bytes())
            .map_err(|e| io_err("file", "write", &e))
    }
}

// ---------------------------------------------------------------------------
// Stdout sink
// ---------------------------------------------------------------------------

/// Writes each event as one JSONL line to kenneld's stdout, for container
/// deployments where an orchestrator captures the daemon's stdout.
#[derive(Default)]
pub struct StdoutSink;

impl Sink for StdoutSink {
    fn name(&self) -> &'static str {
        "stdout"
    }

    fn write(&self, record: &Record) -> Result<(), SinkError> {
        let mut line = record.to_jsonl();
        line.push('\n');
        if line.len() > MAX_EVENT_BYTES {
            return Err(oversize("stdout", line.len()));
        }
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(line.as_bytes())
            .map_err(|e| io_err("stdout", "write", &e))?;
        lock.flush().map_err(|e| io_err("stdout", "flush", &e))
    }
}

// ---------------------------------------------------------------------------
// Syslog sink (RFC 5424)
// ---------------------------------------------------------------------------

/// The maximum syslog message length most receivers accept; longer messages are
/// truncated with a `truncated` SD-PARAM.
const SYSLOG_MAX_BYTES: usize = 2048;

/// The SD-ID for Kennel's structured data. `32473` is the RFC 5612 PEN reserved
/// for documentation/examples; the project's own IANA PEN replaces it at the
/// release that commits to syslog support (`02-3` §What this chapter does not
/// cover).
const SYSLOG_SD_ID: &str = "kennel@32473";

/// Emits events as RFC 5424 messages to a datagram syslog socket (`/dev/log`).
/// For systems without journald.
pub struct SyslogSink {
    socket: UnixDatagram,
    path: PathBuf,
    facility: u8,
    procid: u32,
}

impl SyslogSink {
    /// Create a syslog sink targeting `path` (typically `/dev/log`) with the
    /// given facility code (RFC 5424; `1` = user).
    ///
    /// # Errors
    /// Returns the underlying error if an unbound datagram socket cannot be
    /// created.
    pub fn new(path: PathBuf, facility: u8) -> std::io::Result<Self> {
        Ok(Self {
            socket: UnixDatagram::unbound()?,
            path,
            facility,
            procid: std::process::id(),
        })
    }

    fn format(&self, record: &Record) -> String {
        // PRI = facility*8 + severity. Both small; no overflow.
        let severity = record.outcome.severity();
        let pri = u16::from(self.facility)
            .wrapping_mul(8)
            .wrapping_add(u16::from(severity));
        let ts = field_str(record, "ts").unwrap_or("-");
        let host = field_str(record, "host").unwrap_or("-");

        let mut sd = String::new();
        sd.push('[');
        sd.push_str(SYSLOG_SD_ID);
        for (key, value) in &record.fields {
            if let Some(text) = sd_param_text(value) {
                sd.push(' ');
                sd.push_str(key);
                sd.push_str("=\"");
                push_sd_escaped(&mut sd, &text);
                sd.push('"');
            }
        }
        sd.push(']');

        let msg = record.message();
        let mut out = format!(
            "<{pri}>1 {ts} {host} kennel-audit {procid} {msgid} {sd} {msg}",
            procid = self.procid,
            msgid = record.event_type,
        );
        if out.len() > SYSLOG_MAX_BYTES {
            // Truncate on a char boundary and flag it.
            let mut cut = SYSLOG_MAX_BYTES.saturating_sub(16);
            while cut > 0 && !out.is_char_boundary(cut) {
                cut = cut.saturating_sub(1);
            }
            out.truncate(cut);
            out.push_str("...[truncated]");
        }
        out
    }
}

impl Sink for SyslogSink {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn write(&self, record: &Record) -> Result<(), SinkError> {
        let msg = self.format(record);
        self.socket
            .send_to(msg.as_bytes(), &self.path)
            .map(|_| ())
            .map_err(|e| io_err("syslog", "send_to", &e))
    }
}

/// The string form of a scalar for a syslog SD-PARAM, or `None` to omit.
fn sd_param_text(value: &Rendered) -> Option<String> {
    match value {
        Rendered::Str(s) => Some(s.clone()),
        Rendered::Int(i) => Some(i.to_string()),
        Rendered::Uint(u) => Some(u.to_string()),
        Rendered::Bool(b) => Some(b.to_string()),
        Rendered::Null | Rendered::Array(_) | Rendered::Object(_) => None,
    }
}

/// Escape an SD-PARAM value per RFC 5424 §6.3.3: `"`, `\`, and `]` are escaped.
/// Control bytes are already gone (content sanitisation upstream).
fn push_sd_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        if matches!(ch, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(ch);
    }
}

fn field_str<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.fields.iter().find_map(|(k, v)| {
        if *k == key {
            if let Rendered::Str(s) = v {
                return Some(s.as_str());
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Outcome;
    use crate::time::Clock;

    /// A monotonic test clock: each `now` call returns the next integer second,
    /// so rotation suffixes are unique and `compress`'s "now" advances past the
    /// rotations it sweeps.
    struct Tick(std::sync::atomic::AtomicI64);
    impl Clock for Tick {
        fn now_unix_micros(&self) -> (i64, u32) {
            (self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0)
        }
    }

    fn rec() -> Record {
        Record {
            resource: Resource::Net,
            event_type: "net.connect-deny",
            outcome: Outcome::Deny,
            fields: vec![
                ("schema_version", Rendered::Uint(1)),
                (
                    "ts",
                    Rendered::Str("2026-05-25T12:34:56.789012Z".to_owned()),
                ),
                ("host", Rendered::Str("workstation".to_owned())),
                ("addr", Rendered::Str("169.254.169.254".to_owned())),
                ("port", Rendered::Uint(80)),
                ("reason", Rendered::Str("cloud metadata".to_owned())),
            ],
        }
    }

    #[test]
    fn file_sink_writes_per_class_files() {
        let dir = std::env::temp_dir().join(format!("kennel-audit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sink = FileSink::new(dir.clone(), None, None, None).expect("create");
        sink.write(&rec()).expect("write");
        let body = std::fs::read_to_string(dir.join("network.jsonl")).expect("read");
        assert!(body.contains(r#""addr":"169.254.169.254""#));
        assert!(body.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_sink_rotates_and_retains() {
        let dir = std::env::temp_dir().join(format!("kennel-audit-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Rotate at a tiny size, keep 2 rotated files.
        let sink = FileSink::with_clock(
            dir.clone(),
            Some(80),
            None,
            Some(2),
            Box::new(Tick(std::sync::atomic::AtomicI64::new(1000))),
        )
        .expect("create");
        for _ in 0..6 {
            sink.write(&rec()).expect("write");
        }
        let rotated = std::fs::read_dir(&dir)
            .expect("read_dir")
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("network.") && n != "network.jsonl")
            })
            .count();
        assert!(rotated <= 2, "retention kept {rotated} rotated files");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_sink_compresses_old_rotations() {
        // Skip where the system gzip is absent (the feature degrades gracefully).
        if std::process::Command::new("gzip")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: no system gzip(1)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("kennel-audit-gz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Rotate at a tiny size; compress any rotation at least 0s old (i.e. as
        // soon as a later rotation runs the sweep); keep everything.
        let sink = FileSink::with_clock(
            dir.clone(),
            Some(80),
            Some(0),
            None,
            Box::new(Tick(std::sync::atomic::AtomicI64::new(1000))),
        )
        .expect("create");
        for _ in 0..5 {
            sink.write(&rec()).expect("write");
        }
        let gz = std::fs::read_dir(&dir)
            .expect("read_dir")
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("network.") && n.ends_with(".jsonl.gz"))
            })
            .count();
        assert!(
            gz >= 1,
            "expected at least one compressed rotation, found {gz}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_sink_rejects_oversize() {
        let dir = std::env::temp_dir().join(format!("kennel-audit-big-{}", std::process::id()));
        let sink = FileSink::new(dir.clone(), None, None, None).expect("create");
        let big = "x".repeat(MAX_EVENT_BYTES + 1);
        let r = Record {
            resource: Resource::Fs,
            event_type: "fs.access-deny",
            outcome: Outcome::Deny,
            fields: vec![("path", Rendered::Str(big))],
        };
        assert!(sink.write(&r).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn syslog_format_is_rfc5424_shaped() {
        let sink = SyslogSink::new(PathBuf::from("/dev/log"), 1).expect("socket");
        let msg = sink.format(&rec());
        // PRI for user.warning = 1*8 + 4 = 12.
        assert!(msg.starts_with("<12>1 2026-05-25T12:34:56.789012Z workstation kennel-audit "));
        assert!(msg.contains("net.connect-deny"));
        assert!(msg.contains("[kennel@32473"));
        assert!(msg.contains(r#"addr="169.254.169.254""#));
    }

    #[test]
    fn syslog_escapes_sd_param_specials() {
        let r = Record {
            resource: Resource::Unix,
            event_type: "unix.connect-deny",
            outcome: Outcome::Deny,
            fields: vec![("path", Rendered::Str(r#"a"b]c\d"#.to_owned()))],
        };
        let sink = SyslogSink::new(PathBuf::from("/dev/log"), 1).expect("socket");
        let msg = sink.format(&r);
        assert!(msg.contains(r#"path="a\"b\]c\\d""#), "{msg}");
    }
}
