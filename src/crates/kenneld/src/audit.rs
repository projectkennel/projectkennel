//! The per-kennel audit writer kenneld builds, and the events it emits.
//!
//! kenneld constructs the `kennel-lib-audit` writer from the settled
//! [`AuditRuntime`] and records lifecycle events through it (`02-3`).
//! kenneld is one userspace audit *source* (daemon and kennel lifecycle); the
//! netproxy is the other. Sink/writer assembly is shared via
//! [`kennel_lib_audit::build`]; kenneld maps the settled runtime onto it.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kennel_lib_audit::build::{writer, SinkConfig};
use kennel_lib_audit::{
    Event, Level, Levels, Outcome, Resource, SinkKind, Source, Value, Writer, WriterContext,
};
use kennel_lib_policy::{AuditRuntime, AuditSinkKind};
use kennel_privhelper::exec::refusal_message;
use kennel_privhelper::wire::{Response, Status};

use crate::Privileged;

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
    let rand = kennel_lib_syscall::random::bytes::<10>().unwrap_or([0_u8; 10]);
    kennel_lib_audit::format_uuid_v7(ms, rand)
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
        host: kennel_lib_audit::hostname(),
    };
    let cfg = SinkConfig {
        kinds: runtime.sinks.iter().map(|k| sink_kind(*k)).collect(),
        dir: state_dir.to_path_buf(),
        rotate_at_bytes: runtime.file.rotate_at_bytes,
        compress_after_seconds: runtime.file.compress_after_seconds,
        retain_count: runtime
            .file
            .retain_count
            .and_then(|n| usize::try_from(n).ok()),
        syslog_facility: runtime.syslog_facility.clone(),
    };
    writer(ctx, levels_from(runtime), &cfg)
}

/// A writer with **no sinks** — discards every event.
///
/// Used when a kennel has no audit state directory configured: every kennel now runs the
/// factory + binder bus (`07-1`), so the registry/lifecycle always needs *a* writer, but
/// with nothing to write to it is a sink-less drain. (Empty `SinkConfig.kinds` would default
/// to the file sink, so this uses the lower-level `Writer::new` with an empty sink vector.)
#[must_use]
pub fn noop_writer(name: &str, kennel_uuid: String) -> Writer {
    let ctx = WriterContext {
        kennel: name.to_owned(),
        kennel_uuid,
        host: kennel_lib_audit::hostname(),
    };
    Writer::new(ctx, Levels::default(), Vec::new())
}

/// The maximum size of an `audit.toml` defaults file (a sanity guard).
const MAX_AUDIT_TOML: u64 = 64 * 1024;

/// Load the installation-wide and per-user audit defaults, overlaid.
///
/// Precedence (low → high): built-in &lt; `/etc/kennel/audit.toml` &lt;
/// `~/.config/kennel/audit.toml` (`08` §8.1). The per-kennel policy `[audit]`
/// then overlays this result. A missing file is skipped; a malformed or oversize
/// one is reported to stderr and skipped, so a bad defaults file never blocks a
/// spawn — the built-in defaults still apply.
#[must_use]
pub fn load_audit_defaults() -> AuditRuntime {
    overlay_files(&default_paths())
}

fn overlay_files(paths: &[PathBuf]) -> AuditRuntime {
    let mut defaults = AuditRuntime::default();
    for path in paths {
        let len = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                eprintln!("kennel-lib-audit: cannot stat {}: {e}", path.display());
                continue;
            }
        };
        if len > MAX_AUDIT_TOML {
            eprintln!(
                "kennel-lib-audit: ignoring {} ({len} bytes exceeds the {MAX_AUDIT_TOML}-byte limit)",
                path.display()
            );
            continue;
        }
        match std::fs::read_to_string(path) {
            Ok(toml) => match kennel_lib_policy::parse_audit_defaults(&toml) {
                Ok(rt) => defaults = defaults.overlay(&rt),
                Err(e) => eprintln!("kennel-lib-audit: ignoring {}: {e}", path.display()),
            },
            Err(e) => eprintln!("kennel-lib-audit: cannot read {}: {e}", path.display()),
        }
    }
    defaults
}

/// The defaults search path: the installation file then the per-user file (so the
/// user's overlays the installation's). `$KENNEL_ETC_DIR` overrides `/etc/kennel`
/// (tests/relocatable installs); the per-user file follows `$XDG_CONFIG_HOME`,
/// else `$HOME/.config`.
fn default_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let etc = std::env::var_os("KENNEL_ETC_DIR")
        .map_or_else(|| PathBuf::from("/etc/kennel"), PathBuf::from);
    paths.push(etc.join("audit.toml"));
    if let Some(cfg) = user_config_dir() {
        paths.push(cfg.join("kennel").join("audit.toml"));
    }
    paths
}

fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
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

/// `fs.mutation`: a watched workspace trigger was mutated during the run (§2.5, T2.8).
///
/// `path` is the affected entry (a planted `.git/hooks/post-commit`), `action` is the applied
/// `[trust].on_change` disposition (`warn`/`freeze`/`kill`). `enforced` is true when the
/// workload was acted on (freeze/kill), making it a `Deny`; a `warn` is informational.
#[must_use]
pub fn fs_mutation(path: &str, action: &'static str, enforced: bool) -> Event {
    let outcome = if enforced { Outcome::Deny } else { Outcome::Info };
    Event::new("fs.mutation", Resource::Fs, outcome, Source::Kenneld)
        .field("path", Value::untrusted(path))
        .field("action", Value::untrusted(action))
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

/// `priv.invoke`: a privileged operation the helper performed (`02-3`).
///
/// `source` is `privhelper` (the originator) even though kenneld writes the
/// line — the helper has no writer, so kenneld records on its behalf at the IPC
/// boundary, exactly as it does for the kernel/BPF sources.
#[must_use]
pub fn priv_invoke(operation: &'static str, params: Value, duration_ms: u64) -> Event {
    Event::new(
        "priv.invoke",
        Resource::Priv,
        Outcome::Allow,
        Source::Privhelper,
    )
    .field("operation", Value::str(operation))
    .field("params", params)
    .field("duration_ms", Value::Uint(duration_ms))
}

/// `priv.refuse`: a privileged operation that did not happen (`02-3`).
///
/// `outcome` is `deny` for a policy refusal (`Status::Refused`, `code` the wire
/// refusal code) and `error` for a protocol/syscall/IPC failure. `message` is
/// the project's own description (trusted text).
#[must_use]
pub fn priv_refuse(
    operation: &'static str,
    params: Value,
    outcome: Outcome,
    code: i64,
    message: String,
) -> Event {
    Event::new("priv.refuse", Resource::Priv, outcome, Source::Privhelper)
        .field("operation", Value::str(operation))
        .field("params", params)
        .field("code", Value::Int(code))
        .field("message", Value::str(message))
}

/// A `Privileged` decorator that records each privhelper invocation through the
/// writer as a `priv.invoke` / `priv.refuse` event (`02-3` §Privileged).
///
/// kenneld wraps its real [`Privileged`] in this for the spawn and teardown, so
/// every loopback-address, egress-BPF, and `gid_map` operation — and every
/// refusal — is audited at the one IPC boundary, without threading a writer
/// through the bring-up sequence. With no writer (a kennel without an audit
/// state dir) it is a transparent pass-through.
pub struct AuditedPrivileged<'a, P> {
    inner: &'a P,
    writer: Option<&'a Writer>,
}

impl<'a, P> AuditedPrivileged<'a, P> {
    /// Wrap `inner`, emitting through `writer` when one is configured.
    #[must_use]
    pub const fn new(inner: &'a P, writer: Option<&'a Writer>) -> Self {
        Self { inner, writer }
    }

    /// Emit the `priv.invoke`/`priv.refuse` event for one completed call.
    fn record(
        &self,
        operation: &'static str,
        params: Value,
        started: Instant,
        result: &io::Result<Response>,
    ) {
        let Some(writer) = self.writer else { return };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let event = match result {
            Ok(r) => match r.status {
                Status::Ok => priv_invoke(operation, params, duration_ms),
                Status::Refused => priv_refuse(
                    operation,
                    params,
                    Outcome::Deny,
                    i64::from(r.refusal),
                    refusal_message(r.refusal).to_owned(),
                ),
                Status::Protocol => priv_refuse(
                    operation,
                    params,
                    Outcome::Error,
                    0,
                    "privhelper rejected the request as malformed".to_owned(),
                ),
                Status::Internal => priv_refuse(
                    operation,
                    params,
                    Outcome::Error,
                    i64::from(r.errno),
                    "privileged syscall failed in the helper".to_owned(),
                ),
            },
            Err(e) => priv_refuse(operation, params, Outcome::Error, -1, e.to_string()),
        };
        writer.emit(&event);
    }
}

fn addr_params(ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> Value {
    Value::object(vec![
        ("ctx", Value::Uint(u64::from(ctx))),
        ("interface", Value::str(interface.to_owned())),
        ("addr", Value::str(addr.to_string())),
        ("prefix", Value::Uint(u64::from(prefix))),
    ])
}

impl<P: Privileged> Privileged for AuditedPrivileged<'_, P> {
    fn del_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response> {
        let started = Instant::now();
        let result = self.inner.del_address(ctx, interface, addr, prefix);
        self.record(
            "del-addr",
            addr_params(ctx, interface, addr, prefix),
            started,
            &result,
        );
        result
    }

    /// Forward factory construction to the inner privhelper.
    ///
    /// Not recorded as a `priv.*` event here: construction is a long-lived process whose
    /// outcome is the kennel's exit status, audited through the lifecycle chain, not a single
    /// request/response op. Without this forward the decorator falls through to the trait
    /// default and refuses the factory — which is exactly the production path `run_kennel`
    /// takes (so the decorator, not just the raw helper, must support it).
    fn construct_kennel(
        &self,
        construction_half: &[u8],
        egress: Option<&[u8]>,
        pty_fd: Option<std::os::fd::RawFd>,
        workload_fd: Option<std::os::fd::RawFd>,
    ) -> io::Result<(std::process::Child, i32, std::os::fd::OwnedFd)> {
        self.inner
            .construct_kennel(construction_half, egress, pty_fd, workload_fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Privileged` that returns one fixed response for every operation.
    struct FixedPriv(Response);
    impl Privileged for FixedPriv {
        fn del_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<Response> {
            Ok(self.0)
        }
    }

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

    #[test]
    fn audit_defaults_overlay_system_then_user() {
        let base = std::env::temp_dir().join(format!("kenneld-auditdefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mkdir");
        let sys = base.join("etc-audit.toml");
        let usr = base.join("user-audit.toml");
        std::fs::write(
            &sys,
            "sinks = [\"journald\"]\n[syslog]\nfacility = \"local0\"\n",
        )
        .expect("write system");
        std::fs::write(
            &usr,
            "[syslog]\nfacility = \"local5\"\n[file]\nretain_count = 3\n",
        )
        .expect("write user");

        // System first, user second: the user file overlays the system file.
        let rt = overlay_files(&[sys, usr]);
        assert_eq!(rt.syslog_facility.as_deref(), Some("local5"), "user wins");
        assert_eq!(
            rt.sinks,
            vec![AuditSinkKind::Journald],
            "system sinks survive where the user file is silent"
        );
        assert_eq!(rt.file.retain_count, Some(3), "user-only field");

        // A missing file is simply skipped (built-in defaults remain).
        assert!(overlay_files(&[base.join("nope.toml")]).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn audited_privileged_records_invoke_and_refuse() {
        let dir = std::env::temp_dir().join(format!("kenneld-audit-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let writer = build_writer("ai-coding", &dir, &AuditRuntime::default(), "u7".to_owned());

        // A refusal (code 2 = AddrOutOfScope) on del_address (the one standalone priv op left).
        let refusing = FixedPriv(Response::refused(2));
        let audited = AuditedPrivileged::new(&refusing, Some(&writer));
        let addr = "127.0.0.1".parse::<IpAddr>().expect("addr");
        let _ = audited.del_address(7, "lo", addr, 28);

        // A success (invoke) on del_address.
        let ok = FixedPriv(Response::ok());
        let audited_ok = AuditedPrivileged::new(&ok, Some(&writer));
        let _ = audited_ok.del_address(8, "lo", addr, 28);

        // Dropping the writer joins the buffered sink so priv.jsonl is flushed.
        drop(writer);
        let body = std::fs::read_to_string(dir.join("priv.jsonl")).expect("priv log");

        assert!(body.contains(r#""event":"priv.refuse""#), "{body}");
        assert!(body.contains(r#""source":"privhelper""#), "{body}");
        assert!(body.contains(r#""operation":"del-addr""#), "{body}");
        assert!(body.contains(r#""code":2"#), "{body}");
        assert!(body.contains("reserved per-kennel subnet"), "{body}");
        assert!(body.contains(r#""params":{"ctx":7,"#), "{body}");
        assert!(body.contains(r#""addr":"127.0.0.1""#), "{body}");
        assert!(body.contains(r#""event":"priv.invoke""#), "{body}");
        assert!(body.contains(r#""duration_ms":"#), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
