//! The per-kennel audit writer kenneld builds, and the events it emits.
//!
//! kenneld constructs the `kennel-audit` writer from the settled
//! [`AuditRuntime`] and records lifecycle events through it (`02-3`).
//! kenneld is one userspace audit *source* (daemon and kennel lifecycle); the
//! netproxy is the other. Sink/writer assembly is shared via
//! [`kennel_audit::build`]; kenneld maps the settled runtime onto it.

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use kennel_audit::build::{writer, SinkConfig};
use kennel_audit::{
    Event, Level, Levels, Outcome, Resource, SinkKind, Source, Value, Writer, WriterContext,
};
use kennel_policy::{AuditRuntime, AuditSinkKind};
use kennel_privhelper::exec::refusal_message;
use kennel_privhelper::wire::{EgressPayload, Response, Status};

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
        compress_after_seconds: runtime.file.compress_after_seconds,
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

fn count(n: usize) -> Value {
    Value::Uint(u64::try_from(n).unwrap_or(u64::MAX))
}

impl<P: Privileged> Privileged for AuditedPrivileged<'_, P> {
    fn add_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response> {
        let started = Instant::now();
        let result = self.inner.add_address(ctx, interface, addr, prefix);
        self.record(
            "add-addr",
            addr_params(ctx, interface, addr, prefix),
            started,
            &result,
        );
        result
    }

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

    fn setup_egress(&self, cgroup: &Path, payload: &EgressPayload) -> io::Result<Response> {
        let started = Instant::now();
        let result = self.inner.setup_egress(cgroup, payload);
        let params = Value::object(vec![
            ("cgroup", Value::str(cgroup.display().to_string())),
            ("allow_v4", count(payload.allow_v4.len())),
            ("deny_v4", count(payload.deny_v4.len())),
            ("allow_v6", count(payload.allow_v6.len())),
            ("deny_v6", count(payload.deny_v6.len())),
        ]);
        self.record("setup-egress", params, started, &result);
        result
    }

    fn set_gid_map(&self, pid: u32, gids: &[u32]) -> io::Result<Response> {
        let started = Instant::now();
        let result = self.inner.set_gid_map(pid, gids);
        let params = Value::object(vec![
            ("pid", Value::Uint(u64::from(pid))),
            (
                "gids",
                Value::Array(gids.iter().map(|g| Value::Uint(u64::from(*g))).collect()),
            ),
        ]);
        self.record("set-gid-map", params, started, &result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Privileged` that returns one fixed response for every operation.
    struct FixedPriv(Response);
    impl Privileged for FixedPriv {
        fn add_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<Response> {
            Ok(self.0)
        }
        fn del_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<Response> {
            Ok(self.0)
        }
        fn setup_egress(&self, _: &Path, _: &EgressPayload) -> io::Result<Response> {
            Ok(self.0)
        }
        fn set_gid_map(&self, _: u32, _: &[u32]) -> io::Result<Response> {
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
    fn audited_privileged_records_invoke_and_refuse() {
        let dir = std::env::temp_dir().join(format!("kenneld-audit-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let writer = build_writer("ai-coding", &dir, &AuditRuntime::default(), "u7".to_owned());

        // A refusal (code 2 = AddrOutOfScope) on add_address.
        let refusing = FixedPriv(Response::refused(2));
        let audited = AuditedPrivileged::new(&refusing, Some(&writer));
        let addr = "127.0.0.1".parse::<IpAddr>().expect("addr");
        let _ = audited.add_address(7, "lo", addr, 28);

        // A success on set_gid_map.
        let ok = FixedPriv(Response::ok());
        let audited_ok = AuditedPrivileged::new(&ok, Some(&writer));
        let _ = audited_ok.set_gid_map(1234, &[20, 44]);

        // Dropping the writer joins the buffered sink so priv.jsonl is flushed.
        drop(writer);
        let body = std::fs::read_to_string(dir.join("priv.jsonl")).expect("priv log");

        assert!(body.contains(r#""event":"priv.refuse""#), "{body}");
        assert!(body.contains(r#""source":"privhelper""#), "{body}");
        assert!(body.contains(r#""operation":"add-addr""#), "{body}");
        assert!(body.contains(r#""code":2"#), "{body}");
        assert!(body.contains("reserved per-kennel subnet"), "{body}");
        assert!(body.contains(r#""params":{"ctx":7,"#), "{body}");
        assert!(body.contains(r#""addr":"127.0.0.1""#), "{body}");

        assert!(body.contains(r#""event":"priv.invoke""#), "{body}");
        assert!(body.contains(r#""operation":"set-gid-map""#), "{body}");
        assert!(
            body.contains(r#""params":{"pid":1234,"gids":[20,44]}"#),
            "{body}"
        );
        assert!(body.contains(r#""duration_ms":"#), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
