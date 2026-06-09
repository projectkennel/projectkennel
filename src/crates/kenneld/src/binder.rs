//! kenneld as the per-kennel binder context manager (`07-1-binder.md` §7.1 / `02-4`).
//!
//! kenneld owns node 0 of each kennel's binderfs instance and serves the service
//! registry on a per-kennel thread (like [`crate::bpf_audit`]'s drain). It gates
//! every `addService`/`getService` against the settled [`BinderRuntime`] and the
//! reserved-namespace rules, records the registered services, and emits a
//! `binder.*` audit event per call through the unified [`Writer`].
//!
//! This module is the *policy* layer; the binder transport (the looper, the wire
//! codec, the ioctls) is [`kennel_binder`]. The transaction payload convention on
//! node 0 (the verb codes and the status/byte replies) is internal-stable
//! (`02-4-binder.md` §Node 0): `kenneld` and the in-kennel client agree because
//! they ship from one release.
//!
//! M1a scope: the registry decision point with status replies, proven by a root
//! e2e. Returning a node *handle* from `getService` (so a client can then transact
//! to a registered service) is the next increment (it needs `flat_binder_object`
//! handle passing); the reserved `org.projectkennel.*` facades land with M2.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use kennel_audit::{Event, Outcome, Resource, Source, Value, Writer};
use kennel_binder::client::Incoming;
use kennel_binder::ctxmgr::{ContextManager, Reply};
use kennel_policy::{BinderRuntime, UnixRuntime};

/// The binder buffer mapping size per instance (ample for service-name transactions).
const MAP_SIZE: usize = 128 * 1024;
/// How long the looper waits per poll before re-checking the stop flag.
const POLL_MS: i32 = 200;
/// A service name is bounded (binderfs's own `BINDERFS_MAX_NAME`); reject longer.
const MAX_NAME: usize = 255;

// The node-0 verb codes and reply status bytes are the shared wire convention
// (`kennel_binder::service`), used by both kenneld here and the in-kennel clients.
pub use kennel_binder::service::{lifecycle, status, verb};

/// The per-kennel service registry, gated by the settled `[binder]` policy.
///
/// Pure decision logic (no I/O); the serve loop calls it and turns the outcome into
/// a reply and an audit event.
pub struct Registry {
    policy: BinderRuntime,
    registered: std::collections::BTreeSet<String>,
}

impl Registry {
    /// A registry for a kennel whose settled binder policy is `policy`.
    #[must_use]
    pub const fn new(policy: BinderRuntime) -> Self {
        Self {
            policy,
            registered: std::collections::BTreeSet::new(),
        }
    }

    /// Whether `name` is in the reserved kenneld-owned namespace.
    fn is_reserved(name: &str) -> bool {
        name.starts_with(kennel_policy::binder::RESERVED_PREFIX)
    }

    /// Whether policy lets this kennel *provide* (register) `name`.
    fn may_provide(&self, name: &str) -> bool {
        self.policy.provide.iter().any(|p| p.name == name)
    }

    /// Whether policy lets this kennel *look up* `name`: a service it provides is
    /// locally resolvable, and a declared `consume` is permitted (one kennel is one
    /// trust domain; `consume` additionally gates cross-instance — `07-1` §7.1.6).
    fn may_consume(&self, name: &str) -> bool {
        self.may_provide(name) || self.policy.consume.iter().any(|c| c.name == name)
    }

    /// Handle an `addService`: register `name` if policy permits it.
    pub fn add_service(&mut self, name: &str) -> u8 {
        if Self::is_reserved(name) {
            return status::REFUSED_RESERVED;
        }
        if self.may_provide(name) {
            self.registered.insert(name.to_owned());
            status::OK
        } else {
            status::DENIED
        }
    }

    /// Handle a `getService`: resolve `name` if policy permits and it is registered.
    #[must_use]
    pub fn get_service(&self, name: &str) -> u8 {
        if Self::is_reserved(name) {
            // Reserved facades resolve locally to kenneld; none are built in M1a, so
            // the lookup is permitted but finds nothing.
            return status::NOT_FOUND;
        }
        if !self.may_consume(name) {
            return status::DENIED;
        }
        if self.registered.contains(name) {
            status::OK
        } else {
            status::NOT_FOUND
        }
    }

    /// Whether `name` is declared (provide ∪ consume) for this kennel.
    #[must_use]
    pub fn is_declared(&self, name: &str) -> bool {
        self.may_consume(name)
    }

    /// The declared service names the caller may look up, sorted and de-duplicated.
    #[must_use]
    pub fn list_services(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        names.extend(self.policy.provide.iter().map(|p| p.name.clone()));
        names.extend(self.policy.consume.iter().map(|c| c.name.clone()));
        names.into_iter().collect()
    }
}

/// The lifecycle/config state `kenneld` serves to a kennel's `kennel-init` (`07-2`).
///
/// Served over node 0 (§7.2.4). Disabled by default (`init_host_pid == None`): the
/// lifecycle verbs are refused until the factory reports the init pid and stages the
/// supervision-half.
#[derive(Debug, Default)]
pub struct Lifecycle {
    /// The **host** pid of `kennel-init`, reported by the privhelper factory. The single
    /// authority for the lifecycle gate: a host-side context manager sees the sender's
    /// host pid (`task_tgid_nr_ns`), never the kennel-internal `1`. `None` ⇒ disabled.
    pub init_host_pid: Option<i32>,
    /// The encoded supervision-half (`kennel-spawn::wire::encode_supervision`) served on
    /// `GET_SANDBOX_PLAN`.
    pub supervision: Vec<u8>,
    /// The controlling-pty return socket for an interactive run, handed over (once) as a
    /// `BINDER_TYPE_FD` object on the first `GET_SANDBOX_PLAN`. `None` for non-interactive.
    pub pty_fd: Option<OwnedFd>,
}

/// A running per-kennel binder context manager: the serve thread plus its stop flag.
#[derive(Debug)]
pub struct Manager {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Manager {
    /// Signal the serve loop to finish and join it. Best-effort.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Take node 0 of the binder instance behind `device_fd` and serve its registry on a
/// per-kennel thread, gating against `policy` and auditing through `writer`.
///
/// # Errors
///
/// Returns the OS error if becoming context manager (open/`mmap`/`SET_CONTEXT_MGR`/
/// looper) fails, or the worker thread cannot be spawned.
pub fn spawn(
    device_fd: OwnedFd,
    ctx: u16,
    policy: BinderRuntime,
    unix: UnixRuntime,
    lifecycle: Lifecycle,
    writer: Arc<Writer>,
) -> io::Result<Manager> {
    let cm = ContextManager::new(device_fd, MAP_SIZE)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name(format!("kennel-binder-{ctx}"))
        .spawn(move || {
            let mut registry = Registry::new(policy);
            let mut lifecycle = lifecycle;
            let _ = cm.serve(POLL_MS, &worker_stop, |incoming| {
                handle(&mut registry, &unix, &mut lifecycle, incoming, ctx, &writer)
            });
        })?;
    Ok(Manager {
        stop,
        join: Some(join),
    })
}

/// Decode one node-0 transaction, apply the policy decision, emit an audit event, and
/// produce the reply (status bytes for the registry verbs, or a connected fd for the
/// af-unix facade).
fn handle(
    registry: &mut Registry,
    unix: &UnixRuntime,
    lifecycle: &mut Lifecycle,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    // Lifecycle/config verbs (the high range) are spoken only by kennel-init and gated
    // on its kernel-stamped identity — handled before the registry/af-unix dispatch.
    if incoming.code >= lifecycle::GET_SANDBOX_PLAN {
        return lifecycle_handle(lifecycle, incoming, ctx, writer);
    }
    // The af-unix facade returns a file descriptor, so it is handled apart from the
    // byte-reply registry verbs.
    if incoming.code == verb::CONNECT_AFUNIX {
        return af_unix_connect(unix, incoming, ctx, writer);
    }
    let name = decode_name(&incoming.data);
    let (action, outcome, reply) = match (incoming.code, name) {
        (verb::ADD_SERVICE, Some(name)) => {
            let s = registry.add_service(&name);
            ("binder.register", outcome_for(s), one(s))
        }
        (verb::GET_SERVICE, Some(name)) => {
            let s = registry.get_service(&name);
            ("binder.lookup", outcome_for(s), one(s))
        }
        (verb::IS_DECLARED, Some(name)) => {
            let declared = registry.is_declared(&name);
            (
                "binder.is-declared",
                Outcome::Info,
                vec![status::OK, u8::from(declared)],
            )
        }
        (verb::LIST_SERVICES, _) => {
            let body = registry.list_services().join("\n").into_bytes();
            let mut reply = vec![status::OK];
            reply.extend_from_slice(&body);
            ("binder.list", Outcome::Info, reply)
        }
        _ => (
            "binder.bad-request",
            Outcome::Error,
            one(status::BAD_REQUEST),
        ),
    };

    let service = decode_name(&incoming.data).unwrap_or_default();
    writer.emit(
        &Event::new(action, Resource::Binder, outcome, Source::Kenneld)
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("service", Value::untrusted(service))
            .field("ctx", Value::Uint(u64::from(ctx))),
    );
    Reply::Data(reply)
}

/// Serve a node-0 **lifecycle/config verb**, gated on the caller's kernel-stamped
/// identity: only `kennel-init` (the host pid the privhelper reported, running as
/// uid 0) may pull the plan or post notifications (`07-2` §7.2.4). A caller that is
/// not the registered init pid — a spoof, or any other in-kennel process — is denied
/// and audited.
fn lifecycle_handle(
    lifecycle: &mut Lifecycle,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    let authorized = lifecycle_authorized(
        lifecycle.init_host_pid,
        incoming.sender_pid,
        incoming.sender_euid,
    );
    if !authorized {
        writer.emit(
            &Event::new(
                "binder.lifecycle-denied",
                Resource::Binder,
                Outcome::Deny,
                Source::Kenneld,
            )
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("code", Value::Uint(u64::from(incoming.code)))
            .field("ctx", Value::Uint(u64::from(ctx))),
        );
        return Reply::Data(one(status::DENIED));
    }

    let (action, outcome, reply) = match incoming.code {
        lifecycle::GET_SANDBOX_PLAN => {
            // The pty fd (if any) is handed over once; a length-prefixed data-and-fd
            // reply that kennel-init decodes with transact_with_fd.
            let bytes = lifecycle.supervision.clone();
            (
                "binder.get-sandbox-plan",
                Outcome::Allow,
                Reply::DataAndFd(bytes, lifecycle.pty_fd.take()),
            )
        }
        lifecycle::NOTIFY_BOOT_SYNC => (
            "binder.notify-boot-sync",
            Outcome::Info,
            Reply::Data(one(status::OK)),
        ),
        lifecycle::NOTIFY_FACADE_CRASH => (
            "binder.notify-facade-crash",
            Outcome::Error,
            Reply::Data(one(status::OK)),
        ),
        lifecycle::NOTIFY_WORKLOAD_EXEC => (
            "binder.notify-workload-exec",
            Outcome::Info,
            Reply::Data(one(status::OK)),
        ),
        _ => (
            "binder.bad-request",
            Outcome::Error,
            Reply::Data(one(status::BAD_REQUEST)),
        ),
    };
    writer.emit(
        &Event::new(action, Resource::Binder, outcome, Source::Kenneld)
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("ctx", Value::Uint(u64::from(ctx))),
    );
    reply
}

/// Whether a node-0 lifecycle transaction is authorised: the kernel-stamped sender pid
/// must be exactly the registered `kennel-init` host pid. That pid is the binding fact —
/// kernel-stamped (`task_tgid_nr_ns`), unforgeable, and unique to `kennel-init` (the
/// workload and facades have different pids). `init == None` (lifecycle disabled) denies
/// everything because `Some(pid) != None`.
///
/// `sender_euid == 0` is defense-in-depth alongside the pid match: `kennel-init` is the
/// only uid-0 process in the kennel (host root via the `0 0 1` map; the workload and facades
/// run as the operator's non-zero uid), so a lifecycle verb from a non-zero euid is never
/// `kennel-init` and is denied (`07-2` §7.2.2). The pid match is the primary, exact gate.
const fn lifecycle_authorized(init: Option<i32>, sender_pid: i32, sender_euid: u32) -> bool {
    matches!(init, Some(pid) if pid == sender_pid) && sender_euid == 0
}

/// The af-unix facade (`07-1`/`02-4`): resolve the requested socket against the
/// `[[unix.allow]]` grants (by its in-view `shim` path or logical `name`), connect to
/// the real host socket, and return the connected fd. A non-granted request is denied.
///
/// The connect is host-side I/O run inline on the looper for now; moving it to a
/// worker (so a slow connect cannot head-of-line-block the instance) is the hardening
/// in `02-4-binder.md` §Threading model.
fn af_unix_connect(unix: &UnixRuntime, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let requested = decode_name(&incoming.data);
    let target = requested
        .as_deref()
        .and_then(|p| unix.sockets.iter().find(|s| s.shim == p || s.name == p));
    let (outcome, reply) = target.map_or_else(
        || (Outcome::Deny, Reply::Data(one(status::DENIED))),
        |socket| {
            std::os::unix::net::UnixStream::connect(&socket.real).map_or_else(
                // Granted but unreachable (the host socket is absent/refused).
                |_| (Outcome::Error, Reply::Data(one(status::NOT_FOUND))),
                |stream| (Outcome::Allow, Reply::Fd(OwnedFd::from(stream))),
            )
        },
    );
    writer.emit(
        &Event::new(
            "binder.afunix-connect",
            Resource::Binder,
            outcome,
            Source::Kenneld,
        )
        .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
        .field("path", Value::untrusted(requested.unwrap_or_default()))
        .field("ctx", Value::Uint(u64::from(ctx))),
    );
    reply
}

/// A one-byte status reply.
fn one(status: u8) -> Vec<u8> {
    vec![status]
}

/// The audit outcome for a status byte.
const fn outcome_for(status: u8) -> Outcome {
    match status {
        status::OK => Outcome::Allow,
        status::DENIED | status::REFUSED_RESERVED => Outcome::Deny,
        _ => Outcome::Info,
    }
}

/// Decode a transaction's service-name payload: bounded, UTF-8, non-empty. `None`
/// for an empty, oversized, or non-UTF-8 name (an untrusted payload).
fn decode_name(data: &[u8]) -> Option<String> {
    if data.is_empty() || data.len() > MAX_NAME {
        return None;
    }
    std::str::from_utf8(data).ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_policy::{BinderConsumeRuntime, BinderProvideRuntime};

    fn registry(provide: &[&str], consume: &[&str]) -> Registry {
        Registry::new(BinderRuntime {
            provide: provide
                .iter()
                .map(|n| BinderProvideRuntime {
                    name: (*n).to_owned(),
                    accept_from: Vec::new(),
                })
                .collect(),
            consume: consume
                .iter()
                .map(|n| BinderConsumeRuntime {
                    name: (*n).to_owned(),
                    from: None,
                })
                .collect(),
        })
    }

    #[test]
    fn add_service_registers_a_provided_name() {
        let mut r = registry(&["svc"], &[]);
        assert_eq!(r.add_service("svc"), status::OK);
        // Now resolvable locally.
        assert_eq!(r.get_service("svc"), status::OK);
    }

    #[test]
    fn add_service_denies_an_undeclared_name() {
        let mut r = registry(&["svc"], &[]);
        assert_eq!(r.add_service("other"), status::DENIED);
    }

    #[test]
    fn add_service_refuses_a_reserved_name() {
        let mut r = registry(&["org.projectkennel.IAfUnix/default"], &[]);
        assert_eq!(
            r.add_service("org.projectkennel.IAfUnix/default"),
            status::REFUSED_RESERVED
        );
    }

    #[test]
    fn get_service_denies_an_undeclared_name() {
        let r = registry(&[], &[]);
        assert_eq!(r.get_service("svc"), status::DENIED);
    }

    #[test]
    fn get_service_of_a_declared_but_unregistered_name_is_not_found() {
        let r = registry(&[], &["peer-svc"]);
        assert_eq!(r.get_service("peer-svc"), status::NOT_FOUND);
    }

    #[test]
    fn is_declared_covers_provide_and_consume() {
        let r = registry(&["p"], &["c"]);
        assert!(r.is_declared("p"));
        assert!(r.is_declared("c"));
        assert!(!r.is_declared("x"));
    }

    #[test]
    fn list_services_is_the_sorted_declared_union() {
        let r = registry(&["b"], &["a", "b"]);
        assert_eq!(r.list_services(), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn lifecycle_gate_requires_the_exact_init_pid_and_uid0() {
        // `kennel-init` is the only uid-0 process; the gate is the exact init host pid AND
        // euid 0.
        assert!(lifecycle_authorized(Some(4242), 4242, 0));
        // Right pid but a non-zero euid (the operator-uid workload/facades) — denied.
        assert!(!lifecycle_authorized(Some(4242), 4242, 1000));
        // Wrong pid (a spoof from another in-kennel process) — denied.
        assert!(!lifecycle_authorized(Some(4242), 9999, 0));
        // An unmapped (overflow-uid) sender is rejected even with a matching pid.
        assert!(!lifecycle_authorized(Some(4242), 4242, 65534));
        // Lifecycle disabled (no init pid registered) — everything denied.
        assert!(!lifecycle_authorized(None, 4242, 0));
    }

    #[test]
    fn decode_name_rejects_empty_oversized_and_non_utf8() {
        assert_eq!(decode_name(b""), None);
        assert_eq!(decode_name(&[0xff, 0xfe]), None);
        assert_eq!(decode_name(&[b'a'; 256]), None);
        assert_eq!(decode_name(b"svc"), Some("svc".to_owned()));
    }
}
