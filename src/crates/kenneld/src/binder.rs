//! kenneld as the per-kennel binder context manager (`07-9-ipc.md` §7.9 / `02-7`).
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
//! (`02-7-binder.md` §Node 0): `kenneld` and the in-kennel client agree because
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
use kennel_binder::ctxmgr::ContextManager;
use kennel_policy::BinderRuntime;

/// The binder buffer mapping size per instance (ample for service-name transactions).
const MAP_SIZE: usize = 128 * 1024;
/// How long the looper waits per poll before re-checking the stop flag.
const POLL_MS: i32 = 200;
/// A service name is bounded (binderfs's own `BINDERFS_MAX_NAME`); reject longer.
const MAX_NAME: usize = 255;

/// Node-0 transaction verbs (the `code` field). `IServiceManager`-style semantics
/// (`02-7-binder.md` §Node 0); the numeric codes are kenneld's own.
pub mod verb {
    /// Register a service the caller provides.
    pub const ADD_SERVICE: u32 = 1;
    /// Resolve a service name.
    pub const GET_SERVICE: u32 = 2;
    /// Whether a service is declared for the caller.
    pub const IS_DECLARED: u32 = 3;
    /// The service names the caller is granted to look up.
    pub const LIST_SERVICES: u32 = 4;
}

/// Reply status byte (first byte of the reply payload).
pub mod status {
    /// Success (registered / found / true).
    pub const OK: u8 = 0;
    /// Refused by policy (not declared for this caller).
    pub const DENIED: u8 = 1;
    /// Permitted but no such registered service.
    pub const NOT_FOUND: u8 = 2;
    /// Refused: the name is in the reserved `org.projectkennel.*` namespace.
    pub const REFUSED_RESERVED: u8 = 3;
    /// The request was malformed (bad verb, oversized/!UTF-8 name).
    pub const BAD_REQUEST: u8 = 4;
}

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
    /// trust domain; `consume` additionally gates cross-instance — `07-9` §7.9.6).
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

/// A running per-kennel binder context manager: the serve thread plus its stop flag.
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
    writer: Arc<Writer>,
) -> io::Result<Manager> {
    let cm = ContextManager::new(device_fd, MAP_SIZE)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name(format!("kennel-binder-{ctx}"))
        .spawn(move || {
            let mut registry = Registry::new(policy);
            let _ = cm.serve(POLL_MS, &worker_stop, |incoming| {
                handle(&mut registry, incoming, ctx, &writer)
            });
        })?;
    Ok(Manager {
        stop,
        join: Some(join),
    })
}

/// Decode one node-0 transaction, apply the registry decision, emit an audit event,
/// and encode the reply payload.
fn handle(registry: &mut Registry, incoming: &Incoming, ctx: u16, writer: &Writer) -> Vec<u8> {
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
    fn decode_name_rejects_empty_oversized_and_non_utf8() {
        assert_eq!(decode_name(b""), None);
        assert_eq!(decode_name(&[0xff, 0xfe]), None);
        assert_eq!(decode_name(&[b'a'; 256]), None);
        assert_eq!(decode_name(b"svc"), Some("svc".to_owned()));
    }
}
