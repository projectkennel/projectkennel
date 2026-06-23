//! kenneld as the per-kennel binder context manager (`07-1-binder.md` §7.1 / `02-4`).
//!
//! kenneld owns node 0 of each kennel's binderfs instance and serves the service
//! registry on a per-kennel thread (like [`crate::bpf_audit`]'s drain). It gates
//! every `addService`/`getService` against the settled [`BinderRuntime`] and the
//! reserved-namespace rules, records the registered services, and emits a
//! `binder.*` audit event per call through the unified [`Writer`].
//!
//! This module is the *policy* layer; the binder transport (the looper, the wire
//! codec, the ioctls) is [`kennel_lib_binder`]. The transaction payload convention on
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
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};
use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::ctxmgr::{ContextManager, DeathHandler, Handler, Reply};
use kennel_lib_policy::{BinderRuntime, UnixRuntime};

use crate::dbus::DbusRelay;

/// The binder buffer mapping size per instance (ample for service-name transactions).
const MAP_SIZE: usize = 128 * 1024;
/// How long the looper waits per poll before re-checking the stop flag.
const POLL_MS: i32 = 200;
/// Per-kennel looper-pool ceiling: a blocking facade call (af-unix / `INet` dial) occupies one
/// looper, so the pool must be deep enough that the registry and lifecycle/TTL verbs always
/// find a free thread. Fixed for now; `[resources]` will make it policy-tunable.
const POOL_MAX_THREADS: u32 = 8;
/// Deadline for a facade dial (`IAfUnix` `CONNECT`) so a wedged or unresponsive host socket
/// reclaims its looper instead of tying it up indefinitely (bounding pool exhaustion alongside
/// `POOL_MAX_THREADS`).
const AFUNIX_CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
/// A service name is bounded (binderfs's own `BINDERFS_MAX_NAME`); reject longer.
const MAX_NAME: usize = 255;

// The node-0 verb codes and reply status bytes are the shared wire convention
// (`kennel_lib_binder::service`), used by both kenneld here and the in-kennel clients.
pub use kennel_lib_binder::service::{lifecycle, status, ttl, verb};

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
        name.starts_with(kennel_lib_policy::settled::RESERVED_PREFIX)
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

/// The lifecycle/config state `kenneld` serves to a kennel's `kennel-bin-init` (`07-2`).
///
/// Served over node 0 (§7.2.4). Disabled by default (`init_host_pid == None`): the
/// lifecycle verbs are refused until the factory reports the init pid and stages the
/// supervision-half.
#[derive(Debug, Default)]
pub struct Lifecycle {
    /// The **host** pid of `kennel-bin-init`, reported by the privhelper factory. The single
    /// authority for the lifecycle gate: a host-side context manager sees the sender's
    /// host pid (`task_tgid_nr_ns`), never the kennel-internal `1`. `None` ⇒ disabled.
    pub init_host_pid: Option<i32>,
    /// The encoded supervision-half (`kennel-lib-spawn::wire::encode_supervision`) served on
    /// `GET_SANDBOX_PLAN`. (The interactive pty does NOT ride binder: the privhelper factory
    /// passes the return socket on the construction channel and `kennel-bin-init` inherits it at
    /// `PTY_RETURN_FD` — `07-2`, decoupled from the bus.)
    pub supervision: Vec<u8>,
    /// The kennel's cgroup (kenneld's delegated subtree). On `NOTIFY_TTL_EXPIRED` kenneld
    /// freezes/thaws/kills this cgroup — the TTL custodian's mechanism stays in the trusted
    /// daemon, never exposed to the sandbox (§9.7). Empty on a lifecycle with no TTL.
    pub cgroup: std::path::PathBuf,
    /// What to do when the TTL expires (`[lifecycle].on-expiry`), decided kenneld-side.
    pub ttl_action: kennel_lib_policy::TtlAction,
    /// The kennel's name, for the operator-facing TTL `renew` prompt text.
    pub name: String,
    /// The operator-prompt channel (§9.7): a clone of the control connection over which the
    /// `renew` action asks the attached operator whether to extend the lifetime. `None` when
    /// no operator can be prompted (a non-interactive run) — `renew` then falls back to a warn.
    pub prompt: Option<crate::prompt::PromptPort>,
}

/// A running per-kennel binder context manager: the looper pool plus its stop flag.
#[derive(Debug)]
pub struct Manager {
    stop: Arc<AtomicBool>,
    loopers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    waker: kennel_lib_binder::ctxmgr::Waker,
}

impl Manager {
    /// Signal the looper pool to finish and join every thread. Best-effort.
    pub fn stop(self) {
        self.stop.store(true, Ordering::Release);
        // Break every looper out of its `poll` now, so teardown does not wait out a `POLL_MS`
        // cycle per thread (the latency profile's dominant teardown cost).
        self.waker.wake();
        let drained: Vec<JoinHandle<()>> = {
            let mut guard = self
                .loopers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for join in drained {
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
#[allow(clippy::too_many_arguments)] // the node-0 serve inputs; each is one subsystem's state
pub fn spawn(
    device_fd: OwnedFd,
    ctx: u16,
    policy: BinderRuntime,
    unix: UnixRuntime,
    lifecycle: Lifecycle,
    net: crate::inet::NetRuntime,
    inbound: Arc<crate::inbound::InboundRuntime>,
    dbus: Option<Arc<DbusRelay>>,
    writer: Arc<Writer>,
    spawn: Option<Arc<crate::spawn::SpawnRuntime>>,
    consumes: Vec<kennel_lib_policy::ConsumeRuntime>,
    catalogue: Option<Arc<Mutex<crate::catalogue::Catalogue>>>,
) -> io::Result<Manager> {
    let cm = Arc::new(ContextManager::new(device_fd, MAP_SIZE)?);
    let stop = Arc::new(AtomicBool::new(false));

    // kenneld pushes DELIVER_INET (§7.5.7) on this same connection — a binder handle is valid only
    // on the open that received it — so the inbound runtime borrows the context manager. Attached
    // before the pool serves, so a REGISTER_MIRROR can never race an unattached pusher.
    inbound.attach_pusher(Arc::clone(&cm));

    // The handler runs concurrently on every looper, so its state is shared: the registry behind
    // a Mutex (taken only for the O(1) registry verbs, never across the blocking facade dial), and
    // the rest by Arc.
    let registry = Arc::new(Mutex::new(Registry::new(policy)));
    let unix = Arc::new(unix);
    let net = Arc::new(net);
    let lifecycle = Arc::new(lifecycle);
    // The mesh broker's per-kennel inputs: this kennel's signed consumes (the request-don't-author
    // floor) and the daemon's live catalogue (resolved against on SVC_CONNECT), shared across loopers.
    let consumes = Arc::new(consumes);
    let inbound_for_death = Arc::clone(&inbound);
    let handler: Handler = Arc::new(move |incoming: &Incoming, conn: &Connection| {
        handle(
            &registry,
            &unix,
            &net,
            &inbound,
            &lifecycle,
            dbus.as_deref(),
            spawn.as_deref(),
            &consumes,
            catalogue.as_ref(),
            incoming,
            conn,
            ctx,
            &writer,
        )
    });
    // A watched mirror node died: drop its stale handle (§7.5.7, guard 1).
    let death: DeathHandler = Arc::new(move |cookie: u64, conn: &Connection| {
        inbound_for_death.drop_dead(conn, cookie);
    });

    let waker = cm.waker();
    let loopers = cm.serve_pool(POOL_MAX_THREADS, POLL_MS, &stop, &handler, &death)?;
    Ok(Manager {
        stop,
        loopers,
        waker,
    })
}

/// Decode one node-0 transaction, apply the policy decision, emit an audit event, and
/// produce the reply (status bytes for the registry verbs, or a connected fd for the
/// af-unix facade).
// The registry lock is held for exactly the O(1) registry-verb match and released before the
// audit emit; that scope is intentional (each arm calls a registry method), so the nursery
// "tighten the guard further" lint does not apply.
#[allow(clippy::significant_drop_tightening)]
#[allow(clippy::too_many_arguments)] // the handler's shared state; each piece is one concern
fn handle(
    registry: &Mutex<Registry>,
    unix: &UnixRuntime,
    net: &crate::inet::NetRuntime,
    inbound: &crate::inbound::InboundRuntime,
    lifecycle: &Lifecycle,
    dbus: Option<&DbusRelay>,
    spawn: Option<&crate::spawn::SpawnRuntime>,
    consumes: &[kennel_lib_policy::ConsumeRuntime],
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    incoming: &Incoming,
    conn: &Connection,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    // Lifecycle/config verbs (the high range) are spoken only by kennel-bin-init and gated
    // on its kernel-stamped identity — handled before the registry/af-unix dispatch.
    if incoming.code >= lifecycle::GET_SANDBOX_PLAN {
        return lifecycle_handle(lifecycle, incoming, ctx, writer);
    }
    // Dynamic spawn (§7.12): the requester workload asks kenneld to instantiate a signed-template
    // sibling. A facade-class verb (no registry lock): the validation is verify-half and the only fd
    // movement is the outbound reply ([[binder-fd-passing-safety-verdict]]).
    if incoming.code == verb::SPAWN {
        return crate::spawn::handle_spawn(spawn, incoming, ctx, writer);
    }
    // Read-only interrogation of this kennel's own [spawn] grant (§7.12): what it may ask SPAWN for.
    if incoming.code == verb::SPAWN_QUERY {
        return crate::spawn::handle_spawn_query(spawn, incoming, ctx, writer);
    }
    // The service-connector broker (§7.13.4a): resolve a mesh capability name against the live
    // catalogue and broker a connector. A facade-class verb (no registry lock): the request-don't-author
    // gate is the kennel's signed [[consumes]], and the resolve is against the daemon catalogue.
    if incoming.code == verb::SVC_CONNECT {
        return svc_connect(consumes, catalogue, incoming, ctx, writer);
    }
    // The af-unix and INet facades dial host I/O (blocking) and return a descriptor, so they are
    // handled apart from the byte-reply registry verbs and **without** the registry lock — the
    // blocking call must not serialise the whole pool.
    if incoming.code == verb::CONNECT_AFUNIX {
        return af_unix_connect(unix, incoming, ctx, writer);
    }
    if incoming.code == verb::CONNECT_INET {
        return inet_connect(net, incoming, ctx, writer);
    }
    // Inbound mirror registration (§7.5.7): the facade hands kenneld its callback node; kenneld
    // gates the port, acquires the handle, watches its death, and maps port → handle. No conduit
    // is handed back here (the reply is a status byte) — kenneld pushes DELIVER_INET on accept.
    if incoming.code == verb::REGISTER_MIRROR {
        return register_mirror(inbound, incoming, conn, ctx, writer);
    }
    // The D-Bus mediation membrane (§7.7.2a): kenneld relays opaque frames to the host-dbus
    // delegate by connection id, lock-free (the relay owns its own state + rate cap). `DBUS_RECV`
    // parks the looper until a frame is ready, so — like the af-unix/INet dials — it is dispatched
    // off the registry lock; the relay bounds parked loopers to one per connection.
    if matches!(
        incoming.code,
        verb::DBUS_OPEN | verb::DBUS_SEND | verb::DBUS_RECV | verb::DBUS_CLOSE
    ) {
        return dbus_handle(dbus, incoming, ctx, writer);
    }
    let name = decode_name(&incoming.data);
    // The registry verbs are O(1) in-memory; take the lock only for them.
    let (action, outcome, reply) = {
        let mut registry = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (incoming.code, name) {
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
        }
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

/// Act on a fired TTL (§9.7). `kennel-bin-init` is blocked in the `NOTIFY_TTL_EXPIRED` call,
/// so freezing the cgroup atomically suspends the whole kennel (no act-past-deadline race);
/// kenneld's own threads are not in that cgroup, so this stays live to prompt the operator.
///
/// `exit` kills the frozen cgroup; `warn` thaws and resumes once (the one-shot alarm is not
/// re-armed); `renew` asks the attached operator whether to extend — this thread blocks for
/// the answer while the kennel stays frozen — and re-arms (`RENEW`) on yes, terminates on an
/// explicit no, or falls back to a warn when no operator could be asked (never destroying a
/// kennel on a missed prompt). Returns the audit name, outcome, and reply byte.
fn ttl_expired(lifecycle: &Lifecycle) -> (&'static str, Outcome, Reply) {
    let _ = crate::cgroup::freeze_cgroup(&lifecycle.cgroup);
    match lifecycle.ttl_action {
        kennel_lib_policy::TtlAction::Exit => {
            // Stay frozen and terminate (SIGKILL reaches frozen tasks). kennel-bin-init is
            // killed, so it never reads the reply; the reply byte is moot.
            let _ = crate::cgroup::kill_cgroup(&lifecycle.cgroup);
            (
                "binder.ttl-terminate",
                Outcome::Allow,
                Reply::Data(one(ttl::TERMINATE)),
            )
        }
        kennel_lib_policy::TtlAction::Warn => {
            let _ = crate::cgroup::thaw_cgroup(&lifecycle.cgroup);
            (
                "binder.ttl-warn",
                Outcome::Info,
                Reply::Data(one(ttl::RESUME)),
            )
        }
        kennel_lib_policy::TtlAction::Renew => {
            let question = format!(
                "kennel '{}' reached its TTL — renew for another period? [y/N]",
                lifecycle.name
            );
            match lifecycle.prompt.as_ref().and_then(|p| p.ask(&question)) {
                Some(true) => {
                    // Approved: thaw and tell kennel-bin-init to re-arm for another period.
                    let _ = crate::cgroup::thaw_cgroup(&lifecycle.cgroup);
                    (
                        "binder.ttl-renew",
                        Outcome::Info,
                        Reply::Data(one(ttl::RENEW)),
                    )
                }
                Some(false) => {
                    // Declined: the deadline stands — terminate like `exit`.
                    let _ = crate::cgroup::kill_cgroup(&lifecycle.cgroup);
                    (
                        "binder.ttl-decline",
                        Outcome::Allow,
                        Reply::Data(one(ttl::TERMINATE)),
                    )
                }
                None => {
                    // No operator could be asked (non-interactive, detached, timed out): fall
                    // back to a warn (resume, no re-arm).
                    let _ = crate::cgroup::thaw_cgroup(&lifecycle.cgroup);
                    (
                        "binder.ttl-warn-no-operator",
                        Outcome::Info,
                        Reply::Data(one(ttl::RESUME)),
                    )
                }
            }
        }
    }
}

/// Serve a node-0 **lifecycle/config verb**, gated on the caller's kernel-stamped
/// identity: only `kennel-bin-init` (the host pid the privhelper reported, running as
/// uid 0) may pull the plan or post notifications (`07-2` §7.2.4). A caller that is
/// not the registered init pid — a spoof, or any other in-kennel process — is denied
/// and audited.
fn lifecycle_handle(
    lifecycle: &Lifecycle,
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
            // The supervision-half only; the interactive pty rides the construction channel
            // (kennel-bin-init inherits the return socket at PTY_RETURN_FD), not this reply.
            (
                "binder.get-sandbox-plan",
                Outcome::Allow,
                Reply::Data(lifecycle.supervision.clone()),
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
        lifecycle::NOTIFY_FACADE_RESTART => (
            "binder.notify-facade-restart",
            Outcome::Info,
            Reply::Data(one(status::OK)),
        ),
        lifecycle::NOTIFY_WORKLOAD_EXEC => (
            "binder.notify-workload-exec",
            Outcome::Info,
            Reply::Data(one(status::OK)),
        ),
        lifecycle::NOTIFY_TTL_EXPIRED => ttl_expired(lifecycle),
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
/// must be exactly the registered `kennel-bin-init` host pid. That pid is the binding fact —
/// kernel-stamped (`task_tgid_nr_ns`), unforgeable, and unique to `kennel-bin-init` (the
/// workload and facades have different pids). `init == None` (lifecycle disabled) denies
/// everything because `Some(pid) != None`.
///
/// `sender_euid == 0` is defense-in-depth alongside the pid match: `kennel-bin-init` is the
/// only uid-0 process in the kennel (host root via the `0 0 1` map; the workload and facades
/// run as the operator's non-zero uid), so a lifecycle verb from a non-zero euid is never
/// `kennel-bin-init` and is denied (`07-2` §7.2.2). The pid match is the primary, exact gate.
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
/// The service-connector broker (§7.13.4a): resolve a mesh capability name against the live catalogue
/// and broker a connector, gated by this kennel's signed `[[consumes]]` (request-don't-author).
///
/// The broker decision ([`crate::broker::decide`]) maps to a reply status. The connector handoff for a
/// `Ready` provider (the af-unix fd bridge) and the socket-activation + consume-with-wait of a
/// `Pending` one are the supervisor's (W6), reached once providers actually run; until then every
/// enabled provider is `Pending`/`Failed`, so the live outcomes are the deny/not-found/unavailable
/// gates — all enforced here.
fn svc_connect(
    consumes: &[kennel_lib_policy::ConsumeRuntime],
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    use crate::broker::Decision;
    use kennel_lib_binder::service::svc_connect as wire;

    let Some(name) = wire::decode_request(&incoming.data) else {
        return emit_svc_connect(
            writer,
            incoming,
            ctx,
            "",
            Outcome::Deny,
            status::BAD_REQUEST,
        );
    };
    // Resolve against the live catalogue (an absent catalogue resolves nothing — the gate still runs).
    let empty = crate::catalogue::Catalogue::default();
    let decision = catalogue.map_or_else(
        || crate::broker::decide(consumes, &empty, name),
        |cat| {
            let guard = cat
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            crate::broker::decide(consumes, &guard, name)
        },
    );
    let (outcome, status) = match decision {
        Decision::NoGrant => (Outcome::Deny, status::DENIED),
        Decision::NoProvider => (Outcome::Deny, status::NOT_FOUND),
        // `NotServing` is a failed provider; `Pending`/`Ready` need the supervisor (W6) to
        // socket-activate and hand off the connector. Until W6 no provider runs, so all three are
        // unavailable here — W6 splits `Pending` (activate + consume-with-wait) and `Ready` (connect).
        Decision::NotServing | Decision::Pending(_) | Decision::Ready(_) => {
            (Outcome::Error, status::UNAVAILABLE)
        }
    };
    emit_svc_connect(writer, incoming, ctx, name, outcome, status)
}

/// Audit one `SVC_CONNECT` outcome and reply with the status byte (no connector object on a non-OK).
fn emit_svc_connect(
    writer: &Writer,
    incoming: &Incoming,
    ctx: u16,
    name: &str,
    outcome: Outcome,
    status: u8,
) -> Reply {
    writer.emit(
        &Event::new(
            "binder.svc-connect",
            Resource::Binder,
            outcome,
            Source::Kenneld,
        )
        .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
        .field("name", Value::untrusted(name.to_owned()))
        .field("ctx", Value::Uint(u64::from(ctx))),
    );
    Reply::Data(one(status))
}

fn af_unix_connect(unix: &UnixRuntime, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let requested = decode_name(&incoming.data);
    let target = requested
        .as_deref()
        .and_then(|p| unix.sockets.iter().find(|s| s.shim == p || s.name == p));
    let (outcome, reply) = target.map_or_else(
        || (Outcome::Deny, Reply::Data(one(status::DENIED))),
        |socket| {
            kennel_lib_syscall::net::connect_unix_timeout(
                std::path::Path::new(&socket.real),
                AFUNIX_CONNECT_DEADLINE,
            )
            .map_or_else(
                // Granted but unreachable (absent / refused / timed out): never tie up the
                // looper on a wedged target.
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

/// The `INet` egress facade (§7.5.2): decode the request, decide it under `[net.proxy]` via
/// [`crate::inet`], and reply with either the connection fd or a status byte.
///
/// On an approved request kenneld pins the vetted address, mints the per-connection socketpair
/// conduit, drives the `host-netproxy` delegate to dial it, and returns the kennel-facing end as
/// [`Reply::Fd`]. A denied/unreachable request returns a status byte. Audited either way.
fn inet_connect(
    net: &crate::inet::NetRuntime,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    use crate::inet::allow::Destination;
    use crate::inet::dns::SystemResolver;
    let Some((transport, port, dest)) = crate::inet::decode_request(&incoming.data, MAX_NAME)
    else {
        writer.emit(&inet_event(incoming, ctx, "", 0, Outcome::Error));
        return Reply::Data(one(status::BAD_REQUEST));
    };
    let label = match &dest {
        Destination::Name(name) => name.clone(),
        Destination::Addr(addr) => addr.to_string(),
    };
    let (outcome, reply) = match crate::inet::decide(net, &SystemResolver, &dest, port, transport) {
        crate::inet::InetDecision::Denied => (Outcome::Deny, Reply::Data(one(status::DENIED))),
        crate::inet::InetDecision::Unreachable => {
            (Outcome::Error, Reply::Data(one(status::NOT_FOUND)))
        }
        // Approved + pinned: mint the conduit via the delegate and hand the kennel-facing end back
        // over binder. No command socket (no egress delegate) ⇒ unreachable.
        crate::inet::InetDecision::Pinned(addrs) => net.command_socket().map_or_else(
            || (Outcome::Error, Reply::Data(one(status::NOT_FOUND))),
            |sock| {
                crate::inet::dial_via_delegate(sock, port, &addrs).map_or_else(
                    |_| (Outcome::Error, Reply::Data(one(status::NOT_FOUND))),
                    |end| (Outcome::Allow, Reply::Fd(OwnedFd::from(end))),
                )
            },
        ),
    };
    writer.emit(&inet_event(incoming, ctx, &label, port, outcome));
    reply
}

/// Serve a `REGISTER_MIRROR` request: bind a facade's callback node to a mirrored port (§7.5.7).
///
/// The push counterpart of the old `BIND_INET` poll. The facade transacts `[transport | port]`
/// plus its own binder node (`transact_node`); kenneld:
/// 1. **port-gates** the request against the policy mirror set (guard 3) — `DENIED` otherwise;
/// 2. parses the translated handle from the node object (the trailing `flat_binder_object`);
/// 3. **acquires** the handle so it survives this transaction's buffer free, and requests its
///    **death notification** (guard 1) — both must happen before the reply frees the buffer;
/// 4. maps `port → handle` and drains any bounced conduits.
///
/// **No per-connection policy decision** — the `[net.bpf].bind` ACL already gated the bind. The
/// reply is a status byte; conduits are pushed later with `DELIVER_INET`.
fn register_mirror(
    inbound: &crate::inbound::InboundRuntime,
    incoming: &Incoming,
    conn: &Connection,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    use kennel_lib_binder::proto::{flat_binder_object_handle_value, FLAT_BINDER_OBJECT_SIZE};
    use kennel_lib_binder::service::inet::decode_port_prefix;

    let Some((_transport, port)) = decode_port_prefix(&incoming.data) else {
        writer.emit(&inet_event(
            incoming,
            ctx,
            "mirror-register",
            0,
            Outcome::Error,
        ));
        return Reply::Data(one(status::BAD_REQUEST));
    };
    // Guard 3: registration is port-gated, not caller-gated (the facade and the workload share the
    // persona uid, so kenneld cannot tell them apart by sender_euid). Only a policy-mirrored port
    // is accepted; a workload registering its own mirrored port merely gets its own conduits.
    if !inbound.is_allowed(port) {
        writer.emit(&inet_event(
            incoming,
            ctx,
            "mirror-register",
            port,
            Outcome::Deny,
        ));
        return Reply::Data(one(status::DENIED));
    }
    // The node object the facade sent is the trailing flat_binder_object; the driver translated it
    // to a handle for us.
    let handle = incoming
        .data
        .len()
        .checked_sub(FLAT_BINDER_OBJECT_SIZE)
        .and_then(|off| incoming.data.get(off..))
        .and_then(flat_binder_object_handle_value);
    let Some(handle) = handle else {
        writer.emit(&inet_event(
            incoming,
            ctx,
            "mirror-register",
            port,
            Outcome::Error,
        ));
        return Reply::Data(one(status::BAD_REQUEST));
    };
    // Keep the handle past this transaction's buffer free, and learn when its node dies. Both ride
    // `conn` here, before the reply (and its BC_FREE_BUFFER) drops the transaction's temporary ref.
    if conn.acquire_handle(handle).is_err() {
        writer.emit(&inet_event(
            incoming,
            ctx,
            "mirror-register",
            port,
            Outcome::Error,
        ));
        return Reply::Data(one(status::BAD_REQUEST));
    }
    let _ = conn.request_death(handle, u64::from(handle));
    inbound.register(conn, port, handle);
    writer.emit(&inet_event(
        incoming,
        ctx,
        "mirror-register",
        port,
        Outcome::Allow,
    ));
    Reply::Data(one(status::OK))
}

/// The audit event for an `INet` CONNECT decision.
fn inet_event(incoming: &Incoming, ctx: u16, dest: &str, port: u16, outcome: Outcome) -> Event {
    Event::new(
        "binder.inet-connect",
        Resource::Binder,
        outcome,
        Source::Kenneld,
    )
    .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
    .field("dest", Value::untrusted(dest.to_owned()))
    .field("port", Value::Uint(u64::from(port)))
    .field("ctx", Value::Uint(u64::from(ctx)))
}

/// Serve a D-Bus mediation verb (§7.7.2a). kenneld is the **membrane**, not a filter or parser:
/// it binds each connection to its opener (the relay's per-connection owner check, on the
/// kernel-attested sender pid), applies the token-bucket rate cap, and relays the opaque frame
/// to/from the `host-dbus` delegate by connection id. The relay owns all of that state, so no
/// registry lock is taken here.
///
/// `dbus == None` means the kennel enabled no bus (`[dbus]` absent or the delegate failed to
/// start): every verb is denied — fail-closed, never a silent bus exposure.
///
/// Only the connection-lifecycle verbs (`OPEN`/`CLOSE`) are audited here: they are low-volume and
/// security-relevant. `SEND`/`RECV` are per-message transport — auditing them at the membrane would
/// drown the log, and the real bus decisions (the allowlist, §7.7.2a) are audited by the delegate,
/// which owns filtering.
fn dbus_handle(dbus: Option<&DbusRelay>, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let Some(relay) = dbus else {
        return Reply::Data(one(status::DENIED));
    };
    let pid = incoming.sender_pid;
    match incoming.code {
        verb::DBUS_OPEN => {
            let reply = relay.open(pid, &incoming.data);
            audit_dbus(
                writer,
                incoming,
                ctx,
                "binder.dbus-open",
                reply.first().copied(),
            );
            Reply::Data(reply)
        }
        verb::DBUS_CLOSE => {
            let reply = relay.close(pid, &incoming.data);
            audit_dbus(
                writer,
                incoming,
                ctx,
                "binder.dbus-close",
                reply.first().copied(),
            );
            Reply::Data(reply)
        }
        verb::DBUS_SEND => Reply::Data(relay.send(pid, &incoming.data)),
        verb::DBUS_RECV => Reply::Data(relay.recv(pid, &incoming.data)),
        // Unreachable: `handle` dispatches here only for the four DBUS_* codes.
        _ => Reply::Data(one(status::BAD_REQUEST)),
    }
}

/// Audit one D-Bus lifecycle verb, mapping the relay's reply status byte to an outcome (an empty
/// reply — a denied/gone `recv` — is `Info`).
fn audit_dbus(
    writer: &Writer,
    incoming: &Incoming,
    ctx: u16,
    action: &'static str,
    status_byte: Option<u8>,
) {
    let outcome = status_byte.map_or(Outcome::Info, outcome_for);
    writer.emit(
        &Event::new(action, Resource::Binder, outcome, Source::Kenneld)
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("ctx", Value::Uint(u64::from(ctx))),
    );
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
    use kennel_lib_policy::{BinderConsumeRuntime, BinderProvideRuntime};

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
        // `kennel-bin-init` is the only uid-0 process; the gate is the exact init host pid AND
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
