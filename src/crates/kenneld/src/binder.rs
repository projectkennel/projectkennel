//! kenneld as the per-kennel binder context manager.
//!
//! kenneld owns node 0 of each kennel's binderfs instance and serves it on a
//! per-kennel thread (like [`crate::bpf_audit`]'s drain): the lifecycle/config verbs
//! `kennel-bin-init` speaks, the af-unix/INet/D-Bus facades, the dynamic-spawn verbs,
//! and the service-connector broker (`SVC_CONNECT`) for the cross-kennel mesh. Each
//! call emits a `binder.*` audit event through the unified [`Writer`].
//!
//! This module is the *policy* layer; the binder transport (the looper, the wire
//! codec, the ioctls) is [`kennel_lib_binder`]. The transaction payload convention on
//! node 0 (the verb codes and the status/byte replies) is internal-stable: `kenneld`
//! and the in-kennel client agree because they ship from one release.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};
use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::ctxmgr::{ContextManager, DeathHandler, Handler, Reply};
use kennel_lib_policy::UnixRuntime;

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
/// The consume-with-wait deadline (§7.13.4a): a `SVC_CONNECT` to a cold `ondemand` provider holds the
/// transaction this long for it to become declared-and-ready before returning `UNAVAILABLE`. A broker
/// constant sized to the slowest legitimate provider start; also the dependency-cycle safety valve (a
/// mutual consume double-times-out rather than deadlocking).
const CONSUME_WAIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
/// How often the consume-with-wait loop re-resolves the activated provider's readiness.
const CONSUME_WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(50);
/// A service name is bounded (binderfs's own `BINDERFS_MAX_NAME`); reject longer.
const MAX_NAME: usize = 255;
/// The in-view device path of the D-Bus connector mesh bus (the template's binder-connector
/// endpoint, bind-mounted into the consumer's view). The per-kennel `SVC_CONNECT(dbus-name)`
/// hands this back so the facade opens the mesh bus and connects to the broker there (§7.7).
pub(crate) const MESH_DBUS_DEVICE: &str = "/dev/binderfs-mesh/binder";

// The node-0 verb codes and reply status bytes are the shared wire convention
// (`kennel_lib_binder::service`), used by both kenneld here and the in-kennel clients.
pub use kennel_lib_binder::service::{lifecycle, status, ttl, verb};

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

/// The tun-egress inputs threaded into the node-0 handler (§8 / W2).
///
/// `sink` is the daemon-global [`crate::tun_sink::TunSink`] this kennel's manager either **registers**
/// (when it is the tun-broker, on [`verb::REGISTER_TUN_SINK`]) or **delivers to** (when it is a
/// `[net.udp]` consumer, on a [`verb::CONNECT_AFUNIX`] for the tun capability). `cm` is this manager's
/// own context manager, recorded against the sink so the cross-connection deliver can reach the
/// broker. `session` is this kennel's own pre-resolved [`verb::DELIVER_TUN_SESSION`] payload —
/// `Some` iff it is a `[net.udp]` tun consumer (its presence is the grant).
struct TunCtx<'a> {
    sink: &'a crate::tun_sink::TunSink,
    /// Whether this kennel's signed policy provides the tun capability — required to register.
    provider: bool,
    session: Option<&'a [u8]>,
    cm: &'a Arc<ContextManager>,
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

/// What node 0 of one kennel's binder instance serves with.
///
/// The device, and each subsystem's state for that kennel. Named fields, because several are
/// the same type (two `bool`s among them) and a positional call could swap them unnoticed.
pub struct NodeZero {
    /// The kennel's binder device, opened by the daemon from the handle the factory returned.
    pub device_fd: OwnedFd,
    /// The kennel's context number.
    pub ctx: u16,
    /// The `[unix]` grants.
    pub unix: UnixRuntime,
    /// The supervision plan, exit reporting and prompts.
    pub lifecycle: Lifecycle,
    /// The egress decision state.
    pub net: crate::inet::NetRuntime,
    /// The inbound mirror state.
    pub inbound: Arc<crate::inbound::InboundRuntime>,
    /// Whether D-Bus is brokered through the mesh for this kennel.
    pub dbus_mesh: bool,
    /// The kennel's audit writer.
    pub writer: Arc<Writer>,
    /// The spawn runtime, when the policy allows spawning.
    pub spawn: Option<Arc<crate::spawn::SpawnRuntime>>,
    /// The mesh services this kennel consumes.
    pub consumes: Vec<kennel_lib_policy::ConsumeRuntime>,
    /// The mesh catalogue, when the kennel takes part in the mesh.
    pub catalogue: Option<Arc<Mutex<crate::catalogue::Catalogue>>>,
    /// Starts a provider kennel on demand.
    pub activator: Option<Arc<dyn crate::supervisor::ProviderActivator>>,
    /// Where a tun broker's session sink is registered and looked up.
    pub tun_sink: crate::tun_sink::TunSink,
    /// Whether this kennel is the tun broker (it may register the sink).
    pub tun_provider: bool,
    /// The session payload for a kennel with UDP egress.
    pub tun_session: Option<Vec<u8>>,
}

impl NodeZero {
    /// A node 0 that grants nothing: no socket grants, egress denied, no inbound mirror, no
    /// spawn, no mesh, no tun.
    ///
    /// The starting point for a caller that enables one subsystem — a test of a single verb,
    /// say — with `NodeZero { unix, ..NodeZero::closed(fd, ctx, writer) }`. Every field it
    /// fills in is the refusing value, so forgetting to set one leaves that subsystem shut.
    #[must_use]
    pub fn closed(device_fd: OwnedFd, ctx: u16, writer: Arc<Writer>) -> Self {
        Self {
            device_fd,
            ctx,
            unix: UnixRuntime::default(),
            lifecycle: Lifecycle::default(),
            net: crate::inet::NetRuntime::denied(),
            inbound: Arc::new(crate::inbound::InboundRuntime::new()),
            dbus_mesh: false,
            writer,
            spawn: None,
            consumes: Vec::new(),
            catalogue: None,
            activator: None,
            tun_sink: crate::tun_sink::TunSink::new(),
            tun_provider: false,
            tun_session: None,
        }
    }
}

/// Take node 0 of the binder instance behind `serve.device_fd` and serve its registry on a
/// per-kennel thread, gating against the policy state and auditing through `serve.writer`.
///
/// # Errors
///
/// Returns the OS error if becoming context manager (open/`mmap`/`SET_CONTEXT_MGR`/
/// looper) fails, or the worker thread cannot be spawned.
pub fn spawn(serve: NodeZero) -> io::Result<Manager> {
    let NodeZero {
        device_fd,
        ctx,
        unix,
        lifecycle,
        net,
        inbound,
        dbus_mesh,
        writer,
        spawn,
        consumes,
        catalogue,
        activator,
        tun_sink,
        tun_provider,
        tun_session,
    } = serve;
    let cm = Arc::new(ContextManager::new(device_fd, MAP_SIZE)?);
    let stop = Arc::new(AtomicBool::new(false));

    // kenneld pushes DELIVER_INET (§7.5.7) on this same connection — a binder handle is valid only
    // on the open that received it — so the inbound runtime borrows the context manager. Attached
    // before the pool serves, so a REGISTER_MIRROR can never race an unattached pusher.
    inbound.attach_pusher(Arc::clone(&cm));
    inbound.attach_audit(Arc::clone(&writer), ctx);

    // The handler runs concurrently on every looper, so its shared state is held by Arc.
    let unix = Arc::new(unix);
    let net = Arc::new(net);
    let lifecycle = Arc::new(lifecycle);
    // The mesh broker's per-kennel inputs: this kennel's signed consumes (the request-don't-author
    // floor) and the daemon's live catalogue (resolved against on SVC_CONNECT), shared across loopers.
    let consumes = Arc::new(consumes);
    let inbound_for_death = Arc::clone(&inbound);
    // Tun egress (§8 / W2): the handler records the broker's sink against THIS manager's context
    // manager (not the borrowed serve connection), so it captures a clone; the death closure keeps
    // its own clone of the daemon-global sink to clear on the broker's death.
    let cm_for_handler = Arc::clone(&cm);
    let tun_sink_for_death = tun_sink.clone();
    let handler: Handler = Arc::new(move |incoming: &Incoming, conn: &Connection| {
        let tun = TunCtx {
            sink: &tun_sink,
            provider: tun_provider,
            session: tun_session.as_deref(),
            cm: &cm_for_handler,
        };
        handle(
            &unix,
            &net,
            &inbound,
            &lifecycle,
            dbus_mesh,
            spawn.as_deref(),
            &consumes,
            catalogue.as_ref(),
            activator.as_ref(),
            &tun,
            incoming,
            conn,
            ctx,
            &writer,
        )
    });
    // A watched node died: the tun-broker's sink (clear it) or an inbound mirror handle (drop it,
    // §7.5.7 guard 1). The sink is keyed by a sentinel cookie distinct from every mirror cookie.
    let death: DeathHandler = Arc::new(move |cookie: u64, conn: &Connection| {
        // Only the tun-broker's own manager ever watches the sink node, and only it may clear the
        // daemon-global record.
        if cookie == crate::tun_sink::SINK_DEATH_COOKIE && tun_provider {
            tun_sink_for_death.clear();
            let _ = conn.dead_binder_done(cookie);
            return;
        }
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

/// Decode one node-0 transaction, dispatch it, emit an audit event, and produce the
/// reply (a status byte, or a connected fd for the af-unix facade).
#[allow(clippy::too_many_arguments)] // the handler's shared state; each piece is one concern
fn handle(
    unix: &UnixRuntime,
    net: &crate::inet::NetRuntime,
    inbound: &crate::inbound::InboundRuntime,
    lifecycle: &Lifecycle,
    dbus_mesh: bool,
    spawn: Option<&crate::spawn::SpawnRuntime>,
    consumes: &[kennel_lib_policy::ConsumeRuntime],
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
    tun: &TunCtx<'_>,
    incoming: &Incoming,
    conn: &Connection,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    // Lifecycle/config verbs (the high range) are spoken only by kennel-bin-init and gated
    // on its kernel-stamped identity — handled before the facade dispatch.
    if incoming.code >= lifecycle::GET_SANDBOX_PLAN {
        return lifecycle_handle(lifecycle, catalogue, activator, incoming, ctx, writer);
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
        return svc_connect(
            consumes, catalogue, activator, incoming, ctx, writer, dbus_mesh,
        );
    }
    // The af-unix and INet facades dial host I/O (blocking) and return a descriptor, so they are
    // handled apart from the byte-reply registry verbs and **without** the registry lock — the
    // blocking call must not serialise the whole pool.
    if incoming.code == verb::CONNECT_AFUNIX {
        // The af-unix facade is one mechanism over two resolutions. If the requested name matches a
        // signed `[[consumes]]` stanza, it is a mesh capability: route to the broker (§7.13.4 — resolve,
        // socket-activate if cold, connect the provider's endpoint). Otherwise it is a host
        // `[[unix.allow]]` socket: the regular path. The request payload is the bare name in both, and
        // the reply (a connected fd in the binder object table) is identical, so the facade is unaware.
        if let Some(name) = kennel_lib_binder::service::svc_connect::decode_request(&incoming.data)
        {
            // The tun-broker's egress capability is af-unix-shaped but NOT a plain rendezvous connect:
            // kenneld resolves this consumer's grants and has the broker mint a per-session mediator
            // (§8 / W2), so it is special-cased ahead of the generic mesh / host-socket dispatch.
            if name == kennel_lib_binder::service::tun_broker::CAPABILITY {
                return tun_connect(tun, catalogue, activator, incoming, ctx, writer);
            }
            if consumes.iter().any(|c| c.name == name) {
                return svc_connect(
                    consumes, catalogue, activator, incoming, ctx, writer, dbus_mesh,
                );
            }
        }
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
    // Tun-egress sink registration (§8 / W2): the standing tun-broker hands kenneld its sink node so
    // kenneld can deliver each `[net.udp]` consumer's session to it. Modelled on REGISTER_MIRROR —
    // acquire the handle, watch its death, record it — but daemon-global (the broker and consumers
    // are different kennels) rather than per-port. No conduit is handed back here (a status byte).
    if incoming.code == verb::REGISTER_TUN_SINK {
        return register_tun_sink(tun, incoming, conn, ctx, writer);
    }
    // Any other verb is unrecognised on node 0.
    let service = decode_name(&incoming.data).unwrap_or_default();
    writer.emit(
        &Event::new(
            "binder.bad-request",
            Resource::Binder,
            Outcome::Error,
            Source::Kenneld,
        )
        .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
        .field("service", Value::untrusted(service))
        .field("ctx", Value::Uint(u64::from(ctx))),
    );
    Reply::Data(one(status::BAD_REQUEST))
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
fn ttl_expired(
    lifecycle: &Lifecycle,
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
) -> (&'static str, Outcome, Reply) {
    // The freeze holds the workload still while this is decided. If it fails the decision is
    // still made, and the kill or thaw below reports its own result.
    if let Err(e) = crate::cgroup::freeze_cgroup(&lifecycle.cgroup) {
        eprintln!(
            "kenneld: kennel '{}': TTL freeze failed: {e}",
            lifecycle.name
        );
    }
    // W6 idle-reap (§7.13.6): an ondemand provider's TTL is its idle grace. On each fire, keep it
    // (re-arm) while a consumer kennel runs, reap it when none — riding this existing TTL custodian,
    // not a parallel reaper. "Consumer" = a running kennel whose `[[consumes]]` names a capability
    // this provider offers.
    let provider_offers = catalogue.and_then(|cat| {
        cat.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ondemand_provider_offers(&lifecycle.name)
    });
    if let Some(offers) = provider_offers {
        // No activator (a construction-only path) ⇒ cannot census ⇒ keep it: never destroy a
        // provider on a blind check (mirrors the missed-prompt `renew` fallback).
        if activator.is_none_or(|a| a.has_running_consumer(&offers)) {
            return (
                "binder.ttl-provider-keep",
                ttl_thaw(lifecycle),
                Reply::Data(one(ttl::RENEW)),
            );
        }
        // Mark the reap before the kill so the supervisor reads the resulting exit as a reap
        // (→ declared-but-pending, re-activatable), not a crash to restart. The activator is
        // `Some` here — `is_none_or` only falls through when it is present and reports no consumer.
        if let Some(a) = activator {
            a.mark_idle_reaped(&lifecycle.name);
        }
        return (
            "binder.ttl-provider-reap",
            ttl_kill(lifecycle),
            Reply::Data(one(ttl::TERMINATE)),
        );
    }
    match lifecycle.ttl_action {
        kennel_lib_policy::TtlAction::Exit => {
            // Stay frozen and terminate (SIGKILL reaches frozen tasks). kennel-bin-init is
            // killed, so it never reads the reply; the reply byte is moot.
            (
                "binder.ttl-terminate",
                ttl_kill(lifecycle),
                Reply::Data(one(ttl::TERMINATE)),
            )
        }
        kennel_lib_policy::TtlAction::Warn => (
            "binder.ttl-warn",
            ttl_thaw(lifecycle),
            Reply::Data(one(ttl::RESUME)),
        ),
        kennel_lib_policy::TtlAction::Renew => {
            let question = format!(
                "kennel '{}' reached its TTL — renew for another period? [y/N]",
                lifecycle.name
            );
            match lifecycle.prompt.as_ref().and_then(|p| p.ask(&question)) {
                Some(true) => {
                    // Approved: thaw and tell kennel-bin-init to re-arm for another period.
                    (
                        "binder.ttl-renew",
                        ttl_thaw(lifecycle),
                        Reply::Data(one(ttl::RENEW)),
                    )
                }
                Some(false) => {
                    // Declined: the deadline stands — terminate like `exit`.
                    (
                        "binder.ttl-decline",
                        ttl_kill(lifecycle),
                        Reply::Data(one(ttl::TERMINATE)),
                    )
                }
                None => {
                    // No operator could be asked (non-interactive, detached, timed out): fall
                    // back to a warn (resume, no re-arm).
                    (
                        "binder.ttl-warn-no-operator",
                        ttl_thaw(lifecycle),
                        Reply::Data(one(ttl::RESUME)),
                    )
                }
            }
        }
    }
}

/// Kill the kennel for its TTL; the outcome to audit (`Allow` if the kill took effect).
fn ttl_kill(lifecycle: &Lifecycle) -> Outcome {
    let result = crate::cgroup::kill_cgroup(&lifecycle.cgroup);
    enforced(lifecycle, "kill", result, Outcome::Allow)
}

/// Thaw the kennel after a TTL decision; the outcome to audit (`Info` if the thaw took effect).
fn ttl_thaw(lifecycle: &Lifecycle) -> Outcome {
    let result = crate::cgroup::thaw_cgroup(&lifecycle.cgroup);
    enforced(lifecycle, "thaw", result, Outcome::Info)
}

/// The outcome to audit for one TTL step: `done` if the cgroup write took effect, `Error` if it
/// did not. A kill that failed leaves the workload running past its deadline, and a thaw that
/// failed leaves it frozen; neither may be recorded as the action having happened.
fn enforced(
    lifecycle: &Lifecycle,
    step: &str,
    result: std::io::Result<()>,
    done: Outcome,
) -> Outcome {
    match result {
        Ok(()) => done,
        Err(e) => {
            eprintln!(
                "kenneld: kennel '{}': TTL {step} failed: {e}",
                lifecycle.name
            );
            Outcome::Error
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
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
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
        lifecycle::NOTIFY_TTL_EXPIRED => ttl_expired(lifecycle, catalogue, activator),
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
/// The broker decision ([`crate::broker::decide`]) maps to a reply status: `NoGrant` → `DENIED`,
/// `NoProvider` → `NOT_FOUND`, `NotServing` → `UNAVAILABLE`. A `Ready` provider gets the connector
/// handoff (the af-unix fd bridge) now; a `Pending` (enabled-but-cold) one is **socket-activated and
/// consume-with-waited** ([`svc_connect_activate_wait`]) until it is ready or the deadline fires.
fn svc_connect(
    consumes: &[kennel_lib_policy::ConsumeRuntime],
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
    dbus_mesh: bool,
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
        // A `Ready` provider is running: broker the connector now.
        Decision::Ready(sel) => {
            return svc_connect_handoff(writer, incoming, ctx, name, &sel, dbus_mesh)
        }
        // A `Pending` provider is enabled but cold: socket-activate it and consume-with-wait until it
        // is declared-and-ready (broker the connector) or the deadline fires (§7.13.4a).
        Decision::Pending(sel) => {
            return svc_connect_activate_wait(
                consumes, catalogue, activator, incoming, ctx, name, writer, &sel, dbus_mesh,
            );
        }
        // A `NotServing` (declared-but-failed) provider cannot hand a connector — no fallback (§7.13.4).
        Decision::NotServing => (Outcome::Error, status::UNAVAILABLE),
    };
    emit_svc_connect(writer, incoming, ctx, name, outcome, status)
}

/// Socket-activate a cold `ondemand` provider and consume-with-wait (§7.13.4a): trigger its start,
/// then hold the transaction — re-resolving against the live catalogue — until it is
/// declared-and-ready (broker the connector) or the consume-with-wait deadline fires (`UNAVAILABLE`).
///
/// The bounded wait is the dependency-cycle safety valve: a mutual consume double-times-out into
/// `UNAVAILABLE` rather than deadlocking (§7.13.4a). It runs on a dedicated binder looper, so the wait
/// head-of-line-blocks nothing else on the instance. With no activator installed (a test path) the
/// provider stays cold and the wait simply times out.
#[allow(clippy::too_many_arguments)] // the broker's per-consume inputs; each is one concern
fn svc_connect_activate_wait(
    consumes: &[kennel_lib_policy::ConsumeRuntime],
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
    incoming: &Incoming,
    ctx: u16,
    name: &str,
    writer: &Writer,
    sel: &crate::broker::Selected,
    dbus_mesh: bool,
) -> Reply {
    use crate::broker::Decision;
    let unavailable = || {
        emit_svc_connect(
            writer,
            incoming,
            ctx,
            name,
            Outcome::Error,
            status::UNAVAILABLE,
        )
    };
    // Trigger the lazy start (idempotent — a second consume does not double-start it).
    if let Some(act) = activator {
        act.activate(&sel.provider);
    }
    // The `Pending` decision came from the live catalogue, so it is present; without it (a no-catalogue
    // construction path) there is nothing to wait on.
    let Some(cat) = catalogue else {
        return unavailable();
    };
    // Track elapsed against the deadline (never `Instant + Duration`, which can overflow-panic).
    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(CONSUME_WAIT_POLL);
        let decision = {
            let guard = cat
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            crate::broker::decide(consumes, &guard, name)
        };
        match decision {
            // Construction sealed: the provider is ready — broker the connector.
            Decision::Ready(ready) => {
                return svc_connect_handoff(writer, incoming, ctx, name, &ready, dbus_mesh)
            }
            // Crash-loop-exhausted / vanished / grant lost: stop waiting, report unavailable.
            Decision::NoGrant | Decision::NoProvider | Decision::NotServing => {
                return unavailable()
            }
            // Still coming up — keep waiting until the deadline.
            Decision::Pending(_) => {}
        }
        if start.elapsed() >= CONSUME_WAIT_DEADLINE {
            return unavailable();
        }
    }
}

/// Broker the connector to a `Ready` provider (§7.13.4b). The af-unix shape connects to the host
/// rendezvous point — the directory derived from `(tier, name, key)` plus the policy `endpoint`'s
/// basename — and hands the consumer the connected fd (the §4.3 fd-broker, as [`af_unix_connect`]
/// does for a `[[unix.allow]]` socket). Other shapes' handoff lands later; a connect failure
/// (provider not yet bound, gone) is reported `UNAVAILABLE`, never a wedged looper.
fn svc_connect_handoff(
    writer: &Writer,
    incoming: &Incoming,
    ctx: u16,
    name: &str,
    sel: &crate::broker::Selected,
    dbus_mesh: bool,
) -> Reply {
    use kennel_lib_policy::settled::Shape;

    match sel.shape {
        Shape::AfUnix => {} // handled below
        Shape::DbusName => {
            // The dbus-name handoff (§7.7) is a pure *locator*: on the per-kennel bus kenneld only
            // tells the facade where the dbus mesh bus is, and the facade connects THERE. It makes
            // no session and resolves no identity here — the mesh bus's node-0 handler does that,
            // resolving the connecting facade afresh (sender_pid → cgroup → ctx → filter) and
            // minting the session. The standing broker is the ONE mediation home (W4): with no
            // enabled broker there is nothing to locate, and the connect is refused (fail-closed).
            let (reply, outcome) = if dbus_mesh {
                let mut r = vec![status::OK];
                r.extend_from_slice(MESH_DBUS_DEVICE.as_bytes());
                (r, Outcome::Allow)
            } else {
                (vec![status::UNAVAILABLE], Outcome::Deny)
            };
            writer.emit(
                &Event::new(
                    "binder.svc-connect",
                    Resource::Binder,
                    outcome,
                    Source::Kenneld,
                )
                .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
                .field("name", Value::untrusted(name.to_owned()))
                .field("provider", Value::untrusted(sel.provider.clone()))
                .field("shape", Value::untrusted("dbus-name".to_owned()))
                .field("ctx", Value::Uint(u64::from(ctx))),
            );
            return Reply::Data(reply);
        }
        Shape::BinderConnector => {
            // The binder-connector handoff is mediated on the mesh bus, not the per-kennel
            // bus. A SVC_CONNECT here is a programming error by the facade — deny.
            return emit_svc_connect(
                writer,
                incoming,
                ctx,
                name,
                Outcome::Error,
                status::UNAVAILABLE,
            );
        }
    }
    // The host rendezvous socket: kenneld's derived directory + the provider's policy endpoint leaf,
    // the same inode bound into the provider's view (§7.13.4b). The §4.3 fd-broker.
    // The provider can WRITE that directory (it must, to bind its socket), and this connect is
    // made by kenneld, on the host. So it is not made by name: a symlink left there would send
    // the connection — and the consumer — to whatever host socket it points at, kenneld's own
    // control socket included. Pin the entry inside the directory, require it to be a socket,
    // and connect to that inode.
    let (dir, leaf) = crate::mesh::host_rp_parts(sel.tier, name, sel.key.as_deref(), &sel.endpoint);
    kennel_lib_syscall::fd::socket_in_dir(&dir, &leaf)
        .and_then(|sock| {
            kennel_lib_syscall::net::connect_unix_timeout(
                &kennel_lib_syscall::fd::proc_path(&sock),
                AFUNIX_CONNECT_DEADLINE,
            )
        })
        .map_or_else(
            // Granted but unreachable (provider not yet bound / gone): never tie up the looper.
            |_| {
                emit_svc_connect(
                    writer,
                    incoming,
                    ctx,
                    name,
                    Outcome::Error,
                    status::UNAVAILABLE,
                )
            },
            |stream| {
                writer.emit(
                    &Event::new(
                        "binder.svc-connect",
                        Resource::Binder,
                        Outcome::Allow,
                        Source::Kenneld,
                    )
                    .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
                    .field("name", Value::untrusted(name.to_owned()))
                    .field("provider", Value::untrusted(sel.provider.clone()))
                    .field("ctx", Value::Uint(u64::from(ctx))),
                );
                Reply::Fd(OwnedFd::from(stream))
            },
        )
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

/// Why a granted host socket was not connected.
enum GrantedConnect {
    /// The path leads to one of the daemon's own sockets.
    DaemonSocket,
    /// Nothing connectable is there.
    Unreachable,
}

/// Connect to the host socket a `[[unix.allow]]` grants at `real`.
///
/// The socket is opened once and held by descriptor; the daemon-socket rule is applied to the
/// path of that open file, and the connect goes to that same file. Checking the name and then
/// connecting to the name would leave a moment in which it can be made to point elsewhere.
///
/// The rule backstops the compiler's: never broker a connect to a kenneld socket (the control
/// socket, a delegate's command socket), even if a signed settled policy carries the grant.
fn connect_granted_socket(
    real: &std::path::Path,
) -> Result<std::os::unix::net::UnixStream, GrantedConnect> {
    use kennel_lib_control::socket::is_daemon_socket;
    if is_daemon_socket(real) {
        return Err(GrantedConnect::DaemonSocket);
    }
    let pinned = kennel_lib_syscall::net::PinnedSocket::open(real)
        .map_err(|_| GrantedConnect::Unreachable)?;
    // Fail closed: a socket whose resolved path cannot be read is not shown to be someone else's.
    let resolved = pinned.path().map_err(|_| GrantedConnect::Unreachable)?;
    if is_daemon_socket(&resolved) {
        return Err(GrantedConnect::DaemonSocket);
    }
    pinned
        .connect(AFUNIX_CONNECT_DEADLINE)
        .map_err(|_| GrantedConnect::Unreachable)
}

fn af_unix_connect(unix: &UnixRuntime, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let requested = decode_name(&incoming.data);
    let target = requested
        .as_deref()
        .and_then(|p| unix.sockets.iter().find(|s| s.shim == p || s.name == p));
    let (outcome, reply) = target.map_or_else(
        || (Outcome::Deny, Reply::Data(one(status::DENIED))),
        |socket| {
            match connect_granted_socket(std::path::Path::new(&socket.real)) {
                Ok(stream) => (Outcome::Allow, Reply::Fd(OwnedFd::from(stream))),
                Err(GrantedConnect::DaemonSocket) => {
                    (Outcome::Deny, Reply::Data(one(status::DENIED)))
                }
                // Granted but unreachable (absent / not a socket / refused / timed out): never
                // tie up the looper on a wedged target.
                Err(GrantedConnect::Unreachable) => {
                    (Outcome::Error, Reply::Data(one(status::NOT_FOUND)))
                }
            }
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
    // The conduit this verb mints is a TCP stream. A request for UDP that a `protocol = "udp"`
    // rule admits would be answered with a TCP connection to the same host and port: a
    // different service from the one the rule allows. UDP leaves through the tun path
    // (`[net.udp]`), never through here.
    if transport == crate::inet::allow::Transport::Udp {
        writer.emit(&inet_event(incoming, ctx, &label, port, Outcome::Deny));
        return Reply::Data(one(status::DENIED));
    }
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
    let handle = incoming.trailing_handle();
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
    // Without the death notification the daemon would go on pushing conduits to a node that is
    // gone. A registration that cannot be watched is not made.
    if conn.request_death(handle, u64::from(handle)).is_err() {
        let _ = conn.release_handle(handle);
        writer.emit(&inet_event(
            incoming,
            ctx,
            "mirror-register",
            port,
            Outcome::Error,
        ));
        return Reply::Data(one(status::UNAVAILABLE));
    }
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

/// Serve `REGISTER_TUN_SINK`: bind the standing tun-broker's sink node so kenneld can deliver egress
/// sessions to it (§8 / W2).
///
/// The [`register_mirror`] move for L3 egress: parse the translated handle from the trailing node
/// object, **acquire** it (so it survives this transaction's buffer free), request its **death
/// notification** under the [`crate::tun_sink::SINK_DEATH_COOKIE`] sentinel, and record `(this
/// manager's context manager, handle)` in the daemon-global [`crate::tun_sink::TunSink`]. The record
/// is daemon-global — not per-kennel — because the broker and its consumers run in different kennels
/// (different binder instances), so a consumer's deliver reaches the broker over *its* connection.
///
/// Any kennel can send this verb to its own node 0, so the handler authorises it: only a kennel
/// whose signed policy provides the tun capability ([`TunCtx::provider`], read by the daemon from
/// the settled policy it verified) may register. The reply is a status byte.
fn register_tun_sink(
    tun: &TunCtx<'_>,
    incoming: &Incoming,
    conn: &Connection,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    // The sink is daemon-global: whoever registers it receives every `[net.udp]` kennel's egress
    // session. Every kennel can send this verb to its own node 0, so the verb arriving proves
    // nothing — only a kennel whose signed policy provides the tun capability may register.
    if !tun.provider {
        writer.emit(&tun_event(
            incoming,
            ctx,
            "tun-sink-register",
            Outcome::Deny,
        ));
        return Reply::Data(one(status::DENIED));
    }

    // The node object the broker sent is the trailing flat_binder_object (the driver translated it to
    // a handle for us); REGISTER_TUN_SINK carries no data before it.
    let handle = incoming.trailing_handle();
    let Some(handle) = handle else {
        writer.emit(&tun_event(
            incoming,
            ctx,
            "tun-sink-register",
            Outcome::Error,
        ));
        return Reply::Data(one(status::BAD_REQUEST));
    };
    // Keep the handle past this transaction's buffer free, and learn when the broker dies — both ride
    // `conn` here, before the reply (and its BC_FREE_BUFFER) drops the transaction's temporary ref.
    if conn.acquire_handle(handle).is_err() {
        writer.emit(&tun_event(
            incoming,
            ctx,
            "tun-sink-register",
            Outcome::Error,
        ));
        return Reply::Data(one(status::BAD_REQUEST));
    }
    // Without the death notification a dead broker would stay registered, and every consumer
    // would be sent to it. A sink that cannot be watched is not recorded.
    if conn
        .request_death(handle, crate::tun_sink::SINK_DEATH_COOKIE)
        .is_err()
    {
        let _ = conn.release_handle(handle);
        writer.emit(&tun_event(
            incoming,
            ctx,
            "tun-sink-register",
            Outcome::Error,
        ));
        return Reply::Data(one(status::UNAVAILABLE));
    }
    tun.sink.set(Arc::clone(tun.cm), handle);
    writer.emit(&tun_event(
        incoming,
        ctx,
        "tun-sink-register",
        Outcome::Allow,
    ));
    Reply::Data(one(status::OK))
}

/// Socket-activate the enabled provider that offers `capability`, if it is a cold `ondemand` one
/// (§7.13.4a) — the generic af-unix activation trigger, shared across mesh capabilities rather than
/// reimplemented per provider.
///
/// Resolves the offering provider against the live catalogue and asks the [`ProviderActivator`] to
/// start it. Idempotent (a second consume does not double-start it — the activator dedups a live
/// supervision thread) and a no-op with no catalogue/activator (a test path), an unoffered name, or
/// a provider that is not `ondemand` (an `autorun` one is already supervised; an activate is a
/// harmless no-op there).
fn activate_for_capability(
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
    capability: &str,
) {
    let (Some(cat), Some(act)) = (catalogue, activator) else {
        return;
    };
    let provider = {
        let guard = cat
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .resolve(capability)
            .first()
            .map(|c| c.provider.to_owned())
    };
    if let Some(p) = provider {
        act.activate(&p);
    }
}

/// Serve a `[net.udp]` consumer's `CONNECT_AFUNIX` for the tun capability (§8 / W2): deliver its
/// pre-resolved grants + tun `/64` to the tun-broker's registered sink and hand back the broker's
/// minted per-session fd as the consumer's af-unix connection.
///
/// Activation is the generic af-unix mesh mechanism ([`activate_for_capability`]): the first
/// consumer's connect socket-activates a cold `ondemand` tun-broker, exactly as an `svc_connect`
/// consume activates a cold mesh provider. Only the *delivery* is role-specific — a per-session sink
/// mint, not a rendezvous connector handoff — so the consume-with-wait polls the sink becoming
/// **deliverable** (the tun delivery's own readiness, which the broker reaches on `REGISTER_TUN_SINK`
/// a beat after its construction seals) rather than the catalogue's construction-readiness, up to the
/// same broker deadline (§7.13.4a). The bounded wait is the dependency-cycle safety valve.
///
/// `session == None` means this kennel signed no `[net.udp]` grant → `DENIED`. A sink that never
/// becomes deliverable within the deadline → `UNAVAILABLE`, never a wedged looper. The deliver is a
/// synchronous cross-connection transact to the broker's connection; safe because the broker is a
/// different process, so this thread's outgoing transaction only draws its own reply back.
fn tun_connect(
    tun: &TunCtx<'_>,
    catalogue: Option<&Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<&Arc<dyn crate::supervisor::ProviderActivator>>,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    let Some(payload) = tun.session else {
        writer.emit(&tun_event(incoming, ctx, "tun-connect", Outcome::Deny));
        return Reply::Data(one(status::DENIED));
    };
    // What a settled delivery replies, audited. `None` means no broker answered: worth waiting.
    let settle = |delivery: Delivery| -> Option<Reply> {
        let (outcome, reply) = match delivery {
            Delivery::Session(fd) => (Outcome::Allow, Reply::Fd(fd)),
            Delivery::Refused => (Outcome::Deny, Reply::Data(one(status::UNAVAILABLE))),
            Delivery::NoBroker => return None,
        };
        writer.emit(&tun_event(incoming, ctx, "tun-connect", outcome));
        Some(reply)
    };
    // Fast path: a warm sink (the standing/already-activated broker) delivers now.
    if let Some(reply) = settle(tun_deliver(tun, payload)) {
        return reply;
    }
    // Cold: socket-activate the tun-broker generically, then consume-with-wait until its sink is
    // deliverable (the delivery's readiness) or the broker deadline fires.
    activate_for_capability(
        catalogue,
        activator,
        kennel_lib_binder::service::tun_broker::CAPABILITY,
    );
    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(CONSUME_WAIT_POLL);
        if let Some(reply) = settle(tun_deliver(tun, payload)) {
            return reply;
        }
        if start.elapsed() >= CONSUME_WAIT_DEADLINE {
            writer.emit(&tun_event(incoming, ctx, "tun-connect", Outcome::Error));
            return Reply::Data(one(status::UNAVAILABLE));
        }
    }
}

/// What one attempt to deliver a tun session came to.
enum Delivery {
    /// The broker minted a session and replied with the consumer end.
    Session(OwnedFd),
    /// The broker answered without a session (a kennel at its session ceiling, a payload it would
    /// not read). Asking again will not change the answer, so the consume is not retried.
    Refused,
    /// No broker is registered, or it did not answer: worth waiting for.
    NoBroker,
}

/// Deliver the session `payload` to the tun sink once, and say which of the three outcomes it was.
fn tun_deliver(tun: &TunCtx<'_>, payload: &[u8]) -> Delivery {
    match tun.sink.deliver(payload) {
        Ok(fd) => Delivery::Session(fd),
        // A reply that carries no descriptor is the broker's answer, not its absence.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Delivery::Refused,
        Err(_) => Delivery::NoBroker,
    }
}

/// The audit event for a tun-egress node-0 decision (sink registration / consumer connect).
fn tun_event(incoming: &Incoming, ctx: u16, op: &str, outcome: Outcome) -> Event {
    Event::new("binder.tun", Resource::Binder, outcome, Source::Kenneld)
        .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
        .field("op", Value::untrusted(op.to_owned()))
        .field("ctx", Value::Uint(u64::from(ctx)))
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

/// A one-byte status reply.
fn one(status: u8) -> Vec<u8> {
    vec![status]
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

    // ─── node-0 handlers, without a binder device ────────────────────────
    //
    // Each handler below takes the decoded transaction and returns the reply; none of these
    // needs the connection. They are what the root-only suite exercised until now.

    use kennel_lib_audit::{Levels, Record, Sink, SinkError, WriterContext};

    /// The `(event, outcome)` of every record a handler emitted.
    #[derive(Default, Clone)]
    struct Seen(Arc<Mutex<Vec<(&'static str, Outcome)>>>);
    impl Seen {
        fn all(&self) -> Vec<(&'static str, Outcome)> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }
    impl Sink for Seen {
        fn name(&self) -> &'static str {
            "seen"
        }
        fn write(&self, record: &Record) -> Result<(), SinkError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((record.event_type, record.outcome));
            Ok(())
        }
    }

    fn recording_writer() -> (Writer, Seen) {
        let seen = Seen::default();
        let ctx = WriterContext {
            kennel: "k".to_owned(),
            kennel_uuid: "u".to_owned(),
            host: "h".to_owned(),
        };
        let writer = Writer::new(ctx, Levels::default(), vec![Box::new(seen.clone())]);
        (writer, seen)
    }

    /// A transaction with `code` and `data` from the given sender.
    fn request(code: u32, data: &[u8], pid: i32, euid: u32) -> Incoming {
        Incoming {
            code,
            data: data.to_vec(),
            fds: Vec::new(),
            objects: Vec::new(),
            sender_pid: pid,
            sender_euid: euid,
            node_cookie: 0,
            buffer: 0,
            one_way: false,
        }
    }

    /// The status byte of a data reply, or `None` for a reply that carries a descriptor.
    fn status_of(reply: &Reply) -> Option<u8> {
        match reply {
            Reply::Data(bytes) => bytes.first().copied(),
            _ => None,
        }
    }

    fn unix_grant(name: &str, real: &std::path::Path) -> UnixRuntime {
        UnixRuntime {
            sockets: vec![kennel_lib_policy::UnixSocket {
                name: name.to_owned(),
                real: real.to_string_lossy().into_owned(),
                shim: format!("/tmp/{name}.sock"),
                env: None,
            }],
        }
    }

    #[test]
    fn afunix_connect_denies_a_name_the_policy_does_not_grant() {
        let (writer, seen) = recording_writer();
        let unix = unix_grant("granted", std::path::Path::new("/nonexistent/granted.sock"));
        let reply = af_unix_connect(
            &unix,
            &request(verb::CONNECT_AFUNIX, b"other", 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::DENIED));
        assert_eq!(seen.all(), [("binder.afunix-connect", Outcome::Deny)]);
        // An empty or undecodable name is denied the same way.
        let reply = af_unix_connect(
            &unix,
            &request(verb::CONNECT_AFUNIX, b"", 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::DENIED));
    }

    #[test]
    fn afunix_connect_hands_back_a_connection_to_the_granted_socket() {
        let dir = std::env::temp_dir().join(format!("kennel-node0-afunix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        let path = dir.join("host.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let (writer, seen) = recording_writer();
        // Granted by name, and equally by shim path.
        for asked in ["agent", "/tmp/agent.sock"] {
            let reply = af_unix_connect(
                &unix_grant("agent", &path),
                &request(verb::CONNECT_AFUNIX, asked.as_bytes(), 9, 1000),
                3,
                &writer,
            );
            assert!(
                matches!(reply, Reply::Fd(_)),
                "`{asked}` yields a descriptor"
            );
            listener.accept().expect("the host socket was connected");
        }
        assert_eq!(
            seen.all().last(),
            Some(&("binder.afunix-connect", Outcome::Allow))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn afunix_connect_reports_a_granted_but_absent_socket_as_not_found() {
        let (writer, seen) = recording_writer();
        let unix = unix_grant(
            "agent",
            std::path::Path::new("/nonexistent/kennel/agent.sock"),
        );
        let reply = af_unix_connect(
            &unix,
            &request(verb::CONNECT_AFUNIX, b"agent", 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::NOT_FOUND));
        assert_eq!(seen.all(), [("binder.afunix-connect", Outcome::Error)]);
    }

    #[test]
    fn afunix_connect_never_brokers_a_daemon_socket_even_if_granted() {
        // A signed settled policy that somehow carries the grant: the handler still refuses.
        let (writer, seen) = recording_writer();
        let daemon = kennel_lib_control::socket::runtime_dir().join("proxy/netproxy-cmd-3.sock");
        let reply = af_unix_connect(
            &unix_grant("cmd", &daemon),
            &request(verb::CONNECT_AFUNIX, b"cmd", 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::DENIED));
        assert_eq!(seen.all(), [("binder.afunix-connect", Outcome::Deny)]);
    }

    #[test]
    fn inet_connect_refuses_malformed_udp_and_ungranted_requests() {
        use kennel_lib_binder::service::{inet, transport};
        let (writer, seen) = recording_writer();
        let net = crate::inet::NetRuntime::denied();
        // Too short to carry a transport, a port and a host.
        let reply = inet_connect(
            &net,
            &request(verb::CONNECT_INET, &[0], 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::BAD_REQUEST));
        // UDP never leaves through this verb, whatever the rules say.
        let udp = inet::encode_request(transport::UDP, 53, "example.com");
        let reply = inet_connect(
            &net,
            &request(verb::CONNECT_INET, &udp, 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::DENIED));
        // A kennel with no network: every destination is denied.
        let tcp = inet::encode_request(transport::TCP, 443, "example.com");
        let reply = inet_connect(
            &net,
            &request(verb::CONNECT_INET, &tcp, 9, 1000),
            3,
            &writer,
        );
        assert_eq!(status_of(&reply), Some(status::DENIED));
        assert_eq!(
            seen.all(),
            [
                ("binder.inet-connect", Outcome::Error),
                ("binder.inet-connect", Outcome::Deny),
                ("binder.inet-connect", Outcome::Deny),
            ]
        );
    }

    #[test]
    fn lifecycle_verbs_are_served_to_init_alone() {
        let (writer, seen) = recording_writer();
        let lifecycle = Lifecycle {
            init_host_pid: Some(4242),
            supervision: b"plan-bytes".to_vec(),
            ..Lifecycle::default()
        };
        // The workload (operator uid, another pid) asks for the plan: denied, audited.
        let asked = request(lifecycle::GET_SANDBOX_PLAN, &[], 4300, 1000);
        let reply = lifecycle_handle(&lifecycle, None, None, &asked, 3, &writer);
        assert_eq!(status_of(&reply), Some(status::DENIED));
        // A process that is uid 0 in the kennel but is not init: denied.
        let asked = request(lifecycle::GET_SANDBOX_PLAN, &[], 4300, 0);
        let reply = lifecycle_handle(&lifecycle, None, None, &asked, 3, &writer);
        assert_eq!(status_of(&reply), Some(status::DENIED));
        // Init itself gets the supervision half, byte for byte.
        let asked = request(lifecycle::GET_SANDBOX_PLAN, &[], 4242, 0);
        let reply = lifecycle_handle(&lifecycle, None, None, &asked, 3, &writer);
        assert!(matches!(&reply, Reply::Data(bytes) if bytes == b"plan-bytes"));
        // A code in the lifecycle range that names no verb is a bad request, also for init.
        let asked = request(0x1ff, &[], 4242, 0);
        let reply = lifecycle_handle(&lifecycle, None, None, &asked, 3, &writer);
        assert_eq!(status_of(&reply), Some(status::BAD_REQUEST));
        assert_eq!(
            seen.all(),
            [
                ("binder.lifecycle-denied", Outcome::Deny),
                ("binder.lifecycle-denied", Outcome::Deny),
                ("binder.get-sandbox-plan", Outcome::Allow),
                ("binder.bad-request", Outcome::Error),
            ]
        );
    }

    #[test]
    fn svc_connect_denies_a_capability_the_policy_does_not_consume() {
        let (writer, seen) = recording_writer();
        let asked = request(verb::SVC_CONNECT, b"org.example.thing", 9, 1000);
        let reply = svc_connect(&[], None, None, &asked, 3, &writer, false);
        assert_eq!(status_of(&reply), Some(status::DENIED));
        assert_eq!(seen.all(), [("binder.svc-connect", Outcome::Deny)]);
    }

    #[test]
    fn spawn_verbs_are_denied_to_a_kennel_with_no_spawn_grant() {
        let (writer, seen) = recording_writer();
        let asked = request(verb::SPAWN, b"anything", 9, 1000);
        let reply = crate::spawn::handle_spawn(None, &asked, 3, &writer);
        assert_eq!(status_of(&reply), Some(status::DENIED));
        let asked = request(verb::SPAWN_QUERY, &[], 9, 1000);
        let reply = crate::spawn::handle_spawn_query(None, &asked, 3, &writer);
        assert_eq!(status_of(&reply), Some(status::DENIED));
        assert!(seen
            .all()
            .iter()
            .all(|(_, outcome)| *outcome == Outcome::Deny));
        assert_eq!(seen.all().len(), 2);
    }

    /// A TTL action that could not be applied must not be audited as applied.
    #[test]
    fn a_ttl_kill_or_thaw_that_fails_is_audited_as_an_error() {
        let missing = std::env::temp_dir().join(format!("kennel-ttl-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        for action in [
            kennel_lib_policy::TtlAction::Exit,
            kennel_lib_policy::TtlAction::Warn,
        ] {
            let lifecycle = Lifecycle {
                cgroup: missing.clone(),
                ttl_action: action,
                name: "k".to_owned(),
                ..Lifecycle::default()
            };
            let (name, outcome, _reply) = ttl_expired(&lifecycle, None, None);
            assert_eq!(outcome, Outcome::Error, "{name}");
        }
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

    /// A `ProviderActivator` that records the providers it was asked to start.
    #[derive(Default)]
    struct RecordingActivator {
        started: std::sync::Mutex<Vec<String>>,
    }
    impl crate::supervisor::ProviderActivator for RecordingActivator {
        fn activate(&self, provider: &str) {
            self.started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(provider.to_owned());
        }
        fn has_running_consumer(&self, _capabilities: &[String]) -> bool {
            false
        }
        fn mark_idle_reaped(&self, _provider: &str) {}
    }

    /// A one-provider catalogue offering `capability` (af-unix, ondemand).
    fn catalogue_offering(
        provider: &str,
        capability: &str,
    ) -> Arc<Mutex<crate::catalogue::Catalogue>> {
        use kennel_lib_policy::settled::{RestartPolicy, ServiceRuntime};
        let ep = crate::catalogue::EnabledProvider {
            provider: provider.to_owned(),
            signing_key_id: "k".to_owned(),
            tier: crate::catalogue::Tier::Host,
            enablement: crate::catalogue::Enablement::Ondemand,
            provides: vec![kennel_lib_policy::settled::ProvideRuntime {
                name: capability.to_owned(),
                shape: kennel_lib_policy::settled::Shape::AfUnix,
                endpoint: "/run/mesh/tun.sock".to_owned(),
                key: None,
            }],
            policy_path: std::path::PathBuf::new(),
            service: ServiceRuntime {
                restart: RestartPolicy::OnFailure,
                backoff_ms: 500,
                max_attempts: 5,
            },
        };
        Arc::new(Mutex::new(crate::catalogue::Catalogue::project(&[ep])))
    }

    #[test]
    fn activate_for_capability_starts_the_offering_provider_generically() {
        let cap = kennel_lib_binder::service::tun_broker::CAPABILITY;
        let cat = catalogue_offering("tun-broker", cap);
        let rec = Arc::new(RecordingActivator::default());
        let act: Arc<dyn crate::supervisor::ProviderActivator> = rec.clone();
        // The provider offering the capability is resolved from the catalogue and started.
        activate_for_capability(Some(&cat), Some(&act), cap);
        // An unoffered capability starts nothing.
        activate_for_capability(Some(&cat), Some(&act), "org.projectkennel.nope");
        // No activator / no catalogue is a clean no-op (a test/construction path).
        activate_for_capability(Some(&cat), None, cap);
        activate_for_capability(None, Some(&act), cap);

        let started = {
            let guard = rec
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.clone()
        };
        assert_eq!(
            started,
            ["tun-broker".to_owned()],
            "only the offering capability's provider is started, exactly once"
        );
    }

    #[test]
    fn decode_name_rejects_empty_oversized_and_non_utf8() {
        assert_eq!(decode_name(b""), None);
        assert_eq!(decode_name(&[0xff, 0xfe]), None);
        assert_eq!(decode_name(&[b'a'; 256]), None);
        assert_eq!(decode_name(b"svc"), Some("svc".to_owned()));
    }
}
