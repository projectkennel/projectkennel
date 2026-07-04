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
    unix: UnixRuntime,
    lifecycle: Lifecycle,
    net: crate::inet::NetRuntime,
    inbound: Arc<crate::inbound::InboundRuntime>,
    dbus: Option<Arc<DbusRelay>>,
    writer: Arc<Writer>,
    spawn: Option<Arc<crate::spawn::SpawnRuntime>>,
    consumes: Vec<kennel_lib_policy::ConsumeRuntime>,
    catalogue: Option<Arc<Mutex<crate::catalogue::Catalogue>>>,
    activator: Option<Arc<dyn crate::supervisor::ProviderActivator>>,
    tun_sink: crate::tun_sink::TunSink,
    tun_session: Option<Vec<u8>>,
) -> io::Result<Manager> {
    let cm = Arc::new(ContextManager::new(device_fd, MAP_SIZE)?);
    let stop = Arc::new(AtomicBool::new(false));

    // kenneld pushes DELIVER_INET (§7.5.7) on this same connection — a binder handle is valid only
    // on the open that received it — so the inbound runtime borrows the context manager. Attached
    // before the pool serves, so a REGISTER_MIRROR can never race an unattached pusher.
    inbound.attach_pusher(Arc::clone(&cm));

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
            session: tun_session.as_deref(),
            cm: &cm_for_handler,
        };
        handle(
            &unix,
            &net,
            &inbound,
            &lifecycle,
            dbus.as_deref(),
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
        if cookie == crate::tun_sink::SINK_DEATH_COOKIE {
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
    dbus: Option<&DbusRelay>,
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
        return svc_connect(consumes, catalogue, activator, incoming, ctx, writer, dbus);
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
                return tun_connect(tun, incoming, ctx, writer);
            }
            if consumes.iter().any(|c| c.name == name) {
                return svc_connect(consumes, catalogue, activator, incoming, ctx, writer, dbus);
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
    let _ = crate::cgroup::freeze_cgroup(&lifecycle.cgroup);
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
            let _ = crate::cgroup::thaw_cgroup(&lifecycle.cgroup);
            return (
                "binder.ttl-provider-keep",
                Outcome::Info,
                Reply::Data(one(ttl::RENEW)),
            );
        }
        // Mark the reap before the kill so the supervisor reads the resulting exit as a reap
        // (→ declared-but-pending, re-activatable), not a crash to restart. The activator is
        // `Some` here — `is_none_or` only falls through when it is present and reports no consumer.
        if let Some(a) = activator {
            a.mark_idle_reaped(&lifecycle.name);
        }
        let _ = crate::cgroup::kill_cgroup(&lifecycle.cgroup);
        return (
            "binder.ttl-provider-reap",
            Outcome::Allow,
            Reply::Data(one(ttl::TERMINATE)),
        );
    }
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
    dbus: Option<&DbusRelay>,
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
            return svc_connect_handoff(writer, incoming, ctx, name, &sel, dbus)
        }
        // A `Pending` provider is enabled but cold: socket-activate it and consume-with-wait until it
        // is declared-and-ready (broker the connector) or the deadline fires (§7.13.4a).
        Decision::Pending(sel) => {
            return svc_connect_activate_wait(
                consumes, catalogue, activator, incoming, ctx, name, writer, &sel, dbus,
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
    dbus: Option<&DbusRelay>,
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
                return svc_connect_handoff(writer, incoming, ctx, name, &ready, dbus)
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
    dbus: Option<&DbusRelay>,
) -> Reply {
    use kennel_lib_policy::settled::Shape;

    match sel.shape {
        Shape::AfUnix => {} // handled below
        Shape::DbusName => {
            // The dbus-name handoff (§7.7) is a pure *locator*: on the per-kennel bus kenneld only
            // tells the facade where the dbus mesh bus is, and the facade connects THERE. It makes
            // no session and resolves no identity here — the mesh bus's node-0 handler does that,
            // resolving the connecting facade afresh (sender_pid → cgroup → ctx → filter) and
            // minting the session. Brokered → `[OK][mesh-path]`; no broker → `[OK]` and the facade
            // takes the legacy host-dbus route via DBUS_* on this bus (unchanged behaviour).
            let reply = if dbus.is_some_and(DbusRelay::is_brokered) {
                let mut r = vec![status::OK];
                r.extend_from_slice(MESH_DBUS_DEVICE.as_bytes());
                r
            } else {
                vec![status::OK]
            };
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
    // the same inode bound into the provider's view (§7.13.4b). A plain connect, the §4.3 fd-broker.
    let path = crate::mesh::host_rp_socket(sel.tier, name, sel.key.as_deref(), &sel.endpoint);
    kennel_lib_syscall::net::connect_unix_timeout(&path, AFUNIX_CONNECT_DEADLINE).map_or_else(
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

fn af_unix_connect(unix: &UnixRuntime, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let requested = decode_name(&incoming.data);
    let target = requested
        .as_deref()
        .and_then(|p| unix.sockets.iter().find(|s| s.shim == p || s.name == p));
    let (outcome, reply) = target.map_or_else(
        || (Outcome::Deny, Reply::Data(one(status::DENIED))),
        |socket| {
            let real = std::path::Path::new(&socket.real);
            // Backstop the compiler's control-socket ungrantability rule at the daemon, against the
            // REAL endpoint (symlink-resolved): never broker a connect to the kenneld control socket,
            // even if a signed settled policy somehow carries the grant. The compiler refuses it at
            // install (the loud primary guard); this is the construction-time belt to those braces.
            let resolved = std::fs::canonicalize(real);
            if kennel_lib_control::socket::is_control_socket(real)
                || resolved
                    .as_deref()
                    .is_ok_and(kennel_lib_control::socket::is_control_socket)
            {
                (Outcome::Deny, Reply::Data(one(status::DENIED)))
            } else {
                kennel_lib_syscall::net::connect_unix_timeout(real, AFUNIX_CONNECT_DEADLINE)
                    .map_or_else(
                        // Granted but unreachable (absent / refused / timed out): never tie up the
                        // looper on a wedged target.
                        |_| (Outcome::Error, Reply::Data(one(status::NOT_FOUND))),
                        |stream| (Outcome::Allow, Reply::Fd(OwnedFd::from(stream))),
                    )
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
/// Only the tun-broker's own per-kennel bus ever carries this verb (a consumer never holds the sink
/// node), so reaching the handler is the authorization. The reply is a status byte.
fn register_tun_sink(
    tun: &TunCtx<'_>,
    incoming: &Incoming,
    conn: &Connection,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    use kennel_lib_binder::proto::{flat_binder_object_handle_value, FLAT_BINDER_OBJECT_SIZE};

    // The node object the broker sent is the trailing flat_binder_object (the driver translated it to
    // a handle for us); REGISTER_TUN_SINK carries no data before it.
    let handle = incoming
        .data
        .len()
        .checked_sub(FLAT_BINDER_OBJECT_SIZE)
        .and_then(|off| incoming.data.get(off..))
        .and_then(flat_binder_object_handle_value);
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
    let _ = conn.request_death(handle, crate::tun_sink::SINK_DEATH_COOKIE);
    tun.sink.set(Arc::clone(tun.cm), handle);
    writer.emit(&tun_event(
        incoming,
        ctx,
        "tun-sink-register",
        Outcome::Allow,
    ));
    Reply::Data(one(status::OK))
}

/// Serve a `[net.udp]` consumer's `CONNECT_AFUNIX` for the tun capability (§8 / W2): deliver its
/// pre-resolved grants + tun `/64` to the registered sink and hand back the broker's minted
/// per-session fd as the consumer's af-unix connection.
///
/// `session == None` means this kennel signed no `[net.udp]` grant (nothing to deliver, so it is not
/// really a tun consumer) → `DENIED`. A delivery failure — no broker registered yet, or an
/// unreachable/dead one — → `UNAVAILABLE`, never a wedged looper. The deliver is a synchronous
/// cross-connection transact to the broker's connection; safe because the broker is a different
/// process, so this thread's outgoing transaction only draws its own reply back.
fn tun_connect(tun: &TunCtx<'_>, incoming: &Incoming, ctx: u16, writer: &Writer) -> Reply {
    let Some(payload) = tun.session else {
        writer.emit(&tun_event(incoming, ctx, "tun-connect", Outcome::Deny));
        return Reply::Data(one(status::DENIED));
    };
    tun.sink.deliver(payload).map_or_else(
        |_| {
            writer.emit(&tun_event(incoming, ctx, "tun-connect", Outcome::Error));
            Reply::Data(one(status::UNAVAILABLE))
        },
        |fd| {
            writer.emit(&tun_event(incoming, ctx, "tun-connect", Outcome::Allow));
            Reply::Fd(fd)
        },
    )
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
