//! The mesh bus: a shared binderfs instance for `binder-connector` capabilities (§7.13.4a).
//!
//! The binder analogue of the `af-unix` rendezvous directory ([`super::mesh`]):
//! `kenneld` owns one binderfs instance per `binder-connector` capability, serving as
//! context manager (node 0) on that bus. Providers register via `ADD_SERVICE` (their
//! node arrives as a `BINDER_TYPE_HANDLE`); consumers resolve via `SVC_CONNECT` and
//! receive the provider's handle. After handoff, provider and consumer transact
//! directly — `kenneld` is out of the data path.
//!
//! Created lazily (D4: at first consumes/provides match) and ref-counted for teardown.
//! The teardown lifecycle unmounts bind-mounts from reaped kennels, the mesh binderfs
//! itself when the last participant disconnects, and all remaining instances at `kenneld`
//! shutdown.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::ctxmgr::{ContextManager, DeathHandler, Handler, Reply, Waker};
use kennel_lib_binder::service::{broker, mesh, status, verb};

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};

use crate::catalogue::Tier;

/// The mmap size for mesh bus context managers. The mesh carries only mediation
/// transactions (`ADD_SERVICE` / `SVC_CONNECT`) — small payloads — so 64 KiB suffices.
const MESH_MAP_SIZE: usize = 64 * 1024;
/// The dbus-broker's control-node service name on the mesh bus (where kenneld pushes
/// `ACCEPT_SESSION`). Consumers never resolve this — only kenneld holds it.
const DBUS_BROKER_SERVICE: &str = "org.projectkennel.dbus-broker";

/// Maximum looper threads for a mesh bus. The D-Bus `SVC_CONNECT` blocks on an `ACCEPT_SESSION`
/// round-trip to the broker (a separate kennel), so the pool must hold ≥2 threads: one parked on
/// that transaction while another serves the next consumer.
const MESH_POOL_MAX: u32 = 4;

/// Resolve a mesh `SVC_CONNECT` to the per-session `ACCEPT_SESSION` filter for the caller.
///
/// Given the kernel-attested `sender_pid` and the requested capability `name`, returns the encoded
/// [`broker::encode_accept`] payload (the kennel's one D-Bus filter for the requested bus) when the
/// name is a D-Bus capability and the pid resolves to a kennel with that bus enabled; `None`
/// otherwise. kenneld owns this: the mesh handler stays out of identity logic and never trusts the
/// caller. Resolved fresh per connect (`sender_pid` → cgroup → ctx → policy) — nothing remembered.
pub type DbusResolver = Arc<dyn Fn(i32, &str) -> Option<Vec<u8>> + Send + Sync>;

/// Poll timeout (ms) for the mesh bus looper.
const MESH_POLL_MS: i32 = 500;

/// One live mesh bus: a binderfs instance `kenneld` owns as node 0, serving the
/// `ADD_SERVICE` / `SVC_CONNECT` mediation for one `binder-connector` capability.
///
/// The binderfs is mounted by an **unprivileged fork-holder** (in its own kenneld-owned user
/// namespace — [`crate::mesh_holder`]). kenneld serves node 0 by opening the device via the holder's
/// `/proc/<pid>/root`; to place the device in a kennel view it asks the holder (over the control
/// socket) for an `open_tree(CLONE)` of the binderfs and relays that detached mount fd into the
/// kennel, where `kennel-bin-init` `move_mount`s it. The holder lives as long as the bus — teardown
/// `SIGKILL`s it, and the binderfs goes with its mount namespace.
pub struct MeshBus {
    /// The host pid of the mount holder (a child of kenneld via the subreaper). `SIGKILL`'d and
    /// reaped on teardown.
    holder_pid: i32,
    /// The control socket to the holder: a one-byte write requests an `open_tree(CLONE)`; the reply
    /// carries the detached mount fd (or zero fds on a clone failure). One clone at a time.
    holder_sock: Mutex<std::os::fd::OwnedFd>,
    /// Stop flag for the serve loop.
    stop: Arc<AtomicBool>,
    /// Wake signal for the serve loop.
    waker: Waker,
    /// The looper thread(s) — joined on teardown.
    loopers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// The registered provider handles, keyed by service name. Shared with the handler.
    handles: Arc<Mutex<HashMap<String, u32>>>,
    /// Number of live participants (bind-mounts) — when this drops to zero, the bus is unmounted.
    refcount: usize,
}

impl MeshBus {
    /// Create and serve a new mesh bus for a `binder-connector` capability.
    ///
    /// Mounts a binderfs at `<runtime>/mesh/<tier>/<component>/`, allocates the binder
    /// device, opens it, becomes context manager (node 0), and starts the serve loop.
    ///
    /// `dbus_resolver` is `Some` only for the D-Bus connector bus: it maps a consumer's
    /// `SVC_CONNECT` to the per-session `ACCEPT_SESSION` filter (see [`DbusResolver`]). Every
    /// other connector bus passes `None` and resolves consumers to their provider's handle.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the binderfs mount, device allocation, device open,
    /// or context-manager claim fails.
    /// `holder_pid`/`holder_sock` are the unprivileged fork-holder the caller obtained from
    /// [`crate::mesh_holder::spawn`]; the binderfs lives in its mount namespace, reached via
    /// `/proc/<holder_pid>/root` for kenneld's own node-0 open (its nodes owned by kenneld's uid),
    /// and cloned on request over `holder_sock` for placement in kennel views.
    pub fn create(
        tier: Tier,
        name: &str,
        key: Option<&str>,
        writer: &Arc<Writer>,
        dbus_resolver: Option<DbusResolver>,
        holder_pid: i32,
        holder_sock: std::os::fd::OwnedFd,
    ) -> io::Result<Self> {
        let mount_dir = super::mesh::host_rp_dir(tier, name, key);
        // The binderfs lives in the holder's mount namespace; reach it via `/proc/<pid>/root` (the
        // holder's userns is kenneld-owned, so this resolves for kenneld) to serve node 0 here.
        let device_dir = PathBuf::from(format!("/proc/{holder_pid}/root"))
            .join(mount_dir.strip_prefix("/").unwrap_or(&mount_dir));
        let device_fd = kennel_lib_binder::binderfs::open_binder_device(&device_dir)?;

        // Become node 0 on this bus.
        let cm = Arc::new(ContextManager::new(device_fd, MESH_MAP_SIZE)?);
        let stop = Arc::new(AtomicBool::new(false));

        // The shared handle map: providers register → handle stored; consumers resolve → handle delivered.
        let handle_map: Arc<Mutex<HashMap<String, u32>>> = Arc::new(Mutex::new(HashMap::new()));

        let handles_for_handler = Arc::clone(&handle_map);
        let writer_for_handler = Arc::clone(writer);

        let handler: Handler = Arc::new(move |incoming: &Incoming, conn: &Connection| {
            mesh_handle(
                &handles_for_handler,
                dbus_resolver.as_ref(),
                incoming,
                conn,
                &writer_for_handler,
            )
        });

        let handles_for_death = Arc::clone(&handle_map);
        let writer_for_death = Arc::clone(writer);

        let death: DeathHandler = Arc::new(move |cookie: u64, _conn: &Connection| {
            // A provider's node died. The cookie is the handle we stored.
            let Ok(handle) = u32::try_from(cookie) else {
                return; // not a handle we ever stored
            };
            let mut map = handles_for_death
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            map.retain(|name, &mut h| {
                if h == handle {
                    writer_for_death.emit(
                        &Event::new(
                            "mesh.provider-death",
                            Resource::Binder,
                            Outcome::Info,
                            Source::Kenneld,
                        )
                        .field("service", Value::untrusted(name.clone())),
                    );
                    false
                } else {
                    true
                }
            });
        });

        let waker = cm.waker();
        let loopers = cm.serve_pool(MESH_POOL_MAX, MESH_POLL_MS, &stop, &handler, &death)?;

        Ok(Self {
            holder_pid,
            holder_sock: Mutex::new(holder_sock),
            stop,
            waker,
            loopers,
            handles: handle_map,
            refcount: 0,
        })
    }

    /// Request a fresh `open_tree(CLONE)` of the binderfs from the holder — a detached, movable mount
    /// fd to relay into a kennel (where `kennel-bin-init` `move_mount`s it into the view).
    ///
    /// One clone at a time (the control socket is serialized). The reply is one data byte plus the
    /// mount fd; a zero-fd reply means the holder's clone failed.
    ///
    /// # Errors
    ///
    /// The OS error if the request/reply fails, or other-kind if the holder returned no fd.
    pub fn clone_mount_fd(&self) -> io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsFd as _;
        let mut fds = {
            let sock = self
                .holder_sock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            kennel_lib_syscall::scm::send_with_fds(sock.as_fd(), &[1u8], &[])?;
            let mut buf = [0u8; 1];
            let (_, fds) = kennel_lib_syscall::scm::recv_with_fds(sock.as_fd(), &mut buf)?;
            fds
        };
        fds.pop()
            .ok_or_else(|| io::Error::other("mesh holder returned no mount fd"))
    }

    /// Increment the participant count (a kennel bind-mounted the device).
    pub const fn add_participant(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the participant count (a kennel's bind-mount was unmounted by the reaper).
    ///
    /// Returns `true` if the refcount reached zero (the bus should be unmounted).
    #[must_use]
    pub const fn remove_participant(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }

    /// Whether a provider has registered a service with the given name on this bus.
    pub fn has_service(&self, name: &str) -> bool {
        self.handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(name)
    }

    /// Stop the serve loop and tear the binderfs down by ending its holder.
    ///
    /// Called when the last participant disconnects or at `kenneld` shutdown.
    pub fn teardown(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.waker.wake();
        // Join the looper threads.
        if let Ok(mut threads) = self.loopers.lock() {
            for t in threads.drain(..) {
                let _ = t.join();
            }
        }
        // End the holder: SIGKILL drops its mount namespace, and the binderfs with it. Then reap it
        // (it reparented to kenneld, a subreaper, when the one-shot privhelper exited).
        let _ = kennel_lib_syscall::process::kill_pid(self.holder_pid);
        let _ = kennel_lib_syscall::process::wait_pid(self.holder_pid);
    }
}

impl Drop for MeshBus {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// The mesh bus node-0 handler: `ADD_SERVICE` (provider registration) and `SVC_CONNECT`
/// (consumer resolution).
fn mesh_handle(
    handles: &Mutex<HashMap<String, u32>>,
    dbus_resolver: Option<&DbusResolver>,
    incoming: &Incoming,
    conn: &Connection,
    writer: &Writer,
) -> Reply {
    match incoming.code {
        verb::ADD_SERVICE => mesh_add_service(handles, incoming, conn, writer),
        verb::SVC_CONNECT => mesh_svc_connect(handles, dbus_resolver, incoming, conn, writer),
        _ => {
            writer.emit(
                &Event::new(
                    "mesh.bad-request",
                    Resource::Binder,
                    Outcome::Error,
                    Source::Kenneld,
                )
                .pid(u32::try_from(incoming.sender_pid).unwrap_or(0)),
            );
            Reply::Data(vec![status::BAD_REQUEST])
        }
    }
}

/// Handle `ADD_SERVICE` on the mesh bus: extract the service name and the provider's
/// node handle, acquire the handle so it outlives the transaction, watch for death,
/// and store it. The `REGISTER_MIRROR` pattern (§7.5.7) — same acquire/death dance.
fn mesh_add_service(
    handles: &Mutex<HashMap<String, u32>>,
    incoming: &Incoming,
    conn: &Connection,
    writer: &Writer,
) -> Reply {
    let Some((name, handle)) = mesh::decode_add_service(&incoming.data) else {
        writer.emit(
            &Event::new(
                "mesh.add-service",
                Resource::Binder,
                Outcome::Error,
                Source::Kenneld,
            )
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("reason", Value::untrusted("malformed request")),
        );
        return Reply::Data(vec![status::BAD_REQUEST]);
    };

    // Acquire the handle before the reply frees the transaction buffer.
    if conn.acquire_handle(handle).is_err() {
        writer.emit(
            &Event::new(
                "mesh.add-service",
                Resource::Binder,
                Outcome::Error,
                Source::Kenneld,
            )
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("service", Value::untrusted(name))
            .field("reason", Value::untrusted("acquire_handle failed")),
        );
        return Reply::Data(vec![status::BAD_REQUEST]);
    }
    // Watch for death — the cookie is the handle itself.
    let _ = conn.request_death(handle, u64::from(handle));

    // Store the handle.
    {
        let mut map = handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.insert(name.to_owned(), handle);
    }

    writer.emit(
        &Event::new(
            "mesh.add-service",
            Resource::Binder,
            Outcome::Allow,
            Source::Kenneld,
        )
        .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
        .field("service", Value::untrusted(name))
        .field("handle", Value::Uint(u64::from(handle))),
    );
    Reply::Data(vec![status::OK])
}

/// Handle `SVC_CONNECT` on the mesh bus: look up the provider's handle and reply
/// with a `BINDER_TYPE_HANDLE` object. The kernel translates it from `kenneld`'s
/// handle table into the consumer's — valid because they share the same binder context.
///
/// On the D-Bus connector bus (`dbus_resolver` is `Some`), a consumer's `SVC_CONNECT` is resolved
/// *fresh*: kenneld reads the kernel-attested `sender_pid`, maps it (cgroup → ctx → policy) to the
/// kennel's one D-Bus filter, pushes `ACCEPT_SESSION(filter)` to the broker's control node, and
/// hands the consumer the per-session node the broker mints. No table, no cookie — identity is the
/// kernel's attestation on this transaction, never anything the consumer said.
fn mesh_svc_connect(
    handles: &Mutex<HashMap<String, u32>>,
    dbus_resolver: Option<&DbusResolver>,
    incoming: &Incoming,
    conn: &Connection,
    writer: &Writer,
) -> Reply {
    use kennel_lib_binder::service::svc_connect;

    let Some(name) = svc_connect::decode_request(&incoming.data) else {
        writer.emit(
            &Event::new(
                "mesh.svc-connect",
                Resource::Binder,
                Outcome::Error,
                Source::Kenneld,
            )
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("reason", Value::untrusted("malformed request")),
        );
        return Reply::Data(vec![status::BAD_REQUEST]);
    };

    // D-Bus connector bus: resolve identity fresh and mint a filtered session via the broker.
    if let Some(resolver) = dbus_resolver {
        if let Some(filter) = resolver(incoming.sender_pid, name) {
            return mesh_accept_dbus_session(handles, conn, incoming, name, &filter, writer);
        }
        // A D-Bus capability the caller could not be authorized for (not under a kennel cgroup, or
        // no filter for the requested bus) falls through to the provider map, which has no entry
        // named for a consumer capability — so it resolves to NOT_FOUND below.
    }

    let handle = handles
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(name)
        .copied();

    handle.map_or_else(
        || {
            writer.emit(
                &Event::new(
                    "mesh.svc-connect",
                    Resource::Binder,
                    Outcome::Deny,
                    Source::Kenneld,
                )
                .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
                .field("service", Value::untrusted(name)),
            );
            Reply::Data(vec![status::NOT_FOUND])
        },
        |h| {
            writer.emit(
                &Event::new(
                    "mesh.svc-connect",
                    Resource::Binder,
                    Outcome::Allow,
                    Source::Kenneld,
                )
                .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
                .field("service", Value::untrusted(name))
                .field("handle", Value::Uint(u64::from(h))),
            );
            Reply::Handle(h)
        },
    )
}

/// Push `ACCEPT_SESSION(filter)` to the broker's control node and hand the consumer the
/// per-session node it mints. `filter` is the already-encoded payload kenneld resolved for this
/// caller; the broker keys the session by that node (never the consumer's word) and reclaims it on
/// `Br::Release`. kenneld is out of the byte path once the handle is delivered.
///
/// The `ACCEPT_SESSION` is a nested transaction on `conn` — the same context-manager connection
/// serving this `SVC_CONNECT`. It must be: the broker's control handle was acquired on this
/// connection's binder proc ([`mesh_add_service`]), and the session handle the broker returns is
/// likewise valid only in this proc's table — the very table [`Reply::Handle`] hands the consumer.
/// A separate client connection would see neither handle.
fn mesh_accept_dbus_session(
    handles: &Mutex<HashMap<String, u32>>,
    conn: &Connection,
    incoming: &Incoming,
    name: &str,
    filter: &[u8],
    writer: &Writer,
) -> Reply {
    let control = handles
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(DBUS_BROKER_SERVICE)
        .copied();
    let emit = |outcome: Outcome, reason: &str| {
        writer.emit(
            &Event::new(
                "mesh.dbus-session",
                Resource::Binder,
                outcome,
                Source::Kenneld,
            )
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("capability", Value::untrusted(name.to_owned()))
            .field("detail", Value::untrusted(reason.to_owned())),
        );
    };
    let Some(control) = control else {
        emit(Outcome::Error, "dbus-broker control node not registered");
        return Reply::Data(vec![status::UNAVAILABLE]);
    };
    match conn.transact_handle(control, broker::ACCEPT_SESSION, filter) {
        Ok(session) => {
            emit(Outcome::Allow, "session accepted");
            // `transact_handle` took a ref on the session node so it would not dangle; forward it,
            // then release our ref (HandleOnce) so the broker reclaims the session when the consumer
            // disconnects — kenneld is not a persistent holder of per-session nodes.
            Reply::HandleOnce(session)
        }
        Err(e) => {
            emit(Outcome::Error, &format!("ACCEPT_SESSION failed: {e}"));
            Reply::Data(vec![status::UNAVAILABLE])
        }
    }
}
