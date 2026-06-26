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
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::ctxmgr::{ContextManager, DeathHandler, Handler, Reply, Waker};
use kennel_lib_binder::service::{mesh, status, verb};

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};

use crate::catalogue::Tier;

/// The mmap size for mesh bus context managers. The mesh carries only mediation
/// transactions (`ADD_SERVICE` / `SVC_CONNECT`) — small payloads — so 64 KiB suffices.
const MESH_MAP_SIZE: usize = 64 * 1024;

/// Maximum looper threads for a mesh bus. One is enough: the mesh verbs are O(1)
/// in-memory (no blocking facade dials), so a single looper handles all requests.
const MESH_POOL_MAX: u32 = 1;

/// Poll timeout (ms) for the mesh bus looper.
const MESH_POLL_MS: i32 = 500;

/// One live mesh bus: a binderfs instance `kenneld` owns as node 0, serving the
/// `ADD_SERVICE` / `SVC_CONNECT` mediation for one `binder-connector` capability.
pub struct MeshBus {
    /// The host directory the binderfs is mounted at.
    mount_dir: PathBuf,
    /// The host path of the binder device (the file consumers/providers bind-mount into views).
    device_path: PathBuf,
    /// Stop flag for the serve loop.
    stop: Arc<AtomicBool>,
    /// Wake signal for the serve loop.
    waker: Waker,
    /// The looper thread(s) — joined on teardown.
    loopers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// The registered provider handles, keyed by service name. Shared with the handler.
    handles: Arc<Mutex<HashMap<String, u32>>>,
    /// A binder client connection for kenneld to transact on registered service handles
    /// (e.g. `REGISTER_CONSUMER` to the `dbus-broker`). Distinct from the context-manager
    /// connection that serves node-0 requests.
    client: Connection,
    /// Number of live participants (bind-mounts) — when this drops to zero, the bus is unmounted.
    refcount: usize,
}

impl MeshBus {
    /// Create and serve a new mesh bus for a `binder-connector` capability.
    ///
    /// Mounts a binderfs at `<runtime>/mesh/<tier>/<component>/`, allocates the binder
    /// device, opens it, becomes context manager (node 0), and starts the serve loop.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the binderfs mount, device allocation, device open,
    /// or context-manager claim fails.
    pub fn create(
        tier: Tier,
        name: &str,
        key: Option<&str>,
        writer: &Arc<Writer>,
    ) -> io::Result<Self> {
        let mount_dir = super::mesh::host_rp_dir(tier, name, key);
        let device_path = mount_dir.join(kennel_lib_binder::binderfs::BINDER_DEVICE);

        // Mount the binderfs instance, allocate and open the device.
        kennel_lib_binder::binderfs::mount_instance(&mount_dir, 1)?;
        kennel_lib_binder::binderfs::add_binder_device(&mount_dir)?;
        let device_fd = kennel_lib_binder::binderfs::open_binder_device(&mount_dir)?;

        // Become node 0 on this bus.
        let cm = Arc::new(ContextManager::new(device_fd, MESH_MAP_SIZE)?);
        let stop = Arc::new(AtomicBool::new(false));

        // Open a second connection as a binder **client** on this bus. kenneld uses this to
        // transact on registered service handles (e.g. REGISTER_CONSUMER to the dbus-broker).
        // This is distinct from the context-manager connection (which serves node-0 requests).
        let client_fd = kennel_lib_binder::binderfs::open_binder_device(&mount_dir)?;
        let client = Connection::open(client_fd, MESH_MAP_SIZE)?;

        // The shared handle map: providers register → handle stored; consumers resolve → handle delivered.
        let handle_map: Arc<Mutex<HashMap<String, u32>>> = Arc::new(Mutex::new(HashMap::new()));

        let handles_for_handler = Arc::clone(&handle_map);
        let writer_for_handler = Arc::clone(writer);

        let handler: Handler = Arc::new(move |incoming: &Incoming, conn: &Connection| {
            mesh_handle(&handles_for_handler, incoming, conn, &writer_for_handler)
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
            mount_dir,
            device_path,
            stop,
            waker,
            loopers,
            handles: handle_map,
            client,
            refcount: 0,
        })
    }

    /// The host path of the binder device — bind-mount this into a kennel's view.
    #[must_use]
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// The host directory the binderfs is mounted at.
    #[must_use]
    pub fn mount_dir(&self) -> &Path {
        &self.mount_dir
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

    /// Look up the handle for a registered service. `None` if not registered.
    pub fn get_handle(&self, name: &str) -> Option<u32> {
        self.handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .copied()
    }

    /// Transact on a registered service's handle using the client connection.
    ///
    /// `kenneld` uses this to push control transactions (e.g. `REGISTER_CONSUMER`) to a
    /// service kennel's node on the mesh bus. Returns the reply data.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the service is not registered, or the OS error if the
    /// binder transaction fails.
    pub fn transact_service(
        &self,
        service_name: &str,
        code: u32,
        data: &[u8],
    ) -> io::Result<Vec<u8>> {
        let handle = self.get_handle(service_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("service `{service_name}` not registered on mesh bus"),
            )
        })?;
        self.client.transact(handle, code, data)
    }

    /// Stop the serve loop and unmount the binderfs instance.
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
        // Unmount the binderfs instance.
        let _ = kennel_lib_syscall::mount::unmount_detach(&self.mount_dir);
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
    incoming: &Incoming,
    conn: &Connection,
    writer: &Writer,
) -> Reply {
    match incoming.code {
        verb::ADD_SERVICE => mesh_add_service(handles, incoming, conn, writer),
        verb::SVC_CONNECT => mesh_svc_connect(handles, incoming, writer),
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
fn mesh_svc_connect(
    handles: &Mutex<HashMap<String, u32>>,
    incoming: &Incoming,
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
