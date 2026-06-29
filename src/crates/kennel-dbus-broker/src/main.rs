//! `dbus-broker@v1`: the standing D-Bus mediation service kennel (§7.7).
//!
//! A long-running service — the replacement for the per-consumer `host-dbus` delegate —
//! that mediates D-Bus for consumer kennels over the connector mesh bus. It runs inside
//! its own kennel, not on the host, and decides nothing: kenneld is the only authority.
//!
//! **Control plane (kenneld → broker):** kenneld owns node 0 of the mesh bus and reaches
//! the broker's **control node** (the cookie it registered via `ADD_SERVICE`). When a
//! consumer asks to connect, kenneld resolves the consumer's identity and filter *in its
//! own namespace* and sends one `ACCEPT_SESSION(bus, filter)` to the control node. The
//! broker mints a fresh **per-session node**, stores the filter against that node's cookie,
//! and replies with the node — which kenneld forwards to the consumer. The broker honors the
//! control verb only on its control node, which consumers are never handed; the auth is
//! structural, not a check on anything the consumer says.
//!
//! **Data plane (consumer → broker, kenneld absent):** the consumer transacts its session
//! node directly with `DBUS_SEND`/`DBUS_RECV`/`DBUS_CLOSE`. The broker keys the session by
//! the kernel-attested **target node cookie** (never by the sender — a confined broker
//! cannot resolve sibling-namespace pids) and mediates each frame through the reused
//! `host-dbus::mediate` engine against the real bus. When the consumer's kennel exits, its
//! last reference to the session node drops, the broker is told via `Br::Release`, and the
//! session is reclaimed — no teardown verb.
//!
//! ```text
//! kenneld(node 0) ──ACCEPT_SESSION──▶ broker control node ──mints──▶ session node
//!        │                                                               ▲
//!        └──forwards session node──▶ consumer ──DBUS_SEND/RECV──────────┘──▶ real bus
//! ```

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::dbus::{frame_len, Bus};
use kennel_lib_binder::service::{broker, dbus as dbus_svc, status, verb};
use kennel_lib_dbus::filter::{BusRules, Filter};

/// The mesh binder device path — the `[[provides]]` endpoint, bind-mounted by `kenneld`.
const MESH_DEVICE: &str = "/dev/binderfs-mesh/binder";

/// The control service registered on the mesh bus via `ADD_SERVICE`. kenneld reaches this
/// node to push `ACCEPT_SESSION`; consumers are never handed it.
const SERVICE_NAME: &str = "org.projectkennel.dbus-broker";

/// The mmap size for the broker's binder connection. Sized for D-Bus frames in transit.
const MAP_SIZE: usize = 1024 * 1024;

/// Poll timeout for the binder serve loop (milliseconds).
const POLL_MS: i32 = 5000;

/// The control node's local pointer and cookie. Session cookies start above it, so the
/// control node is distinguishable from every session node by `Incoming::node_cookie`.
const CONTROL_NODE_PTR: u64 = 1;
const CONTROL_NODE_COOKIE: u64 = 1;
const FIRST_SESSION_COOKIE: u64 = 2;

/// Inbound frames a session has mediated from the bus (replies and allowlisted signals),
/// queued for the consumer's next `DBUS_RECV`.
#[derive(Default)]
struct Inbound {
    queue: Mutex<VecDeque<Vec<u8>>>,
}

/// One active D-Bus session: the mediation running over a socketpair, keyed by node cookie.
struct Session {
    /// The broker's end of the conduit to the mediation; consumer frames are written here.
    to_mediate: UnixStream,
    /// Mediated inbound frames, drained from the conduit by this session's reader thread.
    inbound: Arc<Inbound>,
}

/// The broker's in-memory state: the live sessions, keyed by their node cookie.
struct Broker {
    sessions: HashMap<u64, Session>,
    next_cookie: u64,
    session_bus_addr: String,
    system_bus_addr: String,
}

impl Broker {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_cookie: FIRST_SESSION_COOKIE,
            session_bus_addr: std::env::var("DBUS_SESSION_BUS_ADDRESS")
                .unwrap_or_else(|_| "unix:path=/run/user/dbus/bus".to_owned()),
            system_bus_addr: std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
                .unwrap_or_else(|_| "unix:path=/run/dbus/system_bus_socket".to_owned()),
        }
    }

    /// Dispatch one incoming transaction, replying through `conn`. Control verbs are honored
    /// only on the control node; everything else addresses a session node.
    fn handle(&mut self, conn: &Connection, incoming: &Incoming) {
        if incoming.node_cookie == CONTROL_NODE_COOKIE {
            self.handle_control(conn, incoming);
        } else {
            self.handle_session(conn, incoming);
        }
    }

    /// The control node: kenneld pushes `ACCEPT_SESSION` here. Consumers never hold this
    /// node, so reaching it is itself the authorization.
    fn handle_control(&mut self, conn: &Connection, incoming: &Incoming) {
        if incoming.code == broker::ACCEPT_SESSION {
            self.accept_session(conn, incoming);
        } else {
            let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
        }
    }

    /// Mint a per-session node for a session kenneld has authorized, start its mediation
    /// against the real bus with the supplied filter, and reply with the node so kenneld can
    /// forward it to the consumer.
    fn accept_session(&mut self, conn: &Connection, incoming: &Incoming) {
        let Some(acc) = broker::decode_accept(&incoming.data) else {
            let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
            return;
        };
        let (bus, bus_addr) = if acc.bus == dbus_svc::SESSION {
            (Bus::Session, self.session_bus_addr.clone())
        } else {
            (Bus::System, self.system_bus_addr.clone())
        };
        let rules = BusRules {
            talk: acc.talk,
            call: acc.call,
            broadcast: acc.broadcast,
            own: acc.own,
            deny_talk: acc.deny_talk,
        };
        let filter = if acc.bus == dbus_svc::SESSION {
            Filter {
                session: Some(rules),
                system: None,
            }
        } else {
            Filter {
                session: None,
                system: Some(rules),
            }
        };

        // Bridge the consumer's frames to a reused `host-dbus::mediate` over a socketpair:
        // the broker keeps one end (and a clone for the inbound reader); the mediation owns
        // the other and drives the real bus.
        let Ok((broker_end, mediate_end)) = UnixStream::pair() else {
            let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
            return;
        };
        let Ok(reader_end) = broker_end.try_clone() else {
            let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
            return;
        };

        std::thread::spawn(move || {
            let _ = kennel_host_dbus::mediate(mediate_end, bus, &bus_addr, filter);
        });
        let inbound = Arc::new(Inbound::default());
        let inbound_reader = Arc::clone(&inbound);
        std::thread::spawn(move || drain_inbound(reader_end, &inbound_reader));

        let cookie = self.next_cookie;
        self.next_cookie = self.next_cookie.saturating_add(1);
        self.sessions.insert(
            cookie,
            Session {
                to_mediate: broker_end,
                inbound,
            },
        );

        // Hand kenneld the freshly-minted session node (ptr == cookie); it forwards the
        // handle to the consumer, which then transacts the session directly.
        if conn.reply_with_node(incoming, cookie, cookie, 0).is_err() {
            self.sessions.remove(&cookie); // mint failed → tear the half-built session down
        }
    }

    /// A session node: the consumer's data-plane verbs, keyed by the target node cookie.
    fn handle_session(&mut self, conn: &Connection, incoming: &Incoming) {
        let cookie = incoming.node_cookie;
        match incoming.code {
            verb::DBUS_SEND => {
                let wrote = self
                    .sessions
                    .get_mut(&cookie)
                    .map(|s| s.to_mediate.write_all(&incoming.data).is_ok());
                let reply = match wrote {
                    Some(true) => vec![status::OK],
                    Some(false) => {
                        // The mediation is gone — drop the session and report it closed.
                        self.sessions.remove(&cookie);
                        vec![status::NOT_FOUND]
                    }
                    None => vec![status::NOT_FOUND],
                };
                let _ = conn.reply_and_free(incoming, &reply);
            }
            verb::DBUS_RECV => {
                let reply = self.sessions.get(&cookie).map_or_else(
                    || vec![status::NOT_FOUND],
                    |s| {
                        let mut q = s
                            .inbound
                            .queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        q.pop_front().map_or_else(
                            || vec![status::AGAIN],
                            |frame| {
                                let mut out = Vec::with_capacity(frame.len().saturating_add(1));
                                out.push(status::OK);
                                out.extend_from_slice(&frame);
                                out
                            },
                        )
                    },
                );
                let _ = conn.reply_and_free(incoming, &reply);
            }
            verb::DBUS_CLOSE => {
                self.sessions.remove(&cookie); // drop closes the conduit → mediation exits
                let _ = conn.reply_and_free(incoming, &[status::OK]);
            }
            _ => {
                let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
            }
        }
    }

    /// Reclaim a session whose node lost its last external reference (`Br::Release`) — the
    /// consumer's kennel exited. Dropping the [`Session`] closes the conduit, ending the
    /// mediation and its reader thread.
    fn release(&mut self, cookie: u64) {
        if self.sessions.remove(&cookie).is_some() {
            eprintln!("dbus-broker: session {cookie} released");
        }
    }
}

/// Drain whole `[u32 len][frame]` conduit units the mediation produces, queueing each for
/// the consumer's `DBUS_RECV`. Returns on EOF (the conduit closed → session over).
fn drain_inbound(mut conduit: UnixStream, inbound: &Inbound) {
    loop {
        let mut len_buf = [0u8; 4];
        if conduit.read_exact(&mut len_buf).is_err() {
            return;
        }
        let Ok(Some(len)) = frame_len(&len_buf) else {
            return; // malformed / over-long prefix — end this session's reader
        };
        let mut body = vec![0u8; len];
        if conduit.read_exact(&mut body).is_err() {
            return;
        }
        let mut unit = Vec::with_capacity(len.saturating_add(4));
        unit.extend_from_slice(&len_buf);
        unit.extend_from_slice(&body);
        inbound
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(unit);
    }
}

fn run() -> std::io::Result<()> {
    eprintln!("dbus-broker: starting");

    let device_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(MESH_DEVICE)?;
    let conn = Connection::open(device_fd.into(), MAP_SIZE)?;

    // Register the control node on node 0 of the mesh bus. Its cookie distinguishes it
    // from every session node the broker later mints.
    let name_bytes = kennel_lib_binder::service::mesh::encode_add_service(SERVICE_NAME);
    conn.transact_node(
        0,
        kennel_lib_binder::service::verb::ADD_SERVICE,
        &name_bytes,
        CONTROL_NODE_PTR,
        CONTROL_NODE_COOKIE,
        0,
    )?;
    eprintln!("dbus-broker: registered control service `{SERVICE_NAME}` on mesh bus");

    conn.enter_looper()?;
    let mut state = Broker::new();
    loop {
        if !conn.poll(POLL_MS)? {
            continue;
        }
        let batch = conn.recv_batch()?;
        for cookie in batch.released {
            state.release(cookie);
        }
        for incoming in batch.transactions {
            state.handle(&conn, &incoming);
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dbus-broker: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
