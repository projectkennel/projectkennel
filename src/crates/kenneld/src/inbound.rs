//! The inbound BIND runtime: kenneld as the fd router for the §7.5.7 host-side mirror.
//!
//! The reverse of [`crate::inet`]'s egress dial. The `[net.bpf].bind` cgroup ACL already decided —
//! at the workload's `bind()` — which ports the kennel may listen on, so there is **no
//! per-connection policy decision here**: kenneld eagerly registers each policy-mirrored port with
//! the `host-inetd` delegate, which binds it on the host loopback, accepts, splices each connection
//! locally, and pushes back the conduit's *kennel* end.
//!
//! **Push, not poll (§7.5.7).** `facade-client` registers a binder callback node per mirrored port
//! ([`verb::REGISTER_MIRROR`]) and then sleeps in a server loop. On each `host-inetd` accept, the
//! reader thread ([`run_reader`]) pushes the conduit to that node with a one-way
//! [`verb::DELIVER_INET`] transaction ([`Connection::transact_oneway_fd`]) — no looper is ever
//! parked and an idle mirror costs nothing. The three guards (§7.5.7): the registration is
//! **port-gated** ([`InboundRuntime::register`] checks the policy mirror set); delivery is
//! **one-way** with the per-port queue as a **bounce buffer** for the brief window before a node
//! registers or when its binder buffer is momentarily full; and kenneld watches each node's
//! **death** ([`InboundRuntime::drop_dead`]) so it never transacts to a stale handle.
//!
//! [`verb::REGISTER_MIRROR`]: kennel_lib_binder::service::verb::REGISTER_MIRROR
//! [`verb::DELIVER_INET`]: kennel_lib_binder::service::verb::DELIVER_INET

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};
use kennel_lib_binder::client::Connection;
use kennel_lib_binder::ctxmgr::ContextManager;
use kennel_lib_binder::service::{inet, transport, verb};

/// The per-kennel inbound mirror runtime.
///
/// Holds the `port → callback-node handle` map, the bounce-buffer queues, the set of
/// policy-mirrored ports (the registration gate), and the binder connection kenneld pushes on.
///
/// Shared `Arc<InboundRuntime>` across the binder loopers (which register nodes and handle deaths)
/// and the `host-inetd` reader threads (which push conduits), like [`crate::inet::NetRuntime`].
#[derive(Default)]
pub struct InboundRuntime {
    /// Registered callback nodes: mirrored port → the (acquired) binder handle to push to.
    mirrors: Mutex<HashMap<u16, u32>>,
    /// Conduits that arrived before their port's node registered, or while its binder buffer was
    /// full — the §7.5.7 bounce buffer, drained on the next register/push, never the primary path.
    bounce: Mutex<HashMap<u16, VecDeque<OwnedFd>>>,
    /// The ports the policy mirrors — the registration gate (guard 3). A `REGISTER_MIRROR` for a
    /// port not in this set is refused. Empty ⇒ no inbound mirror (every registration refused).
    allowed: Mutex<HashSet<u16>>,
    /// The context manager whose connection kenneld pushes `DELIVER_INET` on. Set once, right after
    /// [`crate::binder::spawn`] takes node 0 — a binder handle is valid only on the open that
    /// received it, so pushes ride the same connection the loopers serve.
    pusher: OnceLock<Arc<ContextManager>>,
    /// Where each inbound connection is recorded, with the kennel's ctx. Set with the pusher.
    audit: OnceLock<(Arc<Writer>, u16)>,
}

/// What became of one inbound connection, as its audit record says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arrival {
    /// Pushed to the facade's node.
    Delivered,
    /// Held in the bounce buffer: no facade has registered, or its node would not take it.
    Held,
    /// Closed: the bounce buffer for the port is full.
    Dropped,
}

impl std::fmt::Debug for InboundRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pusher (a ContextManager wrapping a binder connection) is not Debug; report the
        // observable counts instead.
        f.debug_struct("InboundRuntime")
            .field("mirrors", &self.mirrors.lock().map_or(0, |m| m.len()))
            .field("bounce", &self.bounce.lock().map_or(0, |b| b.len()))
            .field("allowed", &self.allowed.lock().map_or(0, |a| a.len()))
            .field("pusher_attached", &self.pusher.get().is_some())
            .field("audit_attached", &self.audit.get().is_some())
            .finish()
    }
}

/// The most conduits held per port while no facade can take them.
const MAX_BOUNCED: usize = 64;

impl InboundRuntime {
    /// An empty runtime (no mirrored ports). The default for a kennel with no inbound mirror.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the policy-mirrored ports — the registration gate. Called at bring-up, before any
    /// facade can register. A `REGISTER_MIRROR` for a port outside this set is refused.
    pub fn allow_ports(&self, ports: impl IntoIterator<Item = u16>) {
        let mut allowed = self
            .allowed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        allowed.extend(ports);
    }

    /// Attach the context manager kenneld pushes on (idempotent; the first wins). Called once after
    /// [`crate::binder::spawn`] creates node 0.
    pub fn attach_pusher(&self, cm: Arc<ContextManager>) {
        let _ = self.pusher.set(cm);
    }

    /// Attach the audit writer inbound connections are recorded through, and the kennel's ctx
    /// (idempotent; the first wins).
    pub fn attach_audit(&self, writer: Arc<Writer>, ctx: u16) {
        let _ = self.audit.set((writer, ctx));
    }

    /// Whether `port` is in the policy mirror set (the registration gate).
    #[must_use]
    pub fn is_allowed(&self, port: u16) -> bool {
        self.allowed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&port)
    }

    /// Register a facade's callback `handle` for `port` and drain any bounced conduits to it.
    ///
    /// The caller (the `REGISTER_MIRROR` handler) has already gated the port, acquired the handle,
    /// and requested its death notification on `conn`. This stores `port → handle`, gives back the
    /// reference a replaced registration held, and pushes anything the bounce buffer holds for
    /// that port (the common case is empty — a facade registers before any connection arrives).
    pub fn register(&self, conn: &Connection, port: u16, handle: u32) {
        if let Some(replaced) = self.remember(port, handle) {
            // Each registration acquired its handle once. Without this a process that registers
            // the same port over and over leaves one reference (and its death notification) in
            // the daemon per call. The driver counts references per handle, so this is right
            // whether the new registration reuses the handle or not.
            let _ = conn.release_handle(replaced);
        }
        self.drain(conn, port, handle);
    }

    /// Record `port → handle`; returns the handle a previous registration of `port` held.
    fn remember(&self, port: u16, handle: u32) -> Option<u32> {
        self.mirrors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(port, handle)
    }

    /// Push the bounce buffer for `port` to `handle`, oldest first. Pops one at a time (lock
    /// briefly) and pushes without the lock held; a conduit the node will not take goes back to
    /// the front and the drain stops (the node is wedged or dying).
    fn drain(&self, conn: &Connection, port: u16, handle: u32) {
        while let Some(fd) = self.pop_bounce(port) {
            if push_conduit(conn, handle, port, fd.as_fd()).is_err() {
                self.unpop_bounce(port, fd);
                break;
            }
        }
    }

    /// Deliver one conduit `fd` for `port` (the `host-inetd` reader thread, per accept).
    ///
    /// The conduit joins the back of the port's bounce buffer and the buffer is then pushed to the
    /// registered node, so connections reach the facade in the order they arrived and one that was
    /// held earlier does not wait for a new registration. With no node or no pusher yet it stays
    /// held. Every arrival is audited.
    pub fn deliver(&self, port: u16, fd: OwnedFd) {
        let handle = self
            .mirrors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&port)
            .copied();
        let arrival = if !self.bounce(port, fd) {
            Arrival::Dropped
        } else if let (Some(handle), Some(cm)) = (handle, self.pusher.get()) {
            self.drain(cm.connection(), port, handle);
            if self.bounced(port) == 0 {
                Arrival::Delivered
            } else {
                Arrival::Held
            }
        } else {
            Arrival::Held
        };
        self.record(port, arrival);
    }

    /// Audit one inbound connection. The mirror makes no decision about a connection (the bind
    /// ACL decided the port), so a delivered or held one is `info`; one closed at the cap is a
    /// `deny`.
    fn record(&self, port: u16, arrival: Arrival) {
        let Some((writer, ctx)) = self.audit.get() else {
            return;
        };
        let (outcome, state) = match arrival {
            Arrival::Delivered => (Outcome::Info, "delivered"),
            Arrival::Held => (Outcome::Info, "held"),
            Arrival::Dropped => (Outcome::Deny, "dropped"),
        };
        writer.emit(
            &Event::new(
                "net.inbound-connect",
                Resource::Net,
                outcome,
                Source::Kenneld,
            )
            .field("port", Value::Uint(u64::from(port)))
            .field("state", Value::str(state))
            .field("ctx", Value::Uint(u64::from(*ctx))),
        );
    }

    /// Drop a callback node that died (`BR_DEAD_BINDER`), keyed by the cookie kenneld registered
    /// (the handle value). Removes every port that mapped to it and releases the handle + acks the
    /// notification on `conn`. Bounced conduits for those ports stay queued for a re-registration.
    pub fn drop_dead(&self, conn: &Connection, cookie: u64) {
        if let Ok(handle) = u32::try_from(cookie) {
            if self.forget_handle(handle) {
                let _ = conn.release_handle(handle);
            }
        }
        let _ = conn.dead_binder_done(cookie);
    }

    /// Remove every port mapping to `handle`; returns whether any were removed. The map-pruning
    /// half of [`Self::drop_dead`], split out so it is testable without a binder device.
    fn forget_handle(&self, handle: u32) -> bool {
        let mut mirrors = self
            .mirrors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = mirrors.len();
        mirrors.retain(|_port, h| *h != handle);
        mirrors.len() != before
    }

    /// Push a conduit into the per-port bounce buffer, up to [`MAX_BOUNCED`] per port. Returns
    /// whether it was taken.
    ///
    /// The buffer holds connections that arrived before a facade registered (or while its node is
    /// wedged). Each entry is an open descriptor in the daemon, and a host-local peer decides how
    /// many arrive, so the queue is bounded: past the cap the new conduit is closed, which the
    /// connecting peer sees as a closed connection — what it would get with nothing listening.
    fn bounce(&self, port: u16, fd: OwnedFd) -> bool {
        let mut bounce = self
            .bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let queue = bounce.entry(port).or_default();
        let refused = if queue.len() < MAX_BOUNCED {
            queue.push_back(fd);
            None
        } else {
            Some(fd)
        };
        drop(bounce);
        // Close a refused conduit outside the lock.
        refused.is_none()
    }

    /// Pop one conduit from the per-port bounce buffer, if any.
    fn pop_bounce(&self, port: u16) -> Option<OwnedFd> {
        self.bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&port)
            .and_then(VecDeque::pop_front)
    }

    /// Put back a conduit [`Self::pop_bounce`] took, at the front, keeping arrival order.
    fn unpop_bounce(&self, port: u16, fd: OwnedFd) {
        self.bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(port)
            .or_default()
            .push_front(fd);
    }

    /// How many conduits the bounce buffer holds for `port`.
    fn bounced(&self, port: u16) -> usize {
        self.bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&port)
            .map_or(0, VecDeque::len)
    }
}

/// Push one conduit `fd` to `handle` as a one-way [`verb::DELIVER_INET`] carrying the port.
fn push_conduit(
    conn: &Connection,
    handle: u32,
    port: u16,
    fd: std::os::fd::BorrowedFd<'_>,
) -> io::Result<()> {
    let payload = inet::encode_bind_request(transport::TCP, port);
    conn.transact_oneway_fd(handle, verb::DELIVER_INET, &payload, fd)
}

/// Register a mirror port with the `host-inetd` delegate: bind `addr:port` on the host loopback.
///
/// Mirrors [`crate::inet::dial_via_delegate`] in reverse — instead of handing the delegate a
/// conduit to dial, this hands it a bind registration and **keeps the connection open**, because
/// `host-inetd` pushes each accepted connection's conduit back on the *same* socket. The returned
/// [`UnixStream`] is the registration connection the reader thread then services.
///
/// Unlike the egress dial (driven lazily, long after the delegate is up), kenneld registers mirror
/// ports *eagerly* right after spawning `host-inetd`, so the connect can race the delegate's
/// `bind(2)` of its command socket. A short bounded retry closes that startup window; past it the
/// delegate is presumed dead and the error propagates.
///
/// # Errors
///
/// The OS error if the delegate's socket never appears within the retry budget, or the registration
/// send fails.
pub fn bind_via_delegate(command_socket: &Path, addr: IpAddr, port: u16) -> io::Result<UnixStream> {
    // ~1s total: the delegate binds its socket within a few ms of spawn; this just covers that
    // startup window. The final attempt's error propagates if the socket never appears.
    const ATTEMPTS: u32 = 100;
    const RETRY: std::time::Duration = std::time::Duration::from_millis(10);
    let mut last_err = io::Error::other("delegate socket never appeared");
    let mut conn = None;
    for _ in 0..ATTEMPTS {
        match UnixStream::connect(command_socket) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                last_err = e;
                std::thread::sleep(RETRY);
            }
        }
    }
    let conn = conn.ok_or(last_err)?;
    let payload = kennel_host_delegate::inetd::listen::encode_bind(addr, port);
    kennel_lib_syscall::scm::send_with_fds(conn.as_fd(), &payload, &[])?;
    Ok(conn)
}

/// Service one `host-inetd` registration connection: receive each `{port, conduit kennel-end}`
/// notification and push the conduit to the port's registered mirror node (or bounce it).
///
/// Runs on its own thread, off the binder looper pool — this is where the unbounded wait for an
/// external connection lives. Returns when `host-inetd` closes the connection (the delegate died
/// or the kennel is tearing down).
pub fn run_reader(runtime: &InboundRuntime, conn: &UnixStream) {
    let why = read_notifications(runtime, conn);
    // The port has no mirror from here on. Say so: the alternative is a listener that silently
    // stopped delivering.
    eprintln!("kenneld: inbound mirror reader ended: {why}");
}

/// The reader loop; returns why it ended.
fn read_notifications(runtime: &InboundRuntime, conn: &UnixStream) -> String {
    let mut buf = [0u8; 8];
    loop {
        let (n, mut fds) = match kennel_lib_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf) {
            Ok(received) => received,
            // A signal is not the end of the mirror.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return format!("receive failed: {e}"),
        };
        let Some(fd) = fds.pop() else {
            return if n == 0 {
                "host-inetd closed the connection".to_owned()
            } else {
                "a notification carried no conduit".to_owned()
            };
        };
        if !fds.is_empty() {
            return "a notification carried more than one descriptor".to_owned();
        }
        let Some(port) = decode_notify(buf.get(..n).unwrap_or_default()) else {
            return "a notification was not a port".to_owned();
        };
        runtime.deliver(port, fd);
    }
}

/// Decode the `host-inetd` notification framing `[port: u16 big-endian]` (the inverse of
/// `kennel_host_delegate::inetd::listen::encode_notify`).
fn decode_notify(data: &[u8]) -> Option<u16> {
    let [hi, lo] = data else { return None };
    Some(u16::from_be_bytes([*hi, *lo]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_ports_gates_registration() {
        let rt = InboundRuntime::new();
        assert!(!rt.is_allowed(3000), "nothing allowed by default");
        rt.allow_ports([3000, 8080]);
        assert!(rt.is_allowed(3000));
        assert!(rt.is_allowed(8080));
        assert!(!rt.is_allowed(9999), "a port outside the set stays gated");
    }

    #[test]
    fn deliver_bounces_when_no_node_registered() {
        // With no registered node and no attached pusher, a delivered conduit is bounced (not
        // lost); pop_bounce then yields it exactly once.
        let rt = InboundRuntime::new();
        let (_host, kennel) = UnixStream::pair().expect("pair");
        rt.deliver(3000, kennel.into());
        assert!(rt.pop_bounce(3000).is_some(), "bounced, not dropped");
        assert!(rt.pop_bounce(3000).is_none(), "exactly one");
    }

    #[test]
    fn the_bounce_buffer_is_bounded_per_port() {
        // A peer that connects before any facade registers cannot make the daemon hold an
        // unbounded number of descriptors: past the cap a conduit is closed, not queued.
        let rt = InboundRuntime::new();
        for _ in 0..MAX_BOUNCED.saturating_add(8) {
            let (_host, kennel) = UnixStream::pair().expect("pair");
            rt.deliver(3000, kennel.into());
        }
        let mut held = 0_usize;
        while rt.pop_bounce(3000).is_some() {
            held = held.saturating_add(1);
        }
        assert_eq!(held, MAX_BOUNCED);
    }

    #[test]
    fn a_new_registration_reports_the_handle_it_replaced() {
        // The handler releases what `remember` returns; a registration that replaced nothing
        // must release nothing.
        let rt = InboundRuntime::new();
        assert_eq!(rt.remember(3000, 7), None);
        assert_eq!(
            rt.remember(3000, 9),
            Some(7),
            "the replaced handle is given back"
        );
        assert_eq!(
            rt.remember(3000, 9),
            Some(9),
            "also when the same node registers again"
        );
        assert_eq!(rt.remember(8080, 9), None, "another port replaced nothing");
    }

    #[test]
    fn a_conduit_put_back_keeps_its_place_at_the_front() {
        use std::os::fd::AsRawFd as _;
        let rt = InboundRuntime::new();
        let (_a_host, a) = UnixStream::pair().expect("pair");
        let (_b_host, b) = UnixStream::pair().expect("pair");
        let (a_raw, b_raw) = (a.as_raw_fd(), b.as_raw_fd());
        assert!(rt.bounce(3000, a.into()));
        assert!(rt.bounce(3000, b.into()));
        let first = rt.pop_bounce(3000).expect("first");
        assert_eq!(first.as_raw_fd(), a_raw);
        rt.unpop_bounce(3000, first);
        assert_eq!(rt.bounced(3000), 2);
        assert_eq!(rt.pop_bounce(3000).expect("a").as_raw_fd(), a_raw);
        assert_eq!(rt.pop_bounce(3000).expect("b").as_raw_fd(), b_raw);
    }

    #[test]
    fn forget_handle_prunes_only_that_handles_ports() {
        let rt = InboundRuntime::new();
        {
            let mut m = rt.mirrors.lock().expect("lock");
            m.insert(3000, 7);
            m.insert(8080, 7);
            m.insert(9090, 9);
        }
        assert!(rt.forget_handle(7), "handle 7 mapped two ports → removed");
        let (has_3000, has_8080, h9090) = {
            let m = rt.mirrors.lock().expect("lock");
            (
                m.contains_key(&3000),
                m.contains_key(&8080),
                m.get(&9090).copied(),
            )
        };
        assert!(!has_3000, "3000 (handle 7) gone");
        assert!(!has_8080, "8080 (handle 7) gone");
        assert_eq!(h9090, Some(9), "9090 (handle 9) untouched");
        assert!(!rt.forget_handle(7), "second forget removes nothing");
    }

    #[test]
    fn notify_framing_round_trips() {
        let bytes = kennel_host_delegate::inetd::listen::encode_notify(3000);
        assert_eq!(decode_notify(&bytes), Some(3000));
        assert!(decode_notify(&[0x0B]).is_none()); // short
        assert!(decode_notify(&[0x0B, 0xB8, 0x00]).is_none()); // long
    }

    #[test]
    fn reader_bounces_pushed_conduits_then_stops_on_close() {
        let rt = InboundRuntime::new();
        let (kenneld_side, delegate_side) = UnixStream::pair().expect("pair");
        // The "delegate" pushes one notification {port 3000, a conduit end}, then closes. With no
        // registered node, the reader bounces it.
        let (_conduit_host, conduit_kennel) = UnixStream::pair().expect("conduit pair");
        kennel_lib_syscall::scm::send_with_fds(
            delegate_side.as_fd(),
            &kennel_host_delegate::inetd::listen::encode_notify(3000),
            &[conduit_kennel.as_fd()],
        )
        .expect("push notification");
        drop(conduit_kennel);
        drop(delegate_side); // close → run_reader returns after draining
        run_reader(&rt, &kenneld_side);
        assert!(
            rt.pop_bounce(3000).is_some(),
            "the pushed conduit was bounced"
        );
        assert!(rt.pop_bounce(3000).is_none(), "exactly one");
    }
}
