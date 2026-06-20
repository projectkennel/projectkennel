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
            .finish()
    }
}

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
    /// and requested its death notification on `conn`. This stores `port → handle` and immediately
    /// pushes anything the bounce buffer holds for that port (the common case is empty — a facade
    /// registers before any connection arrives).
    pub fn register(&self, conn: &Connection, port: u16, handle: u32) {
        {
            let mut mirrors = self
                .mirrors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            mirrors.insert(port, handle);
        }
        // Drain the bounce buffer for this port. Pop one at a time (lock briefly), push without the
        // lock held; on a push failure re-bounce it and stop (the node is wedged or dying).
        while let Some(fd) = self.pop_bounce(port) {
            if push_conduit(conn, handle, port, fd.as_fd()).is_err() {
                self.bounce(port, fd);
                break;
            }
        }
    }

    /// Deliver one conduit `fd` for `port` (the `host-inetd` reader thread, per accept).
    ///
    /// Pushes it to the registered node if one exists and the connection is attached; otherwise (no
    /// node yet, no pusher yet, or a push failure) it lands in the bounce buffer for the next
    /// register/push to drain.
    pub fn deliver(&self, port: u16, fd: OwnedFd) {
        let handle = self
            .mirrors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&port)
            .copied();
        if let (Some(handle), Some(cm)) = (handle, self.pusher.get()) {
            if push_conduit(cm.connection(), handle, port, fd.as_fd()).is_ok() {
                return;
            }
        }
        self.bounce(port, fd);
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

    /// Push a conduit into the per-port bounce buffer.
    fn bounce(&self, port: u16, fd: OwnedFd) {
        self.bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(port)
            .or_default()
            .push_back(fd);
    }

    /// Pop one conduit from the per-port bounce buffer, if any.
    fn pop_bounce(&self, port: u16) -> Option<OwnedFd> {
        self.bounce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&port)
            .and_then(VecDeque::pop_front)
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
    let mut buf = [0u8; 8];
    loop {
        let Ok((n, mut fds)) = kennel_lib_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf)
        else {
            return; // delegate gone
        };
        let Some(fd) = fds.pop() else {
            return; // a notification without a conduit fd is malformed; stop
        };
        if !fds.is_empty() {
            return; // exactly one fd per notification
        }
        let Some(port) = decode_notify(buf.get(..n).unwrap_or_default()) else {
            return;
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
