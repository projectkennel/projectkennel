//! The D-Bus mediation membrane (§7.7.2a): kenneld's minimal-work relay between the in-kennel
//! facade (binder node 0) and the operator-context `host-dbus` delegate (an owner-only pipe).
//!
//! kenneld is the membrane, not a filter and not a parser. Per message it authenticates the
//! sender (only the real facade may inject D-Bus traffic — the pid is kernel-attested), applies
//! the token-bucket rate cap (§7.7.2c), and shovels the opaque frame bytes to/from the bus's
//! delegate by connection id. It never decodes the TLV (so `mini-sansio-dbus` never enters the
//! daemon TCB) and never applies the allowlist (the delegate's mechanical job).
//!
//! # Denial-of-service isolation (the facade is untrusted)
//!
//! `conn_id` is an arbitrary number the in-kennel facade chooses, not a kernel-backed fd, so it
//! is not constrained by the cgroup. kenneld must therefore bound every piece of state the facade
//! can grow and must never let the facade stall a binder thread:
//!
//! - **Connection count** is capped ([`MAX_CONNS`]); a new id beyond it is refused.
//! - **Inbound queues** are byte-budgeted ([`MAX_QUEUE_BYTES`]); a facade that never drains via
//!   `DBUS_RECV` cannot grow kenneld — excess inbound is dropped.
//! - **Outbound to the delegate** rides a *bounded* channel drained by a dedicated writer thread,
//!   so a slow delegate fills the channel (handlers shed, non-blocking) rather than blocking a
//!   binder looper or holding the relay lock. The blocking `write(2)` lives only on that thread.
//! - **Rate** — `OPEN`/`SEND`/`CLOSE` each spend a token; `RECV` is bounded structurally (one
//!   parked recv per connection, so parked binder threads ≤ `MAX_CONNS`).

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use kennel_lib_binder::dbus::{Bus, Record};
use kennel_lib_binder::ratelimit::RateLimiter;
use kennel_lib_binder::service::{dbus as wire, status};

/// The most workload bus connections a single kennel may have open at once. A kennel realistically
/// has one (its workload) per bus; this is a generous ceiling that bounds the connection map.
pub const MAX_CONNS: usize = 64;

/// The most inbound bytes kenneld will buffer for one connection awaiting `DBUS_RECV`. A facade
/// that stops draining cannot grow kenneld past this; excess inbound frames are dropped.
pub const MAX_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// The depth of a bus's outbound channel to its delegate. A slow delegate fills it and handlers
/// shed (non-blocking); it bounds the in-flight outbound frames per bus.
const OUTBOUND_DEPTH: usize = 32;

/// The per-kennel D-Bus relay state.
///
/// Constructed once (with a bounded sender to each enabled bus's delegate, see
/// [`spawn_pipe_writer`]) and shared by the node-0 handlers; pipe reader threads feed its inbound
/// queues via [`DbusRelay::deliver_inbound`].
pub struct DbusRelay {
    /// The kernel-attested pid of the spawned `facade-dbus`; only it may transact these verbs.
    facade_pid: i32,
    /// Monotonic base for the rate limiter's clock.
    start: Instant,
    /// The bounded outbound channel to each enabled bus's delegate. Immutable after construction
    /// (so no lock needed to relay); `try_send` is non-blocking.
    senders: HashMap<Bus, SyncSender<Vec<u8>>>,
    inner: Mutex<Inner>,
    inbound: Condvar,
}

struct Inner {
    /// Per-connection state, keyed by the facade-allocated connection id.
    conns: HashMap<u32, ConnState>,
    /// The membrane rate cap, shared across all of this kennel's connections.
    limiter: RateLimiter,
}

struct ConnState {
    bus: Bus,
    /// Inbound frames (encoded TLV, `[len][payload]`) awaiting a `DBUS_RECV`.
    queue: VecDeque<Vec<u8>>,
    /// Total bytes currently in `queue` (the byte budget, [`MAX_QUEUE_BYTES`]).
    queued_bytes: usize,
    /// Whether a `DBUS_RECV` is already parked on this connection (bounds parked binder threads).
    recv_parked: bool,
    closed: bool,
}

impl ConnState {
    const fn new(bus: Bus) -> Self {
        Self {
            bus,
            queue: VecDeque::new(),
            queued_bytes: 0,
            recv_parked: false,
            closed: false,
        }
    }
}

/// Spawn a writer thread draining a bounded channel to `pipe`, returning the channel's sender.
///
/// The blocking `write(2)` to the delegate lives only on this dedicated thread — never on a binder
/// looper or under the relay lock (the isolation in audit point 3). A slow delegate fills the
/// channel and the relay handlers shed; a dead delegate ends the thread and disconnects the sender.
#[must_use]
pub fn spawn_pipe_writer(mut pipe: UnixStream) -> SyncSender<Vec<u8>> {
    let (tx, rx) = sync_channel::<Vec<u8>>(OUTBOUND_DEPTH);
    std::thread::spawn(move || {
        while let Ok(bytes) = rx.recv() {
            if pipe.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    tx
}

impl DbusRelay {
    /// A relay for `facade_pid`, given a bounded sender to each enabled bus's delegate.
    #[must_use]
    pub fn new(
        facade_pid: i32,
        senders: HashMap<Bus, SyncSender<Vec<u8>>>,
        limiter: RateLimiter,
    ) -> Self {
        Self {
            facade_pid,
            start: Instant::now(),
            senders,
            inner: Mutex::new(Inner {
                conns: HashMap::new(),
                limiter,
            }),
            inbound: Condvar::new(),
        }
    }

    /// Handle `DBUS_OPEN` `[conn_id | bus]`: register the connection and tell the delegate.
    #[must_use]
    pub fn open(&self, sender_pid: i32, data: &[u8]) -> Vec<u8> {
        if sender_pid != self.facade_pid {
            return vec![status::DENIED];
        }
        let Some((conn_id, bus_byte)) = wire::decode_open(data) else {
            return vec![status::BAD_REQUEST];
        };
        let Some(bus) = bus_from_byte(bus_byte) else {
            return vec![status::BAD_REQUEST];
        };
        if !self.senders.contains_key(&bus) {
            return vec![status::DENIED]; // the bus is not enabled by policy
        }
        {
            let mut inner = self.lock();
            if !inner.limiter.allow(self.now_ms()) {
                return vec![status::AGAIN]; // rate cap (audit 4)
            }
            // Connection cap (audit 1): refuse a *new* id once the table is full; re-opening an
            // existing id is idempotent and always allowed.
            if !inner.conns.contains_key(&conn_id) && inner.conns.len() >= MAX_CONNS {
                return vec![status::DENIED];
            }
            inner.conns.entry(conn_id).or_insert_with(|| ConnState::new(bus));
        }
        // Tell the delegate (no lock held — the write rides the bounded channel). Roll the
        // registration back if a stalled delegate sheds it, so no half-open connection lingers.
        if self.try_relay(bus, &Record::Open { conn_id, bus }) {
            vec![status::OK]
        } else {
            self.lock().conns.remove(&conn_id);
            vec![status::AGAIN]
        }
    }

    /// Handle `DBUS_SEND` `[conn_id | frame]`: rate-limit, relay the frame, ack immediately.
    #[must_use]
    pub fn send(&self, sender_pid: i32, data: &[u8]) -> Vec<u8> {
        if sender_pid != self.facade_pid {
            return vec![status::DENIED];
        }
        let Some((conn_id, frame)) = wire::decode_send(data) else {
            return vec![status::BAD_REQUEST];
        };
        let bus = {
            let mut inner = self.lock();
            if !inner.limiter.allow(self.now_ms()) {
                return vec![status::AGAIN]; // rate cap (audit 4)
            }
            match inner.conns.get(&conn_id).map(|c| c.bus) {
                Some(bus) => bus,
                None => return vec![status::BAD_REQUEST],
            }
        };
        // Relay is non-blocking and lock-free; a stalled delegate sheds (audit 3) rather than
        // blocking the binder thread or holding the relay lock.
        if self.try_relay(bus, &Record::Frame { conn_id, frame: frame.to_vec() }) {
            vec![status::OK]
        } else {
            vec![status::AGAIN]
        }
    }

    /// Handle `DBUS_RECV` `[conn_id]`: block until an inbound frame is queued (or the connection
    /// closes), then reply `[OK | frame]`. An empty reply means the connection is gone or a recv is
    /// already parked on it (only one is allowed, bounding parked binder threads).
    #[must_use]
    pub fn recv(&self, sender_pid: i32, data: &[u8]) -> Vec<u8> {
        if sender_pid != self.facade_pid {
            return Vec::new();
        }
        let Some(conn_id) = wire::decode_conn(data) else {
            return Vec::new();
        };
        let mut inner = self.lock();
        // One parked recv per connection: refuse a duplicate so a (compromised) facade cannot park
        // many binder loopers on one connection. With MAX_CONNS this bounds parked threads.
        match inner.conns.get_mut(&conn_id) {
            None => return Vec::new(),
            Some(conn) if conn.recv_parked => return Vec::new(),
            Some(conn) => conn.recv_parked = true,
        }
        let result = loop {
            match inner.conns.get_mut(&conn_id) {
                None => break Vec::new(),
                Some(conn) => {
                    if let Some(frame) = conn.queue.pop_front() {
                        conn.queued_bytes = conn.queued_bytes.saturating_sub(frame.len());
                        let mut reply = Vec::with_capacity(frame.len().saturating_add(1));
                        reply.push(status::OK);
                        reply.extend_from_slice(&frame);
                        break reply;
                    }
                    if conn.closed {
                        break Vec::new();
                    }
                }
            }
            inner = self
                .inbound
                .wait(inner)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        };
        if let Some(conn) = inner.conns.get_mut(&conn_id) {
            conn.recv_parked = false;
        }
        drop(inner);
        result
    }

    /// Handle `DBUS_CLOSE` `[conn_id]`: tear the connection down and wake any parked `DBUS_RECV`.
    #[must_use]
    pub fn close(&self, sender_pid: i32, data: &[u8]) -> Vec<u8> {
        if sender_pid != self.facade_pid {
            return vec![status::DENIED];
        }
        let Some(conn_id) = wire::decode_conn(data) else {
            return vec![status::BAD_REQUEST];
        };
        let bus = {
            let mut inner = self.lock();
            if !inner.limiter.allow(self.now_ms()) {
                return vec![status::AGAIN]; // rate cap (audit 4)
            }
            match inner.conns.get_mut(&conn_id) {
                Some(conn) => {
                    conn.closed = true;
                    Some(conn.bus)
                }
                None => None,
            }
        };
        if let Some(bus) = bus {
            let _ = self.try_relay(bus, &Record::Close { conn_id });
        }
        // Wake every parked recv so the one for this conn observes `closed` and returns.
        self.inbound.notify_all();
        vec![status::OK]
    }

    /// Queue an inbound frame the delegate sent (called by the pipe reader). Byte-budgeted: a
    /// connection whose facade has stopped draining cannot grow kenneld past [`MAX_QUEUE_BYTES`]
    /// — excess frames are dropped (audit 2).
    pub fn deliver_inbound(&self, conn_id: u32, frame: Vec<u8>) {
        {
            let mut inner = self.lock();
            if let Some(conn) = inner.conns.get_mut(&conn_id) {
                if conn.queued_bytes.saturating_add(frame.len()) <= MAX_QUEUE_BYTES {
                    conn.queued_bytes = conn.queued_bytes.saturating_add(frame.len());
                    conn.queue.push_back(frame);
                }
                // else: drop — the facade is not draining; bound kenneld's memory.
            }
        }
        self.inbound.notify_all();
    }

    /// Non-blocking relay of `record` to the bus's delegate; `false` if the bus is unknown or its
    /// outbound channel is full (stalled delegate) or disconnected (dead delegate).
    fn try_relay(&self, bus: Bus, record: &Record) -> bool {
        self.senders
            .get(&bus)
            .is_some_and(|tx| tx.try_send(record.encode()).is_ok())
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

const fn bus_from_byte(byte: u8) -> Option<Bus> {
    match byte {
        wire::SESSION => Some(Bus::Session),
        wire::SYSTEM => Some(Bus::System),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const FACADE_PID: i32 = 4242;

    /// A relay wired to a fake session-bus delegate; returns the relay and the delegate's read end
    /// of the pipe (what `host-dbus` would read). A generous bucket so the bound tests are not
    /// limited by rate.
    fn relay_with_session() -> (DbusRelay, UnixStream) {
        relay_with_limiter(RateLimiter::new(100_000, 100_000))
    }

    fn relay_with_limiter(limiter: RateLimiter) -> (DbusRelay, UnixStream) {
        let (kenneld_end, delegate_end) = UnixStream::pair().expect("pipe");
        let mut senders = HashMap::new();
        senders.insert(Bus::Session, spawn_pipe_writer(kenneld_end));
        (DbusRelay::new(FACADE_PID, senders, limiter), delegate_end)
    }

    fn read_record(stream: &mut UnixStream) -> Record {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("len");
        let n = u32::from_be_bytes(len) as usize;
        let mut payload = vec![0u8; n];
        stream.read_exact(&mut payload).expect("payload");
        Record::decode(&payload).expect("decode")
    }

    #[test]
    fn wrong_sender_is_denied() {
        let (relay, _delegate) = relay_with_session();
        assert_eq!(
            relay.open(9999, &wire::encode_open(1, wire::SESSION)),
            vec![status::DENIED]
        );
    }

    #[test]
    fn open_registers_and_notifies_the_delegate() {
        let (relay, mut delegate) = relay_with_session();
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(7, wire::SESSION)),
            vec![status::OK]
        );
        assert_eq!(
            read_record(&mut delegate),
            Record::Open {
                conn_id: 7,
                bus: Bus::Session
            }
        );
    }

    #[test]
    fn open_on_a_disabled_bus_is_denied() {
        let (relay, _delegate) = relay_with_session(); // only session is wired
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(1, wire::SYSTEM)),
            vec![status::DENIED]
        );
    }

    #[test]
    fn connection_count_is_capped() {
        let (relay, mut delegate) = relay_with_session();
        for id in 0..u32::try_from(MAX_CONNS).expect("MAX_CONNS fits u32") {
            assert_eq!(
                relay.open(FACADE_PID, &wire::encode_open(id, wire::SESSION)),
                vec![status::OK]
            );
            let _ = read_record(&mut delegate); // drain the Open so the channel never fills
        }
        // One past the cap (a new id) is refused — the conns map cannot grow unbounded.
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(9999, wire::SESSION)),
            vec![status::DENIED]
        );
    }

    #[test]
    fn send_relays_a_frame_to_the_delegate() {
        let (relay, mut delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(3, wire::SESSION));
        let _ = read_record(&mut delegate); // the Open
        let frame = vec![0xDE, 0xAD];
        assert_eq!(
            relay.send(FACADE_PID, &wire::encode_send(3, &frame)),
            vec![status::OK]
        );
        assert_eq!(
            read_record(&mut delegate),
            Record::Frame { conn_id: 3, frame }
        );
    }

    #[test]
    fn recv_returns_a_delivered_inbound_frame() {
        let (relay, _delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(5, wire::SESSION));
        relay.deliver_inbound(5, vec![1, 2, 3]);
        let reply = relay.recv(FACADE_PID, &wire::encode_conn(5));
        assert_eq!(reply.first(), Some(&status::OK));
        assert_eq!(reply.get(1..), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn inbound_queue_is_byte_budgeted() {
        let (relay, _delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(5, wire::SESSION));
        // A facade that never drains: push frames past the budget; kenneld must not grow without
        // bound. After the budget is exceeded, further frames are dropped, so a single drain sees
        // a bounded amount queued rather than everything.
        let chunk = vec![0u8; 64 * 1024];
        let pushes = (MAX_QUEUE_BYTES / chunk.len()) + 10;
        for _ in 0..pushes {
            relay.deliver_inbound(5, chunk.clone());
        }
        // Close so `recv` returns empty once the queue drains (rather than blocking), then drain
        // and count: it must be ≤ the budget (not all `pushes` — excess was dropped).
        let _ = relay.close(FACADE_PID, &wire::encode_conn(5));
        let mut drained = 0usize;
        while relay.recv(FACADE_PID, &wire::encode_conn(5)).first() == Some(&status::OK) {
            drained += 1;
            if drained > pushes {
                break; // safety
            }
        }
        assert!(
            drained <= MAX_QUEUE_BYTES / chunk.len(),
            "queued {drained} chunks, budget allows {}",
            MAX_QUEUE_BYTES / chunk.len()
        );
    }

    #[test]
    fn recv_on_a_closed_connection_returns_empty() {
        let (relay, _delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(6, wire::SESSION));
        let _ = relay.close(FACADE_PID, &wire::encode_conn(6));
        assert!(relay.recv(FACADE_PID, &wire::encode_conn(6)).is_empty());
    }

    #[test]
    fn rate_limit_sheds_a_send_flood() {
        // A tiny bucket: one token, no refill within the test instant.
        let (relay, mut delegate) = relay_with_limiter(RateLimiter::new(0, 2));
        // open + the first send spend the two tokens.
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(1, wire::SESSION)),
            vec![status::OK]
        );
        let _ = read_record(&mut delegate);
        assert_eq!(
            relay.send(FACADE_PID, &wire::encode_send(1, &[0])),
            vec![status::OK]
        );
        // The next verb is over the cap — shed, no token spent on the delegate.
        assert_eq!(
            relay.send(FACADE_PID, &wire::encode_send(1, &[0])),
            vec![status::AGAIN]
        );
    }

    #[test]
    fn open_is_rate_limited_too() {
        // Audit 4: OPEN/CLOSE must spend tokens, not just SEND. One token total.
        let (relay, mut delegate) = relay_with_limiter(RateLimiter::new(0, 1));
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(1, wire::SESSION)),
            vec![status::OK]
        );
        let _ = read_record(&mut delegate);
        assert_eq!(
            relay.open(FACADE_PID, &wire::encode_open(2, wire::SESSION)),
            vec![status::AGAIN]
        );
    }

    #[test]
    fn duplicate_recv_on_one_conn_is_refused() {
        // Bounds parked binder threads: a second recv on a conn that already has one parked is
        // refused immediately (here both would-be-parked, so the second returns empty at once).
        let (relay, _delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(8, wire::SESSION));
        // Park one recv on a background thread (it blocks with nothing queued).
        let r = std::sync::Arc::new(relay);
        let r2 = std::sync::Arc::clone(&r);
        let parked = std::thread::spawn(move || r2.recv(FACADE_PID, &wire::encode_conn(8)));
        // Give it a moment to park, then a second recv must be refused (empty) without parking.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(r.recv(FACADE_PID, &wire::encode_conn(8)).is_empty());
        // Close to release the parked recv and join.
        let _ = r.close(FACADE_PID, &wire::encode_conn(8));
        assert!(parked.join().expect("join").is_empty());
    }
}
