//! The D-Bus mediation membrane (§7.7.2a): kenneld's minimal-work relay between the in-kennel
//! facade (binder node 0) and the operator-context `host-dbus` delegate (an owner-only pipe).
//!
//! kenneld is the membrane, not a filter and not a parser. Per message it authenticates the
//! sender (only the real facade may inject D-Bus traffic — the pid is kernel-attested), applies
//! the token-bucket rate cap (§7.7.2c), and shovels the opaque frame bytes to/from the bus's
//! delegate by connection id. It never decodes the TLV (so `mini-sansio-dbus` never enters the
//! daemon TCB) and never applies the allowlist (the delegate's mechanical job).
//!
//! # The four verbs
//!
//! - `DBUS_OPEN` registers a connection on its bus (or `DENIED` if the bus is not enabled).
//! - `DBUS_SEND` relays one frame to the delegate and **acks immediately** — kenneld does not
//!   wait for the bus round-trip, so no looper thread is held per call (the reply returns on
//!   `DBUS_RECV`). The ack carries the rate-limit verdict.
//! - `DBUS_RECV` blocks the calling looper until the connection has an inbound frame, then
//!   replies with it. The reply is **thread-bound** (binder, [[binder-serving-threadpool-not-cookie-worker]]),
//!   so the handler that received the `DBUS_RECV` is the one that replies — a dedicated pipe
//!   reader demultiplexes inbound frames into per-connection queues and wakes the waiter.
//! - `DBUS_CLOSE` tears the connection down and wakes any parked `DBUS_RECV`.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use kennel_lib_binder::dbus::{Bus, Record};
use kennel_lib_binder::ratelimit::RateLimiter;
use kennel_lib_binder::service::{dbus as wire, status};

/// The per-kennel D-Bus relay state. Constructed once (with the bus pipes to the delegate) and
/// shared by the node-0 handlers; the pipe reader threads feed its inbound queues.
pub struct DbusRelay {
    /// The kernel-attested pid of the spawned `facade-dbus`; only it may transact these verbs.
    facade_pid: i32,
    /// Monotonic base for the rate limiter's clock.
    start: Instant,
    inner: Mutex<Inner>,
    inbound: Condvar,
}

struct Inner {
    /// The write end of the owner-only pipe to each enabled bus's `host-dbus`.
    pipes: HashMap<Bus, UnixStream>,
    /// Per-connection state, keyed by the facade-allocated connection id.
    conns: HashMap<u32, ConnState>,
    /// The membrane rate cap, shared across all of this kennel's connections.
    limiter: RateLimiter,
}

struct ConnState {
    bus: Bus,
    /// Inbound frames (encoded TLV, `[len][payload]`) awaiting a `DBUS_RECV`.
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

impl DbusRelay {
    /// A relay for `facade_pid`, given the write end of each enabled bus's delegate pipe.
    #[must_use]
    pub fn new(facade_pid: i32, pipes: HashMap<Bus, UnixStream>, limiter: RateLimiter) -> Self {
        Self {
            facade_pid,
            start: Instant::now(),
            inner: Mutex::new(Inner {
                pipes,
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
        let mut inner = self.lock();
        if !inner.pipes.contains_key(&bus) {
            return vec![status::DENIED]; // the bus is not enabled by policy
        }
        inner.conns.insert(
            conn_id,
            ConnState {
                bus,
                queue: VecDeque::new(),
                closed: false,
            },
        );
        let ok = write_record(&mut inner, bus, &Record::Open { conn_id, bus });
        vec![if ok { status::OK } else { status::DENIED }]
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
        let now = self.now_ms();
        let mut inner = self.lock();
        if !inner.limiter.allow(now) {
            return vec![status::AGAIN]; // over the membrane rate cap — shed it.
        }
        let Some(bus) = inner.conns.get(&conn_id).map(|c| c.bus) else {
            return vec![status::BAD_REQUEST];
        };
        let ok = write_record(
            &mut inner,
            bus,
            &Record::Frame {
                conn_id,
                frame: frame.to_vec(),
            },
        );
        vec![if ok { status::OK } else { status::DENIED }]
    }

    /// Handle `DBUS_RECV` `[conn_id]`: block until an inbound frame is queued (or the connection
    /// closes), then reply `[OK | frame]`. An empty reply means the connection is gone.
    #[must_use]
    pub fn recv(&self, sender_pid: i32, data: &[u8]) -> Vec<u8> {
        if sender_pid != self.facade_pid {
            return Vec::new();
        }
        let Some(conn_id) = wire::decode_conn(data) else {
            return Vec::new();
        };
        let mut inner = self.lock();
        loop {
            match inner.conns.get_mut(&conn_id) {
                None => return Vec::new(), // unknown/closed: tell the facade to stop.
                Some(conn) => {
                    if let Some(frame) = conn.queue.pop_front() {
                        let mut reply = Vec::with_capacity(frame.len().saturating_add(1));
                        reply.push(status::OK);
                        reply.extend_from_slice(&frame);
                        return reply;
                    }
                    if conn.closed {
                        return Vec::new();
                    }
                }
            }
            // Park this looper until the pipe reader (or close) wakes it.
            inner = self
                .inbound
                .wait(inner)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
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
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&conn_id) {
            conn.closed = true;
            let bus = conn.bus;
            let _ = write_record(&mut inner, bus, &Record::Close { conn_id });
        }
        drop(inner);
        // Wake every parked recv so the one(s) for this conn observe `closed`.
        self.inbound.notify_all();
        vec![status::OK]
    }

    /// Push an inbound frame the delegate sent (called by the pipe reader): queue it for the
    /// connection's parked `DBUS_RECV` and wake it.
    pub fn deliver_inbound(&self, conn_id: u32, frame: Vec<u8>) {
        let mut inner = self.lock();
        if let Some(conn) = inner.conns.get_mut(&conn_id) {
            conn.queue.push_back(frame);
        }
        drop(inner);
        self.inbound.notify_all();
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

/// Write a record to the bus's delegate pipe; `false` if the pipe is gone (the delegate died).
fn write_record(inner: &mut Inner, bus: Bus, record: &Record) -> bool {
    inner
        .pipes
        .get_mut(&bus)
        .is_some_and(|pipe| pipe.write_all(&record.encode()).is_ok())
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

    /// A relay wired to a fake session-bus delegate; returns the relay and the delegate's read
    /// end of the pipe (what `host-dbus` would read).
    fn relay_with_session() -> (DbusRelay, UnixStream) {
        let (kenneld_end, delegate_end) = UnixStream::pair().expect("pipe");
        let mut pipes = HashMap::new();
        pipes.insert(Bus::Session, kenneld_end);
        let relay = DbusRelay::new(FACADE_PID, pipes, RateLimiter::new(1000, 1000));
        (relay, delegate_end)
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
            Record::Frame {
                conn_id: 3,
                frame
            }
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
    fn recv_on_a_closed_connection_returns_empty() {
        let (relay, _delegate) = relay_with_session();
        let _ = relay.open(FACADE_PID, &wire::encode_open(6, wire::SESSION));
        let _ = relay.close(FACADE_PID, &wire::encode_conn(6));
        assert!(relay.recv(FACADE_PID, &wire::encode_conn(6)).is_empty());
    }

    #[test]
    fn rate_limit_sheds_a_flood() {
        let (kenneld_end, _delegate) = UnixStream::pair().expect("pipe");
        let mut pipes = HashMap::new();
        pipes.insert(Bus::Session, kenneld_end);
        // A tiny bucket: 1 token, no refill within the test instant.
        let relay = DbusRelay::new(FACADE_PID, pipes, RateLimiter::new(0, 1));
        let _ = relay.open(FACADE_PID, &wire::encode_open(1, wire::SESSION));
        assert_eq!(
            relay.send(FACADE_PID, &wire::encode_send(1, &[0])),
            vec![status::OK]
        );
        assert_eq!(
            relay.send(FACADE_PID, &wire::encode_send(1, &[0])),
            vec![status::AGAIN]
        );
    }
}
