//! `host-dbus`: the D-Bus mediation **delegate** (§7.7.2b).
//!
//! `kenneld` compiles the `[dbus]` policy into a match table and brokers the facade↔delegate
//! conduit; this is what's left — the bus-side I/O around the I/O-free
//! [`kennel_lib_dbus::delegate::Delegate`] core. It holds the operator's real bus connection,
//! reads typed [`Frame`]s off the conduit, runs each through the compiled
//! [`Filter`] (the real enforcement boundary — the in-kennel
//! facade is untrusted), reconstructs and sends the approved calls, and demultiplexes the bus's
//! replies and allowlisted signals back over the conduit.
//!
//! A single-threaded `poll(2)` event loop over the conduit and bus fds — no per-message threads
//! and no head-of-line blocking on a quiet bus. (The §7.7.2b thread-pool model is a throughput
//! refinement for very chatty buses; one connection's mediation is correct on the event loop.)
//!
//! This is a **separate crate** from `kennel-host-delegate` on purpose: kenneld depends on that
//! crate's conduit-wire helpers, so putting the D-Bus engine (and `mini-sansio-dbus`) here keeps
//! it out of kenneld's dependency closure — the daemon TCB only shrinks.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};

use mini_sansio_dbus::{
    DBusConnection, DBusConnectorWants, MessageType, OutgoingQueue, SliceMessageEncoder,
};
use nix::poll::{PollFd, PollFlags, PollTimeout};

use std::collections::HashMap;
use std::net::Shutdown;
use std::sync::mpsc::{sync_channel, SyncSender};

use kennel_lib_dbus::delegate::{BusReply, BusSignal, Delegate, Outbound};
use kennel_lib_dbus::filter::Filter;
use kennel_lib_dbus::message::body_slice;
use kennel_lib_dbus::wire::{self, Bus, Frame, Record};

/// The read buffer for the bus connection's decoder.
const READBUF: usize = wire::MAX_BODY + 64 * 1024;

/// High-water mark for `conduit_out` (the buffer of real-bus messages bound for kenneld over the
/// conduit). Above it, [`Loop::run`] stops reading the real bus so the kernel socket backpressures
/// it, bounding the delegate's memory when a kennel stops draining. Two read buffers' worth leaves
/// room for one in-flight max-size message plus slack.
const CONDUIT_OUT_HIGH_WATER: usize = 2 * READBUF;

/// The depth of an outbound channel (to a mediation's bridge, and to kenneld). A stalled peer
/// fills it and the sender sheds or back-pressures rather than blocking the dispatcher.
const OUTBOUND_DEPTH: usize = 64;

/// Serve the owner-only command socket.
///
/// `kenneld` connects and streams [`Record`]s over it for **all** of this kennel's bus
/// connections, multiplexed by connection id (§7.7.2a — kenneld is the membrane; host-dbus is
/// reachable only from it, never from the kennel).
///
/// host-dbus is one process per kennel: it demultiplexes the records and runs one mediation per
/// connection. Each mediation is the existing single-connection poll loop ([`mediate`]), bridged
/// to kenneld by an internal socketpair, so the per-connection logic is unchanged.
pub fn serve(listener: &UnixListener, bus: Bus, bus_address: &str, filter: &Filter) {
    for stream in listener.incoming().flatten() {
        if let Err(e) = dispatch(stream, bus, bus_address, filter) {
            eprintln!("host-dbus: {e}");
        }
    }
}

/// One demultiplexed connection: the bounded inbound channel to its mediation, and a handle to
/// shut the bridge down (both directions) on teardown.
struct Conn {
    to_bridge: SyncSender<Vec<u8>>,
    shutdown: UnixStream,
}

/// Demultiplex kenneld's record stream into per-connection mediations.
///
/// The dispatcher reads kenneld's single pipe; it must never block on a per-connection write (one
/// stalled mediation would head-of-line-block every connection), and it must not serialise all
/// outbound under a shared lock held across I/O. So every cross-thread write rides a *bounded*
/// channel drained by a dedicated writer thread ([`spawn_writer`]): the dispatcher and the conn
/// pumps `try_send`/`send` and never hold a lock across blocking I/O — the same isolation the
/// kenneld relay uses.
fn dispatch(kenneld: UnixStream, bus: Bus, bus_address: &str, filter: &Filter) -> io::Result<()> {
    // One writer thread owns the kenneld write half; conn pumps send to it. No shared lock is ever
    // held across the blocking write.
    let to_kenneld = spawn_writer(kenneld.try_clone()?);
    let mut conns: HashMap<u32, Conn> = HashMap::new();
    let mut reader = kenneld;
    while let Some(record) = read_record(&mut reader)? {
        match record {
            Record::Open { conn_id, bus: _ } => {
                if conns.contains_key(&conn_id) {
                    continue; // duplicate open id — ignore
                }
                let (ours, theirs) = UnixStream::pair()?;
                // Inbound to the mediation rides a bounded channel + writer thread, so the
                // dispatcher's `try_send` below is non-blocking.
                let to_bridge = spawn_writer(ours.try_clone()?);
                let shutdown = ours.try_clone()?;
                // Outbound: read this conn's mediation output and forward to kenneld.
                let out = to_kenneld.clone();
                std::thread::spawn(move || conn_to_kenneld(ours, conn_id, &out));
                // The per-connection mediation (the robust single-conn poll loop, unchanged).
                let addr = bus_address.to_owned();
                let filt = filter.clone();
                std::thread::spawn(move || {
                    let _ = mediate(theirs, bus, &addr, filt);
                });
                conns.insert(
                    conn_id,
                    Conn {
                        to_bridge,
                        shutdown,
                    },
                );
            }
            Record::Frame { conn_id, frame } => {
                if let Some(conn) = conns.get(&conn_id) {
                    // Non-blocking, so one connection's stall does not block every other. But a
                    // dropped frame is NOT safe: `Record::Frame` has no ACK back to kenneld, so a
                    // silently-shed `MethodCall` leaves the workload hanging forever on a
                    // `MethodReturn` that never comes. Both `Full` (the mediation thread is stalled
                    // on a slow real bus) and `Disconnected` (dead mediation) therefore tear the
                    // connection down — the workload sees a clean reset and a D-Bus client
                    // reconnects, rather than wedging.
                    if conn.to_bridge.try_send(frame).is_err() {
                        teardown(&mut conns, conn_id);
                    }
                }
            }
            Record::Close { conn_id } => teardown(&mut conns, conn_id),
        }
    }
    Ok(())
}

/// Remove a connection and shut its bridge down both ways, so the mediation and both pump threads
/// unblock and exit (rather than leaking until process end).
fn teardown(conns: &mut HashMap<u32, Conn>, conn_id: u32) {
    if let Some(conn) = conns.remove(&conn_id) {
        let _ = conn.shutdown.shutdown(Shutdown::Both);
    }
}

/// Read outgoing frames from one connection's mediation and forward each to kenneld as a
/// [`Record::Frame`]. The blocking is the channel send on this dedicated per-conn thread — never a
/// shared lock — so a slow kenneld back-pressures only this connection, not all of them.
fn conn_to_kenneld(mut bridge: UnixStream, conn_id: u32, to_kenneld: &SyncSender<Vec<u8>>) {
    while let Some(frame) = read_frame_bytes(&mut bridge) {
        let record = Record::Frame { conn_id, frame };
        if to_kenneld.send(record.encode()).is_err() {
            return; // kenneld writer gone — the pipe is dead.
        }
    }
}

/// Spawn a writer thread draining a bounded channel to `stream`, returning the channel's sender.
/// The blocking `write_all` lives only on this dedicated thread — never on the dispatcher, a conn
/// reader, or under a lock. A dead peer ends the thread and disconnects the sender.
fn spawn_writer(mut stream: UnixStream) -> SyncSender<Vec<u8>> {
    let (tx, rx) = sync_channel::<Vec<u8>>(OUTBOUND_DEPTH);
    std::thread::spawn(move || {
        while let Ok(bytes) = rx.recv() {
            if stream.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    tx
}

/// Read one length-prefixed [`Record`] from kenneld's stream. `Ok(None)` on a clean EOF.
fn read_record(stream: &mut UnixStream) -> io::Result<Option<Record>> {
    let Some(payload) = read_len_prefixed(stream)? else {
        return Ok(None);
    };
    Record::decode(&payload).map(Some).map_err(|_| broken())
}

/// Read one length-prefixed frame from a bridge and return the **full** `[len][payload]` bytes
/// (the encoded TLV, ready to relay verbatim in a [`Record::Frame`]). `None` on EOF.
fn read_frame_bytes(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let payload = read_len_prefixed(stream).ok().flatten()?;
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    Some(out)
}

/// Read a `[u32 len][payload]` record off a stream, returning the payload. `Ok(None)` on a clean
/// EOF at a record boundary; bounded by [`wire::MAX_FRAME`].
fn read_len_prefixed(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let len = match wire::frame_len(&len_buf) {
        Ok(Some(len)) => len,
        Ok(None) => return Ok(None),
        Err(_) => return Err(broken()),
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Mediate one workload bus connection against `bus` at `bus_address`, applying `filter`.
///
/// Connects the operator's real bus, runs the SASL handshake, sends the delegate's own `Hello`,
/// then services the conduit and the bus until either closes.
///
/// # Errors
///
/// Returns an I/O error on a fatal socket failure; a clean EOF on either side is `Ok(())`.
pub fn mediate(conduit: UnixStream, bus: Bus, bus_address: &str, filter: Filter) -> io::Result<()> {
    let path = parse_unix_address(bus_address)?;
    let bus_stream = UnixStream::connect(path)?;
    let seq = handshake(&bus_stream)?;

    let mut conn = DBusConnection::new(seq);
    let mut queue = RawQueue::default();
    // The delegate's own Hello (serial 1) so the bus assigns it a unique name; its reply is
    // unmatched in the delegate's serial map (which starts at 2) and is dropped.
    queue.push_raw(&hello_message()?);

    let mut delegate = Delegate::new(filter);
    let mut state = Loop {
        conn: &mut conn,
        queue: &mut queue,
        delegate: &mut delegate,
        bus,
        bus_stream,
        conduit,
        readbuf: vec![0u8; READBUF],
        conduit_in: Vec::new(),
        conduit_out: VecDeque::new(),
    };
    state.run()
}

/// The event-loop state for one mediation.
struct Loop<'a> {
    conn: &'a mut DBusConnection,
    queue: &'a mut RawQueue,
    delegate: &'a mut Delegate,
    bus: Bus,
    bus_stream: UnixStream,
    conduit: UnixStream,
    readbuf: Vec<u8>,
    conduit_in: Vec<u8>,
    conduit_out: VecDeque<u8>,
}

impl Loop<'_> {
    fn run(&mut self) -> io::Result<()> {
        self.bus_stream.set_nonblocking(true)?;
        self.conduit.set_nonblocking(true)?;
        loop {
            // Flush whatever is queued for the bus and the conduit first.
            if self.pump_bus_writes()?.closed() || self.pump_conduit_writes()?.closed() {
                return Ok(());
            }

            // Read from the real bus only while the conduit-out buffer is below its high-water
            // mark. If the kennel stops draining (the facade stops issuing DBUS_RECV), kenneld's
            // MAX_QUEUE_BYTES backs up the conduit pipe, `pump_conduit_writes` stops draining, and
            // `read_bus` would otherwise keep appending to `conduit_out` unboundedly — an idle or
            // hostile kennel OOMs the delegate. Stopping the bus read lets the kernel socket
            // backpressure the real bus naturally; we resume once the conduit drains.
            let mut bus_flags = PollFlags::empty();
            if self.conduit_out.len() < CONDUIT_OUT_HIGH_WATER {
                bus_flags |= PollFlags::POLLIN;
            }
            if self.bus_has_pending_write() {
                bus_flags |= PollFlags::POLLOUT;
            }
            let mut conduit_flags = PollFlags::POLLIN;
            if !self.conduit_out.is_empty() {
                conduit_flags |= PollFlags::POLLOUT;
            }
            // SAFETY-equivalent: PollFd borrows the streams we own for the call's duration.
            let mut fds = [
                PollFd::new(self.bus_stream_borrow(), bus_flags),
                PollFd::new(self.conduit_borrow(), conduit_flags),
            ];
            if nix::poll::poll(&mut fds, PollTimeout::NONE).is_err() {
                return Ok(());
            }
            let bus_ready = fds
                .first()
                .and_then(PollFd::revents)
                .unwrap_or_else(PollFlags::empty);
            let conduit_ready = fds
                .get(1)
                .and_then(PollFd::revents)
                .unwrap_or_else(PollFlags::empty);
            // `revents` are Copy; `fds` (and its borrows of self) are unused past here, so the
            // borrow ends and `self` is free to mutate below.

            if conduit_ready.intersects(PollFlags::POLLIN) && self.read_conduit()?.closed() {
                return Ok(());
            }
            if bus_ready.intersects(PollFlags::POLLIN) && self.read_bus()?.closed() {
                return Ok(());
            }
            if bus_ready.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
                || conduit_ready.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
            {
                return Ok(());
            }
        }
    }

    fn bus_stream_borrow(&self) -> BorrowedFd<'_> {
        self.bus_stream.as_fd()
    }

    fn conduit_borrow(&self) -> BorrowedFd<'_> {
        self.conduit.as_fd()
    }

    /// Whether the bus connection still has bytes queued to write.
    fn bus_has_pending_write(&mut self) -> bool {
        matches!(
            self.conn.wants(&*self.queue, &mut self.readbuf),
            Ok((_, Some(_)))
        )
    }

    /// Drain as much of the bus outbound queue as the socket accepts (non-blocking).
    fn pump_bus_writes(&mut self) -> io::Result<Flow> {
        loop {
            let n = {
                let Ok((_r, w)) = self.conn.wants(&*self.queue, &mut self.readbuf) else {
                    return Ok(Flow::Closed);
                };
                let Some(write) = w else {
                    return Ok(Flow::Open);
                };
                match (&self.bus_stream).write(write.buf) {
                    Ok(0) => return Ok(Flow::Closed),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Flow::Open),
                    Err(e) => return Err(e),
                }
            };
            if self.conn.satisfy_write(n, self.queue).is_err() {
                return Ok(Flow::Closed);
            }
        }
    }

    /// Drain the conduit outbound buffer (non-blocking).
    fn pump_conduit_writes(&mut self) -> io::Result<Flow> {
        while !self.conduit_out.is_empty() {
            let (head, _) = self.conduit_out.as_slices();
            match (&self.conduit).write(head) {
                Ok(0) => return Ok(Flow::Closed),
                Ok(n) => {
                    self.conduit_out.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Flow::Open),
                Err(e) => return Err(e),
            }
        }
        Ok(Flow::Open)
    }

    /// One non-blocking read from the bus, dispatching a completed message.
    fn read_bus(&mut self) -> io::Result<Flow> {
        let n = {
            let Ok((read, _w)) = self.conn.wants(&*self.queue, &mut self.readbuf) else {
                return Ok(Flow::Closed);
            };
            match (&self.bus_stream).read(read.buf) {
                Ok(0) => return Ok(Flow::Closed),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Flow::Open),
                Err(e) => return Err(e),
            }
        };
        let frame = match self.conn.satisfy_read(n, &self.readbuf) {
            Ok(Some(msg)) => dispatch_bus_message(self.delegate, self.bus, &msg, &self.readbuf),
            Ok(None) => None,
            Err(_) => return Ok(Flow::Closed),
        };
        if let Some(frame) = frame {
            self.conduit_out.extend(frame.encode());
        }
        Ok(Flow::Open)
    }

    /// Read conduit bytes, decode each complete frame, and feed the delegate.
    fn read_conduit(&mut self) -> io::Result<Flow> {
        let mut chunk = [0u8; 16 * 1024];
        match (&self.conduit).read(&mut chunk) {
            Ok(0) => return Ok(Flow::Closed),
            Ok(n) => self
                .conduit_in
                .extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Flow::Open),
            Err(e) => return Err(e),
        }
        while let Some(frame) = self.take_conduit_frame()? {
            if let Frame::Call(call) = frame {
                match self.delegate.on_conduit_call(&call) {
                    Ok(Outbound::ToBus(bytes)) => {
                        self.queue.push_raw(&bytes);
                    }
                    Ok(Outbound::ToConduit(reply)) => {
                        self.conduit_out.extend(reply.encode());
                    }
                    Err(_) => {} // an unencodable approved call: drop it
                }
            }
            // The facade never sends Reply/Error/Signal to the delegate; ignore.
        }
        Ok(Flow::Open)
    }

    /// Pop one complete length-prefixed frame from the conduit input buffer, if present.
    fn take_conduit_frame(&mut self) -> io::Result<Option<Frame>> {
        let Some(len) = wire::frame_len(&self.conduit_in).map_err(|_| broken())? else {
            return Ok(None);
        };
        let total = 4usize.checked_add(len).ok_or_else(broken)?;
        if self.conduit_in.len() < total {
            return Ok(None);
        }
        let payload: Vec<u8> = self.conduit_in.drain(..total).skip(4).collect();
        wire::Frame::decode(&payload)
            .map(Some)
            .map_err(|_| broken())
    }
}

/// Whether the connection should keep running or has hit a clean close.
#[derive(Clone, Copy)]
enum Flow {
    Open,
    Closed,
}

impl Flow {
    const fn closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Turn a decoded bus message into the conduit frame to forward, or `None` to drop it.
fn dispatch_bus_message(
    delegate: &mut Delegate,
    bus: Bus,
    msg: &mini_sansio_dbus::IncomingMessage<'_>,
    raw: &[u8],
) -> Option<Frame> {
    let (body_endian, body) = body_slice(raw).ok()?;
    match msg.message_type {
        MessageType::MethodReturn | MessageType::Error => {
            let reply_serial = msg.reply_serial?;
            delegate.on_bus_reply(BusReply {
                reply_serial,
                error_name: if msg.message_type == MessageType::Error {
                    msg.error_name
                } else {
                    None
                },
                error_message: None,
                signature: msg.signature.unwrap_or(""),
                body_endian,
                body,
            })
        }
        MessageType::Signal => delegate.on_bus_signal(BusSignal {
            bus,
            path: msg.path.unwrap_or(""),
            interface: msg.interface.unwrap_or(""),
            member: msg.member.unwrap_or(""),
            signature: msg.signature.unwrap_or(""),
            body_endian,
            body,
        }),
        // An inbound MethodCall to an owned name (rare) or anything else: drop in phase 4.
        _ => None,
    }
}

/// Drive the `mini-sansio-dbus` client connector over a blocking stream until connected,
/// returning the sequence number to seed the [`DBusConnection`].
fn handshake(bus: &UnixStream) -> io::Result<u64> {
    let mut connector = mini_sansio_dbus::DBusConnector::new();
    let mut readbuf = [0u8; 1024];
    loop {
        let wants = connector.wants(&mut readbuf).map_err(|_| broken())?;
        match wants {
            DBusConnectorWants::Read { buf, .. } => {
                let n = (&*bus).read(buf)?;
                if n == 0 {
                    return Err(broken());
                }
                connector.satisfy_read(n, &readbuf).map_err(|_| broken())?;
            }
            DBusConnectorWants::Write { buf, .. } => {
                let n = (&*bus).write(buf)?;
                if let Some(seq) = connector.satisfy_write(n).map_err(|_| broken())? {
                    return Ok(seq);
                }
            }
        }
    }
}

/// The delegate's own `Hello` call to the bus driver (serial 1).
fn hello_message() -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 256];
    let mut enc =
        SliceMessageEncoder::new(&mut buf, MessageType::MethodCall).map_err(|_| broken())?;
    enc.set_destination("org.freedesktop.DBus")
        .map_err(|_| broken())?;
    enc.set_path("/org/freedesktop/DBus")
        .map_err(|_| broken())?;
    enc.set_interface("org.freedesktop.DBus")
        .map_err(|_| broken())?;
    enc.set_member("Hello").map_err(|_| broken())?;
    enc.__dbus_begin_body().map_err(|_| broken())?;
    let len = enc.finish().map_err(|_| broken())?;
    let mut out = buf.get(..len).ok_or_else(broken)?.to_vec();
    mini_sansio_dbus::DBusSerial::write_to_message(&mut out, 1).map_err(|_| broken())?;
    Ok(out)
}

/// Parse a `unix:path=/run/user/1000/bus` (or `unix:abstract=…`) D-Bus address into the socket
/// path. Only the `path=` form is handled (abstract sockets are a noted gap).
fn parse_unix_address(address: &str) -> io::Result<String> {
    let body = address.strip_prefix("unix:").ok_or_else(broken)?;
    for field in body.split(',') {
        if let Some(path) = field.strip_prefix("path=") {
            return Ok(path.to_owned());
        }
    }
    Err(broken())
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "D-Bus mediation error")
}

/// A queue of fully-formed outbound messages sent to the bus verbatim — the serial is already
/// written by [`message::reconstruct_call`] (the delegate owns the bus serial namespace), so
/// `push_raw` does **not** rewrite it.
#[derive(Default)]
struct RawQueue {
    messages: VecDeque<Vec<u8>>,
}

impl OutgoingQueue for RawQueue {
    fn push_raw(&mut self, buf: &[u8]) -> u32 {
        let serial = buf
            .get(8..12)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map_or(0, u32::from_le_bytes);
        self.messages.push_back(buf.to_vec());
        serial
    }

    fn peek(&self) -> Option<&[u8]> {
        self.messages.front().map(Vec::as_slice)
    }

    fn pop(&mut self) {
        self.messages.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_unix_path_address() {
        assert_eq!(
            parse_unix_address("unix:path=/run/user/1000/bus").expect("path"),
            "/run/user/1000/bus"
        );
        assert_eq!(
            parse_unix_address("unix:guid=abc,path=/tmp/dbus-XYZ").expect("path"),
            "/tmp/dbus-XYZ"
        );
        assert!(parse_unix_address("tcp:host=localhost").is_err());
    }

    #[test]
    fn raw_queue_preserves_bytes_and_reads_the_serial() {
        let mut q = RawQueue::default();
        // A 12-byte stub with serial 0x2A at offset 8 (little-endian).
        let mut msg = vec![0u8; 8];
        msg.extend_from_slice(&0x2Au32.to_le_bytes());
        assert_eq!(q.push_raw(&msg), 0x2A);
        assert_eq!(q.peek(), Some(msg.as_slice()));
        q.pop();
        assert!(q.peek().is_none());
    }

    #[test]
    fn hello_message_is_a_valid_method_call_serial_1() {
        let bytes = hello_message().expect("hello");
        // Little-endian, MethodCall (type 1), serial at [8..12] == 1.
        assert_eq!(bytes.first(), Some(&b'l'));
        assert_eq!(bytes.get(1), Some(&1u8));
        let serial = bytes
            .get(8..12)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes);
        assert_eq!(serial, Some(1));
    }
}
