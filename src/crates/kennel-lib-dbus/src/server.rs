//! The facade's connection state machine (§7.7.2): terminate one workload D-Bus connection,
//! parse its adversarial wire, and emit typed transactions.
//!
//! `facade-dbus` owns the socket I/O; this is the sans-IO core it drives. Feed it the bytes
//! read off the workload's bus connection ([`Facade::on_workload_bytes`]) and the frames the
//! delegate sends back ([`Facade::on_delegate_frame`]); it returns [`Action`]s — bytes to write
//! to the workload and typed [`wire::Frame`]s to forward to the delegate. It runs the SASL
//! handshake ([`crate::sasl`]), then the binary message loop over the `mini-sansio-dbus`
//! decoder — the sole parser of adversarial D-Bus wire (§7.7.2), quarantined here on the
//! untrusted side of the boundary.
//!
//! Two things are answered locally without ever touching the bus: the `Hello` bootstrap (every
//! client's first call — the facade assigns the workload a unique name) and the
//! refuse-to-broker backstop (§7.7.5/§7.7.10 — a hard-coded refusal even though policy
//! compilation already rejects these destinations). Everything else becomes a [`wire::Call`]
//! for the delegate to filter and reconstruct.

use mini_sansio_dbus::{DBusConnection, MessageType, OutgoingQueue};

use crate::{message, wire};

/// The D-Bus bus driver's well-known name; calls to it are the bus-management interface the
/// facade answers or relays rather than a normal mediated destination.
const BUS_DRIVER: &str = "org.freedesktop.DBus";

/// The refuse-to-broker set (§7.7.5): destinations the facade refuses regardless of policy.
/// Policy compilation already rejects naming these in an `allow` list; this is the runtime
/// backstop (§7.7.10). A prefix entry ending in `.` matches that destination and its children.
const REFUSE_TO_BROKER: &[&str] = &[
    "org.freedesktop.secrets",
    "org.freedesktop.systemd1",
    "org.freedesktop.login1",
    "org.gnome.SessionManager",
    "org.kde.ksmserver",
];

/// The unique name the facade assigns the workload at `Hello`. A kennel has exactly one bus
/// client (its workload), so a fixed name is sufficient and need not be allocated.
const WORKLOAD_UNIQUE_NAME: &str = ":1.0";

/// What the [`Facade`] wants done with a chunk of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write these bytes to the workload's bus connection (a SASL reply, a local
    /// `MethodReturn`/`Error`, or a reconstructed reply/signal from the delegate).
    ToWorkload(Vec<u8>),
    /// Forward this typed transaction to the delegate over the conduit.
    ToDelegate(wire::Frame),
}

/// A fatal connection error; `facade-dbus` drops the workload connection on any of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FacadeError {
    /// The SASL handshake failed.
    Sasl(crate::sasl::SaslError),
    /// The D-Bus decoder rejected the wire (malformed message from the workload).
    Decode(String),
    /// A message could not be reconstructed (encoder error / unsupported body).
    Message(message::MessageError),
}

impl From<message::MessageError> for FacadeError {
    fn from(e: message::MessageError) -> Self {
        Self::Message(e)
    }
}

impl core::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sasl(e) => write!(f, "D-Bus SASL: {e:?}"),
            Self::Decode(e) => write!(f, "D-Bus decode: {e}"),
            Self::Message(e) => write!(f, "D-Bus message: {e}"),
        }
    }
}

impl core::error::Error for FacadeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Running the SASL handshake.
    Authing,
    /// In the binary message phase.
    Running,
}

/// The read buffer for the `mini-sansio-dbus` decoder: large enough for any message the facade
/// forwards (the conduit body bound plus header slack).
const READBUF: usize = wire::MAX_BODY + 64 * 1024;

/// A no-op outgoing queue: the facade drives only the decoder's read path, never queues an
/// outbound message through `mini-sansio-dbus` (it builds replies via [`crate::message`]).
struct NoQueue;
impl OutgoingQueue for NoQueue {
    fn push_raw(&mut self, _buf: &[u8]) -> u32 {
        0
    }
    fn peek(&self) -> Option<&[u8]> {
        None
    }
    fn pop(&mut self) {}
}

/// One workload bus connection's mediation state.
pub struct Facade {
    bus: wire::Bus,
    phase: Phase,
    sasl: crate::sasl::SaslServer,
    conn: DBusConnection,
    readbuf: Vec<u8>,
    pending: Vec<u8>,
    out_serial: u32,
}

impl Facade {
    /// A fresh facade for a workload connecting to `bus`.
    #[must_use]
    pub fn new(bus: wire::Bus) -> Self {
        Self {
            bus,
            phase: Phase::Authing,
            sasl: crate::sasl::SaslServer::new(),
            conn: DBusConnection::new(0),
            readbuf: vec![0u8; READBUF],
            pending: Vec::new(),
            out_serial: 1,
        }
    }

    /// Feed bytes read from the workload's connection.
    ///
    /// # Errors
    ///
    /// [`FacadeError`] on a SASL or decode failure; the caller drops the connection.
    pub fn on_workload_bytes(&mut self, data: &[u8]) -> Result<Vec<Action>, FacadeError> {
        let mut actions = Vec::new();
        if self.phase == Phase::Authing {
            match self.sasl.push(data).map_err(FacadeError::Sasl)? {
                crate::sasl::Outcome::Continue { reply } => {
                    push_write(&mut actions, reply);
                    return Ok(actions);
                }
                crate::sasl::Outcome::Begin { reply, leftover } => {
                    push_write(&mut actions, reply);
                    self.phase = Phase::Running;
                    self.pending.extend_from_slice(&leftover);
                }
            }
        } else {
            self.pending.extend_from_slice(data);
        }
        self.drive_decoder(&mut actions)?;
        Ok(actions)
    }

    /// Feed a typed frame the delegate sent back over the conduit, producing the
    /// reconstructed D-Bus message to hand the workload.
    ///
    /// # Errors
    ///
    /// [`FacadeError::Message`] if reconstruction fails.
    pub fn on_delegate_frame(&mut self, frame: wire::Frame) -> Result<Vec<Action>, FacadeError> {
        let serial = self.next_serial();
        let bytes = match frame {
            wire::Frame::Reply(r) => {
                message::reconstruct_return(&r, serial, Some(WORKLOAD_UNIQUE_NAME))?
            }
            wire::Frame::Error(e) => {
                message::reconstruct_error(&e, serial, Some(WORKLOAD_UNIQUE_NAME))?
            }
            wire::Frame::Signal(s) => message::reconstruct_signal(&s, serial)?,
            // The delegate never sends a Call to the facade; ignore defensively.
            wire::Frame::Call(_) => return Ok(Vec::new()),
        };
        Ok(vec![Action::ToWorkload(bytes)])
    }

    /// Drive the decoder over `self.pending`, appending actions for each complete message.
    fn drive_decoder(&mut self, actions: &mut Vec<Action>) -> Result<(), FacadeError> {
        loop {
            // Fill the slice the decoder wants from the pending buffer.
            let n = {
                let (read, _w) = self
                    .conn
                    .wants(&NoQueue, &mut self.readbuf)
                    .map_err(|e| FacadeError::Decode(format!("{e:?}")))?;
                let want = read.buf.len();
                let take = want.min(self.pending.len());
                if take == 0 {
                    // The decoder wants bytes we do not have yet (or wants nothing): wait.
                    break;
                }
                read.buf
                    .get_mut(..take)
                    .unwrap_or(&mut [])
                    .copy_from_slice(self.pending.get(..take).unwrap_or(&[]));
                take
            };
            self.pending.drain(..n);

            let completed = self
                .conn
                .satisfy_read(n, &self.readbuf)
                .map_err(|e| FacadeError::Decode(format!("{e:?}")))?;
            if let Some(msg) = completed {
                let action = handle_message(&msg, &self.readbuf, self.bus, &mut self.out_serial)?;
                if let Some(a) = action {
                    actions.push(a);
                }
            }
        }
        Ok(())
    }

    fn next_serial(&mut self) -> u32 {
        let s = self.out_serial;
        self.out_serial = self.out_serial.checked_add(1).unwrap_or(1);
        s
    }
}

/// Turn one decoded workload message into an [`Action`] (or `None` to drop it). Pure over the
/// decoded message + the raw buffer (for the body slice); takes the facade's serial counter to
/// number any locally-built reply.
fn handle_message(
    msg: &mini_sansio_dbus::IncomingMessage<'_>,
    readbuf: &[u8],
    bus: wire::Bus,
    out_serial: &mut u32,
) -> Result<Option<Action>, FacadeError> {
    // Only method calls are mediated; anything else from the workload is dropped (a workload
    // does not legitimately send replies, and signals to the bus are not part of phase 3).
    if msg.message_type != MessageType::MethodCall {
        return Ok(None);
    }
    let destination = msg.destination.unwrap_or("");

    // The bus driver's own interface: answer `Hello` locally (assign the unique name). Every
    // other management call (AddMatch/GetNameOwner/…) falls through and is forwarded like any
    // other call — it reaches the real bus driver via the delegate.
    if destination == BUS_DRIVER && msg.member == Some("Hello") {
        let reply = wire::Reply {
            reply_serial: msg.serial,
            signature: "s".to_owned(),
            body_endian: b'l',
            body: message::marshal_string(WORKLOAD_UNIQUE_NAME),
        };
        let serial = take_serial(out_serial);
        let bytes = message::reconstruct_return(&reply, serial, Some(WORKLOAD_UNIQUE_NAME))?;
        return Ok(Some(Action::ToWorkload(bytes)));
    }

    // Refuse-to-broker backstop (§7.7.5/§7.7.10): refuse before the conduit.
    if is_refused(destination) {
        let err = wire::ErrorReply {
            reply_serial: msg.serial,
            name: "org.freedesktop.DBus.Error.AccessDenied".to_owned(),
            message: format!("{destination} is refused to brokering by Project Kennel"),
        };
        let serial = take_serial(out_serial);
        let bytes = message::reconstruct_error(&err, serial, Some(WORKLOAD_UNIQUE_NAME))?;
        return Ok(Some(Action::ToWorkload(bytes)));
    }

    // A normal mediated call: forward the typed fields + the verbatim body to the delegate.
    let (body_endian, body) = message::body_slice(readbuf)?;
    let call = wire::Call {
        bus,
        serial: msg.serial,
        no_reply: false,
        destination: destination.to_owned(),
        path: msg.path.unwrap_or("").to_owned(),
        interface: msg.interface.unwrap_or("").to_owned(),
        member: msg.member.unwrap_or("").to_owned(),
        signature: msg.signature.unwrap_or("").to_owned(),
        body_endian,
        body: body.to_vec(),
    };
    Ok(Some(Action::ToDelegate(wire::Frame::Call(call))))
}

/// Whether `destination` is in the refuse-to-broker set (exact name or a `.`-prefixed child).
fn is_refused(destination: &str) -> bool {
    REFUSE_TO_BROKER.iter().any(|&r| {
        destination == r
            || destination
                .strip_prefix(r)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn take_serial(out_serial: &mut u32) -> u32 {
    let s = *out_serial;
    *out_serial = out_serial.checked_add(1).unwrap_or(1);
    s
}

fn push_write(actions: &mut Vec<Action>, bytes: Vec<u8>) {
    if !bytes.is_empty() {
        actions.push(Action::ToWorkload(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a `Hello` (or any) method call to `org.freedesktop.DBus` via the real encoder.
    fn method_call(dest: &str, path: &str, iface: &str, member: &str, serial: u32) -> Vec<u8> {
        use mini_sansio_dbus::{MessageType, SliceMessageEncoder};
        let mut buf = vec![0u8; 512];
        let mut enc = SliceMessageEncoder::new(&mut buf, MessageType::MethodCall).expect("enc");
        enc.set_destination(dest).expect("dest");
        enc.set_path(path).expect("path");
        if !iface.is_empty() {
            enc.set_interface(iface).expect("iface");
        }
        enc.set_member(member).expect("member");
        enc.__dbus_begin_body().expect("body");
        let len = enc.finish().expect("finish");
        buf.truncate(len);
        mini_sansio_dbus::DBusSerial::write_to_message(&mut buf, serial).expect("serial");
        buf
    }

    /// Run the SASL handshake and return the facade in the Running phase, plus the SASL reply.
    fn authed_facade() -> Facade {
        let mut f = Facade::new(wire::Bus::Session);
        let mut input = vec![0u8];
        input.extend_from_slice(b"AUTH EXTERNAL\r\nBEGIN\r\n");
        let actions = f.on_workload_bytes(&input).expect("handshake");
        // The SASL OK is written back; no message yet.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ToWorkload(b) if b.starts_with(b"OK "))));
        f
    }

    #[test]
    fn hello_is_answered_locally() {
        let mut f = authed_facade();
        let hello = method_call(BUS_DRIVER, "/org/freedesktop/DBus", BUS_DRIVER, "Hello", 1);
        let actions = f.on_workload_bytes(&hello).expect("hello");
        // Exactly one action: a MethodReturn to the workload, no conduit forward.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions.first(), Some(Action::ToWorkload(_))));
    }

    #[test]
    fn a_normal_call_is_forwarded_as_a_typed_frame() {
        let mut f = authed_facade();
        let notify = method_call(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "GetCapabilities",
            2,
        );
        let actions = f.on_workload_bytes(&notify).expect("notify");
        let call = actions
            .iter()
            .find_map(|a| match a {
                Action::ToDelegate(wire::Frame::Call(c)) => Some(c),
                _ => None,
            })
            .expect("a forwarded Call");
        assert_eq!(call.destination, "org.freedesktop.Notifications");
        assert_eq!(call.member, "GetCapabilities");
        assert_eq!(call.serial, 2);
        assert_eq!(call.bus, wire::Bus::Session);
    }

    #[test]
    fn refuse_to_broker_destination_is_refused_at_the_facade() {
        let mut f = authed_facade();
        let secrets = method_call(
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
            "OpenSession",
            3,
        );
        let actions = f.on_workload_bytes(&secrets).expect("secrets");
        // Refused locally: a ToWorkload error, never forwarded to the delegate.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions.first(), Some(Action::ToWorkload(_))));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ToDelegate(_))));
    }

    #[test]
    fn systemd1_child_paths_are_refused() {
        assert!(is_refused("org.freedesktop.systemd1"));
        assert!(is_refused("org.freedesktop.login1"));
        // A name that merely shares a prefix segment is NOT refused.
        assert!(!is_refused("org.freedesktop.secretsmanager"));
        assert!(!is_refused("org.freedesktop.Notifications"));
    }

    #[test]
    fn a_delegate_reply_is_reconstructed_to_the_workload() {
        let mut f = authed_facade();
        let reply = wire::Frame::Reply(wire::Reply {
            reply_serial: 2,
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        });
        let actions = f.on_delegate_frame(reply).expect("reply");
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions.first(), Some(Action::ToWorkload(_))));
    }

    #[test]
    fn a_call_split_across_two_reads_is_assembled() {
        let mut f = authed_facade();
        let notify = method_call(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "GetCapabilities",
            4,
        );
        let (head, tail) = notify.split_at(notify.len() / 2);
        assert!(f.on_workload_bytes(head).expect("head").is_empty());
        let actions = f.on_workload_bytes(tail).expect("tail");
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ToDelegate(wire::Frame::Call(_)))));
    }
}
