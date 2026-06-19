//! The typed `IDBus` transaction wire spoken across the facade↔delegate conduit (§7.7.2).
//!
//! `facade-dbus` parses the workload's adversarial D-Bus bytes into typed fields and
//! frames them here; `host-dbus` decodes the frame, runs the compiled allowlist over the
//! typed fields, and reconstructs a fresh D-Bus message. The conduit is a socketpair
//! kenneld mints at construction (§7.7.2a), exactly as `facade-socks5`↔`host-netproxy`.
//!
//! # Trust
//!
//! This frame is *not* the D-Bus grammar. It is a flat, length-prefixed format with a
//! handful of fields, deliberately small so the side that decodes a peer's frames has a
//! trivial parse surface. The decoder in the delegate reads frames produced by the
//! in-kennel (untrusted) facade, so [`Frame::decode`] is a trusted component parsing
//! untrusted input: it is fully bounds-checked, never panics, and is fuzzed
//! (CODING-STANDARDS §10.6). The adversarial *D-Bus* parse stays quarantined in
//! `facade-dbus`; only typed fields cross the conduit.
//!
//! This codec lives in `kennel-lib-binder` (the node-0 service wire) rather than the D-Bus
//! engine crate because the conduit frame is the `DBUS_SEND` node-0 transaction payload:
//! kenneld frames, rate-limits, and relays it, so it must be reachable from the daemon — and
//! it is pure data, so the marshaller (`mini-sansio-dbus`) never follows it into the TCB.
//!
//! # Layout
//!
//! Every frame is `[u32 len][u8 tag][payload]`, `len` counting `tag`+`payload` (big-endian,
//! matching the binder service wire's convention). A string is `[u32 len][UTF-8 bytes]`; a
//! body is `[u32 len][bytes]` preceded by its one-byte D-Bus endianness flag (`b'l'`/`b'B'`),
//! which the delegate preserves when it copies the body into the reconstructed message. Field
//! lengths are bounded ([`MAX_NAME`], [`MAX_PATH`], [`MAX_BODY`]); anything larger is a decode
//! error, not an allocation.

/// Which bus a transaction targets. The numeric values are internal-stable (both ends
/// ship from one release), mirroring the `[dbus]` `session`/`system` split (§7.7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    /// The session bus (`session.enabled`).
    Session,
    /// The system bus (`system.enabled`).
    System,
}

impl Bus {
    const SESSION: u8 = 0;
    const SYSTEM: u8 = 1;

    const fn from_u8(b: u8) -> Result<Self, WireError> {
        match b {
            Self::SESSION => Ok(Self::Session),
            Self::SYSTEM => Ok(Self::System),
            _ => Err(WireError::BadBus),
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::Session => Self::SESSION,
            Self::System => Self::SYSTEM,
        }
    }
}

/// The largest a D-Bus name field (bus name / interface / member) may be. The D-Bus
/// spec caps names at 255 bytes; we use it as a hard bound on every short string.
pub const MAX_NAME: usize = 255;
/// The largest object path / error message we frame. Paths have no spec maximum but are
/// not large in practice; 4 KiB is generous and bounded.
pub const MAX_PATH: usize = 4096;
/// The largest message body we forward across the conduit. The D-Bus spec allows 128 MiB;
/// a kennel's mediated calls are small, so we cap far lower to bound conduit allocation.
pub const MAX_BODY: usize = 1024 * 1024;
/// The largest whole frame, so a corrupt length prefix cannot drive an allocation.
pub const MAX_FRAME: usize = MAX_BODY + 64 * 1024;

// Frame tags.
const TAG_CALL: u8 = 0x01;
const TAG_REPLY: u8 = 0x02;
const TAG_ERROR: u8 = 0x03;
const TAG_SIGNAL: u8 = 0x04;

/// A typed transaction crossing the conduit.
///
/// Outbound ([`Frame::Call`]) flows facade→delegate; the rest flow delegate→facade
/// (§7.7.4: outbound and inbound are different paths — only the outbound call is
/// reconstructed and sent to the bus).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A method call to mediate (facade→delegate). The delegate matches the typed fields
    /// against the compiled allowlist and, on a pass, reconstructs and sends it.
    Call(Call),
    /// A reply to an approved call (delegate→facade), matched back by `reply_serial`.
    Reply(Reply),
    /// An error reply (delegate→facade) — a bus error or the delegate's own
    /// `org.freedesktop.DBus.Error.AccessDenied` for a denied call.
    Error(ErrorReply),
    /// An allowlisted inbound signal (delegate→facade), re-emitted to the workload.
    Signal(Signal),
}

/// A mediated method call's typed fields (§7.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The bus the call targets.
    pub bus: Bus,
    /// The kennel-side serial (the facade's namespace; the delegate maps it to a fresh
    /// bus serial and records the pairing for the reply, §7.7.2b).
    pub serial: u32,
    /// The `NO_REPLY_EXPECTED` header flag: no reply frame is owed for this call.
    pub no_reply: bool,
    /// Destination bus name (e.g. `org.freedesktop.Notifications`). Required for a call.
    pub destination: String,
    /// Object path (e.g. `/org/freedesktop/Notifications`).
    pub path: String,
    /// Interface (e.g. `org.freedesktop.Notifications`). May be empty (some calls omit it).
    pub interface: String,
    /// Member (the method name, e.g. `Notify`).
    pub member: String,
    /// Body signature (e.g. `susssasa{sv}i`). Empty for a no-argument call.
    pub signature: String,
    /// The source message's D-Bus endianness flag (`b'l'` little, `b'B'` big), preserved
    /// so the delegate can copy the body verbatim into the reconstructed message.
    pub body_endian: u8,
    /// The marshalled body bytes, opaque to mediation (the decision is on the header
    /// fields above, §7.7.3); forwarded as data.
    pub body: Vec<u8>,
}

/// A successful reply's body (delegate→facade).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The kennel serial of the call this replies to.
    pub reply_serial: u32,
    /// The reply body signature.
    pub signature: String,
    /// The reply body's endianness flag.
    pub body_endian: u8,
    /// The reply body bytes (handed to the workload as data).
    pub body: Vec<u8>,
}

/// An error reply (delegate→facade).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReply {
    /// The kennel serial of the call this errors.
    pub reply_serial: u32,
    /// The D-Bus error name (e.g. `org.freedesktop.DBus.Error.AccessDenied`).
    pub name: String,
    /// A human-readable error message (may be empty).
    pub message: String,
}

/// An allowlisted inbound signal (delegate→facade).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// The bus the signal arrived on.
    pub bus: Bus,
    /// Object path of the emitting object.
    pub path: String,
    /// Interface the signal belongs to.
    pub interface: String,
    /// Member (the signal name).
    pub member: String,
    /// Body signature.
    pub signature: String,
    /// Body endianness flag.
    pub body_endian: u8,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// A frame decode/encode failure. Every variant is a clean refusal — the decoder never
/// panics or over-reads on a malformed frame from the untrusted peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before the field being read completed.
    Truncated,
    /// A length prefix exceeds the field's bound ([`MAX_NAME`]/[`MAX_PATH`]/[`MAX_BODY`]/[`MAX_FRAME`]).
    TooLong,
    /// A string field was not valid UTF-8.
    NotUtf8,
    /// An unknown frame tag byte.
    BadTag,
    /// An out-of-range [`Bus`] discriminant.
    BadBus,
    /// Trailing bytes remained after the frame's declared length.
    Trailing,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Truncated => "truncated IDBus frame",
            Self::TooLong => "IDBus frame field exceeds its bound",
            Self::NotUtf8 => "non-UTF-8 string in IDBus frame",
            Self::BadTag => "unknown IDBus frame tag",
            Self::BadBus => "unknown IDBus bus discriminant",
            Self::Trailing => "trailing bytes after IDBus frame",
        };
        f.write_str(s)
    }
}

impl core::error::Error for WireError {}

impl Frame {
    /// Encode the frame, including the outer `[u32 len]` conduit prefix, ready to write.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(64);
        match self {
            Self::Call(c) => {
                body.push(TAG_CALL);
                body.push(c.bus.to_u8());
                body.push(u8::from(c.no_reply));
                body.extend_from_slice(&c.serial.to_be_bytes());
                put_str(&mut body, &c.destination);
                put_str(&mut body, &c.path);
                put_str(&mut body, &c.interface);
                put_str(&mut body, &c.member);
                put_str(&mut body, &c.signature);
                body.push(c.body_endian);
                put_bytes(&mut body, &c.body);
            }
            Self::Reply(r) => {
                body.push(TAG_REPLY);
                body.extend_from_slice(&r.reply_serial.to_be_bytes());
                put_str(&mut body, &r.signature);
                body.push(r.body_endian);
                put_bytes(&mut body, &r.body);
            }
            Self::Error(e) => {
                body.push(TAG_ERROR);
                body.extend_from_slice(&e.reply_serial.to_be_bytes());
                put_str(&mut body, &e.name);
                put_str(&mut body, &e.message);
            }
            Self::Signal(s) => {
                body.push(TAG_SIGNAL);
                body.push(s.bus.to_u8());
                put_str(&mut body, &s.path);
                put_str(&mut body, &s.interface);
                put_str(&mut body, &s.member);
                put_str(&mut body, &s.signature);
                body.push(s.body_endian);
                put_bytes(&mut body, &s.body);
            }
        }
        let mut out = Vec::with_capacity(body.len().saturating_add(4));
        // The outer length prefix is bounded by construction (bodies are capped before
        // they reach here); a peer's *decode* re-checks the bound.
        put_len(&mut out, body.len());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one frame's payload — the bytes *after* the outer `[u32 len]` prefix, exactly
    /// `len` of them (see [`frame_len`] for reading the prefix off a stream).
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for any malformed input; never panics or over-reads.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut cur = Cursor::new(buf);
        let tag = cur.u8()?;
        let frame = match tag {
            TAG_CALL => Self::Call(Call {
                bus: Bus::from_u8(cur.u8()?)?,
                no_reply: cur.u8()? != 0,
                serial: cur.u32()?,
                destination: cur.str(MAX_NAME)?,
                path: cur.str(MAX_PATH)?,
                interface: cur.str(MAX_NAME)?,
                member: cur.str(MAX_NAME)?,
                signature: cur.str(MAX_NAME)?,
                body_endian: cur.u8()?,
                body: cur.bytes(MAX_BODY)?,
            }),
            TAG_REPLY => Self::Reply(Reply {
                reply_serial: cur.u32()?,
                signature: cur.str(MAX_NAME)?,
                body_endian: cur.u8()?,
                body: cur.bytes(MAX_BODY)?,
            }),
            TAG_ERROR => Self::Error(ErrorReply {
                reply_serial: cur.u32()?,
                name: cur.str(MAX_NAME)?,
                message: cur.str(MAX_PATH)?,
            }),
            TAG_SIGNAL => Self::Signal(Signal {
                bus: Bus::from_u8(cur.u8()?)?,
                path: cur.str(MAX_PATH)?,
                interface: cur.str(MAX_NAME)?,
                member: cur.str(MAX_NAME)?,
                signature: cur.str(MAX_NAME)?,
                body_endian: cur.u8()?,
                body: cur.bytes(MAX_BODY)?,
            }),
            _ => return Err(WireError::BadTag),
        };
        if cur.remaining() != 0 {
            return Err(WireError::Trailing);
        }
        Ok(frame)
    }
}

/// Read the outer `[u32 len]` prefix from the front of `buf`.
///
/// Returns the declared payload length if the prefix is present and within [`MAX_FRAME`].
/// `Ok(None)` means fewer than 4 bytes are buffered yet (read more); `Err(TooLong)` rejects
/// an over-large declaration before any allocation.
///
/// # Errors
///
/// [`WireError::TooLong`] if the declared length exceeds [`MAX_FRAME`].
pub fn frame_len(buf: &[u8]) -> Result<Option<usize>, WireError> {
    let Some(prefix) = buf.get(..4) else {
        return Ok(None);
    };
    let array = <[u8; 4]>::try_from(prefix).map_err(|_| WireError::Truncated)?;
    let len = u32::from_be_bytes(array) as usize;
    if len > MAX_FRAME {
        return Err(WireError::TooLong);
    }
    Ok(Some(len))
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_len(out, b.len());
    out.extend_from_slice(b);
}

/// Write a `u32` length prefix. Lengths are bounded well under `u32::MAX` by construction;
/// the saturating conversion cannot truncate, and an (impossible) over-long value would be
/// rejected by the peer's bound check rather than silently wrapping.
fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
}

/// A bounds-checked forward reader over a frame payload.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::TooLong)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        let b = self.take(1)?;
        b.first().copied().ok_or(WireError::Truncated)
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        let array = <[u8; 4]>::try_from(b).map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(array))
    }

    fn len_prefixed(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(WireError::TooLong);
        }
        self.take(n)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        Ok(self.len_prefixed(max)?.to_vec())
    }

    /// Take all remaining bytes (used for a record's trailing inner frame).
    fn rest(&mut self) -> &'a [u8] {
        let r = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        r
    }

    fn str(&mut self, max: usize) -> Result<String, WireError> {
        let b = self.len_prefixed(max)?;
        core::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| WireError::NotUtf8)
    }
}

// Record tags on the kenneld↔host-dbus relay pipe.
const REC_OPEN: u8 = 0x01;
const REC_FRAME: u8 = 0x02;
const REC_CLOSE: u8 = 0x03;

/// A record on the owner-only kenneld↔host-dbus relay pipe (§7.7.2a).
///
/// kenneld is the membrane: it never hands the kennel a raw channel to `host-dbus`, only relays
/// these records over its own owner-only pipe. kenneld writes [`Record::Open`] (a new connection,
/// with its bus), [`Record::Frame`] (a workload `DBUS_SEND`, relayed opaquely — kenneld does not
/// re-encode the inner TLV), and [`Record::Close`]; `host-dbus` writes [`Record::Frame`] back (a
/// reply/error/signal). Each record is length-prefixed for the byte stream, with the same
/// `[u32 len][u8 tag][payload]` shape and bounds as [`Frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A workload bus connection opened on `bus`; `host-dbus` allocates its delegate state.
    Open {
        /// The facade-allocated connection id this record concerns.
        conn_id: u32,
        /// The bus the connection targets.
        bus: Bus,
    },
    /// One relayed `IDBus` TLV frame (the inner `frame` bytes are an encoded [`Frame`]).
    Frame {
        /// The connection the frame belongs to.
        conn_id: u32,
        /// The encoded [`Frame`] bytes, relayed verbatim.
        frame: Vec<u8>,
    },
    /// A workload bus connection closed; `host-dbus` releases its serial map for it.
    Close {
        /// The connection torn down.
        conn_id: u32,
    },
}

impl Record {
    /// Encode the record, including the outer `[u32 len]` pipe prefix.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(16);
        match self {
            Self::Open { conn_id, bus } => {
                body.push(REC_OPEN);
                body.extend_from_slice(&conn_id.to_be_bytes());
                body.push(bus.to_u8());
            }
            Self::Frame { conn_id, frame } => {
                body.push(REC_FRAME);
                body.extend_from_slice(&conn_id.to_be_bytes());
                body.extend_from_slice(frame);
            }
            Self::Close { conn_id } => {
                body.push(REC_CLOSE);
                body.extend_from_slice(&conn_id.to_be_bytes());
            }
        }
        let mut out = Vec::with_capacity(body.len().saturating_add(4));
        put_len(&mut out, body.len());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one record's payload — the bytes after the outer `[u32 len]` prefix (see
    /// [`frame_len`], which reads the prefix the same way for both records and frames).
    ///
    /// # Errors
    ///
    /// [`WireError`] for any malformed input; never panics or over-reads.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut cur = Cursor::new(buf);
        let rec = match cur.u8()? {
            REC_OPEN => Self::Open {
                conn_id: cur.u32()?,
                bus: Bus::from_u8(cur.u8()?)?,
            },
            REC_FRAME => Self::Frame {
                conn_id: cur.u32()?,
                // The remaining bytes are the inner encoded frame; bound them like a body.
                frame: {
                    let rest = cur.rest();
                    if rest.len() > MAX_FRAME {
                        return Err(WireError::TooLong);
                    }
                    rest.to_vec()
                },
            },
            REC_CLOSE => Self::Close {
                conn_id: cur.u32()?,
            },
            _ => return Err(WireError::BadTag),
        };
        // Frame consumed the remainder; Open/Close must have no trailing bytes.
        if !matches!(rec, Self::Frame { .. }) && cur.remaining() != 0 {
            return Err(WireError::Trailing);
        }
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frame payload — the bytes after the outer 4-byte length prefix.
    fn payload(bytes: &[u8]) -> &[u8] {
        bytes.get(4..).expect("a frame is at least its length prefix")
    }

    fn sample_call() -> Call {
        Call {
            bus: Bus::Session,
            serial: 0x0102_0304,
            no_reply: false,
            destination: "org.freedesktop.Notifications".to_owned(),
            path: "/org/freedesktop/Notifications".to_owned(),
            interface: "org.freedesktop.Notifications".to_owned(),
            member: "Notify".to_owned(),
            signature: "susssasa{sv}i".to_owned(),
            body_endian: b'l',
            body: vec![1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn call_round_trips() {
        let f = Frame::Call(sample_call());
        let bytes = f.encode();
        let len = frame_len(&bytes).expect("len ok").expect("present");
        assert_eq!(len, bytes.len().saturating_sub(4));
        assert_eq!(Frame::decode(payload(&bytes)).expect("decode"), f);
    }

    #[test]
    fn every_variant_round_trips() {
        let frames = [
            Frame::Call(sample_call()),
            Frame::Call(Call {
                no_reply: true,
                interface: String::new(),
                signature: String::new(),
                body: Vec::new(),
                ..sample_call()
            }),
            Frame::Reply(Reply {
                reply_serial: 7,
                signature: "s".to_owned(),
                body_endian: b'B',
                body: vec![0, 0, 0, 2, b'h', b'i'],
            }),
            Frame::Error(ErrorReply {
                reply_serial: 7,
                name: "org.freedesktop.DBus.Error.AccessDenied".to_owned(),
                message: "policy denied org.freedesktop.UDisks2".to_owned(),
            }),
            Frame::Signal(Signal {
                bus: Bus::System,
                path: "/org/freedesktop/Notifications".to_owned(),
                interface: "org.freedesktop.Notifications".to_owned(),
                member: "NotificationClosed".to_owned(),
                signature: "uu".to_owned(),
                body_endian: b'l',
                body: vec![1, 0, 0, 0, 2, 0, 0, 0],
            }),
        ];
        for f in frames {
            let bytes = f.encode();
            assert_eq!(Frame::decode(payload(&bytes)).expect("decode"), f);
        }
    }

    #[test]
    fn truncations_never_panic_and_error_cleanly() {
        let bytes = Frame::Call(sample_call()).encode();
        let body = payload(&bytes);
        for cut in 0..body.len() {
            // Any prefix of the payload must decode-error, not panic.
            let _ = Frame::decode(body.get(..cut).expect("prefix in range"));
        }
        // The full payload still decodes.
        assert!(Frame::decode(body).is_ok());
    }

    #[test]
    fn over_long_length_prefix_is_rejected_before_allocation() {
        // A body length prefix of u32::MAX must be TooLong, not an OOM attempt.
        let mut payload = vec![TAG_REPLY];
        payload.extend_from_slice(&9u32.to_be_bytes()); // reply_serial
        put_str(&mut payload, ""); // signature
        payload.push(b'l'); // endian
        payload.extend_from_slice(&u32::MAX.to_be_bytes()); // body len = 4 GiB
        assert_eq!(Frame::decode(&payload), Err(WireError::TooLong));
    }

    #[test]
    fn frame_len_rejects_oversize_and_waits_on_short_prefix() {
        assert_eq!(frame_len(&[0, 0]).expect("short ok"), None);
        let over = u32::try_from(MAX_FRAME).expect("fits u32").saturating_add(1);
        let mut huge = over.to_be_bytes().to_vec();
        huge.push(0);
        assert_eq!(frame_len(&huge), Err(WireError::TooLong));
    }

    #[test]
    fn records_round_trip() {
        let records = [
            Record::Open {
                conn_id: 7,
                bus: Bus::Session,
            },
            Record::Frame {
                conn_id: 42,
                frame: Frame::Call(sample_call()).encode(),
            },
            Record::Close { conn_id: 7 },
        ];
        for r in records {
            let bytes = r.encode();
            let len = frame_len(&bytes).expect("len ok").expect("present");
            assert_eq!(len, bytes.len().saturating_sub(4));
            assert_eq!(Record::decode(payload(&bytes)).expect("decode"), r);
        }
    }

    #[test]
    fn record_truncations_never_panic() {
        let bytes = Record::Frame {
            conn_id: 1,
            frame: Frame::Call(sample_call()).encode(),
        }
        .encode();
        let body = payload(&bytes);
        for cut in 0..body.len() {
            let _ = Record::decode(body.get(..cut).expect("prefix"));
        }
        assert!(Record::decode(body).is_ok());
    }

    #[test]
    fn bad_tag_and_trailing_bytes_are_errors() {
        assert_eq!(Frame::decode(&[0xfe]), Err(WireError::BadTag));
        let mut bytes = Frame::Error(ErrorReply {
            reply_serial: 1,
            name: "x".to_owned(),
            message: String::new(),
        })
        .encode();
        bytes.push(0x00); // trailing junk past the declared payload
        assert_eq!(Frame::decode(payload(&bytes)), Err(WireError::Trailing));
    }
}
