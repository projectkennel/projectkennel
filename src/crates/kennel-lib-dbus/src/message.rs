//! Reconstruction: a vetted typed frame ([`crate::wire`]) → a fresh, well-formed D-Bus
//! message (§7.7.3).
//!
//! This is the "reconstruct, never forward raw bytes" half of the mediation. `host-dbus`
//! turns an approved [`wire::Call`] into a `MethodCall` it sends to the real bus;
//! `facade-dbus` turns a [`wire::Reply`]/[`wire::ErrorReply`]/[`wire::Signal`] from the
//! delegate into the `MethodReturn`/`Error`/`Signal` it hands the workload. In every case the
//! header is built fresh from the typed fields (`mini-sansio-dbus`'s encoder, which emits
//! little-endian), and the message **body** is copied verbatim — the body is method
//! *arguments* (opaque data, §7.7.3), not a protocol surface trusted code must parse; the
//! decision was made on the header fields. The body copies byte-for-byte because the encoder
//! emits little-endian and a D-Bus body is 8-aligned in both the source and the reconstruction.
//!
//! Big-endian source bodies (rare — libdbus/sd-bus default to native, little-endian on every
//! supported target) cannot be copied verbatim into a little-endian message and are refused
//! ([`MessageError::BigEndianBody`]) pending transcoding.

use mini_sansio_dbus::{DBusSerial, EncodeError, MessageType, SliceMessageEncoder};

use crate::wire;

/// A reconstruction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// The source body is big-endian; verbatim copy into a little-endian message is not yet
    /// supported (the body would need transcoding against its signature).
    BigEndianBody,
    /// A message buffer was too short or self-inconsistent to locate its body (only seen on
    /// a message that did not come from the validating decoder).
    Framing,
    /// The encoder rejected the message (field too long, buffer exhausted, …).
    Encode(EncodeError),
}

impl From<EncodeError> for MessageError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BigEndianBody => f.write_str("big-endian D-Bus body is not yet supported"),
            Self::Framing => f.write_str("malformed D-Bus message framing"),
            Self::Encode(e) => write!(f, "D-Bus encode error: {e}"),
        }
    }
}

impl core::error::Error for MessageError {}

/// The little-endian flag the encoder emits and the only body endianness we copy verbatim.
const LE: u8 = b'l';

/// A header string field to set if non-empty.
struct Field<'a>(Option<&'a str>);

/// Reconstruct an approved method call as a `MethodCall` for the real bus.
///
/// `serial` is the sender's own serial for this message (the delegate's namespace). `sender`
/// is left unset — the bus assigns it. An empty `interface` is omitted (legal for a call).
///
/// # Errors
///
/// [`MessageError`] if the body is big-endian or the encoder rejects a field.
pub fn reconstruct_call(call: &wire::Call, serial: u32) -> Result<Vec<u8>, MessageError> {
    build(&Spec {
        ty: MessageType::MethodCall,
        serial,
        destination: Field(Some(&call.destination)),
        path: Field(non_empty(&call.path)),
        interface: Field(non_empty(&call.interface)),
        member: Field(non_empty(&call.member)),
        error_name: Field(None),
        reply_serial: None,
        signature: &call.signature,
        body_endian: call.body_endian,
        body: &call.body,
    })
}

/// Reconstruct a successful reply as a `MethodReturn` for the workload.
///
/// `serial` is the facade's own serial; `reply_serial` is the workload call this answers;
/// `destination` is the workload's unique name (or `None`).
///
/// # Errors
///
/// [`MessageError`] if the body is big-endian or the encoder rejects a field.
pub fn reconstruct_return(
    reply: &wire::Reply,
    serial: u32,
    destination: Option<&str>,
) -> Result<Vec<u8>, MessageError> {
    build(&Spec {
        ty: MessageType::MethodReturn,
        serial,
        destination: Field(destination),
        path: Field(None),
        interface: Field(None),
        member: Field(None),
        error_name: Field(None),
        reply_serial: Some(reply.reply_serial),
        signature: &reply.signature,
        body_endian: reply.body_endian,
        body: &reply.body,
    })
}

/// Reconstruct an error reply as an `Error` message for the workload.
///
/// The human-readable `message` becomes the standard single-string error body (signature
/// `s`), marshalled freshly (not copied), so it carries no endianness constraint.
///
/// # Errors
///
/// [`MessageError`] if the encoder rejects a field.
pub fn reconstruct_error(
    err: &wire::ErrorReply,
    serial: u32,
    destination: Option<&str>,
) -> Result<Vec<u8>, MessageError> {
    let cap = 256usize
        .saturating_add(err.name.len())
        .saturating_add(err.message.len());
    let mut buf = vec![0u8; cap];
    let mut enc = SliceMessageEncoder::new(&mut buf, MessageType::Error)?;
    enc.set_error_name(&err.name)?;
    enc.set_reply_serial(err.reply_serial)?;
    if let Some(d) = destination {
        enc.set_destination(d)?;
    }
    if err.message.is_empty() {
        enc.__dbus_begin_body()?;
    } else {
        enc.set_body_signature("s")?;
        enc.__dbus_begin_body()?;
        enc.__dbus_write_string_like(&err.message)?;
    }
    let len = enc.finish()?;
    buf.truncate(len);
    DBusSerial::write_to_message(&mut buf, serial)?;
    Ok(buf)
}

/// Reconstruct an allowlisted inbound signal as a `Signal` message for the workload.
///
/// # Errors
///
/// [`MessageError`] if the body is big-endian or the encoder rejects a field.
pub fn reconstruct_signal(sig: &wire::Signal, serial: u32) -> Result<Vec<u8>, MessageError> {
    build(&Spec {
        ty: MessageType::Signal,
        serial,
        destination: Field(None),
        path: Field(non_empty(&sig.path)),
        interface: Field(non_empty(&sig.interface)),
        member: Field(non_empty(&sig.member)),
        error_name: Field(None),
        reply_serial: None,
        signature: &sig.signature,
        body_endian: sig.body_endian,
        body: &sig.body,
    })
}

/// The raw marshalled body of an already-decoded D-Bus message: its endianness flag and the
/// body byte slice, with no re-marshalling.
///
/// `mini-sansio-dbus` exposes typed header fields and an iterator over body *values*, but not
/// the raw body bytes the facade must forward verbatim (§7.7.3). The fixed D-Bus header
/// records the body length (`message[4..8]`) and the header-fields length (`message[12..16]`),
/// from which the body offset (`align8(16 + header_fields_len)`) and extent follow. `message`
/// is a complete message the decoder already validated; this only relocates the body slice.
///
/// # Errors
///
/// [`MessageError::Framing`] if the buffer is too short or the lengths overflow its bounds.
pub fn body_slice(message: &[u8]) -> Result<(u8, &[u8]), MessageError> {
    let head = message.get(..16).ok_or(MessageError::Framing)?;
    let endian = *head.first().ok_or(MessageError::Framing)?;
    let read_u32 = |off: usize| -> Result<usize, MessageError> {
        let end = off.checked_add(4).ok_or(MessageError::Framing)?;
        let b = message.get(off..end).ok_or(MessageError::Framing)?;
        let array = <[u8; 4]>::try_from(b).map_err(|_| MessageError::Framing)?;
        let v = match endian {
            b'B' => u32::from_be_bytes(array),
            // Default (and `b'l'`): little-endian, what every supported client emits.
            _ => u32::from_le_bytes(array),
        };
        Ok(v as usize)
    };
    let body_len = read_u32(4)?;
    let header_fields_len = read_u32(12)?;
    let after_fields = 16usize
        .checked_add(header_fields_len)
        .ok_or(MessageError::Framing)?;
    let body_offset = after_fields
        .checked_next_multiple_of(8)
        .ok_or(MessageError::Framing)?;
    let body_end = body_offset
        .checked_add(body_len)
        .ok_or(MessageError::Framing)?;
    let body = message
        .get(body_offset..body_end)
        .ok_or(MessageError::Framing)?;
    Ok((endian, body))
}

/// Marshal a single D-Bus string as a little-endian message body (signature `s`).
///
/// A 4-byte length, the UTF-8 bytes, and a NUL terminator. The body starts 8-aligned in a
/// message, so the string's 4-byte alignment is already satisfied. Used for the facade's local
/// replies (e.g. `Hello` returning the assigned unique name) that it answers without the bus.
#[must_use]
pub fn marshal_string(s: &str) -> Vec<u8> {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    let mut body = Vec::with_capacity(s.len().saturating_add(5));
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(s.as_bytes());
    body.push(0);
    body
}

/// The fields of a message to build with a verbatim-copied body.
struct Spec<'a> {
    ty: MessageType,
    serial: u32,
    destination: Field<'a>,
    path: Field<'a>,
    interface: Field<'a>,
    member: Field<'a>,
    error_name: Field<'a>,
    reply_serial: Option<u32>,
    signature: &'a str,
    body_endian: u8,
    body: &'a [u8],
}

const fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn build(spec: &Spec<'_>) -> Result<Vec<u8>, MessageError> {
    // A body can only be copied verbatim if it shares the encoder's little-endian byte order.
    if !spec.body.is_empty() && spec.body_endian != LE {
        return Err(MessageError::BigEndianBody);
    }
    // Header overhead is bounded; size generously for every field plus the body.
    let cap = 256usize
        .saturating_add(spec.signature.len())
        .saturating_add(spec.body.len())
        .saturating_add(field_len(&spec.destination))
        .saturating_add(field_len(&spec.path))
        .saturating_add(field_len(&spec.interface))
        .saturating_add(field_len(&spec.member))
        .saturating_add(field_len(&spec.error_name));
    let mut buf = vec![0u8; cap];
    let mut enc = SliceMessageEncoder::new(&mut buf, spec.ty)?;
    if let Some(d) = spec.destination.0 {
        enc.set_destination(d)?;
    }
    if let Some(p) = spec.path.0 {
        enc.set_path(p)?;
    }
    if let Some(i) = spec.interface.0 {
        enc.set_interface(i)?;
    }
    if let Some(m) = spec.member.0 {
        enc.set_member(m)?;
    }
    if let Some(n) = spec.error_name.0 {
        enc.set_error_name(n)?;
    }
    if let Some(rs) = spec.reply_serial {
        enc.set_reply_serial(rs)?;
    }
    enc.set_body_signature(spec.signature)?;
    enc.__dbus_begin_body()?;
    // Copy the body verbatim (little-endian, 8-aligned in both messages, §7.7.3).
    for &byte in spec.body {
        enc.__dbus_write_u8(byte)?;
    }
    let len = enc.finish()?;
    buf.truncate(len);
    DBusSerial::write_to_message(&mut buf, spec.serial)?;
    Ok(buf)
}

fn field_len(f: &Field<'_>) -> usize {
    // Each string header field: code + variant sig + length-prefixed string + alignment.
    f.0.map_or(0, |s| s.len().saturating_add(16))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mini_sansio_dbus::{DBusConnection, OutgoingQueue};

    /// A no-op outgoing queue so `DBusConnection::wants` can report read-readiness while we
    /// feed it a reconstructed message to re-parse.
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

    /// Drive a complete message buffer through the real decoder and return the parsed fields
    /// as owned strings — the round-trip oracle for reconstruction.
    struct Parsed {
        ty: MessageType,
        serial: u32,
        destination: Option<String>,
        path: Option<String>,
        interface: Option<String>,
        member: Option<String>,
        error_name: Option<String>,
        reply_serial: Option<u32>,
        signature: Option<String>,
    }

    /// Parse a complete message's header fields. Body fidelity is checked separately by
    /// [`first_body_u32`], which decodes a known body value back out.
    fn parse(message: &[u8]) -> Parsed {
        let mut conn = DBusConnection::new(0);
        let queue = NoQueue;
        let mut readbuf = vec![0u8; message.len().saturating_add(16)];
        let mut pos = 0usize;
        loop {
            let avail = message.len().saturating_sub(pos);
            assert!(avail > 0, "decoder did not complete the message");
            let n;
            {
                let (read, _w) = conn.wants(&queue, &mut readbuf).expect("wants");
                let want = read.buf.len();
                n = want.min(avail);
                let end = pos.saturating_add(n);
                read.buf
                    .get_mut(..n)
                    .expect("fits")
                    .copy_from_slice(message.get(pos..end).expect("in range"));
            }
            pos = pos.saturating_add(n);
            if let Some(msg) = conn.satisfy_read(n, &readbuf).expect("decode") {
                return Parsed {
                    ty: msg.message_type,
                    serial: msg.serial,
                    destination: msg.destination.map(str::to_owned),
                    path: msg.path.map(str::to_owned),
                    interface: msg.interface.map(str::to_owned),
                    member: msg.member.map(str::to_owned),
                    error_name: msg.error_name.map(str::to_owned),
                    reply_serial: msg.reply_serial,
                    signature: msg.signature.map(str::to_owned),
                };
            }
        }
    }

    fn sample_call() -> wire::Call {
        wire::Call {
            bus: wire::Bus::Session,
            serial: 1,
            no_reply: false,
            destination: "org.freedesktop.Notifications".to_owned(),
            path: "/org/freedesktop/Notifications".to_owned(),
            interface: "org.freedesktop.Notifications".to_owned(),
            member: "GetCapabilities".to_owned(),
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        }
    }

    #[test]
    fn call_reconstructs_with_stable_header_fields() {
        let call = sample_call();
        let bytes = reconstruct_call(&call, 42).expect("reconstruct");
        let p = parse(&bytes);
        assert_eq!(p.ty, MessageType::MethodCall);
        assert_eq!(p.serial, 42);
        assert_eq!(p.destination.as_deref(), Some(call.destination.as_str()));
        assert_eq!(p.path.as_deref(), Some(call.path.as_str()));
        assert_eq!(p.interface.as_deref(), Some(call.interface.as_str()));
        assert_eq!(p.member.as_deref(), Some(call.member.as_str()));
    }

    #[test]
    fn call_with_no_interface_is_legal() {
        let mut call = sample_call();
        call.interface = String::new();
        let bytes = reconstruct_call(&call, 7).expect("reconstruct");
        let p = parse(&bytes);
        assert_eq!(p.interface, None);
        assert_eq!(p.member.as_deref(), Some("GetCapabilities"));
    }

    #[test]
    fn return_carries_reply_serial() {
        let reply = wire::Reply {
            reply_serial: 99,
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        };
        let bytes = reconstruct_return(&reply, 3, Some(":1.5")).expect("reconstruct");
        let p = parse(&bytes);
        assert_eq!(p.ty, MessageType::MethodReturn);
        assert_eq!(p.reply_serial, Some(99));
        assert_eq!(p.destination.as_deref(), Some(":1.5"));
    }

    #[test]
    fn error_carries_name_and_reply_serial() {
        let err = wire::ErrorReply {
            reply_serial: 12,
            name: "org.freedesktop.DBus.Error.AccessDenied".to_owned(),
            message: "policy denied org.freedesktop.UDisks2".to_owned(),
        };
        let bytes = reconstruct_error(&err, 4, Some(":1.5")).expect("reconstruct");
        let p = parse(&bytes);
        assert_eq!(p.ty, MessageType::Error);
        assert_eq!(p.error_name.as_deref(), Some(err.name.as_str()));
        assert_eq!(p.reply_serial, Some(12));
        assert_eq!(p.signature.as_deref(), Some("s"));
    }

    #[test]
    fn signal_reconstructs() {
        let sig = wire::Signal {
            bus: wire::Bus::Session,
            path: "/org/freedesktop/Notifications".to_owned(),
            interface: "org.freedesktop.Notifications".to_owned(),
            member: "NotificationClosed".to_owned(),
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        };
        let bytes = reconstruct_signal(&sig, 8).expect("reconstruct");
        let p = parse(&bytes);
        assert_eq!(p.ty, MessageType::Signal);
        assert_eq!(p.member.as_deref(), Some("NotificationClosed"));
    }

    /// Decode the first body value of `message` as a `u32` — proves the copied body bytes
    /// land at the right (8-aligned) offset and decode to the original value.
    fn first_body_u32(message: &[u8]) -> Option<u32> {
        use mini_sansio_dbus::IncomingValue;
        let mut conn = DBusConnection::new(0);
        let queue = NoQueue;
        let mut readbuf = vec![0u8; message.len().saturating_add(16)];
        let mut pos = 0usize;
        loop {
            let avail = message.len().saturating_sub(pos);
            assert!(avail > 0, "decoder did not complete");
            let n;
            {
                let (read, _w) = conn.wants(&queue, &mut readbuf).expect("wants");
                n = read.buf.len().min(avail);
                let end = pos.saturating_add(n);
                read.buf
                    .get_mut(..n)
                    .expect("fits")
                    .copy_from_slice(message.get(pos..end).expect("in range"));
            }
            pos = pos.saturating_add(n);
            if let Some(msg) = conn.satisfy_read(n, &readbuf).expect("decode") {
                let value = msg.body?.try_next().expect("value").expect("present");
                return if let IncomingValue::UInt32(v) = value {
                    Some(v)
                } else {
                    None
                };
            }
        }
    }

    #[test]
    fn body_bytes_are_copied_verbatim() {
        // A little-endian `u32` body of 0x2A; reconstruct, re-parse, and the value survives —
        // i.e. the body bytes were copied to the right offset with the right alignment.
        let mut call = sample_call();
        call.signature = "u".to_owned();
        call.body_endian = b'l';
        call.body = 0x2Au32.to_le_bytes().to_vec();
        let bytes = reconstruct_call(&call, 5).expect("reconstruct");
        assert_eq!(first_body_u32(&bytes), Some(0x2A));
    }

    #[test]
    fn body_slice_recovers_the_reconstructed_body() {
        // Reconstruct a call with a known little-endian u32 body, then recover the raw body
        // bytes — body_slice must return exactly what reconstruct copied in (the round trip
        // facade-dbus relies on to forward a call's arguments verbatim).
        let mut call = sample_call();
        call.signature = "u".to_owned();
        call.body = 0xDEAD_BEEFu32.to_le_bytes().to_vec();
        let bytes = reconstruct_call(&call, 9).expect("reconstruct");
        let (endian, body) = body_slice(&bytes).expect("body slice");
        assert_eq!(endian, b'l');
        assert_eq!(body, call.body.as_slice());
    }

    #[test]
    fn body_slice_of_empty_body_is_empty() {
        let bytes = reconstruct_call(&sample_call(), 1).expect("reconstruct");
        let (_, body) = body_slice(&bytes).expect("body slice");
        assert!(body.is_empty());
    }

    #[test]
    fn body_slice_rejects_a_truncated_message() {
        assert_eq!(body_slice(&[0u8; 4]), Err(MessageError::Framing));
    }

    #[test]
    fn big_endian_body_is_refused() {
        let mut call = sample_call();
        call.body_endian = b'B';
        call.body = vec![1, 2, 3, 4];
        call.signature = "u".to_owned();
        assert_eq!(reconstruct_call(&call, 1), Err(MessageError::BigEndianBody));
    }
}
