//! The privhelper IPC wire format: fixed-layout request/response messages.
//!
//! Per the maintainer's call, the protocol is *classic struct messages* — a
//! fixed-size byte layout, not a serialisation language (no serde/JSON/TOML).
//! The caller writes a [`Request`]'s bytes to the helper's stdin and reads a
//! [`Response`] from its stdout; the helper validates ([`crate::validate`]) and
//! performs exactly one privileged operation, then exits.
//!
//! Because the helper is `#![forbid(unsafe_code)]`, the fixed layout is packed
//! and unpacked field-by-field (no `transmute`); the wire format is nonetheless
//! the C-struct layout below. All multi-byte integers are native-endian — the
//! helper and its caller are the same machine.
//!
//! ```text
//! Request (292 bytes):
//!   0      op           u8     (1 add-addr, 2 del-addr, 3 create-cg, 4 delete-cg)
//!   1      family       u8     (4 or 6; 0 for cgroup ops)
//!   2      prefix       u8
//!   3      ctx          u8
//!   4..20  addr         [u8;16] (v4 in the first 4 bytes)
//!   20..36 interface    [u8;16] (NUL-padded; kernel IFNAMSIZ)
//!   36..292 cgroup_path [u8;256] (NUL-padded)
//!
//! Response (6 bytes):
//!   0      status       u8     (0 ok, 1 refused, 2 protocol, 3 internal)
//!   1      refusal      u8     (refusal code when status==1, else 0)
//!   2..6   errno        i32    (OS errno when status==3, else 0)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// The on-wire length of a [`Request`].
pub const REQUEST_LEN: usize = 292;
/// The on-wire length of a [`Response`].
pub const RESPONSE_LEN: usize = 6;

const INTERFACE_FIELD: usize = 16;
const PATH_FIELD: usize = 256;

/// The privileged operation a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Add a per-kennel loopback address.
    AddAddr,
    /// Remove a per-kennel loopback address.
    DelAddr,
    /// Create a per-kennel cgroup.
    CreateCgroup,
    /// Delete a per-kennel cgroup.
    DeleteCgroup,
}

impl Op {
    const fn to_byte(self) -> u8 {
        match self {
            Self::AddAddr => 1,
            Self::DelAddr => 2,
            Self::CreateCgroup => 3,
            Self::DeleteCgroup => 4,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::AddAddr),
            2 => Some(Self::DelAddr),
            3 => Some(Self::CreateCgroup),
            4 => Some(Self::DeleteCgroup),
            _ => None,
        }
    }
}

/// The outcome status of a [`Response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The operation succeeded.
    Ok,
    /// The request was refused as out of scope (see `refusal`).
    Refused,
    /// The request could not be parsed.
    Protocol,
    /// A privileged syscall failed (see `errno`).
    Internal,
}

impl Status {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Refused => 1,
            Self::Protocol => 2,
            Self::Internal => 3,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::Refused),
            2 => Some(Self::Protocol),
            3 => Some(Self::Internal),
            _ => None,
        }
    }
}

/// A parsed request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The operation.
    pub op: Op,
    /// The per-kennel context byte.
    pub ctx: u8,
    /// The address (for address ops; `0.0.0.0` is the placeholder for cgroup ops).
    pub addr: IpAddr,
    /// The subnet prefix length (for address ops).
    pub prefix: u8,
    /// The interface name (for address ops).
    pub interface: String,
    /// The cgroup path (for cgroup ops).
    pub cgroup_path: PathBuf,
}

/// A failure to decode a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer was not exactly the expected length.
    BadLength,
    /// The op byte was not a known operation.
    BadOp,
    /// The family byte was not 4 or 6.
    BadFamily,
    /// A NUL-padded string field was not valid UTF-8.
    BadString,
}

/// Copy `src` into a fresh `N`-byte NUL-padded field (truncating if longer),
/// without indexing.
fn pad_field<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut field = [0u8; N];
    for (dst, byte) in field.iter_mut().zip(src.iter()) {
        *dst = *byte;
    }
    field
}

/// Trim trailing NULs and interpret a fixed string field as UTF-8.
fn read_string(field: &[u8]) -> Result<String, WireError> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let bytes = field.get(..end).unwrap_or(&[]);
    core::str::from_utf8(bytes).map(str::to_owned).map_err(|_| WireError::BadString)
}

impl Request {
    /// Encode this request to its fixed-length wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(REQUEST_LEN);
        b.push(self.op.to_byte());
        let (family, addr16): (u8, [u8; 16]) = match self.addr {
            IpAddr::V4(a) => {
                let [o0, o1, o2, o3] = a.octets();
                (4, [o0, o1, o2, o3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            }
            IpAddr::V6(a) => (6, a.octets()),
        };
        b.push(family);
        b.push(self.prefix);
        b.push(self.ctx);
        b.extend_from_slice(&addr16);
        b.extend_from_slice(&pad_field::<INTERFACE_FIELD>(self.interface.as_bytes()));
        b.extend_from_slice(&pad_field::<PATH_FIELD>(
            self.cgroup_path.as_os_str().as_encoded_bytes(),
        ));
        b
    }

    /// Decode a request from its wire bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`WireError`] if the buffer is the wrong length, the op or
    /// family byte is invalid, or a string field is not UTF-8.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != REQUEST_LEN {
            return Err(WireError::BadLength);
        }
        let op = buf.first().copied().and_then(Op::from_byte).ok_or(WireError::BadOp)?;
        let family = buf.get(1).copied().ok_or(WireError::BadLength)?;
        let prefix = buf.get(2).copied().ok_or(WireError::BadLength)?;
        let ctx = buf.get(3).copied().ok_or(WireError::BadLength)?;
        let addr16: [u8; 16] = buf
            .get(4..20)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        let addr = match family {
            4 => {
                let v4: [u8; 4] = addr16.get(..4).and_then(|s| s.try_into().ok()).ok_or(WireError::BadLength)?;
                IpAddr::V4(Ipv4Addr::from(v4))
            }
            6 => IpAddr::V6(Ipv6Addr::from(addr16)),
            _ => return Err(WireError::BadFamily),
        };
        let interface = read_string(buf.get(20..36).ok_or(WireError::BadLength)?)?;
        let cgroup_path = PathBuf::from(read_string(buf.get(36..292).ok_or(WireError::BadLength)?)?);
        Ok(Self { op, ctx, addr, prefix, interface, cgroup_path })
    }
}

/// A response message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    /// The outcome.
    pub status: Status,
    /// The refusal code when `status` is [`Status::Refused`], else 0.
    pub refusal: u8,
    /// The OS errno when `status` is [`Status::Internal`], else 0.
    pub errno: i32,
}

impl Response {
    /// A success response.
    #[must_use]
    pub const fn ok() -> Self {
        Self { status: Status::Ok, refusal: 0, errno: 0 }
    }

    /// A refusal response carrying the refusal `code`.
    #[must_use]
    pub const fn refused(code: u8) -> Self {
        Self { status: Status::Refused, refusal: code, errno: 0 }
    }

    /// A protocol-error response.
    #[must_use]
    pub const fn protocol() -> Self {
        Self { status: Status::Protocol, refusal: 0, errno: 0 }
    }

    /// An internal-error response carrying the OS `errno`.
    #[must_use]
    pub const fn internal(errno: i32) -> Self {
        Self { status: Status::Internal, refusal: 0, errno }
    }

    /// Encode this response to its fixed-length wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(RESPONSE_LEN);
        b.push(self.status.to_byte());
        b.push(self.refusal);
        b.extend_from_slice(&self.errno.to_ne_bytes());
        b
    }

    /// Decode a response from its wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the buffer is the wrong length or the status is
    /// invalid.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != RESPONSE_LEN {
            return Err(WireError::BadLength);
        }
        let status = buf.first().copied().and_then(Status::from_byte).ok_or(WireError::BadOp)?;
        let refusal = buf.get(1).copied().ok_or(WireError::BadLength)?;
        let errno = buf
            .get(2..6)
            .and_then(|s| s.try_into().ok())
            .map(i32::from_ne_bytes)
            .ok_or(WireError::BadLength)?;
        Ok(Self { status, refusal, errno })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_v4() {
        let req = Request {
            op: Op::AddAddr,
            ctx: 7,
            addr: "127.7.3.1".parse().expect("v4"),
            prefix: 24,
            interface: "lo".to_owned(),
            cgroup_path: PathBuf::new(),
        };
        let bytes = req.encode();
        assert_eq!(bytes.len(), REQUEST_LEN);
        assert_eq!(Request::decode(&bytes), Ok(req));
    }

    #[test]
    fn request_round_trips_v6_and_cgroup() {
        let req = Request {
            op: Op::CreateCgroup,
            ctx: 3,
            addr: "fd00:1:2::1".parse().expect("v6"),
            prefix: 64,
            interface: "kennel-abc".to_owned(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/kennel/3"),
        };
        let bytes = req.encode();
        assert_eq!(Request::decode(&bytes), Ok(req));
    }

    #[test]
    fn response_round_trips() {
        for r in [Response::ok(), Response::refused(5), Response::protocol(), Response::internal(13)] {
            assert_eq!(Response::decode(&r.encode()), Ok(r));
        }
    }

    #[test]
    fn decode_rejects_bad_length_and_op() {
        assert_eq!(Request::decode(&[0u8; 10]), Err(WireError::BadLength));
        let mut bytes = Request {
            op: Op::AddAddr,
            ctx: 0,
            addr: "0.0.0.0".parse().expect("v4"),
            prefix: 24,
            interface: String::new(),
            cgroup_path: PathBuf::new(),
        }
        .encode();
        // Corrupt the op byte.
        if let Some(b) = bytes.first_mut() {
            *b = 99;
        }
        assert_eq!(Request::decode(&bytes), Err(WireError::BadOp));
    }
}
