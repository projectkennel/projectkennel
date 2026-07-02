//! The parent-child relay protocol: the sealed monitor's only channel outward.
//!
//! # Purpose
//!
//! `kenneld` forks once at startup into an **unsealed parent** and a **sealed
//! monitor** child (Kennel book Vol 2 ch.2 (Process and Privilege Model)). The
//! monitor installs its Landlock+seccomp seal before touching any kennel input;
//! the seal denies it direct inet, arbitrary exec, and reaching a target across
//! a mount-namespace boundary (W0 P1). The parent stays unconfined and performs
//! exactly those operations *on the monitor's behalf*, over one
//! `SOCK_SEQPACKET` socketpair held across the fork. This module is the wire
//! format of that channel: three request messages and their replies.
//!
//! The message set is held to three, deliberately — the parent is the entire
//! confinement boundary the monitor can drive, so the smaller its protocol the
//! smaller the surface a compromised monitor can push the parent across:
//!
//! - [`RelayRequest::Resolve`] — resolve a name to addresses (the parent runs
//!   `getaddrinfo`; the monitor re-checks every address under policy and pins
//!   the vetted set, so resolution moves out of the seal but the *decision* does
//!   not).
//! - [`RelayRequest::SpawnDelegate`] — exec a host delegate the monitor may not
//!   (`host-netproxy` / `host-inetd`), returning the monitor's end of its
//!   command channel as an fd.
//! - [`RelayRequest::FdRelay`] — open a per-kennel resource that lives across a
//!   mount-namespace boundary (the binder device and the mesh-bus reaches under
//!   `/proc/<pid>/root`, ungrantable to the sealed monitor by Landlock — W0 P1),
//!   returning the resolved fd. A one-time handoff: the monitor does its I/O on
//!   the fd directly afterwards.
//!
//! # Invariants
//!
//! - The parser is the trust boundary. The parent treats every request from the
//!   monitor as hostile: [`RelayRequest::decode`] validates length, tag, and
//!   every bounded field before constructing a value, and never reads past the
//!   frame. Bounds ([`MAX_NAME`], [`MAX_ADDRS`]) are enforced so a malformed
//!   length prefix cannot drive an absurd read.
//! - Fixed-layout, field-by-field encoding — no `serde`, no `transmute` (the
//!   crate is `#![forbid(unsafe_code)]`), mirroring the privhelper wire
//!   discipline. Multi-byte integers are native-endian: parent and monitor are
//!   the same machine, forked from one image.
//! - Passed file descriptors ride *beside* the frame via `SCM_RIGHTS`
//!   ([`kennel_lib_scm`]), never inside it. [`RelayResponse::expected_fds`]
//!   states how many accompany each reply so the receiver bounds its `cmsg`
//!   space.
//!
//! # Threat bearing
//!
//! Bears on the W1 self-confinement threat (a kennel breakout into a sealed
//! monitor is bounded, not total): this channel is the whole surface the monitor
//! can reach the unconfined parent through, so its adversarial-input parsing is
//! the fuzz target and its message set is minimised.
//!
//! # Non-goals
//!
//! This module does not perform the operations (that is the parent's serve
//! loop), does not fork or seal (that is startup), and does not pass fds (that
//! is [`kennel_lib_scm`]); it is only the codec.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum encoded length of a name in a [`RelayRequest::Resolve`] (DNS limit).
pub const MAX_NAME: usize = 253;

/// Defensive cap on the address count in a [`RelayResponse::Resolved`], so a
/// malformed count byte cannot drive an absurd read.
pub const MAX_ADDRS: usize = 64;

/// The request opcode (first frame byte). Private: callers use [`RelayRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Resolve,
    SpawnDelegate,
    FdRelay,
}

impl Op {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Resolve => 1,
            Self::SpawnDelegate => 2,
            Self::FdRelay => 3,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Resolve),
            2 => Some(Self::SpawnDelegate),
            3 => Some(Self::FdRelay),
            _ => None,
        }
    }
}

/// A host delegate the sealed monitor may not `exec` itself, so the parent does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateKind {
    /// The `host-netproxy` egress dial delegate.
    NetProxy,
    /// The `host-inetd` inbound BIND delegate.
    Inetd,
}

impl DelegateKind {
    const fn to_byte(self) -> u8 {
        match self {
            Self::NetProxy => 1,
            Self::Inetd => 2,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::NetProxy),
            2 => Some(Self::Inetd),
            _ => None,
        }
    }
}

/// A per-kennel resource the parent opens across a mount-namespace boundary on
/// the monitor's behalf (ungrantable to the sealed monitor by Landlock, W0 P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayResource {
    /// The kennel's binder device: `/proc/<pid>/root/dev/binderfs/binder`.
    BinderDevice,
    /// The mesh-bus binderfs device directory in the holder's mount namespace.
    MeshBusDeviceDir,
    /// The host-owned mesh rendezvous socket reached via `/proc/<pid>/root`.
    RendezvousSocket,
}

impl RelayResource {
    const fn to_byte(self) -> u8 {
        match self {
            Self::BinderDevice => 1,
            Self::MeshBusDeviceDir => 2,
            Self::RendezvousSocket => 3,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::BinderDevice),
            2 => Some(Self::MeshBusDeviceDir),
            3 => Some(Self::RendezvousSocket),
            _ => None,
        }
    }
}

/// Why the parent refused or could not satisfy a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The name did not resolve to any address.
    NotFound,
    /// The resolver backend itself failed.
    ResolveFailed,
    /// The delegate could not be spawned.
    SpawnFailed,
    /// The requested resource could not be opened.
    OpenFailed,
    /// An internal parent-side error.
    Internal,
}

impl RefusalCode {
    const fn to_byte(self) -> u8 {
        match self {
            Self::NotFound => 1,
            Self::ResolveFailed => 2,
            Self::SpawnFailed => 3,
            Self::OpenFailed => 4,
            Self::Internal => 5,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::NotFound),
            2 => Some(Self::ResolveFailed),
            3 => Some(Self::SpawnFailed),
            4 => Some(Self::OpenFailed),
            5 => Some(Self::Internal),
            _ => None,
        }
    }
}

/// A decoding failure. The parent maps this to a [`RefusalCode::Internal`]-style
/// reply and does not act on a malformed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// The frame is too short (or too long) for its tag.
    BadLength,
    /// The opcode / response tag byte is not recognised.
    BadTag,
    /// A [`DelegateKind`] byte is not recognised.
    BadKind,
    /// A [`RelayResource`] byte is not recognised.
    BadResource,
    /// A [`RefusalCode`] byte is not recognised.
    BadRefusal,
    /// An address family byte is neither 4 nor 6.
    BadFamily,
    /// A name field exceeds [`MAX_NAME`].
    NameTooLong,
    /// A name field is not valid UTF-8.
    NonUtf8Name,
    /// An address count exceeds [`MAX_ADDRS`].
    TooManyAddrs,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadLength => "frame length does not match its tag",
            Self::BadTag => "unrecognised message tag",
            Self::BadKind => "unrecognised delegate kind",
            Self::BadResource => "unrecognised relay resource",
            Self::BadRefusal => "unrecognised refusal code",
            Self::BadFamily => "address family is neither 4 nor 6",
            Self::NameTooLong => "name exceeds the maximum length",
            Self::NonUtf8Name => "name is not valid UTF-8",
            Self::TooManyAddrs => "address count exceeds the maximum",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RelayError {}

/// A request from the sealed monitor to the unconfined parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRequest {
    /// Resolve `name` to its addresses (no accompanying fd).
    Resolve {
        /// The name to resolve; bounded by [`MAX_NAME`] on decode.
        name: String,
    },
    /// Spawn a host delegate for kennel context `ctx` (reply carries one fd).
    SpawnDelegate {
        /// Which delegate to exec.
        kind: DelegateKind,
        /// The kennel context the delegate serves.
        ctx: u16,
    },
    /// Open a cross-mount-namespace resource for `pid` (reply carries one fd).
    FdRelay {
        /// Which resource to open.
        resource: RelayResource,
        /// The target kennel init pid whose `/proc/<pid>/root` is traversed.
        pid: i32,
    },
}

impl RelayRequest {
    /// Encode this request to its wire frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    /// Decode a request frame received by the parent.
    ///
    /// # Errors
    ///
    /// [`RelayError::BadLength`] if the frame is truncated for its opcode;
    /// [`RelayError::BadTag`] on an unknown opcode; [`RelayError::BadKind`] /
    /// [`RelayError::BadResource`] on an unknown enum byte;
    /// [`RelayError::NameTooLong`] / [`RelayError::NonUtf8Name`] on a bad name.
    pub fn decode(buf: &[u8]) -> Result<Self, RelayError> {
        let _ = buf;
        todo!()
    }
}

/// A reply from the parent to the sealed monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayResponse {
    /// A successful [`RelayRequest::Resolve`]: the vetted-by-the-monitor-later
    /// address set (no accompanying fd).
    Resolved {
        /// The resolved addresses; bounded by [`MAX_ADDRS`] on decode.
        addrs: Vec<IpAddr>,
    },
    /// A successful `SpawnDelegate` / `FdRelay`: one fd accompanies this reply.
    FdReady,
    /// The parent refused or could not satisfy the request (no fd).
    Refused {
        /// Why.
        code: RefusalCode,
    },
}

impl RelayResponse {
    /// The number of file descriptors that accompany this reply via `SCM_RIGHTS`.
    #[must_use]
    pub const fn expected_fds(&self) -> usize {
        match self {
            Self::Resolved { .. } | Self::Refused { .. } => 0,
            Self::FdReady => 1,
        }
    }

    /// Encode this reply to its wire frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    /// Decode a reply frame received by the monitor.
    ///
    /// # Errors
    ///
    /// [`RelayError::BadLength`] if the frame is truncated for its tag;
    /// [`RelayError::BadTag`] on an unknown tag; [`RelayError::BadFamily`] on a
    /// bad address family; [`RelayError::TooManyAddrs`] past [`MAX_ADDRS`];
    /// [`RelayError::BadRefusal`] on an unknown refusal code.
    pub fn decode(buf: &[u8]) -> Result<Self, RelayError> {
        let _ = buf;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // --- request round trips ---

    #[test]
    fn resolve_round_trips() {
        let r = RelayRequest::Resolve {
            name: "example.com".to_owned(),
        };
        assert_eq!(RelayRequest::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn resolve_round_trips_empty_name() {
        let r = RelayRequest::Resolve {
            name: String::new(),
        };
        assert_eq!(RelayRequest::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn resolve_round_trips_max_name() {
        let r = RelayRequest::Resolve {
            name: "a".repeat(MAX_NAME),
        };
        assert_eq!(RelayRequest::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn spawn_delegate_round_trips_each_kind() {
        for kind in [DelegateKind::NetProxy, DelegateKind::Inetd] {
            let r = RelayRequest::SpawnDelegate { kind, ctx: 4242 };
            assert_eq!(RelayRequest::decode(&r.encode()), Ok(r));
        }
    }

    #[test]
    fn fd_relay_round_trips_each_resource() {
        for resource in [
            RelayResource::BinderDevice,
            RelayResource::MeshBusDeviceDir,
            RelayResource::RendezvousSocket,
        ] {
            let r = RelayRequest::FdRelay {
                resource,
                pid: 31337,
            };
            assert_eq!(RelayRequest::decode(&r.encode()), Ok(r));
        }
    }

    // --- request decode rejections (the hostile boundary) ---

    #[test]
    fn decode_rejects_empty_frame() {
        assert_eq!(RelayRequest::decode(&[]), Err(RelayError::BadLength));
    }

    #[test]
    fn decode_rejects_unknown_op() {
        assert_eq!(RelayRequest::decode(&[0xff]), Err(RelayError::BadTag));
    }

    #[test]
    fn decode_rejects_truncated_resolve_length_prefix() {
        // op=1 then a single length byte (needs two).
        assert_eq!(RelayRequest::decode(&[1, 0]), Err(RelayError::BadLength));
    }

    #[test]
    fn decode_rejects_resolve_name_shorter_than_prefix() {
        // op=1, name_len=5, but only 3 name bytes follow.
        let mut buf = vec![1u8];
        buf.extend_from_slice(&5u16.to_ne_bytes());
        buf.extend_from_slice(b"abc");
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::BadLength));
    }

    #[test]
    fn decode_rejects_name_too_long() {
        let mut buf = vec![1u8];
        let n = MAX_NAME + 1;
        buf.extend_from_slice(&u16::try_from(n).unwrap().to_ne_bytes());
        buf.extend_from_slice(&vec![b'a'; n]);
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::NameTooLong));
    }

    #[test]
    fn decode_rejects_non_utf8_name() {
        let mut buf = vec![1u8];
        buf.extend_from_slice(&2u16.to_ne_bytes());
        buf.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::NonUtf8Name));
    }

    #[test]
    fn decode_rejects_bad_delegate_kind() {
        // op=2, kind=9 (unknown), ctx=0.
        let buf = [2u8, 9, 0, 0];
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::BadKind));
    }

    #[test]
    fn decode_rejects_truncated_spawn_delegate() {
        // op=2, kind=1, but ctx (u16) missing.
        assert_eq!(RelayRequest::decode(&[2, 1]), Err(RelayError::BadLength));
    }

    #[test]
    fn decode_rejects_bad_resource() {
        // op=3, resource=9 (unknown), pid bytes.
        let mut buf = vec![3u8, 9];
        buf.extend_from_slice(&1i32.to_ne_bytes());
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::BadResource));
    }

    #[test]
    fn decode_rejects_truncated_fd_relay_pid() {
        // op=3, resource=1, pid truncated to 3 bytes.
        let buf = [3u8, 1, 0, 0, 0];
        assert_eq!(RelayRequest::decode(&buf), Err(RelayError::BadLength));
    }

    // --- response round trips ---

    #[test]
    fn resolved_round_trips_various_counts() {
        for addrs in [
            vec![],
            vec![v4(1, 1, 1, 1)],
            vec![v4(8, 8, 8, 8), IpAddr::V6(Ipv6Addr::LOCALHOST)],
        ] {
            let r = RelayResponse::Resolved { addrs };
            assert_eq!(RelayResponse::decode(&r.encode()), Ok(r));
        }
    }

    #[test]
    fn fd_ready_round_trips_and_expects_one_fd() {
        let r = RelayResponse::FdReady;
        assert_eq!(r.expected_fds(), 1);
        assert_eq!(RelayResponse::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn refused_round_trips_each_code_and_expects_no_fd() {
        for code in [
            RefusalCode::NotFound,
            RefusalCode::ResolveFailed,
            RefusalCode::SpawnFailed,
            RefusalCode::OpenFailed,
            RefusalCode::Internal,
        ] {
            let r = RelayResponse::Refused { code };
            assert_eq!(r.expected_fds(), 0);
            assert_eq!(RelayResponse::decode(&r.encode()), Ok(r));
        }
    }

    #[test]
    fn resolved_expects_no_fd() {
        assert_eq!(RelayResponse::Resolved { addrs: vec![] }.expected_fds(), 0);
    }

    // --- response decode rejections ---

    #[test]
    fn response_decode_rejects_empty_frame() {
        assert_eq!(RelayResponse::decode(&[]), Err(RelayError::BadLength));
    }

    #[test]
    fn response_decode_rejects_unknown_tag() {
        assert_eq!(RelayResponse::decode(&[0xff]), Err(RelayError::BadTag));
    }

    #[test]
    fn response_decode_rejects_too_many_addrs() {
        // tag=0 (Resolved), count past the cap.
        let buf = [0u8, u8::try_from(MAX_ADDRS + 1).unwrap_or(u8::MAX)];
        assert_eq!(RelayResponse::decode(&buf), Err(RelayError::TooManyAddrs));
    }

    #[test]
    fn response_decode_rejects_bad_family() {
        // tag=0, count=1, family=9 (bad), then 16 addr bytes.
        let mut buf = vec![0u8, 1, 9];
        buf.extend_from_slice(&[0u8; 16]);
        assert_eq!(RelayResponse::decode(&buf), Err(RelayError::BadFamily));
    }

    #[test]
    fn response_decode_rejects_truncated_entry() {
        // tag=0, count=1, family=4, but fewer than 16 addr bytes.
        let buf = [0u8, 1, 4, 0, 0, 0];
        assert_eq!(RelayResponse::decode(&buf), Err(RelayError::BadLength));
    }

    #[test]
    fn response_decode_rejects_bad_refusal_code() {
        // tag=2 (Refused), code=9 (unknown).
        assert_eq!(
            RelayResponse::decode(&[2, 9]),
            Err(RelayError::BadRefusal)
        );
    }
}
