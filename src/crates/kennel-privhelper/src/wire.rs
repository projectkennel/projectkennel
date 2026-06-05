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
//! Request (294 bytes):
//!   0      op           u8     (1 add-addr, 2 del-addr, 5 setup-egress, 6 set-gid-map)
//!   1      family       u8     (4 or 6; 0 for the egress op)
//!   2      prefix       u8
//!   3      _reserved    u8     (0)
//!   4..6   ctx          u16    (16-bit kennel context; v4 uses ctx <= 255)
//!   6..22  addr         [u8;16] (v4 in the first 4 bytes)
//!   22..38 interface    [u8;16] (NUL-padded; kernel IFNAMSIZ)
//!   38..294 cgroup_path [u8;256] (NUL-padded; the egress op's target cgroup)
//!
//! Response (6 bytes):
//!   0      status       u8     (0 ok, 1 refused, 2 protocol, 3 internal)
//!   1      refusal      u8     (refusal code when status==1, else 0)
//!   2..6   errno        i32    (OS errno when status==3, else 0)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// The on-wire length of a [`Request`].
pub const REQUEST_LEN: usize = 294;
/// The on-wire length of a [`Response`].
pub const RESPONSE_LEN: usize = 6;

const INTERFACE_FIELD: usize = 16;
const PATH_FIELD: usize = 256;

/// Length of the `kennel_meta` map value (`bpf/maps.h`).
pub const META_LEN: usize = 64;
/// Defensive cap on the number of entries in any one map array, so a malformed
/// length prefix cannot make the helper attempt an absurd read.
const MAX_ENTRIES: usize = 8192;

/// An IPv4 egress LPM map entry: `(lpm_v4_key[8], allow_value[8])`. Matches
/// `kennel_spawn::plan::LpmV4Entry`.
pub type V4Entry = ([u8; 8], [u8; 8]);
/// An IPv6 egress LPM map entry: `(lpm_v6_key[20], allow_value[8])`. Matches
/// `kennel_spawn::plan::LpmV6Entry`.
pub type V6Entry = ([u8; 20], [u8; 8]);

/// The privileged operation a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Add a per-kennel loopback address.
    AddAddr,
    /// Remove a per-kennel loopback address.
    DelAddr,
    /// Load, populate, and attach the egress BPF programs to a kennel's cgroup.
    /// The fixed [`Request`] carries the cgroup path (the helper validates the
    /// caller owns it); a variable-length [`EgressPayload`] tail carries the map
    /// contents. (Op byte 5; bytes 3 and 4 were the retired cgroup create/delete
    /// ops — kenneld now manages cgroups unprivileged in its delegated subtree.)
    SetupEgress,
    /// Write a workload's user-namespace `gid_map` so it retains specific
    /// supplementary groups (§7.2.8 device passthrough). An unprivileged process
    /// can map only its own primary gid, so a process that needs another granted
    /// group (e.g. `dialout`) cannot self-map it; the helper, holding `CAP_SETGID`
    /// in the parent (init) user namespace, writes the map for it. A variable-length
    /// [`GidMapPayload`] tail carries the target pid and the gids. **Gated** by the
    /// helper re-checking the caller is a member of every gid and owns the target
    /// pid — mapping a gid the user is not in would be an escalation.
    SetGidMap,
}

impl Op {
    const fn to_byte(self) -> u8 {
        match self {
            Self::AddAddr => 1,
            Self::DelAddr => 2,
            Self::SetupEgress => 5,
            Self::SetGidMap => 6,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::AddAddr),
            2 => Some(Self::DelAddr),
            5 => Some(Self::SetupEgress),
            6 => Some(Self::SetGidMap),
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
    /// The per-kennel context (16-bit; a v4-enabled kennel uses `ctx <= 255`).
    pub ctx: u16,
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
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| WireError::BadString)
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
        b.push(0u8); // reserved
        b.extend_from_slice(&self.ctx.to_ne_bytes());
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
        let op = buf
            .first()
            .copied()
            .and_then(Op::from_byte)
            .ok_or(WireError::BadOp)?;
        let family = buf.get(1).copied().ok_or(WireError::BadLength)?;
        let prefix = buf.get(2).copied().ok_or(WireError::BadLength)?;
        // buf[3] is reserved (0).
        let ctx = buf
            .get(4..6)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_ne_bytes)
            .ok_or(WireError::BadLength)?;
        let addr16: [u8; 16] = buf
            .get(6..22)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        let addr = match family {
            4 => {
                let v4: [u8; 4] = addr16
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(WireError::BadLength)?;
                IpAddr::V4(Ipv4Addr::from(v4))
            }
            6 => IpAddr::V6(Ipv6Addr::from(addr16)),
            _ => return Err(WireError::BadFamily),
        };
        let interface = read_string(buf.get(22..38).ok_or(WireError::BadLength)?)?;
        let cgroup_path =
            PathBuf::from(read_string(buf.get(38..294).ok_or(WireError::BadLength)?)?);
        Ok(Self {
            op,
            ctx,
            addr,
            prefix,
            interface,
            cgroup_path,
        })
    }
}

/// The variable-length tail of a [`Op::SetupEgress`] request: the BPF map
/// contents the helper writes into the egress programs' maps before attaching.
///
/// Layout (appended directly after the fixed [`Request`] bytes):
///
/// ```text
///   0..64    meta            [u8; 64]   kennel_meta_map[0]
///   64..68   n_allow_v4      u32        native-endian
///   68..72   n_deny_v4       u32
///   72..76   n_allow_v6      u32
///   76..80   n_deny_v6       u32
///   80..     allow_v4 (16 B each) | deny_v4 (16) | allow_v6 (28) | deny_v6 (28)
/// ```
///
/// The map contents are *not* scope-validated: they only define the kennel's
/// own egress allowlist, which the calling user already controls. The cgroup
/// path in the fixed [`Request`] is the cross-user boundary, and is validated
/// like any other cgroup op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPayload {
    /// The 64-byte `kennel_meta` value for `kennel_meta_map[0]`.
    pub meta: [u8; META_LEN],
    /// `allow_v4` LPM entries.
    pub allow_v4: Vec<V4Entry>,
    /// `deny_v4` LPM entries.
    pub deny_v4: Vec<V4Entry>,
    /// `allow_v6` LPM entries.
    pub allow_v6: Vec<V6Entry>,
    /// `deny_v6` LPM entries.
    pub deny_v6: Vec<V6Entry>,
    /// The bind-port allowlist (`[net.bind].allowed_ports`, §7.3.7) for the
    /// `bind_subnet` map (host order). Empty ⇒ any port at or above the floor. Capped
    /// at [`MAX_BIND_PORTS`] on decode (the BPF array is fixed-size).
    pub bind_allowed_ports: Vec<u16>,
    /// The kennel's runtime id (`<id>` in `07-paths.md`; the kennel name). When
    /// non-empty, the helper pins this kennel's BPF maps under the owner's
    /// `/run/user/<uid>/kennel/bpf/<id>/` (for `bpftool` inspection and the
    /// audit-ringbuf drain). Empty ⇒ pinning disabled. The helper validates the
    /// grammar before using it as a path component. Capped at [`MAX_PIN_ID`] bytes
    /// on decode.
    pub pin_id: String,
}

/// The maximum number of `bind_allowed_ports` the wire carries (the `bind_subnet`
/// BPF array size; mirrors `kennel_policy::settled::MAX_BIND_PORTS`).
pub const MAX_BIND_PORTS: usize = 8;

/// The maximum byte length of the [`EgressPayload::pin_id`] field on the wire.
/// A kennel id is a name or UUID; this is a generous defensive cap.
const MAX_PIN_ID: usize = 256;

/// Read the bind-port allowlist tail: a `u32` count then that many host-order `u16`
/// ports. Tolerant of an absent tail (fewer than 4 bytes ⇒ empty, fail-closed: no
/// extra ports). A count above [`MAX_BIND_PORTS`] is rejected. Returns the ports
/// and the number of bytes consumed (so a following field can be located).
fn read_bind_ports(bytes: &[u8]) -> Result<(Vec<u16>, usize), WireError> {
    let Some(count_bytes) = bytes.get(..4) else {
        return Ok((Vec::new(), 0));
    };
    let n = count_bytes
        .try_into()
        .map(u32::from_ne_bytes)
        .map(|v| v as usize)
        .map_err(|_| WireError::BadLength)?;
    if n > MAX_BIND_PORTS {
        return Err(WireError::BadLength);
    }
    let span = n.checked_mul(2).ok_or(WireError::BadLength)?;
    let end = span.checked_add(4).ok_or(WireError::BadLength)?;
    let region = bytes.get(4..end).ok_or(WireError::BadLength)?;
    let ports = region
        .chunks_exact(2)
        .filter_map(|c| c.try_into().ok().map(u16::from_ne_bytes))
        .collect();
    Ok((ports, end))
}

/// Read the optional pin-id tail: a `u32` byte-length then that many UTF-8 bytes.
/// Tolerant of an absent tail (fewer than 4 bytes ⇒ empty: pinning disabled). A
/// length above [`MAX_PIN_ID`] is rejected.
fn read_pin_id(bytes: &[u8]) -> Result<String, WireError> {
    let Some(len_bytes) = bytes.get(..4) else {
        return Ok(String::new());
    };
    let n = len_bytes
        .try_into()
        .map(u32::from_ne_bytes)
        .map(|v| v as usize)
        .map_err(|_| WireError::BadLength)?;
    if n > MAX_PIN_ID {
        return Err(WireError::BadLength);
    }
    let end = n.checked_add(4).ok_or(WireError::BadLength)?;
    let region = bytes.get(4..end).ok_or(WireError::BadLength)?;
    core::str::from_utf8(region)
        .map(str::to_owned)
        .map_err(|_| WireError::BadString)
}

/// Read `n` IPv4 entries (8-byte key + 8-byte value) from the front of `bytes`,
/// returning them and the number of bytes consumed.
fn read_v4_entries(bytes: &[u8], n: usize) -> Result<(Vec<V4Entry>, usize), WireError> {
    let span = n.checked_mul(16).ok_or(WireError::BadLength)?;
    let region = bytes.get(..span).ok_or(WireError::BadLength)?;
    let mut out = Vec::with_capacity(n);
    for chunk in region.chunks_exact(16) {
        let key: [u8; 8] = chunk
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        let val: [u8; 8] = chunk
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        out.push((key, val));
    }
    Ok((out, span))
}

/// Read `n` IPv6 entries (20-byte key + 8-byte value) from the front of `bytes`,
/// returning them and the number of bytes consumed.
fn read_v6_entries(bytes: &[u8], n: usize) -> Result<(Vec<V6Entry>, usize), WireError> {
    let span = n.checked_mul(28).ok_or(WireError::BadLength)?;
    let region = bytes.get(..span).ok_or(WireError::BadLength)?;
    let mut out = Vec::with_capacity(n);
    for chunk in region.chunks_exact(28) {
        let key: [u8; 20] = chunk
            .get(..20)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        let val: [u8; 8] = chunk
            .get(20..28)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        out.push((key, val));
    }
    Ok((out, span))
}

/// Read a native-endian `u32` count at `off`, rejecting absurd values.
fn read_count(bytes: &[u8], off: usize) -> Result<usize, WireError> {
    let end = off.checked_add(4).ok_or(WireError::BadLength)?;
    let raw = bytes
        .get(off..end)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or(WireError::BadLength)?;
    let n = usize::try_from(raw).map_err(|_| WireError::BadLength)?;
    if n > MAX_ENTRIES {
        return Err(WireError::BadLength);
    }
    Ok(n)
}

impl EgressPayload {
    /// Encode the payload tail (appended after the request bytes by the client).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.meta);
        for n in [
            self.allow_v4.len(),
            self.deny_v4.len(),
            self.allow_v6.len(),
            self.deny_v6.len(),
        ] {
            // Counts are bounded by MAX_ENTRIES on decode; encode is local data.
            b.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_ne_bytes());
        }
        for (k, v) in self.allow_v4.iter().chain(&self.deny_v4) {
            b.extend_from_slice(k);
            b.extend_from_slice(v);
        }
        for (k, v) in self.allow_v6.iter().chain(&self.deny_v6) {
            b.extend_from_slice(k);
            b.extend_from_slice(v);
        }
        // Bind-port allowlist tail: a count then the host-order ports. Appended last so
        // the existing prefix layout is unchanged.
        b.extend_from_slice(
            &u32::try_from(self.bind_allowed_ports.len())
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        for port in &self.bind_allowed_ports {
            b.extend_from_slice(&port.to_ne_bytes());
        }
        // Pin-id tail: a byte-length then the UTF-8 id. Appended last so the existing
        // layout is unchanged and an older consumer simply ignores it.
        b.extend_from_slice(
            &u32::try_from(self.pin_id.len())
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        b.extend_from_slice(self.pin_id.as_bytes());
        b
    }

    /// Decode a payload tail.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BadLength`] if the buffer is short, a count exceeds
    /// the defensive cap, or the entry bytes do not match the declared counts.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let meta: [u8; META_LEN] = buf
            .get(..META_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(WireError::BadLength)?;
        let n_allow_v4 = read_count(buf, META_LEN)?;
        let n_deny_v4 = read_count(buf, META_LEN + 4)?;
        let n_allow_v6 = read_count(buf, META_LEN + 8)?;
        let n_deny_v6 = read_count(buf, META_LEN + 12)?;
        let mut off = META_LEN + 16;
        let rest = buf.get(off..).ok_or(WireError::BadLength)?;

        let (allow_v4, used) = read_v4_entries(rest, n_allow_v4)?;
        off = used;
        let (deny_v4, used) =
            read_v4_entries(rest.get(off..).ok_or(WireError::BadLength)?, n_deny_v4)?;
        off = off.checked_add(used).ok_or(WireError::BadLength)?;
        let (allow_v6, used) =
            read_v6_entries(rest.get(off..).ok_or(WireError::BadLength)?, n_allow_v6)?;
        off = off.checked_add(used).ok_or(WireError::BadLength)?;
        let (deny_v6, used) =
            read_v6_entries(rest.get(off..).ok_or(WireError::BadLength)?, n_deny_v6)?;
        off = off.checked_add(used).ok_or(WireError::BadLength)?;
        let ports_tail = rest.get(off..).unwrap_or(&[]);
        let (bind_allowed_ports, used) = read_bind_ports(ports_tail)?;
        let pin_id = read_pin_id(ports_tail.get(used..).unwrap_or(&[]))?;

        Ok(Self {
            meta,
            allow_v4,
            deny_v4,
            allow_v6,
            deny_v6,
            bind_allowed_ports,
            pin_id,
        })
    }
}

/// The variable-length tail of a [`Op::SetGidMap`] request: the target process and
/// the gids to identity-map into its user namespace.
///
/// Layout (appended directly after the fixed [`Request`] bytes):
///
/// ```text
///   0..4    pid       u32   native-endian; the process whose userns gid_map to write
///   4..8    n_gids    u32   native-endian
///   8..     gids      u32 each (native-endian)
/// ```
///
/// Each gid becomes one identity line (`<gid> <gid> 1`) in the written `gid_map`,
/// so inside the kennel the workload keeps exactly these groups and the kernel sees
/// the same real gids outside. The helper does **not** trust this list: it refuses
/// any gid the caller is not a member of, and refuses a pid it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GidMapPayload {
    /// The target process (the workload's user-namespace owner).
    pub pid: u32,
    /// The gids to identity-map (primary + each granted supplementary group).
    pub gids: Vec<u32>,
}

impl GidMapPayload {
    /// Encode the payload tail (appended after the request bytes by the client).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8usize.saturating_add(self.gids.len().saturating_mul(4)));
        b.extend_from_slice(&self.pid.to_ne_bytes());
        b.extend_from_slice(
            &u32::try_from(self.gids.len())
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        for gid in &self.gids {
            b.extend_from_slice(&gid.to_ne_bytes());
        }
        b
    }

    /// Decode a payload tail.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BadLength`] if the buffer is short, the count exceeds
    /// the defensive cap, or the gid bytes do not match the declared count.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let pid = buf
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_ne_bytes)
            .ok_or(WireError::BadLength)?;
        let n = read_count(buf, 4)?;
        let span = n.checked_mul(4).ok_or(WireError::BadLength)?;
        let region = buf
            .get(8..8usize.checked_add(span).ok_or(WireError::BadLength)?)
            .ok_or(WireError::BadLength)?;
        let mut gids = Vec::with_capacity(n);
        for chunk in region.chunks_exact(4) {
            let g: [u8; 4] = chunk.try_into().map_err(|_| WireError::BadLength)?;
            gids.push(u32::from_ne_bytes(g));
        }
        Ok(Self { pid, gids })
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
        Self {
            status: Status::Ok,
            refusal: 0,
            errno: 0,
        }
    }

    /// A refusal response carrying the refusal `code`.
    #[must_use]
    pub const fn refused(code: u8) -> Self {
        Self {
            status: Status::Refused,
            refusal: code,
            errno: 0,
        }
    }

    /// A protocol-error response.
    #[must_use]
    pub const fn protocol() -> Self {
        Self {
            status: Status::Protocol,
            refusal: 0,
            errno: 0,
        }
    }

    /// An internal-error response carrying the OS `errno`.
    #[must_use]
    pub const fn internal(errno: i32) -> Self {
        Self {
            status: Status::Internal,
            refusal: 0,
            errno,
        }
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
        let status = buf
            .first()
            .copied()
            .and_then(Status::from_byte)
            .ok_or(WireError::BadOp)?;
        let refusal = buf.get(1).copied().ok_or(WireError::BadLength)?;
        let errno = buf
            .get(2..6)
            .and_then(|s| s.try_into().ok())
            .map(i32::from_ne_bytes)
            .ok_or(WireError::BadLength)?;
        Ok(Self {
            status,
            refusal,
            errno,
        })
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
    fn request_round_trips_v6_and_egress() {
        let req = Request {
            op: Op::SetupEgress,
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
    fn egress_payload_round_trips() {
        let payload = EgressPayload {
            meta: [7u8; META_LEN],
            allow_v4: vec![([1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 15, 16])],
            deny_v4: vec![([0xff; 8], [0; 8]), ([0x11; 8], [0x22; 8])],
            allow_v6: vec![([3u8; 20], [4u8; 8])],
            deny_v6: Vec::new(),
            bind_allowed_ports: vec![8080, 9090],
            pin_id: "ai-coding".to_owned(),
        };
        let bytes = payload.encode();
        assert_eq!(EgressPayload::decode(&bytes), Ok(payload));
    }

    #[test]
    fn egress_payload_tolerates_a_missing_bind_port_tail() {
        // A payload encoded without the bind-port/pin-id tails (e.g. an older producer)
        // decodes with empty values rather than failing — fail-closed (no extra ports,
        // no pinning).
        let payload = EgressPayload {
            meta: [0u8; META_LEN],
            allow_v4: Vec::new(),
            deny_v4: Vec::new(),
            allow_v6: Vec::new(),
            deny_v6: Vec::new(),
            bind_allowed_ports: vec![1234],
            pin_id: String::new(),
        };
        let mut bytes = payload.encode();
        // Drop both optional tails: pin-id length (4) + bind-port count (4) + one port (2).
        bytes.truncate(bytes.len().saturating_sub(10));
        let decoded = EgressPayload::decode(&bytes).expect("decode without tail");
        assert!(decoded.bind_allowed_ports.is_empty());
        assert!(decoded.pin_id.is_empty());
        // A count claiming more ports than bytes is rejected (drop the port + pin-id tail,
        // leaving the bind-port count saying 1).
        let mut bad = payload.encode();
        bad.truncate(bad.len().saturating_sub(6));
        assert!(EgressPayload::decode(&bad).is_err());
    }

    #[test]
    fn egress_payload_round_trips_with_pin_id_and_tolerates_its_absence() {
        let payload = EgressPayload {
            meta: [1u8; META_LEN],
            allow_v4: Vec::new(),
            deny_v4: Vec::new(),
            allow_v6: Vec::new(),
            deny_v6: Vec::new(),
            bind_allowed_ports: vec![443],
            pin_id: "kennel-9f3a".to_owned(),
        };
        assert_eq!(
            EgressPayload::decode(&payload.encode()),
            Ok(payload.clone())
        );
        // Drop just the pin-id tail (length 4 + 11 id bytes): the rest still decodes,
        // with pinning disabled.
        let mut bytes = payload.encode();
        bytes.truncate(bytes.len().saturating_sub(4 + "kennel-9f3a".len()));
        let decoded = EgressPayload::decode(&bytes).expect("decode without pin-id");
        assert!(decoded.pin_id.is_empty());
        assert_eq!(decoded.bind_allowed_ports, vec![443]);
    }

    #[test]
    fn egress_payload_rejects_truncated_entries() {
        // Claim one v4 entry but provide no entry bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; META_LEN]);
        bytes.extend_from_slice(&1u32.to_ne_bytes()); // n_allow_v4 = 1
        bytes.extend_from_slice(&[0u8; 12]); // remaining three counts = 0
        assert_eq!(EgressPayload::decode(&bytes), Err(WireError::BadLength));
    }

    #[test]
    fn egress_payload_rejects_absurd_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; META_LEN]);
        bytes.extend_from_slice(&u32::MAX.to_ne_bytes()); // n_allow_v4 = 4 billion
        bytes.extend_from_slice(&[0u8; 12]);
        assert_eq!(EgressPayload::decode(&bytes), Err(WireError::BadLength));
    }

    #[test]
    fn setup_egress_op_round_trips() {
        assert_eq!(
            Op::from_byte(Op::SetupEgress.to_byte()),
            Some(Op::SetupEgress)
        );
    }

    #[test]
    fn set_gid_map_op_round_trips() {
        assert_eq!(Op::from_byte(Op::SetGidMap.to_byte()), Some(Op::SetGidMap));
    }

    #[test]
    fn gidmap_payload_round_trips() {
        let payload = GidMapPayload {
            pid: 4242,
            gids: vec![1000, 20, 24],
        };
        let bytes = payload.encode();
        assert_eq!(GidMapPayload::decode(&bytes), Ok(payload));
    }

    #[test]
    fn gidmap_payload_rejects_truncated_gids() {
        // Claim two gids but provide one.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u32.to_ne_bytes()); // pid
        bytes.extend_from_slice(&2u32.to_ne_bytes()); // n_gids = 2
        bytes.extend_from_slice(&20u32.to_ne_bytes()); // only one gid
        assert_eq!(GidMapPayload::decode(&bytes), Err(WireError::BadLength));
    }

    #[test]
    fn gidmap_payload_rejects_absurd_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u32.to_ne_bytes()); // pid
        bytes.extend_from_slice(&u32::MAX.to_ne_bytes()); // n_gids = 4 billion
        assert_eq!(GidMapPayload::decode(&bytes), Err(WireError::BadLength));
    }

    #[test]
    fn response_round_trips() {
        for r in [
            Response::ok(),
            Response::refused(5),
            Response::protocol(),
            Response::internal(13),
        ] {
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
