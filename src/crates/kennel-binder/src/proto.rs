//! The binder `BC_*`/`BR_*` command-stream codec (`<linux/android/binder.h>`).
//!
//! A `BINDER_WRITE_READ` ioctl carries two byte buffers: a *write* buffer of
//! `BC_*` commands the caller issues, and a *read* buffer the kernel fills with
//! `BR_*` commands. Each command is a `u32` code (an `_IOC`-encoded value, **not**
//! a bare index) optionally followed by a fixed payload. This module encodes the
//! commands Project Kennel issues and decodes the ones it receives; it is pure and
//! holds no `unsafe`.
//!
//! The read buffer is filled by the kernel but its *contents past the command
//! framing* (transaction payloads) originate with the sending workload, so the
//! decoder is treated as an untrusted-input parser: every field is read with
//! bounds-checked slicing, never indexed (CODING-STANDARDS.md §10).

/// Encode an `_IOC` value the way `<asm-generic/ioctl.h>` does, so the `BC_*`/
/// `BR_*` constants below match the kernel's command codes exactly.
const fn ioc(dir: u32, ty: u8, nr: u32, size: u32) -> u32 {
    // dir<<30 | size<<16 | type<<8 | nr  (sizebits=14)
    (dir << 30) | ((size & 0x3fff) << 16) | (u32::from_le_bytes([ty, 0, 0, 0]) << 8) | nr
}

const DIR_NONE: u32 = 0;
const DIR_WRITE: u32 = 1;
const DIR_READ: u32 = 2;

/// Size of `struct binder_transaction_data` (the `(BC|BR)_TRANSACTION` payload).
pub const TRANSACTION_DATA_SIZE: usize = 64;
/// Size of `struct binder_ptr_cookie` (`{ binder_uintptr_t ptr; binder_uintptr_t cookie; }`).
pub const PTR_COOKIE_SIZE: usize = 16;

/// The binder protocol version we require (`BINDER_CURRENT_PROTOCOL_VERSION` on a
/// 64-bit kernel).
pub const PROTOCOL_VERSION: i32 = 8;

/// `BC_TRANSACTION`: begin an outbound transaction.
pub const BC_TRANSACTION: u32 = ioc(DIR_WRITE, b'c', 0, 64);
/// `BC_REPLY`: reply to a received `BR_TRANSACTION`.
pub const BC_REPLY: u32 = ioc(DIR_WRITE, b'c', 1, 64);
/// `BC_FREE_BUFFER`: release a transaction buffer the kernel allocated in our map.
pub const BC_FREE_BUFFER: u32 = ioc(DIR_WRITE, b'c', 3, 8);
/// `BC_INCREFS`: take a weak reference on a remote handle.
pub const BC_INCREFS: u32 = ioc(DIR_WRITE, b'c', 4, 4);
/// `BC_ACQUIRE`: take a strong reference on a remote handle.
pub const BC_ACQUIRE: u32 = ioc(DIR_WRITE, b'c', 5, 4);
/// `BC_RELEASE`: drop a strong reference on a remote handle.
pub const BC_RELEASE: u32 = ioc(DIR_WRITE, b'c', 6, 4);
/// `BC_DECREFS`: drop a weak reference on a remote handle.
pub const BC_DECREFS: u32 = ioc(DIR_WRITE, b'c', 7, 4);
/// `BC_INCREFS_DONE`: ack a kernel `BR_INCREFS` on a node we own.
pub const BC_INCREFS_DONE: u32 = ioc(DIR_WRITE, b'c', 8, 16);
/// `BC_ACQUIRE_DONE`: ack a kernel `BR_ACQUIRE` on a node we own.
pub const BC_ACQUIRE_DONE: u32 = ioc(DIR_WRITE, b'c', 9, 16);
/// `BC_REGISTER_LOOPER`: register a kernel-requested looper thread.
pub const BC_REGISTER_LOOPER: u32 = ioc(DIR_NONE, b'c', 11, 0);
/// `BC_ENTER_LOOPER`: announce a self-started looper thread.
pub const BC_ENTER_LOOPER: u32 = ioc(DIR_NONE, b'c', 12, 0);
/// `BC_EXIT_LOOPER`: announce a looper thread is leaving the pool.
pub const BC_EXIT_LOOPER: u32 = ioc(DIR_NONE, b'c', 13, 0);

// BR_* — driver return protocol ('r'), received from the read buffer.
const BR_ERROR: u32 = ioc(DIR_READ, b'r', 0, 4);
const BR_OK: u32 = ioc(DIR_NONE, b'r', 1, 0);
const BR_TRANSACTION: u32 = ioc(DIR_READ, b'r', 2, 64);
const BR_REPLY: u32 = ioc(DIR_READ, b'r', 3, 64);
const BR_DEAD_REPLY: u32 = ioc(DIR_NONE, b'r', 5, 0);
const BR_TRANSACTION_COMPLETE: u32 = ioc(DIR_NONE, b'r', 6, 0);
const BR_INCREFS: u32 = ioc(DIR_READ, b'r', 7, 16);
const BR_ACQUIRE: u32 = ioc(DIR_READ, b'r', 8, 16);
const BR_RELEASE: u32 = ioc(DIR_READ, b'r', 9, 16);
const BR_DECREFS: u32 = ioc(DIR_READ, b'r', 10, 16);
const BR_NOOP: u32 = ioc(DIR_NONE, b'r', 12, 0);
const BR_SPAWN_LOOPER: u32 = ioc(DIR_NONE, b'r', 13, 0);
const BR_FINISHED: u32 = ioc(DIR_NONE, b'r', 14, 0);
const BR_DEAD_BINDER: u32 = ioc(DIR_READ, b'r', 15, 8);
const BR_FAILED_REPLY: u32 = ioc(DIR_NONE, b'r', 17, 0);

/// Transaction flag: a one-way (async, no reply) transaction (`TF_ONE_WAY`).
pub const TF_ONE_WAY: u32 = 0x01;
/// Transaction flag: replies may carry file descriptors (`TF_ACCEPT_FDS`).
pub const TF_ACCEPT_FDS: u32 = 0x10;

/// Size of `struct flat_binder_object` (hdr.type + flags + union + cookie).
pub const FLAT_BINDER_OBJECT_SIZE: usize = 24;

/// `BINDER_TYPE_FD`: a `flat_binder_object` carrying a file descriptor.
///
/// The kernel dups it into the receiver (`07-9`/`02-7` §The af-unix facade). The
/// value is `B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE=0x85)`; the test cross-checks it.
pub const BINDER_TYPE_FD: u32 = 0x6664_2a85;

/// Encode a `flat_binder_object` of type `BINDER_TYPE_FD` carrying `fd`.
///
/// Placed in a transaction's data buffer (with an offsets entry pointing at it) so
/// the kernel dups `fd` into the receiving process and rewrites it to that process's
/// fd number.
#[must_use]
pub fn flat_binder_object_fd(fd: i32) -> [u8; FLAT_BINDER_OBJECT_SIZE] {
    // hdr.type @0, flags @4, union (fd in low 4 of 8) @8, cookie (8) @16.
    let seq = BINDER_TYPE_FD
        .to_ne_bytes()
        .into_iter()
        .chain(0u32.to_ne_bytes()) // flags
        .chain(u32::from_ne_bytes(fd.to_ne_bytes()).to_ne_bytes()) // union low (fd)
        .chain(0u32.to_ne_bytes()) // union high
        .chain(0u64.to_ne_bytes()); // cookie
    let mut out = [0u8; FLAT_BINDER_OBJECT_SIZE];
    for (slot, byte) in out.iter_mut().zip(seq) {
        *slot = byte;
    }
    out
}

/// Decode the fd from a `flat_binder_object` at the start of `bytes`, if it is a
/// `BINDER_TYPE_FD` object. `None` if the slice is too short or not an fd object.
#[must_use]
pub fn flat_binder_object_fd_value(bytes: &[u8]) -> Option<i32> {
    let mut r = Reader::new(bytes);
    if r.u32()? != BINDER_TYPE_FD {
        return None;
    }
    let _flags = r.u32()?;
    let fd = r.u32()?; // union low: the (translated) fd
    let _high = r.u32()?;
    let _cookie = r.u64()?;
    Some(i32::from_ne_bytes(fd.to_ne_bytes()))
}

/// A `struct binder_transaction_data`.
///
/// The payload of a `(BC|BR)_TRANSACTION` / `_REPLY`. Held as plain fields (not a
/// cast `repr(C)`) so encode/decode is alignment-safe over the kernel's
/// (4-byte-aligned) read buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransactionData {
    /// `target` union: the destination handle (low 32 bits) for `BC_TRANSACTION`;
    /// ignored for `BC_REPLY`.
    pub target: u64,
    /// Cookie associated with the target node (set by the node owner).
    pub cookie: u64,
    /// Transaction code (the method selector — e.g. `addService`).
    pub code: u32,
    /// `TF_*` flags.
    pub flags: u32,
    /// Sending process pid, filled by the kernel on `BR_TRANSACTION`.
    pub sender_pid: i32,
    /// Sending process euid, filled by the kernel on `BR_TRANSACTION`.
    pub sender_euid: u32,
    /// Number of bytes of transaction data.
    pub data_size: u64,
    /// Number of bytes of `flat_binder_object` offsets.
    pub offsets_size: u64,
    /// `data.ptr.buffer`: pointer to the data (in the receiver's mapped region on
    /// `BR_`, supplied by the sender on `BC_`).
    pub buffer: u64,
    /// `data.ptr.offsets`: pointer to the offsets array.
    pub offsets: u64,
}

impl TransactionData {
    /// Serialise to the 64-byte `struct binder_transaction_data` layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TRANSACTION_DATA_SIZE] {
        let parts = [
            self.target.to_ne_bytes(),
            self.cookie.to_ne_bytes(),
            // code + flags pack into the next 8 bytes.
            pack_u32_pair(self.code, self.flags),
            // sender_pid (i32) + sender_euid (u32).
            pack_u32_pair(self.sender_pid.to_ne_bytes_u32(), self.sender_euid),
            self.data_size.to_ne_bytes(),
            self.offsets_size.to_ne_bytes(),
            self.buffer.to_ne_bytes(),
            self.offsets.to_ne_bytes(),
        ];
        let mut out = [0u8; TRANSACTION_DATA_SIZE];
        for (slot, byte) in out.iter_mut().zip(parts.into_iter().flatten()) {
            *slot = byte;
        }
        out
    }

    /// Parse from the 64-byte layout. `None` if `b` is shorter than the struct.
    ///
    /// # Errors
    ///
    /// Returns `None` (a decode predicate, not an error type) when the slice is
    /// too short to hold a `binder_transaction_data`.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let target = r.u64()?;
        let cookie = r.u64()?;
        let code = r.u32()?;
        let flags = r.u32()?;
        let sender_pid = r.i32()?;
        let sender_euid = r.u32()?;
        let data_size = r.u64()?;
        let offsets_size = r.u64()?;
        let buffer = r.u64()?;
        let offsets = r.u64()?;
        Some(Self {
            target,
            cookie,
            code,
            flags,
            sender_pid,
            sender_euid,
            data_size,
            offsets_size,
            buffer,
            offsets,
        })
    }
}

/// A decoded `BR_*` command from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Br {
    /// An inbound transaction to one of our nodes.
    Transaction(TransactionData),
    /// A reply to a transaction we sent.
    Reply(TransactionData),
    /// The kernel accepted our transaction (no reply yet).
    TransactionComplete,
    /// Idle filler; ignore.
    Noop,
    /// The kernel suggests we spawn another looper thread.
    SpawnLooper,
    /// Take a weak reference on a local node we own.
    IncRefs {
        /// The node's userspace pointer.
        ptr: u64,
        /// The node's cookie.
        cookie: u64,
    },
    /// Take a strong reference on a local node we own.
    Acquire {
        /// The node's userspace pointer.
        ptr: u64,
        /// The node's cookie.
        cookie: u64,
    },
    /// Drop a strong reference on a local node we own.
    Release {
        /// The node's userspace pointer.
        ptr: u64,
        /// The node's cookie.
        cookie: u64,
    },
    /// Drop a weak reference on a local node we own.
    DecRefs {
        /// The node's userspace pointer.
        ptr: u64,
        /// The node's cookie.
        cookie: u64,
    },
    /// The transaction failed (a policy refusal upstream, or a malformed request).
    Failed,
    /// The target node is dead.
    Dead,
    /// A node we were watching died (`BR_DEAD_BINDER`), carrying its cookie.
    DeadBinder(u64),
    /// The driver reported an error code.
    Error(i32),
    /// A recognised-but-uninteresting command (`BR_OK`, `BR_FINISHED`).
    Other(u32),
}

/// Decode the next `BR_*` command at the start of `buf`, returning it and the
/// number of bytes consumed (the `u32` code plus its fixed payload).
///
/// Returns `None` if `buf` is empty, too short for the command's payload, or
/// carries a command code we do not recognise (whose payload length we cannot know
/// to skip safely) — the caller treats that as end-of-buffer / a protocol stop.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<(Br, usize)> {
    let mut r = Reader::new(buf);
    let code = r.u32()?;
    let br = match code {
        BR_NOOP => Br::Noop,
        BR_TRANSACTION_COMPLETE => Br::TransactionComplete,
        BR_SPAWN_LOOPER => Br::SpawnLooper,
        BR_FAILED_REPLY => Br::Failed,
        BR_DEAD_REPLY => Br::Dead,
        BR_OK | BR_FINISHED => Br::Other(code),
        BR_TRANSACTION => Br::Transaction(read_td(&mut r)?),
        BR_REPLY => Br::Reply(read_td(&mut r)?),
        BR_INCREFS => ptr_cookie(&mut r, |ptr, cookie| Br::IncRefs { ptr, cookie })?,
        BR_ACQUIRE => ptr_cookie(&mut r, |ptr, cookie| Br::Acquire { ptr, cookie })?,
        BR_RELEASE => ptr_cookie(&mut r, |ptr, cookie| Br::Release { ptr, cookie })?,
        BR_DECREFS => ptr_cookie(&mut r, |ptr, cookie| Br::DecRefs { ptr, cookie })?,
        BR_DEAD_BINDER => Br::DeadBinder(r.u64()?),
        BR_ERROR => Br::Error(r.i32()?),
        _ => return None,
    };
    Some((br, r.pos))
}

/// Append a `BC_TRANSACTION` (or `BC_REPLY` when `reply`) and its
/// `binder_transaction_data` to a write buffer.
pub fn write_transaction(out: &mut Vec<u8>, reply: bool, td: &TransactionData) {
    let cmd = if reply { BC_REPLY } else { BC_TRANSACTION };
    out.extend_from_slice(&cmd.to_ne_bytes());
    out.extend_from_slice(&td.to_bytes());
}

/// Append a payload-less `BC_*` command (e.g. `BC_ENTER_LOOPER`).
pub fn write_cmd(out: &mut Vec<u8>, cmd: u32) {
    out.extend_from_slice(&cmd.to_ne_bytes());
}

/// Append a `BC_FREE_BUFFER` releasing the transaction buffer at `buffer_ptr`.
pub fn write_free_buffer(out: &mut Vec<u8>, buffer_ptr: u64) {
    out.extend_from_slice(&BC_FREE_BUFFER.to_ne_bytes());
    out.extend_from_slice(&buffer_ptr.to_ne_bytes());
}

/// Append a handle-refcount `BC_*` (`BC_INCREFS`/`ACQUIRE`/`RELEASE`/`DECREFS`).
pub fn write_ref(out: &mut Vec<u8>, cmd: u32, handle: u32) {
    out.extend_from_slice(&cmd.to_ne_bytes());
    out.extend_from_slice(&handle.to_ne_bytes());
}

/// Append a `{ptr, cookie}` `BC_*` (`BC_INCREFS_DONE`/`BC_ACQUIRE_DONE`).
pub fn write_ptr_cookie(out: &mut Vec<u8>, cmd: u32, ptr: u64, cookie: u64) {
    out.extend_from_slice(&cmd.to_ne_bytes());
    out.extend_from_slice(&ptr.to_ne_bytes());
    out.extend_from_slice(&cookie.to_ne_bytes());
}

/// Read a `binder_transaction_data` from the reader, advancing past it.
fn read_td(r: &mut Reader<'_>) -> Option<TransactionData> {
    let bytes = r.take(TRANSACTION_DATA_SIZE)?;
    TransactionData::from_bytes(bytes)
}

/// Read a `{ptr, cookie}` pair and map it through `f`, advancing the reader.
fn ptr_cookie(r: &mut Reader<'_>, f: impl FnOnce(u64, u64) -> Br) -> Option<Br> {
    let ptr = r.u64()?;
    let cookie = r.u64()?;
    Some(f(ptr, cookie))
}

/// Pack two little-/native-order `u32`s into the next 8 bytes in field order.
const fn pack_u32_pair(a: u32, b: u32) -> [u8; 8] {
    let lo = a.to_ne_bytes();
    let hi = b.to_ne_bytes();
    [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]
}

/// `i32`-as-`u32` reinterpretation for the `sender_pid` slot, preserving bytes.
trait ToNeBytesU32 {
    fn to_ne_bytes_u32(self) -> u32;
}
impl ToNeBytesU32 for i32 {
    fn to_ne_bytes_u32(self) -> u32 {
        u32::from_ne_bytes(self.to_ne_bytes())
    }
}

/// A bounds-checked sequential reader over a byte slice.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    /// Take the next `n` bytes, advancing the cursor; `None` if out of range.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_ne_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_ne_bytes(self.take(8)?.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_match_the_ioc_encoding() {
        assert_eq!(BC_TRANSACTION, ioc(DIR_WRITE, b'c', 0, 64));
        assert_eq!(BC_ENTER_LOOPER, ioc(DIR_NONE, b'c', 12, 0));
        // BC_ENTER_LOOPER = _IO('c',12): dir 0, type 'c'=0x63, nr 12 => 0x630c.
        assert_eq!(BC_ENTER_LOOPER, 0x0000_630c);
        // BR_TRANSACTION = _IOR('r',2,64): dir 2, type 'r', nr 2, size 64.
        assert_eq!(parse_code(BR_TRANSACTION), (2, b'r', 2, 64));
    }

    /// Decompose an `_IOC` value for the assertion above.
    fn parse_code(code: u32) -> (u32, u8, u32, u32) {
        let dir = code >> 30;
        let size = (code >> 16) & 0x3fff;
        let ty = u8::try_from((code >> 8) & 0xff).unwrap_or(0);
        let nr = code & 0xff;
        (dir, ty, nr, size)
    }

    #[test]
    fn transaction_data_round_trips_through_bytes() {
        let td = TransactionData {
            target: 0,
            cookie: 0xdead_beef,
            code: 1,
            flags: TF_ACCEPT_FDS,
            sender_pid: 4242,
            sender_euid: 1000,
            data_size: 12,
            offsets_size: 0,
            buffer: 0x7fff_0000_1234,
            offsets: 0,
        };
        let bytes = td.to_bytes();
        assert_eq!(bytes.len(), TRANSACTION_DATA_SIZE);
        assert_eq!(TransactionData::from_bytes(&bytes), Some(td));
    }

    #[test]
    fn from_bytes_rejects_a_short_slice() {
        assert_eq!(TransactionData::from_bytes(&[0u8; 10]), None);
    }

    #[test]
    fn parses_a_noop_then_a_transaction_complete() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BR_NOOP.to_ne_bytes());
        buf.extend_from_slice(&BR_TRANSACTION_COMPLETE.to_ne_bytes());
        let (first, n1) = parse(&buf).expect("noop");
        assert_eq!(first, Br::Noop);
        assert_eq!(n1, 4);
        let (second, n2) = parse(buf.get(n1..).expect("rest")).expect("complete");
        assert_eq!(second, Br::TransactionComplete);
        assert_eq!(n2, 4);
    }

    #[test]
    fn parses_a_br_transaction_payload() {
        let td = TransactionData {
            target: 0,
            cookie: 7,
            code: 2,
            flags: 0,
            sender_pid: 99,
            sender_euid: 1000,
            data_size: 4,
            offsets_size: 0,
            buffer: 0x1000,
            offsets: 0x2000,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&BR_TRANSACTION.to_ne_bytes());
        buf.extend_from_slice(&td.to_bytes());
        let (br, n) = parse(&buf).expect("transaction");
        assert_eq!(n, 4 + TRANSACTION_DATA_SIZE);
        assert_eq!(br, Br::Transaction(td));
    }

    #[test]
    fn parse_rejects_truncated_and_unknown() {
        assert_eq!(parse(&BR_TRANSACTION.to_ne_bytes()), None);
        assert_eq!(parse(&0xffff_ffffu32.to_ne_bytes()), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn write_transaction_frames_code_then_struct() {
        let td = TransactionData::default();
        let mut out = Vec::new();
        write_transaction(&mut out, false, &td);
        assert_eq!(out.len(), 4 + TRANSACTION_DATA_SIZE);
        assert_eq!(out.get(..4), Some(&BC_TRANSACTION.to_ne_bytes()[..]));
    }

    #[test]
    fn write_cmd_emits_only_the_code() {
        let mut out = Vec::new();
        write_cmd(&mut out, BC_ENTER_LOOPER);
        assert_eq!(out, BC_ENTER_LOOPER.to_ne_bytes());
    }

    #[test]
    fn binder_type_fd_matches_b_pack_chars() {
        // Independently compute B_PACK_CHARS('f','d','*', 0x85) to verify the literal.
        let pack = |c1: u8, c2: u8, c3: u8, c4: u8| {
            (u32::from(c1) << 24) | (u32::from(c2) << 16) | (u32::from(c3) << 8) | u32::from(c4)
        };
        assert_eq!(BINDER_TYPE_FD, pack(b'f', b'd', b'*', 0x85));
    }

    #[test]
    fn flat_binder_object_fd_round_trips() {
        let obj = flat_binder_object_fd(7);
        assert_eq!(obj.len(), FLAT_BINDER_OBJECT_SIZE);
        assert_eq!(flat_binder_object_fd_value(&obj), Some(7));
    }

    #[test]
    fn flat_binder_object_fd_value_rejects_wrong_type_and_short() {
        // Wrong type tag.
        let mut bad = flat_binder_object_fd(7);
        if let Some(b) = bad.first_mut() {
            *b ^= 0xff;
        }
        assert_eq!(flat_binder_object_fd_value(&bad), None);
        // Too short.
        assert_eq!(flat_binder_object_fd_value(&[0u8; 8]), None);
    }
}
