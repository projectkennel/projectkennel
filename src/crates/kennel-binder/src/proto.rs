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
    (dir << 30) | ((size & 0x3fff) << 16) | ((ty as u32) << 8) | nr
}

const DIR_NONE: u32 = 0;
const DIR_WRITE: u32 = 1;
const DIR_READ: u32 = 2;

/// Size of `struct binder_transaction_data` (the `BC_/BR_TRANSACTION` payload).
pub const TRANSACTION_DATA_SIZE: usize = 64;
/// Size of `struct binder_ptr_cookie` (`{ binder_uintptr_t ptr; binder_uintptr_t cookie; }`).
pub const PTR_COOKIE_SIZE: usize = 16;

/// The binder protocol version we require (`BINDER_CURRENT_PROTOCOL_VERSION` on a
/// 64-bit kernel).
pub const PROTOCOL_VERSION: i32 = 8;

// BC_* — driver command protocol ('c'). Issued by us into the write buffer.
/// `BC_TRANSACTION`: begin an outbound transaction.
pub const BC_TRANSACTION: u32 = ioc(DIR_WRITE, b'c', 0, TRANSACTION_DATA_SIZE as u32);
/// `BC_REPLY`: reply to a received `BR_TRANSACTION`.
pub const BC_REPLY: u32 = ioc(DIR_WRITE, b'c', 1, TRANSACTION_DATA_SIZE as u32);
/// `BC_FREE_BUFFER`: release a transaction buffer the kernel allocated in our map.
pub const BC_FREE_BUFFER: u32 = ioc(DIR_WRITE, b'c', 3, 8);
/// `BC_INCREFS` / `BC_ACQUIRE` / `BC_RELEASE` / `BC_DECREFS`: handle refcounting.
pub const BC_INCREFS: u32 = ioc(DIR_WRITE, b'c', 4, 4);
pub const BC_ACQUIRE: u32 = ioc(DIR_WRITE, b'c', 5, 4);
pub const BC_RELEASE: u32 = ioc(DIR_WRITE, b'c', 6, 4);
pub const BC_DECREFS: u32 = ioc(DIR_WRITE, b'c', 7, 4);
/// `BC_INCREFS_DONE` / `BC_ACQUIRE_DONE`: ack a kernel `BR_INCREFS`/`BR_ACQUIRE`.
pub const BC_INCREFS_DONE: u32 = ioc(DIR_WRITE, b'c', 8, PTR_COOKIE_SIZE as u32);
pub const BC_ACQUIRE_DONE: u32 = ioc(DIR_WRITE, b'c', 9, PTR_COOKIE_SIZE as u32);
/// `BC_REGISTER_LOOPER` / `BC_ENTER_LOOPER` / `BC_EXIT_LOOPER`: looper lifecycle.
pub const BC_REGISTER_LOOPER: u32 = ioc(DIR_NONE, b'c', 11, 0);
pub const BC_ENTER_LOOPER: u32 = ioc(DIR_NONE, b'c', 12, 0);
pub const BC_EXIT_LOOPER: u32 = ioc(DIR_NONE, b'c', 13, 0);

// BR_* — driver return protocol ('r'). Received by us from the read buffer.
const BR_ERROR: u32 = ioc(DIR_READ, b'r', 0, 4);
const BR_OK: u32 = ioc(DIR_NONE, b'r', 1, 0);
const BR_TRANSACTION: u32 = ioc(DIR_READ, b'r', 2, TRANSACTION_DATA_SIZE as u32);
const BR_REPLY: u32 = ioc(DIR_READ, b'r', 3, TRANSACTION_DATA_SIZE as u32);
const BR_DEAD_REPLY: u32 = ioc(DIR_NONE, b'r', 5, 0);
const BR_TRANSACTION_COMPLETE: u32 = ioc(DIR_NONE, b'r', 6, 0);
const BR_INCREFS: u32 = ioc(DIR_READ, b'r', 7, PTR_COOKIE_SIZE as u32);
const BR_ACQUIRE: u32 = ioc(DIR_READ, b'r', 8, PTR_COOKIE_SIZE as u32);
const BR_RELEASE: u32 = ioc(DIR_READ, b'r', 9, PTR_COOKIE_SIZE as u32);
const BR_DECREFS: u32 = ioc(DIR_READ, b'r', 10, PTR_COOKIE_SIZE as u32);
const BR_NOOP: u32 = ioc(DIR_NONE, b'r', 12, 0);
const BR_SPAWN_LOOPER: u32 = ioc(DIR_NONE, b'r', 13, 0);
const BR_FINISHED: u32 = ioc(DIR_NONE, b'r', 14, 0);
const BR_DEAD_BINDER: u32 = ioc(DIR_READ, b'r', 15, 8);
const BR_FAILED_REPLY: u32 = ioc(DIR_NONE, b'r', 17, 0);

/// Transaction flag: a one-way (async, no reply) transaction (`TF_ONE_WAY`).
pub const TF_ONE_WAY: u32 = 0x01;
/// Transaction flag: replies may carry file descriptors (`TF_ACCEPT_FDS`).
pub const TF_ACCEPT_FDS: u32 = 0x10;

/// A `struct binder_transaction_data`, the payload of a `(BC|BR)_TRANSACTION` /
/// `_REPLY`. Held as plain fields (not a cast `repr(C)`) so encode/decode is
/// alignment-safe over the kernel's (4-byte-aligned) read buffer.
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
        todo!("proto encode")
    }

    /// Parse from the 64-byte layout. `None` if `b` is shorter than the struct.
    ///
    /// # Errors
    ///
    /// Returns `None` (not an error type — this is a decode predicate) when the
    /// slice is too short to hold a `binder_transaction_data`.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let _ = b;
        todo!("proto decode")
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
    /// Refcount management on a local node we own.
    IncRefs { ptr: u64, cookie: u64 },
    Acquire { ptr: u64, cookie: u64 },
    Release { ptr: u64, cookie: u64 },
    DecRefs { ptr: u64, cookie: u64 },
    /// The transaction failed (policy refusal upstream, or a malformed request).
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
/// carries a command code we do not recognise (whose payload length we cannot
/// know to skip safely) — the caller treats that as end-of-buffer / protocol stop.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<(Br, usize)> {
    let _ = buf;
    todo!("proto parse")
}

/// Append a `BC_TRANSACTION` (or `BC_REPLY` when `reply`) and its
/// `binder_transaction_data` to a write buffer.
pub fn write_transaction(out: &mut Vec<u8>, reply: bool, td: &TransactionData) {
    let _ = (out, reply, td);
    todo!("proto write_transaction")
}

/// Append a payload-less `BC_*` command (e.g. `BC_ENTER_LOOPER`).
pub fn write_cmd(out: &mut Vec<u8>, cmd: u32) {
    let _ = (out, cmd);
    todo!("proto write_cmd")
}

/// Append a `BC_FREE_BUFFER` releasing the transaction buffer at `buffer_ptr`.
pub fn write_free_buffer(out: &mut Vec<u8>, buffer_ptr: u64) {
    let _ = (out, buffer_ptr);
    todo!("proto write_free_buffer")
}

/// Append a handle-refcount `BC_*` (`BC_INCREFS`/`ACQUIRE`/`RELEASE`/`DECREFS`).
pub fn write_ref(out: &mut Vec<u8>, cmd: u32, handle: u32) {
    let _ = (out, cmd, handle);
    todo!("proto write_ref")
}

/// Append a `{ptr, cookie}` `BC_*` (`BC_INCREFS_DONE`/`BC_ACQUIRE_DONE`).
pub fn write_ptr_cookie(out: &mut Vec<u8>, cmd: u32, ptr: u64, cookie: u64) {
    let _ = (out, cmd, ptr, cookie);
    todo!("proto write_ptr_cookie")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_match_the_ioc_encoding() {
        // Cross-check a few against the _IOC layout the kernel uses, and a literal.
        assert_eq!(BC_TRANSACTION, ioc(DIR_WRITE, b'c', 0, 64));
        assert_eq!(BC_ENTER_LOOPER, ioc(DIR_NONE, b'c', 12, 0));
        // BC_ENTER_LOOPER = _IO('c',12): dir 0, type 'c'=0x63, nr 12 => 0x630c.
        assert_eq!(BC_ENTER_LOOPER, 0x0000_630c);
        // BR_TRANSACTION = _IOR('r',2,64): dir 2<<30 | 64<<16 | 'r'<<8 | 2.
        assert_eq!(parse_code(BR_TRANSACTION), (2, b'r', 2, 64));
    }

    /// Decompose an `_IOC` value for the assertion above.
    fn parse_code(code: u32) -> (u32, u8, u32, u32) {
        let dir = code >> 30;
        let size = (code >> 16) & 0x3fff;
        let ty = ((code >> 8) & 0xff) as u8;
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
        // A transaction code with no payload: too short.
        assert_eq!(parse(&BR_TRANSACTION.to_ne_bytes()), None);
        // An unknown command code: cannot determine payload length.
        assert_eq!(parse(&0xffff_ffffu32.to_ne_bytes()), None);
        // Empty buffer.
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
}
