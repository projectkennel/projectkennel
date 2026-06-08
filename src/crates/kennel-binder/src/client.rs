//! A binder connection: one `open` of the device, its `mmap`ped buffer, and the
//! `BINDER_WRITE_READ` cycle both endpoints ride.
//!
//! Each participant in a binder instance (the context manager, a service, a
//! client) is a distinct open of the device with its own mapping and looper.
//! [`Connection`] wraps one such open and provides the synchronous client call
//! ([`Connection::transact`]) and the receive/reply primitives the context
//! manager ([`crate::ctxmgr`]) drives. Transaction *payloads* are opaque bytes
//! here; service-name semantics live a layer up in `kenneld`.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::proto::{self, Br, TransactionData};
use crate::sys::{self, BinderWriteRead, Mapping};

/// Read-buffer capacity for one `BINDER_WRITE_READ` cycle (room for several
/// framed `BR_*` commands; the loop spans cycles if more arrive).
const READ_CAP: usize = 4096;

/// The context-manager node: binder reserves handle 0 for it.
pub const CONTEXT_MANAGER_HANDLE: u32 = 0;

/// An inbound transaction received by a node we own.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// The transaction code (method selector).
    pub code: u32,
    /// The transaction payload bytes (copied out of the mapping).
    pub data: Vec<u8>,
    /// The sending process pid (kernel-attested).
    pub sender_pid: i32,
    /// The sending process euid (kernel-attested).
    pub sender_euid: u32,
    /// The kernel buffer holding the data, to release with `BC_FREE_BUFFER` after
    /// the reply is sent.
    pub buffer: u64,
}

/// One open binder endpoint.
pub struct Connection {
    fd: OwnedFd,
    map: Mapping,
}

impl Connection {
    /// Open a binder endpoint over an already-opened device `fd`, verifying the
    /// protocol version and mapping a `map_size`-byte buffer.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the version ioctl or `mmap` fails, or
    /// [`io::ErrorKind::Unsupported`] if the driver's protocol version is not
    /// [`proto::PROTOCOL_VERSION`].
    pub fn open(fd: OwnedFd, map_size: usize) -> io::Result<Self> {
        let version = sys::version(fd.as_fd())?;
        if version != proto::PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "binder protocol version {version}, need {}",
                    proto::PROTOCOL_VERSION
                ),
            ));
        }
        let map = sys::map(fd.as_fd(), map_size)?;
        Ok(Self { fd, map })
    }

    /// Borrow the underlying device fd (for `set_context_mgr` / `poll`).
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Wait up to `timeout_ms` for inbound work; see [`sys::poll_in`].
    ///
    /// # Errors
    ///
    /// Returns the OS error if `poll(2)` fails.
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        sys::poll_in(self.fd.as_fd(), timeout_ms)
    }

    /// Announce this thread as a binder looper (`BC_ENTER_LOOPER`).
    ///
    /// # Errors
    ///
    /// Returns the OS error if the command cannot be written.
    pub fn enter_looper(&self) -> io::Result<()> {
        let mut w = Vec::new();
        proto::write_cmd(&mut w, proto::BC_ENTER_LOOPER);
        self.write_only(&w)
    }

    /// Send a synchronous transaction to `handle` with `code` and `data`, blocking
    /// until the reply, which is returned as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Other`] if the driver reports the transaction
    /// failed or the target is dead, or the OS error if a `BINDER_WRITE_READ` or a
    /// reply-buffer copy fails.
    pub fn transact(&self, handle: u32, code: u32, data: &[u8]) -> io::Result<Vec<u8>> {
        let td = TransactionData {
            target: u64::from(handle),
            code,
            data_size: len_u64(data.len())?,
            buffer: data.as_ptr() as u64,
            ..TransactionData::default()
        };
        let mut write = Vec::new();
        proto::write_transaction(&mut write, false, &td);
        let mut to_send: &[u8] = &write;
        loop {
            let brs = self.cycle(to_send)?;
            to_send = &[];
            self.ack_refcounts(&brs)?;
            for br in brs {
                match br {
                    Br::Reply(reply) => return self.take_buffer(reply),
                    Br::Failed => {
                        let errno = sys::extended_error(self.fd.as_fd()).unwrap_or(0);
                        return Err(io::Error::other(format!(
                            "binder transaction failed (BR_FAILED_REPLY, extended errno {errno})"
                        )));
                    }
                    Br::Dead => return Err(io::Error::other("binder target dead (BR_DEAD_REPLY)")),
                    Br::Error(code) => {
                        return Err(io::Error::other(format!("binder driver error {code}")))
                    }
                    _ => {}
                }
            }
        }
    }

    /// Send a synchronous transaction expecting a file descriptor in the reply (the
    /// af-unix facade: `CONNECT` a path, receive the connected socket — `07-9`/`02-7`).
    /// Sets `TF_ACCEPT_FDS` so the kernel permits the reply's fd, and returns the fd
    /// the kernel dup'd into us.
    ///
    /// # Errors
    ///
    /// As [`Self::transact`], plus [`io::ErrorKind::InvalidData`] if the reply carries
    /// no `BINDER_TYPE_FD` object or an invalid fd.
    pub fn transact_fd(&self, handle: u32, code: u32, data: &[u8]) -> io::Result<OwnedFd> {
        let td = TransactionData {
            target: u64::from(handle),
            code,
            flags: proto::TF_ACCEPT_FDS,
            data_size: len_u64(data.len())?,
            buffer: data.as_ptr() as u64,
            ..TransactionData::default()
        };
        let mut write = Vec::new();
        proto::write_transaction(&mut write, false, &td);
        let mut to_send: &[u8] = &write;
        loop {
            let brs = self.cycle(to_send)?;
            to_send = &[];
            self.ack_refcounts(&brs)?;
            for br in brs {
                match br {
                    Br::Reply(reply) => return self.take_fd(reply),
                    Br::Failed => {
                        let errno = sys::extended_error(self.fd.as_fd()).unwrap_or(0);
                        return Err(io::Error::other(format!(
                            "binder fd transaction failed (BR_FAILED_REPLY, extended errno {errno})"
                        )));
                    }
                    Br::Dead => return Err(io::Error::other("binder target dead (BR_DEAD_REPLY)")),
                    Br::Error(code) => {
                        return Err(io::Error::other(format!("binder driver error {code}")))
                    }
                    _ => {}
                }
            }
        }
    }

    /// Send a synchronous transaction expecting **data and, optionally, a file
    /// descriptor** in one reply (the `kennel-init` `GET_SANDBOX_PLAN` pull: the
    /// supervision-half bytes plus the controlling-pty fd — `07-11` §7.11.3). Sets
    /// `TF_ACCEPT_FDS` and returns the data bytes with the fd, or `None` if the reply
    /// carried no fd object.
    ///
    /// # Reply wire format (shared with the serving end)
    ///
    /// The reply data buffer is `[u32 data_len LE][data_len payload bytes]`, optionally
    /// followed by padding to an 8-byte boundary and one `BINDER_TYPE_FD`
    /// `flat_binder_object`. When an fd is present the transaction's single offset points
    /// at that object; when absent the offsets array is empty. The explicit length prefix
    /// lets the receiver hand the decoder *exactly* the payload, never the alignment
    /// padding (which a strict, trailing-byte-rejecting decoder would refuse).
    ///
    /// # Errors
    ///
    /// As [`Self::transact`], plus [`io::ErrorKind::InvalidData`] if the reply is shorter
    /// than its own length prefix or its fd object is malformed.
    pub fn transact_with_fd(
        &self,
        handle: u32,
        code: u32,
        data: &[u8],
    ) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
        let td = TransactionData {
            target: u64::from(handle),
            code,
            flags: proto::TF_ACCEPT_FDS,
            data_size: len_u64(data.len())?,
            buffer: data.as_ptr() as u64,
            ..TransactionData::default()
        };
        let mut write = Vec::new();
        proto::write_transaction(&mut write, false, &td);
        let mut to_send: &[u8] = &write;
        loop {
            let brs = self.cycle(to_send)?;
            to_send = &[];
            self.ack_refcounts(&brs)?;
            for br in brs {
                match br {
                    Br::Reply(reply) => return self.take_data_and_fd(reply),
                    Br::Failed => {
                        let errno = sys::extended_error(self.fd.as_fd()).unwrap_or(0);
                        return Err(io::Error::other(format!(
                            "binder data+fd transaction failed (BR_FAILED_REPLY, extended errno {errno})"
                        )));
                    }
                    Br::Dead => return Err(io::Error::other("binder target dead (BR_DEAD_REPLY)")),
                    Br::Error(code) => {
                        return Err(io::Error::other(format!("binder driver error {code}")))
                    }
                    _ => {}
                }
            }
        }
    }

    /// Reply to a received transaction with a single file descriptor (a
    /// `BINDER_TYPE_FD` object), then free its inbound buffer. The kernel dups `fd`
    /// into the original caller. Used by the af-unix facade to return a connected
    /// socket.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the `BINDER_WRITE_READ` fails.
    pub fn reply_with_fd(&self, incoming: &Incoming, fd: BorrowedFd<'_>) -> io::Result<()> {
        let object = proto::flat_binder_object_fd(fd.as_raw_fd());
        let offsets: [u64; 1] = [0]; // the single object sits at offset 0 in `object`
        let td = TransactionData {
            flags: proto::TF_ACCEPT_FDS,
            data_size: len_u64(object.len())?,
            offsets_size: len_u64(std::mem::size_of_val(&offsets))?,
            buffer: object.as_ptr() as u64,
            offsets: offsets.as_ptr() as u64,
            ..TransactionData::default()
        };
        let mut write = Vec::new();
        proto::write_transaction(&mut write, true, &td);
        proto::write_free_buffer(&mut write, incoming.buffer);
        self.write_only(&write)
    }

    /// Extract the fd from a `BINDER_TYPE_FD` reply, then free the reply buffer.
    fn take_fd(&self, reply: TransactionData) -> io::Result<OwnedFd> {
        let bytes = self
            .map
            .read_at(reply.buffer, proto::FLAT_BINDER_OBJECT_SIZE)
            .ok_or_else(|| io::Error::other("reply fd-object out of range"))?;
        let raw = proto::flat_binder_object_fd_value(bytes)
            .filter(|&fd| fd >= 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reply carried no valid fd object",
                )
            })?;
        let owned = sys::own_fd(raw);
        let mut w = Vec::new();
        proto::write_free_buffer(&mut w, reply.buffer);
        self.write_only(&w)?;
        Ok(owned)
    }

    /// Extract the length-prefixed payload and the optional fd from a data-and-fd
    /// reply (the [`Self::transact_with_fd`] format), then free the reply buffer.
    fn take_data_and_fd(&self, reply: TransactionData) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
        let total = usize::try_from(reply.data_size).unwrap_or(0);
        let buf = self
            .map
            .read_at(reply.buffer, total)
            .ok_or_else(|| io::Error::other("reply buffer out of range"))?;
        // The u32 length prefix bounds the payload exactly (excludes alignment padding).
        let len_bytes: [u8; 4] = buf
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reply missing length prefix"))?;
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        let payload = buf
            .get(4..4usize.saturating_add(payload_len))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "reply shorter than its length prefix")
            })?
            .to_vec();

        // An fd rides only when the reply declared at least one offset (its object
        // position). The offsets array is a native-order u64 array (kernel convention).
        let fd = if reply.offsets_size >= 8 {
            let off_bytes = self
                .map
                .read_at(reply.offsets, 8)
                .and_then(|s| <[u8; 8]>::try_from(s).ok())
                .ok_or_else(|| io::Error::other("reply offsets out of range"))?;
            let obj_off = u64::from_ne_bytes(off_bytes);
            let obj = self
                .map
                .read_at(reply.buffer.wrapping_add(obj_off), proto::FLAT_BINDER_OBJECT_SIZE)
                .ok_or_else(|| io::Error::other("reply fd-object out of range"))?;
            let raw = proto::flat_binder_object_fd_value(obj)
                .filter(|&fd| fd >= 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "reply carried no valid fd object")
                })?;
            Some(sys::own_fd(raw))
        } else {
            None
        };

        let mut w = Vec::new();
        proto::write_free_buffer(&mut w, reply.buffer);
        self.write_only(&w)?;
        Ok((payload, fd))
    }

    /// Receive any transactions delivered in one cycle (after `poll` signalled
    /// work), auto-acking node refcount commands. Returns the inbound transactions
    /// for the caller to handle and reply to with [`Self::reply_and_free`].
    ///
    /// # Errors
    ///
    /// Returns the OS error if the `BINDER_WRITE_READ` or a payload copy fails.
    pub fn recv(&self) -> io::Result<Vec<Incoming>> {
        let brs = self.cycle(&[])?;
        self.ack_refcounts(&brs)?;
        let mut out = Vec::new();
        for br in brs {
            if let Br::Transaction(td) = br {
                let len = usize::try_from(td.data_size).unwrap_or(0);
                let data = self
                    .map
                    .read_at(td.buffer, len)
                    .ok_or_else(|| io::Error::other("transaction buffer out of range"))?
                    .to_vec();
                out.push(Incoming {
                    code: td.code,
                    data,
                    sender_pid: td.sender_pid,
                    sender_euid: td.sender_euid,
                    buffer: td.buffer,
                });
            }
        }
        Ok(out)
    }

    /// Reply to the most recently received transaction with `data`, then free its
    /// inbound buffer. Must be called on the same thread that `recv`d it (binder
    /// tracks the transaction stack per thread).
    ///
    /// # Errors
    ///
    /// Returns the OS error if the `BINDER_WRITE_READ` fails.
    pub fn reply_and_free(&self, incoming: &Incoming, data: &[u8]) -> io::Result<()> {
        let td = TransactionData {
            data_size: len_u64(data.len())?,
            buffer: data.as_ptr() as u64,
            ..TransactionData::default()
        };
        let mut write = Vec::new();
        proto::write_transaction(&mut write, true, &td);
        proto::write_free_buffer(&mut write, incoming.buffer);
        // Write-only: the BR_TRANSACTION_COMPLETE for this reply is drained by the
        // next serve cycle; blocking to read it here would stall the looper.
        self.write_only(&write)
    }

    /// Copy a reply's data out of the mapping and free its buffer.
    fn take_buffer(&self, reply: TransactionData) -> io::Result<Vec<u8>> {
        let len = usize::try_from(reply.data_size).unwrap_or(0);
        let bytes = self
            .map
            .read_at(reply.buffer, len)
            .ok_or_else(|| io::Error::other("reply buffer out of range"))?
            .to_vec();
        let mut w = Vec::new();
        proto::write_free_buffer(&mut w, reply.buffer);
        self.write_only(&w)?;
        Ok(bytes)
    }

    /// Ack any kernel-requested strong/weak references on our local nodes so the
    /// driver's bookkeeping stays balanced (`BR_INCREFS`/`BR_ACQUIRE` →
    /// `BC_INCREFS_DONE`/`BC_ACQUIRE_DONE`); releases need no ack.
    fn ack_refcounts(&self, brs: &[Br]) -> io::Result<()> {
        let mut w = Vec::new();
        for br in brs {
            match *br {
                Br::IncRefs { ptr, cookie } => {
                    proto::write_ptr_cookie(&mut w, proto::BC_INCREFS_DONE, ptr, cookie);
                }
                Br::Acquire { ptr, cookie } => {
                    proto::write_ptr_cookie(&mut w, proto::BC_ACQUIRE_DONE, ptr, cookie);
                }
                _ => {}
            }
        }
        if !w.is_empty() {
            self.write_only(&w)?;
        }
        Ok(())
    }

    /// Issue `BC_*` commands without waiting to read any `BR_*` (so a write-only
    /// command never blocks the caller in `BINDER_WRITE_READ`).
    fn write_only(&self, write: &[u8]) -> io::Result<()> {
        let mut bwr = BinderWriteRead {
            write_size: len_u64(write.len())?,
            write_consumed: 0,
            write_buffer: write.as_ptr() as u64,
            read_size: 0,
            read_consumed: 0,
            read_buffer: 0,
        };
        sys::write_read(self.fd.as_fd(), &mut bwr)
    }

    /// Run one `BINDER_WRITE_READ`: hand the driver `write` (`BC_*` commands) and
    /// parse the `BR_*` commands it returns.
    fn cycle(&self, write: &[u8]) -> io::Result<Vec<Br>> {
        let mut read = [0u8; READ_CAP];
        let mut bwr = BinderWriteRead {
            write_size: len_u64(write.len())?,
            write_consumed: 0,
            write_buffer: write.as_ptr() as u64,
            read_size: len_u64(read.len())?,
            read_consumed: 0,
            read_buffer: read.as_mut_ptr() as u64,
        };
        sys::write_read(self.fd.as_fd(), &mut bwr)?;
        let n = usize::try_from(bwr.read_consumed).unwrap_or(0);
        let mut rest = read.get(..n).unwrap_or(&[]);
        let mut out = Vec::new();
        while let Some((br, consumed)) = proto::parse(rest) {
            out.push(br);
            rest = rest.get(consumed..).unwrap_or(&[]);
            if rest.is_empty() {
                break;
            }
        }
        Ok(out)
    }
}

/// Convert a buffer length to the `u64` binder uses, rejecting the impossible.
fn len_u64(len: usize) -> io::Result<u64> {
    u64::try_from(len).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length too large"))
}
