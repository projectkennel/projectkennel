//! The binder context manager: node 0 of an instance, and its serve loop.
//!
//! `kenneld` becomes the context manager of each kennel's binderfs instance
//! ([`ContextManager::new`]) and drives [`ContextManager::serve`] on a per-kennel
//! thread, handling each inbound transaction to node 0. This crate provides only
//! the transport — the loop hands each [`Incoming`] to a handler closure and
//! sends back its reply bytes; the registry / reserved-namespace / policy
//! semantics (which service a code names, whether it is granted) live in
//! `kenneld`, layered on this.
//!
//! The loop polls with a timeout so a stop flag is honoured promptly rather than
//! blocking forever in `BINDER_WRITE_READ`.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::client::{Connection, Incoming};
use crate::sys;

/// What a node-0 handler returns for one transaction: reply bytes, a file descriptor,
/// or both (data with an optional fd — the `kennel-init` `GET_SANDBOX_PLAN` pull).
pub enum Reply {
    /// Reply with these payload bytes.
    Data(Vec<u8>),
    /// Reply with this file descriptor (a `BINDER_TYPE_FD` object); the kernel dups
    /// it into the caller. Dropped after the reply (the caller owns its copy).
    Fd(OwnedFd),
    /// Reply with a length-prefixed payload and, when `Some`, a `BINDER_TYPE_FD` object
    /// (the supervision-half bytes plus the controlling-pty fd — `07-11` §7.2.3). The
    /// receiver decodes it with [`Connection::transact_with_fd`].
    DataAndFd(Vec<u8>, Option<OwnedFd>),
}

/// A context-manager endpoint owning node 0 of one binder instance.
pub struct ContextManager {
    conn: Connection,
}

impl ContextManager {
    /// Take node 0 of the instance behind `device_fd` and enter its looper.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the version/`mmap` open fails, the
    /// `BINDER_SET_CONTEXT_MGR` is refused (another manager already holds the
    /// instance, `EBUSY`), or entering the looper fails.
    pub fn new(device_fd: OwnedFd, map_size: usize) -> io::Result<Self> {
        let conn = Connection::open(device_fd, map_size)?;
        sys::set_context_mgr(conn.fd())?;
        conn.enter_looper()?;
        Ok(Self { conn })
    }

    /// Borrow the underlying connection (for tests / advanced drivers).
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Serve node 0 until `stop` is set: poll up to `poll_ms`, then handle each
    /// inbound transaction by calling `handler` and replying with its bytes.
    ///
    /// `handler` runs on the serve thread and must not block on I/O (registry
    /// lookups are O(1); the relay facades hand work off — `02-7-binder.md`
    /// §Threading model).
    ///
    /// # Errors
    ///
    /// Returns the OS error if a poll, receive, or reply `BINDER_WRITE_READ` fails.
    pub fn serve(
        &self,
        poll_ms: i32,
        stop: &AtomicBool,
        mut handler: impl FnMut(&Incoming) -> Reply,
    ) -> io::Result<()> {
        while !stop.load(Ordering::Acquire) {
            if !self.conn.poll(poll_ms)? {
                continue;
            }
            for incoming in self.conn.recv()? {
                match handler(&incoming) {
                    Reply::Data(data) => self.conn.reply_and_free(&incoming, &data)?,
                    Reply::Fd(fd) => self.conn.reply_with_fd(&incoming, fd.as_fd())?,
                    Reply::DataAndFd(data, fd) => self.conn.reply_with_data_and_fd(
                        &incoming,
                        &data,
                        fd.as_ref().map(AsFd::as_fd),
                    )?,
                }
            }
        }
        Ok(())
    }
}
