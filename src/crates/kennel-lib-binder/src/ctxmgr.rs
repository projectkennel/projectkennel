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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::client::{Connection, Incoming};
use crate::sys;

/// A node-0 transaction handler shared across the looper pool.
///
/// `Fn + Send + Sync` because every looper thread calls it concurrently; any state it mutates
/// (the per-kennel registry) sits behind a lock the handler takes only for the O(1) registry
/// verbs, never across a blocking facade call.
pub type Handler = Arc<dyn Fn(&Incoming) -> Reply + Send + Sync>;

/// What a node-0 handler returns for one transaction: reply bytes, a file descriptor,
/// or both (data with an optional fd — the `kennel-bin-init` `GET_SANDBOX_PLAN` pull).
pub enum Reply {
    /// Reply with these payload bytes.
    Data(Vec<u8>),
    /// Reply with this file descriptor (a `BINDER_TYPE_FD` object); the kernel dups
    /// it into the caller. Dropped after the reply (the caller owns its copy).
    Fd(OwnedFd),
    /// Reply with a length-prefixed payload and, when `Some`, a `BINDER_TYPE_FD` object
    /// (the supervision-half bytes plus the controlling-pty fd — `07-2` §7.2.3). The
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
        // Looper registration (BC_ENTER_LOOPER / BC_REGISTER_LOOPER) happens on each serve
        // thread, not here — the driver registers the *calling* thread.
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
    /// lookups are O(1); the relay facades hand work off — `02-4-binder.md`
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
        self.conn.enter_looper()?;
        while !stop.load(Ordering::Acquire) {
            if !self.conn.poll(poll_ms)? {
                continue;
            }
            for incoming in self.conn.recv()? {
                let reply = handler(&incoming);
                self.dispatch_reply(&incoming, reply)?;
            }
        }
        Ok(())
    }

    /// Send `reply` for `incoming` on this thread (binder ties the reply to the receiving
    /// thread's transaction stack — see [`Connection::reply_and_free`]).
    fn dispatch_reply(&self, incoming: &Incoming, reply: Reply) -> io::Result<()> {
        match reply {
            Reply::Data(data) => self.conn.reply_and_free(incoming, &data),
            Reply::Fd(fd) => self.conn.reply_with_fd(incoming, fd.as_fd()),
            Reply::DataAndFd(data, fd) => {
                self.conn
                    .reply_with_data_and_fd(incoming, &data, fd.as_ref().map(AsFd::as_fd))
            }
        }
    }

    /// Serve node 0 with a **thread pool**: each looper receives, handles, and replies to its
    /// own transactions on its own thread.
    ///
    /// A handler that blocks (the af-unix / `INet` facades dial host I/O) occupies one looper
    /// while the others keep serving the registry and lifecycle/TTL verbs. Binder replies are
    /// thread-bound, so this — not a separate reply thread — is how blocking work is made
    /// non-head-of-line (the AOSP looper pattern: one thread at first, growing toward
    /// `max_threads` on the driver's `BR_SPAWN_LOOPER`). Returns the live looper join handles
    /// (the pool grows into this list); the caller sets `stop` and joins them to wind it down.
    ///
    /// # Errors
    ///
    /// Returns the OS error if `set_max_threads` fails.
    pub fn serve_pool(
        self: &Arc<Self>,
        max_threads: u32,
        poll_ms: i32,
        stop: &Arc<AtomicBool>,
        handler: &Handler,
    ) -> io::Result<Arc<Mutex<Vec<JoinHandle<()>>>>> {
        // Non-blocking reads: a transaction may `poll`-wake several loopers, and all but the one
        // that reads it must not block in `BINDER_WRITE_READ` (which would also wedge shutdown).
        self.conn.set_nonblocking()?;
        sys::set_max_threads(self.conn.fd(), max_threads)?;
        let live = Arc::new(AtomicU32::new(0));
        let loopers = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_looper(
            self,
            true,
            max_threads,
            &live,
            &loopers,
            poll_ms,
            stop,
            handler,
        );
        Ok(loopers)
    }

    /// Spawn one looper thread (the first is `entered`, the rest are driver-requested
    /// `register`ed) and record its handle.
    #[allow(clippy::too_many_arguments)]
    fn spawn_looper(
        cm: &Arc<Self>,
        entered: bool,
        max_threads: u32,
        live: &Arc<AtomicU32>,
        loopers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
        poll_ms: i32,
        stop: &Arc<AtomicBool>,
        handler: &Handler,
    ) {
        let cm = Arc::clone(cm);
        let live = Arc::clone(live);
        let loopers_for_loop = Arc::clone(loopers);
        let stop = Arc::clone(stop);
        let handler = Arc::clone(handler);
        let spawned = std::thread::Builder::new()
            .name("kennel-lib-binder-looper".to_owned())
            .spawn(move || {
                live.fetch_add(1, Ordering::AcqRel);
                let _ = if entered {
                    cm.conn.enter_looper()
                } else {
                    cm.conn.register_looper()
                };
                cm.looper_loop(
                    poll_ms,
                    max_threads,
                    &live,
                    &loopers_for_loop,
                    &stop,
                    &handler,
                );
                live.fetch_sub(1, Ordering::AcqRel);
            });
        if let Ok(h) = spawned {
            if let Ok(mut v) = loopers.lock() {
                v.push(h);
            }
        }
    }

    /// One looper thread's loop: poll, receive, grow the pool if the driver asked and we
    /// are below `max_threads`, then handle and reply to each transaction inline.
    fn looper_loop(
        self: &Arc<Self>,
        poll_ms: i32,
        max_threads: u32,
        live: &Arc<AtomicU32>,
        loopers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
        stop: &Arc<AtomicBool>,
        handler: &Handler,
    ) {
        while !stop.load(Ordering::Acquire) {
            match self.conn.poll(poll_ms) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(_) => break,
            }
            let Ok(batch) = self.conn.recv_batch() else {
                break;
            };
            if batch.spawn_looper
                && !stop.load(Ordering::Acquire)
                && live.load(Ordering::Acquire) < max_threads
            {
                Self::spawn_looper(
                    self,
                    false,
                    max_threads,
                    live,
                    loopers,
                    poll_ms,
                    stop,
                    handler,
                );
            }
            for incoming in batch.transactions {
                let reply = handler(&incoming);
                let _ = self.dispatch_reply(&incoming, reply);
            }
        }
    }
}
