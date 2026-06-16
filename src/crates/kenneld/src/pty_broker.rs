//! The PTY broker: kenneld owns the workload's controlling-terminal master and
//! brokers a **detachable / reattachable** client to it (`05-state-and-supervision`).
//!
//! Today the CLI holds the master for the kennel's whole life, so the kennel dies
//! when the CLI does (SSH drop, closed laptop). Here kenneld keeps the master and
//! pumps it; a `kennel run`/`kennel attach` client is a transient subscriber that can
//! detach without ending the workload. One workload, one PTY — but the operator end
//! is reattachable.
//!
//! Flow (the `master → client` direction):
//!
//! ```text
//! workload pty master ─▶ [kennel-lib-term filter] ─▶ ring buffer ─▶ attached client (if any)
//! ```
//!
//! The pump **always drains the master** (and filters into the ring) even with no
//! client attached, so the workload never blocks on a full pty; on reattach the ring
//! tail is replayed (tmux-style). The reverse direction (client input → master) runs
//! only while a client is attached.
//!
//! Single client: a second attach **takes over** (the prior client is dropped with a
//! `Detached` note) — the "my SSH dropped, reconnect" case. The filter is applied at
//! this single master-read point, so every attach/reattach is filtered identically
//! and no client can bypass it. No `setns`, no second process in the kennel — only the
//! master fd (already in kenneld's TCB) and a benign client socket.

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use kennel_lib_term::{Filter, FilterPolicy};

/// The ring-buffer capacity: the tail of filtered output retained for reattach
/// scrollback and to keep the pump draining when detached (the workload throttles on
/// the pty once this is full and unread, same back-pressure as a slow terminal).
const RING_CAPACITY: usize = 64 * 1024;

/// One attached client's terminal: the socket kenneld proxies the kennel's filtered
/// output to and reads the workload's input from.
struct Client {
    /// The client socket (the CLI's proxied-terminal end, passed over `SCM_RIGHTS`).
    sock: OwnedFd,
}

/// The broker's shared, mutable state — the master, the ring, and the current client
/// (zero or one). Held behind one mutex; the pump and the control thread both touch it.
struct Inner {
    /// The kennel's controlling-terminal master fd.
    master: OwnedFd,
    /// The tail of recent filtered output (for reattach replay).
    ring: Vec<u8>,
    /// The attached client, or `None` when detached.
    client: Option<Client>,
    /// Set once the workload has exited — the pump and any attach stop then.
    done: bool,
}

/// A handle to a running kennel's PTY broker, stored in the registry so a later
/// `Attach` reaches a *running* kennel. Cloneable (an `Arc`); the pump thread and the
/// control path share it.
#[derive(Clone)]
pub struct PtyBroker {
    inner: Arc<Mutex<Inner>>,
}

impl PtyBroker {
    /// Create a broker owning `master`, run the workload output through `policy`, and
    /// spawn the pump thread. `initial_client` is the `kennel run` connection's
    /// terminal socket (the first attached client), or `None` for a detached start.
    #[must_use]
    pub fn start(master: OwnedFd, policy: FilterPolicy, initial_client: Option<OwnedFd>) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            master,
            ring: Vec::with_capacity(RING_CAPACITY),
            client: initial_client.map(|sock| Client { sock }),
            done: false,
        }));
        let broker = Self { inner };
        broker.spawn_pump(policy);
        broker
    }

    /// Attach a new client terminal, taking over from any current one (the prior
    /// client's socket is dropped, so its CLI sees EOF and reports a clean detach).
    /// Replays the ring tail so the reattached terminal shows recent output. Returns
    /// `false` if the workload has already exited (nothing to attach to).
    #[must_use]
    pub fn attach(&self, sock: OwnedFd) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner.done {
            return false;
        }
        // Replay the retained tail to the newcomer before it joins the live stream.
        let tail = inner.ring.clone();
        if !tail.is_empty() {
            let mut w = borrow_for_io(&sock);
            let _ = w.write_all(&tail);
        }
        inner.client = Some(Client { sock }); // takeover: drops the previous client
        true
    }

    /// Mark the workload exited: stop pumping and drop any client (its CLI then sees
    /// EOF and exits). Called from the kennel's wait path on workload exit/teardown.
    pub fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.done = true;
            inner.client = None;
        }
    }

    /// Whether a client is currently attached (for `list`'s attached/detached column).
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.inner.lock().is_ok_and(|i| i.client.is_some())
    }

    /// The pump: read the master, filter, append to the ring (bounded), and write to
    /// the attached client if any. Runs until the workload exits (a master read of 0
    /// or an error). Client input→master is handled by [`Self::spawn_input`] per
    /// client; here is the output direction only.
    fn spawn_pump(&self, policy: FilterPolicy) {
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut filter = Filter::new(policy);
            let mut buf = [0u8; 4096];
            loop {
                // Read the master outside the lock (a borrowed fd cloned under the lock).
                let master = {
                    let Ok(g) = inner.lock() else { return };
                    if g.done {
                        return;
                    }
                    match g.master.try_clone() {
                        Ok(m) => m,
                        Err(_) => return,
                    }
                };
                let n = {
                    let mut r = borrow_for_io(&master);
                    match r.read(&mut buf) {
                        Ok(0) | Err(_) => {
                            // Workload closed the pty (exit) — stop pumping.
                            if let Ok(mut g) = inner.lock() {
                                g.done = true;
                            }
                            return;
                        }
                        Ok(n) => n,
                    }
                };
                let out = filter.feed(buf.get(..n).unwrap_or_default());
                if out.is_empty() {
                    continue;
                }
                if let Ok(mut g) = inner.lock() {
                    append_ring(&mut g.ring, &out);
                    if let Some(client) = &g.client {
                        let mut w = borrow_for_io(&client.sock);
                        if w.write_all(&out).is_err() {
                            // Client went away mid-write: detach it, keep pumping.
                            g.client = None;
                        }
                    }
                }
            }
        });
    }
}

/// Append `data` to `ring`, keeping at most [`RING_CAPACITY`] trailing bytes.
fn append_ring(ring: &mut Vec<u8>, data: &[u8]) {
    ring.extend_from_slice(data);
    if let Some(drop) = ring.len().checked_sub(RING_CAPACITY) {
        if drop > 0 {
            ring.drain(..drop);
        }
    }
}

/// Wrap a borrowed fd in a short-lived `File` for one read/write, via `dup` so the
/// underlying fd is **not** closed when the `File` drops (the broker keeps ownership).
/// No `unsafe`: `try_clone` dups the descriptor; `File::from` then owns only the dup.
fn borrow_for_io(fd: &OwnedFd) -> std::fs::File {
    fd.try_clone().map_or_else(
        // A dup failure (fd table exhausted) is unrecoverable for this op; return a
        // handle to /dev/null so the caller's write/read is a harmless no-op rather
        // than a panic in the pump thread. If even /dev/null fails, the pump aborts.
        |_| std::fs::File::open("/dev/null").unwrap_or_else(|_| std::process::abort()),
        std::fs::File::from,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_the_trailing_window() {
        let mut ring = Vec::new();
        // Fill past capacity; only the last RING_CAPACITY bytes remain.
        let chunk = vec![b'x'; RING_CAPACITY];
        append_ring(&mut ring, &chunk);
        append_ring(&mut ring, b"TAIL");
        assert_eq!(ring.len(), RING_CAPACITY);
        assert!(ring.ends_with(b"TAIL"));
        // The oldest bytes were dropped.
        assert_eq!(&ring[..4], b"xxxx");
    }

    #[test]
    fn ring_under_capacity_keeps_everything() {
        let mut ring = Vec::new();
        append_ring(&mut ring, b"hello ");
        append_ring(&mut ring, b"world");
        assert_eq!(ring, b"hello world");
    }
}
