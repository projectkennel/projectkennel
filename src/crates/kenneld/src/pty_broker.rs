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
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::{Arc, Condvar, Mutex};

use kennel_lib_term::{Filter, FilterPolicy};

/// Why a client's session ended (the `kennel run`/`kennel attach` outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The workload exited — the kennel is gone; the caller reports `Exited`.
    WorkloadExited,
    /// This client was superseded by a take-over (another `attach`); report `Detached`.
    TakenOver,
}

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
    /// Monotonic client generation; bumped on each attach so a superseded client's
    /// input thread can detect it has been replaced and exit.
    generation: u64,
    /// Set once the workload has exited — the pump and any attach stop then.
    done: bool,
}

/// A handle to a running kennel's PTY broker, stored in the registry so a later
/// `Attach` reaches a *running* kennel. Cloneable (an `Arc`); the pump thread and the
/// control path share it.
#[derive(Clone)]
pub struct PtyBroker {
    inner: Arc<Mutex<Inner>>,
    /// Notified when `generation` or `done` changes, so a waiting `run_attach` learns
    /// it was taken over or the workload exited.
    changed: Arc<Condvar>,
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
            client: None,
            generation: 0,
            done: false,
        }));
        let broker = Self {
            inner,
            changed: Arc::new(Condvar::new()),
        };
        broker.spawn_pump(policy);
        if let Some(sock) = initial_client {
            let _ = broker.attach(sock);
        }
        broker
    }

    /// Attach a new client terminal, taking over from any current one (the prior
    /// client's socket is dropped, so its CLI sees EOF and reports a clean detach).
    /// Replays the ring tail so the reattached terminal shows recent output, then
    /// spawns the client→master input thread. Returns this attach's generation (pass
    /// it to [`Self::wait_for_outcome`]), or `None` if the workload has already exited.
    #[must_use]
    pub fn attach(&self, sock: OwnedFd) -> Option<u64> {
        let generation = {
            let Ok(mut inner) = self.inner.lock() else {
                return None;
            };
            if inner.done {
                return None;
            }
            // Replay the retained tail to the newcomer before it joins the live stream.
            let tail = inner.ring.clone();
            if !tail.is_empty() {
                let mut w = borrow_for_io(&sock);
                let _ = w.write_all(&tail);
            }
            inner.generation = inner.generation.wrapping_add(1);
            let generation = inner.generation;
            let input_sock = borrow_for_io(&sock); // a dup for the input thread
            inner.client = Some(Client { sock }); // takeover: drops prior client
                                                  // Spawn the client→master input thread for this generation.
            if let Ok(master) = inner.master.try_clone() {
                self.spawn_input(input_sock, master, generation);
            }
            generation
        };
        // Wake any prior client's `wait_for_outcome` (it was taken over).
        self.changed.notify_all();
        Some(generation)
    }

    /// Block until this client's session ends: the workload exits ([`AttachOutcome::
    /// WorkloadExited`]) or a take-over supersedes this `generation`
    /// ([`AttachOutcome::TakenOver`]). The caller (`run_kennel`/`run_attach`) reports
    /// `Exited`/`Detached` accordingly.
    #[must_use]
    pub fn wait_for_outcome(&self, generation: u64) -> AttachOutcome {
        let Ok(mut inner) = self.inner.lock() else {
            return AttachOutcome::WorkloadExited;
        };
        loop {
            if inner.done {
                return AttachOutcome::WorkloadExited;
            }
            if inner.generation != generation {
                return AttachOutcome::TakenOver;
            }
            match self.changed.wait(inner) {
                Ok(g) => inner = g,
                Err(_) => return AttachOutcome::WorkloadExited,
            }
        }
    }

    /// Spawn the client→master input thread: copy the client's keystrokes to the pty
    /// master until the client closes, the workload exits, or this client is superseded
    /// by a take-over (generation mismatch).
    fn spawn_input(&self, mut client_in: std::fs::File, master: OwnedFd, generation: u64) {
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let n = match client_in.read(&mut buf) {
                    Ok(0) | Err(_) => break, // client detached / closed
                    Ok(n) => n,
                };
                let Ok(g) = inner.lock() else { break };
                if g.done || g.generation != generation {
                    break; // workload gone, or we were taken over
                }
                let mut w = borrow_for_io(&g.master);
                drop(g);
                if w.write_all(buf.get(..n).unwrap_or_default()).is_err() {
                    break;
                }
            }
            let _ = &master; // keep the master dup alive for this thread's lifetime
        });
    }

    /// Mark the workload exited: stop pumping and drop any client (its CLI then sees
    /// EOF and exits). Called from the kennel's wait path on workload exit/teardown.
    pub fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.done = true;
            inner.client = None;
        }
        self.changed.notify_all();
    }

    /// Whether a client is currently attached (for `list`'s attached/detached column).
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.inner.lock().is_ok_and(|i| i.client.is_some())
    }

    /// Resize the workload's pty (`TIOCSWINSZ` on the master, raising `SIGWINCH`
    /// inside the kennel). The broker holds the master, so the client relays its
    /// window size here on `SIGWINCH` rather than touching the fd itself.
    pub fn resize(&self, rows: u16, cols: u16) {
        if let Ok(inner) = self.inner.lock() {
            if inner.done {
                return;
            }
            let ws = kennel_lib_syscall::pty::Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let _ = kennel_lib_syscall::pty::set_winsize(inner.master.as_fd(), &ws);
        }
    }

    /// The pump: read the master, filter, append to the ring (bounded), and write to
    /// the attached client if any. Runs until the workload exits (a master read of 0
    /// or an error). Client input→master is handled by [`Self::spawn_input`] per
    /// client; here is the output direction only.
    fn spawn_pump(&self, policy: FilterPolicy) {
        let inner = Arc::clone(&self.inner);
        let changed = Arc::clone(&self.changed);
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
                            // Workload closed the pty (exit) — stop pumping and wake a
                            // waiting client (it reports WorkloadExited).
                            if let Ok(mut g) = inner.lock() {
                                g.done = true;
                            }
                            changed.notify_all();
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
        assert_eq!(ring.get(..4), Some(b"xxxx".as_slice()));
    }

    #[test]
    fn ring_under_capacity_keeps_everything() {
        let mut ring = Vec::new();
        append_ring(&mut ring, b"hello ");
        append_ring(&mut ring, b"world");
        assert_eq!(ring, b"hello world");
    }
}
