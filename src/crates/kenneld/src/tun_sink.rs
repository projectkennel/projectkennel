//! The cross-kennel egress sink: kenneld's handle to the standing tun-broker (§8 / W2).
//!
//! One tun-broker serves every `[net.udp]` consumer. It registers a single **sink node** with
//! kenneld over its own per-kennel bus ([`verb::REGISTER_TUN_SINK`]); kenneld records the broker's
//! `(connection, handle)` here, daemon-global. When a consumer's `facade-tun` connects its
//! `org.projectkennel.tun-udp` `[[consumes]]`, kenneld resolves that consumer's grants + tun `/64` in
//! its own namespace and [`deliver`](TunSink::deliver)s them to this sink — a cross-connection
//! [`verb::DELIVER_TUN_SESSION`] transact from the consumer's binder looper to the broker's connection
//! — and hands the replied per-session fd back to the consumer. The broker being a different process
//! is what makes the synchronous cross-connection call safe: the calling thread holds an outgoing
//! transaction on its stack, so the kernel routes only the reply back (no unrelated node-0 work is
//! stolen), exactly as the inbound mirror's cross-thread push (§7.5.7) does one-way.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use kennel_lib_binder::ctxmgr::ContextManager;
use kennel_lib_binder::service::verb;

/// The death-notification cookie kenneld registers the sink node under.
///
/// A sentinel distinct from every inbound-mirror death cookie (those are handle values, small
/// integers — see [`crate::inbound`]), so the per-kennel death handler can tell a dead sink from a
/// dead mirror and clear the sink rather than mis-route it through the mirror path.
pub const SINK_DEATH_COOKIE: u64 = u64::MAX;

/// The registered egress sink: the tun-broker's connection and the acquired handle to its node.
struct Sink {
    cm: Arc<ContextManager>,
    handle: u32,
}

/// The daemon-global egress sink registry — one tun-broker for the whole daemon.
///
/// Cloned (a cheap `Arc`) into every kennel's binder manager: the broker's manager populates it on
/// [`verb::REGISTER_TUN_SINK`] and clears it on the broker's death; every `[net.udp]` consumer's
/// manager reads it to [`deliver`](Self::deliver) a session.
#[derive(Default, Clone)]
pub struct TunSink {
    inner: Arc<Mutex<Option<Sink>>>,
}

impl std::fmt::Debug for TunSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The sink wraps a ContextManager (not Debug); report only whether one is registered.
        let registered = self.inner.lock().is_ok_and(|g| g.is_some());
        f.debug_struct("TunSink")
            .field("registered", &registered)
            .finish()
    }
}

impl TunSink {
    /// An empty registry (no broker yet). The daemon builds one and clones it into every manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the tun-broker's `(connection, acquired handle)`. A restarted broker re-registers, so
    /// this replaces any prior sink.
    pub fn set(&self, cm: Arc<ContextManager>, handle: u32) {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Sink { cm, handle });
    }

    /// Forget the registered sink (the broker died). A later consume then fails
    /// [`UNAVAILABLE`](kennel_lib_binder::service::status::UNAVAILABLE) until a broker re-registers.
    pub fn clear(&self) {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Deliver one egress session: transact [`verb::DELIVER_TUN_SESSION`] with `payload` (the
    /// consumer's grants + tun `/64`) to the sink and return the broker's minted per-session fd.
    ///
    /// The `(cm, handle)` are cloned out under the lock and the transact runs **without** it held, so
    /// a slow broker never serialises other consumers' setups behind one lock.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotConnected`] if no broker is registered; otherwise the binder transact's
    /// error (a dead/unreachable broker).
    pub fn deliver(&self, payload: &[u8]) -> io::Result<OwnedFd> {
        // Clone `(cm, handle)` out under the lock and release it before the (blocking) transact, so a
        // slow broker never serialises other consumers' setups behind the registry lock.
        let sink = {
            let guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_ref().map(|s| (Arc::clone(&s.cm), s.handle))
        };
        let (cm, handle) = sink.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no tun-broker sink registered")
        })?;
        cm.connection()
            .transact_fd(handle, verb::DELIVER_TUN_SESSION, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_without_a_registered_sink_is_not_connected() {
        let sink = TunSink::new();
        let err = sink.deliver(&[]).expect_err("no sink registered");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn clear_forgets_the_registration_state() {
        // Without a live ContextManager we cannot `set`, but `clear` on an empty registry is a
        // no-op and leaves it reporting unregistered — the shape the death handler relies on.
        let sink = TunSink::new();
        sink.clear();
        assert_eq!(
            sink.deliver(&[]).expect_err("still empty").kind(),
            io::ErrorKind::NotConnected
        );
    }
}
