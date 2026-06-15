//! The inbound BIND runtime: kenneld as the fd router for the §7.5.7 host-side mirror.
//!
//! The reverse of [`crate::inet`]'s egress dial. The `[net.bpf].bind` cgroup ACL already decided —
//! at the workload's `bind()` — which ports the kennel may listen on, so there is **no policy
//! decision here**: kenneld eagerly registers each policy-mirrored port with the `host-inetd`
//! delegate, which binds it on the host loopback, accepts, splices each connection locally, and
//! pushes back the conduit's *kennel* end. kenneld holds those pending ends in a per-port queue;
//! `facade-client` collects them with [`verb::BIND_INET`] and connects the workload's listener.
//!
//! **Looper-safe by construction.** The `BIND_INET` handler ([`InboundRuntime::take_pending`]) only ever pops a
//! ready fd or returns `AGAIN` — it never parks a binder looper waiting for a connection. The
//! unbounded wait lives in the `host-inetd` reader thread ([`run_reader`]), off the binder pool.
//!
//! [`verb::BIND_INET`]: kennel_lib_binder::service::verb::BIND_INET

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;

/// The per-kennel inbound conduit queues: ready conduit kennel-ends keyed by mirrored port.
///
/// Filled by [`run_reader`] (the `host-inetd` notification thread) and drained by [`InboundRuntime::take_pending`]
/// (the `BIND_INET` binder handler). Shared `Arc<InboundRuntime>` across the binder loopers and the
/// reader thread, like [`crate::inet::NetRuntime`].
#[derive(Debug, Default)]
pub struct InboundRuntime {
    pending: Mutex<HashMap<u16, VecDeque<OwnedFd>>>,
}

impl InboundRuntime {
    /// An empty runtime (no mirrored ports). The default for a kennel with no inbound mirror.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pop a ready conduit kennel-end for `port`, if one is pending.
    ///
    /// The `BIND_INET` handler calls this and replies with the fd (a hit) or `AGAIN` (`None`). It
    /// never blocks: the bounded poll is the facade-client's re-arm loop, never a parked looper.
    #[must_use]
    pub fn take_pending(&self, port: u16) -> Option<OwnedFd> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.get_mut(&port).and_then(VecDeque::pop_front)
    }

    /// Enqueue a conduit kennel-end for `port` (the reader thread, per `host-inetd` notification).
    fn enqueue(&self, port: u16, fd: OwnedFd) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.entry(port).or_default().push_back(fd);
    }
}

/// Register a mirror port with the `host-inetd` delegate: bind `addr:port` on the host loopback.
///
/// Mirrors [`crate::inet::dial_via_delegate`] in reverse — instead of handing the delegate a
/// conduit to dial, this hands it a bind registration and **keeps the connection open**, because
/// `host-inetd` pushes each accepted connection's conduit back on the *same* socket. The returned
/// [`UnixStream`] is the registration connection the reader thread then services.
///
/// Unlike the egress dial (driven lazily, long after the delegate is up), kenneld registers mirror
/// ports *eagerly* right after spawning `host-inetd`, so the connect can race the delegate's
/// `bind(2)` of its command socket. A short bounded retry closes that startup window; past it the
/// delegate is presumed dead and the error propagates.
///
/// # Errors
///
/// The OS error if the delegate's socket never appears within the retry budget, or the registration
/// send fails.
pub fn bind_via_delegate(command_socket: &Path, addr: IpAddr, port: u16) -> io::Result<UnixStream> {
    // ~1s total: the delegate binds its socket within a few ms of spawn; this just covers that
    // startup window. The final attempt's error propagates if the socket never appears.
    const ATTEMPTS: u32 = 100;
    const RETRY: std::time::Duration = std::time::Duration::from_millis(10);
    let mut last_err = io::Error::other("delegate socket never appeared");
    let mut conn = None;
    for _ in 0..ATTEMPTS {
        match UnixStream::connect(command_socket) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                last_err = e;
                std::thread::sleep(RETRY);
            }
        }
    }
    let conn = conn.ok_or(last_err)?;
    let payload = host_inetd::listen::encode_bind(addr, port);
    kennel_lib_syscall::scm::send_with_fds(conn.as_fd(), &payload, &[])?;
    Ok(conn)
}

/// Service one `host-inetd` registration connection: receive each `{port, conduit kennel-end}`
/// notification and enqueue the fd for the `BIND_INET` handler to hand to `facade-client`.
///
/// Runs on its own thread, off the binder looper pool — this is where the unbounded wait for an
/// external connection lives, so the binder handler never has to park. Returns when `host-inetd`
/// closes the connection (the delegate died or the kennel is tearing down).
pub fn run_reader(runtime: &InboundRuntime, conn: &UnixStream) {
    let mut buf = [0u8; 8];
    loop {
        let Ok((n, mut fds)) = kennel_lib_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf)
        else {
            return; // delegate gone
        };
        let Some(fd) = fds.pop() else {
            return; // a notification without a conduit fd is malformed; stop
        };
        if !fds.is_empty() {
            return; // exactly one fd per notification
        }
        let Some(port) = decode_notify(buf.get(..n).unwrap_or_default()) else {
            return;
        };
        runtime.enqueue(port, fd);
    }
}

/// Decode the `host-inetd` notification framing `[port: u16 big-endian]` (the inverse of
/// `host_inetd::listen::encode_notify`).
fn decode_notify(data: &[u8]) -> Option<u16> {
    let [hi, lo] = data else { return None };
    Some(u16::from_be_bytes([*hi, *lo]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn take_pending_drains_per_port_and_is_none_when_empty() {
        let rt = InboundRuntime::new();
        assert!(
            rt.take_pending(3000).is_none(),
            "empty → None (the AGAIN path)"
        );
        // Two ends for 3000, one for 8080; draining is per-port and isolated across ports.
        let (a, _ka) = UnixStream::pair().expect("pair");
        let (b, _kb) = UnixStream::pair().expect("pair");
        let (c, _kc) = UnixStream::pair().expect("pair");
        rt.enqueue(3000, a.into());
        rt.enqueue(3000, b.into());
        rt.enqueue(8080, c.into());
        assert!(rt.take_pending(3000).is_some(), "first 3000 end");
        assert!(rt.take_pending(3000).is_some(), "second 3000 end");
        assert!(rt.take_pending(3000).is_none(), "3000 now drained");
        assert!(
            rt.take_pending(8080).is_some(),
            "8080 unaffected by 3000 drains"
        );
        assert!(rt.take_pending(8080).is_none(), "8080 drained");
    }

    #[test]
    fn notify_framing_round_trips() {
        let bytes = host_inetd::listen::encode_notify(3000);
        assert_eq!(decode_notify(&bytes), Some(3000));
        assert!(decode_notify(&[0x0B]).is_none()); // short
        assert!(decode_notify(&[0x0B, 0xB8, 0x00]).is_none()); // long
    }

    #[test]
    fn reader_enqueues_pushed_conduits_then_stops_on_close() {
        let rt = InboundRuntime::new();
        let (kenneld_side, delegate_side) = UnixStream::pair().expect("pair");
        // The "delegate" pushes one notification {port 3000, a conduit end}, then closes.
        let (_conduit_host, conduit_kennel) = UnixStream::pair().expect("conduit pair");
        kennel_lib_syscall::scm::send_with_fds(
            delegate_side.as_fd(),
            &host_inetd::listen::encode_notify(3000),
            &[conduit_kennel.as_fd()],
        )
        .expect("push notification");
        drop(conduit_kennel);
        drop(delegate_side); // close → run_reader returns after draining
        run_reader(&rt, &kenneld_side);
        assert!(
            rt.take_pending(3000).is_some(),
            "the pushed conduit was enqueued"
        );
        assert!(rt.take_pending(3000).is_none(), "exactly one");
    }
}
