//! The inbound BIND conduit: kenneld drives the dumb listener (Kennel book Vol 2 ch.8 (The Network)).
//!
//! The reverse of `host_netproxy::conduit`. kenneld is the decision point — the `[net.bpf].bind`
//! cgroup ACL already gated the workload's `bind()`, so kenneld registers the allowed `ip:port`
//! here. This delegate binds it on the host loopback (the address and the `lo` device), `accept()`s, mints a conduit socketpair,
//! splices the accepted connection to the host end locally, and pushes the *kennel* end back to
//! kenneld over the same `AF_UNIX` connection the registration arrived on. kenneld routes that one
//! fd to `facade-client` and never touches a payload byte (the host-netproxy split, in reverse).
//!
//! No policy, no resolver — the "dumb listener" half of the split. The wire format (kenneld encodes
//! the registration via [`encode_bind`], the delegate decodes; the delegate frames each
//! notification's port via [`encode_notify`]) is internal-stable: both ship from one release.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The address-family tag bytes in the wire format (mirrors `host_netproxy::conduit`).
const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

/// The most concurrent inbound conduits one delegate will splice at once, across all its listeners.
///
/// Unlike egress (`host-netproxy`), where the workload initiates and the kennel cgroup bounds the
/// connection count, the inbound mirror is `accept()`ed here in the **operator's context** — outside
/// the cgroup — on behalf of whoever connects to the mirrored host-loopback port. Each conduit is
/// two threads and four descriptors in this process, so the cap is on the process, not on each
/// listener: a kennel with many mirrored ports does not multiply it. Once reached, further accepts
/// are **shed** (dropped before any socketpair, thread or kenneld wake).
const MAX_ACTIVE_CONDUITS: usize = 1024;

/// How long an accept loop waits after `accept(2)` fails before it tries again. A failure that
/// persists (the process is out of descriptors) would otherwise spin the loop.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// One claimed conduit slot in the delegate-wide count; released on drop, so the count is right
/// even if the splice thread panics or was never created.
struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    /// Claim a slot, or `None` at [`MAX_ACTIVE_CONDUITS`].
    fn claim(counter: &Arc<AtomicUsize>) -> Option<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_ACTIVE_CONDUITS).then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| Self(Arc::clone(counter)))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Encode a bind registration: `[tag: u8 | addr | port: u16 big-endian]`.
///
/// `tag` is 4 (then 4 address bytes) or 6 (then 16). Tells the delegate to bind `addr:port` on the
/// host loopback and accept on it. The reverse of `host_netproxy::conduit::encode_command` — one
/// address (the kennel's own loopback alias), and an inbound bind rather than an outbound dial.
#[must_use]
pub fn encode_bind(addr: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    match addr {
        IpAddr::V4(a) => {
            out.push(TAG_V4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(TAG_V6);
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode a bind registration. `None` for a short, unknown-tag, or trailing-junk buffer.
fn decode_bind(data: &[u8]) -> Option<(IpAddr, u16)> {
    let (tag, rest) = data.split_first()?;
    let (addr, rest) = match *tag {
        TAG_V4 => {
            let (raw, rest) = rest.split_at_checked(4)?;
            (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(raw).ok()?)),
                rest,
            )
        }
        TAG_V6 => {
            let (raw, rest) = rest.split_at_checked(16)?;
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?)),
                rest,
            )
        }
        _ => return None,
    };
    let [hi, lo] = rest else { return None };
    Some((addr, u16::from_be_bytes([*hi, *lo])))
}

/// Encode the per-accept notification framing: `[port: u16 big-endian]`.
///
/// The conduit's kennel end rides alongside as `SCM_RIGHTS`, not in this buffer. The port lets
/// kenneld route the conduit to the right `pending-inbound[port]` queue.
#[must_use]
pub const fn encode_notify(port: u16) -> [u8; 2] {
    port.to_be_bytes()
}

/// Serve the command socket: one registration per accepted `kenneld` connection.
///
/// Each connection carries exactly one [`encode_bind`] registration; the delegate binds the
/// `ip:port`, then accepts on it forever, pushing each accepted fd back on the *same* connection.
/// Loops until `listener` errors unrecoverably.
pub fn serve(listener: &std::os::unix::net::UnixListener) {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            std::thread::sleep(ACCEPT_BACKOFF);
            continue;
        };
        let active = Arc::clone(&active);
        // A refused thread drops the registration: kenneld sees the connection close and reports
        // the port as not mirrored.
        let _ = std::thread::Builder::new()
            .name("mirror".to_owned())
            .spawn(move || handle_registration(&stream, &active));
    }
}

/// Handle one registration: read `{bind command}`, bind the host-side listener, then accept
/// forever. For each accepted connection, mint a socketpair, splice the accepted connection to the
/// host end locally (kenneld stays out of the data path), and push the kennel end + port to kenneld
/// over `stream`. Returns (dropping the listener) on a malformed command, a bind failure, or once
/// kenneld closes `stream`. `active` is the delegate-wide count of live conduits.
fn handle_registration(stream: &UnixStream, active: &Arc<AtomicUsize>) {
    let mut buf = [0u8; 64];
    // The registration carries no fd; read it as a plain datagram (recv_with_fds tolerates zero fds).
    let Ok((n, fds)) = kennel_lib_scm::recv_with_fds(stream.as_fd(), &mut buf) else {
        return;
    };
    if !fds.is_empty() {
        return; // a registration carries no fd
    }
    let Some((addr, port)) = decode_bind(buf.get(..n).unwrap_or_default()) else {
        eprintln!("host-inetd: malformed bind registration");
        return;
    };
    // The kennel's address is assigned to host `lo`, which does not keep other interfaces from
    // reaching it; the listener is bound to the loopback device as well as to the address.
    let listener = match kennel_lib_os::net::loopback_listener(SocketAddr::new(addr, port)) {
        Ok(l) => l,
        Err(e) => {
            // The host-side bind failed (e.g. the kennel's loopback alias is not on host `lo`, or
            // the port is taken). kenneld sees `stream` close. Log it — a silent failure here is
            // the mirror simply not appearing, which is undebuggable.
            eprintln!("host-inetd: bind {addr}:{port} failed: {e}");
            return;
        }
    };
    for conn in listener.incoming() {
        let Ok(accepted) = conn else {
            std::thread::sleep(ACCEPT_BACKOFF);
            continue;
        };
        // Shed before minting anything once at the host-resource cap: drop the accepted connection
        // (the client sees it close) rather than spawn a thread + fds + wake kenneld.
        let Some(guard) = ActiveGuard::claim(active) else {
            drop(accepted);
            continue;
        };
        // Mint the conduit socketpair: the host end stays here (spliced to the accepted
        // connection), the kennel end goes to kenneld → facade-client. kenneld routes the kennel
        // end as one opaque fd and never touches a payload byte (mirrors host-netproxy's split).
        let Ok((host_end, kennel_end)) = UnixStream::pair() else {
            continue; // drop this connection; the external client sees it close
        };
        // Start the splice before telling kenneld: if no thread can be had, nothing was promised.
        // The closure owns both ends, so a refused spawn closes them and frees the slot.
        let spliced = std::thread::Builder::new()
            .name("conduit".to_owned())
            .spawn(move || {
                let _guard = guard; // frees the slot when the splice ends
                splice(accepted, host_end);
            });
        if spliced.is_err() {
            continue;
        }
        // Push the kennel end + its port to kenneld. If kenneld has gone, stop serving.
        if kennel_lib_scm::send_with_fds(
            stream.as_fd(),
            &encode_notify(port),
            &[kennel_end.as_fd()],
        )
        .is_err()
        {
            return;
        }
        drop(kennel_end); // kenneld holds its received copy via SCM_RIGHTS
    }
}

/// Bidirectionally splice the accepted host-side TCP connection against the conduit's host end.
/// The bidirectional relay is shared (`kennel_lib_scm::splice`) across the delegates and facades.
fn splice(accepted: TcpStream, host_end: UnixStream) {
    kennel_lib_scm::splice::splice(accepted, host_end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write as _};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::UnixListener;

    #[test]
    fn bind_command_round_trips_v4_and_v6() {
        let v4 = IpAddr::V4(Ipv4Addr::new(127, 2, 160, 1));
        let bytes = encode_bind(v4, 3000);
        assert_eq!(decode_bind(&bytes), Some((v4, 3000)));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let bytes = encode_bind(v6, 8080);
        assert_eq!(decode_bind(&bytes), Some((v6, 8080)));
    }

    #[test]
    fn decode_bind_rejects_short_unknown_tag_and_junk() {
        assert!(decode_bind(&[]).is_none()); // empty
        assert!(decode_bind(&[TAG_V4, 1, 2, 3]).is_none()); // truncated addr
        assert!(decode_bind(&[TAG_V4, 1, 2, 3, 4, 0x0B]).is_none()); // short port
        assert!(decode_bind(&[TAG_V4, 1, 2, 3, 4, 0x0B, 0xB8, 0xFF]).is_none()); // trailing junk
        assert!(decode_bind(&[9, 1, 2, 3, 4, 0x0B, 0xB8]).is_none()); // unknown tag
    }

    #[test]
    fn notify_framing_is_the_port_big_endian() {
        assert_eq!(encode_notify(3000), [0x0B, 0xB8]);
    }

    #[test]
    fn an_accepted_connection_is_pushed_back_with_its_port() {
        use std::time::Duration;

        // The per-kennel command socket the delegate listens on.
        let sock = std::env::temp_dir().join(format!("kennel-inetd-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind cmd socket");
        std::thread::spawn(move || serve(&listener));

        // Picking a free port by bind+drop and asking the delegate to *re*bind it is a TOCTOU: under
        // parallel load another process can steal the port between the drop and the delegate's bind,
        // so the delegate's bind fails and it drops the command connection. (Production has no such
        // race — kenneld registers the exact port the workload already bound, on a per-kennel
        // loopback alias.) So retry the whole handshake on a fresh port until one survives the
        // round-trip, bounded so a genuine failure still terminates. The `recv` timeout is what turns
        // a stolen port (no delegate behind the connection) from a hang into a retry.
        let mut succeeded = false;
        for _ in 0..40 {
            let cmd = UnixStream::connect(&sock).expect("connect cmd socket");
            cmd.set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set cmd recv timeout");
            let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe");
            let port = probe.local_addr().expect("addr").port();
            drop(probe);
            let reg = encode_bind(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            kennel_lib_scm::send_with_fds(cmd.as_fd(), &reg, &[]).expect("send registration");

            // Connect to the mirrored host-side port from "outside", retrying until the delegate's
            // listener is up. If the port was stolen, nobody we control bound it.
            let mut external = None;
            for _ in 0..50 {
                if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                    external = Some(s);
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let Some(mut external) = external else {
                continue; // nobody bound it in time — fresh port
            };

            // The conduit's KENNEL end + the port notification arrive on the command connection
            // (host-inetd already spliced the accepted connection to the host end). A stolen port
            // means no delegate is behind this connection, so the timed `recv` errors → retry.
            let mut nbuf = [0u8; 8];
            let Ok((n, mut fds)) = kennel_lib_scm::recv_with_fds(cmd.as_fd(), &mut nbuf) else {
                continue; // timed out / closed: the bind lost the race, try a fresh port
            };
            assert_eq!(nbuf.get(..n), Some(&port.to_be_bytes()[..]), "port framing");
            let kennel_end = fds.pop().expect("a conduit fd");
            assert!(fds.is_empty(), "exactly one fd");

            // Bytes from the external client traverse external → accepted → host_end → kennel_end
            // through host-inetd's splice. The kennel end is a UnixStream (the socketpair end), so
            // reading it back yields what the external client wrote — proving the splice is live.
            let mut conduit = UnixStream::from(kennel_end);
            external.write_all(b"hello").expect("client write");
            let mut got = [0u8; 5];
            conduit
                .read_exact(&mut got)
                .expect("read off the conduit kennel end");
            assert_eq!(&got, b"hello");

            succeeded = true;
            break;
        }
        let _ = std::fs::remove_file(&sock);
        assert!(
            succeeded,
            "the delegate never bound a free loopback port in 40 attempts"
        );
    }
}
