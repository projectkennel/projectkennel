//! The inbound BIND conduit: kenneld drives the dumb listener (`docs/design/07-5-network.md` §7.5.7).
//!
//! The reverse of `host_netproxy::conduit`. kenneld is the decision point — the `[net.bpf].bind`
//! cgroup ACL already gated the workload's `bind()`, so kenneld registers the allowed `ip:port`
//! here. This delegate binds it on the host loopback, `accept()`s, and pushes each accepted
//! connection's fd back to kenneld over the same `AF_UNIX` connection the registration arrived on.
//!
//! No policy, no resolver — the "dumb listener" half of the split. The wire format (kenneld encodes
//! the registration via [`encode_bind`], the delegate decodes; the delegate frames each
//! notification's port via [`encode_notify`]) is internal-stable: both ship from one release.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

/// The address-family tag bytes in the wire format (mirrors `host_netproxy::conduit`).
const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

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
/// The accepted connection's fd rides alongside as `SCM_RIGHTS`, not in this buffer. The port lets
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
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        std::thread::spawn(move || handle_registration(&stream));
    }
}

/// Handle one registration: read `{bind command}`, bind the host-side listener, then accept forever
/// and push each accepted connection's fd + port back to kenneld over `stream`. Returns (dropping
/// the listener) on a malformed command, a bind failure, or once kenneld closes `stream`.
fn handle_registration(stream: &UnixStream) {
    let mut buf = [0u8; 64];
    // The registration carries no fd; read it as a plain datagram (recv_with_fds tolerates zero fds).
    let Ok((n, fds)) = kennel_lib_scm::recv_with_fds(stream.as_fd(), &mut buf) else {
        return;
    };
    if !fds.is_empty() {
        return; // a registration carries no fd
    }
    let Some((addr, port)) = decode_bind(buf.get(..n).unwrap_or_default()) else {
        return;
    };
    let Ok(listener) = TcpListener::bind((addr, port)) else {
        return; // the host-side bind failed; kenneld sees `stream` close
    };
    for conn in listener.incoming() {
        let Ok(accepted) = conn else { continue };
        // Push the accepted fd + its port back to kenneld. If kenneld has gone, stop.
        if kennel_lib_scm::send_with_fds(stream.as_fd(), &encode_notify(port), &[accepted.as_fd()])
            .is_err()
        {
            return;
        }
        // The accepted fd drops here; kenneld holds its received copy via SCM_RIGHTS.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write as _};
    use std::net::TcpStream;
    use std::net::{Ipv4Addr, Ipv6Addr};
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
        // The per-kennel command socket the delegate listens on.
        let sock = std::env::temp_dir().join(format!("kennel-inetd-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind cmd socket");
        std::thread::spawn(move || serve(&listener));

        // kenneld's side: connect, register a bind on an ephemeral loopback port.
        let cmd = UnixStream::connect(&sock).expect("connect cmd socket");
        // Pick a free port by binding+dropping, then register it (race-tolerant for a test).
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let reg = encode_bind(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        kennel_lib_scm::send_with_fds(cmd.as_fd(), &reg, &[]).expect("send registration");

        // Give the delegate a moment to bind, then connect to the host-side port from "outside".
        // Retry the connect until the listener is up.
        let mut external = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                external = Some(s);
                break;
            }
            std::thread::yield_now();
        }
        let mut external = external.expect("connect to the mirrored host port");

        // kenneld receives the accepted fd + the port notification on the command connection.
        let mut nbuf = [0u8; 8];
        let (n, mut fds) =
            kennel_lib_scm::recv_with_fds(cmd.as_fd(), &mut nbuf).expect("recv notification");
        assert_eq!(nbuf.get(..n), Some(&port.to_be_bytes()[..]), "port framing");
        let accepted_fd = fds.pop().expect("an accepted fd");
        assert!(fds.is_empty(), "exactly one fd");

        // The accepted fd is a connected TCP socket; std gives a safe OwnedFd → TcpStream
        // conversion (no unsafe — this crate forbids it). Write through the external client and
        // read it off the fd kenneld received, proving it is the same connection.
        let mut tcp = TcpStream::from(accepted_fd);
        external.write_all(b"hello").expect("client write");
        let mut got = [0u8; 5];
        tcp.read_exact(&mut got).expect("read off accepted fd");
        assert_eq!(&got, b"hello");

        let _ = std::fs::remove_file(&sock);
    }
}
