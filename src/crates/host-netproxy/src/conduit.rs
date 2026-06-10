//! The `INet` conduit: kenneld drives the dumb dialer (`docs/design/07-5-network.md` §7.5.2).
//!
//! kenneld is the decision point — it approves a request, resolves the name, and **pins** the
//! vetted address (`kenneld::inet`). It then mints a `socketpair`, returns one end into the kennel
//! over binder, and hands this delegate the other end plus the pinned address over the per-kennel
//! `kenneld`↔delegate `AF_UNIX` socket. This module is that delegate side: it receives the command
//! and the conduit fd, `connect(2)`s the pinned address from the host stack, and splices the two.
//!
//! No policy, no resolver, no listener of its own beyond the owner-only command socket — the
//! "dumb dialer" half of the split. The wire format (kenneld encodes via [`encode_command`], the
//! delegate decodes) is internal-stable: both ship from one release.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};

/// The largest number of pinned addresses one command may carry (kenneld pins the resolver's vetted
/// answers; a handful is ample, and the cap bounds the decode).
pub const MAX_ADDRS: usize = 16;

/// The address-family tag bytes in the wire format.
const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

/// Encode a conduit command: `[port: u16 big-endian | count: u8 | (tag: u8, addr) × count]`.
///
/// `tag` is 4 (then 4 bytes) or 6 (then 16 bytes). The conduit fd rides alongside as `SCM_RIGHTS`,
/// not in this buffer. Addresses past [`MAX_ADDRS`] are dropped (the caller pins a small set).
#[must_use]
pub fn encode_command(port: u16, addrs: &[IpAddr]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&port.to_be_bytes());
    out.push(u8::try_from(addrs.len().min(MAX_ADDRS)).unwrap_or(0));
    for addr in addrs.iter().take(MAX_ADDRS) {
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
    }
    out
}

/// Decode a conduit command. `None` for a short, over-long, unknown-tag, or trailing-junk buffer.
fn decode_command(data: &[u8]) -> Option<(u16, Vec<IpAddr>)> {
    let [p_hi, p_lo, count, rest @ ..] = data else {
        return None;
    };
    let port = u16::from_be_bytes([*p_hi, *p_lo]);
    let count = usize::from(*count);
    if count == 0 || count > MAX_ADDRS {
        return None;
    }
    let mut rest: &[u8] = rest;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        let (tag, after) = rest.split_first()?;
        let addr = match *tag {
            TAG_V4 => {
                let (raw, remainder) = after.split_at_checked(4)?;
                let octets: [u8; 4] = raw.try_into().ok()?;
                rest = remainder;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            TAG_V6 => {
                let (raw, remainder) = after.split_at_checked(16)?;
                let octets: [u8; 16] = raw.try_into().ok()?;
                rest = remainder;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        addrs.push(addr);
    }
    rest.is_empty().then_some((port, addrs))
}

/// Serve the conduit command socket.
///
/// Accept each `kenneld` connection on its own thread, dial the pinned address, and splice the
/// conduit fd to the upstream. Loops until `listener` errors unrecoverably; each connection carries
/// exactly one command and one conduit fd.
pub fn serve_conduit(listener: &UnixListener) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        std::thread::spawn(move || handle_conduit(&stream));
    }
}

/// Handle one conduit command: receive `{command, conduit fd}`, dial the first pinned address that
/// connects, and splice. A malformed command, a missing/extra fd, or an all-unreachable address set
/// drops the conduit (the in-kennel shim then sees EOF).
fn handle_conduit(stream: &UnixStream) {
    let mut buf = [0u8; 512];
    let Ok((n, mut fds)) = kennel_lib_scm::recv_with_fds(stream.as_fd(), &mut buf) else {
        return;
    };
    // Exactly one fd (the conduit end) is expected.
    let Some(conduit_fd) = fds.pop() else { return };
    if !fds.is_empty() {
        return;
    }
    let Some((port, addrs)) = decode_command(buf.get(..n).unwrap_or_default()) else {
        return;
    };
    let conduit = UnixStream::from(conduit_fd);
    for addr in addrs {
        if let Ok(upstream) = TcpStream::connect((addr, port)) {
            relay(conduit, upstream);
            return;
        }
    }
}

/// Bidirectionally splice the conduit (the in-kennel byte stream) against the upstream TCP socket,
/// one thread per direction, propagating half-close (mirrors `server::relay`).
fn relay(conduit: UnixStream, upstream: TcpStream) {
    let (Ok(mut conduit_rd), Ok(mut upstream_wr)) = (conduit.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let mut upstream_rd = upstream;
    let mut conduit_wr = conduit;
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut conduit_rd, &mut upstream_wr);
        let _ = upstream_wr.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_rd, &mut conduit_wr);
    let _ = conduit_wr.shutdown(Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn command_round_trips_through_encode_decode() {
        let addrs = [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let bytes = encode_command(443, &addrs);
        assert_eq!(decode_command(&bytes), Some((443, addrs.to_vec())));
    }

    #[test]
    fn decode_rejects_short_unknown_tag_and_trailing_junk() {
        assert!(decode_command(&[0x01]).is_none()); // short
        assert!(decode_command(&[0x01, 0xBB, 0x00]).is_none()); // count 0
        assert!(decode_command(&[0x01, 0xBB, 0x01, 9, 1, 2, 3, 4]).is_none()); // unknown tag
        assert!(decode_command(&[0x01, 0xBB, 0x01, TAG_V4, 1, 2, 3]).is_none()); // truncated addr
        assert!(decode_command(&[0x01, 0xBB, 0x01, TAG_V4, 1, 2, 3, 4, 0xFF]).is_none()); // junk
    }

    #[test]
    fn the_conduit_splices_to_the_dialed_upstream() {
        // An echo upstream the delegate will dial.
        let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = echo.accept() {
                let mut b = [0u8; 64];
                if let Ok(n) = s.read(&mut b) {
                    let _ = s.write_all(b.get(..n).unwrap_or_default());
                }
            }
        });

        // The per-kennel command socket the delegate listens on.
        let sock = std::env::temp_dir().join(format!("kennel-conduit-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind cmd socket");
        std::thread::spawn(move || serve_conduit(&listener));

        // kenneld's side: connect, mint the socketpair, send {command, end a}, keep end b.
        let cmd = UnixStream::connect(&sock).expect("connect cmd socket");
        let (a, b) = UnixStream::pair().expect("socketpair");
        let payload = encode_command(echo_addr.port(), &[echo_addr.ip()]);
        kennel_lib_scm::send_with_fds(cmd.as_fd(), &payload, &[a.as_fd()]).expect("send command");
        drop(a); // the delegate owns its received copy

        // Through end b: bytes traverse b → a → delegate → upstream(echo) → back.
        let mut workload = b;
        workload.write_all(b"ping").expect("write");
        workload
            .shutdown(Shutdown::Write)
            .expect("half-close so the echo returns");
        let mut got = Vec::new();
        workload.read_to_end(&mut got).expect("read echo");
        assert_eq!(got, b"ping");
        let _ = std::fs::remove_file(&sock);
    }
}
