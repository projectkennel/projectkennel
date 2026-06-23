//! Bidirectional byte relay between two connected stream sockets.
//!
//! The conduit pattern shared by every connector delegate and facade: once kenneld (or a delegate)
//! has two connected endpoints — a workload-facing socket and an upstream/conduit socket — it copies
//! bytes each way until both close. `facade-socks5`, `facade-client`, `host-inetd`, and
//! `host-netproxy` all need exactly this, in different `TcpStream`/`UnixStream` pairings, so it lives
//! here once rather than hand-rolled four times.
//!
//! The relay is blocking, one extra thread per call (the up direction); the down direction runs on
//! the caller's thread. Each direction half-closes the *write* side of its destination on EOF so a
//! peer doing a request/response (e.g. an HTTP client that reads until close) sees the end. Both
//! endpoints are owned and dropped here, closing them at the relay's end of life.
//!
//! [`splice_with_fds`] is the `AF_UNIX`-only fd-passing variant: it forwards `SCM_RIGHTS` file
//! descriptors alongside the bytes, for protocols (Wayland) where a byte-only copy would silently
//! drop the fds and break the peer.

use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

/// A connected stream socket this module can relay.
///
/// Cloneable (to split read/write across two threads), readable+writable through a shared reference
/// (`&T: Read + Write`, which both `std::net::TcpStream` and `std::os::unix::net::UnixStream`
/// provide), and half-closeable. `Sized + Send + 'static` so an owned endpoint can move into the
/// relay's up-direction thread.
pub trait Conduit: Sized + Send + 'static
where
    for<'a> &'a Self: io::Read + io::Write,
{
    /// Duplicate the handle (a new fd onto the same connection), so one copy reads while the other
    /// writes.
    ///
    /// # Errors
    ///
    /// The OS error if the underlying `dup` fails; [`splice`] treats it as "abort, nothing spliced".
    fn try_clone(&self) -> io::Result<Self>;
    /// Shut down the write half (send `FIN`), signalling EOF to the peer after a direction drains.
    ///
    /// # Errors
    ///
    /// The OS error if the shutdown fails (e.g. the peer already closed); [`splice`] ignores it.
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Conduit for std::net::TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl Conduit for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

/// Splice `a` and `b` bidirectionally until both directions close, propagating half-close.
///
/// One thread copies `a → b`; the caller's thread copies `b → a`; each half-closes the write side of
/// its destination on EOF and the call returns once both finish. A clone failure on either endpoint
/// aborts cleanly (no bytes relayed). Both endpoints are consumed and dropped at return.
pub fn splice<A, B>(a: A, b: B)
where
    A: Conduit,
    B: Conduit,
    for<'x> &'x A: io::Read + io::Write,
    for<'x> &'x B: io::Read + io::Write,
{
    let (Ok(a_rd), Ok(b_rd)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    // Up direction (a → b) on its own thread; it owns `a_rd` (read) and `b` (write).
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut &a_rd, &mut &b);
        let _ = b.shutdown_write();
    });
    // Down direction (b → a) on this thread; `b_rd` reads, `a` writes.
    let _ = io::copy(&mut &b_rd, &mut &a);
    let _ = a.shutdown_write();
    let _ = up.join();
    // Own `a` to its close (the up thread's `b` dropped on join); explicit so the relay's end of
    // life — both connections closed — is visible, not an implicit scope-end drop.
    drop(a);
}

/// Splice two `AF_UNIX` streams bidirectionally, **forwarding `SCM_RIGHTS` fds** as well as bytes.
///
/// The fd-passing analogue of [`splice`], for protocols that send file descriptors in ancillary data
/// (Wayland: the keymap, shm pools, dmabuf buffers). A byte-only copy drops those fds (`file
/// descriptor expected` → a dead client), so this relays bytes and fds together, in order, never
/// parsing the protocol — it stays a transport, not an interposer. `AF_UNIX`-only, since
/// `SCM_RIGHTS` rides Unix ancillary data. Both endpoints are consumed and dropped at return.
pub fn splice_with_fds(a: UnixStream, b: UnixStream) {
    let (Ok(a_w), Ok(b_w)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    // a → b on a worker (reads `a`, writes the `b` clone); b → a here (reads `b`, writes the `a`
    // clone). Both directions forward SCM_RIGHTS fds.
    let up = std::thread::spawn(move || relay_fds(&a, &b_w));
    relay_fds(&b, &a_w);
    let _ = up.join();
    drop(b); // own the pair to their close (the relay's end of life)
}

/// Forward bytes and any `SCM_RIGHTS` fds from `from` to `to` until `from` reaches EOF, then
/// half-close `to`'s write side. The fds ride the first `sendmsg` of the chunk they arrived with;
/// any bytes the kernel could not place in that one call follow as plain data, preserving fd order
/// (all a consumer like libwayland needs — it pulls the next fd as it parses each fd-typed message).
fn relay_fds(from: &UnixStream, to: &UnixStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match crate::recv_with_fds(from.as_fd(), &mut buf) {
            Ok((0, _)) | Err(_) => break, // EOF or read error
            Ok((n, fds)) => {
                let Some(chunk) = buf.get(..n) else { break };
                let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
                match crate::send_with_fds(to.as_fd(), chunk, &borrowed) {
                    Ok(sent) if sent < n => {
                        // Send the tail without fds (they already rode the first call).
                        let Some(rest) = buf.get(sent..n) else { break };
                        let mut w = to;
                        if w.write_all(rest).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::{splice, splice_with_fds};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn relays_both_directions_and_half_closes() {
        // Two socketpairs model the two connections the relay bridges: (left ⇄ a) and (b ⇄ right).
        // splice(a, b) should make `left` and `right` talk to each other.
        let (left, a) = UnixStream::pair().expect("pair a");
        let (b, right) = UnixStream::pair().expect("pair b");
        let h = std::thread::spawn(move || splice(a, b));

        let mut left = left;
        let mut right = right;
        // left → a → b → right
        left.write_all(b"ping").expect("write left");
        left.shutdown(std::net::Shutdown::Write)
            .expect("half-close left");
        let mut got = Vec::new();
        right.read_to_end(&mut got).expect("read right");
        assert_eq!(got, b"ping");

        // right → b → a → left (the reverse direction, before right closes fully)
        right.write_all(b"pong").expect("write right");
        right
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close right");
        let mut back = Vec::new();
        left.read_to_end(&mut back).expect("read left");
        assert_eq!(back, b"pong");

        h.join().expect("splice thread");
    }

    #[test]
    fn returns_when_both_peers_close() {
        // With both far ends closed, both copy directions hit EOF and the relay returns promptly
        // (no panic, no hang). (Only one side closing is a half-open relay — it correctly keeps
        // running for the still-open direction, so that is not what this asserts.)
        let (a, dead_a) = UnixStream::pair().expect("pair a");
        let (b, dead_b) = UnixStream::pair().expect("pair b");
        drop(dead_a);
        drop(dead_b);
        splice(a, b); // both directions see EOF immediately → returns
    }

    #[test]
    fn fd_passing_relay_forwards_a_live_fd() {
        // The property the byte-only `splice` cannot provide and Wayland depends on: an fd sent
        // through `splice_with_fds` arrives as a *working* descriptor on the far side. We send the
        // read end of a pipe through the relay and prove the arrived fd is the same live pipe by
        // writing to its write end and reading the bytes back through the relayed fd.
        use crate::{recv_with_fds, send_with_fds};
        use std::io::{Read, Write};
        use std::os::fd::AsFd;

        let (left, a) = UnixStream::pair().expect("pair a");
        let (b, right) = UnixStream::pair().expect("pair b");
        let h = std::thread::spawn(move || splice_with_fds(a, b));

        let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe");
        // left → a → (relay) → b → right, carrying the pipe's read end as an SCM_RIGHTS fd.
        send_with_fds(left.as_fd(), b"x", &[pipe_r.as_fd()]).expect("send byte + fd");
        drop(pipe_r); // only the relayed copy should reach `right`

        let mut buf = [0u8; 8];
        let (n, fds) = recv_with_fds(right.as_fd(), &mut buf).expect("recv");
        assert_eq!(n, 1, "the byte rode through");
        assert_eq!(fds.len(), 1, "the fd survived the relay");

        // Prove the arrived fd is the live pipe end, not a dead number.
        let mut writer = std::fs::File::from(pipe_w);
        writer.write_all(b"ping").expect("write pipe");
        drop(writer); // EOF the pipe so read_to_end returns
        let received = fds.into_iter().next().expect("one fd");
        let mut reader = std::fs::File::from(received);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read relayed fd");
        assert_eq!(got, b"ping", "bytes flow through the relayed descriptor");

        drop(left);
        drop(right);
        h.join().expect("relay thread");
    }
}
