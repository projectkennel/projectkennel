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

use std::io;
use std::net::Shutdown;

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

#[cfg(test)]
mod tests {
    use super::splice;
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
}
