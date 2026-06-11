//! Safe socket helpers (no `unsafe`; std + nix).

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{
    connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};

/// Connect to an `AF_UNIX` stream socket at `path`, giving up after `timeout` rather than blocking
/// indefinitely on an unresponsive peer.
///
/// A non-blocking `connect(2)` followed by `poll(2)`: a wedged target yields `TimedOut` instead of
/// tying up the caller (a binder looper, [`crate`] docs aside) forever. No `unsafe` — nix's safe
/// wrappers plus `UnixStream::from(OwnedFd)`.
///
/// # Errors
///
/// The OS error if the socket/address/connect/poll fails, `TimedOut` if the peer does not accept
/// within `timeout`, or the connection's `SO_ERROR` if the asynchronous connect failed.
pub fn connect_unix_timeout(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let addr = UnixAddr::new(path)?;
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    match connect(sock.as_raw_fd(), &addr) {
        Ok(()) => {} // connected immediately (the common AF_UNIX case)
        Err(Errno::EINPROGRESS) => {
            // Async connect in flight: wait for writable within the deadline, then read SO_ERROR.
            let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLOUT)];
            let timeout = PollTimeout::try_from(millis).unwrap_or(PollTimeout::MAX);
            if nix::poll::poll(&mut fds, timeout)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "AF_UNIX connect timed out",
                ));
            }
            let err = getsockopt(&sock, sockopt::SocketError)?;
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err));
            }
        }
        Err(e) => return Err(e.into()),
    }

    // Hand back a *blocking* socket: the deadline only governs the connect, and the caller (the
    // af-unix shim) splices it with blocking reads/writes.
    let stream = UnixStream::from(sock);
    stream.set_nonblocking(false)?;
    Ok(stream)
}
