//! Safe socket helpers (no `unsafe`; std + nix).

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{
    connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::sys::stat::Mode;

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
    connect_addr_timeout(&addr, timeout)
}

/// A socket file held open by descriptor, so that what is checked is what is connected.
///
/// Connecting by name resolves the name at connect time; a check made on the name beforehand says
/// nothing about what is there by then. This opens the file once (`O_PATH`), and both
/// [`path`](Self::path) and [`connect`](Self::connect) act on that one open file.
#[derive(Debug)]
pub struct PinnedSocket {
    fd: OwnedFd,
}

impl PinnedSocket {
    /// Open the socket file at `path`, following symlinks.
    ///
    /// # Errors
    ///
    /// The OS error if the path cannot be opened; `InvalidInput` if it is not a socket.
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::FileTypeExt as _;
        let fd = open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())?;
        let file = std::fs::File::from(fd);
        if !file.metadata()?.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a socket", path.display()),
            ));
        }
        Ok(Self { fd: file.into() })
    }

    /// The path the kernel records for the open file: symlinks resolved, as `realpath` would.
    ///
    /// # Errors
    ///
    /// The OS error if `/proc/self/fd` cannot be read.
    pub fn path(&self) -> io::Result<PathBuf> {
        std::fs::read_link(self.proc_path())
    }

    /// Connect to this socket, giving up after `timeout` ([`connect_unix_timeout`]).
    ///
    /// # Errors
    ///
    /// As [`connect_unix_timeout`].
    pub fn connect(&self, timeout: Duration) -> io::Result<UnixStream> {
        // The address is the descriptor's own `/proc` entry: the kernel follows it to the open
        // file, whatever its original name points at now.
        let addr = UnixAddr::new(&self.proc_path())?;
        connect_addr_timeout(&addr, timeout)
    }

    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
}

fn connect_addr_timeout(addr: &UnixAddr, timeout: Duration) -> io::Result<UnixStream> {
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    match connect(sock.as_raw_fd(), addr) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// A fresh directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("kennel-net-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("scratch dir");
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_pinned_socket_connects_to_the_file_it_opened_not_to_the_name() {
        let scratch = Scratch::new("pin");
        let granted = scratch.0.join("granted.sock");
        let other = scratch.0.join("other.sock");
        let granted_listener = UnixListener::bind(&granted).expect("bind granted");
        let other_listener = UnixListener::bind(&other).expect("bind other");
        other_listener.set_nonblocking(true).expect("nonblocking");

        let pinned = PinnedSocket::open(&granted).expect("open");
        assert_eq!(pinned.path().expect("path"), granted);

        // The name now leads somewhere else.
        std::fs::rename(&granted, scratch.0.join("moved.sock")).expect("move");
        std::os::unix::fs::symlink(&other, &granted).expect("symlink");

        let _stream = pinned.connect(Duration::from_secs(2)).expect("connect");
        granted_listener.accept().expect("the opened socket got it");
        assert!(
            other_listener.accept().is_err(),
            "the socket the name now points at must not be reached"
        );
    }

    #[test]
    fn a_pinned_socket_reports_where_a_symlink_led() {
        let scratch = Scratch::new("link");
        let target = scratch.0.join("target.sock");
        let _listener = UnixListener::bind(&target).expect("bind");
        let link = scratch.0.join("link.sock");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let pinned = PinnedSocket::open(&link).expect("open");
        assert_eq!(pinned.path().expect("path"), target);
    }

    #[test]
    fn a_file_that_is_not_a_socket_is_not_pinned() {
        let scratch = Scratch::new("file");
        let plain = scratch.0.join("plain");
        std::fs::write(&plain, b"x").expect("write");
        let err = PinnedSocket::open(&plain).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
