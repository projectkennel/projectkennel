// SPDX-License-Identifier: Apache-2.0

//! Safe socket helpers (no `unsafe`; std + nix).

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{
    bind, connect, getsockopt, listen, setsockopt, socket, sockopt, AddressFamily, Backlog,
    SockFlag, SockType, SockaddrIn, SockaddrIn6, UnixAddr,
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

/// Every address assigned to an interface of this host, in the calling network namespace.
///
/// # Errors
///
/// The OS error if the interfaces cannot be listed.
pub fn host_addresses() -> io::Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for interface in nix::ifaddrs::getifaddrs()? {
        let Some(address) = interface.address else {
            continue;
        };
        if let Some(v4) = address.as_sockaddr_in() {
            out.push(IpAddr::V4(v4.ip()));
        } else if let Some(v6) = address.as_sockaddr_in6() {
            out.push(IpAddr::V6(v6.ip()));
        }
    }
    Ok(out)
}

/// Whether `addr` is one of this host's own addresses ([`host_addresses`]).
///
/// A connection the host makes to one of its own addresses never leaves it: it arrives at
/// whatever the host has listening on that address or on the wildcard. An egress path that
/// dials from the host stack asks this before it dials. An IPv4-mapped IPv6 address is judged
/// as the IPv4 address it names. If the interfaces cannot be listed the answer is `true`: the
/// caller is deciding whether to refuse, and an unknown must not pass.
#[must_use]
pub fn is_host_address(addr: IpAddr) -> bool {
    host_addresses().map_or(true, |own| own.contains(&addr.to_canonical()))
}

/// The loopback interface's name. Linux creates it as `lo` in every network namespace.
const LOOPBACK_DEVICE: &str = "lo";

/// Listen for TCP on `addr`, taking connections only from the loopback interface.
///
/// An address assigned to `lo` is not confined to it: Linux accepts a packet for any local
/// address on whichever interface it arrives, so a peer on the LAN that routes the address to
/// this host reaches a socket that is only bound to the address. The socket is therefore also
/// bound to the device (`SO_BINDTODEVICE`), before `bind(2)`, so there is no moment in which it
/// listens unbound. A process may bind its own unbound socket to a device without privilege
/// (Linux 5.7 and later); on a kernel that refuses, this fails and nothing listens.
///
/// # Errors
///
/// The OS error if the socket cannot be created, bound to the device, bound to `addr`, or put
/// into the listening state.
pub fn loopback_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let family = match addr {
        SocketAddr::V4(_) => AddressFamily::Inet,
        SocketAddr::V6(_) => AddressFamily::Inet6,
    };
    let sock = socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)?;
    setsockopt(&sock, sockopt::ReuseAddr, &true)?;
    setsockopt(
        &sock,
        sockopt::BindToDevice,
        &std::ffi::OsString::from(LOOPBACK_DEVICE),
    )?;
    match addr {
        SocketAddr::V4(v4) => bind(sock.as_raw_fd(), &SockaddrIn::from(v4))?,
        SocketAddr::V6(v6) => bind(sock.as_raw_fd(), &SockaddrIn6::from(v6))?,
    }
    listen(&sock, Backlog::MAXCONN)?;
    Ok(TcpListener::from(sock))
}

/// The interface `listener` is bound to (`SO_BINDTODEVICE`), or the empty string for none.
///
/// # Errors
///
/// The OS error if the option cannot be read.
pub fn bound_device(listener: &TcpListener) -> io::Result<String> {
    let name = getsockopt(listener, sockopt::BindToDevice)?;
    Ok(name.to_string_lossy().into_owned())
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
    fn a_loopback_listener_takes_connections_only_from_the_loopback_interface() {
        // An address on `lo` is not loopback-scoped: the kernel accepts a packet for it on any
        // interface. Only binding the socket to the device keeps other interfaces out.
        let listener = loopback_listener("[::1]:0".parse().expect("addr")).expect("listen");
        assert_eq!(bound_device(&listener).expect("device"), "lo");
        let addr = listener.local_addr().expect("addr");
        std::net::TcpStream::connect(addr).expect("a local connection still arrives");
        listener.accept().expect("accept");
    }

    #[test]
    fn the_hosts_own_addresses_are_recognised() {
        let own = host_addresses().expect("interfaces");
        assert!(own.contains(&IpAddr::from(std::net::Ipv4Addr::LOCALHOST)));
        for addr in own {
            assert!(is_host_address(addr), "{addr}");
        }
        // The IPv4-mapped spelling of a local address is the same address.
        assert!(is_host_address("::ffff:127.0.0.1".parse().expect("addr")));
        // TEST-NET-1 and the documentation prefix are assigned to no interface.
        assert!(!is_host_address("192.0.2.1".parse().expect("addr")));
        assert!(!is_host_address("2001:db8::1".parse().expect("addr")));
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
