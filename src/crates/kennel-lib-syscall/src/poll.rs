//! Level-triggered readiness multiplexing (`epoll`) for the event-loop leaves.
//!
//! A curated [`Poller`] over `epoll(7)`: register a file descriptor with a caller `token`, wait for
//! any registered fd to become readable, error, or hang up, and read back the ready tokens. The
//! UDP-egress broker uses one to fold its facade channel and its per-flow sockets into a single loop
//! (Kennel book Vol 2 ch.8 (The Network)) without a thread per flow.
//!
//! The heavy lifting is `nix`'s safe `Epoll` wrapper; this presents it as the workspace's curated
//! primitive so the leaves stay `#![forbid(unsafe_code)]` and never name `nix` directly.

use std::io;
use std::os::fd::AsFd;
use std::time::Duration;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

/// A readiness notification for one registered fd: the caller's `token` and what the kernel reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    /// The token the fd was registered with.
    pub token: u64,
    /// The fd is readable (`EPOLLIN`).
    pub readable: bool,
    /// An error condition is pending (`EPOLLERR`) — e.g. a connected socket that took an ICMP error;
    /// a `recv` will surface the specific errno.
    pub error: bool,
    /// The peer hung up (`EPOLLHUP`) — the facade channel closed on kennel teardown.
    pub hangup: bool,
}

/// An `epoll` interest set: register fds against caller tokens and wait for readiness.
pub struct Poller {
    epoll: Epoll,
    events: Vec<EpollEvent>,
}

impl Poller {
    /// Create a poller sized to report up to `max_events` ready fds per [`wait`](Self::wait). The
    /// epoll fd is close-on-exec.
    ///
    /// # Errors
    ///
    /// The OS error if `epoll_create1` fails.
    pub fn new(max_events: usize) -> io::Result<Self> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).map_err(errno)?;
        Ok(Self {
            epoll,
            events: vec![EpollEvent::empty(); max_events.max(1)],
        })
    }

    /// Register `fd` for readability under `token`. `EPOLLERR`/`EPOLLHUP` are reported unconditionally
    /// by the kernel, so an errored or hung-up fd surfaces even though only `EPOLLIN` is requested.
    ///
    /// # Errors
    ///
    /// The OS error if `epoll_ctl(ADD)` fails (e.g. the fd is already registered).
    pub fn add<Fd: AsFd>(&self, fd: Fd, token: u64) -> io::Result<()> {
        self.epoll
            .add(fd, EpollEvent::new(EpollFlags::EPOLLIN, token))
            .map_err(errno)
    }

    /// Deregister `fd`.
    ///
    /// # Errors
    ///
    /// The OS error if `epoll_ctl(DEL)` fails (e.g. the fd was not registered).
    pub fn delete<Fd: AsFd>(&self, fd: Fd) -> io::Result<()> {
        self.epoll.delete(fd).map_err(errno)
    }

    /// Wait for readiness, up to `timeout` (or indefinitely when `None`), returning the ready tokens.
    ///
    /// An empty result means the timeout elapsed with nothing ready. `EINTR` is surfaced as an
    /// error for the caller to retry, not swallowed.
    ///
    /// # Errors
    ///
    /// The OS error if `epoll_wait` fails.
    pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<Vec<Ready>> {
        let to = timeout.map_or(EpollTimeout::NONE, |d| {
            EpollTimeout::try_from(d).unwrap_or(EpollTimeout::MAX)
        });
        let n = self.epoll.wait(&mut self.events, to).map_err(errno)?;
        let ready = self
            .events
            .get(..n)
            .unwrap_or(&[])
            .iter()
            .map(|e| {
                let flags = e.events();
                Ready {
                    token: e.data(),
                    readable: flags.contains(EpollFlags::EPOLLIN),
                    error: flags.contains(EpollFlags::EPOLLERR),
                    hangup: flags.contains(EpollFlags::EPOLLHUP),
                }
            })
            .collect();
        Ok(ready)
    }
}

/// Map a `nix` errno to a `std::io::Error`.
fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn reports_a_readable_fd_under_its_token() {
        let (a, b) = UnixDatagram::pair().expect("pair");
        let mut poller = Poller::new(4).expect("poller");
        poller.add(&b, 0x1234).expect("add");

        // Nothing sent yet → a short wait times out empty.
        assert!(poller
            .wait(Some(Duration::from_millis(20)))
            .expect("wait")
            .is_empty());

        a.send(b"hi").expect("send");
        let ready = poller.wait(Some(Duration::from_millis(200))).expect("wait");
        assert_eq!(ready.len(), 1);
        let r = ready.first().expect("one");
        assert_eq!(r.token, 0x1234);
        assert!(r.readable, "the fd is readable");
    }

    #[test]
    fn deleting_an_fd_stops_its_notifications() {
        let (a, b) = UnixDatagram::pair().expect("pair");
        let mut poller = Poller::new(2).expect("poller");
        poller.add(&b, 9).expect("add");
        poller.delete(&b).expect("delete");
        a.send(b"x").expect("send");
        // With `b` deregistered, the pending datagram no longer wakes the poller.
        assert!(poller
            .wait(Some(Duration::from_millis(20)))
            .expect("wait")
            .is_empty());
    }
}
