//! Passing open file descriptors over a `AF_UNIX` socket (`SCM_RIGHTS`).
//!
//! The `kennel` CLI hands its terminal fds (stdin/stdout/stderr) to the kenneld
//! daemon so the daemon-spawned, confined workload is attached to the user's
//! terminal even though it is `fork`ed in another process. `SCM_RIGHTS` is the
//! kernel mechanism: the sender names fds in a `sendmsg` control message, and the
//! kernel installs *new* fds referring to the same open files in the receiver.
//!
//! There is no `std` API for this, so it goes through nix's safe `sendmsg` /
//! `recvmsg` / `ControlMessage` wrappers (`CODING-STANDARDS.md` §4 — prefer a
//! vetted crate to our own `unsafe`; nix's `socket` feature is already enabled for
//! this and `netlink`). The only `unsafe` left is adopting each received raw fd
//! into an `OwnedFd`, the same one-line ownership transfer the rest of the crate
//! uses. Received fds arrive with `MSG_CMSG_CLOEXEC` set, so they never leak
//! across an `execve`.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{
    getsockopt, recvmsg, sendmsg, socketpair, sockopt, AddressFamily, ControlMessage,
    ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
};

/// The largest number of fds [`recv_with_fds`] will accept in one message.
pub const MAX_FDS: usize = 8;

/// Create a connected `AF_UNIX` `SOCK_SEQPACKET` socket pair (both ends `O_CLOEXEC`).
///
/// The bidirectional, message-framed channel the privhelper-factory invocation rides
/// (`07-11` §7.2.1): `kenneld` keeps one end and hands the other to the factory as its
/// stdin, sending the construction-half plus the `kennel-init`/pty fds (`SCM_RIGHTS`) one
/// way and receiving the init pid back. `SEQPACKET` preserves message boundaries, so each
/// `send_with_fds`/`recv_with_fds` is one datagram.
///
/// # Errors
///
/// Returns the OS error if `socketpair(2)` fails.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// The connected peer's uid on an `AF_UNIX` socket (`SO_PEERCRED`).
///
/// kenneld calls this to reject any control-socket client whose uid is not the
/// user the daemon serves — defence-in-depth behind the socket's `0600` mode
/// (`04-trust-boundaries.md` boundary 7). The kernel stamps the credentials at
/// `connect(2)` time, so they cannot be spoofed by the peer.
///
/// # Errors
/// An OS error if `getsockopt(SO_PEERCRED)` fails (e.g. not a connected
/// `AF_UNIX` socket).
pub fn peer_uid(sock: BorrowedFd<'_>) -> io::Result<u32> {
    // nix's PeerCredentials getsockopt fills and returns the kernel-stamped
    // `ucred`; no manual buffer or length juggling, and no `unsafe`.
    let cred = getsockopt(&sock, sockopt::PeerCredentials)?;
    Ok(cred.uid())
}

/// Send `data` (at least one byte) over `sock`, attaching `fds` as an
/// `SCM_RIGHTS` control message. Returns the number of data bytes sent.
///
/// `SCM_RIGHTS` requires at least one data byte, so `data` must be non-empty.
///
/// # Errors
/// An OS error if `sendmsg` fails, or `InvalidInput` if `data` is empty or there
/// are more than [`MAX_FDS`] fds.
pub fn send_with_fds(
    sock: BorrowedFd<'_>,
    data: &[u8],
    fds: &[BorrowedFd<'_>],
) -> io::Result<usize> {
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCM_RIGHTS needs at least one data byte",
        ));
    }
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many fds"));
    }

    // nix builds and sizes the SCM_RIGHTS control message for us from this slice.
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let iov = [IoSlice::new(data)];
    let cmsgs = [ControlMessage::ScmRights(&raw)];
    // No fds: send a plain message with no control data (matching the SCM_RIGHTS
    // contract that an empty rights message is pointless).
    let cmsgs: &[ControlMessage<'_>] = if raw.is_empty() { &[] } else { &cmsgs };

    // `UnixAddr` only names the (unused) address type; a connected socket needs no
    // destination, so `addr` is None.
    let n = sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::MSG_NOSIGNAL, None)?;
    Ok(n)
}

/// Receive into `buf` from `sock`, collecting any `SCM_RIGHTS` fds (up to
/// [`MAX_FDS`]). Returns the number of data bytes read and the received fds, each
/// already `O_CLOEXEC`.
///
/// # Errors
/// An OS error if `recvmsg` fails, or `InvalidData` if the control data was
/// truncated (more fds than [`MAX_FDS`] were sent).
pub fn recv_with_fds(sock: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = [IoSliceMut::new(buf)];
    // A control buffer sized for MAX_FDS fds; nix's macro accounts for the cmsg
    // header and alignment.
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);
    // MSG_CMSG_CLOEXEC marks received fds close-on-exec so they do not leak through
    // the workload's execve.
    let msg = recvmsg::<UnixAddr>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control data truncated (too many fds)",
        ));
    }

    let mut fds = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(raw_fds) = cmsg {
            for raw in raw_fds {
                // SAFETY: `raw` is a fresh fd the kernel just installed for this
                // process (with O_CLOEXEC, via MSG_CMSG_CLOEXEC) and that nothing
                // else owns; wrapping it transfers ownership for RAII close.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
    }

    Ok((msg.bytes, fds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn passes_a_writable_fd_across_a_socket() {
        let (a, b) = UnixStream::pair().expect("socketpair");

        // A temp file whose fd we send; the receiver writes through its copy.
        let mut file = tempfile();
        let sent = send_with_fds(a.as_fd(), b"x", &[file.as_fd()]).expect("send");
        assert_eq!(sent, 1);

        let mut buf = [0u8; 16];
        let (n, fds) = recv_with_fds(b.as_fd(), &mut buf).expect("recv");
        assert_eq!(n, 1);
        assert_eq!(buf.first(), Some(&b'x'));
        assert_eq!(fds.len(), 1, "exactly one fd received");

        // Write through the received fd; it must land in the same file.
        let mut received: std::fs::File = fds.into_iter().next().expect("one fd").into();
        received
            .write_all(b"hello from the other side")
            .expect("write via received fd");
        received.flush().expect("flush");

        file.rewind().expect("rewind");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read original");
        assert_eq!(
            contents, "hello from the other side",
            "the received fd refers to the same file"
        );
    }

    #[test]
    fn no_fds_is_an_ordinary_message() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        send_with_fds(a.as_fd(), b"hi", &[]).expect("send");
        let mut buf = [0u8; 8];
        let (n, fds) = recv_with_fds(b.as_fd(), &mut buf).expect("recv");
        assert_eq!(buf.get(..n), Some(&b"hi"[..]));
        assert!(fds.is_empty());
    }

    /// A fresh, unlinked temp file for the round-trip test.
    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("kennel-scm-test-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp file");
        let _ = std::fs::remove_file(&path); // unlink; the fd keeps it alive
        file
    }

    #[test]
    fn peer_uid_reports_the_connected_peer() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;
        // Both ends of a socketpair belong to this process, so the peer uid is
        // our own real uid.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let uid = peer_uid(a.as_fd()).expect("SO_PEERCRED");
        assert_eq!(uid, crate::unistd::real_uid());
    }
}
