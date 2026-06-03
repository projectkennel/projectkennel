//! Passing open file descriptors over a `AF_UNIX` socket (`SCM_RIGHTS`).
//!
//! The `kennel` CLI hands its terminal fds (stdin/stdout/stderr) to the kenneld
//! daemon so the daemon-spawned, confined workload is attached to the user's
//! terminal even though it is `fork`ed in another process. `SCM_RIGHTS` is the
//! kernel mechanism: the sender names fds in a `sendmsg` control message, and the
//! kernel installs *new* fds referring to the same open files in the receiver.
//!
//! There is no `std` API for this, and the established crates (`sendfd`,
//! `passfd`, `nix`'s `sendmsg`) each pull a tree we would rather not vendor for
//! one call site, so it lives here as reviewed `unsafe` (`CODING-STANDARDS.md`
//! §4) over `libc::{sendmsg,recvmsg}`. Received fds arrive with `MSG_CMSG_CLOEXEC`
//! set, so they never leak across an `execve`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// The largest number of fds [`recv_with_fds`] will accept in one message.
pub const MAX_FDS: usize = 8;

/// Send `data` (at least one byte) over `sock`, attaching `fds` as an
/// `SCM_RIGHTS` control message. Returns the number of data bytes sent.
///
/// `SCM_RIGHTS` requires at least one data byte, so `data` must be non-empty.
///
/// # Errors
/// An OS error if `sendmsg` fails, or `InvalidInput` if `data` is empty or there
/// are more than [`MAX_FDS`] fds.
// The CMSG_DATA fd payload is written via copy_nonoverlapping, which does not
// require the destination pointer to be aligned.
#[allow(clippy::cast_ptr_alignment)]
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

    // A raw-fd array the control message copies from.
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let payload_len = std::mem::size_of_val(raw.as_slice());

    // SAFETY: a zeroed iovec/msghdr is a valid all-zero structure; we then set
    // the fields. `data` is read-only here (sendmsg only reads it).
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;

    // Control buffer sized for `raw.len()` fds. CMSG_SPACE includes alignment.
    // SAFETY: CMSG_SPACE is a pure size calculation over a constant payload size.
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(payload_len).unwrap_or(0)) } as usize;
    let mut control = vec![0u8; space];

    if !raw.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = space as _;
        // SAFETY: msg.msg_control points at `space` writable bytes; CMSG_FIRSTHDR
        // returns a pointer into that buffer (or null if it is too small, which it
        // is not). We initialise the single cmsg header it returns.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(std::ptr::from_ref(&msg)) };
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        // SAFETY: `cmsg` is a valid, writable cmsghdr inside `control`. CMSG_LEN
        // computes the header+payload length; CMSG_DATA points at the payload
        // region, which is `payload_len` bytes for `raw.len()` fds.
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(u32::try_from(payload_len).unwrap_or(0)) as _;
            std::ptr::copy_nonoverlapping(
                raw.as_ptr(),
                libc::CMSG_DATA(cmsg).cast::<RawFd>(),
                raw.len(),
            );
        }
    }

    // SAFETY: `msg` is fully initialised and describes valid buffers; sendmsg
    // reads them and returns the byte count or -1.
    let n = unsafe {
        libc::sendmsg(
            sock.as_raw_fd(),
            std::ptr::from_ref(&msg),
            libc::MSG_NOSIGNAL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Receive into `buf` from `sock`, collecting any `SCM_RIGHTS` fds (up to
/// [`MAX_FDS`]). Returns the number of data bytes read and the received fds, each
/// already `O_CLOEXEC`.
///
/// # Errors
/// An OS error if `recvmsg` fails, or `InvalidData` if the control data was
/// truncated (more fds than [`MAX_FDS`] were sent).
// The CMSG_DATA fd payload is read via read_unaligned, which does not require
// the source pointer to be aligned.
#[allow(clippy::cast_ptr_alignment)]
pub fn recv_with_fds(sock: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    // SAFETY: zeroed iovec/msghdr is valid; we set the fields to describe `buf`
    // and the control buffer below.
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;

    // SAFETY: CMSG_SPACE is a pure size calculation.
    let fd_bytes = std::mem::size_of::<RawFd>().saturating_mul(MAX_FDS);
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(fd_bytes).unwrap_or(0)) } as usize;
    let mut control = vec![0u8; space];
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space as _;

    // SAFETY: `msg` describes valid writable buffers; recvmsg fills them and
    // returns the data byte count or -1. MSG_CMSG_CLOEXEC marks received fds
    // close-on-exec so they do not leak through the workload's execve.
    let n = unsafe {
        libc::recvmsg(
            sock.as_raw_fd(),
            std::ptr::from_mut(&mut msg),
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control data truncated (too many fds)",
        ));
    }

    let mut fds = Vec::new();
    // SAFETY: `msg` was populated by recvmsg; CMSG_FIRSTHDR/CMSG_NXTHDR walk the
    // control buffer it filled, returning valid cmsghdr pointers or null at the end.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(std::ptr::from_ref(&msg)) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a valid cmsghdr inside `control`.
        let (level, ctype, len) = unsafe {
            (
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type,
                (*cmsg).cmsg_len as usize,
            )
        };
        if level == libc::SOL_SOCKET && ctype == libc::SCM_RIGHTS {
            // SAFETY: CMSG_LEN(0) is the header size; the remainder is the fd payload.
            let header = unsafe { libc::CMSG_LEN(0) as usize };
            let payload = len.saturating_sub(header);
            let count = payload
                .checked_div(std::mem::size_of::<RawFd>())
                .unwrap_or(0);
            // SAFETY: CMSG_DATA points at `payload` valid bytes holding `count`
            // RawFds the kernel just installed; we read them out one at a time and
            // take ownership via OwnedFd (so each is closed exactly once).
            let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
            for i in 0..count {
                let raw = unsafe { data.add(i).read_unaligned() };
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        // SAFETY: walking to the next header in the same control buffer.
        cmsg = unsafe { libc::CMSG_NXTHDR(std::ptr::from_mut(&mut msg), cmsg) };
    }

    Ok((usize::try_from(n).unwrap_or(0), fds))
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
}
