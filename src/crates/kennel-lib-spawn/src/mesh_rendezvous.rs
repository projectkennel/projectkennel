//! The mesh-mount rendezvous (§7.13.4a): how `kenneld` hands `kennel-bin-init` the detached binderfs
//! mounts to place in the view — without touching the privhelper factory.
//!
//! The shared connector binderfs lives only in an unprivileged holder's mount namespace, so it cannot
//! be reached by path from inside a kennel (the construction has its own PID namespace). Instead the
//! holder `open_tree(CLONE)`s a movable copy per participant; `kenneld` relays each detached mount fd
//! to `kennel-bin-init`, and the init `move_mount`s it into the view before it forks the workload
//! (adding the device path to the workload's Landlock ruleset).
//!
//! The datagram rides the **boot-sync socket**, right after `kenneld`'s GO: the kennel's user
//! namespace is root-owned, so `kenneld` cannot reach a socket inside the view, and the boot-sync
//! pair is the one channel the factory already gives both ends. One datagram carries the whole set
//! (≤ [`MAX_MESH_MOUNTS`]), with the mount fds and their in-view target directories.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

/// The most mesh mounts one kennel can receive in a single rendezvous datagram (the `SCM_RIGHTS`
/// fd cap).
pub const MAX_MESH_MOUNTS: usize = kennel_lib_syscall::scm::MAX_FDS;

/// Encode the data half of the rendezvous datagram — `[u8 count]` then, per mount, `[u16 len][path]`
/// — and collect the mount fds in the same order for the `SCM_RIGHTS` control message.
///
/// Pairs with [`decode`]. The returned fds borrow `mounts`, to pass straight to
/// [`kennel_lib_syscall::scm::send_with_fds`].
#[must_use]
pub fn encode(mounts: &[(OwnedFd, PathBuf)]) -> (Vec<u8>, Vec<BorrowedFd<'_>>) {
    let mut data = vec![u8::try_from(mounts.len()).unwrap_or(u8::MAX)];
    let mut fds = Vec::with_capacity(mounts.len());
    for (fd, target) in mounts {
        let bytes = target.as_os_str().as_bytes();
        data.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_le_bytes());
        data.extend_from_slice(bytes);
        fds.push(fd.as_fd());
    }
    (data, fds)
}

/// Decode the rendezvous datagram into `(mount fd, in-view target dir)` pairs.
///
/// `fds` are the received mounts in send order (as [`kennel_lib_syscall::scm::recv_with_fds`] returns
/// them). A truncated or short datagram yields only the pairs that parse cleanly.
#[must_use]
pub fn decode(data: &[u8], fds: Vec<OwnedFd>) -> Vec<(OwnedFd, PathBuf)> {
    let count = data.first().copied().unwrap_or(0) as usize;
    let mut out = Vec::with_capacity(count.min(fds.len()));
    let mut rest = data.get(1..).unwrap_or(&[]);
    let mut it = fds.into_iter();
    for _ in 0..count {
        let Some((lenb, after_len)) = rest.split_at_checked(2) else {
            break;
        };
        let [a, b] = *lenb else { break };
        let Some((pathb, after_path)) =
            after_len.split_at_checked(usize::from(u16::from_le_bytes([a, b])))
        else {
            break;
        };
        let Some(fd) = it.next() else {
            break;
        };
        out.push((fd, PathBuf::from(std::ffi::OsStr::from_bytes(pathb))));
        rest = after_path;
    }
    out
}
