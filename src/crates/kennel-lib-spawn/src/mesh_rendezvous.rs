// SPDX-License-Identifier: Apache-2.0

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

use std::io;
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

/// Why a rendezvous datagram was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousError {
    /// The datagram has no count byte.
    Empty,
    /// The datagram names one number of mounts and carries another number of descriptors.
    CountMismatch {
        /// The count the datagram states.
        named: usize,
        /// The descriptors that came with it.
        carried: usize,
    },
    /// A record ends before its length field is complete.
    RecordCutShort,
    /// A path ends before the length its record states.
    PathCutShort,
    /// Bytes follow the last record.
    TrailingBytes,
}

impl std::fmt::Display for RendezvousError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mesh rendezvous datagram: ")?;
        match self {
            Self::Empty => f.write_str("it is empty"),
            Self::CountMismatch { named, carried } => write!(
                f,
                "it names {named} mount(s) and carries {carried} descriptor(s)"
            ),
            Self::RecordCutShort => f.write_str("a record is cut short"),
            Self::PathCutShort => f.write_str("a path is cut short"),
            Self::TrailingBytes => f.write_str("bytes follow the last record"),
        }
    }
}

impl std::error::Error for RendezvousError {}

impl From<RendezvousError> for io::Error {
    fn from(e: RendezvousError) -> Self {
        Self::new(io::ErrorKind::InvalidData, e)
    }
}

/// Decode the rendezvous datagram into `(mount fd, in-view target dir)` pairs.
///
/// `fds` are the received mounts in send order (as [`kennel_lib_syscall::scm::recv_with_fds`] returns
/// them). The datagram is all or nothing: the workload starts with every mesh mount its policy
/// names or it does not start.
///
/// # Errors
///
/// The [`RendezvousError`] if the datagram is empty, a record or a path is cut short, bytes
/// follow the last record, or the number of descriptors is not the count the datagram states.
pub fn decode(data: &[u8], fds: Vec<OwnedFd>) -> Result<Vec<(OwnedFd, PathBuf)>, RendezvousError> {
    let (count, mut rest) = data.split_first().ok_or(RendezvousError::Empty)?;
    let count = usize::from(*count);
    if fds.len() != count {
        return Err(RendezvousError::CountMismatch {
            named: count,
            carried: fds.len(),
        });
    }
    let mut out = Vec::with_capacity(count);
    for fd in fds {
        let (lenb, after_len) = rest
            .split_at_checked(2)
            .ok_or(RendezvousError::RecordCutShort)?;
        let [a, b] = *lenb else {
            return Err(RendezvousError::RecordCutShort);
        };
        let (pathb, after_path) = after_len
            .split_at_checked(usize::from(u16::from_le_bytes([a, b])))
            .ok_or(RendezvousError::PathCutShort)?;
        out.push((fd, PathBuf::from(std::ffi::OsStr::from_bytes(pathb))));
        rest = after_path;
    }
    if !rest.is_empty() {
        return Err(RendezvousError::TrailingBytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn mounts(targets: &[&str]) -> Vec<(OwnedFd, PathBuf)> {
        targets
            .iter()
            .map(|t| {
                let (a, _b) = UnixStream::pair().expect("pair");
                (OwnedFd::from(a), PathBuf::from(t))
            })
            .collect()
    }

    fn fds(n: usize) -> Vec<OwnedFd> {
        mounts(&vec!["/x"; n])
            .into_iter()
            .map(|(fd, _)| fd)
            .collect()
    }

    #[test]
    fn a_datagram_round_trips() {
        let sent = mounts(&["/run/mesh/a", "/run/mesh/b"]);
        let (data, _borrowed) = encode(&sent);
        let got = decode(&data, fds(2)).expect("decode");
        let targets: Vec<&PathBuf> = got.iter().map(|(_, t)| t).collect();
        assert_eq!(
            targets,
            [&PathBuf::from("/run/mesh/a"), &PathBuf::from("/run/mesh/b")]
        );
        assert!(decode(&[0], Vec::new()).expect("no mesh").is_empty());
    }

    /// A workload must not start with some of its mesh mounts.
    #[test]
    fn a_damaged_datagram_yields_nothing_rather_than_a_partial_mesh() {
        let sent = mounts(&["/run/mesh/a", "/run/mesh/b"]);
        let (data, _borrowed) = encode(&sent);
        let cut = data.get(..data.len().saturating_sub(3)).expect("cut");
        assert!(decode(cut, fds(2)).is_err(), "truncated");
        assert_eq!(
            decode(&data, fds(1)).map(|_| ()),
            Err(RendezvousError::CountMismatch {
                named: 2,
                carried: 1
            }),
            "a descriptor short"
        );
        assert!(decode(&data, fds(3)).is_err(), "a descriptor over");
        let mut long = data.clone();
        long.push(0);
        assert_eq!(
            decode(&long, fds(2)).map(|_| ()),
            Err(RendezvousError::TrailingBytes),
            "trailing bytes"
        );
        assert_eq!(
            decode(&[], Vec::new()).map(|_| ()),
            Err(RendezvousError::Empty),
            "empty"
        );
        assert_eq!(
            RendezvousError::Empty.to_string(),
            "mesh rendezvous datagram: it is empty"
        );
    }
}
