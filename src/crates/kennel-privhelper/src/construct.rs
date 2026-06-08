//! The privhelper **factory**: build a kennel and `fexecve` `kennel-init` into it.
//!
//! The construction inversion (`docs/design/07-11-kennel-init.md` §7.11.1): rather than
//! `kenneld` (the operator) building the sandbox unprivileged, the privhelper — real
//! root — does *all* privileged construction in its own post-`clone` child, then
//! `fexecve`s the trusted root-owned `kennel-init` as the kennel's uid-0 PID 1. Doing it
//! here is what gives the kennel a **real uid 0** (host root mapped `0 0 1`) so the view
//! root, `/dev`, the library binds, and the binderfs nodes are owned by and display as
//! root — and what fixes the binderfs `EACCES` (a binderfs instance assigns its nodes to
//! uid 0 of the mounting userns; with the old pure-identity map there was no uid 0).
//!
//! # Transport
//!
//! `kenneld` invokes the helper as `kennel-privhelper construct` with one end of a
//! `SOCK_SEQPACKET` pair as the helper's **stdin**. It sends one datagram: the
//! `ConstructionHalf` bytes as data, the `kennel-init` binary fd and (optionally) the
//! controlling-pty socket as `SCM_RIGHTS`. The helper replies on the same channel with
//! the construction child's **host pid** (so `kenneld` can take binder node 0 via
//! `/proc/<pid>/root` and gate the lifecycle verbs), then stays alive as that child's
//! parent and `_exit`s with its status — the reliable exit path up to `kenneld`.
//!
//! # The clone / map handshake
//!
//! `clone(NEWUSER|…)` creates the child with **no** identity mapping, so it holds no
//! capability in the new userns until the parent writes its `uid_map`/`gid_map`. The
//! child therefore blocks on a pipe until the parent (real root, holding `CAP_SETUID`/
//! `CAP_SETGID`) has written the `0 0 1`+operator maps and acked; only then does it run
//! the (privileged) construction and `fexecve`. No operator-controlled code ever runs as
//! userns-0: between `clone` and `fexecve` only this factory code runs, and `kennel-init`
//! is the trusted root-owned binary.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use kennel_spawn::wire::decode_construction;
use kennel_syscall::handshake::{pipe_cloexec, recv_ack, send_ack, ACK_PROCEED};
use kennel_syscall::namespace::clone_pid1;
use kennel_syscall::process::{wait_any, Reaped};
use kennel_syscall::scm::{recv_with_fds, send_with_fds};
use kennel_syscall::spawn::fexecve;
use kennel_syscall::unistd::{real_gid, real_uid};

/// Receive buffer for the construction-half datagram (the half is small and bounded).
const RECV_CAP: usize = 1 << 16;

/// Exit code when construction fails before the child is running (parsing, clone, maps).
const CONSTRUCT_FAILED: i32 = 125;

/// Run the factory over `chan` (the `SOCK_SEQPACKET` end `kenneld` handed us as stdin).
///
/// Never returns: the construction child `fexecve`s `kennel-init` (or `_exit`s on
/// failure), and this parent `_exit`s with the child's status once it terminates. A
/// failure before the child exists exits [`CONSTRUCT_FAILED`].
pub fn run_construct(chan: BorrowedFd<'_>) -> ! {
    let code = construct(chan).unwrap_or(CONSTRUCT_FAILED);
    std::process::exit(code);
}

/// Receive the construction request, clone the kennel, write its maps, hand off to
/// `kennel-init`, and wait for it — returning the child's exit status.
// `op_uid`/`op_gid` are the domain names; the pedantic similar-names heuristic flags the
// pair, but renaming would only obscure them.
#[allow(clippy::similar_names)]
fn construct(chan: BorrowedFd<'_>) -> io::Result<i32> {
    // 1. Receive the construction-half + the kennel-init fd (+ optional pty fd).
    let mut buf = vec![0u8; RECV_CAP];
    let (n, mut fds) = recv_with_fds(chan, &mut buf)?;
    let half = decode_construction(buf.get(..n).unwrap_or(&[]))
        .map_err(|e| io::Error::other(format!("construction-half decode: {e:?}")))?;
    if fds.is_empty() {
        return Err(io::Error::other("construct: no kennel-init fd received"));
    }
    // The first fd is kennel-init; a second (if any) is the pty return socket, which the
    // construction child must keep open across the fexecve for kennel-init to inherit.
    // (Wired through to the seal in a later increment; held here so it is not dropped.)
    let init_fd = fds.remove(0);
    let _pty_fd: Option<OwnedFd> = (!fds.is_empty()).then(|| fds.remove(0));

    // 2. The maps-written handshake pipe (child blocks until the parent writes the maps).
    let (ready_r, ready_w) = pipe_cloexec()?;

    // 3. Clone the construction child — PID 1 of the new namespaces, no identity yet.
    // The operator identity (the caller's real ids; setuid leaves the real uid as the
    // invoking user) — never wire-supplied (security review §6).
    let op_uid = real_uid();
    let op_gid = real_gid();
    let granted = half.granted_gids.clone();
    let child = move || {
        // Wait until the parent has written our identity maps; abort closed otherwise.
        if recv_ack(ready_r.as_fd()).ok().flatten() != Some(ACK_PROCEED) {
            return; // clone_pid1 backstops a returning child with _exit(127)
        }
        // [E.4: cgroup join, in-ns lo, view + binderfs + pivot_root here.]
        // Hand off to the trusted root-owned init with empty argv/envp (the pull model).
        let _err = fexecve(init_fd.as_fd(), &[], &[]);
        // fexecve returned ⇒ failure; fall through to the _exit(127) backstop.
    };
    let init_pid = clone_pid1(half.namespaces, child)?;

    // 4. Parent (real root): write the child's identity maps, then release it.
    write_identity_maps(init_pid, op_uid, op_gid, &granted)?;
    send_ack(ready_w.as_fd(), ACK_PROCEED)?;
    drop(ready_w); // close our write end

    // 5. Tell kenneld the init host pid (so it can take node 0 / gate the lifecycle).
    send_with_fds(chan, &init_pid.to_le_bytes(), &[])?;

    // 6. Stay as the child's parent; relay its exit status up the chain.
    loop {
        match wait_any()? {
            Reaped::Exited { pid, code } if pid == init_pid => return Ok(code),
            Reaped::Exited { .. } => {} // some other reaped child; keep waiting for init
            Reaped::NoChildren => return Ok(CONSTRUCT_FAILED),
        }
    }
}

/// Write the construction child's `uid_map` and `gid_map` (`07-11` §7.11.1).
///
/// Always maps host root in (`0 0 1`) so the kennel has a real uid 0, then the operator's
/// own real uid/gid (so the workload's masked identity is a sane non-root id), then each
/// granted supplementary gid. The operator line is omitted when the operator *is* root
/// (the maps would otherwise overlap — the case when the factory runs under a root test).
/// Writing requires the parent's `CAP_SETUID`/`CAP_SETGID`; `setgroups` is left enabled
/// (not denied) because `kennel-init` needs it for the workload's supplementary-group drop.
fn write_identity_maps(pid: i32, uid: u32, gid: u32, granted: &[u32]) -> io::Result<()> {
    let (uid_map, gid_map) = build_identity_maps(uid, gid, granted);
    std::fs::write(format!("/proc/{pid}/uid_map"), uid_map)?;
    std::fs::write(format!("/proc/{pid}/gid_map"), gid_map)?;
    Ok(())
}

/// Build the `uid_map`/`gid_map` strings (pure; the write is in [`write_identity_maps`]).
fn build_identity_maps(uid: u32, gid: u32, granted: &[u32]) -> (String, String) {
    use std::fmt::Write as _;
    let mut uid_map = String::from("0 0 1\n");
    if uid != 0 {
        let _ = writeln!(uid_map, "{uid} {uid} 1");
    }
    let mut gid_map = String::from("0 0 1\n");
    if gid != 0 {
        let _ = writeln!(gid_map, "{gid} {gid} 1");
    }
    for &g in granted {
        if g != 0 && g != gid {
            let _ = writeln!(gid_map, "{g} {g} 1");
        }
    }
    (uid_map, gid_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_dedupe_root_and_carry_granted_groups() {
        // Operator is root (the root-test case): a single 0 0 1 line, no overlap.
        assert_eq!(build_identity_maps(0, 0, &[]), ("0 0 1\n".into(), "0 0 1\n".into()));
        // Operator is a normal user: host root mapped in, then the operator's own id.
        let (u, g) = build_identity_maps(1000, 1000, &[27, 44]);
        assert_eq!(u, "0 0 1\n1000 1000 1\n");
        assert_eq!(g, "0 0 1\n1000 1000 1\n27 27 1\n44 44 1\n");
        // A granted gid equal to the primary (or 0) is not duplicated.
        let (_, g2) = build_identity_maps(1000, 1000, &[1000, 0, 27]);
        assert_eq!(g2, "0 0 1\n1000 1000 1\n27 27 1\n");
    }
}
