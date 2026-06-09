//! The privhelper **factory**: build a kennel and `fexecve` `kennel-init` into it.
//!
//! The construction inversion (`docs/design/07-2-kennel-init.md` §7.2.1): rather than
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
use kennel_spawn::{build_view_and_pivot, join_cgroup, ConstructionHalf};
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
    let code = match construct(chan) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("kennel-privhelper: kennel construction failed: {e}");
            CONSTRUCT_FAILED
        }
    };
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

    // The operator identity (the caller's real ids; setcap/setuid leave the real uid as
    // the invoking user) — never wire-supplied (sec review §6).
    let op_uid = real_uid();
    let op_gid = real_gid();

    // 3. Clone the construction child as the OPERATOR (NOT escalated): this sets the new
    //    user namespace's **owner** to the operator, so the operator `kenneld` is
    //    privileged over the kennel's binderfs (an `FS_USERNS_MOUNT` whose `s_user_ns` is
    //    the kennel userns) and can open it via `/proc/<init>/root`. A root-owned userns
    //    would deny the operator that access. The child still gets full capabilities in the
    //    new userns (a `CLONE_NEWUSER` child always does), so it can escalate to the
    //    kennel's uid 0 itself for the root-owned construction (see below).
    let granted = half.granted_gids.clone();
    let namespaces = half.namespaces; // captured before `half` moves into the child
    let child = move || {
        // Wait until the parent has written our identity maps (so the kennel's uid 0 is
        // mappable); abort closed otherwise.
        if recv_ack(ready_r.as_fd()).ok().flatten() != Some(ACK_PROCEED) {
            return; // clone_pid1 backstops a returning child with _exit(127)
        }
        // Become the kennel's uid 0 (inside-0 = host root via the `0 0 1` map line) using the
        // userns capabilities the clone granted, so the view/dev/binderfs are root-owned.
        if kennel_syscall::unistd::set_gid(0).is_err()
            || kennel_syscall::unistd::set_uid(0).is_err()
        {
            return;
        }
        // All privileged construction runs here, as the kennel's uid 0, BEFORE the hand-off
        // — so the surfaces are root-owned and no operator code runs as userns-0. A failure
        // returns, tripping the _exit(127) backstop (no half-built kennel runs the workload).
        if build_kennel(&half, op_uid, op_gid).is_err() {
            return;
        }
        // Hand off to the trusted root-owned init **as the kennel's uid 0** (no drop): PID 1
        // must NOT share the operator uid, or the operator-uid workload/facades could signal
        // or ptrace it (07-11 §7.2.5). `kennel-init` itself drops the workload and facades to
        // the operator. kenneld still reaches `/proc/<init>/root` because the kennel userns is
        // operator-owned, so the operator kenneld holds CAP_SYS_PTRACE in it. Empty argv/envp
        // (the pull model).
        let _err = fexecve(init_fd.as_fd(), &[], &[]);
        // fexecve returned ⇒ failure; fall through to the _exit(127) backstop.
    };
    let init_pid = clone_pid1(namespaces, child)?;

    // 4. Escalate the parent to real root ONLY to write the child's identity maps: mapping
    //    host uid 0 into the kennel (the `0 0 1` line) requires the writer to own outside uid 0
    //    (`verify_root_map`, euid 0) and `CAP_SETFCAP` (since Linux 5.12). This does not
    //    change the userns owner (fixed at clone above). Then release the child and report
    //    the init host pid to kenneld.
    kennel_syscall::unistd::set_gid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setgid(0): {e}")))?;
    kennel_syscall::unistd::set_uid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setuid(0): {e}")))?;
    write_identity_maps(init_pid, op_uid, op_gid, &granted)?;
    send_ack(ready_w.as_fd(), ACK_PROCEED)?;
    drop(ready_w); // close our write end
    send_with_fds(chan, &init_pid.to_le_bytes(), &[])?;

    // 5. Stay as the child's parent; relay its exit status up the chain.
    loop {
        match wait_any()? {
            Reaped::Exited { pid, code } if pid == init_pid => return Ok(code),
            Reaped::Exited { .. } => {} // some other reaped child; keep waiting for init
            Reaped::NoChildren => return Ok(CONSTRUCT_FAILED),
        }
    }
}

/// The privileged construction the factory child runs as the kennel's uid 0, after its
/// maps are written and before the `fexecve` (`07-11` §7.2.1): join the cgroup, build
/// and `pivot_root` into the view, and hand the per-kennel binderfs device to the
/// operator (the fix for the binderfs `EACCES`).
///
/// Runs entirely inside the construction child's namespaces; nothing here is visible to,
/// or reversible by, the workload (it precedes the `fexecve` of `kennel-init`, which
/// precedes the operator-identity drop).
#[allow(clippy::similar_names)] // op_uid / op_gid are the domain names
fn build_kennel(half: &ConstructionHalf, op_uid: u32, op_gid: u32) -> io::Result<()> {
    use kennel_syscall::mount;

    if half.cgroup_join {
        join_cgroup(&half.cgroup)?;
    }
    // In-namespace loopback is the per-kennel net-ns path (07-10); not yet built, and the
    // kennel currently shares the host net namespace, so `lo` is always false here.
    if half.lo {
        return Err(io::Error::other("in-namespace loopback not yet implemented"));
    }

    // Detach mount propagation from the host before any mount in either path.
    mount::make_root_private()?;
    if let (Some(view), Some(new_root)) = (&half.view, &half.new_root) {
        // Build + pivot into the constructed view.
        build_view_and_pivot(view, new_root, &half.file_binds)?;
        // The constructed $HOME is the WORKLOAD's private space (the home dir on the view-root
        // tmpfs plus the copied dotfiles / synthetic ~/.ssh). The construction child built it
        // as the kennel's uid 0, so it is root-owned — but the workload, the af-unix proxy,
        // and any in-kennel tool run as the OPERATOR and must read (0600 ~/.ssh keys) and
        // write (bind sockets) there. Hand the operator only the inodes we constructed.
        chown_constructed_home(&view.shim_root, op_uid, op_gid)?;
        // Hand the binderfs device to the operator: it is created mode 0600 owned by uid 0 of
        // the (now real) userns, but every binder client — kennel-init, the af-unix proxy,
        // kenneld via /proc/<init>/root — acts as the operator. The mount-root dir is 0755
        // (operator-traversable already), so only the device itself needs chowning.
        if view.binder {
            kennel_syscall::unistd::chown_to(
                std::path::Path::new("/dev/binderfs/binder"),
                op_uid,
                op_gid,
            )?;
        }
    } else {
        // Fallback (no constructed view): a private root with fresh /proc + /tmp, so the
        // PID namespace still gets a correct /proc. No binderfs without a view.
        mount::mount_special("proc", std::path::Path::new("/proc"))?;
        mount::mount_special("tmpfs", std::path::Path::new("/tmp"))?;
    }
    Ok(())
}

/// Hand the operator the constructed `$HOME` — and **only inodes we constructed**.
///
/// The home dir and the copied dotfiles / synthetic `~/.ssh` live on the **view-root tmpfs**
/// (the privhelper built them as the kennel's uid 0, so they are root-owned), but the
/// workload / af-unix proxy / in-kennel tools run as the operator and must read the 0600 ssh
/// keys and bind sockets there. So chown them to the operator — but writable **binds**
/// (persisted home paths: the operator's own real host inodes), `/dev`, `/proc`, `/tmp`, and
/// binderfs must NEVER be touched.
///
/// The discriminator is the device id: the view root (`/`, post-pivot) is the constructed
/// tmpfs; every bind/special mount has a different device. So we chown only inodes whose
/// device matches `/`, skipping any sub-mount — and if `$HOME` *itself* is a bind (the
/// whole-home-persist case) it is on a different device and we touch nothing under it (it is
/// already the operator's own data). Symlinks are skipped entirely (ownership is irrelevant
/// for them and it avoids any follow), so no `lchown` dance is needed.
fn chown_constructed_home(shim_root: &std::path::Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    // The constructed view root: only its inodes are ours to chown.
    let root_dev = std::fs::symlink_metadata("/")?.dev();
    let Ok(home) = std::fs::symlink_metadata(shim_root) else {
        return Ok(()); // no constructed home (e.g. the fallback path)
    };
    if home.file_type().is_symlink() || home.dev() != root_dev {
        return Ok(()); // $HOME is a bind (persisted) or a symlink — not ours to chown
    }
    kennel_syscall::unistd::chown_to(shim_root, uid, gid)?;
    let mut stack = vec![shim_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // Skip symlinks (don't chown, don't follow) and anything on another mount
            // (a writable bind / special fs) — chown only constructed view-root inodes.
            if meta.file_type().is_symlink() || meta.dev() != root_dev {
                continue;
            }
            kennel_syscall::unistd::chown_to(&path, uid, gid)?;
            if meta.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Write the construction child's `uid_map` and `gid_map` (`07-11` §7.2.1).
///
/// Always maps host root in (`0 0 1`) so the kennel has a real uid 0, then the operator's
/// own real uid/gid (so the workload's masked identity is a sane non-root id), then each
/// granted supplementary gid. The operator line is omitted when the operator *is* root
/// (the maps would otherwise overlap — the case when the factory runs under a root test).
/// Writing requires the parent's `CAP_SETUID`/`CAP_SETGID`; `setgroups` is left enabled
/// (not denied) because `kennel-init` needs it for the workload's supplementary-group drop.
fn write_identity_maps(pid: i32, uid: u32, gid: u32, granted: &[u32]) -> io::Result<()> {
    let (uid_map, gid_map) = build_identity_maps(uid, gid, granted);
    std::fs::write(format!("/proc/{pid}/uid_map"), &uid_map)
        .map_err(|e| io::Error::new(e.kind(), format!("uid_map write ({uid_map:?}): {e}")))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), &gid_map)
        .map_err(|e| io::Error::new(e.kind(), format!("gid_map write ({gid_map:?}): {e}")))?;
    Ok(())
}

/// Build the `uid_map`/`gid_map` strings (pure; the write is in [`write_identity_maps`]).
///
/// **Precise multi-extent map** — exactly host uid/gid 0 (the kennel's real root) plus the
/// operator's own id (the masked identity the workload runs as), plus each granted
/// supplementary gid. NOT a `0 0 N` range: the kernel allows a multi-extent map mapping
/// host 0 as long as it is written in a **single `write(2)`** (which `write_identity_maps`
/// does) and the writer holds `CAP_SETFCAP` (Linux 5.12+) — so the kennel never maps the
/// unrelated host system uids between 0 and the operator. The operator line is omitted when
/// the operator *is* root (the lines would overlap — the root-test case).
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
    fn maps_are_precise_root_plus_operator_plus_granted() {
        // Operator is root (the root-test case): a single 0 0 1 line, no overlap.
        assert_eq!(build_identity_maps(0, 0, &[]), ("0 0 1\n".into(), "0 0 1\n".into()));
        // Operator is a normal user: host root + the operator's own id — NOT the whole
        // 0..operator range (multi-extent is fine in one write() with CAP_SETFCAP).
        let (u, g) = build_identity_maps(1000, 1000, &[27, 44]);
        assert_eq!(u, "0 0 1\n1000 1000 1\n");
        assert_eq!(g, "0 0 1\n1000 1000 1\n27 27 1\n44 44 1\n");
        // A granted gid equal to the primary (or 0) is not duplicated.
        let (_, g2) = build_identity_maps(1000, 1000, &[1000, 0, 27]);
        assert_eq!(g2, "0 0 1\n1000 1000 1\n27 27 1\n");
    }
}
