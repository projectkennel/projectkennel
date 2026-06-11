//! The privhelper **factory**: build a kennel and `fexecve` `kennel-bin-init` into it.
//!
//! The construction inversion (`docs/design/07-2-kennel-bin-init.md` §7.2.1): rather than
//! `kenneld` (the operator) building the sandbox unprivileged, the privhelper — real
//! root — does *all* privileged construction in its own post-`clone` child, then
//! `fexecve`s the trusted root-owned `kennel-bin-init` as the kennel's uid-0 PID 1. Doing it
//! here is what gives the kennel a **real uid 0** (host root mapped `0 0 1`) so the view
//! root, `/dev`, the library binds, and the binderfs nodes are owned by and display as
//! root — and what fixes the binderfs `EACCES` (a binderfs instance assigns its nodes to
//! uid 0 of the mounting userns; with the old pure-identity map there was no uid 0).
//!
//! # Transport
//!
//! `kenneld` invokes the helper as `kennel-privhelper construct` with one end of a
//! `SOCK_SEQPACKET` pair as the helper's **stdin**. It sends one datagram: the
//! `ConstructionHalf` bytes as data (and, later, a controlling-pty socket as `SCM_RIGHTS`).
//! The `kennel-bin-init` binary is **not** taken from the wire — the helper resolves it from the
//! root-owned deployment cascade itself (see below). The helper replies on the same channel
//! with the construction child's **host pid** (so `kenneld` can take binder node 0 via
//! `/proc/<pid>/root` and gate the lifecycle verbs), then stays alive as that child's parent
//! and `_exit`s with its status — the reliable exit path up to `kenneld`.
//!
//! # The clone / map handshake
//!
//! `clone(NEWUSER|…)` creates the child with **no** identity mapping, so it holds no
//! capability in the new userns until the parent writes its `uid_map`/`gid_map`. The
//! child therefore blocks on a pipe until the parent (real root, holding `CAP_SETUID`/
//! `CAP_SETGID`) has written the `0 0 1`+operator maps and acked; only then does it run
//! the (privileged) construction and `fexecve`. No operator-controlled code ever runs as
//! userns-0: between `clone` and `fexecve` only this factory code runs, and `kennel-bin-init` is
//! the trusted root-owned binary the helper resolves from its own root-only config — never a
//! path or fd the operator supplies (sec review: trusted init source).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use kennel_lib_spawn::wire::decode_construction;
use kennel_lib_spawn::{build_view_and_pivot, join_cgroup, ConstructionHalf, LoopbackAddr};
use kennel_lib_syscall::boot::BOOT_SYNC_FD;
use kennel_lib_syscall::fd::dup_onto;
use kennel_lib_syscall::handshake::{pipe_cloexec, recv_ack, send_ack, ACK_PROCEED};
use kennel_lib_syscall::namespace::clone_pid1;
use kennel_lib_syscall::pty::PTY_RETURN_FD;
use kennel_lib_syscall::scm::{recv_with_fds, send_with_raw_fds, seqpacket_pair};
use kennel_lib_syscall::spawn::fexecve;
use kennel_lib_syscall::unistd::{real_gid, real_uid};

use crate::validate::{validate_addr, AddrRequest, ReservedScope};
use crate::wire::EgressPayload;

/// The interface the per-kennel loopback addresses live on (shared host net namespace).
const LOOPBACK: &str = "lo";

/// Receive buffer for the construction datagram: the length-prefixed construction-half plus
/// the (variable-length) egress payload tail. Sized for a large allow/deny ruleset.
const RECV_CAP: usize = 1 << 18;

/// Exit code when construction fails before the child is running (parsing, clone, maps).
const CONSTRUCT_FAILED: i32 = 125;

/// Run the factory over `chan` (the `SOCK_SEQPACKET` end `kenneld` handed us as stdin).
///
/// Never returns: the construction child `fexecve`s `kennel-bin-init` (or `_exit`s on
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
/// `kennel-bin-init`, and wait for it — returning the child's exit status.
// `op_uid`/`op_gid` are the domain names; the pedantic similar-names heuristic flags the
// pair, but renaming would only obscure them.
#[allow(clippy::similar_names)]
fn construct(chan: BorrowedFd<'_>) -> io::Result<i32> {
    // 0. `chan` (our stdin) is the privileged kenneld↔helper SEQPACKET. The `clone` below
    //    copies our fd table into the construction child, so mark `chan` close-on-exec now:
    //    `kennel-bin-init` (and the workload it later spawns) must NEVER inherit a handle to the
    //    factory transport across the `fexecve` (sec review: fd hygiene). The received SCM
    //    fds are already `MSG_CMSG_CLOEXEC` and the handshake pipe is `pipe_cloexec`, so this
    //    leaves only stdout/stderr inherited.
    kennel_lib_syscall::fd::set_cloexec(chan)?;

    // 1. Receive the construction datagram. Framing: `[u32 ch_len][construction-half][egress]`
    //    — the fixed construction-half (length-prefixed so its decoder gets exactly its bytes)
    //    followed by the optional egress payload tail. For an interactive run the datagram also
    //    carries the controlling-pty **return socket** as the sole `SCM_RIGHTS` fd (the binary
    //    to run as uid 0 is NOT taken from the wire — see step 1b). It arrives
    //    `MSG_CMSG_CLOEXEC`; the construction child re-homes it at `PTY_RETURN_FD` (clearing
    //    close-on-exec) just before `fexecve` so the argv-less `kennel-bin-init` inherits it there.
    let mut buf = vec![0u8; RECV_CAP];
    let (n, mut wire_fds) = recv_with_fds(chan, &mut buf)?;
    let pty_fd: Option<OwnedFd> = (!wire_fds.is_empty()).then(|| wire_fds.remove(0));
    let msg = buf.get(..n).unwrap_or(&[]);
    let ch_len = msg
        .get(0..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .map(|v| v as usize)
        .ok_or_else(|| io::Error::other("construction datagram missing length prefix"))?;
    let ch_end = 4usize.saturating_add(ch_len);
    let ch_bytes = msg
        .get(4..ch_end)
        .ok_or_else(|| io::Error::other("construction datagram shorter than its length prefix"))?;
    let egress_bytes = msg.get(ch_end..).unwrap_or(&[]);
    let half = decode_construction(ch_bytes)
        .map_err(|e| io::Error::other(format!("construction-half decode: {e:?}")))?;

    // 1a. Provision the kennel's host-side network resources — folded into this one op (the
    //     former separate `add-addr`/`setup-egress` privhelper invocations are gone). Runs as
    //     the operator with the helper's file caps (`cap_net_admin` + the BPF caps), before any
    //     privilege change, in the host net namespace (the kennel still shares it). Each
    //     loopback address is re-validated against the caller's reserved subnet — the operator
    //     does not get to pick arbitrary addresses — then added on `lo`; the egress BPF, if
    //     present, is attached to the kennel cgroup (whose ownership the attach re-checks).
    let Some(scope) = crate::alloc::load(real_uid()) else {
        return Err(io::Error::other("caller has no reserved scope"));
    };
    add_loopback_addresses(&half.loopback, half.ctx, &scope)?;
    if !egress_bytes.is_empty() {
        let payload = EgressPayload::decode(egress_bytes)
            .map_err(|e| io::Error::other(format!("egress payload decode: {e:?}")))?;
        let resp = crate::exec::attach_egress_programs(&half.cgroup, &payload);
        if resp.status != crate::wire::Status::Ok {
            return Err(io::Error::other(format!(
                "egress attach refused (code {})",
                resp.refusal
            )));
        }
    }

    // 1b. Resolve and open the trusted `kennel-bin-init` from the **root-owned** deployment
    //     cascade (`/usr/lib/kennel` → `/etc/kennel`; never a user-writable dir or the
    //     environment — `kennel_lib_config::Deployment::load`). The operator (`kenneld`) does not
    //     get to choose what runs as the kennel's uid 0 (= host root via the `0 0 1` map): a
    //     wire-supplied fd would let a compromised or hostile operator `fexecve` arbitrary
    //     code as root, defeating the very boundary the helper exists to hold. We open it
    //     ourselves and the child `fexecve`s this fd (sec review: trusted init source) — the
    //     same principle as the never-wire-supplied operator identity below (sec review §6).
    let init_path = kennel_lib_config::Deployment::load()
        .map_err(|e| {
            io::Error::other(format!(
                "resolve kennel-bin-init from deployment config: {e}"
            ))
        })?
        .kennel_bin_init();
    let init_file = std::fs::File::open(&init_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("open trusted kennel-bin-init {}: {e}", init_path.display()),
        )
    })?;
    verify_trusted_init(&init_file, &init_path)?;

    // 2. The maps-written handshake pipe (child blocks until the parent writes the maps).
    let (ready_r, ready_w) = pipe_cloexec()?;

    // The boot-sync socket (07-2 §7.2.1a) that makes startup deterministic. `kennel-bin-init` cannot
    // take node 0 before it `fexecve`s (kenneld opens the binderfs via `/proc/<init>/root`, which
    // only resolves post-exec), yet must not pull before node 0 is up — so the factory gates the
    // *pull*, not the exec: the child inherits `init_sync` at `BOOT_SYNC_FD` across the `fexecve`,
    // and kenneld holds `daemon_sync` (we hand it over with the init pid below). `kennel-bin-init`
    // signals "ready" on it after exec and blocks; kenneld claims node 0 and signals "go".
    let (init_sync, daemon_sync) = seqpacket_pair()?;

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
        if kennel_lib_syscall::unistd::set_gid(0).is_err()
            || kennel_lib_syscall::unistd::set_uid(0).is_err()
        {
            return;
        }
        // All privileged construction runs here, as the kennel's uid 0, BEFORE the hand-off
        // — so the surfaces are root-owned and no operator code runs as userns-0. A failure
        // returns, tripping the _exit(127) backstop (no half-built kennel runs the workload).
        if build_kennel(&half, op_uid, op_gid).is_err() {
            return;
        }
        // Place the descriptors `kennel-bin-init` inherits at fixed numbers (`BOOT_SYNC_FD`, and
        // `PTY_RETURN_FD` for an interactive run), returning the init-binary fd to exec.
        let pty_ref = pty_fd.as_ref().map(AsFd::as_fd);
        let Ok(init_file) = place_handoff_fds(init_file.as_fd(), init_sync.as_fd(), pty_ref) else {
            return;
        };
        // Hand off to the trusted `kennel-bin-init` (resolved from root-owned config, not the
        // wire) **as the kennel's uid 0** (no drop): PID 1 must NOT share the operator uid, or
        // the operator-uid workload/facades could signal or ptrace it (07-2 §7.2.5).
        // `kennel-bin-init` itself drops the workload and facades to the operator. kenneld still
        // reaches `/proc/<init>/root` because the kennel userns is operator-owned, so the
        // operator kenneld holds CAP_SYS_PTRACE in it. Empty argv/envp (the pull model).
        let _err = fexecve(init_file.as_fd(), &[], &[]);
        // fexecve returned ⇒ failure; fall through to the _exit(127) backstop.
    };
    let init_pid = clone_pid1(namespaces, child)?;

    // 4. Escalate the parent to real root ONLY to write the child's identity maps: mapping
    //    host uid 0 into the kennel (the `0 0 1` line) requires the writer to own outside uid 0
    //    (`verify_root_map`, euid 0) and `CAP_SETFCAP` (since Linux 5.12). This does not
    //    change the userns owner (fixed at clone above). Then release the child and report
    //    the init host pid to kenneld.
    kennel_lib_syscall::unistd::set_gid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setgid(0): {e}")))?;
    kennel_lib_syscall::unistd::set_uid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setuid(0): {e}")))?;
    write_identity_maps(init_pid, op_uid, op_gid, &granted)?;

    // Drop straight back to the operator now that the maps are written: the parent escalated
    // ONLY to write them. setgid before setuid (the uid drop to a non-zero value is what
    // clears the capability sets — capabilities(7)); for its brief remaining life (report the
    // pid, then exit) the factory parent is the unprivileged operator, never a long-lived
    // host-root process (sec review: minimise the privileged window). A no-op when the operator
    // is root (the root-test case, op_uid == 0).
    kennel_lib_syscall::unistd::set_gid(op_gid)
        .map_err(|e| io::Error::new(e.kind(), format!("factory drop setgid({op_gid}): {e}")))?;
    kennel_lib_syscall::unistd::set_uid(op_uid)
        .map_err(|e| io::Error::new(e.kind(), format!("factory drop setuid({op_uid}): {e}")))?;

    // "build": maps are written, so the child may become uid 0, construct the binderfs, and
    // `fexecve` `kennel-bin-init` (which then blocks on the boot-sync socket before pulling).
    send_ack(ready_w.as_fd(), ACK_PROCEED)?;
    drop(ready_w);

    // Report the init pid AND hand kenneld the boot-sync socket as the sole SCM fd: kenneld waits
    // on it for `kennel-bin-init`'s post-exec "ready", claims node 0 (now reachable via
    // /proc/<pid>/root), and signals "go". With that off our hands, the factory's job is done.
    send_with_raw_fds(chan, &init_pid.to_le_bytes(), &[daemon_sync.as_raw_fd()])?;

    // 5. Done. The factory's whole job was to build the kennel, write the maps, and report the init
    //    pid (plus the boot-sync socket) — `kennel-bin-init` is now PID 1 of the new namespace and an
    //    autonomous daemon, so there is nothing left for this process to do. It exits immediately
    //    rather than lingering as a reaper proxy: `kennel-bin-init` outlives it (a PID namespace is
    //    tied to its own PID 1, not to the cloner), and kenneld — a `set_child_subreaper` — adopts
    //    the orphaned init and `waitpid`s it directly for the workload's exit status. One
    //    fewer resident host process per kennel.
    Ok(0)
}

/// Place the descriptors `kennel-bin-init` inherits at the fixed numbers it reads — the boot-sync
/// socket at [`BOOT_SYNC_FD`] and (interactive) the pty return socket at [`PTY_RETURN_FD`] —
/// returning the init-binary fd to `fexecve`.
///
/// Every descriptor we still need (the init binary, the boot-sync socket, the pty socket) is
/// first lifted ABOVE the target range with [`dup_above`], so `dup2`-ing onto the low fixed
/// numbers cannot clobber one of them — their natural fd numbers depend on what else is open and
/// could otherwise land on a target (the bug an interactive run, with its extra pty fd, exposed).
/// `dup_above` keeps close-on-exec; [`dup_onto`] clears it on the fixed targets so they survive
/// the `fexecve`; the relocated copies (still cloexec) close across it.
fn place_handoff_fds(
    init_file: BorrowedFd<'_>,
    init_sync: BorrowedFd<'_>,
    pty_fd: Option<BorrowedFd<'_>>,
) -> io::Result<OwnedFd> {
    use kennel_lib_syscall::fd::dup_above;
    let base = if PTY_RETURN_FD > BOOT_SYNC_FD {
        PTY_RETURN_FD + 1
    } else {
        BOOT_SYNC_FD + 1
    };
    let init_file = dup_above(init_file, base)?;
    let init_sync = dup_above(init_sync, base)?;
    let pty_hi = pty_fd.map(|p| dup_above(p, base)).transpose()?;
    dup_onto(init_sync.as_fd(), BOOT_SYNC_FD)?;
    if let Some(pty) = &pty_hi {
        dup_onto(pty.as_fd(), PTY_RETURN_FD)?;
    }
    Ok(init_file)
}

/// Validate each loopback address against the caller's reserved `scope`, then add it on `lo`
/// via netlink (host net namespace, the helper's `cap_net_admin`). The operator supplies the
/// addresses but the factory does not trust them: one outside the per-kennel subnet is refused
/// — the same [`validate_addr`] gate the standalone `add-addr` op used before this fold.
fn add_loopback_addresses(
    addrs: &[LoopbackAddr],
    ctx: u16,
    scope: &ReservedScope,
) -> io::Result<()> {
    if addrs.is_empty() {
        return Ok(());
    }
    let cname = std::ffi::CString::new(LOOPBACK).map_err(|_| io::Error::other("bad ifname"))?;
    let ifindex = kennel_lib_syscall::netlink::if_index(&cname)?;
    for lb in addrs {
        let req = AddrRequest {
            ctx,
            interface: LOOPBACK.to_owned(),
            addr: lb.addr,
            prefix: lb.prefix,
        };
        if let Err(refusal) = validate_addr(&req, scope) {
            return Err(io::Error::other(format!(
                "loopback address {} refused: {refusal}",
                lb.addr
            )));
        }
        kennel_lib_syscall::netlink::add_address(ifindex, lb.addr, lb.prefix)?;
    }
    Ok(())
}

/// The privileged construction the factory child runs as the kennel's uid 0, after its
/// maps are written and before the `fexecve` (`07-2` §7.2.1): join the cgroup, build
/// and `pivot_root` into the view, and hand the per-kennel binderfs device to the
/// operator (the fix for the binderfs `EACCES`).
///
/// Runs entirely inside the construction child's namespaces; nothing here is visible to,
/// or reversible by, the workload (it precedes the `fexecve` of `kennel-bin-init`, which
/// precedes the operator-identity drop).
#[allow(clippy::similar_names)] // op_uid / op_gid are the domain names
fn build_kennel(half: &ConstructionHalf, op_uid: u32, op_gid: u32) -> io::Result<()> {
    use kennel_lib_syscall::mount;

    if half.cgroup_join {
        join_cgroup(&half.cgroup)?;
    }
    // In-namespace loopback (§7.3): a fresh net-ns starts with `lo` DOWN and no addresses. Bring it
    // up and add the kennel's own loopback addresses inside the net-ns — the mirror of the host-lo
    // alias the factory already added (the same addresses on both sides of the boundary). The
    // construction child holds CAP_NET_ADMIN over its own new userns+netns, so this is unprivileged.
    // The addresses were re-validated against the caller's reserved scope before the host add above.
    if half.lo {
        let cname = std::ffi::CString::new(LOOPBACK).map_err(|_| io::Error::other("bad ifname"))?;
        let lo = kennel_lib_syscall::netlink::if_index(&cname)?;
        kennel_lib_syscall::netlink::set_link_up(lo)?;
        for lb in &half.loopback {
            kennel_lib_syscall::netlink::add_address(lo, lb.addr, lb.prefix)?;
        }
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
        // the (now real) userns, but every binder client — kennel-bin-init, the af-unix proxy,
        // kenneld via /proc/<init>/root — acts as the operator. The mount-root dir is 0755
        // (operator-traversable already), so only the device itself needs chowning.
        if view.binder {
            kennel_lib_syscall::unistd::chown_to(
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
    kennel_lib_syscall::unistd::chown_to(shim_root, uid, gid)?;
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
            kennel_lib_syscall::unistd::chown_to(&path, uid, gid)?;
            if meta.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Verify the opened `kennel-bin-init` is a trusted root-owned binary before `fexecve`
/// (`07-2`; `02-adversary-model`): a **regular file**, owned by **uid 0**, and **not writable
/// by group or other**. The path already comes from root-only config, so this is defence in
/// depth — it catches a deployment config that points `init` at an operator-writable file,
/// which would otherwise let non-root-controlled code run as the kennel's uid 0. The check is
/// on the already-open fd (no TOCTOU between the stat and the `fexecve`).
fn verify_trusted_init(file: &std::fs::File, path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other(format!(
            "kennel-bin-init {} is not a regular file",
            path.display()
        )));
    }
    if meta.uid() != 0 {
        return Err(io::Error::other(format!(
            "kennel-bin-init {} is not owned by root (owner uid {})",
            path.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(io::Error::other(format!(
            "kennel-bin-init {} is writable by group or other (mode {:o})",
            path.display(),
            meta.mode()
        )));
    }
    Ok(())
}

/// Write the construction child's `uid_map` and `gid_map` (`07-2` §7.2.1).
///
/// Always maps host root in (`0 0 1`) so the kennel has a real uid 0, then the operator's
/// own real uid/gid (so the workload's masked identity is a sane non-root id), then each
/// granted supplementary gid. The operator line is omitted when the operator *is* root
/// (the maps would otherwise overlap — the case when the factory runs under a root test).
/// Writing requires the parent's `CAP_SETUID`/`CAP_SETGID`; `setgroups` is left enabled
/// (not denied) because `kennel-bin-init` needs it for the workload's supplementary-group drop.
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
        assert_eq!(
            build_identity_maps(0, 0, &[]),
            ("0 0 1\n".into(), "0 0 1\n".into())
        );
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
