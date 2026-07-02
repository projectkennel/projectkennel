//! The privhelper **factory**: build a kennel and `fexecve` `kennel-bin-init` into it.
//!
//! The construction inversion (Kennel book Vol 2 ch.2 (Process and Privilege Model)): rather than
//! `kenneld` (the operator) building the sandbox unprivileged, the privhelper — holding the
//! factory file capabilities `{cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin}` — does *all*
//! privileged construction in its own post-`clone` child, then `fexecve`s the trusted root-owned
//! `kennel-bin-init` as the kennel's uid-0 PID 1. Doing it here is what gives the kennel a **real
//! uid 0** (host root mapped `0 0 1`) so the view root, `/dev`, the library binds, and the
//! binderfs nodes are owned by and display as root — and what fixes the binderfs `EACCES` (a
//! binderfs instance assigns its nodes to uid 0 of the mounting userns; with a pure-identity map
//! there is no uid 0). Mapping host uid 0 into the new userns is exactly what makes `cap_sys_admin`
//! load-bearing: the kernel's `uid_map` write gate requires `CAP_SYS_ADMIN` over the target
//! namespace.
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
//! capability in the new userns until the parent writes its `uid_map`/`gid_map`. The child
//! therefore blocks on a pipe until the parent — which briefly raises its euid to 0 (via
//! `CAP_SETUID`) and uses `CAP_SETGID`/`CAP_SETFCAP`/`CAP_SYS_ADMIN` to write the `0 0 1`+operator
//! maps — has written them and acked; only then does it run the (privileged) construction and
//! `fexecve`. No operator-controlled code ever runs as
//! userns-0: between `clone` and `fexecve` only this factory code runs, and `kennel-bin-init` is
//! the trusted root-owned binary the helper resolves from its own root-only config — never a
//! path or fd the operator supplies (sec review: trusted init source).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use kennel_lib_spawn::wire::decode_construction;
use kennel_lib_spawn::{build_view_and_pivot, ConstructionHalf, LoopbackAddr};
use kennel_lib_syscall::boot::BOOT_SYNC_FD;
use kennel_lib_syscall::fd::dup_onto;
use kennel_lib_syscall::handshake::{pipe_cloexec, recv_ack, send_ack, ACK_PROCEED};
use kennel_lib_syscall::namespace::{clone_pid1, clone_pid1_in_cgroup};
use kennel_lib_syscall::pty::PTY_RETURN_FD;
use kennel_lib_syscall::scm::{recv_with_fds, send_with_raw_fds, seqpacket_pair};
use kennel_lib_syscall::spawn::fexecve;
use kennel_lib_syscall::unistd::{real_gid, real_uid};

/// The loopback interface name (`lo`). The kennel's own addresses are added to `lo` on BOTH
/// sides of the boundary: inside the kennel's own net-ns (where the workload sees them) and,
/// as a mirror, on the host `lo` (so an operator's `ss`/`lsof` maps a kennel address back to
/// the kennel, §7.5.6). Host (`mode = host`) shares the host `lo` directly and adds no in-ns copy.
const LOOPBACK: &str = "lo";

/// Receive buffer for the construction datagram: the length-prefixed construction-half plus
/// the (variable-length) egress payload tail. Sized for a large allow/deny ruleset.
const RECV_CAP: usize = 1 << 18;

/// Exit code when construction fails before the child is running (parsing, clone, maps).
const CONSTRUCT_FAILED: i32 = 125;

/// Pop the next SCM fd from `fds` iff `present`, returning it (or `None` when not present).
///
/// The fds arrive in a fixed order (pty then workload), each gated by a construction-half
/// flag. `present` with no fd left is a malformed datagram — fail closed. `role` names the
/// fd for the error.
fn pop_flagged_fd(
    fds: &mut Vec<OwnedFd>,
    present: bool,
    role: &str,
) -> io::Result<Option<OwnedFd>> {
    if !present {
        return Ok(None);
    }
    if fds.is_empty() {
        return Err(io::Error::other(format!(
            "construction datagram declares a {role} fd but none was passed"
        )));
    }
    Ok(Some(fds.remove(0)))
}

/// Run the factory over `chan` (the `SOCK_SEQPACKET` end `kenneld` handed us as stdin).
///
/// Never returns: the construction child `fexecve`s `kennel-bin-init` (or `_exit`s on
/// failure), and this parent `_exit`s with the child's status once it terminates. A
/// failure before the child exists exits `CONSTRUCT_FAILED`.
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
// allow(too_many_lines): one cohesive privileged construction — recv, clone with the
// operator-owned userns, write maps, hand off — that cannot be split without breaking the
// linear fd/identity/clone ordering the security argument depends on.
#[allow(clippy::similar_names, clippy::too_many_lines)]
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
    // The spawn-path tracer (the `log_level` knob): resolved from the root-owned deployment
    // config, the same cascade the privhelper already reads for `kennel-bin-init` below. The
    // privhelper's stderr is inherited from kenneld, so these lines reach the same journal. The
    // child trace lines below are especially load-bearing: the construction child's only failure
    // signal upstream is its `_exit(127)`, so a step trace is the sole way to see WHERE it died.
    let tracer = kennel_lib_config::Deployment::load().map_or_else(
        |_| kennel_lib_config::Tracer::new("kennel-privhelper", kennel_lib_config::LogLevel::Info),
        |d| kennel_lib_config::Tracer::new("kennel-privhelper", d.log_level()),
    );

    let mut buf = vec![0u8; RECV_CAP];
    let (n, mut wire_fds) = recv_with_fds(chan, &mut buf)?;
    tracer.step(&format!(
        "construct: received datagram ({n} bytes, {} fds)",
        wire_fds.len()
    ));
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

    // Pull the SCM fds in the FIXED send order (pty then workload), guided by the half's
    // presence flags — so an absent pty does not misalign the workload fd. A flag set but no
    // fd present is a malformed datagram (fail closed). `remove(0)` keeps the order.
    let pty_fd: Option<OwnedFd> = pop_flagged_fd(&mut wire_fds, half.pty_fd_present, "pty")?;
    let workload_fd: Option<OwnedFd> =
        pop_flagged_fd(&mut wire_fds, half.workload_fd_present, "workload")?;
    // The three injected-stdio fds (a non-interactive run), placed last in the fixed order.
    let stdio_fds: Option<[OwnedFd; 3]> = pop_stdio_fds(&mut wire_fds, half.stdio_present)?;

    // 1a. Provision the kennel's host-side network resources by delegating to the capability-split
    //     sub-helpers — the factory itself holds no `cap_net_admin` or BPF caps. Runs as the
    //     operator, before any privilege change, in the **host** net namespace. This adds the
    //     kennel's loopback addresses as a MIRROR on the host `lo`: a proxied kennel runs in its OWN
    //     net-ns (the in-ns copy is added later, in `build_kennel`), and this host-side mirror is
    //     what makes a kennel address visible to the operator's `ss`/`lsof` and reachable by the
    //     host-side BIND delegate (§7.5.6/§7.5.7). `mode = host` shares the host `lo` outright (no
    //     own net-ns, no in-ns copy). Each address is re-validated against the caller's reserved
    //     subnet inside `kennel-privhelper-net` — the operator does not get to pick arbitrary
    //     addresses — then added on `lo`; the egress BPF, if present, is attached to the kennel
    //     cgroup by `kennel-privhelper-bpf` (cgroup ownership re-checked there).
    // Gate (defence in depth; `main.rs` gates `construct` on the same allocation): the caller
    // must hold a subkennel allocation. The per-address subnet validation now lives in the
    // `kennel-privhelper-net` sub-helper, which re-loads the scope and validates itself.
    if crate::alloc::load(real_uid()).is_none() {
        return Err(io::Error::other("caller has no reserved scope"));
    }
    tracer.step(&format!(
        "construct: adding {} host loopback address(es) (ctx {})",
        half.loopback.len(),
        half.ctx
    ));
    // Diagnostic (trace): the effective uid + capability words at the host-side add, so an
    // EPERM here is attributable to euid/caps rather than the netns or the address itself.
    {
        let euid = kennel_lib_syscall::unistd::effective_uid();
        let caps = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let cap_eff = caps
            .lines()
            .find(|l| l.starts_with("CapEff:"))
            .unwrap_or("CapEff: ?");
        let addrs: Vec<String> = half.loopback.iter().map(|l| l.addr.to_string()).collect();
        tracer.detail(&format!(
            "construct: euid={euid} {cap_eff} addrs={addrs:?} ns=host-add"
        ));
    }
    add_loopback_via_helper(&half.loopback, half.ctx)?;
    if !egress_bytes.is_empty() {
        tracer.step(&format!(
            "construct: attaching egress BPF ({} bytes) via privhelper-bpf",
            egress_bytes.len()
        ));
        attach_egress_via_helper(&half.cgroup, egress_bytes)?;
    }

    // 1a-bis. Verify the binder filesystem is registered BEFORE the construction child tries to
    //     mount its per-kennel binderfs instance — the child mounts in an unprivileged userns and
    //     the factory carries no CAP_SYS_MODULE, so neither can load the module. It is loaded at
    //     install and on boot (`/etc/modules-load.d/kennel.conf`); if it is genuinely absent, fail
    //     fast with a clear message rather than a cryptic in-child `mount` ENODEV.
    check_binderfs()?;

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

    // The view-built handshake pipe (§2.7): the child signals after `build_kennel` (the source
    // binds are done and it has `pivot_root`ed away from the source), so the parent can over-mount
    // the exclusive sources operator-side *after* the kennel captured the real inode — the shadow
    // then cannot reach the kennel's view. Only used when there are exclusive binds.
    let (built_r, built_w) = pipe_cloexec()?;

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

    // 3. Clone the construction child with the new user namespace **owned by the operator**.
    //    `CLONE_NEWUSER` records the creating process's *effective* uid as the namespace owner,
    //    and the owner is what grants `CAP_SYS_PTRACE` in that userns to a process of the same
    //    uid — so the operator `kenneld` can open the kennel's binderfs (an `FS_USERNS_MOUNT`
    //    whose `s_user_ns` is this userns) via `/proc/<init>/root`. A root-owned userns denies
    //    the operator that access (the `/proc/<init>/root` EACCES under Yama `ptrace_scope=1`).
    //    The factory therefore drops its *effective* uid to the operator across the clone, then
    //    restores euid 0 to write the maps. The child still gets full capabilities in the new
    //    userns (a `CLONE_NEWUSER` child always does), so it self-escalates to the kennel's uid 0
    //    for the root-owned construction (below).
    let granted = half.granted_gids.clone();
    let namespaces = half.namespaces; // captured before `half` moves into the child
                                      // The host sources of the exclusive binds (§2.7), captured before `half` moves into the child;
                                      // the parent over-mounts them once the child signals its view is built (below).
    let exclusive_sources: Vec<std::path::PathBuf> =
        half.view.as_ref().map_or_else(Vec::new, |v| {
            v.binds
                .iter()
                .filter(|b| b.exclusive)
                .map(|b| b.source.clone())
                .collect()
        });
    // Captured before the child closure moves `half`: the cgroup to birth the child into.
    let cgroup_path = half.cgroup_join.then(|| half.cgroup.clone());
    // The child's inherited copy of the maps-ack pipe **write** end (`clone` copies the fd table).
    // The child closes it first thing so its `recv_ack` below sees EOF — not a forever block — if the
    // parent dies before `send_ack` (a `uid_map`-write `EPERM` is the motivating case): fail fast
    // rather than hang to the service-stop SIGKILL. A `RawFd` is `Copy`, so this does not move the
    // parent's `ready_w` `OwnedFd` into the closure (the parent still `send_ack`s on it below).
    let child_ready_w = ready_w.as_raw_fd();
    let child = move || {
        // Each early return trips clone_pid1's `_exit(127)` backstop. Name the failing step on
        // stderr first (inherited from the factory, so it reaches kenneld's journal): a silent
        // 127 at this boundary is undebuggable, and the construction child has no other channel.
        // Drop the inherited write end so a dead parent yields EOF (fail-fast), then wait until the
        // parent has written our identity maps (so the kennel's uid 0 is mappable); abort closed otherwise.
        let _ = kennel_lib_syscall::fd::close_inherited(child_ready_w);
        tracer.step("construct: child cloned, awaiting maps-ready ack from parent");
        if recv_ack(ready_r.as_fd()).ok().flatten() != Some(ACK_PROCEED) {
            eprintln!("kennel-privhelper: construction child: maps-ready ack not received");
            return;
        }
        // Become the kennel's uid 0 (inside-0 = host root via the `0 0 1` map line) using the
        // userns capabilities the clone granted, so the view/dev/binderfs are root-owned.
        if let Err(e) = kennel_lib_syscall::unistd::set_gid(0) {
            eprintln!("kennel-privhelper: construction child: setgid(0) in userns: {e}");
            return;
        }
        if let Err(e) = kennel_lib_syscall::unistd::set_uid(0) {
            eprintln!("kennel-privhelper: construction child: setuid(0) in userns: {e}");
            return;
        }
        tracer.step("construct: child is kennel uid 0; building view/binderfs");
        // All privileged construction runs here, as the kennel's uid 0, BEFORE the hand-off
        // — so the surfaces are root-owned and no operator code runs as userns-0. A failure
        // returns, tripping the _exit(127) backstop (no half-built kennel runs the workload).
        if let Err(e) = build_kennel(&half, op_uid, op_gid) {
            eprintln!("kennel-privhelper: construction child: build_kennel: {e}");
            return;
        }
        // Signal the parent that the view is built and `pivot_root`ed: the source path is now
        // detached from this view, so the parent may over-mount it operator-side (§2.7). Sent
        // before the `fexecve` (which would CLOEXEC `built_w`); best-effort.
        let _ = send_ack(built_w.as_fd(), ACK_PROCEED);
        tracer.step("construct: view built; placing handoff fds + fexecve kennel-bin-init");
        // Place the descriptors `kennel-bin-init` inherits at fixed numbers (`BOOT_SYNC_FD`,
        // `PTY_RETURN_FD` for an interactive run, and `WORKLOAD_FD` for a sha256-pinned
        // workload), returning the init-binary fd to exec.
        let pty_ref = pty_fd.as_ref().map(AsFd::as_fd);
        let workload_ref = workload_fd.as_ref().map(AsFd::as_fd);
        let stdio_ref = stdio_fds
            .as_ref()
            .map(|[i, o, e]| [i.as_fd(), o.as_fd(), e.as_fd()]);
        let init_file = match place_handoff_fds(
            init_file.as_fd(),
            init_sync.as_fd(),
            pty_ref,
            workload_ref,
            stdio_ref,
        ) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("kennel-privhelper: construction child: place_handoff_fds: {e}");
                return;
            }
        };
        // Hand off to the trusted `kennel-bin-init` (resolved from root-owned config, not the
        // wire) **as the kennel's uid 0** (no drop): PID 1 must NOT share the operator uid, or
        // the operator-uid workload/facades could signal or ptrace it (07-2 §7.2.5).
        // `kennel-bin-init` itself drops the workload and facades to the operator. kenneld still
        // reaches `/proc/<init>/root` because the kennel userns is operator-owned, so the
        // operator kenneld holds CAP_SYS_PTRACE in it. Empty argv/envp (the pull model).
        let err = fexecve(init_file.as_fd(), &[], &[]);
        // fexecve returned ⇒ failure; name it, then fall through to the _exit(127) backstop.
        eprintln!("kennel-privhelper: construction child: fexecve kennel-bin-init: {err}");
    };
    // Open the kennel's cgroup (operator-owned, in kenneld's delegated subtree) so the child is
    // BORN in it via `clone3(CLONE_INTO_CGROUP)` — skipping the ~10–14 ms `cgroup.procs` migration
    // (a `cgroup_threadgroup_rwsem` RCU-grace-period wait), the dominant bring-up cost. Opened here
    // as root, before the euid drop; the fd outlives it and is CLOEXEC'd at the child's `fexecve`.
    let cgroup_dir = cgroup_path
        .as_deref()
        .map(|p| {
            std::fs::File::open(p)
                .map_err(|e| io::Error::new(e.kind(), format!("open cgroup {}: {e}", p.display())))
        })
        .transpose()?;
    // Drop the *effective* uid to the operator so the clone's `CLONE_NEWUSER` records the
    // operator as the userns owner (see step 3); real/saved stay (operator, 0) so the parent
    // restores euid 0 below to write the maps. A no-op when the operator already is root.
    if op_uid != 0 {
        kennel_lib_syscall::unistd::set_euid(op_uid)
            .map_err(|e| io::Error::new(e.kind(), format!("factory seteuid({op_uid}): {e}")))?;
    }
    let init_pid = match &cgroup_dir {
        Some(dir) => clone_pid1_in_cgroup(namespaces, dir.as_fd(), child)?,
        None => clone_pid1(namespaces, child)?,
    };
    tracer.step(&format!(
        "construct: cloned PID 1 (host pid {init_pid}); writing identity maps"
    ));

    // 4. Restore the parent's **effective** uid to 0 (undo the pre-clone operator drop) before the
    //    map write: the `/proc/<pid>/uid_map` file is owned by global root (the factory holds file
    //    caps, so its construction child is non-dumpable), so euid 0 is what lets us open it.
    //    Permitted via `CAP_SETUID` under the setcap factory (and via the saved uid 0 under the
    //    setuid-root fallback). The userns owner is already fixed (operator) at the clone.
    if op_uid != 0 {
        kennel_lib_syscall::unistd::set_euid(0)
            .map_err(|e| io::Error::new(e.kind(), format!("factory seteuid(0): {e}")))?;
    }

    // Escalate the parent to uid 0 ONLY to write the child's identity maps. The kernel's `uid_map`
    //    write gate requires `CAP_SYS_ADMIN` over the new user namespace (checked against the
    //    opener's creds) — satisfied here by the factory's `cap_sys_admin` at euid 0; and the line
    //    mapping host uid 0 (`0 0 1`) additionally requires `CAP_SETFCAP` (Linux 5.12+). This does
    //    not change the userns owner (fixed at clone above). Then release the child and report the
    //    init host pid to kenneld.
    kennel_lib_syscall::unistd::set_gid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setgid(0): {e}")))?;
    kennel_lib_syscall::unistd::set_uid(0)
        .map_err(|e| io::Error::new(e.kind(), format!("factory setuid(0): {e}")))?;
    write_identity_maps(init_pid, op_uid, op_gid, &granted)?;

    // "build": maps are written, so the child may become uid 0, construct the binderfs, build its
    // view, and `fexecve` `kennel-bin-init`. We still hold root — the exclusive over-mount below
    // needs it — so the drop to the operator happens *after*, not here.
    tracer.step("construct: identity maps written; releasing child to build + fexecve");
    send_ack(ready_w.as_fd(), ACK_PROCEED)?;
    drop(ready_w);

    // Drop straight back to the operator now that the maps are written: the parent escalated ONLY
    // for the map write. setgid before setuid (the uid drop to a non-zero value is what clears the
    // capability sets — capabilities(7)); for its brief remaining life (the exclusive over-mount,
    // then report the pid and exit) the factory parent is the unprivileged operator, never a
    // long-lived host-root process (sec review: minimise the privileged window). A no-op when the
    // operator is root (the root-test case, op_uid == 0).
    kennel_lib_syscall::unistd::set_gid(op_gid)
        .map_err(|e| io::Error::new(e.kind(), format!("factory drop setgid({op_gid}): {e}")))?;
    kennel_lib_syscall::unistd::set_uid(op_uid)
        .map_err(|e| io::Error::new(e.kind(), format!("factory drop setuid({op_uid}): {e}")))?;

    // Over-mount the opaque sentinel on each exclusive bind's host source (§2.7), AFTER the child
    // signals its view is built and `pivot_root`ed away from the source: the kennel's bind is then
    // a snapshot independent of this shadow, so only the operator side is shadowed. Delegated to the
    // `{sys_admin}` kennel-privhelper-mounts sub-helper — the common factory holds no
    // `CAP_SYS_ADMIN` — and run *after* the drop to the operator, so the helper inherits the
    // operator's real uid for its allocation gate and its owner check. Best-effort per path: a
    // failure degrades that path to a plain writable bind (always permitted), logged, never fatal.
    if !exclusive_sources.is_empty() {
        let _ = recv_ack(built_r.as_fd()); // proceed even if the child died (the mount then refuses)
        for src in &exclusive_sources {
            over_mount_exclusive_via_helper(src);
        }
    }
    drop(built_r);

    // Report the init pid AND hand kenneld the boot-sync socket as the sole SCM fd: kenneld waits
    // on it for `kennel-bin-init`'s post-exec "ready", claims node 0 (now reachable via
    // /proc/<pid>/root), and signals "go". With that off our hands, the factory's job is done.
    send_with_raw_fds(chan, &init_pid.to_le_bytes(), &[daemon_sync.as_raw_fd()])?;
    tracer.step(&format!(
        "construct: reported init pid {init_pid} + boot-sync socket to kenneld; factory done"
    ));

    // 5. Done. The factory's whole job was to build the kennel, write the maps, and report the init
    //    pid (plus the boot-sync socket) — `kennel-bin-init` is now PID 1 of the new namespace and an
    //    autonomous daemon, so there is nothing left for this process to do. It exits immediately
    //    rather than lingering as a reaper proxy: `kennel-bin-init` outlives it (a PID namespace is
    //    tied to its own PID 1, not to the cloner), and kenneld — a `set_child_subreaper` — adopts
    //    the orphaned init and `waitpid`s it directly for the workload's exit status. One
    //    fewer resident host process per kennel.
    Ok(0)
}

/// Ensure the `binder` filesystem type is registered, loading `binder_linux` if not.
///
/// binderfs (`FS_USERNS_MOUNT`) is what every kennel mounts for its per-kennel bus. The
/// `binder_linux` module is loaded at install and on every boot (`/etc/modules-load.d/kennel.conf`);
/// neither the factory (no `CAP_SYS_MODULE`) nor the construction child (an unprivileged userns) can
/// load it. If it is genuinely absent, fail fast here with a clear message rather than let the
/// child's binderfs `mount` fail with a cryptic `ENODEV`. A host with binder built-in lists it too.
fn check_binderfs() -> io::Result<()> {
    if binderfs_registered() {
        return Ok(());
    }
    Err(io::Error::other(
        "binder filesystem not registered: load the `binder_linux` module \
         (install.sh loads it and writes /etc/modules-load.d/kennel.conf for boot)",
    ))
}

/// Whether the kernel has registered the `binder` filesystem (read `/proc/filesystems`).
fn binderfs_registered() -> bool {
    std::fs::read_to_string("/proc/filesystems").is_ok_and(|s| {
        s.lines()
            .any(|l| l.split_whitespace().any(|f| f == "binder"))
    })
}

/// Place the descriptors `kennel-bin-init` inherits at the fixed numbers it reads — the boot-sync
/// socket at [`BOOT_SYNC_FD`] and (interactive) the pty return socket at [`PTY_RETURN_FD`] —
/// returning the init-binary fd to `fexecve`.
///
/// Every descriptor we still need (the init binary, the boot-sync socket, the pty socket) is
/// first lifted ABOVE the target range with [`kennel_lib_syscall::fd::dup_above`], so `dup2`-ing onto the low fixed
/// numbers cannot clobber one of them — their natural fd numbers depend on what else is open and
/// could otherwise land on a target (the bug an interactive run, with its extra pty fd, exposed).
/// `dup_above` keeps close-on-exec; [`dup_onto`] clears it on the fixed targets so they survive
/// the `fexecve`; the relocated copies (still cloexec) close across it.
fn place_handoff_fds(
    init_file: BorrowedFd<'_>,
    init_sync: BorrowedFd<'_>,
    pty_fd: Option<BorrowedFd<'_>>,
    workload_fd: Option<BorrowedFd<'_>>,
    stdio_fds: Option<[BorrowedFd<'_>; 3]>,
) -> io::Result<OwnedFd> {
    use kennel_lib_syscall::boot::{
        INJECT_STDERR_FD, INJECT_STDIN_FD, INJECT_STDOUT_FD, WORKLOAD_FD,
    };
    use kennel_lib_syscall::fd::dup_above;
    // Lift every fd we still need ABOVE the fixed target range first, so `dup2`-ing onto the
    // low fixed numbers cannot clobber one of them. The range spans BOOT_SYNC_FD, PTY_RETURN_FD,
    // WORKLOAD_FD, and the three INJECT_STD* slots.
    let base = [
        PTY_RETURN_FD,
        BOOT_SYNC_FD,
        WORKLOAD_FD,
        INJECT_STDIN_FD,
        INJECT_STDOUT_FD,
        INJECT_STDERR_FD,
    ]
    .into_iter()
    .max()
    .unwrap_or(BOOT_SYNC_FD)
    .saturating_add(1);
    let init_file = dup_above(init_file, base)?;
    let init_sync = dup_above(init_sync, base)?;
    let pty_hi = pty_fd.map(|p| dup_above(p, base)).transpose()?;
    let workload_hi = workload_fd.map(|w| dup_above(w, base)).transpose()?;
    let stdio_hi = stdio_fds
        .map(|[i, o, e]| -> io::Result<[OwnedFd; 3]> {
            Ok([
                dup_above(i, base)?,
                dup_above(o, base)?,
                dup_above(e, base)?,
            ])
        })
        .transpose()?;
    dup_onto(init_sync.as_fd(), BOOT_SYNC_FD)?;
    if let Some(pty) = &pty_hi {
        dup_onto(pty.as_fd(), PTY_RETURN_FD)?;
    }
    if let Some(workload) = &workload_hi {
        dup_onto(workload.as_fd(), WORKLOAD_FD)?;
    }
    if let Some([i, o, e]) = &stdio_hi {
        dup_onto(i.as_fd(), INJECT_STDIN_FD)?;
        dup_onto(o.as_fd(), INJECT_STDOUT_FD)?;
        dup_onto(e.as_fd(), INJECT_STDERR_FD)?;
    }
    Ok(init_file)
}

/// Pop the three injected-stdio fds from the received SCM fds when `present`, preserving order
/// (stdin, stdout, stderr). A flag set but fewer than three fds is a malformed datagram.
fn pop_stdio_fds(fds: &mut Vec<OwnedFd>, present: bool) -> io::Result<Option<[OwnedFd; 3]>> {
    if !present {
        return Ok(None);
    }
    let mut next = || -> io::Result<OwnedFd> {
        if fds.is_empty() {
            return Err(io::Error::other(
                "stdio_present set but an injected-stdio fd is missing",
            ));
        }
        Ok(fds.remove(0))
    };
    Ok(Some([next()?, next()?, next()?]))
}

/// Add each host-`lo` mirror address by exec'ing the `{net_admin}` `kennel-privhelper-net`
/// sub-helper — the common factory holds **no** `CAP_NET_ADMIN` of its own, so the one
/// construction step that touches the host network is delegated to a binary that carries that
/// single capability. The sub-helper re-loads the caller's reserved scope and re-validates each
/// address against the per-kennel subnet before the netlink op (the factory does not trust the
/// operator-supplied addresses; the gate moves with the privilege). One exec per address; an
/// empty list — the common no-bind case (100% of ephemeral spawns) — execs nothing, so the
/// network helper is never even invoked.
fn add_loopback_via_helper(addrs: &[LoopbackAddr], ctx: u16) -> io::Result<()> {
    if addrs.is_empty() {
        return Ok(());
    }
    let net_helper = kennel_lib_config::Deployment::load()
        .map_err(|e| io::Error::other(format!("resolve kennel-privhelper-net: {e}")))?
        .privhelper_net();
    for lb in addrs {
        let status = std::process::Command::new(&net_helper)
            .args([
                "add",
                &ctx.to_string(),
                &lb.addr.to_string(),
                &lb.prefix.to_string(),
            ])
            .status()
            .map_err(|e| io::Error::new(e.kind(), format!("exec {}: {e}", net_helper.display())))?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "kennel-privhelper-net add {}/{} on lo failed ({status})",
                lb.addr, lb.prefix
            )));
        }
    }
    Ok(())
}

/// Attach the per-kennel egress BPF by exec'ing the `{bpf,net_admin,perfmon}`
/// `kennel-privhelper-bpf` sub-helper — the common factory holds **no** `CAP_BPF` of its own.
/// Reached only for `net.mode = host` (a non-empty egress payload); the cgroup path rides argv
/// and the payload (the allow/deny ruleset) rides stdin. The sub-helper re-checks that the caller
/// owns the target cgroup before the attach (the delegation boundary moves with the privilege).
fn attach_egress_via_helper(cgroup: &std::path::Path, egress_bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    // Mount the per-user bpffs the sub-helper pins the maps into. Only the *mount* needs
    // `CAP_SYS_ADMIN` (which the factory holds and the bpf sub-helper does not), so the factory
    // does it here — in the host mount namespace `kenneld` shares — before delegating; the
    // sub-helper (`CAP_BPF`) then creates the per-kennel pin dir and pins into it.
    ensure_bpf_pin_bpffs();
    let bpf_helper = kennel_lib_config::Deployment::load()
        .map_err(|e| io::Error::other(format!("resolve kennel-privhelper-bpf: {e}")))?
        .privhelper_bpf();
    // stdout/stderr are inherited from the factory (itself inherited from kenneld), so the
    // sub-helper's per-step `eprintln` cause lands in the same journal — the net/mounts
    // sub-helpers report the same way. stdin is piped to carry the egress payload.
    let mut child = std::process::Command::new(&bpf_helper)
        .arg("attach")
        .arg(cgroup)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("exec {}: {e}", bpf_helper.display())))?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("kennel-privhelper-bpf stdin missing"))?
        .write_all(egress_bytes)?;
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "kennel-privhelper-bpf attach failed ({status})"
        )));
    }
    Ok(())
}

/// Mount the per-user bpffs at [`crate::bpf_pin_root`] that the egress sub-helper pins into.
///
/// The bpffs *mount* is the one egress step that needs `CAP_SYS_ADMIN`; the factory holds it
/// (the bpf sub-helper does not), and mounts here in the host mount namespace so `kenneld` can
/// `BPF_OBJ_GET` the pinned `audit_ringbuf` to drain it. Idempotent — one bpffs per user serves
/// all their kennels; the per-kennel pin dir and the pins are created operator-side by the
/// sub-helper. Best-effort: a mount failure degrades to "no audit drain", never fatal.
fn ensure_bpf_pin_bpffs() {
    let base = crate::bpf_pin_root(real_uid());
    if std::fs::create_dir_all(&base).is_err() {
        return;
    }
    if !kennel_lib_syscall::mount::is_bpffs(&base).unwrap_or(false) {
        let _ = kennel_lib_syscall::mount::mount_bpffs(&base);
    }
}

/// Over-mount the exclusive-bind sentinel on `src` by exec'ing the `{sys_admin}`
/// `kennel-privhelper-mounts` sub-helper — the common factory holds **no** `CAP_SYS_ADMIN` of
/// its own. Best-effort: a failure (including an unresolvable helper) leaves the path a plain
/// writable bind, logged, never fatal — so the construction never fails on the over-mount.
fn over_mount_exclusive_via_helper(src: &std::path::Path) {
    let helper = match kennel_lib_config::Deployment::load() {
        Ok(d) => d.privhelper_mounts(),
        Err(e) => {
            eprintln!("kennel-privhelper: resolve kennel-privhelper-mounts: {e}");
            return;
        }
    };
    let ok = std::process::Command::new(&helper)
        .arg("mount")
        .arg(src)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!(
            "kennel-privhelper: exclusive bind not enforced for {}",
            src.display()
        );
    }
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

    // The kennel cgroup is joined at birth (`clone3(CLONE_INTO_CGROUP)` in `construct`), not here —
    // a post-clone `cgroup.procs` migration is the dominant bring-up cost (an RCU-grace-period wait).
    // In-namespace loopback (§7.5.6): a proxied kennel runs in its OWN net-ns (`half.lo` is set
    // only when the plan unshared NEWNET and the kennel has addresses — i.e. constrained/
    // unconstrained; `none` has no addresses, `host` shares the host stack). A fresh net-ns
    // starts with `lo` DOWN and no addresses, so bring it up and add the kennel's own addresses
    // here — these are the copy the WORKLOAD sees (the host-side add in step 1a is the operator-
    // visible mirror on the other side of the boundary). The construction child holds
    // CAP_NET_ADMIN over its own new userns+netns, so this is unprivileged; the addresses were
    // re-validated against the caller's reserved scope before the host add above.
    if half.lo {
        let cname = std::ffi::CString::new(LOOPBACK).map_err(|_| io::Error::other("bad ifname"))?;
        let lo = kennel_lib_syscall::netlink::if_index(&cname)?;
        kennel_lib_syscall::netlink::set_link_up(lo)?;
        for lb in &half.loopback {
            kennel_lib_syscall::netlink::add_address(lo, lb.addr, lb.prefix)?;
        }
    }

    // Detach mount propagation from the host before any mount in either path.
    mount::make_root_private()
        .map_err(|e| io::Error::new(e.kind(), format!("make_root_private: {e}")))?;
    if let (Some(view), Some(new_root)) = (&half.view, &half.new_root) {
        // Build + pivot into the constructed view.
        build_view_and_pivot(view, new_root, &half.file_binds)
            .map_err(|e| io::Error::new(e.kind(), format!("build_view_and_pivot: {e}")))?;
        // The constructed $HOME is the WORKLOAD's private space (the home dir on the view-root
        // tmpfs plus the copied dotfiles / synthetic ~/.ssh). The construction child built it
        // as the kennel's uid 0, so it is root-owned — but the workload, the af-unix proxy,
        // and any in-kennel tool run as the OPERATOR and must read (0600 ~/.ssh keys) and
        // write (bind sockets) there. Hand the operator only the inodes we constructed.
        chown_constructed_home(&view.shim_root, op_uid, op_gid)?;
        // Hand the constructed /tmp to the operator. It is the workload's private scratch — a
        // fresh tmpfs the construction child built as the kennel's uid 0 — but the workload runs
        // as the OPERATOR, so without this the persona cannot write it (mktemp, build scratch, even
        // `touch` all EACCES despite the Landlock /tmp grant; the grant is necessary, not
        // sufficient, against DAC). Chown the tmpfs root only — it is empty here — so the mode
        // (0700) stands and /tmp is the persona's own tmp, owned by the workload user.
        // (A view always mounts /tmp; with `fs.tmp.writable = false` there is simply no Landlock
        // grant, so this chown is inert there.)
        kennel_lib_syscall::unistd::chown_to(std::path::Path::new("/tmp"), op_uid, op_gid)?;
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
/// The discriminator is the **home's own device** plus ownership: the constructed home and its
/// contents share `$HOME`'s device (the view-root tmpfs for a constructed view, or the dedicated
/// `/home` tmpfs for an OCI overlay root — the merged overlay's `/` has a *different* device, so
/// `/` is the wrong reference there); every writable bind / special mount under it has a different
/// device and is skipped. If `$HOME` *itself* is a writable whole-home bind it already resolves to
/// the operator's own (operator-owned) inode — not ours to touch — so we skip when the home root is
/// already operator-owned. Symlinks are skipped entirely (ownership is irrelevant and it avoids any
/// follow), so no `lchown` dance is needed.
fn chown_constructed_home(shim_root: &std::path::Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(home) = std::fs::symlink_metadata(shim_root) else {
        return Ok(()); // no constructed home (e.g. the fallback path)
    };
    // A whole-home bind resolves to the operator's own inode (already operator-owned); a symlink
    // is not ours to chown. The constructed home is built by the kennel's uid 0 (root-owned).
    if home.file_type().is_symlink() || home.uid() == uid {
        return Ok(());
    }
    // Only inodes on the home's own mount are constructed; sub-mounts (writable binds) differ.
    let home_dev = home.dev();
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
            // (a writable bind / special fs) — chown only constructed home-mount inodes.
            if meta.file_type().is_symlink() || meta.dev() != home_dev {
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
/// Writing requires `CAP_SYS_ADMIN` over the new namespace (the kernel's map-write gate) plus
/// `CAP_SETUID`/`CAP_SETGID`, and `CAP_SETFCAP` for the host-uid-0 line; `setgroups` is left
/// enabled (not denied) because `kennel-bin-init` needs it for the workload's supplementary-group
/// drop.
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
/// does) and the writer holds `CAP_SYS_ADMIN` over the namespace plus `CAP_SETFCAP` (Linux
/// 5.12+) — so the kennel never maps the unrelated host system uids between 0 and the operator. The operator line is omitted when
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
