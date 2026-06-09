//! Linux namespace operations.
//!
//! Safe wrappers (over nix) for `unshare(2)`, the first step of the spawn
//! sequence (`docs/design/08` §spawn). The flag set is our own [`Namespaces`] type
//! rather than a re-export, so the rest of the workspace depends on this curated
//! API and not on nix's `CloneFlags` directly. No `unsafe` of ours.

use std::io;

use bitflags::bitflags;
use nix::sched::CloneFlags;

bitflags! {
    /// The namespaces the spawn sequence may unshare. Each maps to a `CLONE_NEW*`
    /// flag; the numeric values here are our own (translated in [`to_clone_flags`]),
    /// not the kernel constants.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Namespaces: u32 {
        /// Mount namespace (`CLONE_NEWNS`).
        const MOUNT = 1 << 0;
        /// PID namespace (`CLONE_NEWPID`); only children enter the new namespace.
        const PID = 1 << 1;
        /// System V IPC namespace (`CLONE_NEWIPC`).
        const IPC = 1 << 2;
        /// Network namespace (`CLONE_NEWNET`).
        const NET = 1 << 3;
        /// User namespace (`CLONE_NEWUSER`).
        const USER = 1 << 4;
        /// UTS (hostname) namespace (`CLONE_NEWUTS`).
        const UTS = 1 << 5;
        /// Cgroup namespace (`CLONE_NEWCGROUP`).
        const CGROUP = 1 << 6;
    }
}

/// Translate our [`Namespaces`] set to nix's `CloneFlags`.
fn to_clone_flags(ns: Namespaces) -> CloneFlags {
    let mut f = CloneFlags::empty();
    f.set(CloneFlags::CLONE_NEWNS, ns.contains(Namespaces::MOUNT));
    f.set(CloneFlags::CLONE_NEWPID, ns.contains(Namespaces::PID));
    f.set(CloneFlags::CLONE_NEWIPC, ns.contains(Namespaces::IPC));
    f.set(CloneFlags::CLONE_NEWNET, ns.contains(Namespaces::NET));
    f.set(CloneFlags::CLONE_NEWUSER, ns.contains(Namespaces::USER));
    f.set(CloneFlags::CLONE_NEWUTS, ns.contains(Namespaces::UTS));
    f.set(CloneFlags::CLONE_NEWCGROUP, ns.contains(Namespaces::CGROUP));
    f
}

/// Disassociate parts of the calling process's execution context, creating new
/// namespaces (`unshare(2)`).
///
/// Note the kernel semantics: a new PID namespace takes effect only for
/// *children* forked afterwards, not the caller; the others affect the caller
/// immediately. Most namespaces require `CAP_SYS_ADMIN` (in the current user
/// namespace); `USER` does not, and unsharing it first is the usual way an
/// unprivileged caller gains the capability for the rest.
///
/// # Errors
///
/// Returns the OS error if the unshare is not permitted (`EPERM`) or a flag is
/// unsupported.
pub fn unshare(ns: Namespaces) -> io::Result<()> {
    nix::sched::unshare(to_clone_flags(ns)).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// `clone(2)` a child that is **PID 1** of a fresh PID namespace, entering all of
/// `ns` in a single syscall, and run `child` in it.
///
/// This is the privhelper-factory's construction primitive (`docs/design/07-2`):
/// where the old unprivileged path did `unshare(CLONE_NEWUSER)` then a later
/// [`fork_into_pid1`](crate::spawn::fork_into_pid1) double-fork to reach PID 1, the
/// factory instead `clone`s once with `NEWUSER|NEWNS|NEWPID|NEWIPC[|NEWNET]`: the
/// cloned child is itself PID 1 of the new PID namespace (a `clone(CLONE_NEWPID)`
/// child *is* the namespace init, unlike the `unshare` caller, which is not), so no
/// second fork is needed. The parent gets the child's **host** pid back — the fact
/// kenneld needs to gate the binder lifecycle verbs and to open
/// `/proc/<pid>/root/dev/binderfs/binder`.
///
/// # The map-write handshake (caller's responsibility)
///
/// With `CLONE_NEWUSER`, the child starts with **no** uid/gid mapping and therefore
/// **no** capabilities in the new user namespace until the parent writes
/// `/proc/<pid>/uid_map` and `gid_map`. So `child` MUST block (e.g. read a pipe)
/// until the parent signals the maps are written before it attempts any privileged
/// operation. This primitive does not impose that handshake — it only creates the
/// process; the construction closure wires the synchronisation.
///
/// # The child closure
///
/// `child` runs in the cloned process and **must not return** — it either
/// `execve`s/`fexecve`s the next image or `_exit`s. It is the same constrained
/// post-`clone` environment as a `pre_exec` hook — single-threaded, address space
/// shared copy-on-write with the parent — so it must keep to async-signal-safe work
/// (and the syscalls the construction sequence needs) and not unwind into the
/// parent's `Drop`/atexit glue. The contract cannot be expressed in the type on
/// stable Rust (the never type is unstable in a trait bound), so a closure that
/// does return is treated as a construction bug: the child is terminated `_exit(127)`
/// fail-closed rather than ever continuing as a second copy of the parent.
///
/// # Errors
///
/// Returns the OS error if `clone` fails (e.g. `EPERM` where the host forbids the
/// requested namespaces). On success the parent returns `Ok(child_pid)`; the child
/// never returns to the caller.
pub fn clone_pid1<F>(ns: Namespaces, child: F) -> io::Result<libc::pid_t>
where
    F: FnOnce(),
{
    // The clone flags: the namespace set plus SIGCHLD as the termination signal, so
    // the parent can `waitpid` the child (fork() implies SIGCHLD; raw clone does not).
    // The flag bits and SIGCHLD are kernel constants known non-negative, so
    // `unsigned_abs` reproduces their exact bit value and `u64::from` widens totally —
    // no cast, no panic path.
    let flags: u64 =
        u64::from(to_clone_flags(ns).bits().unsigned_abs()) | u64::from(libc::SIGCHLD.unsigned_abs());
    // SAFETY: a raw `clone` syscall with a NULL child stack and all-zero
    // parent_tid/child_tid/tls behaves like `fork()` — the child returns 0 on a
    // copy-on-write copy of the caller's stack, the parent gets the child pid. Passing
    // zero for every pointer argument makes the call robust to the per-arch ordering of
    // clone's stack/tid/tls operands (only their values, all zero, would differ). The
    // child branch runs the caller's closure under the same post-fork discipline as a
    // pre_exec hook (module docs / spawn.rs) and then `_exit`s — it never returns into
    // safe parent code.
    //
    // INVARIANTS UPHELD: exactly one child is created; the parent's only side effect is
    // obtaining the pid.
    //
    // FAILURE MODE: a clone failure surfaces as Err (no child exists); a child closure
    // that wrongly returns is terminated _exit(127) rather than continuing.
    let ret = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    match ret {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            child();
            // The closure must have execed or _exited; if it returned, fail closed.
            // SAFETY: _exit ends the child without unwinding the parent's shared state.
            unsafe { libc::_exit(127) }
        }
        // A clone-returned pid is a real, small process id and always fits in pid_t.
        pid => libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("clone returned an out-of-range pid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_map_to_the_right_clone_bits() {
        assert_eq!(to_clone_flags(Namespaces::empty()), CloneFlags::empty());
        assert_eq!(to_clone_flags(Namespaces::MOUNT), CloneFlags::CLONE_NEWNS);
        assert_eq!(to_clone_flags(Namespaces::PID), CloneFlags::CLONE_NEWPID);
        assert_eq!(to_clone_flags(Namespaces::IPC), CloneFlags::CLONE_NEWIPC);
        assert_eq!(to_clone_flags(Namespaces::NET), CloneFlags::CLONE_NEWNET);
        assert_eq!(to_clone_flags(Namespaces::USER), CloneFlags::CLONE_NEWUSER);
        assert_eq!(to_clone_flags(Namespaces::UTS), CloneFlags::CLONE_NEWUTS);
        assert_eq!(
            to_clone_flags(Namespaces::CGROUP),
            CloneFlags::CLONE_NEWCGROUP
        );
        // a combination
        assert_eq!(
            to_clone_flags(Namespaces::MOUNT | Namespaces::IPC),
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC
        );
    }

    #[test]
    fn unshare_of_nothing_succeeds() {
        // unshare(0) is a no-op the kernel accepts unprivileged: validates the
        // call path without needing any capability.
        unshare(Namespaces::empty()).expect("no-op unshare");
    }

    /// **The foundational premise:** a normal user builds a mount namespace by first
    /// establishing an identity-mapped user namespace — without the userns,
    /// `unshare(MOUNT)` is `EPERM` for an unprivileged caller; with it, it succeeds,
    /// which is how an unprivileged `kenneld` constructs the sandbox.
    ///
    /// The host must **permit** unprivileged user namespaces *with capabilities*. Two
    /// host policies break this, and the test reports each precisely instead of a
    /// blanket pass:
    /// * `kernel.unprivileged_userns_clone=0` / `user.max_user_namespaces=0` — the
    ///   `unshare(CLONE_NEWUSER)` itself is refused.
    /// * `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10+/24.04
    ///   default) — the unshare *succeeds* but the process holds **no capabilities**
    ///   in the new userns, so the first `/proc/self/setgroups`/map write is `EACCES`.
    ///   Production needs an `AppArmor` profile granting `userns` to the kenneld binary
    ///   (an install step), or the admin relaxes the sysctl.
    ///
    /// Where the mechanism is unavailable the test **skips with the precise cause**;
    /// it asserts success only where the host actually permits it. A skip is not a
    /// proof — `cargo test` cannot demonstrate the unprivileged spawn on a host that
    /// forbids it.
    #[test]
    fn identity_userns_grants_an_unprivileged_mount_namespace() {
        let uid = crate::unistd::real_uid();
        let gid = crate::unistd::real_gid();
        // SAFETY: fork(); the child only unshares, writes its own /proc maps, and
        // _exit()s — it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                // Distinguish "userns refused outright" (4) from "userns created but
                // capability-stripped — the AppArmor case" (5) from success/mount-fail.
                let code = if unshare(Namespaces::USER).is_err() {
                    4
                } else if std::fs::write("/proc/self/setgroups", "deny").is_err() {
                    5
                } else {
                    let _ = std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"));
                    let _ = std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"));
                    i32::from(unshare(Namespaces::MOUNT | Namespaces::IPC).is_err()) * 2
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                let aa = std::fs::read_to_string(
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                )
                .unwrap_or_default();
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 4) => {
                        eprintln!("SKIP: unprivileged user namespaces are disabled on this host");
                    }
                    nix::sys::wait::WaitStatus::Exited(_, 5) => {
                        eprintln!(
                            "SKIP: userns created but capability-stripped — \
                             kernel.apparmor_restrict_unprivileged_userns={} (needs an \
                             AppArmor profile granting `userns`, or the sysctl relaxed)",
                            aa.trim()
                        );
                    }
                    other => assert!(
                        matches!(other, nix::sys::wait::WaitStatus::Exited(_, 0)),
                        "unprivileged userns→mount-namespace failed (2 = mount EPERM): {other:?}"
                    ),
                }
            }
        }
    }

    /// The deferred-gid variant leaves the `gid_map` empty while still granting the
    /// in-namespace capability: an unprivileged caller establishes the userns
    /// without a `gid_map`, observes `/proc/self/gid_map` empty, and can still
    /// `unshare(MOUNT)` — exactly the window in which the privileged helper writes
    /// the multi-gid map (§7.4.8). Skips with the precise cause where the host
    /// forbids the userns or strips its capabilities (the same two conditions as
    /// [`identity_userns_grants_an_unprivileged_mount_namespace`]).
    #[test]
    fn defer_gid_userns_leaves_the_gid_map_empty_but_grants_the_capability() {
        let uid = crate::unistd::real_uid();
        // SAFETY: fork(); the child only unshares, writes its own /proc maps, reads
        // its own gid_map, and _exit()s — it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if unshare(Namespaces::USER).is_err() {
                    4
                } else if std::fs::write("/proc/self/setgroups", "deny").is_err()
                    || std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).is_err()
                {
                    5
                } else {
                    // gid_map must be empty (deferred), AND the capability present
                    // (mount unshare succeeds). 0 = both hold; 6 = gid_map not empty;
                    // 2 = mount unshare failed despite the userns.
                    let gid_map = std::fs::read_to_string("/proc/self/gid_map").unwrap_or_default();
                    if gid_map.trim().is_empty() {
                        i32::from(unshare(Namespaces::MOUNT | Namespaces::IPC).is_err()) * 2
                    } else {
                        6
                    }
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                let aa = std::fs::read_to_string(
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                )
                .unwrap_or_default();
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 4) => {
                        eprintln!("SKIP: unprivileged user namespaces are disabled on this host");
                    }
                    nix::sys::wait::WaitStatus::Exited(_, 5) => {
                        eprintln!(
                            "SKIP: userns created but capability-stripped — \
                             kernel.apparmor_restrict_unprivileged_userns={} (needs an \
                             AppArmor profile granting `userns`, or the sysctl relaxed)",
                            aa.trim()
                        );
                    }
                    other => assert!(
                        matches!(other, nix::sys::wait::WaitStatus::Exited(_, 0)),
                        "deferred-gid userns failed (6 = gid_map not empty, 2 = mount EPERM): {other:?}"
                    ),
                }
            }
        }
    }

    /// `clone_pid1` with an empty namespace set behaves like `fork()` and needs no
    /// privilege: the child runs the closure and `_exit`s with a code, the parent
    /// receives the child pid and reaps it, observing that exact code. Proves the
    /// fork-like raw-clone path and the pid return without touching any namespace.
    #[test]
    fn clone_pid1_empty_flags_relays_the_child_exit_code() {
        let child = || {
            // SAFETY: _exit ends the child without running Drop/atexit glue (shared
            // copy-on-write with the test harness).
            unsafe { libc::_exit(42) }
        };
        let pid = clone_pid1(Namespaces::empty(), child).expect("clone_pid1");
        let status = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 42)),
            "child should _exit(42): {status:?}"
        );
    }

    /// With privilege, `clone_pid1(PID|USER)` produces a child that is **PID 1** of a
    /// fresh PID namespace in a single syscall — the property the factory relies on to
    /// skip the double fork. The child reports its in-namespace pid via its exit code
    /// (0 ⇒ `getpid()==1`); `getpid` needs no uid mapping, so the still-empty userns
    /// map does not matter here. Gated behind `e2e`.
    #[cfg(feature = "e2e")]
    #[test]
    fn clone_pid1_makes_the_child_pid_namespace_init() {
        if crate::unistd::skip_if_unprivileged("clone_pid1_makes_the_child_pid_namespace_init") {
            return;
        }
        let child = || {
            // SAFETY: getpid()/_exit are async-signal-safe; the child does nothing
            // that needs the (still unwritten) userns maps.
            let me = unsafe { libc::getpid() };
            unsafe { libc::_exit(i32::from(me != 1)) }
        };
        let pid = clone_pid1(Namespaces::PID | Namespaces::USER, child).expect("clone_pid1");
        let status = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
            "cloned child must be PID 1 of its new PID namespace: {status:?}"
        );
    }

    /// With privilege, unsharing the mount namespace gives the caller a private
    /// mount namespace — observable as a changed `/proc/self/ns/mnt` link.
    /// Gated behind `e2e`; run via `sudo -E cargo test --features e2e`.
    #[cfg(feature = "e2e")]
    #[test]
    fn unshare_mount_namespace_changes_the_mount_ns() {
        if crate::unistd::skip_if_unprivileged("unshare_mount_namespace_changes_the_mount_ns") {
            return;
        }
        let before = std::fs::read_link("/proc/self/ns/mnt").expect("read ns link");
        // SAFETY: fork(); the child only unshares, reads a proc link, and _exit()s.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if unshare(Namespaces::MOUNT | Namespaces::IPC).is_err() {
                    1
                } else {
                    match std::fs::read_link("/proc/self/ns/mnt") {
                        Ok(after) if after != before => 0,
                        _ => 2,
                    }
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "child failed (1=unshare err, 2=ns unchanged): {status:?}"
                );
            }
        }
    }
}
