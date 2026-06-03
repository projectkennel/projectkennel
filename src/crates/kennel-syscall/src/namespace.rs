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

/// Establish an identity-mapped **user namespace** for the calling process.
///
/// The unprivileged foundation of the spawn — the bubblewrap-equivalent mechanism
/// (`docs/architecture/01-process-model.md`, `docs/design/08-enforcement-architecture.md`).
/// Unshares `CLONE_NEWUSER` and maps the caller's `uid`/`gid` **1:1** into the new
/// namespace — the real uid is preserved (not subuid; `design/11-open-questions.md`).
/// The caller then holds `CAP_SYS_ADMIN` *within the new namespace*, so it can unshare
/// a mount/IPC namespace and `mount`/`pivot_root` **with no real privilege** — this is
/// what lets an unprivileged `kenneld` build the constructed view without root or
/// sudo. The privhelper stays reserved for the host-global operations a user namespace
/// cannot reach (loopback addresses, cgroup BPF).
///
/// Ordering is load-bearing for an unprivileged user namespace: `setgroups` must be
/// **denied** before `gid_map` is written, then each map is written once. Because
/// `setgroups` is denied, supplementary-group selection is expressed through the
/// `gid_map` (mapped gids retain identity; unmapped ones fall to the overflow gid),
/// **not** a later `setgroups`.
///
/// # Errors
///
/// An OS error if the `CLONE_NEWUSER` unshare is refused (e.g. the distro disables
/// unprivileged user namespaces) or any `/proc/self` map write fails.
pub fn establish_identity_userns(uid: u32, gid: u32) -> io::Result<()> {
    establish_userns_defer_gid_map(uid)?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))?;
    Ok(())
}

/// Establish the identity-mapped user namespace but **leave the `gid_map`
/// unwritten**, for the granted-supplementary-group handshake (§7.2.8).
///
/// Unshares `CLONE_NEWUSER`, denies `setgroups`, and writes the identity `uid_map`
/// — exactly the prefix of [`establish_identity_userns`] — but does **not** write
/// the `gid_map`. After this returns the caller already holds `CAP_SYS_ADMIN`
/// *within* the new namespace (the `uid_map` is what grants it), so it can unshare
/// mount/IPC and `mount`/`pivot_root`; the `gid_map`, however, is still empty.
///
/// This is used when a specific supplementary group is re-granted into the kennel:
/// an unprivileged `gid_map` can map only the caller's own primary gid, so a
/// privileged helper (holding `CAP_SETGID` in the init userns) writes the
/// multi-gid map against this process's pid out of band. The caller MUST complete
/// that write — and so MUST NOT rely on group identity, nor fork the workload —
/// before the helper has written the map (the workload would otherwise see every
/// group, primary included, fall to the overflow gid). The single-line default
/// (drop every supplementary group to the overflow gid, for free) is the
/// `gid`-writing [`establish_identity_userns`] instead.
///
/// # Errors
///
/// An OS error if the `CLONE_NEWUSER` unshare is refused (e.g. the distro disables
/// unprivileged user namespaces, or Ubuntu's `AppArmor` restriction strips the
/// capability — the `setgroups`/`uid_map` write then fails `EACCES`).
pub fn establish_userns_defer_gid_map(uid: u32) -> io::Result<()> {
    unshare(Namespaces::USER)?;
    // Unprivileged userns: deny setgroups before writing gid_map (a kernel rule that
    // prevents using a new userns to drop groups for a privilege check).
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))?;
    // gid_map intentionally NOT written here — the privileged helper writes it.
    Ok(())
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
                let aa = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
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
    /// the multi-gid map (§7.2.8). Skips with the precise cause where the host
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
                let aa = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
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

    /// With privilege, unsharing the mount namespace gives the caller a private
    /// mount namespace — observable as a changed `/proc/self/ns/mnt` link.
    /// Gated behind `root-tests`; run via `sudo -E cargo test --features root-tests`.
    #[cfg(feature = "root-tests")]
    #[test]
    fn unshare_mount_namespace_changes_the_mount_ns() {
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
