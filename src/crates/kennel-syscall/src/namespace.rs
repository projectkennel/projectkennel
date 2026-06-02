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
