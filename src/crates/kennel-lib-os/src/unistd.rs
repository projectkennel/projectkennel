// SPDX-License-Identifier: Apache-2.0

//! Process-credential syscalls.
//!
//! # Purpose
//!
//! Thin wrappers exposing the credential calls `std` does not — via nix's safe
//! bindings, so this module (and the crate) needs no `unsafe` of its own. This
//! is the "don't roll your own `unsafe`" principle (CODING-STANDARDS.md §4):
//! where a vetted crate already wraps a syscall soundly, we use it rather than
//! writing the `unsafe` ourselves.
//!
//! # Why it exists
//!
//! Components that must know whether they hold privilege — the privhelper
//! (boundary 1) and the spawn path — need the effective uid, which `std` has no
//! API for. Routing it through one reviewed place keeps the dependency on nix
//! confined to this crate, so the rest of the workspace calls a small safe API.

use std::io;

use nix::unistd::{getegid, geteuid, getgid, getgroups, getuid, setgroups, Gid, Group, Uid};

/// The effective user ID of the calling process (`geteuid(2)`).
#[must_use]
pub fn effective_uid() -> u32 {
    geteuid().as_raw()
}

/// The real user ID of the calling process (`getuid(2)`).
#[must_use]
pub fn real_uid() -> u32 {
    getuid().as_raw()
}

/// The effective group ID of the calling process (`getegid(2)`).
#[must_use]
pub fn effective_gid() -> u32 {
    getegid().as_raw()
}

/// The real group ID of the calling process (`getgid(2)`).
#[must_use]
pub fn real_gid() -> u32 {
    getgid().as_raw()
}

/// Test helper: skip a privilege-requiring test with cause on an unprivileged runner.
///
/// A skip is not a proof, so `cargo test --all-features` stays green for any runner while
/// `sudo … --features e2e` still exercises the test. Shared across the crates' e2e tests, so it
/// is `pub` and feature-gated (not `cfg(test)`) to cross the crate boundary.
#[cfg(feature = "e2e")]
#[must_use]
pub fn skip_if_unprivileged(test: &str) -> bool {
    let euid = effective_uid();
    if euid != 0 {
        eprintln!("skipping {test}: requires root (euid={euid}) for the privileged operation");
        return true;
    }
    false
}

/// The calling process's supplementary group IDs (`getgroups(2)`).
///
/// Used to membership-check a policy's `[identity].groups` before the privileged
/// seal `setgroups` to them: `kenneld` runs as the operator, so this is the
/// operator's group set, and a group not in it (nor the real gid) must never be
/// granted (the root seal could otherwise over-grant, §7.4).
#[must_use]
pub fn supplementary_groups() -> Vec<u32> {
    getgroups()
        .map(|gids| gids.iter().map(|g| g.as_raw()).collect())
        .unwrap_or_default()
}

/// The GID of the group named `name` (`getgrnam(3)` via NSS), or `None` if no such
/// group exists.
///
/// # Errors
///
/// An OS error if the lookup itself fails (NSS error). A simple "not found" is
/// `Ok(None)`: that includes `ENOENT` and `ESRCH`, which `getgrnam_r(3)` documents as ways
/// some NSS back ends report a name that is not there.
pub fn group_gid(name: &str) -> io::Result<Option<u32>> {
    match Group::from_name(name) {
        Ok(group) => Ok(group.map(|g| g.gid.as_raw())),
        Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ESRCH) => Ok(None),
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// Set the calling process's supplementary groups to exactly `gids` (`setgroups(2)`).
///
/// Requires `CAP_SETGID` — called in the privileged spawn seal (where the namespace
/// `unshare` also requires privilege), to drop the inherited host groups down to the
/// policy-granted set (§7.4). An empty slice drops all supplementary groups.
///
/// # Errors
///
/// An OS error if the process lacks `CAP_SETGID` or the call otherwise fails.
pub fn set_supplementary_groups(gids: &[u32]) -> io::Result<()> {
    let gids: Vec<Gid> = gids.iter().map(|g| Gid::from_raw(*g)).collect();
    setgroups(&gids).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Set the real, effective, and saved **gid** to `gid` (`setresgid`).
///
/// Used by `kennel-bin-init` to drop the workload child from the kennel's uid-0/gid-0 init
/// identity to the non-root operator's gid before `execve`.
/// Set the gid (and supplementary groups) **before** the uid: dropping the uid first
/// would forfeit `CAP_SETGID` in the userns and leave the group identity stuck at root.
///
/// # Errors
///
/// An OS error if the caller lacks `CAP_SETGID` in its user namespace (it must run
/// before the uid drop) or the gid is unmapped.
pub fn set_gid(gid: u32) -> io::Result<()> {
    let g = Gid::from_raw(gid);
    nix::unistd::setresgid(g, g, g).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Set the real, effective, and saved **uid** to `uid` (`setresuid`).
///
/// The final step of the workload drop in `kennel-bin-init`: after the gid and
/// supplementary groups are set, drop the uid to the non-root operator. Once this
/// returns the process holds no uid-0 capability, and the subsequent `no_new_privs` +
/// seccomp make the drop irreversible.
///
/// # Errors
///
/// An OS error if the caller lacks `CAP_SETUID` in its user namespace or the uid is
/// unmapped.
pub fn set_uid(uid: u32) -> io::Result<()> {
    let u = Uid::from_raw(uid);
    nix::unistd::setresuid(u, u, u).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Set **only the effective uid** (`seteuid`), leaving the real and saved uids intact so
/// the caller can return to its prior identity.
///
/// The privhelper factory uses this so the kennel user namespace is owned by **root**:
/// `CLONE_NEWUSER` records the creator's *effective* uid as the namespace owner, and the owner
/// holds every capability inside it. The namespace maps host uid 0, so it must never be owned by
/// the operator. The factory therefore raises its effective uid to 0 immediately before the clone
/// (see [`set_fsuid`] for the companion filesystem-uid pin).
///
/// # Errors
///
/// An OS error if the target uid is not the real or saved uid and the caller lacks `CAP_SETUID`.
pub fn set_euid(uid: u32) -> io::Result<()> {
    nix::unistd::seteuid(Uid::from_raw(uid)).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Set the calling thread's *filesystem* uid (`setfsuid(2)`), leaving the effective uid alone.
///
/// The privhelper factory clones the kennel with effective uid 0 (so the new user namespace is
/// root-owned) but must still pass the kernel's write-permission check on the operator's delegated
/// cgroup for `CLONE_INTO_CGROUP`; that check uses the filesystem uid, and the factory holds no
/// `CAP_DAC_OVERRIDE`. So it pins fsuid to the operator across the clone.
///
/// `setfsuid` reports no error: it returns the previous value whether or not it changed anything.
/// The documented way to detect failure is a second call, which returns the value now in force.
///
/// # Errors
///
/// `EPERM` if the filesystem uid did not take the requested value.
pub fn set_fsuid(uid: u32) -> io::Result<()> {
    let want = Uid::from_raw(uid);
    let _previous = nix::unistd::setfsuid(want);
    if nix::unistd::setfsuid(want) == want {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}

/// Set the calling thread's *filesystem* gid (`setfsgid(2)`), the group counterpart of
/// [`set_fsuid`].
///
/// Like `setfsuid`, it reports no error; a second call returns the value now in force.
///
/// # Errors
///
/// `EPERM` if the filesystem gid did not take the requested value.
pub fn set_fsgid(gid: u32) -> io::Result<()> {
    let want = Gid::from_raw(gid);
    let _previous = nix::unistd::setfsgid(want);
    if nix::unistd::setfsgid(want) == want {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}

/// Change the owner of `path` to `uid`:`gid` (`chown(2)`).
///
/// The privhelper factory uses this to hand the freshly-allocated per-kennel binderfs
/// device to the operator: a binderfs instance assigns its nodes to uid 0 of the
/// mounting user namespace (now a real uid 0 under the `0 0 1` map), but the workload,
/// the af-unix proxy, and `kenneld` all act as the **operator**, so the device must be
/// operator-owned for them to open it (`07-2`; the fix for the binderfs `EACCES`).
///
/// # Errors
///
/// An OS error if the caller lacks the privilege to chown `path` or it does not exist.
pub fn chown_to(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<()> {
    nix::unistd::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_group_is_not_found_rather_than_an_error() {
        // Some NSS back ends answer ENOENT for a name that is not there.
        assert!(matches!(group_gid("kennel-no-such-group-xyzzy"), Ok(None)));
    }

    /// The effective uid parsed from `/proc/self/status` (`Uid: real eff saved
    /// fs`) — an independent witness, via the kernel rather than nix/libc, that
    /// the wrappers return the correct value.
    fn proc_effective_uid() -> u32 {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1)) // real(0) effective(1) saved(2) fs(3)
            .expect("Uid: line with an effective field")
            .parse()
            .expect("effective uid parses as u32")
    }

    #[test]
    fn effective_uid_matches_proc() {
        assert_eq!(effective_uid(), proc_effective_uid());
    }

    /// The effective gid parsed from `/proc/self/status` (`Gid: real eff saved
    /// fs`) — an independent witness via the kernel.
    fn proc_effective_gid() -> u32 {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        status
            .lines()
            .find_map(|l| l.strip_prefix("Gid:"))
            .and_then(|rest| rest.split_whitespace().nth(1)) // real(0) effective(1) saved(2) fs(3)
            .expect("Gid: line with an effective field")
            .parse()
            .expect("effective gid parses as u32")
    }

    #[test]
    fn effective_gid_matches_proc() {
        assert_eq!(effective_gid(), proc_effective_gid());
    }

    #[test]
    fn credentials_are_stable_across_calls() {
        assert_eq!(effective_uid(), effective_uid());
        assert_eq!(real_uid(), real_uid());
        assert_eq!(real_gid(), real_gid());
    }
}
