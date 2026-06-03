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

use nix::unistd::{getegid, getgroups, geteuid, getgid, getuid, setgroups, Gid, Group};

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

/// The calling process's supplementary group IDs (`getgroups(2)`).
///
/// Used to membership-check a policy's `[identity].groups` before the privileged
/// seal `setgroups` to them: `kenneld` runs as the operator, so this is the
/// operator's group set, and a group not in it (nor the real gid) must never be
/// granted (the root seal could otherwise over-grant, §7.2).
#[must_use]
pub fn supplementary_groups() -> Vec<u32> {
    getgroups().map(|gids| gids.iter().map(|g| g.as_raw()).collect()).unwrap_or_default()
}

/// The GID of the group named `name` (`getgrnam(3)` via NSS), or `None` if no such
/// group exists.
///
/// # Errors
///
/// An OS error if the lookup itself fails (NSS error). A simple "not found" is
/// `Ok(None)`.
pub fn group_gid(name: &str) -> io::Result<Option<u32>> {
    Group::from_name(name)
        .map(|g| g.map(|g| g.gid.as_raw()))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Set the calling process's supplementary groups to exactly `gids` (`setgroups(2)`).
///
/// Requires `CAP_SETGID` — called in the privileged spawn seal (where the namespace
/// `unshare` also requires privilege), to drop the inherited host groups down to the
/// policy-granted set (§7.2). An empty slice drops all supplementary groups.
///
/// # Errors
///
/// An OS error if the process lacks `CAP_SETGID` or the call otherwise fails.
pub fn set_supplementary_groups(gids: &[u32]) -> io::Result<()> {
    let gids: Vec<Gid> = gids.iter().map(|g| Gid::from_raw(*g)).collect();
    setgroups(&gids).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

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
