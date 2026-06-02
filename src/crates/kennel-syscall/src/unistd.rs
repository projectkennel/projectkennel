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

use nix::unistd::{getegid, geteuid, getgid, getuid};

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
