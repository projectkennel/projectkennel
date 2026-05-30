//! Process-credential syscalls.
//!
//! # Purpose
//!
//! Thin safe wrappers over the libc credential calls that `std` does not expose.
//! Each wraps a single syscall whose safety is unconditional — no pointers, no
//! buffers, no caller preconditions — so the `unsafe` is minimal and local, and
//! the wrapper is total (it cannot fail).
//!
//! # Why it exists
//!
//! Components that must know whether they hold privilege — the privhelper
//! (boundary 1) and the spawn path — need the effective uid, which `std` has no
//! API for. Routing it through one reviewed place keeps the raw FFI confined to
//! this crate (CODING-STANDARDS.md §4).

/// The effective user ID of the calling process (`geteuid(2)`).
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid() takes no arguments and reads only the calling process's
    // effective uid from the kernel; there are no preconditions a caller could
    // violate and no memory is accessed.
    //
    // INVARIANTS UPHELD: none required — the call touches no memory we own and
    // yields a plain integer by value.
    //
    // FAILURE MODE: cannot fail. POSIX specifies geteuid() always succeeds, so
    // there is no errno path to check or propagate.
    unsafe { libc::geteuid() }
}

/// The real user ID of the calling process (`getuid(2)`).
#[must_use]
pub fn real_uid() -> u32 {
    // SAFETY: getuid() takes no arguments and reads only the calling process's
    // real uid; no preconditions, no memory accessed.
    //
    // INVARIANTS UPHELD: none required — integer returned by value.
    //
    // FAILURE MODE: cannot fail (POSIX specifies getuid() always succeeds).
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The effective uid parsed from `/proc/self/status` (`Uid: real eff saved
    /// fs`) — an independent witness, via the kernel rather than libc, that the
    /// vendored libc bindings return the correct value.
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

    #[test]
    fn credentials_are_stable_across_calls() {
        assert_eq!(effective_uid(), effective_uid());
        assert_eq!(real_uid(), real_uid());
    }
}
