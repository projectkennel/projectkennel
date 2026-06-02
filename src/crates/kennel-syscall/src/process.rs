//! Process-wide privilege settings.
//!
//! Thin safe wrappers (over nix) for the `prctl` flags the spawn sequence sets.
//! No `unsafe` of ours — nix owns it.

use std::io;

/// Set `PR_SET_NO_NEW_PRIVS`: from now on no `execve` can grant this process (or
/// its descendants) new privileges via setuid/setgid/file capabilities.
///
/// Irreversible and inherited across `fork`/`execve`. It is a prerequisite for
/// installing an unprivileged seccomp filter and for Landlock's `restrict_self`,
/// and the design sets it unconditionally on every workload
/// (`01-process-model.md`).
///
/// # Errors
///
/// Returns the OS error if the `prctl` fails (it does not on a kernel ≥ 3.5).
pub fn set_no_new_privs() -> io::Result<()> {
    nix::sys::prctl::set_no_new_privs().map_err(|e| io::Error::from_raw_os_error(e as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set the flag in a child and confirm the kernel reports it, without
    /// touching the (irreversible) state of the test runner. Child exit code:
    /// 0 = `NoNewPrivs: 1` as expected, 1 = call failed, 2 = flag not set.
    #[test]
    fn no_new_privs_is_set_and_visible_in_proc() {
        // SAFETY: fork() in a multi-threaded test. The child only sets the prctl,
        // reads /proc/self/status, and _exit()s; it never returns to the harness.
        // The read allocates, but no other thread's lock state matters here
        // because we do not call into the allocator-sensitive paths before it in
        // a way that could deadlock (a single read_to_string of a small proc
        // file). This mirrors the Landlock seal test.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if set_no_new_privs().is_err() {
                    1
                } else if proc_no_new_privs() == Some(1) {
                    0
                } else {
                    2
                };
                // SAFETY: _exit ends the child without running Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "child failed (1=call err, 2=flag unset): {status:?}"
                );
            }
        }
    }

    fn proc_no_new_privs() -> Option<u32> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("NoNewPrivs:"))
            .and_then(|v| v.trim().parse().ok())
    }
}
