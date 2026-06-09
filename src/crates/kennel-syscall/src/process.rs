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

pub use nix::sys::resource::{Resource, RLIM_INFINITY};

/// Map a short `[ulimits]` resource name to its `setrlimit(2)` [`Resource`].
///
/// The policy translator validates names against `kennel_policy::ULIMIT_RESOURCES`,
/// so the spawn layer should only ever pass a known name; an unknown one returns
/// `None` (the caller treats that as a policy error). Kept in lock-step with that
/// list — a spawn-side test asserts every accepted name resolves here.
#[must_use]
pub fn resource_by_name(name: &str) -> Option<Resource> {
    Some(match name {
        "as" => Resource::RLIMIT_AS,
        "core" => Resource::RLIMIT_CORE,
        "cpu" => Resource::RLIMIT_CPU,
        "data" => Resource::RLIMIT_DATA,
        "fsize" => Resource::RLIMIT_FSIZE,
        "locks" => Resource::RLIMIT_LOCKS,
        "memlock" => Resource::RLIMIT_MEMLOCK,
        "msgqueue" => Resource::RLIMIT_MSGQUEUE,
        "nice" => Resource::RLIMIT_NICE,
        "nofile" => Resource::RLIMIT_NOFILE,
        "nproc" => Resource::RLIMIT_NPROC,
        "rtprio" => Resource::RLIMIT_RTPRIO,
        "rttime" => Resource::RLIMIT_RTTIME,
        "sigpending" => Resource::RLIMIT_SIGPENDING,
        "stack" => Resource::RLIMIT_STACK,
        _ => return None,
    })
}

/// The canonical name for a `setrlimit(2)` resource — the inverse of [`resource_by_name`].
///
/// Lets a [`Resource`] be serialised by name across a process boundary (the construction
/// request the privhelper forwards to `kennel-init`) and decoded back. Kept in lock-step
/// with [`resource_by_name`]; a round-trip test asserts it. Returns `None` for a resource
/// this build does not enumerate.
#[must_use]
pub const fn resource_name(resource: Resource) -> Option<&'static str> {
    Some(match resource {
        Resource::RLIMIT_AS => "as",
        Resource::RLIMIT_CORE => "core",
        Resource::RLIMIT_CPU => "cpu",
        Resource::RLIMIT_DATA => "data",
        Resource::RLIMIT_FSIZE => "fsize",
        Resource::RLIMIT_LOCKS => "locks",
        Resource::RLIMIT_MEMLOCK => "memlock",
        Resource::RLIMIT_MSGQUEUE => "msgqueue",
        Resource::RLIMIT_NICE => "nice",
        Resource::RLIMIT_NOFILE => "nofile",
        Resource::RLIMIT_NPROC => "nproc",
        Resource::RLIMIT_RTPRIO => "rtprio",
        Resource::RLIMIT_RTTIME => "rttime",
        Resource::RLIMIT_SIGPENDING => "sigpending",
        Resource::RLIMIT_STACK => "stack",
        _ => return None,
    })
}

/// Set a `setrlimit(2)` resource limit on the current process.
///
/// Use [`RLIM_INFINITY`] for "unlimited". Called in the seal, after the Landlock
/// ruleset is built (lowering `RLIMIT_NOFILE` must not starve the rule-building opens)
/// and just before `execve`, so the workload inherits exactly the policy's limits.
///
/// An unprivileged process can only lower a hard limit; raising one above the
/// daemon's inherited ceiling needs `CAP_SYS_RESOURCE` and otherwise fails closed.
///
/// # Errors
///
/// Returns the OS error if the `setrlimit` fails (e.g. `EPERM` when raising a hard
/// limit without privilege, or `EINVAL` for `soft > hard`).
pub fn set_rlimit(resource: Resource, soft: u64, hard: u64) -> io::Result<()> {
    nix::sys::resource::setrlimit(resource, soft, hard)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// The result of reaping one child with [`wait_any`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaped {
    /// A child terminated: `pid` is its host pid, `code` its exit status (an exit code,
    /// or `128 + signal` for a signalled death — the shell convention, so a caller can
    /// propagate a single number up the process chain).
    Exited {
        /// The terminated child's pid.
        pid: i32,
        /// Its exit code (or `128 + signal`).
        code: i32,
    },
    /// There are no remaining children to reap (`ECHILD`).
    NoChildren,
}

/// Block until any child changes to a terminal state and reap it (`wait(2)`).
///
/// The reaping primitive `kennel-init` (the kennel's PID 1) drives in its supervise
/// loop: it must reap every child to prevent zombies and to learn when the workload
/// exits. Stopped/continued transitions are not requested, so every [`Reaped::Exited`]
/// is a real termination. `EINTR` is retried.
///
/// # Errors
///
/// Returns the OS error if `wait` fails for a reason other than `ECHILD` (reported as
/// [`Reaped::NoChildren`]) or `EINTR` (retried).
pub fn wait_any() -> io::Result<Reaped> {
    loop {
        match nix::sys::wait::wait() {
            Ok(status) => return Ok(reaped_from(status)),
            Err(nix::errno::Errno::ECHILD) => return Ok(Reaped::NoChildren),
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
}

/// Mark this process as a **child subreaper** (`PR_SET_CHILD_SUBREAPER`).
///
/// An orphaned descendant then reparents to this process instead of to init. kenneld sets
/// this at startup so that when the privhelper **factory** exits — its job done once it has
/// written the maps and reported the init pid (`07-2`) — the now-orphaned `kennel-init`
/// reparents to kenneld, which can therefore `waitpid` it for the workload's exit status
/// (and reap it, no zombie). Without this, init would reparent to `systemd --user` and
/// kenneld could never collect the status.
///
/// # Errors
/// The OS error if the `prctl` fails (it does not on a kernel ≥ 3.4).
pub fn set_child_subreaper() -> io::Result<()> {
    nix::sys::prctl::set_child_subreaper(true).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// `SIGKILL` process `pid`. A process that is already gone (`ESRCH`) is success.
///
/// # Errors
/// The OS error if signalling fails for a reason other than the process being gone.
pub fn kill_pid(pid: i32) -> io::Result<()> {
    use nix::sys::signal::{kill, Signal};
    match kill(nix::unistd::Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// Block until child `pid` terminates and reap it; return its exit code (or `128 + signal`).
///
/// `pid` must be a child of the calling process — for `kennel-init` this holds because
/// kenneld is a [`set_child_subreaper`] and the orphaned init reparented to it. `ECHILD`
/// (already gone / not ours) yields `0`. `EINTR` is retried.
///
/// # Errors
/// The OS error if `waitpid` fails for a reason other than `ECHILD`/`EINTR`.
pub fn wait_pid(pid: i32) -> io::Result<i32> {
    let p = nix::unistd::Pid::from_raw(pid);
    loop {
        match nix::sys::wait::waitpid(p, None) {
            Ok(status) => return Ok(code_of(status)),
            Err(nix::errno::Errno::ECHILD) => return Ok(0),
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
}

/// Non-blocking check on child `pid`, reaping it if it has terminated.
///
/// `Ok(None)` while it runs, `Ok(Some(code))` once terminated (the exit code, or `128 +
/// signal`). `ECHILD` yields `Some(0)`; `EINTR` is reported as `None` (the caller's poll loop
/// retries).
///
/// # Errors
/// The OS error if `waitpid` fails for a reason other than `ECHILD`/`EINTR`.
pub fn try_wait_pid(pid: i32) -> io::Result<Option<i32>> {
    use nix::sys::wait::{WaitPidFlag, WaitStatus};
    let p = nix::unistd::Pid::from_raw(pid);
    match nix::sys::wait::waitpid(p, Some(WaitPidFlag::WNOHANG)) {
        // Still running, or interrupted before any state change — the poll loop tries again.
        Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => Ok(None),
        Ok(status) => Ok(Some(code_of(status))),
        Err(nix::errno::Errno::ECHILD) => Ok(Some(0)),
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// The exit code (or `128 + signal`) of a terminal wait status.
fn code_of(status: nix::sys::wait::WaitStatus) -> i32 {
    match reaped_from(status) {
        Reaped::Exited { code, .. } => code,
        Reaped::NoChildren => 0,
    }
}

/// Map a terminal [`nix::sys::wait::WaitStatus`] to a [`Reaped::Exited`]. Non-terminal
/// statuses (stopped/continued, never requested here) collapse to code 0.
fn reaped_from(status: nix::sys::wait::WaitStatus) -> Reaped {
    use nix::sys::wait::WaitStatus;
    match status {
        WaitStatus::Exited(pid, code) => Reaped::Exited {
            pid: pid.as_raw(),
            code,
        },
        WaitStatus::Signaled(pid, sig, _) => Reaped::Exited {
            pid: pid.as_raw(),
            // 128 + signal, matching the shell so a killed child is distinguishable.
            code: 128i32.saturating_add(sig as i32),
        },
        other => Reaped::Exited {
            pid: other.pid().map_or(0, nix::unistd::Pid::as_raw),
            code: 0,
        },
    }
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
