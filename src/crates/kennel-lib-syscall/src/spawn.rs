//! Spawning a child with a post-`fork`, pre-`execve` *seal* hook.
//!
//! The confinement that must be irreversible and inherited across `execve` —
//! `no_new_privs`, the seccomp filter, the Landlock ruleset, namespace and mount
//! setup, cgroup join — has to run *after* `fork` (so it affects only the child)
//! and *before* `execve` (so the target program starts already confined). The
//! standard mechanism is `CommandExt::pre_exec`: a closure run in the forked
//! child immediately before exec. This module wraps it in one reviewed `unsafe`
//! so the rest of the workspace (notably `kennel-lib-spawn`) provides only the safe
//! seal closure and stays `#![forbid(unsafe_code)]`.
//!
//! # The post-`fork` hazard
//!
//! Between `fork` and `execve` the child shares the parent's address space but
//! has only the calling thread. If the parent is *multithreaded*, a lock another
//! thread held at `fork` time (the allocator's, for instance) is now held by a
//! thread that no longer exists, so any operation that takes it can deadlock.
//! The discipline, enforced by the caller, is: spawn from a single-threaded
//! context, and/or keep the seal to syscalls, preparing any allocations before
//! the call. This matches how every sandbox launcher (bubblewrap, crun, …) uses
//! a pre-exec hook.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

/// `fork` a child that **drops to the operator identity** and `execve`s `path`.
///
/// The `kennel-bin-init` spawn-owner primitive (Kennel book Vol 2 ch.2 (Process and Privilege Model)): init runs
/// as uid 0 in the kennel's user namespace and forks each facade and the workload,
/// each of which must run as the **non-root masked operator**, not as init's uid 0.
/// The child drops in the load-bearing order `set_gid` → `set_supplementary_groups`
/// → `set_uid` (dropping the uid first forfeits `CAP_SETGID`, stranding the group
/// identity at root) and then `execve`s `path` with `argv` (full vector incl.
/// `argv[0]`) and `envp` (the synthesised environment; `envp` empty ⇒ an empty env).
///
/// `groups` is `Some(set)` to set the supplementary groups to exactly that set
/// (`Some(&[])` drops all — the default), or `None` to leave the inherited groups
/// untouched (the escape hatch where the caller lacks `CAP_SETGID`, e.g. the
/// unprivileged unit tests; production always passes `Some`). Returns the child's
/// pid to the parent (`kennel-bin-init`, which records it and `waitpid`s).
///
/// Facades use this directly (no further confinement — they must reach the bus); the
/// workload uses [`fork_drop_exec_confined`], which additionally runs a seal closure
/// (`no_new_privs`/seccomp/Landlock/ulimits/pty) after the drop and before `execve`.
///
/// # Errors
///
/// Returns the OS error if `fork` fails. A child whose drop fails `_exit`s `126`; one
/// whose `execve` fails `_exit`s `127` — the parent observes those via `waitpid`, not
/// as an `Err` here (fire-and-forget at the syscall level, supervised by `kennel-bin-init`).
pub fn fork_drop_exec(
    path: &CStr,
    argv: &[&CStr],
    envp: &[&CStr],
    gid: u32,
    groups: Option<&[u32]>,
    uid: u32,
) -> io::Result<libc::pid_t> {
    fork_drop_exec_confined(path, None, argv, envp, gid, groups, uid, || Ok(()))
}

/// As [`fork_drop_exec`], but run `seal` after the drop and before `execve`.
///
/// `seal` is the workload's irreversible confinement (`no_new_privs`, seccomp,
/// Landlock, ulimits, the controlling pty). The drop precedes the seal so the workload is already the unprivileged operator
/// when it is confined, and the seal precedes `execve` so the program starts fully
/// confined. A seal that returns `Err` aborts the child fail-closed (`_exit(126)`):
/// there is no path on which the workload execs only partially confined. The seal
/// runs in the post-`fork` child, so the caller must respect the post-`fork` hazard
/// (module docs): fork from a single-threaded context.
///
/// # Errors
///
/// Returns the OS error if `fork` fails. A child whose drop or `seal` fails `_exit`s
/// `126`; one whose `execve` fails `_exit`s `127` — observed by the supervisor via
/// `waitpid`.
// allow(too_many_arguments): a fork/drop/seal/exec primitive — path-or-fd, argv, envp, the
// three identity ids, and the seal are all irreducibly part of one confined spawn.
#[allow(clippy::too_many_arguments)]
pub fn fork_drop_exec_confined<F>(
    path: &CStr,
    exec_fd: Option<RawFd>,
    argv: &[&CStr],
    envp: &[&CStr],
    gid: u32,
    groups: Option<&[u32]>,
    uid: u32,
    mut seal: F,
) -> io::Result<libc::pid_t>
where
    F: FnMut() -> io::Result<()>,
{
    // Build the NULL-terminated C pointer arrays in the PARENT (allocation before the
    // fork), pointing into the borrowed CStrs which the fork copies into the child.
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_p.push(std::ptr::null());

    // SAFETY: `fork` in the (caller-guaranteed single-threaded) process. The child path
    // runs the identity drop + seal + `execve`/`_exit`; all are async-signal-safe or run
    // under the same post-fork discipline a pre_exec hook imposes (module docs). The
    // parent only returns the pid.
    //
    // INVARIANTS UPHELD: exactly one child is forked; the drop order (gid, groups, uid)
    // is fixed so CAP_SETGID survives long enough to set the groups; the seal runs only
    // after the full drop and only before `execve`.
    //
    // FAILURE MODE: a fork failure surfaces as Err; a drop/seal failure ends the child
    // _exit(126) without execing (never a partially-confined workload); an execve
    // failure ends it _exit(127). The supervisor reaps and classifies via waitpid.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // Child. Drop, then seal — short-circuit on the first failure.
            let dropped = crate::unistd::set_gid(gid).is_ok()
                && groups.is_none_or(|g| crate::unistd::set_supplementary_groups(g).is_ok())
                && crate::unistd::set_uid(uid).is_ok()
                && seal().is_ok();
            if !dropped {
                // SAFETY: _exit ends the child fail-closed without unwinding the
                // parent's shared Drop/atexit state.
                unsafe { libc::_exit(126) };
            }
            // Exec the workload. With `exec_fd` set, `fexecve` the pinned fd — the exact
            // inode kenneld hashed (the sha256 TOCTOU fix): no path relookup, so nothing can
            // swap the binary between the hash and the exec. Otherwise `execve` the path.
            // SAFETY: both pointer arrays are NULL-terminated and point into fork-copied
            // CStrs; on success the image is replaced, on failure control returns and we _exit.
            unsafe {
                match exec_fd {
                    Some(fd) => {
                        libc::fexecve(fd, argv_p.as_ptr(), envp_p.as_ptr());
                    }
                    None => {
                        libc::execve(path.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
                    }
                }
                libc::_exit(127);
            }
        }
        pid => Ok(pid),
    }
}

/// Replace the current process image with the program referred to by the open file
/// descriptor `fd` (`fexecve(2)`), passing `argv` (full vector incl. `argv[0]`) and
/// `envp`.
///
/// The privhelper-factory's hand-off (`07-2` §7.2.1): it opens the trusted
/// root-owned `kennel-bin-init` on the host *before* `clone`, then — inside the construction
/// child, after `pivot_root` has detached the host filesystem — `fexecve`s it. Executing
/// by fd is essential because the host path is gone post-pivot, and it keeps the init
/// binary out of the kennel's view entirely (it is never bound in).
///
/// On success this **does not return** (the image is replaced); it returns only on
/// failure, yielding the OS error, so the caller can `_exit` fail-closed.
#[must_use]
pub fn fexecve(fd: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> io::Error {
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    // SAFETY: `fexecve` replaces the process image with the program behind `fd`; both
    // pointer arrays are NULL-terminated and point into the borrowed CStrs, which outlive
    // this call. On success control never returns here; on failure it returns and we read
    // errno. No shared state is mutated.
    unsafe {
        libc::fexecve(fd.as_raw_fd(), argv_p.as_ptr(), envp_p.as_ptr());
    }
    io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io;

    #[test]
    fn fork_drop_exec_drops_to_self_and_relays_status() {
        // Unprivileged: dropping the uid/gid to our OWN ids is permitted without
        // CAP_SETUID/SETGID, and `groups: None` skips the privileged setgroups. The
        // child execs a shell that exits 7; we waitpid the returned pid and observe
        // that exact status — proving fork + identity drop + execve + status relay.
        let uid = crate::unistd::real_uid();
        let gid = crate::unistd::real_gid();
        let path = CString::new("/bin/sh").expect("cstr path");
        let dash_c = CString::new("-c").expect("cstr -c");
        let script = CString::new("exit 7").expect("cstr script");
        let argv = [path.as_c_str(), dash_c.as_c_str(), script.as_c_str()];

        let pid = super::fork_drop_exec(&path, &argv, &[], gid, None, uid).expect("fork_drop_exec");
        let status =
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 7)),
            "the dropped child should have execed and exited 7: {status:?}"
        );
    }

    #[test]
    fn fork_drop_exec_confined_applies_the_seal_before_exec() {
        // The confined variant runs a seal after the (self-)drop and before execve.
        // The seal sets no_new_privs (unprivileged, inherited across execve); the
        // child then execs a shell that exits 0 only if NoNewPrivs is set — proving
        // the seal ran in the child and the program execed confined.
        let uid = crate::unistd::real_uid();
        let gid = crate::unistd::real_gid();
        let path = CString::new("/bin/sh").expect("cstr path");
        let dash_c = CString::new("-c").expect("cstr -c");
        let script =
            CString::new(r#"test "$(grep NoNewPrivs /proc/self/status | tr -dc 0-9)" = 1"#)
                .expect("cstr script");
        let argv = [path.as_c_str(), dash_c.as_c_str(), script.as_c_str()];

        let pid = super::fork_drop_exec_confined(
            &path,
            None,
            &argv,
            &[],
            gid,
            None,
            uid,
            crate::process::set_no_new_privs,
        )
        .expect("fork_drop_exec_confined");
        let status =
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
            "no_new_privs must be set in the execed child (seal ran before exec): {status:?}"
        );
    }

    #[test]
    fn fork_drop_exec_confined_aborts_when_the_seal_fails() {
        // A seal failure must abort fail-closed: the child _exit(126)s and never execs.
        let uid = crate::unistd::real_uid();
        let gid = crate::unistd::real_gid();
        let path = CString::new("/bin/sh").expect("cstr path");
        let dash_c = CString::new("-c").expect("cstr -c");
        let script = CString::new("exit 0").expect("cstr script");
        let argv = [path.as_c_str(), dash_c.as_c_str(), script.as_c_str()];

        let pid = super::fork_drop_exec_confined(&path, None, &argv, &[], gid, None, uid, || {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .expect("fork succeeds even though the seal will fail");
        let status =
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 126)),
            "a failing seal must _exit(126) without execing: {status:?}"
        );
    }

    #[test]
    fn fexecve_replaces_the_image_with_the_fd_program() {
        // Open /bin/true and exec it BY FD in a forked child; the parent observes exit 0.
        // Proves fexecve runs the program behind the fd (the factory's post-pivot hand-off
        // mechanism) without needing a path.
        use std::os::fd::AsFd;
        let f = std::fs::File::open("/bin/true").expect("open /bin/true");
        let argv0 = CString::new("true").expect("argv0");
        // SAFETY: fork(); the child only fexecves (replacing its image) or _exit()s on
        // failure — it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let _err = super::fexecve(f.as_fd(), &[argv0.as_c_str()], &[]);
                // SAFETY: only reached if fexecve failed; end the child without unwinding.
                unsafe { libc::_exit(127) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "fexecve should have run /bin/true to exit 0: {status:?}"
                );
            }
        }
    }
}
