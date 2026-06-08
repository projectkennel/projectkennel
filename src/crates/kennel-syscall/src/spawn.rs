//! Spawning a child with a post-`fork`, pre-`execve` *seal* hook.
//!
//! The confinement that must be irreversible and inherited across `execve` —
//! `no_new_privs`, the seccomp filter, the Landlock ruleset, namespace and mount
//! setup, cgroup join — has to run *after* `fork` (so it affects only the child)
//! and *before* `execve` (so the target program starts already confined). The
//! standard mechanism is `CommandExt::pre_exec`: a closure run in the forked
//! child immediately before exec. This module wraps it in one reviewed `unsafe`
//! so the rest of the workspace (notably `kennel-spawn`) provides only the safe
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
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

/// Fork once more inside the seal so the workload becomes **PID 1** of the new PID
/// namespace, then run `seal` in that grandchild.
///
/// # Why a second fork is mandatory
///
/// `unshare(CLONE_NEWPID)` only places *future children* of the unsharing process
/// into the new PID namespace — the unsharing process itself stays in the old one.
/// So the process that unshared `PID` is not PID 1, and the kernel refuses to mount
/// a fresh `proc` from outside a PID namespace it owns (`mount("proc", …)` is
/// `EPERM`). To get a workload that is PID 1 *and* can mount `/proc`, the unsharing
/// process (call it **A**) must fork again; the grandchild (**B**) is PID 1 of the
/// new namespace and is where the rest of the seal (mount/`pivot_root`, Landlock,
/// seccomp) and the `execve` happen.
///
/// This is the bubblewrap/crun model. It is called from inside a `pre_exec` hook
/// (so this is already the forked child A); after it returns `Ok(())` in B, the
/// caller's `pre_exec` returns and std `execve`s the workload **in B**. In A it
/// **never returns** — A becomes a minimal init that reaps B and `_exit`s with B's
/// status, so kenneld (which holds a [`Child`] for A) observes the workload's exit.
///
/// # The fd handshake
///
/// std reports a `pre_exec` failure to the parent over an internal close-on-exec
/// pipe: the parent reads until every write end is closed (EOF ⇒ the child execed
/// successfully). A inherits a copy of that write end. If A kept it open while
/// waiting on the long-lived B, the parent would block on the read forever — a
/// deadlock. So **A closes every fd ≥ 3** (its copy of the pipe, nothing else it
/// needs — the workload's stdio are 0/1/2) before waiting. B keeps its copy, so a
/// seal failure in B is still reported (B writes the errno and `_exit`s), and a
/// success closes B's copy on `execve` ⇒ the parent sees EOF.
///
/// # Errors
///
/// Returns the OS error if the inner `fork` fails (in A; B then never starts), or
/// whatever `seal` returns in B. A never returns to the caller.
pub fn fork_into_pid1<F>(seal: &mut F) -> io::Result<()>
where
    F: FnMut() -> io::Result<()>,
{
    // SAFETY: we are already in the forked, single-threaded child A (inside a
    // pre_exec hook). `fork()` here creates B; both branches use only
    // async-signal-safe calls (close_range/waitpid/_exit) until B runs `seal`,
    // which is the same constrained post-fork environment pre_exec already imposes.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // B: PID 1 of the new PID namespace. Run the seal; on Ok the caller's
            // pre_exec returns and std execve()s the workload here.
            seal()
        }
        b => {
            // A: relinquish the workload's fds (incl. our copy of std's CLOEXEC
            // error pipe — see the fd handshake above), then act as a tiny init:
            // reap B and exit with its status. Never returns to the caller.
            // SAFETY: close_range/waitpid/_exit are async-signal-safe; A holds no
            // resources it must drop, and _exit skips atexit/Drop deliberately.
            unsafe {
                libc::close_range(3, libc::c_uint::MAX, 0);
            }
            let mut status: libc::c_int = 0;
            loop {
                // SAFETY: waitpid on our own child B into a local; retried on EINTR.
                let r = unsafe { libc::waitpid(b, &raw mut status, 0) };
                if r == b {
                    break;
                }
                if r == -1 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                // Mirror the shell's 128+signal convention so a killed workload is
                // distinguishable from a clean exit.
                128_i32.saturating_add(libc::WTERMSIG(status))
            } else {
                0
            };
            // SAFETY: end A without running Drop/atexit (which belong to kenneld's
            // address space, shared by fork).
            unsafe { libc::_exit(code) };
        }
    }
}

/// Launch a sealed auxiliary process.
///
/// `fork`s; the child `execv`s `path` with `argv` (the full argument vector including
/// `argv[0]`), the parent returns to continue the seal. The caller passes borrowed
/// `CStr`s; this builds the `NULL`-terminated C pointer array, so callers need no `libc`
/// dependency or `unsafe`.
///
/// Run inside the seal **after** the namespaces, view, cgroup, and Landlock are in
/// place, and before the workload `execve`: the aux inherits the fully-confined
/// environment, joins the kennel's cgroup, and becomes a child of the workload (PID 1
/// of the kennel's PID namespace), so it dies with the kennel. Used to launch the
/// in-kennel proxies (e.g. `kennel-afunix-shim`, `07-9` §7.1.5).
///
/// # Errors
///
/// Returns the OS error if `fork` fails. A child whose `execv` fails `_exit`s `127`;
/// the parent does not observe that (the aux is fire-and-forget, reaped by the
/// workload-as-PID-1 / the PID namespace teardown).
pub fn launch_aux(path: &CStr, argv: &[&CStr]) -> io::Result<()> {
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `fork` in the single-threaded sealed child. The child path uses only
    // `execv` (async-signal-safe) and `_exit` on its failure; the parent returns. `ptrs`
    // is NULL-terminated and points into `argv`'s CStrs, which outlive this call and are
    // copied into the child by `fork`.
    //
    // INVARIANTS UPHELD: exactly one aux is forked per call; the parent's control flow
    // (the rest of the seal, then the workload execve) is unchanged.
    //
    // FAILURE MODE: a fork failure surfaces as Err; an execv failure ends only the aux
    // child (_exit 127), never the workload.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // SAFETY: execv replaces the child image; ptrs is NULL-terminated. On
            // failure it returns and we _exit without unwinding kenneld's shared state.
            unsafe {
                libc::execv(path.as_ptr(), ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        _ => Ok(()),
    }
}

/// `fork` a child that **drops to the operator identity** and `execve`s `path`.
///
/// The `kennel-init` spawn-owner primitive (`docs/design/07-11` §7.2.2): init runs
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
/// pid to the parent (`kennel-init`, which records it and `waitpid`s).
///
/// Facades use this directly (no further confinement — they must reach the bus); the
/// workload uses [`fork_drop_exec_confined`], which additionally runs a seal closure
/// (`no_new_privs`/seccomp/Landlock/ulimits/pty) after the drop and before `execve`.
///
/// # Errors
///
/// Returns the OS error if `fork` fails. A child whose drop fails `_exit`s `126`; one
/// whose `execve` fails `_exit`s `127` — the parent observes those via `waitpid`, not
/// as an `Err` here (fire-and-forget at the syscall level, supervised by `kennel-init`).
pub fn fork_drop_exec(
    path: &CStr,
    argv: &[&CStr],
    envp: &[&CStr],
    gid: u32,
    groups: Option<&[u32]>,
    uid: u32,
) -> io::Result<libc::pid_t> {
    fork_drop_exec_confined(path, argv, envp, gid, groups, uid, || Ok(()))
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
pub fn fork_drop_exec_confined<F>(
    path: &CStr,
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
            // SAFETY: execve replaces the image; both arrays are NULL-terminated and
            // point into the fork-copied CStrs. On failure it returns and we _exit.
            unsafe {
                libc::execve(path.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
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
/// The privhelper-factory's hand-off (`07-11` §7.2.1): it opens the trusted
/// root-owned `kennel-init` on the host *before* `clone`, then — inside the construction
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

/// Spawn `command`, running `seal` in the forked child immediately before
/// `execve`.
///
/// `seal` is the place to install the irreversible confinement. If it returns an
/// error the child does **not** exec: the failure is reported back to the parent
/// (std propagates it over an internal close-on-exec pipe) and surfaces as the
/// error from this call. There is therefore no path on which a program execs
/// only partially confined — either the whole seal succeeds and the program runs
/// confined, or nothing runs.
///
/// See the module docs for the post-`fork` hazard the caller must respect.
///
/// # Errors
///
/// Returns the error `seal` produced in the child, or any error from the spawn
/// itself (e.g. the program not being found).
pub fn spawn_sealed<F>(command: &mut Command, seal: F) -> io::Result<Child>
where
    F: FnMut() -> io::Result<()> + Send + Sync + 'static,
{
    // SAFETY: `pre_exec` registers `seal` to run in the child between `fork` and
    // `execve`. The only `unsafe` is registering the hook; std performs the
    // fork/exec and the error plumbing. The post-fork environment is hazardous in
    // a multithreaded parent (module docs), which the caller's contract covers.
    //
    // INVARIANTS UPHELD: `seal` is `'static + Send + Sync` and `FnMut() ->
    // io::Result<()>`, so no borrowed or thread-shared state escapes into the
    // child, and a seal failure is expressible. We register exactly one hook and
    // do nothing else `unsafe`.
    //
    // FAILURE MODE: if `seal` returns `Err`, std makes the child `_exit` without
    // execing and returns that error from `command.spawn()` below — fail-closed,
    // never a partially-confined or unconfined exec.
    unsafe {
        command.pre_exec(seal);
    }
    command.spawn()
}

#[cfg(test)]
mod tests {
    use super::spawn_sealed;
    use std::ffi::CString;
    use std::io;
    use std::process::Command;

    #[test]
    fn seal_runs_in_child_and_confinement_takes_effect() {
        // The seal sets no_new_privs (unprivileged, inherited across execve). The
        // child then execs a shell that reports the resulting flag via its exit
        // code, proving the seal ran in the child *and* the program execed.
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            r#"test "$(grep NoNewPrivs /proc/self/status | tr -dc 0-9)" = 1"#,
        ]);
        let mut child = spawn_sealed(&mut cmd, crate::process::set_no_new_privs).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "no_new_privs should be set in the execed child"
        );
    }

    #[test]
    fn seal_error_aborts_the_spawn() {
        // A seal that fails must abort the spawn fail-closed: no program runs.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"]);
        let result = spawn_sealed(&mut cmd, || Err(io::Error::from_raw_os_error(libc::EPERM)));
        let err = result.expect_err("a failing seal must abort the spawn");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn happy_path_runs_the_program() {
        // A trivially-succeeding seal must not prevent a normal spawn.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"]);
        let mut child = spawn_sealed(&mut cmd, || Ok(())).expect("spawn");
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(7),
            "the program should have run and exited 7"
        );
    }

    #[test]
    fn fork_into_pid1_propagates_the_workload_exit_status() {
        // The double-fork primitive, exercised WITHOUT a user/PID namespace (so it
        // needs no privilege): the seal forks a grandchild B that execs the workload;
        // the intermediate A reaps B and exits with B's status. The parent (this
        // test's `Child`) must observe the *workload's* exit code, propagated through
        // A — proving both the status relay and the fd handshake (a spawn that did
        // not close A's pipe copy would deadlock here instead of returning).
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"]);
        let seal = || {
            let mut inner = || Ok(());
            super::fork_into_pid1(&mut inner)
        };
        let mut child = spawn_sealed(&mut cmd, seal).expect("spawn with double-fork");
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(7),
            "workload exit code must propagate A←B←kenneld"
        );
    }

    #[test]
    fn fork_into_pid1_aborts_when_the_inner_seal_fails() {
        // An inner-seal failure in B must abort fail-closed: B reports the errno over
        // std's pipe and never execs, so no program runs and the spawn errors.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"]);
        let seal = || {
            let mut inner = || Err(io::Error::from_raw_os_error(libc::EPERM));
            super::fork_into_pid1(&mut inner)
        };
        let err =
            spawn_sealed(&mut cmd, seal).expect_err("a failing inner seal must abort the spawn");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

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

        let pid = super::fork_drop_exec_confined(&path, &argv, &[], gid, None, uid, || {
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

    #[test]
    fn launch_aux_forks_and_execs_the_binary() {
        // launch_aux is the seal-side primitive that starts an in-kennel aux process
        // (the af-unix proxy). Fire-and-forget: it returns Ok after the fork and the
        // child execs independently. Prove the child actually ran by having it write a
        // marker file, then poll for it. `/bin/sh -c 'echo > marker'` exercises the full
        // argv (argv[0]=path, then -c and the script).
        let marker = std::env::temp_dir().join(format!("kennel-launch-aux-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let path = CString::new("/bin/sh").expect("cstr path");
        let dash_c = CString::new("-c").expect("cstr -c");
        let script = CString::new(format!(":>{}", marker.display())).expect("cstr script");
        let argv = [path.as_c_str(), dash_c.as_c_str(), script.as_c_str()];

        super::launch_aux(&path, &argv).expect("launch_aux forks");

        let mut appeared = false;
        for _ in 0..100 {
            if marker.exists() {
                appeared = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(appeared, "the aux child did not exec (no marker file)");
        let _ = std::fs::remove_file(&marker);
    }
}
