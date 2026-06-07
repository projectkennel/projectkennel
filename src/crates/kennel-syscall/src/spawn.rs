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
/// in-kennel proxies (e.g. `kennel-afunix-shim`, `07-9` §7.9.5).
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
