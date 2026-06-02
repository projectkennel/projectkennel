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

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

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
        assert!(status.success(), "no_new_privs should be set in the execed child");
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
        assert_eq!(status.code(), Some(7), "the program should have run and exited 7");
    }
}
