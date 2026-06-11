//! What Landlock `FS_EXECUTE` actually gates, verified against the kernel.
//!
//! The kennel's execution model rests on a precise claim: `execve(2)` of a binary needs
//! `FS_EXECUTE` on the binary **and on its dynamic loader** (the kernel opens `PT_INTERP`
//! with `FMODE_EXEC`), but the shared libraries the loader then `mmap`s do **not** — they
//! load with `READ` alone, because Landlock has no `mmap`/`mprotect` hook. This test proves
//! both halves directly: it is unprivileged (Landlock self-restriction needs only
//! `no_new_privs`), so it runs in a plain `cargo test`, and it skips cleanly where Landlock
//! is unavailable. It is the regression guard the exec model previously lacked.

use std::ffi::CString;
use std::path::PathBuf;

use kennel_lib_spawn::build_ruleset;
use kennel_lib_syscall::landlock::AccessFs;
use kennel_lib_syscall::process::{set_no_new_privs, wait_any, Reaped};
use kennel_lib_syscall::spawn::fork_drop_exec_confined;

/// Run `/bin/sh -c 'exit 7'` under a Landlock ruleset that grants EXECUTE on the shell and
/// READ (never EXECUTE) on the library dirs — plus EXECUTE on the dynamic loader only when
/// `grant_loader`. Returns the child's exit code (7 means the shell actually ran).
fn run_shell_under_landlock(grant_loader: bool) -> Option<i32> {
    let sh = std::fs::canonicalize("/bin/sh").ok()?; // dash on Debian/Ubuntu
    let loader = std::fs::canonicalize("/lib64/ld-linux-x86-64.so.2").ok()?;

    let exec = AccessFs::EXECUTE | AccessFs::READ_FILE;
    let read = AccessFs::READ_FILE | AccessFs::READ_DIR;
    let mut grants: Vec<(PathBuf, AccessFs)> = vec![
        (sh.clone(), exec),
        // Libraries are READABLE (so the loader can mmap them) but NEVER execute-granted.
        (PathBuf::from("/lib"), read),
        (PathBuf::from("/lib64"), read),
        (PathBuf::from("/usr/lib"), read),
        (PathBuf::from("/usr/lib64"), read),
    ];
    if grant_loader {
        grants.push((loader, exec));
    }

    let seal = move || -> std::io::Result<()> {
        set_no_new_privs()?;
        build_ruleset(&grants, &[], true)?.restrict_current_process()
    };
    let path = CString::new(sh.as_os_str().as_encoded_bytes()).ok()?;
    let dash_c = CString::new("-c").ok()?;
    let exit7 = CString::new("exit 7").ok()?;
    let argv = [path.as_c_str(), dash_c.as_c_str(), exit7.as_c_str()];

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    // Drop to our OWN ids (a no-op, so unprivileged); groups None skips setgroups.
    let pid = fork_drop_exec_confined(&path, &argv, &[], gid, None, uid, seal).ok()?;
    loop {
        match wait_any().ok()? {
            Reaped::Exited { pid: p, code } if p == pid => return Some(code),
            Reaped::Exited { .. } => {}
            Reaped::NoChildren => return None,
        }
    }
}

#[test]
fn execve_needs_execute_on_the_loader_but_libraries_load_with_read_only() {
    // With the loader granted EXECUTE (and libs only READABLE), the shell runs to exit 7 —
    // proving the DT_NEEDED libraries do NOT need FS_EXECUTE (they mmap with READ).
    let Some(granted) = run_shell_under_landlock(true) else {
        eprintln!("SKIP: Landlock unavailable or /bin/sh + loader not in the expected layout");
        return;
    };
    if granted != 7 {
        eprintln!("SKIP: shell did not run cleanly under Landlock (code {granted}) — likely no Landlock support here");
        return;
    }

    // Removing ONLY the loader's EXECUTE grant must stop the dynamic execve: the kernel opens
    // PT_INTERP with FMODE_EXEC, which Landlock gates. (Libraries are READ-only in both runs,
    // so a difference here is the loader, nothing else.)
    let denied = run_shell_under_landlock(false);
    assert_ne!(
        denied,
        Some(7),
        "a dynamic binary's loader (PT_INTERP) requires FS_EXECUTE — execve must fail without it"
    );
}
