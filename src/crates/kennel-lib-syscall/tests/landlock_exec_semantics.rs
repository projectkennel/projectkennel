//! Empirical proof of the exec-allowlist model (`docs/design/07-3-exec.md`):
//! a binary runs with only **READ** on its library dirs plus **EXECUTE** on the
//! binary itself — and a binary that has READ but *not* EXECUTE is refused.
//!
//! This is the kernel-behaviour assumption the §7.3 exec policy rests on: that
//! Landlock's `FS_EXECUTE` gates `execve` while the dynamic linker loads
//! libraries with `FS_READ_FILE` alone. Landlock needs no privilege, so this
//! runs in the ordinary test suite.

use std::ffi::CString;
use std::path::Path;

use kennel_lib_syscall::landlock::{abi_version, AccessFs, Ruleset};

/// Read access without execute — what a library/data path gets.
fn read_only() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::READ_DIR
}

/// Execute access for an allowlisted binary (plus read, so the loader can map it).
fn exec_access() -> AccessFs {
    AccessFs::EXECUTE | AccessFs::READ_FILE
}

/// Fork; in the child apply `ruleset`, `execve(bin)`, and on failure exit 13
/// (EACCES) or 127 (other). Returns the child's exit status, or `None` on a
/// fork failure. The ruleset is built in the parent so the post-fork child does
/// only async-signal-safe syscalls (`restrict` + `execve`).
fn exec_under(ruleset: Ruleset, bin: &str) -> Option<i32> {
    let c_bin = CString::new(bin).expect("nul-free path");
    let argv = [c_bin.as_ptr(), std::ptr::null()];
    // SAFETY: between fork and execve the child calls only syscalls (no malloc,
    // no locks). The ruleset's path FDs were opened in the parent.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        // Child: seal, then exec. Any failure exits with a distinguishing code.
        if ruleset.restrict_current_process().is_err() {
            unsafe { libc::_exit(126) };
        }
        unsafe { libc::execv(c_bin.as_ptr(), argv.as_ptr()) };
        let code = if std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
            13
        } else {
            127
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on our own child with a valid status pointer.
    unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        Some(-1)
    }
}

/// Grant READ on the dirs a dynamically-linked binary needs (libs + ld.so.cache).
fn grant_lib_reads(r: &mut Ruleset) {
    for d in ["/usr", "/lib", "/lib64", "/etc"] {
        if Path::new(d).exists() {
            r.allow_path(Path::new(d), read_only()).expect("grant read");
        }
    }
}

/// Grant EXECUTE (+read) on the loader's dirs.
fn grant_lib_exec(r: &mut Ruleset) {
    for d in ["/usr/lib", "/lib", "/lib64", "/usr/lib64"] {
        if Path::new(d).exists() {
            r.allow_path(Path::new(d), exec_access())
                .expect("grant exec");
        }
    }
}

#[test]
fn landlock_fs_execute_gates_libraries_not_just_the_binary() {
    // Establishes the kernel fact the exec-allowlist model (kennel-lib-spawn) must
    // build to: under Landlock, the dynamic loader maps shared libraries (and the
    // ELF interpreter) with PROT_EXEC, which FS_EXECUTE gates — so EXECUTE on the
    // binary alone is NOT enough; the loader's lib dirs need EXECUTE too. This
    // corrects docs/design/07-3-exec.md §7.3.7 ("libs need only READ").
    if abi_version().is_err() {
        eprintln!("SKIP: Landlock unavailable");
        return;
    }
    let bin = "/usr/bin/true";
    if !Path::new(bin).exists() {
        eprintln!("SKIP: {bin} absent");
        return;
    }

    // A: read-only on lib dirs + EXECUTE on the binary -> still refused (EACCES),
    // because the loader cannot map libc/ld.so without EXECUTE on the lib dirs.
    let mut a = Ruleset::new().expect("ruleset");
    grant_lib_reads(&mut a);
    a.allow_path(Path::new(bin), exec_access()).expect("grant");
    assert_eq!(
        exec_under(a, bin),
        Some(13),
        "EXECUTE on the binary alone must NOT run a dynamically-linked program"
    );

    // B: EXECUTE on the lib dirs too -> runs. This is the model kennel-lib-spawn builds.
    let mut b = Ruleset::new().expect("ruleset");
    grant_lib_reads(&mut b);
    grant_lib_exec(&mut b);
    b.allow_path(Path::new(bin), exec_access()).expect("grant");
    assert_eq!(
        exec_under(b, bin),
        Some(0),
        "EXECUTE on the loader's lib dirs + the binary must run it"
    );

    // C: read everywhere, EXECUTE nowhere -> refused. The allowlist binds.
    let mut c = Ruleset::new().expect("ruleset");
    grant_lib_reads(&mut c);
    assert_eq!(
        exec_under(c, bin),
        Some(13),
        "a readable-but-not-EXECUTE-granted binary must fail execve with EACCES"
    );
}
