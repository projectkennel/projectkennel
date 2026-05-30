//! Seccomp-BPF syscall filtering.
//!
//! A thin, curated wrapper over `seccompiler` (rust-vmm): it compiles a simple
//! allow/deny filter to seccomp-BPF and installs it. Hand-rolling the BPF
//! bytecode is exactly the "don't roll your own `unsafe`" case (§4) — a subtly
//! wrong filter is a silent hole — so the vetted crate does the compilation and
//! the `seccomp(2)` install; this module adds no `unsafe` of its own and keeps
//! `seccompiler`'s types out of the public API.
//!
//! Installing a filter requires either `CAP_SYS_ADMIN` or
//! [`crate::process::set_no_new_privs`] (the design always sets the latter); the
//! filter is inherited across `execve` and cannot be removed.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

/// What the kernel does when a filter rule matches (or, as the default, when no
/// rule matches). A curated subset of seccomp's return actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Permit the syscall.
    Allow,
    /// Fail the syscall with this `errno`.
    Errno(u16),
    /// Kill the whole process (`SIGSYS`, no handler).
    KillProcess,
    /// Kill the calling thread.
    KillThread,
    /// Deliver `SIGSYS` to the process (catchable).
    Trap,
    /// Permit, but log the syscall.
    Log,
}

impl From<Action> for SeccompAction {
    fn from(a: Action) -> Self {
        match a {
            Action::Allow => Self::Allow,
            Action::Errno(e) => Self::Errno(u32::from(e)),
            Action::KillProcess => Self::KillProcess,
            Action::KillThread => Self::KillThread,
            Action::Trap => Self::Trap,
            Action::Log => Self::Log,
        }
    }
}

/// A seccomp filter: a set of syscalls treated specially, plus a default for all
/// others. Build with [`Filter::allowlist`] or [`Filter::denylist`], then
/// [`Filter::install`].
pub struct Filter {
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    match_action: Action,
    mismatch_action: Action,
}

impl Filter {
    /// Permit `allowed` (by syscall number, e.g. `libc::SYS_read`); every other
    /// syscall gets `otherwise` (which must not be [`Action::Allow`], else the
    /// filter is a no-op the compiler rejects).
    #[must_use]
    pub fn allowlist(allowed: &[i64], otherwise: Action) -> Self {
        Self {
            rules: allowed.iter().map(|&s| (s, Vec::new())).collect(),
            match_action: Action::Allow,
            mismatch_action: otherwise,
        }
    }

    /// Apply `action` to `denied` (by syscall number); every other syscall is
    /// allowed. `action` must not be [`Action::Allow`].
    #[must_use]
    pub fn denylist(denied: &[i64], action: Action) -> Self {
        Self {
            rules: denied.iter().map(|&s| (s, Vec::new())).collect(),
            match_action: action,
            mismatch_action: Action::Allow,
        }
    }

    fn compile(&self) -> io::Result<BpfProgram> {
        let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(io::Error::other)?;
        let filter = SeccompFilter::new(
            self.rules.clone(),
            self.mismatch_action.into(),
            self.match_action.into(),
            arch,
        )
        .map_err(io::Error::other)?;
        BpfProgram::try_from(filter).map_err(io::Error::other)
    }

    /// Compile and install the filter on every thread of the current process.
    /// Requires `no_new_privs` (or `CAP_SYS_ADMIN`); irreversible; inherited
    /// across `execve`.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter cannot be compiled (e.g. unsupported
    /// target architecture or contradictory actions) or installed.
    pub fn install(&self) -> io::Result<()> {
        let prog = self.compile()?;
        seccompiler::apply_filter_all_threads(&prog).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowlist_with_allow_default_is_rejected() {
        // match=Allow and mismatch=Allow are identical actions; the compiler
        // refuses it. This catches the obvious misuse at install time.
        let f = Filter::allowlist(&[libc::SYS_read], Action::Allow);
        assert!(f.compile().is_err());
    }

    #[test]
    fn a_sensible_denylist_compiles() {
        let f = Filter::denylist(
            &[libc::SYS_uname],
            Action::Errno(u16::try_from(libc::EPERM).expect("EPERM fits u16")),
        );
        assert!(f.compile().is_ok());
    }

    /// Install a denylist on `uname` (no root needed: we set `no_new_privs`
    /// first) in a child and confirm the syscall is then blocked with the chosen
    /// errno while the process otherwise runs. Child exit code: 0 = blocked with
    /// EPERM as configured; non-zero = a setup/expectation failure.
    #[test]
    fn installed_filter_blocks_the_denied_syscall() {
        // SAFETY: fork(); the child sets no_new_privs, installs the filter, makes
        // one uname() call, and _exit()s — never returning to the harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = child_body();
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "child failed (1=nnp,2=install,3=not blocked,4=wrong errno): {status:?}"
                );
            }
        }
    }

    fn child_body() -> i32 {
        if crate::process::set_no_new_privs().is_err() {
            return 1;
        }
        let filter = Filter::denylist(
            &[libc::SYS_uname],
            Action::Errno(u16::try_from(libc::EPERM).expect("EPERM fits u16")),
        );
        if filter.install().is_err() {
            return 2;
        }
        let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: uname() writes into `buf`, a valid, fully-owned utsname; the
        // seccomp filter we just installed makes the kernel fail it with EPERM
        // before any write, but the call is sound either way.
        let ret = unsafe { libc::uname(std::ptr::from_mut(&mut buf)) };
        if ret != -1 {
            return 3; // should have been blocked
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            4
        }
    }
}
