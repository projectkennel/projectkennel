//! The enforcement plan: a pure translation of a verified, substituted settled
//! policy into the kernel objects `kennel-syscall` and `kennel-bpf` apply.
//!
//! Building the plan has no side effects — it allocates no file descriptors and
//! makes no syscalls — so it is fully testable off the spawn path. The execution
//! step (fork, namespace/mount setup, Landlock/seccomp seal, cgroup join, BPF
//! attach, exec) consumes a `Plan`; that step is a separate increment because it
//! needs a fork/exec primitive in `kennel-syscall` (no `unsafe` lives here).

use std::path::PathBuf;

use kennel_syscall::landlock::{AccessFs, AccessNet};
use kennel_syscall::namespace::Namespaces;
use kennel_syscall::seccomp::{Action, Filter};

use kennel_policy::{NetMode, Protocol, SeccompAction, SettledPolicy};

/// `EPERM` — the errno a seccomp `Errno` default returns. (1 on Linux; named
/// here to avoid a libc dependency in this pure crate.)
const EPERM: u16 = 1;

/// The Landlock access a read-granted path subtree receives: read files and
/// directories, and execute.
fn read_access() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE
}

/// The Landlock access a write-granted path subtree receives: read plus the
/// mutating rights (create/remove/truncate).
fn write_access() -> AccessFs {
    AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::WRITE_FILE
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_DIR
        | AccessFs::REMOVE_FILE
        | AccessFs::REMOVE_DIR
        | AccessFs::TRUNCATE
}

/// The kernel enforcement objects derived from a settled policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Namespaces the spawn unshares. The network namespace is deliberately
    /// *not* unshared: egress is confined by cgroup BPF on the host stack plus
    /// the loopback proxy, not by net-ns isolation.
    pub namespaces: Namespaces,
    /// The per-kennel cgroup the workload joins and the BPF programs attach to.
    pub cgroup: PathBuf,
    /// Paths bind-mounted read-only into the shim view.
    pub bind_read: Vec<PathBuf>,
    /// Paths bind-mounted writable into the shim view.
    pub bind_write: Vec<PathBuf>,
    /// Landlock path rules `(path, access)`.
    pub landlock_fs: Vec<(PathBuf, AccessFs)>,
    /// Landlock TCP-port rules `(port, access)`. Best-effort port hardening that
    /// complements the authoritative BPF (CIDR+port) egress control.
    pub landlock_net: Vec<(u16, AccessNet)>,
    /// Syscall numbers the seccomp filter allows.
    pub seccomp_allow: Vec<i64>,
    /// The seccomp action for syscalls not on the allowlist.
    pub seccomp_default: Action,
}

impl Plan {
    /// Build the plan from a settled policy whose deferred placeholders have
    /// already been substituted. `ctx` is the kennel's context byte, used to
    /// locate its cgroup.
    #[must_use]
    pub fn from_policy(policy: &SettledPolicy, ctx: u8) -> Self {
        let ep = &policy.effective_policy;

        // Mount/PID/IPC isolation; never NET (see field docs).
        let namespaces = Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC;

        let cgroup = PathBuf::from(format!("/sys/fs/cgroup/kennel/{ctx}"));

        let bind_read: Vec<PathBuf> = ep.fs.read.iter().map(PathBuf::from).collect();
        let bind_write: Vec<PathBuf> = ep.fs.write.iter().map(PathBuf::from).collect();

        let mut landlock_fs: Vec<(PathBuf, AccessFs)> = Vec::new();
        for p in &ep.fs.read {
            landlock_fs.push((PathBuf::from(p), read_access()));
        }
        for p in &ep.fs.write {
            landlock_fs.push((PathBuf::from(p), write_access()));
        }

        // Landlock net only expresses per-port allow; map single-port TCP/Any
        // allow rules to CONNECT_TCP. Port *ranges* and CIDR scoping are left to
        // BPF, which is the authoritative egress gate. Skip in `open` mode.
        let mut landlock_net: Vec<(u16, AccessNet)> = Vec::new();
        if ep.net.mode == NetMode::Constrained {
            for r in &ep.net.allow {
                let tcp = matches!(r.protocol, Protocol::Tcp | Protocol::Any);
                if tcp && r.port_min == r.port_max {
                    landlock_net.push((r.port_min, AccessNet::CONNECT_TCP));
                }
            }
        }

        let seccomp_default = match ep.seccomp.default_action {
            SeccompAction::Errno => Action::Errno(EPERM),
            SeccompAction::KillThread => Action::KillThread,
            SeccompAction::KillProcess => Action::KillProcess,
        };

        Self {
            namespaces,
            cgroup,
            bind_read,
            bind_write,
            landlock_fs,
            landlock_net,
            seccomp_allow: ep.seccomp.allow.clone(),
            seccomp_default,
        }
    }

    /// Build the seccomp filter this plan describes. Pure — the filter is not
    /// installed until [`kennel_syscall::seccomp::Filter::install`] is called on
    /// the spawn path.
    #[must_use]
    pub fn seccomp_filter(&self) -> Filter {
        Filter::allowlist(&self.seccomp_allow, self.seccomp_default)
    }
}
