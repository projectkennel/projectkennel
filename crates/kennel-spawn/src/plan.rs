//! The enforcement plan: a pure translation of a verified, substituted settled
//! policy into the kernel objects `kennel-syscall` and `kennel-bpf` apply.
//!
//! Building the plan has no side effects — it allocates no file descriptors and
//! makes no syscalls — so it is fully testable off the spawn path. The execution
//! step (fork, namespace/mount setup, Landlock/seccomp seal, cgroup join, BPF
//! attach, exec) consumes a `Plan`; that step is a separate increment because it
//! needs a fork/exec primitive in `kennel-syscall` (no `unsafe` lives here).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use kennel_syscall::landlock::{AccessFs, AccessNet};
use kennel_syscall::namespace::Namespaces;
use kennel_syscall::seccomp::{Action, Filter};

use kennel_policy::{NetMode, NetRule, Protocol, SeccompAction, SettledPolicy};

use crate::SpawnError;

/// `EPERM` — the errno a seccomp `Errno` default returns. (1 on Linux; named
/// here to avoid a libc dependency in this pure crate.)
const EPERM: u16 = 1;

/// `KENNEL_META_MAGIC` ("KNEL") from `bpf/maps.h`.
const KENNEL_META_MAGIC: u32 = 0x4B4E_454C;
/// `KENNEL_ABI_VERSION` from `bpf/maps.h`.
const KENNEL_ABI_VERSION: u16 = 1;
/// `IPPROTO_TCP` / `IPPROTO_UDP` as the BPF `allow_entry.protocol` byte
/// (`KENNEL_PROTO_ANY` is 0).
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// One BPF LPM map entry: an `(lpm_v4_key, allow_entry)` byte pair, both 8 bytes.
pub type LpmV4Entry = ([u8; 8], [u8; 8]);

/// Encode an `lpm_v4_key { __u32 prefixlen; __u32 addr }` (8 bytes). `addr` is in
/// network byte order — i.e. the raw octets. (Built by destructuring rather than
/// slice-indexing, per the workspace's `indexing_slicing` lint.)
fn lpm_v4_key(addr: [u8; 4], prefix_len: u8) -> [u8; 8] {
    let [p0, p1, p2, p3] = u32::from(prefix_len).to_ne_bytes();
    let [a0, a1, a2, a3] = addr;
    [p0, p1, p2, p3, a0, a1, a2, a3]
}

/// Encode an `allow_entry { __u16 port_min; __u16 port_max; __u8 protocol;
/// __u8 flags; __u8 _pad[2] }` (8 bytes). Ports are host order; flags 0.
const fn allow_entry(port_min: u16, port_max: u16, protocol: Protocol) -> [u8; 8] {
    let [lo0, lo1] = port_min.to_ne_bytes();
    let [hi0, hi1] = port_max.to_ne_bytes();
    let proto = match protocol {
        Protocol::Any => 0,
        Protocol::Tcp => IPPROTO_TCP,
        Protocol::Udp => IPPROTO_UDP,
    };
    [lo0, lo1, hi0, hi1, proto, 0, 0, 0]
}

/// Encode `bpf/maps.h`'s `kennel_meta` (64 bytes); only magic/abi/ctx are set,
/// the proxy and policy-hash fields are left zero until those land.
fn meta_bytes(ctx: u8) -> [u8; 64] {
    let [m0, m1, m2, m3] = KENNEL_META_MAGIC.to_ne_bytes();
    let [a0, a1] = KENNEL_ABI_VERSION.to_ne_bytes();
    let [c0, c1] = u16::from(ctx).to_ne_bytes();
    let head = [m0, m1, m2, m3, a0, a1, c0, c1];
    let mut m = [0u8; 64];
    for (dst, src) in m.iter_mut().zip(head.iter()) {
        *dst = *src;
    }
    m
}

/// Encode the IPv4 rules of `rules` into `(lpm_v4_key, allow_entry)` byte pairs.
/// IPv6 rules are skipped for now (the v6 maps are a later increment); a CIDR
/// that is neither a valid v4 nor v6 address is an error.
fn encode_v4(rules: &[NetRule]) -> Result<Vec<LpmV4Entry>, SpawnError> {
    let mut out = Vec::new();
    for r in rules {
        if let Ok(addr) = r.cidr.parse::<Ipv4Addr>() {
            out.push((
                lpm_v4_key(addr.octets(), r.prefix_len),
                allow_entry(r.port_min, r.port_max, r.protocol),
            ));
        } else if r.cidr.parse::<Ipv6Addr>().is_err() {
            return Err(SpawnError::InvalidPolicy(format!("invalid CIDR address `{}`", r.cidr)));
        }
    }
    Ok(out)
}

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
    /// BPF `allow_v4` LPM entries for the egress allowlist. IPv6 entries are a
    /// later increment.
    pub bpf_allow_v4: Vec<LpmV4Entry>,
    /// BPF `deny_v4` LPM entries (invariant deny CIDRs), consulted deny-first.
    pub bpf_deny_v4: Vec<LpmV4Entry>,
    /// The `kennel_meta` map value (64 bytes) for `kennel_meta_map[0]`.
    pub bpf_meta: [u8; 64],
}

impl Plan {
    /// Build the plan from a settled policy whose deferred placeholders have
    /// already been substituted. `ctx` is the kennel's context byte, used to
    /// locate its cgroup and stamp the BPF metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::InvalidPolicy`] if a network rule's CIDR is not a
    /// valid IPv4 or IPv6 address.
    pub fn from_policy(policy: &SettledPolicy, ctx: u8) -> Result<Self, SpawnError> {
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

        Ok(Self {
            namespaces,
            cgroup,
            bind_read,
            bind_write,
            landlock_fs,
            landlock_net,
            seccomp_allow: ep.seccomp.allow.clone(),
            seccomp_default,
            bpf_allow_v4: encode_v4(&ep.net.allow)?,
            bpf_deny_v4: encode_v4(&ep.net.deny_invariant)?,
            bpf_meta: meta_bytes(ctx),
        })
    }

    /// Build the seccomp filter this plan describes. Pure — the filter is not
    /// installed until [`kennel_syscall::seccomp::Filter::install`] is called on
    /// the spawn path.
    #[must_use]
    pub fn seccomp_filter(&self) -> Filter {
        Filter::allowlist(&self.seccomp_allow, self.seccomp_default)
    }
}
