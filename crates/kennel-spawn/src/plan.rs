//! The enforcement plan: a pure translation of a verified, substituted settled
//! policy into the kernel objects `kennel-syscall` and `kennel-bpf` apply.
//!
//! Building the plan has no side effects — it allocates no file descriptors and
//! makes no syscalls — so it is fully testable off the spawn path. The execution
//! step (fork, namespace/mount setup, Landlock/seccomp seal, cgroup join, BPF
//! attach, exec) consumes a `Plan`; that step is a separate increment because it
//! needs a fork/exec primitive in `kennel-syscall` (no `unsafe` lives here).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

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
/// `KENNEL_ALLOW_FLAG_PROXY` from `bpf/maps.h`: the `allow_entry.flags` bit that
/// marks an entry as the kennel's own SOCKS5 proxy.
const KENNEL_ALLOW_FLAG_PROXY: u8 = 0x01;
/// LPM prefix length for a host route to the IPv4 proxy address (`/32`).
const HOST_PREFIX_V4: u8 = 32;
/// LPM prefix length for a host route to the IPv6 proxy address (`/128`).
const HOST_PREFIX_V6: u8 = 128;

/// One BPF IPv4 LPM map entry: an `(lpm_v4_key, allow_entry)` byte pair.
pub type LpmV4Entry = ([u8; 8], [u8; 8]);

/// One BPF IPv6 LPM map entry: a 20-byte `lpm_v6_key { __u32 prefixlen;
/// __u8 addr[16] }` and the same 8-byte `allow_entry`.
pub type LpmV6Entry = ([u8; 20], [u8; 8]);

/// Encode an `lpm_v4_key { __u32 prefixlen; __u32 addr }` (8 bytes). `addr` is in
/// network byte order — i.e. the raw octets. (Built by destructuring rather than
/// slice-indexing, per the workspace's `indexing_slicing` lint.)
fn lpm_v4_key(addr: [u8; 4], prefix_len: u8) -> [u8; 8] {
    let [p0, p1, p2, p3] = u32::from(prefix_len).to_ne_bytes();
    let [a0, a1, a2, a3] = addr;
    [p0, p1, p2, p3, a0, a1, a2, a3]
}

/// Encode an `allow_entry { __u16 port_min; __u16 port_max; __u8 protocol;
/// __u8 flags; __u8 _pad[2] }` (8 bytes). Ports are host order.
const fn allow_entry(port_min: u16, port_max: u16, protocol: Protocol, flags: u8) -> [u8; 8] {
    let [lo0, lo1] = port_min.to_ne_bytes();
    let [hi0, hi1] = port_max.to_ne_bytes();
    let proto = match protocol {
        Protocol::Any => 0,
        Protocol::Tcp => IPPROTO_TCP,
        Protocol::Udp => IPPROTO_UDP,
    };
    [lo0, lo1, hi0, hi1, proto, flags, 0, 0]
}

/// Encode `bpf/maps.h`'s `kennel_meta` (64 bytes); magic/abi/ctx are set here,
/// the proxy fields are filled by [`stamp_proxy_meta`] once kenneld knows the
/// proxy address, and the policy-hash tail stays zero until that lands.
fn meta_bytes(ctx: u16) -> [u8; 64] {
    let [m0, m1, m2, m3] = KENNEL_META_MAGIC.to_ne_bytes();
    let [a0, a1] = KENNEL_ABI_VERSION.to_ne_bytes();
    let [c0, c1] = ctx.to_ne_bytes();
    let head = [m0, m1, m2, m3, a0, a1, c0, c1];
    let mut m = [0u8; 64];
    for (dst, src) in m.iter_mut().zip(head.iter()) {
        *dst = *src;
    }
    m
}

/// Fill the `kennel_meta` proxy fields in place from `endpoint`: `proxy_addr_v4`
/// (offset 8), `proxy_port` (offset 12), and `proxy_addr_v6` (offset 16), all in
/// network byte order per the C ABI (`bpf/maps.h`). A v6-only kennel leaves
/// `proxy_addr_v4` zero. `_pad0` (offset 14) is untouched, staying zero.
fn stamp_proxy_meta(meta: &mut [u8; 64], endpoint: &ProxyEndpoint) {
    let v4 = endpoint.v4.map_or([0u8; 4], |a| a.octets());
    if let Some(slot) = meta.get_mut(8..12) {
        slot.copy_from_slice(&v4);
    }
    if let Some(slot) = meta.get_mut(12..14) {
        slot.copy_from_slice(&endpoint.port.to_be_bytes());
    }
    if let Some(slot) = meta.get_mut(16..32) {
        slot.copy_from_slice(&endpoint.v6.octets());
    }
}

/// Encode an `lpm_v6_key { __u32 prefixlen; __u8 addr[16] }` (20 bytes). `addr`
/// is the network-order octets.
fn lpm_v6_key(addr: [u8; 16], prefix_len: u8) -> [u8; 20] {
    let [p0, p1, p2, p3] = u32::from(prefix_len).to_ne_bytes();
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15] = addr;
    [
        p0, p1, p2, p3, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15,
    ]
}

/// Partition `rules` into encoded IPv4 and IPv6 LPM entries. A CIDR that is
/// neither a valid v4 nor v6 address is an error.
fn encode(rules: &[NetRule]) -> Result<(Vec<LpmV4Entry>, Vec<LpmV6Entry>), SpawnError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for r in rules {
        let value = allow_entry(r.port_min, r.port_max, r.protocol, 0);
        if let Ok(addr) = r.cidr.parse::<Ipv4Addr>() {
            v4.push((lpm_v4_key(addr.octets(), r.prefix_len), value));
        } else if let Ok(addr) = r.cidr.parse::<Ipv6Addr>() {
            v6.push((lpm_v6_key(addr.octets(), r.prefix_len), value));
        } else {
            return Err(SpawnError::InvalidPolicy(format!("invalid CIDR address `{}`", r.cidr)));
        }
    }
    Ok((v4, v6))
}

/// The Landlock access a read-granted path subtree receives: read files and
/// directories, and execute.
fn read_access() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE
}

/// The Landlock access a granted device node receives: read and write the file,
/// and `ioctl(2)` on it (`IOCTL_DEV`, ABI 5; [`Ruleset::allow_path`] masks the
/// bit away on older kernels). Not `EXECUTE`/`READ_DIR` — a device node is
/// neither a program nor a directory.
///
/// [`Ruleset::allow_path`]: kennel_syscall::landlock::Ruleset::allow_path
fn dev_access() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::WRITE_FILE | AccessFs::IOCTL_DEV
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

/// The kennel's egress proxy endpoint.
///
/// The per-kennel loopback address(es) and TCP port its SOCKS5/HTTP proxy listens
/// on. Computed by kenneld from the caller's reserved scope and the kennel's
/// `ctx`, then [stamped into the plan](Plan::stamp_proxy) before the BPF payload
/// is derived.
///
/// The IPv4 address is absent for a v6-only kennel (one whose `ctx` does not fit
/// the 8-bit field the v4 loopback address carries), matching the addressing in
/// `kenneld`'s bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyEndpoint {
    /// The proxy's IPv4 loopback address, if the kennel has one.
    pub v4: Option<Ipv4Addr>,
    /// The proxy's IPv6 loopback address.
    pub v6: Ipv6Addr,
    /// The TCP port the proxy listens on.
    pub port: u16,
}

/// One bind mount composing the constructed view.
///
/// `source` (a host path) is made visible at `target` (an absolute path as seen
/// inside the kennel, after `pivot_root`), read-only unless `writable`.
///
/// Writable binds resolve to **persistent host locations** — the granted paths
/// under the user's real `$HOME`. The workload's writes land on the real inode,
/// so the work survives the kennel's teardown even though the new root that
/// frames it is an ephemeral tmpfs (§7.2.5: the constructed view is scaffolding;
/// the bound content is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    /// The host path bound in.
    pub source: PathBuf,
    /// Where it appears inside the kennel (absolute, post-`pivot_root`).
    pub target: PathBuf,
    /// Writable when true; read-only (bind, then RO remount) otherwise.
    pub writable: bool,
}

/// The constructed-`$HOME` view (§7.2.5).
///
/// What the mount seal needs to build a fresh root for the kennel and
/// `pivot_root` into it, so non-granted path *names* do not exist in the view —
/// absent, not merely denied.
///
/// Present whenever the policy shadows `$HOME` (a framework invariant, so always
/// in a policy-derived [`Plan`]); `None` is the escape hatch for the
/// unprivileged/unit-test path that does not unshare a mount namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimView {
    /// The in-kennel `$HOME` (the substituted `fs.shim_root`, under
    /// `/run/kennel/`). The workload's `HOME` is set to this; granted `~/…` paths
    /// are bound beneath it.
    pub shim_root: PathBuf,
    /// The bind mounts composing the view (system paths read-only, granted `~/…`
    /// paths remapped beneath `shim_root`). The synthetic `/etc` is *not* here —
    /// it is constructed fresh, never bound from the host.
    pub binds: Vec<BindMount>,
    /// Device nodes the constructed `/dev` exposes (absolute, under `/dev`).
    pub dev_allow: Vec<PathBuf>,
    /// Private-`/tmp` tmpfs size cap, in mebibytes.
    pub tmp_size_mib: u32,
    /// Private-`/tmp` tmpfs mode (octal digits, validated at translation).
    pub tmp_mode: String,
    /// Mount `/proc` with `hidepid=2`.
    pub proc_hidepid: bool,
}

/// Remap a granted host path to where it appears inside the kennel: a path under
/// the real `$HOME` moves beneath `shim_root`; any other absolute path keeps its
/// own location in the new root.
fn remap_target(path: &Path, home: &Path, shim_root: &Path) -> PathBuf {
    path.strip_prefix(home).map_or_else(|_| path.to_path_buf(), |rel| shim_root.join(rel))
}

/// Whether `path` is served by the constructed synthetic `/etc` (and so is *not*
/// bound from the host). Matches `/etc` and anything beneath it on a component
/// boundary (`/etcfoo` does not match).
fn is_constructed_etc(path: &Path) -> bool {
    path.starts_with("/etc")
}

/// Whether `mode` is a safe tmpfs `mode=` value: 3 or 4 octal digits and nothing
/// else, so it cannot inject extra comma-separated mount options (§10.3).
fn is_octal_mode(mode: &str) -> bool {
    matches!(mode.len(), 3 | 4) && mode.bytes().all(|b| matches!(b, b'0'..=b'7'))
}

/// Whether `path` is a device node safe to bind into the constructed `/dev`:
/// beneath `/dev`, not the bare `/dev`, and free of `..` components.
fn is_safe_dev_path(path: &Path) -> bool {
    path.starts_with("/dev")
        && path != Path::new("/dev")
        && !path.components().any(|c| c == Component::ParentDir)
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
    /// Whether the workload joins [`cgroup`](Self::cgroup) (writes its own pid to
    /// `cgroup.procs`) in the seal, before the irreversible confinement. True for
    /// policy-derived plans; the migration succeeds because kenneld and the
    /// workload share kenneld's delegated `user@<uid>` subtree, of which the
    /// kennel cgroup is a descendant (`08-enforcement-architecture.md` §8.5).
    pub cgroup_join: bool,
    /// The constructed-`$HOME` view (§7.2.5) the mount seal builds before
    /// `pivot_root`, or `None` for the escape-hatch path that does not unshare a
    /// mount namespace.
    pub view: Option<ShimView>,
    /// The host staging directory the mount seal mounts the fresh tmpfs new root
    /// on, then `pivot_root`s into. A runtime input (kenneld creates it under
    /// `$XDG_RUNTIME_DIR`, outside `/tmp`, and sets this at bring-up, like
    /// [`cgroup`](Self::cgroup)); `None` falls back to the in-place fresh-`/proc`
    /// + private-`/tmp` seal without a `pivot_root`. Not policy-derived.
    pub new_root: Option<PathBuf>,
    /// Landlock path rules `(path, access)`. With a [`view`](Self::view) these are
    /// the **post-`pivot_root`** targets (Landlock seals after the pivot), so a
    /// granted `~/…` path is keyed on its remapped location under `shim_root`.
    pub landlock_fs: Vec<(PathBuf, AccessFs)>,
    /// Landlock TCP-port rules `(port, access)`. Best-effort port hardening that
    /// complements the authoritative BPF (CIDR+port) egress control.
    pub landlock_net: Vec<(u16, AccessNet)>,
    /// Syscall numbers the seccomp filter allows.
    pub seccomp_allow: Vec<i64>,
    /// The seccomp action for syscalls not on the allowlist.
    pub seccomp_default: Action,
    /// BPF `allow_v4` LPM entries for the egress allowlist.
    pub bpf_allow_v4: Vec<LpmV4Entry>,
    /// BPF `deny_v4` LPM entries (invariant deny CIDRs), consulted deny-first.
    pub bpf_deny_v4: Vec<LpmV4Entry>,
    /// BPF `allow_v6` LPM entries for the egress allowlist.
    pub bpf_allow_v6: Vec<LpmV6Entry>,
    /// BPF `deny_v6` LPM entries (invariant deny CIDRs), consulted deny-first.
    pub bpf_deny_v6: Vec<LpmV6Entry>,
    /// The `kennel_meta` map value (64 bytes) for `kennel_meta_map[0]`.
    pub bpf_meta: [u8; 64],
    /// Single-file bind mounts `(source, target)` applied read-only in the mount
    /// seal, after the root is made private and `/proc`/`/tmp` are mounted. Used to
    /// shadow individual files (the synthetic `/etc` set) over their host
    /// counterparts in the kennel's view; a target that does not exist is skipped.
    /// Not derived from policy — kenneld populates it at bring-up with the
    /// per-kennel staged files.
    pub file_binds: Vec<(PathBuf, PathBuf)>,
}

impl Plan {
    /// Build the plan from a settled policy whose deferred placeholders have
    /// already been substituted. `ctx` is the kennel's context number, and
    /// `namespace` the caller's resource namespace (from their
    /// `/etc/kennel/subkennel` allocation); together they locate the kennel's
    /// cgroup (`/sys/fs/cgroup/<namespace>/<ctx>`), and `ctx` stamps the BPF
    /// metadata. The cgroup path is the one the privhelper will independently
    /// re-validate against the caller's allocation before creating it.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::InvalidPolicy`] if a network rule's CIDR is not a
    /// valid IPv4 or IPv6 address, if `fs.tmp.mode` is not octal digits, or if an
    /// `fs.dev.allow` entry is not a device path under `/dev`.
    pub fn from_policy(policy: &SettledPolicy, ctx: u16, namespace: &str, home: &Path) -> Result<Self, SpawnError> {
        let ep = &policy.effective_policy;

        // Mount/PID/IPC isolation; never NET (see field docs).
        let namespaces = Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC;

        let cgroup = PathBuf::from(format!("/sys/fs/cgroup/{namespace}/{ctx}"));

        let shim_root = PathBuf::from(&ep.fs.shim_root);

        // Classify every granted path once. The in-kennel target — `~/…` paths
        // remap beneath `shim_root`, `/etc` is the constructed synthetic set, any
        // other absolute path keeps its place — drives both the Landlock rule and
        // the bind mount. Landlock is sealed AFTER `pivot_root`, so it references
        // the post-pivot target, not the host source. `/etc` gets a Landlock rule
        // (on the constructed `/etc`) but no bind (it is built, not bound).
        let mut landlock_fs: Vec<(PathBuf, AccessFs)> = Vec::new();
        let mut binds: Vec<BindMount> = Vec::new();
        let grants = ep.fs.read.iter().map(|p| (p, false)).chain(ep.fs.write.iter().map(|p| (p, true)));
        for (path_str, writable) in grants {
            let source = PathBuf::from(path_str.as_str());
            let target = remap_target(&source, home, &shim_root);
            landlock_fs.push((target.clone(), if writable { write_access() } else { read_access() }));
            if !is_constructed_etc(&source) {
                binds.push(BindMount { source, target, writable });
            }
        }

        // Validate the tmpfs mode and device allowlist before they reach mount
        // syscalls: the mode flows into a comma-separated mount data string, so a
        // non-octal value is an option-injection vector (§10.3); a device path
        // outside `/dev` or carrying `..` would escape the constructed `/dev`.
        if !is_octal_mode(&ep.fs.tmp.mode) {
            return Err(SpawnError::InvalidPolicy(format!(
                "fs.tmp.mode must be 3-4 octal digits, got `{}`",
                ep.fs.tmp.mode
            )));
        }
        let mut dev_allow: Vec<PathBuf> = Vec::new();
        for d in &ep.fs.dev.allow {
            let path = PathBuf::from(d.as_str());
            if !is_safe_dev_path(&path) {
                return Err(SpawnError::InvalidPolicy(format!(
                    "fs.dev.allow entry must be a device under /dev, got `{d}`"
                )));
            }
            // Grant the device its Landlock access too, not just view visibility:
            // read/write plus `ioctl` (IOCTL_DEV). The ruleset handles IOCTL_DEV on
            // ABI >= 5, so without an explicit grant here a device `ioctl` (a tty
            // TCGETS/TIOCGWINSZ, §7.7.2) is denied even on an allowlisted node;
            // the grant makes the allowed devices usable while every non-granted
            // device — and the gated ioctls on them — stays denied.
            landlock_fs.push((path.clone(), dev_access()));
            dev_allow.push(path);
        }

        let view = Some(ShimView {
            shim_root,
            binds,
            dev_allow,
            tmp_size_mib: ep.fs.tmp.size_mib,
            tmp_mode: ep.fs.tmp.mode.clone(),
            proc_hidepid: ep.proc.hidepid,
        });

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

        let (bpf_allow_v4, bpf_allow_v6) = encode(&ep.net.allow)?;
        let (bpf_deny_v4, bpf_deny_v6) = encode(&ep.net.deny_invariant)?;

        Ok(Self {
            namespaces,
            cgroup,
            cgroup_join: true,
            view,
            new_root: None,
            landlock_fs,
            landlock_net,
            seccomp_allow: ep.seccomp.allow.clone(),
            seccomp_default,
            bpf_allow_v4,
            bpf_deny_v4,
            bpf_allow_v6,
            bpf_deny_v6,
            bpf_meta: meta_bytes(ctx),
            file_binds: Vec::new(),
        })
    }

    /// Stamp the kennel's egress proxy `endpoint` into the plan: record it in the
    /// BPF `kennel_meta` (`proxy_addr_v4`/`proxy_port`/`proxy_addr_v6`), and add a
    /// `KENNEL_ALLOW_FLAG_PROXY`-flagged allow-entry for the proxy's exact
    /// address and port to `bpf_allow_v4`/`bpf_allow_v6`.
    ///
    /// That flagged entry is what lets the confined workload `connect()` to its
    /// proxy; every other destination outside the policy's allowlist is denied by
    /// the cgroup BPF, which is what makes the proxy the unbypassable egress
    /// funnel (`08-enforcement-architecture.md`; the proxy thesis in the exec
    /// summary). Call once, after [`from_policy`](Self::from_policy) and before
    /// deriving the BPF payload.
    pub fn stamp_proxy(&mut self, endpoint: &ProxyEndpoint) {
        stamp_proxy_meta(&mut self.bpf_meta, endpoint);

        // The proxy speaks TCP (SOCKS5 / HTTP CONNECT). Host-order port on a
        // single-port range; the `KENNEL_ALLOW_FLAG_PROXY` flag marks it as the
        // proxy entry for the audit and for any program that distinguishes it.
        let value = allow_entry(endpoint.port, endpoint.port, Protocol::Tcp, KENNEL_ALLOW_FLAG_PROXY);
        if let Some(v4) = endpoint.v4 {
            self.bpf_allow_v4.push((lpm_v4_key(v4.octets(), HOST_PREFIX_V4), value));
        }
        self.bpf_allow_v6.push((lpm_v6_key(endpoint.v6.octets(), HOST_PREFIX_V6), value));
    }

    /// Build the seccomp filter this plan describes. Pure — the filter is not
    /// installed until [`kennel_syscall::seccomp::Filter::install`] is called on
    /// the spawn path.
    #[must_use]
    pub fn seccomp_filter(&self) -> Filter {
        Filter::allowlist(&self.seccomp_allow, self.seccomp_default)
    }
}
