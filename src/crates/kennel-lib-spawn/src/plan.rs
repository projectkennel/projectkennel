//! The enforcement plan: a pure translation of a verified, substituted settled
//! policy into the kernel objects `kennel-lib-syscall` and `kennel-lib-bpf` apply.
//!
//! Building the plan has no side effects — it allocates no file descriptors and
//! makes no syscalls — so it is fully testable off the spawn path. The execution
//! step (fork, namespace/mount setup, Landlock/seccomp seal, cgroup join, BPF
//! attach, exec) consumes a `Plan`; that step is a separate increment because it
//! needs a fork/exec primitive in `kennel-lib-syscall` (no `unsafe` lives here).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::path::{Component, Path, PathBuf};

use kennel_lib_syscall::landlock::{AccessFs, AccessNet};
use kennel_lib_syscall::namespace::Namespaces;
use kennel_lib_syscall::process::{Resource, RLIM_INFINITY};
use kennel_lib_syscall::seccomp::{Action, Filter};

use kennel_lib_policy::{NetMode, NetPolicy, NetRule, Protocol, SeccompAction, SettledPolicy};

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
/// The per-kennel loopback subnet prefixes (§7.5.6): the kennel's own addresses live in a
/// `/28` (v4) / `/64` (v6) carved from the reserved range. `stamp_proxy` seeds this subnet
/// into the bind ACL so an in-subnet or wildcard-rewritten bind is allowed by default.
const LOOPBACK_PREFIX_V4: u8 = 28;
const LOOPBACK_PREFIX_V6: u8 = 64;

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

/// Stamp the `kennel_meta` `bind_port_min` field (the repurposed `_pad0` slot, offset
/// 14, host byte order) — the lowest port a workload may `bind()` (§7.5.7). `0` leaves
/// no floor. Read by the `bind4`/`bind6` BPF; host order because it compares against a
/// host-order bind port on the same machine that wrote it.
fn stamp_bind_port_min(meta: &mut [u8; 64], min_port: u16) {
    if let Some(slot) = meta.get_mut(14..16) {
        slot.copy_from_slice(&min_port.to_ne_bytes());
    }
}

/// Fill the `kennel_meta` proxy fields in place from `endpoint`: `proxy_addr_v4`
/// (offset 8), `proxy_port` (offset 12), and `proxy_addr_v6` (offset 16), all in
/// network byte order per the C ABI (`bpf/maps.h`). A v6-only kennel leaves
/// `proxy_addr_v4` zero. The `bind_port_min` slot (offset 14) is set separately by
/// [`stamp_bind_port_min`].
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
            return Err(SpawnError::InvalidPolicy(format!(
                "invalid CIDR address `{}`",
                r.cidr
            )));
        }
    }
    Ok((v4, v6))
}

/// The eight cgroup-BPF LPM ACL vectors a plan carries: the connect ACL (deny-first, allow
/// non-empty only in `host` mode) and the inbound BIND ACL (§7.5.7, deny-first, default-deny).
struct BpfAcls {
    allow_v4: Vec<LpmV4Entry>,
    allow_v6: Vec<LpmV6Entry>,
    deny_v4: Vec<LpmV4Entry>,
    deny_v6: Vec<LpmV6Entry>,
    bind_allow_v4: Vec<LpmV4Entry>,
    bind_allow_v6: Vec<LpmV6Entry>,
    bind_deny_v4: Vec<LpmV4Entry>,
    bind_deny_v6: Vec<LpmV6Entry>,
}

impl BpfAcls {
    /// Encode the connect + bind ACLs from the settled net policy (§7.5.4/§7.5.7).
    ///
    /// CONNECT allow base is non-empty only in `host` mode (the BPF is the egress gate there);
    /// the proxied modes reach only the proxy endpoint, added by [`Plan::stamp_proxy`]. CONNECT
    /// deny is enforced in every mode: the invariant floor + `[net.bpf].connect.deny` +
    /// `[net.proxy].deny.policy`. BIND allow/deny are the author's `[net.bpf].bind` rules; the
    /// kennel's own loopback `/28`-`/64` is seeded into bind-allow later by `stamp_proxy`.
    fn from_policy(net: &NetPolicy) -> Result<Self, SpawnError> {
        let connect_allow: &[NetRule] = if net.mode == NetMode::Host {
            &net.bpf_connect_allow
        } else {
            &[]
        };
        let (allow_v4, allow_v6) = encode(connect_allow)?;
        let mut deny_rules = net.deny_invariant.clone();
        deny_rules.extend(net.bpf_connect_deny.iter().cloned());
        deny_rules.extend(net.deny_author.iter().cloned());
        let (deny_v4, deny_v6) = encode(&deny_rules)?;
        let (bind_allow_v4, bind_allow_v6) = encode(&net.bpf_bind_allow)?;
        let (bind_deny_v4, bind_deny_v6) = encode(&net.bpf_bind_deny)?;
        Ok(Self {
            allow_v4,
            allow_v6,
            deny_v4,
            deny_v6,
            bind_allow_v4,
            bind_allow_v6,
            bind_deny_v4,
            bind_deny_v6,
        })
    }
}

/// Resolve the settled `[ulimits]` entries (§7.4) to `(resource, soft, hard)` triples for
/// `setrlimit`. The translator already validated names and normalised values, so an unknown
/// name here is a bug, surfaced as an invalid-policy error rather than silently dropped.
fn resolve_ulimits(policy: &SettledPolicy) -> Result<Vec<(Resource, u64, u64)>, SpawnError> {
    let mut ulimits = Vec::new();
    for (name, value) in &policy.ulimits.limits {
        let resource = kennel_lib_syscall::process::resource_by_name(name).ok_or_else(|| {
            SpawnError::InvalidPolicy(format!("unknown ulimit resource `{name}`"))
        })?;
        let (soft, hard) = parse_ulimit_value(name, value)?;
        ulimits.push((resource, soft, hard));
    }
    Ok(ulimits)
}

/// Map the single-port TCP rules in `rules` to `(port, access)` Landlock grants. Landlock has
/// no port range, so only single-port (`port_min == port_max`) TCP/Any rules become grants; range
/// rules are left to the BPF ACL. Used for both the connect (`CONNECT_TCP`) and bind (`BIND_TCP`)
/// ACLs so Landlock never denies what the BPF ACL permits.
fn single_port_tcp_grants(rules: &[NetRule], access: AccessNet) -> Vec<(u16, AccessNet)> {
    rules
        .iter()
        .filter(|r| matches!(r.protocol, Protocol::Tcp | Protocol::Any) && r.port_min == r.port_max)
        .map(|r| (r.port_min, access))
        .collect()
}

/// The Landlock access a read-granted path subtree receives: read files and
/// directories, plus `EXECUTE` only under the explicit `permissive-exec` (`**`)
/// opt-in.
///
/// Execution is deny-by-default (§7.3): a readable path is NOT implicitly
/// executable — otherwise the allowlist would enforce nothing (anything under a
/// read grant could run). Reads are read-only and execution is granted separately,
/// on the allowlist plus the loader's lib dirs. Only an explicit `**` exec wildcard
/// restores the open posture and re-adds `EXECUTE` to reads.
fn read_access(executable: bool) -> AccessFs {
    let base = AccessFs::READ_FILE | AccessFs::READ_DIR;
    if executable {
        base | AccessFs::EXECUTE
    } else {
        base
    }
}

/// Strip a trailing `/**` or `/*` glob from a grant entry, yielding the real
/// directory (a Landlock rule and a bind both apply to the whole subtree) or file
/// the rule applies to. A glob suffix has no inode of its own, so the bind source
/// and the post-pivot Landlock target must both key on this root — used for
/// `fs.read`/`fs.write` grants and `exec.allow` entries alike.
fn glob_root(entry: &str) -> PathBuf {
    let trimmed = entry
        .strip_suffix("/**")
        .or_else(|| entry.strip_suffix("/*"))
        .unwrap_or(entry);
    PathBuf::from(trimmed)
}

/// Whether an `exec.allow` entry is the explicit "allow all execution" wildcard
/// (`**` or `/**`) — the `permissive-exec` opt-in that restores the open,
/// pre-deny-default posture. Every other entry is a concrete path/subtree grant.
fn is_exec_wildcard(entry: &str) -> bool {
    matches!(entry.trim(), "**" | "/**")
}

/// The Landlock access a granted device node receives: read and write the file,
/// and `ioctl(2)` on it (`IOCTL_DEV`, ABI 5; [`Ruleset::allow_path`] masks the
/// bit away on older kernels). Not `EXECUTE`/`READ_DIR` — a device node is
/// neither a program nor a directory.
///
/// [`Ruleset::allow_path`]: kennel_lib_syscall::landlock::Ruleset::allow_path
fn dev_access() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::WRITE_FILE | AccessFs::IOCTL_DEV
}

/// The Landlock access a write-granted path subtree receives: read plus the
/// mutating rights (create/remove/truncate, including symlink creation).
///
/// `MAKE_SYM` is included: ordinary writable-path work (an unpack, `npm`, a build) creates
/// symlinks, and Landlock re-evaluates a symlink's *target* against the ruleset on every access,
/// so a created link cannot reach a path the policy did not grant (a link to `/etc/shadow` resolves
/// to a denied path). `MAKE_SOCK`/`MAKE_FIFO`/`MAKE_CHAR`/`MAKE_BLOCK` are deliberately omitted —
/// no writable-path workflow needs to mint those, and device nodes are the constructed `/dev`'s job.
///
/// `REFER` is included so a `rename`/`link` *between two directories* within a writable subtree
/// succeeds (without it Landlock fails such a cross-directory move with `EXDEV` — the
/// "invalid cross-device link" a temp-then-rename, e.g. skopeo's blob writer or an editor's
/// atomic save, hits). Landlock's REFER rule still forbids moving a file into a directory with
/// *broader* rights, so it cannot escalate access across the boundary of a writable subtree.
fn write_access() -> AccessFs {
    AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::WRITE_FILE
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_DIR
        | AccessFs::MAKE_SYM
        | AccessFs::REFER
        | AccessFs::REMOVE_FILE
        | AccessFs::REMOVE_DIR
        | AccessFs::TRUNCATE
}

/// Parse a settled `[ulimits]` value into `(soft, hard)`. The translator normalised
/// it to one whitespace-separated token (`soft == hard`) or two (`soft hard`), each a
/// decimal or the literal `unlimited` (→ [`RLIM_INFINITY`]). A malformed value here is
/// a compiler bug, surfaced as an invalid-policy error.
fn parse_ulimit_value(name: &str, value: &str) -> Result<(u64, u64), SpawnError> {
    let bad =
        || SpawnError::InvalidPolicy(format!("ulimit `{name}` has a malformed value `{value}`"));
    let token = |t: &str| -> Result<u64, SpawnError> {
        if t == "unlimited" {
            Ok(RLIM_INFINITY)
        } else {
            t.parse::<u64>().map_err(|_| bad())
        }
    };
    let mut parts = value.split_whitespace();
    let soft = token(parts.next().ok_or_else(bad)?)?;
    let hard = match parts.next() {
        Some(h) => token(h)?,
        None => soft,
    };
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok((soft, hard))
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
/// frames it is an ephemeral tmpfs (§7.4.5: the constructed view is scaffolding;
/// the bound content is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    /// The host path bound in.
    pub source: PathBuf,
    /// Where it appears inside the kennel (absolute, post-`pivot_root`).
    pub target: PathBuf,
    /// Writable when true; read-only (bind, then RO remount) otherwise.
    pub writable: bool,
    /// **Exclusive** (`[fs].exclusive`, §2.7, T2.8): the kennel keeps the real inode through
    /// this bind, but the factory *also* over-mounts an opaque sentinel on `source` in the
    /// operator's host namespace, so the operator and the workload cannot use the path
    /// concurrently. Released at teardown (`exclusive-unmount`). Only meaningful with `writable`.
    pub exclusive: bool,
}

/// The constructed-`$HOME` view (§7.4.5).
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
    /// Mount a per-kennel binderfs instance in the view and expose the standard
    /// `binder` device + `/dev/binder` symlink (`07-1`/`02-4`). Set when the settled
    /// `[binder]` policy is non-empty; kenneld takes node 0 via `/proc` at spawn.
    pub binder: bool,
    /// In-view absolute paths to **mask** with an empty over-mount: the workspace trust
    /// manifests (`<writable-bind>/.trust-manifest.json`, §7.4 / T2.8). The host inode is
    /// reachable through the writable bind, so the factory overmounts an empty read-only
    /// file at each, making `open()/stat()/read()` see an empty file the workload cannot
    /// use — the agent can neither read the integrity pins nor forge them. Empty when
    /// `[trust].manifest = false` or there are no writable binds.
    pub mask_paths: Vec<PathBuf>,
    /// In-view absolute paths to mask with an empty over-mounted **directory**: the trust
    /// manifest's content-addressed blob store (`<writable-bind>/.trust-manifest.d`, §2.3 /
    /// T2.8). Masked alongside the manifest so the workload can neither read the pinned blobs
    /// (a `revert` baseline / diff source) nor write into — or create — the host store. Empty
    /// when `[trust].manifest = false` or there are no writable binds.
    pub mask_dir_paths: Vec<PathBuf>,
    /// OCI substrate root (§7.11.4a / T3.8): the layered overlay's inputs, or `None` for
    /// the ordinary constructed view (a fresh `tmpfs` new-root). When `Some`, the view is a
    /// three-lower `overlay` (`kennel-etc : image : scaffold`) with the persistence tri-state
    /// choosing the upper; the host system closure is *not* mirrored (the image carries its
    /// own `/usr` layout) and `/etc` wins by layer precedence, not by a synthesised copy.
    pub image: Option<ImageRoot>,
}

/// Rootfs persistence mode (§7.11.4a): which upper the OCI overlay gets.
///
/// **Binary** — there is always an upper now (whole-tree-immutable is `[rootfs].readonly = ["/"]`
/// via Landlock, §7.11.4c, not a no-upper mount mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Persistence {
    /// An ephemeral `tmpfs` upper (under the kenneld staging dir), gone at teardown.
    #[default]
    Discard,
    /// A Kennel-managed upper under the store entry; accumulates divergence (the loud value).
    Persist,
}

impl Persistence {
    /// Parse the settled `[rootfs].persistence` string; empty (unset) ⇒ the default `Discard`.
    /// An unrecognised value never reaches here (the compiler validates it), so it maps to the
    /// safe default.
    #[must_use]
    pub fn from_settled(s: &str) -> Self {
        match s {
            "persist" => Self::Persist,
            _ => Self::Discard,
        }
    }
}

/// The OCI substrate root (§7.11.4a): the inputs the construction child assembles the overlay from.
///
/// `image` + `persistence` are policy-derived; `store_upper` is a kenneld runtime input filled at
/// bring-up (like the view staging dir), so the struct is complete before it crosses to the
/// privileged construction child. The other two lowers are built in the staging tmpfs per spawn:
/// `kennel-etc` from the synthetic `/etc` (`file_binds`), and the `scaffold` of empty mountpoint
/// dirs + `/etc` placeholders (fixed content, so it needs no shipped artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRoot {
    /// The unpacked image `rootfs/` — the overlay's read-only middle lower. **Never an upper.**
    pub image: PathBuf,
    /// The persistence mode for the upper.
    pub persistence: Persistence,
    /// The managed `(upper, work)` dirs under the store entry — `Some` iff `persistence` is
    /// `Persist`. Filled (and validated/created) by kenneld; `None` for `Discard`/`Readonly`.
    pub store_upper: Option<(PathBuf, PathBuf)>,
    /// Closure-lock (§7.11.4c): rootfs paths made **read-only mounts** over the merged root, so a
    /// write fails `EROFS`. Landlock rights are additive (a broad `/` write cannot be subtracted
    /// at `/usr`), so the executable closure is locked at the *mount* layer instead — robust
    /// because the persona workload holds no `CAP_SYS_ADMIN` to remount and `mount` is
    /// seccomp-blocked. `["/"]` makes the whole tree immutable.
    pub readonly: Vec<PathBuf>,
    /// Closure-lock holes (§7.11.4c): rootfs paths remounted **read-write** on top of a `readonly`
    /// ancestor (longest-prefix wins by mount nesting), carving a writable hole back out.
    pub writable: Vec<PathBuf>,
}

/// Remap a granted host path to where it appears inside the kennel: a path under
/// the real `$HOME` moves beneath `shim_root`; any other absolute path keeps its
/// own location in the new root.
fn remap_target(path: &Path, home: &Path, shim_root: &Path) -> PathBuf {
    path.strip_prefix(home)
        .map_or_else(|_| path.to_path_buf(), |rel| shim_root.join(rel))
}

/// Whether `path` is served by a constructed/special mount and so is *not* bound
/// from the host: the synthetic `/etc`, or the freshly-mounted namespaced `/proc`.
/// A read grant under either still gets its Landlock rule (on the constructed inode,
/// post-pivot) — it just must not bind the host's version over it (which for `/proc`
/// would recursively bind the host's whole procfs before the fresh mount shadows it).
/// Matches on a component boundary (`/etcfoo` / `/procfoo` do not match).
fn is_special_mount(path: &Path) -> bool {
    path.starts_with("/etc") || path.starts_with("/proc")
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
    /// Namespaces the spawn unshares. The network namespace is unshared for
    /// every mode except `host`: a proxied (`constrained`/`unconstrained`) or
    /// `none` kennel gets its own net-ns (the only egress path is the binder
    /// gateway), while `host` shares the host stack and is confined by cgroup
    /// BPF + Landlock instead. See the comment on the unshare set below.
    pub namespaces: Namespaces,
    /// The per-kennel cgroup the workload joins and the BPF programs attach to.
    pub cgroup: PathBuf,
    /// Whether to **birth** the kennel into [`cgroup`](Self::cgroup): the privhelper factory passes the
    /// cgroup fd to `clone3(CLONE_INTO_CGROUP)`, so the kennel's PID 1 is created *already inside* the
    /// cgroup — no post-clone `cgroup.procs` migration, which would block on the
    /// `cgroup_threadgroup_rwsem` RCU grace period (the ~13 ms construction cost W10 removed). The
    /// factory selects the birth path on this flag (`kennel-privhelper::construct`: `Some(cgroup) →
    /// clone_pid1_in_cgroup`, `None → clone_pid1` with no cgroup). True for policy-derived plans; it
    /// works because the kennel cgroup is a descendant of kenneld's delegated `user@<uid>` subtree
    /// (`08-enforcement-architecture.md` §8.5).
    pub cgroup_join: bool,
    /// The constructed-`$HOME` view (§7.4.5) the mount seal builds before
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
    /// Syscall numbers the seccomp filter denies (resolved from the policy's deny
    /// names via `kennel_lib_syscall::seccomp::syscall_number`). Empty ⇒ no filter.
    pub seccomp_deny: Vec<i64>,
    /// The seccomp action applied to a denied syscall.
    pub seccomp_deny_action: Action,
    /// BPF `allow_v4` LPM entries for the egress allowlist.
    pub bpf_allow_v4: Vec<LpmV4Entry>,
    /// BPF `deny_v4` LPM entries (invariant deny CIDRs), consulted deny-first.
    pub bpf_deny_v4: Vec<LpmV4Entry>,
    /// BPF `allow_v6` LPM entries for the egress allowlist.
    pub bpf_allow_v6: Vec<LpmV6Entry>,
    /// BPF `deny_v6` LPM entries (invariant deny CIDRs), consulted deny-first.
    pub bpf_deny_v6: Vec<LpmV6Entry>,
    /// BPF `bind_allow_v4` LPM entries — the inbound BIND ACL allowlist (§7.5.7). Seeded
    /// with the kennel's own loopback /28 (so in-subnet/wildcard binds stay allowed) plus
    /// the author's `[net.bpf].bind.allow` rules. Default-deny: a bind missing this is denied.
    pub bpf_bind_allow_v4: Vec<LpmV4Entry>,
    /// BPF `bind_deny_v4` LPM entries — the author's `[net.bpf].bind.deny`, consulted deny-first.
    pub bpf_bind_deny_v4: Vec<LpmV4Entry>,
    /// BPF `bind_allow_v6` LPM entries (the v6 bind allowlist; see `bpf_bind_allow_v4`).
    pub bpf_bind_allow_v6: Vec<LpmV6Entry>,
    /// BPF `bind_deny_v6` LPM entries (the v6 bind denylist; see `bpf_bind_deny_v4`).
    pub bpf_bind_deny_v6: Vec<LpmV6Entry>,
    /// The `kennel_meta` map value (64 bytes) for `kennel_meta_map[0]`.
    pub bpf_meta: [u8; 64],
    /// The bind-port allowlist (`[net.bind].allowed_ports`, §7.5.7) to write into the
    /// `bind_subnet` map (host order). Empty ⇒ any port at or above the floor. The
    /// `min_port` floor itself rides `bpf_meta`; this is the explicit set.
    pub bind_allowed_ports: Vec<u16>,
    /// Single-file bind mounts `(source, target)` applied read-only in the mount
    /// seal, after the root is made private and `/proc`/`/tmp` are mounted. Used to
    /// shadow individual files (the synthetic `/etc` set) over their host
    /// counterparts in the kennel's view; a target that does not exist is skipped.
    /// Not derived from policy — kenneld populates it at bring-up with the
    /// per-kennel staged files.
    pub file_binds: Vec<(PathBuf, PathBuf)>,
    /// The supplementary group IDs the workload retains (§7.4). `Some(gids)` makes the
    /// privileged seal `setgroups` to **exactly** these (empty ⇒ drop all inherited
    /// host groups); `None` leaves the inherited set untouched (the unprivileged /
    /// non-kenneld path). The names are resolved to GIDs and membership-checked by
    /// kenneld (the host-runtime gate), so this carries only already-verified GIDs.
    pub supplementary_groups: Option<Vec<u32>>,
    /// Resource limits applied via `setrlimit(2)` in the seal, just before `execve`
    /// (after Landlock — lowering `RLIMIT_NOFILE` must not starve the rule-building
    /// opens). Each entry is `(resource, soft, hard)`; [`RLIM_INFINITY`] is unlimited.
    /// Derived from the settled `[ulimits]`; empty ⇒ nothing applied.
    pub ulimits: Vec<(Resource, u64, u64)>,
    /// Interactive controlling-terminal hand-off (§7.9.2): the raw fd of a connected
    /// socket over which the seal returns a freshly-allocated controlling pty's
    /// master. `Some` for an interactive `kennel run` — the seal allocates the pty
    /// from the kennel's own (post-`pivot_root`) `devpts` so `ttyname(3)` resolves it,
    /// then sends the master back for the CLI to proxy. `None` (the default) keeps the
    /// non-interactive path, where stdio is whatever the controller passed. Not
    /// policy-derived — kenneld sets it at bring-up, like [`new_root`](Self::new_root).
    pub interactive_return_fd: Option<RawFd>,
    /// The sha256-pinned workload binary fd kenneld opened + hashed, to be placed at
    /// [`WORKLOAD_FD`] for `kennel-bin-init` to `fexecve` (the TOCTOU fix, §7.4). `Some`
    /// only when the policy pins the workload's digest; `None` (the default) keeps the
    /// resolve-and-execve path. Not policy-derived — kenneld sets it at bring-up.
    ///
    /// [`WORKLOAD_FD`]: kennel_lib_syscall::boot::WORKLOAD_FD
    pub workload_fd: Option<RawFd>,
    /// The workload's injected stdin/stdout/stderr fds for a **non-interactive** run (`02-10` §7.12):
    /// a piped `kennel run`'s three controller fds, or a `SPAWN` channel's spawned ends. kenneld
    /// passes them through construction; the factory places them at
    /// [`INJECT_STDIN_FD`]/[`INJECT_STDOUT_FD`]/[`INJECT_STDERR_FD`] and `kennel-bin-init` `dup2`s
    /// them onto 0/1/2 after the seal. `None` (the default) keeps the inherit-controller-stdio path;
    /// mutually exclusive with [`interactive_return_fd`](Self::interactive_return_fd) (the pty path).
    /// Not policy-derived — kenneld sets it at bring-up.
    ///
    /// [`INJECT_STDIN_FD`]: kennel_lib_syscall::boot::INJECT_STDIN_FD
    /// [`INJECT_STDOUT_FD`]: kennel_lib_syscall::boot::INJECT_STDOUT_FD
    /// [`INJECT_STDERR_FD`]: kennel_lib_syscall::boot::INJECT_STDERR_FD
    pub stdio_fds: Option<[RawFd; 3]>,
    /// Auxiliary processes to launch inside the kennel, in the seal after Landlock and
    /// before the workload `execve`, so they inherit the confined environment and die
    /// with the kennel's PID namespace (`07-1` §7.1.5). Used for the in-kennel proxies
    /// (e.g. `facade-afunix`). Each binary must be bound into the view and granted
    /// Landlock execute. Not policy-derived — kenneld sets it at bring-up.
    pub aux: Vec<AuxProcess>,
    /// The kennel's time-to-live in seconds (`[lifecycle].ttl`); `None` ⇒ no TTL. `kennel-bin-init`
    /// runs the timer (it rides the supervision-half) and, at expiry, makes a blocking binder
    /// call to kenneld to suspend-or-stop the kennel (§9.7; the cgroup freezer).
    pub ttl_seconds: Option<u64>,
    /// What kenneld does when the TTL expires (`[lifecycle].on-expiry`): freeze + warn/renew
    /// (resume) or terminate. Decided kenneld-side (it owns the cgroup), so it rides the binder
    /// lifecycle, not the supervision-half.
    pub ttl_action: kennel_lib_policy::TtlAction,
}

/// An auxiliary in-kennel process launched by the seal (a binary path in the view and
/// its argument vector, `argv[0]` excluded — the path is used as `argv[0]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxProcess {
    /// The binary's path *inside the view* (bound in, Landlock-execute-granted).
    pub path: PathBuf,
    /// Arguments after `argv[0]`.
    pub args: Vec<String>,
}

/// The **supervision-half** of a kennel's enforcement (`07-2-kennel-bin-init.md` §7.2.3).
///
/// Everything `kennel-bin-init` needs to spawn and confine the workload from *inside* the
/// already-constructed, pivoted view.
///
/// The [`Plan`] is split three ways (`kennel-bin-init-and-uid0`): `kenneld` holds the full
/// plan, the **construction-half** goes to the privhelper factory (namespaces, maps,
/// view, binderfs, pivot — applied *before* `kennel-bin-init` exists), and this
/// supervision-half is what `kennel-bin-init` pulls back over binder (`GET_SANDBOX_PLAN`).
/// It is a **distinct struct, not the whole `Plan`**, so the contained root parser sees
/// only its own half — never the construction data — and so it can carry the workload
/// program/argv/env the `Plan` never held (the old in-process path passed those as a
/// separate [`std::process::Command`]).
///
/// `kennel-bin-init` runs as the kennel's uid-0 PID 1 and forks each facade and the
/// workload, dropping every one to the masked operator identity
/// (`drop_gid`/`groups`/`drop_uid`, in that order) before `execve`. The facades exec
/// unconfined (they must reach the bus); the workload additionally gets
/// `no_new_privs` + seccomp + Landlock + ulimits + the pty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supervision {
    /// The workload binary's path *inside the view*.
    pub program: PathBuf,
    /// The workload's full argument vector, **including** `argv[0]`.
    pub argv: Vec<String>,
    /// The fully-synthesised environment (`execve` replaces the env wholesale, so this
    /// is the complete set — there is no inheritance to clear, `run-environment-design`).
    pub env: Vec<(String, String)>,
    /// The workload's working directory (`kennel-bin-init` `chdir`s here before `execve`);
    /// `None` keeps the inherited cwd (the view root).
    pub cwd: Option<std::path::PathBuf>,
    /// The masked operator uid every child is dropped to (`set_uid`, last in the drop).
    pub drop_uid: u32,
    /// The masked operator gid every child is dropped to (`set_gid`, first in the drop).
    pub drop_gid: u32,
    /// Supplementary groups for the drop: `Some(set)` calls `setgroups` (the granted
    /// groups, §7.4; `Some(&[])` drops all), `None` leaves the inherited set.
    pub groups: Option<Vec<u32>>,
    /// The workload's Landlock filesystem rules (built post-pivot with `skip_missing`).
    pub landlock_fs: Vec<(PathBuf, AccessFs)>,
    /// The workload's Landlock network-port rules.
    pub landlock_net: Vec<(u16, AccessNet)>,
    /// The workload's seccomp denylist (syscall numbers); empty ⇒ no filter.
    pub seccomp_deny: Vec<i64>,
    /// The action a denied syscall triggers.
    pub seccomp_deny_action: Action,
    /// The workload's resource limits (`setrlimit`), applied last before `execve`.
    pub ulimits: Vec<(Resource, u64, u64)>,
    /// The facades to launch (af-unix proxy, future socks5/dbus), each forked and
    /// dropped to the operator but **not** confined.
    pub aux: Vec<AuxProcess>,
    /// Whether a controlling-pty fd accompanies the reply (a `BINDER_TYPE_FD` object);
    /// the real fd is injected out of band, never serialised (see [`crate::wire`]).
    pub interactive: bool,
    /// Whether the workload binary is sha256-pinned: kenneld opened+hashed it and passed the
    /// fd at [`WORKLOAD_FD`], which `kennel-bin-init` `fexecve`s instead of resolving a path
    /// (the TOCTOU fix, §7.4). The fd rides out of band; this is the presence flag.
    ///
    /// [`WORKLOAD_FD`]: kennel_lib_syscall::boot::WORKLOAD_FD
    pub workload_fd_pinned: bool,
    /// Whether the workload's stdio is **injected** (a non-interactive run, `02-10` §7.12): three fds
    /// ride out of band at `INJECT_STDIN_FD`/`INJECT_STDOUT_FD`/`INJECT_STDERR_FD`, and
    /// `kennel-bin-init` `dup2`s them onto 0/1/2 as the final pre-exec step instead of adopting the
    /// inherited stdin as a controlling tty. Mutually exclusive with [`interactive`](Self::interactive)
    /// (the pty path). This is the presence flag; the fds are out of band.
    pub stdio_injected: bool,
    /// The kennel's TTL in seconds (`None` ⇒ none). `kennel-bin-init` runs this timer and, at
    /// expiry, makes a blocking `NOTIFY_TTL_EXPIRED` binder call to kenneld, which freezes the
    /// cgroup and decides whether to resume or terminate (§9.7). The action itself is decided
    /// kenneld-side, so it is not carried here.
    pub ttl_seconds: Option<u64>,
    /// The spawn-path diagnostic verbosity (`log_level`, as `kennel_lib_config::LogLevel as u8`:
    /// 0=info, 1=debug, 2=trace). `kennel-bin-init` runs with an empty argv/envp and is
    /// post-`pivot_root`, so it cannot read `system.toml` itself — kenneld threads the level here,
    /// over the supervision-half init pulls, so init's seal/spawn/supervise steps can trace to its
    /// (inherited, journald-bound) stderr. 0 ⇒ errors only, as before.
    pub log_level: u8,
}

impl Supervision {
    /// Build the workload's seccomp [`Filter`] from the denylist (mirrors
    /// [`Plan::seccomp_filter`]). Not installed until `Filter::install` runs in the
    /// drop seal.
    #[must_use]
    pub fn seccomp_filter(&self) -> Filter {
        Filter::denylist(&self.seccomp_deny, self.seccomp_deny_action)
    }
}

/// The **construction-half** of a kennel's enforcement (`07-2-kennel-bin-init.md` §7.2.1).
///
/// Everything the **privhelper factory** needs to build the kennel host-side, in its own
/// post-`clone` child, *before* `kennel-bin-init` exists: the namespaces to enter, the
/// identity maps, the cgroup to join, the in-namespace loopback, the view to construct +
/// `pivot_root` into, and whether to mount + chown the per-kennel binderfs. The factory
/// parses **only** this half (never the supervision-half), so a decoder bug there cannot
/// reach the workload's confinement policy.
///
/// The operator uid/gid for the identity map are deliberately **absent**: the factory
/// uses its own real uid/gid (the caller's, since `kenneld` `execve`s it), never a
/// wire-supplied value (`kennel-bin-init-and-uid0`, security review §6). The granted
/// supplementary `gids` are carried (they are policy) but re-validated host-side against
/// the caller's membership before any map is written.
// allow(struct_excessive_bools): a wire/data DTO, not a state machine — each bool is an
// independent construction directive the factory reads (cgroup_join, lo, the two fd flags).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructionHalf {
    /// The namespaces the factory `clone`s with (`USER|MOUNT|PID|IPC[|NET]`).
    pub namespaces: Namespaces,
    /// The kennel's cgroup; the factory writes the construction child's pid into its
    /// `cgroup.procs` (re-validated against the caller's delegated subtree).
    pub cgroup: PathBuf,
    /// Whether to join the cgroup (mirrors [`Plan::cgroup_join`]).
    pub cgroup_join: bool,
    /// The constructed view to build and `pivot_root` into; `None` ⇒ the fallback
    /// in-place path (fresh `/proc` + `/tmp`).
    pub view: Option<ShimView>,
    /// The fresh root the view is staged under before the pivot.
    pub new_root: Option<PathBuf>,
    /// Single-file shadow binds (`(source, target)`) applied into the view.
    pub file_binds: Vec<(PathBuf, PathBuf)>,
    /// The granted supplementary gids to identity-map (after the `0 0 1` and operator
    /// lines); each re-checked against the caller's membership before the `gid_map` write.
    pub granted_gids: Vec<u32>,
    /// Whether to bring up the in-namespace loopback (`lo`) — set for a proxied
    /// (`constrained`/`unconstrained`) kennel, which has its own net-ns *and* loopback
    /// addresses. `false` for `none` (own net-ns but no addresses) and `host` (shares the
    /// host net-ns, so there is no in-namespace `lo` to bring up).
    pub lo: bool,
    /// The kennel's context number — re-supplied so the factory can re-validate each
    /// [`loopback`](Self::loopback) address against the caller's reserved per-kennel subnet.
    pub ctx: u16,
    /// The per-kennel loopback addresses to add on host `lo` (`127.<tag>.<ctx>.x/28` and
    /// `fd<gid>:<tag>:<ctx>::/64`). The factory adds these itself (folding the former
    /// separate `add-addr` privhelper ops into the one `construct` op), re-validating each is
    /// within the caller's reserved scope before the netlink add. Empty ⇒ no loopback adds.
    pub loopback: Vec<LoopbackAddr>,
    /// Whether an interactive controlling-pty return socket accompanies the construction
    /// datagram as an `SCM_RIGHTS` fd (placed at [`PTY_RETURN_FD`]). The factory needs
    /// this — it decodes the half but forwards the supervision-half (which holds the workload
    /// flag) opaquely — to know which inherited fds to place. The fds travel in a fixed order:
    /// pty (if any) then workload (if any).
    ///
    /// [`PTY_RETURN_FD`]: kennel_lib_syscall::pty::PTY_RETURN_FD
    pub pty_fd_present: bool,
    /// Whether the sha256-pinned workload binary fd accompanies the datagram, to be placed at
    /// [`WORKLOAD_FD`] for `kennel-bin-init` to `fexecve` (§7.4).
    ///
    /// [`WORKLOAD_FD`]: kennel_lib_syscall::boot::WORKLOAD_FD
    pub workload_fd_present: bool,
    /// Whether three **injected-stdio** fds accompany the datagram, to be placed at
    /// `INJECT_STDIN_FD`/`INJECT_STDOUT_FD`/`INJECT_STDERR_FD` for `kennel-bin-init` to `dup2` onto
    /// 0/1/2 (`02-10` §7.12). They travel last in the fixed fd order: pty, workload, then stdio×3.
    pub stdio_present: bool,
}

/// A per-kennel loopback address for the factory to add on host `lo` (§7.3).
///
/// Carries the address and its fixed family prefix. The interface is always `lo` (the
/// shared-net-namespace path); the factory re-validates the address is inside the caller's
/// reserved subnet before the netlink add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackAddr {
    /// The loopback address (v4 or v6).
    pub addr: std::net::IpAddr,
    /// The subnet prefix length (28 for v4, 64 for v6).
    pub prefix: u8,
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
    // allow: one cohesive policy→plan translation (namespaces, fs view, exec gate,
    // landlock, seccomp, BPF); splitting it would only scatter the shared locals.
    #[allow(clippy::too_many_lines)]
    pub fn from_policy(
        policy: &SettledPolicy,
        ctx: u16,
        namespace: &str,
        home: &Path,
    ) -> Result<Self, SpawnError> {
        let ep = &policy.effective_policy;

        // The unprivileged spawn: USER establishes the identity-mapped user
        // namespace (granting CAP_SYS_ADMIN within it) so MOUNT/IPC/PID and the
        // mount/pivot_root need no real privilege; `kennel-bin-init` is the kennel's PID 1
        // (it mounts the fresh /proc and forks the workload). NET is unshared for every mode
        // EXCEPT `host`: a proxied kennel (`constrained`/`unconstrained`) gets its own net-ns
        // with an in-ns `lo` carrying the proxy's loopback alias (the only path out is the
        // binder gateway); `none` gets an own EMPTY net-ns (no interfaces). `host` deliberately
        // shares the HOST net-ns for direct egress, gated by cgroup BPF + Landlock.
        let mut namespaces =
            Namespaces::USER | Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC;
        if ep.net.mode != NetMode::Host {
            namespaces |= Namespaces::NET;
        }

        let cgroup = PathBuf::from(format!("/sys/fs/cgroup/{namespace}/{ctx}"));

        // The in-view `$HOME`: a normal non-system user's home, `/home/<user>` (the
        // masked `[identity].user`, default `kennel`). `~/…` grants remap beneath it.
        let shim_root = PathBuf::from(format!("/home/{}", policy.identity.user));

        // Classify every granted path once. The in-kennel target — `~/…` paths
        // remap beneath `shim_root`, `/etc` is the constructed synthetic set, any
        // other absolute path keeps its place — drives both the Landlock rule and
        // the bind mount. Landlock is sealed AFTER `pivot_root`, so it references
        // the post-pivot target, not the host source. `/etc` gets a Landlock rule
        // (on the constructed `/etc`) but no bind (it is built, not bound).
        let mut landlock_fs: Vec<(PathBuf, AccessFs)> = Vec::new();
        let mut binds: Vec<BindMount> = Vec::new();
        // Deny-by-default execution (§7.3), matching fs (allow-only) and net
        // (`constrained` permits nothing): the allowlist is ALWAYS enforced — a merely
        // readable file is NOT implicitly executable. Execution is granted only to the
        // allowlisted binaries plus the loader's lib dirs; an empty allowlist denies
        // ALL execution (so a bare `base-confined` cannot run anything). The sole
        // escape hatch is an explicit `**` entry — the `permissive-exec` opt-in — which
        // restores the open posture (reads carry EXECUTE, nothing is gated).
        let permissive_exec = ep.exec.allow.iter().any(|e| is_exec_wildcard(e));
        // A path is, at the end of the day, ONE bind mount with one mode. `fs.read`/`fs.write` only
        // express which mode; the implied rule (translate) already folds every write path into read,
        // so a writable path appears in both lists. Collapse to one entry per glob-stripped source,
        // writable iff it is in `fs.write` (write wins — read is subsumed). Then mount **shortest
        // path first**, so a broad parent grant lands before a more-specific child and the child
        // (e.g. a writable subtree inside a read-only tree) nests on top deterministically.
        //
        // A read/write grant may use a `/**` or `/*` glob (e.g. `/usr/**`); the bind source and
        // Landlock target must be the real directory root — the literal glob has no inode, so
        // binding it is `ENOENT` and the Landlock rule would be dropped by skip-missing. Strip it.
        let mut fs_grants: Vec<(PathBuf, bool)> = Vec::new();
        for (path_str, writable) in ep
            .fs
            .read
            .iter()
            .map(|p| (p, false))
            .chain(ep.fs.write.iter().map(|p| (p, true)))
        {
            let source = glob_root(path_str);
            if let Some(existing) = fs_grants.iter_mut().find(|(s, _)| *s == source) {
                existing.1 |= writable; // a path in both read and write is writable
            } else {
                fs_grants.push((source, writable));
            }
        }
        // The exclusive sources (§2.7), transformed identically to the bind sources so they
        // match: `exclusive` is a subset of `write`, so `glob_root` of each yields the same
        // source path the writable bind carries.
        let exclusive_sources: std::collections::BTreeSet<PathBuf> =
            ep.fs.exclusive.iter().map(|p| glob_root(p)).collect();
        // Shortest source path first (parent before child). Stable: equal-length paths keep their
        // first-seen order, so the result is deterministic.
        fs_grants.sort_by_key(|(s, _)| s.as_os_str().len());
        for (source, writable) in fs_grants {
            let target = remap_target(&source, home, &shim_root);
            landlock_fs.push((
                target.clone(),
                if writable {
                    write_access()
                } else {
                    read_access(permissive_exec)
                },
            ));
            if !is_special_mount(&source) {
                let exclusive = writable && exclusive_sources.contains(&source);
                binds.push(BindMount {
                    source,
                    target,
                    writable,
                    exclusive,
                });
            }
        }

        // The execution gate (§7.3): grant FS_EXECUTE on the allowlisted binaries and on
        // each one's dynamic loader (`PT_INTERP`/`ld.so`, resolved at compile time into
        // `exec.loaders`). Both are needed because the kernel opens a dynamic binary AND its
        // loader `FMODE_EXEC` during `execve`, which Landlock gates. The binaries' shared
        // libraries are deliberately NOT granted EXECUTE: the loader `mmap`s them and
        // Landlock has no `mmap` hook, so they load via READ alone (07-3-exec) — granting
        // execute would be unenforceable, so the kennel makes no such claim. Skipped under
        // `permissive-exec` (`**`), where reads already carry EXECUTE.
        let exec_access = AccessFs::EXECUTE | AccessFs::READ_FILE;
        if !permissive_exec {
            for entry in &ep.exec.allow {
                let root = glob_root(entry);
                // deny_writable (§7.3): a writable path must never be executable.
                if ep.exec.deny_writable
                    && ep
                        .fs
                        .write
                        .iter()
                        .any(|w| root.starts_with(PathBuf::from(w.as_str())))
                {
                    return Err(SpawnError::InvalidPolicy(format!(
                        "exec.allow `{entry}` lies under a writable path, but deny_writable is set"
                    )));
                }
                landlock_fs.push((remap_target(&root, home, &shim_root), exec_access));
            }
            // The resolved dynamic loaders (each allowlisted binary's PT_INTERP): exact
            // paths settled at compile time. `skip_missing` drops any the view omits.
            for loader in &ep.exec.loaders {
                landlock_fs.push((
                    remap_target(Path::new(loader), home, &shim_root),
                    exec_access,
                ));
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
            // A device grant may use a `/**`/`/*` glob (e.g. `/dev/pts/**` for the ptys);
            // strip it to the real node/dir — `/dev/pts` is mounted as a fresh devpts in
            // the view, every other entry is bound as a single node.
            let path = glob_root(d.as_str());
            if !is_safe_dev_path(&path) {
                return Err(SpawnError::InvalidPolicy(format!(
                    "fs.dev.allow entry must be a device under /dev, got `{d}`"
                )));
            }
            // Grant the device its Landlock access too, not just view visibility:
            // read/write plus `ioctl` (IOCTL_DEV). The ruleset handles IOCTL_DEV on
            // ABI >= 5, so without an explicit grant here a device `ioctl` (a tty
            // TCGETS/TIOCGWINSZ, §7.9.2) is denied even on an allowlisted node;
            // the grant makes the allowed devices usable while every non-granted
            // device — and the gated ioctls on them — stays denied.
            landlock_fs.push((path.clone(), dev_access()));
            dev_allow.push(path);
        }

        // The constructed `$HOME` is writable by default (§7.4.3): grant Landlock
        // write on the home root so the workload owns its home like any ordinary
        // user. Its safety is that it is a *fresh tmpfs* — ephemeral, reconstructed
        // each spawn, so nothing written here survives unless a path is opted into
        // persistence via `[fs.home].persist` (which binds the real host inode,
        // read-write, beneath the home). Read-only project binds beneath the home
        // stay read-only at the VFS layer (`MS_RDONLY` remount). `write_access()`
        // omits `EXECUTE` (so the home is not an `execve` target), but that is not an
        // execution barrier — an allowlisted interpreter reads a script as data
        // (`sh script`, `python evil.py`), needing no `EXECUTE` on it. `[fs.home].readonly`
        // suppresses the grant (escape hatch), leaving only `write`-granted `~/` paths
        // writable.
        if !ep.fs.home_readonly {
            landlock_fs.push((shim_root.clone(), write_access()));
        }

        // The workload's own scratch space: the private `/tmp` is a fresh, ephemeral
        // tmpfs each spawn, so grant it read+write+list. Without this the mounted
        // `/tmp` is present but unusable (no Landlock grant) — `mktemp`, build scratch,
        // and even `ls /tmp` would be denied.
        if ep.fs.tmp.private {
            landlock_fs.push((PathBuf::from("/tmp"), write_access()));
        }
        // The view-root grant. For a constructed view: READ_DIR on `/` only (`ls /`; the
        // top-level entries are not sensitive and their contents stay separately gated).
        //
        // For an OCI image root: the substrate base. The unprivileged `oci build` flattens every
        // image inode to the one persona uid, so the flattened rootfs is read+write+execute by
        // default (the flatten made DAC vacuous; there is no boundary to assert on an unlisted
        // path). Landlock grants the broad writable substrate here — `/` read+write+execute — and
        // the **closure-lock is enforced at the mount layer** (`[rootfs].readonly` → read-only
        // mounts in the construction child, §7.11.4c), because Landlock rights are additive: a `/`
        // write cannot be subtracted at `/usr`. Read-only `[fs.read]` binds and the T2.8 masks are
        // likewise read-only *mounts*, so this broad Landlock grant does not make them writable.
        if policy.rootfs.path.is_empty() {
            landlock_fs.push((PathBuf::from("/"), AccessFs::READ_DIR));
        } else {
            landlock_fs.push((PathBuf::from("/"), write_access() | AccessFs::EXECUTE));
        }

        // Binder IPC (07-1/02-4): the binder bus is the universal control plane — every
        // kennel mounts a per-kennel binderfs instance so `kennel-bin-init` can pull its
        // supervision-half over node 0, whether or not the policy grants any IPC facade. The
        // workload always gets its standard `binder` device (read/write/ioctl) and read of
        // the binderfs dir + features; `binder-control` is never granted (only the factory
        // allocates devices).
        landlock_fs.push((PathBuf::from("/dev/binderfs/binder"), dev_access()));
        landlock_fs.push((PathBuf::from("/dev/binderfs"), AccessFs::READ_DIR));
        landlock_fs.push((
            PathBuf::from("/dev/binderfs/features"),
            AccessFs::READ_DIR | AccessFs::READ_FILE,
        ));

        // Mask the workspace trust manifest (§7.4 / T2.8): at each writable bind's root the
        // host `.trust-manifest.json` is reachable through the bind, so the factory
        // overmounts an empty file there — the workload can neither read the integrity pins
        // nor forge them, while the host IDE reads the untouched real inode. Gated by
        // `[trust].manifest` (default on); only writable binds carry a manifest. The mask
        // target keys on the bind *target* (the in-kennel path).
        let (mask_paths, mask_dir_paths): (Vec<PathBuf>, Vec<PathBuf>) = if ep.trust.manifest {
            let writable = || binds.iter().filter(|b| b.writable);
            (
                writable()
                    .map(|b| b.target.join(".trust-manifest.json"))
                    .collect(),
                // The blob store beside the manifest (kennel-lib-manifest STORE_DIRNAME);
                // hardcoded here like the manifest filename to keep it off the spawn crate's deps.
                writable()
                    .map(|b| b.target.join(".trust-manifest.d"))
                    .collect(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        let view = Some(ShimView {
            shim_root,
            binds,
            dev_allow,
            tmp_size_mib: ep.fs.tmp.size_mib,
            tmp_mode: ep.fs.tmp.mode.clone(),
            proc_hidepid: ep.proc.hidepid,
            binder: true,
            mask_paths,
            mask_dir_paths,
            // OCI-model policy (§7.11.4a): a non-empty `[rootfs].path` boots the image as the
            // overlay's middle lower. The translate step subst-resolved it to an absolute host
            // path; empty means an ordinary constructed view. `scaffold`/`store_upper` are
            // kenneld runtime inputs filled at bring-up (the staging dir is set the same way).
            image: (!policy.rootfs.path.is_empty()).then(|| ImageRoot {
                image: PathBuf::from(&policy.rootfs.path),
                persistence: Persistence::from_settled(&policy.rootfs.persistence),
                store_upper: None,
                // Closure-lock paths are enforced as read-only mounts in the construction child
                // (§7.11.4c) — `glob_root`-stripped so a `/usr/**` entry keys on `/usr`.
                readonly: policy
                    .rootfs
                    .readonly
                    .iter()
                    .map(|p| glob_root(p))
                    .collect(),
                writable: policy
                    .rootfs
                    .writable
                    .iter()
                    .map(|p| glob_root(p))
                    .collect(),
            }),
        });

        // Landlock net expresses per-port CONNECT_TCP allow only (no CIDR, no deny — BPF is the
        // authoritative gate; Landlock is defence-in-depth). In `host` mode map the author's
        // `[net.bpf].connect.allow` single-port TCP rules so Landlock does not deny what BPF
        // permits. In the proxied modes the workload connects only to the proxy port, which
        // `stamp_proxy` grants; `none` has no network. So the base is non-empty only for `host`.
        let mut landlock_net: Vec<(u16, AccessNet)> = Vec::new();

        let seccomp_deny_action = match ep.seccomp.deny_action {
            SeccompAction::Errno => Action::Errno(EPERM),
            SeccompAction::KillThread => Action::KillThread,
            SeccompAction::KillProcess => Action::KillProcess,
        };
        // Resolve deny names → numbers on this arch; unknown names are skipped
        // (seccomp is defence-in-depth under Landlock + the cgroup BPF).
        let seccomp_deny: Vec<i64> = ep
            .seccomp
            .deny
            .iter()
            .filter_map(|name| kennel_lib_syscall::seccomp::syscall_number(name))
            .collect();

        let ulimits = resolve_ulimits(policy)?;

        // The cgroup-BPF connect + bind ACLs (§7.5.4/§7.5.7), default-deny + deny-first —
        // see `BpfAcls::from_policy` for the per-mode allow/deny composition.
        let acls = BpfAcls::from_policy(&ep.net)?;
        // A single-port TCP allow needs the matching Landlock grant or Landlock denies what the
        // BPF ACL permits. Connect grants only in `host` mode (proxied modes reach only the proxy
        // endpoint, granted by `stamp_proxy`); bind grants in every mode.
        if ep.net.mode == NetMode::Host {
            landlock_net.extend(single_port_tcp_grants(
                &ep.net.bpf_connect_allow,
                AccessNet::CONNECT_TCP,
            ));
        }
        landlock_net.extend(single_port_tcp_grants(
            &ep.net.bpf_bind_allow,
            AccessNet::BIND_TCP,
        ));

        // The bind floor (§7.5.7): stamped into the kennel_meta `bind_port_min` slot
        // so the bind4/bind6 BPF can deny a privileged-port bind (T6).
        let mut bpf_meta = meta_bytes(ctx);
        stamp_bind_port_min(&mut bpf_meta, ep.net.bind_port_min);

        Ok(Self {
            namespaces,
            cgroup,
            cgroup_join: true,
            view,
            new_root: None,
            landlock_fs,
            landlock_net,
            seccomp_deny,
            seccomp_deny_action,
            bpf_allow_v4: acls.allow_v4,
            bpf_deny_v4: acls.deny_v4,
            bpf_allow_v6: acls.allow_v6,
            bpf_deny_v6: acls.deny_v6,
            bpf_bind_allow_v4: acls.bind_allow_v4,
            bpf_bind_deny_v4: acls.bind_deny_v4,
            bpf_bind_allow_v6: acls.bind_allow_v6,
            bpf_bind_deny_v6: acls.bind_deny_v6,
            bpf_meta,
            bind_allowed_ports: ep.net.bind_allowed_ports.clone(),
            file_binds: Vec::new(),
            supplementary_groups: None,
            ulimits,
            interactive_return_fd: None,
            workload_fd: None,
            stdio_fds: None,
            aux: Vec::new(),
            ttl_seconds: ep.lifecycle.ttl_seconds,
            ttl_action: ep.lifecycle.ttl_action,
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

        // The kennel's own loopback is one trust domain in one net-ns: the proxy listener, the
        // workload's mirrored listeners (§7.5.7), and any intra-kennel loopback service all live on
        // it. Grant a SINGLE `/32` CONNECT entry on that exact address with ANY port and the
        // FLAG_PROXY marker. A /32 is the longest prefix, so it wins LPM cleanly — a coarser /28
        // seed would lose to this /32 and re-introduce the proxy entry's port restriction, which is
        // exactly the bug that blocked facade-client → workload (it dials a non-proxy port).
        let own_loopback = allow_entry(0, u16::MAX, Protocol::Any, KENNEL_ALLOW_FLAG_PROXY);
        if let Some(v4) = endpoint.v4 {
            self.bpf_allow_v4
                .push((lpm_v4_key(v4.octets(), HOST_PREFIX_V4), own_loopback));
        }
        self.bpf_allow_v6.push((
            lpm_v6_key(endpoint.v6.octets(), HOST_PREFIX_V6),
            own_loopback,
        ));

        // Landlock always handles net; the workload reaches its proxy endpoint at the proxy port,
        // so grant CONNECT_TCP there (the per-mirror-port CONNECT_TCP grants are added by
        // apply_facade_client). Without it Landlock denies the connect the BPF ACL permits.
        if !self.landlock_net.iter().any(|(p, _)| *p == endpoint.port) {
            self.landlock_net
                .push((endpoint.port, AccessNet::CONNECT_TCP));
        }

        // Seed the kennel's own loopback subnet (§7.5.6) into the inbound BIND ACL: a proxied
        // kennel rewrites a wildcard bind to this loopback and allows in-subnet binds, so the
        // subnet must pass the (default-deny) bind ACL without an author rule. A full port range
        // over the /28 (v4) / /64 (v6); the bind ACL is deny-first, so an author deny still wins.
        let any_port = allow_entry(0, u16::MAX, Protocol::Any, 0);
        if let Some(v4) = endpoint.v4 {
            self.bpf_bind_allow_v4
                .push((lpm_v4_key(v4.octets(), LOOPBACK_PREFIX_V4), any_port));
        }
        self.bpf_bind_allow_v6.push((
            lpm_v6_key(endpoint.v6.octets(), LOOPBACK_PREFIX_V6),
            any_port,
        ));
    }

    /// Build the seccomp filter this plan describes. Pure — the filter is not
    /// installed until [`kennel_lib_syscall::seccomp::Filter::install`] is called on
    /// the spawn path.
    #[must_use]
    pub fn seccomp_filter(&self) -> Filter {
        Filter::denylist(&self.seccomp_deny, self.seccomp_deny_action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_port_min_lands_in_the_meta_pad_slot() {
        // `bind_port_min` occupies the repurposed `_pad0` slot at offset 14 (host
        // order) and disturbs nothing else; `0` leaves the slot zero.
        let mut meta = meta_bytes(7);
        assert_eq!(&meta[14..16], &[0, 0], "no floor ⇒ slot stays zero");
        stamp_bind_port_min(&mut meta, 1024);
        assert_eq!(meta.get(14..16), Some(1024u16.to_ne_bytes().as_slice()));
        // The ctx/magic head and the proxy region around it are untouched.
        assert_eq!(&meta[6..8], &7u16.to_ne_bytes(), "ctx preserved");
        assert_eq!(&meta[8..14], &[0u8; 6], "proxy v4/port slots still zero");
    }
}
