//! The settled-policy types — the flat, signed, runtime artefact consumed by
//! `kennel-spawn`.
//!
//! This is the resolved output of `kennel compile`: no `template_base`, no
//! `include`, no delta operators — only the final effective rules, plus
//! provenance and a single signature. The template/resolution machinery that
//! *produces* a settled policy (chain-walking, includes, deltas, the lockfile)
//! lives alongside this module ([`crate::compile`] and friends) but is a separate,
//! compile-time concern off the spawn hot path.
//!
//! ## Serialisation format
//!
//! The settled policy is TOML, like every Project Kennel config artefact
//! (`02-2-config-schema.md`) — there is no JSON config. The struct field order
//! below is chosen so the TOML serialisation is valid (scalars and inline arrays
//! precede sub-tables and arrays-of-tables) and deterministic, which is what the
//! canonical-form signature relies on: because the same implementation produces
//! and verifies the canonical bytes, a fixed-field-order serialisation is
//! reproducible without JSON's canonicalisation machinery.

use serde::{Deserialize, Serialize};

/// Network enforcement mode. `unrestricted` is deliberately not representable
/// (a framework invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetMode {
    /// Egress confined to the allowlist (the default posture).
    Constrained,
    /// Egress unconfined by the allowlist (only the invariant denies apply).
    Open,
}

/// Transport protocol selector for a network rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Any protocol.
    Any,
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
}

/// Procfs visibility. Only `self` is permitted (a framework invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcVisibility {
    /// `hidepid` such that the workload sees only its own processes.
    #[serde(rename = "self")]
    SelfOnly,
}

/// The default action for syscalls not explicitly allowed by the seccomp filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    /// Return `EPERM`.
    Errno,
    /// Kill the offending thread.
    KillThread,
    /// Kill the whole process.
    KillProcess,
}

/// What to do when a kennel's TTL expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlAction {
    /// Send SIGTERM, then SIGKILL after a grace period.
    Stop,
    /// Leave the workload running; emit an audit event only.
    Warn,
}

/// One network allow/deny rule: a CIDR plus a port range and protocol.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetRule {
    /// Network address in dotted-quad (v4) or colon (v6) form.
    pub cidr: String,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Inclusive lower bound of the port range (host order).
    pub port_min: u16,
    /// Inclusive upper bound of the port range (host order).
    pub port_max: u16,
    /// Protocol the rule applies to.
    pub protocol: Protocol,
}

/// One by-name egress allow rule, enforced by the per-kennel egress proxy.
///
/// Names cannot be expressed in the cgroup BPF (which matches addresses), so a
/// by-name allow is honoured only by the proxy: the workload's request names the
/// host, the proxy checks it here, resolves it under DNS policy, re-checks the
/// resolved address against the deny rules, and connects. `name` follows the
/// proxy's dot-convention: `example.com` is an exact match; `.example.com` is the
/// apex plus any subdomain on a label boundary. Ports are a discrete set (the
/// representation the proxy consumes), unlike the [`NetRule`] range the BPF
/// consumes — each rule mirrors the engine that enforces it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NameRule {
    /// The destination host, or dot-prefixed suffix, the rule permits.
    pub name: String,
    /// Permitted ports; empty means any port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Protocol the rule applies to.
    pub protocol: Protocol,
}

/// Where the per-kennel egress proxy listens, resolved from the source policy's
/// `proxy_listen_*_address = "offset:port"` (`docs/design/07-3-network.md` §7.3.4).
///
/// `offset` is the host offset within the kennel's own subnet (the `/28` in IPv4,
/// the `/64` in IPv6); offset 1 is the kennel's primary address, where the proxy
/// lives by default. `port` is the listener's TCP port. Carrying these in the
/// signed policy makes the BPF-enforced proxy address signature-bound rather than
/// a runtime constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyListen {
    /// Host offset within the kennel's subnet (1..=14; 0 and 15 reserved).
    pub offset: u8,
    /// The proxy's listen port (1025..=32767).
    pub port: u16,
}

impl Default for ProxyListen {
    /// The documented default: offset 1 (the kennel's primary address), port 1080.
    fn default() -> Self {
        Self {
            offset: 1,
            port: 1080,
        }
    }
}

/// Network policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetPolicy {
    /// Enforcement mode.
    pub mode: NetMode,
    /// Where the egress proxy listens (offset + port within the kennel's subnet).
    #[serde(default)]
    pub proxy: ProxyListen,
    /// Allowlisted destinations by address. Enforced directly by the cgroup BPF
    /// (a direct `connect()` to one of these is permitted) and also honoured by
    /// the proxy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetRule>,
    /// Allowlisted destinations by name. Enforced only by the per-kennel egress
    /// proxy (the BPF cannot match names); consulted in `constrained` mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_names: Vec<NameRule>,
    /// Invariant deny CIDRs (cloud metadata, link-local, RFC1918). Must be
    /// present; cannot be removed by any delta.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_invariant: Vec<NetRule>,
}

/// Private-`/tmp` tmpfs parameters (§7.2.6).
///
/// The settled policy carries the resolved numeric size; the source policy's
/// human form (`size = "512M"`) is converted to mebibytes at compile time so the
/// runtime parses a plain integer, not a units string.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TmpPolicy {
    /// Whether `/tmp` is a private tmpfs. Confined templates always set this
    /// true; `false` would bind-mount the host `/tmp` (which templates never do).
    pub private: bool,
    /// Size cap of the tmpfs, in mebibytes.
    pub size_mib: u32,
    /// Mount mode for the tmpfs root, as octal digits (e.g. `"0700"`). The
    /// runtime validates it is octal-only before it reaches the mount data
    /// string (it would otherwise be an option-injection vector).
    pub mode: String,
}

/// Device-file policy (§7.2.8): which `/dev` nodes the kennel's constructed
/// `/dev` exposes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevPolicy {
    /// Device paths the kennel may access (absolute, under `/dev` — e.g.
    /// `/dev/null`, `/dev/urandom`, `/dev/tty`). The runtime refuses any entry
    /// outside `/dev` or carrying a `..` component before it binds it.
    pub allow: Vec<String>,
}

/// Filesystem policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsPolicy {
    /// Whether `$HOME` is shadowed by the shim (must be true).
    pub home_shadow: bool,
    /// The shim root, which must live under `/run/kennel/`.
    pub shim_root: String,
    /// Paths granted read (and directory-read/execute) access.
    pub read: Vec<String>,
    /// Paths granted write access.
    pub write: Vec<String>,
    /// Private-`/tmp` tmpfs parameters. Declared after the scalar/array fields
    /// so the canonical TOML emits this sub-table last (valid table ordering).
    pub tmp: TmpPolicy,
    /// Device-file allowlist for the constructed `/dev`.
    pub dev: DevPolicy,
}

/// Exec policy. The four `deny_*` flags are framework invariants (all true);
/// they are independent boolean facts mirroring the schema, not a state machine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExecPolicy {
    /// Refuse to honour setuid bits on exec.
    pub deny_setuid: bool,
    /// Refuse to honour setgid bits on exec.
    pub deny_setgid: bool,
    /// Refuse to honour file capabilities on exec.
    pub deny_setcap: bool,
    /// Refuse to exec writable files.
    pub deny_writable: bool,
    /// Allowlisted binaries (absolute paths). Empty means "no exec allowlist
    /// enforced beyond the deny flags".
    pub allow: Vec<String>,
}

/// Procfs policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcPolicy {
    /// Procfs visibility (must be `self`).
    pub visibility: ProcVisibility,
    /// Mount `/proc` with `hidepid=2` (§7.2.7): even within the PID namespace,
    /// `/proc/<pid>` is accessible only to the process owner. Belt-and-braces
    /// atop the namespace, which is the strong isolation.
    pub hidepid: bool,
}

/// Capability policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapPolicy {
    /// `PR_SET_NO_NEW_PRIVS` (must be true).
    pub no_new_privs: bool,
}

/// Seccomp policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompPolicy {
    /// Action applied to a denied syscall (the source policy's seccomp filter is a
    /// denylist; everything not named here is permitted).
    pub deny_action: SeccompAction,
    /// Denied syscalls, by *name*. Names (not numbers) keep the signed policy
    /// architecture-independent; the spawn layer resolves them to numbers via
    /// `kennel_syscall::seccomp::syscall_number` (`libc::SYS_*`) at plan time. An
    /// empty list means no seccomp filter is installed (Landlock + the cgroup BPF
    /// remain the primary controls).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// Lifecycle policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePolicy {
    /// Optional time-to-live in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// What to do when the TTL expires.
    pub ttl_action: TtlAction,
}

/// The fully-resolved effective policy — the final rule sets only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    /// Network rules.
    pub net: NetPolicy,
    /// Filesystem rules.
    pub fs: FsPolicy,
    /// Exec rules.
    pub exec: ExecPolicy,
    /// Procfs rules.
    pub proc: ProcPolicy,
    /// Capability rules.
    pub cap: CapPolicy,
    /// Seccomp rules.
    pub seccomp: SeccompPolicy,
    /// Lifecycle rules.
    pub lifecycle: LifecyclePolicy,
}

/// The per-kennel SSH runtime: the bastion grants `kenneld` realises (§7.8).
///
/// Unlike the enforcement rule sets in [`EffectivePolicy`], this is a *service*
/// input — `kenneld` mints a synthetic key per grant, runs the bastion, and builds
/// the kennel's synthetic `~/.ssh` from it. It is carried in the settled policy (so
/// it is signed and per-instance-substituted) but kept out of the enforcement core.
/// Absent (empty) for a kennel with no `[ssh]` policy — then omitted from the
/// canonical form entirely, so a policy without SSH signs exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshRuntime {
    /// Whether a non-interactive kennel may drive a granted key with no per-use
    /// touch (loud, threat-tagged at compile time; §7.8.6).
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_headless: bool,
    /// The granted `(destination, real-key)` edges — one bastion forced command each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<SshGrant>,
    /// Host-key pins for granted destinations the operator's store lacks (§7.8.7).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_hosts: Vec<SshKnownHostPin>,
}

impl SshRuntime {
    /// Whether there is nothing to realise (no grant, no pin, default headless).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.allow_headless && self.grants.is_empty() && self.known_hosts.is_empty()
    }
}

/// One granted SSH edge: a destination reachable with a specific real key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshGrant {
    /// The destination host (`⊆ net.allow:22`, checked at compile time).
    pub host: String,
    /// The real key's `SHA256:` fingerprint; the key itself lives host-side only.
    pub fingerprint: String,
}

/// A pinned host key for a granted destination.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshKnownHostPin {
    /// The destination hostname.
    pub host: String,
    /// The host key (`ssh-ed25519 AAAA…`).
    pub key: String,
}

/// The per-kennel `AF_UNIX` socket shims `kenneld` realises (`docs/design/07-4-afunix.md` §7.4).
///
/// Like [`SshRuntime`], a *service* input rather than enforcement: `kenneld` binds
/// each granted host socket into the kennel's constructed view at its shim path and
/// sets any named env var, so the application finds its socket at the standard path.
/// What is *not* bound in is structurally absent (default-deny). Abstract-namespace
/// connections are denied unconditionally by the always-on Landlock scope (ABI 6+,
/// §7.4.3), so they are not represented here. Carried in the signed settled policy
/// (so it is signed and per-instance-substituted) but kept out of the enforcement
/// core; omitted from the canonical form when empty, so a no-`[unix]` policy signs
/// exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixRuntime {
    /// The granted socket shims — one bind mount each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sockets: Vec<UnixSocket>,
}

impl UnixRuntime {
    /// Whether there is nothing to realise (no granted socket).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

/// One granted `AF_UNIX` socket shim: a real host socket bound into the kennel's view.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixSocket {
    /// A logical name (audit / `--dry-run` output).
    pub name: String,
    /// The real host socket path (may carry per-instance placeholders, `~`, or
    /// `$XDG_RUNTIME_DIR`, resolved by `kenneld` at spawn).
    pub real: String,
    /// The path the socket is bound at inside the kennel's view (where the
    /// application looks).
    pub shim: String,
    /// An environment variable to set to the shim path inside the kennel (e.g.
    /// `WAYLAND_DISPLAY`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
}

/// The workload's identity inside the kennel (`docs/design/07-2-filesystem.md`): the
/// supplementary Unix groups it retains.
///
/// Like [`SshRuntime`]/[`UnixRuntime`], a *service* input `kenneld` realises, not part
/// of the kernel-enforcement core. `kenneld` resolves each group name to a GID at
/// spawn (refusing any the operator is not a member of), the privileged seal
/// `setgroups` to exactly that set (default empty — all inherited host groups dropped),
/// and the synthetic `/etc/group` names them so `id` shows names not bare numbers.
/// Carried in the signed settled policy; omitted from the canonical form when empty.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRuntime {
    /// Supplementary group names to retain (resolved to GIDs at spawn). Includes the
    /// groups named by `[[fs.dev.passthrough]]` (merged at translation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl IdentityRuntime {
    /// Whether there is nothing to realise (no supplementary group granted).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// `skip_serializing_if` helper: a `false` bool is omitted from the canonical form.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// Installation-specific constants baked in at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallConstants {
    /// The installation's tag byte (`<tag>`).
    pub tag: u8,
    /// The IPv6 ULA GID for this installation (`<gid>`).
    pub ula_gid: String,
}

/// One resolved template or fragment that contributed to the settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedArtifact {
    /// Artefact name.
    pub name: String,
    /// Resolved version (e.g. `v4`, `v2.33.2`).
    pub version: String,
    /// SHA-256 of the artefact's canonical form (hex), lifted from the lockfile.
    pub content_sha256: String,
    /// The `key_id` that signed this artefact.
    pub signing_key_id: String,
}

/// Provenance: every input that produced this settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The `kennel-policy` compiler version that produced this artefact.
    pub compiler_version: String,
    /// The policy schema version used at compile time.
    pub schema_version: u32,
    /// The THREATS.md catalogue version the templates were authored against.
    pub threat_catalogue_version: String,
    /// SHA-256 (hex) of the leaf policy's canonical form.
    pub leaf_policy_sha256: String,
    /// SHA-256 (hex) of the invariant set enforced at compile time.
    pub invariant_set_sha256: String,
    /// Installation constants baked in.
    pub install_constants: InstallConstants,
    /// The resolved templates/fragments, from the lockfile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_artifacts: Vec<ResolvedArtifact>,
}

/// An active audit sink (`docs/architecture/02-3-audit-schema.md` §Sinks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSinkKind {
    /// Per-class JSONL files under the kennel state dir (the default).
    File,
    /// systemd-journald (needs the `audit-journald` build of kenneld).
    Journald,
    /// RFC 5424 syslog to `/dev/log`.
    Syslog,
    /// JSONL on kenneld's stdout (container deployments).
    Stdout,
}

/// File-sink tuning carried in the settled policy. Every field is optional; an
/// unset field means kenneld applies the `02-3` default. All-unset is "empty"
/// and omitted from the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileConfig {
    /// Override the per-kennel directory (placeholders allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Rotate a class file once it would exceed this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_at_bytes: Option<u64>,
    /// Gzip a rotated file this many seconds after rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress_after_seconds: Option<u64>,
    /// Keep at most this many rotated files per class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_count: Option<u64>,
}

impl AuditFileConfig {
    /// Whether nothing is overridden (kenneld uses all defaults).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.dir.is_none()
            && self.rotate_at_bytes.is_none()
            && self.compress_after_seconds.is_none()
            && self.retain_count.is_none()
    }
}

/// The per-kennel audit runtime (`02-3`): which sinks are active and any
/// per-class level / file / syslog deviation from the defaults.
///
/// Like [`SshRuntime`]/[`UnixRuntime`] this is a *service* input, not
/// enforcement: kenneld realises it by constructing the `kennel-audit` writer.
/// A class level left unset inherits the `02-3` default (summary, or denies-only
/// for filesystem), so only deviations are carried — an all-default policy has
/// an empty runtime and signs exactly as a no-`[audit]` policy did before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRuntime {
    /// Active sinks. Empty means kenneld uses the default (`file`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<AuditSinkKind>,
    /// `net` class level override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_level: Option<String>,
    /// `fs` class level override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_level: Option<String>,
    /// `exec` class level override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_level: Option<String>,
    /// `unix` class level override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_level: Option<String>,
    /// `dbus` class level override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbus_level: Option<String>,
    /// Syslog facility name (default `user`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog_facility: Option<String>,
    /// File-sink tuning. A table, so declared last; omitted when empty.
    #[serde(default, skip_serializing_if = "AuditFileConfig::is_empty")]
    pub file: AuditFileConfig,
}

impl AuditRuntime {
    /// Whether nothing deviates from the defaults (omitted from canonical form).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sinks.is_empty()
            && self.network_level.is_none()
            && self.filesystem_level.is_none()
            && self.exec_level.is_none()
            && self.unix_level.is_none()
            && self.dbus_level.is_none()
            && self.syslog_facility.is_none()
            && self.file.is_empty()
    }
}

/// The settled policy body (everything the signature covers).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettledPolicy {
    /// Settled-policy schema version (this build emits/accepts version 1).
    pub settled_schema_version: u32,
    /// The kennel name.
    pub name: String,
    /// Placeholders the runtime must substitute (`<ctx>`, `<uid>`, …).
    pub deferred_substitutions: Vec<String>,
    /// Framework-invariant IDs the compiler asserted (audit only; re-asserted at
    /// runtime regardless).
    pub framework_invariants_asserted: Vec<String>,
    /// The resolved effective policy.
    pub effective_policy: EffectivePolicy,
    /// Provenance of the resolution.
    pub provenance: Provenance,
    /// The per-kennel SSH runtime (§7.8). Declared last: it is a table, and TOML
    /// requires the scalar/array fields above it to serialise first. Omitted from
    /// the canonical form when empty, so a no-SSH policy signs exactly as before.
    #[serde(default, skip_serializing_if = "SshRuntime::is_empty")]
    pub ssh: SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.4). A table like [`ssh`](Self::ssh) and
    /// declared after it; omitted from the canonical form when empty, so a no-`[unix]`
    /// policy signs exactly as before.
    #[serde(default, skip_serializing_if = "UnixRuntime::is_empty")]
    pub unix: UnixRuntime,
    /// The workload's in-kennel identity (§7.2): the supplementary groups it retains.
    /// A table like [`ssh`](Self::ssh)/[`unix`](Self::unix); omitted from the canonical
    /// form when empty, so a policy that grants no group signs exactly as before.
    #[serde(default, skip_serializing_if = "IdentityRuntime::is_empty")]
    pub identity: IdentityRuntime,
    /// The per-kennel audit runtime (`02-3`). A table like [`ssh`](Self::ssh) and
    /// declared after the others; omitted from the canonical form when empty, so a
    /// policy with no (or all-default) `[audit]` signs exactly as before.
    #[serde(default, skip_serializing_if = "AuditRuntime::is_empty")]
    pub audit: AuditRuntime,
}

/// A settled policy plus its signature envelope — the on-disk document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSettledPolicy {
    /// The signature over the canonical form of `policy`.
    pub signature: crate::signature::SignatureEnvelope,
    /// The settled policy body.
    pub policy: SettledPolicy,
}
