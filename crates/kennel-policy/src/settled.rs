//! The settled-policy types — the flat, signed, runtime artefact consumed by
//! `kennel-spawn`.
//!
//! This is the resolved output of `kennel compile`: no `template_base`, no
//! `include`, no delta operators — only the final effective rules, plus
//! provenance and a single signature. The template/resolution machinery that
//! *produces* a settled policy (chain-walking, includes, deltas, the lockfile)
//! is a separate, compile-time concern not yet implemented here.
//!
//! ## Serialisation format
//!
//! The architecture specifies the settled policy as canonical JSON for fleet
//! interop (`02-2-config-schema.md`). This increment serialises it as TOML via
//! `basic-toml`; the JSON form is deferred until `serde_json`'s dependency
//! closure (`zmij`) is vendored under §5.5. The struct field order below is
//! chosen so the TOML serialisation is valid (scalars and inline arrays precede
//! sub-tables and arrays-of-tables) and deterministic, which is what the
//! canonical-form signature relies on.

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

/// Network policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetPolicy {
    /// Enforcement mode.
    pub mode: NetMode,
    /// Allowlisted destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetRule>,
    /// Invariant deny CIDRs (cloud metadata, link-local, RFC1918). Must be
    /// present; cannot be removed by any delta.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_invariant: Vec<NetRule>,
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
    /// Action for syscalls not in the allowlist.
    pub default_action: SeccompAction,
    /// Allowlisted syscall numbers (architecture-specific).
    pub allow: Vec<i64>,
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
