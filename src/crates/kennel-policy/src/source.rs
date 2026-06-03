//! The source-policy schema — what an operator (or a template author) writes.
//!
//! # Purpose
//!
//! This is the **input** to `kennel compile`: a template or leaf policy as authored
//! in TOML (`docs/architecture/02-2-config-schema.md`, `docs/design/05-templates.md`). It is the
//! rich, human-facing surface — every resource section (`exec`, `fs`, `net`, `unix`,
//! `ssh`, `dbus`, `x11`, `env`, `cap`, `seccomp`, `proc`, `ptrace`, `signal`,
//! `lifecycle`, `container`), identity and inheritance (`template_base`, `template_name`, `name`,
//! `include`), and signing metadata. The compiler resolves a chain of these into the
//! flat [`crate::settled::SettledPolicy`] the runtime enforces.
//!
//! # Invariants
//!
//! - Every struct is `#[serde(deny_unknown_fields)]`: an unrecognised key is a hard
//!   parse error (`02-2` §File layout). The schema is the allowlist.
//! - All section fields are optional. A section absent from a file contributes
//!   nothing; presence is what a delta/merge step (the resolver) acts on. Faithful
//!   *parsing* is this module's job; *composition* is the resolver's (`source.rs`
//!   stays I/O-free and merge-free).
//! - Paths are carried verbatim as strings. Tilde/`<…>` expansion happens later, and
//!   only after signature verification (`02-2` §Path syntax) — never at parse time.
//!
//! # Threat bearing
//!
//! `deny_unknown_fields` is a supply-chain control: a template that smuggles an
//! unknown key (a typo'd `deny` that silently does nothing, or a future field an old
//! binary would ignore) is rejected rather than under-enforced. [`SourcePolicy::validate`]
//! additionally requires a `reason` on every capability-granting entry, so a grant
//! cannot enter a policy without recorded intent.
//!
//! # Non-goals
//!
//! This build parses the **template direct form** (the six in-tree templates). The
//! leaf-policy *delta operators* (`[[fs.read.add]]`, `[[net.allow.remove]]`,
//! `[net.audit.override]`) and their folding are the resolver increment's concern —
//! a delta is inert without a folder to apply it — and are added there alongside the
//! composition logic, not here.

use crate::signature::SignatureEnvelope;
use crate::PolicyError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A parsed source policy: a template or a leaf, before resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicy {
    /// Versioned reference to the parent template (`<name>@v<ver>`), or a bare name
    /// in the legacy two-field form. Absent only for the root template
    /// (`base-confined`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_base: Option<String>,
    /// This artefact's own version (templates), or — in the legacy two-field leaf
    /// form — the referenced parent's version. A quoted string by convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_version: Option<String>,
    /// The template's own name. Present on templates, absent on leaf policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    /// The kennel name. Present on leaf policies, absent on templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Additional signed fragments composed additively (versioned references).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// The `THREATS.md` catalogue version this artefact was authored against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_catalogue_version: Option<String>,
    /// The signature envelope over the artefact's canonical content. Required for
    /// templates and fragments; optional for leaf policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,

    /// Capability section (`[cap]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<CapSection>,
    /// Execution section (`[exec]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSection>,
    /// Filesystem section (`[fs]` and `[fs.*]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsSection>,
    /// Network section (`[net]` and `[net.*]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetSection>,
    /// `AF_UNIX` section (`[unix]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixSection>,
    /// SSH egress section (`[ssh]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshSection>,
    /// Identity section (`[identity]`) — the supplementary groups carried in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentitySection>,
    /// D-Bus section (`[dbus]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbus: Option<DbusSection>,
    /// X11/Wayland section (`[x11]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x11: Option<X11Section>,
    /// Procfs section (`[proc]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proc: Option<ProcSection>,
    /// Ptrace section (`[ptrace]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptrace: Option<PtraceSection>,
    /// Signal section (`[signal]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<SignalSection>,
    /// Environment section (`[env]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvSection>,
    /// Seccomp section (`[seccomp]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<SeccompSection>,
    /// Lifecycle section (`[lifecycle]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleSection>,
    /// Container section (`[container]`) — design-level; no runtime yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerSection>,
}

/// Threat-tag metadata attached to a grant (`threats.exposed` / `threats.mitigated`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Threats {
    /// Threat IDs this entry weakens defence against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposed: Vec<String>,
    /// Threat IDs this entry actively mitigates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitigated: Vec<String>,
}

/// `[cap]` — capabilities and `no_new_privs`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapSection {
    /// `PR_SET_NO_NEW_PRIVS`. A framework invariant once resolved (must be true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_new_privs: Option<bool>,
    /// The capability bounding set to retain (empty drops them all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounding_set: Option<Vec<String>>,
}

/// `[exec]` — what may be `execve()`'d.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSection {
    /// Allowlisted absolute binary paths (empty list = no allowlist constraint here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// Denylisted absolute paths or globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Refuse setuid binaries at execve (framework invariant once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setuid: Option<bool>,
    /// Refuse setgid binaries (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setgid: Option<bool>,
    /// Refuse file-capability binaries (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setcap: Option<bool>,
    /// Refuse execution of files in writable paths (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_writable: Option<bool>,
    /// `PATH` search roots the resolver records for the workload's environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

/// `[fs]` and its sub-tables.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsSection {
    /// Paths granted read (and directory traversal / execute).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<Vec<String>>,
    /// Paths granted write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Vec<String>>,
    /// Categorical denies (belt-and-braces over the constructed view).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// `[fs.home]` — the constructed `$HOME` view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<FsHome>,
    /// `[fs.tmp]` — the private `/tmp` tmpfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmp: Option<FsTmp>,
    /// `[fs.proc]` — procfs visibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proc: Option<FsProc>,
    /// `[fs.dev]` — the minimal `/dev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<FsDev>,
    /// `[fs.scrub]` — credential-shaped paths overlaid empty/absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub: Option<FsScrub>,
}

/// `[fs.home]` — the mandatory constructed-`$HOME` shim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsHome {
    /// Whether `$HOME` is shadowed by a constructed view (must be true once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<bool>,
    /// The shim root path (must be under `/run/kennel/<kennel>/` once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim_root: Option<String>,
    /// `[[fs.home.sanitise]]` — host config files copied in with secrets stripped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sanitise: Vec<FsHomeSanitise>,
}

/// One `[[fs.home.sanitise]]` entry (`docs/design/05-templates.md` §5.9).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsHomeSanitise {
    /// The real host file to read.
    pub real: String,
    /// The shim path the sanitised copy is bound at.
    pub shim: String,
    /// Key globs to strip from the copy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip: Vec<String>,
    /// Why this file is needed inside the kennel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `[fs.tmp]` — private `/tmp`. `size` is the human form (`"512M"`); the resolver
/// converts it to mebibytes for the settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsTmp {
    /// Whether `/tmp` is a private tmpfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    /// Size cap in human form (`"512M"`, `"1G"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// Mount mode (octal digits, e.g. `"0700"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// `[fs.proc]` — procfs visibility and hidepid.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsProc {
    /// Visibility (`"self"` is the only permitted value once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// Mount `/proc` with `hidepid=2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidepid: Option<bool>,
}

/// `[fs.dev]` — the constructed `/dev` allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsDev {
    /// The trivial pseudo-device baseline bound into the kennel's `/dev` (`/dev/null`,
    /// `/dev/urandom`, `/dev/tty`, …) — bare paths, no documentation needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// `[[fs.dev.passthrough]]` — specific *real host devices* exposed to the kennel
    /// (a serial console, `/dev/ppp`, `/dev/net/tun`; `docs/design/07-2-filesystem.md`
    /// §7.2.8). Each is loud: a documented `reason` and a threat tag are required,
    /// because passing a hardware device through widens the kernel attack surface and
    /// its DAC group right reaches into the kennel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough: Vec<DevPassthrough>,
}

/// One `[[fs.dev.passthrough]]` entry: a specific host device made available in the
/// kennel's constructed `/dev` (§7.2.8).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevPassthrough {
    /// The device node, an absolute path under `/dev` (e.g. `/dev/ttyUSB0`,
    /// `/dev/net/tun`). Bound from the host, preserving its owner/group/mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The owning group that gates access (e.g. `dialout`, `modem`, `dip`). Access is
    /// DAC: the kennel reaches the device only if this group is in its group set, and
    /// the user must already be a member. Documentary today (the kennel inherits the
    /// user's groups); the hook for the future hardening that drops non-granted groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Why this device is exposed (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags — required to carry an `exposed` tag (passthrough widens the
    /// kernel attack surface and carries a group right into the kennel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[fs.scrub]` — credential-shaped files masked inside a granted tree.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsScrub {
    /// Glob patterns to mask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    /// `"empty"` (zero-byte file) or `"enoent"` (appears absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// `[net]` and its sub-tables.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetSection {
    /// Egress mode: `"constrained"`, `"open"`, or `"none"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Whether the per-kennel proxy listens on IPv4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v4: Option<bool>,
    /// Whether the per-kennel proxy listens on IPv6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v6: Option<bool>,
    /// IPv4 proxy listen address as `"offset:port"` within the kennel's subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v4_address: Option<String>,
    /// IPv6 proxy listen address as `"offset:port"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v6_address: Option<String>,
    /// `[[net.allow]]` — by-name (or by-CIDR) egress allow entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetAllow>,
    /// `[net.deny]` — deny entries, including the `[[net.deny.invariant]]` set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<NetDeny>,
    /// `[net.bind]` — bind-address rewriting policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBind>,
    /// `[net.ipv6]` — IPv6-specific options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<NetIpv6>,
    /// `[net.audit]` — per-kennel egress audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<NetAudit>,
}

/// One `[[net.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetAllow {
    /// The destination host (or dot-prefixed suffix). Mutually informative with `cidr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A CIDR destination, when the rule is by-address rather than by-name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Permitted ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Transport protocol (`"tcp"`, `"udp"`, `"any"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Why this destination is permitted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    // `tls` and `threats` are TOML tables: declared after the scalar fields so they
    // serialise last (`basic-toml` emits values before tables).
    /// `tls.required` and friends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<NetTls>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `tls.*` on a `[[net.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetTls {
    /// Whether TLS is required to the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// `[net.deny]` — its `invariant` array carries the non-removable denies.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetDeny {
    /// `[[net.deny.invariant]]` — cloud-metadata / RFC1918 / link-local / CGNAT.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant: Vec<NetDenyRule>,
}

/// One `[[net.deny.invariant]]` entry: a CIDR plus its required `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetDenyRule {
    /// The denied CIDR (e.g. `"169.254.169.254/32"`).
    pub cidr: String,
    /// Why the deny exists (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[net.bind]` — bind-address handling.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBind {
    /// What to do with a wildcard IPv4 bind (`"rewrite"` / `"deny"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inaddr_any_policy: Option<String>,
    /// What to do with a wildcard IPv6 bind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in6addr_any_policy: Option<String>,
    /// Whether binding the host IPv4 loopback is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_host_loopback_v4: Option<bool>,
    /// Whether binding the host IPv6 loopback is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_host_loopback_v6: Option<bool>,
    /// Lowest bindable port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_port: Option<u16>,
}

/// `[net.ipv6]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetIpv6 {
    /// Force `IPV6_V6ONLY=1` so a dual-stack socket cannot escape the v4 rewrite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_v6only: Option<bool>,
}

/// `[net.audit]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetAudit {
    /// Where the per-kennel egress JSONL log is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// Audit verbosity (`"summary"`, `"full"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// `[unix]` — `AF_UNIX` policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixSection {
    /// Default disposition (`"deny"` / `"allow"`; `"allow"` is forbidden once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Abstract-namespace socket disposition (`"deny"` / `"allow"`).
    #[serde(rename = "abstract", default, skip_serializing_if = "Option::is_none")]
    pub abstract_ns: Option<String>,
    /// `[[unix.allow]]` — granted sockets, including per-kennel service instances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<UnixAllow>,
}

/// One `[[unix.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixAllow {
    /// A logical name (e.g. `"ssh-agent"`) for a per-kennel service instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The real host socket path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real: Option<String>,
    /// The shim path the socket is bound at inside the kennel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// An environment variable to set to the shim path (e.g. `SSH_AUTH_SOCK`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Why this socket is granted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[identity]` — the workload's identity inside the kennel (`docs/design/07-2-filesystem.md`).
///
/// Source-only and realised by `kenneld`: the supplementary Unix groups the confined
/// workload retains. By default a kennel carries **none** (the inherited host groups
/// are dropped by the privileged seal, §7.2); each name listed here is kept — but only
/// if the operator is actually a member (a group the user lacks is refused, never
/// granted, since the privileged `setgroups` could otherwise over-grant). Groups named
/// by `[[fs.dev.passthrough]]` are added automatically. The resolved set drives the
/// seal's `setgroups` and is named in the synthetic `/etc/group` so `id` shows names.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Supplementary group names to retain (e.g. `["dialout", "plugdev"]`). The user
    /// must be a member of each; resolved to GIDs at spawn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// `[ssh]` — per-kennel SSH egress (source-only; `docs/design/07-8-ssh.md` §7.8).
///
/// Resolved and folded like [`UnixSection`] and dropped from the settled
/// `EffectivePolicy` (`translate.rs`): its effect is realised by `kenneld`'s SSH
/// re-origination bastion (`kennel-sshd`), the synthetic `~/.ssh`, and the egress
/// allowlist — never by the runtime artefact. A kennel never holds a real key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshSection {
    /// Whether a granted key may be driven by a non-interactive (CI) kennel with no
    /// per-use touch/confirmation. Loud and threat-tagged; default `false`. When
    /// `true`, [`threats`](Self::threats) must carry an `exposed` tag (§7.8.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_headless: Option<bool>,
    /// Threat tags for the section — required to carry an `exposed` tag whenever
    /// `allow_headless = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
    /// `[[ssh.keys]]` — granted `(real-key, hosts)` edges. Each mints a disposable
    /// synthetic key bound to a forced command on the bastion (§7.8.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<SshKey>,
    /// `[[ssh.known_hosts]]` — host-key pins for granted destinations the operator's
    /// own `known_hosts` lacks (§7.8.7). A granted host with no known key fails closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_hosts: Vec<SshKnownHost>,
}

/// One `[[ssh.keys]]` entry: a real key and the destinations it may reach.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshKey {
    /// The user's real key, by its stable `SHA256:<base64>` (`ssh-add -l`) identity.
    /// The key material itself lives only in the user's host-side store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Destinations this key may reach (each `⊆ net.allow` on port 22).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Why this key/host edge is granted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// One `[[ssh.known_hosts]]` entry: a pinned host key for a granted destination.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshKnownHost {
    /// The destination hostname this key pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The host key in `authorized_keys`/`known_hosts` form (`ssh-ed25519 AAAA…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// `[dbus]` — session/system bus enablement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DbusSection {
    /// Session bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<DbusBus>,
    /// System bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<DbusBus>,
}

/// A D-Bus bus's enablement (`session.enabled = false`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DbusBus {
    /// Whether the bus is reachable from the kennel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// `[x11]` — display-server isolation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct X11Section {
    /// Isolate via Xwayland on Wayland hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xwayland_isolated: Option<bool>,
    /// Isolate via Xephyr on X11 hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xephyr_isolated: Option<bool>,
}

/// `[proc]` — procfs visibility (mirrors `[fs.proc]`; both appear in the corpus).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcSection {
    /// Visibility (`"self"` only, once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// Mount `/proc` with `hidepid=2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidepid: Option<bool>,
}

/// `[ptrace]` — ptrace across the kennel boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PtraceSection {
    /// Permitted ptrace targets (`"self"` etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_targets: Option<Vec<String>>,
    /// Permitted ptrace sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_from: Option<Vec<String>>,
}

/// `[signal]` — signalling across the kennel boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignalSection {
    /// Permitted signal targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_targets: Option<Vec<String>>,
    /// Permitted signal sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_from: Option<Vec<String>>,
}

/// `[env]` — environment curation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSection {
    /// Variables passed through from the caller's environment (globs allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<Vec<String>>,
    /// Variables denied even if passed (globs allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Variables forced to a specific value. Declared last: as a TOML table it must
    /// serialise after the array-valued fields (`basic-toml` emits values first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<BTreeMap<String, String>>,
}

/// `[seccomp]` — the seccomp filter (source carries a deny list; the resolver
/// produces the settled allow list + default action).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompSection {
    /// The baseline profile name (`"default"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Syscalls denied on top of the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Syscalls explicitly allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
}

/// `[lifecycle]` — TTL and TTL action. `ttl` is the human form (`"8h"`); the
/// resolver converts it to seconds for the settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSection {
    /// Time-to-live in human form (`"8h"`, `"1h"`, `"30m"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// What to do at TTL expiry (`"stop"` / `"warn"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_action: Option<String>,
}

/// `[container]` — design-level container orchestration (no runtime yet).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSection {
    /// The container image reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The pinned image digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    /// Invariant: never `--privileged`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privileged: Option<bool>,
    /// Invariant: never `--pid=host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_pid_host: Option<bool>,
    /// Invariant: never `--network=host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_network_host: Option<bool>,
    /// Run as the image's non-root user where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_nonroot: Option<bool>,
    /// `[[container.published_ports]]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub published_ports: Vec<ContainerPort>,
    /// `[[container.volumes]]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<ContainerVolume>,
}

/// One `[[container.published_ports]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPort {
    /// The in-container port.
    pub container_port: u16,
    /// Host offset within the kennel's subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_offset: Option<u8>,
    /// The host port on the kennel's loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    /// Why this port is published (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// One `[[container.volumes]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerVolume {
    /// The host path.
    pub host: String,
    /// The in-container mount path.
    pub container: String,
    /// Why this volume is mounted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Parse source-policy TOML bytes into a [`SourcePolicy`].
///
/// This is parse-only: it enforces the schema shape (`deny_unknown_fields`, types,
/// no duplicate keys) but not the semantic rules. Call [`SourcePolicy::validate`]
/// for identity coherence, reference grammar, and required `reason`s.
///
/// # Errors
///
/// Returns [`PolicyError::Parse`] if the bytes are not valid TOML matching the schema.
pub fn parse(bytes: &[u8]) -> Result<SourcePolicy, PolicyError> {
    basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))
}

impl SourcePolicy {
    /// Validate the semantic rules this build enforces on a single source artefact.
    ///
    /// Checks: identity coherence (template vs leaf), `template_base`/`include`
    /// reference grammar, no duplicate includes, and a non-empty `reason` on every
    /// capability-granting entry (`[[net.allow]]`, `[[net.deny.invariant]]`,
    /// `[[unix.allow]]`, `[[container.published_ports]]`, `[[container.volumes]]`).
    ///
    /// Chain resolution, signature verification, lockfile byte-pinning, and
    /// framework-invariant assertion are *cross-artefact* or *post-resolution*
    /// concerns handled by later compiler stages, not here.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::SourceValidation`] carrying one message per problem.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errs: Vec<String> = Vec::new();
        self.check_identity(&mut errs);
        self.check_references(&mut errs);
        self.check_reasons(&mut errs);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::SourceValidation(errs))
        }
    }

    /// Whether this artefact is a leaf policy (has `name`, no `template_name`).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.name.is_some() && self.template_name.is_none()
    }

    fn check_identity(&self, errs: &mut Vec<String>) {
        match (self.template_name.is_some(), self.name.is_some()) {
            (true, true) => {
                errs.push("artefact sets both `template_name` and `name`; a file is either a template or a leaf, not both".to_owned());
            }
            (false, false) => {
                errs.push(
                    "artefact sets neither `template_name` (templates) nor `name` (leaf policies)"
                        .to_owned(),
                );
            }
            _ => {}
        }
        // A leaf policy must name a parent template; only the root template may omit it.
        if self.is_leaf() && self.template_base.is_none() {
            errs.push(
                "leaf policy has no `template_base`; every leaf derives from a template".to_owned(),
            );
        }
    }

    fn check_references(&self, errs: &mut Vec<String>) {
        if let Some(base) = &self.template_base {
            // The legacy two-field form carries a bare name plus a separate
            // `template_version`; the canonical form carries `@v<ver>` inline.
            if base.contains('@') {
                if let Err(msg) = validate_reference(base) {
                    errs.push(format!("`template_base` = \"{base}\": {msg}"));
                }
            } else if let Err(msg) = validate_ref_name(base) {
                errs.push(format!("`template_base` = \"{base}\": {msg}"));
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for inc in &self.include {
            if let Err(msg) = validate_reference(inc) {
                errs.push(format!("`include` entry \"{inc}\": {msg}"));
            }
            if seen.contains(&inc.as_str()) {
                errs.push(format!("`include` entry \"{inc}\" is duplicated"));
            }
            seen.push(inc.as_str());
        }
    }

    fn check_reasons(&self, errs: &mut Vec<String>) {
        if let Some(net) = &self.net {
            for a in &net.allow {
                let who = a
                    .name
                    .as_deref()
                    .or(a.cidr.as_deref())
                    .unwrap_or("<unnamed>");
                if is_blank(a.reason.as_deref()) {
                    errs.push(format!("[[net.allow]] \"{who}\" is missing a `reason`"));
                }
            }
            if let Some(deny) = &net.deny {
                for d in &deny.invariant {
                    if is_blank(d.reason.as_deref()) {
                        errs.push(format!(
                            "[[net.deny.invariant]] \"{}\" is missing a `reason`",
                            d.cidr
                        ));
                    }
                }
            }
        }
        if let Some(unix) = &self.unix {
            for a in &unix.allow {
                let who = a
                    .name
                    .as_deref()
                    .or(a.real.as_deref())
                    .unwrap_or("<unnamed>");
                if is_blank(a.reason.as_deref()) {
                    errs.push(format!("[[unix.allow]] \"{who}\" is missing a `reason`"));
                }
            }
        }
        if let Some(fs) = &self.fs {
            if let Some(dev) = &fs.dev {
                for d in &dev.passthrough {
                    let who = d.path.as_deref().unwrap_or("<no-path>");
                    if is_blank(d.reason.as_deref()) {
                        errs.push(format!(
                            "[[fs.dev.passthrough]] \"{who}\" is missing a `reason`"
                        ));
                    }
                }
            }
        }
        if let Some(ssh) = &self.ssh {
            for k in &ssh.keys {
                let who = k.fingerprint.as_deref().unwrap_or("<no-fingerprint>");
                if is_blank(k.reason.as_deref()) {
                    errs.push(format!("[[ssh.keys]] \"{who}\" is missing a `reason`"));
                }
            }
        }
        if let Some(c) = &self.container {
            for p in &c.published_ports {
                if is_blank(p.reason.as_deref()) {
                    errs.push(format!(
                        "[[container.published_ports]] {} is missing a `reason`",
                        p.container_port
                    ));
                }
            }
            for v in &c.volumes {
                if is_blank(v.reason.as_deref()) {
                    errs.push(format!(
                        "[[container.volumes]] \"{}\" is missing a `reason`",
                        v.container
                    ));
                }
            }
        }
    }
}

/// Whether an optional string is absent or whitespace-only.
fn is_blank(s: Option<&str>) -> bool {
    s.is_none_or(|v| v.trim().is_empty())
}

/// Validate a full versioned reference `<name>@v<semver-core>`.
pub(crate) fn validate_reference(reference: &str) -> Result<(), String> {
    let Some((name, version)) = reference.split_once('@') else {
        return Err("missing `@version` (expected `<name>@v<ver>`)".to_owned());
    };
    validate_ref_name(name)?;
    validate_ref_version(version)
}

/// Validate the `<name>` part of a reference: `[a-z0-9][a-z0-9-]{0,63}`.
pub(crate) fn validate_ref_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("name must be 1..=64 characters".to_owned());
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return Err("name must start with a lowercase letter or digit".to_owned()),
    }
    if chars.any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
        return Err("name may contain only lowercase letters, digits, and `-`".to_owned());
    }
    Ok(())
}

/// Validate the `<version>` part of a reference: `v` + a 1..=3-component numeric core.
pub(crate) fn validate_ref_version(version: &str) -> Result<(), String> {
    let Some(core) = version.strip_prefix('v') else {
        return Err("version must start with `v` (e.g. `v4`, `v2.33.2`)".to_owned());
    };
    if core.is_empty() {
        return Err("version has no numeric core after `v`".to_owned());
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 {
        return Err("version has more than three numeric components".to_owned());
    }
    for part in parts {
        if part.is_empty() || part.parse::<u32>().is_err() {
            return Err("version components must be non-negative integers".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CONFINED: &str = include_str!("../../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../templates/ai-coding-strict/policy.toml");
    const PACKAGE_INSTALL: &str = include_str!("../../../../templates/package-install/policy.toml");
    const UNTRUSTED_BUILD: &str = include_str!("../../../../templates/untrusted-build/policy.toml");
    const INSPECT_ONLY: &str = include_str!("../../../../templates/inspect-only/policy.toml");
    const CONTAINERISED_SERVICE: &str =
        include_str!("../../../../templates/containerised-service/policy.toml");

    const ALL_TEMPLATES: &[(&str, &str)] = &[
        ("base-confined", BASE_CONFINED),
        ("ai-coding-strict", AI_CODING_STRICT),
        ("package-install", PACKAGE_INSTALL),
        ("untrusted-build", UNTRUSTED_BUILD),
        ("inspect-only", INSPECT_ONLY),
        ("containerised-service", CONTAINERISED_SERVICE),
    ];

    #[test]
    fn every_in_tree_template_parses_and_validates() {
        for (name, src) in ALL_TEMPLATES {
            let parsed = parse(src.as_bytes());
            assert!(
                parsed.is_ok(),
                "template {name} failed to parse: {parsed:?}"
            );
            let pol = parsed.expect("checked ok above");
            let validated = pol.validate();
            assert!(
                validated.is_ok(),
                "template {name} failed to validate: {validated:?}"
            );
            assert_eq!(
                pol.template_name.as_deref(),
                Some(*name),
                "template {name} name"
            );
            assert!(!pol.is_leaf(), "template {name} must not be a leaf");
        }
    }

    #[test]
    fn base_confined_is_the_root_with_no_parent() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        assert!(pol.template_base.is_none(), "base-confined is the root");
        let cap = pol.cap.expect("cap section");
        assert_eq!(cap.no_new_privs, Some(true));
        assert_eq!(cap.bounding_set.as_deref(), Some(&[][..]));
    }

    #[test]
    fn base_confined_carries_the_invariant_denies_with_reasons() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let net = pol.net.expect("net section");
        let deny = net.deny.expect("net.deny");
        assert!(
            deny.invariant
                .iter()
                .any(|d| d.cidr == "169.254.169.254/32"),
            "cloud-metadata deny present"
        );
        assert!(
            deny.invariant
                .iter()
                .all(|d| !is_blank(d.reason.as_deref())),
            "every invariant deny has a reason"
        );
    }

    #[test]
    fn derived_templates_name_their_parent_by_versioned_reference() {
        for (name, src) in ALL_TEMPLATES.iter().filter(|(n, _)| *n != "base-confined") {
            let pol = parse(src.as_bytes()).expect("parse");
            assert_eq!(
                pol.template_base.as_deref(),
                Some("base-confined@v1"),
                "template {name} extends base-confined@v1"
            );
        }
    }

    #[test]
    fn ai_coding_strict_carries_its_net_allow_and_unix_agent() {
        let pol = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        let net = pol.net.expect("net");
        assert!(net
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
        assert!(
            net.allow.iter().all(|a| !is_blank(a.reason.as_deref())),
            "every allow has a reason"
        );
        let unix = pol.unix.expect("unix");
        // The shim grants a per-kennel gpg-agent (a non-SSH agent socket). SSH is
        // NOT shimmed — it goes through the §7.8 bastion via the [ssh] section.
        let agent = unix
            .allow
            .iter()
            .find(|a| a.name.as_deref() == Some("gpg-agent"))
            .expect("gpg-agent");
        assert_eq!(agent.shim.as_deref(), Some("~/.gnupg/S.gpg-agent"));
        assert!(
            !unix
                .allow
                .iter()
                .any(|a| a.name.as_deref() == Some("ssh-agent")
                    || a.env.as_deref() == Some("SSH_AUTH_SOCK")),
            "no ssh-agent shim — SSH is a destination-blind oracle, routed via the bastion"
        );
    }

    #[test]
    fn env_set_is_an_inline_table() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let env = pol.env.expect("env");
        let set = env.set.expect("env.set");
        assert_eq!(set.get("TMPDIR").map(String::as_str), Some("/tmp"));
    }

    #[test]
    fn containerised_service_parses_design_level_container_block() {
        let pol = parse(CONTAINERISED_SERVICE.as_bytes()).expect("parse");
        let c = pol.container.expect("container");
        assert_eq!(c.allow_privileged, Some(false));
        assert_eq!(c.allow_pid_host, Some(false));
        assert!(c.published_ports.iter().any(|p| p.container_port == 5432));
        assert!(c
            .published_ports
            .iter()
            .all(|p| !is_blank(p.reason.as_deref())));
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let src = "template_name = \"x\"\nbogus_key = 1\n";
        assert!(
            parse(src.as_bytes()).is_err(),
            "deny_unknown_fields rejects bogus_key"
        );
    }

    #[test]
    fn unknown_key_in_known_section_is_rejected() {
        let src = "template_name = \"x\"\n[cap]\nno_new_privs = true\nnope = 1\n";
        assert!(
            parse(src.as_bytes()).is_err(),
            "deny_unknown_fields rejects nested unknown"
        );
    }

    #[test]
    fn leaf_without_template_base_is_rejected() {
        let src = "name = \"myproj\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(pol.is_leaf());
        let err = pol
            .validate()
            .expect_err("leaf with no template_base must fail");
        assert!(matches!(err, PolicyError::SourceValidation(_)));
    }

    #[test]
    fn artefact_with_both_identities_is_rejected() {
        let src = "template_name = \"t\"\nname = \"n\"\ntemplate_base = \"base-confined@v1\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(
            pol.validate().is_err(),
            "template_name + name is incoherent"
        );
    }

    #[test]
    fn net_allow_without_reason_is_rejected() {
        let src = "name = \"n\"\ntemplate_base = \"base-confined@v1\"\n\
                   [[net.allow]]\nname = \"evil.example\"\nports = [443]\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let err = pol.validate().expect_err("missing reason must fail");
        assert!(
            matches!(err, PolicyError::SourceValidation(_)),
            "expected SourceValidation, got {err}"
        );
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms
                .iter()
                .any(|m| m.contains("evil.example") && m.contains("reason")));
        }
    }

    #[test]
    fn malformed_versioned_reference_is_rejected() {
        // `@4` lacks the leading `v`; the name `Bad` has an uppercase letter.
        let cases = [
            "base-confined@4",
            "Bad@v1",
            "base-confined@v1.2.3.4",
            "base-confined@v",
        ];
        for case in cases {
            let src = format!("name = \"n\"\ntemplate_base = \"{case}\"\n");
            let pol = parse(src.as_bytes()).expect("parse");
            assert!(pol.validate().is_err(), "reference {case} must be rejected");
        }
        // A well-formed reference validates.
        let src = "name = \"n\"\ntemplate_base = \"base-confined@v2.33.2\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(pol.validate().is_ok(), "well-formed reference accepted");
    }

    #[test]
    fn duplicate_include_is_rejected() {
        let src = "name = \"n\"\ntemplate_base = \"base-confined@v1\"\n\
                   include = [\"corp-egress@v2\", \"corp-egress@v2\"]\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let err = pol.validate().expect_err("duplicate include must fail");
        assert!(
            matches!(err, PolicyError::SourceValidation(_)),
            "expected SourceValidation, got {err}"
        );
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms.iter().any(|m| m.contains("duplicated")));
        }
    }
}
