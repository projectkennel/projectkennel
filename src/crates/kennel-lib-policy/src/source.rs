//! The source-policy schema — what an operator (or a template author) writes.
//!
//! # Purpose
//!
//! This is the **input** to `kennel compile`: a template or leaf policy as authored
//! in TOML (`docs/architecture/02-2-config-schema.md`, `docs/design/05-templates.md`). It is the
//! rich, human-facing surface — every resource section (`exec`, `fs`, `net`, `unix`,
//! `ssh`, `binder`, `env`, `cap`, `seccomp`, `proc`, `ptrace`, `signal`,
//! `lifecycle`), identity and inheritance (`template_base`, `template_name`, `name`,
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
    /// Versioned reference to the parent template (`<name>@v<ver>`). Absent only for the
    /// root template (`base-confined`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_base: Option<String>,
    /// This artefact's own version. A quoted string by convention.
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
    /// Binder IPC section (`[binder]`) — user-defined services this kennel may
    /// register (`[[binder.provide]]`) and look up (`[[binder.consume]]`). The
    /// reserved `org.projectkennel.*` facades are enabled by their own sections,
    /// never declared here (`07-1-binder.md` §7.1.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder: Option<BinderSection>,
    /// `[unsafe]` — advisory footgun sub-sections whose scoping is real but enforced
    /// elsewhere (the PID namespace + seccomp), not by the section. Grouped under one
    /// `[unsafe]` umbrella so an author sees they are in footgun territory; each
    /// present sub-section is warned at compile (`footgun-warn-dont-forbid`).
    #[serde(default, rename = "unsafe", skip_serializing_if = "Option::is_none")]
    pub unsafe_section: Option<UnsafeSection>,
    /// Environment section (`[env]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvSection>,
    /// Seccomp section (`[seccomp]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<SeccompSection>,
    /// Lifecycle section (`[lifecycle]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleSection>,
    /// Audit section (`[audit]` and `[audit.*]`) — sinks and per-class levels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSection>,
    /// Resource limits (`[ulimits]`) — a table of `name = "value"` pairs applied via
    /// `setrlimit(2)` in the seal. Nothing is set by default. The name is a short
    /// `setrlimit` resource (`nofile`, `nproc`, `as`, `cpu`, …); the value is `soft`,
    /// or `"soft:hard"`, each a number (with optional `K`/`M`/`G`) or `"unlimited"`.
    /// Validated at translate time; folds per-key like `[env].set`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<BTreeMap<String, String>>,
    /// The workload to run (`[workload]`). Optional: when absent, the command is given
    /// at `kennel run … -- <cmd>`. Folds scalar-wins up the chain like `[lifecycle]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadSection>,
    /// Terminal hardening (`[tty]`, §7.9.5): the escape-sequence filter on the
    /// workload→operator PTY stream. Folds scalar-wins up the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<TtySection>,
    /// Workspace trust marker (`[trust]`, §7.4): the masked `.trust-manifest.json` at
    /// each writable root. Folds scalar-wins up the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustSection>,
}

/// `[audit]`: sink selection, per-class levels, and per-sink tuning
/// (`docs/architecture/02-3-audit-schema.md` §Sink configuration). Levels and
/// sink names are validated at translate time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Active sinks (`file`, `journald`, `syslog`, `stdout`). Default `["file"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<String>,
    /// `[audit.file]` tuning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<AuditFileSection>,
    /// `[audit.syslog]` tuning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog: Option<AuditSyslogSection>,
    /// `[audit.journald]` — no fields; present to allow the empty table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journald: Option<AuditEmptySection>,
    /// `[audit.stdout]` — no fields; present to allow the empty table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<AuditEmptySection>,
    /// `[audit.network]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<AuditClassSection>,
    /// `[audit.filesystem]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<AuditClassSection>,
    /// `[audit.exec]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<AuditClassSection>,
    /// `[audit.unix]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<AuditClassSection>,
    /// `[audit.dbus]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbus: Option<AuditClassSection>,
}

/// `[audit.file]`: file-sink tuning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileSection {
    /// Override the per-kennel directory (placeholders allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Rotate at this size (e.g. `"64M"`, `"1G"`; bare = bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_at_bytes: Option<String>,
    /// Gzip a rotated file this many seconds after rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress_after_seconds: Option<u64>,
    /// Keep at most this many rotated files per class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_count: Option<u64>,
}

/// `[audit.syslog]`: syslog-sink tuning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSyslogSection {
    /// Syslog facility (`user`, `daemon`, `auth`, …). Default `user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<String>,
}

/// A `[audit.<class>]` level sub-table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditClassSection {
    /// One of `off`, `denies-only`, `summary`, `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// An empty `[audit.*]` table (journald, stdout: no fields).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEmptySection {}

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
    /// Allowlisted binary paths (the execve allowlist). Execution is deny-by-default:
    /// an empty/absent allow denies ALL execve; a bare `**`/`/**` is the explicit
    /// `permissive-exec` opt-out (the one case the compiler warns on). §7.3.4.
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
    /// The kennel's login shell (§7.9.2a): the synthetic-`passwd` `pw_shell` and
    /// `$SHELL`. Default `/bin/sh`; must be in [`allow`](Self::allow) when an
    /// allowlist is enforced (compile error otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
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
}

/// `[fs.home]` — the mandatory constructed-`$HOME` shim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsHome {
    /// Whether `$HOME` is shadowed by a constructed view (must be true once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<bool>,
    /// Home-relative paths that **persist** across runs (§7.9.2a). By default the
    /// synthesised dotfiles are reconstructed read-only each spawn (no
    /// self-poisoning); a path named here is *not* reconstructed, so a writable
    /// home grant for it survives. Opt-in, per path — this list is where the
    /// persistent-`~/.bashrc` re-execution trade-off is taken, visible in the diff.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persist: Vec<String>,
    /// Make the constructed `$HOME` **read-only** (default: writable). The home root
    /// is writable by default — a non-system user owns their home — but it is a fresh
    /// tmpfs, so writes are ephemeral. Setting this suppresses the home write grant:
    /// only explicitly `write`-granted `~/` paths are then writable, the rest of the
    /// home read-only. The escape hatch for a workload that must not write its home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
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
    /// (a serial console, `/dev/ppp`, `/dev/net/tun`; `docs/design/07-4-filesystem.md`
    /// §7.4.8). Each is loud: a documented `reason` and a threat tag are required,
    /// because passing a hardware device through widens the kernel attack surface and
    /// its DAC group right reaches into the kennel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough: Vec<DevPassthrough>,
}

/// One `[[fs.dev.passthrough]]` entry: a specific host device made available in the
/// kennel's constructed `/dev` (§7.4.8).
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

/// `[net]` and its sub-tables.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetSection {
    /// Egress mode: `"none"` (own empty net-ns, no interfaces), `"constrained"` (own net-ns,
    /// SOCKS proxy, default-deny — the default), `"unconstrained"` (own net-ns, SOCKS proxy,
    /// default-allow minus invariant + `net.deny` carve-outs), or `"host"` (host net-ns,
    /// direct egress, `net.allow` enforced by BPF/Landlock — no proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Required (non-empty) only when `mode = "host"`: the documented justification for
    /// sharing the host network stack, which reinstates the host-recon residual (T1.6).
    /// The compiler refuses `mode = host` without it; the T1.6 exposure is *derived*
    /// from the mode (surfaced by `kennel policy risks` / the `risks` engine), not
    /// stored on a `threats.reinstated` field (`07-5-network.md` §7.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// IPv4 proxy listen address as `"offset:port"` within the kennel's subnet. A
    /// family is enabled iff its address is set (there is no separate on/off flag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v4_address: Option<String>,
    /// IPv6 proxy listen address as `"offset:port"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v6_address: Option<String>,
    /// `[net.proxy]` — the user-space egress policy the per-kennel proxy enforces
    /// (`constrained`/`unconstrained`): by-name (+CIDR) allow/deny, resolve-and-pin, plus
    /// the non-removable `[[net.proxy.deny.invariant]]` floor. Not enforced in `mode=host`
    /// (no proxy runs there) — a `[net.proxy]` rule under `host` is a compile error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<NetProxy>,
    /// `[net.bpf]` — the kernel/syscall ACL (the cgroup `connect4/6` + `bind4/6` BPF and the
    /// matching Landlock grants): CIDR + port allow/deny, deny-first, **no names**. Present in
    /// every mode: in `host` it is the egress gate; in the proxied modes it is defence-in-depth
    /// (intersected with the framework's proxy-endpoint lock — an author rule can only narrow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf: Option<NetBpf>,
    /// `[net.bind]` — bind-address rewriting policy (the wildcard-rewrite knobs; the bind
    /// *allow/deny gate* is `[net.bpf.bind]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBind>,
    /// `[net.ipv6]` — IPv6-specific options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<NetIpv6>,
    /// `[net.audit]` — per-kennel egress audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<NetAudit>,
}

/// `[net.proxy]` — the user-space egress policy kenneld's proxy enforces (`07-5` §7.5.4).
///
/// Meaningful only in the proxied modes (`constrained`/`unconstrained`): kenneld resolves a
/// name, vets the answer against `allow`, re-checks the resolved address against `deny` +
/// `deny_invariant`, and pins it. In `mode=host` there is no proxy, so any rule here is a
/// compile error (names cannot be enforced by the kernel ACL — use `[net.bpf]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetProxy {
    /// `[[net.proxy.allow]]` — by-name (or by-CIDR) egress allow entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetAllow>,
    /// `[net.proxy.deny]` — the deny table: the non-removable `invariant` floor and the
    /// optional author `policy` denylist, both CIDR, both evaluated deny-first before `allow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<NetProxyDeny>,
}

/// `[net.proxy.deny]` — the proxy denies: the framework floor + the optional author list.
///
/// Two arrays in one table (TOML cannot nest `[[net.proxy.deny]]` under
/// `[[net.proxy.deny.invariant]]`): `invariant` is the non-removable floor (cloud-metadata /
/// link-local), `policy` is the author's optional subtraction (RFC1918, a known-bad range).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetProxyDeny {
    /// `[[net.proxy.deny.invariant]]` — cloud-metadata / link-local, non-removable (T1.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant: Vec<NetDenyRule>,
    /// `[[net.proxy.deny.policy]]` — the author's optional denylist (NOT mandatory).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<NetDenyRule>,
}

/// `[net.bpf]` — the kernel/syscall ACL (`07-5` §7.5.4): socket-family shaping + the
/// directional connect/bind allow-deny gates the cgroup BPF and Landlock enforce.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBpf {
    /// Permitted socket families (defence in depth; e.g. `["AF_INET", "AF_INET6", "AF_UNIX"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    /// Denied socket families (`inet_sock_create` returns EPERM): `AF_NETLINK`, `AF_PACKET`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_families: Option<Vec<String>>,
    /// `[net.bpf.connect]` — the outbound CONNECT ACL (cidr + ports, deny-first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<NetBpfAcl>,
    /// `[net.bpf.bind]` — the inbound BIND ACL (cidr + ports, deny-first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBpfAcl>,
}

/// One direction of the `[net.bpf]` kernel ACL: CIDR+port allow/deny, deny-first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBpfAcl {
    /// `[[net.bpf.connect.allow]]` / `[[net.bpf.bind.allow]]` — CIDR+port allow rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<BpfRule>,
    /// `[[net.bpf.connect.deny]]` / `[[net.bpf.bind.deny]]` — CIDR+port deny rules (deny-first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<BpfRule>,
}

/// One `[net.bpf]` rule: a CIDR (or `"*"` = any host) + ports + protocol. **No name field** —
/// the kernel ACL cannot resolve names, so a by-name rule is structurally inexpressible here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BpfRule {
    /// The CIDR (`"10.0.0.0/8"`, a bare address, or `"*"` = `0.0.0.0/0` + `::/0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Permitted ports (empty = any port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Transport protocol (`"tcp"`, `"udp"`, `"any"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Why this rule exists (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
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

/// One `[[net.proxy.deny.invariant]]` / `[[net.proxy.deny.policy]]` entry: a CIDR plus its
/// required `reason`.
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
    /// Explicit allowlist of bindable ports (§7.5.7). When non-empty, the workload may
    /// `bind()` only these ports (in addition to passing [`min_port`](Self::min_port));
    /// empty/absent means any port at or above `min_port`. At most
    /// [`MAX_BIND_PORTS`](crate::settled::MAX_BIND_PORTS) entries survive translation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ports: Option<Vec<u16>>,
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

/// `[binder]` — binder IPC policy (`docs/design/07-1-binder.md` §7.1.4).
///
/// Covers **user-defined** services only: the reserved `org.projectkennel.*` facades
/// (the af-unix shim) are enabled by their own sections and are never named
/// here. Source-only and realised by `kenneld`'s context manager, which gates
/// `addService`/`getService` against the resolved set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinderSection {
    /// `[[binder.provide]]` — services a process in this kennel may register.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provide: Vec<BinderProvide>,
    /// `[[binder.consume]]` — services this kennel may look up (cross-instance).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consume: Vec<BinderConsume>,
}

/// One `[[binder.provide]]` entry: a service this kennel registers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinderProvide {
    /// The service name (must not begin with the reserved `org.projectkennel.`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Peer kennels permitted to look this service up (cross-instance, §7.1.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept_from: Vec<String>,
    /// Why this service is provided (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// One `[[binder.consume]]` entry: a service this kennel looks up.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinderConsume {
    /// The service name (must not begin with the reserved `org.projectkennel.`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The providing kennel (cross-instance, §7.1.6); absent for a local service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Why this service is consumed (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[identity]` — the workload's identity inside the kennel (`docs/design/07-4-filesystem.md`).
///
/// Source-only and realised by `kenneld`: the supplementary Unix groups the confined
/// workload retains. By default a kennel carries **none** (the inherited host groups
/// are dropped by the privileged seal, §7.4); each name listed here is kept — but only
/// if the operator is actually a member (a group the user lacks is refused, never
/// granted, since the privileged `setgroups` could otherwise over-grant). Groups named
/// by `[[fs.dev.passthrough]]` are added automatically. The resolved set drives the
/// seal's `setgroups` and is named in the synthetic `/etc/group` so `id` shows names.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// The workload's masked user name — `$USER`/`$LOGNAME` and the synthetic
    /// `/etc/passwd` account, and the base of `$HOME` (`/home/<user>`). Defaults to
    /// `kennel` (a non-system, non-privileged account) when unset; an operator may
    /// override it. Validated as a portable username at translation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The workload's masked **primary** group name (synthetic `/etc/passwd` `pw_gid`
    /// name and the `/etc/group` entry for the primary gid). Defaults to `kennel`;
    /// validated as a portable name at translation. Distinct from `groups` below (the
    /// *supplementary* groups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Supplementary group names to retain (e.g. `["dialout", "plugdev"]`). The user
    /// must be a member of each; resolved to GIDs at spawn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// `[ssh]` — per-kennel SSH egress (source-only; `docs/design/07-10-ssh.md` §7.10).
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
    /// `true`, [`threats`](Self::threats) must carry an `exposed` tag (§7.10.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_headless: Option<bool>,
    /// Threat tags for the section — required to carry an `exposed` tag whenever
    /// `allow_headless = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
    /// `[[ssh.destinations]]` — the SSH egress allowlist. Each entry is one destination
    /// the kennel may reach; `kenneld` mints a per-destination synthetic key (the
    /// capability the kennel authenticates to the bastion with) bound to a forced
    /// command that runs `ssh <options> -- <dest>` **as the operator on the host**
    /// (§7.10.3). The destination — and which real key/port/config the host-side `ssh`
    /// uses — is fixed by *which synthetic key authenticated*, never by the workload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<SshDestination>,
}

/// One `[[ssh.destinations]]` entry: a destination the kennel may reach over the bastion.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshDestination {
    /// The SSH destination, in the form the host-side `ssh` is invoked with
    /// (`git@github.com`, `root@localhost`, a `~/.ssh/config` host alias). It is the
    /// capability the minted synthetic key stands for, never parsed from the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    /// Host-side `ssh` invocation options for this destination, passed verbatim as argv
    /// tokens before `<dest>` in the bastion's forced command (`-i ~/.ssh/id_x`,
    /// `-o IdentitiesOnly=yes`, `-p 2222`, …). They run **as the operator** and name
    /// which real key/port/config the outbound hop uses — host-side, never the kennel's
    /// choice. Trusted because the policy is operator-signed; passed as separate argv
    /// tokens (no shell), so a metacharacter cannot break out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// Why this destination is granted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[workload]` — the command the kennel runs, optionally pinned.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSection {
    /// The command + args (`argv[0]` is the program). Absent ⇒ supplied at `kennel run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Working directory inside the view (may carry a `~`/`<home>` placeholder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Refuse a CLI `--` override of `argv` unless `--force` (pin exactly what runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    /// Accepted lowercase-hex SHA-256 digests of the workload binary; the spawn verifies
    /// the binary against this set before exec. A list so multiple accepted versions of
    /// one binary validate under a single policy. Absent/empty ⇒ no pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Vec<String>>,
}

/// `[unsafe]` — the advisory footgun umbrella.
///
/// Its sub-sections describe controls whose *scoping is real* but is enforced by the
/// PID namespace + seccomp, not by the section itself. Grouping them under `[unsafe]`
/// makes the footgun visible; each present sub-section is warned at compile
/// (`footgun-warn-dont-forbid`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsafeSection {
    /// `[unsafe.ptrace]` — ptrace across the kennel boundary (scoping from PID-ns + seccomp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptrace: Option<BoundaryAcl>,
    /// `[unsafe.signal]` — signalling across the kennel boundary (scoping from PID-ns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<BoundaryAcl>,
}

/// A cross-boundary allowlist (`allow_targets`/`allow_from`), shared by the
/// `[unsafe.ptrace]` and `[unsafe.signal]` sub-sections.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryAcl {
    /// Permitted targets (`"self"`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_targets: Option<Vec<String>>,
    /// Permitted sources.
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
    /// What to do at TTL expiry: `"exit"` (alias `"stop"`, the default) ends the
    /// kennel; `"warn"` emits an audit event and leaves it running; `"renew"` is an
    /// audited `warn` today (the interactive renewal prompt is still owed, §9.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_action: Option<String>,
}

/// `[tty]` — terminal hardening for an interactive (PTY) workload (§7.9.5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TtySection {
    /// Filter the dangerous escape sequences a workload could write toward the
    /// operator's real terminal — OSC 52 (clipboard), OSC 9/777 (notifications),
    /// and the DCS/APC/PM/SOS opaque bands (`kennel-lib-term`, T2.6). Benign
    /// sequences (titles, hyperlinks, colour) pass through. Default `true`; set
    /// `false` only in an interactive template that needs raw terminal control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_terminal_escapes: Option<bool>,
}

/// `[trust]` — the masked workspace manifest (§7.4, T2.8).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSection {
    /// Maintain a `.trust-manifest.json` at the root of every writable/persistent
    /// workspace (the CLI generates it pre-flight; the view masks it invisible to the
    /// workload, so the agent cannot forge the integrity pins host tooling trusts).
    /// Default `true`; set `false` for a workload where host-side trigger trust is
    /// irrelevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<bool>,
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
    /// capability-granting entry (`[[net.proxy.allow]]`, `[[net.proxy.deny.*]]`,
    /// `[[net.bpf.*]]`, `[[unix.allow]]`).
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
            // A `template_base` is a versioned reference: `<name>@v<ver>`. The bare-name form is
            // rejected — the version must be inline so the lockfile pins an exact parent.
            if let Err(msg) = validate_reference(base) {
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
            if let Some(proxy) = &net.proxy {
                for a in &proxy.allow {
                    let who = a
                        .name
                        .as_deref()
                        .or(a.cidr.as_deref())
                        .unwrap_or("<unnamed>");
                    if is_blank(a.reason.as_deref()) {
                        errs.push(format!(
                            "[[net.proxy.allow]] \"{who}\" is missing a `reason`"
                        ));
                    }
                }
                if let Some(deny) = &proxy.deny {
                    for d in deny.invariant.iter().chain(&deny.policy) {
                        if is_blank(d.reason.as_deref()) {
                            errs.push(format!(
                                "[[net.proxy.deny]] \"{}\" is missing a `reason`",
                                d.cidr
                            ));
                        }
                    }
                }
            }
            if let Some(bpf) = &net.bpf {
                let acls = bpf.connect.iter().chain(&bpf.bind);
                for acl in acls {
                    for r in acl.allow.iter().chain(&acl.deny) {
                        let who = r.cidr.as_deref().unwrap_or("<no-cidr>");
                        if is_blank(r.reason.as_deref()) {
                            errs.push(format!("[[net.bpf]] \"{who}\" is missing a `reason`"));
                        }
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
            for d in &ssh.destinations {
                let who = d.dest.as_deref().unwrap_or("<no-dest>");
                if is_blank(d.reason.as_deref()) {
                    errs.push(format!(
                        "[[ssh.destinations]] \"{who}\" is missing a `reason`"
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
        let deny = net.proxy.expect("net.proxy").deny.expect("net.proxy.deny");
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
        let proxy = net.proxy.expect("net.proxy");
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
        assert!(
            proxy.allow.iter().all(|a| !is_blank(a.reason.as_deref())),
            "every allow has a reason"
        );
        let unix = pol.unix.expect("unix");
        // The shim grants a per-kennel gpg-agent (a non-SSH agent socket). SSH is
        // NOT shimmed — it goes through the §7.10 bastion via the [ssh] section.
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
    fn container_block_is_now_rejected_at_parse() {
        // [container] was design-level language (parse + compile-warn, no runtime). It is now
        // removed from the schema entirely — assumptions on unbuilt code are off — so a policy
        // declaring it fails `deny_unknown_fields` at parse, rather than compiling with a warning.
        let src = "\
template_name = \"x\"
[container]
image = \"docker.io/library/postgres:17\"
";
        assert!(
            parse(src.as_bytes()).is_err(),
            "[container] is no longer a known section"
        );
    }

    #[test]
    fn containerised_service_is_an_honest_direct_service() {
        // The rewritten template carries NO [container] block — the kennel is the
        // container. It derives base-confined, persists one data dir, and stays
        // deny-by-default on exec (the leaf adds the server binary).
        let pol = parse(CONTAINERISED_SERVICE.as_bytes()).expect("parse");
        let fs = pol.fs.expect("fs");
        assert!(
            fs.write
                .as_deref()
                .is_some_and(|w| w.iter().any(|p| p.contains("data/<kennel>"))),
            "persists one data dir"
        );
    }

    #[test]
    fn ulimits_section_parses_into_a_name_value_map() {
        let src = "template_name = \"x\"\n\n[ulimits]\nnofile = \"8192\"\nas = \"4G\"\ncpu = \"unlimited\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let ulimits = pol.ulimits.expect("ulimits");
        assert_eq!(ulimits.get("nofile").map(String::as_str), Some("8192"));
        assert_eq!(ulimits.get("as").map(String::as_str), Some("4G"));
        assert_eq!(ulimits.get("cpu").map(String::as_str), Some("unlimited"));
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
                   [[net.proxy.allow]]\nname = \"evil.example\"\nports = [443]\n";
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
