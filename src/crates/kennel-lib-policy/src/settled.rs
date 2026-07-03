//! The settled-policy types — the flat, signed, runtime artefact consumed by
//! `kennel-lib-spawn`.
//!
//! This is the resolved output of `kennel compile`: no `template_base`, no
//! `include`, no delta operators — only the final effective rules, plus
//! provenance and a single signature. The template/resolution machinery that
//! *produces* a settled policy (chain-walking, includes, deltas, the lockfile)
//! lives in the separate `kennel-lib-compile` crate but is a separate,
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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::variant::Manifest;

/// The reserved binder service namespace `kenneld` owns (`07-1-binder.md` §Naming).
///
/// User-defined services may not begin with it. It lives in the runtime crate
/// because `kenneld` gates `addService`/`getService` against it at runtime; the
/// policy compiler's binder validator rejects user services that claim it.
pub const RESERVED_PREFIX: &str = "org.projectkennel.";

/// Network enforcement mode — four tiers (`07-5-network.md` §7.5).
///
/// The proxy/own-netns pair (`constrained`/`unconstrained`) differ only in the proxy's
/// default verdict; `open` is host-netns direct egress with its own BPF/Landlock allowlist;
/// `none` is total isolation. A truly unrestricted (no invariant denies) mode is not
/// representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum NetMode {
    /// No network at all: an own net namespace with no interfaces (not even `lo`).
    None,
    /// Own net namespace, egress via the SOCKS proxy, **default-deny**: only the
    /// `net.allow` allowlist passes (the default posture).
    Constrained,
    /// Own net namespace, egress via the SOCKS proxy, **default-allow**: everything
    /// passes except the always-on invariant denies and any `net.deny` carve-outs.
    Unconstrained,
    /// **Host** net namespace, **direct** egress (no SOCKS proxy, no `HTTPS_PROXY`); the
    /// `net.allow` allowlist is still enforced via BPF + Landlock. Shares the host network
    /// stack, so it reinstates the host-recon residual (T1.6) — it requires a non-empty
    /// `net.reason`; the T1.6 exposure is derived from the mode (surfaced by
    /// `kennel policy risks`), not stored on a `threats.reinstated` field (`07-5-network.md` §7.5.1).
    Host,
}

/// Transport protocol selector for a network rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum Protocol {
    /// Any protocol.
    Any,
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
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

/// What to do when a kennel's TTL expires (Kennel book Vol 2 ch.16 (The Policy Compiler)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum TtlAction {
    /// Terminate the kennel cleanly. The default for a policy that sets a `ttl` without an
    /// action. (With the cgroup freezer this is an atomic freeze-then-kill — no SIGTERM grace
    /// race — but the intent is unchanged: the kennel stops at its deadline.)
    #[default]
    Exit,
    /// Leave the workload running; emit an audit event only.
    Warn,
    /// Request renewal: emit a renewal-requested audit event and leave the workload
    /// running. The interactive user-session prompt (notification/terminal) is the
    /// remaining piece — kenneld is a daemon with no session channel — so today this
    /// behaves as a distinct, louder `warn`. See `08-as-built-notes.md §8.1`.
    Renew,
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

/// Whether a policy name `pattern` matches a destination/query `name`, by the proxy's
/// dot-convention.
///
/// This is the single source both the egress proxy (`kenneld`'s `NetRuntime`) and the UDP-egress
/// broker's naming shim (`kennel-udp-broker`) match names against, so the two cannot drift:
///
/// - a plain pattern (`example.com`) matches that name **exactly** — the safe whitelist default, so
///   an allow of `example.com` does not silently admit subdomains;
/// - a leading dot (`.example.com`) matches the apex **and** any subdomain (`example.com`,
///   `api.example.com`) on a label boundary, so it does not match `notexample.com`.
///
/// Case-insensitive (ASCII).
#[must_use]
pub fn name_matches(pattern: &str, name: &str) -> bool {
    pattern.strip_prefix('.').map_or_else(
        || pattern.eq_ignore_ascii_case(name),
        |apex| name.eq_ignore_ascii_case(apex) || ends_with_label(name, pattern),
    )
}

/// Whether `name` ends with the dotted `suffix` (e.g. `.example.com`) on a label boundary,
/// case-insensitively. `suffix` includes its leading dot, so the match is inherently label-aligned.
fn ends_with_label(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len()
        && name
            .get(name.len().saturating_sub(suffix.len())..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod name_match_tests {
    use super::name_matches;

    #[test]
    fn plain_pattern_matches_exactly_only() {
        assert!(name_matches("example.com", "example.com"));
        assert!(
            name_matches("example.com", "EXAMPLE.COM"),
            "case-insensitive"
        );
        assert!(
            !name_matches("example.com", "api.example.com"),
            "no implicit subdomain"
        );
        assert!(!name_matches("example.com", "notexample.com"));
    }

    #[test]
    fn dotted_pattern_matches_apex_and_subdomains_on_a_label_boundary() {
        assert!(name_matches(".example.com", "example.com"), "apex");
        assert!(name_matches(".example.com", "api.example.com"), "subdomain");
        assert!(
            name_matches(".example.com", "a.b.example.com"),
            "deep subdomain"
        );
        assert!(
            !name_matches(".example.com", "notexample.com"),
            "label boundary"
        );
        assert!(!name_matches(".example.com", "example.com.evil.net"));
    }
}

/// Where the per-kennel egress proxy listens, resolved from the source policy's
/// `proxy_listen_*_address = "offset:port"` (Kennel book Vol 2 ch.8 (The Network)).
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

impl ProxyListen {
    /// The "no proxy" marker — `offset 0` (reserved, never a real listener).
    ///
    /// Used by the non-proxied modes (`open`/`none`) so the daemon stands up no SOCKS facade
    /// and the settled policy says so explicitly. [`is_disabled`](Self::is_disabled) tests it.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { offset: 0, port: 0 }
    }

    /// Whether this is the [`disabled`](Self::disabled) (no-proxy) marker.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.offset == 0
    }
}

/// Network policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetPolicy {
    /// Enforcement mode.
    pub mode: NetMode,
    /// Whether UDP egress is enabled (`[net.udp]`, W2): the tun + fenced-broker path on the
    /// proxied modes. The destination grants are [`udp_allow_names`](Self::udp_allow_names).
    /// Omitted from the canonical form when false, so a policy without it signs unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp: bool,
    /// Lowest port the workload may `bind()` (`[net.bind].min_port`, §7.5.7). A bind
    /// below this is denied by the cgroup `bind4`/`bind6` BPF — the privileged-port
    /// protection (T6, §7.5.9 item 17). `0` means no minimum is enforced. Carried into
    /// the `kennel_meta` BPF map (the repurposed `_pad0` slot); omitted from the
    /// canonical form when `0`, so a policy without it signs unchanged. Declared before
    /// the table fields so the canonical TOML emits this scalar before them.
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub bind_port_min: u16,
    /// Explicit bind-port allowlist (`[net.bind].allowed_ports`, §7.5.7).
    ///
    /// When non-empty, the workload may `bind()` only these ports (and still no lower
    /// than [`bind_port_min`](Self::bind_port_min)); empty means any port at or above
    /// the floor. Capped at [`MAX_BIND_PORTS`] by translation (the `bind_subnet` BPF map
    /// carries a fixed-size array). Carried into the `bind_subnet` map; omitted from the
    /// canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_allowed_ports: Vec<u16>,
    /// Where the egress proxy listens (offset + port within the kennel's subnet).
    #[serde(default)]
    pub proxy: ProxyListen,
    /// Allowlisted destinations **by address** — the by-CIDR half of `[net.proxy.allow]`. Enforced by
    /// the per-kennel egress **proxy**: `kenneld`'s `NetRuntime` builds its allowlist as the union of
    /// this and [`allow_names`](Self::allow_names) (`inet.rs`), re-checking each against the deny rules
    /// before it pins and dials. The cgroup BPF connect/bind ACL is the *separate* `[net.bpf]`
    /// mechanism (CIDR-only, the primary gate only in `mode = host`, where `[net.proxy]` is rejected at
    /// compile); a `net.proxy.allow` rule does **not** populate the BPF map.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetRule>,
    /// Allowlisted destinations **by name** — the by-name half of `[net.proxy.allow]`. Enforced only by
    /// the per-kennel egress proxy (the BPF cannot match names); consulted in `constrained` mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_names: Vec<NameRule>,
    /// UDP egress destinations **by name** — the grants from `[[net.udp.allow]]` (`[net.udp]`, W2),
    /// each a `Protocol::Udp` [`NameRule`]. Carried SEPARATELY from
    /// [`allow_names`](Self::allow_names): the egress proxy is TCP-CONNECT and protocol-blind over
    /// `allow_names` (`inet.rs` maps every entry into a proxy rule), so a UDP name must never enter
    /// that list. The fenced broker (the tun's flow provider) is the sole consumer; omitted from the
    /// canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_allow_names: Vec<NameRule>,
    /// Invariant deny CIDRs (cloud metadata, link-local, RFC1918). Must be
    /// present; cannot be removed by any delta.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_invariant: Vec<NetRule>,
    /// Author denylist from `[net.proxy.deny.policy]` (`07-5` §7.5.4): the optional,
    /// removable CIDR denies the proxy evaluates deny-first alongside
    /// [`deny_invariant`](Self::deny_invariant). Honoured only by the proxy (the proxied
    /// modes); omitted from the canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_author: Vec<NetRule>,
    /// The kernel CONNECT allow ACL from `[net.bpf.connect.allow]` (`07-5` §7.5.4): CIDR+port
    /// rules the cgroup `connect4`/`connect6` BPF permits. No names (the kernel cannot resolve
    /// them). Omitted from the canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bpf_connect_allow: Vec<NetRule>,
    /// The kernel CONNECT deny ACL from `[net.bpf.connect.deny]` (`07-5` §7.5.4): CIDR+port
    /// rules the cgroup connect BPF refuses, evaluated deny-first. Omitted from the canonical
    /// form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bpf_connect_deny: Vec<NetRule>,
    /// The kernel BIND allow ACL from `[net.bpf.bind.allow]` (`07-5` §7.5.4): CIDR+port rules
    /// the cgroup `bind4`/`bind6` BPF permits. Omitted from the canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bpf_bind_allow: Vec<NetRule>,
    /// The kernel BIND deny ACL from `[net.bpf.bind.deny]` (`07-5` §7.5.4): CIDR+port rules the
    /// cgroup bind BPF refuses, evaluated deny-first. Omitted from the canonical form when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bpf_bind_deny: Vec<NetRule>,
}

/// `skip_serializing_if` helper: a `u16` that is `0`.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

/// The maximum number of `[net.bind].allowed_ports` entries (§7.5.7).
///
/// The `bind_subnet` BPF map carries a fixed-size array of this width, so a policy
/// listing more is a translation error (the author learns the limit rather than having
/// ports silently dropped).
pub const MAX_BIND_PORTS: usize = 8;

/// Capacity of each per-family cgroup-BPF **allow** LPM trie (`allow_v4`/`allow_v6`).
///
/// AUTHORITATIVE SOURCE: `src/bpf/maps.h` (`allow_v4`/`allow_v6` `max_entries`). Mirrored
/// here so translation can reject an over-large allowlist with a clear error rather than
/// letting the `(N+1)`th map update fail opaquely at spawn (`ENOSPC`/`E2BIG`). Counted
/// per family per map AFTER `cidr = "*"` expands to both families.
pub const MAX_BPF_ALLOW_PER_FAMILY: usize = 1024;

/// Capacity of each per-family cgroup-BPF **deny** LPM trie (`deny_v4`/`deny_v6`).
///
/// AUTHORITATIVE SOURCE: `src/bpf/maps.h` (`deny_v4`/`deny_v6` `max_entries`). The deny
/// map carries the invariant floor PLUS the author's `[net.bpf].*.deny` and
/// `[net.proxy].deny.policy` — author-extensible since the `[net.proxy]`/`[net.bpf]`
/// split — so this bound is now reachable and must be enforced at compile time.
pub const MAX_BPF_DENY_PER_FAMILY: usize = 256;

/// Private-`/tmp` tmpfs parameters (§7.4.6).
///
/// The settled policy carries the resolved numeric size; the source policy's
/// human form (`size = "512M"`) is converted to mebibytes at compile time so the
/// runtime parses a plain integer, not a units string.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TmpPolicy {
    /// Whether the workload may **write** to its `/tmp` tmpfs (the Landlock write grant). `/tmp` is
    /// always a fresh per-kennel tmpfs in the constructed view; `false` withholds the write grant,
    /// leaving it read-only. (It never binds the host `/tmp`.)
    pub writable: bool,
    /// Size cap of the tmpfs, in mebibytes.
    pub size_mib: u32,
}

/// Device-file policy (§7.4.8): which `/dev` nodes the kennel's constructed
/// `/dev` exposes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevPolicy {
    /// Device paths the kennel may access (absolute, under `/dev` — e.g.
    /// `/dev/null`, `/dev/urandom`, `/dev/tty`). The runtime refuses any entry
    /// outside `/dev` or carrying a `..` component before it binds it.
    pub allow: Vec<String>,
}

/// How the invocation cwd is materialised into the view (`[fs.cwd].grant`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum CwdGrant {
    /// The invocation cwd is not materialised (default).
    #[default]
    None,
    /// The invocation cwd is bound **read-only** into the view.
    Read,
    /// The invocation cwd is bound **writable** into the view.
    Write,
}

impl CwdGrant {
    /// Whether no cwd grant is declared (the default; omitted from the canonical form).
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// The invocation-cwd grant (`[fs.cwd]`, §7.9): a signed policy declares that the
/// directory `kennel run` is invoked from is materialised into the view.
///
/// The grant is a *slot*: the policy states the mode and the required markers, and the
/// spawn fills it with the resolved invocation cwd, subject to a non-overridable framework
/// floor (realpath-normalised, operator-owned, never `$HOME`) checked host-side. `reason`
/// is compile-time-only (validated, then dropped like other informational fields), so the
/// settled artefact carries only the enforced shape.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CwdPolicy {
    /// Whether and how the invocation cwd is bound into the view.
    #[serde(default, skip_serializing_if = "CwdGrant::is_none")]
    pub grant: CwdGrant,
    /// Dirent markers that must be present in the invocation cwd for the grant to apply
    /// (e.g. `.git`, `.claude/`; a trailing slash requires a directory). Empty ⇒ no marker
    /// requirement. A marker that is absent refuses the run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

impl CwdPolicy {
    /// Whether this is the default (no grant, no markers) — omitted from the canonical form
    /// so a policy without a `[fs.cwd]` signs exactly as before.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.grant.is_none() && self.required.is_empty()
    }
}

/// Filesystem policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsPolicy {
    /// Whether `$HOME` is shadowed by the shim (must be true).
    pub home_shadow: bool,
    /// Paths granted read (and directory-read/execute) access.
    pub read: Vec<String>,
    /// Paths granted write access.
    pub write: Vec<String>,
    /// Writable paths bound **exclusively** (§2.7, T2.8): while the kennel runs, `kenneld`
    /// over-mounts an opaque sentinel on the host path (a transient privhelper op) so the
    /// operator and the workload cannot use it concurrently. Each is also in `write`. Empty ⇒
    /// none. Compile and the privhelper both verify the operator owns / can write each host
    /// path before the privileged blind mount.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusive: Vec<String>,
    /// Home-relative paths that persist across runs (§7.9.2a). The synthesised
    /// dotfiles are reconstructed read-only each spawn except for the paths named
    /// here, which the dotfile seeder skips. Empty ⇒ everything is reconstructed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub home_persist: Vec<String>,
    /// Whether the constructed `$HOME` is read-only (`[fs.home].readonly`). False (the
    /// default) gives the home root a Landlock write grant — the workload owns its
    /// ephemeral home; true suppresses it, so only `write`-granted `~/` paths are
    /// writable. Omitted from the canonical form when false, so a policy without it
    /// signs unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    pub home_readonly: bool,
    /// The invocation-cwd grant. Declared among the sub-tables so the canonical TOML
    /// emits it as a table; omitted entirely when default, so a policy without a
    /// `[fs.cwd]` signs exactly as before.
    #[serde(default, skip_serializing_if = "CwdPolicy::is_default")]
    pub cwd: CwdPolicy,
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
    /// enforced beyond the deny flags". Exact-match entries named in
    /// [`deny`](Self::deny) are already subtracted here at translation.
    pub allow: Vec<String>,
    /// Denylisted absolute paths or globs (§7.3.4), composed up the template chain
    /// and carried for audit and runtime warning. Landlock is allow-only and cannot
    /// subtract a single path from a granted directory, so a deny is *enforced* only
    /// where it removes an exact `allow` entry (done at translation) or where the
    /// path is simply never granted; a deny that falls inside an allowed directory
    /// (or that is set without any `allow`) is *advisory* and warned about at compile
    /// and spawn. See [`Self::deny_warnings`]. Omitted from the canonical form when
    /// empty, so an existing policy with no `exec.deny` signs unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// `PATH` search roots, synthesised into the workload's `$PATH` (§7.3.6).
    /// Empty ⇒ `$PATH` is not set from policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// The kennel's login shell (synthetic-`passwd` `pw_shell` and `$SHELL`,
    /// §7.9.2a). Defaults to `/bin/sh`; must be in [`allow`](Self::allow) when an
    /// allowlist is enforced.
    #[serde(default = "default_shell", skip_serializing_if = "is_default_shell")]
    pub shell: String,
    /// The **resolved dynamic loaders** of [`allow`](Self::allow): the absolute `PT_INTERP`
    /// (`ld.so`) path of each allowlisted dynamic binary, computed at compile time
    /// ([`crate::libresolve`]). The runtime grants `EXECUTE` on these in addition to the
    /// binaries, because the kernel opens a dynamic binary's loader `FMODE_EXEC` during
    /// `execve` and Landlock gates it (`07-3-exec`). The binary's *libraries* are NOT listed:
    /// the loader `mmap`s them and Landlock does not gate `mmap`, so they load via `READ`
    /// alone — the kennel makes no (unenforceable) execute claim over them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loaders: Vec<String>,
}

impl ExecPolicy {
    /// Warnings for [`deny`](Self::deny) entries that cannot be enforced by Landlock.
    ///
    /// Landlock grants execution; it cannot *subtract* a path from a granted
    /// directory. Execution is deny-by-default, so translation already removes any
    /// deny that exactly matches an `allow` entry (enforced — the binary is simply
    /// never granted `EXECUTE`), and an empty allowlist denies everything. What
    /// remains warnable:
    ///
    /// - a deny that falls **inside an allowed directory/glob** (e.g. `allow =
    ///   ["/usr/bin/**"]`, `deny = ["/usr/bin/sudo"]`): the directory grant
    ///   re-exposes it, so the deny is advisory only; and
    /// - **any** deny under the explicit `**` `permissive-exec` opt-in: execution is
    ///   ungated, so Landlock cannot subtract a single path and the deny does nothing.
    ///
    /// A deny against an empty allowlist is *redundant* (everything is already denied)
    /// — harmless, so no warning. A deny simply never granted is enforced by omission.
    /// Returns one message per warnable deny.
    #[must_use]
    pub fn deny_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let permissive = self.allow.iter().any(|a| matches!(a.trim(), "**" | "/**"));
        for d in &self.deny {
            if permissive {
                out.push(format!(
                    "exec.deny `{d}` is advisory: `permissive-exec` (`**`) grants all execution, so \
                     Landlock cannot subtract a single path — the deny enforces nothing"
                ));
            } else if let Some(dir) = self.allow.iter().find(|a| glob_covers(a, d)) {
                out.push(format!(
                    "exec.deny `{d}` falls inside allowed directory `{dir}`: Landlock cannot subtract a \
                     single path from a granted directory, so this deny is advisory only"
                ));
            }
            // else: empty allow ⇒ deny-by-default already denies everything (the deny
            // is redundant), or the path is simply never granted (enforced by
            // omission). Either way there is nothing to warn about.
        }
        out
    }
}

/// Whether glob/dir `allow` entry covers path `deny` (a `…/*` or `…/**` whose root is
/// a prefix of `deny`). An exact non-glob `allow` does not "cover" — that case is
/// handled by exact-match subtraction at translation.
fn glob_covers(allow: &str, deny: &str) -> bool {
    let root = allow
        .strip_suffix("/**")
        .or_else(|| allow.strip_suffix("/*"))
        .or_else(|| allow.strip_suffix("**"))
        .or_else(|| allow.strip_suffix('*'));
    root.is_some_and(|root| {
        let root = root.trim_end_matches('/');
        !root.is_empty() && (deny == root || deny.starts_with(&format!("{root}/")))
    })
}

/// The default kennel login shell.
#[must_use]
pub fn default_shell() -> String {
    "/bin/sh".to_owned()
}

fn is_default_shell(s: &str) -> bool {
    s == "/bin/sh"
}

/// Procfs policy.
///
/// Procfs is always mounted self-only (the workload sees only its own processes);
/// that is structural, not a setting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcPolicy {
    /// Mount `/proc` with `hidepid=2`: even within the PID namespace, `/proc/<pid>`
    /// is accessible only to the process owner. Belt-and-braces atop the namespace,
    /// which is the strong isolation.
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
    /// `kennel_lib_syscall::seccomp::syscall_number` (`libc::SYS_*`) at plan time. An
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

/// Terminal hardening (`[tty]`, §7.9.5): the PTY escape filter on the
/// workload→operator stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TtyPolicy {
    /// Filter the dangerous escape sequences (OSC 52 clipboard, OSC 9/777
    /// notifications, DCS/APC/PM/SOS bands) out of the workload's terminal output
    /// (T2.6). Default `true`.
    pub filter_terminal_escapes: bool,
}

impl Default for TtyPolicy {
    /// The secure default: filtering on.
    fn default() -> Self {
        Self {
            filter_terminal_escapes: true,
        }
    }
}

/// The live `on_change` disposition (§2.5, T2.8): what `kenneld` does the moment a watched
/// execution trigger is mutated *during* the run.
///
/// Distinct from the host-side teardown disposition. Unprivileged: it acts on the workload
/// via the cgroup `kenneld` already owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum OnChangeAction {
    /// Record an `fs.mutation` audit event and let the workload run on (the live watch is
    /// best-effort; the authoritative verdict is the teardown review).
    #[default]
    Warn,
    /// Suspend the workload — freeze the cgroup — so the operator can inspect and decide.
    Freeze,
    /// Terminate the workload (kill the cgroup).
    Kill,
}

/// `[trust]` — the masked workspace manifest + the live tripwire disposition (§7.4, §2.5, T2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// Maintain a masked `.trust-manifest.json` at each writable root. Default `true`.
    pub manifest: bool,
    /// What `kenneld` does when a watched trigger is mutated during the run. Default `warn`.
    #[serde(default)]
    pub on_change: OnChangeAction,
}

impl Default for TrustPolicy {
    /// The secure default: the manifest is maintained; a live mutation is warned (audited).
    fn default() -> Self {
        Self {
            manifest: true,
            on_change: OnChangeAction::Warn,
        }
    }
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
    /// Terminal hardening (the PTY escape filter, §7.9.5).
    #[serde(default)]
    pub tty: TtyPolicy,
    /// Workspace trust marker (the masked `.trust-manifest.json`, §7.4).
    #[serde(default)]
    pub trust: TrustPolicy,
}

/// The per-kennel SSH runtime: the bastion grants `kenneld` realises (§7.10).
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
    /// touch (loud, threat-tagged at compile time; §7.10.6).
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_headless: bool,
    /// The granted destinations — one minted synthetic key + one bastion forced command
    /// each (§7.10.3). The synthetic key is the capability the kennel authenticates with;
    /// the destination + options are realised host-side by the bastion, as the operator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<SshGrant>,
}

impl SshRuntime {
    /// Whether there is nothing to realise (no grant, default headless).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.allow_headless && self.grants.is_empty()
    }
}

impl SshGrant {
    /// A stable, filename-safe id for this destination's synthetic keypair under
    /// `<policy-dir>/ssh/`. Derived from `dest` (not its index), so re-compiling a policy
    /// whose destinations were reordered reuses the same persisted keys. The form is
    /// `ssh-<16 hex>`: a non-cryptographic [`std::hash`] digest of `dest` — this is only a
    /// filename (collision merely shares a key file between two literally-distinct dests,
    /// which the compiler avoids by also de-duplicating destinations), not a security
    /// boundary, so no `sha2` dependency is pulled in for it.
    #[must_use]
    pub fn key_id(&self) -> String {
        use std::hash::{Hash as _, Hasher as _};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.dest.hash(&mut h);
        format!("ssh-{:016x}", h.finish())
    }
}

/// One granted SSH destination: a host the kennel may reach over the bastion.
///
/// The synthetic keypair is minted at **compile time** (`kennel policy compile`), once
/// per `(policy, destination)`, and persisted beside the artifact in the policy dir; the
/// public half is recorded here and so is **signature-pinned** (the akc trusts only a key
/// whose public half matches a signed grant), while the private half lives in a file the
/// kennel's `~/.ssh` is materialised from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshGrant {
    /// The SSH destination the host-side `ssh` connects to (`git@github.com`), fixed by
    /// which synthetic key authenticated — never parsed from the wire.
    pub dest: String,
    /// Host-side `ssh` invocation options, prepended verbatim (as argv tokens) before
    /// `<dest>` in the bastion's forced command (`-i …`, `-o …`, `-p …`). They run as the
    /// operator and name which real key/port/config the outbound hop uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// The synthetic public key bound to this destination (`ssh-ed25519 AAAA…`), pinned
    /// by the policy signature: the akc authorises an offered key only if its public half
    /// matches this. Empty until the compiler mints the keypair (an unsigned/in-memory
    /// compile may leave it empty, in which case no SSH route is realised).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    /// The basename of the minted keypair under `<policy-dir>/ssh/` (a stable, filename-
    /// safe id derived from `dest`). The private half is `<key_file>`, the public half
    /// `<key_file>.pub`; the kennel's `~/.ssh` is materialised from the private half.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_file: String,
}

/// The per-kennel `AF_UNIX` socket shims `kenneld` realises (Kennel book Vol 2 ch.9 (Local Services)).
///
/// Like [`SshRuntime`], a *service* input rather than enforcement: `kenneld` binds
/// each granted host socket into the kennel's constructed view at its shim path and
/// sets any named env var, so the application finds its socket at the standard path.
/// What is *not* bound in is structurally absent (default-deny). Abstract-namespace
/// connections are denied unconditionally by the always-on Landlock scope (ABI 6+,
/// §7.6.3), so they are not represented here. Carried in the signed settled policy
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

/// The per-kennel D-Bus runtime (§7.7) — a *service* input `kenneld` realises (the
/// `IDBus` facade/delegate pair), not part of the enforcement core.
///
/// Carries the resolved `[dbus]` rule set the operator-context delegate compiles into its
/// match table at construction. Absent (empty) for a kennel with no `[dbus]` policy — then
/// omitted from the canonical form, so a policy without D-Bus signs exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DbusRuntime {
    /// Audit verbosity (`"off"`/`"summary"`/`"full"`); default `"summary"` realised by kenneld.
    /// A scalar — declared before the bus tables so the canonical TOML emits values first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_level: Option<String>,
    /// The session bus rule set, present iff `[dbus.session].enabled = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<DbusBusRuntime>,
    /// The system bus rule set, present iff `[dbus.system].enabled = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<DbusBusRuntime>,
}

impl DbusRuntime {
    /// Whether there is no D-Bus access to realise (no enabled bus).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.session.is_none() && self.system.is_none()
    }
}

/// One enabled bus's resolved rules — the allow/deny lists at destination/interface/
/// member granularity, as the facade's match table is built from.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DbusBusRuntime {
    /// Destinations the kennel may call (and receive replies/signals from).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub talk: Vec<String>,
    /// Specific `destination=interface.member` calls (finer than `talk`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call: Vec<String>,
    /// Signals the kennel may receive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcast: Vec<String>,
    /// Names the kennel may own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub own: Vec<String>,
    /// Explicit denies layered over the allow lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_talk: Vec<String>,
}

/// The typed shape of a mesh capability: how its connector is delivered.
///
/// Declared on both `[[provides]]` and `[[consumes]]` and carried verbatim into the
/// settled policy; defined here so the source parser and the signed runtime share one type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum Shape {
    /// An `AF_UNIX` socket the workload connects to (the display render leg).
    AfUnix,
    /// Reachability of a D-Bus name through the `IDBus` facade (§7.7).
    DbusName,
    /// A connector to a binder node the provider offers (§7.1).
    BinderConnector,
}

impl Shape {
    /// The canonical kebab-case name (`af-unix`/`dbus-name`/`binder-connector`), for
    /// display in policy tooling and audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AfUnix => "af-unix",
            Self::DbusName => "dbus-name",
            Self::BinderConnector => "binder-connector",
        }
    }
}

/// The cross-kennel capability mesh runtime (`07-13-service-catalog.md` §7.13) — the
/// `[[provides]]`/`[[consumes]]` the broker (§7.13.4) and catalogue read at runtime.
///
/// A *service* input `kenneld` realises, not part of the kernel-enforcement core. Carried in
/// the signed settled policy; omitted from the canonical form when empty, so a policy with no
/// mesh declarations signs exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRuntime {
    /// Capabilities this kennel offers (`[[provides]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<ProvideRuntime>,
    /// Capabilities this kennel reaches (`[[consumes]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumes: Vec<ConsumeRuntime>,
}

impl MeshRuntime {
    /// Whether there is no mesh grant to realise.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.provides.is_empty() && self.consumes.is_empty()
    }
}

/// One offered capability: a public name, its shape, where it is exposed, and an optional
/// private match token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvideRuntime {
    /// The capability's public identifier — what the catalogue advertises.
    pub name: String,
    /// The typed transport.
    pub shape: Shape,
    /// Where the capability is exposed, in the provider's own view.
    pub endpoint: String,
    /// Optional private match token, never advertised in the catalogue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// One reached capability: a name, the expected shape, where the connector is delivered,
/// the env naming it, an optional match token, and whether it is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeRuntime {
    /// The capability's public identifier, resolved against the catalogue at runtime.
    pub name: String,
    /// The expected transport; the broker refuses a mismatched shape.
    pub shape: Shape,
    /// Where the brokered connector is delivered, in this kennel's own view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// Environment variable(s) synthesised into this kennel to name the connector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Optional private match token; must match the provider's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Whether the capability's absence fails kennel construction (hard dependency).
    pub required: bool,
}

/// The restart discipline for a service kennel (`07-13-service-catalog.md` §7.13.7) — how
/// `kenneld` supervises a provider the operator has enabled. The systemd `Restart=` analogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum RestartPolicy {
    /// Restart on any exit — a long-running service expected to stay up.
    Always,
    /// Restart only on a non-zero exit or signal (the default). A clean exit is *done*.
    #[default]
    OnFailure,
    /// Run once; any exit, clean or not, leaves it down.
    Never,
}

// The authored value-set enums: the canonical closed sets the source-policy `String` fields
// accept. The fields stay `String` (lenient authoring, scalar-chain folding), but the schema
// enumerates them from these types via `#[schema(values_from = …)]` — so the editor hint is
// derived from a real type, never a hand-written list.

/// Rootfs upper-layer persistence (`[rootfs].persistence`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum Persistence {
    /// Ephemeral upper, discarded at teardown (default).
    Discard,
    /// Managed upper retained under the store entry.
    Persist,
}

/// Disposition of a wildcard (`INADDR_ANY`/`IN6ADDR_ANY`) bind (`[net.bind].*_any_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum WildcardBindPolicy {
    /// Rewrite a wildcard bind to the kennel's own address.
    Rewrite,
    /// Refuse a wildcard bind.
    Deny,
}

/// Per-kennel egress audit verbosity (`[net.audit].level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum NetAuditLevel {
    /// One summary line per connection.
    Summary,
    /// Full per-event detail.
    Full,
}

/// D-Bus call audit verbosity (`[dbus.audit].level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum DbusAuditLevel {
    /// No D-Bus audit events.
    Off,
    /// One summary line per call.
    Summary,
    /// Full per-call detail.
    Full,
}

/// Per-class audit level override (`[audit.<class>].level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum AuditClassLevel {
    /// Suppress the class entirely.
    Off,
    /// Only denied/blocked events.
    DeniesOnly,
    /// One summary line per event.
    Summary,
    /// Full per-event detail.
    Full,
}

/// Abstract-namespace `AF_UNIX` socket disposition (`[unix].abstract`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub enum AbstractSocketPolicy {
    /// Deny abstract-namespace sockets (default).
    Deny,
    /// Allow abstract-namespace sockets.
    Allow,
}

/// The `[service]` supervision discipline, resolved into the settled policy
/// (`07-13-service-catalog.md` §7.13.7).
///
/// A *service* input `kenneld` realises (it governs how the daemon restarts an enabled provider),
/// not part of the kernel-enforcement core. Carried in the signed settled policy; present only when
/// the policy declares `[service]` — a non-service policy omits it entirely, so it signs unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRuntime {
    /// The restart discipline.
    pub restart: RestartPolicy,
    /// Initial delay before a restart, in milliseconds; doubles each successive attempt (to a cap).
    pub backoff_ms: u64,
    /// Restarts within the crash-loop window before the provider is driven declared-but-failed.
    pub max_attempts: u32,
}

/// The workload's identity inside the kennel (Kennel book Vol 2 ch.6 (The Filesystem)): the
/// supplementary Unix groups it retains.
///
/// Like [`SshRuntime`]/[`UnixRuntime`], a *service* input `kenneld` realises, not part
/// of the kernel-enforcement core. `kenneld` resolves each group name to a GID at
/// spawn (refusing any the operator is not a member of), the privileged seal
/// `setgroups` to exactly that set (default empty — all inherited host groups dropped),
/// and the synthetic `/etc/group` names them so `id` shows names not bare numbers.
/// Carried in the signed settled policy; omitted from the canonical form when empty.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRuntime {
    /// The workload's masked user name — `$USER`/`$LOGNAME`, the synthetic
    /// `/etc/passwd` account, and the base of `$HOME` (`/home/<user>`). Defaults to
    /// [`DEFAULT_USER`] (`kennel`); omitted from the canonical form when it is the
    /// default, so a policy that does not override it signs unchanged.
    #[serde(default = "default_user", skip_serializing_if = "is_default_user")]
    pub user: String,
    /// The workload's masked **primary** group name — the synthetic `/etc/passwd`
    /// `pw_gid`'s name and the `/etc/group` entry for the workload's primary gid.
    /// Defaults to [`DEFAULT_GROUP`] (`kennel`); omitted from the canonical form when
    /// it is the default. (Distinct from [`groups`](Self::groups), the *supplementary*
    /// groups.)
    #[serde(default = "default_group", skip_serializing_if = "is_default_group")]
    pub group: String,
    /// Supplementary group names to retain (resolved to GIDs at spawn). Includes the
    /// groups named by `[[fs.dev.passthrough]]` (merged at translation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// The default masked user name: a non-system, non-privileged account.
pub const DEFAULT_USER: &str = "kennel";
/// The default masked primary-group name.
pub const DEFAULT_GROUP: &str = "kennel";

fn default_user() -> String {
    DEFAULT_USER.to_owned()
}

fn is_default_user(user: &str) -> bool {
    user == DEFAULT_USER
}

fn default_group() -> String {
    DEFAULT_GROUP.to_owned()
}

fn is_default_group(group: &str) -> bool {
    group == DEFAULT_GROUP
}

impl Default for IdentityRuntime {
    fn default() -> Self {
        Self {
            user: default_user(),
            group: default_group(),
            groups: Vec::new(),
        }
    }
}

impl IdentityRuntime {
    /// Whether there is nothing to realise (the default user and group, no
    /// supplementary group).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_default_user(&self.user) && is_default_group(&self.group) && self.groups.is_empty()
    }
}

/// `skip_serializing_if` helper: a `false` bool is omitted from the canonical form.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// One resolved template or fragment that contributed to the settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedArtifact {
    /// Artefact name.
    pub name: String,
    /// The `key_id` that signed this artefact.
    pub signing_key_id: String,
    /// The artefact's ed25519 signature (base64) — the content commitment lifted from the lockfile.
    /// A deterministic signature over the canonical form *is* the content pin (no `sha2`); empty for
    /// an unsigned development artefact.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// Provenance: every input that produced this settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// The `kennel-lib-policy` compiler version that produced this artefact.
    pub compiler_version: String,
    /// The policy schema version used at compile time.
    pub schema_version: u32,
    /// The THREATS.md catalogue version the templates were authored against.
    pub threat_catalogue_version: String,
    /// The resolved templates/fragments, each pinned to its signing key and signature (the
    /// deterministic ed25519 commitment over its canonical form — no separate hash).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_artifacts: Vec<ResolvedArtifact>,
}

/// An active audit sink (Kennel book Vol 2 ch.19 (The Audit Account)).
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

impl AuditSinkKind {
    /// The stable lowercase token (matches the policy and proxy-config spelling).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Journald => "journald",
            Self::Syslog => "syslog",
            Self::Stdout => "stdout",
        }
    }
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

    /// Layer `over` onto `self`: each field `over` sets wins, the rest stay.
    #[must_use]
    pub fn overlay(&self, over: &Self) -> Self {
        Self {
            dir: over.dir.clone().or_else(|| self.dir.clone()),
            rotate_at_bytes: over.rotate_at_bytes.or(self.rotate_at_bytes),
            compress_after_seconds: over.compress_after_seconds.or(self.compress_after_seconds),
            retain_count: over.retain_count.or(self.retain_count),
        }
    }
}

/// The per-kennel audit runtime (`02-3`): which sinks are active and any
/// per-class level / file / syslog deviation from the defaults.
///
/// Like [`SshRuntime`]/[`UnixRuntime`] this is a *service* input, not
/// enforcement: kenneld realises it by constructing the `kennel-lib-audit` writer.
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

    /// Layer `over` onto `self`: every field `over` sets wins, the rest stay.
    ///
    /// kenneld combines the installation default, the per-user override, and the
    /// per-kennel policy `[audit]` with this (`08` §8.1; precedence built-in <
    /// `/etc/kennel/audit.toml` < `~/.config/kennel/audit.toml` < policy). A field
    /// left unset everywhere falls through to the built-in default at writer build.
    #[must_use]
    pub fn overlay(&self, over: &Self) -> Self {
        Self {
            sinks: if over.sinks.is_empty() {
                self.sinks.clone()
            } else {
                over.sinks.clone()
            },
            network_level: over
                .network_level
                .clone()
                .or_else(|| self.network_level.clone()),
            filesystem_level: over
                .filesystem_level
                .clone()
                .or_else(|| self.filesystem_level.clone()),
            exec_level: over.exec_level.clone().or_else(|| self.exec_level.clone()),
            unix_level: over.unix_level.clone().or_else(|| self.unix_level.clone()),
            dbus_level: over.dbus_level.clone().or_else(|| self.dbus_level.clone()),
            syslog_facility: over
                .syslog_facility
                .clone()
                .or_else(|| self.syslog_facility.clone()),
            file: self.file.overlay(&over.file),
        }
    }
}

/// The synthesised environment (`07-9-other.md` §7.9.2).
///
/// The spawn clears the inherited environment and builds the workload's from
/// scratch; `vars` are the fixed `KEY=value` pairs from `[env].set` (and, in
/// future, a compile-time `[env].template`). `PATH`/`HOME`/`USER`/`SHELL` are
/// synthesised separately by the spawn (from `[exec].path`/`shell` and the masked
/// identity) and are not repeated here. A *service* input like [`AuditRuntime`]:
/// omitted from the canonical form when empty, so a policy with no `[env].set`
/// signs as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvRuntime {
    /// Fixed environment variables, applied after the synthesised base. Sorted
    /// (a `BTreeMap`) so the canonical form is deterministic.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
}

impl EnvRuntime {
    /// Whether no environment variables are set (omitted from the canonical form).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

/// The `setrlimit(2)` resources a policy may name in `[ulimits]`, as their short
/// policy names.
///
/// The spawn layer maps each to its `RLIMIT_*` constant; the translator validates
/// against this list so a typo is a compile error. Kept here (the pure crate) so
/// policy and spawn share one source of truth — a spawn-side test asserts every name
/// maps to a resource.
pub const ULIMIT_RESOURCES: &[&str] = &[
    "as",
    "core",
    "cpu",
    "data",
    "fsize",
    "locks",
    "memlock",
    "msgqueue",
    "nice",
    "nofile",
    "nproc",
    "rtprio",
    "rttime",
    "sigpending",
    "stack",
];

/// The per-kennel resource limits (`[ulimits]`, §7.4).
///
/// A *service* input applied via `setrlimit(2)` in the seal, not a kernel-enforcement
/// object. Each value is the normalised `soft` (when `soft == hard`) or `"soft hard"`
/// form, every token either a decimal string or the literal `unlimited`. Omitted from
/// the canonical form when empty, so a policy with no `[ulimits]` signs as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UlimitsRuntime {
    /// Resource name → normalised limit. Sorted (`BTreeMap`) for a deterministic
    /// canonical form.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, String>,
}

impl UlimitsRuntime {
    /// Whether no limits are set (omitted from the canonical form).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }
}

/// The workload a kennel runs (`[workload]`, §7.4).
///
/// Optional: when empty the workload is supplied at `kennel run … -- <cmd>`. When the
/// policy carries an `argv`, `kennel run` with no `--` runs it; a `--` overrides it
/// unless `pinned` is set (then `--force` is required). A *service* input like the other
/// runtimes — omitted from the canonical form when empty, so a policy with no `[workload]`
/// signs exactly as before. `cwd` is a string (not a `PathBuf`) because it may carry a
/// deferred `~`/`<home>` placeholder the spawn resolves against the persona home.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRuntime {
    /// The command and its arguments (`argv[0]` is the program; resolved against the
    /// kennel's `PATH` when bare). Empty ⇒ no policy-embedded workload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// The working directory inside the view, or `None` to let the spawn default it
    /// (the persona home, then `/`). May carry a deferred `~`/`<home>` placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// When true, refuse a CLI `--` override of `argv` unless `--force` is given — the
    /// signed policy pins exactly what runs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pinned: bool,
    /// When true, CLI `-- <args>` tokens are *appended* to the pinned `argv` rather than
    /// refused. The program and base argv stay pinned exactly (the fd-pin/digest binds the
    /// program, not the args); only meaningful with `pinned`. Omitted when false, so a
    /// policy without it signs unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allowed_args: bool,
    /// Accepted lowercase-hex SHA-256 digests of the workload binary (`argv[0]` resolved
    /// against `PATH`). When non-empty, the spawn hashes the resolved binary just before
    /// `execve` and refuses to run it unless its digest is in this set — the signed policy
    /// pins not just *which* program but its exact bytes. A SET (not one digest) so several
    /// accepted versions of the same binary (e.g. successive Claude Code releases) validate
    /// under one policy. Each is 64 hex chars; validated at translate time. Empty ⇒ no pin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sha256: Vec<String>,
}

impl WorkloadRuntime {
    /// Whether no workload is embedded (omitted from the canonical form). `pinned`/`cwd`/
    /// `sha256` without an `argv` is vacuous, so only `argv` gates emptiness.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.argv.is_empty()
    }
}

/// The per-kennel OCI substrate runtime (§7.11): the unpacked image `kenneld` boots as the kennel
/// root, plus the provenance digest the runner must match.
///
/// Like [`SshRuntime`]/[`WorkloadRuntime`] a *service* input `kenneld` realises (the
/// view-construction branch), not part of the enforcement core; omitted from the canonical form
/// when empty, so a non-OCI policy signs exactly as before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsRuntime {
    /// The unpacked image rootfs (the store entry's `rootfs/`), `subst`-resolved.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// The `image@sha256:…` the build pulled from; the runner refuses unless it equals the store
    /// entry's recorded `digest`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    /// Rootfs persistence (§7.11.4a): `"discard"` (default) | `"persist"`. Empty in the settled
    /// form means the default `discard`, so an OCI policy that does not set it signs unchanged; the
    /// spawn path reads empty as `discard`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persistence: String,
    /// Closure-lock (§7.11.4c): rootfs paths the spawn Landlock-denies writes to (read+execute
    /// kept). The executable-closure boundary the DAC-flatten erased; build-derived for a non-root
    /// image. `["/"]` is whole-tree-immutable. Longest-prefix wins with `writable`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly: Vec<String>,
    /// Closure-lock holes (§7.11.4c): rootfs paths kept writable, carved out of `readonly`
    /// (longest-prefix wins). Each carve-out is a loud, separately-derived exposure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writable: Vec<String>,
}

impl RootfsRuntime {
    /// Whether no OCI substrate is declared (the policy is not OCI-model).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.path.is_empty()
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
    /// The per-kennel SSH runtime (§7.10). Declared last: it is a table, and TOML
    /// requires the scalar/array fields above it to serialise first. Omitted from
    /// the canonical form when empty, so a no-SSH policy signs exactly as before.
    #[serde(default, skip_serializing_if = "SshRuntime::is_empty")]
    pub ssh: SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.6). A table like [`ssh`](Self::ssh) and
    /// declared after it; omitted from the canonical form when empty, so a no-`[unix]`
    /// policy signs exactly as before.
    #[serde(default, skip_serializing_if = "UnixRuntime::is_empty")]
    pub unix: UnixRuntime,
    /// The workload's in-kennel identity (§7.4): the supplementary groups it retains.
    /// A table like [`ssh`](Self::ssh)/[`unix`](Self::unix); omitted from the canonical
    /// form when empty, so a policy that grants no group signs exactly as before.
    #[serde(default, skip_serializing_if = "IdentityRuntime::is_empty")]
    pub identity: IdentityRuntime,
    /// The cross-kennel capability mesh runtime — the `[[provides]]`/`[[consumes]]` the
    /// broker and catalogue read. A table like [`identity`](Self::identity); omitted from
    /// the canonical form when empty, so a policy with no mesh declarations signs exactly
    /// as before.
    #[serde(default, skip_serializing_if = "MeshRuntime::is_empty")]
    pub mesh: MeshRuntime,
    /// The `[service]` supervision discipline (§7.13.7) — the restart policy `kenneld` applies to an
    /// enabled provider. Present only when the policy declares `[service]`; omitted otherwise, so a
    /// non-service policy signs exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceRuntime>,
    /// The per-kennel D-Bus runtime (§7.7) — the `IDBus` facade's rule set. A table like
    /// [`mesh`](Self::mesh); omitted from the canonical form when empty, so a
    /// no-`[dbus]` policy signs exactly as before.
    #[serde(default, skip_serializing_if = "DbusRuntime::is_empty")]
    pub dbus: DbusRuntime,
    /// The per-kennel audit runtime (`02-3`). A table like [`ssh`](Self::ssh) and
    /// declared after the others; omitted from the canonical form when empty, so a
    /// policy with no (or all-default) `[audit]` signs exactly as before.
    #[serde(default, skip_serializing_if = "AuditRuntime::is_empty")]
    pub audit: AuditRuntime,
    /// The synthesised environment (§7.9.2). A table like [`audit`](Self::audit);
    /// omitted from the canonical form when empty, so a policy with no `[env].set`
    /// signs exactly as before.
    #[serde(default, skip_serializing_if = "EnvRuntime::is_empty")]
    pub env: EnvRuntime,
    /// The per-kennel resource limits (§7.4). A table like [`env`](Self::env) and
    /// declared after it; omitted from the canonical form when empty, so a policy with
    /// no `[ulimits]` signs exactly as before.
    #[serde(default, skip_serializing_if = "UlimitsRuntime::is_empty")]
    pub ulimits: UlimitsRuntime,
    /// The workload to run (§7.4). A table like [`ulimits`](Self::ulimits) and declared
    /// last; omitted from the canonical form when empty, so a policy with no `[workload]`
    /// signs exactly as before.
    #[serde(default, skip_serializing_if = "WorkloadRuntime::is_empty")]
    pub workload: WorkloadRuntime,
    /// The per-kennel OCI substrate (§7.11): the image root the daemon boots. A table like
    /// [`workload`](Self::workload) and declared last; omitted from the canonical form when
    /// empty, so a non-OCI policy signs exactly as before.
    #[serde(default, skip_serializing_if = "RootfsRuntime::is_empty")]
    pub rootfs: RootfsRuntime,
    /// The `[spawn]` delegated-instantiation grant (§7.12.2) — present only on a policy that may
    /// instantiate siblings (a **requester**), the mirror of [`manifest`](Self::manifest) (the
    /// spawn-*target* side; the two never coexist — a target is depth-1). Omitted from the canonical
    /// form when absent, so a non-spawner policy signs exactly as before. Carried into the settled
    /// policy so `kenneld` holds the requester's ACL in its runtime record from construction and
    /// validates a `SPAWN` against it in the **verify half**, never a compiler (`tcb-only-shrinks`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn: Option<SpawnGrant>,
    /// The mutable-field manifest (§7.12.3) — present only on a **spawn-target template**, where it is
    /// the signed statement of how far an in-memory instance may diverge from this template (the
    /// [`variant`](crate::variant) constraints). An array-of-tables, declared last so the canonical
    /// TOML emits it after every scalar/table field; omitted from the canonical form when empty, so a
    /// policy that is not a spawn target signs exactly as before. The instantiated policy carries none
    /// (the variants have been applied and it is never re-signed).
    ///
    /// Declared after [`spawn`](Self::spawn) so the canonical TOML emits this array-of-tables last,
    /// after every scalar/table field (TOML cannot place a table after an array-of-tables).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifest: Manifest,
}

/// The `[spawn]` grant (§7.12.2) carried into a settled policy — the requester-side ACL `kenneld`
/// validates a `SPAWN` against. Present only on a policy that carries `[spawn]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnGrant {
    /// Concurrent-instance ceiling across this grant's spawns — the fork-bomb bound (§7.12.7),
    /// enforced by an atomic check-and-claim at `SPAWN`.
    pub max_instances: u32,
    /// The templates this grant may instantiate (`[[spawn.allow]]`), each pinned to the signature
    /// commitment recorded at this policy's compile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<SpawnTemplate>,
}

/// One template a `[spawn]` grant may instantiate, pinned to its signature commitment (§7.12.8).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnTemplate {
    /// The trust-store template name.
    pub template: String,
    /// The `key_id` the template's signature verified against at this policy's compile.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_key_id: String,
    /// The template's ed25519 signature (Base64) recorded at this policy's compile — the
    /// **content-pin**. A deterministic ed25519 signature over the canonical template *is* its
    /// content commitment (the lockfile idiom — no `sha2`): at `SPAWN`, `kenneld` re-resolves the
    /// named template from the *mutable* trust store and fails closed unless the re-verified
    /// signature matches this, defeating a re-signed-in-place TOCTOU (§7.12.8). Empty only when the
    /// template resolved unsigned (local-development `AllowUnsigned`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Optional per-requester narrowing: the subset of the template's `[[mutable]]` manifest fields
    /// this requester may write (empty ⇒ the template's full manifest). Narrows, never widens
    /// (§7.12.2/§7.12.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mutable_narrow: Vec<String>,
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

/// A representative settled policy for cross-module tests (signing, canonical-form, and the spawn
/// patch applicator). The single fixture so every test shares one shape.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
#[allow(clippy::too_many_lines)] // one cohesive struct-literal fixture; splitting it obscures it.
pub fn sample_settled() -> SettledPolicy {
    SettledPolicy {
        settled_schema_version: crate::SETTLED_SCHEMA_VERSION,
        name: "ai-coding".to_owned(),
        deferred_substitutions: vec!["<ctx>".to_owned(), "<uid>".to_owned()],
        framework_invariants_asserted: vec!["cap.no_new_privs".to_owned()],
        effective_policy: EffectivePolicy {
            net: NetPolicy {
                mode: NetMode::Constrained,
                udp: false,
                udp_allow_names: Vec::new(),
                proxy: ProxyListen::default(),
                allow: vec![NetRule {
                    cidr: "93.184.216.0".to_owned(),
                    prefix_len: 24,
                    port_min: 443,
                    port_max: 443,
                    protocol: Protocol::Tcp,
                }],
                allow_names: Vec::new(),
                deny_invariant: vec![NetRule {
                    cidr: "169.254.169.254".to_owned(),
                    prefix_len: 32,
                    port_min: 0,
                    port_max: 65535,
                    protocol: Protocol::Any,
                }],
                bind_port_min: 0,
                bind_allowed_ports: Vec::new(),
                deny_author: Vec::new(),
                bpf_connect_allow: Vec::new(),
                bpf_connect_deny: Vec::new(),
                bpf_bind_allow: Vec::new(),
                bpf_bind_deny: Vec::new(),
            },
            fs: FsPolicy {
                home_shadow: true,
                read: vec!["/usr".to_owned()],
                write: vec!["/run/kennel/ai-coding/home".to_owned()],
                exclusive: Vec::new(),
                home_persist: Vec::new(),
                home_readonly: false,
                cwd: CwdPolicy::default(),
                tmp: TmpPolicy {
                    writable: true,
                    size_mib: 512,
                },
                dev: DevPolicy {
                    allow: vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()],
                },
            },
            exec: ExecPolicy {
                deny_setuid: true,
                deny_setgid: true,
                deny_setcap: true,
                deny_writable: true,
                allow: vec!["/usr/bin/python3".to_owned()],
                deny: Vec::new(),
                path: vec!["/usr/bin".to_owned()],
                shell: default_shell(),
                loaders: Vec::new(),
            },
            proc: ProcPolicy { hidepid: true },
            cap: CapPolicy { no_new_privs: true },
            seccomp: SeccompPolicy {
                deny_action: SeccompAction::Errno,
                deny: vec!["bpf".to_owned()],
            },
            lifecycle: LifecyclePolicy {
                ttl_seconds: Some(3600),
                ttl_action: TtlAction::Exit,
            },
            tty: TtyPolicy::default(),
            trust: TrustPolicy::default(),
        },
        spawn: None,
        manifest: Vec::new(),
        provenance: Provenance {
            compiler_version: "0.0.0".to_owned(),
            schema_version: crate::SETTLED_SCHEMA_VERSION,
            threat_catalogue_version: "0.1".to_owned(),
            resolved_artifacts: vec![ResolvedArtifact {
                name: "base-confined".to_owned(),
                signing_key_id: "kennel-maint-2026-01".to_owned(),
                signature: "c2ln".to_owned(),
            }],
        },
        ssh: SshRuntime::default(),
        unix: UnixRuntime::default(),
        identity: IdentityRuntime::default(),
        mesh: MeshRuntime::default(),
        service: None,
        dbus: DbusRuntime::default(),
        audit: AuditRuntime::default(),
        env: EnvRuntime::default(),
        ulimits: UlimitsRuntime::default(),
        workload: WorkloadRuntime::default(),
        rootfs: RootfsRuntime::default(),
    }
}
