//! Template-chain resolution and folding — the first compiler stage proper.
//!
//! # Purpose
//!
//! Given an entry source policy (a leaf, or a template being inspected), walk its
//! `template_base` chain to the root template (`base-confined`) and fold the chain,
//! root-first, into a single *effective* [`SourcePolicy`] with no `template_base`
//! left to resolve (`docs/architecture/02-2-config-schema.md` §Template inheritance).
//! The effective policy is what the later stages substitute, translate to a
//! [`kennel_lib_policy::settled::SettledPolicy`], and sign.
//!
//! # Composition model (the SSH `Ciphers` model)
//!
//! Fields compose down the chain (parent → child, child = more derived):
//!
//! - **Scalars** (`net.mode`, `cap.no_new_privs`, `lifecycle.ttl`, …): the most-derived
//!   value that sets the field wins; an absent field inherits.
//! - **List fields** (`exec.allow`, `fs.read`, `env.pass`, …): a child's bare list
//!   *sets* (replaces) the inherited list — the SSH `Ciphers = …` form. An absent
//!   field inherits. The additive/subtractive `+=` / `-=` operators (leaf-policy
//!   `[[*.add]]` / `[[*.remove]]`) are a later increment; this stage implements the
//!   `=` (set/override/merge) half, which is everything the in-tree templates use.
//! - **Object sub-tables** (`fs.home`, `net.bind`, `dbus`, …): merged shallowly,
//!   field-by-field, with the child overriding.
//! - **Invariant denies** (`net.proxy.deny.invariant`): *unioned*, never replaced —
//!   invariants propagate down the chain and a child can only add to them
//!   (`02-2` §Framework invariants, `docs/design/05-templates.md` §5.5). This is the one
//!   list field that does not follow the bare-set rule, precisely because its
//!   non-removability is the point.
//!
//! # Threat bearing
//!
//! Resolution is the supply-chain choke point: every parent is parsed, validated,
//! and signature-checked against the trust store ([`resolve_verified`]) before its
//! bytes are folded in. Cycles, over-deep chains, and missing references are hard
//! errors, so a policy cannot quietly resolve against an unexpected or absent base.
//! (Lockfile byte-pinning of each resolved reference is the remaining increment.)
//!
//! # Non-goals
//!
//! I/O-free by construction: callers supply a [`TemplateSource`] that maps a
//! `<name>@<version>` reference to bytes (the CLI reads files; tests use an
//! in-memory map). Signature verification, lockfile byte-pinning, includes, and
//! the `+=`/`-=` delta operators land in later increments.

use crate::source::{
    self, BinderSection, BoundaryAcl, CapSection, EnvSection, ExecSection, FsDev, FsHome, FsProc,
    FsSection, FsTmp, IdentitySection, LifecycleSection, NetAudit, NetBind, NetBpf, NetBpfAcl,
    NetIpv6, NetProxy, NetProxyDeny, NetSection, SeccompSection, SourcePolicy, SshSection,
    TrustSection, TtySection, UnixSection, UnsafeSection, WorkloadSection,
};
use crate::source_sig::Trust;
use kennel_lib_policy::audit::{
    AuditClassSection, AuditFileSection, AuditSection, AuditSyslogSection,
};
use kennel_lib_policy::PolicyError;

/// Maximum inheritance-chain depth (number of `template_base` hops), per
/// `02-2-config-schema.md` §Resolution order.
pub const MAX_CHAIN_DEPTH: usize = 16;

/// A source of template/fragment artefacts by versioned reference. Keeps
/// [`resolve`] I/O-free: the CLI implements this over the filesystem search path,
/// tests over an in-memory map.
pub trait TemplateSource {
    /// Return the raw TOML bytes for `<name>@<version>`, or `None` if not found.
    /// `version` carries its leading `v` (e.g. `"v1"`, `"v2.33.2"`).
    fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>>;
}

/// One resolved link in the inheritance chain, recorded for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// The artefact's name.
    pub name: String,
    /// The artefact's version (with leading `v`).
    pub version: String,
    /// The signing-key id its signature verified against, if it was verified.
    pub signing_key_id: Option<String>,
    /// The artefact's on-disk ed25519 signature (base64), if it carried one. This is
    /// the deterministic content commitment the lockfile pins.
    pub signature: Option<String>,
}

/// The product of resolving a chain: the folded effective policy plus the list of
/// parent artefacts that were composed (root-first), for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedChain {
    /// The folded effective policy (no `template_base`).
    pub effective: SourcePolicy,
    /// The parents that were fetched and folded in, root-first.
    pub chain: Vec<ChainLink>,
}

/// Resolve and fold `entry`'s inheritance chain into one effective policy.
///
/// `entry` is the most-derived artefact (a leaf policy, or a template being
/// inspected); it is folded last. Each ancestor is fetched from `source` by its
/// `template_base` reference, parsed, and per-artefact validated before folding.
///
/// # Errors
///
/// Returns [`PolicyError::Resolution`] if a reference is malformed, missing from
/// `source`, forms a cycle, or the chain exceeds [`MAX_CHAIN_DEPTH`];
/// [`PolicyError::Parse`] if an ancestor is unparseable; or
/// [`PolicyError::SourceValidation`] if an ancestor fails validation.
pub fn resolve(
    entry: &SourcePolicy,
    source: &dyn TemplateSource,
) -> Result<ResolvedChain, PolicyError> {
    resolve_verified(entry, source, &Trust::dev())
}

/// Resolve and fold, verifying each fetched ancestor against `trust`.
///
/// Identical to [`resolve`] but each parent's `[signature]` is checked according to
/// `trust` ([`Trust::require`] in attested deployments, [`Trust::dev`] / unsigned in
/// development). The entry itself is *not* signature-checked — a leaf policy is loaded
/// under the user's own authority (`02-2` §Signatures).
///
/// # Errors
///
/// As [`resolve`], plus [`PolicyError::Signature`] / [`PolicyError::Resolution`] when an
/// ancestor fails the trust check.
pub fn resolve_verified(
    entry: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<ResolvedChain, PolicyError> {
    entry.validate()?;
    // Walk parents, leaf-first, detecting cycles and bounding depth.
    let mut parents: Vec<SourcePolicy> = Vec::new();
    let mut links: Vec<ChainLink> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut current = entry.clone();
    while let Some(reference) = current.template_base.clone() {
        let (name, version) = split_reference(&reference)?;
        let key = format!("{name}@{version}");
        if seen.iter().any(|s| s == &key) {
            return Err(PolicyError::Resolution(format!(
                "cycle detected at `{key}`"
            )));
        }
        if parents.len() >= MAX_CHAIN_DEPTH {
            return Err(PolicyError::Resolution(format!(
                "inheritance chain exceeds the maximum depth of {MAX_CHAIN_DEPTH}"
            )));
        }
        seen.push(key.clone());
        let bytes = source.fetch(&name, &version).ok_or_else(|| {
            PolicyError::Resolution(format!("reference `{key}` not found in the search path"))
        })?;
        let parent = source::parse(&bytes)?;
        parent.validate()?;
        let signing_key_id = trust.check(&name, &parent)?;
        let signature = parent.signature.as_ref().map(|e| e.signature.clone());
        links.push(ChainLink {
            name,
            version,
            signing_key_id,
            signature,
        });
        parents.push(parent.clone());
        current = parent;
    }

    // Fold root-first: the deepest ancestor is the accumulator, then each more-derived
    // artefact overrides it, and finally `entry`. `parents` is leaf-first, so the root
    // is its last element.
    // A root template with no parent resolves to itself.
    let mut acc = parents.pop().unwrap_or_else(|| entry.clone());
    while let Some(child) = parents.pop() {
        acc = fold(&acc, &child);
    }
    acc = fold(&acc, entry);

    // The `template_base` chain is fully folded; nothing left to inherit. The folded
    // `include` list is *kept* (not cleared): includes are applied separately by
    // `compile`/`compile_leaf` via `apply_includes`, which reads exactly this list, so
    // clearing it here silently dropped every `include` declared on a source template.
    acc.template_base = None;
    entry.template_version.clone_into(&mut acc.template_version);
    entry.template_name.clone_into(&mut acc.template_name);
    entry.name.clone_into(&mut acc.name);
    acc.signature = None;

    links.reverse(); // root-first for provenance
    Ok(ResolvedChain {
        effective: acc,
        chain: links,
    })
}

/// Split and validate a versioned reference into `(name, version)`.
pub(crate) fn split_reference(reference: &str) -> Result<(String, String), PolicyError> {
    let bad =
        |d: String| PolicyError::Resolution(format!("`template_base` = \"{reference}\": {d}"));
    let (name, version) = reference
        .split_once('@')
        .ok_or_else(|| bad("missing `@version` (expected `<name>@v<ver>`)".to_owned()))?;
    source::validate_ref_name(name).map_err(bad)?;
    source::validate_ref_version(version).map_err(bad)?;
    Ok((name.to_owned(), version.to_owned()))
}

/// Fold `child` over `parent`, child overriding. Identity fields are settled by the
/// caller after the full fold; here they take the child's value.
fn fold(parent: &SourcePolicy, child: &SourcePolicy) -> SourcePolicy {
    SourcePolicy {
        template_base: child.template_base.clone(),
        template_version: or(&child.template_version, &parent.template_version),
        template_name: or(&child.template_name, &parent.template_name),
        name: or(&child.name, &parent.name),
        include: union_strings(&parent.include, &child.include),
        threat_catalogue_version: or(
            &child.threat_catalogue_version,
            &parent.threat_catalogue_version,
        ),
        signature: None,
        cap: merge(&parent.cap, &child.cap, fold_cap),
        exec: merge(&parent.exec, &child.exec, fold_exec),
        fs: merge(&parent.fs, &child.fs, fold_fs),
        net: merge(&parent.net, &child.net, fold_net),
        unix: merge(&parent.unix, &child.unix, fold_unix),
        ssh: merge(&parent.ssh, &child.ssh, fold_ssh),
        identity: merge(&parent.identity, &child.identity, fold_identity),
        binder: merge(&parent.binder, &child.binder, fold_binder),
        unsafe_section: merge(&parent.unsafe_section, &child.unsafe_section, fold_unsafe),
        env: merge(&parent.env, &child.env, fold_env),
        seccomp: merge(&parent.seccomp, &child.seccomp, fold_seccomp),
        lifecycle: merge(&parent.lifecycle, &child.lifecycle, fold_lifecycle),
        audit: merge(&parent.audit, &child.audit, fold_audit),
        ulimits: merge(&parent.ulimits, &child.ulimits, fold_ulimits),
        workload: merge(&parent.workload, &child.workload, fold_workload),
        tty: merge(&parent.tty, &child.tty, fold_tty),
        trust: merge(&parent.trust, &child.trust, fold_trust),
    }
}

/// Fold `[tty]` scalar-wins (child overrides), like `[lifecycle]`.
fn fold_tty(p: &TtySection, c: &TtySection) -> TtySection {
    TtySection {
        filter_terminal_escapes: or(&c.filter_terminal_escapes, &p.filter_terminal_escapes),
    }
}

/// Fold `[trust]` scalar-wins (child overrides), like `[tty]`.
fn fold_trust(p: &TrustSection, c: &TrustSection) -> TrustSection {
    TrustSection {
        manifest: or(&c.manifest, &p.manifest),
        on_change: or(&c.on_change, &p.on_change),
    }
}

/// Fold `[workload]` scalar-wins (child overrides), like `[lifecycle]`. argv is a
/// replace (not a union) — a derived policy fully redefines what runs.
fn fold_workload(p: &WorkloadSection, c: &WorkloadSection) -> WorkloadSection {
    WorkloadSection {
        argv: or(&c.argv, &p.argv),
        cwd: or(&c.cwd, &p.cwd),
        pinned: or(&c.pinned, &p.pinned),
        sha256: or(&c.sha256, &p.sha256),
    }
}

/// Fold `[ulimits]` per-key: the child's entry for a resource overrides the
/// parent's, other resources carry through (same model as `[env].set`).
fn fold_ulimits(
    parent: &std::collections::BTreeMap<String, String>,
    child: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    let mut m = parent.clone();
    for (k, v) in child {
        m.insert(k.clone(), v.clone());
    }
    m
}

// ---- generic combinators -------------------------------------------------------

// `&Option<T>` (not `Option<&T>`) is deliberate here: these helpers are called on
// every section field as `or(&c.field, &p.field)`, and taking borrows of the option
// keeps those call sites readable. They are private to the folder, not public API.
/// Scalar / set-list override: the child's value if present, else the parent's.
#[allow(clippy::ref_option)]
fn or<T: Clone>(child: &Option<T>, parent: &Option<T>) -> Option<T> {
    child.clone().or_else(|| parent.clone())
}

/// Merge two optional sub-objects, applying `f(parent, child)` when both are present.
#[allow(clippy::ref_option)]
fn merge<T: Clone>(parent: &Option<T>, child: &Option<T>, f: impl Fn(&T, &T) -> T) -> Option<T> {
    match (parent, child) {
        (Some(p), Some(c)) => Some(f(p, c)),
        (p, c) => c.clone().or_else(|| p.clone()),
    }
}

/// Union of two string lists, parent-first, de-duplicated (order preserved).
fn union_strings(parent: &[String], child: &[String]) -> Vec<String> {
    let mut out = parent.to_vec();
    for s in child {
        if !out.iter().any(|e| e == s) {
            out.push(s.clone());
        }
    }
    out
}

// ---- per-section folds (child overrides) ---------------------------------------

fn fold_cap(p: &CapSection, c: &CapSection) -> CapSection {
    CapSection {
        no_new_privs: or(&c.no_new_privs, &p.no_new_privs),
        bounding_set: or(&c.bounding_set, &p.bounding_set),
    }
}

fn fold_exec(p: &ExecSection, c: &ExecSection) -> ExecSection {
    ExecSection {
        allow: or(&c.allow, &p.allow),
        deny: or(&c.deny, &p.deny),
        deny_setuid: or(&c.deny_setuid, &p.deny_setuid),
        deny_setgid: or(&c.deny_setgid, &p.deny_setgid),
        deny_setcap: or(&c.deny_setcap, &p.deny_setcap),
        deny_writable: or(&c.deny_writable, &p.deny_writable),
        path: or(&c.path, &p.path),
        shell: or(&c.shell, &p.shell),
    }
}

fn fold_fs(p: &FsSection, c: &FsSection) -> FsSection {
    FsSection {
        read: or(&c.read, &p.read),
        write: or(&c.write, &p.write),
        exclusive: or(&c.exclusive, &p.exclusive),
        deny: or(&c.deny, &p.deny),
        home: merge(&p.home, &c.home, fold_fs_home),
        tmp: merge(&p.tmp, &c.tmp, fold_fs_tmp),
        proc: merge(&p.proc, &c.proc, fold_fs_proc),
        dev: merge(&p.dev, &c.dev, fold_fs_dev),
    }
}

fn fold_fs_home(p: &FsHome, c: &FsHome) -> FsHome {
    FsHome {
        shadow: or(&c.shadow, &p.shadow),
        persist: union_strings(&p.persist, &c.persist),
        readonly: or(&c.readonly, &p.readonly),
    }
}

fn fold_fs_tmp(p: &FsTmp, c: &FsTmp) -> FsTmp {
    FsTmp {
        private: or(&c.private, &p.private),
        size: or(&c.size, &p.size),
        mode: or(&c.mode, &p.mode),
    }
}

fn fold_fs_proc(p: &FsProc, c: &FsProc) -> FsProc {
    FsProc {
        visibility: or(&c.visibility, &p.visibility),
        hidepid: or(&c.hidepid, &p.hidepid),
    }
}

fn fold_fs_dev(p: &FsDev, c: &FsDev) -> FsDev {
    FsDev {
        allow: or(&c.allow, &p.allow),
        // Bare-set: a child's non-empty passthrough list replaces the parent's (as
        // `unix.allow`). A leaf adds individual devices via `[[fs.dev.passthrough.add]]`.
        passthrough: if c.passthrough.is_empty() {
            p.passthrough.clone()
        } else {
            c.passthrough.clone()
        },
    }
}

fn fold_net(p: &NetSection, c: &NetSection) -> NetSection {
    NetSection {
        mode: or(&c.mode, &p.mode),
        reason: or(&c.reason, &p.reason),
        proxy_listen_v4_address: or(&c.proxy_listen_v4_address, &p.proxy_listen_v4_address),
        proxy_listen_v6_address: or(&c.proxy_listen_v6_address, &p.proxy_listen_v6_address),
        proxy: merge(&p.proxy, &c.proxy, fold_net_proxy),
        bpf: merge(&p.bpf, &c.bpf, fold_net_bpf),
        bind: merge(&p.bind, &c.bind, fold_net_bind),
        ipv6: merge(&p.ipv6, &c.ipv6, fold_net_ipv6),
        audit: merge(&p.audit, &c.audit, fold_net_audit),
    }
}

fn fold_net_proxy(p: &NetProxy, c: &NetProxy) -> NetProxy {
    NetProxy {
        // Bare-set: a child's non-empty allow list replaces the parent's.
        allow: if c.allow.is_empty() {
            p.allow.clone()
        } else {
            c.allow.clone()
        },
        deny: merge(&p.deny, &c.deny, fold_net_proxy_deny),
    }
}

fn fold_net_proxy_deny(p: &NetProxyDeny, c: &NetProxyDeny) -> NetProxyDeny {
    // Invariant denies UNION and never drop — invariants propagate down the chain.
    let mut invariant = p.invariant.clone();
    for d in &c.invariant {
        if !invariant.iter().any(|e| e.cidr == d.cidr) {
            invariant.push(d.clone());
        }
    }
    // The author denylist is bare-set: a child's non-empty list replaces the parent's.
    let policy = if c.policy.is_empty() {
        p.policy.clone()
    } else {
        c.policy.clone()
    };
    NetProxyDeny { invariant, policy }
}

fn fold_net_bpf(p: &NetBpf, c: &NetBpf) -> NetBpf {
    NetBpf {
        // Socket-family shaping is scalar-wins (child overrides when set).
        families: or(&c.families, &p.families),
        deny_families: or(&c.deny_families, &p.deny_families),
        connect: merge(&p.connect, &c.connect, fold_net_bpf_acl),
        bind: merge(&p.bind, &c.bind, fold_net_bpf_acl),
    }
}

fn fold_net_bpf_acl(p: &NetBpfAcl, c: &NetBpfAcl) -> NetBpfAcl {
    // Each direction's allow/deny is bare-set: a child's non-empty list replaces the parent's.
    NetBpfAcl {
        allow: if c.allow.is_empty() {
            p.allow.clone()
        } else {
            c.allow.clone()
        },
        deny: if c.deny.is_empty() {
            p.deny.clone()
        } else {
            c.deny.clone()
        },
    }
}

fn fold_net_bind(p: &NetBind, c: &NetBind) -> NetBind {
    NetBind {
        inaddr_any_policy: or(&c.inaddr_any_policy, &p.inaddr_any_policy),
        in6addr_any_policy: or(&c.in6addr_any_policy, &p.in6addr_any_policy),
        allow_host_loopback_v4: or(&c.allow_host_loopback_v4, &p.allow_host_loopback_v4),
        allow_host_loopback_v6: or(&c.allow_host_loopback_v6, &p.allow_host_loopback_v6),
        min_port: or(&c.min_port, &p.min_port),
        // A child's explicit allowlist overrides the parent's (set-wins, like min_port).
        allowed_ports: or(&c.allowed_ports, &p.allowed_ports),
    }
}

fn fold_net_ipv6(p: &NetIpv6, c: &NetIpv6) -> NetIpv6 {
    NetIpv6 {
        force_v6only: or(&c.force_v6only, &p.force_v6only),
    }
}

fn fold_net_audit(p: &NetAudit, c: &NetAudit) -> NetAudit {
    NetAudit {
        log_path: or(&c.log_path, &p.log_path),
        level: or(&c.level, &p.level),
    }
}

fn fold_audit(p: &AuditSection, c: &AuditSection) -> AuditSection {
    AuditSection {
        // Bare-set: a child's non-empty sink list replaces the parent's.
        sinks: if c.sinks.is_empty() {
            p.sinks.clone()
        } else {
            c.sinks.clone()
        },
        file: merge(&p.file, &c.file, fold_audit_file),
        syslog: merge(&p.syslog, &c.syslog, fold_audit_syslog),
        journald: or(&c.journald, &p.journald),
        stdout: or(&c.stdout, &p.stdout),
        network: merge(&p.network, &c.network, fold_audit_class),
        filesystem: merge(&p.filesystem, &c.filesystem, fold_audit_class),
        exec: merge(&p.exec, &c.exec, fold_audit_class),
        unix: merge(&p.unix, &c.unix, fold_audit_class),
        dbus: merge(&p.dbus, &c.dbus, fold_audit_class),
    }
}

fn fold_audit_file(p: &AuditFileSection, c: &AuditFileSection) -> AuditFileSection {
    AuditFileSection {
        dir: or(&c.dir, &p.dir),
        rotate_at_bytes: or(&c.rotate_at_bytes, &p.rotate_at_bytes),
        compress_after_seconds: or(&c.compress_after_seconds, &p.compress_after_seconds),
        retain_count: or(&c.retain_count, &p.retain_count),
    }
}

fn fold_audit_syslog(p: &AuditSyslogSection, c: &AuditSyslogSection) -> AuditSyslogSection {
    AuditSyslogSection {
        facility: or(&c.facility, &p.facility),
    }
}

fn fold_audit_class(p: &AuditClassSection, c: &AuditClassSection) -> AuditClassSection {
    AuditClassSection {
        level: or(&c.level, &p.level),
    }
}

fn fold_unix(p: &UnixSection, c: &UnixSection) -> UnixSection {
    UnixSection {
        default: or(&c.default, &p.default),
        abstract_ns: or(&c.abstract_ns, &p.abstract_ns),
        allow: if c.allow.is_empty() {
            p.allow.clone()
        } else {
            c.allow.clone()
        },
    }
}

fn fold_identity(p: &IdentitySection, c: &IdentitySection) -> IdentitySection {
    // Bare-set: a child's non-empty group list replaces the parent's; the child's
    // `user` overrides the parent's when set.
    IdentitySection {
        user: or(&c.user, &p.user),
        group: or(&c.group, &p.group),
        groups: if c.groups.is_empty() {
            p.groups.clone()
        } else {
            c.groups.clone()
        },
    }
}

fn fold_binder(p: &BinderSection, c: &BinderSection) -> BinderSection {
    // Bare-set: a child's non-empty list replaces the parent's (as `unix.allow`).
    BinderSection {
        provide: if c.provide.is_empty() {
            p.provide.clone()
        } else {
            c.provide.clone()
        },
        consume: if c.consume.is_empty() {
            p.consume.clone()
        } else {
            c.consume.clone()
        },
    }
}

fn fold_ssh(p: &SshSection, c: &SshSection) -> SshSection {
    SshSection {
        allow_headless: or(&c.allow_headless, &p.allow_headless),
        threats: or(&c.threats, &p.threats),
        // Bare-set: a child's non-empty list replaces the parent's (as `unix.allow`).
        destinations: if c.destinations.is_empty() {
            p.destinations.clone()
        } else {
            c.destinations.clone()
        },
    }
}

fn fold_unsafe(p: &UnsafeSection, c: &UnsafeSection) -> UnsafeSection {
    UnsafeSection {
        ptrace: merge(&p.ptrace, &c.ptrace, fold_boundary_acl),
        signal: merge(&p.signal, &c.signal, fold_boundary_acl),
    }
}

fn fold_boundary_acl(p: &BoundaryAcl, c: &BoundaryAcl) -> BoundaryAcl {
    BoundaryAcl {
        allow_targets: or(&c.allow_targets, &p.allow_targets),
        allow_from: or(&c.allow_from, &p.allow_from),
    }
}

fn fold_env(p: &EnvSection, c: &EnvSection) -> EnvSection {
    // `set` is a map: merge key-by-key, child keys overriding.
    let set = match (&p.set, &c.set) {
        (Some(ps), Some(cs)) => {
            let mut m = ps.clone();
            for (k, v) in cs {
                m.insert(k.clone(), v.clone());
            }
            Some(m)
        }
        (ps, cs) => cs.clone().or_else(|| ps.clone()),
    };
    EnvSection {
        pass: or(&c.pass, &p.pass),
        set,
        deny: or(&c.deny, &p.deny),
    }
}

fn fold_seccomp(p: &SeccompSection, c: &SeccompSection) -> SeccompSection {
    SeccompSection {
        profile: or(&c.profile, &p.profile),
        deny: or(&c.deny, &p.deny),
        allow: or(&c.allow, &p.allow),
    }
}

fn fold_lifecycle(p: &LifecycleSection, c: &LifecycleSection) -> LifecycleSection {
    LifecycleSection {
        ttl: or(&c.ttl, &p.ttl),
        ttl_action: or(&c.ttl_action, &p.ttl_action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse;

    const BASE_CONFINED: &str = include_str!("../../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../templates/ai-coding-strict/policy.toml");
    const UNTRUSTED_BUILD: &str = include_str!("../../../../templates/untrusted-build/policy.toml");

    #[test]
    fn fold_ulimits_is_per_key_child_overrides() {
        let mut parent = std::collections::BTreeMap::new();
        parent.insert("nofile".to_owned(), "1024".to_owned());
        parent.insert("nproc".to_owned(), "256".to_owned());
        let mut child = std::collections::BTreeMap::new();
        child.insert("nofile".to_owned(), "8192".to_owned());
        let folded = fold_ulimits(&parent, &child);
        // child raises nofile; parent's nproc carries through untouched.
        assert_eq!(folded.get("nofile").map(String::as_str), Some("8192"));
        assert_eq!(folded.get("nproc").map(String::as_str), Some("256"));
    }

    /// An in-memory [`TemplateSource`] backed by `(name, version) -> bytes`.
    struct MapSource(Vec<(String, String, Vec<u8>)>);

    impl MapSource {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn with(mut self, name: &str, version: &str, bytes: &[u8]) -> Self {
            self.0
                .push((name.to_owned(), version.to_owned(), bytes.to_vec()));
            self
        }
    }

    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(n, v, _)| n == name && v == version)
                .map(|(_, _, b)| b.clone())
        }
    }

    fn base_source() -> MapSource {
        MapSource::new().with("base-confined", "v1", BASE_CONFINED.as_bytes())
    }

    #[test]
    fn folding_ai_coding_strict_inherits_base_and_adds_its_own() {
        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        let resolved = resolve(&entry, &base_source()).expect("resolve");
        let eff = &resolved.effective;

        // Nothing left to resolve; identity is the entry's.
        assert!(eff.template_base.is_none());
        assert_eq!(eff.template_name.as_deref(), Some("ai-coding-strict"));

        // Inherited from base-confined (ai-coding-strict does not restate these).
        let cap = eff.cap.as_ref().expect("cap");
        assert_eq!(cap.no_new_privs, Some(true), "no_new_privs inherited");
        let exec = eff.exec.as_ref().expect("exec");
        assert_eq!(
            exec.deny_setuid,
            Some(true),
            "base's deny_setuid invariant flag is inherited"
        );
        let net = eff.net.as_ref().expect("net");
        let proxy = net.proxy.as_ref().expect("net.proxy");
        let nd = proxy.deny.as_ref().expect("net.proxy.deny");
        assert!(
            nd.invariant.iter().any(|d| d.cidr == "169.254.169.254/32"),
            "invariant deny inherited"
        );

        // Set by ai-coding-strict (replaces base's empty allow / adds its own).
        let allow = exec.allow.as_ref().expect("exec.allow set");
        assert!(
            allow.iter().any(|a| a.contains("git")),
            "ai-coding-strict tool present"
        );
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
        let unix = eff.unix.as_ref().expect("unix");
        assert!(unix
            .allow
            .iter()
            .any(|u| u.name.as_deref() == Some("gpg-agent")));

        // Provenance records the folded parent.
        assert_eq!(resolved.chain.len(), 1);
        let root = resolved.chain.first().expect("root link");
        assert_eq!(
            (root.name.as_str(), root.version.as_str()),
            ("base-confined", "v1")
        );
    }

    #[test]
    fn untrusted_build_overrides_net_mode_to_none() {
        let entry = parse(UNTRUSTED_BUILD.as_bytes()).expect("parse");
        let resolved = resolve(&entry, &base_source()).expect("resolve");
        let net = resolved.effective.net.as_ref().expect("net");
        assert_eq!(
            net.mode.as_deref(),
            Some("none"),
            "child scalar overrides parent"
        );
        // The invariant denies still propagate even though mode is none (the
        // mandatory cloud-metadata deny; RFC1918 is no longer an invariant).
        let nd = net
            .proxy
            .as_ref()
            .expect("net.proxy")
            .deny
            .as_ref()
            .expect("net.proxy.deny");
        assert!(nd.invariant.iter().any(|d| d.cidr == "169.254.169.254/32"));
    }

    #[test]
    fn root_template_resolves_to_itself() {
        let entry = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let resolved = resolve(&entry, &MapSource::new()).expect("resolve");
        assert!(resolved.chain.is_empty(), "root has no parents");
        assert_eq!(
            resolved.effective.template_name.as_deref(),
            Some("base-confined")
        );
    }

    #[test]
    fn bare_list_sets_and_absent_inherits() {
        // parent sets exec.deny=[a,b] and exec.allow=[x]; child sets exec.deny=[c] only.
        let parent = "template_name = \"p\"\n[exec]\nallow = [\"/x\"]\ndeny = [\"/a\", \"/b\"]\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p@v1\"\n[exec]\ndeny = [\"/c\"]\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let exec = resolved.effective.exec.as_ref().expect("exec");
        // deny: child's bare list REPLACES the parent's.
        assert_eq!(exec.deny.as_deref(), Some(&["/c".to_owned()][..]));
        // allow: child omitted it, so it INHERITS the parent's.
        assert_eq!(exec.allow.as_deref(), Some(&["/x".to_owned()][..]));
    }

    #[test]
    fn invariant_denies_union_across_the_chain() {
        let parent = "template_name = \"p\"\n[[net.proxy.deny.invariant]]\ncidr = \"10.0.0.0/8\"\nreason = \"rfc1918\"\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p@v1\"\n[[net.proxy.deny.invariant]]\ncidr = \"192.168.0.0/16\"\nreason = \"rfc1918\"\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let nd = resolved
            .effective
            .net
            .as_ref()
            .expect("net")
            .proxy
            .as_ref()
            .expect("net.proxy")
            .deny
            .as_ref()
            .expect("deny");
        assert!(
            nd.invariant.iter().any(|d| d.cidr == "10.0.0.0/8"),
            "parent invariant kept"
        );
        assert!(
            nd.invariant.iter().any(|d| d.cidr == "192.168.0.0/16"),
            "child invariant added"
        );
    }

    #[test]
    fn missing_reference_is_an_error() {
        let entry = "name = \"n\"\ntemplate_base = \"absent@v1\"\n";
        let err = resolve(&parse(entry.as_bytes()).expect("parse"), &MapSource::new())
            .expect_err("missing base must fail");
        assert!(matches!(err, PolicyError::Resolution(_)), "got {err}");
    }

    #[test]
    fn cycle_is_detected() {
        let a = "template_name = \"a\"\ntemplate_base = \"b@v1\"\n";
        let b = "template_name = \"b\"\ntemplate_base = \"a@v1\"\n";
        let src = MapSource::new()
            .with("a", "v1", a.as_bytes())
            .with("b", "v1", b.as_bytes());
        let err = resolve(&parse(a.as_bytes()).expect("parse"), &src).expect_err("cycle must fail");
        assert!(
            matches!(err, PolicyError::Resolution(_)),
            "expected Resolution, got {err}"
        );
        if let PolicyError::Resolution(m) = err {
            assert!(m.contains("cycle"), "message names the cycle: {m}");
        }
    }

    #[test]
    fn over_deep_chain_is_rejected() {
        // Build a linear chain t0 -> t1 -> ... -> t20 (deeper than MAX_CHAIN_DEPTH).
        let mut src = MapSource::new();
        let depth = MAX_CHAIN_DEPTH.saturating_add(4);
        for i in 0..=depth {
            let body = if i == depth {
                format!("template_name = \"t{i}\"\n")
            } else {
                let next = i.saturating_add(1);
                format!("template_name = \"t{i}\"\ntemplate_base = \"t{next}@v1\"\n")
            };
            src = src.with(&format!("t{i}"), "v1", body.as_bytes());
        }
        let entry = "template_name = \"t0\"\ntemplate_base = \"t1@v1\"\n";
        let err = resolve(&parse(entry.as_bytes()).expect("parse"), &src)
            .expect_err("over-deep chain must fail");
        assert!(
            matches!(err, PolicyError::Resolution(_)),
            "expected Resolution, got {err}"
        );
        if let PolicyError::Resolution(m) = err {
            assert!(m.contains("depth"), "message names the depth bound: {m}");
        }
    }

    #[test]
    fn malformed_template_base_reference_is_rejected() {
        // `@4` lacks the leading `v`. The entry's own validate() is the first gate,
        // so this surfaces as a SourceValidation error before resolution walks it.
        let entry = "name = \"n\"\ntemplate_base = \"base-confined@4\"\n";
        let err = resolve(&parse(entry.as_bytes()).expect("parse"), &base_source())
            .expect_err("malformed ref must fail");
        assert!(
            matches!(
                err,
                PolicyError::SourceValidation(_) | PolicyError::Resolution(_)
            ),
            "got {err}"
        );
        assert!(
            err.to_string().contains("version must start"),
            "explains why: {err}"
        );
    }

    #[test]
    fn bare_name_template_base_is_rejected() {
        // A `template_base` must carry an inline `@v<ver>`; the bare-name form is no longer
        // accepted — per-artefact validation rejects it outright.
        let entry = "name = \"n\"\ntemplate_base = \"base-confined\"\n";
        let err = parse(entry.as_bytes())
            .expect("parse")
            .validate()
            .expect_err("bare-name base must fail validation");
        assert!(matches!(err, PolicyError::SourceValidation(_)), "got {err}");
    }
}
