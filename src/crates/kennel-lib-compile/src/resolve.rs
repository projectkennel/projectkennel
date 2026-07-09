//! Template-chain resolution and folding — the first compiler stage proper.
//!
//! # Purpose
//!
//! Given an entry source policy (a leaf, or a template being inspected), walk its
//! `template_base` chain to the root template (`base-confined`) and fold the chain,
//! root-first, into a single *effective* [`SourcePolicy`] with no `template_base`
//! left to resolve.
//! The effective policy is what the later stages substitute, translate to a
//! [`kennel_lib_policy::settled::SettledPolicy`], and sign.
//!
//! # Composition model (the SSH `Ciphers` model)
//!
//! Fields compose down the chain (parent → child, child = more derived):
//!
//! - **Scalars** (`net.mode`, `cap.no_new_privs`, `lifecycle.ttl`, …): the most-derived
//!   value that sets the field wins; an absent field inherits.
//! - **List fields** (`exec.allow`, `fs.read`, `env.pass`, …): replace *or* increment at the same
//!   key. A child's bare list — a [`PathField::Set`](crate::source::PathField) /
//!   [`ListField::Set`](crate::source::ListField) — *sets* (replaces) the inherited list (the SSH
//!   `Ciphers = …` form); a child's `{ add, remove }` table (`[[*.add]]` / `[[*.remove]]`)
//!   *increments* it (the `+=` / `-=` form). An absent field inherits. The fold collapses every
//!   field to a `Set`, so the effective policy carries concrete lists.
//! - **Object sub-tables** (`fs.home`, `net.bind`, `dbus`, …): merged shallowly,
//!   field-by-field, with the child overriding.
//! - **Union floors** (`net.proxy.deny.invariant`, `[seccomp] deny`): *unioned*, never replaced —
//!   a child can only add to them. These do not follow the bare-set rule precisely because their
//!   non-removability is the point: the invariant metadata deny and base-confined's seccomp
//!   hardening are floors a leaf must not be able to narrow (W14).
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
//! in-memory map). Included fragments and lockfile byte-pinning are applied by
//! [`compile`](mod@crate::compile), after this stage folds the `template_base` chain.

use crate::source::{
    self, bpf_key, consumes_key, deny_key, dev_key, net_key, spawn_key, ssh_key, unix_key,
    BoundaryAcl, CapSection, DbusAudit, DbusBus, DbusRules, DbusSection, EnvSection, ExecSection,
    FsDev, FsHome, FsProc, FsSection, FsTmp, GroupField, IdentitySection, LifecycleSection,
    ListField, NetAudit, NetBind, NetBpf, NetBpfAcl, NetIpv6, NetProxy, NetProxyDeny, NetSection,
    NetUdp, PathField, RedirectEntry, RootfsSection, SeccompSection, ServiceSection, SourcePolicy,
    SpawnSection, SshSection, TrustSection, TtySection, UnixSection, UnsafeSection,
    WorkloadSection,
};
use crate::source_sig::{Tier, Trust};
use kennel_lib_policy::audit::{
    AuditClassSection, AuditFileSection, AuditSection, AuditSyslogSection,
};
use kennel_lib_policy::PolicyError;

/// Maximum inheritance-chain depth (number of `template_base` hops).
pub const MAX_CHAIN_DEPTH: usize = 16;

/// A source of template/fragment artefacts by name. Keeps [`resolve`] I/O-free: the
/// CLI implements this over the filesystem search path, tests over an in-memory map.
pub trait TemplateSource {
    /// Return the raw TOML bytes for `<name>`, or `None` if not found.
    fn fetch(&self, name: &str) -> Option<Vec<u8>>;

    /// Return the **settled, signed** form of `<name>` — the complete, chain-folded policy
    /// a spawn instantiates, beside the source (`<name>/<name>.settled.toml`). Distinct from
    /// [`Self::fetch`] (the source leaf the chain-folder composes): a spawn target is load-verified and
    /// instantiated as-is, never compiled in the daemon. `None` if no settled form is present (the
    /// default; an in-memory test source may not provide one).
    fn fetch_settled(&self, _name: &str) -> Option<Vec<u8>> {
        None
    }
}

/// One resolved link in the inheritance chain, recorded for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// The artefact's name.
    pub name: String,
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
    /// Where the folded `[[provides]]` came from — the provenance the reserved-namespace
    /// gate keys on.
    pub provides_origin: ProvidesOrigin,
    /// Non-fatal composition warnings raised while folding (W6): a bare-set clobber of a
    /// non-empty inherited list is legal but never silent. `compile` surfaces these with
    /// the rest of the compile warnings.
    pub warnings: Vec<String>,
}

/// Where a resolved policy's effective `[[provides]]` originated.
///
/// Provides fold *set-replace* (a child's non-empty list replaces the inherited one), so
/// exactly one layer supplies the whole effective set, and a single origin describes it. The
/// reserved-namespace gate keys on this: a reserved `org.projectkennel.*` name is
/// maintainer-trust material, so it is permitted only when it traces to a signature-verified
/// template — never an unverified layer that could inject it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvidesOrigin {
    /// No `[[provides]]` in the resolved policy.
    Absent,
    /// The entry (the most-derived artefact) authored them — the template-authoring path. Its
    /// reserved-name authority is conferred by the **tier** of the key that signs the settled output
    /// (the `--key`), checked at compile, since the entry itself is not signature-checked here.
    Entry,
    /// An ancestor template supplied them. `tier` is the [`Tier`] the supplying template's signature
    /// verified at (which trust dir loaded the key), or `None` if it did not verify. The
    /// reserved-namespace gate keys on this: `org.projectkennel.*` is permitted only when `tier` is
    /// [`Tier::Vendor`] — any vendor key qualifies, identity never enters it.
    Ancestor {
        /// The trust tier the supplying ancestor's signature verified at, or `None` if unverified.
        tier: Option<Tier>,
    },
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
/// under the user's own authority.
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
        let name = parse_reference(&reference)?;
        if seen.iter().any(|s| s == &name) {
            return Err(PolicyError::Resolution(format!(
                "cycle detected at `{name}`"
            )));
        }
        if parents.len() >= MAX_CHAIN_DEPTH {
            return Err(PolicyError::Resolution(format!(
                "inheritance chain exceeds the maximum depth of {MAX_CHAIN_DEPTH}"
            )));
        }
        seen.push(name.clone());
        let bytes = source.fetch(&name).ok_or_else(|| {
            PolicyError::Resolution(format!("reference `{name}` not found in the search path"))
        })?;
        let parent = source::parse(&bytes)?;
        parent.validate()?;
        let signing_key_id = trust.check(&name, &parent)?;
        let signature = parent.signature.as_ref().map(|e| e.signature.clone());
        links.push(ChainLink {
            name,
            signing_key_id,
            signature,
        });
        parents.push(parent.clone());
        current = parent;
    }

    // Provides fold set-replace, so the effective set comes from one layer; record which, for
    // the reserved-namespace gate. The entry (most-derived) wins if it declares any;
    // else the most-derived *ancestor* that does (parents is leaf-first, so `position` finds it),
    // tagged with whether that ancestor's signature verified against the trust store.
    let provides_origin = if !entry.provides.is_empty() {
        ProvidesOrigin::Entry
    } else if let Some(i) = parents.iter().position(|p| !p.provides.is_empty()) {
        // `i` indexes the parent that supplies the provides; `links[i]` is its verification record
        // (built in the same leaf-first order). `.get` keeps clippy's no-indexing rule satisfied.
        ProvidesOrigin::Ancestor {
            tier: links
                .get(i)
                .and_then(|l| l.signing_key_id.as_deref())
                .map(|kid| trust.tier_of(kid)),
        }
    } else {
        ProvidesOrigin::Absent
    };

    // Fold root-first: the deepest ancestor is the accumulator, then each more-derived
    // artefact overrides it, and finally `entry`. `parents` is leaf-first, so the root
    // is its last element.
    // A root template with no parent resolves to itself.
    let mut warnings = Vec::new();
    let mut acc = parents.pop().unwrap_or_else(|| entry.clone());
    while let Some(child) = parents.pop() {
        acc = fold(&acc, &child, &mut warnings);
    }
    acc = fold(&acc, entry, &mut warnings);

    // The `template_base` chain is fully folded; nothing left to inherit. The folded
    // `include` list is *kept* (not cleared): includes are applied separately by
    // `compile`/`compile_leaf` via `apply_includes`, which reads exactly this list, so
    // clearing it here silently dropped every `include` declared on a source template.
    acc.template_base = None;
    entry.template_name.clone_into(&mut acc.template_name);
    entry.name.clone_into(&mut acc.name);
    acc.signature = None;

    links.reverse(); // root-first for provenance
    Ok(ResolvedChain {
        effective: acc,
        chain: links,
        provides_origin,
        warnings,
    })
}

/// Fold an additive included **fragment** onto an already-resolved effective policy.
///
/// Applies the fragment's add-only increments (and unions its `[[net.proxy.deny.invariant]]` floors)
/// the same way [`fold`] folds a chain step, but the identity, `include`, and signature fields stay
/// the base's — a fragment contributes capability, never identity. The caller has already
/// checked [`SourcePolicy::is_additive_only`].
#[must_use]
pub(crate) fn apply_fragment(base: &SourcePolicy, fragment: &SourcePolicy) -> SourcePolicy {
    // A fragment is add-only (`is_additive_only`, checked by the caller), so a bare-set
    // clobber cannot occur on this fold; the sink is a formality.
    let mut folded = fold(base, fragment, &mut Vec::new());
    base.template_base.clone_into(&mut folded.template_base);
    base.template_name.clone_into(&mut folded.template_name);
    base.name.clone_into(&mut folded.name);
    folded.include.clone_from(&base.include);
    folded.signature = None;
    folded
}

/// Validate a template reference (a bare name) and return it.
pub(crate) fn parse_reference(reference: &str) -> Result<String, PolicyError> {
    let bad =
        |d: String| PolicyError::Resolution(format!("`template_base` = \"{reference}\": {d}"));
    source::validate_ref_name(reference).map_err(bad)?;
    Ok(reference.to_owned())
}

/// Fold `child` over `parent`, child overriding. Identity fields are settled by the
/// caller after the full fold; here they take the child's value.
fn fold(parent: &SourcePolicy, child: &SourcePolicy, warn: &mut Vec<String>) -> SourcePolicy {
    SourcePolicy {
        template_base: child.template_base.clone(),
        template_name: or(&child.template_name, &parent.template_name),
        name: or(&child.name, &parent.name),
        include: union_strings(&parent.include, &child.include),
        threat_catalogue_version: or(
            &child.threat_catalogue_version,
            &parent.threat_catalogue_version,
        ),
        signature: None,
        cap: merge(&parent.cap, &child.cap, fold_cap),
        exec: merge(&parent.exec, &child.exec, |p, c| fold_exec(p, c, warn)),
        fs: merge(&parent.fs, &child.fs, |p, c| fold_fs(p, c, warn)),
        net: merge(&parent.net, &child.net, |p, c| fold_net(p, c, warn)),
        unix: merge(&parent.unix, &child.unix, |p, c| fold_unix(p, c, warn)),
        ssh: merge(&parent.ssh, &child.ssh, |p, c| fold_ssh(p, c, warn)),
        identity: merge(&parent.identity, &child.identity, |p, c| {
            fold_identity(p, c, warn)
        }),
        // `[[provides]]` folds set-replace DELIBERATELY (W6): the reserved-namespace gate
        // attributes the effective provides set to ONE declaring layer (`provides_origin`)
        // and resolves its tier from that layer's signature — per-entry delta composition
        // would smear that authority attribution across layers. Renaming is no escape and
        // neither is composition. The clobber is still never silent (the warning below).
        provides: {
            if !child.provides.is_empty() && !parent.provides.is_empty() {
                warn_clobber(warn, "[[provides]]", parent.provides.len());
            }
            if child.provides.is_empty() {
                parent.provides.clone()
            } else {
                child.provides.clone()
            }
        },
        // `[[consumes]]` is demand-side (it claims no name authority), so it composes:
        // replace or increment (`[[consumes.add]]`), keyed by capability name.
        consumes: fold_listfield(
            &child.consumes,
            &parent.consumes,
            consumes_key,
            "consumes",
            warn,
        ),
        service: merge(&parent.service, &child.service, fold_service),
        unsafe_section: merge(&parent.unsafe_section, &child.unsafe_section, fold_unsafe),
        env: merge(&parent.env, &child.env, fold_env),
        seccomp: merge(&parent.seccomp, &child.seccomp, fold_seccomp),
        lifecycle: merge(&parent.lifecycle, &child.lifecycle, fold_lifecycle),
        audit: merge(&parent.audit, &child.audit, |p, c| fold_audit(p, c, warn)),
        ulimits: merge(&parent.ulimits, &child.ulimits, fold_ulimits),
        workload: merge(&parent.workload, &child.workload, fold_workload),
        tty: merge(&parent.tty, &child.tty, fold_tty),
        trust: merge(&parent.trust, &child.trust, fold_trust),
        dbus: merge(&parent.dbus, &child.dbus, fold_dbus),
        rootfs: merge(&parent.rootfs, &child.rootfs, fold_rootfs),
        spawn: merge(&parent.spawn, &child.spawn, |p, c| fold_spawn(p, c, warn)),
        // The `[[mutable]]` manifest folds set-replace DELIBERATELY (W6): it is the spawn
        // target template's OWN contract about which of its fields a spawner may patch —
        // letting an includer or child inject mutability additively would be a hole, not
        // a feature. Never silent (the warning), but never composed either.
        mutable: {
            if !child.mutable.is_empty() && !parent.mutable.is_empty() {
                warn_clobber(warn, "[[mutable]]", parent.mutable.len());
            }
            if child.mutable.is_empty() {
                parent.mutable.clone()
            } else {
                child.mutable.clone()
            }
        },
    }
}

/// Fold `[spawn]` down the chain: `max_instances` and `reason` are scalar-wins (child overriding);
/// the `[[spawn.allow]]` target set replaces or increments (`[[spawn.allow.add]]`), keyed by
/// template name — a child extends the instantiable set without restating it (W6).
fn fold_spawn(p: &SpawnSection, c: &SpawnSection, warn: &mut Vec<String>) -> SpawnSection {
    SpawnSection {
        max_instances: or(&c.max_instances, &p.max_instances),
        reason: or(&c.reason, &p.reason),
        allow: fold_listfield(&c.allow, &p.allow, spawn_key, "spawn.allow", warn),
    }
}

/// Fold `[rootfs]` down the chain: each field is scalar-wins, child overriding. OCI-model
/// policies are leaves, so a leaf names the substrate; this lets a template carry a default
/// `reason` or a leaf override one field without restating all three.
fn fold_rootfs(p: &RootfsSection, c: &RootfsSection) -> RootfsSection {
    RootfsSection {
        path: or(&c.path, &p.path),
        image: or(&c.image, &p.image),
        reason: or(&c.reason, &p.reason),
        persistence: or(&c.persistence, &p.persistence),
        // Closure-lock lists fold scalar-wins like `fs.read` (the SSH list model — the chain
        // replaces, leaf `+=`/`-=` deltas apply separately); in practice these live on the leaf,
        // build-derived, so the leaf's set wins.
        readonly: or(&c.readonly, &p.readonly),
        writable: or(&c.writable, &p.writable),
    }
}

/// Fold `[dbus]` down the chain: `enabled` is scalar-wins per bus; the allow/deny rule
/// lists union (a child or fragment widens what the bus may reach), matching how
/// `[[net.proxy.allow]]` composes. The `[dbus.audit]` level is scalar-wins.
fn fold_dbus(p: &DbusSection, c: &DbusSection) -> DbusSection {
    DbusSection {
        session: fold_dbus_bus(p.session.as_ref(), c.session.as_ref()),
        system: fold_dbus_bus(p.system.as_ref(), c.system.as_ref()),
        audit: match (&c.audit, &p.audit) {
            (Some(ca), Some(pa)) => Some(DbusAudit {
                level: or(&ca.level, &pa.level),
            }),
            (some, None) | (None, some) => some.clone(),
        },
    }
}

/// Fold one bus: child `enabled` wins; allow/deny rule lists union parent ∪ child.
fn fold_dbus_bus(p: Option<&DbusBus>, c: Option<&DbusBus>) -> Option<DbusBus> {
    match (p, c) {
        (None, None) => None,
        (Some(b), None) | (None, Some(b)) => Some(b.clone()),
        (Some(p), Some(c)) => Some(DbusBus {
            enabled: or(&c.enabled, &p.enabled),
            allow: union_dbus_rules(p.allow.as_ref(), c.allow.as_ref()),
            deny: union_dbus_rules(p.deny.as_ref(), c.deny.as_ref()),
        }),
    }
}

/// Union two optional rule sets, de-duplicating each class (order-independent compose).
fn union_dbus_rules(p: Option<&DbusRules>, c: Option<&DbusRules>) -> Option<DbusRules> {
    match (p, c) {
        (None, None) => None,
        (Some(r), None) | (None, Some(r)) => Some(r.clone()),
        (Some(p), Some(c)) => {
            let join = |a: &[String], b: &[String]| {
                let mut v = a.to_vec();
                for x in b {
                    if !v.contains(x) {
                        v.push(x.clone());
                    }
                }
                v
            };
            Some(DbusRules {
                talk: join(&p.talk, &c.talk),
                call: join(&p.call, &c.call),
                broadcast: join(&p.broadcast, &c.broadcast),
                own: join(&p.own, &c.own),
            })
        }
    }
}

/// Fold `[service]` scalar-wins (child overrides), like `[lifecycle]` — a derived policy may
/// override any one restart-policy field without restating the others.
fn fold_service(p: &ServiceSection, c: &ServiceSection) -> ServiceSection {
    ServiceSection {
        restart: or(&c.restart, &p.restart),
        backoff: or(&c.backoff, &p.backoff),
        max_attempts: or(&c.max_attempts, &p.max_attempts),
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
        allowed_args: or(&c.allowed_args, &p.allowed_args),
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
/// `FnMut` so a caller's closure may capture the fold's warning sink mutably.
#[allow(clippy::ref_option)]
fn merge<T: Clone>(
    parent: &Option<T>,
    child: &Option<T>,
    mut f: impl FnMut(&T, &T) -> T,
) -> Option<T> {
    match (parent, child) {
        (Some(p), Some(c)) => Some(f(p, c)),
        (p, c) => c.clone().or_else(|| p.clone()),
    }
}

/// Report a bare-set clobber: a child's non-empty set form replacing a non-empty inherited
/// list. Legal (a template may define its own floor; a leaf may redefine wholesale) but
/// NEVER silent (W6) — previously visible only in a compiled-artefact diff.
fn warn_clobber(warn: &mut Vec<String>, field: &str, dropped: usize) {
    warn.push(format!(
        "`{field}` bare-set replaces {dropped} inherited entr{} — an `add` increment \
         extends the inherited list instead",
        if dropped == 1 { "y" } else { "ies" }
    ));
}

/// Fold a path-list field one chain step (`fs.read`/`fs.write`/`fs.deny`/`exec.allow`): a child
/// `Set` *replaces*, a child `Delta` *increments* the inherited value, an absent field inherits.
/// The result is always a `Set` — the deltas have been folded into a concrete list.
#[allow(clippy::ref_option)]
fn fold_pathfield(
    child: &Option<PathField>,
    parent: &Option<PathField>,
    field: &str,
    warn: &mut Vec<String>,
) -> Option<PathField> {
    match child {
        None => parent.clone(),
        Some(PathField::Set(v)) => {
            if let Some(PathField::Set(pv)) = parent {
                if !v.is_empty() && !pv.is_empty() {
                    warn_clobber(warn, field, pv.len());
                }
            }
            Some(PathField::Set(v.clone()))
        }
        Some(PathField::Delta(d)) => {
            let mut base: Vec<String> = match parent {
                Some(PathField::Set(v)) => v.clone(),
                _ => Vec::new(),
            };
            for e in &d.add {
                for path in &e.path {
                    if !base.contains(path) {
                        base.push(path.clone());
                    }
                }
            }
            base.retain(|p| !d.remove.iter().any(|e| e.path.contains(p)));
            Some(PathField::Set(base))
        }
    }
}

/// Fold a typed-list field one chain step (`unix.allow`, `net.proxy.allow`, …): a non-empty child
/// `Set` *replaces*, an empty `Set` inherits (the bare-list "absent" sentinel), a `Delta`
/// *increments* (dedup/match by `key`). The result is always a `Set`.
fn fold_listfield<T: Clone>(
    child: &ListField<T>,
    parent: &ListField<T>,
    key: fn(&T) -> &str,
    field: &str,
    warn: &mut Vec<String>,
) -> ListField<T> {
    match child {
        ListField::Set(v) if v.is_empty() => parent.clone(),
        ListField::Set(v) => {
            if let ListField::Set(pv) = parent {
                if !pv.is_empty() {
                    warn_clobber(warn, field, pv.len());
                }
            }
            ListField::Set(v.clone())
        }
        ListField::Delta(d) => {
            let mut base: Vec<T> = match parent {
                ListField::Set(v) => v.clone(),
                ListField::Delta(_) => Vec::new(),
            };
            for e in &d.add {
                if !base.iter().any(|x| key(x) == key(e)) {
                    base.push(e.clone());
                }
            }
            base.retain(|x| !d.remove.iter().any(|r| key(r) == key(x)));
            ListField::Set(base)
        }
    }
}

/// Fold the `[identity].groups` field one chain step: a non-empty bare set *replaces*
/// (warned), an empty set inherits, an `{ add, remove }` of `{ group, reason }` entries
/// *increments* — the [`fold_listfield`] model over the group-entry shape.
fn fold_groupfield(child: &GroupField, parent: &GroupField, warn: &mut Vec<String>) -> GroupField {
    match child {
        GroupField::Set(v) if v.is_empty() => parent.clone(),
        GroupField::Set(v) => {
            if let GroupField::Set(pv) = parent {
                if !pv.is_empty() {
                    warn_clobber(warn, "identity.groups", pv.len());
                }
            }
            GroupField::Set(v.clone())
        }
        GroupField::Delta(d) => {
            let mut base: Vec<String> = match parent {
                GroupField::Set(v) => v.clone(),
                GroupField::Delta(_) => Vec::new(),
            };
            for e in &d.add {
                if !base.contains(&e.group) {
                    base.push(e.group.clone());
                }
            }
            base.retain(|g| !d.remove.iter().any(|e| e.group == *g));
            GroupField::Set(base)
        }
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
    }
}

fn fold_exec(p: &ExecSection, c: &ExecSection, warn: &mut Vec<String>) -> ExecSection {
    ExecSection {
        allow: fold_pathfield(&c.allow, &p.allow, "exec.allow", warn),
        // exec.deny is a FLOOR (W6, the W14 seccomp model): a child ADDS paths, never
        // replaces the chain's — a deny should never silently vanish under a bare-set.
        deny: union_names(p.deny.as_deref(), c.deny.as_deref()),
        deny_setuid: or(&c.deny_setuid, &p.deny_setuid),
        deny_setgid: or(&c.deny_setgid, &p.deny_setgid),
        deny_setcap: or(&c.deny_setcap, &p.deny_setcap),
        deny_writable: or(&c.deny_writable, &p.deny_writable),
        path: or(&c.path, &p.path),
        shell: or(&c.shell, &p.shell),
    }
}

fn fold_fs(p: &FsSection, c: &FsSection, warn: &mut Vec<String>) -> FsSection {
    FsSection {
        read: fold_pathfield(&c.read, &p.read, "fs.read", warn),
        write: fold_pathfield(&c.write, &p.write, "fs.write", warn),
        exclusive: or(&c.exclusive, &p.exclusive),
        deny: fold_pathfield(&c.deny, &p.deny, "fs.deny", warn),
        home: merge(&p.home, &c.home, fold_fs_home),
        tmp: merge(&p.tmp, &c.tmp, fold_fs_tmp),
        proc: merge(&p.proc, &c.proc, fold_fs_proc),
        dev: merge(&p.dev, &c.dev, |p, c| fold_fs_dev(p, c, warn)),
        // Scalar-wins: a child that declares `[fs.cwd]` redefines it wholesale (the grant is
        // an authority the leaf owns end-to-end, not a set to union into).
        cwd: or(&c.cwd, &p.cwd),
        redirect: fold_redirects(p, c),
    }
}

/// Fold the `source` redirects (W15) one chain step, mirroring [`fold_pathfield`] per axis.
///
/// A redirect rides its granting entry, so it follows that entry's fold fate on its own axis
/// (`fs.read` or `fs.write`): a child that *replaces* the axis (`Set`) clobbers the axis's
/// inherited redirects (bare strings carry no `source`); a `Delta` inherits them, drops any
/// whose path the delta removes, and adds/overrides one per `source`-bearing add (child wins
/// on the same path); an absent field inherits unchanged. Per-artefact validation caps a
/// `source`-bearing add at one path, so `path.first()` is total here.
fn fold_redirects(p: &FsSection, c: &FsSection) -> Vec<RedirectEntry> {
    let mut out = Vec::new();
    for (write, child_field) in [(false, &c.read), (true, &c.write)] {
        let inherited = p.redirect.iter().filter(|r| r.write == write);
        match child_field {
            None => out.extend(inherited.cloned()),
            Some(PathField::Set(_)) => {}
            Some(PathField::Delta(d)) => {
                let mut axis: Vec<RedirectEntry> = inherited.cloned().collect();
                axis.retain(|r| !d.remove.iter().any(|e| e.path.contains(&r.path)));
                for e in &d.add {
                    let (Some(source), Some(path)) = (&e.source, e.path.first()) else {
                        continue;
                    };
                    axis.retain(|r| r.path != *path);
                    axis.push(RedirectEntry {
                        path: path.clone(),
                        source: source.clone(),
                        write,
                    });
                }
                out.extend(axis);
            }
        }
    }
    out
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
        writable: or(&c.writable, &p.writable),
        size: or(&c.size, &p.size),
    }
}

fn fold_fs_proc(p: &FsProc, c: &FsProc) -> FsProc {
    FsProc {
        hidepid: or(&c.hidepid, &p.hidepid),
    }
}

fn fold_fs_dev(p: &FsDev, c: &FsDev, warn: &mut Vec<String>) -> FsDev {
    FsDev {
        allow: or(&c.allow, &p.allow),
        // Replace or increment (`[[fs.dev.passthrough.add]]`), keyed by device path.
        passthrough: fold_listfield(
            &c.passthrough,
            &p.passthrough,
            dev_key,
            "fs.dev.passthrough",
            warn,
        ),
    }
}

fn fold_net(p: &NetSection, c: &NetSection, warn: &mut Vec<String>) -> NetSection {
    NetSection {
        mode: or(&c.mode, &p.mode),
        reason: or(&c.reason, &p.reason),
        proxy_listen_address: or(&c.proxy_listen_address, &p.proxy_listen_address),
        proxy: merge(&p.proxy, &c.proxy, |p, c| fold_net_proxy(p, c, warn)),
        bpf: merge(&p.bpf, &c.bpf, |p, c| fold_net_bpf(p, c, warn)),
        bind: merge(&p.bind, &c.bind, fold_net_bind),
        ipv6: merge(&p.ipv6, &c.ipv6, fold_net_ipv6),
        audit: merge(&p.audit, &c.audit, fold_net_audit),
        udp: merge(&p.udp, &c.udp, |p, c| fold_net_udp(p, c, warn)),
    }
}

/// Fold `[net.udp]`: compose the destination allowlist (fragments increment via
/// `[[net.udp.allow.add]]`), keyed like `[[net.proxy.allow]]`.
fn fold_net_udp(p: &NetUdp, c: &NetUdp, warn: &mut Vec<String>) -> NetUdp {
    NetUdp {
        allow: fold_listfield(&c.allow, &p.allow, net_key, "net.udp.allow", warn),
    }
}

fn fold_net_proxy(p: &NetProxy, c: &NetProxy, warn: &mut Vec<String>) -> NetProxy {
    NetProxy {
        // Replace or increment (`[[net.proxy.allow.add]]`), keyed by name/cidr.
        allow: fold_listfield(&c.allow, &p.allow, net_key, "net.proxy.allow", warn),
        deny: merge(&p.deny, &c.deny, |p, c| fold_net_proxy_deny(p, c, warn)),
    }
}

fn fold_net_proxy_deny(p: &NetProxyDeny, c: &NetProxyDeny, warn: &mut Vec<String>) -> NetProxyDeny {
    // Invariant denies UNION and never drop — invariants propagate down the chain.
    let mut invariant = p.invariant.clone();
    for d in &c.invariant {
        if !invariant.iter().any(|e| e.cidr == d.cidr) {
            invariant.push(d.clone());
        }
    }
    // The author denylist replaces or increments (`[[net.proxy.deny.policy.add]]`), keyed by cidr.
    let policy = fold_listfield(
        &c.policy,
        &p.policy,
        deny_key,
        "net.proxy.deny.policy",
        warn,
    );
    NetProxyDeny { invariant, policy }
}

fn fold_net_bpf(p: &NetBpf, c: &NetBpf, warn: &mut Vec<String>) -> NetBpf {
    NetBpf {
        // The allow-shaped family list is scalar-wins (child overrides when set); the
        // deny list is a FLOOR (W6, the W14 seccomp model): a child adds, never removes.
        families: or(&c.families, &p.families),
        deny_families: union_names(p.deny_families.as_deref(), c.deny_families.as_deref()),
        connect: merge(&p.connect, &c.connect, |p, c| {
            fold_net_bpf_acl(p, c, "net.bpf.connect", warn)
        }),
        bind: merge(&p.bind, &c.bind, |p, c| {
            fold_net_bpf_acl(p, c, "net.bpf.bind", warn)
        }),
    }
}

fn fold_net_bpf_acl(p: &NetBpfAcl, c: &NetBpfAcl, dir: &str, warn: &mut Vec<String>) -> NetBpfAcl {
    // Each direction's allow/deny replaces or increments (`[[net.bpf.connect.allow.add]]`), by cidr.
    NetBpfAcl {
        allow: fold_listfield(&c.allow, &p.allow, bpf_key, &format!("{dir}.allow"), warn),
        deny: fold_listfield(&c.deny, &p.deny, bpf_key, &format!("{dir}.deny"), warn),
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

fn fold_audit(p: &AuditSection, c: &AuditSection, warn: &mut Vec<String>) -> AuditSection {
    AuditSection {
        // Bare-set replace DELIBERATELY (W6): the sink list is deployment configuration
        // (where events go), not a capability floor, and `AuditSection` lives in the
        // policy crate — importing the compose machinery there would grow the TCB for a
        // config list. The clobber is warned, never silent.
        sinks: {
            if !c.sinks.is_empty() && !p.sinks.is_empty() {
                warn_clobber(warn, "audit.sinks", p.sinks.len());
            }
            if c.sinks.is_empty() {
                p.sinks.clone()
            } else {
                c.sinks.clone()
            }
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

fn fold_unix(p: &UnixSection, c: &UnixSection, warn: &mut Vec<String>) -> UnixSection {
    UnixSection {
        abstract_ns: or(&c.abstract_ns, &p.abstract_ns),
        // Replace or increment (`[[unix.allow.add]]`), keyed by name/real.
        allow: fold_listfield(&c.allow, &p.allow, unix_key, "unix.allow", warn),
    }
}

fn fold_identity(
    p: &IdentitySection,
    c: &IdentitySection,
    warn: &mut Vec<String>,
) -> IdentitySection {
    // `user`/`hostname` are scalar-wins; the supplementary-group list replaces or
    // increments (`[[identity.groups.add]]`, each add carrying its reason — a group is a
    // real privilege), so a leaf extends a template's group floor without restating it (W6).
    IdentitySection {
        user: or(&c.user, &p.user),
        group: or(&c.group, &p.group),
        hostname: or(&c.hostname, &p.hostname),
        groups: fold_groupfield(&c.groups, &p.groups, warn),
    }
}

fn fold_ssh(p: &SshSection, c: &SshSection, warn: &mut Vec<String>) -> SshSection {
    SshSection {
        allow_headless: or(&c.allow_headless, &p.allow_headless),
        threats: or(&c.threats, &p.threats),
        // Replace or increment (`[[ssh.destinations.add]]`), keyed by destination.
        destinations: fold_listfield(
            &c.destinations,
            &p.destinations,
            ssh_key,
            "ssh.destinations",
            warn,
        ),
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
        // env.deny is a FLOOR (W6, the W14 seccomp model): a child adds names, never
        // removes the chain's — a denied variable never silently reappears.
        deny: union_names(p.deny.as_deref(), c.deny.as_deref()),
    }
}

fn fold_seccomp(p: &SeccompSection, c: &SeccompSection) -> SeccompSection {
    SeccompSection {
        profile: or(&c.profile, &p.profile),
        // Seccomp deny is a **floor**: a child ADDS to the resolved base, never replaces it (W14).
        // A bare `deny = [...]` on a leaf previously clobbered base-confined's hardening via the
        // scalar `or`-fold; now it unions, so a leaf can only strengthen the denylist. There is no
        // remove form — that is the point (base-confined's deny is not a leaf's to weaken).
        deny: union_names(p.deny.as_deref(), c.deny.as_deref()),
        allow: or(&c.allow, &p.allow),
    }
}

/// Union two optional name lists, order-preserving and de-duplicated (parent first).
///
/// `None ∪ None = None`; either present yields `Some(union)`. Backs the additive `[seccomp]`
/// deny floor (W14) — a child may add names, never remove the parent's.
fn union_names(p: Option<&[String]>, c: Option<&[String]>) -> Option<Vec<String>> {
    if p.is_none() && c.is_none() {
        return None;
    }
    let mut out: Vec<String> = p.unwrap_or_default().to_vec();
    for name in c.unwrap_or_default() {
        if !out.contains(name) {
            out.push(name.clone());
        }
    }
    Some(out)
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

    #[test]
    fn dbus_folds_additively_with_scalar_enabled_winning() {
        // Parent enables session + grants Notifications; child adds portals (union) and the
        // child's enabled wins. The deny union holds too.
        let parent = parse(
            b"template_name = \"p\"\n[dbus.session]\nenabled = true\n[dbus.session.allow]\ntalk = [\"org.freedesktop.Notifications\"]\n",
        )
        .expect("parent");
        let child = parse(
            b"name = \"k\"\ntemplate_base = \"p\"\n[dbus.session]\nenabled = true\n[dbus.session.allow]\ntalk = [\"org.freedesktop.portal.*\"]\n",
        )
        .expect("child");
        let folded = fold_dbus(
            parent.dbus.as_ref().expect("p dbus"),
            child.dbus.as_ref().expect("c dbus"),
        );
        let allow = folded.session.expect("session").allow.expect("allow");
        assert!(allow
            .talk
            .contains(&"org.freedesktop.Notifications".to_owned()));
        assert!(allow.talk.contains(&"org.freedesktop.portal.*".to_owned()));
    }

    const BASE_CONFINED: &str =
        include_str!("../../../../toml/templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../toml/templates/ai-coding-strict/policy.toml");
    const UNTRUSTED_BUILD: &str =
        include_str!("../../../../toml/templates/untrusted-build/policy.toml");

    /// Redirects (W15) ride their granting entry through the fold, per axis.
    #[test]
    fn redirects_fold_with_their_axis_and_child_wins_on_the_same_path() {
        let parent = parse(
            b"template_name = \"p\"\n[[fs.read.add]]\npath = \"~/.app/cred.json\"\nsource = \"~/stores/a.json\"\nreason = \"redirected credential\"\n",
        )
        .expect("parent");
        let pfs = parent.fs.as_ref().expect("p fs");
        // The entry's own fold step populates the carrier.
        let folded = fold_fs(&FsSection::default(), pfs, &mut Vec::new());
        assert_eq!(folded.redirect.len(), 1);
        assert_eq!(
            folded.redirect.first().map(|r| r.source.as_str()),
            Some("~/stores/a.json")
        );
        assert!(folded.redirect.first().is_some_and(|r| !r.write));

        // An absent child field inherits; a child re-adding the same path with its own
        // `source` overrides (child wins); a child removing the path drops the redirect.
        let inherit = fold_fs(&folded, &FsSection::default(), &mut Vec::new());
        assert_eq!(inherit.redirect, folded.redirect);

        let override_child = parse(
            b"name = \"k\"\ntemplate_base = \"p\"\n[[fs.read.add]]\npath = \"~/.app/cred.json\"\nsource = \"~/stores/b.json\"\nreason = \"retargeted\"\n",
        )
        .expect("override child");
        let folded2 = fold_fs(
            &folded,
            override_child.fs.as_ref().expect("c fs"),
            &mut Vec::new(),
        );
        assert_eq!(folded2.redirect.len(), 1);
        assert_eq!(
            folded2.redirect.first().map(|r| r.source.as_str()),
            Some("~/stores/b.json")
        );

        let removing_child = parse(
            b"name = \"k\"\ntemplate_base = \"p\"\n[[fs.read.remove]]\npath = \"~/.app/cred.json\"\nreason = \"dropped\"\n",
        )
        .expect("removing child");
        let folded3 = fold_fs(
            &folded,
            removing_child.fs.as_ref().expect("c fs"),
            &mut Vec::new(),
        );
        assert!(folded3.redirect.is_empty());

        // A set-form replacement of the axis clobbers its redirects (bare strings carry no
        // `source`), while the other axis's redirects survive.
        let replacing_child =
            parse(b"name = \"k\"\ntemplate_base = \"p\"\n[fs]\nread = [\"/usr\"]\n")
                .expect("replacing child");
        let folded4 = fold_fs(
            &folded,
            replacing_child.fs.as_ref().expect("c fs"),
            &mut Vec::new(),
        );
        assert!(folded4.redirect.is_empty());
    }

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
        fn fetch(&self, name: &str) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, _, b)| b.clone())
        }
    }

    fn base_source() -> MapSource {
        let mut src = MapSource::new().with("base-confined", "v1", BASE_CONFINED.as_bytes());
        for (name, body) in crate::TEST_FRAGMENTS {
            src = src.with(name, "v1", body.as_bytes());
        }
        src
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

        // Set by ai-coding-strict's own inline allow (its shared userland now comes from included
        // fragments, applied by `compile`, not `resolve` — so resolve sees only the bespoke tools).
        let allow = exec.allow.as_ref().expect("exec.allow set");
        assert!(
            allow.iter().any(|a| a.contains("python3")),
            "ai-coding-strict tool present"
        );
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
        // ai-coding-strict grants no agent socket — no gpg-agent (GPG signing can't be
        // made safe in a kennel) and no ssh-agent (SSH goes via the bastion).
        let has_agent = eff.unix.as_ref().is_some_and(|u| {
            u.allow.iter().any(|a| {
                a.name.as_deref() == Some("gpg-agent") || a.name.as_deref() == Some("ssh-agent")
            })
        });
        assert!(!has_agent, "no agent shim in the folded template");

        // Provenance records the folded parent.
        assert_eq!(resolved.chain.len(), 1);
        let root = resolved.chain.first().expect("root link");
        assert_eq!(root.name.as_str(), "base-confined");
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
    fn exec_deny_floors_and_absent_allow_inherits() {
        // parent sets exec.deny=[a,b] and exec.allow=[x]; child sets exec.deny=[c] only.
        let parent = "template_name = \"p\"\n[exec]\nallow = [\"/x\"]\ndeny = [\"/a\", \"/b\"]\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n[exec]\ndeny = [\"/c\"]\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let exec = resolved.effective.exec.as_ref().expect("exec");
        // deny is a FLOOR (W6, the W14 seccomp model): the child's list UNIONS onto the
        // chain's — a deny never silently vanishes under a bare-set.
        assert_eq!(
            exec.deny.as_deref(),
            Some(&["/a".to_owned(), "/b".to_owned(), "/c".to_owned()][..])
        );
        // allow: child omitted it, so it INHERITS the parent's.
        assert_eq!(
            exec.allow.as_ref().and_then(PathField::set),
            Some(&["/x".to_owned()][..])
        );
    }

    /// The W6 floors: `env.deny` and `net.bpf.deny_families` union up the chain like
    /// exec.deny and the W14 seccomp deny — a child adds, never removes.
    #[test]
    fn env_and_bpf_deny_floors_union_across_the_chain() {
        let parent = "template_name = \"p\"\n[env]\ndeny = [\"LD_PRELOAD\"]\n[net.bpf]\ndeny_families = [\"packet\"]\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n[env]\ndeny = [\"DOCKER_HOST\"]\n[net.bpf]\ndeny_families = [\"vsock\"]\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let env = resolved.effective.env.as_ref().expect("env");
        assert_eq!(
            env.deny.as_deref(),
            Some(&["LD_PRELOAD".to_owned(), "DOCKER_HOST".to_owned()][..])
        );
        let bpf = resolved
            .effective
            .net
            .as_ref()
            .and_then(|n| n.bpf.as_ref())
            .expect("bpf");
        assert_eq!(
            bpf.deny_families.as_deref(),
            Some(&["packet".to_owned(), "vsock".to_owned()][..])
        );
    }

    /// A bare-set that discards a non-empty inherited list is legal but WARNED (W6):
    /// the silent-floor-drop class closes by visibility on every covered field.
    #[test]
    fn bare_set_clobber_is_warned_never_silent() {
        let parent =
            "template_name = \"p\"\n[fs]\nread = [\"/usr/**\", \"/lib/**\"]\n[identity]\ngroups = [\"dialout\"]\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n[fs]\nread = [\"/opt/**\"]\n[identity]\ngroups = [\"plugdev\"]\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        assert!(
            resolved
                .warnings
                .iter()
                .any(|w| w.contains("`fs.read` bare-set replaces 2 inherited entries")),
            "fs.read clobber warned: {:?}",
            resolved.warnings
        );
        assert!(
            resolved
                .warnings
                .iter()
                .any(|w| w.contains("`identity.groups` bare-set replaces 1 inherited entry")),
            "groups clobber warned: {:?}",
            resolved.warnings
        );
        // An increment raises no warning — that IS the recommended form.
        let delta_child = "template_name = \"c\"\ntemplate_base = \"p\"\n[[fs.read.add]]\npath = \"/opt/**\"\nreason = \"tooling\"\n";
        let resolved =
            resolve(&parse(delta_child.as_bytes()).expect("parse"), &src).expect("resolve");
        assert!(
            resolved.warnings.is_empty(),
            "no warning on an add increment: {:?}",
            resolved.warnings
        );
    }

    /// `[[identity.groups.add]]` extends the inherited group set (each add reasoned);
    /// a remove drops one; the resolved form is the plain list.
    #[test]
    fn identity_groups_delta_extends_the_inherited_set() {
        let parent = "template_name = \"p\"\n[identity]\ngroups = [\"dialout\", \"video\"]\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n\
                     [[identity.groups.add]]\ngroup = \"plugdev\"\nreason = \"usb devices\"\n\
                     [[identity.groups.remove]]\ngroup = \"video\"\nreason = \"no gpu\"\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let groups = resolved
            .effective
            .identity
            .as_ref()
            .expect("identity")
            .groups
            .resolved()
            .to_vec();
        assert_eq!(groups, vec!["dialout".to_owned(), "plugdev".to_owned()]);
    }

    /// `[[consumes.add]]` composes demand-side down the chain, keyed by name.
    #[test]
    fn consumes_delta_extends_the_inherited_set() {
        let parent = "template_name = \"p\"\n[[consumes]]\nname = \"org.x.a\"\nshape = \"af-unix\"\nreason = \"a\"\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n[[consumes.add]]\nname = \"org.x.b\"\nshape = \"af-unix\"\nreason = \"b\"\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let resolved = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let names: Vec<&str> = resolved
            .effective
            .consumes
            .resolved()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["org.x.a", "org.x.b"]);
    }

    #[test]
    fn invariant_denies_union_across_the_chain() {
        let parent = "template_name = \"p\"\n[[net.proxy.deny.invariant]]\ncidr = \"10.0.0.0/8\"\nreason = \"rfc1918\"\n";
        let child = "template_name = \"c\"\ntemplate_base = \"p\"\n[[net.proxy.deny.invariant]]\ncidr = \"192.168.0.0/16\"\nreason = \"rfc1918\"\n";
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
        let entry = "name = \"n\"\ntemplate_base = \"absent\"\n";
        let err = resolve(&parse(entry.as_bytes()).expect("parse"), &MapSource::new())
            .expect_err("missing base must fail");
        assert!(matches!(err, PolicyError::Resolution(_)), "got {err}");
    }

    #[test]
    fn cycle_is_detected() {
        let a = "template_name = \"a\"\ntemplate_base = \"b\"\n";
        let b = "template_name = \"b\"\ntemplate_base = \"a\"\n";
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
        // Build a linear chain t0 -> t1 ->... -> t20 (deeper than MAX_CHAIN_DEPTH).
        let mut src = MapSource::new();
        let depth = MAX_CHAIN_DEPTH.saturating_add(4);
        for i in 0..=depth {
            let body = if i == depth {
                format!("template_name = \"t{i}\"\n")
            } else {
                let next = i.saturating_add(1);
                format!("template_name = \"t{i}\"\ntemplate_base = \"t{next}\"\n")
            };
            src = src.with(&format!("t{i}"), "v1", body.as_bytes());
        }
        let entry = "template_name = \"t0\"\ntemplate_base = \"t1\"\n";
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
        // A `template_base` is a bare name; an invalid name (disallowed chars) is rejected by
        // the entry's own validate before resolution walks it.
        let entry = "name = \"n\"\ntemplate_base = \"Bad Name\"\n";
        let err = parse(entry.as_bytes())
            .expect("parse")
            .validate()
            .expect_err("malformed ref must fail");
        assert!(matches!(err, PolicyError::SourceValidation(_)), "got {err}");
    }

    // ---- provides_origin: the reserved-namespace gate's signature provenance ----

    /// A well-formed `[[provides]]` body for a given name (resolve does not mesh-validate, but
    /// keeping it well-formed keeps these tests honest about what a real provider looks like).
    fn provides_block(name: &str) -> String {
        format!(
            "[[provides]]\nname = \"{name}\"\nshape = \"af-unix\"\nendpoint = \"e\"\nreason = \"r\"\n"
        )
    }

    #[test]
    fn provides_origin_is_entry_when_the_entry_declares_them() {
        // The most-derived artefact authored the provides — the template-authoring path.
        let parent = "template_name = \"p\"\n";
        let child = format!(
            "name = \"c\"\ntemplate_base = \"p\"\n{}",
            provides_block("org.projectkennel.wayland")
        );
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let r = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        assert_eq!(r.provides_origin, ProvidesOrigin::Entry);
    }

    #[test]
    fn provides_origin_is_unverified_ancestor_in_dev() {
        // An ancestor supplies the provides; dev mode verifies nothing → unverified.
        let parent = format!(
            "template_name = \"p\"\n{}",
            provides_block("doe.john.cache")
        );
        let child = "name = \"c\"\ntemplate_base = \"p\"\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let r = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        assert_eq!(r.provides_origin, ProvidesOrigin::Ancestor { tier: None });
    }

    #[test]
    fn provides_origin_is_verified_ancestor_when_the_supplier_is_signed_under_require() {
        use std::collections::BTreeSet;

        use crate::source_sig::sign_source;
        use kennel_lib_policy::keys::{KeySet, SigningKey};
        let key = SigningKey::from_seed("a-vendor-key", &[3u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");
        // Tag the key as vendor-tier (loaded from the vendor dir): any such key is equivalent.
        let vendor: BTreeSet<String> = std::iter::once(key.key_id().to_owned()).collect();
        let host = BTreeSet::new();
        let parent = parse(
            format!(
                "template_name = \"p\"\n{}",
                provides_block("org.projectkennel.wayland")
            )
            .as_bytes(),
        )
        .expect("parse parent");
        let signed = basic_toml::to_string(&sign_source(&parent, &key).expect("sign"))
            .expect("ser")
            .into_bytes();
        let src = MapSource::new().with("p", "v1", &signed);
        let child = parse(b"name = \"c\"\ntemplate_base = \"p\"\n").expect("parse child");
        let r = resolve_verified(
            &child,
            &src,
            &Trust::require(&ks).with_tiers(&vendor, &host),
        )
        .expect("resolve");
        assert_eq!(
            r.provides_origin,
            ProvidesOrigin::Ancestor {
                tier: Some(Tier::Vendor)
            }
        );
    }

    #[test]
    fn service_folds_scalar_wins_per_field() {
        // Parent sets restart + max_attempts; child overrides only backoff — the others inherit.
        let parent = "template_name = \"p\"\n[service]\nrestart = \"always\"\nmax_attempts = 9\n";
        let child = "name = \"c\"\ntemplate_base = \"p\"\n[service]\nbackoff = \"2s\"\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let r = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let svc = r.effective.service.expect("service");
        assert_eq!(svc.restart, Some(kennel_lib_policy::RestartPolicy::Always));
        assert_eq!(svc.max_attempts, Some(9));
        assert_eq!(svc.backoff.as_deref(), Some("2s"));
    }

    #[test]
    fn provides_origin_is_absent_without_any_provides() {
        let entry = parse(b"template_name = \"p\"\n").expect("parse");
        let r = resolve(&entry, &MapSource::new()).expect("resolve");
        assert_eq!(r.provides_origin, ProvidesOrigin::Absent);
    }

    /// W14: `[seccomp] deny` is a floor — a child's `deny` ADDS to the base, it does not replace
    /// it. A leaf writing a bare `deny = [...]` can only strengthen the inherited denylist.
    #[test]
    fn seccomp_deny_composes_additively_a_child_cannot_drop_a_base_deny() {
        let parent = "template_name = \"p\"\n[seccomp]\ndeny = [\"mount\", \"bpf\"]\n";
        // The child denies only `ptrace` — under the old scalar fold this would have dropped the
        // parent's mount/bpf hardening.
        let child = "name = \"c\"\ntemplate_base = \"p\"\n[seccomp]\ndeny = [\"ptrace\"]\n";
        let src = MapSource::new().with("p", "v1", parent.as_bytes());
        let r = resolve(&parse(child.as_bytes()).expect("parse"), &src).expect("resolve");
        let deny = r.effective.seccomp.expect("seccomp").deny.expect("deny");
        assert!(
            deny.contains(&"mount".to_owned()),
            "base deny kept: {deny:?}"
        );
        assert!(deny.contains(&"bpf".to_owned()), "base deny kept: {deny:?}");
        assert!(
            deny.contains(&"ptrace".to_owned()),
            "child deny added: {deny:?}"
        );
    }
}
