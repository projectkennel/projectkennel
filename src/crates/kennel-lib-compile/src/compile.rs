//! The compiler orchestrator: a source policy + its templates → a settled policy.
//!
//! # Purpose
//!
//! Ties the compile stages together (`02-2-config-schema.md` §The settled policy):
//! [`crate::resolve::resolve`] walks and folds the inheritance chain,
//! [`crate::translate::translate`] flattens the result into the runtime
//! `EffectivePolicy`, and [`compile`] assembles the [`SettledPolicy`] — name,
//! deferred substitutions, the asserted-invariant list, and the [`Provenance`]
//! block — then re-asserts the framework invariants the runtime will check again.
//! [`kennel_lib_policy::sign_settled`] signs the result; the CLI writes it to disk.
//!
//! # Integrity model
//!
//! Ed25519 signatures are the integrity control end to end. Each source template is
//! signature-verified at resolution against the trust store ([`crate::source_sig`],
//! threaded in as [`Trust`]); the settled policy is itself ed25519-signed over its
//! canonical body. A deterministic signature over canonical content *is* the content
//! commitment, so no separate content hash — and no `sha2` dependency — is needed
//! (the maintainer's call). `resolved_artifacts` records each verified artefact's
//! `signing_key_id` and `signature` (the commitment), never a hash.
//!
//! # Non-goals
//!
//! I/O-free: the caller supplies the [`TemplateSource`] and writes the output.

use crate::leaf::LeafPolicy;
use crate::lock::Lockfile;
use crate::resolve::{resolve_verified, ChainLink, ProvidesOrigin, TemplateSource};
use crate::source::SourcePolicy;
use crate::source_sig::Trust;
use crate::translate::{translate, Translated};
use kennel_lib_policy::settled::{
    Provenance, ResolvedArtifact, SettledPolicy, SignedSettledPolicy,
};
use kennel_lib_policy::signature::SignatureEnvelope;
use kennel_lib_policy::{PolicyError, SETTLED_SCHEMA_VERSION};

/// The framework-invariant IDs the compiler asserts, mirroring
/// [`kennel_lib_policy::invariant::validate`]. Recorded in the settled policy for audit; the
/// runtime re-asserts them regardless of this list.
pub const ASSERTED_INVARIANTS: &[&str] = &[
    "cap.no_new_privs",
    "exec.deny_setuid",
    "exec.deny_setgid",
    "exec.deny_setcap",
    "exec.deny_writable",
    "fs.home.shadow",
    "net.mode",
    "net.proxy.deny.invariant",
    "proc.visibility",
];

/// The `algorithm` marker used for a content-sealed but unsigned settled policy.
pub const UNSIGNED_ALGORITHM: &str = "none";

/// The output of a compile: the settled policy plus the lockfile.
///
/// The lockfile describes the source references that produced the policy. The caller
/// signs/writes the policy and checks/writes the lockfile against any prior `kennel.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    /// The settled policy.
    pub policy: SettledPolicy,
    /// The freshly-resolved lockfile (one entry per resolved reference).
    pub lock: Lockfile,
    /// Non-fatal warnings raised during compilation — footgun grants the policy is
    /// allowed to keep but should be loud about (e.g. shimming a real ssh-agent
    /// socket via `[[unix.allow]]`). The caller surfaces these (the `kennel compile`
    /// CLI prints them to stderr); they are not part of the signed artefact.
    pub warnings: Vec<String>,
}

/// Resolve, translate, and assemble `entry` into a settled policy.
///
/// `entry` is the most-derived source artefact (a leaf or a template); `source`
/// supplies its ancestors; `compiler_version` is recorded in provenance. All
/// placeholders (including `<tag>`/`<gid>`) are deferred to spawn — the compiler
/// never needs the installation's tag/gid.
///
/// # Errors
///
/// Propagates [`PolicyError`] from resolution, translation, or the framework-invariant
/// re-assertion the compiler performs on its own output.
pub fn compile(
    entry: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
    compiler_version: &str,
) -> Result<Compiled, PolicyError> {
    let resolved = resolve_verified(entry, source, trust)?;
    let provides_origin = resolved.provides_origin;
    let mut effective = resolved.effective;
    let name = effective
        .name
        .clone()
        .or_else(|| effective.template_name.clone())
        .ok_or_else(|| {
            PolicyError::Translation("policy has neither `name` nor `template_name`".to_owned())
        })?;
    // Apply included fragments additively (chain → includes), then translate.
    let mut chain = resolved.chain;
    let include_refs = effective.include.clone();
    let include_links = apply_includes(&mut effective, &include_refs, source, trust)?;
    chain.extend(include_links);

    let tcv = effective
        .threat_catalogue_version
        .clone()
        .unwrap_or_default();
    // The `[ssh]` section is source-only (dropped in translate); validate it here,
    // on the resolved policy, while the cross-referenced `net.proxy.allow` is still visible.
    crate::ssh::validate(&effective)?;
    let mut warnings = crate::unix::validate(&effective)?;
    warnings.extend(crate::binder::validate(&effective)?);
    warnings.extend(crate::mesh::validate(
        &effective,
        &reserved_authority(provides_origin, trust),
    )?);
    crate::dev::validate(&effective)?;
    crate::identity::validate(&effective)?;
    let spawn_grant = crate::spawn::resolve_grant(&effective, source, trust)?;
    let translated = translate(&effective)?;
    warnings.extend(translated.effective_policy.exec.deny_warnings());
    warnings.extend(unenforced_section_warnings(&effective));
    warnings.extend(spawn_manifest_warnings(&effective));
    assemble(
        name,
        &translated,
        &chain,
        &tcv,
        compiler_version,
        warnings,
        spawn_grant,
    )
}

/// The tier-aware reserved-namespace authority for this resolved policy (§7.13.5).
///
/// The reserved namespace is tier-trust material: `org.projectkennel.*` is claimable only through a
/// vendor-tier (maintainer) template, a host `[[reserved]]` name only through a host-tier one — and
/// **any** key at the required tier is equivalent. This is the *sole* authorizer: there is no runtime
/// re-check (the daemon trusts the settled signature it verifies). The declaring tier is the verified
/// tier of the ancestor template that supplied the provides (ancestor-origin), or the output `--key`'s
/// tier when the leaf authored them itself (entry-origin); `None` (unverified / no signer) claims
/// nothing reserved. With no trust store (development authoring) the gate does not enforce.
fn reserved_authority<'a>(
    origin: ProvidesOrigin,
    trust: &Trust<'a>,
) -> crate::mesh::ReservedAuthority<'a> {
    // An *entry-origin* reserved provide's authority is the output signer's tier — unknown when no
    // output signer is set (inspection: `kennel policy validate`/`risks`, or an unsigned dev build).
    // There we do not enforce: the tier check is the act of compiling *with* a key to produce the
    // signed artefact. An ancestor-origin provide is always checkable (its tier comes from resolution).
    let entry_unsigned = matches!(origin, ProvidesOrigin::Entry) && trust.signing_tier().is_none();
    crate::mesh::ReservedAuthority {
        enforce: trust.keys().is_some() && !entry_unsigned,
        declaring_tier: match origin {
            ProvidesOrigin::Ancestor { tier } => tier,
            ProvidesOrigin::Entry => trust.signing_tier(),
            ProvidesOrigin::Absent => None,
        },
        reserved: trust.reserved(),
    }
}

/// Resolve, apply a leaf's deltas, translate, and assemble a settled policy.
///
/// A leaf policy is the delta form (`[[fs.read.add]]`, …); its chain is resolved
/// from `template_base`, the deltas are applied to the folded effective policy
/// (`+=`/`-=`), and the result is translated and assembled as for a template.
///
/// # Errors
///
/// Propagates [`PolicyError`] from validation, resolution, translation, or the
/// framework-invariant re-assertion.
pub fn compile_leaf(
    leaf: &LeafPolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
    compiler_version: &str,
) -> Result<Compiled, PolicyError> {
    leaf.validate()?;
    let base = leaf
        .template_base
        .clone()
        .ok_or_else(|| PolicyError::Resolution("leaf policy has no `template_base`".to_owned()))?;
    let name = leaf
        .name
        .clone()
        .ok_or_else(|| PolicyError::Translation("leaf policy has no `name`".to_owned()))?;

    // Resolve the parent chain via a stub that carries only the leaf's base.
    let stub = SourcePolicy {
        template_base: Some(base),
        template_name: Some("<leaf>".to_owned()),
        ..SourcePolicy::default()
    };
    let resolved = resolve_verified(&stub, source, trust)?;
    let provides_origin = resolved.provides_origin;
    let mut effective = resolved.effective;

    // Resolution order (02-2 §Includes): chain → includes (chain's + leaf's, in
    // listed order) → the leaf's own deltas.
    let mut chain = resolved.chain;
    let mut include_refs = effective.include.clone();
    include_refs.extend(leaf.include.iter().cloned());
    let include_links = apply_includes(&mut effective, &include_refs, source, trust)?;
    chain.extend(include_links);

    leaf.apply(&mut effective);

    let tcv = leaf
        .threat_catalogue_version
        .clone()
        .or_else(|| effective.threat_catalogue_version.clone())
        .unwrap_or_default();
    crate::ssh::validate(&effective)?;
    let mut warnings = crate::unix::validate(&effective)?;
    warnings.extend(crate::binder::validate(&effective)?);
    warnings.extend(crate::mesh::validate(
        &effective,
        &reserved_authority(provides_origin, trust),
    )?);
    crate::dev::validate(&effective)?;
    crate::identity::validate(&effective)?;
    let spawn_grant = crate::spawn::resolve_grant(&effective, source, trust)?;
    let translated = translate(&effective)?;
    warnings.extend(translated.effective_policy.exec.deny_warnings());
    warnings.extend(unenforced_section_warnings(&effective));
    warnings.extend(spawn_manifest_warnings(&effective));
    assemble(
        name,
        &translated,
        &chain,
        &tcv,
        compiler_version,
        warnings,
        spawn_grant,
    )
}

/// Resolve a policy's folded **effective source**, stopping *before* translation
/// so the threat tags survive.
///
/// The fold is the inheritance chain, its included fragments, and (for a leaf) its
/// `+=`/`-=` deltas applied.
///
/// This is the honest input for the [risk](crate::risks) and [diff](crate::diff)
/// engines: threat tags live only in source, never the settled artefact. It
/// accepts either policy form — a template/source document or a delta-leaf —
/// mirroring [`compile`]/[`compile_leaf`] exactly up to the translate step, so
/// the engines see the same folded grants the compiler enforces.
///
/// # Errors
///
/// Propagates [`PolicyError`] from parsing, signature verification, chain
/// resolution, include composition, or leaf validation.
pub fn effective_source(
    bytes: &[u8],
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<SourcePolicy, PolicyError> {
    match crate::source::parse(bytes) {
        Ok(entry) => {
            let mut effective = resolve_verified(&entry, source, trust)?.effective;
            let include_refs = effective.include.clone();
            apply_includes(&mut effective, &include_refs, source, trust)?;
            Ok(effective)
        }
        // Not a source document — try the delta-leaf form (mirrors `build_settled`).
        Err(source_err) => {
            let leaf = crate::leaf::parse(bytes).map_err(|_| source_err)?;
            leaf.validate()?;
            let base = leaf.template_base.clone().ok_or_else(|| {
                PolicyError::Resolution("leaf policy has no `template_base`".to_owned())
            })?;
            let stub = SourcePolicy {
                template_base: Some(base),
                template_name: Some("<leaf>".to_owned()),
                ..SourcePolicy::default()
            };
            let mut effective = resolve_verified(&stub, source, trust)?.effective;
            let mut include_refs = effective.include.clone();
            include_refs.extend(leaf.include.iter().cloned());
            apply_includes(&mut effective, &include_refs, source, trust)?;
            leaf.apply(&mut effective);
            Ok(effective)
        }
    }
}

/// Warn about policy sections that parse but whose effect comes from elsewhere, so an author
/// does not believe the section itself imposes a control. Unbuilt *features* (`[container]`,
/// `[dbus]`, `[x11]`, `[fs.scrub]`, `[[fs.home.sanitise]]`) are no longer accepted at all — they
/// are rejected at parse by `deny_unknown_fields`, not warned — to keep assumptions off unbuilt
/// code. What remains here are the *informational* sections whose scoping is real but enforced by
/// another mechanism (the PID namespace + seccomp), not by the section. One message per present
/// section (warn, don't refuse — `footgun-warn-dont-forbid`).
fn unenforced_section_warnings(effective: &SourcePolicy) -> Vec<String> {
    let u = effective.unsafe_section.as_ref();
    [
        (
            u.is_some_and(|u| u.ptrace.is_some()),
            "[unsafe.ptrace]",
            "ptrace scoping comes from the PID namespace + seccomp, not this section",
        ),
        (
            u.is_some_and(|u| u.signal.is_some()),
            "[unsafe.signal]",
            "signal scoping comes from the PID namespace, not this section",
        ),
    ]
    .into_iter()
    .filter(|(present, _, _)| *present)
    .map(|(_, section, what)| {
        format!(
            "{section} is declared but NOT enforced by the runtime ({what}) — it is dropped at \
             compile and has no effect"
        )
    })
    .collect()
}

/// Warn loudly about each `freeform` variant in a spawn-target template's `[[mutable]]` manifest
/// (§7.12.3). Freeform is the open footgun — any value the agent supplies is accepted — so it is
/// warned at compile (warn, never forbid — `footgun-warn-dont-forbid`); the mandatory `reason` is
/// surfaced so the operator sees what they signed off.
fn spawn_manifest_warnings(effective: &SourcePolicy) -> Vec<String> {
    effective
        .mutable
        .iter()
        .filter(|m| m.freeform == Some(true))
        .map(|m| {
            let field = m.field.as_deref().unwrap_or("?");
            let reason = m.reason.as_deref().unwrap_or("");
            format!(
                "[[mutable]] field = \"{field}\" is FREEFORM — a spawn may write any value to it, \
                 the loudest mutable surface (reason: {reason}). Prefer a closed (oneof/pool) or \
                 shaped (pattern) constraint unless nothing narrower can express the need."
            )
        })
        .collect()
}

/// Resolve and apply included fragments additively, in listed order.
///
/// A fragment is a signed, version-pinned, **additive-only** policy piece (`02-2`
/// §Includes): it may add rules but not remove or override. Fragments are applied
/// after the inheritance chain and before the leaf's own deltas. Two fragments that
/// add a conflicting `[[net.proxy.allow]]` for the same host (different ports/protocol) are
/// an [`PolicyError::IncludeConflict`] — resolution is not last-wins. Returns the
/// resolved fragments as chain links for the lockfile.
///
/// Scope: fragment-declared **invariants** (`[[net.proxy.deny.invariant]]` inside a
/// fragment) are not yet honoured; fragment signatures, however, are verified
/// against `trust` exactly like template ancestors.
fn apply_includes(
    effective: &mut SourcePolicy,
    includes: &[String],
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<Vec<ChainLink>, PolicyError> {
    use crate::resolve::split_reference;

    let mut links = Vec::new();
    let mut seen_net: Vec<crate::source::NetAllow> = Vec::new();
    for reference in includes {
        let (name, version) = split_reference(reference)?;
        let bytes = source.fetch(&name, &version).ok_or_else(|| {
            PolicyError::Resolution(format!(
                "include `{name}@{version}` not found in the search path"
            ))
        })?;
        let fragment = crate::leaf::parse(&bytes)?;

        if !fragment.is_additive_only() {
            return Err(PolicyError::SourceValidation(vec![format!(
                "fragment `{name}` uses a `.remove` delta; includes are additive-only"
            )]));
        }
        if let Some(tb) = &fragment.template_base {
            if !tb.starts_with("base-confined@") {
                return Err(PolicyError::Resolution(format!(
                    "fragment `{name}` derives from `{tb}`; a fragment may only extend base-confined"
                )));
            }
        }
        // Verify the fragment's signature against the trust store (refuses an
        // unsigned/unverifiable fragment under --require-signed).
        let signing_key_id = trust.check(&name, &fragment)?;

        // Conflict check: a host added by two fragments with differing rules.
        for entry in fragment.net_allow_adds() {
            let key = crate::leaf::net_key(entry);
            if let Some(prev) = seen_net.iter().find(|e| crate::leaf::net_key(e) == key) {
                if prev != entry {
                    return Err(PolicyError::IncludeConflict(format!(
                        "two includes add conflicting rules for `{key}`; reconcile them in the leaf"
                    )));
                }
            } else {
                seen_net.push(entry.clone());
            }
        }

        fragment.apply(effective);
        // Union the fragment's invariant denies into the effective policy (additive;
        // invariants are non-removable, so a fragment can only add to them).
        let invariants = fragment.invariant_denies();
        if !invariants.is_empty() {
            let net = effective.net.get_or_insert_with(Default::default);
            let proxy = net.proxy.get_or_insert_with(Default::default);
            let deny = proxy.deny.get_or_insert_with(Default::default);
            for rule in invariants {
                if !deny.invariant.iter().any(|e| e.cidr == rule.cidr) {
                    deny.invariant.push(rule.clone());
                }
            }
        }
        links.push(ChainLink {
            name,
            version,
            signing_key_id,
            signature: fragment.signature.as_ref().map(|e| e.signature.clone()),
        });
    }
    Ok(links)
}

/// Assemble a [`SettledPolicy`] from a translated effective policy and provenance
/// inputs, then re-assert the framework invariants on the result.
fn assemble(
    name: String,
    translated: &Translated,
    chain: &[ChainLink],
    threat_catalogue_version: &str,
    compiler_version: &str,
    warnings: Vec<String>,
    spawn: Option<kennel_lib_policy::SpawnGrant>,
) -> Result<Compiled, PolicyError> {
    let resolved_artifacts = chain
        .iter()
        .map(|link| ResolvedArtifact {
            name: link.name.clone(),
            version: link.version.clone(),
            signing_key_id: link.signing_key_id.clone().unwrap_or_default(),
            // Integrity is the ed25519 signature verified at resolution — a deterministic signature
            // over canonical content is itself the commitment, so no separate content hash (no sha2).
            signature: link.signature.clone().unwrap_or_default(),
        })
        .collect();

    let policy = SettledPolicy {
        settled_schema_version: SETTLED_SCHEMA_VERSION,
        name,
        deferred_substitutions: translated.deferred_substitutions.clone(),
        framework_invariants_asserted: ASSERTED_INVARIANTS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        effective_policy: translated.effective_policy.clone(),
        ssh: translated.ssh.clone(),
        unix: translated.unix.clone(),
        identity: translated.identity.clone(),
        binder: translated.binder.clone(),
        mesh: translated.mesh.clone(),
        service: translated.service,
        dbus: translated.dbus.clone(),
        audit: translated.audit.clone(),
        env: translated.env.clone(),
        ulimits: translated.ulimits.clone(),
        workload: translated.workload.clone(),
        rootfs: translated.rootfs.clone(),
        spawn,
        manifest: translated.manifest.clone(),
        provenance: Provenance {
            compiler_version: compiler_version.to_owned(),
            schema_version: SETTLED_SCHEMA_VERSION,
            threat_catalogue_version: threat_catalogue_version.to_owned(),
            resolved_artifacts,
        },
    };

    // Defence in depth: assert now what the runtime will re-assert at spawn.
    kennel_lib_policy::invariant::validate(&policy).map_err(PolicyError::InvariantViolations)?;
    Ok(Compiled {
        policy,
        lock: Lockfile::from_chain(chain),
        warnings,
    })
}

/// Seal a settled policy without a signature (development use only).
///
/// The bytes are content-complete but carry an `algorithm = "none"` envelope; the
/// runtime accepts such a policy only in development mode (a later increment),
/// never in an attested deployment.
#[must_use]
pub fn seal_unsigned(policy: &SettledPolicy) -> SignedSettledPolicy {
    SignedSettledPolicy {
        signature: SignatureEnvelope {
            algorithm: UNSIGNED_ALGORITHM.to_owned(),
            key_id: String::new(),
            signature: String::new(),
            signed_fields: Vec::new(),
        },
        policy: policy.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse;
    use kennel_lib_policy::keys::{KeySet, SigningKey};
    use kennel_lib_policy::{sign_settled, to_bytes, verify_settled};

    const BASE_CONFINED: &str = include_str!("../../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../templates/ai-coding-strict/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(n, v, _)| n == name && v == version)
                .map(|(_, _, b)| b.clone())
        }
    }
    fn src() -> MapSource {
        let mut entries = vec![(
            "base-confined".to_owned(),
            "v1".to_owned(),
            BASE_CONFINED.as_bytes().to_vec(),
        )];
        for (name, body) in crate::TEST_FRAGMENTS {
            entries.push((
                (*name).to_owned(),
                "v1".to_owned(),
                body.as_bytes().to_vec(),
            ));
        }
        MapSource(entries)
    }
    fn compile_ai() -> SettledPolicy {
        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        compile(&entry, &src(), &Trust::dev(), "test-0.0.0")
            .expect("compile")
            .policy
    }

    #[test]
    fn informational_sections_warn_as_unenforced() {
        use crate::source::{BoundaryAcl, SourcePolicy, UnsafeSection};
        // The unbuilt *features* ([dbus]/[x11]/[container]/[fs.scrub]/[[fs.home.sanitise]]) are
        // gone from the schema (rejected at parse). What warns here are the `[unsafe.*]`
        // sub-sections whose scoping is enforced elsewhere (PID namespace + seccomp).
        let sp = SourcePolicy {
            unsafe_section: Some(UnsafeSection {
                ptrace: Some(BoundaryAcl::default()),
                signal: Some(BoundaryAcl::default()),
            }),
            ..SourcePolicy::default()
        };
        let w = unenforced_section_warnings(&sp);
        assert_eq!(w.len(), 2, "one warning per [unsafe.*] sub-section: {w:?}");
        assert!(w
            .iter()
            .any(|s| s.contains("[unsafe.ptrace]") && s.contains("NOT enforced")));
        assert!(w.iter().any(|s| s.contains("[unsafe.signal]")));
        // A clean policy warns about none of this.
        assert!(unenforced_section_warnings(&SourcePolicy::default()).is_empty());
    }

    #[test]
    fn compiles_a_template_into_a_settled_policy() {
        let p = compile_ai();
        assert_eq!(
            p.settled_schema_version,
            kennel_lib_policy::SETTLED_SCHEMA_VERSION
        );
        assert_eq!(p.name, "ai-coding-strict");
        assert_eq!(p.provenance.compiler_version, "test-0.0.0");
        assert!(p
            .provenance
            .resolved_artifacts
            .iter()
            .any(|a| a.name == "base-confined" && a.version == "v1"));
        assert!(p
            .framework_invariants_asserted
            .iter()
            .any(|i| i == "cap.no_new_privs"));
    }

    #[test]
    fn compiled_policy_signs_and_verifies_end_to_end() {
        let policy = compile_ai();
        let key = SigningKey::from_seed("kennel-maint-test", &[9u8; 32]).expect("key");
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");

        let mut keys = KeySet::new();
        keys.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");
        let verified = verify_settled(&bytes, &keys).expect("verify");
        assert_eq!(verified.name, "ai-coding-strict");
    }

    #[test]
    fn require_mode_compiles_with_a_signed_ancestor_and_records_the_key_id() {
        use crate::source_sig::sign_source;
        let key = SigningKey::from_seed("kennel-maint-2026", &[3u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");
        // Sign base-confined and serve the signed bytes.
        let signed =
            sign_source(&parse(BASE_CONFINED.as_bytes()).expect("parse"), &key).expect("sign");
        let signed_bytes = basic_toml::to_string(&signed)
            .expect("serialise")
            .into_bytes();
        let source = MapSource(vec![(
            "base-confined".to_owned(),
            "v1".to_owned(),
            signed_bytes,
        )]);

        // A minimal template deriving the signed ancestor (no catalogue includes — this test is about
        // the signed-ancestor provenance/lockfile flow, not a specific template's content).
        let entry = parse(b"template_name = \"min\"\ntemplate_base = \"base-confined@v1\"\n")
            .expect("parse");
        let compiled = compile(&entry, &source, &Trust::require(&ks), "v")
            .expect("compile with signed ancestor");
        assert!(
            compiled
                .policy
                .provenance
                .resolved_artifacts
                .iter()
                .any(|a| a.signing_key_id == "kennel-maint-2026"),
            "the verified signing key is recorded in provenance"
        );
        // The lockfile pins the signed ancestor with its signature.
        let locked = compiled
            .lock
            .entries
            .iter()
            .find(|e| e.name == "base-confined")
            .expect("locked");
        assert_eq!(locked.signing_key_id, "kennel-maint-2026");
        assert!(
            !locked.signature.is_empty(),
            "the signature commitment is recorded"
        );
    }

    #[test]
    fn require_mode_refuses_an_unsigned_ancestor() {
        // `src()` serves the unsigned in-tree base-confined.
        let ks = KeySet::new();
        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        assert!(
            compile(&entry, &src(), &Trust::require(&ks), "v").is_err(),
            "an unsigned ancestor is refused when signatures are required"
        );
    }

    fn source_with_fragments(frags: &[(&str, &str)]) -> MapSource {
        let mut v = vec![
            (
                "base-confined".to_owned(),
                "v1".to_owned(),
                BASE_CONFINED.as_bytes().to_vec(),
            ),
            (
                "ai-coding-strict".to_owned(),
                "v1".to_owned(),
                AI_CODING_STRICT.as_bytes().to_vec(),
            ),
        ];
        // ai-coding-strict composes the catalogue fragments, so serve them too.
        for (name, body) in crate::TEST_FRAGMENTS {
            v.push((
                (*name).to_owned(),
                "v1".to_owned(),
                body.as_bytes().to_vec(),
            ));
        }
        for (name, body) in frags {
            v.push((
                (*name).to_owned(),
                "v1".to_owned(),
                body.as_bytes().to_vec(),
            ));
        }
        MapSource(v)
    }

    #[test]
    fn includes_apply_additively_and_are_lock_pinned() {
        let frag = "name = \"corp-egress\"\n[[net.proxy.allow.add]]\nname = \"proxy.corp.example\"\nports = [443]\nreason = \"corp egress proxy\"\n";
        let source = source_with_fragments(&[("corp-egress", frag)]);
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\ninclude = [\"corp-egress@v1\"]\n",
        )
        .expect("parse leaf");
        let compiled = compile_leaf(&leaf, &source, &Trust::dev(), "v").expect("compile");
        let names = &compiled.policy.effective_policy.net.allow_names;
        assert!(
            names.iter().any(|n| n.name == "proxy.corp.example"),
            "fragment host added"
        );
        assert!(
            names.iter().any(|n| n.name == "github.com"),
            "inherited host kept"
        );
        assert!(
            compiled
                .lock
                .entries
                .iter()
                .any(|e| e.name == "corp-egress"),
            "include lock-pinned"
        );
    }

    #[test]
    fn conflicting_includes_are_rejected() {
        let f1 = "name = \"a\"\n[[net.proxy.allow.add]]\nname = \"proxy.corp\"\nports = [443]\nreason = \"r\"\n";
        let f2 = "name = \"b\"\n[[net.proxy.allow.add]]\nname = \"proxy.corp\"\nports = [8443]\nreason = \"r\"\n";
        let source = source_with_fragments(&[("frag-a", f1), ("frag-b", f2)]);
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\ninclude = [\"frag-a@v1\", \"frag-b@v1\"]\n",
        )
        .expect("parse leaf");
        let err = compile_leaf(&leaf, &source, &Trust::dev(), "v").expect_err("conflict");
        assert!(matches!(err, PolicyError::IncludeConflict(_)), "got {err}");
    }

    #[test]
    fn a_fragment_can_contribute_an_invariant_deny() {
        let frag = "name = \"corp-deny\"\n[[net.proxy.deny.invariant]]\ncidr = \"203.0.113.0/24\"\nreason = \"corp blocklist\"\n";
        let source = source_with_fragments(&[("corp-deny", frag)]);
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\ninclude = [\"corp-deny@v1\"]\n",
        )
        .expect("parse leaf");
        let compiled = compile_leaf(&leaf, &source, &Trust::dev(), "v").expect("compile");
        let denies = &compiled.policy.effective_policy.net.deny_invariant;
        assert!(
            denies
                .iter()
                .any(|r| r.cidr == "203.0.113.0" && r.prefix_len == 24),
            "fragment invariant added"
        );
        assert!(
            denies.iter().any(|r| r.cidr == "169.254.169.254"),
            "base invariants still present"
        );
    }

    #[test]
    fn a_leaf_may_not_declare_an_invariant_deny() {
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\n[[net.proxy.deny.invariant]]\ncidr = \"10.0.0.0/8\"\nreason = \"r\"\n",
        )
        .expect("parse leaf");
        let err = leaf
            .validate()
            .expect_err("leaf invariant must be rejected");
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms.iter().any(|m| m.contains("invariant")));
        }
    }

    #[test]
    fn a_remove_in_a_fragment_is_rejected() {
        let frag =
            "name = \"bad\"\n[[net.proxy.allow.remove]]\nname = \"github.com\"\nreason = \"r\"\n";
        let source = source_with_fragments(&[("bad-frag", frag)]);
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\ninclude = [\"bad-frag@v1\"]\n",
        )
        .expect("parse leaf");
        assert!(
            compile_leaf(&leaf, &source, &Trust::dev(), "v").is_err(),
            "an additive-only fragment cannot remove"
        );
    }

    #[test]
    fn unsigned_include_is_refused_under_require_signed() {
        let frag = "name = \"corp-egress\"\n[[net.proxy.allow.add]]\nname = \"x.corp\"\nports = [443]\nreason = \"r\"\n";
        let source = source_with_fragments(&[("corp-egress", frag)]);
        let ks = KeySet::new();
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"ai-coding-strict@v1\"\ninclude = [\"corp-egress@v1\"]\n",
        )
        .expect("parse leaf");
        // An unsigned fragment must not be silently trusted when signatures are required.
        assert!(compile_leaf(&leaf, &source, &Trust::require(&ks), "v").is_err());
    }

    #[test]
    fn signed_include_verifies_and_is_lock_pinned_under_require_signed() {
        use crate::source_sig::{sign_leaf, sign_source};
        let key = SigningKey::from_seed("kennel-maint-2026", &[3u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");

        // Sign the chain (base-confined, ai-coding-strict) and the fragment.
        let to_bytes = |p: &crate::source::SourcePolicy| {
            basic_toml::to_string(&sign_source(p, &key).expect("sign"))
                .expect("ser")
                .into_bytes()
        };
        let frag = crate::leaf::parse(
            b"name = \"corp-egress\"\n[[net.proxy.allow.add]]\nname = \"proxy.corp\"\nports = [443]\nreason = \"r\"\n",
        )
        .expect("parse fragment");
        let signed_frag = basic_toml::to_string(&sign_leaf(&frag, &key).expect("sign"))
            .expect("ser")
            .into_bytes();
        let source = MapSource(vec![
            (
                "base-confined".to_owned(),
                "v1".to_owned(),
                to_bytes(&parse(BASE_CONFINED.as_bytes()).expect("p")),
            ),
            ("corp-egress".to_owned(), "v1".to_owned(), signed_frag),
        ]);
        // Derive the signed ancestor directly and include the signed fragment — this test is about a
        // signed include verifying and lock-pinning under require, not a specific template's content.
        let leaf = crate::leaf::parse(
            b"name = \"p\"\ntemplate_base = \"base-confined@v1\"\ninclude = [\"corp-egress@v1\"]\n",
        )
        .expect("parse leaf");
        let compiled = compile_leaf(&leaf, &source, &Trust::require(&ks), "v")
            .expect("signed chain + signed fragment verifies under require");
        assert!(compiled
            .policy
            .effective_policy
            .net
            .allow_names
            .iter()
            .any(|n| n.name == "proxy.corp"));
        let locked = compiled
            .lock
            .entries
            .iter()
            .find(|e| e.name == "corp-egress")
            .expect("locked");
        assert_eq!(
            locked.signing_key_id, "kennel-maint-2026",
            "fragment key recorded in the lock"
        );
    }

    #[test]
    fn unsigned_seal_round_trips_to_bytes() {
        let policy = compile_ai();
        let doc = seal_unsigned(&policy);
        assert_eq!(doc.signature.algorithm, "none");
        let bytes = to_bytes(&doc).expect("serialise");
        assert!(!bytes.is_empty());
        // It parses back as a document, but verify_settled rejects the "none" alg.
        let keys = KeySet::new();
        assert!(
            verify_settled(&bytes, &keys).is_err(),
            "unsigned is not verifiable"
        );
    }
}
