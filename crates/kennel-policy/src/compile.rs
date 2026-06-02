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
//! [`crate::sign_settled`] signs the result; the CLI writes it to disk.
//!
//! # Integrity model
//!
//! Ed25519 signatures are the integrity control end to end. Each source template is
//! signature-verified at resolution against the trust store ([`crate::source_sig`],
//! threaded in as [`Trust`]); the settled policy is itself ed25519-signed over its
//! canonical body. A deterministic signature over canonical content *is* the content
//! commitment, so no separate content hash — and no `sha2` dependency — is needed
//! (the maintainer's call). `resolved_artifacts` records each verified
//! `signing_key_id`; the `*_sha256` fields stay empty pending the lockfile increment,
//! which will record the signature commitment rather than a hash.
//!
//! # Non-goals
//!
//! I/O-free: the caller supplies the [`TemplateSource`] and writes the output.

use crate::leaf::LeafPolicy;
use crate::resolve::{resolve_verified, ChainLink, TemplateSource};
use crate::settled::{InstallConstants, Provenance, ResolvedArtifact, SettledPolicy, SignedSettledPolicy};
use crate::signature::SignatureEnvelope;
use crate::source::SourcePolicy;
use crate::source_sig::Trust;
use crate::translate::{translate, Translated};
use crate::{PolicyError, SETTLED_SCHEMA_VERSION};

/// The framework-invariant IDs the compiler asserts, mirroring
/// [`crate::invariant::validate`]. Recorded in the settled policy for audit; the
/// runtime re-asserts them regardless of this list.
pub const ASSERTED_INVARIANTS: &[&str] = &[
    "cap.no_new_privs",
    "exec.deny_setuid",
    "exec.deny_setgid",
    "exec.deny_setcap",
    "exec.deny_writable",
    "fs.home.shadow",
    "fs.home.shim_root",
    "net.mode",
    "net.deny.invariant",
    "proc.visibility",
];

/// The `algorithm` marker used for a content-sealed but unsigned settled policy.
pub const UNSIGNED_ALGORITHM: &str = "none";

/// Resolve, translate, and assemble `entry` into a settled policy.
///
/// `entry` is the most-derived source artefact (a leaf or a template); `source`
/// supplies its ancestors; `install` carries the installation constants substituted
/// at compile time; `compiler_version` is recorded in provenance.
///
/// # Errors
///
/// Propagates [`PolicyError`] from resolution, translation, or the framework-invariant
/// re-assertion the compiler performs on its own output.
pub fn compile(
    entry: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
    install: &InstallConstants,
    compiler_version: &str,
) -> Result<SettledPolicy, PolicyError> {
    let resolved = resolve_verified(entry, source, trust)?;
    let translated = translate(&resolved.effective, install)?;
    let name = resolved
        .effective
        .name
        .clone()
        .or_else(|| resolved.effective.template_name.clone())
        .ok_or_else(|| {
            PolicyError::Translation("policy has neither `name` nor `template_name`".to_owned())
        })?;
    let tcv = resolved.effective.threat_catalogue_version.clone().unwrap_or_default();
    assemble(name, &translated, &resolved.chain, &tcv, install, compiler_version)
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
    install: &InstallConstants,
    compiler_version: &str,
) -> Result<SettledPolicy, PolicyError> {
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
    let mut effective = resolved.effective;
    leaf.apply(&mut effective);

    let tcv = leaf
        .threat_catalogue_version
        .clone()
        .or_else(|| effective.threat_catalogue_version.clone())
        .unwrap_or_default();
    let translated = translate(&effective, install)?;
    assemble(name, &translated, &resolved.chain, &tcv, install, compiler_version)
}

/// Assemble a [`SettledPolicy`] from a translated effective policy and provenance
/// inputs, then re-assert the framework invariants on the result.
fn assemble(
    name: String,
    translated: &Translated,
    chain: &[ChainLink],
    threat_catalogue_version: &str,
    install: &InstallConstants,
    compiler_version: &str,
) -> Result<SettledPolicy, PolicyError> {
    let resolved_artifacts = chain
        .iter()
        .map(|link| ResolvedArtifact {
            name: link.name.clone(),
            version: link.version.clone(),
            // Integrity is the ed25519 signature verified at resolution (no separate
            // content hash, hence no sha2 dependency); `content_sha256` stays empty
            // pending the lockfile increment that records the signature commitment.
            content_sha256: String::new(),
            signing_key_id: link.signing_key_id.clone().unwrap_or_default(),
        })
        .collect();

    let policy = SettledPolicy {
        settled_schema_version: SETTLED_SCHEMA_VERSION,
        name,
        deferred_substitutions: translated.deferred_substitutions.clone(),
        framework_invariants_asserted: ASSERTED_INVARIANTS.iter().map(|s| (*s).to_owned()).collect(),
        effective_policy: translated.effective_policy.clone(),
        provenance: Provenance {
            compiler_version: compiler_version.to_owned(),
            schema_version: SETTLED_SCHEMA_VERSION,
            threat_catalogue_version: threat_catalogue_version.to_owned(),
            leaf_policy_sha256: String::new(),
            invariant_set_sha256: String::new(),
            install_constants: install.clone(),
            resolved_artifacts,
        },
    };

    // Defence in depth: assert now what the runtime will re-assert at spawn.
    crate::invariant::validate(&policy).map_err(PolicyError::InvariantViolations)?;
    Ok(policy)
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
    use crate::keys::{KeySet, SigningKey};
    use crate::source::parse;
    use crate::{sign_settled, to_bytes, verify_settled};

    const BASE_CONFINED: &str = include_str!("../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str = include_str!("../../../templates/ai-coding-strict/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0.iter().find(|(n, v, _)| n == name && v == version).map(|(_, _, b)| b.clone())
        }
    }
    fn src() -> MapSource {
        MapSource(vec![("base-confined".to_owned(), "v1".to_owned(), BASE_CONFINED.as_bytes().to_vec())])
    }
    fn install() -> InstallConstants {
        InstallConstants { tag: 42, ula_gid: "fd00:abcd::".to_owned() }
    }

    fn compile_ai() -> SettledPolicy {
        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        compile(&entry, &src(), &Trust::dev(), &install(), "test-0.0.0").expect("compile")
    }

    #[test]
    fn compiles_a_template_into_a_settled_policy() {
        let p = compile_ai();
        assert_eq!(p.settled_schema_version, 1);
        assert_eq!(p.name, "ai-coding-strict");
        assert_eq!(p.provenance.compiler_version, "test-0.0.0");
        assert_eq!(p.provenance.install_constants.tag, 42);
        assert!(p.provenance.resolved_artifacts.iter().any(|a| a.name == "base-confined" && a.version == "v1"));
        assert!(p.framework_invariants_asserted.iter().any(|i| i == "cap.no_new_privs"));
        assert!(p.deferred_substitutions.iter().any(|d| d == "<kennel>"));
    }

    #[test]
    fn compiled_policy_signs_and_verifies_end_to_end() {
        let policy = compile_ai();
        let key = SigningKey::from_seed("kennel-maint-test", &[9u8; 32]).expect("key");
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");

        let mut keys = KeySet::new();
        keys.insert(key.key_id(), &key.public_key_bytes()).expect("insert");
        let verified = verify_settled(&bytes, &keys).expect("verify");
        assert_eq!(verified.name, "ai-coding-strict");
    }

    #[test]
    fn require_mode_compiles_with_a_signed_ancestor_and_records_the_key_id() {
        use crate::source_sig::sign_source;
        let key = SigningKey::from_seed("kennel-maint-2026", &[3u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes()).expect("insert");
        // Sign base-confined and serve the signed bytes.
        let signed = sign_source(&parse(BASE_CONFINED.as_bytes()).expect("parse"), &key).expect("sign");
        let signed_bytes = basic_toml::to_string(&signed).expect("serialise").into_bytes();
        let source = MapSource(vec![("base-confined".to_owned(), "v1".to_owned(), signed_bytes)]);

        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        let policy = compile(&entry, &source, &Trust::require(&ks), &install(), "v")
            .expect("compile with signed ancestor");
        assert!(
            policy.provenance.resolved_artifacts.iter().any(|a| a.signing_key_id == "kennel-maint-2026"),
            "the verified signing key is recorded in provenance"
        );
    }

    #[test]
    fn require_mode_refuses_an_unsigned_ancestor() {
        // `src()` serves the unsigned in-tree base-confined.
        let ks = KeySet::new();
        let entry = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        assert!(
            compile(&entry, &src(), &Trust::require(&ks), &install(), "v").is_err(),
            "an unsigned ancestor is refused when signatures are required"
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
        assert!(verify_settled(&bytes, &keys).is_err(), "unsigned is not verifiable");
    }
}
