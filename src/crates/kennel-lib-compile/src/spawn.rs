//! Install-time spawn-eligibility.
//!
//! # Purpose
//!
//! A `[spawn]` grant names the templates it may instantiate (`[[spawn.allow]]`). Eligibility is
//! checked at the **spawner's** compile, not the target's: when a policy carrying `[spawn]` is
//! compiled, each template it names is resolved from the trust store and refused unless it is a
//! sound spawn target. The target cannot know which future policy will name it, and depth-1 means
//! there is no chain to walk — so the check runs when the *spawner* is compiled. The
//! grant's own local well-formedness (reason, `max_instances`, ref shape) is checked separately in
//! [`crate::translate`](mod@crate::translate); this module is the cross-template half, which needs the [`TemplateSource`]
//! and [`Trust`] to resolve and signature-verify each named target.
//!
//! # What makes a template spawn-eligible
//!
//! - **Depth-1.** It carries no `[spawn]` of its own. Recursion would turn `max_instances` from a
//!   global ceiling into a per-node one (`max_instances`^N N levels deep); the rule keeps the
//!   ceiling global by construction. A fork-bomb prohibition, fail-closed before any instantiation.
//! - **A lifetime bound.** It declares `[lifecycle].ttl` — the self-reap that backstops the
//!   fate-sharing reaper; a tool that never exits must still be torn down.
//! - **Resource ceilings.** It declares an explicit memory, pids, and CPU ceiling
//!   (`[ulimits].as` / `.nproc` / `.cpu`). These are **mandatory, not defaulted**: the open
//!   eligibility-default question (02-10) is resolved fail-closed — a spawn target bounds its own
//!   resource use or it is ineligible, so no spawn can inherit an unbounded ambient ceiling.
//! - **A fenced write surface.** Whatever the agent may write is the `[[mutable]]` manifest and
//!   nothing else. A template with no manifest is the *most* fenced (zero writable fields), so an
//!   absent manifest is eligible; a present one is validated for well-formedness in
//!   [`crate::translate`](mod@crate::translate). A per-requester `[[spawn.allow]].mutable` narrowing may only *select*
//!   from the target's manifest — naming a field the manifest does not declare is rejected here.
//!
//! Install-time eligibility is **fail-fast authoring feedback**, not the authoritative gate: the
//! trust store is mutable, so `kenneld` re-verifies the content-pin and re-runs eligibility on the
//! resolved bytes at `SPAWN` (02-10). Catching an ineligible target at the spawner's
//! install turns a runtime spawn failure into a compile error.

use std::collections::BTreeSet;

use kennel_lib_policy::{PolicyError, SettledPolicy, SpawnGrant, SpawnTemplate};

use crate::resolve::{parse_reference, TemplateSource};
use crate::source::{SourcePolicy, SpawnAllow};
use crate::source_sig::Trust;

/// Validate the `[spawn]` grant's targets and resolve it into the settled-policy form.
///
/// Each `[[spawn.allow]]` target is the **settled, signed** template a spawn instantiates — the
/// complete, chain-folded policy ([`TemplateSource::fetch_settled`]), not the source leaf. The grant
/// is resolved into the form `kenneld` holds at runtime: each template pinned to its signature
/// commitment (the content-pin) and verified spawn-eligible. A no-op (`None`) without a `[spawn]`.
///
/// The content-pin is the settled artefact's own ed25519 `[signature]`: a deterministic signature
/// over canonical content *is* the commitment (the lockfile idiom — no `sha2`), so a re-signed
/// template resolves to a different signature and `kenneld` catches it at `SPAWN` ([`verify_pinned`]).
///
/// [`verify_pinned`]: kennel_lib_policy::verify_pinned
///
/// # Errors
///
/// Returns [`PolicyError`] if a named template has no settled artefact in the trust store, fails
/// signature verification, is not spawn-eligible, or a `mutable` narrowing names a field the
/// template's manifest does not declare.
pub fn resolve_grant(
    effective: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<Option<SpawnGrant>, PolicyError> {
    let Some(spawn) = &effective.spawn else {
        return Ok(None);
    };
    let mut allow = Vec::with_capacity(spawn.allow.resolved().len());
    for entry in &spawn.allow {
        // A missing `template` is already rejected by `translate::validate_spawn`; skip rather than
        // double-report.
        let Some(reference) = entry.template.as_deref() else {
            continue;
        };
        let name = parse_reference(reference)?;
        let bytes = source.fetch_settled(&name).ok_or_else(|| {
            PolicyError::Resolution(format!(
                "[[spawn.allow]] template = \"{reference}\" has no settled artefact in the trust \
                 store — compile and sign it (`kennel policy compile`) so a spawn instantiates the \
                 complete signed template"
            ))
        })?;
        // Read the settled signature envelope (the content-pin). Verify it cryptographically when the
        // artefact is signed and a trust store is present; require a signature only when the trust
        // context demands it (the daemon re-verifies this exact commitment at SPAWN —
        // [`kennel_lib_policy::verify_pinned`]).
        let doc = kennel_lib_policy::parse_signed_settled_unverified(&bytes)?;
        if doc.signature.algorithm == kennel_lib_policy::signature::SSHSIG_ALGORITHM {
            if let Some(keys) = trust.keys() {
                kennel_lib_policy::verify_settled(&bytes, keys)?;
            }
        } else if trust.requires_signatures() {
            return Err(PolicyError::Resolution(format!(
                "[[spawn.allow]] template = \"{reference}\": its settled artefact is unsigned, but \
                 this compile requires signatures — sign it (`kennel policy compile --key …`)"
            )));
        }
        // Re-run spawn-eligibility on the SETTLED form — the same verify-half gate the daemon runs.
        kennel_lib_policy::spawn_eligible(&doc.policy)?;
        check_narrowing(reference, entry, &doc.policy)?;
        allow.push(SpawnTemplate {
            template: reference.to_owned(),
            signing_key_id: doc.signature.key_id,
            signature: doc.signature.signature,
            mutable_narrow: entry.mutable.clone().unwrap_or_default(),
        });
    }
    // `max_instances` is guaranteed `Some(>= 1)` once `translate::validate_spawn` runs (next in the
    // compile pipeline); an unset value here only survives onto an error path that never assembles.
    Ok(Some(SpawnGrant {
        max_instances: spawn.max_instances.unwrap_or(0),
        allow,
    }))
}

/// Check a per-requester `mutable` narrowing selects only fields the settled template's `[[mutable]]`
/// manifest declares (narrowing selects from the manifest, it cannot add fields —).
fn check_narrowing(
    reference: &str,
    entry: &SpawnAllow,
    target: &SettledPolicy,
) -> Result<(), PolicyError> {
    let Some(narrow) = &entry.mutable else {
        return Ok(());
    };
    let declared: BTreeSet<&str> = target.manifest.iter().map(|v| v.field.as_str()).collect();
    for field in narrow {
        if !declared.contains(field.as_str()) {
            return Err(PolicyError::Spawn(format!(
                "[[spawn.allow]] template = \"{reference}\": `mutable` narrowing names `{field}`, \
                 which the template's manifest does not declare — narrowing selects from the \
                 manifest, it cannot add fields"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> SourcePolicy {
        crate::source::parse(toml.as_bytes()).expect("parse spawner")
    }

    /// The in-tree `templates/` source (for `base-confined`, the security foundation every target
    /// inherits — a self-contained policy would have to declare every required section by hand).
    struct RealTemplates;
    impl TemplateSource for RealTemplates {
        fn fetch(&self, name: &str) -> Option<Vec<u8>> {
            let root =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../toml/templates");
            std::fs::read(root.join(name).join("policy.toml")).ok()
        }
    }

    /// The **settled** bytes of a minimal eligible spawn target: inherits `base-confined`, no
    /// `[spawn]`, a TTL, memory/pids/CPU ceilings, and an optional `[[mutable]]` field — sealed
    /// **unsigned**, as `fetch_settled` would return. A spawn target *is* a complete (here
    /// unsigned-dev) settled policy, not a source leaf.
    fn settled_target(manifest_field: Option<&str>) -> Vec<u8> {
        let manifest = manifest_field
            .map(|f| format!("[[mutable]]\nfield = \"{f}\"\noneof = [\"a\"]\n"))
            .unwrap_or_default();
        let src = format!(
            "template_base = \"base-confined\"\ntemplate_name = \"net-fetch\"\n\
             [net]\nmode = \"none\"\n[lifecycle]\nttl = \"5m\"\nttl_action = \"exit\"\n\
             [ulimits]\nas = \"512M\"\nnproc = \"64\"\ncpu = \"30\"\n{manifest}"
        );
        let compiled =
            crate::compile::compile(&parse(&src), &RealTemplates, &Trust::dev(), "0.0.0")
                .expect("compile settled target");
        kennel_lib_policy::to_bytes(&crate::compile::seal_unsigned(&compiled.policy))
            .expect("serialise settled target")
    }

    /// A source serving one named target's **settled** bytes via `fetch_settled`.
    struct OneSettled(Vec<u8>);
    impl TemplateSource for OneSettled {
        fn fetch(&self, _name: &str) -> Option<Vec<u8>> {
            None
        }
        fn fetch_settled(&self, name: &str) -> Option<Vec<u8>> {
            (name == "net-fetch").then(|| self.0.clone())
        }
    }

    /// Resolves `base-confined` (the real templates) for chain-folding AND serves `net-fetch`'s
    /// settled form — for compiling a depth>1 target that itself names a spawn allow-target.
    struct BothSources(Vec<u8>);
    impl TemplateSource for BothSources {
        fn fetch(&self, name: &str) -> Option<Vec<u8>> {
            RealTemplates.fetch(name)
        }
        fn fetch_settled(&self, name: &str) -> Option<Vec<u8>> {
            (name == "net-fetch").then(|| self.0.clone())
        }
    }

    fn spawner(extra_allow: &str) -> SourcePolicy {
        parse(&format!(
            "name = \"s\"\n[spawn]\nmax_instances = 3\nreason = \"r\"\n\
             [[spawn.allow]]\ntemplate = \"net-fetch\"\n{extra_allow}"
        ))
    }

    #[test]
    fn resolve_grant_is_none_without_a_spawn_grant() {
        let p = parse("name = \"s\"\n");
        assert!(resolve_grant(&p, &RealTemplates, &Trust::dev())
            .expect("ok")
            .is_none());
    }

    #[test]
    fn resolve_grant_requires_a_settled_artefact() {
        // `fetch_settled` returns None ⇒ the target was never compiled+signed to its settled form.
        let err =
            resolve_grant(&spawner(""), &RealTemplates, &Trust::dev()).expect_err("no settled");
        assert!(format!("{err}").contains("settled artefact"));
    }

    #[test]
    fn resolve_grant_pins_an_unsigned_settled_target() {
        let grant = resolve_grant(
            &spawner(""),
            &OneSettled(settled_target(None)),
            &Trust::dev(),
        )
        .expect("resolve")
        .expect("grant");
        assert_eq!(grant.max_instances, 3, "max_instances carried verbatim");
        let pinned = grant.allow.first().expect("one target");
        assert_eq!(pinned.template, "net-fetch");
        // Sealed unsigned (dev), so the commitment is empty — kenneld accepts it only when it likewise
        // resolves the target unsigned.
        assert!(pinned.signature.is_empty() && pinned.signing_key_id.is_empty());
    }

    #[test]
    fn resolve_grant_rejects_an_ineligible_settled_target() {
        // A settled target that itself carries `[spawn]` is not depth-1 — caught by spawn_eligible on
        // the settled form. (It also names a settled allow-target, so its own grant resolves; that is
        // beside the point — what fails is that *this* target may not be spawned.)
        let src =
            "template_base = \"base-confined\"\ntemplate_name = \"x\"\n[net]\nmode = \"none\"\n\
                   [lifecycle]\nttl = \"5m\"\nttl_action = \"exit\"\n\
                   [ulimits]\nas = \"512M\"\nnproc = \"64\"\ncpu = \"30\"\n\
                   [spawn]\nmax_instances = 1\nreason = \"r\"\n\
                   [[spawn.allow]]\ntemplate = \"net-fetch\"\n";
        let compiled = crate::compile::compile(
            &parse(src),
            &BothSources(settled_target(None)),
            &Trust::dev(),
            "0.0.0",
        )
        .expect("compile depth>1 target");
        let bytes = kennel_lib_policy::to_bytes(&crate::compile::seal_unsigned(&compiled.policy))
            .expect("bytes");
        let err =
            resolve_grant(&spawner(""), &OneSettled(bytes), &Trust::dev()).expect_err("ineligible");
        assert!(format!("{err}").contains("depth-1"));
    }

    #[test]
    fn resolve_grant_carries_and_checks_a_per_requester_narrowing() {
        let target = OneSettled(settled_target(Some("fs.write")));
        // A narrowing that selects a declared field is carried.
        let grant = resolve_grant(
            &spawner("mutable = [\"fs.write\"]\n"),
            &target,
            &Trust::dev(),
        )
        .expect("resolve")
        .expect("grant");
        assert_eq!(
            grant.allow.first().expect("target").mutable_narrow,
            vec!["fs.write".to_owned()]
        );
        // A narrowing naming an undeclared field is rejected.
        let err = resolve_grant(
            &spawner("mutable = [\"net.proxy.allow\"]\n"),
            &OneSettled(settled_target(Some("fs.write"))),
            &Trust::dev(),
        )
        .expect_err("undeclared narrowing");
        assert!(format!("{err}").contains("does not declare"));
    }
}
