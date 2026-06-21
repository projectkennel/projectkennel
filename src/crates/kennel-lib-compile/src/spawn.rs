//! Install-time spawn-eligibility (`docs/design/07-12-dynamic-spawn.md` §7.12.8).
//!
//! # Purpose
//!
//! A `[spawn]` grant names the templates it may instantiate (`[[spawn.allow]]`). Eligibility is
//! checked at the **spawner's** compile, not the target's: when a policy carrying `[spawn]` is
//! compiled, each template it names is resolved from the trust store and refused unless it is a
//! sound spawn target. The target cannot know which future policy will name it, and depth-1 means
//! there is no chain to walk — so the check runs when the *spawner* is compiled (§7.12.8). The
//! grant's own local well-formedness (reason, `max_instances`, ref shape) is checked separately in
//! [`crate::translate`](mod@crate::translate); this module is the cross-template half, which needs the [`TemplateSource`]
//! and [`Trust`] to resolve and signature-verify each named target.
//!
//! # What makes a template spawn-eligible (§7.12.8)
//!
//! - **Depth-1.** It carries no `[spawn]` of its own. Recursion would turn `max_instances` from a
//!   global ceiling into a per-node one (`max_instances`^N N levels deep); the rule keeps the
//!   ceiling global by construction. A fork-bomb prohibition, fail-closed before any instantiation.
//! - **A lifetime bound.** It declares `[lifecycle].ttl` — the self-reap that backstops the
//!   fate-sharing reaper (§7.12.7); a tool that never exits must still be torn down.
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
//! resolved bytes at `SPAWN` (§7.12.8, 02-10). Catching an ineligible target at the spawner's
//! install turns a runtime spawn failure into a compile error.

use std::collections::BTreeSet;

use kennel_lib_policy::{PolicyError, SpawnGrant, SpawnTemplate};

use crate::resolve::{split_reference, TemplateSource};
use crate::source::{SourcePolicy, SpawnAllow};
use crate::source_sig::Trust;

/// Validate the `[spawn]` grant's targets and resolve it into the settled-policy form.
///
/// Every `[[spawn.allow]]` target named by `effective`'s `[spawn]` grant is checked against the
/// spawn-eligibility preconditions (§7.12.8), and the grant is resolved into the form `kenneld` holds
/// at runtime — each allowed template pinned to its signature commitment (the content-pin, §7.12.8).
/// A no-op (`None`) when the policy carries no `[spawn]`.
///
/// The content-pin is the target artefact's own ed25519 `[signature]`: a deterministic signature
/// over canonical content *is* the content commitment (the lockfile idiom — no `sha2`), so a
/// re-signed-in-place template resolves to a different signature and `kenneld` catches it at `SPAWN`.
///
/// # Errors
///
/// Returns [`PolicyError`] if a named template is missing from the trust store, fails signature
/// verification or resolution, is not spawn-eligible, or a `mutable` narrowing names a field the
/// target's manifest does not declare.
pub fn resolve_grant(
    effective: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<Option<SpawnGrant>, PolicyError> {
    let Some(spawn) = &effective.spawn else {
        return Ok(None);
    };
    let mut allow = Vec::with_capacity(spawn.allow.len());
    for entry in &spawn.allow {
        // A missing `template` is already rejected by `translate::validate_spawn`; skip rather than
        // double-report.
        let Some(reference) = entry.template.as_deref() else {
            continue;
        };
        let (name, version) = split_reference(reference)?;
        let bytes = source.fetch(&name, &version).ok_or_else(|| {
            PolicyError::Resolution(format!(
                "[[spawn.allow]] template = \"{reference}\" is not in the trust store \
                 (spawn-eligibility is checked at this policy's compile, §7.12.8)"
            ))
        })?;
        // The content-pin (§7.12.8): a spawn target is signed pre-resolved, so the fetched
        // artefact's own `[signature]` is the commitment `kenneld` re-verifies at `SPAWN`.
        let (signing_key_id, signature) = crate::source::parse(&bytes)?
            .signature
            .map(|e| (e.key_id, e.signature))
            .unwrap_or_default();
        // Resolves the target's chain and verifies its signature against the trust store.
        let target = crate::compile::effective_source(&bytes, source, trust)?;
        check_eligible(reference, &target)?;
        check_narrowing(reference, entry, &target)?;
        allow.push(SpawnTemplate {
            template: reference.to_owned(),
            signing_key_id,
            signature,
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

/// Check one resolved target against the eligibility preconditions.
fn check_eligible(reference: &str, target: &SourcePolicy) -> Result<(), PolicyError> {
    let ineligible = |why: &str| {
        PolicyError::Translation(format!(
            "[[spawn.allow]] template = \"{reference}\" is not spawn-eligible: {why} (§7.12.8)"
        ))
    };
    // Depth-1: a spawn target may not itself spawn.
    if target.spawn.is_some() {
        return Err(ineligible(
            "it carries its own `[spawn]` grant — spawning is depth-1, a target may not spawn",
        ));
    }
    // Lifetime bound: the self-reap TTL (§7.12.7).
    let has_ttl = target
        .lifecycle
        .as_ref()
        .and_then(|l| l.ttl.as_deref())
        .is_some_and(|t| !t.trim().is_empty());
    if !has_ttl {
        return Err(ineligible(
            "it declares no `[lifecycle].ttl` (the mandatory self-reap lifetime bound, §7.12.7)",
        ));
    }
    // Resource ceilings: memory + pids + CPU, each an explicit `[ulimits]` declaration.
    let ulimits = target.ulimits.as_ref();
    for (key, what) in [("as", "memory"), ("nproc", "pids"), ("cpu", "CPU")] {
        if !ulimits.is_some_and(|u| u.contains_key(key)) {
            return Err(ineligible(&format!(
                "it declares no `[ulimits].{key}` ({what} ceiling); a spawn target must bound \
                 memory, pids, and CPU"
            )));
        }
    }
    Ok(())
}

/// Check a per-requester `mutable` narrowing selects only fields the target's manifest declares.
fn check_narrowing(
    reference: &str,
    entry: &SpawnAllow,
    target: &SourcePolicy,
) -> Result<(), PolicyError> {
    let Some(narrow) = &entry.mutable else {
        return Ok(());
    };
    let declared: BTreeSet<&str> = target
        .mutable
        .iter()
        .filter_map(|m| m.field.as_deref())
        .collect();
    for field in narrow {
        if !declared.contains(field.as_str()) {
            return Err(PolicyError::Translation(format!(
                "[[spawn.allow]] template = \"{reference}\": `mutable` narrowing names `{field}`, \
                 which the template's manifest does not declare — narrowing selects from the \
                 manifest, it cannot add fields (§7.12.2)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> SourcePolicy {
        crate::source::parse(toml.as_bytes()).expect("parse target")
    }

    /// A minimal eligible spawn-target template: no `[spawn]`, a TTL, and memory/pids/CPU ceilings.
    fn eligible_target() -> String {
        "template_name = \"net-fetch\"\n[lifecycle]\nttl = \"5m\"\n\
         [ulimits]\nas = \"512M\"\nnproc = \"64\"\ncpu = \"30\"\n"
            .to_owned()
    }

    #[test]
    fn a_well_formed_target_is_eligible() {
        assert!(check_eligible("net-fetch@v1", &parse(&eligible_target())).is_ok());
    }

    #[test]
    fn a_target_that_itself_spawns_is_rejected_depth_1() {
        let toml = format!(
            "{}[spawn]\nmax_instances = 1\nreason = \"r\"\n[[spawn.allow]]\ntemplate = \"x@v1\"\n",
            eligible_target()
        );
        let err = check_eligible("net-fetch@v1", &parse(&toml)).expect_err("depth-1");
        assert!(format!("{err}").contains("depth-1"));
    }

    #[test]
    fn a_target_without_a_ttl_is_rejected() {
        let t = parse(
            "template_name = \"x\"\n[ulimits]\nas = \"512M\"\nnproc = \"64\"\ncpu = \"30\"\n",
        );
        assert!(format!("{}", check_eligible("x@v1", &t).expect_err("no ttl")).contains("ttl"));
    }

    #[test]
    fn a_target_missing_a_resource_ceiling_is_rejected() {
        // memory + CPU present, pids (`nproc`) missing.
        let t = parse(
            "template_name = \"x\"\n[lifecycle]\nttl = \"5m\"\n[ulimits]\nas = \"512M\"\ncpu = \"30\"\n",
        );
        assert!(format!("{}", check_eligible("x@v1", &t).expect_err("no nproc")).contains("nproc"));
    }

    #[test]
    fn narrowing_must_select_from_the_targets_manifest() {
        let target = parse(&format!(
            "{}[[mutable]]\nfield = \"net.allow\"\noneof = [\"a\"]\n",
            eligible_target()
        ));
        let ok = SpawnAllow {
            template: Some("net-fetch@v1".to_owned()),
            mutable: Some(vec!["net.allow".to_owned()]),
        };
        assert!(check_narrowing("net-fetch@v1", &ok, &target).is_ok());
        let bad = SpawnAllow {
            template: Some("net-fetch@v1".to_owned()),
            mutable: Some(vec!["fs.write".to_owned()]),
        };
        assert!(format!(
            "{}",
            check_narrowing("net-fetch@v1", &bad, &target).expect_err("undeclared")
        )
        .contains("does not declare"));
    }

    /// A source serving a single named target's bytes.
    struct OneTarget(Vec<u8>);
    impl TemplateSource for OneTarget {
        fn fetch(&self, name: &str, _version: &str) -> Option<Vec<u8>> {
            (name == "net-fetch").then(|| self.0.clone())
        }
    }

    #[test]
    fn resolve_grant_is_none_without_a_spawn_grant() {
        let p = parse(&eligible_target());
        let grant = resolve_grant(&p, &OneTarget(Vec::new()), &Trust::dev()).expect("ok");
        assert!(
            grant.is_none(),
            "a policy with no [spawn] resolves no grant"
        );
    }

    #[test]
    fn resolve_grant_pins_an_unsigned_target_to_an_empty_commitment() {
        // The target is unsigned, so its content-pin is empty — kenneld will accept it only when it
        // likewise resolves the target unsigned (the `AllowUnsigned`/dev path).
        let spawner = parse(
            "name = \"s\"\n[spawn]\nmax_instances = 3\nreason = \"r\"\n\
             [[spawn.allow]]\ntemplate = \"net-fetch@v1\"\n",
        );
        let grant = resolve_grant(
            &spawner,
            &OneTarget(eligible_target().into_bytes()),
            &Trust::dev(),
        )
        .expect("resolve")
        .expect("grant present");
        assert_eq!(grant.max_instances, 3, "max_instances carried verbatim");
        assert_eq!(grant.allow.len(), 1);
        let pinned = grant.allow.first().expect("one allowed target");
        assert_eq!(pinned.template, "net-fetch@v1");
        assert!(
            pinned.signature.is_empty() && pinned.signing_key_id.is_empty(),
            "an unsigned target carries no signature commitment"
        );
    }

    #[test]
    fn resolve_grant_carries_a_per_requester_narrowing() {
        let target = format!(
            "{}[[mutable]]\nfield = \"fs.write\"\noneof = [\"/w\"]\n",
            eligible_target()
        );
        let spawner = parse(
            "name = \"s\"\n[spawn]\nmax_instances = 1\nreason = \"r\"\n\
             [[spawn.allow]]\ntemplate = \"net-fetch@v1\"\nmutable = [\"fs.write\"]\n",
        );
        let grant = resolve_grant(&spawner, &OneTarget(target.into_bytes()), &Trust::dev())
            .expect("resolve")
            .expect("grant");
        let pinned = grant.allow.first().expect("one allowed target");
        assert_eq!(pinned.mutable_narrow, vec!["fs.write".to_owned()]);
    }
}
