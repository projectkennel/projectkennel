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

use kennel_lib_policy::PolicyError;

use crate::resolve::{split_reference, TemplateSource};
use crate::source::{SourcePolicy, SpawnAllow};
use crate::source_sig::Trust;

/// Validate every `[[spawn.allow]]` target named by `effective`'s `[spawn]` grant against the
/// spawn-eligibility preconditions (§7.12.8). A no-op when the policy carries no `[spawn]`.
///
/// # Errors
///
/// Returns [`PolicyError`] if a named template is missing from the trust store, fails signature
/// verification or resolution, is not spawn-eligible, or a `mutable` narrowing names a field the
/// target's manifest does not declare.
pub fn validate(
    effective: &SourcePolicy,
    source: &dyn TemplateSource,
    trust: &Trust<'_>,
) -> Result<(), PolicyError> {
    let Some(spawn) = &effective.spawn else {
        return Ok(());
    };
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
        // Resolves the target's chain and verifies its signature against the trust store.
        let target = crate::compile::effective_source(&bytes, source, trust)?;
        check_eligible(reference, &target)?;
        check_narrowing(reference, entry, &target)?;
    }
    Ok(())
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
}
