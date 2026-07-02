//! Verify-half spawn gates (Kennel book Vol 2 ch.13 (Dynamic Spawning)).
//!
//! At `SPAWN`, `kenneld` re-runs spawn-eligibility on the **resolved** template — the authoritative
//! gate, because the trust store is mutable and a re-signed entry must not slip an ineligible target
//! past a stale install-time result (a TOCTOU). The compile-time check (`kennel-lib-compile`) is
//! fail-fast authoring feedback on the *source* form; this is the runtime check on the verified
//! *settled* bytes, in the verify half the daemon links — never the compiler (`tcb-only-shrinks`).
//!
//! The content-pin check (the re-verified signature equals the commitment the spawner recorded) is
//! `kenneld`'s — it needs the trust store and the requester's grant, which live host-side. This
//! module is the representation-only half: the eligibility predicate over a [`SettledPolicy`].

use crate::settled::SettledPolicy;
use crate::PolicyError;

/// The resource ceilings a spawn target must declare (§7.12.8): settled `[ulimits]` keys → English.
const REQUIRED_CEILINGS: &[(&str, &str)] = &[("as", "memory"), ("nproc", "pids"), ("cpu", "CPU")];

/// Check a resolved spawn-target `template` is spawn-eligible (§7.12.8).
///
/// Eligible means: **depth-1** (it carries no `[spawn]` grant of its own, so `max_instances` stays a
/// global ceiling), a **self-reap TTL** (`[lifecycle].ttl` — the backstop that tears down a tool
/// that never exits), and explicit **memory, pids, and CPU ceilings** (`[ulimits].as`/`.nproc`/`.cpu`
/// — mandatory, never defaulted, so no spawn inherits an unbounded ambient ceiling).
///
/// This is the authoritative gate `kenneld` runs on the content-pinned bytes at `SPAWN`; the
/// compile-time pass (`kennel_lib_compile::spawn`) is the matching fail-fast check on the source.
///
/// # Errors
///
/// [`PolicyError::Spawn`] naming the first failed precondition.
pub fn spawn_eligible(template: &SettledPolicy) -> Result<(), PolicyError> {
    let ineligible = |why: String| {
        PolicyError::Spawn(format!("template is not spawn-eligible: {why} (§7.12.8)"))
    };
    // Depth-1: a spawn target may not itself spawn.
    if template.spawn.is_some() {
        return Err(ineligible(
            "it carries its own [spawn] grant — spawning is depth-1, a target may not spawn"
                .to_owned(),
        ));
    }
    // Lifetime bound: the self-reap TTL (§7.12.7).
    if template.effective_policy.lifecycle.ttl_seconds.is_none() {
        return Err(ineligible(
            "it declares no [lifecycle].ttl (the mandatory self-reap lifetime bound, §7.12.7)"
                .to_owned(),
        ));
    }
    // Resource ceilings: memory + pids + CPU, each an explicit [ulimits] declaration.
    for (key, what) in REQUIRED_CEILINGS {
        if !template.ulimits.limits.contains_key(*key) {
            return Err(ineligible(format!(
                "it declares no [ulimits].{key} ({what} ceiling); a spawn target must bound memory, \
                 pids, and CPU"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settled::{SpawnGrant, SpawnTemplate};

    /// A minimal eligible spawn target: no `[spawn]`, a TTL, and memory/pids/CPU ceilings.
    fn eligible() -> SettledPolicy {
        let mut p = crate::settled::sample_settled();
        p.spawn = None;
        p.effective_policy.lifecycle.ttl_seconds = Some(300);
        p.ulimits.limits.clear();
        for k in ["as", "nproc", "cpu"] {
            p.ulimits.limits.insert(k.to_owned(), "1".to_owned());
        }
        p
    }

    #[test]
    fn a_well_formed_target_is_eligible() {
        assert!(spawn_eligible(&eligible()).is_ok());
    }

    #[test]
    fn a_target_that_itself_spawns_is_rejected_depth_1() {
        let mut p = eligible();
        p.spawn = Some(SpawnGrant {
            max_instances: 1,
            allow: vec![SpawnTemplate::default()],
        });
        assert!(format!("{}", spawn_eligible(&p).expect_err("depth-1")).contains("depth-1"));
    }

    #[test]
    fn a_target_without_a_ttl_is_rejected() {
        let mut p = eligible();
        p.effective_policy.lifecycle.ttl_seconds = None;
        assert!(format!("{}", spawn_eligible(&p).expect_err("no ttl")).contains("ttl"));
    }

    #[test]
    fn a_target_missing_a_resource_ceiling_is_rejected() {
        let mut p = eligible();
        p.ulimits.limits.remove("nproc");
        assert!(format!("{}", spawn_eligible(&p).expect_err("no nproc")).contains("nproc"));
    }
}
