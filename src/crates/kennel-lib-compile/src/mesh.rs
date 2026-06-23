//! Compile-time **local** validation of the `[[provides]]` / `[[consumes]]` mesh surface
//! (`docs/design/07-13-service-catalog.md` §7.13.3).
//!
//! Only what is checkable from the one policy in hand plus its signature provenance:
//! well-formedness, the reserved-namespace gate, and a duplicate `name` within *this* policy.
//! Cross-kennel resolution — does a consume's `name` resolve to a provider of the matching shape
//! — is a **runtime** act (the broker against the live catalogue) and is never attempted here:
//! the compiler only ever holds one policy (§7.13.3).
//!
//! The reserved-namespace gate keys on **whether a reserved name may be claimed**, computed from
//! the policy's signature provenance ([`crate::resolve::ProvidesOrigin`]) by the caller: a reserved
//! `org.projectkennel.*` name is maintainer-trust material, claimable only through a maintainer-signed
//! template (§7.13.5) — the same trust mechanism spawn targets use. This module enforces that
//! permission; the *authoritative* gate (a reserved provide's settled signature must be a maintainer
//! key) is the catalogue's, at runtime (§7.13.4).
//!
//! Validation runs on the *resolved* policy. Errors fail the compile; there are no footgun
//! warnings for this surface, so success returns an empty warning list, kept `Vec<String>`
//! for a uniform caller signature with the other source-section validators.

use std::collections::BTreeSet;

use crate::source::SourcePolicy;
use kennel_lib_policy::settled::RESERVED_PREFIX;
use kennel_lib_policy::PolicyError;

/// Validate the `[[provides]]` / `[[consumes]]` entries of a resolved source policy.
///
/// `reserved_permitted` is computed by the caller from the policy's signature provenance
/// (§7.13.5): a reserved `org.projectkennel.*` name may be claimed only through a maintainer-signed
/// template. Returns every problem found, not just the first. On success returns an empty warning
/// list.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem: a missing
/// `name`/`shape`/`endpoint`/`reason`, a reserved name claimed by a policy not permitted to, or a
/// duplicate provide `name`.
pub fn validate(
    policy: &SourcePolicy,
    reserved_permitted: bool,
) -> Result<Vec<String>, PolicyError> {
    let mut errs: Vec<String> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for p in &policy.provides {
        match p.name.as_deref() {
            None | Some("") => errs.push("[[provides]] entry is missing `name`".to_owned()),
            Some(name) => {
                if name.starts_with(RESERVED_PREFIX) && !reserved_permitted {
                    errs.push(format!(
                        "[[provides]] `{name}` is in the reserved `{RESERVED_PREFIX}*` namespace: a \
                         reserved capability name may be claimed only through a maintainer-signed \
                         template (§7.13.5); an unreserved name is free to any signed template"
                    ));
                }
                if !seen.insert(name) {
                    errs.push(format!(
                        "[[provides]] `{name}` is declared more than once in this policy \
                         (duplicate provide)"
                    ));
                }
            }
        }
        if p.shape.is_none() {
            errs.push(format!(
                "[[provides]] `{}` is missing `shape`",
                who(p.name.as_deref())
            ));
        }
        if p.endpoint.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[provides]] `{}` is missing `endpoint`",
                who(p.name.as_deref())
            ));
        }
        if p.reason.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[provides]] `{}` is missing a `reason`",
                who(p.name.as_deref())
            ));
        }
    }

    for c in &policy.consumes {
        if c.name.as_deref().unwrap_or("").is_empty() {
            errs.push("[[consumes]] entry is missing `name`".to_owned());
        }
        if c.shape.is_none() {
            errs.push(format!(
                "[[consumes]] `{}` is missing `shape`",
                who(c.name.as_deref())
            ));
        }
        if c.reason.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[consumes]] `{}` is missing a `reason`",
                who(c.name.as_deref())
            ));
        }
    }

    if errs.is_empty() {
        Ok(Vec::new())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// A display handle for an entry whose `name` may be absent or empty.
fn who(name: Option<&str>) -> &str {
    name.filter(|s| !s.is_empty()).unwrap_or("(unnamed)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{ConsumesEntry, ProvidesEntry, Shape};

    fn policy_with(provides: Vec<ProvidesEntry>, consumes: Vec<ConsumesEntry>) -> SourcePolicy {
        SourcePolicy {
            provides,
            consumes,
            ..SourcePolicy::default()
        }
    }

    fn provide(name: &str) -> ProvidesEntry {
        ProvidesEntry {
            name: Some(name.to_owned()),
            shape: Some(Shape::AfUnix),
            endpoint: Some("$XDG_RUNTIME_DIR/x".to_owned()),
            reason: Some("a reason".to_owned()),
            ..ProvidesEntry::default()
        }
    }

    fn consume(name: &str) -> ConsumesEntry {
        ConsumesEntry {
            name: Some(name.to_owned()),
            shape: Some(Shape::AfUnix),
            reason: Some("a reason".to_owned()),
            ..ConsumesEntry::default()
        }
    }

    fn err_has(policy: &SourcePolicy, reserved_permitted: bool, needle: &str) -> bool {
        matches!(
            validate(policy, reserved_permitted),
            Err(PolicyError::SourceValidation(ref m)) if m.iter().any(|s| s.contains(needle))
        )
    }

    #[test]
    fn empty_is_vacuously_valid() {
        validate(&SourcePolicy::default(), false).expect("vacuously valid");
    }

    #[test]
    fn well_formed_provide_and_consume_validate() {
        let p = policy_with(vec![provide("build-cache")], vec![consume("metrics")]);
        assert!(validate(&p, false).expect("valid").is_empty());
    }

    #[test]
    fn an_unreserved_provide_accepts_even_when_reserved_is_not_permitted() {
        // Anyone may author and sign a template for an unreserved name (e.g. `doe.john.cache`):
        // the reserved gate never touches it, regardless of `reserved_permitted`.
        let p = policy_with(vec![provide("doe.john.cache")], vec![]);
        assert!(validate(&p, false).expect("valid").is_empty());
    }

    #[test]
    fn a_reserved_name_rejects_when_not_permitted() {
        // A reserved name from a non-maintainer-signed origin (the caller computes
        // `reserved_permitted = false`) is refused.
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(err_has(&p, false, "reserved"));
        assert!(err_has(&p, false, "maintainer-signed template"));
    }

    #[test]
    fn a_reserved_name_accepts_when_permitted() {
        // Permitted (the caller traced it to a maintainer-signed template, or development).
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(validate(&p, true)
            .expect("valid when reserved is permitted")
            .is_empty());
    }

    #[test]
    fn a_duplicate_provide_name_rejects() {
        let p = policy_with(vec![provide("build-cache"), provide("build-cache")], vec![]);
        assert!(err_has(&p, false, "duplicate"));
    }

    #[test]
    fn a_missing_provide_name_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                name: None,
                ..provide("x")
            }],
            vec![],
        );
        assert!(err_has(&p, false, "missing `name`"));
    }

    #[test]
    fn a_missing_provide_shape_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                shape: None,
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(err_has(&p, false, "missing `shape`"));
    }

    #[test]
    fn a_missing_provide_endpoint_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                endpoint: None,
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(err_has(&p, false, "missing `endpoint`"));
    }

    #[test]
    fn a_missing_provide_reason_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                reason: None,
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(err_has(&p, false, "missing a `reason`"));
    }

    #[test]
    fn a_missing_consume_shape_rejects() {
        let p = policy_with(
            vec![],
            vec![ConsumesEntry {
                shape: None,
                ..consume("metrics")
            }],
        );
        assert!(err_has(&p, false, "missing `shape`"));
    }
}
