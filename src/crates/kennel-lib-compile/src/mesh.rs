//! Compile-time **local** validation of the `[[provides]]` / `[[consumes]]` mesh surface
//! (`docs/design/07-13-service-catalog.md` §7.13.3).
//!
//! Only what is checkable from the one policy in hand plus the operator's service-class
//! context: well-formedness, the reserved-namespace gate, and a duplicate `name` within
//! *this* policy. Cross-kennel resolution — does a consume's `name` resolve to a provider
//! of the matching shape — is a **runtime** act (the broker against the live catalogue) and
//! is never attempted here: the compiler only ever holds one policy (§7.13.3).
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
/// `service_class` is the operator-supplied trust context (§7.13.5): only a service-class
/// policy may `[[provides]]` a reserved `org.projectkennel.*` capability name. Returns every
/// problem found, not just the first. On success returns an empty warning list.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem: a missing
/// `name`/`shape`/`endpoint`/`reason`, a reserved name claimed without the service-class
/// context, or a duplicate provide `name`.
pub fn validate(policy: &SourcePolicy, service_class: bool) -> Result<Vec<String>, PolicyError> {
    let mut errs: Vec<String> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for p in &policy.provides {
        match p.name.as_deref() {
            None | Some("") => errs.push("[[provides]] entry is missing `name`".to_owned()),
            Some(name) => {
                if name.starts_with(RESERVED_PREFIX) && !service_class {
                    errs.push(format!(
                        "[[provides]] `{name}` is in the reserved `{RESERVED_PREFIX}*` namespace: \
                         only an operator-signed service-class kennel may claim a reserved capability \
                         name (§7.13.5)"
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

    fn err_has(policy: &SourcePolicy, service_class: bool, needle: &str) -> bool {
        matches!(
            validate(policy, service_class),
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
    fn an_unreserved_provide_accepts_without_service_class() {
        let p = policy_with(vec![provide("build-cache")], vec![]);
        assert!(validate(&p, false).expect("valid").is_empty());
    }

    #[test]
    fn a_reserved_name_by_a_non_service_class_kennel_rejects() {
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(err_has(&p, false, "reserved"));
    }

    #[test]
    fn a_reserved_name_by_a_service_class_kennel_accepts() {
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(validate(&p, true)
            .expect("valid for the service class")
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
