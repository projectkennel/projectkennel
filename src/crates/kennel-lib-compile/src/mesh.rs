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

use crate::source::{Shape, SourcePolicy};
use kennel_lib_policy::settled::RESERVED_PREFIX;
use kennel_lib_policy::PolicyError;

/// The per-capability directory component for a provide rendezvous: `<name>`, or `<name>.<key>` when
/// a private key is set (§7.13.4b).
fn provide_dir_component(name: &str, key: Option<&str>) -> String {
    key.map_or_else(|| name.to_owned(), |k| format!("{name}.{k}"))
}

/// The default in-view `endpoint` for an `af-unix` provide that omits one (§7.13.4b): a `sock` socket
/// in a per-capability `/run` subdirectory `kenneld` binds its rendezvous directory at.
#[must_use]
pub fn default_af_unix_endpoint(name: &str, key: Option<&str>) -> String {
    format!("/run/{}/sock", provide_dir_component(name, key))
}

/// Whether an author-supplied `af-unix` `endpoint` is a safe rendezvous bind target: absolute, under
/// `/run`, with a subdirectory (so `dirname(endpoint)` is a `/run` subdir, never bare `/run`), and no
/// `..` traversal.
fn af_unix_endpoint_under_run(endpoint: &str) -> bool {
    let path = std::path::Path::new(endpoint);
    path.is_absolute()
        && path.starts_with("/run")
        && path.components().count() >= 4
        && !path
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new(".."))
}

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
        // An `af-unix` endpoint is optional — `kenneld` defaults it to `/run/<name>[.key]/sock`
        // (§7.13.4b). When supplied, it must be a safe rendezvous bind target: absolute, under `/run`,
        // with a subdirectory, since construction binds `dirname(endpoint)` into the view. Other
        // shapes author a required `endpoint` (a bus name, a node).
        match p.shape {
            Some(Shape::AfUnix) => {
                if let Some(e) = p
                    .endpoint
                    .as_deref()
                    .filter(|e| !af_unix_endpoint_under_run(e))
                {
                    errs.push(format!(
                        "[[provides]] `{}` endpoint `{e}` must be an absolute path under `/run` with \
                         a subdirectory (e.g. `/run/<dir>/<sock>`) — `kenneld` binds \
                         `dirname(endpoint)` at construction (§7.13.4b); omit it for the \
                         `/run/<name>[.key]/sock` default",
                        who(p.name.as_deref())
                    ));
                }
            }
            // Other (deferred) shapes author a required `endpoint` (a bus name, a node).
            Some(_) if p.endpoint.as_deref().unwrap_or("").is_empty() => errs.push(format!(
                "[[provides]] `{}` is missing `endpoint`",
                who(p.name.as_deref())
            )),
            _ => {} // valid af-unix endpoint, a present other-shape endpoint, or a missing shape
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
        // A well-formed af-unix provide omits `endpoint` (§7.13.4b): kenneld defaults it.
        ProvidesEntry {
            name: Some(name.to_owned()),
            shape: Some(Shape::AfUnix),
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
    fn an_omitted_af_unix_endpoint_is_valid_and_defaults() {
        // af-unix may omit `endpoint`; kenneld defaults it to /run/<name>[.key]/sock (§7.13.4b).
        let p = policy_with(vec![provide("build-cache")], vec![]);
        assert!(validate(&p, false).expect("valid").is_empty());
        assert_eq!(
            default_af_unix_endpoint("build-cache", None),
            "/run/build-cache/sock"
        );
        assert_eq!(
            default_af_unix_endpoint("org.x.wl", Some("K1")),
            "/run/org.x.wl.K1/sock"
        );
    }

    #[test]
    fn an_af_unix_endpoint_outside_run_rejects() {
        for bad in [
            "/tmp/x.sock",
            "$XDG_RUNTIME_DIR/x",
            "/run/x.sock",
            "/run/../etc/x/y",
        ] {
            let p = policy_with(
                vec![ProvidesEntry {
                    endpoint: Some((*bad).to_owned()),
                    ..provide("build-cache")
                }],
                vec![],
            );
            assert!(
                err_has(&p, false, "under `/run`"),
                "endpoint {bad} should be rejected"
            );
        }
    }

    #[test]
    fn an_af_unix_endpoint_under_run_with_a_subdir_is_accepted() {
        let p = policy_with(
            vec![ProvidesEntry {
                endpoint: Some("/run/mesh/echo.sock".to_owned()),
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(validate(&p, false).expect("valid").is_empty());
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
