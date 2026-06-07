//! Compile-time validation of the `[binder]` section (`docs/design/07-9-ipc.md` §7.9.4).
//!
//! # Purpose
//!
//! `[binder]` declares the **user-defined** services this kennel may register
//! (`[[binder.provide]]`) and look up (`[[binder.consume]]`). It is resolved and
//! folded like `[unix]`, then flattened into the settled [`BinderRuntime`]
//! (`translate.rs`) that `kenneld`'s context manager gates `addService`/`getService`
//! against. This is the only place to reject a malformed or reserved-namespace
//! declaration, at compile time, on the resolved source policy.
//!
//! # What this checks (§7.9.4)
//!
//! - **No reserved name.** The `org.projectkennel.*` namespace is owned by kenneld
//!   (the af-unix/dbus/gpg/wayland facades are enabled by their own sections, never
//!   declared here). A `provide`/`consume` name in that namespace is a categorical
//!   error — declaring it would shadow a kenneld-owned node.
//! - **Every entry has a `name` and a `reason`.** A service grant is a capability;
//!   like every other granting entry it carries a documented reason (`02-2`).
//!
//! Validation runs on the *resolved* policy. Errors fail the compile; there are no
//! footgun warnings for this section (unlike `[unix]`), so success returns an empty
//! warning list, kept `Vec<String>` for a uniform caller signature with the other
//! source-section validators.
//!
//! [`BinderRuntime`]: crate::settled::BinderRuntime

use crate::source::SourcePolicy;
use crate::PolicyError;

/// The reserved service namespace kenneld owns (`07-9-ipc.md` §Naming): user-defined
/// services may not begin with it.
pub const RESERVED_PREFIX: &str = "org.projectkennel.";

/// Validate the `[binder]` section of a resolved source policy.
///
/// A policy with no `[binder]` section is vacuously valid. Returns every problem
/// found, not just the first. On success returns an empty warning list (this section
/// has no footgun-but-allowed grants).
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem: a
/// reserved-namespace name, or a missing `name`/`reason`.
pub fn validate(policy: &SourcePolicy) -> Result<Vec<String>, PolicyError> {
    let Some(binder) = &policy.binder else {
        return Ok(Vec::new());
    };
    let mut errs: Vec<String> = Vec::new();

    for p in &binder.provide {
        check_entry(
            &mut errs,
            "binder.provide",
            p.name.as_deref(),
            p.reason.as_deref(),
        );
    }
    for c in &binder.consume {
        check_entry(
            &mut errs,
            "binder.consume",
            c.name.as_deref(),
            c.reason.as_deref(),
        );
    }

    if errs.is_empty() {
        Ok(Vec::new())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// Check one provide/consume entry's `name` and `reason`, pushing any problems.
fn check_entry(errs: &mut Vec<String>, label: &str, name: Option<&str>, reason: Option<&str>) {
    match name {
        None | Some("") => {
            errs.push(format!("[[{label}]] entry is missing `name`"));
        }
        Some(n) if n.starts_with(RESERVED_PREFIX) => {
            errs.push(format!(
                "[[{label}]] `{n}` is in the reserved `{RESERVED_PREFIX}*` namespace: reserved \
                 services are enabled by their own sections (e.g. [unix]/[dbus]/[gpg]), never \
                 declared here (§7.9.4)"
            ));
        }
        Some(_) => {}
    }
    let who = name.unwrap_or("(unnamed)");
    if reason.unwrap_or("").is_empty() {
        errs.push(format!("[[{label}]] `{who}` is missing a `reason`"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{BinderConsume, BinderProvide, BinderSection};

    fn policy_with(binder: BinderSection) -> SourcePolicy {
        SourcePolicy {
            binder: Some(binder),
            ..SourcePolicy::default()
        }
    }

    fn provide(name: &str) -> BinderProvide {
        BinderProvide {
            name: Some(name.to_owned()),
            reason: Some("r".to_owned()),
            ..BinderProvide::default()
        }
    }

    fn consume(name: &str) -> BinderConsume {
        BinderConsume {
            name: Some(name.to_owned()),
            reason: Some("r".to_owned()),
            ..BinderConsume::default()
        }
    }

    #[test]
    fn no_binder_section_is_valid() {
        validate(&SourcePolicy::default()).expect("vacuously valid");
    }

    #[test]
    fn well_formed_provide_and_consume_validate() {
        let binder = BinderSection {
            provide: vec![provide("mcp-filesystem")],
            consume: vec![consume("mcp-shell")],
        };
        assert!(validate(&policy_with(binder)).expect("valid").is_empty());
    }

    #[test]
    fn a_reserved_provide_name_is_refused() {
        let binder = BinderSection {
            provide: vec![provide("org.projectkennel.IAfUnix/default")],
            ..BinderSection::default()
        };
        let err = validate(&policy_with(binder)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("reserved")))
        );
    }

    #[test]
    fn a_reserved_consume_name_is_refused() {
        let binder = BinderSection {
            consume: vec![consume("org.projectkennel.IDBus/default")],
            ..BinderSection::default()
        };
        let err = validate(&policy_with(binder)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("reserved")))
        );
    }

    #[test]
    fn a_missing_name_is_refused() {
        let binder = BinderSection {
            provide: vec![BinderProvide {
                reason: Some("r".to_owned()),
                ..BinderProvide::default()
            }],
            ..BinderSection::default()
        };
        let err = validate(&policy_with(binder)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("missing `name`")))
        );
    }

    #[test]
    fn a_missing_reason_is_refused() {
        let binder = BinderSection {
            consume: vec![BinderConsume {
                name: Some("svc".to_owned()),
                ..BinderConsume::default()
            }],
            ..BinderSection::default()
        };
        let err = validate(&policy_with(binder)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("missing a `reason`")))
        );
    }
}
