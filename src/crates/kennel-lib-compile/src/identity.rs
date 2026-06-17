//! Compile-time validation of `[identity].groups` (`docs/design/07-4-filesystem.md` §7.4).
//!
//! # Purpose
//!
//! `[identity].groups` (and the groups named by `[[fs.dev.passthrough]]`) name the
//! supplementary Unix groups the confined workload retains. `kenneld` resolves each to
//! a GID at spawn, **refuses any the operator is not a member of**, the privileged
//! seal `setgroups` to exactly that set, and the synthetic `/etc/group` lists them by
//! name. The membership check (the security gate against over-granting via the
//! privileged `setgroups`) is a host-runtime fact, so it lives in `kenneld`; this is
//! the compile-time check that the *names* are well-formed.
//!
//! # What this checks
//!
//! - **Every group name is non-empty and free of `:`, whitespace, NUL, or other
//!   control characters.** `/etc/group` is colon-delimited and newline-separated; a
//!   name carrying `:` or `\n` would corrupt the synthetic file (an injection of
//!   arbitrary group entries / memberships), so it is refused here.

use crate::source::SourcePolicy;
use kennel_lib_policy::PolicyError;

/// Validate the `[identity].groups` of a resolved source policy.
///
/// A policy with no `[identity]` is vacuously valid. Returns every problem found.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem.
pub fn validate(policy: &SourcePolicy) -> Result<(), PolicyError> {
    let Some(identity) = &policy.identity else {
        return Ok(());
    };
    let mut errs: Vec<String> = Vec::new();
    for g in &identity.groups {
        if g.is_empty() {
            errs.push("[identity] groups contains an empty group name".to_owned());
        } else if !is_safe_group_name(g) {
            errs.push(format!(
                "[identity] group `{g}` is not a well-formed group name (no `:`, whitespace, or control chars — \
                 they would corrupt the synthetic /etc/group)"
            ));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// Whether `name` is safe to render into the colon-delimited, newline-separated
/// `/etc/group`: non-control, and free of `:` and whitespace.
fn is_safe_group_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c != ':' && !c.is_whitespace() && !c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::IdentitySection;

    fn policy_with(groups: &[&str]) -> SourcePolicy {
        SourcePolicy {
            identity: Some(IdentitySection {
                groups: groups.iter().map(|s| (*s).to_owned()).collect(),
                ..IdentitySection::default()
            }),
            ..SourcePolicy::default()
        }
    }

    #[test]
    fn no_identity_is_valid() {
        validate(&SourcePolicy::default()).expect("vacuously valid");
    }

    #[test]
    fn well_formed_group_names_validate() {
        validate(&policy_with(&["dialout", "plugdev", "kvm", "_render"])).expect("valid");
    }

    #[test]
    fn a_name_with_a_colon_or_whitespace_or_newline_is_refused() {
        for bad in ["dialout:x:0:root", "two words", "with\nnewline", ""] {
            let err = validate(&policy_with(&[bad])).expect_err("refused");
            assert!(matches!(err, PolicyError::SourceValidation(_)), "got {err}");
        }
    }
}
