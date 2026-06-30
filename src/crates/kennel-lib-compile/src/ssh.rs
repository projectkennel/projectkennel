//! Compile-time validation of the `[ssh]` section.
//!
//! # Purpose
//!
//! The `[ssh]` section is source-only: it is resolved and folded like `[unix]` and
//! dropped from the settled `EffectivePolicy` (`translate.rs`). Its effects are
//! realised at runtime by `kenneld`'s SSH re-origination bastion, the synthetic
//! `~/.ssh`, and the egress allowlist — none of which the settled artefact carries.
//! So the *only* place the framework can reject a malformed SSH grant is here, at
//! compile time, on the resolved source policy.
//!
//! # What this checks
//!
//! - **Every destination is non-empty.** A `[[ssh.destinations]]` entry with no `dest`
//!   mints a synthetic key that stands for nothing — a dead grant; catch it here.
//! - **`allow_headless = true` carries a threat tag.** Letting a non-interactive kennel
//!   drive a granted destination with no per-use touch is a real exposure; the
//!   policy must record it as one (`[ssh].threats.exposed`).
//!
//! There is deliberately **no** `dest ⊆ net.proxy.allow` check: the SSH destination is reached
//! by the *host-side* `ssh` the bastion's forced command runs, as the operator, entirely
//! outside the kennel's egress purview. The only egress the kennel needs is the
//! bastion's own loopback endpoint, which `kenneld` grants as a host-service literal — not
//! a policy `net.proxy.allow` rule. So a destination is never a kennel egress target.
//!
//! This validation runs on the *resolved* policy (after the chain is folded, includes
//! applied, and a leaf's deltas merged).

use crate::source::{SourcePolicy, SshSection};
use kennel_lib_policy::PolicyError;

/// Validate the `[ssh]` section of a resolved source policy.
///
/// A policy with no `[ssh]` section is vacuously valid. Returns every problem found,
/// not just the first, so an author fixes them in one pass.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem.
pub fn validate(policy: &SourcePolicy) -> Result<(), PolicyError> {
    let Some(ssh) = &policy.ssh else {
        return Ok(());
    };
    let mut errs: Vec<String> = Vec::new();

    for d in &ssh.destinations {
        match d.dest.as_deref() {
            None => errs.push("[[ssh.destinations]] entry is missing a `dest`".to_owned()),
            Some(dest) if dest.trim().is_empty() => {
                errs.push("[[ssh.destinations]] `dest` is empty".to_owned());
            }
            Some(_) => {}
        }
    }

    if ssh.allow_headless == Some(true) && !has_threat_tag(ssh) {
        errs.push(
            "[ssh] `allow_headless = true` lets a non-interactive kennel drive a granted \
             destination with no per-use touch; it must carry a threat tag \
             (`[ssh].threats.exposed`)."
                .to_owned(),
        );
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// Whether `[ssh]` carries an `exposed` threat tag (on the section or any destination).
fn has_threat_tag(ssh: &SshSection) -> bool {
    let section = ssh.threats.as_ref().is_some_and(|t| !t.exposed.is_empty());
    let per_dest = ssh
        .destinations
        .iter()
        .any(|d| d.threats.as_ref().is_some_and(|t| !t.exposed.is_empty()));
    section || per_dest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{SshDestination, Threats};

    fn dest(dest: &str) -> SshDestination {
        SshDestination {
            dest: Some(dest.to_owned()),
            options: Vec::new(),
            reason: Some("push".to_owned()),
            threats: None,
        }
    }

    fn policy_with(ssh: SshSection) -> SourcePolicy {
        SourcePolicy {
            ssh: Some(ssh),
            ..SourcePolicy::default()
        }
    }

    #[test]
    fn no_ssh_section_is_vacuously_valid() {
        assert!(validate(&SourcePolicy::default()).is_ok());
    }

    #[test]
    fn a_well_formed_destination_validates() {
        let ssh = SshSection {
            destinations: vec![dest("git@github.com")].into(),
            ..SshSection::default()
        };
        assert!(validate(&policy_with(ssh)).is_ok());
    }

    #[test]
    fn a_destination_with_options_validates() {
        let ssh = SshSection {
            destinations: vec![SshDestination {
                dest: Some("root@localhost".to_owned()),
                options: vec!["-p".to_owned(), "2222".to_owned()],
                reason: Some("deploy".to_owned()),
                threats: None,
            }]
            .into(),
            ..SshSection::default()
        };
        assert!(validate(&policy_with(ssh)).is_ok());
    }

    #[test]
    fn a_missing_dest_is_rejected() {
        let ssh = SshSection {
            destinations: vec![SshDestination {
                dest: None,
                options: Vec::new(),
                reason: Some("x".to_owned()),
                threats: None,
            }]
            .into(),
            ..SshSection::default()
        };
        assert!(validate(&policy_with(ssh)).is_err());
    }

    #[test]
    fn an_empty_dest_is_rejected() {
        let ssh = SshSection {
            destinations: vec![dest("   ")].into(),
            ..SshSection::default()
        };
        assert!(validate(&policy_with(ssh)).is_err());
    }

    #[test]
    fn allow_headless_without_a_threat_tag_is_rejected() {
        let ssh = SshSection {
            allow_headless: Some(true),
            destinations: vec![dest("git@github.com")].into(),
            ..SshSection::default()
        };
        let err = validate(&policy_with(ssh)).expect_err("untagged headless");
        assert!(
            matches!(&err, PolicyError::SourceValidation(m) if m.iter().any(|s| s.contains("allow_headless")))
        );
    }

    #[test]
    fn allow_headless_with_a_section_threat_tag_validates() {
        let ssh = SshSection {
            allow_headless: Some(true),
            threats: Some(Threats {
                exposed: vec!["T1.6".to_owned()],
                mitigated: vec![],
            }),
            destinations: vec![dest("git@github.com")].into(),
        };
        assert!(validate(&policy_with(ssh)).is_ok());
    }

    #[test]
    fn allow_headless_with_a_per_destination_threat_tag_validates() {
        let mut d = dest("git@github.com");
        d.threats = Some(Threats {
            exposed: vec!["T1.6".to_owned()],
            mitigated: vec![],
        });
        let ssh = SshSection {
            allow_headless: Some(true),
            destinations: vec![d].into(),
            ..SshSection::default()
        };
        assert!(validate(&policy_with(ssh)).is_ok());
    }
}
