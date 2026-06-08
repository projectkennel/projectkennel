//! Compile-time validation of `[[fs.dev.passthrough]]` (`docs/design/07-4-filesystem.md` §7.4.8).
//!
//! # Purpose
//!
//! Passing a *specific real host device* into a kennel — a serial console, `/dev/ppp`,
//! `/dev/net/tun` — is a significant, loud grant: it widens the kernel attack surface
//! (the device's whole `ioctl` surface becomes reachable) and carries a DAC group
//! right into the kennel. Unlike the trivial pseudo-device baseline (`fs.dev.allow`),
//! a passthrough must therefore be documented and threat-tagged. The runtime binds the
//! node and grants Landlock the same way for both, so the *only* place to reject an
//! undocumented or malformed passthrough is here, at compile time.
//!
//! # What this checks (§7.4.8)
//!
//! - **Every entry has a `path`, absolute under `/dev`, with no `..`.** It is bound
//!   from the host into the constructed `/dev`; anything outside `/dev` or with a
//!   parent-dir escape is refused (the spawn re-checks this too, fail-closed).
//! - **Every entry carries an `exposed` threat tag.** Passthrough weakens the
//!   confinement; the policy must record it (`threats.exposed`), exactly as
//!   `[ssh] allow_headless` must.
//!
//! The required-`reason` check lives in `SourcePolicy::validate`/`LeafPolicy::validate`
//! (with the other resource sections). Validation runs on the *resolved* policy.

use crate::source::{DevPassthrough, SourcePolicy};
use crate::PolicyError;

/// Validate the `[[fs.dev.passthrough]]` entries of a resolved source policy.
///
/// A policy with no passthrough is vacuously valid. Returns every problem found.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem.
pub fn validate(policy: &SourcePolicy) -> Result<(), PolicyError> {
    let Some(dev) = policy.fs.as_ref().and_then(|fs| fs.dev.as_ref()) else {
        return Ok(());
    };
    let mut errs: Vec<String> = Vec::new();

    for entry in &dev.passthrough {
        let who = entry.path.as_deref().unwrap_or("<no-path>");
        match &entry.path {
            None => errs.push("[[fs.dev.passthrough]] entry is missing a `path`".to_owned()),
            Some(p) if !is_dev_path(p) => errs.push(format!(
                "[[fs.dev.passthrough]] `{p}` must be an absolute device path under `/dev` with no `..`"
            )),
            Some(_) => {}
        }
        if !has_exposed_tag(entry) {
            errs.push(format!(
                "[[fs.dev.passthrough]] `{who}` exposes a host device (kernel attack surface + a DAC \
                 group right into the kennel); it must carry a threat tag (`threats.exposed`)"
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// Whether `p` is an absolute device path under `/dev`, free of `..` components.
/// (`is_safe_dev_path` in `kennel-spawn` re-asserts this at the bind, fail-closed.)
fn is_dev_path(p: &str) -> bool {
    (p == "/dev" || p.starts_with("/dev/")) && !p.split('/').any(|c| c == "..")
}

/// Whether the entry carries an `exposed` threat tag.
fn has_exposed_tag(entry: &DevPassthrough) -> bool {
    entry
        .threats
        .as_ref()
        .is_some_and(|t| !t.exposed.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{FsDev, FsSection, Threats};

    fn policy_with(passthrough: Vec<DevPassthrough>) -> SourcePolicy {
        SourcePolicy {
            fs: Some(FsSection {
                dev: Some(FsDev {
                    allow: None,
                    passthrough,
                }),
                ..FsSection::default()
            }),
            ..SourcePolicy::default()
        }
    }

    fn entry(path: &str, tagged: bool) -> DevPassthrough {
        DevPassthrough {
            path: Some(path.to_owned()),
            group: Some("dialout".to_owned()),
            reason: Some("flash firmware over the serial console".to_owned()),
            threats: tagged.then(|| Threats {
                exposed: vec!["T2.1".to_owned()],
                mitigated: vec![],
            }),
        }
    }

    #[test]
    fn no_passthrough_is_valid() {
        validate(&SourcePolicy::default()).expect("vacuously valid");
        validate(&policy_with(Vec::new())).expect("empty list valid");
    }

    #[test]
    fn a_well_formed_threat_tagged_device_validates() {
        validate(&policy_with(vec![entry("/dev/ttyUSB0", true)])).expect("valid");
        validate(&policy_with(vec![entry("/dev/net/tun", true)])).expect("subdir device valid");
    }

    #[test]
    fn an_untagged_passthrough_is_refused() {
        let err = validate(&policy_with(vec![entry("/dev/ttyUSB0", false)])).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("threat tag")))
        );
    }

    #[test]
    fn a_path_outside_dev_or_with_dotdot_is_refused() {
        for bad in ["/etc/shadow", "/dev/../etc/shadow", "relative"] {
            let err = validate(&policy_with(vec![entry(bad, true)])).expect_err("refused");
            assert!(
                matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("under `/dev`")))
            );
        }
    }

    #[test]
    fn a_missing_path_is_refused() {
        let mut e = entry("/dev/ttyUSB0", true);
        e.path = None;
        let err = validate(&policy_with(vec![e])).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("missing a `path`")))
        );
    }
}
