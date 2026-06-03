//! Compile-time validation of the `[ssh]` section (`docs/design/07-8-ssh.md` §7.8.8).
//!
//! # Purpose
//!
//! The `[ssh]` section is source-only: it is resolved and folded like `[unix]` and
//! dropped from the settled `EffectivePolicy` (`translate.rs`). Its effects are
//! realised at runtime by `kenneld`'s SSH re-origination bastion, the synthetic
//! `~/.ssh`, and the egress allowlist — none of which the settled artefact carries.
//! So the *only* place the framework can reject a malformed or dead SSH grant is
//! here, at compile time, on the resolved source policy.
//!
//! # What this checks (§7.8.8)
//!
//! - **Every `fingerprint` is well-formed** — the modern `SHA256:<base64>` identity
//!   `ssh-add -l` prints. A typo'd fingerprint mints a synthetic key that no real
//!   key can ever back, so the grant is dead; catch it at compile time, not at the
//!   bastion.
//! - **Every `hosts` entry is `⊆ net.allow` on port 22.** SSH leaves the kennel only
//!   over the egress proxy, and direct `:22` is denied; a host not in the egress
//!   allowlist on 22 is either a dead grant or a recon hint (a destination named in
//!   policy the kennel can never reach). Both are author errors.
//! - **`allow_headless = true` carries a threat tag.** Letting a non-interactive
//!   kennel drive a real key with no per-use touch is a real exposure (§7.8.6); the
//!   policy must record it as one (`[ssh].threats.exposed`).
//!
//! This validation runs on the *resolved* policy (after the chain is folded, includes
//! applied, and a leaf's deltas merged), so an `[ssh]` grant may reference a
//! `net.allow` host contributed anywhere up the chain or by the same leaf.

use crate::source::{SourcePolicy, SshSection};
use crate::PolicyError;

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

    // Hosts the egress allowlist reaches on port 22: a by-name `net.allow` entry whose
    // port set includes 22 (an empty port set means "all ports" — translate.rs).
    let net_22: Vec<&str> = policy
        .net
        .as_ref()
        .map(|n| {
            n.allow
                .iter()
                .filter(|a| a.ports.is_empty() || a.ports.contains(&22))
                .filter_map(|a| a.name.as_deref())
                .collect()
        })
        .unwrap_or_default();

    for k in &ssh.keys {
        match k.fingerprint.as_deref() {
            None => errs.push("[[ssh.keys]] entry is missing a `fingerprint`".to_owned()),
            Some(fp) if !is_sha256_fingerprint(fp) => errs.push(format!(
                "[[ssh.keys]] fingerprint `{fp}` is not a well-formed `SHA256:<base64>` \
                 key fingerprint (the form `ssh-add -l` prints)"
            )),
            Some(_) => {}
        }
        if k.hosts.is_empty() {
            let who = k.fingerprint.as_deref().unwrap_or("<no-fingerprint>");
            errs.push(format!("[[ssh.keys]] `{who}` grants no `hosts`"));
        }
        for h in &k.hosts {
            if !net_22.contains(&h.as_str()) {
                errs.push(format!(
                    "[[ssh.keys]] host `{h}` is not in `net.allow` on port 22; SSH leaves the \
                     kennel only over the egress proxy, so this is a dead grant or a recon hint. \
                     Add a [[net.allow]] for `{h}` with `ports = [22]`."
                ));
            }
        }
    }

    if ssh.allow_headless == Some(true) && !has_threat_tag(ssh) {
        errs.push(
            "[ssh] `allow_headless = true` lets a non-interactive kennel drive a real key with \
             no per-use touch; it must carry a threat tag (`[ssh].threats.exposed`)."
                .to_owned(),
        );
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// Whether `[ssh]` carries an `exposed` threat tag (on the section or any key grant).
fn has_threat_tag(ssh: &SshSection) -> bool {
    let section = ssh.threats.as_ref().is_some_and(|t| !t.exposed.is_empty());
    let per_key = ssh
        .keys
        .iter()
        .any(|k| k.threats.as_ref().is_some_and(|t| !t.exposed.is_empty()));
    section || per_key
}

/// Whether `fp` is a well-formed OpenSSH `SHA256:<base64>` key fingerprint.
///
/// `ssh-keygen`/`ssh-add -l` render a SHA-256 fingerprint as the literal `SHA256:`
/// followed by the unpadded standard-base64 encoding of the 32-byte digest — exactly
/// 43 characters over the `[A-Za-z0-9+/]` alphabet, no `=` padding.
fn is_sha256_fingerprint(fp: &str) -> bool {
    let Some(b64) = fp.strip_prefix("SHA256:") else {
        return false;
    };
    b64.len() == 43
        && b64
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{NetAllow, NetSection, SshKey, Threats};

    // A real ed25519 fingerprint shape: "SHA256:" + 43 base64 chars.
    const FP: &str = "SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt";

    fn policy_with(ssh: SshSection, net_hosts: &[(&str, Vec<u16>)]) -> SourcePolicy {
        SourcePolicy {
            net: Some(NetSection {
                allow: net_hosts
                    .iter()
                    .map(|(n, ports)| NetAllow {
                        name: Some((*n).to_owned()),
                        ports: ports.clone(),
                        reason: Some("test".to_owned()),
                        ..NetAllow::default()
                    })
                    .collect(),
                ..NetSection::default()
            }),
            ssh: Some(ssh),
            ..SourcePolicy::default()
        }
    }

    fn key(fp: &str, hosts: &[&str]) -> SshKey {
        SshKey {
            fingerprint: Some(fp.to_owned()),
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            reason: Some("push".to_owned()),
            threats: None,
        }
    }

    #[test]
    fn no_ssh_section_is_vacuously_valid() {
        assert!(validate(&SourcePolicy::default()).is_ok());
    }

    #[test]
    fn a_well_formed_grant_within_net_allow_22_validates() {
        let ssh = SshSection {
            keys: vec![key(FP, &["github.com"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![22])]);
        assert!(validate(&p).is_ok(), "{:?}", validate(&p));
    }

    #[test]
    fn a_host_with_empty_ports_covers_22() {
        let ssh = SshSection {
            keys: vec![key(FP, &["git.internal"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("git.internal", vec![])]);
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn a_host_outside_net_allow_22_is_rejected() {
        // github is allowed on 443 only — not reachable over SSH.
        let ssh = SshSection {
            keys: vec![key(FP, &["github.com"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![443])]);
        let err = validate(&p).expect_err("host not on :22");
        assert!(
            matches!(&err, PolicyError::SourceValidation(m) if m.iter().any(|s| s.contains("not in `net.allow` on port 22")))
        );
    }

    #[test]
    fn a_host_absent_from_net_allow_is_rejected() {
        let ssh = SshSection {
            keys: vec![key(FP, &["evil.example"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![22])]);
        assert!(validate(&p).is_err());
    }

    #[test]
    fn a_malformed_fingerprint_is_rejected() {
        for bad in [
            "github-key",
            "MD5:aa:bb:cc",
            "SHA256:tooshort",
            "SHA256:has=padding+chars/xxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            let ssh = SshSection {
                keys: vec![key(bad, &["github.com"])],
                ..SshSection::default()
            };
            let p = policy_with(ssh, &[("github.com", vec![22])]);
            assert!(validate(&p).is_err(), "expected `{bad}` to be rejected");
        }
    }

    #[test]
    fn a_grant_with_no_hosts_is_rejected() {
        let ssh = SshSection {
            keys: vec![key(FP, &[])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[]);
        assert!(validate(&p).is_err());
    }

    #[test]
    fn allow_headless_without_a_threat_tag_is_rejected() {
        let ssh = SshSection {
            allow_headless: Some(true),
            keys: vec![key(FP, &["github.com"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![22])]);
        let err = validate(&p).expect_err("untagged headless");
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
            keys: vec![key(FP, &["github.com"])],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![22])]);
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn allow_headless_with_a_per_key_threat_tag_validates() {
        let mut k = key(FP, &["github.com"]);
        k.threats = Some(Threats {
            exposed: vec!["T1.6".to_owned()],
            mitigated: vec![],
        });
        let ssh = SshSection {
            allow_headless: Some(true),
            keys: vec![k],
            ..SshSection::default()
        };
        let p = policy_with(ssh, &[("github.com", vec![22])]);
        assert!(validate(&p).is_ok());
    }
}
