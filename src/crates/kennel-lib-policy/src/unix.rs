//! Compile-time validation of the `[unix]` section (`docs/design/07-6-afunix.md` §7.6).
//!
//! # Purpose
//!
//! The `[unix]` section is source-only: it is resolved and folded like `[ssh]` and
//! dropped from the settled `EffectivePolicy` (`translate.rs`). Its effect — binding
//! granted host sockets into the kennel's constructed view, default-deny for
//! everything else, abstract-namespace denial via the always-on Landlock scope — is
//! realised by `kenneld`'s shim builder and the kernel, never by the settled
//! enforcement core. So the *only* place to reject a malformed or unsafe socket grant
//! is here, at compile time, on the resolved source policy.
//!
//! # What this checks (§7.6)
//!
//! - **`default` is not `"allow"` once resolved.** Default-deny is structural (the
//!   shim only contains what is bound in, §7.6.2); a resolved `default = "allow"`
//!   would contradict that and is refused.
//! - **`abstract` is `"deny"` or absent.** Abstract-namespace sockets are denied
//!   unconditionally by the always-on Landlock scope (§7.6.3); `abstract = "allow"`
//!   cannot be honoured, so a policy claiming it is refused rather than silently lied
//!   to. (A future ABI-gated escape hatch may revisit this.)
//! - **Every `[[unix.allow]]` has `real` and `shim`.** A shim is a bind mount from a
//!   real host path to a path in the view; both ends are required.
//! - **A `[[unix.allow]]` that shims an SSH agent is a *footgun*, warned not forbidden.**
//!   An exposed ssh-agent socket is a destination-blind signing oracle (§7.10.1); the
//!   intended path for SSH egress is the `[ssh]` section and the §7.10 re-origination
//!   bastion. But a policy author *may* deliberately shim a real agent — the framework
//!   warns loudly (here at compile, and again at runtime when `kenneld` realises the
//!   shim) rather than amputating the choice. An entry named `ssh-agent` or setting
//!   `SSH_AUTH_SOCK` raises a warning with that pointer; it does not fail the compile.
//!
//! Validation runs on the *resolved* policy (chain folded, includes applied, leaf
//! deltas merged). The required-`reason` check lives in `SourcePolicy::validate`.
//!
//! Errors (malformed/unhonourable grants) fail the compile; warnings (footguns the
//! author can knowingly accept) are returned on the `Ok` path and surfaced by the
//! caller (the `kennel compile` CLI prints them; `kenneld` re-derives and logs them).

use crate::source::SourcePolicy;
use crate::PolicyError;

/// Validate the `[unix]` section of a resolved source policy.
///
/// A policy with no `[unix]` section is vacuously valid. Returns every problem found,
/// not just the first, so an author fixes them in one pass. On success returns the
/// (possibly empty) list of **warnings** — footgun grants the policy is allowed to
/// keep but should be loud about (e.g. shimming a real ssh-agent socket).
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per hard problem
/// (a malformed grant or an unhonourable `default`/`abstract`).
pub fn validate(policy: &SourcePolicy) -> Result<Vec<String>, PolicyError> {
    let Some(unix) = &policy.unix else {
        return Ok(Vec::new());
    };
    let mut errs: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    match unix.default.as_deref() {
        None | Some("deny") => {}
        Some("allow") => errs.push(
            "[unix] default = \"allow\" is forbidden once resolved — default-deny is structural \
             (only what is bound into the shim is present, §7.6.2)"
                .to_owned(),
        ),
        Some(other) => errs.push(format!("[unix] default `{other}` is not deny/allow")),
    }

    match unix.abstract_ns.as_deref() {
        None | Some("deny") => {}
        Some("allow") => errs.push(
            "[unix] abstract = \"allow\" is not supported: abstract-namespace sockets are denied \
             by the always-on Landlock scope (§7.6.3)"
                .to_owned(),
        ),
        Some(other) => errs.push(format!("[unix] abstract `{other}` is not deny/allow")),
    }

    for a in &unix.allow {
        let who = a
            .name
            .as_deref()
            .or(a.real.as_deref())
            .unwrap_or("(unnamed)");
        if a.real.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[unix.allow]] `{who}` is missing `real` (the host socket path to bind)"
            ));
        }
        if a.shim.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[unix.allow]] `{who}` is missing `shim` (the in-view path to bind it at)"
            ));
        }
        // Shimming a real ssh-agent socket is a footgun, not a crime: an exposed agent
        // is a destination-blind signing oracle (§7.10.1) and the [ssh] bastion is the
        // intended path — but the framework warns loudly rather than forbidding it
        // (footguns are warned, not amputated). The warning fires again at runtime.
        let shims_ssh = a
            .name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("ssh-agent"))
            || a.env.as_deref() == Some("SSH_AUTH_SOCK");
        if shims_ssh {
            warnings.push(format!(
                "[[unix.allow]] `{who}` shims an SSH agent (name = \"ssh-agent\" / env = \"SSH_AUTH_SOCK\"): \
                 an exposed agent is a destination-blind signing oracle (§7.10.1). This is the intended \
                 job of the [ssh] section and the §7.10 re-origination bastion — shim a raw agent only if \
                 you accept that any code in the kennel can sign for any destination"
            ));
        }
    }

    if errs.is_empty() {
        Ok(warnings)
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{UnixAllow, UnixSection};

    fn policy_with(unix: UnixSection) -> SourcePolicy {
        SourcePolicy {
            unix: Some(unix),
            ..SourcePolicy::default()
        }
    }

    fn allow(name: &str, real: &str, shim: &str) -> UnixAllow {
        UnixAllow {
            name: Some(name.to_owned()),
            real: Some(real.to_owned()),
            shim: Some(shim.to_owned()),
            reason: Some("r".to_owned()),
            ..UnixAllow::default()
        }
    }

    #[test]
    fn no_unix_section_is_valid() {
        validate(&SourcePolicy::default()).expect("vacuously valid");
    }

    #[test]
    fn a_well_formed_grant_validates() {
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            abstract_ns: Some("deny".to_owned()),
            allow: vec![allow(
                "gpg-agent",
                "~/.gnupg/kennels/<kennel>/S.gpg-agent",
                "~/.gnupg/S.gpg-agent",
            )],
        };
        validate(&policy_with(unix)).expect("valid");
    }

    #[test]
    fn default_allow_is_refused() {
        let unix = UnixSection {
            default: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        let err = validate(&policy_with(unix)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("default-deny")))
        );
    }

    #[test]
    fn abstract_allow_is_refused_as_unsupported() {
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        let err = validate(&policy_with(unix)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("Landlock scope")))
        );
    }

    #[test]
    fn a_missing_real_or_shim_is_refused() {
        let unix = UnixSection {
            allow: vec![UnixAllow {
                name: Some("x".to_owned()),
                reason: Some("r".to_owned()),
                ..UnixAllow::default()
            }],
            ..UnixSection::default()
        };
        let err = validate(&policy_with(unix)).expect_err("refused");
        let PolicyError::SourceValidation(m) = err else {
            unreachable!()
        };
        assert!(m.iter().any(|s| s.contains("missing `real`")));
        assert!(m.iter().any(|s| s.contains("missing `shim`")));
    }

    #[test]
    fn an_ssh_agent_shim_warns_but_is_allowed_by_name() {
        let unix = UnixSection {
            allow: vec![allow(
                "ssh-agent",
                "/run/kennel/<kennel>/ssh-agent.sock",
                "~/.ssh/agent.sock",
            )],
            ..UnixSection::default()
        };
        // Footgun: permitted, but loudly warned (not refused).
        let warnings = validate(&policy_with(unix)).expect("allowed with a warning");
        assert!(warnings.iter().any(|s| s.contains("destination-blind")));
    }

    #[test]
    fn an_ssh_auth_sock_env_warns_but_is_allowed() {
        let mut a = allow("custom", "/run/x.sock", "~/.ssh/agent.sock");
        a.env = Some("SSH_AUTH_SOCK".to_owned());
        let unix = UnixSection {
            allow: vec![a],
            ..UnixSection::default()
        };
        let warnings = validate(&policy_with(unix)).expect("allowed with a warning");
        assert!(warnings.iter().any(|s| s.contains("destination-blind")));
    }

    #[test]
    fn a_clean_grant_yields_no_warnings() {
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            abstract_ns: Some("deny".to_owned()),
            allow: vec![allow("gpg-agent", "/run/gpg.sock", "~/.gnupg/S.gpg-agent")],
        };
        assert!(validate(&policy_with(unix)).expect("valid").is_empty());
    }
}
