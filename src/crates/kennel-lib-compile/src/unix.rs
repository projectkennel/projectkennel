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
//! - **A `[[unix.allow]]` that shims an SSH or GPG agent is a *footgun*, warned not
//!   forbidden.** An exposed `ssh-agent` socket is a destination-blind signing oracle
//!   (§7.10.1); a `gpg-agent` socket is the same oracle and worse (a signature stamps the
//!   user's identity permanently onto arbitrary artefacts — there is no bastion equivalent,
//!   design §11.1). The intended path for SSH egress is the `[ssh]` section and the §7.10
//!   re-origination bastion; for commit signing the safe default is to sign on the host.
//!   But a policy author *may* deliberately shim a real agent — the framework warns loudly
//!   (here at compile, and again at runtime when `kenneld` realises the shim) rather than
//!   amputating the choice. An entry named `ssh-agent`/`gpg-agent` or setting
//!   `SSH_AUTH_SOCK`/`GPG_AGENT_INFO` raises a warning with that pointer; it does not fail
//!   the compile.
//!
//! Validation runs on the *resolved* policy (chain folded, includes applied, leaf
//! deltas merged). The required-`reason` check lives in `SourcePolicy::validate`.
//!
//! Errors (malformed/unhonourable grants) fail the compile; warnings (footguns the
//! author can knowingly accept) are returned on the `Ok` path and surfaced by the
//! caller (the `kennel compile` CLI prints them; `kenneld` re-derives and logs them).

use crate::source::SourcePolicy;
use kennel_lib_policy::PolicyError;

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
        // The host control socket is ungrantable by rule (W10): it is the CLI→daemon trust boundary,
        // and a kennel that could connect to it could drive the daemon — a privilege escalation, not
        // a footgun. Unlike the agent shims below (warned, not forbidden), this is a hard refusal,
        // and it keys on the *target endpoint* (lexically normalised, so a `..` disguise is caught),
        // never a literal string. It joins the structurally-refused-regardless-of-policy set; the
        // spawn factory backstops it at construction against the real, symlink-resolved endpoint.
        if let Some(real) = a.real.as_deref() {
            if kennel_lib_control::socket::is_control_socket(std::path::Path::new(real)) {
                errs.push(format!(
                    "[[unix.allow]] `{who}` targets the kenneld control socket (`{real}`) — the \
                     CLI→daemon trust boundary. Reaching it from inside a kennel is privilege \
                     escalation; it is refused by rule, grantable by no policy"
                ));
            }
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
        // A gpg-agent socket is the same destination-blind oracle and WORSE: a signing
        // oracle stamps the user's verified identity permanently onto arbitrary artefacts
        // (malware, releases, forged commits), not just one authenticated session. There
        // is no bastion equivalent (commit signing is data-integrity, not transport — the
        // §7.10 re-origination trick does not carry over; design §11.1). Warned, not
        // forbidden, per the footgun discipline.
        let shims_gpg = a
            .name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("gpg-agent"))
            || a.env.as_deref() == Some("GPG_AGENT_INFO");
        if shims_gpg {
            warnings.push(format!(
                "[[unix.allow]] `{who}` shims a GPG agent (name = \"gpg-agent\" / env = \"GPG_AGENT_INFO\"): \
                 an exposed agent is a destination-blind signing oracle — worse than ssh-agent, because a \
                 signature permanently stamps your identity onto whatever the kennel asks it to sign \
                 (malware, releases, forged commits). There is no bastion equivalent (design §11.1). Shim \
                 it only if you accept that any code in the kennel can sign as you; the safe default is to \
                 leave commit signing to the host (the workload commits unsigned)"
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
    fn a_grant_targeting_the_control_socket_is_refused_by_rule() {
        // Exact structural form → refused (escalation, not a footgun warning).
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            allow: vec![allow(
                "ctl",
                "/run/user/1000/kennel/control.sock",
                "~/ctl.sock",
            )],
            ..UnixSection::default()
        };
        let err = validate(&policy_with(unix)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("control socket"))),
            "got {err:?}"
        );
    }

    #[test]
    fn a_dotdot_disguised_control_socket_grant_is_still_refused() {
        // A path-string that differs but normalises to the control socket — a naive string check
        // would pass; the endpoint check catches it.
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            allow: vec![allow(
                "sneaky",
                "/run/user/1000/kennel/../kennel/control.sock",
                "~/x.sock",
            )],
            ..UnixSection::default()
        };
        let err = validate(&policy_with(unix)).expect_err("refused");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("control socket")))
        );
    }

    #[test]
    fn an_ordinary_agent_socket_grant_is_not_caught_by_the_control_socket_rule() {
        // The rule must not overcatch: a normal agent shim under the same runtime tree is allowed
        // (it draws the footgun warning, not the hard refusal).
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            allow: vec![allow(
                "ssh-agent",
                "/run/user/1000/kennel/agent.sock",
                "~/.ssh/agent.sock",
            )],
            ..UnixSection::default()
        };
        let warnings = validate(&policy_with(unix)).expect("valid (warned, not refused)");
        assert!(warnings.iter().any(|w| w.contains("SSH agent")));
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
    fn a_gpg_agent_shim_warns_but_is_allowed_by_name() {
        let unix = UnixSection {
            allow: vec![allow(
                "gpg-agent",
                "~/.gnupg/kennels/<kennel>/S.gpg-agent",
                "~/.gnupg/S.gpg-agent",
            )],
            ..UnixSection::default()
        };
        // Same footgun as ssh-agent, worse oracle: permitted, loudly warned.
        let warnings = validate(&policy_with(unix)).expect("allowed with a warning");
        assert!(
            warnings
                .iter()
                .any(|s| s.contains("GPG agent") && s.contains("destination-blind")),
            "gpg-agent shim must warn about the signing oracle: {warnings:?}"
        );
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
        // A non-agent socket: no signing-oracle footgun, so no warning. (An `ssh-agent`
        // or `gpg-agent` grant deliberately DOES warn — see the dedicated tests above.)
        let unix = UnixSection {
            default: Some("deny".to_owned()),
            abstract_ns: Some("deny".to_owned()),
            allow: vec![allow(
                "app-bus",
                "/run/user/1000/app.sock",
                "~/.local/run/app.sock",
            )],
        };
        assert!(validate(&policy_with(unix)).expect("valid").is_empty());
    }
}
