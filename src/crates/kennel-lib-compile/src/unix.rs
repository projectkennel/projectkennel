//! Compile-time validation of the `[unix]` section.
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
//! # What this checks
//!
//! - **`default` is not `"allow"` once resolved.** Default-deny is structural (the
//!   shim only contains what is bound in); a resolved `default = "allow"`
//!   would contradict that and is refused.
//! - **`abstract` is `"deny"`, absent, or `"allow"` (escape hatch).**
//!   Abstract-namespace sockets are denied by default by the always-on Landlock
//!   scope (ABI 6+). `abstract = "allow"` is accepted when the kennel
//!   owns its `CLONE_NEWNET` (`net.mode` ≠ `"host"`) — the net-ns boundary is
//!   the structural control; ABI-6 scoping is defence-in-depth. The combination
//!   `abstract = "allow"` + `net.mode = "host"` is a **hard compile error**
//!   (T1.13): host mode shares the host's network namespace, so abstract sockets
//!   reach the host namespace directly.
//! - **Every `[[unix.allow]]` has `real` and `shim`.** A shim is a bind mount from a
//!   real host path to a path in the view; both ends are required.
//! - **A `[[unix.allow]]` that shims an SSH or GPG agent is a *footgun*, warned not
//!   forbidden.** An exposed `ssh-agent` socket is a destination-blind signing oracle; a `gpg-agent` socket is the same oracle and worse (a signature stamps the
//!   user's identity permanently onto arbitrary artefacts — there is no bastion equivalent by
//!   design). The intended path for SSH egress is the `[ssh]` section and the
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
// allow(too_many_lines): one cohesive validation pass over the `[unix]` section — the
// per-grant checks share the accumulated diagnostics and cannot split without threading state.
#[allow(clippy::too_many_lines)]
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
             (only what is bound into the shim is present)"
                .to_owned(),
        ),
        Some(other) => errs.push(format!("[unix] default `{other}` is not deny/allow")),
    }

    // Resolve net.mode from the source policy: absent → "constrained" (the default).
    let net_mode = policy
        .net
        .as_ref()
        .and_then(|n| n.mode.as_deref())
        .unwrap_or("constrained");

    match unix.abstract_ns.as_deref() {
        None | Some("deny") => {}
        Some("allow") => {
            // abstract = "allow" is valid ONLY when the kennel owns its CLONE_NEWNET
            // (net.mode = none / constrained / unconstrained). A host-mode kennel
            // shares the host's network namespace — abstract sockets reach the host
            // namespace directly (X11, D-Bus session bus, arbitrary daemon IPC),
            // below Landlock, the proxy, and BPF. That combination is a hard compile
            // error citing T1.13.
            if net_mode == "host" {
                errs.push(
                    "[unix] abstract = \"allow\" with net.mode = \"host\" is a hard compile error: \
                     host mode shares CLONE_NEWNET with the host, so abstract-namespace sockets \
                     reach the host namespace directly — X11, the D-Bus session bus, and any \
                     daemon binding an abstract socket — with no Landlock, proxy, or BPF gate \
                     in the path. This is an IPC escape below the proxy layer (T1.13). \
                     abstract = \"allow\" is valid only when the kennel owns its CLONE_NEWNET \
                     (net.mode = none / constrained / unconstrained)"
                        .to_owned(),
                );
            }
            // When accepted (non-host mode): the Landlock ABI-6 abstract scope is the
            // defence-in-depth gate. On pre-ABI-6 kernels the scope silently does
            // nothing, so the net-ns boundary is the ONLY control. Warn the operator.
            // (We don't have the live ABI here — the warning is informational, keyed
            // on the grant existing rather than the runtime ABI, because compile runs
            // on any host and the settled artefact deploys to another.)
            if net_mode != "host" {
                warnings.push(
                    "[unix] abstract = \"allow\" accepted: abstract-namespace sockets are \
                     permitted within the kennel's own network namespace. Defence-in-depth \
                     requires Landlock ABI ≥ 6 (Scope::ABSTRACT_UNIX_SOCKET); on older kernels \
                     the network-namespace boundary is the only control"
                        .to_owned(),
                );
            }
        }
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
        // is a destination-blind signing oracle and the [ssh] bastion is the
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
                 an exposed agent is a destination-blind signing oracle. This is the intended \
                 job of the [ssh] section and the re-origination bastion — shim a raw agent only if \
                 you accept that any code in the kennel can sign for any destination"
            ));
        }
        // A gpg-agent socket is the same destination-blind oracle and WORSE: a signing
        // oracle stamps the user's verified identity permanently onto arbitrary artefacts
        // (malware, releases, forged commits), not just one authenticated session. There
        // is no bastion equivalent (commit signing is data-integrity, not transport — the
        // re-origination trick does not carry over, by design). Warned, not
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
                 (malware, releases, forged commits). There is no bastion equivalent. Shim \
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
            )]
            .into(),
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
            )]
            .into(),
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
            )]
            .into(),
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
            )]
            .into(),
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

    // ─── abstract = "allow" escape hatch ──────────────────────────────────

    /// Helper: build a policy with both `[unix]` and `[net]` sections.
    fn policy_with_net(unix: UnixSection, net_mode: Option<&str>) -> SourcePolicy {
        use crate::source::NetSection;
        SourcePolicy {
            unix: Some(unix),
            net: net_mode.map(|m| NetSection {
                mode: Some(m.to_owned()),
                ..NetSection::default()
            }),
            ..SourcePolicy::default()
        }
    }

    #[test]
    fn abstract_allow_accepted_with_constrained_mode() {
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        let warnings = validate(&policy_with_net(unix, Some("constrained")))
            .expect("abstract=allow with constrained mode should compile");
        assert!(warnings
            .iter()
            .any(|w| w.contains("abstract = \"allow\" accepted")));
    }

    #[test]
    fn abstract_allow_accepted_with_net_none() {
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        let warnings = validate(&policy_with_net(unix, Some("none")))
            .expect("abstract=allow with net.mode=none should compile");
        assert!(warnings.iter().any(|w| w.contains("ABI")));
    }

    #[test]
    fn abstract_allow_accepted_with_unconstrained_mode() {
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        validate(&policy_with_net(unix, Some("unconstrained")))
            .expect("abstract=allow with unconstrained mode should compile");
    }

    #[test]
    fn abstract_allow_without_explicit_net_mode_is_accepted() {
        // No [net] section → defaults to "constrained" → owns CLONE_NEWNET → accepted.
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        validate(&policy_with(unix))
            .expect("abstract=allow with default (constrained) mode should compile");
    }

    #[test]
    fn abstract_allow_with_host_mode_is_hard_error() {
        let unix = UnixSection {
            abstract_ns: Some("allow".to_owned()),
            ..UnixSection::default()
        };
        let err = validate(&policy_with_net(unix, Some("host")))
            .expect_err("abstract=allow with host mode must be a hard compile error");
        assert!(
            matches!(err, PolicyError::SourceValidation(ref m) if m.iter().any(|s| s.contains("T1.13"))),
            "error must cite T1.13: {err:?}"
        );
    }

    #[test]
    fn a_missing_real_or_shim_is_refused() {
        let unix = UnixSection {
            allow: vec![UnixAllow {
                name: Some("x".to_owned()),
                reason: Some("r".to_owned()),
                ..UnixAllow::default()
            }]
            .into(),
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
            )]
            .into(),
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
            )]
            .into(),
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
            allow: vec![a].into(),
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
            )]
            .into(),
        };
        assert!(validate(&policy_with(unix)).expect("valid").is_empty());
    }
}
