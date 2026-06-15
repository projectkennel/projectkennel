//! Framework-invariant re-assertion.
//!
//! Framework invariants (`docs/architecture/02-2-config-schema.md` §Invariants) are
//! re-checked against the `effective_policy` at runtime, even for a validly
//! signed settled policy: a signature proves *who* authored the policy, not that
//! it is safe. A settled policy that violates any invariant is refused at spawn.

use crate::settled::{NetMode, ProcVisibility, SettledPolicy};

/// A single framework-invariant violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantViolation {
    /// Stable identifier for the violated invariant.
    pub id: &'static str,
    /// Human-readable detail.
    pub detail: String,
}

impl InvariantViolation {
    fn new(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            detail: detail.into(),
        }
    }
}

/// Re-assert the framework invariants against `policy`'s effective rules.
///
/// # Errors
///
/// Returns every [`InvariantViolation`] found (not just the first), so the
/// caller can report them all.
pub fn validate(policy: &SettledPolicy) -> Result<(), Vec<InvariantViolation>> {
    let ep = &policy.effective_policy;
    let mut v = Vec::new();

    if !ep.cap.no_new_privs {
        v.push(InvariantViolation::new("cap.no_new_privs", "must be true"));
    }
    if !ep.exec.deny_setuid {
        v.push(InvariantViolation::new("exec.deny_setuid", "must be true"));
    }
    if !ep.exec.deny_setgid {
        v.push(InvariantViolation::new("exec.deny_setgid", "must be true"));
    }
    if !ep.exec.deny_setcap {
        v.push(InvariantViolation::new("exec.deny_setcap", "must be true"));
    }
    if !ep.exec.deny_writable {
        v.push(InvariantViolation::new(
            "exec.deny_writable",
            "must be true",
        ));
    }
    if !ep.fs.home_shadow {
        v.push(InvariantViolation::new(
            "fs.home.shadow",
            "the home shim is mandatory",
        ));
    }
    // net.mode is structurally one of the four tiers (no truly-unrestricted variant
    // exists), but assert the allowed set explicitly so a future schema addition cannot
    // silently weaken it. The mandatory invariant denies below apply in every mode.
    match ep.net.mode {
        NetMode::None | NetMode::Constrained | NetMode::Unconstrained | NetMode::Host => {}
    }
    // The one egress destination that is NEVER defensible: the cloud-metadata IPv4
    // (the SSRF crown jewel). It must be an invariant deny on every policy — enforced
    // deny-first by the proxy even in `open` mode. RFC1918/CGNAT are deliberately NOT
    // mandated here: making private space permanently unreachable is self-defeating
    // (local dev servers, LAN/corp services, private registries), so the floor leaves
    // them reachable via `host` mode or an explicit `[[net.proxy.allow]]`.
    let metadata_denied = ep
        .net
        .deny_invariant
        .iter()
        .any(|r| r.cidr == "169.254.169.254");
    if !metadata_denied {
        v.push(InvariantViolation::new(
            "net.proxy.deny.invariant",
            "the cloud-metadata deny (169.254.169.254) is mandatory and must not be removed",
        ));
    }
    match ep.proc.visibility {
        ProcVisibility::SelfOnly => {}
    }

    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}
