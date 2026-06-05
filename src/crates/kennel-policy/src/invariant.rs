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
    // net.mode is structurally constrained to constrained|open (no
    // `unrestricted` variant exists), but assert the allowed set explicitly so a
    // future schema addition cannot silently weaken it.
    match ep.net.mode {
        NetMode::Constrained | NetMode::Open => {}
    }
    if ep.net.deny_invariant.is_empty() {
        v.push(InvariantViolation::new(
            "net.deny.invariant",
            "the invariant deny CIDRs (cloud metadata, link-local, RFC1918) must be present",
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
