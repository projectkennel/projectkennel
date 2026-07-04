//! Framework-invariant re-assertion.
//!
//! Framework invariants are re-checked against the `effective_policy` at runtime,
//! even for a validly signed settled policy: a signature proves *who* authored the
//! policy, not that it is safe. A settled policy that violates any invariant is
//! refused at spawn.

use crate::settled::{NetMode, SettledPolicy};

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
    // The redirect floor (W15): a `source` must not intersect the workload-writable surface.
    // Signing authenticates the redirect's author, not its correctness — a signed `source`
    // inside the write set is a valid signature over a confused-deputy hole (the workload
    // writes the source, reads it back at `path` as operator-provided content). The writable
    // surface is `write` ∪ `exclusive` ∪ `home_persist` (persist paths are host-side state a
    // writable home grant carries across runs); `[fs.cwd]` — the one writable surface settle
    // cannot see — is floor-checked at spawn against the resolved cwd.
    for r in &ep.fs.redirect {
        let writable = ep
            .fs
            .write
            .iter()
            .chain(&ep.fs.exclusive)
            .map(|w| normalize_grant(w))
            .chain(ep.fs.home_persist.iter().map(|p| normalize_persist(p)));
        for w in writable {
            if paths_intersect(&r.source, &w) {
                v.push(InvariantViolation::new(
                    "fs.redirect.write-set",
                    format!(
                        "redirect source `{}` (for view path `{}`) intersects the \
                         workload-writable path `{w}`; a source the workload can write is a \
                         confused-deputy hole",
                        r.source, r.path
                    ),
                ));
            }
        }
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

/// A grant path with any trailing `/**` / `/*` glob stripped — the real tree root the
/// grant covers, comparable by prefix.
fn normalize_grant(entry: &str) -> String {
    entry
        .strip_suffix("/**")
        .or_else(|| entry.strip_suffix("/*"))
        .unwrap_or(entry)
        .to_owned()
}

/// A `home_persist` entry as the home-relative grant path it persists (`.claude` → `~/.claude`),
/// so it compares against `~`-prefixed sources like any write grant.
fn normalize_persist(entry: &str) -> String {
    if entry.starts_with('~') || entry.starts_with('/') {
        normalize_grant(entry)
    } else {
        format!("~/{}", normalize_grant(entry))
    }
}

/// Whether two grant paths intersect: equal, or either is a directory prefix of the other.
///
/// Both sides are policy-authored grant strings in the same namespace (`~`-relative or
/// absolute), so a literal component-boundary comparison is exact for what a settled policy
/// can express. A `source` that *contains* a writable path is as unsound as one contained by
/// it — part of the redirected tree is workload-authored — so the test is symmetric.
fn paths_intersect(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|r| r.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|r| r.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settled::{sample_settled, FsRedirect};

    /// The `fs.redirect.write-set` violations `validate` reports for `policy`.
    fn redirect_violations(policy: &SettledPolicy) -> Vec<String> {
        match validate(policy) {
            Ok(()) => Vec::new(),
            Err(v) => v
                .into_iter()
                .filter(|x| x.id == "fs.redirect.write-set")
                .map(|x| x.detail)
                .collect(),
        }
    }

    fn with_redirect(path: &str, source: &str) -> SettledPolicy {
        let mut p = sample_settled();
        p.effective_policy.fs.read.push(path.to_owned());
        p.effective_policy.fs.redirect.push(FsRedirect {
            path: path.to_owned(),
            source: source.to_owned(),
        });
        p
    }

    /// The floor (W15): a `source` covered by — or covering — any workload-writable path is
    /// refused, whether the writable surface is `write`, `exclusive`, or `home_persist`.
    #[test]
    fn redirect_source_intersecting_the_writable_surface_is_refused() {
        // Inside a write grant.
        let mut p = with_redirect("~/.app/cred.json", "~/data/store/cred.json");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "inside write");

        // Containing a write grant (part of the redirected tree is workload-authored).
        let mut p = with_redirect("~/.app", "~/stores/app");
        p.effective_policy
            .fs
            .write
            .push("~/stores/app/cache".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "contains write");

        // A glob write grant covers by its real root.
        let mut p = with_redirect("~/.app/cred.json", "~/data/cred.json");
        p.effective_policy.fs.write.push("~/data/**".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "glob write");

        // `home_persist` entries are home-relative; they intersect a `~`-form source.
        let mut p = with_redirect("~/.app/cred.json", "~/.claude/cred.json");
        p.effective_policy
            .fs
            .home_persist
            .push(".claude".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "home_persist");
    }

    /// A source outside every writable path passes; sibling paths do not intersect
    /// (`~/data` vs `~/database` share a string prefix but not a component).
    #[test]
    fn redirect_source_outside_the_writable_surface_passes() {
        let mut p = with_redirect("~/.app/cred.json", "~/stores/app/cred.json");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert!(redirect_violations(&p).is_empty());

        let mut p = with_redirect("~/.app/cred.json", "~/database/cred.json");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert!(redirect_violations(&p).is_empty(), "sibling prefix");
    }
}
