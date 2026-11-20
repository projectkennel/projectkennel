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

    // A mesh `name`/`key` becomes a component of a host path the daemon creates and binds, so it
    // must be one safe component. The compiler enforces this; re-assert it here because a settled
    // artefact can be signed without ever passing through the compiler.
    for (kind, name, key) in policy
        .mesh
        .provides
        .iter()
        .map(|p| ("provides", &p.name, &p.key))
        .chain(
            policy
                .mesh
                .consumes
                .iter()
                .map(|c| ("consumes", &c.name, &c.key)),
        )
    {
        if !crate::meshname::name_ok(name) {
            v.push(InvariantViolation::new(
                "mesh.name",
                format!("[[{kind}]] name is not a well-formed capability name"),
            ));
        }
        if key.as_deref().is_some_and(|k| !crate::meshname::key_ok(k)) {
            v.push(InvariantViolation::new(
                "mesh.key",
                format!("[[{kind}]] key is not a well-formed token"),
            ));
        }
    }

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
    address_rule_violations(&ep.net, &mut v);
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
    // The deny must be the whole address: every port, every protocol. An entry that names the
    // address but only one port would satisfy a check on the address alone and deny nothing
    // that matters.
    let metadata_denied = ep.net.deny_invariant.iter().any(|r| {
        r.cidr == "169.254.169.254"
            && r.prefix_len == 32
            && r.port_min == 0
            && r.port_max == u16::MAX
            && r.protocol == crate::settled::Protocol::Any
    });
    if !metadata_denied {
        v.push(InvariantViolation::new(
            "net.proxy.deny.invariant",
            "the cloud-metadata deny (169.254.169.254) is mandatory and must not be removed",
        ));
    }
    redirect_violations_into(ep, &mut v);
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

/// The redirect floor (W15): a `source` must not intersect the workload-writable surface.
/// Signing authenticates the redirect's author, not its correctness — a signed `source`
/// inside the write set is a valid signature over a confused-deputy hole (the workload
/// writes the source, reads it back at `path` as operator-provided content). The writable
/// surface is `write` ∪ `exclusive` ∪ `home_persist` (persist paths are host-side state a
/// writable home grant carries across runs); `[fs.cwd]` — the one writable surface settle
/// cannot see — is floor-checked at spawn against the resolved cwd.
fn redirect_violations_into(ep: &crate::settled::EffectivePolicy, v: &mut Vec<InvariantViolation>) {
    // A redirect whose view path is itself a write grant makes its *source* workload-writable:
    // that host path belongs to the writable surface too, under its own name.
    let is_write_redirect = |r: &crate::settled::FsRedirect| {
        ep.fs
            .write
            .iter()
            .chain(&ep.fs.exclusive)
            .any(|w| normalize_grant(w) == normalize_grant(&r.path))
    };
    for r in &ep.fs.redirect {
        if is_write_redirect(r) {
            continue; // its source is meant to be written; it is checked as a writable path
        }
        let writable = ep
            .fs
            .write
            .iter()
            .chain(&ep.fs.exclusive)
            .map(|w| normalize_grant(w))
            .chain(ep.fs.home_persist.iter().map(|p| normalize_persist(p)))
            .chain(
                ep.fs
                    .redirect
                    .iter()
                    .filter(|w| is_write_redirect(w))
                    .map(|w| normalize_grant(&w.source)),
            );
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
}

/// Report every address rule the enforcement side could not match on.
///
/// The proxy and the BPF loader parse these literals; one that does not parse would be skipped
/// there, and a deny that is skipped is a deny the author believes in and does not have. The
/// compiler refuses such a rule; this re-asserts it for an artefact signed without passing
/// through it.
fn address_rule_violations(net: &crate::settled::NetPolicy, v: &mut Vec<InvariantViolation>) {
    for (list, rules) in [
        ("net.allow", &net.allow),
        ("net.proxy.deny.invariant", &net.deny_invariant),
        ("net.proxy.deny.policy", &net.deny_author),
        ("net.bpf.connect.allow", &net.bpf_connect_allow),
        ("net.bpf.connect.deny", &net.bpf_connect_deny),
        ("net.bpf.bind.allow", &net.bpf_bind_allow),
        ("net.bpf.bind.deny", &net.bpf_bind_deny),
    ] {
        for rule in rules {
            if let Some(problem) = address_rule_problem(&rule.cidr, rule.prefix_len) {
                v.push(InvariantViolation::new(
                    list,
                    format!("`{}/{}` {problem}", rule.cidr, rule.prefix_len),
                ));
            }
        }
    }
}

/// Why an address rule cannot be enforced, or `None` if it can: the address must be an IP literal
/// and the prefix must fit its family.
fn address_rule_problem(addr: &str, prefix_len: u8) -> Option<&'static str> {
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return Some("is not an IP address, so no rule can match on it");
    };
    let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
    (prefix_len > width).then_some("has a prefix longer than its address")
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
/// absolute). The comparison is by PATH COMPONENT, not by raw string prefix: a raw
/// `strip_prefix` is fooled by a trailing `/` on either side (`"~/data/cred.json"` does not
/// string-prefix-match `"~/data/"`, so the confused-deputy source slips the floor) and by a
/// `.`/`..` component. So each side is split into components with `.`/`""` dropped and `..`
/// collapsed, and one must be a component-prefix of the other. A `source` that *contains* a
/// writable path is as unsound as one contained by it — part of the redirected tree is
/// workload-authored — so the test is symmetric.
fn paths_intersect(a: &str, b: &str) -> bool {
    // One is a component-prefix of the other iff every zipped (shorter-length) component is equal —
    // `zip` stops at the shorter side, so this is the `a[..n] == b[..n]` prefix test without slicing.
    clean_components(a)
        .iter()
        .zip(clean_components(b).iter())
        .all(|(x, y)| x == y)
}

/// A path's components with `""`/`.` dropped and `..` collapsed (popping the prior component,
/// clamped at the root). Lexical only — the floor is a structural check on grant strings, and
/// non-canonical redirect `source`s are already refused at translate, so this is the runtime
/// re-assertion's defense-in-depth against a trailing slash or a stray `.`/`..`.
fn clean_components(p: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
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

    /// The metadata deny is only the invariant if it covers the whole address.
    #[test]
    fn a_metadata_deny_limited_to_one_port_does_not_satisfy_the_floor() {
        let mut p = sample_settled();
        for rule in &mut p.effective_policy.net.deny_invariant {
            if rule.cidr == "169.254.169.254" {
                rule.port_min = 81;
                rule.port_max = 81;
            }
        }
        let violations = validate(&p).expect_err("refused");
        assert!(violations
            .iter()
            .any(|x| x.id == "net.proxy.deny.invariant"));
    }

    /// A deny whose address does not parse would be skipped by the proxy, so it is refused at
    /// load instead of being honoured as a deny that matches nothing.
    #[test]
    fn an_address_rule_that_cannot_be_matched_is_refused() {
        assert!(validate(&sample_settled()).is_ok(), "the fixture is valid");
        for (cidr, prefix_len) in [("10.0.0/8", 8), ("metadata.internal", 32), ("10.0.0.0", 33)] {
            let mut p = sample_settled();
            let mut rule = p
                .effective_policy
                .net
                .deny_invariant
                .first()
                .cloned()
                .expect("the fixture carries the metadata deny");
            cidr.clone_into(&mut rule.cidr);
            rule.prefix_len = prefix_len;
            p.effective_policy.net.deny_author.push(rule);
            let violations = validate(&p).expect_err("refused");
            assert!(
                violations.iter().any(|x| x.id == "net.proxy.deny.policy"),
                "`{cidr}/{prefix_len}` must be refused"
            );
        }
    }

    /// The host side of a writable redirect is writable: a read redirect served from inside it
    /// is refused, though no `write` grant names that host path.
    #[test]
    fn the_source_of_a_write_redirect_counts_as_writable() {
        let mut p = with_redirect("~/.app/cred.json", "~/stores/app/cred.json");
        p.effective_policy.fs.write.push("~/work".to_owned());
        p.effective_policy.fs.redirect.push(FsRedirect {
            path: "~/work".to_owned(),
            source: "~/stores/app".to_owned(),
        });
        assert_eq!(redirect_violations(&p).len(), 1);
        // Unrelated host paths: no violation, and the write redirect itself is not one.
        let mut p = with_redirect("~/.app/cred.json", "~/stores/app/cred.json");
        p.effective_policy.fs.write.push("~/work".to_owned());
        p.effective_policy.fs.redirect.push(FsRedirect {
            path: "~/work".to_owned(),
            source: "~/scratch".to_owned(),
        });
        assert!(redirect_violations(&p).is_empty());
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

    /// Regression (W8 ship-gate): the floor compares by PATH COMPONENT, so a trailing `/` on
    /// either side — or a `.`/`..` segment — cannot slip a confused-deputy source past it. The
    /// raw-`strip_prefix` floor accepted `write = "~/data/"` with `source = "~/data/cred.json"`.
    #[test]
    fn redirect_floor_not_fooled_by_trailing_slash_or_dot_segments() {
        // The confirmed bypass: a trailing slash on the write grant.
        let mut p = with_redirect("~/.app/cred.json", "~/data/cred.json");
        p.effective_policy.fs.write.push("~/data/".to_owned());
        assert_eq!(
            redirect_violations(&p).len(),
            1,
            "trailing-slash write grant"
        );

        // Trailing slash on the source side.
        let mut p = with_redirect("~/.app/cred.json", "~/data/cred.json/");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "trailing-slash source");

        // `.`/`..` collapse to the same real tree (defense-in-depth; translate also rejects `..`).
        let mut p = with_redirect("~/.app/cred.json", "~/data/./sub/../cred.json");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert_eq!(redirect_violations(&p).len(), 1, "dot/dotdot source");

        // A genuine sibling still passes — the component compare adds no false positive.
        let mut p = with_redirect("~/.app/cred.json", "~/data-other/cred.json");
        p.effective_policy.fs.write.push("~/data".to_owned());
        assert!(
            redirect_violations(&p).is_empty(),
            "sibling not intersecting"
        );
    }
}
