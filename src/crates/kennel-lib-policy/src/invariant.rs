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
    // A UDP grant is name-only by design; a "name" that is an address would resolve to itself
    // and be dialled. The compiler refuses one; so does the loader.
    for rule in &ep.net.udp_allow_names {
        if !crate::settled::host_pattern_ok(&rule.name) {
            v.push(InvariantViolation::new(
                "net.udp.allow.name",
                format!("`{}` is not a host name", rule.name),
            ));
        }
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
    unix_violations_into(policy, &mut v);
    compiled_rule_violations_into(policy, &mut v);
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
    for r in &ep.fs.redirect {
        if is_write_redirect(ep, r) {
            continue; // its source is meant to be written; it is checked as a writable path
        }
        for w in writable_surface(ep) {
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

/// Whether a redirect's view path is itself a write grant, which makes its *source*
/// workload-writable: that host path belongs to the writable surface too, under its own name.
fn is_write_redirect(ep: &crate::settled::EffectivePolicy, r: &crate::settled::FsRedirect) -> bool {
    ep.fs
        .write
        .iter()
        .chain(&ep.fs.exclusive)
        .any(|w| normalize_grant(w) == normalize_grant(&r.path))
}

/// The host paths the workload can write, as the policy states them: `write` ∪ `exclusive` ∪
/// `home_persist` ∪ the sources of write redirects. `[fs.cwd]` is not here; it is known only at
/// spawn.
fn writable_surface(ep: &crate::settled::EffectivePolicy) -> Vec<String> {
    ep.fs
        .write
        .iter()
        .chain(&ep.fs.exclusive)
        .map(|w| normalize_grant(w))
        .chain(ep.fs.home_persist.iter().map(|p| normalize_persist(p)))
        .chain(
            ep.fs
                .redirect
                .iter()
                .filter(|r| is_write_redirect(ep, r))
                .map(|r| normalize_grant(&r.source)),
        )
        .collect()
}

/// The `[unix]` floor: what a granted socket's two paths may be.
///
/// - `real` must not lie in the workload-writable surface. The daemon connects to whatever is at
///   that path when the workload asks, so a path the workload can replace is a grant of any socket
///   the operator can reach.
/// - `shim` (and the `at` of an af-unix `[[consumes]]`) must be a plain path below a directory of
///   its own ([`shim_path_ok`]): the in-kennel facade is given Landlock rights over the parent
///   directory to create the socket there.
fn unix_violations_into(policy: &SettledPolicy, v: &mut Vec<InvariantViolation>) {
    let writable = writable_surface(&policy.effective_policy);
    for sock in &policy.unix.sockets {
        if !shim_path_ok(&sock.shim) {
            v.push(InvariantViolation::new(
                "unix.shim",
                format!(
                    "[[unix.allow]] `{}`: shim `{}` is not a plain path below a directory of \
                     its own",
                    sock.name, sock.shim
                ),
            ));
        }
        if let Some(w) = writable.iter().find(|w| paths_intersect(&sock.real, w)) {
            v.push(InvariantViolation::new(
                "unix.real.write-set",
                format!(
                    "[[unix.allow]] `{}`: real path `{}` intersects the workload-writable path \
                     `{w}`; the workload could put another socket there",
                    sock.name, sock.real
                ),
            ));
        }
    }
    for consume in &policy.mesh.consumes {
        if consume.shape != crate::settled::Shape::AfUnix {
            continue;
        }
        if consume.at.as_deref().is_some_and(|at| !shim_path_ok(at)) {
            v.push(InvariantViolation::new(
                "mesh.at",
                format!(
                    "[[consumes]] `{}`: `at` is not a plain path below a directory of its own",
                    consume.name
                ),
            ));
        }
    }
}

/// Rules the compiler enforces on values that reach files, paths and fixed-size kernel maps.
///
/// A settled artefact can be signed without passing through the compiler, and a spawn patch
/// produces a policy the compiler never saw, so each rule is asserted again here with the same
/// predicate the compiler uses.
fn compiled_rule_violations_into(policy: &SettledPolicy, v: &mut Vec<InvariantViolation>) {
    use crate::settled::{
        account_name_ok, group_ref_ok, hostname_label_ok, sha256_hex_ok, MAX_BIND_PORTS,
    };
    let identity = &policy.identity;
    for (id, name) in [
        ("identity.user", &identity.user),
        ("identity.group", &identity.group),
    ] {
        if !account_name_ok(name) {
            v.push(InvariantViolation::new(
                id,
                "not a portable account name (`[a-z_][a-z0-9_-]*`, at most 32 characters)",
            ));
        }
    }
    // A supplementary group is looked up by name at spawn and written into `/etc/group`.
    if identity.groups.iter().any(|g| !group_ref_ok(g)) {
        v.push(InvariantViolation::new(
            "identity.groups",
            "a supplementary group's name cannot be written into /etc/group",
        ));
    }
    if identity
        .hostname
        .as_deref()
        .is_some_and(|h| !hostname_label_ok(h))
    {
        v.push(InvariantViolation::new(
            "identity.hostname",
            "not a hostname label (1 to 63 letters, digits or hyphens)",
        ));
    }
    let ports = policy.effective_policy.net.bind_allowed_ports.len();
    if ports > MAX_BIND_PORTS {
        v.push(InvariantViolation::new(
            "net.bind.allowed_ports",
            format!("{ports} ports; the bind map holds {MAX_BIND_PORTS}"),
        ));
    }
    if policy.workload.sha256.iter().any(|d| !sha256_hex_ok(d)) {
        v.push(InvariantViolation::new(
            "workload.sha256",
            "a digest is not 64 lowercase hex characters",
        ));
    }
}

/// Whether `shim` is an acceptable in-view socket path.
///
/// It must be rooted (`/`, `~/`, `$HOME/`, `$XDG_RUNTIME_DIR/` or `<home>/`), have no empty, `.`
/// or `..` component, and carry no `=` or NUL (the facade takes its sockets as `path=name`
/// arguments). An absolute path needs a directory between it and `/`: the facade is granted the
/// parent directory, and that must never be the root.
#[must_use]
pub fn shim_path_ok(shim: &str) -> bool {
    const ROOTS: [&str; 4] = ["~/", "$HOME/", "$XDG_RUNTIME_DIR/", "<home>/"];
    if shim.contains(['=', '\0']) {
        return false;
    }
    let (rest, least) = shim
        .strip_prefix('/')
        .map_or_else(
            || {
                ROOTS
                    .iter()
                    .find_map(|root| shim.strip_prefix(root))
                    .map(|rest| (rest, 1))
            },
            |rest| Some((rest, 2)),
        )
        .unwrap_or(("", usize::MAX));
    let mut count: usize = 0;
    for component in rest.split('/') {
        if matches!(component, "" | "." | "..") {
            return false;
        }
        count = count.saturating_add(1);
    }
    count >= least
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

    fn unix_violations(real: &str, shim: &str, write: &[&str]) -> Vec<&'static str> {
        let mut p = sample_settled();
        p.effective_policy
            .fs
            .write
            .extend(write.iter().map(|w| (*w).to_owned()));
        p.unix.sockets.push(crate::settled::UnixSocket {
            name: "s".to_owned(),
            real: real.to_owned(),
            shim: shim.to_owned(),
            env: None,
        });
        match validate(&p) {
            Ok(()) => Vec::new(),
            Err(v) => v
                .into_iter()
                .map(|x| x.id)
                .filter(|id| id.starts_with("unix."))
                .collect(),
        }
    }

    /// A socket the workload can replace is not the socket the operator granted.
    #[test]
    fn a_unix_grant_whose_real_path_is_workload_writable_is_refused() {
        for (real, write) in [
            ("~/proj/agent.sock", "~/proj/**"),
            ("~/proj/run/agent.sock", "~/proj"),
            ("/srv/data/./x/../agent.sock", "/srv/data/"),
        ] {
            assert_eq!(
                unix_violations(real, "/tmp/s.sock", &[write]),
                ["unix.real.write-set"],
                "`{real}` under `{write}`"
            );
        }
        assert!(unix_violations("~/.gnupg/S.gpg-agent", "/tmp/s.sock", &["~/proj/**"]).is_empty());
    }

    /// The facade gets Landlock rights over its shim's parent directory.
    #[test]
    fn a_unix_shim_that_is_not_a_plain_path_is_refused() {
        for shim in ["/x.sock", "x.sock", "/tmp/../x.sock", "/tmp/a=b.sock", ""] {
            assert_eq!(
                unix_violations("/run/host.sock", shim, &[]),
                ["unix.shim"],
                "shim `{shim}`"
            );
        }
        assert!(unix_violations("/run/host.sock", "~/x.sock", &[]).is_empty());
    }

    /// A UDP grant names a host. An address in that field would be dialled as itself.
    #[test]
    fn a_udp_grant_whose_name_is_an_address_is_refused() {
        for (name, refused) in [("10.0.0.5", true), ("::1", true), (".example.com", false)] {
            let mut p = sample_settled();
            p.effective_policy
                .net
                .udp_allow_names
                .push(crate::settled::NameRule {
                    name: name.to_owned(),
                    ports: Vec::new(),
                    protocol: crate::settled::Protocol::Udp,
                });
            let hit = validate(&p)
                .err()
                .is_some_and(|v| v.iter().any(|x| x.id == "net.udp.allow.name"));
            assert_eq!(hit, refused, "`{name}`");
        }
    }

    fn violation_ids(policy: &SettledPolicy) -> Vec<&'static str> {
        validate(policy).map_or_else(|v| v.into_iter().map(|x| x.id).collect(), |()| Vec::new())
    }

    /// The identity names reach `/etc/passwd`, `$HOME` and the hostname; the loader checks
    /// them with the compiler's own rule.
    #[test]
    fn identity_names_are_checked_at_load() {
        let mut p = sample_settled();
        p.identity.user = "x:0:0::/:/bin/sh\nroot".to_owned();
        p.identity.group = "../wheel".to_owned();
        p.identity.groups = vec!["Domain Users".to_owned(), "x:0:root".to_owned()];
        p.identity.hostname = Some("host\n127.0.0.1 evil".to_owned());
        let ids = violation_ids(&p);
        for id in [
            "identity.user",
            "identity.group",
            "identity.groups",
            "identity.hostname",
        ] {
            assert!(ids.contains(&id), "{id} missing from {ids:?}");
        }
    }

    #[test]
    fn the_bind_port_cap_and_digest_form_are_checked_at_load() {
        let mut p = sample_settled();
        p.effective_policy.net.bind_allowed_ports = (1..=9).map(|n| 8000 + n).collect();
        p.workload.sha256 = vec!["ABC".to_owned()];
        let ids = violation_ids(&p);
        assert!(ids.contains(&"net.bind.allowed_ports"), "{ids:?}");
        assert!(ids.contains(&"workload.sha256"), "{ids:?}");
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
