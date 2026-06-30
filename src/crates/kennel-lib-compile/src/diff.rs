//! Effective-policy diff: the interpreted `+`/`~`/`-` grant delta between two
//! resolved (folded) source policies, annotated with threat impact.
//!
//! `kennel policy diff` answers a question neither `policy show` (full effective
//! dump) nor `policy upgrade` (raw source line diff) answers: *which grants
//! widened or narrowed, and what does each change cost in threat exposure*. It is
//! the semantic counterpart of the line diff —/
//!
//! The engine is pure over two folded [`SourcePolicy`] values (the same honest
//! input the [risk engine](crate::risks) reads — threat tags live only in source,
//! never the settled artefact). The caller resolves both sides; this module does
//! no I/O. The two common pairings are:
//!
//! - **leaf vs its template baseline** — what the leaf's own deltas add over the
//!   template it inherits (the "your deltas" view), and
//! - **two policies** — an org baseline against a user policy, or a before/after
//!   across an upgrade.
//!
//! Both reduce to: enumerate each side's capability surface into comparable grant
//! atoms, match by a stable key, and classify each into added / removed / changed.
//! Each change carries the granting site, its `reason`, the threats it exposes or
//! mitigates (resolved against the [catalogue](crate::threats)), and — where the
//! direction is unambiguous — an honest impact note. A net **threat delta**
//! summary (reusing [`crate::risks::evaluate`] on both sides) reports which threats
//! the change newly exposes, stops exposing, newly mitigates, or stops mitigating.
//!
//! The public types derive [`serde::Serialize`] so the CLI can emit a structured
//! `--json` delta through a real serialiser (no hand-rolled JSON).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::risks;
use crate::source::{SourcePolicy, Threats};
use crate::threats::Catalogue;

/// Whether a grant grants capability (`Allow`), removes it (`Deny`), or is a
/// scalar knob (`Scalar`). Polarity decides which direction of a change *widens*
/// the workload's reach: adding an allow or removing a deny widens; adding a deny
/// or removing an allow narrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polarity {
    Allow,
    Deny,
    Scalar,
}

/// One comparable capability atom extracted from a folded policy.
#[derive(Debug, Clone)]
struct Grant {
    /// Stable identity for matching the same grant across the two sides
    /// (`net.proxy.allow:api.x.com`). Two grants with the same key are "the same
    /// grant"; a differing [`value`](Self::value) makes it a *modification*.
    key: String,
    /// Display label for the carrier (`[[net.proxy.allow]] api.x.com`).
    carrier: String,
    /// Section bucket for grouping/ordering the output (see [`rank`]).
    section: &'static str,
    /// The comparable value beyond identity (ports, flags, the scalar's value).
    /// Equal keys with differing values are reported as `~` modifications.
    value: String,
    /// The grant's documented `reason`, if any.
    reason: Option<String>,
    /// Threat ids this grant exposes (authored tags + compiler-derived exposures).
    exposed: Vec<String>,
    /// Threat ids this grant mitigates (authored tags).
    mitigated: Vec<String>,
    /// Allow / deny / scalar — drives the widening determination.
    polarity: Polarity,
}

/// A threat resolved against the catalogue for display.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatRef {
    /// The threat id (`T1.6`).
    pub id: String,
    /// The catalogue title, or `None` when the id is not catalogued (a likely typo).
    pub title: Option<String>,
    /// The one-line catalogue residual (empty when uncatalogued).
    pub residual: String,
}

/// How a grant changed between the two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// Present on the new side, absent on the old (`+`).
    Added,
    /// Present on the old side, absent on the new (`-`).
    Removed,
    /// Present on both, but the value differs (`~`).
    Modified,
}

/// One grant-level change between the two policies.
#[derive(Debug, Clone, Serialize)]
pub struct GrantChange {
    /// Added / removed / modified.
    pub kind: ChangeKind,
    /// The carrier label (`[[net.proxy.allow]] api.x.com`).
    pub carrier: String,
    /// For a modification, `"<old> → <new>"`; for add/remove, the single value
    /// (empty when the carrier label already says everything).
    pub detail: String,
    /// The grant's documented `reason` (the *new* side's, for a modification).
    pub reason: Option<String>,
    /// Threats this grant exposes, resolved against the catalogue.
    pub exposed: Vec<ThreatRef>,
    /// Threats this grant mitigates, resolved against the catalogue.
    pub mitigated: Vec<ThreatRef>,
    /// Whether this change *widens* the workload's reach (a louder change: a new
    /// allow, or a removed deny). Narrowing changes are reassuring; widening ones
    /// are what a reviewer must weigh.
    pub widening: bool,
    /// An honest one-line impact note for the unambiguous cases (a removed deny
    /// weakens; a permissive `exec.allow` runs anything), else `None`.
    pub note: Option<String>,
}

/// The net change in threat posture between the two policies (reusing the risk
/// engine on each side and differencing the exposed/mitigated sets).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ThreatDelta {
    /// Threats the new side exposes that the old side did not.
    pub newly_exposed: Vec<ThreatRef>,
    /// Threats the old side exposed that the new side no longer does.
    pub no_longer_exposed: Vec<ThreatRef>,
    /// Threats the new side mitigates that the old side did not.
    pub newly_mitigated: Vec<ThreatRef>,
    /// Threats the old side mitigated that the new side no longer does.
    pub no_longer_mitigated: Vec<ThreatRef>,
}

impl ThreatDelta {
    /// Whether the threat posture is unchanged in both directions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.newly_exposed.is_empty()
            && self.no_longer_exposed.is_empty()
            && self.newly_mitigated.is_empty()
            && self.no_longer_mitigated.is_empty()
    }
}

/// The full interpreted diff between two effective policies.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDiff {
    /// The catalogue version the threat annotations used.
    pub catalogue_version: String,
    /// Every grant-level change, ordered by section then carrier.
    pub changes: Vec<GrantChange>,
    /// The net threat-posture delta.
    pub summary: ThreatDelta,
}

impl PolicyDiff {
    /// Whether the two policies have an identical capability surface.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Diff `old` → `new` (both folded effective source policies), annotating each
/// change against `catalogue`.
///
/// The result reads "what `new` does that `old` did not": added grants are in
/// `new`, removed grants were in `old`.
#[must_use]
pub fn diff(old: &SourcePolicy, new: &SourcePolicy, catalogue: &Catalogue) -> PolicyDiff {
    let old_grants = index(grants(old));
    let new_grants = index(grants(new));

    let mut keys: Vec<&String> = old_grants.keys().chain(new_grants.keys()).collect();
    keys.sort();
    keys.dedup();

    // Pair each change with its section rank so the output groups by subsystem.
    let mut ranked: Vec<(u8, GrantChange)> = Vec::new();
    for key in keys {
        match (old_grants.get(key), new_grants.get(key)) {
            (None, Some(n)) => {
                ranked.push((
                    rank(n.section),
                    change(ChangeKind::Added, n, n.value.clone(), catalogue),
                ));
            }
            (Some(o), None) => {
                ranked.push((
                    rank(o.section),
                    change(ChangeKind::Removed, o, o.value.clone(), catalogue),
                ));
            }
            (Some(o), Some(n)) if o.value != n.value => {
                let detail = format!("{} \u{2192} {}", o.value, n.value);
                ranked.push((
                    rank(n.section),
                    change(ChangeKind::Modified, n, detail, catalogue),
                ));
            }
            _ => {} // present on both, unchanged
        }
    }

    // Stable, readable ordering: by section, then by carrier within a section.
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.carrier.cmp(&b.1.carrier)));
    let changes = ranked.into_iter().map(|(_, c)| c).collect();

    PolicyDiff {
        catalogue_version: catalogue.version.clone(),
        changes,
        summary: threat_delta(old, new, catalogue),
    }
}

/// Build a [`GrantChange`] from a matched grant and a precomputed `detail` string.
fn change(kind: ChangeKind, g: &Grant, detail: String, catalogue: &Catalogue) -> GrantChange {
    let widening = match g.polarity {
        Polarity::Allow => kind == ChangeKind::Added,
        Polarity::Deny => kind == ChangeKind::Removed,
        // A scalar modification is louder when it adds exposure; otherwise it is
        // merely a change the reader judges from the old → new value.
        Polarity::Scalar => kind != ChangeKind::Removed && !g.exposed.is_empty(),
    };
    GrantChange {
        kind,
        carrier: g.carrier.clone(),
        reason: g.reason.clone(),
        // Suppress the detail line when the carrier label already shows it (a
        // simple path/identity grant); keep it for ports and `old → new` changes.
        detail: if g.carrier.contains(&detail) {
            String::new()
        } else {
            detail
        },
        exposed: g
            .exposed
            .iter()
            .map(|id| resolve_ref(id, catalogue))
            .collect(),
        mitigated: g
            .mitigated
            .iter()
            .map(|id| resolve_ref(id, catalogue))
            .collect(),
        widening,
        note: note(kind, g),
    }
}

/// The unambiguous impact note for a change, or `None` when the carrier + threats
/// already say everything (no invented risk — `footgun-warn-dont-forbid`).
fn note(kind: ChangeKind, g: &Grant) -> Option<String> {
    match (kind, g.polarity) {
        (ChangeKind::Removed, Polarity::Deny) => {
            Some("weakens: a deny was removed — the floor is lower".to_owned())
        }
        (ChangeKind::Removed, Polarity::Allow) => {
            Some("no longer granted — a workload relying on it fails".to_owned())
        }
        (ChangeKind::Added, Polarity::Allow) if is_permissive_exec(&g.value) => {
            Some("permissive: this runs any executable in the view".to_owned())
        }
        _ => None,
    }
}

/// Whether an `exec.allow` value is the permissive `**`/`/**` opt-out.
fn is_permissive_exec(value: &str) -> bool {
    matches!(value.trim(), "**" | "/**")
}

/// Resolve a threat id against the catalogue (uncatalogued ⇒ bare id, no title).
fn resolve_ref(id: &str, catalogue: &Catalogue) -> ThreatRef {
    catalogue.lookup(id).map_or_else(
        || ThreatRef {
            id: id.to_owned(),
            title: None,
            residual: String::new(),
        },
        |e| ThreatRef {
            id: id.to_owned(),
            title: Some(e.title.clone()),
            residual: e.residual.clone(),
        },
    )
}

/// Index grants by key; the first wins on a (rare, folded) duplicate key.
fn index(grants: Vec<Grant>) -> BTreeMap<String, Grant> {
    let mut map = BTreeMap::new();
    for g in grants {
        map.entry(g.key.clone()).or_insert(g);
    }
    map
}

/// The net threat-posture delta: run the risk engine on each side and difference
/// the exposed / mitigated id sets.
fn threat_delta(old: &SourcePolicy, new: &SourcePolicy, catalogue: &Catalogue) -> ThreatDelta {
    let o = risks::evaluate(old, catalogue);
    let n = risks::evaluate(new, catalogue);
    let exposed = |r: &risks::RiskReport| ids(&r.exposures);
    let mitig = |r: &risks::RiskReport| ids(&r.mitigations);
    let (oe, ne) = (exposed(&o), exposed(&n));
    let (om, nm) = (mitig(&o), mitig(&n));
    ThreatDelta {
        newly_exposed: diff_ids(&ne, &oe, catalogue),
        no_longer_exposed: diff_ids(&oe, &ne, catalogue),
        newly_mitigated: diff_ids(&nm, &om, catalogue),
        no_longer_mitigated: diff_ids(&om, &nm, catalogue),
    }
}

/// The distinct threat ids in a finding list, sorted.
fn ids(findings: &[risks::Finding]) -> Vec<String> {
    let mut v: Vec<String> = findings.iter().map(|f| f.threat_id.clone()).collect();
    v.sort();
    v.dedup();
    v
}

/// The ids in `a` not in `b`, resolved against the catalogue.
fn diff_ids(a: &[String], b: &[String], catalogue: &Catalogue) -> Vec<ThreatRef> {
    a.iter()
        .filter(|id| !b.contains(id))
        .map(|id| resolve_ref(id, catalogue))
        .collect()
}

/// A coarse rank for grouping the changes by subsystem in the output.
fn rank(section: &str) -> u8 {
    match section {
        "exec" => 0,
        "fs" => 1,
        "net" => 2,
        "unix" => 3,
        "ssh" => 4,
        "binder" => 5,
        "mesh" => 6,
        "identity" => 7,
        "workload" => 8,
        _ => 9, // lifecycle / tty / trust and other posture toggles
    }
}

/// One carrier label, distinguishing a per-entry grant by its identity.
fn label(section: &str, ident: Option<&str>) -> String {
    ident.map_or_else(|| section.to_owned(), |id| format!("{section} {id}"))
}

/// Enumerate a folded policy's capability surface into comparable grant atoms.
/// The surface covered is the one that shapes confinement and threat exposure —
/// the same carriers the risk engine reads, plus the core capability lists
/// (`exec`/`fs`) and the scalar posture knobs. Audit-tuning and env-curation
/// knobs that do not change what the workload can reach are intentionally omitted.
#[allow(clippy::too_many_lines)] // a flat, cohesive enumeration of every carrier.
fn grants(p: &SourcePolicy) -> Vec<Grant> {
    let mut out: Vec<Grant> = Vec::new();

    // [exec] — the execve allowlist.
    if let Some(exec) = &p.exec {
        for path in exec.allow.iter().flatten() {
            out.push(Grant {
                key: format!("exec.allow:{path}"),
                carrier: format!("[[exec.allow]] {path}"),
                section: "exec",
                value: path.clone(),
                reason: None,
                exposed: Vec::new(),
                mitigated: Vec::new(),
                polarity: Polarity::Allow,
            });
        }
    }

    // [fs] — read/write grants and host-device passthrough.
    if let Some(fs) = &p.fs {
        for path in fs.read.iter().flatten() {
            out.push(simple_allow("fs.read", "fs", "[[fs.read]]", path));
        }
        for path in fs.write.iter().flatten() {
            out.push(simple_allow("fs.write", "fs", "[[fs.write]]", path));
        }
        if let Some(dev) = &fs.dev {
            for pt in &dev.passthrough {
                let path = pt.path.as_deref().unwrap_or("(device)");
                out.push(Grant {
                    key: format!("fs.dev.passthrough:{path}"),
                    carrier: label("[[fs.dev.passthrough]]", pt.path.as_deref()),
                    section: "fs",
                    value: path.to_owned(),
                    reason: pt.reason.clone(),
                    // Authored tags plus the compiler-derived T2.1 (mirrors `risks`).
                    exposed: exposed_with(pt.threats.as_ref(), &["T2.1"]),
                    mitigated: mitigated_of(pt.threats.as_ref()),
                    polarity: Polarity::Allow,
                });
            }
        }
    }

    if let Some(net) = &p.net {
        // [net] mode — the posture scalar; host mode derives T1.6 (mirrors `risks`).
        if let Some(mode) = &net.mode {
            out.push(Grant {
                key: "net.mode".to_owned(),
                carrier: "[net] mode".to_owned(),
                section: "net",
                value: mode.clone(),
                reason: net.reason.clone(),
                exposed: if mode == "host" {
                    vec!["T1.6".to_owned()]
                } else {
                    Vec::new()
                },
                mitigated: Vec::new(),
                polarity: Polarity::Scalar,
            });
        }
        if let Some(proxy) = &net.proxy {
            for a in &proxy.allow {
                let ident = a.name.as_deref().or(a.cidr.as_deref());
                out.push(Grant {
                    key: format!("net.proxy.allow:{}", ident.unwrap_or("?")),
                    carrier: label("[[net.proxy.allow]]", ident),
                    section: "net",
                    value: ports_value(&a.ports),
                    reason: a.reason.clone(),
                    exposed: exposed_of(a.threats.as_ref()),
                    mitigated: mitigated_of(a.threats.as_ref()),
                    polarity: Polarity::Allow,
                });
            }
            if let Some(deny) = &proxy.deny {
                for (kind, rule) in deny
                    .invariant
                    .iter()
                    .map(|r| ("invariant", r))
                    .chain(deny.policy.iter().map(|r| ("policy", r)))
                {
                    out.push(Grant {
                        key: format!("net.proxy.deny.{kind}:{}", rule.cidr),
                        carrier: label(&format!("[[net.proxy.deny.{kind}]]"), Some(&rule.cidr)),
                        section: "net",
                        value: rule.cidr.clone(),
                        reason: rule.reason.clone(),
                        exposed: exposed_of(rule.threats.as_ref()),
                        mitigated: mitigated_of(rule.threats.as_ref()),
                        polarity: Polarity::Deny,
                    });
                }
            }
        }
        if let Some(bpf) = &net.bpf {
            for (sect, acl) in [("connect", &bpf.connect), ("bind", &bpf.bind)] {
                let Some(acl) = acl else { continue };
                for (pol, rule) in acl
                    .allow
                    .iter()
                    .map(|r| (Polarity::Allow, r))
                    .chain(acl.deny.iter().map(|r| (Polarity::Deny, r)))
                {
                    let dir = if pol == Polarity::Allow {
                        "allow"
                    } else {
                        "deny"
                    };
                    let cidr = rule.cidr.as_deref().unwrap_or("*");
                    out.push(Grant {
                        key: format!("net.bpf.{sect}.{dir}:{cidr}:{}", ports_value(&rule.ports)),
                        carrier: label(&format!("[[net.bpf.{sect}.{dir}]]"), Some(cidr)),
                        section: "net",
                        value: ports_value(&rule.ports),
                        reason: rule.reason.clone(),
                        exposed: exposed_of(rule.threats.as_ref()),
                        mitigated: mitigated_of(rule.threats.as_ref()),
                        polarity: pol,
                    });
                }
            }
        }
    }

    // [unix] — granted AF_UNIX sockets.
    if let Some(unix) = &p.unix {
        for a in &unix.allow {
            let ident = a.name.as_deref().or(a.real.as_deref());
            out.push(Grant {
                key: format!("unix.allow:{}", ident.unwrap_or("?")),
                carrier: label("[[unix.allow]]", ident),
                section: "unix",
                value: a.real.clone().unwrap_or_default(),
                reason: a.reason.clone(),
                exposed: exposed_of(a.threats.as_ref()),
                mitigated: mitigated_of(a.threats.as_ref()),
                polarity: Polarity::Allow,
            });
        }
    }

    // [ssh] — the headless scalar and the egress destinations.
    if let Some(ssh) = &p.ssh {
        if let Some(headless) = ssh.allow_headless {
            out.push(Grant {
                key: "ssh.allow_headless".to_owned(),
                carrier: "[ssh] allow_headless".to_owned(),
                section: "ssh",
                value: headless.to_string(),
                reason: None,
                exposed: if headless {
                    exposed_with(ssh.threats.as_ref(), &["T1.6"])
                } else {
                    exposed_of(ssh.threats.as_ref())
                },
                mitigated: mitigated_of(ssh.threats.as_ref()),
                polarity: Polarity::Scalar,
            });
        }
        for d in &ssh.destinations {
            let dest = d.dest.as_deref().unwrap_or("(dest)");
            out.push(Grant {
                key: format!("ssh.destination:{dest}"),
                carrier: label("[[ssh.destinations]]", d.dest.as_deref()),
                section: "ssh",
                value: if d.options.is_empty() {
                    dest.to_owned()
                } else {
                    format!("{dest} ({})", d.options.join(" "))
                },
                reason: d.reason.clone(),
                exposed: exposed_of(d.threats.as_ref()),
                mitigated: mitigated_of(d.threats.as_ref()),
                polarity: Polarity::Allow,
            });
        }
    }

    // [[provides]] / [[consumes]] — the cross-kennel capability mesh. Top-level,
    // distinguished by capability name; the shape is the grant's value.
    for prov in &p.provides {
        out.push(Grant {
            key: format!("provides:{}", prov.name.as_deref().unwrap_or("?")),
            carrier: label("[[provides]]", prov.name.as_deref()),
            section: "mesh",
            value: prov
                .shape
                .map(|s| s.as_str().to_owned())
                .unwrap_or_default(),
            reason: prov.reason.clone(),
            exposed: exposed_of(prov.threats.as_ref()),
            mitigated: mitigated_of(prov.threats.as_ref()),
            polarity: Polarity::Allow,
        });
    }
    for cons in &p.consumes {
        out.push(Grant {
            key: format!("consumes:{}", cons.name.as_deref().unwrap_or("?")),
            carrier: label("[[consumes]]", cons.name.as_deref()),
            section: "mesh",
            value: cons
                .shape
                .map(|s| s.as_str().to_owned())
                .unwrap_or_default(),
            reason: cons.reason.clone(),
            exposed: exposed_of(cons.threats.as_ref()),
            mitigated: mitigated_of(cons.threats.as_ref()),
            polarity: Polarity::Allow,
        });
    }

    // [identity] — retained supplementary groups.
    if let Some(identity) = &p.identity {
        for group in &identity.groups {
            out.push(simple_allow(
                "identity.group",
                "identity",
                "[identity] groups",
                group,
            ));
        }
    }

    // [workload] — argv and the binary pins (scalar posture).
    if let Some(w) = &p.workload {
        if let Some(argv) = &w.argv {
            out.push(scalar(
                "workload.argv",
                "workload",
                "[workload] argv",
                argv.join(" "),
            ));
        }
        if let Some(pinned) = w.pinned {
            out.push(scalar(
                "workload.pinned",
                "workload",
                "[workload] pinned",
                pinned.to_string(),
            ));
        }
        if let Some(sha) = &w.sha256 {
            if !sha.is_empty() {
                out.push(scalar(
                    "workload.sha256",
                    "workload",
                    "[workload] sha256",
                    format!("{} pin(s)", sha.len()),
                ));
            }
        }
    }

    // [lifecycle] / [tty] / [trust] — the remaining posture toggles.
    if let Some(lc) = &p.lifecycle {
        if let Some(ttl) = &lc.ttl {
            out.push(scalar(
                "lifecycle.ttl",
                "misc",
                "[lifecycle] ttl",
                ttl.clone(),
            ));
        }
        if let Some(action) = &lc.ttl_action {
            out.push(scalar(
                "lifecycle.ttl_action",
                "misc",
                "[lifecycle] ttl_action",
                action.clone(),
            ));
        }
    }
    if let Some(tty) = &p.tty {
        if let Some(f) = tty.filter_terminal_escapes {
            out.push(scalar(
                "tty.filter_terminal_escapes",
                "misc",
                "[tty] filter_terminal_escapes",
                f.to_string(),
            ));
        }
    }
    if let Some(trust) = &p.trust {
        if let Some(m) = trust.manifest {
            out.push(scalar(
                "trust.manifest",
                "misc",
                "[trust] manifest",
                m.to_string(),
            ));
        }
    }

    out
}

/// A capability-list allow atom carrying no threat tags (its identity *is* its value).
fn simple_allow(
    prefix: &'static str,
    section: &'static str,
    carrier_section: &str,
    path: &str,
) -> Grant {
    Grant {
        key: format!("{prefix}:{path}"),
        carrier: format!("{carrier_section} {path}"),
        section,
        value: path.to_owned(),
        reason: None,
        exposed: Vec::new(),
        mitigated: Vec::new(),
        polarity: Polarity::Allow,
    }
}

/// A scalar posture atom (its value is the comparable; a change is a modification).
fn scalar(key: &str, section: &'static str, carrier: &str, value: String) -> Grant {
    Grant {
        key: key.to_owned(),
        carrier: carrier.to_owned(),
        section,
        value,
        reason: None,
        exposed: Vec::new(),
        mitigated: Vec::new(),
        polarity: Polarity::Scalar,
    }
}

/// The exposed tags of an optional `threats`, or empty.
fn exposed_of(t: Option<&Threats>) -> Vec<String> {
    t.map(|t| t.exposed.clone()).unwrap_or_default()
}

/// The mitigated tags of an optional `threats`, or empty.
fn mitigated_of(t: Option<&Threats>) -> Vec<String> {
    t.map(|t| t.mitigated.clone()).unwrap_or_default()
}

/// Authored exposed tags plus the compiler-derived ones, de-duplicated.
fn exposed_with(t: Option<&Threats>, derived: &[&str]) -> Vec<String> {
    let mut v = exposed_of(t);
    for d in derived {
        if !v.iter().any(|x| x == d) {
            v.push((*d).to_owned());
        }
    }
    v
}

/// Render a port list as a stable comparable value.
fn ports_value(ports: &[u16]) -> String {
    if ports.is_empty() {
        "ports=any".to_owned()
    } else {
        let mut p: Vec<u16> = ports.to_vec();
        p.sort_unstable();
        format!(
            "ports=[{}]",
            p.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalogue {
        Catalogue::embedded().expect("embedded catalogue")
    }

    fn parse(toml: &str) -> SourcePolicy {
        crate::source::parse(toml.as_bytes()).expect("parse source")
    }

    #[test]
    fn added_net_allow_is_classified_and_threat_tagged() {
        let old = parse("name = \"x\"\n[net]\nmode = \"constrained\"\n");
        let new = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443]\nreason = \"api\"\n\
             threats = { exposed = [\"T1.8\"] }\n",
        );
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("api.x.com"))
            .expect("the new allow shows up");
        assert_eq!(c.kind, ChangeKind::Added);
        assert!(c.widening);
        assert_eq!(c.reason.as_deref(), Some("api"));
        assert!(c
            .exposed
            .iter()
            .any(|t| t.id == "T1.8" && t.title.is_some()));
        // The summary reflects the newly-exposed threat too.
        assert!(d.summary.newly_exposed.iter().any(|t| t.id == "T1.8"));
    }

    #[test]
    fn an_added_provide_shows_as_a_mesh_grant() {
        let old = parse("name = \"x\"\n");
        let new = parse(
            "name = \"x\"\n[[provides]]\nname = \"build-cache\"\nshape = \"binder-connector\"\n\
             endpoint = \"/run/cache.sock\"\nreason = \"serve build cache\"\n",
        );
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("[[provides]]") && c.carrier.contains("build-cache"))
            .expect("the new provide shows up");
        assert_eq!(c.kind, ChangeKind::Added);
        assert_eq!(c.reason.as_deref(), Some("serve build cache"));
    }

    #[test]
    fn removed_allow_is_narrowing_with_a_note() {
        let old = parse("name = \"x\"\n[fs]\nread = [\"~/projects/**\"]\n");
        let new = parse("name = \"x\"\n");
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("projects"))
            .expect("the removed read shows up");
        assert_eq!(c.kind, ChangeKind::Removed);
        assert!(!c.widening);
        assert!(c
            .note
            .as_deref()
            .unwrap_or("")
            .contains("no longer granted"));
    }

    #[test]
    fn removed_deny_widens_and_warns() {
        let old = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[net.proxy.deny]\n\
             [[net.proxy.deny.policy]]\ncidr = \"10.0.0.0/8\"\nreason = \"rfc1918\"\n",
        );
        let new = parse("name = \"x\"\n[net]\nmode = \"constrained\"\n");
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("10.0.0.0/8"))
            .expect("the removed deny shows up");
        assert_eq!(c.kind, ChangeKind::Removed);
        assert!(c.widening, "removing a deny widens reach");
        assert!(c.note.as_deref().unwrap_or("").contains("weakens"));
    }

    #[test]
    fn changed_ports_is_a_modification() {
        let old = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443]\nreason = \"api\"\n",
        );
        let new = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443, 8443]\nreason = \"api\"\n",
        );
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("api.x.com"))
            .expect("the modified allow shows up");
        assert_eq!(c.kind, ChangeKind::Modified);
        assert!(c.detail.contains("\u{2192}"), "shows old → new");
    }

    #[test]
    fn host_mode_change_derives_t1_6_in_change_and_summary() {
        let old = parse("name = \"x\"\n[net]\nmode = \"constrained\"\n");
        let new = parse("name = \"x\"\n[net]\nmode = \"host\"\nreason = \"need host net\"\n");
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier == "[net] mode")
            .expect("the mode change shows up");
        assert_eq!(c.kind, ChangeKind::Modified);
        assert!(c.detail.contains("constrained") && c.detail.contains("host"));
        assert!(c.exposed.iter().any(|t| t.id == "T1.6"));
        assert!(d.summary.newly_exposed.iter().any(|t| t.id == "T1.6"));
    }

    #[test]
    fn identical_policies_have_no_changes() {
        let p = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443]\nreason = \"api\"\n",
        );
        let d = diff(&p, &p, &cat());
        assert!(d.is_empty());
        assert!(d.summary.is_empty());
    }

    #[test]
    fn permissive_exec_carries_a_loud_note() {
        let old = parse("name = \"x\"\n");
        let new = parse("name = \"x\"\n[exec]\nallow = [\"**\"]\n");
        let d = diff(&old, &new, &cat());
        let c = d
            .changes
            .iter()
            .find(|c| c.carrier.contains("exec.allow"))
            .expect("the permissive exec shows up");
        assert!(c.note.as_deref().unwrap_or("").contains("any executable"));
    }
}
