//! Effective-policy diff: the interpreted `+`/`~`/`-` grant delta between two
//! resolved (folded) source policies, annotated with threat impact.
//!
//! `kennel policy diff` answers a question neither `policy show` (full effective
//! dump) nor `policy upgrade` (raw source line diff) answers: *which grants
//! widened or narrowed, and what does each change cost in threat exposure*. It is
//! the semantic counterpart of the line diff — `05-templates.md` §5.11/§5.13.
//!
//! The engine is pure over two folded [`SourcePolicy`] values (the same honest
//! input the [risk engine](crate::risks) reads — threat tags live only in source,
//! never the settled artefact). The caller resolves both sides; this module does
//! no I/O. The two common pairings are:
//!
//! - **leaf vs its template baseline** — what the leaf's own deltas add over the
//!   template it inherits (the §5.13 "your deltas" view), and
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

use serde::Serialize;

use crate::source::SourcePolicy;
use crate::threats::Catalogue;

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
    let _ = (old, new, catalogue);
    todo!("diff engine implemented in the feat: phase")
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
        assert!(c.exposed.iter().any(|t| t.id == "T1.8" && t.title.is_some()));
        // The summary reflects the newly-exposed threat too.
        assert!(d.summary.newly_exposed.iter().any(|t| t.id == "T1.8"));
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
        assert!(c.note.as_deref().unwrap_or("").contains("no longer granted"));
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
