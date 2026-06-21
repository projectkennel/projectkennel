//! Risk evaluation: map a resolved policy's `threats` tags against the catalogue.
//!
//! `kennel policy risks` surfaces what a policy's grants **expose** and **mitigate**
//! per the threat framework, each with the granting site, its documented `reason`,
//! and the catalogue residual. The engine is pure over the resolved source policy
//! (the folded inheritance) — threat tags live only in source, never the settled
//! artefact, so this is the honest input.
//!
//! It also adds the **compile-time-derived** exposures the compiler infers (so the
//! report matches what is actually enforced): `mode = host` reinstates T1.6,
//! `[[fs.dev.passthrough]]` exposes T2.1, `[ssh].allow_headless` exposes T1.6. These
//! are marked `derived` so the reader can tell an inferred tag from an authored one.
//!
//! Tags that name no catalogued threat are collected separately as `unknown_tags`
//! (a likely typo) rather than silently dropped — no theatre, no invented risk.

use crate::source::{SourcePolicy, Threats};
use crate::threats::Catalogue;

/// Whether a finding's threat tag was authored on a grant or derived by the compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The tag is written on the grant (`threats.exposed`/`threats.mitigated`).
    Authored,
    /// The compiler derives the tag from the grant's shape (e.g. `mode = host`).
    Derived,
}

/// One exposure or mitigation: a threat, the grant that carries it, and context.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The threat id (`T1.6`).
    pub threat_id: String,
    /// The catalogue title, or `None` if the id is not catalogued (see `unknown_tags`).
    pub title: Option<String>,
    /// The catalogue residual one-liner (empty if the id is not catalogued).
    pub residual: String,
    /// The granting site, e.g. `[net] mode = host` or `[[net.proxy.allow]] api.x.com`.
    pub carrier: String,
    /// The grant's documented reason, if any.
    pub reason: Option<String>,
    /// Authored on the grant or derived by the compiler.
    pub origin: Origin,
}

/// The risk report for one resolved policy.
#[derive(Debug, Clone, Default)]
pub struct RiskReport {
    /// The catalogue version the evaluation used.
    pub catalogue_version: String,
    /// The policy's declared `threat_catalogue_version` (for a drift note), if set.
    pub policy_catalogue_version: Option<String>,
    /// Threats the policy's grants expose / re-expose.
    pub exposures: Vec<Finding>,
    /// Threats the policy's grants mitigate.
    pub mitigations: Vec<Finding>,
    /// Threat tags found on grants that name no catalogued threat (likely typos),
    /// as `(tag, carrier)`.
    pub unknown_tags: Vec<(String, String)>,
}

/// Evaluate `resolved` (a folded effective source policy) against `catalogue`.
#[must_use]
pub fn evaluate(resolved: &SourcePolicy, catalogue: &Catalogue) -> RiskReport {
    let mut report = RiskReport {
        catalogue_version: catalogue.version.clone(),
        policy_catalogue_version: resolved.threat_catalogue_version.clone(),
        ..RiskReport::default()
    };

    // 1. Authored tags on every threat-carrying grant.
    for (carrier, reason, threats) in authored_carriers(resolved) {
        let Some(threats) = threats else { continue };
        for id in &threats.exposed {
            report.push(
                catalogue,
                id,
                &carrier,
                reason.clone(),
                Origin::Authored,
                true,
            );
        }
        for id in &threats.mitigated {
            report.push(
                catalogue,
                id,
                &carrier,
                reason.clone(),
                Origin::Authored,
                false,
            );
        }
    }

    // 2. Compiler-derived exposures (the single source of truth for what the
    //    compiler infers; mirrored here so the report matches enforcement).
    for (id, carrier, reason) in derived_exposures(resolved) {
        report.push(catalogue, &id, &carrier, reason, Origin::Derived, true);
    }

    report
}

impl RiskReport {
    /// Resolve `id` against the catalogue and file it as an exposure or mitigation;
    /// an uncatalogued id goes to `unknown_tags`.
    fn push(
        &mut self,
        catalogue: &Catalogue,
        id: &str,
        carrier: &str,
        reason: Option<String>,
        origin: Origin,
        exposure: bool,
    ) {
        let Some(entry) = catalogue.lookup(id) else {
            self.unknown_tags.push((id.to_owned(), carrier.to_owned()));
            return;
        };
        let finding = Finding {
            threat_id: id.to_owned(),
            title: Some(entry.title.clone()),
            residual: entry.residual.clone(),
            carrier: carrier.to_owned(),
            reason,
            origin,
        };
        if exposure {
            self.exposures.push(finding);
        } else {
            self.mitigations.push(finding);
        }
    }
}

/// One label for a grant carrier, distinguishing it when several share a section.
fn label(section: &str, ident: Option<&str>) -> String {
    ident.map_or_else(|| section.to_owned(), |id| format!("{section} {id}"))
}

/// Every authored threat-carrying grant in the resolved policy:
/// `(carrier label, reason, threats)`.
#[allow(clippy::too_many_lines)] // a flat enumeration of every carrier site; cohesive.
fn authored_carriers(p: &SourcePolicy) -> Vec<(String, Option<String>, Option<&Threats>)> {
    let mut out: Vec<(String, Option<String>, Option<&Threats>)> = Vec::new();

    if let Some(net) = &p.net {
        // [net] carries no authored `threats` field (mode/reason only); the host-mode
        // tradeoff is a derived exposure (see `derived_exposures`).
        if let Some(proxy) = &net.proxy {
            for a in &proxy.allow {
                let ident = a.name.as_deref().or(a.cidr.as_deref());
                out.push((
                    label("[[net.proxy.allow]]", ident),
                    a.reason.clone(),
                    a.threats.as_ref(),
                ));
            }
            if let Some(deny) = &proxy.deny {
                for d in deny.invariant.iter().chain(deny.policy.iter()) {
                    out.push((
                        label("[[net.proxy.deny]]", Some(&d.cidr)),
                        d.reason.clone(),
                        d.threats.as_ref(),
                    ));
                }
            }
        }
        if let Some(bpf) = &net.bpf {
            for (sect, acl) in [("connect", &bpf.connect), ("bind", &bpf.bind)] {
                let Some(acl) = acl else { continue };
                for r in acl.allow.iter().chain(acl.deny.iter()) {
                    out.push((
                        label(&format!("[[net.bpf.{sect}]]"), r.cidr.as_deref()),
                        r.reason.clone(),
                        r.threats.as_ref(),
                    ));
                }
            }
        }
    }

    if let Some(unix) = &p.unix {
        for a in &unix.allow {
            out.push((
                label("[[unix.allow]]", a.name.as_deref().or(a.real.as_deref())),
                a.reason.clone(),
                a.threats.as_ref(),
            ));
        }
    }

    if let Some(fs) = &p.fs {
        if let Some(dev) = &fs.dev {
            for pt in &dev.passthrough {
                out.push((
                    label("[[fs.dev.passthrough]]", pt.path.as_deref()),
                    pt.reason.clone(),
                    pt.threats.as_ref(),
                ));
            }
        }
    }

    if let Some(ssh) = &p.ssh {
        out.push(("[ssh]".to_owned(), None, ssh.threats.as_ref()));
        for d in &ssh.destinations {
            out.push((
                label("[[ssh.destinations]]", d.dest.as_deref()),
                d.reason.clone(),
                d.threats.as_ref(),
            ));
        }
    }

    if let Some(binder) = &p.binder {
        for prov in &binder.provide {
            out.push((
                label("[[binder.provide]]", prov.name.as_deref()),
                prov.reason.clone(),
                prov.threats.as_ref(),
            ));
        }
        for cons in &binder.consume {
            out.push((
                label("[[binder.consume]]", cons.name.as_deref()),
                cons.reason.clone(),
                cons.threats.as_ref(),
            ));
        }
    }

    out
}

/// The exposures the compiler derives from a grant's shape (mirrors `translate`/
/// `dev`/`ssh`): `(threat id, carrier, reason)`.
fn derived_exposures(p: &SourcePolicy) -> Vec<(String, String, Option<String>)> {
    let mut out = Vec::new();

    if let Some(net) = &p.net {
        if net.mode.as_deref() == Some("host") {
            out.push((
                "T1.6".to_owned(),
                "[net] mode = host".to_owned(),
                net.reason.clone(),
            ));
        }
    }

    if let Some(fs) = &p.fs {
        if let Some(dev) = &fs.dev {
            for pt in &dev.passthrough {
                out.push((
                    "T2.1".to_owned(),
                    label("[[fs.dev.passthrough]]", pt.path.as_deref()),
                    pt.reason.clone(),
                ));
            }
        }
    }

    if let Some(ssh) = &p.ssh {
        if ssh.allow_headless == Some(true) {
            out.push((
                "T1.6".to_owned(),
                "[ssh] allow_headless = true".to_owned(),
                None,
            ));
        }
    }

    // `[rootfs]` boots an operator-declared OCI image as the kennel root; the substrate-trust
    // residual (the image's runtime closure is unvetted by construction) is derived from the
    // grant the way T1.6 is derived from `mode = host` (design §7.11.9).
    if let Some(rootfs) = &p.rootfs {
        out.push((
            "T3.8".to_owned(),
            label("[rootfs]", rootfs.image.as_deref()),
            rootfs.reason.clone(),
        ));
        // `persistence = "persist"` adds a distinct exposure: the managed overlay upper
        // accumulates divergence outside the integrity ladder (§7.11.4a), surfaced against the
        // same `[rootfs]` reason.
        if rootfs.persistence.as_deref() == Some("persist") {
            out.push((
                "T3.8".to_owned(),
                "[rootfs].persistence = persist (managed upper diverges from the pinned image)"
                    .to_owned(),
                rootfs.reason.clone(),
            ));
        }
        // Each closure-lock `writable` carve-out re-opens a hole in the executable-closure
        // boundary (§7.11.4c) — a loud, separately-derived exposure.
        for hole in rootfs.writable.as_deref().unwrap_or_default() {
            out.push((
                "T3.8".to_owned(),
                format!(
                    "[rootfs].writable = {hole} (closure-lock hole — path is workload-writable)"
                ),
                rootfs.reason.clone(),
            ));
        }
    }

    // `[spawn]` delegates instantiation to the workload — it may spawn ephemeral sibling kennels
    // from the operator-signed templates it names. The delegated-spawning residual (T3.9) is derived
    // from the grant the way T1.6 is derived from `mode = host` (design §7.12.9). The carrier names
    // the templates the grant reaches, so the report shows the delegation's actual breadth.
    if let Some(spawn) = &p.spawn {
        let templates: Vec<&str> = spawn
            .allow
            .iter()
            .filter_map(|a| a.template.as_deref())
            .collect();
        let carrier = if templates.is_empty() {
            "[spawn]".to_owned()
        } else {
            format!("[spawn.allow] {}", templates.join(", "))
        };
        out.push(("T3.9".to_owned(), carrier, spawn.reason.clone()));
    }

    out
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
    fn host_mode_derives_t1_6_exposure() {
        let p = parse("name = \"x\"\n[net]\nmode = \"host\"\nreason = \"need host net\"\n");
        let r = evaluate(&p, &cat());
        let f = r
            .exposures
            .iter()
            .find(|f| f.threat_id == "T1.6")
            .expect("T1.6 derived");
        assert_eq!(f.origin, Origin::Derived);
        assert_eq!(f.reason.as_deref(), Some("need host net"));
        assert!(f.title.is_some());
        assert!(!f.residual.is_empty());
    }

    #[test]
    fn passthrough_derives_t2_1_and_carries_authored_tag() {
        let p = parse(
            "name = \"x\"\n[fs.dev]\n[[fs.dev.passthrough]]\npath = \"/dev/ttyUSB0\"\n\
             reason = \"flash\"\nthreats = { exposed = [\"T2.1\"] }\n",
        );
        let r = evaluate(&p, &cat());
        let count = r.exposures.iter().filter(|f| f.threat_id == "T2.1").count();
        assert!(count >= 1, "T2.1 surfaced (authored and/or derived)");
        assert!(r
            .exposures
            .iter()
            .any(|f| f.carrier.contains("/dev/ttyUSB0")));
    }

    #[test]
    fn rootfs_derives_t3_8_substrate_trust_exposure() {
        let p = parse(
            "name = \"x\"\n[rootfs]\npath = \"~/img/app/rootfs\"\n\
             image = \"ghcr.io/org/app@sha256:abc\"\nreason = \"vendor image\"\n",
        );
        let r = evaluate(&p, &cat());
        let f = r
            .exposures
            .iter()
            .find(|f| f.threat_id == "T3.8")
            .expect("T3.8 derived");
        assert_eq!(f.origin, Origin::Derived);
        assert_eq!(f.reason.as_deref(), Some("vendor image"));
        assert!(f.carrier.contains("ghcr.io/org/app"));
        assert!(f.title.is_some());
        assert!(!f.residual.is_empty());
    }

    #[test]
    fn spawn_derives_t3_9_delegated_spawning_exposure() {
        let p = parse(
            "name = \"x\"\n[spawn]\nmax_instances = 4\nreason = \"agent spawns tools\"\n\
             [[spawn.allow]]\ntemplate = \"net-fetch@v1\"\n",
        );
        let r = evaluate(&p, &cat());
        let f = r
            .exposures
            .iter()
            .find(|f| f.threat_id == "T3.9")
            .expect("T3.9 derived");
        assert_eq!(f.origin, Origin::Derived);
        assert_eq!(f.reason.as_deref(), Some("agent spawns tools"));
        // The carrier names the templates the grant reaches, so the report shows its breadth.
        assert!(f.carrier.contains("net-fetch@v1"));
        assert!(f.title.is_some());
        assert!(!f.residual.is_empty());
    }

    #[test]
    fn authored_mitigation_is_filed_as_mitigation() {
        let p = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443]\nreason = \"api\"\n\
             threats = { mitigated = [\"T1.1\"] }\n",
        );
        let r = evaluate(&p, &cat());
        assert!(r
            .mitigations
            .iter()
            .any(|f| f.threat_id == "T1.1" && f.carrier.contains("api.x.com")));
    }

    #[test]
    fn unknown_tag_is_flagged_not_dropped() {
        let p = parse(
            "name = \"x\"\n[net]\nmode = \"constrained\"\n[[net.proxy.allow]]\n\
             name = \"api.x.com\"\nports = [443]\nreason = \"api\"\n\
             threats = { exposed = [\"T9.9\"] }\n",
        );
        let r = evaluate(&p, &cat());
        assert!(r.unknown_tags.iter().any(|(tag, _)| tag == "T9.9"));
        assert!(!r.exposures.iter().any(|f| f.threat_id == "T9.9"));
    }
}
