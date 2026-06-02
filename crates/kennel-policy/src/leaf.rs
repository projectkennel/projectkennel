//! Leaf-policy delta operators — the `+=` / `-=` half of the SSH composition model.
//!
//! # Purpose
//!
//! A user's leaf policy is mostly metadata plus *deltas* against a chosen template
//! (`docs/05-templates.md` §5.2-5.3): `[[fs.read.add]]`, `[[net.allow.add]]`,
//! `[[fs.deny.remove]]`, … Templates express direct rules (the `=` form handled by
//! [`crate::resolve`]); leaves express add/remove deltas against the folded
//! effective policy. The two forms cannot share one parsed type — TOML cannot hold
//! both `fs.read = [...]` (array) and `[[fs.read.add]]` (table) under the same key —
//! so a leaf parses into this separate [`LeafPolicy`], and [`LeafPolicy::apply`]
//! mutates the effective [`SourcePolicy`] the template chain produced.
//!
//! # Composition (SSH `+=` / `-=`)
//!
//! - `*.add` appends entries not already present (`+=`).
//! - `*.remove` drops entries matching by unique key — `path` for filesystem, `name`
//!   for network, `real`/`name` for unix sockets (`-=`). A remove that matches an
//!   invariant-marked rule is refused by the framework-invariant gate downstream.
//!
//! Every delta entry requires a `reason` (`02-2` §Delta requirements). This build
//! covers add/remove on the list-valued sections; the scalar `[*.override]` form is
//! a later increment (the template chain already overrides scalars).

use crate::source::{NetAllow, SourcePolicy, UnixAllow};
use crate::PolicyError;
use serde::{Deserialize, Serialize};

/// A parsed leaf policy: identity plus add/remove deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeafPolicy {
    /// The parent template reference (`<name>@v<ver>`). Required for a leaf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_base: Option<String>,
    /// Legacy parent-version field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_version: Option<String>,
    /// The kennel name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Additional signed fragments (additive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// The threat-catalogue version this leaf was authored against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_catalogue_version: Option<String>,
    /// Optional signature envelope (leaves may be unsigned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<crate::signature::SignatureEnvelope>,

    /// `[fs.*.add]` / `[fs.*.remove]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsLeaf>,
    /// `[net.allow.add]` / `[net.allow.remove]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetLeaf>,
    /// `[unix.allow.add]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixLeaf>,
    /// `[exec.allow.add]` / `[exec.allow.remove]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecLeaf>,
}

/// One path delta entry (`path` plus the required `reason`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathEntry {
    /// The path to add or remove.
    pub path: String,
    /// Why (required for every delta).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<crate::source::Threats>,
}

/// An add/remove delta over a list of path entries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathListDelta {
    /// Entries to add (`+=`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<PathEntry>,
    /// Entries to remove (`-=`), matched by `path`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<PathEntry>,
}

/// `[fs.*]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsLeaf {
    /// `[[fs.read.add]]` / `[[fs.read.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<PathListDelta>,
    /// `[[fs.write.add]]` / `[[fs.write.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<PathListDelta>,
    /// `[[fs.deny.add]]` / `[[fs.deny.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<PathListDelta>,
}

/// `[net.allow]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetLeaf {
    /// `[[net.allow.add]]` / `[[net.allow.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<NetAllowDelta>,
}

/// An add/remove delta over network allow entries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetAllowDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<NetAllow>,
    /// Entries to remove, matched by `name` (or `cidr`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<NetAllow>,
}

/// `[unix.allow]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixLeaf {
    /// `[[unix.allow.add]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<UnixAllowDelta>,
}

/// An add/remove delta over unix allow entries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixAllowDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<UnixAllow>,
    /// Entries to remove, matched by `name` then `real`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<UnixAllow>,
}

/// `[exec.allow]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecLeaf {
    /// `[[exec.allow.add]]` / `[[exec.allow.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<PathListDelta>,
}

/// Parse leaf-policy TOML into a [`LeafPolicy`].
///
/// # Errors
///
/// Returns [`PolicyError::Parse`] if the bytes are not valid leaf-policy TOML.
pub fn parse(bytes: &[u8]) -> Result<LeafPolicy, PolicyError> {
    basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))
}

impl LeafPolicy {
    /// Validate the leaf's identity and require a `reason` on every delta entry.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::SourceValidation`] with one message per problem.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errs: Vec<String> = Vec::new();
        if self.name.is_none() {
            errs.push("leaf policy has no `name`".to_owned());
        }
        if self.template_base.is_none() {
            errs.push("leaf policy has no `template_base`".to_owned());
        }
        self.check_reasons(&mut errs);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::SourceValidation(errs))
        }
    }

    fn check_reasons(&self, errs: &mut Vec<String>) {
        let path_blank = |e: &PathEntry| e.reason.as_deref().is_none_or(|r| r.trim().is_empty());
        if let Some(fs) = &self.fs {
            for (label, delta) in [("fs.read", &fs.read), ("fs.write", &fs.write), ("fs.deny", &fs.deny)] {
                if let Some(d) = delta {
                    for e in d.add.iter().chain(&d.remove) {
                        if path_blank(e) {
                            errs.push(format!("[[{label}.*]] `{}` is missing a `reason`", e.path));
                        }
                    }
                }
            }
        }
        if let Some(exec) = &self.exec {
            if let Some(d) = &exec.allow {
                for e in d.add.iter().chain(&d.remove) {
                    if path_blank(e) {
                        errs.push(format!("[[exec.allow.*]] `{}` is missing a `reason`", e.path));
                    }
                }
            }
        }
        if let Some(net) = &self.net {
            if let Some(d) = &net.allow {
                for e in d.add.iter().chain(&d.remove) {
                    if e.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                        let who = e.name.as_deref().or(e.cidr.as_deref()).unwrap_or("<unnamed>");
                        errs.push(format!("[[net.allow.*]] `{who}` is missing a `reason`"));
                    }
                }
            }
        }
        if let Some(unix) = &self.unix {
            if let Some(d) = &unix.allow {
                for e in d.add.iter().chain(&d.remove) {
                    if e.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                        let who = e.name.as_deref().or(e.real.as_deref()).unwrap_or("<unnamed>");
                        errs.push(format!("[[unix.allow.*]] `{who}` is missing a `reason`"));
                    }
                }
            }
        }
    }

    /// Whether this policy is additive-only — it carries no `*.remove` deltas. An
    /// included fragment must satisfy this (`02-2` §Includes): fragments may only add.
    #[must_use]
    pub fn is_additive_only(&self) -> bool {
        let path_clean = |d: &Option<PathListDelta>| d.as_ref().is_none_or(|x| x.remove.is_empty());
        let fs_ok = self
            .fs
            .as_ref()
            .is_none_or(|f| path_clean(&f.read) && path_clean(&f.write) && path_clean(&f.deny));
        let exec_ok = self.exec.as_ref().is_none_or(|e| path_clean(&e.allow));
        let net_ok = self.net.as_ref().is_none_or(|n| n.allow.as_ref().is_none_or(|a| a.remove.is_empty()));
        let unix_ok = self.unix.as_ref().is_none_or(|u| u.allow.as_ref().is_none_or(|a| a.remove.is_empty()));
        fs_ok && exec_ok && net_ok && unix_ok
    }

    /// This policy's `[[net.allow.add]]` entries (for include conflict checks).
    #[must_use]
    pub fn net_allow_adds(&self) -> &[NetAllow] {
        self.net.as_ref().and_then(|n| n.allow.as_ref()).map_or(&[], |a| a.add.as_slice())
    }

    /// Apply this leaf's deltas to the folded effective policy, in place.
    ///
    /// `add` appends entries not already present; `remove` drops entries matching by
    /// unique key. The result is then translated and invariant-checked by the
    /// compiler, so a remove that strips an invariant rule is caught downstream.
    pub fn apply(&self, effective: &mut SourcePolicy) {
        if let Some(fs) = &self.fs {
            let target = effective.fs.get_or_insert_with(Default::default);
            apply_paths(&mut target.read, fs.read.as_ref());
            apply_paths(&mut target.write, fs.write.as_ref());
            apply_paths(&mut target.deny, fs.deny.as_ref());
        }
        if let Some(exec) = &self.exec {
            let target = effective.exec.get_or_insert_with(Default::default);
            apply_paths(&mut target.allow, exec.allow.as_ref());
        }
        if let Some(net) = &self.net {
            if let Some(d) = &net.allow {
                let target = effective.net.get_or_insert_with(Default::default);
                for entry in &d.add {
                    if !target.allow.iter().any(|e| net_key(e) == net_key(entry)) {
                        target.allow.push(entry.clone());
                    }
                }
                target.allow.retain(|e| !d.remove.iter().any(|r| net_key(r) == net_key(e)));
            }
        }
        if let Some(unix) = &self.unix {
            if let Some(d) = &unix.allow {
                let target = effective.unix.get_or_insert_with(Default::default);
                for entry in &d.add {
                    if !target.allow.iter().any(|e| unix_key(e) == unix_key(entry)) {
                        target.allow.push(entry.clone());
                    }
                }
                target.allow.retain(|e| !d.remove.iter().any(|r| unix_key(r) == unix_key(e)));
            }
        }
    }
}

/// Apply an add/remove path delta to an optional string list, in place.
fn apply_paths(target: &mut Option<Vec<String>>, delta: Option<&PathListDelta>) {
    let Some(delta) = delta else { return };
    if delta.add.is_empty() && delta.remove.is_empty() {
        return;
    }
    let list = target.get_or_insert_with(Vec::new);
    for e in &delta.add {
        if !list.iter().any(|p| p == &e.path) {
            list.push(e.path.clone());
        }
    }
    list.retain(|p| !delta.remove.iter().any(|e| &e.path == p));
}

/// Unique key for a network allow entry (name, else cidr).
pub(crate) fn net_key(a: &NetAllow) -> &str {
    a.name.as_deref().or(a.cidr.as_deref()).unwrap_or("")
}

/// Unique key for a unix allow entry (name, else real).
fn unix_key(a: &UnixAllow) -> &str {
    a.name.as_deref().or(a.real.as_deref()).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{resolve, TemplateSource};
    use crate::source::parse as parse_source;

    const BASE_CONFINED: &str = include_str!("../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str = include_str!("../../../templates/ai-coding-strict/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0.iter().find(|(n, v, _)| n == name && v == version).map(|(_, _, b)| b.clone())
        }
    }
    fn src() -> MapSource {
        MapSource(vec![
            ("base-confined".to_owned(), "v1".to_owned(), BASE_CONFINED.as_bytes().to_vec()),
            ("ai-coding-strict".to_owned(), "v1".to_owned(), AI_CODING_STRICT.as_bytes().to_vec()),
        ])
    }

    /// Resolve ai-coding-strict's chain, then apply a leaf's deltas on top.
    fn effective_with_leaf(leaf_toml: &str) -> (SourcePolicy, LeafPolicy) {
        let leaf = parse(leaf_toml.as_bytes()).expect("parse leaf");
        let base = leaf.template_base.clone().expect("base");
        let stub = format!("template_name = \"stub\"\ntemplate_base = \"{base}\"\n");
        let stub = parse_source(stub.as_bytes()).expect("stub");
        let mut effective = resolve(&stub, &src()).expect("resolve").effective;
        leaf.apply(&mut effective);
        (effective, leaf)
    }

    const PROJECT_LEAF: &str = r#"
name = "myproj-ai"
template_base = "ai-coding-strict@v1"

[[fs.read.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

[[fs.write.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T8"]
"#;

    #[test]
    fn leaf_add_grants_project_paths_and_api() {
        let (eff, _) = effective_with_leaf(PROJECT_LEAF);
        let fs = eff.fs.expect("fs");
        assert!(fs.read.as_ref().expect("read").iter().any(|p| p == "~/projects/myproj/**"));
        assert!(fs.write.as_ref().expect("write").iter().any(|p| p == "~/projects/myproj/**"));
        // The inherited system read paths survive.
        assert!(fs.read.as_ref().expect("read").iter().any(|p| p == "/usr/**"));
        let net = eff.net.expect("net");
        assert!(net.allow.iter().any(|a| a.name.as_deref() == Some("api.anthropic.com")));
        // The inherited registry allows survive.
        assert!(net.allow.iter().any(|a| a.name.as_deref() == Some("github.com")));
    }

    #[test]
    fn leaf_remove_drops_an_inherited_entry() {
        let leaf = r#"
name = "n"
template_base = "ai-coding-strict@v1"
[[net.allow.remove]]
name = "github.com"
reason = "this workflow does not use github"
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let net = eff.net.expect("net");
        assert!(!net.allow.iter().any(|a| a.name.as_deref() == Some("github.com")), "github removed");
        assert!(net.allow.iter().any(|a| a.name.as_deref() == Some("pypi.org")), "others remain");
    }

    #[test]
    fn add_is_idempotent_no_duplicates() {
        let leaf = r#"
name = "n"
template_base = "ai-coding-strict@v1"
[[net.allow.add]]
name = "github.com"
ports = [443]
reason = "already inherited; should not duplicate"
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let n = eff.net.expect("net").allow.iter().filter(|a| a.name.as_deref() == Some("github.com")).count();
        assert_eq!(n, 1, "no duplicate github.com");
    }

    #[test]
    fn leaf_without_reason_is_rejected() {
        let leaf = "name = \"n\"\ntemplate_base = \"ai-coding-strict@v1\"\n[[fs.read.add]]\npath = \"~/x/**\"\n";
        let pol = parse(leaf.as_bytes()).expect("parse");
        let err = pol.validate().expect_err("missing reason fails");
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms.iter().any(|m| m.contains("reason")));
        }
    }

    #[test]
    fn leaf_missing_identity_is_rejected() {
        let pol = parse(b"name = \"n\"\n").expect("parse");
        assert!(pol.validate().is_err(), "no template_base");
        let pol = parse(b"template_base = \"x@v1\"\n").expect("parse");
        assert!(pol.validate().is_err(), "no name");
    }

    #[test]
    fn delta_form_does_not_parse_as_a_template() {
        // The whole reason leaves get their own type: the delta form is not a SourcePolicy.
        assert!(parse_source(PROJECT_LEAF.as_bytes()).is_err());
        assert!(parse(PROJECT_LEAF.as_bytes()).is_ok());
    }
}
