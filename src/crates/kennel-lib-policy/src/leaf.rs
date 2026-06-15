//! Leaf-policy delta operators — the `+=` / `-=` half of the SSH composition model.
//!
//! # Purpose
//!
//! A user's leaf policy is mostly metadata plus *deltas* against a chosen template
//! (`docs/design/05-templates.md` §5.2-5.3): `[[fs.read.add]]`, `[[net.allow.add]]`,
//! `[[fs.deny.remove]]`, … Templates express direct rules (the `=` form handled by
//! [`crate::resolve`](mod@crate::resolve)); leaves express add/remove deltas against the folded
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

use crate::source::{
    BpfRule, DevPassthrough, LifecycleSection, NetAllow, NetAudit, NetDenyRule, SourcePolicy,
    SshDestination, UnixAllow,
};
use crate::PolicyError;
use serde::{Deserialize, Serialize};

/// A parsed leaf policy: identity plus add/remove deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeafPolicy {
    /// The parent template reference (`<name>@v<ver>`). Required for a leaf; the parent's
    /// version is inline in the reference, so a leaf has no own version field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_base: Option<String>,
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
    /// `[ssh.keys.add]` / `[ssh.keys.remove]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshLeaf>,
    /// `[exec.allow.add]` / `[exec.allow.remove]` deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecLeaf>,
    /// `[lifecycle.override]` — scalar override of the inherited TTL/action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleLeaf>,
}

/// `[lifecycle.override]` — a leaf's scalar override of lifecycle fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLeaf {
    /// The override table (`[lifecycle.override]`).
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub over: Option<LifecycleSection>,
}

/// `[net.audit.override]` — a leaf's scalar override of audit fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLeaf {
    /// The override table (`[net.audit.override]`).
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub over: Option<NetAudit>,
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
    /// `[fs.dev]` deltas (the `[[fs.dev.passthrough.add]]` device grants).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<DevLeaf>,
}

/// `[fs.dev]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevLeaf {
    /// `[[fs.dev.passthrough.add]]` / `[[fs.dev.passthrough.remove]]` — the realistic
    /// authoring path for a host-device grant (a leaf adds its own serial console).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough: Option<DevPassthroughDelta>,
}

/// An add/remove delta over `[[fs.dev.passthrough]]` device grants.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevPassthroughDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<DevPassthrough>,
    /// Entries to remove, matched by `path`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<DevPassthrough>,
}

/// `[net.proxy]` / `[net.bpf]` leaf-and-fragment deltas (`07-5` §7.5.4).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetLeaf {
    /// `[net.proxy]` deltas — the proxy egress allow/deny additions/removals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<NetProxyLeaf>,
    /// `[net.bpf]` deltas — the kernel-ACL connect/bind additions/removals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf: Option<NetBpfLeaf>,
    /// `[net.audit.override]` — scalar override of the inherited audit config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditLeaf>,
}

/// `[net.proxy]` leaf deltas: by-name/CIDR allow add/remove and the author denylist
/// add/remove.
///
/// The non-removable `[[net.proxy.deny.invariant]]` floor is template- and
/// fragment-author only — a leaf carrying one is refused.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetProxyLeaf {
    /// `[[net.proxy.allow.add]]` / `[[net.proxy.allow.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<NetAllowDelta>,
    /// `[net.proxy.deny]` — its `invariant` array carries fragment-declared invariant
    /// denies (permitted only in fragments), `policy` the removable author denylist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<NetProxyDenyLeaf>,
}

/// `[net.proxy.deny]` leaf-and-fragment deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetProxyDenyLeaf {
    /// `[[net.proxy.deny.invariant]]` — non-removable deny CIDRs (fragments only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant: Vec<NetDenyRule>,
    /// `[[net.proxy.deny.policy.add]]` / `[[net.proxy.deny.policy.remove]]` — the
    /// removable author denylist deltas, keyed by `cidr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetDenyDelta>,
}

/// `[net.bpf]` leaf deltas: the kernel-ACL connect/bind allow/deny add/remove.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBpfLeaf {
    /// `[net.bpf.connect]` allow/deny deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<NetBpfAclLeaf>,
    /// `[net.bpf.bind]` allow/deny deltas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBpfAclLeaf>,
}

/// One direction (`connect`/`bind`) of `[net.bpf]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBpfAclLeaf {
    /// `[[net.bpf.<dir>.allow.add]]` / `[[net.bpf.<dir>.allow.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<BpfRuleDelta>,
    /// `[[net.bpf.<dir>.deny.add]]` / `[[net.bpf.<dir>.deny.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<BpfRuleDelta>,
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

/// An add/remove delta over `[net.proxy.deny.policy]` deny rules, keyed by `cidr`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetDenyDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<NetDenyRule>,
    /// Entries to remove, matched by `cidr`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<NetDenyRule>,
}

/// An add/remove delta over `[net.bpf]` ACL rules, keyed by `cidr`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BpfRuleDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<BpfRule>,
    /// Entries to remove, matched by `cidr`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<BpfRule>,
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

/// `[ssh.destinations]` leaf deltas.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshLeaf {
    /// `[[ssh.destinations.add]]` / `[[ssh.destinations.remove]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<SshDestinationDelta>,
}

/// An add/remove delta over SSH destination grants.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshDestinationDelta {
    /// Entries to add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<SshDestination>,
    /// Entries to remove, matched by `dest`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<SshDestination>,
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
        if !self.invariant_denies().is_empty() {
            errs.push(
                "a leaf policy may not declare `[[net.proxy.deny.invariant]]`; invariants are \
                 template- and fragment-author tools (docs/design/05-templates.md §5.5)"
                    .to_owned(),
            );
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
            for (label, delta) in [
                ("fs.read", &fs.read),
                ("fs.write", &fs.write),
                ("fs.deny", &fs.deny),
            ] {
                if let Some(d) = delta {
                    for e in d.add.iter().chain(&d.remove) {
                        if path_blank(e) {
                            errs.push(format!("[[{label}.*]] `{}` is missing a `reason`", e.path));
                        }
                    }
                }
            }
            if let Some(dev) = &fs.dev {
                if let Some(d) = &dev.passthrough {
                    for e in d.add.iter().chain(&d.remove) {
                        if e.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                            let who = e.path.as_deref().unwrap_or("<no-path>");
                            errs.push(format!(
                                "[[fs.dev.passthrough.*]] `{who}` is missing a `reason`"
                            ));
                        }
                    }
                }
            }
        }
        if let Some(exec) = &self.exec {
            if let Some(d) = &exec.allow {
                for e in d.add.iter().chain(&d.remove) {
                    if path_blank(e) {
                        errs.push(format!(
                            "[[exec.allow.*]] `{}` is missing a `reason`",
                            e.path
                        ));
                    }
                }
            }
        }
        if let Some(net) = &self.net {
            check_net_reasons(net, errs);
        }
        if let Some(unix) = &self.unix {
            if let Some(d) = &unix.allow {
                for e in d.add.iter().chain(&d.remove) {
                    if e.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                        let who = e
                            .name
                            .as_deref()
                            .or(e.real.as_deref())
                            .unwrap_or("<unnamed>");
                        errs.push(format!("[[unix.allow.*]] `{who}` is missing a `reason`"));
                    }
                }
            }
        }
        if let Some(ssh) = &self.ssh {
            if let Some(d) = &ssh.destinations {
                for e in d.add.iter().chain(&d.remove) {
                    if e.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                        let who = e.dest.as_deref().unwrap_or("<no-dest>");
                        errs.push(format!(
                            "[[ssh.destinations.*]] `{who}` is missing a `reason`"
                        ));
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
        let fs_ok = self.fs.as_ref().is_none_or(|f| {
            path_clean(&f.read)
                && path_clean(&f.write)
                && path_clean(&f.deny)
                && f.dev
                    .as_ref()
                    .is_none_or(|d| d.passthrough.as_ref().is_none_or(|p| p.remove.is_empty()))
        });
        let exec_ok = self.exec.as_ref().is_none_or(|e| path_clean(&e.allow));
        let net_ok = self.net.as_ref().is_none_or(|n| {
            let proxy_ok = n.proxy.as_ref().is_none_or(|p| {
                p.allow.as_ref().is_none_or(|a| a.remove.is_empty())
                    && p.deny
                        .as_ref()
                        .and_then(|d| d.policy.as_ref())
                        .is_none_or(|x| x.remove.is_empty())
            });
            let bpf_ok = n.bpf.as_ref().is_none_or(|b| {
                let acl_clean = |acl: &Option<NetBpfAclLeaf>| {
                    acl.as_ref().is_none_or(|a| {
                        a.allow.as_ref().is_none_or(|x| x.remove.is_empty())
                            && a.deny.as_ref().is_none_or(|x| x.remove.is_empty())
                    })
                };
                acl_clean(&b.connect) && acl_clean(&b.bind)
            });
            proxy_ok && bpf_ok
        });
        let unix_ok = self
            .unix
            .as_ref()
            .is_none_or(|u| u.allow.as_ref().is_none_or(|a| a.remove.is_empty()));
        let ssh_ok = self
            .ssh
            .as_ref()
            .is_none_or(|s| s.destinations.as_ref().is_none_or(|d| d.remove.is_empty()));
        fs_ok && exec_ok && net_ok && unix_ok && ssh_ok
    }

    /// This policy's `[[net.proxy.allow.add]]` entries (for include conflict checks).
    #[must_use]
    pub fn net_allow_adds(&self) -> &[NetAllow] {
        self.net
            .as_ref()
            .and_then(|n| n.proxy.as_ref())
            .and_then(|p| p.allow.as_ref())
            .map_or(&[], |a| a.add.as_slice())
    }

    /// This policy's fragment-declared invariant denies (`[[net.proxy.deny.invariant]]`).
    #[must_use]
    pub fn invariant_denies(&self) -> &[NetDenyRule] {
        self.net
            .as_ref()
            .and_then(|n| n.proxy.as_ref())
            .and_then(|p| p.deny.as_ref())
            .map_or(&[], |d| d.invariant.as_slice())
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
            if let Some(dev) = &fs.dev {
                if let Some(d) = &dev.passthrough {
                    let dev_target = target.dev.get_or_insert_with(Default::default);
                    for entry in &d.add {
                        if !dev_target
                            .passthrough
                            .iter()
                            .any(|e| dev_key(e) == dev_key(entry))
                        {
                            dev_target.passthrough.push(entry.clone());
                        }
                    }
                    dev_target
                        .passthrough
                        .retain(|e| !d.remove.iter().any(|r| dev_key(r) == dev_key(e)));
                }
            }
        }
        if let Some(exec) = &self.exec {
            let target = effective.exec.get_or_insert_with(Default::default);
            apply_paths(&mut target.allow, exec.allow.as_ref());
        }
        if let Some(net) = &self.net {
            apply_net(effective, net);
        }
        if let Some(unix) = &self.unix {
            if let Some(d) = &unix.allow {
                let target = effective.unix.get_or_insert_with(Default::default);
                for entry in &d.add {
                    if !target.allow.iter().any(|e| unix_key(e) == unix_key(entry)) {
                        target.allow.push(entry.clone());
                    }
                }
                target
                    .allow
                    .retain(|e| !d.remove.iter().any(|r| unix_key(r) == unix_key(e)));
            }
        }
        if let Some(ssh) = &self.ssh {
            if let Some(d) = &ssh.destinations {
                let target = effective.ssh.get_or_insert_with(Default::default);
                for entry in &d.add {
                    if !target
                        .destinations
                        .iter()
                        .any(|e| ssh_dest(e) == ssh_dest(entry))
                    {
                        target.destinations.push(entry.clone());
                    }
                }
                target
                    .destinations
                    .retain(|e| !d.remove.iter().any(|r| ssh_dest(r) == ssh_dest(e)));
            }
        }
        // Scalar overrides (`[*.override]`): replace only the fields the leaf sets.
        if let Some(over) = self.lifecycle.as_ref().and_then(|l| l.over.as_ref()) {
            let target = effective.lifecycle.get_or_insert_with(Default::default);
            if over.ttl.is_some() {
                target.ttl.clone_from(&over.ttl);
            }
            if over.ttl_action.is_some() {
                target.ttl_action.clone_from(&over.ttl_action);
            }
        }
        if let Some(over) = self
            .net
            .as_ref()
            .and_then(|n| n.audit.as_ref())
            .and_then(|a| a.over.as_ref())
        {
            let net = effective.net.get_or_insert_with(Default::default);
            let target = net.audit.get_or_insert_with(Default::default);
            if over.log_path.is_some() {
                target.log_path.clone_from(&over.log_path);
            }
            if over.level.is_some() {
                target.level.clone_from(&over.level);
            }
        }
    }
}

/// Apply a leaf's `[net.proxy]`/`[net.bpf]` deltas to the effective policy, in place.
fn apply_net(effective: &mut SourcePolicy, net: &NetLeaf) {
    if let Some(proxy) = &net.proxy {
        if let Some(d) = &proxy.allow {
            let target = effective
                .net
                .get_or_insert_with(Default::default)
                .proxy
                .get_or_insert_with(Default::default);
            for entry in &d.add {
                if !target.allow.iter().any(|e| net_key(e) == net_key(entry)) {
                    target.allow.push(entry.clone());
                }
            }
            target
                .allow
                .retain(|e| !d.remove.iter().any(|r| net_key(r) == net_key(e)));
        }
        if let Some(d) = proxy.deny.as_ref().and_then(|x| x.policy.as_ref()) {
            let deny = effective
                .net
                .get_or_insert_with(Default::default)
                .proxy
                .get_or_insert_with(Default::default)
                .deny
                .get_or_insert_with(Default::default);
            for entry in &d.add {
                if !deny.policy.iter().any(|e| e.cidr == entry.cidr) {
                    deny.policy.push(entry.clone());
                }
            }
            deny.policy
                .retain(|e| !d.remove.iter().any(|r| r.cidr == e.cidr));
        }
    }
    if let Some(bpf) = &net.bpf {
        apply_bpf_acl(effective, bpf.connect.as_ref(), BpfDir::Connect);
        apply_bpf_acl(effective, bpf.bind.as_ref(), BpfDir::Bind);
    }
}

/// Require a `reason` on every `[net.proxy]`/`[net.bpf]` delta entry.
fn check_net_reasons(net: &NetLeaf, errs: &mut Vec<String>) {
    let blank = |r: &Option<String>| r.as_deref().is_none_or(|x| x.trim().is_empty());
    if let Some(proxy) = &net.proxy {
        if let Some(d) = &proxy.allow {
            for e in d.add.iter().chain(&d.remove) {
                if blank(&e.reason) {
                    let who = e
                        .name
                        .as_deref()
                        .or(e.cidr.as_deref())
                        .unwrap_or("<unnamed>");
                    errs.push(format!(
                        "[[net.proxy.allow.*]] `{who}` is missing a `reason`"
                    ));
                }
            }
        }
        if let Some(policy) = proxy.deny.as_ref().and_then(|x| x.policy.as_ref()) {
            for e in policy.add.iter().chain(&policy.remove) {
                if blank(&e.reason) {
                    errs.push(format!(
                        "[[net.proxy.deny.policy.*]] `{}` is missing a `reason`",
                        e.cidr
                    ));
                }
            }
        }
    }
    if let Some(bpf) = &net.bpf {
        for acl in bpf.connect.iter().chain(&bpf.bind) {
            for d in acl.allow.iter().chain(&acl.deny) {
                for e in d.add.iter().chain(&d.remove) {
                    if blank(&e.reason) {
                        let who = e.cidr.as_deref().unwrap_or("<no-cidr>");
                        errs.push(format!("[[net.bpf.*]] `{who}` is missing a `reason`"));
                    }
                }
            }
        }
    }
}

/// Which `[net.bpf]` direction an ACL delta targets.
#[derive(Clone, Copy)]
enum BpfDir {
    /// `[net.bpf.connect]`.
    Connect,
    /// `[net.bpf.bind]`.
    Bind,
}

/// Apply one `[net.bpf.connect]`/`[net.bpf.bind]` ACL delta (allow + deny, each keyed by
/// `cidr`) to the effective policy, in place. Mirrors the allow/deny add/remove pattern of
/// the other deltas.
fn apply_bpf_acl(effective: &mut SourcePolicy, acl: Option<&NetBpfAclLeaf>, dir: BpfDir) {
    let Some(acl) = acl else { return };
    if acl.allow.is_none() && acl.deny.is_none() {
        return;
    }
    let net = effective.net.get_or_insert_with(Default::default);
    let bpf = net.bpf.get_or_insert_with(Default::default);
    let target = match dir {
        BpfDir::Connect => bpf.connect.get_or_insert_with(Default::default),
        BpfDir::Bind => bpf.bind.get_or_insert_with(Default::default),
    };
    apply_bpf_rules(&mut target.allow, acl.allow.as_ref());
    apply_bpf_rules(&mut target.deny, acl.deny.as_ref());
}

/// Apply an add/remove [`BpfRule`] delta (keyed by `cidr`) to a rule list, in place.
fn apply_bpf_rules(target: &mut Vec<BpfRule>, delta: Option<&BpfRuleDelta>) {
    let Some(delta) = delta else { return };
    for entry in &delta.add {
        if !target.iter().any(|e| bpf_key(e) == bpf_key(entry)) {
            target.push(entry.clone());
        }
    }
    target.retain(|e| !delta.remove.iter().any(|r| bpf_key(r) == bpf_key(e)));
}

/// Unique key for a `[net.bpf]` rule (its cidr).
fn bpf_key(r: &BpfRule) -> &str {
    r.cidr.as_deref().unwrap_or("")
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

/// Unique key for an SSH destination grant (the destination string).
fn ssh_dest(a: &SshDestination) -> &str {
    a.dest.as_deref().unwrap_or("")
}

/// Unique key for a device passthrough entry (the device path).
fn dev_key(a: &DevPassthrough) -> &str {
    a.path.as_deref().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{resolve, TemplateSource};
    use crate::source::parse as parse_source;

    const BASE_CONFINED: &str = include_str!("../../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../templates/ai-coding-strict/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(n, v, _)| n == name && v == version)
                .map(|(_, _, b)| b.clone())
        }
    }
    fn src() -> MapSource {
        MapSource(vec![
            (
                "base-confined".to_owned(),
                "v1".to_owned(),
                BASE_CONFINED.as_bytes().to_vec(),
            ),
            (
                "ai-coding-strict".to_owned(),
                "v1".to_owned(),
                AI_CODING_STRICT.as_bytes().to_vec(),
            ),
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

[[net.proxy.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T1.8"]
"#;

    #[test]
    fn leaf_add_grants_project_paths_and_api() {
        let (eff, _) = effective_with_leaf(PROJECT_LEAF);
        let fs = eff.fs.expect("fs");
        assert!(fs
            .read
            .as_ref()
            .expect("read")
            .iter()
            .any(|p| p == "~/projects/myproj/**"));
        assert!(fs
            .write
            .as_ref()
            .expect("write")
            .iter()
            .any(|p| p == "~/projects/myproj/**"));
        // The inherited system read paths survive.
        assert!(fs
            .read
            .as_ref()
            .expect("read")
            .iter()
            .any(|p| p == "/usr/**"));
        let proxy = eff.net.expect("net").proxy.expect("net.proxy");
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("api.anthropic.com")));
        // The inherited registry allows survive.
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
    }

    #[test]
    fn leaf_add_grants_a_device_passthrough() {
        let leaf = r#"
name = "serial-ai"
template_base = "ai-coding-strict@v1"
[[fs.dev.passthrough.add]]
path = "/dev/ttyUSB0"
group = "dialout"
reason = "flash firmware over the serial console"
threats.exposed = ["T2.1"]
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let dev = eff.fs.expect("fs").dev.expect("fs.dev");
        let pt = dev
            .passthrough
            .iter()
            .find(|p| p.path.as_deref() == Some("/dev/ttyUSB0"))
            .expect("device added");
        assert_eq!(pt.group.as_deref(), Some("dialout"));
        // The inherited pseudo-device baseline survives.
        assert!(dev
            .allow
            .as_ref()
            .expect("allow")
            .iter()
            .any(|d| d == "/dev/null"));
    }

    #[test]
    fn leaf_remove_drops_an_inherited_entry() {
        let leaf = r#"
name = "n"
template_base = "ai-coding-strict@v1"
[[net.proxy.allow.remove]]
name = "github.com"
reason = "this workflow does not use github"
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let proxy = eff.net.expect("net").proxy.expect("net.proxy");
        assert!(
            !proxy
                .allow
                .iter()
                .any(|a| a.name.as_deref() == Some("github.com")),
            "github removed"
        );
        assert!(
            proxy
                .allow
                .iter()
                .any(|a| a.name.as_deref() == Some("pypi.org")),
            "others remain"
        );
    }

    #[test]
    fn add_is_idempotent_no_duplicates() {
        let leaf = r#"
name = "n"
template_base = "ai-coding-strict@v1"
[[net.proxy.allow.add]]
name = "github.com"
ports = [443]
reason = "already inherited; should not duplicate"
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let n = eff
            .net
            .expect("net")
            .proxy
            .expect("net.proxy")
            .allow
            .iter()
            .filter(|a| a.name.as_deref() == Some("github.com"))
            .count();
        assert_eq!(n, 1, "no duplicate github.com");
    }

    #[test]
    fn leaf_override_replaces_inherited_scalars() {
        // ai-coding-strict sets ttl 8h / warn; override to 2h / stop and audit full.
        let leaf = r#"
name = "n"
template_base = "ai-coding-strict@v1"
[lifecycle.override]
ttl = "2h"
ttl_action = "stop"
[net.audit.override]
level = "full"
"#;
        let (eff, _) = effective_with_leaf(leaf);
        let lc = eff.lifecycle.expect("lifecycle");
        assert_eq!(lc.ttl.as_deref(), Some("2h"), "ttl overridden");
        assert_eq!(lc.ttl_action.as_deref(), Some("stop"), "action overridden");
        let audit = eff.net.expect("net").audit.expect("audit");
        assert_eq!(
            audit.level.as_deref(),
            Some("full"),
            "audit level overridden"
        );
        // The log_path the leaf did not set is inherited.
        assert!(audit.log_path.is_some(), "unset override field inherits");
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
