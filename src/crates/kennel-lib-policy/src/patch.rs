//! Instantiation-time patch application (Kennel book Vol 2 ch.13 (Dynamic Spawning)).
//!
//! At `SPAWN`, `kenneld` takes a verified spawn-target template and an agent-supplied patch — a list
//! of `(field, value)` pairs — and applies it to produce the instance the kennel actually runs. The
//! instance lives only in memory and is **never re-signed**: its integrity is the verified template
//! signature plus the signed manifest constraints plus this validator, which can only move a field the
//! manifest opens, within the bound it declares.
//!
//! # The mutable-field registry
//!
//! [`is_mutable_field`] and the private `apply_field` are the single authority for *which existing
//! policy-schema leaves are mutable, and how a validated value applies*. A variant naming a field the
//! registry does not know is a hard reject — at the spawner's compile (the manifest validator calls
//! [`is_mutable_field`]) and again here. A variant **never coins a field**: it opens one the schema
//! already has. To make another existing leaf mutable, add an arm to both — and nowhere else.

use crate::settled::{NameRule, NetRule, Protocol, SettledPolicy};
use crate::variant::Destination;
use crate::PolicyError;

/// One entry of an agent's mutable-field patch: an existing schema-leaf path and the value to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    /// The existing policy-schema leaf this entry writes (must be in the manifest and the registry).
    pub field: String,
    /// The agent-supplied value, checked against the field's variant constraint before it applies.
    pub value: String,
}

/// Whether `field` names an existing policy-schema leaf the variant system may open.
///
/// The compile-time manifest validator and the runtime applicator share this, so a manifest cannot
/// name a field nothing knows how to apply — which is also how it cannot name an *invented* field.
#[must_use]
pub fn is_mutable_field(field: &str) -> bool {
    matches!(
        field,
        "net.proxy.allow" | "fs.read" | "fs.write" | "rootfs.writable" | "workload.argv"
    )
}

/// Apply one validated `(field, value)` to the in-memory instance. The value has already passed the
/// field's constraint; this is the typed mutation onto the existing leaf.
fn apply_field(policy: &mut SettledPolicy, field: &str, value: &str) -> Result<(), PolicyError> {
    match field {
        "net.proxy.allow" => apply_net_proxy_allow(policy, value),
        "fs.read" => {
            policy.effective_policy.fs.read.push(value.to_owned());
            Ok(())
        }
        "fs.write" => {
            policy.effective_policy.fs.write.push(value.to_owned());
            Ok(())
        }
        "rootfs.writable" => {
            policy.rootfs.writable.push(value.to_owned());
            Ok(())
        }
        // The command line: the agent supplies the program and its arguments. `argv[0]` is gated by
        // `[exec].allow` (Landlock execve default-deny) regardless of what is written here, so a template
        // that opens this leaf delegates *what runs* without widening *what is reachable* — the cage
        // (net/fs/exec floor, ttl, ceilings) is unchanged. Entries replace the template default in order;
        // the clear happens once in `instantiate`.
        "workload.argv" => {
            policy.workload.argv.push(value.to_owned());
            Ok(())
        }
        // Defence in depth: a field outside the registry should already have been rejected at compile.
        other => Err(PolicyError::Patch(format!(
            "`{other}` is not a mutable policy field"
        ))),
    }
}

/// Apply a `net.proxy.allow` destination to the egress **proxy** allowlist (§7.5). A name lands on
/// `allow_names` (a [`NameRule`]); an IP literal lands on `allow` (a [`NetRule`], host-bits only). Both
/// are consumed by `kenneld`'s proxy `NetRuntime` (`inet.rs`), re-checked against the deny rules at
/// dial time. The cgroup-BPF ACL (`[net.bpf]`) is a separate mechanism and is **never** touched here.
fn apply_net_proxy_allow(policy: &mut SettledPolicy, value: &str) -> Result<(), PolicyError> {
    let dest = Destination::parse(value)
        .map_err(|e| PolicyError::Patch(format!("net.proxy.allow `{value}`: {e}")))?;
    let net = &mut policy.effective_policy.net;
    if let Ok(ip) = dest.host.parse::<std::net::IpAddr>() {
        let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
        net.allow.push(NetRule {
            cidr: dest.host,
            prefix_len,
            port_min: dest.port,
            port_max: dest.port,
            protocol: Protocol::Tcp,
        });
    } else {
        net.allow_names.push(NameRule {
            name: dest.host,
            ports: vec![dest.port],
            protocol: Protocol::Tcp,
        });
    }
    Ok(())
}

/// Apply an agent patch to a verified spawn-target `template`, returning the in-memory instance.
///
/// For each entry: the field must be one the template's manifest opens (out-of-manifest → reject), the
/// value must pass that variant's constraint, and no field may exceed the constraint's entry cap. The
/// result is a clone of the template with the validated mutations applied and the manifest cleared (it
/// is consumed; the instance is never re-signed).
///
/// # Errors
///
/// [`PolicyError::Patch`] for an out-of-manifest field, a value the constraint refuses, more entries
/// than the constraint admits, or a malformed manifest variant.
pub fn instantiate(
    template: &SettledPolicy,
    patch: &[PatchEntry],
) -> Result<SettledPolicy, PolicyError> {
    let mut instance = template.clone();
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();

    // `workload.argv` is the one leaf the patch SETS rather than appends to (the agent supplies the
    // whole command line). Clear the template default once so the entries below replace it in order.
    if patch.iter().any(|e| e.field == "workload.argv") {
        instance.workload.argv.clear();
    }

    for entry in patch {
        let variant = template
            .manifest
            .iter()
            .find(|v| v.field == entry.field)
            .ok_or_else(|| {
                PolicyError::Patch(format!(
                    "field `{}` is not in the template's manifest (out-of-manifest, fail-closed)",
                    entry.field
                ))
            })?;
        let constraint = variant.resolve().map_err(|e| PolicyError::Patch(e.0))?;
        constraint
            .admits(&entry.value)
            .map_err(|d| PolicyError::Patch(d.0))?;

        // Per-field entry cap (the running count across the patch). `workload.argv` is exempt: a
        // command line is a sequence of tokens, bounded by the wire's 64 KiB SPAWN patch cap and by
        // `[exec].allow` (Landlock gates `argv[0]`), not by a manifest entry count.
        let count = counts.entry(entry.field.as_str()).or_insert(0);
        *count = count.saturating_add(1);
        if entry.field != "workload.argv" {
            if let Some(max) = constraint.max_entries() {
                if *count > max {
                    return Err(PolicyError::Patch(format!(
                        "field `{}` exceeds its {max}-entry cap",
                        entry.field
                    )));
                }
            }
        }

        // A `relpath` constraint confines the value UNDER its signed `under` root: join the
        // (traversal-free, admit_relpath-checked) relative value beneath the root so the instantiated
        // policy never carries a path outside it. Without this the `under` root is inert and the agent
        // writes any relative path — a widening past the signed manifest. (Symlink-following within the
        // root is the runtime bind's RESOLVE_IN_ROOT concern, tracked separately.)
        let applied = match &constraint {
            crate::variant::Constraint::Relpath { under } => {
                std::borrow::Cow::Owned(format!("{}/{}", under.trim_end_matches('/'), entry.value))
            }
            _ => std::borrow::Cow::Borrowed(entry.value.as_str()),
        };
        apply_field(&mut instance, &entry.field, &applied)?;
    }

    // The manifest is consumed: the instance is the concrete policy, never itself signed.
    instance.manifest = Vec::new();
    Ok(instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variant::Variant;

    fn template_with(variants: Vec<Variant>) -> SettledPolicy {
        let mut p = crate::settled::sample_settled();
        p.manifest = variants;
        p
    }

    fn entry(field: &str, value: &str) -> PatchEntry {
        PatchEntry {
            field: field.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn registry_knows_only_existing_leaves() {
        assert!(is_mutable_field("net.proxy.allow"));
        assert!(is_mutable_field("fs.write"));
        assert!(!is_mutable_field("fs.workspace")); // the invented name is not a field
        assert!(!is_mutable_field("net.bpf.allow")); // BPF is a separate mechanism, not mutable here
    }

    #[test]
    fn out_of_manifest_field_is_rejected() {
        let t = template_with(vec![Variant {
            field: "fs.read".to_owned(),
            pool: vec!["/opt/data".to_owned()],
            pool_max: 4,
            ..Variant::default()
        }]);
        let err =
            instantiate(&t, &[entry("fs.write", "/etc/shadow")]).expect_err("out-of-manifest");
        assert!(format!("{err}").contains("out-of-manifest"));
    }

    #[test]
    fn pool_admits_members_up_to_max_and_rejects_the_rest() {
        let t = template_with(vec![Variant {
            field: "fs.read".to_owned(),
            pool: vec!["/opt/a".to_owned(), "/opt/b".to_owned()],
            pool_max: 1,
            ..Variant::default()
        }]);
        // A non-member is refused.
        assert!(instantiate(&t, &[entry("fs.read", "/etc")]).is_err());
        // One member applies.
        let ok = instantiate(&t, &[entry("fs.read", "/opt/a")]).expect("one member");
        assert!(ok.effective_policy.fs.read.contains(&"/opt/a".to_owned()));
        assert!(ok.manifest.is_empty(), "instance carries no manifest");
        // Two members exceed max = 1.
        assert!(instantiate(
            &t,
            &[entry("fs.read", "/opt/a"), entry("fs.read", "/opt/b")]
        )
        .is_err());
    }

    #[test]
    fn net_proxy_allow_routes_name_to_proxy_names_and_ip_to_proxy_addrs_never_bpf() {
        let t = template_with(vec![Variant {
            field: "net.proxy.allow".to_owned(),
            pattern: vec!["*.pypi.org:443".to_owned(), "10.0.0.*:443".to_owned()],
            ..Variant::default()
        }]);
        let inst = instantiate(
            &t,
            &[
                entry("net.proxy.allow", "files.pypi.org:443"),
                entry("net.proxy.allow", "10.0.0.7:443"),
            ],
        )
        .expect("both admitted");
        let net = &inst.effective_policy.net;
        // The name went to the proxy by-name list.
        assert!(net
            .allow_names
            .iter()
            .any(|r| r.name == "files.pypi.org" && r.ports == [443]));
        // The IP went to the proxy by-address list — NOT the BPF connect-allow.
        assert!(net
            .allow
            .iter()
            .any(|r| r.cidr == "10.0.0.7" && r.prefix_len == 32));
        assert!(net.bpf_connect_allow.is_empty(), "BPF is never touched");
        // A destination matching no pattern is refused.
        assert!(instantiate(&t, &[entry("net.proxy.allow", "evil.com:443")]).is_err());
    }

    #[test]
    fn relpath_value_is_confined_under_its_signed_root() {
        let t = template_with(vec![Variant {
            field: "fs.write".to_owned(),
            relpath_under: "~/workspace".to_owned(),
            ..Variant::default()
        }]);
        // A traversal-free relpath lands JOINED under the signed root, never as a bare relative path.
        let inst = instantiate(&t, &[entry("fs.write", "sub/dir/file")]).expect("relpath applies");
        assert!(
            inst.effective_policy
                .fs
                .write
                .contains(&"~/workspace/sub/dir/file".to_owned()),
            "value confined under the root: {:?}",
            inst.effective_policy.fs.write
        );
        // `..`/absolute are refused at admit, so the joined value cannot escape the root.
        assert!(instantiate(&t, &[entry("fs.write", "../escape")]).is_err());
        assert!(instantiate(&t, &[entry("fs.write", "/abs")]).is_err());
    }

    #[test]
    fn workload_argv_replaces_the_default_with_the_supplied_command() {
        let mut t = template_with(vec![Variant {
            field: "workload.argv".to_owned(),
            freeform: true,
            reason: "the agent chooses the command; the cage contains it".to_owned(),
            ..Variant::default()
        }]);
        t.workload.argv = vec!["/bin/true".to_owned()]; // the template default

        // Many tokens replace the default in order — not appended to it, and not capped at one
        // (freeform's single-entry cap does not apply to a command line).
        let inst = instantiate(
            &t,
            &[
                entry("workload.argv", "/bin/echo"),
                entry("workload.argv", "-n"),
                entry("workload.argv", "hello world"),
            ],
        )
        .expect("argv applies");
        assert_eq!(
            inst.workload.argv,
            vec![
                "/bin/echo".to_owned(),
                "-n".to_owned(),
                "hello world".to_owned()
            ]
        );
        assert!(inst.manifest.is_empty(), "instance carries no manifest");

        // No argv patch leaves the template default untouched.
        let untouched = instantiate(&t, &[]).expect("empty patch");
        assert_eq!(untouched.workload.argv, vec!["/bin/true".to_owned()]);
    }
}
