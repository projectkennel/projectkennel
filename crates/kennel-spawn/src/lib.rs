//! Project Kennel spawn orchestration.
//!
//! # Purpose
//!
//! Turn a settled policy into a confined workload. The runtime pipeline is:
//! verify the settled-policy bytes (one signature, schema gate, framework
//! invariants — via [`kennel_policy::verify_settled`]); substitute the
//! per-instance placeholders (`<ctx>`, `<uid>`, `<kennel>`, `<home>`) and refuse
//! any that remain; translate the result into a [`Plan`] of kernel enforcement
//! objects; then apply the plan and exec.
//!
//! This crate holds **no `unsafe`** (`#![forbid(unsafe_code)]`): every syscall
//! routes through `kennel-syscall` and `kennel-bpf`.
//!
//! # Scope of this build
//!
//! Implemented: the pure runtime pipeline up to and including the [`Plan`]
//! (verify → substitute → translate), which is fully testable off the spawn
//! path. **Not yet** implemented: the execution step (fork, namespace/mount
//! setup, the Landlock/seccomp seal, cgroup join, BPF attach, exec). That step
//! needs a fork/exec primitive added to `kennel-syscall` (so the post-fork
//! `unsafe` stays in the sanctioned crate), which is a reviewed addition of its
//! own.

#![forbid(unsafe_code)]

pub mod plan;

use std::path::PathBuf;

use kennel_policy::{KeySet, PolicyError, SettledPolicy};

pub use plan::Plan;

/// The per-instance values the runtime fills into a settled policy's deferred
/// placeholders.
#[derive(Debug, Clone)]
pub struct RuntimeSubstitutions {
    /// The kennel's context byte (`<ctx>`), assigned at start.
    pub ctx: u8,
    /// The user's UID (`<uid>`).
    pub uid: u32,
    /// The kennel's runtime ID (`<kennel>`).
    pub kennel: String,
    /// The user's home directory (`<home>`).
    pub home: PathBuf,
}

/// Everything that can stop a spawn before exec.
#[derive(Debug)]
pub enum SpawnError {
    /// The settled policy failed verification (signature, schema, invariants).
    Policy(PolicyError),
    /// A placeholder remained after substitution — the policy referenced a
    /// variable the runtime does not provide.
    UnsubstitutedPlaceholder {
        /// The policy field the placeholder was found in.
        field: String,
        /// The offending value.
        value: String,
    },
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy verification failed: {e}"),
            Self::UnsubstitutedPlaceholder { field, value } => {
                write!(f, "unsubstituted placeholder in {field}: `{value}`")
            }
        }
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::UnsubstitutedPlaceholder { .. } => None,
        }
    }
}

impl From<PolicyError> for SpawnError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

/// Replace the four deferred placeholders in `s`.
fn substitute_str(s: &str, subst: &RuntimeSubstitutions) -> String {
    s.replace("<ctx>", &subst.ctx.to_string())
        .replace("<uid>", &subst.uid.to_string())
        .replace("<kennel>", &subst.kennel)
        .replace("<home>", &subst.home.to_string_lossy())
}

/// Error if `value` still contains an unresolved `<…>` placeholder.
fn reject_leftover(field: &str, value: &str) -> Result<(), SpawnError> {
    if value.contains('<') {
        return Err(SpawnError::UnsubstitutedPlaceholder {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Apply the runtime substitutions to a verified settled policy, returning a copy
/// with placeholders filled. Refuses any placeholder that remains unresolved.
///
/// # Errors
///
/// Returns [`SpawnError::UnsubstitutedPlaceholder`] if a path field still
/// contains a `<…>` token after substitution.
pub fn substitute(policy: &SettledPolicy, subst: &RuntimeSubstitutions) -> Result<SettledPolicy, SpawnError> {
    let mut p = policy.clone();
    let fs = &mut p.effective_policy.fs;

    fs.shim_root = substitute_str(&fs.shim_root, subst);
    reject_leftover("fs.shim_root", &fs.shim_root)?;

    for path in &mut fs.read {
        *path = substitute_str(path, subst);
        reject_leftover("fs.read", path)?;
    }
    for path in &mut fs.write {
        *path = substitute_str(path, subst);
        reject_leftover("fs.write", path)?;
    }
    for bin in &mut p.effective_policy.exec.allow {
        *bin = substitute_str(bin, subst);
        reject_leftover("exec.allow", bin)?;
    }

    Ok(p)
}

/// The runtime entry point: verify settled-policy `bytes`, substitute the
/// per-instance placeholders, and produce the enforcement [`Plan`].
///
/// # Errors
///
/// Returns [`SpawnError::Policy`] if verification fails, or
/// [`SpawnError::UnsubstitutedPlaceholder`] if a placeholder is unresolved.
pub fn prepare(bytes: &[u8], keys: &KeySet, subst: &RuntimeSubstitutions) -> Result<Plan, SpawnError> {
    let verified = kennel_policy::verify_settled(bytes, keys)?;
    let substituted = substitute(&verified, subst)?;
    Ok(Plan::from_policy(&substituted, subst.ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_policy::{
        CapPolicy, EffectivePolicy, ExecPolicy, FsPolicy, InstallConstants, LifecyclePolicy,
        NetMode, NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance,
        SeccompAction, SeccompPolicy, SettledPolicy, SigningKey, TtlAction,
    };
    use kennel_syscall::landlock::{AccessFs, AccessNet};
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;

    fn policy_with_placeholders() -> SettledPolicy {
        SettledPolicy {
            settled_schema_version: 1,
            name: "ai-coding".to_owned(),
            deferred_substitutions: vec!["<ctx>".to_owned(), "<home>".to_owned()],
            framework_invariants_asserted: Vec::new(),
            effective_policy: EffectivePolicy {
                net: NetPolicy {
                    mode: NetMode::Constrained,
                    allow: vec![
                        NetRule { cidr: "93.184.216.0".to_owned(), prefix_len: 24, port_min: 443, port_max: 443, protocol: Protocol::Tcp },
                        NetRule { cidr: "10.1.0.0".to_owned(), prefix_len: 16, port_min: 1024, port_max: 2048, protocol: Protocol::Tcp },
                    ],
                    deny_invariant: vec![NetRule { cidr: "169.254.169.254".to_owned(), prefix_len: 32, port_min: 0, port_max: 65535, protocol: Protocol::Any }],
                },
                fs: FsPolicy {
                    home_shadow: true,
                    shim_root: "/run/kennel/<kennel>".to_owned(),
                    read: vec!["/usr".to_owned(), "<home>/.config".to_owned()],
                    write: vec!["/run/kennel/<kennel>/home".to_owned()],
                },
                exec: ExecPolicy { deny_setuid: true, deny_setgid: true, deny_setcap: true, deny_writable: true, allow: vec!["/usr/bin/python3".to_owned()] },
                proc: ProcPolicy { visibility: ProcVisibility::SelfOnly },
                cap: CapPolicy { no_new_privs: true },
                seccomp: SeccompPolicy { default_action: SeccompAction::Errno, allow: vec![0, 1, 2, 60] },
                lifecycle: LifecyclePolicy { ttl_seconds: None, ttl_action: TtlAction::Warn },
            },
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: 1,
                threat_catalogue_version: "0.1".to_owned(),
                leaf_policy_sha256: "00".to_owned(),
                invariant_set_sha256: "00".to_owned(),
                install_constants: InstallConstants { tag: 42, ula_gid: "fd00::".to_owned() },
                resolved_artifacts: Vec::new(),
            },
        }
    }

    fn subst() -> RuntimeSubstitutions {
        RuntimeSubstitutions { ctx: 7, uid: 1000, kennel: "ai-coding".to_owned(), home: PathBuf::from("/home/dev") }
    }

    #[test]
    fn substitution_fills_placeholders() {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        assert_eq!(p.effective_policy.fs.shim_root, "/run/kennel/ai-coding");
        assert_eq!(p.effective_policy.fs.read, vec!["/usr".to_owned(), "/home/dev/.config".to_owned()]);
        assert_eq!(p.effective_policy.fs.write, vec!["/run/kennel/ai-coding/home".to_owned()]);
    }

    #[test]
    fn leftover_placeholder_is_rejected() {
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("<unknown>/x".to_owned());
        let err = substitute(&p, &subst()).expect_err("must reject");
        assert!(
            matches!(&err, SpawnError::UnsubstitutedPlaceholder { field, .. } if field == "fs.read"),
            "got {err:?}"
        );
    }

    #[test]
    fn plan_translates_policy() {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7);

        // Namespaces: mount/pid/ipc, never net.
        assert_eq!(plan.namespaces, Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC);
        assert!(!plan.namespaces.contains(Namespaces::NET));

        // cgroup carries the context byte.
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel/7"));

        // Landlock: a read rule for each read path, a write rule for each write.
        assert!(plan.landlock_fs.iter().any(|(path, acc)| path == &PathBuf::from("/usr") && acc.contains(AccessFs::EXECUTE)));
        assert!(plan.landlock_fs.iter().any(|(path, acc)| path == &PathBuf::from("/run/kennel/ai-coding/home") && acc.contains(AccessFs::WRITE_FILE)));

        // Landlock net: only the single-port (443) TCP rule; the 1024-2048 range
        // is left to BPF.
        assert_eq!(plan.landlock_net, vec![(443u16, AccessNet::CONNECT_TCP)]);

        // Seccomp passed through.
        assert_eq!(plan.seccomp_allow, vec![0, 1, 2, 60]);
        assert_eq!(plan.seccomp_default, Action::Errno(1));

        // The filter builds without panicking.
        let _filter = plan.seccomp_filter();
    }

    #[test]
    fn prepare_end_to_end_from_signed_bytes() {
        // Sign the policy, then run the full runtime entry point over its bytes.
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_policy::to_bytes(&doc).expect("bytes");
        let mut ks = KeySet::new();
        ks.insert("k", &key.public_key_bytes()).expect("insert");

        let plan = prepare(&bytes, &ks, &subst()).expect("prepare");
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel/7"));
        assert_eq!(plan.seccomp_allow, vec![0, 1, 2, 60]);
    }

    #[test]
    fn prepare_rejects_bad_signature() {
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_policy::to_bytes(&doc).expect("bytes");
        let empty = KeySet::new(); // no trusted keys
        let err = prepare(&bytes, &empty, &subst()).expect_err("must reject");
        assert!(matches!(err, SpawnError::Policy(_)), "got {err:?}");
    }
}
