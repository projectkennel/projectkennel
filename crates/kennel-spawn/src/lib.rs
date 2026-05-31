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

use std::io;
use std::path::PathBuf;
use std::process::{Child, Command};

use kennel_policy::{KeySet, PolicyError, SettledPolicy};
use kennel_syscall::landlock::Ruleset;
use kennel_syscall::namespace::Namespaces;

pub use plan::Plan;

/// The per-instance values the runtime fills into a settled policy's deferred
/// placeholders.
#[derive(Debug, Clone)]
pub struct RuntimeSubstitutions {
    /// The kennel's context number (`<ctx>`), assigned at start. IPv4-enabled
    /// kennels are capped at 255; v6-only kennels may range higher.
    pub ctx: u16,
    /// The user's UID (`<uid>`).
    pub uid: u32,
    /// The kennel's runtime ID (`<kennel>`).
    pub kennel: String,
    /// The user's home directory (`<home>`).
    pub home: PathBuf,
    /// The caller's resource namespace (from `/etc/kennel/subkennel`), under
    /// which this kennel's cgroup lives (`/sys/fs/cgroup/<namespace>/<ctx>`).
    pub namespace: String,
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
    /// A syscall during confinement setup or the spawn itself failed.
    Syscall(io::Error),
    /// The settled policy could not be translated into an enforcement plan
    /// (e.g. a malformed CIDR).
    InvalidPolicy(String),
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy verification failed: {e}"),
            Self::UnsubstitutedPlaceholder { field, value } => {
                write!(f, "unsubstituted placeholder in {field}: `{value}`")
            }
            Self::Syscall(e) => write!(f, "confinement/spawn syscall failed: {e}"),
            Self::InvalidPolicy(m) => write!(f, "policy could not be translated: {m}"),
        }
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::Syscall(e) => Some(e),
            Self::UnsubstitutedPlaceholder { .. } | Self::InvalidPolicy(_) => None,
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
    Plan::from_policy(&substituted, subst.ctx, &subst.namespace)
}

/// Spawn `command` confined by `plan`.
///
/// Applies the irreversible seal (`no_new_privs`, the seccomp filter, the
/// Landlock ruleset) in the forked child immediately before `execve`, via
/// [`kennel_syscall::spawn::spawn_sealed`].
///
/// The confinement objects are built in the parent (so opens and allocations
/// happen pre-`fork`); the child only issues the sealing syscalls. An empty
/// seccomp allowlist means "no seccomp filter" (rely on Landlock); otherwise the
/// allowlist is enforced with the plan's default action.
///
/// # Namespaces
///
/// `CLONE_NEWPID` is unshared in the **parent** before the `Command` fork, so the
/// workload becomes PID 1 of a fresh PID namespace (the flag only affects future
/// children, not the caller). The caller must therefore treat `spawn` as having
/// fork semantics for its own subsequent children. The remaining namespaces
/// (mount, IPC) are unshared in the **child seal** — doing them in the parent
/// would isolate the caller itself. Unsharing any namespace needs privilege
/// (`CAP_SYS_ADMIN`); an unprivileged caller should pass a plan with no
/// namespaces (the Landlock + seccomp seal is still unprivileged).
///
/// # Scope
///
/// This applies namespaces + `no_new_privs` + seccomp + Landlock. The plan's
/// **mount-shim, cgroup-join, and BPF-attach** layers are **not** applied here —
/// they require the privhelper (loopback address, cgroup creation) and are a
/// separate increment. The returned child is namespace/Landlock/seccomp confined
/// but **not** yet network-isolated.
///
/// # Errors
///
/// Returns [`SpawnError::Syscall`] if a namespace unshare, building the ruleset,
/// the seal, or the spawn fails. A seal failure aborts the spawn fail-closed.
pub fn spawn(plan: &Plan, command: &mut Command) -> Result<Child, SpawnError> {
    // Build in the parent: opening the Landlock path fds and allocating the
    // filter here keeps the post-fork seal to syscalls only.
    let filter = if plan.seccomp_allow.is_empty() {
        None
    } else {
        Some(plan.seccomp_filter())
    };

    let mut ruleset = Ruleset::new().map_err(SpawnError::Syscall)?;
    for (path, access) in &plan.landlock_fs {
        ruleset.allow_path(path, *access).map_err(SpawnError::Syscall)?;
    }
    for (port, access) in &plan.landlock_net {
        ruleset.allow_port(*port, *access);
    }

    // PID namespace: unshare in the parent so the next fork lands the workload as
    // PID 1 of a new namespace. Mount/IPC are deferred to the seal.
    if plan.namespaces.contains(Namespaces::PID) {
        kennel_syscall::namespace::unshare(Namespaces::PID).map_err(SpawnError::Syscall)?;
    }
    let seal_ns = plan.namespaces & !Namespaces::PID;

    // The cgroup the workload joins itself into (writes its own pid before any
    // namespace/seal), or None if this plan does not enter a cgroup.
    let cgroup_join = plan.cgroup_join.then(|| plan.cgroup.clone());

    // `restrict_current_process` consumes the ruleset; an Option lets the FnMut
    // seal move it out on its single call.
    let mut ruleset = Some(ruleset);
    let seal = move || -> io::Result<()> {
        // Join the cgroup first, before any namespace/mount change: the BPF
        // attached to it only governs processes that are members, and cgroup
        // membership inherits across the upcoming exec and any fork. The write
        // happens while still in the host mount namespace (cgroupfs visible) and
        // before Landlock seals (which would otherwise deny the write).
        if let Some(cgroup) = &cgroup_join {
            join_cgroup(cgroup)?;
        }
        // Namespaces next; mounts need the mount ns.
        if !seal_ns.is_empty() {
            kennel_syscall::namespace::unshare(seal_ns)?;
        }
        if seal_ns.contains(Namespaces::MOUNT) {
            // Detach propagation from the host, then give the workload a fresh
            // /proc (reflecting its PID namespace) and a private /tmp. The full
            // pivot_root shim ($HOME shadowing, hiding non-granted paths) is a
            // later increment; Landlock already denies access to non-granted
            // paths in the meantime.
            kennel_syscall::mount::make_root_private()?;
            kennel_syscall::mount::mount_special("proc", std::path::Path::new("/proc"))?;
            kennel_syscall::mount::mount_special("tmpfs", std::path::Path::new("/tmp"))?;
        }
        // no_new_privs next: seccomp requires it (Landlock sets it again, idempotently).
        kennel_syscall::process::set_no_new_privs()?;
        if let Some(f) = filter.as_ref() {
            f.install()?;
        }
        let rs = ruleset
            .take()
            .ok_or_else(|| io::Error::other("landlock ruleset already consumed"))?;
        rs.restrict_current_process()
    };

    kennel_syscall::spawn::spawn_sealed(command, seal).map_err(SpawnError::Syscall)
}

/// Join the current process into `cgroup` by writing its own pid to
/// `<cgroup>/cgroup.procs`.
///
/// Called in the forked child's seal. The kernel resolves the written pid in the
/// writer's pid namespace, so writing `getpid()` is correct even after the PID
/// namespace has been unshared (the child is pid 1 of the new namespace and the
/// kernel maps it back). The migration is permitted because the destination is a
/// descendant of kenneld's own delegated cgroup subtree.
fn join_cgroup(cgroup: &std::path::Path) -> io::Result<()> {
    let procs = cgroup.join("cgroup.procs");
    std::fs::write(procs, std::process::id().to_string())
}

/// Load the given BPF programs, populate their egress maps, and attach to a cgroup.
///
/// Populates each program's maps from `plan` and attaches it to `cgroup`. Returns
/// the loaded handles, which the caller must keep alive: dropping them closes the
/// map/program fds (and, with the program, the attachment).
///
/// `objects` pairs each program spec with its compiled object bytes (from
/// [`kennel_bpf::programs`] in production, or compiled in tests). Each program
/// currently gets its own maps; sharing one map set across all programs is a
/// later increment, so for now pass the program(s) whose maps you populate
/// (e.g. `connect4` for the v4 egress allowlist). IPv6 maps and the bind/proxy
/// maps are not yet populated here.
///
/// # Errors
///
/// Returns [`SpawnError::Syscall`] if loading, map population, or attach fails.
pub fn attach_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
    plan: &Plan,
    objects: &[(&'static kennel_bpf::ProgramSpec, &[u8])],
) -> Result<Vec<kennel_bpf::Loaded>, SpawnError> {
    let mut loaded = Vec::new();
    for (spec, elf) in objects {
        let l = kennel_bpf::load_program(elf, spec, kennel_bpf::KENNEL_MAPS)
            .map_err(SpawnError::Syscall)?;
        populate_egress_maps(&l, plan)?;
        l.attach(cgroup, spec.attach_type).map_err(SpawnError::Syscall)?;
        loaded.push(l);
    }
    Ok(loaded)
}

/// Write the plan's egress entries into whichever of a loaded program's maps it
/// references (`kennel_meta_map`, `allow_v4`, `deny_v4`).
fn populate_egress_maps(loaded: &kennel_bpf::Loaded, plan: &Plan) -> Result<(), SpawnError> {
    use kennel_bpf::sys::BPF_ANY;

    if loaded.maps.contains_key("kennel_meta_map") {
        loaded
            .update_map("kennel_meta_map", &0u32.to_ne_bytes(), &plan.bpf_meta, BPF_ANY)
            .map_err(SpawnError::Syscall)?;
    }
    if loaded.maps.contains_key("allow_v4") {
        for (key, value) in &plan.bpf_allow_v4 {
            loaded.update_map("allow_v4", key, value, BPF_ANY).map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v4") {
        for (key, value) in &plan.bpf_deny_v4 {
            loaded.update_map("deny_v4", key, value, BPF_ANY).map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("allow_v6") {
        for (key, value) in &plan.bpf_allow_v6 {
            loaded.update_map("allow_v6", key, value, BPF_ANY).map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v6") {
        for (key, value) in &plan.bpf_deny_v6 {
            loaded.update_map("deny_v6", key, value, BPF_ANY).map_err(SpawnError::Syscall)?;
        }
    }
    Ok(())
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
        RuntimeSubstitutions {
            ctx: 7,
            uid: 1000,
            kennel: "ai-coding".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-dev".to_owned(),
        }
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
        let plan = Plan::from_policy(&p, 7, "kennel-dev").expect("plan");

        // Namespaces: mount/pid/ipc, never net.
        assert_eq!(plan.namespaces, Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC);
        assert!(!plan.namespaces.contains(Namespaces::NET));

        // cgroup lives under the caller's resource namespace, keyed by ctx.
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
        assert!(plan.cgroup_join, "policy-derived plans enter their cgroup");

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

        // BPF egress: both v4 allow rules encode as (lpm_v4_key, allow_entry).
        // 93.184.216.0/24 :443 TCP -> prefixlen 24, octets, port 443 twice, proto 6.
        assert_eq!(plan.bpf_allow_v4.len(), 2);
        let want_key = {
            let [p0, p1, p2, p3] = 24u32.to_ne_bytes();
            [p0, p1, p2, p3, 93, 184, 216, 0]
        };
        let want_val = {
            let [a, b] = 443u16.to_ne_bytes();
            [a, b, a, b, 6, 0, 0, 0]
        };
        assert_eq!(plan.bpf_allow_v4.first(), Some(&(want_key, want_val)));
        // deny_invariant 169.254.169.254/32 any-proto.
        assert_eq!(plan.bpf_deny_v4.len(), 1);
        // meta: magic "KNEL", abi 1, ctx 7.
        let magic = {
            let [m0, m1, m2, m3] = 0x4B4E_454Cu32.to_ne_bytes();
            [m0, m1, m2, m3]
        };
        assert_eq!(plan.bpf_meta.get(0..4), Some(&magic[..]));
        assert_eq!(plan.bpf_meta.get(6), Some(&7u8), "ctx byte");
    }

    #[test]
    fn v6_rules_encode_to_lpm_v6() {
        let mut p = policy_with_placeholders();
        p.effective_policy.net.allow.push(NetRule {
            cidr: "2606:2800:220::".to_owned(),
            prefix_len: 48,
            port_min: 443,
            port_max: 443,
            protocol: Protocol::Tcp,
        });
        let plan = Plan::from_policy(&substitute(&p, &subst()).expect("subst"), 7, "kennel-dev").expect("plan");

        // The two original rules stay v4; the new one lands in v6.
        assert_eq!(plan.bpf_allow_v4.len(), 2);
        assert_eq!(plan.bpf_allow_v6.len(), 1);
        let (key, value) = plan.bpf_allow_v6.first().expect("v6 entry");
        // lpm_v6_key: prefixlen (4 bytes) then the 16 address octets.
        assert_eq!(key.get(0..4), Some(&48u32.to_ne_bytes()[..]));
        let octets = "2606:2800:220::".parse::<std::net::Ipv6Addr>().expect("v6").octets();
        assert_eq!(key.get(4..20), Some(&octets[..]));
        let want_val = {
            let [a, b] = 443u16.to_ne_bytes();
            [a, b, a, b, 6, 0, 0, 0]
        };
        assert_eq!(value, &want_val);
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
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
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

    /// A Landlock-only plan granting read+exec under `read_dirs` and no seccomp.
    fn fs_only_plan(read_dirs: &[&str]) -> Plan {
        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        Plan {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            bind_read: Vec::new(),
            bind_write: Vec::new(),
            landlock_fs: read_dirs.iter().map(|d| (PathBuf::from(*d), access)).collect(),
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(), // empty => no seccomp, isolating the Landlock check
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
        }
    }

    /// Paths a dynamically-linked `/bin/sh` + `/bin/cat` need to start.
    const RUNTIME_DIRS: &[&str] = &["/usr", "/bin", "/lib", "/lib64", "/etc"];

    fn landlock_available() -> bool {
        kennel_syscall::landlock::abi_version().is_ok()
    }

    #[test]
    fn landlock_seal_blocks_an_unlisted_path() {
        if !landlock_available() {
            return; // kernel without Landlock; the seal cannot be exercised here.
        }
        // A readable file whose directory is deliberately NOT in the allowlist.
        let secret = std::env::temp_dir().join("kennel-spawn-landlock-secret");
        std::fs::write(&secret, b"top secret").expect("write secret");

        let plan = fs_only_plan(RUNTIME_DIRS);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("exec cat {}", secret.display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_file(&secret);

        assert!(
            !status.success(),
            "Landlock should have blocked reading the unlisted path (got {status:?})"
        );
    }

    #[test]
    fn landlock_seal_allows_a_listed_path() {
        if !landlock_available() {
            return;
        }
        // /etc/hostname is under /etc, which is in the allowlist.
        let plan = fs_only_plan(RUNTIME_DIRS);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("exec cat /etc/hostname")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "reading an allowed path under the confinement should succeed (got {status:?})"
        );
    }
}

/// Privileged tests (namespace unshare needs `CAP_SYS_ADMIN`). Run with
/// `sudo -E env PATH=$PATH cargo test -p kennel-spawn --features root-tests`.
/// Kept to a single test so its parent-side `CLONE_NEWPID` unshare (which moves
/// the *caller's* future children into a new PID namespace) cannot perturb other
/// tests in the same process.
#[cfg(all(test, feature = "root-tests"))]
mod root_tests {
    use super::*;
    use kennel_syscall::landlock::AccessFs;
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;
    use std::io::Read;
    use std::process::{Command, Stdio};

    #[test]
    fn pid_and_mount_namespace_isolate_the_workload() {
        // mount/pid/ipc isolation, Landlock allowing just enough to run a shell
        // and read /proc, no seccomp. A new PID namespace makes the shell PID 1;
        // the freshly-mounted /proc shows only the namespace's own processes.
        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let dirs = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"];
        let plan = Plan {
            namespaces: Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            bind_read: Vec::new(),
            bind_write: Vec::new(),
            landlock_fs: dirs.iter().map(|d| (PathBuf::from(*d), access)).collect(),
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(),
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
        };

        // Report "<pid>:<number of visible /proc PID dirs>".
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo \"$$:$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)\"")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        assert!(status.success(), "the shell should have run (got {status:?})");

        let out = out.trim();
        let (pid, nproc) = out.split_once(':').unwrap_or(("", ""));
        assert_eq!(pid, "1", "in a new PID namespace the workload is PID 1 (got {out:?})");
        let nproc: usize = nproc.parse().unwrap_or(usize::MAX);
        // Host /proc would show hundreds; the isolated namespace shows a handful.
        assert!(nproc < 20, "fresh /proc should show only the namespace's processes (saw {nproc})");
    }

    use std::net::TcpListener;
    use std::os::fd::AsFd;
    use std::path::Path;

    /// A Landlock/seccomp-free plan that only carries BPF egress data: allow
    /// 127.0.0.1/32 on any protocol/port when `allow_loopback`, else nothing.
    fn egress_plan(allow_loopback: bool) -> Plan {
        let allow = if allow_loopback {
            // 127.0.0.1/32, ports 0..=65535, any protocol.
            vec![(
                {
                    let [p0, p1, p2, p3] = 32u32.to_ne_bytes();
                    [p0, p1, p2, p3, 127, 0, 0, 1]
                },
                {
                    let [hi0, hi1] = u16::MAX.to_ne_bytes();
                    [0, 0, hi0, hi1, 0, 0, 0, 0]
                },
            )]
        } else {
            Vec::new()
        };
        Plan {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            bind_read: Vec::new(),
            bind_write: Vec::new(),
            landlock_fs: Vec::new(),
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(),
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: allow,
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
        }
    }

    /// Connect to `127.0.0.1:port` from inside `cgroup_dir` via a child process
    /// (no `unsafe` here): the child joins the cgroup, then opens a TCP
    /// connection with bash's `/dev/tcp`. Returns whether the connect succeeded.
    fn connect_from_cgroup(cgroup_dir: &Path, port: u16) -> bool {
        let script = format!(
            "echo $$ > {}/cgroup.procs && exec 3<>/dev/tcp/127.0.0.1/{port}",
            cgroup_dir.display()
        );
        Command::new("/bin/bash")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run bash")
            .success()
    }

    /// Attach connect4 to a fresh cgroup with `plan`'s egress maps, run `body`
    /// while attached, then remove the cgroup (which also detaches the program).
    fn with_egress_cgroup(name: &str, plan: &Plan, body: impl FnOnce(&Path)) {
        let cg_path = PathBuf::from(format!("/sys/fs/cgroup/{name}"));
        let _ = std::fs::create_dir(&cg_path);
        let cgfd = std::fs::File::open(&cg_path).expect("open cgroup");
        let elf = kennel_bpf::programs::object("connect4").expect("embedded connect4 object");
        let spec = kennel_bpf::KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        let _loaded = attach_egress(cgfd.as_fd(), plan, &[(spec, elf)]).expect("attach_egress");
        body(&cg_path);
        // The child has exited, so the cgroup is empty; removing it detaches.
        let _ = std::fs::remove_dir(&cg_path);
    }

    #[test]
    fn bpf_egress_enforces_the_allowlist() {
        // A listener so a permitted connect *succeeds* (vs. a denied one failing
        // with EPERM) — success/failure cleanly distinguishes allow from deny.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("addr").port();

        let mut allowed = false;
        with_egress_cgroup("kennel-spawn-egress-allow", &egress_plan(true), |cg| {
            allowed = connect_from_cgroup(cg, port);
        });

        let mut denied = false;
        with_egress_cgroup("kennel-spawn-egress-deny", &egress_plan(false), |cg| {
            denied = !connect_from_cgroup(cg, port);
        });

        assert!(allowed, "connect to an allowlisted destination should be permitted");
        assert!(denied, "connect with an empty allowlist should be denied (fail closed)");
    }

    #[test]
    fn spawn_joins_the_workload_into_its_cgroup() {
        // The workload, spawned with `cgroup_join`, should write itself into the
        // cgroup in the seal — so its /proc/self/cgroup reports that cgroup. Run
        // as root, which may write any cgroup.procs; the delegated-subtree case
        // (unprivileged migration within user@<uid>) is covered separately.
        let name = "kennel-spawn-join-test";
        let cg_path = PathBuf::from(format!("/sys/fs/cgroup/{name}"));
        let _ = std::fs::remove_dir(&cg_path);
        std::fs::create_dir(&cg_path).expect("create cgroup");

        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let plan = Plan {
            namespaces: Namespaces::empty(),
            cgroup: cg_path.clone(),
            cgroup_join: true,
            bind_read: Vec::new(),
            bind_write: Vec::new(),
            landlock_fs: vec![(PathBuf::from("/"), access)], // permissive: isolate the join
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(),
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
        };

        let mut cmd = Command::new("/bin/cat");
        cmd.arg("/proc/self/cgroup").stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child.stdout.take().expect("piped stdout").read_to_string(&mut out).expect("read stdout");
        assert!(child.wait().expect("wait").success(), "the workload should have run");

        assert!(
            out.contains(name),
            "the workload's /proc/self/cgroup should name its kennel cgroup (got {out:?})"
        );
        let _ = std::fs::remove_dir(&cg_path);
    }
}
