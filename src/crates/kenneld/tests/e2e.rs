//! End-to-end hardware tests of the **unprivileged** production vertical, gated
//! behind the `e2e` feature; they run as the ordinary operator, *no sudo*.
//!
//! These drive the public orchestration (`run_kennel`) in-process with a real signed
//! policy and the **real file-caps privhelper binary**, on the production userns path:
//! the sandbox (mount namespace, `pivot_root`, the constructed view) is built
//! unprivileged via an identity-mapped user namespace, and the privhelper (file-caps,
//! never sudo) writes the maps and attaches the egress BPF. They cover the wiring a
//! shell driver cannot easily reach: the universal-factory gating (`no_ipc`), the TTL
//! lifecycle (`ttl_exit`/`ttl_warn`), and the interactive pty (`interactive_pty`).
//!
//! The **constructed-view behaviour** (fs grants, masked identity, the four net modes,
//! the `AF_UNIX` facade, dev passthrough) is proven separately by the `kennel run`-driven
//! policy suite — self-checking signed policies under `tests/policy-suite/`, run by
//! `src/tools/policy-e2e.sh`. That is the self-hosting path (the workload's exit code is
//! the verdict); these in-process tests complement it where Rust-level harnessing of
//! signals, ptys, or the orchestration return value is needed.
//!
//! Both need the same one-time host setup (factory caps on the privhelper, an
//! `/etc/kennel/subkennel` allocation, a root-owned `kennel-bin-init`, an `AppArmor`
//! `userns` grant, a writable delegated cgroup). For these in-process tests the runner
//! is `src/tools/unprivileged-e2e.sh`; where a prerequisite is missing a test **skips
//! with the precise cause** (never a false pass).

#![cfg(feature = "e2e")]

use std::path::{Path, PathBuf};

use kennel_lib_policy::{
    CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, LifecyclePolicy, NetMode,
    NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction,
    SeccompPolicy, SettledPolicy, SigningKey, TmpPolicy, TtlAction,
};
use kennel_privhelper::validate::ReservedScope;
use kenneld::HelperClient;

/// The operator's allocation, matching the `/etc/kennel/subkennel` line the runner
/// provisions for the test uid: `<uid>:42:0000000002:kennel-dev`.
const TEST_TAG: u16 = 42;
const TEST_ULA_GID: [u8; 5] = [0, 0, 0, 0, 2];
const TEST_NAMESPACE: &str = "kennel-dev";

/// Locate a binary built alongside this test (`target/<profile>/<name>`).
fn sibling_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let profile_dir = exe.parent().and_then(Path::parent).expect("profile dir");
    profile_dir.join(name)
}

/// The file-caps privhelper; must have been built with `--features bpf-egress` and
/// had `setcap cap_net_admin,cap_sys_admin,cap_setgid=ep` applied (the runner does
/// both). We do not assert its caps here — a missing cap surfaces as a precise
/// runtime skip when the first privileged op fails.
fn privhelper_path() -> PathBuf {
    let path = sibling_binary("kennel-privhelper");
    assert!(
        path.exists(),
        "privhelper not found at {} — run src/tools/unprivileged-e2e.sh",
        path.display()
    );
    path
}

/// The operator's user runtime dir (`$XDG_RUNTIME_DIR`, e.g. `/run/user/1000`) — a
/// user-writable location *outside* `/tmp` (which the spawn covers with a fresh
/// tmpfs), where the synthetic `/etc`, view root, audit log, `~/.ssh` stage and
/// `AF_UNIX` socket are staged. Production stages under the same path.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || {
            PathBuf::from(format!(
                "/run/user/{}",
                kennel_lib_syscall::unistd::real_uid()
            ))
        },
        PathBuf::from,
    )
}

/// The operator's own delegated cgroup subtree, derived from `/proc/self/cgroup`
/// (the cgroup-v2 `0::` line) — under `systemd-run --user --scope -p Delegate=yes`
/// this is writable, so kenneld can create the kennel's cgroup beneath it. Returns
/// the `kennel-e2e` base directory to create the per-kennel cgroup in.
fn own_cgroup_base() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let rel = rel.strip_prefix('/').unwrap_or(rel);
    Some(PathBuf::from("/sys/fs/cgroup").join(rel).join("kennel-e2e"))
}

/// A settled policy exercising the constructed view: the system dirs a shell needs
/// (read+exec), the constructed `/etc`, and one granted `~` subdir
/// (`<home>/kennel-e2e/granted`, which remaps beneath the shim root). A sibling
/// `~/kennel-e2e/secret` is deliberately NOT granted, so its name must be absent.
fn minimal_policy(home: &Path) -> SettledPolicy {
    SettledPolicy {
        settled_schema_version: 1,
        name: "e2e".to_owned(),
        deferred_substitutions: Vec::new(),
        framework_invariants_asserted: Vec::new(),
        effective_policy: EffectivePolicy {
            net: NetPolicy {
                mode: NetMode::Constrained,
                proxy: kennel_lib_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
                deny_invariant: vec![NetRule {
                    cidr: "169.254.169.254".to_owned(),
                    prefix_len: 32,
                    port_min: 0,
                    port_max: 65535,
                    protocol: Protocol::Any,
                }],
                deny_author: Vec::new(),
                bpf_connect_allow: Vec::new(),
                bpf_connect_deny: Vec::new(),
                bpf_bind_allow: Vec::new(),
                bpf_bind_deny: Vec::new(),
                bind_port_min: 0,
                bind_allowed_ports: Vec::new(),
            },
            fs: FsPolicy {
                home_shadow: true,
                read: vec![
                    "/usr".to_owned(),
                    "/bin".to_owned(),
                    "/lib".to_owned(),
                    "/lib64".to_owned(),
                    "/etc".to_owned(),
                    format!("{}/kennel-e2e/granted", home.display()),
                ],
                write: Vec::new(),
                home_persist: Vec::new(),
                home_readonly: false,
                tmp: TmpPolicy {
                    private: true,
                    size_mib: 512,
                    mode: "0700".to_owned(),
                },
                dev: DevPolicy { allow: dev_allow() },
            },
            exec: ExecPolicy {
                deny_setuid: true,
                deny_setgid: true,
                deny_setcap: true,
                deny_writable: true,
                // `**` = the permissive-exec opt-in: execution is deny-by-default now,
                // so the vertical's workload (`/bin/sh`, `id`) needs an explicit grant.
                // This test exercises the spawn pipeline, not the exec allowlist.
                allow: vec!["**".to_owned()],
                deny: Vec::new(),
                path: Vec::new(),
                shell: "/bin/sh".to_owned(),
                loaders: Vec::new(),
            },
            proc: ProcPolicy {
                visibility: ProcVisibility::SelfOnly,
                hidepid: true,
            },
            cap: CapPolicy { no_new_privs: true },
            seccomp: SeccompPolicy {
                deny_action: SeccompAction::Errno,
                deny: Vec::new(),
            },
            lifecycle: LifecyclePolicy {
                ttl_seconds: None,
                ttl_action: TtlAction::Warn,
            },
            tty: kennel_lib_policy::TtyPolicy::default(),
            trust: kennel_lib_policy::TrustPolicy::default(),
        },
        provenance: Provenance {
            compiler_version: "0.0.0".to_owned(),
            schema_version: 1,
            threat_catalogue_version: "0.1".to_owned(),
            leaf_policy_sha256: "00".to_owned(),
            invariant_set_sha256: "00".to_owned(),
            resolved_artifacts: Vec::new(),
        },
        ssh: kennel_lib_policy::SshRuntime::default(),
        // One [unix] grant so the derived plan mounts binderfs and grants the binder
        // device (the af-unix facade rides binder). The `real` here is a placeholder —
        // the bring-up's `binder_prep` carries the actual host listener path the facade
        // connects; what matters for the plan is that `unix` is non-empty (mirrors a
        // production settled policy that carries [unix]).
        unix: kennel_lib_policy::UnixRuntime {
            sockets: vec![kennel_lib_policy::UnixSocket {
                name: "echo".to_owned(),
                real: "/placeholder.sock".to_owned(),
                shim: "/home/kennel/kennel-unix.sock".to_owned(),
                env: None,
            }],
        },
        identity: kennel_lib_policy::IdentityRuntime::default(),
        binder: kennel_lib_policy::BinderRuntime::default(),
        audit: kennel_lib_policy::AuditRuntime::default(),
        env: kennel_lib_policy::EnvRuntime::default(),
        ulimits: kennel_lib_policy::UlimitsRuntime::default(),
        workload: kennel_lib_policy::WorkloadRuntime::default(),
    }
}

/// The constructed `/dev` allowlist: the pseudo-device baseline plus the real
/// host-device passthrough `/dev/net/tun` (§7.4.8) when present (`0666`, so `open()`
/// needs no capability or group).
fn dev_allow() -> Vec<String> {
    let mut v = vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()];
    if Path::new("/dev/net/tun").exists() {
        v.push("/dev/net/tun".to_owned());
    }
    v
}

/// Whether `/etc/kennel/subkennel` has a line for `uid` (the privhelper's reserved
/// scope source).
fn subkennel_has_line(uid: u32) -> bool {
    std::fs::read_to_string("/etc/kennel/subkennel")
        .is_ok_and(|t| t.lines().any(|l| l.trim().starts_with(&format!("{uid}:"))))
}

/// on a real error or any other variant.
#[cfg(feature = "e2e")]
#[must_use]
fn bring_up_skipped(resp: &kenneld::control::Response) -> bool {
    use kenneld::control::Response;
    if let Response::Error(msg) = resp {
        let lower = msg.to_lowercase();
        if ["userns", "permission", "capabilit", "privhelper", "eperm"]
            .iter()
            .any(|n| lower.contains(n))
        {
            eprintln!("SKIP: environment not privileged enough for the factory: {msg}");
            return true;
        }
    }
    assert!(
        matches!(resp, Response::Started { .. }),
        "bring-up: expected Started, got {resp:?}"
    );
    false
}

/// A no-IPC settled policy: no `[unix]`/`[ssh]`/`[binder]`, net mode `none`. Used to prove
/// the factory + binder bus are **universal** — even a kennel granting no IPC is built by
/// the privhelper factory and gets a binderfs instance for the `kennel-bin-init` pull.
fn no_ipc_policy(home: &Path) -> SettledPolicy {
    let mut p = minimal_policy(home);
    p.unix = kennel_lib_policy::UnixRuntime::default(); // no af-unix grant (ssh/binder already empty)
    p
}

/// Self-hosting: drive the **real** `run_kennel` (the production per-kennel path the daemon
/// runs) with the real privhelper and a real `TrustStoreLoader`, for a no-IPC kennel.
///
/// This exercises the exact production orchestration in-process: load+verify the policy,
/// build the plan, decide the factory, construct via the privhelper. It is the gate proving
/// the universal-factory gating (`run_kennel` builds a `BinderPrep` for **every** kennel) and
/// that a plain kennel actually constructs + runs via the factory. The broader
/// constructed-view scenarios (fs, identity, net modes, the `AF_UNIX` facade) live in the
/// `kennel run`-driven policy suite (`tests/policy-suite/`, run by `src/tools/policy-e2e.sh`).
#[test]
fn no_ipc_kennel_runs_through_the_factory() {
    use kenneld::control::{recv_response, Response, StartRequest};
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{run_kennel, Identity, Shared};
    use std::os::unix::net::UnixStream;

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    // Play kenneld's role: become a subreaper so the orphaned kennel-bin-init (the factory exits as
    // soon as it reports the pid) reparents to this process and `wait_pid` can collect its status.
    let _ = kennel_lib_syscall::process::set_child_subreaper();
    if uid == 0 {
        eprintln!("SKIP: the unprivileged vertical runs as the operator, not root");
        return;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("SKIP: HOME is not set");
        return;
    };
    if !subkennel_has_line(uid) {
        eprintln!("SKIP: no /etc/kennel/subkennel line — run src/tools/unprivileged-e2e.sh");
        return;
    }
    let Some(base) = own_cgroup_base() else {
        eprintln!("SKIP: cannot read a delegated cgroup base");
        return;
    };
    if std::fs::create_dir_all(&base).is_err() {
        eprintln!("SKIP: cgroup base not writable — run under the e2e runner");
        return;
    }

    // Sign the no-IPC policy and trust the key (the real verify path runs in the loader).
    let key = SigningKey::from_seed("noipc-key", &[7u8; 32]).expect("key");
    let signed = kennel_lib_policy::sign_settled(&no_ipc_policy(&home), &key).expect("sign");
    let bytes = kennel_lib_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_lib_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes())
        .expect("trust key");

    let run = runtime_dir();
    let tag = std::process::id();
    let policy_file = run.join(format!("kenneld-noipc-policy-{tag}.bin"));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let etc_base = run.join(format!("kenneld-noipc-etc-{tag}"));
    let view_root = run.join(format!("kenneld-noipc-root-{tag}"));
    let audit_base = run.join(format!("kenneld-noipc-audit-{tag}"));
    for p in [&etc_base, &view_root, &audit_base] {
        let _ = std::fs::remove_dir_all(p);
    }

    let identity = Identity {
        uid,
        gid,
        username: "dev".to_owned(),
        home,
        scope: ReservedScope::new(TEST_TAG, TEST_ULA_GID, TEST_NAMESPACE),
        cgroup_base: base,
        proxy: None,
        etc_base: Some(etc_base.clone()),
        view_base: Some(view_root.clone()),
        audit_base: Some(audit_base.clone()),
        bastion: None,
        afunix_bin: Some(sibling_binary("facade-afunix")),
        init_bin: Some(sibling_binary("kennel-bin-init")),
        tracer: kennel_lib_config::Tracer::new("kenneld", kennel_lib_config::LogLevel::Info),
    };
    let shared = Shared::new(
        identity,
        HelperClient::new(privhelper_path()),
        TrustStoreLoader::from_keys(keys),
    );

    let req = StartRequest {
        policy: policy_file,
        kennel: "noipc".to_owned(),
        // The workload proves it ran inside a factory-built view: a binderfs device exists
        // (the factory mounted it even with no IPC granted) and the synthetic /etc/passwd
        // carries the masked `kennel` account.
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "test -e /dev/binderfs/binder && grep -q '^kennel:' /etc/passwd".to_owned(),
        ],
        cwd: PathBuf::from("/"),
        term: String::new(),
        interactive: false,
        force: false,
    };

    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    run_kennel(&shared, &req, Vec::new(), &mut server);

    if bring_up_skipped(&recv_response(&mut client).expect("a first response")) {
        return;
    }
    assert_eq!(
        recv_response(&mut client).expect("an exit response"),
        Response::Exited { code: 0 },
        "the no-IPC kennel ran through the factory (binderfs present + masked /etc/passwd)"
    );

    let _ = std::fs::remove_dir_all(&etc_base);
    let _ = std::fs::remove_dir_all(&view_root);
    let _ = std::fs::remove_dir_all(&audit_base);
}

/// **The masked workspace manifest is invisible inside the kennel (T2.8), end to end.**
/// A kennel with `fs.write` to a project containing a real `.trust-manifest.json` runs a
/// workload that inspects the manifest from *inside*: the §7.4 view mask over-mounts an
/// empty file at the manifest path (inside the writable bind), so the workload sees a
/// zero-byte file it cannot read the integrity pins from — yet the host inode underneath
/// is untouched. This is the diode proof, and specifically proves the over-mount of a
/// child path *inside* a writable bind survives the construction (the plan's hardware
/// risk).
// allow(too_many_lines): one cohesive scenario (set up a writable project + host manifest,
// run a workload that inspects the masked file, assert the host inode is untouched).
#[allow(clippy::too_many_lines)]
#[test]
fn trust_manifest_is_masked_inside_the_kennel() {
    use kenneld::control::{recv_response, Response, StartRequest};
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{run_kennel, Identity, Shared};
    use std::os::unix::net::UnixStream;

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    let _ = kennel_lib_syscall::process::set_child_subreaper();
    if uid == 0 {
        eprintln!("SKIP: the unprivileged vertical runs as the operator, not root");
        return;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("SKIP: HOME is not set");
        return;
    };
    if !subkennel_has_line(uid) {
        eprintln!("SKIP: no /etc/kennel/subkennel line — run src/tools/unprivileged-e2e.sh");
        return;
    }
    let Some(base) = own_cgroup_base() else {
        eprintln!("SKIP: cannot read a delegated cgroup base");
        return;
    };
    if std::fs::create_dir_all(&base).is_err() {
        eprintln!("SKIP: cgroup base not writable — run under the e2e runner");
        return;
    }

    // A writable project under the operator's home, with a real (non-empty) manifest the
    // kennel must mask, plus a Makefile (a trigger). `~/kennel-e2e/manifest` remaps beneath
    // the shim $HOME inside the kennel.
    let proj = home.join("kennel-e2e/manifest");
    std::fs::create_dir_all(&proj).expect("mkdir project");
    let host_manifest = proj.join(".trust-manifest.json");
    let manifest_body =
        b"{\n  \"version\": \"1.0\",\n  \"generator\": \"test\",\n  \"execution\": {\n    \"triggers\": {\"Makefile\": \"sha256:deadbeef\"},\n    \"boundaries\": {\"untrusted_paths\": []}\n  }\n}\n";
    std::fs::write(&host_manifest, manifest_body).expect("write host manifest");
    std::fs::write(proj.join("Makefile"), b"all:\n\techo hi\n").expect("write makefile");

    let mut policy = no_ipc_policy(&home);
    policy
        .effective_policy
        .fs
        .write
        .push("~/kennel-e2e/manifest".to_owned());

    let key = SigningKey::from_seed("trust-key", &[9u8; 32]).expect("key");
    let signed = kennel_lib_policy::sign_settled(&policy, &key).expect("sign");
    let bytes = kennel_lib_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_lib_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes())
        .expect("trust key");

    let run = runtime_dir();
    let tag = std::process::id();
    let policy_file = run.join(format!("kenneld-trust-policy-{tag}.bin"));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let etc_base = run.join(format!("kenneld-trust-etc-{tag}"));
    let view_root = run.join(format!("kenneld-trust-root-{tag}"));
    let audit_base = run.join(format!("kenneld-trust-audit-{tag}"));
    for p in [&etc_base, &view_root, &audit_base] {
        let _ = std::fs::remove_dir_all(p);
    }

    let identity = Identity {
        uid,
        gid,
        username: "dev".to_owned(),
        home,
        scope: ReservedScope::new(TEST_TAG, TEST_ULA_GID, TEST_NAMESPACE),
        cgroup_base: base,
        proxy: None,
        etc_base: Some(etc_base.clone()),
        view_base: Some(view_root.clone()),
        audit_base: Some(audit_base.clone()),
        bastion: None,
        afunix_bin: Some(sibling_binary("facade-afunix")),
        init_bin: Some(sibling_binary("kennel-bin-init")),
        tracer: kennel_lib_config::Tracer::new("kenneld", kennel_lib_config::LogLevel::Info),
    };
    let shared = Shared::new(
        identity,
        HelperClient::new(privhelper_path()),
        TrustStoreLoader::from_keys(keys),
    );

    // The workload runs in the remapped project ($HOME/kennel-e2e/manifest → the persona
    // home). It asserts: the manifest path EXISTS but is EMPTY (the empty over-mount) and
    // does NOT contain the host body's "deadbeef" pin. Exit 0 iff masked correctly.
    let req = StartRequest {
        policy: policy_file,
        kennel: "trust".to_owned(),
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "test -e .trust-manifest.json && test ! -s .trust-manifest.json && ! grep -q deadbeef .trust-manifest.json".to_owned(),
        ],
        cwd: PathBuf::from("/home/kennel/kennel-e2e/manifest"),
        term: String::new(),
        interactive: false,
        force: false,
    };

    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    run_kennel(&shared, &req, Vec::new(), &mut server);

    if bring_up_skipped(&recv_response(&mut client).expect("a first response")) {
        let _ = std::fs::remove_dir_all(&proj);
        return;
    }
    assert_eq!(
        recv_response(&mut client).expect("an exit response"),
        Response::Exited { code: 0 },
        "inside the kennel the manifest is present-but-empty and carries none of the host pins (masked)"
    );

    // The host inode is untouched: the real manifest still has its original body + pin.
    let after = std::fs::read(&host_manifest).expect("read host manifest after");
    assert_eq!(
        after, manifest_body,
        "the host-side manifest is unchanged by the masking over-mount"
    );

    let _ = std::fs::remove_dir_all(&proj);
    let _ = std::fs::remove_dir_all(&etc_base);
    let _ = std::fs::remove_dir_all(&view_root);
    let _ = std::fs::remove_dir_all(&audit_base);
}

/// Bring up a kennel with a **1-second TTL** and `action`, running `argv`, and return
/// `(elapsed, exit_code)` — or `None` to skip on an under-privileged runner. Proves the §9.7
/// path end to end: `kennel-bin-init`'s timer → the blocking `NOTIFY_TTL_EXPIRED` call → kenneld
/// freezes the cgroup and, per `action`, kills it (`exit`) or thaws + replies RESUME (`warn`).
fn run_ttl_kennel(
    name: &str,
    action: kennel_lib_policy::TtlAction,
    argv: Vec<String>,
) -> Option<(std::time::Duration, i32)> {
    use kenneld::control::{recv_response, Response, StartRequest};
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{run_kennel, Identity, Shared};
    use std::os::unix::net::UnixStream;

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    let _ = kennel_lib_syscall::process::set_child_subreaper();
    if uid == 0 {
        eprintln!("SKIP: the unprivileged vertical runs as the operator, not root");
        return None;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if !subkennel_has_line(uid) {
        eprintln!("SKIP: no /etc/kennel/subkennel line — run src/tools/unprivileged-e2e.sh");
        return None;
    }
    let base = own_cgroup_base()?;
    if std::fs::create_dir_all(&base).is_err() {
        eprintln!("SKIP: cgroup base not writable — run under the e2e runner");
        return None;
    }

    let mut policy = no_ipc_policy(&home);
    policy.effective_policy.lifecycle.ttl_seconds = Some(1);
    policy.effective_policy.lifecycle.ttl_action = action;

    let key = SigningKey::from_seed("ttl-key", &[8u8; 32]).expect("key");
    let signed = kennel_lib_policy::sign_settled(&policy, &key).expect("sign");
    let bytes = kennel_lib_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_lib_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes())
        .expect("trust key");

    let run = runtime_dir();
    let tag = std::process::id();
    let policy_file = run.join(format!("kenneld-ttl-{name}-{tag}.bin"));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let etc_base = run.join(format!("kenneld-ttl-etc-{name}-{tag}"));
    let view_root = run.join(format!("kenneld-ttl-root-{name}-{tag}"));
    let audit_base = run.join(format!("kenneld-ttl-audit-{name}-{tag}"));
    for p in [&etc_base, &view_root, &audit_base] {
        let _ = std::fs::remove_dir_all(p);
    }
    let cleanup = |a: &Path, b: &Path, c: &Path| {
        let _ = std::fs::remove_dir_all(a);
        let _ = std::fs::remove_dir_all(b);
        let _ = std::fs::remove_dir_all(c);
    };

    let identity = Identity {
        uid,
        gid,
        username: "dev".to_owned(),
        home,
        scope: ReservedScope::new(TEST_TAG, TEST_ULA_GID, TEST_NAMESPACE),
        cgroup_base: base,
        proxy: None,
        etc_base: Some(etc_base.clone()),
        view_base: Some(view_root.clone()),
        audit_base: Some(audit_base.clone()),
        bastion: None,
        afunix_bin: Some(sibling_binary("facade-afunix")),
        init_bin: Some(sibling_binary("kennel-bin-init")),
        tracer: kennel_lib_config::Tracer::new("kenneld", kennel_lib_config::LogLevel::Info),
    };
    let shared = Shared::new(
        identity,
        HelperClient::new(privhelper_path()),
        TrustStoreLoader::from_keys(keys),
    );

    let req = StartRequest {
        policy: policy_file,
        kennel: name.to_owned(),
        argv,
        cwd: PathBuf::from("/"),
        term: String::new(),
        interactive: false,
        force: false,
    };

    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    let started_at = std::time::Instant::now();
    run_kennel(&shared, &req, Vec::new(), &mut server);
    let elapsed = started_at.elapsed();

    if bring_up_skipped(&recv_response(&mut client).expect("a first response")) {
        cleanup(&etc_base, &view_root, &audit_base);
        return None;
    }
    let exit = recv_response(&mut client).expect("an exit response");
    cleanup(&etc_base, &view_root, &audit_base);
    let code = match exit {
        Response::Exited { code } => Some(code),
        _ => None,
    }
    .expect("the ttl kennel should report Exited");
    Some((elapsed, code))
}

/// **TTL `exit`, end to end (§9.7).** A `sleep 30` workload under a 1s exit-TTL: `kennel-bin-init`'s
/// timer fires the blocking `NOTIFY_TTL_EXPIRED`, kenneld freezes + kills the cgroup, and the
/// kennel dies ~1s in (not 30s) with a killed status.
#[test]
fn ttl_exit_terminates_the_kennel_at_the_deadline() {
    let Some((elapsed, code)) = run_ttl_kennel(
        "ttlexit",
        kennel_lib_policy::TtlAction::Exit,
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "sleep 30".to_owned()],
    ) else {
        return;
    };
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "the 1s TTL must terminate the kennel well before the 30s sleep (took {elapsed:?})"
    );
    assert_ne!(
        code, 0,
        "an exit-action TTL terminates the kennel (got a clean {code})"
    );
}

/// **TTL `warn`, end to end (the suspend→resume symmetry).** A `sleep 3; exit 0` workload under
/// a 1s warn-TTL: at 1s the kennel is frozen, audited, thawed, and the blocking call returns
/// RESUME — so the workload survives the TTL and completes cleanly at ~3s.
#[test]
fn ttl_warn_suspends_then_resumes_the_workload() {
    let Some((elapsed, code)) = run_ttl_kennel(
        "ttlwarn",
        kennel_lib_policy::TtlAction::Warn,
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "sleep 3; exit 0".to_owned(),
        ],
    ) else {
        return;
    };
    assert_eq!(
        code, 0,
        "a warn-action TTL leaves the workload running; it exits cleanly (got {code})"
    );
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "the workload ran its full ~3s (it was not killed at the 1s TTL) (took {elapsed:?})"
    );
}

/// The shared setup for the interactive-pty tests: the operator identity, a signed
/// policy that grants `/dev/pts` (so the view gets a devpts and `openpty` works), the
/// `Shared` orchestration handle, and the temp dirs to clean up. `None` ⇒ a precondition
/// is missing (printed); the caller returns (a skip, never a false pass).
struct InteractiveHarness {
    shared: kenneld::server::Shared<HelperClient, kenneld::policy::TrustStoreLoader>,
    policy_file: PathBuf,
    cleanup: Vec<PathBuf>,
}

/// Build [`InteractiveHarness`] keyed by `tag` (so concurrent-free, distinct temp dirs and
/// kennel names per test). Mirrors the host preconditions the runner provisions.
fn interactive_harness(tag: &str) -> Option<InteractiveHarness> {
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{Identity, Shared};

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    // Subreaper: the orphaned kennel-bin-init reparents here so `wait_pid` collects it.
    let _ = kennel_lib_syscall::process::set_child_subreaper();
    if uid == 0 {
        eprintln!("SKIP: the unprivileged vertical runs as the operator, not root");
        return None;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if !subkennel_has_line(uid) {
        eprintln!("SKIP: no /etc/kennel/subkennel line — run src/tools/unprivileged-e2e.sh");
        return None;
    }
    let base = own_cgroup_base()?;
    if std::fs::create_dir_all(&base).is_err() {
        eprintln!("SKIP: cgroup base not writable — run under the e2e runner");
        return None;
    }

    let mut policy = no_ipc_policy(&home);
    policy
        .effective_policy
        .fs
        .dev
        .allow
        .extend(["/dev/pts/**".to_owned(), "/dev/tty".to_owned()]);

    let key = SigningKey::from_seed("pty-key", &[5u8; 32]).expect("key");
    let signed = kennel_lib_policy::sign_settled(&policy, &key).expect("sign");
    let bytes = kennel_lib_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_lib_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes())
        .expect("trust key");

    let run = runtime_dir();
    let policy_file = run.join(format!("kenneld-{tag}-policy-{}.bin", std::process::id()));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let pid = std::process::id();
    let etc_base = run.join(format!("kenneld-{tag}-etc-{pid}"));
    let view_root = run.join(format!("kenneld-{tag}-root-{pid}"));
    let audit_base = run.join(format!("kenneld-{tag}-audit-{pid}"));
    for p in [&etc_base, &view_root, &audit_base] {
        let _ = std::fs::remove_dir_all(p);
    }

    let identity = Identity {
        uid,
        gid,
        username: "dev".to_owned(),
        home,
        scope: ReservedScope::new(TEST_TAG, TEST_ULA_GID, TEST_NAMESPACE),
        cgroup_base: base,
        proxy: None,
        etc_base: Some(etc_base.clone()),
        view_base: Some(view_root.clone()),
        audit_base: Some(audit_base.clone()),
        bastion: None,
        afunix_bin: Some(sibling_binary("facade-afunix")),
        init_bin: Some(sibling_binary("kennel-bin-init")),
        tracer: kennel_lib_config::Tracer::new("kenneld", kennel_lib_config::LogLevel::Info),
    };
    let shared = Shared::new(
        identity,
        HelperClient::new(privhelper_path()),
        TrustStoreLoader::from_keys(keys),
    );
    Some(InteractiveHarness {
        shared,
        policy_file,
        cleanup: vec![etc_base, view_root, audit_base],
    })
}

/// **Interactive pty through the factory, end to end.** Drives the real `run_kennel` with
/// `interactive: true` and a return socket; the workload runs on a controlling tty allocated
/// in the kennel's own devpts, and its pty master is handed back over the return socket. This
/// proves the construction-socket pty path: kenneld passes the return socket on the construct
/// channel → the factory re-homes it at `PTY_RETURN_FD` → `kennel-bin-init` inherits it across
/// `fexecve` → the seal's `setup_view_pty` allocates the pty and sends the master back. The
/// workload's `test -t 1` confirms its stdout really is a tty.
#[test]
fn interactive_pty_attaches_a_controlling_tty_via_the_factory() {
    use kenneld::control::{recv_response, Response, StartRequest};
    use kenneld::server::run_kennel;
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let Some(h) = interactive_harness("pty") else {
        return;
    };

    // The CLI's proxied-terminal socket: kenneld's PtyBroker fans the workload's
    // filtered pty output to `child` and we read it from `ours`. (The master stays in
    // kenneld now — the client gets bytes, not the fd.)
    let (ours, child) = UnixStream::pair().expect("client terminal socketpair");
    let req = StartRequest {
        policy: h.policy_file.clone(),
        kennel: "pty".to_owned(),
        // `test -t 1` proves stdout is a tty (the pty slave); the echo lands on the master.
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "test -t 1 && echo KENNEL_PTY_OK".to_owned(),
        ],
        cwd: PathBuf::from("/"),
        term: "xterm".to_owned(),
        interactive: true,
        force: false,
    };

    let (mut control, mut server) = UnixStream::pair().expect("control socketpair");
    // We are the broker's client: drain `ours` (the proxied-terminal end) until the
    // broker shuts down on workload exit and closes our socket (EOF). `run_kennel`
    // blocks until the workload exits, so the broker pump runs on its own thread.
    let output = std::thread::scope(|s| {
        let reader = s.spawn(|| -> Vec<u8> {
            let mut out = Vec::new();
            let mut sock = ours.try_clone().expect("dup client socket");
            let _ = sock.read_to_end(&mut out);
            out
        });
        run_kennel(&h.shared, &req, vec![OwnedFd::from(child)], &mut server);
        reader.join().expect("pty reader thread")
    });

    if bring_up_skipped(&recv_response(&mut control).expect("a first response")) {
        return;
    }
    assert_eq!(
        recv_response(&mut control).expect("an exit response"),
        Response::Exited { code: 0 },
        "`test -t 1` succeeds ⇒ the workload's stdout is a controlling tty"
    );

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("KENNEL_PTY_OK"),
        "the workload's tty output came back over the pty master: {text:?}"
    );

    for p in &h.cleanup {
        let _ = std::fs::remove_dir_all(p);
    }
}

/// **Detach → workload survives → reattach takes over → exit, end to end.** The crux of
/// the broker: the kennel's life is the *workload's*, not the *client's*. We run a
/// workload that blocks reading its pty until it sees a sentinel line, then:
///
/// 1. attach a first client (the `run_kennel` Start connection), see the prompt;
/// 2. **detach** it (close the socket) — the workload must keep running;
/// 3. `kennel attach` a **second** client, which takes over (replays the ring, so it sees
///    the earlier prompt) and is the only one now reading the pty;
/// 4. write the sentinel through the second client → the workload echoes it and exits.
///
/// If detach killed the workload, step 4's echo never arrives and the run never exits.
// allow(too_many_lines): one cohesive end-to-end scenario (start → read → detach →
// assert-survives → reattach → replay → sentinel → exit); splitting it would hide the
// sequencing the test exists to prove.
#[allow(clippy::too_many_lines)]
#[test]
fn detach_keeps_the_workload_alive_then_reattach_takes_over() {
    use kenneld::control::{recv_response, Request, Response, StartRequest};
    use kenneld::server::{dispatch_request, run_kennel};
    use std::io::{Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let Some(h) = interactive_harness("detach") else {
        return;
    };
    let kennel = "detach";

    // A workload that prints a prompt, then blocks until it reads `GO`, then echoes and
    // exits. `read` blocks on the pty slave — so the workload only ends once a client
    // feeds the sentinel, giving us a window to detach and reattach.
    let req = StartRequest {
        policy: h.policy_file.clone(),
        kennel: kennel.to_owned(),
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo KENNEL_PROMPT; read x; echo GOT:$x".to_owned(),
        ],
        cwd: PathBuf::from("/"),
        term: "xterm".to_owned(),
        interactive: true,
        force: false,
    };

    // First client = the Start connection. Run `run_kennel` on its own thread: it blocks
    // until the workload exits (which won't happen until we feed the sentinel), so the
    // broker (and the kennel) live across the detach/reattach below.
    let (client1, client1_peer) = UnixStream::pair().expect("client1 socketpair");
    let (mut control1, mut server1) = UnixStream::pair().expect("control1 socketpair");
    let shared = std::sync::Arc::new(h.shared);
    let run_shared = std::sync::Arc::clone(&shared);
    let run_thread = std::thread::spawn(move || {
        run_kennel(
            &run_shared,
            &req,
            vec![OwnedFd::from(client1_peer)],
            &mut server1,
        );
        drop(run_shared);
    });

    // The Start handshake: `Started` (or a skip if a precondition like the cgroup is
    // unmet on this host — then we cannot prove the scenario, so skip cleanly).
    let first = recv_response(&mut control1).expect("a first response");
    if bring_up_skipped(&first) {
        let _ = run_thread.join();
        return;
    }
    assert!(
        matches!(first, Response::Started { .. }),
        "interactive run starts: {first:?}"
    );

    // Read the prompt on the first client (proves the broker is fanning output to it).
    let mut c1 = client1.try_clone().expect("dup client1");
    c1.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("rtimeout");
    let mut buf = [0u8; 256];
    let n = c1.read(&mut buf).expect("first client reads the prompt");
    assert!(
        String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).contains("KENNEL_PROMPT"),
        "first client saw the workload prompt"
    );

    // (2) DETACH: drop the first client's sockets. The workload (blocked on `read`) must
    // keep running — the broker keeps draining the master with no client attached.
    drop(c1);
    drop(client1);
    // Give the broker a beat to notice the client went away; the workload must NOT exit.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !run_thread.is_finished(),
        "detaching the client must NOT end the workload"
    );

    // (3) REATTACH a second client via the real Attach dispatch, on its own thread (the
    // attach handler blocks for that client's session, like the daemon's per-conn thread).
    let (client2, client2_peer) = UnixStream::pair().expect("client2 socketpair");
    let (mut control2, mut server2) = UnixStream::pair().expect("control2 socketpair");
    let attach_shared = std::sync::Arc::clone(&shared);
    let kennel_owned = kennel.to_owned();
    let attach_thread = std::thread::spawn(move || {
        dispatch_request(
            &attach_shared,
            Request::Attach {
                kennel: kennel_owned,
            },
            vec![OwnedFd::from(client2_peer)],
            &mut server2,
        );
    });

    let attached = recv_response(&mut control2).expect("an attach response");
    assert!(
        matches!(attached, Response::Attached { .. }),
        "second client attaches to the running kennel: {attached:?}"
    );

    // The reattached client replays the ring tail — so it sees the earlier prompt.
    let mut c2 = client2.try_clone().expect("dup client2");
    c2.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("rtimeout");
    let n = c2
        .read(&mut buf)
        .expect("second client reads the replayed prompt");
    assert!(
        String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).contains("KENNEL_PROMPT"),
        "reattached client replays the ring tail (the earlier prompt)"
    );

    // (4) Feed the sentinel through the second client → the workload echoes and exits.
    c2.write_all(b"GO\n")
        .expect("write sentinel to the workload");

    // The run thread now unblocks (workload exited); its control conn reports Exited.
    let exited = recv_response(&mut control1).expect("an exit response on the run conn");
    assert_eq!(
        exited,
        Response::Exited { code: 0 },
        "the workload exits after the reattached client feeds the sentinel"
    );
    run_thread.join().expect("run thread");
    let _ = attach_thread.join();

    for p in &h.cleanup {
        let _ = std::fs::remove_dir_all(p);
    }
}
