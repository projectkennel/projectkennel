//! End-to-end hardware test of the privileged vertical, gated behind `root-tests`.
//!
//! Drives the public orchestration (`kenneld::start`) with a real signed policy
//! and the **real setuid privhelper binary**, as root, so every privileged step
//! actually happens: the privhelper adds the per-kennel loopback addresses and
//! attaches the egress BPF programs, the spawn joins the workload into its
//! cgroup, and teardown removes it all. Run via:
//!
//! ```text
//! cargo build -p kennel-privhelper --features bpf-egress
//! cargo test  -p kenneld --features root-tests --no-run
//! sudo ./target/debug/deps/e2e-<hash>
//! ```

#![cfg(feature = "root-tests")]

use std::path::{Path, PathBuf};
use std::process::Command;

use kennel_policy::{
    CapPolicy, EffectivePolicy, ExecPolicy, FsPolicy, InstallConstants, LifecyclePolicy, NetMode, NetPolicy, NetRule,
    ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction, SeccompPolicy, SettledPolicy, SigningKey,
    TtlAction,
};
use kennel_privhelper::validate::ReservedScope;
use kennel_spawn::{prepare, RuntimeSubstitutions};
use kennel_syscall::namespace::Namespaces;
use kenneld::{start, HelperClient, Spec};

/// Locate the privhelper binary built alongside this test (`target/<profile>/
/// kennel-privhelper`). It must have been built with `--features bpf-egress`.
fn privhelper_path() -> PathBuf {
    // The test executable lives in target/<profile>/deps/; the binary is one up.
    let exe = std::env::current_exe().expect("current exe");
    let profile_dir = exe.parent().and_then(Path::parent).expect("profile dir");
    let path = profile_dir.join("kennel-privhelper");
    assert!(path.exists(), "privhelper not found at {} — build it with --features bpf-egress", path.display());
    path
}

/// A minimal settled policy that satisfies the framework invariants and lets a
/// trivial workload run: permissive Landlock (read+exec under `/`), no seccomp
/// filter, no network allowlist (the orchestration adds the loopback addresses
/// regardless).
fn minimal_policy() -> SettledPolicy {
    SettledPolicy {
        settled_schema_version: 1,
        name: "e2e".to_owned(),
        deferred_substitutions: Vec::new(),
        framework_invariants_asserted: Vec::new(),
        effective_policy: EffectivePolicy {
            net: NetPolicy {
                mode: NetMode::Constrained,
                allow: Vec::new(),
                deny_invariant: vec![NetRule {
                    cidr: "169.254.169.254".to_owned(),
                    prefix_len: 32,
                    port_min: 0,
                    port_max: 65535,
                    protocol: Protocol::Any,
                }],
            },
            fs: FsPolicy {
                home_shadow: true,
                shim_root: "/run/kennel/e2e".to_owned(),
                read: vec!["/".to_owned()],
                write: Vec::new(),
            },
            exec: ExecPolicy {
                deny_setuid: true,
                deny_setgid: true,
                deny_setcap: true,
                deny_writable: true,
                allow: Vec::new(),
            },
            proc: ProcPolicy { visibility: ProcVisibility::SelfOnly },
            cap: CapPolicy { no_new_privs: true },
            seccomp: SeccompPolicy { default_action: SeccompAction::Errno, allow: Vec::new() },
            lifecycle: LifecyclePolicy { ttl_seconds: None, ttl_action: TtlAction::Warn },
        },
        provenance: Provenance {
            compiler_version: "0.0.0".to_owned(),
            schema_version: 1,
            threat_catalogue_version: "0.1".to_owned(),
            leaf_policy_sha256: "00".to_owned(),
            invariant_set_sha256: "00".to_owned(),
            install_constants: InstallConstants { tag: 9, ula_gid: "fd00::".to_owned() },
            resolved_artifacts: Vec::new(),
        },
    }
}

#[test]
fn full_vertical_brings_up_and_tears_down_a_kennel() {
    // Provision uid 0's allocation (tag 9, gid ...01, namespace kennel-root).
    std::fs::create_dir_all("/etc/kennel").expect("mkdir /etc/kennel");
    std::fs::write("/etc/kennel/subkennel", "0:9:0000000001:kennel-root\n").expect("write allocation");
    let scope = ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-root");

    // Sign the policy and prepare a KeySet that trusts it.
    let key = SigningKey::from_seed("e2e-key", &[3u8; 32]).expect("key");
    let signed = kennel_policy::sign_settled(&minimal_policy(), &key).expect("sign");
    let bytes = kennel_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes()).expect("trust key");

    let ctx = 1u16;
    let subst = RuntimeSubstitutions {
        ctx,
        uid: 0,
        kennel: "e2e".to_owned(),
        home: PathBuf::from("/root"),
        namespace: scope.namespace().to_owned(),
    };
    let mut plan = prepare(&bytes, &keys, &subst).expect("verify + plan");
    // This test verifies the *privileged orchestration* (addresses, BPF, cgroup
    // join, teardown). The namespace isolation is proven separately in
    // kennel-spawn's root tests; we drop it here because spawn unshares the PID
    // namespace in the parent (this test process), which would disrupt the test
    // harness's own forks (e.g. running `ip` to inspect the result).
    plan.namespaces = Namespaces::empty();

    // A cgroup base we own; the kennel cgroup is a child of it.
    let base = PathBuf::from("/sys/fs/cgroup/kennel-e2e");
    let cgroup = base.join(format!("kennel-{ctx}"));
    // Best-effort: clear any state a previous interrupted run leaked.
    cleanup(&base, "127.0.144.17/28", "fd00:0:1:1::1/64");
    std::fs::create_dir_all(&base).expect("create cgroup base");

    let helper = HelperClient::new(privhelper_path());
    let spec = Spec { cgroup: cgroup.clone(), ctx, scope, plan };

    // Bring the kennel up: cgroup + v4/v6 loopback addresses + egress BPF + spawn.
    let kennel = start(&helper, spec, &mut Command::new("/bin/true")).expect("start kennel");
    assert!(cgroup.is_dir(), "the kennel cgroup should exist while running");

    // The loopback v4 address (127 | tag 9 | ctx 1 | host 1) should be present.
    let v4 = "127.0.144.17";
    assert!(lo_has(v4), "the kennel's loopback address {v4} should be added");

    // Wait for /bin/true to finish and tear everything down.
    let status = kennel.stop(&helper).expect("stop");
    assert!(status.success(), "the workload should exit 0 (got {status:?})");

    assert!(!cgroup.exists(), "the cgroup should be removed on teardown");
    assert!(!lo_has(v4), "the loopback address should be removed on teardown");

    let _ = std::fs::remove_dir(&base);
}

/// Whether `addr` appears on the loopback interface.
fn lo_has(addr: &str) -> bool {
    let out = Command::new("ip").args(["addr", "show", "dev", "lo"]).output().expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

/// Best-effort removal of state a prior interrupted run may have leaked.
fn cleanup(base: &Path, v4: &str, v6: &str) {
    let _ = Command::new("ip").args(["addr", "del", v4, "dev", "lo"]).output();
    let _ = Command::new("ip").args(["-6", "addr", "del", v6, "dev", "lo"]).output();
    let _ = std::fs::remove_dir(base.join("kennel-1"));
    let _ = std::fs::remove_dir(base);
}
