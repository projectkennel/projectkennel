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

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use kennel_policy::{
    CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, InstallConstants, LifecyclePolicy, NetMode, NetPolicy,
    NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction, SeccompPolicy, SettledPolicy, SigningKey,
    TmpPolicy, TtlAction,
};
use kennel_privhelper::validate::ReservedScope;
use kennel_spawn::{prepare, RuntimeSubstitutions};
use kennel_syscall::namespace::Namespaces;
use kenneld::{start, EtcSetup, HelperClient, ProxySetup, Spec};

/// Locate a binary built alongside this test (`target/<profile>/<name>`).
fn sibling_binary(name: &str) -> PathBuf {
    // The test executable lives in target/<profile>/deps/; binaries are one up.
    let exe = std::env::current_exe().expect("current exe");
    let profile_dir = exe.parent().and_then(Path::parent).expect("profile dir");
    profile_dir.join(name)
}

/// The privhelper binary; must have been built with `--features bpf-egress`.
fn privhelper_path() -> PathBuf {
    let path = sibling_binary("kennel-privhelper");
    assert!(path.exists(), "privhelper not found at {} — build it with --features bpf-egress", path.display());
    path
}

/// The netproxy binary; build it with `cargo build -p kennel-netproxy`.
fn netproxy_path() -> PathBuf {
    let path = sibling_binary("kennel-netproxy");
    assert!(path.exists(), "netproxy not found at {} — build it with `cargo build -p kennel-netproxy`", path.display());
    path
}

/// Whether something accepts TCP connections at `addr`, retried briefly to let
/// the just-spawned proxy finish binding.
fn listening(addr: &str) -> bool {
    let target: std::net::SocketAddr = addr.parse().expect("addr");
    for _ in 0..40 {
        if TcpStream::connect_timeout(&target, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A settled policy that exercises the constructed view: the system dirs a shell
/// needs (read+exec), the constructed `/etc`, and one granted `~` subdir
/// (`/root/kennel-e2e/granted`, which remaps beneath the shim root). A sibling
/// `~/kennel-e2e/secret` is deliberately NOT granted, so its name must be absent
/// in the view. No seccomp filter; no network allowlist (the orchestration adds
/// the loopback addresses regardless).
fn minimal_policy() -> SettledPolicy {
    SettledPolicy {
        settled_schema_version: 1,
        name: "e2e".to_owned(),
        deferred_substitutions: Vec::new(),
        framework_invariants_asserted: Vec::new(),
        effective_policy: EffectivePolicy {
            net: NetPolicy {
                mode: NetMode::Constrained,
                proxy: kennel_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
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
                read: vec![
                    "/usr".to_owned(),
                    "/bin".to_owned(),
                    "/lib".to_owned(),
                    "/lib64".to_owned(),
                    "/etc".to_owned(),
                    "/root/kennel-e2e/granted".to_owned(),
                ],
                write: Vec::new(),
                tmp: TmpPolicy { private: true, size_mib: 512, mode: "0700".to_owned() },
                dev: DevPolicy { allow: vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()] },
            },
            exec: ExecPolicy {
                deny_setuid: true,
                deny_setgid: true,
                deny_setcap: true,
                deny_writable: true,
                allow: Vec::new(),
            },
            proc: ProcPolicy { visibility: ProcVisibility::SelfOnly, hidepid: true },
            cap: CapPolicy { no_new_privs: true },
            seccomp: SeccompPolicy { deny_action: SeccompAction::Errno, deny: Vec::new() },
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
        ssh: kennel_policy::SshRuntime::default(),
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
    // Drop the PID namespace (spawn unshares CLONE_NEWPID in the *parent* — this
    // test process — which would disrupt the harness's own forks). Keep MOUNT, so
    // the constructed view (pivot_root) is built and the workload observes it;
    // MOUNT is unshared in the child seal and does not affect the harness.
    plan.namespaces = Namespaces::MOUNT;

    // A cgroup base we own; the kennel cgroup is a child of it.
    let base = PathBuf::from("/sys/fs/cgroup/kennel-e2e");
    let cgroup = base.join(format!("kennel-{ctx}"));
    // Best-effort: clear any state a previous interrupted run leaked.
    cleanup(&base, "127.0.144.17/28", "fd00:0:1:1::1/64");
    std::fs::create_dir_all(&base).expect("create cgroup base");

    // Launch the real netproxy as the kennel's egress proxy, and stage a synthetic
    // /etc, both in temp dirs.
    let proxy_cfg = std::env::temp_dir().join(format!("kenneld-e2e-proxy-{}", std::process::id()));
    // Stage /etc under /run, not /tmp: the spawn mounts a fresh tmpfs over /tmp
    // before the shadow binds, which would hide a /tmp-staged source. Production
    // stages under $XDG_RUNTIME_DIR (/run/user/<uid>), likewise outside /tmp.
    let etc_base = PathBuf::from(format!("/run/kenneld-e2e-etc-{}", std::process::id()));
    // The constructed-view new-root staging mountpoint (kenneld creates it, mounts
    // a tmpfs on it in the child seal, pivot_roots into it, removes it on teardown).
    let view_root = PathBuf::from(format!("/run/kenneld-e2e-root-{}", std::process::id()));
    // The per-kennel egress audit log base (production: ~/.local/state/kennel).
    let audit_base = PathBuf::from(format!("/run/kenneld-e2e-audit-{}", std::process::id()));
    let audit_path = audit_base.join("e2e").join("network.jsonl");
    let _ = std::fs::remove_dir_all(&proxy_cfg);
    let _ = std::fs::remove_dir_all(&etc_base);
    let _ = std::fs::remove_dir_all(&view_root);
    let _ = std::fs::remove_dir_all(&audit_base);

    // The granted ~ subdir (with a file) and a non-granted sibling, under the real
    // home. In the view the granted path remaps beneath the shim root; the sibling
    // must be absent (its name gone, not merely denied).
    let home_test = PathBuf::from("/root/kennel-e2e");
    let _ = std::fs::remove_dir_all(&home_test);
    std::fs::create_dir_all(home_test.join("granted")).expect("mkdir granted");
    std::fs::create_dir_all(home_test.join("secret")).expect("mkdir secret");
    std::fs::write(home_test.join("granted/file"), "OK\n").expect("write granted file");
    std::fs::write(home_test.join("secret/file"), "SECRET\n").expect("write secret file");

    let helper = HelperClient::new(privhelper_path());
    let spec = Spec {
        cgroup: cgroup.clone(),
        ctx,
        scope,
        plan,
        net: minimal_policy().effective_policy.net,
        proxy: Some(ProxySetup { binary: netproxy_path(), config_dir: proxy_cfg.clone() }),
        etc: Some(EtcSetup {
            staging_dir: etc_base.join("etc-1"),
            hostname: "e2e".to_owned(),
            username: "root".to_owned(),
            uid: 0,
            gid: 0,
            home: PathBuf::from("/root"),
        }),
        view_root: Some(view_root.clone()),
        audit_path: Some(audit_path.clone()),
    };

    // The workload proves three things about the constructed view, then sleeps so
    // the proxy-listening assertion can run:
    //   1. the synthetic /etc applied — /etc/hosts maps the kennel's own primary
    //      address to its hostname ("e2e"), which the host's /etc/hosts never does;
    //   2. the granted ~ path is readable through the shim ($HOME == shim root);
    //   3. the non-granted sibling's NAME is absent (ENOENT, not merely denied).
    // Any failing clause exits the shell non-zero.
    let mut workload = Command::new("/bin/sh");
    workload.arg("-c").arg(
        "grep -q '127.0.144.17[[:space:]]*localhost e2e' /etc/hosts \
         && test -r \"$HOME/kennel-e2e/granted/file\" \
         && ! test -e \"$HOME/kennel-e2e/secret\" \
         && sleep 2",
    );
    let kennel = start(&helper, spec, &mut workload).expect("start kennel");
    assert!(cgroup.is_dir(), "the kennel cgroup should exist while running");

    // The loopback v4 address (127 | tag 9 | ctx 1 | host 1) should be present.
    let v4 = "127.0.144.17";
    assert!(lo_has(v4), "the kennel's loopback address {v4} should be added");

    // The netproxy should be listening on BOTH the kennel's v4 and v6 addresses
    // (dual-stack: one listener per family, served by the proxy's serve_all).
    let proxy_addr = format!("{v4}:1080");
    assert!(listening(&proxy_addr), "the egress proxy should be listening on {proxy_addr}");
    let proxy_addr6 = "[fd00:0:1:1::1]:1080";
    assert!(listening(proxy_addr6), "the egress proxy should be listening on {proxy_addr6}");
    // And kenneld wrote its config and the synthetic /etc.
    let proxy_config = proxy_cfg.join(format!("proxy-{ctx}.toml"));
    assert!(proxy_config.exists(), "the proxy config should be written");
    let staged_hosts = etc_base.join("etc-1").join("hosts");
    assert!(staged_hosts.exists(), "the synthetic /etc/hosts should be staged");
    // The per-kennel audit log is wired: kenneld created its directory and pointed
    // the proxy config at it (§7.3.4).
    assert!(audit_path.parent().is_some_and(Path::exists), "the audit log directory should be created");
    let written = std::fs::read_to_string(&proxy_config).expect("read proxy config");
    assert!(
        written.contains(&audit_path.display().to_string()),
        "the proxy config should point at the per-kennel audit log"
    );

    // Wait for the workload to finish and tear everything down (incl. the proxy).
    // success ⇒ inside the kennel: synthetic /etc/hosts present, the granted ~ path
    // readable through the shim, and the non-granted sibling's name absent (ENOENT).
    let status = kennel.stop(&helper).expect("stop");
    assert!(status.success(), "the constructed view held (synthetic /etc, granted readable, sibling ENOENT) (got {status:?})");

    assert!(!cgroup.exists(), "the cgroup should be removed on teardown");
    assert!(!lo_has(v4), "the loopback address should be removed on teardown");
    // The proxy is gone: nothing answers on its address now.
    assert!(!quick_connect(&proxy_addr), "the proxy should be killed on teardown");
    // The constructed-view staging mountpoint is removed on teardown.
    assert!(!view_root.exists(), "the view staging mountpoint should be removed on teardown");
    // The audit log directory persists across teardown (it is audit data).
    assert!(audit_base.exists(), "the audit log directory should survive teardown");

    let _ = std::fs::remove_dir_all(&audit_base);
    let _ = std::fs::remove_dir_all(&proxy_cfg);
    let _ = std::fs::remove_dir_all(&etc_base);
    let _ = std::fs::remove_dir_all(&home_test);
    let _ = std::fs::remove_dir(&base);
}

/// Whether `addr` appears on the loopback interface.
fn lo_has(addr: &str) -> bool {
    let out = Command::new("ip").args(["addr", "show", "dev", "lo"]).output().expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

/// A single connection attempt — for asserting the proxy is *gone* without the
/// retry budget of [`listening`].
fn quick_connect(addr: &str) -> bool {
    let target: std::net::SocketAddr = addr.parse().expect("addr");
    TcpStream::connect_timeout(&target, Duration::from_millis(100)).is_ok()
}

/// Best-effort removal of state a prior interrupted run may have leaked.
fn cleanup(base: &Path, v4: &str, v6: &str) {
    // A prior run's proxy could linger and hold the loopback address.
    let _ = Command::new("pkill").args(["-x", "kennel-netproxy"]).output();
    let _ = Command::new("ip").args(["addr", "del", v4, "dev", "lo"]).output();
    let _ = Command::new("ip").args(["-6", "addr", "del", v6, "dev", "lo"]).output();
    let _ = std::fs::remove_dir(base.join("kennel-1"));
    let _ = std::fs::remove_dir(base);
}
