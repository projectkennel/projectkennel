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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
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
use kenneld::{start, EtcSetup, HelperClient, ProxySetup, Spec, UnixPrep};

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
                dev: DevPolicy { allow: dev_allow() },
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
        unix: kennel_policy::UnixRuntime::default(),
    }
}

/// The constructed `/dev` allowlist: the pseudo-device baseline plus a real
/// host-device **passthrough** (`/dev/net/tun`, §7.2.8) when the host has it — a
/// device in a `/dev` *subdirectory*, exercising the parent-dir creation + bind that
/// `[[fs.dev.passthrough]]` produces (translate merges passthrough paths into this
/// same allowlist). `/dev/net/tun` is `0666`, so `open()` succeeds without any
/// capability or group — only `TUNSETIFF` would need more, which is out of scope here.
fn dev_allow() -> Vec<String> {
    let mut v = vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()];
    if Path::new("/dev/net/tun").exists() {
        v.push("/dev/net/tun".to_owned());
    }
    v
}

#[test]
#[allow(clippy::too_many_lines)] // one cohesive end-to-end scenario: view + /etc + ssh + unix + dev
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

    // Prepare an SSH egress for the kennel (§7.8): mint a synthetic key and
    // materialise a synthetic ~/.ssh, exactly as `Shared::register_ssh` does, then
    // hand it to the bring-up via `Spec.ssh`. The workload below verifies it landed
    // in the constructed view. (The bastion's re-origination itself is proven
    // separately by `src/tools/ssh-bastion-e2e.sh`; this checks the spawn-path
    // assembly: the synthetic ~/.ssh, the connector bind, and $KENNEL_SOCKS_PROXY.)
    let ssh_stage = PathBuf::from(format!("/run/kenneld-e2e-ssh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ssh_stage);
    let synth_pub =
        kenneld::ssh::mint_synthetic_key(&ssh_stage, "id_github.com", "e2e synthetic").expect("mint synthetic");
    assert!(synth_pub.starts_with("ssh-ed25519 "), "minted a synthetic ed25519 key");
    let socks_bin = sibling_binary("kennel-socks-connect");
    assert!(socks_bin.exists(), "build kennel-socks-connect: cargo build -p kennel-socks-connect");
    let bastion_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestbastionhostkey";
    let host_grants = [kenneld::ssh::HostGrant { host: "github.com", key_file: "id_github.com" }];
    let socks_str = socks_bin.to_string_lossy().into_owned();
    let ssh_params = kenneld::ssh::SshParams {
        bastion_host: "127.0.0.1",
        bastion_port: 8031,
        bastion_host_key: bastion_key,
        socks_connect_bin: &socks_str,
        hosts: &host_grants,
    };
    let ssh_dir = PathBuf::from("/run/kennel/e2e/.ssh");
    let ssh_binds = kenneld::ssh::materialize(&ssh_stage, &ssh_dir, &ssh_params).expect("materialise ~/.ssh");
    let ssh_prep = kenneld::SshPrep {
        file_binds: ssh_binds,
        host_service: Some("127.0.0.1:8031".parse().expect("addr")),
        socks_connect_bin: Some(socks_bin.clone()),
    };

    // Prepare an AF_UNIX socket shim (§7.4): a real host listener socket, bound into
    // the kennel's view at $HOME/kennel-unix.sock, exactly as `Shared::prepare_unix`
    // would. The workload (below) finds it there, connects, and round-trips a byte —
    // proving the shim binds a *working* socket — while a non-granted name is absent
    // (ENOENT). A host echo thread serves "ping" → "pong" for the connection.
    let unix_sock = PathBuf::from(format!("/run/kenneld-e2e-unix-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&unix_sock);
    let unix_listener = UnixListener::bind(&unix_sock).expect("bind unix listener");
    std::thread::spawn(move || {
        for conn in unix_listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut buf = [0u8; 16];
            if let Ok(n) = conn.read(&mut buf) {
                if buf.get(..n) == Some(b"ping".as_slice()) {
                    let _ = conn.write_all(b"pong");
                }
            }
        }
    });
    // shim_root is /run/kennel/e2e (minimal_policy's fs.home.shim_root) — the in-view
    // $HOME — so the socket lands at $HOME/kennel-unix.sock inside the kennel.
    let unix_prep = UnixPrep {
        socket_binds: vec![(unix_sock.clone(), PathBuf::from("/run/kennel/e2e/kennel-unix.sock"))],
        env: Vec::new(),
    };

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
            uid: 0,
            gid: 0,
            // The in-kennel shim $HOME (matches the view), never the operator's home.
            home: PathBuf::from("/run/kennel/e2e"),
        }),
        view_root: Some(view_root.clone()),
        audit_path: Some(audit_path.clone()),
        ssh: ssh_prep,
        unix: unix_prep,
    };

    // The workload proves three things about the constructed view, then sleeps so
    // the proxy-listening assertion can run:
    //   1. the synthetic /etc applied — /etc/hosts maps the kennel's own primary
    //      address to its hostname ("e2e"), which the host's /etc/hosts never does;
    //   2. the granted ~ path is readable through the shim ($HOME == shim root);
    //   3. the non-granted sibling's NAME is absent (ENOENT, not merely denied).
    // Any failing clause exits the shell non-zero.
    // Clause (4): the synthetic ~/.ssh landed in the view — the generated config
    // routes github through the bastion via the SOCKS connector ProxyCommand, the
    // known_hosts pins only the bastion under its alias, the disposable synthetic
    // key is present, the connector binary is bound in, and $KENNEL_SOCKS_PROXY is
    // set to the kennel's proxy. None of this exists for a kennel without [ssh].
    let ssh_clause = format!(
        "&& test -f \"$HOME/.ssh/config\" \
         && grep -q 'ProxyCommand .*kennel-socks-connect %h %p' \"$HOME/.ssh/config\" \
         && grep -q 'HostKeyAlias kennel-bastion' \"$HOME/.ssh/config\" \
         && grep -q '^kennel-bastion ssh-ed25519 ' \"$HOME/.ssh/known_hosts\" \
         && test -f \"$HOME/.ssh/id_github.com\" \
         && test -e '{socks}' \
         && test -n \"$KENNEL_SOCKS_PROXY\" ",
        socks = socks_bin.display(),
    );
    // Clause (5): the AF_UNIX socket shim (§7.4) — the granted socket is present as a
    // socket at its shim path AND actually connectable (round-trips ping→pong to the
    // host echo listener through the bind), while a non-granted name is absent (ENOENT).
    let unix_clause = "&& test -S \"$HOME/kennel-unix.sock\" \
         && ! test -e \"$HOME/kennel-not-granted.sock\" \
         && test \"$(python3 -c \"import socket,os;s=socket.socket(socket.AF_UNIX);s.connect(os.environ['HOME']+'/kennel-unix.sock');s.sendall(b'ping');print(s.recv(16).decode(),end='')\")\" = pong ";
    // Clause (6): device passthrough (§7.2.8) — the granted /dev/net/tun is present as
    // a char device in its subdir AND openable (O_RDWR), while a non-granted device
    // (/dev/mem) is absent from the constructed /dev (default-deny). Skips the tun
    // checks if the host has no /dev/net/tun (then it was not granted either).
    let dev_clause = if Path::new("/dev/net/tun").exists() {
        "&& test -c /dev/net/tun \
         && python3 -c \"import os;os.close(os.open('/dev/net/tun',os.O_RDWR))\" \
         && ! test -e /dev/mem "
    } else {
        "&& ! test -e /dev/mem "
    };
    // Clause (7): identity masking — the synthetic /etc/passwd + /etc/group present
    // the workload's uid/gid as `kennel`, and the passwd home is the in-kennel $HOME,
    // so no operator login name or real home leaks (`id`/`getpwuid`).
    let id_clause = "&& grep -q '^kennel:' /etc/passwd \
         && grep -q '^kennel:' /etc/group \
         && ! grep -q '/home/' /etc/passwd ";
    let mut workload = Command::new("/bin/sh");
    workload.arg("-c").arg(format!(
        "grep -q '127.0.144.17[[:space:]]*localhost e2e' /etc/hosts \
         && test -r \"$HOME/kennel-e2e/granted/file\" \
         && ! test -e \"$HOME/kennel-e2e/secret\" \
         {ssh_clause} \
         {unix_clause} \
         {dev_clause} \
         {id_clause} \
         && sleep 2",
    ));
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
    // readable through the shim, the non-granted sibling's name absent (ENOENT), and
    // the synthetic ~/.ssh laid in (config via the SOCKS connector, bastion-pinned
    // known_hosts, the synthetic key) with $KENNEL_SOCKS_PROXY set (§7.8).
    let status = kennel.stop(&helper).expect("stop");
    assert!(
        status.success(),
        "the constructed view held (synthetic /etc + ~/.ssh, granted readable, sibling ENOENT, \
         the AF_UNIX socket shim present + connectable, a non-granted socket name absent) (got {status:?})"
    );

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
    let _ = std::fs::remove_dir_all(&ssh_stage);
    let _ = std::fs::remove_file(&unix_sock);
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
