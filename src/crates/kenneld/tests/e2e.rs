//! End-to-end hardware test of the **unprivileged** production vertical, gated
//! behind `root-tests` (the feature name is historical — the test itself runs as
//! the ordinary operator, *no sudo*).
//!
//! Drives the public orchestration (`kenneld::start`) with a real signed policy
//! and the **real file-caps privhelper binary**, as the operator, on the
//! production userns path: the sandbox (mount namespace, `pivot_root`, the
//! constructed view) is built unprivileged via an identity-mapped user namespace,
//! the privhelper (file-caps, never sudo) adds the per-kennel loopback addresses,
//! attaches the egress BPF, and writes the workload's `gid_map` to re-grant a
//! supplementary group (§7.2.8), and teardown removes it all.
//!
//! It needs one-time host setup, all performed by `src/tools/unprivileged-e2e.sh`:
//! the privhelper built with `--features bpf-egress` and `setcap
//! cap_net_admin,cap_sys_admin,cap_setgid=ep`; an `/etc/kennel/subkennel`
//! allocation line for the operator's uid; an `AppArmor` profile granting `userns`
//! to the test binary (Ubuntu's `apparmor_restrict_unprivileged_userns=1`); and a
//! **writable delegated cgroup** — the runner re-executes the test under
//! `systemd-run --user --scope -p Delegate=yes`. Where a prerequisite is missing
//! the test **skips with the precise cause** (never a false pass).
//!
//! ```text
//! src/tools/unprivileged-e2e.sh
//! ```

#![cfg(feature = "root-tests")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use kennel_policy::{
    CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, InstallConstants, LifecyclePolicy, NetMode, NetPolicy,
    NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction, SeccompPolicy, SettledPolicy, SigningKey,
    TmpPolicy, TtlAction,
};
use kennel_privhelper::addr::{loopback_v4, loopback_v6, V4_PREFIX};
use kennel_privhelper::validate::ReservedScope;
use kennel_spawn::{prepare, RuntimeSubstitutions};
use kenneld::{start, EtcSetup, Error, HelperClient, Privileged, ProxySetup, Spec, UnixPrep};

/// The operator's allocation, matching the `/etc/kennel/subkennel` line the runner
/// provisions for the test uid: `<uid>:42:0000000002:kennel-dev`.
const TEST_TAG: u16 = 42;
const TEST_ULA_GID: [u8; 5] = [0, 0, 0, 0, 2];
const TEST_NAMESPACE: &str = "kennel-dev";
/// The synthetic name the granted supplementary group resolves to inside the kennel.
const GRANTED_GROUP_NAME: &str = "kennelgrp";

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
    assert!(path.exists(), "privhelper not found at {} — run src/tools/unprivileged-e2e.sh", path.display());
    path
}

/// The netproxy binary; built by the runner (`cargo build -p kennel-netproxy`).
fn netproxy_path() -> PathBuf {
    let path = sibling_binary("kennel-netproxy");
    assert!(path.exists(), "netproxy not found at {} — run src/tools/unprivileged-e2e.sh", path.display());
    path
}

/// The operator's user runtime dir (`$XDG_RUNTIME_DIR`, e.g. `/run/user/1000`) — a
/// user-writable location *outside* `/tmp` (which the spawn covers with a fresh
/// tmpfs), where the synthetic `/etc`, view root, audit log, `~/.ssh` stage and
/// `AF_UNIX` socket are staged. Production stages under the same path.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", kennel_syscall::unistd::real_uid())),
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

/// A supplementary group the operator actually holds (so the privhelper's
/// membership check passes), other than its primary gid — the group re-granted into
/// the kennel via the `gid_map` handshake. `None` if the operator has no extra
/// group (then the test proves default drop-all instead).
fn pick_granted_group() -> Option<u32> {
    let primary = kennel_syscall::unistd::real_gid();
    kennel_syscall::unistd::supplementary_groups().into_iter().find(|&g| g != primary)
}

/// Whether something accepts TCP connections at `addr`, retried briefly to let the
/// just-spawned proxy finish binding.
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
                    format!("{}/kennel-e2e/granted", home.display()),
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
        identity: kennel_policy::IdentityRuntime::default(),
    }
}

/// The constructed `/dev` allowlist: the pseudo-device baseline plus the real
/// host-device passthrough `/dev/net/tun` (§7.2.8) when present (`0666`, so `open()`
/// needs no capability or group).
fn dev_allow() -> Vec<String> {
    let mut v = vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()];
    if Path::new("/dev/net/tun").exists() {
        v.push("/dev/net/tun".to_owned());
    }
    v
}

#[test]
#[allow(clippy::too_many_lines)] // one cohesive end-to-end scenario: view + /etc + ssh + unix + dev + groups
fn full_vertical_brings_up_and_tears_down_a_kennel_unprivileged() {
    let uid = kennel_syscall::unistd::real_uid();
    let gid = kennel_syscall::unistd::real_gid();
    assert_ne!(uid, 0, "this is the UNPRIVILEGED vertical — run it as the operator, not root (see the runner)");

    // Prerequisite 1: the operator must have an /etc/kennel/subkennel allocation
    // matching TEST_* (the runner provisions it). Without it the privhelper has no
    // reserved scope and refuses every op; skip with the precise cause.
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("SKIP: HOME is not set");
        return;
    };
    if !subkennel_has_line(uid) {
        eprintln!(
            "SKIP: no /etc/kennel/subkennel line for uid {uid} — run src/tools/unprivileged-e2e.sh \
             (it provisions `{uid}:{TEST_TAG}:0000000002:{TEST_NAMESPACE}`)"
        );
        return;
    }

    // Prerequisite 2: a writable delegated cgroup. Under a plain login session
    // scope the subtree is root-owned; the runner re-execs us under
    // `systemd-run --user --scope -p Delegate=yes`. Skip with the precise cause.
    let Some(base) = own_cgroup_base() else {
        eprintln!("SKIP: cannot read /proc/self/cgroup (cgroup v2 `0::` line)");
        return;
    };
    if std::fs::create_dir_all(&base).is_err() {
        eprintln!(
            "SKIP: cgroup base {} is not writable — run the test under \
             `systemd-run --user --scope -p Delegate=yes` (the runner does this)",
            base.display()
        );
        return;
    }

    let scope = ReservedScope::new(TEST_TAG, TEST_ULA_GID, TEST_NAMESPACE);
    let ctx = 1u16;

    // Sign the policy and trust the key.
    let key = SigningKey::from_seed("e2e-key", &[3u8; 32]).expect("key");
    let signed = kennel_policy::sign_settled(&minimal_policy(&home), &key).expect("sign");
    let bytes = kennel_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes()).expect("trust key");

    let subst = RuntimeSubstitutions {
        ctx,
        uid,
        kennel: "e2e".to_owned(),
        home: home.clone(),
        namespace: TEST_NAMESPACE.to_owned(),
    };
    let mut plan = prepare(&bytes, &keys, &subst).expect("verify + plan");
    // The production userns path stands as prepared: USER | MOUNT | IPC | PID. No
    // override (unlike the legacy root scenario) — PID is unshared inside the seal's
    // child, never in this harness, so the harness's own forks are undisturbed.
    assert!(
        plan.namespaces.contains(kennel_syscall::namespace::Namespaces::USER),
        "the production plan unshares a user namespace (the unprivileged foundation)"
    );

    // Re-grant one real supplementary group the operator holds via the gid_map
    // handshake (§7.2.8); the privhelper (cap_setgid) writes the multi-gid map. With
    // no extra group the kennel proves default drop-all instead.
    let granted = pick_granted_group();
    plan.supplementary_groups = granted.map(|g| vec![g]);

    let cgroup = base.join(format!("kennel-{ctx}"));
    let helper = HelperClient::new(privhelper_path());

    // Stage everything the bring-up binds under the user runtime dir (outside /tmp).
    let run = runtime_dir();
    let tag = std::process::id();
    let proxy_cfg = run.join(format!("kenneld-e2e-proxy-{tag}"));
    let etc_base = run.join(format!("kenneld-e2e-etc-{tag}"));
    let view_root = run.join(format!("kenneld-e2e-root-{tag}"));
    let audit_base = run.join(format!("kenneld-e2e-audit-{tag}"));
    let audit_path = audit_base.join("e2e").join("network.jsonl");
    let ssh_stage = run.join(format!("kenneld-e2e-ssh-{tag}"));
    let unix_sock = run.join(format!("kenneld-e2e-unix-{tag}.sock"));
    for p in [&proxy_cfg, &etc_base, &view_root, &audit_base, &ssh_stage] {
        let _ = std::fs::remove_dir_all(p);
    }
    let _ = std::fs::remove_file(&unix_sock);

    // Best-effort: clear any leftover loopback addresses a prior interrupted run left
    // (via the privhelper — unprivileged `ip addr del` cannot).
    let v4 = loopback_v4(scope.tag(), u8::try_from(ctx).expect("ctx fits u8 for a v4 kennel"), kenneld::PROXY_HOST);
    let v6 = loopback_v6(scope.ula_gid(), ctx, u64::from(kenneld::PROXY_HOST));
    let _ = helper.del_address(ctx, "lo", v4.into(), V4_PREFIX);
    let _ = Command::new("pkill").args(["-x", "kennel-netproxy"]).output();

    // The granted ~ subdir (with a file) and a non-granted sibling, under the real
    // home. In the view the granted path remaps beneath the shim root; the sibling
    // must be absent (its name gone, not merely denied).
    let home_test = home.join("kennel-e2e");
    let _ = std::fs::remove_dir_all(&home_test);
    std::fs::create_dir_all(home_test.join("granted")).expect("mkdir granted");
    std::fs::create_dir_all(home_test.join("secret")).expect("mkdir secret");
    std::fs::write(home_test.join("granted/file"), "OK\n").expect("write granted file");
    std::fs::write(home_test.join("secret/file"), "SECRET\n").expect("write secret file");

    // SSH egress (§7.8): mint a synthetic key + ~/.ssh, exactly as
    // `Shared::register_ssh` does, and hand it to the bring-up via `Spec.ssh`.
    let synth_pub =
        kenneld::ssh::mint_synthetic_key(&ssh_stage, "id_github.com", "e2e synthetic").expect("mint synthetic");
    assert!(synth_pub.starts_with("ssh-ed25519 "), "minted a synthetic ed25519 key");
    let socks_bin = sibling_binary("kennel-socks-connect");
    assert!(socks_bin.exists(), "build kennel-socks-connect (the runner does)");
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
        socks_connect_bin: Some(socks_bin),
    };

    // AF_UNIX socket shim (§7.4): a real host listener bound into the view at
    // $HOME/kennel-unix.sock. A host echo thread serves "ping" -> "pong".
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
    let unix_prep = UnixPrep {
        socket_binds: vec![(unix_sock.clone(), PathBuf::from("/run/kennel/e2e/kennel-unix.sock"))],
        env: Vec::new(),
    };

    let spec = Spec {
        cgroup: cgroup.clone(),
        ctx,
        scope,
        plan,
        net: minimal_policy(&home).effective_policy.net,
        proxy: Some(ProxySetup { binary: netproxy_path(), config_dir: proxy_cfg.clone() }),
        etc: Some(EtcSetup {
            staging_dir: etc_base.join("etc-1"),
            hostname: "e2e".to_owned(),
            // The kernel uid/gid inside the userns are the operator's (identity map),
            // so the synthetic passwd/group must name those very ids as `kennel` for
            // `id`/`getpwuid` to resolve without leaking the host login.
            uid,
            gid,
            home: PathBuf::from("/run/kennel/e2e"),
            groups: granted.map(|g| vec![(GRANTED_GROUP_NAME.to_owned(), g)]).unwrap_or_default(),
        }),
        view_root: Some(view_root.clone()),
        audit_path: Some(audit_path.clone()),
        ssh: ssh_prep,
        unix: unix_prep,
    };

    // The workload proves the constructed view; the group clauses below are written
    // for userns semantics (see build_workload).
    let mut workload = build_workload(v4, granted, gid);
    let started = start(&helper, spec, &mut workload);
    // Prerequisite skips, never a false pass:
    if let Some(reason) = userns_skip_reason(&started) {
        cleanup_paths(&[&proxy_cfg, &etc_base, &view_root, &ssh_stage], &home_test, &unix_sock);
        let _ = std::fs::remove_dir(&base);
        eprintln!("SKIP: {reason}");
        return;
    }
    if let Some(reason) = privhelper_skip_reason(&started) {
        cleanup_paths(&[&proxy_cfg, &etc_base, &view_root, &ssh_stage], &home_test, &unix_sock);
        let _ = std::fs::remove_dir(&base);
        eprintln!("SKIP: {reason}");
        return;
    }
    let kennel = started.expect("start kennel");
    assert!(cgroup.is_dir(), "the kennel cgroup should exist while running");

    // The loopback v4 address (127 | tag | ctx | host 1) should be present.
    assert!(lo_has(&v4.to_string()), "the kennel's loopback address {v4} should be added");
    let proxy_addr = format!("{v4}:1080");
    assert!(listening(&proxy_addr), "the egress proxy should be listening on {proxy_addr}");
    let proxy_addr6 = format!("[{v6}]:1080");
    assert!(listening(&proxy_addr6), "the egress proxy should be listening on {proxy_addr6}");
    let proxy_config = proxy_cfg.join(format!("proxy-{ctx}.toml"));
    assert!(proxy_config.exists(), "the proxy config should be written");
    assert!(audit_path.parent().is_some_and(Path::exists), "the audit log directory should be created");

    let status = kennel.stop(&helper).expect("stop");
    assert!(
        status.success(),
        "the constructed view held (synthetic /etc + ~/.ssh, granted readable, sibling ENOENT, the \
         AF_UNIX shim connectable, the granted group re-granted via the gid_map handshake) (got {status:?})"
    );

    assert!(!cgroup.exists(), "the cgroup should be removed on teardown");
    assert!(!lo_has(&v4.to_string()), "the loopback address should be removed on teardown");
    assert!(!quick_connect(&proxy_addr), "the proxy should be killed on teardown");
    assert!(!view_root.exists(), "the view staging mountpoint should be removed on teardown");
    assert!(audit_base.exists(), "the audit log directory should survive teardown");

    cleanup_paths(&[&proxy_cfg, &etc_base, &audit_base, &ssh_stage], &home_test, &unix_sock);
    let _ = std::fs::remove_dir(&base);
}

/// Build the workload shell: the original view/etc/ssh/unix/dev clauses, plus a
/// **userns-correct** group clause (§7.2.8). The legacy `id -G | wc -w == 2` does
/// not hold on the userns path — `getgroups` returns every inherited group with the
/// unmapped ones folded to the overflow gid (`nogroup`, 65534), not an emptied list.
/// So we assert: the granted gid is present and resolves to its synthetic name, and
/// **every** supplementary gid is the primary, the overflow gid, or the granted one
/// (no host group kept its real identity). With no granted group, only the
/// neutralisation invariant is checked.
fn build_workload(v4: Ipv4Addr, granted: Option<u32>, primary: u32) -> Command {
    let ssh_clause = "&& test -f \"$HOME/.ssh/config\" \
         && grep -q 'ProxyCommand .*kennel-socks-connect %h %p' \"$HOME/.ssh/config\" \
         && grep -q 'HostKeyAlias kennel-bastion' \"$HOME/.ssh/config\" \
         && grep -q '^kennel-bastion ssh-ed25519 ' \"$HOME/.ssh/known_hosts\" \
         && test -f \"$HOME/.ssh/id_github.com\" \
         && test -n \"$KENNEL_SOCKS_PROXY\" ";
    let unix_clause = "&& test -S \"$HOME/kennel-unix.sock\" \
         && ! test -e \"$HOME/kennel-not-granted.sock\" \
         && test \"$(python3 -c \"import socket,os;s=socket.socket(socket.AF_UNIX);s.connect(os.environ['HOME']+'/kennel-unix.sock');s.sendall(b'ping');print(s.recv(16).decode(),end='')\")\" = pong ";
    let dev_clause = if Path::new("/dev/net/tun").exists() {
        "&& test -c /dev/net/tun \
         && python3 -c \"import os;os.close(os.open('/dev/net/tun',os.O_RDWR))\" \
         && ! test -e /dev/mem "
    } else {
        "&& ! test -e /dev/mem "
    };
    let id_clause = "&& grep -q '^kennel:' /etc/passwd \
         && grep -q '^kennel:' /etc/group \
         && ! grep -q '/home/' /etc/passwd ";
    // Userns group isolation: every supplementary gid is primary / overflow(65534) /
    // granted; the granted gid is present and resolves to its synthetic name.
    let groups_clause = granted.map_or_else(
        || format!("&& for x in $(id -G); do [ \"$x\" = {primary} ] || [ \"$x\" = 65534 ] || exit 9; done "),
        |g| {
            format!(
                "&& id -G | grep -qw {g} \
                 && id -Gn | grep -qw {GRANTED_GROUP_NAME} \
                 && for x in $(id -G); do [ \"$x\" = {primary} ] || [ \"$x\" = 65534 ] || [ \"$x\" = {g} ] || exit 9; done "
            )
        },
    );
    let mut workload = Command::new("/bin/sh");
    workload.arg("-c").arg(format!(
        "grep -q '{v4}[[:space:]]*localhost e2e' /etc/hosts \
         && test -r \"$HOME/kennel-e2e/granted/file\" \
         && ! test -e \"$HOME/kennel-e2e/secret\" \
         {ssh_clause} \
         {unix_clause} \
         {dev_clause} \
         {id_clause} \
         {groups_clause} \
         && sleep 2",
    ));
    workload
}

/// If `started` failed because the userns was created but capability-stripped
/// (Ubuntu's `AppArmor` restriction with no profile over the test binary), the
/// precise skip reason; else `None`.
fn userns_skip_reason(started: &Result<kenneld::Kennel, Error>) -> Option<String> {
    let Err(Error::Spawn(kennel_spawn::SpawnError::Syscall(e))) = started else {
        return None;
    };
    let restricted = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|s| s.trim() == "1");
    if e.kind() == std::io::ErrorKind::PermissionDenied && restricted {
        Some(format!(
            "userns created but capability-stripped — kernel.apparmor_restrict_unprivileged_userns=1 and \
             this test binary has no AppArmor profile granting `userns` (the runner loads one): {e}"
        ))
    } else {
        None
    }
}

/// If `started` failed because the privhelper could not perform a privileged op
/// (most likely it lacks the file capabilities), the precise skip reason; else
/// `None`. A capability-less helper's netlink/BPF op fails with `EPERM`.
fn privhelper_skip_reason(started: &Result<kenneld::Kennel, Error>) -> Option<String> {
    let Err(Error::Privileged { op, response }) = started else {
        return None;
    };
    Some(format!(
        "privhelper op `{op}` failed ({response:?}) — most likely the helper lacks file capabilities; \
         run src/tools/unprivileged-e2e.sh (it applies `setcap cap_net_admin,cap_sys_admin,cap_setgid=ep`)"
    ))
}

/// Whether `/etc/kennel/subkennel` has a line for `uid` (the privhelper's reserved
/// scope source).
fn subkennel_has_line(uid: u32) -> bool {
    std::fs::read_to_string("/etc/kennel/subkennel")
        .is_ok_and(|t| t.lines().any(|l| l.trim().starts_with(&format!("{uid}:"))))
}

/// Whether `addr` appears on the loopback interface.
fn lo_has(addr: &str) -> bool {
    let out = Command::new("ip").args(["addr", "show", "dev", "lo"]).output().expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

/// A single connection attempt — for asserting the proxy is *gone*.
fn quick_connect(addr: &str) -> bool {
    let target: std::net::SocketAddr = addr.parse().expect("addr");
    TcpStream::connect_timeout(&target, Duration::from_millis(100)).is_ok()
}

/// Remove the staged scratch dirs, the home test tree, and the unix socket.
fn cleanup_paths(dirs: &[&PathBuf], home_test: &Path, unix_sock: &Path) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    let _ = std::fs::remove_dir_all(home_test);
    let _ = std::fs::remove_file(unix_sock);
}
