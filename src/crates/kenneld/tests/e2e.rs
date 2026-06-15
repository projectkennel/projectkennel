//! End-to-end hardware test of the **unprivileged** production vertical, gated
//! behind the `e2e` feature; it runs as the ordinary operator, *no sudo*.
//!
//! Drives the public orchestration (`kenneld::start`) with a real signed policy
//! and the **real file-caps privhelper binary**, as the operator, on the
//! production userns path: the sandbox (mount namespace, `pivot_root`, the
//! constructed view) is built unprivileged via an identity-mapped user namespace,
//! the privhelper (file-caps, never sudo) adds the per-kennel loopback addresses,
//! attaches the egress BPF, and writes the workload's `gid_map` to re-grant a
//! supplementary group (§7.4.8), and teardown removes it all.
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

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use kennel_lib_policy::{
    CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, LifecyclePolicy, NetMode,
    NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction,
    SeccompPolicy, SettledPolicy, SigningKey, TmpPolicy, TtlAction,
};
use kennel_privhelper::addr::{loopback_v4, V4_PREFIX};
use kennel_privhelper::validate::ReservedScope;
use kenneld::{HelperClient, Privileged};

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

/// The netproxy binary; built by the runner (`cargo build -p host-netproxy`).
fn netproxy_path() -> PathBuf {
    let path = sibling_binary("host-netproxy");
    assert!(
        path.exists(),
        "netproxy not found at {} — run src/tools/unprivileged-e2e.sh",
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

/// A supplementary group the operator actually holds (so the privhelper's
/// membership check passes), other than its primary gid — the group re-granted into
/// the kennel via the `gid_map` handshake. `None` if the operator has no extra
/// group (then the test proves default drop-all instead).
fn pick_granted_group() -> Option<u32> {
    let primary = kennel_lib_syscall::unistd::real_gid();
    kennel_lib_syscall::unistd::supplementary_groups()
        .into_iter()
        .find(|&g| g != primary)
}

/// The same granted group as [`pick_granted_group`], but as `(name, gid)` — the form
/// the self-hosting path needs, since a policy's `[identity].groups` names groups and
/// the loader's `resolve_groups` re-resolves the name and membership-checks it. We map
/// a held gid back to a name by scanning `/etc/group` (the loader resolves the name
/// forward again, so the round-trip must agree). `None` when the operator has no extra
/// group whose gid resolves to a name in `/etc/group`.
fn pick_granted_group_named() -> Option<(String, u32)> {
    let gid = pick_granted_group()?;
    let group_db = std::fs::read_to_string("/etc/group").ok()?;
    group_db.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let _passwd = f.next()?;
        let line_gid: u32 = f.next()?.parse().ok()?;
        (line_gid == gid).then(|| (name.to_owned(), gid))
    })
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

/// The full constructed-view scenario as a **signed policy**, for the self-hosting
/// `full_vertical` test: [`minimal_policy`] with the `[unix]` echo socket pointed at
/// the real host listener `real_sock` (the af-unix facade connects to it by name), and
/// — when the operator holds a grantable supplementary group — that group named in
/// `[identity].groups`. The loader resolves both from this policy alone; nothing is
/// hand-wired into the bring-up, so this is the production `run_kennel` path exactly.
fn rich_policy(home: &Path, real_sock: &Path, granted: Option<&(String, u32)>) -> SettledPolicy {
    let mut p = minimal_policy(home);
    p.unix = kennel_lib_policy::UnixRuntime {
        sockets: vec![kennel_lib_policy::UnixSocket {
            name: "echo".to_owned(),
            real: real_sock.to_string_lossy().into_owned(),
            shim: "/home/kennel/kennel-unix.sock".to_owned(),
            env: None,
        }],
    };
    if let Some((name, _gid)) = granted {
        p.identity = kennel_lib_policy::IdentityRuntime {
            groups: vec![name.clone()],
            ..kennel_lib_policy::IdentityRuntime::default()
        };
    }
    p
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

/// The full constructed-view vertical, driven **self-hosting** through the real
/// `run_kennel` (the production per-kennel path the daemon runs) — not the hand-built
/// `Spec`/`BinderPrep` replica the earlier version used, which could drift from
/// `run_kennel`'s real wiring. We sign the rich policy ([`rich_policy`]), hand
/// `run_kennel` the operator's `Identity`, and let it derive everything (the view, the
/// constructed `/etc`, the af-unix facade, the supplementary-group grant) from the
/// signed policy alone. The workload script ([`view_proof_script`]) proves the
/// constructed view from *inside* the kennel; the host side stands up only the one
/// fixture a policy cannot carry — the real `AF_UNIX` echo listener the facade connects
/// to. (SSH egress is proven separately by `src/tools/ssh-bastion-e2e.sh`; this test
/// no longer re-wires a bastion.)
#[test]
#[allow(clippy::too_many_lines)] // one cohesive end-to-end scenario: view + /etc + unix + dev + groups
fn full_vertical_brings_up_and_tears_down_a_kennel_unprivileged() {
    use kenneld::control::{recv_response, Response, StartRequest};
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{run_kennel, Identity, Shared};
    use std::os::unix::net::UnixStream;

    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    // Play kenneld's role: become a subreaper so the orphaned kennel-bin-init (the factory exits as
    // soon as it reports the pid) reparents to this process and `wait_pid` can collect its status.
    let _ = kennel_lib_syscall::process::set_child_subreaper();
    assert_ne!(
        uid, 0,
        "this is the UNPRIVILEGED vertical — run it as the operator, not root (see the runner)"
    );

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
    // `run_kennel` does a single `reserve` on a fresh `Shared`, which allocates ctx 1
    // (proven by `reserve_allocates_and_refuses_duplicates`); the loopback mirror brings
    // up `127 | tag | ctx | host 1` for that ctx, so the workload's net-ns proof can
    // compute the same address test-side.
    let ctx = 1u16;
    let v4 = loopback_v4(
        scope.tag(),
        u8::try_from(ctx).expect("ctx fits u8 for a v4 kennel"),
        kenneld::PROXY_HOST,
    );

    // A real AF_UNIX echo listener on the host — the one fixture a policy cannot carry.
    // The af-unix facade (binder node 0) connects to it by name on the workload's behalf
    // and the in-kennel `facade-afunix` proxy presents it at the shim path. A host echo
    // thread serves "ping" -> "pong". No host socket path is ever bound into the view.
    let run = runtime_dir();
    let tag = std::process::id();
    let unix_sock = run.join(format!("kenneld-e2e-unix-{tag}.sock"));
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

    // The granted ~ subdir (with a file) and a non-granted sibling, under the real home.
    // In the view the granted path remaps beneath the shim root; the sibling must be
    // absent (its name gone, not merely denied). `minimal_policy` grants the `granted`
    // subdir read; `secret` is never named.
    let home_test = home.join("kennel-e2e");
    let _ = std::fs::remove_dir_all(&home_test);
    std::fs::create_dir_all(home_test.join("granted")).expect("mkdir granted");
    std::fs::create_dir_all(home_test.join("secret")).expect("mkdir secret");
    std::fs::write(home_test.join("granted/file"), "OK\n").expect("write granted file");
    std::fs::write(home_test.join("secret/file"), "SECRET\n").expect("write secret file");

    // Re-grant one real supplementary group the operator holds (§7.4.8) by naming it in
    // the policy's `[identity].groups`; the loader resolves + membership-checks it and
    // sets `plan.supplementary_groups`. With no extra group the kennel proves default
    // drop-all instead.
    let granted = pick_granted_group_named();

    // Sign the rich policy and trust the key — the real verify path runs in the loader.
    // The workload (the view-proof script) is embedded in the SIGNED policy, not passed as
    // request argv: this exercises the [workload] path end to end — the script travels through
    // verify + substitute and the daemon fills argv from the loaded policy (req.argv empty).
    let key = SigningKey::from_seed("e2e-key", &[3u8; 32]).expect("key");
    let mut policy = rich_policy(&home, &unix_sock, granted.as_ref());
    policy.workload = kennel_lib_policy::WorkloadRuntime {
        argv: view_proof_script(v4, granted.as_ref(), gid),
        cwd: None,
        pinned: false,
        sha256: Vec::new(),
    };
    let signed = kennel_lib_policy::sign_settled(&policy, &key).expect("sign");
    let bytes = kennel_lib_policy::to_bytes(&signed).expect("serialise");
    let mut keys = kennel_lib_policy::KeySet::new();
    keys.insert(key.key_id(), &key.public_key_bytes())
        .expect("trust key");

    // Stage the per-kennel scratch dirs under the user runtime dir (outside /tmp).
    let policy_file = run.join(format!("kenneld-e2e-policy-{tag}.bin"));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let proxy_cfg = run.join(format!("kenneld-e2e-proxy-{tag}"));
    let etc_base = run.join(format!("kenneld-e2e-etc-{tag}"));
    let view_root = run.join(format!("kenneld-e2e-root-{tag}"));
    let audit_base = run.join(format!("kenneld-e2e-audit-{tag}"));
    for p in [&proxy_cfg, &etc_base, &view_root, &audit_base] {
        let _ = std::fs::remove_dir_all(p);
    }

    // Best-effort: clear any loopback address a prior interrupted run left (the
    // privhelper does it — unprivileged `ip addr del` cannot), and any stale delegate.
    let helper = HelperClient::new(privhelper_path());
    let _ = helper.del_address(ctx, "lo", v4.into(), V4_PREFIX);
    let _ = Command::new("pkill").args(["-x", "host-netproxy"]).output();

    // The operator's `Identity` — exactly what kenneld holds for its user. `run_kennel`
    // derives the view, /etc, af-unix facade, proxy, and the group grant from the signed
    // policy + this identity. A constrained-net policy needs the proxy fixtures.
    let identity = Identity {
        uid,
        gid,
        username: "dev".to_owned(),
        home,
        scope,
        cgroup_base: base.clone(),
        proxy: Some(kenneld::ProxySetup {
            binary: netproxy_path(),
            config_dir: proxy_cfg.clone(),
            socks5: sibling_binary("facade-socks5"),
        }),
        etc_base: Some(etc_base.clone()),
        view_base: Some(view_root.clone()),
        audit_base: Some(audit_base.clone()),
        bastion: None,
        afunix_bin: Some(sibling_binary("facade-afunix")),
        init_bin: Some(sibling_binary("kennel-bin-init")),
    };
    let shared = Shared::new(identity, helper.clone(), TrustStoreLoader::from_keys(keys));

    let req = StartRequest {
        policy: policy_file.clone(),
        kennel: "e2e".to_owned(),
        // EMPTY argv: the daemon fills it from the signed policy's [workload] (above). This is
        // the policy-driven path — the workload is signature-covered, not request-supplied.
        argv: Vec::new(),
        cwd: PathBuf::from("/"),
        term: String::new(),
        interactive: false,
        force: false,
    };

    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    run_kennel(&shared, &req, Vec::new(), &mut server);

    let first = recv_response(&mut client).expect("a first response");
    if bring_up_skipped(&first) {
        let _ = helper.del_address(ctx, "lo", v4.into(), V4_PREFIX);
        cleanup_paths(
            &[&proxy_cfg, &etc_base, &view_root, &audit_base],
            &home_test,
            &unix_sock,
        );
        let _ = std::fs::remove_file(&policy_file);
        let _ = std::fs::remove_dir(&base);
        return;
    }

    // While the kennel runs (the view proof script sleeps briefly at the end), the
    // host-observable bring-up state must hold: the loopback address is up and the egress
    // delegate's command socket is bound. These are the checks the old hand-built test
    // made against `Spec`; here they observe what `run_kennel` actually built.
    assert!(
        lo_has(&v4.to_string()),
        "the kennel's loopback address {v4} should be added during bring-up"
    );
    let command_socket = proxy_cfg.join(format!("netproxy-cmd-{ctx}.sock"));
    // The delegate binds its socket shortly after bring-up; allow a brief settle.
    let mut delegate_up = false;
    for _ in 0..40 {
        if command_socket.exists() {
            delegate_up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        delegate_up,
        "the egress delegate should bind its command socket at {}",
        command_socket.display()
    );

    // The workload's exit code is the verdict: the whole `view_proof_script` ran inside
    // the kennel (granted readable, secret ENOENT, masked /etc, af-unix ping->pong, net-ns
    // loopback + SOCKS endpoint, the supplementary group re-granted) iff it exited 0.
    assert_eq!(
        recv_response(&mut client).expect("an exit response"),
        Response::Exited { code: 0 },
        "the constructed view held: synthetic /etc + granted readable + sibling ENOENT + the \
         AF_UNIX shim connectable + net-ns loopback + the granted group re-granted"
    );

    // Teardown removed it all.
    assert!(
        !lo_has(&v4.to_string()),
        "the loopback address should be removed on teardown"
    );
    assert!(
        !view_root.exists(),
        "the view staging mountpoint should be removed on teardown"
    );
    assert!(
        audit_base.exists(),
        "the audit log directory should survive teardown"
    );

    cleanup_paths(
        &[&proxy_cfg, &etc_base, &audit_base],
        &home_test,
        &unix_sock,
    );
    let _ = std::fs::remove_file(&policy_file);
    let _ = std::fs::remove_dir(&base);
}

/// Build the in-kennel proof script (the workload's argv): a `/bin/sh -c` chain that
/// verifies the constructed view from *inside* the kennel and exits 0 iff every clause
/// holds — the self-hosting test's whole verdict. Covers the constructed `/etc`, the
/// granted `~` subdir + the absent (ENOENT) non-granted sibling, the dev passthrough,
/// the per-kennel net-ns, the `AF_UNIX` facade round-trip, and the supplementary-group
/// grant. (SSH egress is proven by `ssh-bastion-e2e.sh`, not here.)
///
/// The **group clause** is userns-correct (§7.4.8): the legacy `id -G | wc -w == 2`
/// does not hold — `getgroups` returns every inherited group with the unmapped ones
/// folded to the overflow gid (`nogroup`, 65534), not an emptied list. So we assert the
/// granted gid is present and resolves to its name, and **every** supplementary gid is
/// the primary, the overflow gid, or the granted one (no host group kept its identity).
/// With no granted group, only the neutralisation invariant is checked.
fn view_proof_script(v4: Ipv4Addr, granted: Option<&(String, u32)>, primary: u32) -> Vec<String> {
    // The af-unix facade: the in-kennel proxy is launched by the seal (racing this
    // exec) and node 0 comes up shortly after spawn, so the socket appears and the
    // first broker may briefly fail — wait for the listener, then let python retry the
    // ping/pong. A non-granted socket is never presented (no proxy listener for it).
    let unix_clause = "&& for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
             test -S \"$HOME/kennel-unix.sock\" && break; sleep 0.5; done \
         && test -S \"$HOME/kennel-unix.sock\" \
         && ! test -e \"$HOME/kennel-not-granted.sock\" \
         && test \"$(python3 -c \"import socket,os,time;\
p=os.environ['HOME']+'/kennel-unix.sock'\nfor _ in range(40):\n try:\n  s=socket.socket(socket.AF_UNIX);s.connect(p);s.sendall(b'ping')\n  r=s.recv(16)\n  if r==b'pong':\n   print('pong',end='');break\n except OSError:\n  pass\n time.sleep(0.25)\")\" = pong ";
    let dev_clause = if Path::new("/dev/net/tun").exists() {
        "&& test -c /dev/net/tun \
         && python3 -c \"import os;os.close(os.open('/dev/net/tun',os.O_RDWR))\" \
         && ! test -e /dev/mem "
    } else {
        "&& ! test -e /dev/mem "
    };
    // Per-kennel net-ns (§7.5): the kennel's own loopback address is up inside the net-ns (bind
    // succeeds — proves the construction child brought up in-ns `lo` + added the address), and
    // facade-socks5 is listening at {v4}:1080 (the egress SOCKS endpoint, launched in-ns). The
    // host's 127.0.0.1 services are in a different net-ns, so they are unreachable from here.
    let netns_clause = format!(
        "&& python3 -c \"import socket;s=socket.socket();s.bind(('{v4}',0));s.close()\" \
         && for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
              python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('{v4}',1080));s.close()\" \
                2>/dev/null && break; sleep 0.5; done \
         && python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('{v4}',1080));s.close()\" "
    );
    // Identity is masked: the synthetic passwd/group name the account `kennel` with
    // the masked home `/home/kennel` (§7.4 `$HOME = /home/<user>`); no operator
    // identity leaks.
    let id_clause = "&& grep -q '^kennel:' /etc/passwd \
         && grep -q '^kennel:' /etc/group \
         && grep -q ':/home/kennel:' /etc/passwd ";
    // Userns group isolation: every supplementary gid is primary / overflow(65534) /
    // granted; the granted gid is present and resolves to its name (the policy named it
    // in [identity].groups; the synthetic /etc/group carries it under that same name).
    let groups_clause = granted.map_or_else(
        || format!("&& for x in $(id -G); do [ \"$x\" = {primary} ] || [ \"$x\" = 65534 ] || exit 9; done "),
        |(name, g)| {
            format!(
                "&& id -G | grep -qw {g} \
                 && id -Gn | grep -qw {name} \
                 && for x in $(id -G); do [ \"$x\" = {primary} ] || [ \"$x\" = 65534 ] || [ \"$x\" = {g} ] || exit 9; done "
            )
        },
    );
    let script = format!(
        "grep -q '{v4}[[:space:]]*localhost e2e' /etc/hosts \
         && test -r \"$HOME/kennel-e2e/granted/file\" \
         && ! test -e \"$HOME/kennel-e2e/secret\" \
         {unix_clause} \
         {dev_clause} \
         {netns_clause} \
         {id_clause} \
         {groups_clause} \
         && sleep 2",
    );
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script]
}

/// Whether `/etc/kennel/subkennel` has a line for `uid` (the privhelper's reserved
/// scope source).
fn subkennel_has_line(uid: u32) -> bool {
    std::fs::read_to_string("/etc/kennel/subkennel")
        .is_ok_and(|t| t.lines().any(|l| l.trim().starts_with(&format!("{uid}:"))))
}

/// Whether `addr` appears on the loopback interface.
fn lo_has(addr: &str) -> bool {
    let out = Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

/// Classify a bring-up response without `panic!` (the workspace forbids it). `true` means the
/// environment is not privileged enough for the factory and the caller should clean up and return
/// (a skip is not a proof); otherwise this asserts the response is `Started`, failing with context
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

/// Remove the staged scratch dirs, the home test tree, and the unix socket.
fn cleanup_paths(dirs: &[&PathBuf], home_test: &Path, unix_sock: &Path) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    let _ = std::fs::remove_dir_all(home_test);
    let _ = std::fs::remove_file(unix_sock);
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
/// Unlike `full_vertical` (which calls `start` with a hand-built `Spec`/`BinderPrep` — a
/// replica of `run_kennel`'s wiring that can drift), this exercises the exact production
/// orchestration: load+verify the policy, build the plan, decide the factory, construct via
/// the privhelper. It is the gate proving the universal-factory gating (`run_kennel` builds a
/// `BinderPrep` for **every** kennel) and that a plain kennel actually constructs + runs via
/// the factory — coverage the hand-wired test cannot give.
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
    use kenneld::policy::TrustStoreLoader;
    use kenneld::server::{run_kennel, Identity, Shared};
    use std::io::Read as _;
    use std::os::fd::{AsFd, OwnedFd};
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

    // An interactive kennel needs a devpts in its view: granting the `/dev/pts` directory makes
    // build_view_and_pivot mount a fresh `devpts` + symlink `/dev/ptmx`, so `openpty` works.
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
    let tag = std::process::id();
    let policy_file = run.join(format!("kenneld-pty-policy-{tag}.bin"));
    std::fs::write(&policy_file, &bytes).expect("write policy");
    let etc_base = run.join(format!("kenneld-pty-etc-{tag}"));
    let view_root = run.join(format!("kenneld-pty-root-{tag}"));
    let audit_base = run.join(format!("kenneld-pty-audit-{tag}"));
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
    };
    let shared = Shared::new(
        identity,
        HelperClient::new(privhelper_path()),
        TrustStoreLoader::from_keys(keys),
    );

    // The CLI's return socket: the kennel sends the workload's pty master back over `child`;
    // the test reads it from `ours`.
    let (ours, child) = UnixStream::pair().expect("return socketpair");
    let req = StartRequest {
        policy: policy_file,
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
    // A real controller holds the pty master open for the workload's whole life — an unheld
    // master hangs up the session (SIGHUP). So receive + hold + drain the master on a thread
    // while `run_kennel` (which blocks until the workload exits) runs on this one.
    let output = std::thread::scope(|s| {
        let reader = s.spawn(|| -> Vec<u8> {
            let mut byte = [0u8; 1];
            let Ok((_n, fds)) = kennel_lib_syscall::scm::recv_with_fds(ours.as_fd(), &mut byte)
            else {
                return Vec::new();
            };
            let Some(master) = fds.into_iter().next() else {
                return Vec::new();
            };
            // Holds the master for the workload's run; read_to_end drains until the slave's EIO.
            let mut out = Vec::new();
            let _ = std::fs::File::from(master).read_to_end(&mut out);
            out
        });
        run_kennel(&shared, &req, vec![OwnedFd::from(child)], &mut server);
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

    let _ = std::fs::remove_dir_all(&etc_base);
    let _ = std::fs::remove_dir_all(&view_root);
    let _ = std::fs::remove_dir_all(&audit_base);
}
