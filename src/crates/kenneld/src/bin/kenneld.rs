//! The kenneld daemon binary.
//!
//! A user-space, per-user daemon: socket-activated on the first `kennel run` and
//! persisting for the session (see [`kenneld::socket`]). It builds the user's
//! [`Identity`] from kernel-trusted sources — the real uid, the
//! `/etc/kennel/subkennel` allocation, and its own delegated cgroup — and serves
//! the control socket, orchestrating kennels through the setuid privhelper.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use std::net::{IpAddr, Ipv4Addr};

use kenneld::server::{serve, BastionSetup, Identity, Shared};
use kenneld::{policy, socket, HelperClient, ProxySetup};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kenneld: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    // Deployment paths (helper binaries, the trust store) come from the
    // root-owned config cascade — never baked in, never user-overridable
    // (07-paths.md; kennel_config::Deployment).
    let deployment =
        kennel_config::Deployment::load().map_err(|e| format!("loading deployment config: {e}"))?;
    let identity = build_identity(&deployment)?;
    let privileged = HelperClient::new(deployment.privhelper());
    // Settled run policies verify against the system trust store **then** the calling
    // user's own keys (the trust split, 07-paths): a user may run a policy signed with
    // their own key, but a user key cannot shadow a system key id (system is first, so
    // it wins). Templates are a separate, system-only trust at compile time.
    let mut trust_dirs: Vec<std::path::PathBuf> = vec![deployment.trust_dir().to_path_buf()];
    if let Some(user_keys) = kennel_config::user_key_dir() {
        trust_dirs.push(user_keys);
    }
    let dir_refs: Vec<&std::path::Path> =
        trust_dirs.iter().map(std::path::PathBuf::as_path).collect();
    // The loader re-reads these dirs on every request, so a key created, changed, or
    // removed after the daemon started (e.g. by `kennel keygen`) is honoured without a
    // restart — the trust store lives on disk, not frozen in memory at boot.
    let loader = policy::TrustStoreLoader::from_dirs(&dir_refs);

    let shared = Arc::new(Shared::new(identity, privileged, loader));
    let listener = socket::listener().map_err(|e| format!("control socket: {e}"))?;
    serve(&shared, &listener).map_err(|e| format!("serving: {e}"))
}

/// Build the user's identity from kernel-trusted sources, taking the
/// helper-binary locations from the resolved [`kennel_config::Deployment`].
fn build_identity(deployment: &kennel_config::Deployment) -> Result<Identity, String> {
    let uid = kennel_syscall::unistd::real_uid();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let scope = kennel_privhelper::alloc::load(uid)
        .ok_or_else(|| format!("no kennel allocation for uid {uid} in /etc/kennel/subkennel"))?;
    let cgroup_base =
        kenneld::cgroup::self_cgroup().map_err(|e| format!("locating own cgroup: {e}"))?;
    let gid = kennel_syscall::unistd::real_gid();
    // Host-side only: the SSH bastion's AuthorizedKeysCommandUser. The kennel's own
    // synthetic /etc/passwd masks the account name to `kennel` (kenneld::etc).
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    let proxy = Some(ProxySetup {
        binary: deployment.netproxy(),
        config_dir: socket::runtime_dir().join("proxy"),
    });
    let etc_base = Some(socket::runtime_dir().join("etc"));
    let view_base = Some(socket::runtime_dir().join("root"));
    // The per-kennel network audit log persists across runs, so it lives under
    // the state home (not the volatile runtime dir): ~/.local/state/kennel/<kennel>/
    // network.jsonl (§7.3.4), honouring $XDG_STATE_HOME when set.
    let state_home =
        std::env::var_os("XDG_STATE_HOME").map_or_else(|| home.join(".local/state"), PathBuf::from);
    let audit_base = Some(state_home.join("kennel"));
    // The per-user SSH bastion (§7.8): one managed kennel-sshd for the session, on a
    // host-loopback port derived from the user's tag (so two users' daemons do not
    // clash on 127.0.0.1). Its forced commands sign with the user's own agent.
    //
    // Keys are vended through the root-owned AuthorizedKeysCommand (§7.8.7): it queries
    // this running daemon for the live forced-command bindings, so the bindings never
    // touch a file the user could rewrite. The helper is installed root-owned (OpenSSH's
    // safe-path check); it runs as the bastion user so it can reach our control socket.
    let bastion = Some(BastionSetup {
        dir: socket::runtime_dir().join("bastion"),
        reorigin_bin: deployment.ssh_reorigin(),
        socks_connect_bin: deployment.socks_connect(),
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 8022_u16.saturating_add(scope.tag()),
        agent_sock: std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
        akc: Some(kenneld::bastion::Akc {
            command: deployment.akc(),
            user: username.clone(),
        }),
    });
    Ok(Identity {
        uid,
        gid,
        username,
        home,
        scope,
        cgroup_base,
        proxy,
        etc_base,
        view_base,
        audit_base,
        bastion,
        afunix_shim_bin: Some(deployment.afunix_shim()),
    })
}
