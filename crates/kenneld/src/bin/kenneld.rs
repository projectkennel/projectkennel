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

use kenneld::server::{serve, Identity, Shared};
use kenneld::{policy, proxy, socket, HelperClient, ProxySetup};

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
    let identity = build_identity()?;
    let privileged = HelperClient::installed();
    let loader = policy::TrustStoreLoader::from_dir(&policy::trust_dir())
        .map_err(|e| format!("loading trust store {}: {e}", policy::trust_dir().display()))?;

    let shared = Arc::new(Shared::new(identity, privileged, loader));
    let listener = socket::listener().map_err(|e| format!("control socket: {e}"))?;
    serve(&shared, &listener).map_err(|e| format!("serving: {e}"))
}

/// Build the user's identity from kernel-trusted sources.
fn build_identity() -> Result<Identity, String> {
    let uid = kennel_syscall::unistd::real_uid();
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or("HOME is not set")?;
    let scope = kennel_privhelper::alloc::load(uid).ok_or_else(|| format!("no kennel allocation for uid {uid} in /etc/kennel/subkennel"))?;
    let cgroup_base = kenneld::cgroup::self_cgroup().map_err(|e| format!("locating own cgroup: {e}"))?;
    let gid = kennel_syscall::unistd::real_gid();
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    let proxy = Some(ProxySetup {
        binary: PathBuf::from(proxy::DEFAULT_NETPROXY_BIN),
        config_dir: socket::runtime_dir().join("proxy"),
    });
    let etc_base = Some(socket::runtime_dir().join("etc"));
    let view_base = Some(socket::runtime_dir().join("root"));
    // The per-kennel network audit log persists across runs, so it lives under
    // the state home (not the volatile runtime dir): ~/.local/state/kennel/<kennel>/
    // network.jsonl (§7.3.4), honouring $XDG_STATE_HOME when set.
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map_or_else(|| home.join(".local/state"), PathBuf::from);
    let audit_base = Some(state_home.join("kennel"));
    Ok(Identity { uid, gid, username, home, scope, cgroup_base, proxy, etc_base, view_base, audit_base })
}
