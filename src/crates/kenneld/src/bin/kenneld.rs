//! The kenneld daemon binary.
//!
//! A user-space, per-user daemon: socket-activated on the first `kennel run` and
//! persisting for the session (see [`kenneld::socket`]). It builds the user's
//! [`Identity`] from kernel-trusted sources — the real uid (from which the reserved
//! scope is derived) and its own delegated cgroup — and serves the control socket,
//! orchestrating kennels through the setuid privhelper.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use std::net::{IpAddr, Ipv6Addr};

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
    // Become a child subreaper so an orphaned `kennel-bin-init` reparents to us: the privhelper
    // factory exits as soon as it has reported the init pid (it is not a reaper proxy), and we
    // must remain able to `waitpid` the kennel for its exit status (`07-2`). Set once, before
    // any kennel is constructed.
    kennel_lib_syscall::process::set_child_subreaper()
        .map_err(|e| format!("set_child_subreaper: {e}"))?;

    // Deployment paths (helper binaries, the trust store) come from the
    // root-owned config cascade — never baked in, never user-overridable
    // (07-paths.md; kennel_lib_config::Deployment).
    let deployment = kennel_lib_config::Deployment::load()
        .map_err(|e| format!("loading deployment config: {e}"))?;
    let identity = build_identity(&deployment)?;
    let privileged = HelperClient::new(deployment.privhelper());
    // Settled run policies verify against the trust store: the vendor layer first (the
    // package-shipped maintainer key — `org.projectkennel.*` authority, §7.13.5), then the admin
    // trust dir, then the calling user's own keys (the trust split, 07-paths). A user may run a
    // policy signed with their own key, but cannot shadow a vendor/admin key of the same id (earlier
    // dirs win), so the maintainer key is unshadowable. Templates are a separate, system-only trust at
    // compile time.
    let mut rest_dirs: Vec<std::path::PathBuf> = vec![deployment.trust_dir().to_path_buf()];
    if let Some(user_keys) = kennel_lib_config::user_key_dir() {
        rest_dirs.push(user_keys);
    }
    let rest_refs: Vec<&std::path::Path> =
        rest_dirs.iter().map(std::path::PathBuf::as_path).collect();
    // The loader re-reads these dirs on every request, so a key created, changed, or
    // removed after the daemon started (e.g. by `kennel keygen`) is honoured without a
    // restart — the trust store lives on disk, not frozen in memory at boot. The reserved-namespace
    // authority is resolved tier-aware at compile (§7.13.5), so the daemon carries no reserved table.
    let loader = policy::TrustStoreLoader::from_trust_dirs(
        Some(kennel_lib_config::vendor_key_dir()),
        &rest_refs,
        kennel_lib_config::enablement_dirs(),
    );

    let shared = Arc::new(Shared::new(identity, privileged, loader));
    let listener = socket::listener().map_err(|e| format!("control socket: {e}"))?;
    serve(&shared, &listener).map_err(|e| format!("serving: {e}"))
}

/// Build the user's identity from kernel-trusted sources, taking the
/// helper-binary locations from the resolved [`kennel_lib_config::Deployment`].
fn build_identity(deployment: &kennel_lib_config::Deployment) -> Result<Identity, String> {
    let uid = kennel_lib_syscall::unistd::real_uid();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    // The reserved scope derives from the kernel-trusted real uid — no `/etc/kennel/subkennel`
    // allocation (W10). Every uid has a scope; there is no refuse-to-start.
    let scope = kennel_privhelper::validate::ReservedScope::new(uid);
    let cgroup_base =
        kenneld::cgroup::self_cgroup().map_err(|e| format!("locating own cgroup: {e}"))?;
    // Vacate the base cgroup and enable the pids/memory controllers for the kennel children, so
    // each kennel can carry its own pids.max/memory.max. Best-effort: where the controllers are not
    // delegated the per-kennel caps no-op and the aggregate kenneld.service TasksMax is the backstop.
    if let Err(e) = kenneld::cgroup::prepare_delegation(&cgroup_base) {
        eprintln!("kenneld: warning: per-kennel resource controllers unavailable: {e}");
    }
    let gid = kennel_lib_syscall::unistd::real_gid();
    // Host-side only: the SSH bastion's AuthorizedKeysCommandUser. The kennel's own
    // synthetic /etc/passwd masks the account name to `kennel` (kenneld::etc).
    let username = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    let proxy = Some(ProxySetup {
        binary: deployment.netproxy(),
        config_dir: socket::runtime_dir().join("proxy"),
        socks5: deployment.socks5(),
        inetd: deployment.inetd(),
        facade_client: deployment.facade_client(),
    });
    let etc_base = Some(socket::runtime_dir().join("etc"));
    let view_base = Some(socket::runtime_dir().join("root"));
    // The per-kennel network audit log persists across runs, so it lives under
    // the state home (not the volatile runtime dir): ~/.local/state/kennel/<kennel>/
    // network.jsonl (§7.5.4), honouring $XDG_STATE_HOME when set.
    let state_home =
        std::env::var_os("XDG_STATE_HOME").map_or_else(|| home.join(".local/state"), PathBuf::from);
    let audit_base = Some(state_home.join("kennel"));
    // The per-user SSH bastion (§7.10): one managed kennel-sshd for the session, on a
    // v6 host-loopback (`::1`); the bastion picks a random high port at start (trying sshd on it
    // and re-rolling on failure), so co-located daemons do not clash — no per-user derived port.
    // Each forced command runs `ssh <options> -- <dest>` as the operator, signing with whatever the
    // policy's per-destination `options` name from the operator's own host-side key store — no
    // agent, no key material kenneld can reach.
    //
    // Keys are vended through the root-owned AuthorizedKeysCommand (§7.10.7): it queries
    // this running daemon for the live forced-command bindings, so the bindings never
    // touch a file the user could rewrite. The helper is installed root-owned (OpenSSH's
    // safe-path check); it runs as the bastion user so it can reach our control socket.
    let bastion = Some(BastionSetup {
        dir: socket::runtime_dir().join("bastion"),
        ssh_bin: deployment.ssh(),
        listen: IpAddr::V6(Ipv6Addr::LOCALHOST),
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
        afunix_bin: Some(deployment.afunix()),
        facade_dbus_bin: Some(deployment.facade_dbus()),
        host_dbus_bin: Some(deployment.host_dbus()),
        init_bin: Some(deployment.kennel_bin_init()),
        oci_entry_bin: Some(deployment.oci_entry()),
        tracer: kennel_lib_config::Tracer::new("kenneld", deployment.log_level()),
    })
}
