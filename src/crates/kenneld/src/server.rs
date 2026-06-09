//! The daemon: the control-socket serve loop and per-connection request handling.
//!
//! `kennel run` is **blocking and foreground** — the workload's stdio is the
//! user's terminal (fds passed over `SCM_RIGHTS`), and the CLI blocks until it
//! exits. So the daemon serves each connection on its own thread: the connection
//! that started a kennel *owns* the workload and blocks on it, while the shared
//! registry holds only metadata so concurrent `stop`/`list` (and other `run`s)
//! proceed. `stop` signals the workload by pid; the owning thread then tears the
//! kennel down on exit.
//!
//! Two collaborators are abstracted so the dispatch is testable without root or
//! signed-policy crypto: [`Privileged`] (the privhelper) and [`PolicyLoader`]
//! (policy file → [`Plan`]).

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};

use kennel_policy::NetPolicy;
use kennel_privhelper::validate::ReservedScope;
use kennel_spawn::{Plan, RuntimeSubstitutions};

use crate::control::{self, KennelInfo, Request, Response, StartRequest};
use crate::ctx::CtxAllocator;
use crate::{cgroup, start, Privileged};

/// Grace between the TTL reaper's SIGTERM and its SIGKILL for `ttl_action = "exit"`
/// (§9.7): the workload gets this long to exit cleanly before the cgroup is killed.
const TTL_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// A loaded, verified policy, split into the two artefacts kenneld applies.
///
/// The kernel-enforcement [`Plan`] (seal + BPF) and the [`NetPolicy`] the
/// per-kennel egress proxy is configured from both derive from the same signed
/// settled policy — the BPF funnels traffic to the proxy, the proxy enforces the
/// per-destination allowlist (`docs/design/07-5-network.md` §7.5.2), two distinct rule
/// sets from one source.
#[derive(Debug)]
pub struct Loaded {
    /// The kernel-enforcement plan.
    pub plan: Plan,
    /// The workload's masked user name (`[identity].user`, default `kennel`):
    /// `$USER`/`$LOGNAME`, the synthetic `/etc/passwd` account, and the base of
    /// `$HOME` (`/home/<account>`, the plan's view shim root).
    pub account: String,
    /// The workload's masked **primary** group name (`[identity].group`, default
    /// `kennel`): the synthetic `/etc/passwd` `pw_gid` name and the `/etc/group`
    /// entry for the primary gid.
    pub account_group: String,
    /// The network policy the egress proxy enforces.
    pub net: NetPolicy,
    /// The per-kennel SSH runtime (§7.10): the bastion grants `kenneld` realises.
    /// Empty for a kennel with no `[ssh]` policy.
    pub ssh: kennel_policy::SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.6): the host sockets `kenneld` binds
    /// into the kennel's view. Empty for a kennel with no `[unix]` policy.
    pub unix: kennel_policy::UnixRuntime,
    /// The per-kennel binder IPC runtime (§7.1.4): the user-defined services the
    /// context manager gates against. Empty for a kennel with no `[binder]` policy.
    pub binder: kennel_policy::BinderRuntime,
    /// The granted supplementary groups `(name, gid)` (§7.4): resolved and
    /// membership-checked by the loader, named in the synthetic `/etc/group`. The
    /// loader also sets `plan.supplementary_groups` to these gids (what the seal
    /// `setgroups` to). Empty when no group is granted (the kennel drops all).
    pub groups: Vec<(String, u32)>,
    /// The per-kennel audit runtime (§02-3): the sinks and per-class levels
    /// kenneld realises by constructing the `kennel-audit` writer. Empty (all
    /// defaults) for a kennel with no — or an all-default — `[audit]` section.
    pub audit: kennel_policy::AuditRuntime,
    /// The synthesised environment (§7.9.2): the fixed `[env].set` vars the spawn
    /// applies after clearing the inherited environment. Empty for no `[env].set`.
    pub env: kennel_policy::EnvRuntime,
    /// The `PATH` search roots (§7.3.6), synthesised into the workload's `$PATH`.
    /// Empty ⇒ `$PATH` is not set from policy.
    pub exec_path: Vec<String>,
    /// The kennel's login shell (§7.9.2a): the synthetic-`passwd` `pw_shell` and
    /// `$SHELL`. `/bin/sh` unless the policy set `[exec].shell`.
    pub shell: String,
    /// Home-relative paths the dotfile seeder must NOT reconstruct (§7.9.2a
    /// `[fs.home].persist`). Empty ⇒ every synthesised dotfile is reconstructed.
    pub home_persist: Vec<String>,
    /// The lifecycle policy (§9.7): the optional TTL and what to do at expiry. Drives
    /// the TTL reaper in `run_kennel`. `ttl_seconds = None` ⇒ no reaper armed.
    pub lifecycle: kennel_policy::LifecyclePolicy,
}

/// Translate a policy file into the artefacts kenneld applies.
///
/// Abstracted so the dispatch is testable without signed-policy fixtures; the
/// production implementation ([`crate::policy::TrustStoreLoader`]) verifies the
/// signature and substitutes placeholders.
pub trait PolicyLoader {
    /// Load, verify, and substitute the policy at `path` into a [`Loaded`].
    ///
    /// # Errors
    /// A human-readable reason if the policy cannot be loaded, fails
    /// verification, or leaves a placeholder unresolved.
    fn load(&self, path: &Path, subst: &RuntimeSubstitutions) -> Result<Loaded, String>;
}

/// The identity and resources of the user this daemon serves.
pub struct Identity {
    /// The user's real uid.
    pub uid: u32,
    /// The user's real gid.
    pub gid: u32,
    /// The user's account name. Used host-side only — the SSH bastion's
    /// `AuthorizedKeysCommandUser` (§7.10.7). It is **not** written into the kennel's
    /// synthetic `/etc/passwd`, which masks the account name to `kennel` (`crate::etc`).
    pub username: String,
    /// The user's home directory (`<home>` substitution). Never written into the
    /// kennel's synthetic `/etc/passwd` — the workload's home there is the shim
    /// `$HOME`.
    pub home: PathBuf,
    /// The user's reserved scope (tag, ULA GID, namespace).
    pub scope: ReservedScope,
    /// kenneld's own cgroup; kennel cgroups are created as children of it.
    pub cgroup_base: PathBuf,
    /// How to launch each kennel's egress proxy, or `None` to run none.
    pub proxy: Option<crate::ProxySetup>,
    /// Base directory the per-kennel synthetic `/etc` is staged under, or `None`
    /// to skip the synthetic `/etc`.
    pub etc_base: Option<PathBuf>,
    /// Base directory the per-kennel constructed-view new-root mountpoint is
    /// created under (one `root-<ctx>` dir each), or `None` to keep the in-place
    /// fallback seal (no `pivot_root`).
    pub view_base: Option<PathBuf>,
    /// Base directory the per-kennel egress-proxy audit log is written under
    /// (`<audit_base>/<kennel>/network.jsonl`, §7.5.4), or `None` to leave the
    /// proxy logging to stderr. Persistent (state home, not the runtime dir).
    pub audit_base: Option<PathBuf>,
    /// The per-user SSH bastion's configuration (§7.10), or `None` to disable SSH
    /// egress for this daemon. When set, a kennel with `[ssh]` grants gets a
    /// synthetic `~/.ssh` and a route to the shared `kennel-sshd`.
    pub bastion: Option<BastionSetup>,
    /// The host path of `kennel-afunix-shim`, bound into the constructed view and
    /// launched by the seal to broker each granted `AF_UNIX` socket through the binder
    /// facade (§7.6 / `07-1` §7.1.5). `None` disables the facade path, so `[unix]`
    /// grants go unserved (no host socket is exposed by other means).
    pub afunix_shim_bin: Option<PathBuf>,
    /// The host path of the trusted root-owned `kennel-init` the privhelper factory
    /// `fexecve`s as the kennel's uid-0 PID 1 (`07-2`). `Some` selects the factory
    /// construction path (a real uid 0, binderfs chowned to the operator); `None` keeps
    /// the legacy in-process unprivileged spawn.
    pub init_bin: Option<PathBuf>,
}

/// How `kenneld` runs the per-user SSH bastion (§7.10). The daemon holds one
/// `kennel-sshd` for the session; this is its fixed configuration.
#[derive(Debug, Clone)]
pub struct BastionSetup {
    /// The safe-owned runtime dir for the bastion's host key, config, and
    /// `authorized_keys` (under `$XDG_RUNTIME_DIR`, never world-writable).
    pub dir: PathBuf,
    /// The host-side `kennel-ssh-reorigin` the bastion's forced commands invoke.
    pub reorigin_bin: PathBuf,
    /// The in-kennel path of `kennel-socks-connect` (each synthetic `config`
    /// stanza's `ProxyCommand`); also the host path bound into the kennel view.
    pub socks_connect_bin: PathBuf,
    /// The loopback address the bastion listens on.
    pub listen: IpAddr,
    /// The bastion's port.
    pub port: u16,
    /// The host-side agent socket holding the user's real keys (`$SSH_AUTH_SOCK`),
    /// handed to the forced command so it can sign the outbound hop. `None` ⇒ the
    /// helper finds no key and fails closed.
    pub agent_sock: Option<PathBuf>,
    /// The root-owned `AuthorizedKeysCommand` the bastion vends keys through
    /// (production, §7.10.7): it queries this running daemon for the live bindings,
    /// so no `authorized_keys` file is written. `None` falls back to a static
    /// user-owned file (the prototype/e2e source).
    pub akc: Option<crate::bastion::Akc>,
}

/// Registry metadata for one kennel (the workload itself is owned by the
/// connection thread that started it).
struct KennelMeta {
    ctx: u16,
    /// `None` while the kennel is still starting (before the workload's pid is known).
    pid: Option<u32>,
}

/// The mutable shared state: the context allocator and the kennel registry.
#[derive(Default)]
struct Registry {
    ctx: CtxAllocator,
    kennels: BTreeMap<String, KennelMeta>,
}

/// The daemon's shared state, cloned (via `Arc`) into each connection thread.
pub struct Shared<P: Privileged, L: PolicyLoader> {
    identity: Identity,
    privileged: P,
    loader: L,
    registry: Mutex<Registry>,
    /// The per-user SSH bastion (§7.10), created lazily on the first kennel with an
    /// `[ssh]` grant and shared by all of them. `None` until then, or always when
    /// no `bastion` is configured in [`Identity`].
    bastion: Mutex<Option<crate::bastion::Bastion>>,
}

impl<P: Privileged + Clone, L: PolicyLoader> Shared<P, L> {
    /// Build the shared state for `identity`.
    #[must_use]
    pub fn new(identity: Identity, privileged: P, loader: L) -> Self {
        Self {
            identity,
            privileged,
            loader,
            registry: Mutex::new(Registry::default()),
            bastion: Mutex::new(None),
        }
    }

    /// Prepare a kennel's SSH egress (§7.10): mint a synthetic key per grant, register
    /// each `(synthetic-key → dest, real-key)` edge with the per-user bastion (lazily
    /// starting `kennel-sshd`), and materialise the synthetic `~/.ssh` for the kennel
    /// view rooted at `shim_root`. A no-op (empty [`SshPrep`]) when the kennel has no
    /// `[ssh]` grant or this daemon runs no bastion.
    ///
    /// # Errors
    /// A human-readable reason if minting, the bastion, or materialisation fails.
    fn register_ssh(
        &self,
        kennel: &str,
        ssh: &kennel_policy::SshRuntime,
        shim_root: &Path,
    ) -> Result<crate::SshPrep, String> {
        let Some(setup) = self.identity.bastion.as_ref() else {
            return Ok(crate::SshPrep::default());
        };
        if ssh.is_empty() {
            return Ok(crate::SshPrep::default());
        }
        let mut guard = self
            .bastion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bastion = guard.get_or_insert_with(|| {
            crate::bastion::Bastion::new(crate::bastion::BastionConfig {
                dir: setup.dir.clone(),
                reorigin_bin: setup.reorigin_bin.clone(),
                listen: setup.listen,
                port: setup.port,
                agent_sock: setup.agent_sock.clone(),
                akc: setup.akc.clone(),
            })
        });

        let staging = setup.dir.join("synthetic").join(kennel);
        std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
        let mut host_files: Vec<(String, String)> = Vec::new();
        for grant in &ssh.grants {
            let key_file = format!("id_{}", grant.host);
            let comment = format!("kennel {kennel} -> {}", grant.host);
            let pub_line = crate::ssh::mint_synthetic_key(&staging, &key_file, &comment)
                .map_err(|e| e.to_string())?;
            bastion
                .register(crate::bastion::Edge {
                    kennel: kennel.to_owned(),
                    dest: grant.host.clone(),
                    real_fp: grant.fingerprint.clone(),
                    synthetic_pub: pub_line,
                })
                .map_err(|e| e.to_string())?;
            host_files.push((grant.host.clone(), key_file));
        }
        let host_pub = bastion
            .host_pub()
            .ok_or("bastion failed to start (no host key)")?
            .to_owned();
        // The bastion lock is only needed for minting + registration; release it
        // before the synthetic-config file I/O below.
        drop(guard);

        let host_grants: Vec<crate::ssh::HostGrant<'_>> = host_files
            .iter()
            .map(|(h, k)| crate::ssh::HostGrant {
                host: h,
                key_file: k,
            })
            .collect();
        let listen = setup.listen.to_string();
        let socks_bin = setup.socks_connect_bin.to_string_lossy().into_owned();
        let params = crate::ssh::SshParams {
            bastion_host: &listen,
            bastion_port: setup.port,
            bastion_host_key: &host_pub,
            socks_connect_bin: &socks_bin,
            hosts: &host_grants,
        };
        let ssh_dir = shim_root.join(".ssh");
        let file_binds =
            crate::ssh::materialize(&staging, &ssh_dir, &params).map_err(|e| e.to_string())?;
        Ok(crate::SshPrep {
            file_binds,
            host_service: Some(SocketAddr::new(setup.listen, setup.port)),
            socks_connect_bin: Some(setup.socks_connect_bin.clone()),
        })
    }

    /// Prepare a kennel's `AF_UNIX` socket shims (§7.6): resolve each granted socket's
    /// real host path and its in-view shim path (filling `<kennel>`/`<uid>`/`<home>`
    /// and expanding `~`/`$HOME`/`$XDG_RUNTIME_DIR`), and collect any env vars. The
    /// bring-up binds each host socket into the view at its shim path; what is not
    /// granted is structurally absent. A no-op (empty [`crate::UnixPrep`]) when the
    /// kennel has no `[unix]` grant.
    ///
    /// `shim_root` is the kennel's in-view `$HOME` (the constructed-view shim root, or
    /// the real home when there is no view); shim paths rooted at `~`/`$HOME` resolve
    /// under it, real paths under the daemon-user's real home.
    fn prepare_unix(
        &self,
        unix: &kennel_policy::UnixRuntime,
        subst: &RuntimeSubstitutions,
        shim_root: &Path,
    ) -> crate::UnixPrep {
        let mut shims = Vec::new();
        let mut env = Vec::new();
        for sock in &unix.sockets {
            // The real host path is not needed here — the facade (kenneld's binder
            // registry) resolves the name and connects; the proxy only listens at the
            // in-view shim path and brokers by name (`07-1` §7.1.5).
            let shim_path = resolve_path(&sock.shim, subst, shim_root);
            if let Some(var) = &sock.env {
                env.push((var.clone(), shim_path.to_string_lossy().into_owned()));
            }
            shims.push(crate::UnixShim {
                name: sock.name.clone(),
                shim_path,
            });
        }
        crate::UnixPrep {
            shims,
            env,
            afunix_shim_bin: self.identity.afunix_shim_bin.clone(),
        }
    }

    /// Drop a kennel's SSH edges from the bastion on teardown (§7.10.2): a synthetic
    /// key never outlives the kennel it was minted for. Best-effort.
    fn deregister_ssh(&self, kennel: &str) {
        let mut guard = self
            .bastion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bastion) = guard.as_mut() {
            let _ = bastion.deregister(kennel);
        }
    }

    /// Reserve a name and allocate its context, atomically. Returns the context,
    /// or an error response if the name is taken or the pool is exhausted.
    fn reserve(&self, name: &str) -> Result<u16, Response> {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if reg.kennels.contains_key(name) {
            return Err(Response::Error(format!(
                "kennel `{name}` is already running"
            )));
        }
        let Some(ctx) = reg.ctx.allocate() else {
            return Err(Response::Error(
                "no free context (the kennel limit is reached)".to_owned(),
            ));
        };
        reg.kennels
            .insert(name.to_owned(), KennelMeta { ctx, pid: None });
        drop(reg);
        Ok(ctx)
    }

    /// Record the workload's pid once it is spawned.
    fn set_pid(&self, name: &str, pid: u32) {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(meta) = reg.kennels.get_mut(name) {
            meta.pid = Some(pid);
        }
    }

    /// Deregister `name` and return its context to the pool.
    fn release(&self, name: &str, ctx: u16) {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels.remove(name);
        reg.ctx.release(ctx);
    }

    /// Handle a `Stop`: signal the named kennel's workload (the owning thread
    /// reaps and tears it down). Errors if the kennel is unknown or still starting.
    fn stop(&self, name: &str) -> Response {
        let (ctx, started) = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match reg.kennels.get(name) {
                Some(meta) => (meta.ctx, meta.pid.is_some()),
                None => return Response::Error(format!("no kennel named `{name}`")),
            }
        };
        if !started {
            return Response::Error(format!("kennel `{name}` is still starting"));
        }
        // Kill via the cgroup, not the recorded pid: the unprivileged spawn makes
        // the workload PID 1 of a nested PID namespace behind a double-fork, so the
        // recorded handle is the intermediate init — `cgroup.kill` reaches the whole
        // kennel (init + workload + descendants). The owning thread then reaps the
        // init and tears the kennel down.
        let cgroup = cgroup::kennel_cgroup(&self.identity.cgroup_base, ctx);
        match cgroup::kill_cgroup(&cgroup) {
            Ok(()) => Response::Stopped,
            Err(e) => Response::Error(format!("could not stop `{name}`: {e}")),
        }
    }

    /// Handle an `AuthorizedKeys` query (§7.10.7): the bastion's root-owned
    /// `AuthorizedKeysCommand` (`kennel-akc`) asks for the forced-command line(s)
    /// bound to an offered public key. The answer comes from the live [`Bastion`]
    /// edges — the verified, in-memory source of truth — never a file on disk. Empty
    /// (the bastion then refuses the key) when no bastion runs or no edge matches.
    ///
    /// [`Bastion`]: crate::bastion::Bastion
    fn authorized_keys(&self, offered_key: &str) -> Response {
        let guard = self
            .bastion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lines = guard
            .as_ref()
            .map(|b| b.authorized_keys_for(offered_key))
            .unwrap_or_default();
        drop(guard);
        Response::AuthorizedKeys { lines }
    }

    /// Handle a `List`: snapshot the registry.
    fn list(&self) -> Response {
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let kennels: Vec<KennelInfo> = reg
            .kennels
            .iter()
            .map(|(name, meta)| KennelInfo {
                kennel: name.clone(),
                ctx: meta.ctx,
                pid: meta.pid.unwrap_or(0),
                running: meta.pid.is_some(),
            })
            .collect();
        drop(reg);
        Response::Listing(kennels)
    }
}

/// Accept connections on `listener` forever, handling each on its own thread.
///
/// # Errors
/// An OS error if accepting a connection fails.
pub fn serve<P, L>(
    shared: &Arc<Shared<P, L>>,
    listener: &std::os::unix::net::UnixListener,
) -> io::Result<()>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    for conn in listener.incoming() {
        let mut conn = conn?;
        // Boundary 7 (04-trust-boundaries.md): only the user this daemon serves
        // may drive the control socket. The kernel stamps SO_PEERCRED at connect,
        // so this cannot be spoofed; it is defence-in-depth behind the socket's
        // 0600 mode. Reject (close without a wire exchange) anything else.
        let served = shared.identity.uid;
        match kennel_syscall::scm::peer_uid(conn.as_fd()) {
            Ok(uid) if uid == served => {}
            Ok(uid) => {
                eprintln!("kenneld: rejected control connection from uid {uid} (serves {served})");
                continue;
            }
            Err(e) => {
                eprintln!("kenneld: rejecting control connection (peer-cred check failed: {e})");
                continue;
            }
        }
        let shared = Arc::clone(shared);
        std::thread::spawn(move || handle_connection(&shared, &mut conn));
    }
    Ok(())
}

/// Read one request (and any stdio fds) from `conn` and dispatch it. `Start`
/// blocks here until the workload exits; `Stop`/`List` return at once.
fn handle_connection<P, L>(shared: &Shared<P, L>, conn: &mut UnixStream)
where
    P: Privileged + Clone + Sync,
    L: PolicyLoader,
{
    // A malformed/closed connection is just dropped.
    let Ok((request, fds)) = recv_request_with_fds(conn) else {
        return;
    };
    // Trust boundary 6 (§04 trust boundaries): the kennel name arrives from the
    // user's CLI over the control socket and flows into filesystem paths (the
    // synthetic `/etc` staging dir, the per-kennel audit dir), the synthetic
    // `/etc/hostname`, and the registry key. Validate its grammar — `[a-z0-9]`
    // start, then `[a-z0-9-]`, ≤64 chars — *before* it is used anywhere, so a name
    // with `/`, `..`, NUL, whitespace, or control bytes cannot traverse a path or
    // inject a hostname. List/AuthorizedKeys carry no name.
    let response = match request {
        Request::Start(req) => match validate_kennel_name(&req.kennel) {
            Ok(()) => return run_kennel(shared, &req, fds, conn),
            Err(e) => {
                eprintln!("kenneld: rejected start of `{}`: {e}", req.kennel);
                Response::Error(e)
            }
        },
        Request::Stop { kennel } => match validate_kennel_name(&kennel) {
            Ok(()) => shared.stop(&kennel),
            Err(e) => {
                eprintln!("kenneld: rejected stop of `{kennel}`: {e}");
                Response::Error(e)
            }
        },
        Request::List => shared.list(),
        // AuthorizedKeys errors are routine (sshd polls for keys the bastion may not
        // hold), so they are not logged here to avoid spamming the journal.
        Request::AuthorizedKeys { key } => shared.authorized_keys(&key),
    };
    let _ = control::send_response(conn, &response);
}

/// The maximum kennel-name length (`02-2-config-schema.md`: `[a-z0-9][a-z0-9-]{0,63}`).
const MAX_KENNEL_NAME: usize = 64;

/// Validate a kennel name against its grammar `[a-z0-9][a-z0-9-]{0,63}` (§02-2): a
/// lowercase-alphanumeric first character, then lowercase-alphanumeric or hyphen, at
/// most 64 characters. This is the trust-boundary-6 check (§04): the name is
/// untrusted CLI input that becomes path components and the synthetic hostname.
///
/// # Errors
/// A human-readable reason if the name is empty, too long, or contains a character
/// outside the grammar (in particular `/`, `.`, NUL, whitespace, or control bytes).
fn validate_kennel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("kennel name must not be empty".to_owned());
    }
    if name.len() > MAX_KENNEL_NAME {
        return Err(format!(
            "kennel name `{name}` is too long ({} chars; the limit is {MAX_KENNEL_NAME})",
            name.len()
        ));
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "kennel name `{name}` must start with a lowercase letter or digit \
             (the grammar is [a-z0-9][a-z0-9-]{{0,63}})"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
    {
        return Err(format!(
            "kennel name `{name}` contains the illegal character {bad:?} \
             (only [a-z0-9-] are allowed, so it cannot traverse a path or inject a hostname)"
        ));
    }
    Ok(())
}

/// Bring one kennel up for a `Start` request: report `Started`, block until the workload
/// exits, tear it down, and report `Exited`.
///
/// This is the production per-kennel path the daemon's [`serve`] loop calls — and the entry
/// point the self-hosting e2e drives directly (real privhelper + a real [`TrustStoreLoader`]),
/// so the test exercises the same wiring production does, not a hand-built replica.
// allow: one linear request lifecycle (reserve, load, ssh/unix/audit prep, spawn,
// block, tear down); splitting it would scatter the shared `ctx`/`state_dir`/uuid.
#[allow(clippy::too_many_lines)]
pub fn run_kennel<P, L>(
    shared: &Shared<P, L>,
    req: &StartRequest,
    fds: Vec<OwnedFd>,
    conn: &mut UnixStream,
) where
    P: Privileged + Clone + Sync,
    L: PolicyLoader,
{
    let ctx = match shared.reserve(&req.kennel) {
        Ok(ctx) => ctx,
        Err(resp) => {
            if let Response::Error(msg) = &resp {
                eprintln!(
                    "kenneld: kennel `{}` failed to start [reserve]: {msg}",
                    req.kennel
                );
            }
            let _ = control::send_response(conn, &resp);
            return;
        }
    };

    let subst = RuntimeSubstitutions {
        ctx,
        uid: shared.identity.uid,
        kennel: req.kennel.clone(),
        home: shared.identity.home.clone(),
        namespace: shared.identity.scope.namespace().to_owned(),
        // `<tag>`/`<gid>` come from the user's reserved scope (loaded from
        // /etc/kennel/subkennel) — the daemon is the one source of truth, so the
        // compiler/CLI never bakes them in.
        tag: shared.identity.scope.tag(),
        ula_gid: shared.identity.scope.ula_gid(),
    };

    let mut loaded = match shared.loader.load(&req.policy, &subst) {
        Ok(loaded) => loaded,
        Err(reason) => return fail(shared, &req.kennel, ctx, conn, "load policy", reason),
    };
    // Interactive runs pass ONE connected socket (over which the seal returns a
    // controlling pty allocated inside the kennel's devpts); non-interactive runs
    // pass the three stdio fds. `return_sock` must outlive the spawn so the forked
    // child inherits it during the pre-exec seal — it stays in scope below.
    let mut return_sock: Option<OwnedFd> = None;
    let mut command = if req.interactive {
        return_sock = fds.into_iter().next();
        match command_for_interactive(&req.argv, &req.cwd) {
            Ok(command) => command,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "prepare command", reason),
        }
    } else {
        match command_for(&req.argv, &req.cwd, fds) {
            Ok(command) => command,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "prepare command", reason),
        }
    };
    // Prepare SSH egress (§7.10): mint synthetic keys, register the edges with the
    // per-user bastion, and build the synthetic ~/.ssh for the view. The ~/.ssh is
    // rooted at the constructed-view HOME (the plan's shim root) when there is one.
    let shim_root = loaded
        .plan
        .view
        .as_ref()
        .map_or_else(|| shared.identity.home.clone(), |v| v.shim_root.clone());
    let ssh = match shared.register_ssh(&req.kennel, &loaded.ssh, &shim_root) {
        Ok(ssh) => ssh,
        // `fail` deregisters any edges registered before the failure.
        Err(reason) => {
            return fail(
                shared,
                &req.kennel,
                ctx,
                conn,
                "register ssh egress",
                reason,
            )
        }
    };
    // Prepare the AF_UNIX socket shims (§7.6): resolve each granted socket's host
    // and in-view paths. Stateless (no daemon to register with), so no teardown hook.
    let unix = shared.prepare_unix(&loaded.unix, &subst, &shim_root);
    // Re-derive the compile-time footgun warning at spawn (§7.10.1): a policy may shim a
    // real ssh-agent socket via `[[unix.allow]]`, which the framework permits but warns
    // loudly about — an exposed agent is a destination-blind signing oracle. An operator
    // who ran a pre-compiled artefact never saw the `kennel compile` warning, so emit it
    // here too. Warned, not refused — footguns are loud, not amputated.
    for sock in &loaded.unix.sockets {
        let shims_ssh_agent = sock.name.eq_ignore_ascii_case("ssh-agent")
            || sock.env.as_deref() == Some("SSH_AUTH_SOCK");
        if shims_ssh_agent {
            eprintln!(
                "kenneld: warning: kennel `{}` shims an SSH agent (`{}`): an exposed agent is a \
                 destination-blind signing oracle (§7.10.1) — any code in the kennel can sign for \
                 any destination. The [ssh] re-origination bastion is the intended path.",
                req.kennel, sock.name
            );
        }
    }
    // The audit runtime (§02-3): the installation/per-user `audit.toml` defaults
    // (§8.1) overlaid by the per-kennel policy `[audit]` (built-in < /etc/kennel <
    // ~/.config < policy). Captured before `loaded` is consumed below.
    let audit_runtime = crate::audit::load_audit_defaults().overlay(&loaded.audit);
    // One `kennel_uuid` for this run, shared by kenneld's lifecycle writer and the
    // egress proxy's writer so their events correlate. The per-kennel state dir is
    // where both `lifecycle.jsonl` (kenneld) and `network.jsonl` (proxy) land.
    let kennel_uuid = crate::audit::kennel_uuid();
    let state_dir = shared
        .identity
        .audit_base
        .as_ref()
        .map(|base| base.join(&req.kennel));
    let proxy_audit = state_dir.as_ref().map(|dir| crate::proxy::ProxyAudit {
        kennel: req.kennel.clone(),
        kennel_uuid: kennel_uuid.clone(),
        dir: dir.clone(),
        sinks: audit_runtime
            .sinks
            .iter()
            .map(|k| k.token().to_owned())
            .collect(),
        network_level: audit_runtime.network_level.clone(),
        syslog_facility: audit_runtime.syslog_facility.clone(),
        rotate_at_bytes: audit_runtime.file.rotate_at_bytes,
        compress_after_seconds: audit_runtime.file.compress_after_seconds,
        retain_count: audit_runtime.file.retain_count,
    });

    // Hand the seal the interactive return socket's raw fd (it sends the pty master
    // back over it during pre-exec). `return_sock` keeps the fd open until after the
    // spawn returns, so the forked child still has it.
    loaded.plan.interactive_return_fd = return_sock.as_ref().map(AsRawFd::as_raw_fd);

    let id = &shared.identity;
    let etc = id.etc_base.as_ref().map(|base| crate::EtcSetup {
        staging_dir: base.join(format!("etc-{ctx}")),
        account: loaded.account.clone(),
        account_group: loaded.account_group.clone(),
        hostname: req.kennel.clone(),
        uid: id.uid,
        gid: id.gid,
        // The synthetic /etc/passwd home is the in-kennel shim $HOME, not the
        // operator's real home (which would re-leak the masked identity, §7.4.x).
        home: shim_root.clone(),
        // The resolved supplementary groups, named in /etc/group (§7.4). The loader
        // already set plan.supplementary_groups to their gids (what the seal drops to).
        groups: loaded.groups.clone(),
        // The login shell for the synthetic passwd's pw_shell field (§7.9.2a).
        shell: loaded.shell.clone(),
        // Home-relative paths exempt from dotfile reconstruction (§7.9.2a).
        home_persist: loaded.home_persist.clone(),
    });
    // The TTL reaper inputs (§9.7), captured before `loaded` is consumed below.
    let ttl = loaded
        .lifecycle
        .ttl_seconds
        .map(std::time::Duration::from_secs);
    let ttl_action = loaded.lifecycle.ttl_action;
    let mut spec = crate::Spec {
        id: req.kennel.clone(),
        cgroup: cgroup::kennel_cgroup(&id.cgroup_base, ctx),
        ctx,
        scope: id.scope.clone(),
        plan: loaded.plan,
        net: loaded.net,
        proxy: id.proxy.clone(),
        etc,
        view_root: id
            .view_base
            .as_ref()
            .map(|base| base.join(format!("root-{ctx}"))),
        proxy_audit,
        ssh,
        unix,
        binder: None,
    };

    // Construct the per-kennel audit writer *before* start so the privileged
    // operations during bring-up (and any refusal) are recorded as `priv.*`
    // events through the same writer; it shares the run's `kennel_uuid` with the
    // proxy. With no state dir configured, audit is simply not recorded and the
    // decorator is a transparent pass-through.
    let audit = state_dir.as_ref().map(|dir| {
        Arc::new(crate::audit::build_writer(
            &req.kennel,
            dir,
            &audit_runtime,
            kennel_uuid.clone(),
        ))
    });
    let audited = crate::audit::AuditedPrivileged::new(&shared.privileged, audit.as_deref());

    // Every kennel runs the privhelper factory + a per-kennel binder bus: binder is the
    // universal control plane (`kennel-init` pulls its supervision-half over node 0), not an
    // opt-in for [binder]/[unix] kennels (`07-1`/`07-2`). So always wire the daemon-side
    // context manager — it takes node 0, serves the lifecycle pull, and answers any facade.
    // The registry's policy/facade sets are simply empty for a kennel that grants no IPC.
    {
        // The facade connects to the real host socket, so resolve each `real` path's
        // `~`/`$XDG_RUNTIME_DIR`/placeholders against the daemon's own home now (the
        // shim path the proxy listens at was already resolved in `prepare_unix`).
        let facade_unix = kennel_policy::UnixRuntime {
            sockets: loaded
                .unix
                .sockets
                .iter()
                .map(|s| kennel_policy::UnixSocket {
                    real: resolve_path(&s.real, &subst, &shared.identity.home)
                        .to_string_lossy()
                        .into_owned(),
                    ..s.clone()
                })
                .collect(),
        };
        // The registry records every decision (§7.1.4). With no audit state dir, a sink-less
        // writer keeps the bus running without recording.
        let writer = audit
            .clone()
            .unwrap_or_else(|| Arc::new(crate::audit::noop_writer(&req.kennel, kennel_uuid.clone())));
        spec.binder = Some(crate::BinderPrep {
            policy: loaded.binder,
            unix: facade_unix,
            writer,
            init_bin: shared.identity.init_bin.clone(),
        });
    }

    // Synthesise the workload environment from policy (§7.9.2): clear the inherited
    // environment and build it from scratch. `PATH` (from `[exec].path`),
    // `USER`/`LOGNAME` (the masked account), `SHELL` (`[exec].shell`), and `HOME`
    // (the kennel's shim home) are synthesised; `[env].set` is layered on top. The
    // parent's environment is never a source — a secret policy did not name cannot
    // reach the workload. (`bring_up` adds `KENNEL_SOCKS_PROXY` and any unix-shim
    // vars on top of this cleared base.)
    command.env_clear();
    if !loaded.exec_path.is_empty() {
        command.env("PATH", loaded.exec_path.join(":"));
    }
    command.env("USER", &loaded.account);
    command.env("LOGNAME", &loaded.account);
    command.env("SHELL", &loaded.shell);
    command.env("HOME", &shim_root);
    // Forward the caller's TERM (the one host var an interactive workload genuinely
    // needs and cannot be synthesised); everything else is policy [env].set below.
    if !req.term.is_empty() {
        command.env("TERM", &req.term);
    }
    for (key, value) in &loaded.env.vars {
        command.env(key, value);
    }

    let kennel = match start(&audited, spec, &mut command) {
        Ok(kennel) => kennel,
        Err(e) => {
            // A bring-up failure after the egress step may have left BPF pins behind
            // (the teardown removes the cgroup, which detaches the programs, but the
            // pins outlive the helper). Clean them up best-effort.
            crate::bpf_audit::cleanup_pins(&req.kennel);
            return fail(
                shared,
                &req.kennel,
                ctx,
                conn,
                "spawn workload",
                e.to_string(),
            );
        }
    };
    let pid = kennel.id();
    shared.set_pid(&req.kennel, pid);
    if let Some(writer) = &audit {
        writer.emit(&crate::audit::kennel_start(pid, ctx));
    }
    // Drain the per-kennel BPF audit ring buffer (§02-7): reopen the pinned ringbuf
    // and route its connect/bind events through the same writer with `source: bpf`.
    // Best-effort — absent pin (older helper / pinning failed) or no audit writer ⇒
    // no drain, egress unaffected.
    let drain = audit.as_ref().and_then(|writer| {
        crate::bpf_audit::spawn(
            crate::bpf_audit::pin_dir_for(&req.kennel),
            ctx,
            Arc::clone(writer),
        )
    });
    let _ = control::send_response(conn, &Response::Started { ctx, pid });

    // Block until the workload exits (on its own, via `stop`, or via the TTL reaper),
    // then tear down. With a `ttl` the wait polls so the reaper can act at expiry
    // (§9.7); each milestone is recorded through the audit writer. The audited
    // privileged records the teardown's `del_address` refusals too.
    let ttl_writer = audit.as_ref();
    let status = kennel.stop_with_ttl(&audited, ttl, ttl_action, TTL_GRACE, |ev| {
        let stage = match ev {
            crate::TtlEvent::Warned => "warn",
            crate::TtlEvent::RenewRequested => "renew",
            crate::TtlEvent::Terminating => "terminating",
            crate::TtlEvent::Killed => "killed",
        };
        eprintln!(
            "kenneld: kennel `{}` TTL elapsed (action {ttl_action:?}): {stage}",
            req.kennel
        );
        if let Some(writer) = ttl_writer {
            writer.emit(&crate::audit::ttl_expired(pid, stage));
        }
    });
    if let Some(writer) = &audit {
        writer.emit(&crate::audit::workload_exit(pid, exit_code(&status)));
        writer.emit(&crate::audit::kennel_exit("stopped"));
    }
    // Stop the BPF drain after the lifecycle events: a final sweep captures events
    // committed just before exit, then the per-kennel pins are removed.
    if let Some(drain) = drain {
        drain.stop();
    }
    shared.deregister_ssh(&req.kennel);
    shared.release(&req.kennel, ctx);
    let _ = control::send_response(
        conn,
        &Response::Exited {
            code: exit_code(&status),
        },
    );
}

/// Release the reservation, **log the reason**, and report it (a bring-up step
/// failed). The CLI only receives the terse `Response::Error`, so without this log
/// a failed start is invisible to the operator; kenneld runs as a systemd user unit,
/// so stderr lands in the journal — `journalctl --user -u kenneld` shows `stage` and
/// `reason`. Returns the same `Response::Error(reason)` it logged.
fn fail<P: Privileged + Clone, L: PolicyLoader>(
    shared: &Shared<P, L>,
    name: &str,
    ctx: u16,
    conn: &mut UnixStream,
    stage: &str,
    reason: String,
) {
    eprintln!("kenneld: kennel `{name}` failed to start [{stage}]: {reason}");
    // Drop any SSH edges registered before the failing step (a no-op otherwise), so
    // a failed bring-up leaves no synthetic key in the bastion.
    shared.deregister_ssh(name);
    shared.release(name, ctx);
    let _ = control::send_response(conn, &Response::Error(reason));
}

/// The exit code to report: the process's code, `128 + signal` if it was killed,
/// or `-1` if the wait itself failed.
fn exit_code(status: &io::Result<ExitStatus>) -> i32 {
    status.as_ref().map_or(-1, |status| {
        status
            .code()
            .or_else(|| status.signal().map(|s| 128_i32.saturating_add(s)))
            .unwrap_or(-1)
    })
}

/// Read one framed request, plus any stdio fds, from a single `recvmsg`.
fn recv_request_with_fds(conn: &UnixStream) -> io::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 128 * 1024];
    let (n, fds) = kennel_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf)?;
    let frame = buf
        .get(..n)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let len_bytes: [u8; 4] = frame
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let len = u32::from_ne_bytes(len_bytes) as usize;
    let end = len
        .checked_add(4)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let body = frame
        .get(4..end)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let request = Request::decode(body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e:?}")))?;
    Ok((request, fds))
}

/// Resolve a `[unix]` socket path: fill the per-instance placeholders
/// (`<kennel>`/`<ctx>`/`<uid>`/`<home>`) and expand a leading `~`/`$HOME` against
/// `base_home` and `$XDG_RUNTIME_DIR`/`$UID` against the uid (§7.6). `base_home` is
/// the real home for a `real` path, the in-view shim root for a `shim` path.
fn resolve_path(raw: &str, subst: &RuntimeSubstitutions, base_home: &Path) -> PathBuf {
    let uid = subst.uid.to_string();
    let s = raw
        .replace("<kennel>", &subst.kennel)
        .replace("<ctx>", &subst.ctx.to_string())
        .replace("<uid>", &uid)
        .replace("<home>", &subst.home.to_string_lossy())
        .replace("$XDG_RUNTIME_DIR", &format!("/run/user/{uid}"))
        .replace("$UID", &uid);
    if s == "~" || s == "$HOME" {
        return base_home.to_path_buf();
    }
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("$HOME/")) {
        return base_home.join(rest);
    }
    PathBuf::from(s)
}

/// Build the workload command from `argv`/`cwd`, wiring the passed stdio fds if
/// all three are present (otherwise the workload inherits the daemon's stdio).
fn command_for(argv: &[String], cwd: &Path, fds: Vec<OwnedFd>) -> Result<Command, String> {
    let (program, rest) = argv.split_first().ok_or_else(|| "empty argv".to_owned())?;
    let mut command = Command::new(program);
    command.args(rest).current_dir(cwd);
    let mut fds = fds.into_iter();
    if let (Some(stdin), Some(stdout), Some(stderr)) = (fds.next(), fds.next(), fds.next()) {
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
    }
    Ok(command)
}

/// Build the workload command for an **interactive** run. Stdio is `null` here — the
/// spawn seal allocates a controlling pty inside the kennel's devpts and `dup2`s its
/// slave onto fds 0/1/2 (§7.9.2), so any inherited stdio would be overwritten anyway.
fn command_for_interactive(argv: &[String], cwd: &Path) -> Result<Command, String> {
    let (program, rest) = argv.split_first().ok_or_else(|| "empty argv".to_owned())?;
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use kennel_privhelper::wire::{EgressPayload, Response as HelperResponse};
    use kennel_syscall::landlock::AccessFs;
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;

    #[test]
    fn valid_kennel_names_are_accepted() {
        for ok in [
            "a",
            "0",
            "ai-coding-strict",
            "npm2",
            "x".repeat(64).as_str(),
        ] {
            assert!(
                validate_kennel_name(ok).is_ok(),
                "`{ok}` should be a valid kennel name"
            );
        }
    }

    #[test]
    fn invalid_kennel_names_are_rejected() {
        // Empty, too long, path-traversal, hostname/log injection, control bytes.
        for bad in [
            "",
            "-leading-hyphen",
            "Upper",
            "../escape",
            "a/b",
            "a.b",
            "has space",
            "tab\tname",
            "nul\0byte",
            "emoji😀",
        ] {
            assert!(
                validate_kennel_name(bad).is_err(),
                "`{bad}` must be rejected"
            );
        }
        // 65 chars is one over the limit.
        assert!(validate_kennel_name(&"a".repeat(65)).is_err());
    }

    #[derive(Clone)]
    struct OkPriv;
    impl Privileged for OkPriv {
        fn add_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<HelperResponse> {
            Ok(HelperResponse::ok())
        }
        fn del_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<HelperResponse> {
            Ok(HelperResponse::ok())
        }
        fn setup_egress(&self, _: &Path, _: &EgressPayload) -> io::Result<HelperResponse> {
            Ok(HelperResponse::ok())
        }
        fn set_gid_map(&self, _: u32, _: &[u32]) -> io::Result<HelperResponse> {
            Ok(HelperResponse::ok())
        }
    }

    struct FakeLoader;
    impl PolicyLoader for FakeLoader {
        fn load(&self, _: &Path, _: &RuntimeSubstitutions) -> Result<Loaded, String> {
            let plan = Plan {
                namespaces: Namespaces::empty(),
                cgroup: PathBuf::new(),
                cgroup_join: false,
                view: None,
                new_root: None,
                landlock_fs: vec![(
                    PathBuf::from("/"),
                    AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE,
                )],
                landlock_net: Vec::new(),
                seccomp_deny: Vec::new(),
                seccomp_deny_action: Action::KillProcess,
                bpf_allow_v4: Vec::new(),
                bpf_deny_v4: Vec::new(),
                bpf_allow_v6: Vec::new(),
                bpf_deny_v6: Vec::new(),
                bpf_meta: [0u8; 64],
                bind_allowed_ports: Vec::new(),
                file_binds: Vec::new(),
                supplementary_groups: None,
                ulimits: Vec::new(),
                interactive_return_fd: None,
                aux: Vec::new(),
            };
            let net = NetPolicy {
                mode: kennel_policy::NetMode::Constrained,
                proxy: kennel_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
                deny_invariant: Vec::new(),
                bind_port_min: 0,
                bind_allowed_ports: Vec::new(),
            };
            Ok(Loaded {
                plan,
                account: "kennel".to_owned(),
                account_group: "kennel".to_owned(),
                net,
                ssh: kennel_policy::SshRuntime::default(),
                unix: kennel_policy::UnixRuntime::default(),
                binder: kennel_policy::BinderRuntime::default(),
                groups: Vec::new(),
                audit: kennel_policy::AuditRuntime::default(),
                env: kennel_policy::EnvRuntime::default(),
                exec_path: Vec::new(),
                shell: "/bin/sh".to_owned(),
                home_persist: Vec::new(),
                lifecycle: kennel_policy::LifecyclePolicy {
                    ttl_seconds: None,
                    ttl_action: kennel_policy::TtlAction::Exit,
                },
            })
        }
    }

    fn shared() -> Shared<OkPriv, FakeLoader> {
        let base = std::env::temp_dir().join(format!(
            "kenneld-srv-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base dir");
        Shared::new(
            Identity {
                uid: 1000,
                gid: 1000,
                username: "dev".to_owned(),
                home: PathBuf::from("/home/dev"),
                scope: ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-test"),
                cgroup_base: base,
                proxy: None,
                etc_base: None,
                view_base: None,
                audit_base: None,
                bastion: None,
                afunix_shim_bin: None,
                init_bin: None,
            },
            OkPriv,
            FakeLoader,
        )
    }

    #[test]
    fn reserve_allocates_and_refuses_duplicates() {
        let s = shared();
        assert_eq!(s.reserve("a"), Ok(1));
        assert_eq!(s.reserve("b"), Ok(2));
        assert!(s.reserve("a").is_err(), "duplicate name refused");
        s.release("a", 1);
        assert_eq!(s.reserve("a"), Ok(1), "released ctx is reusable");
    }

    #[test]
    fn stop_reports_unknown_and_still_starting() {
        let s = shared();
        assert!(
            matches!(s.stop("ghost"), Response::Error(_)),
            "unknown kennel errors"
        );
        let ctx = s.reserve("p").expect("reserve");
        // pid not yet set -> still starting.
        assert!(
            matches!(s.stop("p"), Response::Error(_)),
            "still-starting kennel cannot be stopped"
        );
        s.release("p", ctx);
    }

    #[test]
    fn authorized_keys_vends_the_forced_command_line_from_live_edges() {
        use crate::bastion::{Bastion, BastionConfig, Edge};

        let s = shared();
        // No bastion yet ⇒ any key authorises nothing (the AKC then refuses it).
        let Response::AuthorizedKeys { lines } = s.authorized_keys("ssh-ed25519 ANY") else {
            unreachable!("authorized_keys response")
        };
        assert!(lines.is_empty(), "no bastion ⇒ no authorised keys");

        // Stand up a bastion with one live edge (no sshd) and query it as the AKC would.
        let mut bastion = Bastion::new(BastionConfig {
            dir: PathBuf::from("/run/user/1000/kennel-bastion"),
            reorigin_bin: PathBuf::from("/opt/kennel/bin/kennel-ssh-reorigin"),
            listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 7022,
            agent_sock: None,
            akc: None,
        });
        bastion.push_edge_for_test(Edge {
            kennel: "ka".to_owned(),
            dest: "github.com".to_owned(),
            real_fp: "SHA256:AAAa1EZ7oO0qfsA5OSDosRRaFD9evYHhSlcrDPTVoZw".to_owned(),
            synthetic_pub: "ssh-ed25519 AAAASYN_A ka".to_owned(),
        });
        *s.bastion.lock().expect("bastion lock") = Some(bastion);

        // The offered key (comment-free, as sshd's %t %k) returns exactly its binding.
        let Response::AuthorizedKeys { lines } = s.authorized_keys("ssh-ed25519 AAAASYN_A") else {
            unreachable!("authorized_keys response")
        };
        let line = lines.first().map(String::as_str).unwrap_or_default();
        assert_eq!(lines.len(), 1, "one matching edge");
        assert!(
            line.contains("--dest github.com") && line.contains("AAAASYN_A"),
            "got {line}"
        );

        // An unknown key authorises nothing.
        let Response::AuthorizedKeys { lines } = s.authorized_keys("ssh-ed25519 UNKNOWN") else {
            unreachable!("authorized_keys response")
        };
        assert!(lines.is_empty(), "unknown key ⇒ refused");
    }

    #[test]
    fn list_reflects_the_registry() {
        let s = shared();
        s.reserve("a").expect("a");
        s.reserve("b").expect("b");
        s.set_pid("a", 4242);
        let Response::Listing(mut kennels) = s.list() else {
            unreachable!("listing")
        };
        kennels.sort_by(|x, y| x.kennel.cmp(&y.kennel));
        let summary: Vec<(&str, bool)> = kennels
            .iter()
            .map(|k| (k.kennel.as_str(), k.running))
            .collect();
        // `a` has a pid (running); `b` is reserved but not yet started.
        assert_eq!(summary, [("a", true), ("b", false)]);
    }

    #[test]
    fn handle_connection_runs_a_kennel_over_a_real_socket() {
        use std::os::unix::net::UnixListener;

        let s = shared();
        let dir = std::env::temp_dir().join(format!("kenneld-conn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).expect("bind");

        // Client: connect, send a Start (framed + no fds) via scm, read the two
        // responses (Started, then Exited).
        let client = std::thread::spawn(move || {
            let mut conn = UnixStream::connect(&path).expect("connect");
            let request = Request::Start(StartRequest {
                policy: PathBuf::from("/dev/null"),
                kennel: "sock".to_owned(),
                argv: vec!["/bin/true".to_owned()],
                cwd: PathBuf::from("/"),
                term: String::new(),
                interactive: false,
            });
            let mut framed = Vec::new();
            control::write_frame(&mut framed, &request.encode()).expect("frame");
            kennel_syscall::scm::send_with_fds(conn.as_fd(), &framed, &[]).expect("send");
            let started = control::recv_response(&mut conn).expect("started");
            let exited = control::recv_response(&mut conn).expect("exited");
            (started, exited)
        });

        // Server: accept one connection and handle it (this drives recv_with_fds,
        // the framing parse, dispatch, and run_kennel end to end).
        let (mut conn, _) = listener.accept().expect("accept");
        handle_connection(&s, &mut conn);

        let (started, exited) = client.join().expect("client thread");
        assert!(
            matches!(started, Response::Started { ctx: 1, .. }),
            "got {started:?}"
        );
        assert_eq!(exited, Response::Exited { code: 0 });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_kennel_reports_started_then_exited() {
        let s = shared();
        let (client, mut server) = UnixStream::pair().expect("socketpair");
        let req = StartRequest {
            policy: PathBuf::from("/dev/null"),
            kennel: "quick".to_owned(),
            argv: vec!["/bin/true".to_owned()],
            cwd: PathBuf::from("/"),
            term: String::new(),
            interactive: false,
        };
        // No fds: the workload inherits this process's stdio. /bin/true exits 0
        // immediately, so run_kennel returns after writing both responses.
        run_kennel(&s, &req, Vec::new(), &mut server);

        let mut client = client;
        let started = control::recv_response(&mut client).expect("started");
        assert!(
            matches!(started, Response::Started { ctx: 1, .. }),
            "got {started:?}"
        );
        let exited = control::recv_response(&mut client).expect("exited");
        assert_eq!(exited, Response::Exited { code: 0 }, "true exits 0");
        // The kennel deregistered on exit.
        assert!(matches!(s.list(), Response::Listing(k) if k.is_empty()));
    }
}
