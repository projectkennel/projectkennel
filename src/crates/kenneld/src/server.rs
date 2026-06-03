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
use std::os::fd::{AsFd, OwnedFd};
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

/// A loaded, verified policy, split into the two artefacts kenneld applies.
///
/// The kernel-enforcement [`Plan`] (seal + BPF) and the [`NetPolicy`] the
/// per-kennel egress proxy is configured from both derive from the same signed
/// settled policy — the BPF funnels traffic to the proxy, the proxy enforces the
/// per-destination allowlist (`docs/design/07-3-network.md` §7.3.2), two distinct rule
/// sets from one source.
#[derive(Debug)]
pub struct Loaded {
    /// The kernel-enforcement plan.
    pub plan: Plan,
    /// The network policy the egress proxy enforces.
    pub net: NetPolicy,
    /// The per-kennel SSH runtime (§7.8): the bastion grants `kenneld` realises.
    /// Empty for a kennel with no `[ssh]` policy.
    pub ssh: kennel_policy::SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.4): the host sockets `kenneld` binds
    /// into the kennel's view. Empty for a kennel with no `[unix]` policy.
    pub unix: kennel_policy::UnixRuntime,
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
    /// `AuthorizedKeysCommandUser` (§7.8.7). It is **not** written into the kennel's
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
    /// (`<audit_base>/<kennel>/network.jsonl`, §7.3.4), or `None` to leave the
    /// proxy logging to stderr. Persistent (state home, not the runtime dir).
    pub audit_base: Option<PathBuf>,
    /// The per-user SSH bastion's configuration (§7.8), or `None` to disable SSH
    /// egress for this daemon. When set, a kennel with `[ssh]` grants gets a
    /// synthetic `~/.ssh` and a route to the shared `kennel-sshd`.
    pub bastion: Option<BastionSetup>,
}

/// How `kenneld` runs the per-user SSH bastion (§7.8). The daemon holds one
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
    /// (production, §7.8.7): it queries this running daemon for the live bindings,
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
    /// The per-user SSH bastion (§7.8), created lazily on the first kennel with an
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

    /// Prepare a kennel's SSH egress (§7.8): mint a synthetic key per grant, register
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
        let Some(setup) = self.identity.bastion.as_ref() else { return Ok(crate::SshPrep::default()) };
        if ssh.is_empty() {
            return Ok(crate::SshPrep::default());
        }
        let mut guard = self.bastion.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let pub_line =
                crate::ssh::mint_synthetic_key(&staging, &key_file, &comment).map_err(|e| e.to_string())?;
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
        let host_pub = bastion.host_pub().ok_or("bastion failed to start (no host key)")?.to_owned();
        // The bastion lock is only needed for minting + registration; release it
        // before the synthetic-config file I/O below.
        drop(guard);

        let host_grants: Vec<crate::ssh::HostGrant<'_>> =
            host_files.iter().map(|(h, k)| crate::ssh::HostGrant { host: h, key_file: k }).collect();
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
        let file_binds = crate::ssh::materialize(&staging, &ssh_dir, &params).map_err(|e| e.to_string())?;
        Ok(crate::SshPrep {
            file_binds,
            host_service: Some(SocketAddr::new(setup.listen, setup.port)),
            socks_connect_bin: Some(setup.socks_connect_bin.clone()),
        })
    }

    /// Prepare a kennel's `AF_UNIX` socket shims (§7.4): resolve each granted socket's
    /// real host path and its in-view shim path (filling `<kennel>`/`<uid>`/`<home>`
    /// and expanding `~`/`$HOME`/`$XDG_RUNTIME_DIR`), and collect any env vars. The
    /// bring-up binds each host socket into the view at its shim path; what is not
    /// granted is structurally absent. A no-op (empty [`crate::UnixPrep`]) when the
    /// kennel has no `[unix]` grant.
    ///
    /// `shim_root` is the kennel's in-view `$HOME` (the constructed-view shim root, or
    /// the real home when there is no view); shim paths rooted at `~`/`$HOME` resolve
    /// under it, real paths under the daemon-user's real home.
    fn prepare_unix(&self, unix: &kennel_policy::UnixRuntime, subst: &RuntimeSubstitutions, shim_root: &Path) -> crate::UnixPrep {
        let mut socket_binds = Vec::new();
        let mut env = Vec::new();
        for sock in &unix.sockets {
            let source = resolve_path(&sock.real, subst, &self.identity.home);
            let target = resolve_path(&sock.shim, subst, shim_root);
            if let Some(var) = &sock.env {
                env.push((var.clone(), target.to_string_lossy().into_owned()));
            }
            socket_binds.push((source, target));
        }
        crate::UnixPrep { socket_binds, env }
    }

    /// Drop a kennel's SSH edges from the bastion on teardown (§7.8.2): a synthetic
    /// key never outlives the kennel it was minted for. Best-effort.
    fn deregister_ssh(&self, kennel: &str) {
        let mut guard = self.bastion.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bastion) = guard.as_mut() {
            let _ = bastion.deregister(kennel);
        }
    }

    /// Reserve a name and allocate its context, atomically. Returns the context,
    /// or an error response if the name is taken or the pool is exhausted.
    fn reserve(&self, name: &str) -> Result<u16, Response> {
        let mut reg = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if reg.kennels.contains_key(name) {
            return Err(Response::Error(format!("kennel `{name}` is already running")));
        }
        let Some(ctx) = reg.ctx.allocate() else {
            return Err(Response::Error("no free context (the kennel limit is reached)".to_owned()));
        };
        reg.kennels.insert(name.to_owned(), KennelMeta { ctx, pid: None });
        drop(reg);
        Ok(ctx)
    }

    /// Record the workload's pid once it is spawned.
    fn set_pid(&self, name: &str, pid: u32) {
        let mut reg = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(meta) = reg.kennels.get_mut(name) {
            meta.pid = Some(pid);
        }
    }

    /// Deregister `name` and return its context to the pool.
    fn release(&self, name: &str, ctx: u16) {
        let mut reg = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels.remove(name);
        reg.ctx.release(ctx);
    }

    /// Handle a `Stop`: signal the named kennel's workload (the owning thread
    /// reaps and tears it down). Errors if the kennel is unknown or still starting.
    fn stop(&self, name: &str) -> Response {
        let pid = {
            let reg = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            match reg.kennels.get(name) {
                Some(meta) => meta.pid,
                None => return Response::Error(format!("no kennel named `{name}`")),
            }
        };
        pid.map_or_else(
            || Response::Error(format!("kennel `{name}` is still starting")),
            |pid| match kennel_syscall::signal::kill(pid) {
                Ok(()) => Response::Stopped,
                Err(e) => Response::Error(format!("could not stop `{name}`: {e}")),
            },
        )
    }

    /// Handle an `AuthorizedKeys` query (§7.8.7): the bastion's root-owned
    /// `AuthorizedKeysCommand` (`kennel-akc`) asks for the forced-command line(s)
    /// bound to an offered public key. The answer comes from the live [`Bastion`]
    /// edges — the verified, in-memory source of truth — never a file on disk. Empty
    /// (the bastion then refuses the key) when no bastion runs or no edge matches.
    ///
    /// [`Bastion`]: crate::bastion::Bastion
    fn authorized_keys(&self, offered_key: &str) -> Response {
        let guard = self.bastion.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let lines = guard.as_ref().map(|b| b.authorized_keys_for(offered_key)).unwrap_or_default();
        drop(guard);
        Response::AuthorizedKeys { lines }
    }

    /// Handle a `List`: snapshot the registry.
    fn list(&self) -> Response {
        let reg = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
pub fn serve<P, L>(shared: &Arc<Shared<P, L>>, listener: &std::os::unix::net::UnixListener) -> io::Result<()>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    for conn in listener.incoming() {
        let mut conn = conn?;
        let shared = Arc::clone(shared);
        std::thread::spawn(move || handle_connection(&shared, &mut conn));
    }
    Ok(())
}

/// Read one request (and any stdio fds) from `conn` and dispatch it. `Start`
/// blocks here until the workload exits; `Stop`/`List` return at once.
fn handle_connection<P, L>(shared: &Shared<P, L>, conn: &mut UnixStream)
where
    P: Privileged + Clone,
    L: PolicyLoader,
{
    // A malformed/closed connection is just dropped.
    let Ok((request, fds)) = recv_request_with_fds(conn) else {
        return;
    };
    let response = match request {
        Request::Start(req) => return run_kennel(shared, &req, fds, conn),
        Request::Stop { kennel } => shared.stop(&kennel),
        Request::List => shared.list(),
        Request::AuthorizedKeys { key } => shared.authorized_keys(&key),
    };
    let _ = control::send_response(conn, &response);
}

/// Bring a kennel up, report it `Started`, block until the workload exits, tear
/// it down, and report `Exited`.
fn run_kennel<P, L>(shared: &Shared<P, L>, req: &StartRequest, fds: Vec<OwnedFd>, conn: &mut UnixStream)
where
    P: Privileged + Clone,
    L: PolicyLoader,
{
    let ctx = match shared.reserve(&req.kennel) {
        Ok(ctx) => ctx,
        Err(resp) => {
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
    };

    let loaded = match shared.loader.load(&req.policy, &subst) {
        Ok(loaded) => loaded,
        Err(reason) => return fail(shared, &req.kennel, ctx, conn, &Response::Error(reason)),
    };
    let mut command = match command_for(&req.argv, &req.cwd, fds) {
        Ok(command) => command,
        Err(reason) => return fail(shared, &req.kennel, ctx, conn, &Response::Error(reason)),
    };
    // Prepare SSH egress (§7.8): mint synthetic keys, register the edges with the
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
        Err(reason) => return fail(shared, &req.kennel, ctx, conn, &Response::Error(reason)),
    };
    // Prepare the AF_UNIX socket shims (§7.4): resolve each granted socket's host
    // and in-view paths. Stateless (no daemon to register with), so no teardown hook.
    let unix = shared.prepare_unix(&loaded.unix, &subst, &shim_root);

    let id = &shared.identity;
    let etc = id.etc_base.as_ref().map(|base| crate::EtcSetup {
        staging_dir: base.join(format!("etc-{ctx}")),
        hostname: req.kennel.clone(),
        uid: id.uid,
        gid: id.gid,
        // The synthetic /etc/passwd home is the in-kennel shim $HOME, not the
        // operator's real home (which would re-leak the masked identity, §7.2.x).
        home: shim_root.clone(),
    });
    let spec = crate::Spec {
        cgroup: cgroup::kennel_cgroup(&id.cgroup_base, ctx),
        ctx,
        scope: id.scope.clone(),
        plan: loaded.plan,
        net: loaded.net,
        proxy: id.proxy.clone(),
        etc,
        view_root: id.view_base.as_ref().map(|base| base.join(format!("root-{ctx}"))),
        audit_path: id.audit_base.as_ref().map(|base| base.join(&req.kennel).join("network.jsonl")),
        ssh,
        unix,
    };

    let kennel = match start(&shared.privileged, spec, &mut command) {
        Ok(kennel) => kennel,
        Err(e) => return fail(shared, &req.kennel, ctx, conn, &Response::Error(e.to_string())),
    };
    let pid = kennel.id();
    shared.set_pid(&req.kennel, pid);
    let _ = control::send_response(conn, &Response::Started { ctx, pid });

    // Block until the workload exits (on its own or via `stop`), then tear down.
    let status = kennel.stop(&shared.privileged);
    shared.deregister_ssh(&req.kennel);
    shared.release(&req.kennel, ctx);
    let _ = control::send_response(conn, &Response::Exited { code: exit_code(&status) });
}

/// Release the reservation and report an error (a bring-up step failed).
fn fail<P: Privileged + Clone, L: PolicyLoader>(
    shared: &Shared<P, L>,
    name: &str,
    ctx: u16,
    conn: &mut UnixStream,
    response: &Response,
) {
    // Drop any SSH edges registered before the failing step (a no-op otherwise), so
    // a failed bring-up leaves no synthetic key in the bastion.
    shared.deregister_ssh(name);
    shared.release(name, ctx);
    let _ = control::send_response(conn, response);
}

/// The exit code to report: the process's code, `128 + signal` if it was killed,
/// or `-1` if the wait itself failed.
fn exit_code(status: &io::Result<ExitStatus>) -> i32 {
    status.as_ref().map_or(-1, |status| {
        status.code().or_else(|| status.signal().map(|s| 128_i32.saturating_add(s))).unwrap_or(-1)
    })
}

/// Read one framed request, plus any stdio fds, from a single `recvmsg`.
fn recv_request_with_fds(conn: &UnixStream) -> io::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 128 * 1024];
    let (n, fds) = kennel_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf)?;
    let frame = buf.get(..n).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let len_bytes: [u8; 4] = frame.get(..4).and_then(|s| s.try_into().ok()).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let len = u32::from_ne_bytes(len_bytes) as usize;
    let end = len.checked_add(4).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let body = frame.get(4..end).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let request = Request::decode(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e:?}")))?;
    Ok((request, fds))
}

/// Resolve a `[unix]` socket path: fill the per-instance placeholders
/// (`<kennel>`/`<ctx>`/`<uid>`/`<home>`) and expand a leading `~`/`$HOME` against
/// `base_home` and `$XDG_RUNTIME_DIR`/`$UID` against the uid (§7.4). `base_home` is
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
        command.stdin(Stdio::from(stdin)).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr));
    }
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
                landlock_fs: vec![(PathBuf::from("/"), AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE)],
                landlock_net: Vec::new(),
                seccomp_deny: Vec::new(),
                seccomp_deny_action: Action::KillProcess,
                bpf_allow_v4: Vec::new(),
                bpf_deny_v4: Vec::new(),
                bpf_allow_v6: Vec::new(),
                bpf_deny_v6: Vec::new(),
                bpf_meta: [0u8; 64],
                file_binds: Vec::new(),
            };
            let net = NetPolicy {
                mode: kennel_policy::NetMode::Constrained,
                proxy: kennel_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
                deny_invariant: Vec::new(),
            };
            Ok(Loaded {
                plan,
                net,
                ssh: kennel_policy::SshRuntime::default(),
                unix: kennel_policy::UnixRuntime::default(),
            })
        }
    }

    fn shared() -> Shared<OkPriv, FakeLoader> {
        let base = std::env::temp_dir().join(format!("kenneld-srv-{}-{:?}", std::process::id(), std::thread::current().id()));
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
        assert!(matches!(s.stop("ghost"), Response::Error(_)), "unknown kennel errors");
        let ctx = s.reserve("p").expect("reserve");
        // pid not yet set -> still starting.
        assert!(matches!(s.stop("p"), Response::Error(_)), "still-starting kennel cannot be stopped");
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
        assert!(line.contains("--dest github.com") && line.contains("AAAASYN_A"), "got {line}");

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
        let Response::Listing(mut kennels) = s.list() else { unreachable!("listing") };
        kennels.sort_by(|x, y| x.kennel.cmp(&y.kennel));
        let summary: Vec<(&str, bool)> = kennels.iter().map(|k| (k.kennel.as_str(), k.running)).collect();
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
        assert!(matches!(started, Response::Started { ctx: 1, .. }), "got {started:?}");
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
        };
        // No fds: the workload inherits this process's stdio. /bin/true exits 0
        // immediately, so run_kennel returns after writing both responses.
        run_kennel(&s, &req, Vec::new(), &mut server);

        let mut client = client;
        let started = control::recv_response(&mut client).expect("started");
        assert!(matches!(started, Response::Started { ctx: 1, .. }), "got {started:?}");
        let exited = control::recv_response(&mut client).expect("exited");
        assert_eq!(exited, Response::Exited { code: 0 }, "true exits 0");
        // The kennel deregistered on exit.
        assert!(matches!(s.list(), Response::Listing(k) if k.is_empty()));
    }
}
