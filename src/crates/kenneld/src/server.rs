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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use kennel_lib_policy::NetPolicy;
use kennel_lib_spawn::{Plan, RuntimeSubstitutions};
use kennel_privhelper::validate::ReservedScope;

use crate::control::{self, KennelInfo, Request, Response, StartRequest};
use crate::ctx::CtxAllocator;
use crate::{cgroup, start, Privileged};

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
    pub ssh: kennel_lib_policy::SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.6): the host sockets `kenneld` binds
    /// into the kennel's view. Empty for a kennel with no `[unix]` policy.
    pub unix: kennel_lib_policy::UnixRuntime,
    /// The per-kennel binder IPC runtime (§7.1.4): the user-defined services the
    /// context manager gates against. Empty for a kennel with no `[binder]` policy.
    pub binder: kennel_lib_policy::BinderRuntime,
    /// The per-kennel D-Bus mediation runtime (§7.7): the enabled buses and their compiled
    /// allow/deny tables. Empty (no bus enabled) for a kennel with no `[dbus]` policy.
    pub dbus: kennel_lib_policy::DbusRuntime,
    /// The granted supplementary groups `(name, gid)` (§7.4): resolved and
    /// membership-checked by the loader, named in the synthetic `/etc/group`. The
    /// loader also sets `plan.supplementary_groups` to these gids (what the seal
    /// `setgroups` to). Empty when no group is granted (the kennel drops all).
    pub groups: Vec<(String, u32)>,
    /// The per-kennel audit runtime (§02-3): the sinks and per-class levels
    /// kenneld realises by constructing the `kennel-lib-audit` writer. Empty (all
    /// defaults) for a kennel with no — or an all-default — `[audit]` section.
    pub audit: kennel_lib_policy::AuditRuntime,
    /// The synthesised environment (§7.9.2): the fixed `[env].set` vars the spawn
    /// applies after clearing the inherited environment. Empty for no `[env].set`.
    pub env: kennel_lib_policy::EnvRuntime,
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
    pub lifecycle: kennel_lib_policy::LifecyclePolicy,
    /// Whether to filter dangerous terminal escapes from the workload's PTY output
    /// (`[tty].filter_terminal_escapes`, §7.9.5). The daemon conveys this decision to the
    /// attached CLI (in `Response::Started`/`Attached`), which owns the `kennel-lib-term`
    /// filter and applies it client-side (§4.8); the `PtyBroker` only carries the bool.
    pub tty_filter: bool,
    /// The live trigger-tripwire disposition (`[trust].on_change`, §2.5): what `kenneld` does
    /// when a watched trigger is mutated during the run.
    pub on_change: kennel_lib_policy::OnChangeAction,
    /// The workload the policy embeds (§7.4): `argv`/`cwd`/`pinned`/`sha256`. Empty ⇒ the
    /// command is supplied at `kennel run … -- <cmd>`. `run_kennel` merges this with the
    /// request's argv (the request wins unless `pinned`); see `effective_workload`.
    pub workload: kennel_lib_policy::WorkloadRuntime,
    /// The `[spawn]` delegated-instantiation grant (§7.12.2): the templates this kennel may
    /// instantiate, each content-pinned, plus `max_instances`. `None` for a kennel with no
    /// `[spawn]`. Drives the node-0 `SPAWN` handler; `kenneld` holds it in the per-kennel binder
    /// runtime from construction.
    pub spawn: Option<kennel_lib_policy::SpawnGrant>,
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

    /// A snapshot of the current trust-store keys, for runtime template re-verification at `SPAWN`
    /// (§7.12.8) — `kenneld` re-resolves a named template and verifies its signature against these.
    ///
    /// Best-effort: an unreadable store yields an empty set (every template signature then fails
    /// closed). The default is no keys — a loader with no trust store cannot honour a `SPAWN`.
    fn trust_keys(&self) -> kennel_lib_policy::KeySet {
        kennel_lib_policy::KeySet::new()
    }
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
    /// The host path of `facade-afunix`, bound into the constructed view and
    /// launched by the seal to broker each granted `AF_UNIX` socket through the binder
    /// facade (§7.6 / `07-1` §7.1.5). `None` disables the facade path, so `[unix]`
    /// grants go unserved (no host socket is exposed by other means).
    pub afunix_bin: Option<PathBuf>,
    /// The host path of `facade-dbus`, bound into the view and launched by the seal to terminate
    /// the workload's bus connection and frame typed transactions onto binder node 0 (§7.7.2).
    /// `None` disables the D-Bus facade path, so `[dbus]` grants go unserved.
    pub facade_dbus_bin: Option<PathBuf>,
    /// The host path of `host-dbus`, the operator-context D-Bus mediation delegate kenneld spawns
    /// per enabled bus (§7.7.2b). `None` disables mediation (no delegate, so the relay denies).
    pub host_dbus_bin: Option<PathBuf>,
    /// The host path of the trusted root-owned `kennel-bin-init` the privhelper factory
    /// `fexecve`s as the kennel's uid-0 PID 1 (`07-2`). `Some` selects the factory
    /// construction path (a real uid 0, binderfs chowned to the operator); `None` keeps
    /// the legacy in-process unprivileged spawn.
    pub init_bin: Option<PathBuf>,
    /// The host path of the workload-side OCI launcher (`kennel-bin-oci-entry`, §7.11). When an
    /// OCI-model policy (`[rootfs]`) supplies no argv, kenneld makes this `argv[0]` and binds it
    /// (with the entry's `config.json`) read-only into the view. `None` disables the
    /// image-entrypoint path (an OCI run then requires an explicit argv).
    pub oci_entry_bin: Option<PathBuf>,
    /// Spawn-path diagnostic tracer (the `log_level` knob, §`system.toml`). Tags lines
    /// `kenneld: [debug]/[trace] …`; no-ops at the default `info`. Carried here so every
    /// step of `run_kennel`/`bring_up` can trace without re-reading config.
    pub tracer: kennel_lib_config::Tracer,
}

/// How `kenneld` runs the per-user SSH bastion (§7.10). The daemon holds one
/// `kennel-sshd` for the session; this is its fixed configuration.
#[derive(Debug, Clone)]
pub struct BastionSetup {
    /// The safe-owned runtime dir for the bastion's host key, config, and
    /// `authorized_keys` (under `$XDG_RUNTIME_DIR`, never world-writable).
    pub dir: PathBuf,
    /// The in-kennel path of `facade-ssh` (each synthetic `config`
    /// stanza's `ProxyCommand`); also the host path bound into the kennel view.
    pub ssh_bin: PathBuf,
    /// The loopback address the bastion listens on.
    pub listen: IpAddr,
    /// The bastion's port.
    pub port: u16,
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
    /// The PTY broker for an interactive kennel, once the master is owned. `None` for
    /// a non-interactive run (no terminal) or before the broker is built. A clone is
    /// handed to an `Attach` so a later client reaches this running kennel's pump.
    broker: Option<crate::pty_broker::PtyBroker>,
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
    /// view rooted at `shim_root`. A no-op (empty [`crate::SshPrep`]) when the kennel has no
    /// `[ssh]` grant or this daemon runs no bastion.
    ///
    /// # Errors
    /// A human-readable reason if minting, the bastion, or materialisation fails.
    fn register_ssh(
        &self,
        kennel: &str,
        ssh: &kennel_lib_policy::SshRuntime,
        shim_root: &Path,
        policy_ssh_dir: &Path,
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
                listen: setup.listen,
                port: setup.port,
                akc: setup.akc.clone(),
            })
        });

        // The synthetic keypairs were minted at compile time and persist beside the signed
        // artefact in `<policy-dir>/ssh/`; the public half is signature-pinned in each grant.
        // Stage a copy of the private key for the kennel's `~/.ssh`, and register the edge
        // with the SIGNED public key (never a key minted here) + the host-side `options`.
        let staging = setup.dir.join("synthetic").join(kennel);
        std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
        let mut host_files: Vec<(String, String)> = Vec::new();
        for grant in &ssh.grants {
            if grant.public_key.is_empty() || grant.key_file.is_empty() {
                return Err(format!(
                    "ssh grant for `{}` has no minted key (recompile the policy with \
                     `kennel policy compile`)",
                    grant.dest
                ));
            }
            let key_file = grant.key_file.clone();
            crate::ssh::stage_synthetic_key(policy_ssh_dir, &staging, &key_file)
                .map_err(|e| e.to_string())?;
            bastion
                .register(crate::bastion::Edge {
                    kennel: kennel.to_owned(),
                    dest: grant.dest.clone(),
                    options: grant.options.clone(),
                    synthetic_pub: grant.public_key.clone(),
                })
                .map_err(|e| e.to_string())?;
            // The synthetic `~/.ssh/config` stanza is keyed by the host the workload types
            // (`ssh git@github.com` → `Host github.com`): OpenSSH matches `Host` against the
            // hostname with any `user@` stripped, so the config alias is the host part while
            // the bastion's forced command holds the full `dest`.
            host_files.push((ssh_host_alias(&grant.dest).to_owned(), key_file));
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
        let connect_bin = setup.ssh_bin.to_string_lossy().into_owned();
        let params = crate::ssh::SshParams {
            bastion_host: &listen,
            bastion_port: setup.port,
            bastion_host_key: &host_pub,
            ssh_bin: &connect_bin,
            // The bastion login user is the operator: the bastion runs the forced command
            // as them, and the kennel persona (`kennel`) is no real host account.
            bastion_user: &self.identity.username,
            hosts: &host_grants,
        };
        let ssh_dir = shim_root.join(".ssh");
        let file_binds =
            crate::ssh::materialize(&staging, &ssh_dir, &params).map_err(|e| e.to_string())?;
        Ok(crate::SshPrep {
            file_binds,
            host_service: Some(SocketAddr::new(setup.listen, setup.port)),
            ssh_bin: Some(setup.ssh_bin.clone()),
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
        unix: &kennel_lib_policy::UnixRuntime,
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
            afunix_bin: self.identity.afunix_bin.clone(),
        }
    }

    /// Prepare a kennel's D-Bus mediation (§7.7): for each enabled bus, pair the compiled
    /// allow/deny table with the operator's real bus address (what `host-dbus` connects) and the
    /// in-view socket path `facade-dbus` binds (what the workload's `DBUS_*_BUS_ADDRESS` points
    /// at). A no-op (empty [`crate::DbusPrep`]) when the kennel enables no bus.
    ///
    /// `shim_root` is the kennel's in-view `$HOME` (a writable tmpfs); the in-view bus sockets live
    /// under it, so the facade can `bind(2)` them and the workload can connect.
    fn prepare_dbus(
        &self,
        dbus: &kennel_lib_policy::DbusRuntime,
        shim_root: &Path,
    ) -> crate::DbusPrep {
        // The in-view directory facade-dbus binds its per-bus sockets in (it create_dir_all's it).
        let listen_dir = shim_root.join(".kennel-dbus");
        let bus_prep = |rules: &kennel_lib_policy::DbusBusRuntime, address: String, leaf: &str| {
            crate::DbusBusPrep {
                rules: rules.clone(),
                bus_address: address,
                listen_path: listen_dir.join(leaf),
            }
        };
        crate::DbusPrep {
            session: dbus
                .session
                .as_ref()
                .map(|r| bus_prep(r, self.session_bus_address(), "session")),
            system: dbus
                .system
                .as_ref()
                .map(|r| bus_prep(r, system_bus_address(), "system")),
            facade_bin: self.identity.facade_dbus_bin.clone(),
            host_bin: self.identity.host_dbus_bin.clone(),
            cmd_dir: crate::socket::runtime_dir().join("dbus"),
        }
    }

    /// The operator's real session-bus address `host-dbus` connects to: the daemon's own
    /// `DBUS_SESSION_BUS_ADDRESS`, else the well-known per-user socket.
    fn session_bus_address(&self) -> String {
        std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .unwrap_or_else(|_| format!("unix:path=/run/user/{}/bus", self.identity.uid))
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
        reg.kennels.insert(
            name.to_owned(),
            KennelMeta {
                ctx,
                pid: None,
                broker: None,
            },
        );
        drop(reg);
        Ok(ctx)
    }

    /// Record the interactive kennel's PTY broker once kenneld owns the master, so a
    /// later `Attach` can reach this running kennel's pump.
    fn set_broker(&self, name: &str, broker: crate::pty_broker::PtyBroker) {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(meta) = reg.kennels.get_mut(name) {
            meta.broker = Some(broker);
        }
    }

    /// A clone of the named kennel's PTY broker, or `None` if the kennel is unknown,
    /// not interactive, or not yet started.
    fn broker_for(&self, name: &str) -> Option<crate::pty_broker::PtyBroker> {
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels.get(name).and_then(|m| m.broker.clone())
    }

    /// The `(ctx, pid)` of a started kennel, or `None` if unknown or still starting.
    fn ctx_pid(&self, name: &str) -> Option<(u16, u32)> {
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels
            .get(name)
            .and_then(|m| m.pid.map(|pid| (m.ctx, pid)))
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
                attached: meta
                    .broker
                    .as_ref()
                    .is_some_and(crate::pty_broker::PtyBroker::is_attached),
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
        match kennel_lib_syscall::scm::peer_uid(conn.as_fd()) {
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
fn handle_connection<P, L>(shared: &Arc<Shared<P, L>>, conn: &mut UnixStream)
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    // A malformed/closed connection is just dropped.
    let Ok((request, fds)) = recv_request_with_fds(conn) else {
        return;
    };
    // The dynamic-spawn construction handle (§7.12): a SPAWN handler hands a validated instance here
    // to be built off the binder looper. Holds an `Arc<Shared>` so the build runs the same path as a
    // CLI `kennel run`. Non-generic (`Arc<dyn ..>`) so it can ride into the binder layer.
    let constructor: Arc<dyn crate::spawn::SpawnConstructor> = Arc::new(Constructor {
        shared: Arc::clone(shared),
    });
    dispatch_request(shared, request, fds, conn, &constructor);
}

/// The daemon-side [`crate::spawn::SpawnConstructor`]: builds a validated spawn instance by driving
/// the same [`run_kennel`] path a CLI run does, on a fresh thread (async to the `SPAWN` reply).
struct Constructor<P: Privileged, L: PolicyLoader> {
    shared: Arc<Shared<P, L>>,
}

impl<P, L> crate::spawn::SpawnConstructor for Constructor<P, L>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    fn enqueue(
        &self,
        instance: kennel_lib_policy::SettledPolicy,
        stdio: [OwnedFd; 3],
        name: String,
        slot: crate::spawn::SlotGuard,
    ) {
        let shared = Arc::clone(&self.shared);
        std::thread::spawn(move || {
            // Hold the max_instances slot for the spawned kennel's whole life: run_kennel blocks
            // until the workload exits (then tears down), so `slot` releases on that exit or on any
            // early construction failure (§7.12.7).
            let _slot = slot;
            // The spawn has no operator on a control socket, so run_kennel's status responses go to a
            // throwaway socketpair whose peer we hold for the build's life — written-but-unread, never
            // EPIPE. A non-interactive run: the three stdio fds are the spawned ends of the channel.
            let Ok((mut sink, _peer)) = UnixStream::pair() else {
                eprintln!("kenneld: spawn `{name}`: could not make a construction sink");
                return;
            };
            let req = StartRequest {
                policy: PathBuf::new(),
                kennel: name,
                argv: Vec::new(),
                cwd: PathBuf::from("/"),
                term: String::new(),
                interactive: false,
                force: false,
                watch_paths: Vec::new(),
                oci_config: None,
            };
            // A spawn target is depth-1 (no `[spawn]` of its own), so its own construction never
            // spawns — a no-op constructor suffices for the nested run.
            run_kennel(
                &shared,
                &req,
                Vec::from(stdio),
                &mut sink,
                Some(instance),
                &crate::spawn::noop_constructor(),
            );
        });
    }
}

/// Validate and dispatch one decoded control request on `conn` (with its passed `fds`).
///
/// The body of `handle_connection` after decode — split out so the e2e tests can drive
/// the *real* dispatch (e.g. `Attach`) without a shim that could diverge from production.
///
/// Trust boundary 6 (§04 trust boundaries): the kennel name arrives from the user's CLI
/// over the control socket and flows into filesystem paths (the synthetic `/etc` staging
/// dir, the per-kennel audit dir), the synthetic `/etc/hostname`, and the registry key.
/// Validate its grammar — `[a-z0-9]` start, then `[a-z0-9-]`, ≤64 chars — *before* it is
/// used anywhere, so a name with `/`, `..`, NUL, whitespace, or control bytes cannot
/// traverse a path or inject a hostname. `List`/`AuthorizedKeys` carry no name.
pub fn dispatch_request<P, L>(
    shared: &Shared<P, L>,
    request: Request,
    fds: Vec<OwnedFd>,
    conn: &mut UnixStream,
    constructor: &Arc<dyn crate::spawn::SpawnConstructor>,
) where
    P: Privileged + Clone + Sync,
    L: PolicyLoader,
{
    let response = match request {
        Request::Start(req) => match validate_kennel_name(&req.kennel) {
            Ok(()) => return run_kennel(shared, &req, fds, conn, None, constructor),
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
        // Attach a terminal to a running kennel's PTY. Like `Start`, this owns its
        // connection for the session (the CLI proxies its terminal until detach or
        // workload exit), so it returns rather than falling through to the single
        // response below.
        Request::Attach { kennel } => match validate_kennel_name(&kennel) {
            Ok(()) => return run_attach(shared, &kennel, fds, conn),
            Err(e) => Response::Error(e),
        },
        // Resize the kennel's pty (the broker holds the master). Fire-and-forget: a
        // `SIGWINCH` relay sends this on a throwaway connection; there is no reply, so
        // it falls through to the single send below only on a bad name.
        Request::Resize { kennel, rows, cols } => match validate_kennel_name(&kennel) {
            Ok(()) => {
                if let Some(broker) = shared.broker_for(&kennel) {
                    broker.resize(rows, cols);
                }
                return;
            }
            Err(e) => Response::Error(e),
        },
        // A `PromptReply` is only meaningful mid-run, read by the `PromptPort` on the
        // already-running connection (§9.7) — never a fresh request to the dispatcher. An
        // unsolicited one is a protocol error.
        Request::PromptReply { .. } => Response::Error("unexpected PromptReply".to_owned()),
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
/// The hostname part of an SSH destination — the `user@` prefix stripped. This is the
/// alias the synthetic `~/.ssh/config` keys its `Host` stanza on, because OpenSSH matches
/// `Host` against the hostname with any user removed (`ssh git@github.com` → `github.com`).
fn ssh_host_alias(dest: &str) -> &str {
    dest.rsplit_once('@').map_or(dest, |(_, host)| host)
}

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
/// point the self-hosting e2e drives directly (real privhelper + a real [`crate::policy::TrustStoreLoader`]),
/// so the test exercises the same wiring production does, not a hand-built replica.
// allow: one linear request lifecycle (reserve, load, ssh/unix/audit prep, spawn,
// block, tear down); splitting it would scatter the shared `ctx`/`state_dir`/uuid.
#[allow(clippy::too_many_lines)]
pub fn run_kennel<P, L>(
    shared: &Shared<P, L>,
    req: &StartRequest,
    fds: Vec<OwnedFd>,
    conn: &mut UnixStream,
    preloaded: Option<kennel_lib_policy::SettledPolicy>,
    constructor: &Arc<dyn crate::spawn::SpawnConstructor>,
) where
    P: Privileged + Clone + Sync,
    L: PolicyLoader,
{
    let tr = shared.identity.tracer;
    tr.step(&format!("run_kennel: starting `{}`", req.kennel));
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
    tr.step(&format!(
        "run_kennel: reserved ctx {ctx} for `{}`",
        req.kennel
    ));

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

    // A dynamic-spawn instance arrives pre-built in memory (patched, never signed — §7.12.6); a
    // normal run loads and verifies the signed policy from disk. Either way `subst` is now applied.
    let mut loaded = if let Some(instance) = preloaded {
        match crate::policy::loaded_from_settled(&instance, &subst) {
            Ok(loaded) => loaded,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "spawn instance", reason),
        }
    } else {
        tr.step(&format!(
            "run_kennel: loading policy {}",
            req.policy.display()
        ));
        match shared.loader.load(&req.policy, &subst) {
            Ok(loaded) => loaded,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "load policy", reason),
        }
    };
    if tr.on() {
        tr.step(&format!(
            "run_kennel: policy loaded — net.mode={:?}, account={}, ssh grants={}, unix sockets={}",
            loaded.net.mode,
            loaded.account,
            loaded.ssh.grants.len(),
            loaded.unix.sockets.len()
        ));
    }
    // OCI substrate (§7.11): an `[rootfs]` policy is ALWAYS launcher-driven — `[rootfs]` and
    // `[workload]` are mutually exclusive, so the image entrypoint runs via the workload-side
    // launcher (`kennel-bin-oci-entry`). kenneld makes it argv[0] (config.json as argv[1]) and
    // binds both into the view; any `kennel oci run … -- <cmd>` tokens follow as a Cmd override
    // the launcher applies (keeping the image Entrypoint + Env), no policy impact.
    let oci_image = loaded.plan.view.as_ref().is_some_and(|v| v.image.is_some());
    let mut oci_prep = crate::OciPrep::default();
    // Merge the request argv/cwd with the policy's embedded [workload] (§7.4). The merge
    // is the DAEMON's job — the request reaches it before the signed policy is loaded, so
    // only here is the policy's workload known. The request wins unless the policy pins it.
    let (argv, cwd) = if oci_image {
        let Some(launcher) = shared.identity.oci_entry_bin.clone() else {
            return fail(
                shared,
                &req.kennel,
                ctx,
                conn,
                "oci launcher",
                "policy declares [rootfs] but no OCI launcher (kennel-bin-oci-entry) is configured"
                    .to_owned(),
            );
        };
        if req.oci_config.is_none() {
            return fail(
                shared,
                &req.kennel,
                ctx,
                conn,
                "oci launcher",
                "OCI run reached the daemon without a config.json path (use `kennel oci run`)"
                    .to_owned(),
            );
        }
        let mut argv = vec![
            launcher.to_string_lossy().into_owned(),
            crate::OCI_CONFIG_VIEW_PATH.to_owned(),
        ];
        // The `-- <cmd>` override tokens (if any), passed through as the launcher's Cmd override.
        argv.extend(req.argv.iter().cloned());
        oci_prep = crate::OciPrep {
            launcher_bin: Some(launcher),
            config_src: req.oci_config.clone(),
        };
        // The launcher chdirs to the image's WorkingDir itself; give it the request cwd as the
        // fallback the kernel starts it in.
        (argv, req.cwd.clone())
    } else {
        match effective_workload(req, &loaded.workload) {
            Ok(pair) => pair,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "workload", reason),
        }
    };
    tr.detail(&format!(
        "run_kennel: effective workload argv={argv:?} cwd={}",
        cwd.display()
    ));
    // Persist-mode rootfs (§7.11.4a): the managed overlay upper lives under the store entry
    // (the `config.json`'s dir). Create `upper/` + `work/` and fill them into the plan so the
    // construction child mounts the overlay with a persisted upper. The store fs must carry
    // `user.*` xattrs for the userxattr whiteouts — if it does not, the overlay mount in the
    // construction child fails with a clear error (the refusal the spec calls for).
    if oci_image {
        if let Some(img) = loaded
            .plan
            .view
            .as_mut()
            .and_then(|v| v.image.as_mut())
            .filter(|i| i.persistence == kennel_lib_spawn::Persistence::Persist)
        {
            let Some(entry) = req.oci_config.as_deref().and_then(std::path::Path::parent) else {
                return fail(
                    shared,
                    &req.kennel,
                    ctx,
                    conn,
                    "oci persist",
                    "persistence = persist needs the store entry path (config.json)".to_owned(),
                );
            };
            let upper = entry.join("upper");
            let work = entry.join("work");
            if let Err(e) =
                std::fs::create_dir_all(&upper).and_then(|()| std::fs::create_dir_all(&work))
            {
                return fail(
                    shared,
                    &req.kennel,
                    ctx,
                    conn,
                    "oci persist",
                    format!(
                        "creating the managed overlay upper under {}: {e}",
                        entry.display()
                    ),
                );
            }
            img.store_upper = Some((upper, work));
        }
    }
    // Verify the workload binary against the policy's sha256 pin (§7.4) — a KENNELD
    // decision made here, on the host, before the kennel is built: kennel-bin-init is a
    // dumb executor and gets no say. Applies only when the policy embedded a pin AND we
    // are running the policy's own workload (an unpinned `--` override is a different
    // command the pin does not cover). On success it returns the OPEN fd of the verified
    // binary, which we pin into the plan: the factory places it at WORKLOAD_FD and init
    // `fexecve`s it (no path relookup → TOCTOU-free). `_workload_fd` must outlive the
    // construction, so it stays in scope until the end of bring-up.
    // Held only to keep the fd open (its raw value is what's used, via the plan); never read.
    #[allow(clippy::collection_is_never_read)]
    let _workload_fd;
    if !loaded.workload.sha256.is_empty() && req.argv.is_empty() {
        match verify_workload_digest(argv.first(), &loaded.exec_path, &loaded.workload.sha256) {
            Ok(fd) => {
                loaded.plan.workload_fd = Some(std::os::fd::AsRawFd::as_raw_fd(&fd));
                _workload_fd = Some(fd);
            }
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "workload sha256", reason),
        }
    } else {
        _workload_fd = None;
    }
    // Interactive runs pass ONE connected socket — the CLI's proxied-terminal end
    // (`client_sock`). KENNELD owns the workload's pty master now (not the CLI): we
    // mint our OWN socketpair, hand the seal its `master_send` end (over which the
    // seal returns the master during pre-exec), and keep `master_recv`. The master
    // then lands in kenneld's PtyBroker, which fans filtered output to whichever
    // client is attached and survives the client detaching (§05). Non-interactive
    // runs pass the three stdio fds, unchanged. `master_send` must outlive the spawn
    // so the forked child inherits it during the pre-exec seal.
    let mut return_sock: Option<OwnedFd> = None;
    let mut client_sock: Option<OwnedFd> = None;
    let mut master_recv: Option<OwnedFd> = None;
    let mut command = if req.interactive {
        client_sock = fds.into_iter().next();
        match UnixStream::pair() {
            Ok((recv, send)) => {
                master_recv = Some(OwnedFd::from(recv));
                return_sock = Some(OwnedFd::from(send));
            }
            Err(e) => {
                return fail(
                    shared,
                    &req.kennel,
                    ctx,
                    conn,
                    "pty master socketpair",
                    e.to_string(),
                )
            }
        }
        match command_for_interactive(&argv, &cwd) {
            Ok(command) => command,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "prepare command", reason),
        }
    } else {
        match command_for(&argv, &cwd, fds) {
            Ok(command) => command,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "prepare command", reason),
        }
    };
    // Prepare SSH egress (§7.10): stage the compile-time synthetic keys, register the
    // edges with the per-user bastion, and build the synthetic ~/.ssh for the view. The
    // ~/.ssh is rooted at the constructed-view HOME (the plan's shim root) when there is
    // one; the persisted keypairs live in `<policy-dir>/ssh/` beside the settled artefact.
    let shim_root = loaded
        .plan
        .view
        .as_ref()
        .map_or_else(|| shared.identity.home.clone(), |v| v.shim_root.clone());
    let policy_ssh_dir = req
        .policy
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("ssh");
    if !loaded.ssh.grants.is_empty() {
        tr.step(&format!(
            "run_kennel: registering {} SSH grant(s) with the bastion",
            loaded.ssh.grants.len()
        ));
    }
    let ssh = match shared.register_ssh(&req.kennel, &loaded.ssh, &shim_root, &policy_ssh_dir) {
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
    // Prepare D-Bus mediation (§7.7): pair each enabled bus's compiled table with the real bus
    // address and the in-view socket the facade presents. Stateless, like the unix shims.
    let dbus = shared.prepare_dbus(&loaded.dbus, &shim_root);
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
        let shims_gpg_agent = sock.name.eq_ignore_ascii_case("gpg-agent")
            || sock.env.as_deref() == Some("GPG_AGENT_INFO");
        if shims_gpg_agent {
            eprintln!(
                "kenneld: warning: kennel `{}` shims a GPG agent (`{}`): an exposed agent is a \
                 destination-blind signing oracle — worse than ssh-agent, a signature stamps your \
                 identity onto whatever the kennel signs (malware, releases, forged commits). There \
                 is no bastion equivalent (design §11.1); the safe default is to sign on the host.",
                req.kennel, sock.name
            );
        }
    }
    // The audit runtime (§02-3): the installation/per-user `audit.toml` defaults
    // (§8.1) overlaid by the per-kennel policy `[audit]` (built-in < /etc/kennel <
    // ~/.config < policy). Captured before `loaded` is consumed below.
    let audit_runtime = crate::audit::load_audit_defaults().overlay(&loaded.audit);
    // The PTY escape-filter decision (§7.9.5), captured before `loaded` is consumed.
    let loaded_tty_filter = loaded.tty_filter;
    // The live trigger-tripwire disposition (§2.5), captured before `loaded` is consumed.
    let on_change = loaded.on_change;
    // The host sources of the exclusive binds (§2.7), captured before the plan moves into the
    // spec: released (unmounted) at teardown so the operator's path is not left shadowed.
    let exclusive_sources: Vec<PathBuf> = loaded.plan.view.as_ref().map_or_else(Vec::new, |v| {
        v.binds
            .iter()
            .filter(|b| b.exclusive)
            .map(|b| b.source.clone())
            .collect()
    });
    // One `kennel_uuid` for this run, shared by kenneld's lifecycle writer and the
    // egress proxy's writer so their events correlate. The per-kennel state dir is
    // where both `lifecycle.jsonl` (kenneld) and `network.jsonl` (proxy) land.
    let kennel_uuid = crate::audit::kennel_uuid();
    let state_dir = shared
        .identity
        .audit_base
        .as_ref()
        .map(|base| base.join(&req.kennel));
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
    // TTL is enforced inside the kennel now (§9.7): `kennel-bin-init` runs the timer and, at
    // expiry, makes the blocking `NOTIFY_TTL_EXPIRED` call that the node-0 handler services
    // (freeze + decide). The ttl_seconds + ttl_action ride the Plan (→ supervision-half /
    // binder Lifecycle), so kenneld no longer polls from out here.
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
        ssh,
        unix,
        dbus,
        binder: None,
        oci: oci_prep,
        tracer: tr,
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
    // universal control plane (`kennel-bin-init` pulls its supervision-half over node 0), not an
    // opt-in for [binder]/[unix] kennels (`07-1`/`07-2`). So always wire the daemon-side
    // context manager — it takes node 0, serves the lifecycle pull, and answers any facade.
    // The registry's policy/facade sets are simply empty for a kennel that grants no IPC.
    {
        // The facade connects to the real host socket, so resolve each `real` path's
        // `~`/`$XDG_RUNTIME_DIR`/placeholders against the daemon's own home now (the
        // shim path the proxy listens at was already resolved in `prepare_unix`).
        let facade_unix = kennel_lib_policy::UnixRuntime {
            sockets: loaded
                .unix
                .sockets
                .iter()
                .map(|s| kennel_lib_policy::UnixSocket {
                    real: resolve_path(&s.real, &subst, &shared.identity.home)
                        .to_string_lossy()
                        .into_owned(),
                    ..s.clone()
                })
                .collect(),
        };
        // The registry records every decision (§7.1.4). With no audit state dir, a sink-less
        // writer keeps the bus running without recording.
        let writer = audit.clone().unwrap_or_else(|| {
            Arc::new(crate::audit::noop_writer(&req.kennel, kennel_uuid.clone()))
        });
        // The operator-prompt channel for the TTL `renew` action (§9.7): a clone of this
        // control connection. Installed only for an interactive run — a non-interactive caller
        // has no terminal to surface the prompt on, so `renew` there falls back to a warn.
        let prompt = if req.interactive {
            crate::prompt::from_conn(&*conn).ok()
        } else {
            None
        };
        // The [spawn] runtime (§7.12): pair the grant with a trust-key snapshot (to verify a
        // re-resolved template against) and the template cascade kenneld resolves `name@version`
        // from. Built only for a kennel that carries a grant; a SPAWN from any other is denied.
        let spawn = loaded.spawn.map(|grant| {
            std::sync::Arc::new(crate::spawn::SpawnRuntime::new(
                grant,
                shared.loader.trust_keys(),
                kennel_lib_config::User::load()
                    .unwrap_or_default()
                    .template_dirs(),
                std::sync::Arc::clone(constructor),
            ))
        });
        spec.binder = Some(crate::BinderPrep {
            policy: loaded.binder,
            unix: facade_unix,
            writer,
            init_bin: shared.identity.init_bin.clone(),
            prompt,
            spawn,
        });
    }

    // Synthesise the workload environment from policy (§7.9.2): clear the inherited
    // environment and build it from scratch. `PATH` (from `[exec].path`),
    // `USER`/`LOGNAME` (the masked account), `SHELL` (`[exec].shell`), and `HOME`
    // (the kennel's shim home) are synthesised; `[env].set` is layered on top. The
    // parent's environment is never a source — a secret policy did not name cannot
    // reach the workload. (`bring_up` adds the workload's proxy env and any unix-shim
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

    tr.step("run_kennel: bring-up — building view, egress, factory construct, boot-sync");
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
    tr.step(&format!("run_kennel: workload running, pid={pid}"));
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
    // For an interactive kennel, kenneld now owns the master: receive it from the
    // seal over `master_recv`, build the PtyBroker (running the workload's output
    // through the [tty] escape filter), register it so a later `kennel attach` reaches
    // this running kennel, and make the `Start` connection's passed socket the first
    // attached client. The broker outlives this connection — detaching the client does
    // not end the workload. `broker` (a registry clone) is shut down on workload exit.
    let broker = if req.interactive {
        master_recv
            .as_ref()
            .and_then(|sock| recv_pty_master(sock).ok())
            .map_or_else(
                || {
                    tr.step(
                        "run_kennel: interactive kennel returned no pty master (filter inactive)",
                    );
                    None
                },
                |master| {
                    // The broker is a raw-byte router; it carries the [tty] filter
                    // decision for the client (which owns the filter, §4.8) but does not
                    // apply it.
                    let b = crate::pty_broker::PtyBroker::start(
                        master,
                        loaded_tty_filter,
                        client_sock.take(),
                    );
                    shared.set_broker(&req.kennel, b.clone());
                    Some(b)
                },
            )
    } else {
        None
    };
    // Convey the [tty] escape-filter decision so the attached CLI filters client-side
    // (§4.8). False for a non-interactive launch — it has no proxied terminal.
    let _ = control::send_response(
        conn,
        &Response::Started {
            ctx,
            pid,
            filter_escapes: req.interactive && loaded_tty_filter,
        },
    );

    // Start the live trigger tripwire (§2.5, T2.8): watch the CLI-resolved trigger paths under
    // the writable binds and apply `[trust].on_change` on a mutation. Best-effort — `None` when
    // there is nothing to watch (no triggers / `[trust].manifest = false` ⇒ empty `watch_paths`)
    // or inotify is unavailable; the teardown `kennel review` is the authoritative backstop.
    let tripwire = {
        let writer = audit.clone().unwrap_or_else(|| {
            Arc::new(crate::audit::noop_writer(&req.kennel, kennel_uuid.clone()))
        });
        crate::tripwire::Tripwire::start(
            &req.watch_paths,
            on_change,
            cgroup::kennel_cgroup(&shared.identity.cgroup_base, ctx),
            writer,
        )
    };

    // Block until the kennel exits, then tear down. TTL is enforced inside the kennel (§9.7):
    // `kennel-bin-init`'s timer makes the blocking `NOTIFY_TTL_EXPIRED` call, which the node-0
    // handler services (freeze + decide; the `ttl-warn`/`ttl-terminate` audit events come from
    // there). So this is a plain wait — on `exit` the handler kills the frozen cgroup, and this
    // wait returns the resulting status. The audited privileged records the teardown too.
    let status = kennel.stop(&audited);
    // The workload exited: stop the tripwire watcher thread (best-effort join).
    if let Some(tripwire) = tripwire {
        tripwire.stop();
    }
    // Release each exclusive over-mount (§2.7) so the operator's path is no longer shadowed —
    // the teardown counterpart to the factory's mount. Best-effort + logged: a failure leaves a
    // leaked lock that `kennel release` / a daemon-restart sweep clears.
    for src in &exclusive_sources {
        if let Err(e) = shared.privileged.release_exclusive(src) {
            eprintln!(
                "kenneld: warning: could not release exclusive over-mount {}: {e} \
                 (run `kennel release {}` to clear it)",
                src.display(),
                req.kennel
            );
        }
    }
    // The workload exited: stop the PTY pump and drop any attached client (its CLI
    // then sees EOF and exits). The broker is also dropped from the registry below.
    if let Some(broker) = &broker {
        broker.shutdown();
    }
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

/// Handle a `kennel attach`: hand the connection's terminal socket to the running
/// kennel's PTY broker (taking over any current client) and block until this client's
/// session ends — `Exited` if the workload exits, `Detached` if a later attach takes
/// over. No workload lifecycle here: the broker (and the kennel's own `run_kennel`
/// thread) own that; attach is a pure subscriber.
fn run_attach<P, L>(shared: &Shared<P, L>, kennel: &str, fds: Vec<OwnedFd>, conn: &mut UnixStream)
where
    P: Privileged + Clone + Sync,
    L: PolicyLoader,
{
    let Some(broker) = shared.broker_for(kennel) else {
        let _ = control::send_response(
            conn,
            &Response::Error(format!(
                "kennel `{kennel}` is not attachable (unknown, not interactive, or still starting)"
            )),
        );
        return;
    };
    let Some(client_sock) = fds.into_iter().next() else {
        let _ = control::send_response(
            conn,
            &Response::Error("attach passed no terminal socket".to_owned()),
        );
        return;
    };
    let Some((ctx, pid)) = shared.ctx_pid(kennel) else {
        let _ = control::send_response(
            conn,
            &Response::Error(format!("no kennel named `{kennel}`")),
        );
        return;
    };
    let Some(generation) = broker.attach(client_sock) else {
        let _ = control::send_response(
            conn,
            &Response::Error(format!("kennel `{kennel}` has already exited")),
        );
        return;
    };
    let _ = control::send_response(
        conn,
        &Response::Attached {
            ctx,
            pid,
            filter_escapes: broker.filter_escapes(),
        },
    );
    // Block until this client's session ends; report why.
    let response = match broker.wait_for_outcome(generation) {
        crate::pty_broker::AttachOutcome::WorkloadExited => Response::Exited { code: 0 },
        crate::pty_broker::AttachOutcome::TakenOver => Response::Detached {
            reason: "another client attached".to_owned(),
        },
    };
    let _ = control::send_response(conn, &response);
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

/// The exit code to report: the kennel's exit code (`128 + signal` if it was killed, as
/// [`kennel_lib_syscall::process::wait_pid`] already encodes), or `-1` if the wait itself failed.
fn exit_code(status: &io::Result<i32>) -> i32 {
    *status.as_ref().unwrap_or(&-1)
}

/// Read one framed request, plus any stdio fds, from a single `recvmsg`.
fn recv_request_with_fds(conn: &UnixStream) -> io::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 128 * 1024];
    let (n, fds) = kennel_lib_syscall::scm::recv_with_fds(conn.as_fd(), &mut buf)?;
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

/// Receive the workload's controlling-pty master, sent by the spawn seal over `sock`
/// as a single `SCM_RIGHTS` fd (with a one-byte payload). kenneld keeps this master
/// in the `PtyBroker` (the CLI no longer holds it).
fn recv_pty_master(sock: &OwnedFd) -> io::Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let (_, mut fds) = kennel_lib_syscall::scm::recv_with_fds(sock.as_fd(), &mut buf)?;
    fds.pop().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the seal returned no controlling terminal",
        )
    })
}

/// Resolve a `[unix]` socket path: fill the per-instance placeholders
/// (`<kennel>`/`<ctx>`/`<uid>`/`<home>`) and expand a leading `~`/`$HOME` against
/// `base_home` and `$XDG_RUNTIME_DIR`/`$UID` against the uid (§7.6). `base_home` is
/// the real home for a `real` path, the in-view shim root for a `shim` path.
/// The operator's real system-bus address `host-dbus` connects to: `DBUS_SYSTEM_BUS_ADDRESS`, else
/// the well-known path. (Free function: the system bus address is uid-independent.)
fn system_bus_address() -> String {
    std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
        .unwrap_or_else(|_| "unix:path=/run/dbus/system_bus_socket".to_owned())
}

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

/// Resolve the effective workload argv + cwd from the request and the policy's embedded
/// `[workload]` (§7.4). The request's `--` argv overrides the policy's by default; a
/// `pinned` policy refuses the override unless `req.force`. With no request argv the
/// policy's argv (and its `cwd`, if any) drive the run.
///
/// # Errors
///
/// A human-readable reason when neither the request nor the policy supplies an argv, or
/// when a non-empty request argv would override a pinned policy workload without `--force`.
fn effective_workload(
    req: &StartRequest,
    workload: &kennel_lib_policy::WorkloadRuntime,
) -> Result<(Vec<String>, PathBuf), String> {
    if req.argv.is_empty() {
        // Policy-driven: use the embedded workload, and its cwd if it set one.
        if workload.argv.is_empty() {
            return Err(
                "no workload: the policy has no [workload] and no command was given \
                 (kennel run … -- <cmd>)"
                    .to_owned(),
            );
        }
        let cwd = workload
            .cwd
            .as_deref()
            .map_or_else(|| req.cwd.clone(), PathBuf::from);
        return Ok((workload.argv.clone(), cwd));
    }
    // Request-supplied argv: overrides the policy workload unless it is pinned.
    if workload.pinned && !req.force {
        return Err(format!(
            "policy [workload] is pinned to `{}`; refusing the `-- {}` override \
             (pass --force to override)",
            workload.argv.join(" "),
            req.argv.join(" ")
        ));
    }
    Ok((req.argv.clone(), req.cwd.clone()))
}

/// Verify the workload binary's SHA-256 against the policy's accepted-digest set, returning
/// the **open fd** of the verified binary for the fd-pin (§7.4).
///
/// TOCTOU-free: the binary is `open`ed ONCE here; the digest is computed over
/// `/proc/self/fd/<fd>` (the very inode now held open), and that same fd is handed to
/// `kennel-bin-init` to `fexecve` — so the bytes hashed are the bytes that run, with no path
/// relookup in between. A writer that swaps the on-disk path afterwards cannot affect the
/// pinned fd.
///
/// A **kenneld** decision (the dumb-executor init gets none): resolve `program` against the
/// policy's `exec_path` on the host, open it, hash it with the system `sha256sum` over the fd
/// (the trusted hasher — no in-process crypto dependency in the privileged path), and accept
/// only if the digest is in `accepted`. Fail closed: an unresolvable program, an open/hash
/// failure, or a non-matching digest all refuse the spawn.
///
/// # Errors
///
/// A human-readable reason on resolution, open, hashing, or digest-mismatch failure.
fn verify_workload_digest(
    program: Option<&String>,
    exec_path: &[String],
    accepted: &[String],
) -> Result<OwnedFd, String> {
    use std::os::fd::AsRawFd as _;
    let program = program.ok_or("workload sha256 pin set but the workload argv is empty")?;
    // Resolve a bare name against the policy PATH (host side); an explicit path is used as-is.
    let resolved = if program.contains('/') {
        PathBuf::from(program)
    } else {
        exec_path
            .iter()
            .map(|d| Path::new(d).join(program))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                format!("workload `{program}` not found on the policy PATH to hash it")
            })?
    };
    // Open the binary ONCE; everything downstream keys on this fd (hash + fexecve).
    let file = std::fs::File::open(&resolved)
        .map_err(|e| format!("opening workload {} to pin it: {e}", resolved.display()))?;
    // Hash the fd itself via /proc/<pid>/fd, so the digest is over the open inode, not a path
    // that could be re-looked-up to different bytes. The pid is THIS process's (not
    // `/proc/self`, which in the spawned sha256sum would be the child's own fd table).
    let fd_path = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    let out = Command::new("sha256sum")
        .arg("-b")
        .arg(&fd_path)
        .output()
        .map_err(|e| format!("running sha256sum on the workload fd: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sha256sum failed on workload {}: {}",
            resolved.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // `sha256sum` prints `<hex>  <path>` (or `<hex> *<path>` with -b); take the first field.
    let digest = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if accepted.iter().any(|a| a == &digest) {
        Ok(OwnedFd::from(file))
    } else {
        Err(format!(
            "workload {} sha256 {digest} is not in the policy's accepted set",
            resolved.display()
        ))
    }
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

    use kennel_lib_syscall::landlock::AccessFs;
    use kennel_lib_syscall::namespace::Namespaces;
    use kennel_lib_syscall::seccomp::Action;
    use kennel_privhelper::wire::Response as HelperResponse;

    fn start_req(argv: &[&str], force: bool) -> StartRequest {
        StartRequest {
            policy: PathBuf::from("/x"),
            kennel: "k".to_owned(),
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: PathBuf::from("/cli/cwd"),
            term: String::new(),
            interactive: false,
            force,
            watch_paths: Vec::new(),
            oci_config: None,
        }
    }

    fn workload(
        argv: &[&str],
        cwd: Option<&str>,
        pinned: bool,
    ) -> kennel_lib_policy::WorkloadRuntime {
        kennel_lib_policy::WorkloadRuntime {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: cwd.map(str::to_owned),
            pinned,
            sha256: Vec::new(),
        }
    }

    #[test]
    fn effective_workload_uses_policy_when_no_cli_argv() {
        let (argv, cwd) = effective_workload(
            &start_req(&[], false),
            &workload(&["run.sh", "--all"], Some("/suite"), false),
        )
        .expect("policy workload");
        assert_eq!(argv, vec!["run.sh", "--all"]);
        assert_eq!(cwd, PathBuf::from("/suite")); // the policy cwd, not the CLI cwd
    }

    #[test]
    fn effective_workload_cli_overrides_unpinned_policy() {
        let (argv, cwd) = effective_workload(
            &start_req(&["bash"], false),
            &workload(&["run.sh"], Some("/suite"), false),
        )
        .expect("override");
        assert_eq!(argv, vec!["bash"]);
        assert_eq!(cwd, PathBuf::from("/cli/cwd")); // the CLI cwd on override
    }

    #[test]
    fn effective_workload_pinned_refuses_override_without_force() {
        let err = effective_workload(
            &start_req(&["bash"], false),
            &workload(&["run.sh"], None, true),
        )
        .expect_err("pinned refuses");
        assert!(err.contains("pinned"), "{err}");
    }

    #[test]
    fn effective_workload_pinned_override_with_force() {
        let (argv, _) = effective_workload(
            &start_req(&["bash"], true),
            &workload(&["run.sh"], None, true),
        )
        .expect("force overrides pin");
        assert_eq!(argv, vec!["bash"]);
    }

    #[test]
    fn effective_workload_errors_when_neither_supplies_argv() {
        let err = effective_workload(&start_req(&[], false), &workload(&[], None, false))
            .expect_err("no workload");
        assert!(err.contains("no workload"), "{err}");
    }

    #[test]
    fn verify_workload_digest_accepts_matching_and_rejects_otherwise() {
        // Hash a real temp file with the host sha256sum (the same tool the check uses), so
        // the expected digest is whatever this host produces — no hard-coded constant.
        let dir = std::env::temp_dir().join(format!("kennel-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bin = dir.join("workload");
        std::fs::write(&bin, b"#!/bin/sh\necho hi\n").expect("write");
        let out = Command::new("sha256sum")
            .arg("-b")
            .arg(&bin)
            .output()
            .expect("sha256sum");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let real = stdout.split_whitespace().next().expect("digest").to_owned();
        let exec_path = vec![dir.to_string_lossy().into_owned()];
        let name = "workload".to_owned();

        // Bare name resolved against the policy PATH, digest in the accepted set → ok.
        assert!(
            verify_workload_digest(Some(&name), &exec_path, std::slice::from_ref(&real)).is_ok()
        );
        // A non-matching set → refused.
        let err = verify_workload_digest(Some(&name), &exec_path, &["0".repeat(64)])
            .expect_err("mismatch");
        assert!(err.contains("not in the policy's accepted set"), "{err}");
        // A program that does not resolve → refused (fail closed).
        let nope = "nope".to_owned();
        assert!(
            verify_workload_digest(Some(&nope), &exec_path, std::slice::from_ref(&real)).is_err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

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
        fn del_address(&self, _: u16, _: &str, _: IpAddr, _: u8) -> io::Result<HelperResponse> {
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
                bpf_bind_allow_v4: Vec::new(),
                bpf_bind_deny_v4: Vec::new(),
                bpf_bind_allow_v6: Vec::new(),
                bpf_bind_deny_v6: Vec::new(),
                bpf_meta: [0u8; 64],
                bind_allowed_ports: Vec::new(),
                file_binds: Vec::new(),
                supplementary_groups: None,
                ulimits: Vec::new(),
                interactive_return_fd: None,
                workload_fd: None,
                aux: Vec::new(),
                ttl_seconds: None,
                ttl_action: kennel_lib_policy::TtlAction::Exit,
            };
            let net = NetPolicy {
                mode: kennel_lib_policy::NetMode::Constrained,
                proxy: kennel_lib_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
                deny_invariant: Vec::new(),
                deny_author: Vec::new(),
                bpf_connect_allow: Vec::new(),
                bpf_connect_deny: Vec::new(),
                bpf_bind_allow: Vec::new(),
                bpf_bind_deny: Vec::new(),
                bind_port_min: 0,
                bind_allowed_ports: Vec::new(),
            };
            Ok(Loaded {
                plan,
                account: "kennel".to_owned(),
                account_group: "kennel".to_owned(),
                net,
                ssh: kennel_lib_policy::SshRuntime::default(),
                unix: kennel_lib_policy::UnixRuntime::default(),
                binder: kennel_lib_policy::BinderRuntime::default(),
                dbus: kennel_lib_policy::DbusRuntime::default(),
                groups: Vec::new(),
                audit: kennel_lib_policy::AuditRuntime::default(),
                env: kennel_lib_policy::EnvRuntime::default(),
                exec_path: Vec::new(),
                shell: "/bin/sh".to_owned(),
                home_persist: Vec::new(),
                lifecycle: kennel_lib_policy::LifecyclePolicy {
                    ttl_seconds: None,
                    ttl_action: kennel_lib_policy::TtlAction::Exit,
                },
                workload: kennel_lib_policy::WorkloadRuntime::default(),
                tty_filter: true,
                on_change: kennel_lib_policy::OnChangeAction::Warn,
                spawn: None,
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
                afunix_bin: None,
                facade_dbus_bin: None,
                host_dbus_bin: None,
                init_bin: None,
                oci_entry_bin: None,
                tracer: kennel_lib_config::Tracer::new(
                    "kenneld",
                    kennel_lib_config::LogLevel::Info,
                ),
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
            listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 7022,
            akc: None,
        });
        bastion.push_edge_for_test(Edge {
            kennel: "ka".to_owned(),
            dest: "git@github.com".to_owned(),
            options: Vec::new(),
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
            line.contains("-- 'git@github.com'") && line.contains("AAAASYN_A"),
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

    // The full per-kennel path (handle_connection / run_kennel driving a real spawn) is now
    // exercised by the self-hosting e2e (`tests/e2e.rs`, run via the unprivileged runner)
    // against the real privhelper + factory — which a `Privileged` double cannot represent
    // (it was a double that hid the broken-on-the-daemon-path factory). The registry/control
    // logic above stays as fast pure unit tests.
}
