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

use std::collections::{BTreeMap, HashMap};
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
/// per-destination allowlist (Kennel book Vol 2 ch.8 (The Network)), two distinct rule
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
    /// The cross-kennel capability mesh consumes (§7.13.1): the `[[consumes]]` this kennel signed.
    /// The `SVC_CONNECT` broker matches a consume request against these (request-don't-author). Empty
    /// for a kennel with no `[[consumes]]`.
    pub consumes: Vec<kennel_lib_policy::ConsumeRuntime>,
    /// The cross-kennel capability mesh provides (§7.13.1): the `[[provides]]` this kennel signed. For
    /// each `af-unix` provide, construction binds the host-owned rendezvous directory at the in-view
    /// `dirname(endpoint)`, so the provider's bind at its policy `endpoint` is host-visible (§7.13.4b).
    /// Empty for a non-provider.
    pub provides: Vec<kennel_lib_policy::ProvideRuntime>,
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
    /// The invocation-cwd grant (`[fs.cwd]`, §7.9). When `grant` is not `none`, `run_kennel`
    /// resolves the request cwd host-side under the framework floor and materialises the
    /// grant into the plan; default (no grant) leaves the plan untouched.
    pub cwd: kennel_lib_policy::settled::CwdPolicy,
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

    /// Build the service catalogue (§7.13.4) from the enabled providers — the projection the broker
    /// resolves against, re-derivable on `daemon-reload`.
    ///
    /// The default is an empty catalogue: a loader with no enablement set (e.g. a test loader) offers
    /// nothing. The production [`crate::policy::TrustStoreLoader`] scans the enablement directories and
    /// projects them through the reserved-namespace gate.
    fn build_catalogue(&self) -> crate::catalogue::Catalogue {
        crate::catalogue::Catalogue::default()
    }

    /// The enabled providers (§7.13.6) — the membership the catalogue projects *and* the supervisor
    /// (W6) autostarts (the `autorun` subset). Default empty (a loader with no enablement set).
    fn enabled_providers(&self) -> Vec<crate::catalogue::EnabledProvider> {
        Vec::new()
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
    /// The mesh capability names this kennel's settled `[[consumes]]` declares — the W6 idle-reap
    /// census (§7.13.6): an ondemand provider is kept alive while any running kennel consumes one of
    /// its capabilities. The shape and required flag are carried for the consumer topology leg
    /// (`kennel list`). Empty for a kennel with no `[[consumes]]`.
    consumed: Vec<ConsumedEntry>,
}

/// One entry in `KennelMeta::consumed`: the name, expected shape, and whether the
/// dependency is required.
struct ConsumedEntry {
    name: String,
    shape: String,
    required: bool,
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
    /// The service catalogue (§7.13.4): the derived projection of the enabled providers' `[[provides]]`
    /// the broker resolves against. Built at startup from the enablement links on disk and re-derived
    /// on `daemon-reload` — never standing authored state. An `Arc` so each kennel's binder serving
    /// shares the one live catalogue its `SVC_CONNECT` handler resolves against.
    catalogue: std::sync::Arc<Mutex<crate::catalogue::Catalogue>>,
    /// The lazy-provider socket-activator (§7.13.6): set once at `serve` startup, after `Shared` is
    /// `Arc`-wrapped (the activator holds a back-reference to it). The binder `SVC_CONNECT` broker
    /// reaches it type-erased to socket-activate an `ondemand` provider on first consume. `None` before
    /// startup wires it, or in a test harness that does not.
    activator: std::sync::OnceLock<std::sync::Arc<dyn crate::supervisor::ProviderActivator>>,
    /// Providers the TTL handler has idle-reaped (§7.13.6), pending the supervisor's observation of
    /// the exit. The supervisor takes the mark to treat the kill as a reap (→ declared-but-pending,
    /// re-activatable) rather than a crash (→ restart/failed). Cleared as it is taken.
    idle_reaped: Mutex<std::collections::BTreeSet<String>>,
    /// The live `binder-connector` mesh buses (§7.13.4a): one per capability, keyed by the
    /// `(tier, name, key)` triple. Created lazily on first consumes/provides match (D4);
    /// ref-counted for teardown. The `MeshBus` serves node 0 on its own looper thread.
    mesh_buses: Mutex<HashMap<String, crate::mesh_bus::MeshBus>>,
    /// Each brokered consumer's settled `[dbus]` filter, keyed by its kennel `ctx` — the policy
    /// already carried on the ctx kenneld built at spawn (§7.7). The D-Bus mesh bus's node-0
    /// handler reads this when a consumer connects: it resolves the caller's `sender_pid` → cgroup
    /// → ctx, looks up the ctx's filter here, and pushes it to the broker as `ACCEPT_SESSION`.
    /// Inserted when a brokered kennel is prepared, removed when its ctx is released — so it lives
    /// exactly as long as the kennel does. It is *not* a session/credential store: identity is the
    /// kernel's per-transaction attestation, this is only the policy to apply once identified.
    dbus_filters: std::sync::Arc<Mutex<HashMap<u16, kennel_lib_policy::DbusRuntime>>>,
    /// Per-`ctx` tun session config for `[net.udp]` consumers, resolved by the tun-broker mesh bus's
    /// node-0 handler. Same lifetime and non-store discipline as [`Self::dbus_filters`].
    tun_filters: std::sync::Arc<Mutex<HashMap<u16, TunSessionConfig>>>,
}

/// A `[net.udp]` consumer's tun session config, pushed to the tun-broker over `ACCEPT_SESSION`.
///
/// The kennel's tun `/64` interface address plus its compiled grants and deny CIDRs, already in the
/// wire shape so the mesh resolver only has to encode them.
#[derive(Clone, Debug)]
pub struct TunSessionConfig {
    /// The consumer's tun interface address (`::1` in its `/64`) — sixteen octets.
    pub tun_addr: [u8; 16],
    /// The UDP name grants (`udp_allow_names`), in the wire shape.
    pub grants: Vec<kennel_lib_binder::service::tun_broker::Grant>,
    /// The deny CIDRs (invariant + author), in the wire shape.
    pub denies: Vec<kennel_lib_binder::service::tun_broker::Deny>,
}

/// Build a [`TunSessionConfig`] from a settled net policy: the kennel's tun `/64` address (derived
/// the single-source way, matching the constructor) plus its UDP grants and deny CIDRs, converted to
/// the tun-broker wire shape.
fn tun_session_config(
    net: &kennel_lib_policy::NetPolicy,
    op_uid: u32,
    ctx: u16,
) -> TunSessionConfig {
    use kennel_lib_binder::service::tun_broker::{Deny, Grant};
    let tun_addr = kennel_privhelper::addr::tun_addr(op_uid, ctx).octets();
    let grants = net
        .udp_allow_names
        .iter()
        .map(|r| Grant {
            name: r.name.clone(),
            ports: r.ports.clone(),
            protocol: protocol_ordinal(r.protocol),
        })
        .collect();
    let denies = net
        .deny_invariant
        .iter()
        .chain(&net.deny_author)
        .map(|r| Deny {
            cidr: r.cidr.clone(),
            prefix_len: r.prefix_len,
            port_min: r.port_min,
            port_max: r.port_max,
            protocol: protocol_ordinal(r.protocol),
        })
        .collect();
    TunSessionConfig {
        tun_addr,
        grants,
        denies,
    }
}

/// The settled `Protocol` as its wire ordinal (`0` any, `1` tcp, `2` udp).
const fn protocol_ordinal(p: kennel_lib_policy::Protocol) -> u8 {
    match p {
        kennel_lib_policy::Protocol::Any => 0,
        kennel_lib_policy::Protocol::Tcp => 1,
        kennel_lib_policy::Protocol::Udp => 2,
    }
}

impl<P: Privileged + Clone, L: PolicyLoader> Shared<P, L> {
    /// Build the shared state for `identity`.
    #[must_use]
    pub fn new(identity: Identity, privileged: P, loader: L) -> Self {
        let catalogue = loader.build_catalogue();
        if !catalogue.is_empty() {
            eprintln!(
                "kenneld: catalogue: {} capabilit{} from the enabled providers",
                catalogue.len(),
                if catalogue.len() == 1 { "y" } else { "ies" }
            );
        }
        Self {
            identity,
            privileged,
            loader,
            registry: Mutex::new(Registry::default()),
            bastion: Mutex::new(None),
            catalogue: std::sync::Arc::new(Mutex::new(catalogue)),
            activator: std::sync::OnceLock::new(),
            idle_reaped: Mutex::new(std::collections::BTreeSet::new()),
            mesh_buses: Mutex::new(HashMap::new()),
            dbus_filters: std::sync::Arc::new(Mutex::new(HashMap::new())),
            tun_filters: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Re-derive the service catalogue from the enablement links on disk (the `daemon-reload`
    /// analogue), returning the number of catalogued capability names. The set is the links on disk,
    /// never authored state, so this simply re-scans and re-projects.
    pub fn rebuild_catalogue(&self) -> usize {
        let cat = self.loader.build_catalogue();
        let n = cat.len();
        if let Ok(mut guard) = self.catalogue.lock() {
            *guard = cat;
        }
        n
    }

    /// Drive a provider's readiness through the W2 machine (§7.13.7) — the supervisor (W6) raises a
    /// construction/restart/crash-loop event as it runs the provider. A no-op if the provider is not
    /// catalogued or the transition is illegal.
    pub fn note_provider_event(&self, provider: &str, event: kennel_lib_control::readiness::Event) {
        if let Ok(mut guard) = self.catalogue.lock() {
            guard.apply_event(provider, event);
        }
    }

    /// Drive a provider to `Ready` (§7.13.6) — the supervisor calls this when construction seals.
    pub fn note_provider_ready(&self, provider: &str) {
        if let Ok(mut guard) = self.catalogue.lock() {
            guard.note_constructed(provider);
        }
    }

    /// A handle to the live catalogue, for the supervisor's autostart thread (§7.13.6). Cloning the
    /// `Arc` lets a supervision thread drive readiness without borrowing `self`.
    #[must_use]
    pub fn catalogue_handle(&self) -> std::sync::Arc<Mutex<crate::catalogue::Catalogue>> {
        std::sync::Arc::clone(&self.catalogue)
    }

    /// The enabled **`autorun`** providers (§7.13.6) the supervisor starts at daemon boot — the eager
    /// subset of the enablement scan (the lazy `ondemand` ones are socket-activated on first consume).
    #[must_use]
    pub fn autorun_providers(&self) -> Vec<crate::catalogue::EnabledProvider> {
        self.loader
            .enabled_providers()
            .into_iter()
            .filter(|p| p.enablement == crate::catalogue::Enablement::Autorun)
            .collect()
    }

    /// The enabled **`ondemand`** provider named `provider`, if any (§7.13.6) — the lazy provider the
    /// broker socket-activates on first consume. `None` for an unknown name, or an `autorun` one
    /// (`autostart` already brings those up). Re-derived from the enablement scan, never authored state.
    #[must_use]
    pub fn ondemand_provider(&self, provider: &str) -> Option<crate::catalogue::EnabledProvider> {
        self.loader.enabled_providers().into_iter().find(|p| {
            p.provider == provider && p.enablement == crate::catalogue::Enablement::Ondemand
        })
    }

    /// Install the lazy-provider [`crate::supervisor::ProviderActivator`] — once, at `serve` startup.
    /// A second call is ignored; the activator is set for the daemon's life.
    pub fn set_activator(
        &self,
        activator: std::sync::Arc<dyn crate::supervisor::ProviderActivator>,
    ) {
        let _ = self.activator.set(activator);
    }

    /// The lazy-provider activator the binder broker socket-activates an `ondemand` provider through,
    /// if one is installed (it is, in a live daemon; `None` in a test harness that skips the wiring).
    #[must_use]
    pub fn activator(&self) -> Option<std::sync::Arc<dyn crate::supervisor::ProviderActivator>> {
        self.activator.get().cloned()
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
        // The port sshd actually bound (a random high port, discovered at start).
        let bastion_port = bastion
            .port()
            .ok_or("bastion started but reported no bound port")?;
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
            bastion_port,
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
            host_service: Some(SocketAddr::new(setup.listen, bastion_port)),
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
        consumes: &[kennel_lib_policy::ConsumeRuntime],
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
        // Mesh consumes of af-unix shape ride the SAME facade: an `at` socket presented in the view,
        // brokered by name. kenneld's `CONNECT_AFUNIX` handler dispatches a `[[consumes]]` name to the
        // broker (§7.13.4 — resolve, socket-activate if cold, connect the provider's endpoint) rather
        // than a host `[[unix.allow]]` socket, so the facade is byte-identical; only kenneld's
        // resolution differs. A consume with no `at` is resolvable-only (no in-view socket); a non
        // af-unix shape is not an af-unix socket and is materialised elsewhere when those shapes land.
        for consume in consumes {
            if consume.shape != kennel_lib_policy::settled::Shape::AfUnix {
                continue;
            }
            let Some(at) = consume.at.as_ref() else {
                continue;
            };
            let shim_path = resolve_path(at, subst, shim_root);
            for var in &consume.env {
                env.push((var.clone(), shim_path.to_string_lossy().into_owned()));
            }
            shims.push(crate::UnixShim {
                name: consume.name.clone(),
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

    /// Get or create a binder-connector mesh bus for the given capability, returning a **detached,
    /// movable clone** of its binderfs (an `open_tree(CLONE)` fd from the holder) for one new
    /// participant. The bus is created lazily on first use (D4) and ref-counted for teardown.
    ///
    /// The caller hands the fd to the kennel (via the mesh rendezvous), where `kennel-bin-init`
    /// `move_mount`s it into the view — the device never enters the view as a host-path bind, so it
    /// is immune to the kennel's PID namespace.
    ///
    /// # Errors
    ///
    /// Returns the OS error if creating the mesh bus or cloning its mount fails.
    fn ensure_mesh_bus(
        &self,
        tier: crate::catalogue::Tier,
        name: &str,
        key: Option<&str>,
    ) -> io::Result<std::os::fd::OwnedFd> {
        let bus_key = mesh_bus_key(tier, name, key);
        let mut buses = self
            .mesh_buses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bus = match buses.entry(bus_key) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                // The mesh bus mediates every cross-kennel D-Bus session — its verdicts are
                // security-relevant, so they go to a real journal-backed writer (not a noop drain),
                // keyed to the bus identity (it has no per-kennel audit state dir).
                let w =
                    std::sync::Arc::new(crate::audit::daemon_writer(&format!("mesh-bus/{name}")));
                // A brokered-session connector bus gets the identity resolver for its shape: its
                // node-0 handler mints a filtered session per consumer (a D-Bus node, or the tun
                // session's fd). Every other connector bus resolves a consumer straight to its
                // provider's handle (no resolver).
                let resolver = if name == "org.projectkennel.dbus-broker" {
                    Some(crate::mesh_bus::MeshResolver::Dbus(self.dbus_resolver()))
                } else if name == "org.projectkennel.tun-broker" {
                    Some(crate::mesh_bus::MeshResolver::Tun(self.tun_resolver()))
                } else {
                    None
                };
                // Mount the shared binderfs by forking an unprivileged holder under kenneld's own
                // AppArmor profile (which carries the `userns` grant): it creates a user namespace,
                // self-maps `0 <kenneld-uid> 1`, and mounts the binderfs — no privilege, no
                // privhelper. The holder pid lets kenneld reach node 0 via `/proc/<pid>/root` (nodes
                // owned by kenneld's own uid); the socket lets kenneld request movable clones.
                let mount_dir = crate::mesh::host_rp_dir(tier, name, key);
                let (holder_pid, holder_sock) = crate::mesh_holder::spawn(&mount_dir)?;
                let mb = crate::mesh_bus::MeshBus::create(
                    tier,
                    name,
                    key,
                    &w,
                    resolver,
                    holder_pid,
                    holder_sock,
                )?;
                e.insert(mb)
            }
        };
        bus.add_participant();
        let clone = bus.clone_mount_fd()?;
        drop(buses);
        Ok(clone)
    }

    /// Release a participant from a mesh bus. If the refcount reaches zero, the bus
    /// is torn down (serve loop stopped, binderfs unmounted).
    fn release_mesh_bus(&self, tier: crate::catalogue::Tier, name: &str, key: Option<&str>) {
        let bus_key = mesh_bus_key(tier, name, key);
        let mut buses = self
            .mesh_buses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let std::collections::hash_map::Entry::Occupied(mut e) = buses.entry(bus_key) {
            if e.get_mut().remove_participant() {
                // Last participant — tear down the bus.
                e.remove();
            }
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
        reg.kennels.insert(
            name.to_owned(),
            KennelMeta {
                ctx,
                pid: None,
                broker: None,
                consumed: Vec::new(),
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

    /// Record the mesh capabilities this kennel consumes, once its policy is loaded. The
    /// idle-reap census (§7.13.6) and the consumer topology leg (`kennel list`) read this.
    fn note_consumes(&self, name: &str, entries: Vec<ConsumedEntry>) {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(meta) = reg.kennels.get_mut(name) {
            meta.consumed = entries;
        }
    }

    /// Whether any running kennel's settled `[[consumes]]` names one of `capabilities` (§7.13.6).
    /// The W6 idle-reap keep-alive: an ondemand provider is reaped only when no consumer kennel runs.
    pub(crate) fn any_running_consumer(&self, capabilities: &[String]) -> bool {
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels
            .values()
            .any(|m| m.consumed.iter().any(|c| capabilities.contains(&c.name)))
    }

    /// Mark `provider` idle-reaped (§7.13.6) — the TTL handler records this before killing the cgroup,
    /// so the supervisor reads the kill as a reap, not a crash.
    pub(crate) fn mark_idle_reaped(&self, provider: &str) {
        self.idle_reaped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(provider.to_owned());
    }

    /// Take `provider`'s idle-reaped mark (§7.13.6): `true` once, then cleared — the supervisor calls
    /// this when the provider exits, to distinguish an idle reap (→ declared-but-pending) from a crash.
    pub(crate) fn take_idle_reaped(&self, provider: &str) -> bool {
        self.idle_reaped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(provider)
    }

    /// Deregister `name` and return its context to the pool.
    fn release(&self, name: &str, ctx: u16) {
        // Drop this kennel's D-Bus and tun filters (if brokered) — its ctx is being freed, so the
        // mesh resolvers must no longer resolve a future caller in a reused cgroup to a stale policy.
        self.dbus_filters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ctx);
        self.tun_filters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&ctx);
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.kennels.remove(name);
        reg.ctx.release(ctx);
    }

    /// Record a brokered consumer's settled `[dbus]` filter under its `ctx`, for the D-Bus mesh
    /// bus's node-0 handler to resolve callers against (see [`Shared::dbus_filters`]). Removed when
    /// the ctx is released ([`Shared::release`]).
    fn register_dbus_filter(&self, ctx: u16, dbus: kennel_lib_policy::DbusRuntime) {
        self.dbus_filters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ctx, dbus);
    }

    /// Build the D-Bus mesh resolver (see [`crate::mesh_bus::SessionResolver`]): map a connecting
    /// consumer's `(sender_pid, capability name)` to the encoded `ACCEPT_SESSION` filter, resolving
    /// `sender_pid` → cgroup → ctx → its `[dbus]` policy *fresh* each call. Nothing is remembered;
    /// the only standing state is the ctx→policy map, keyed on a kernel-managed cgroup lifetime.
    fn dbus_resolver(&self) -> crate::mesh_bus::SessionResolver {
        let filters = std::sync::Arc::clone(&self.dbus_filters);
        std::sync::Arc::new(move |sender_pid: i32, name: &str| {
            let bus = kennel_lib_binder::service::dbus::capability_bus(name)?;
            let ctx = crate::cgroup::pid_to_ctx(sender_pid)?;
            let map = filters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let runtime = map.get(&ctx)?;
            let rules = match bus {
                kennel_lib_binder::service::dbus::SYSTEM => runtime.system.as_ref(),
                _ => runtime.session.as_ref(),
            }?;
            let payload = kennel_lib_binder::service::broker::encode_accept(
                bus,
                &rules.talk,
                &rules.call,
                &rules.broadcast,
                &rules.own,
                &rules.deny_talk,
            );
            drop(map);
            Some(payload)
        })
    }

    /// Record a `[net.udp]` consumer's tun session config (its tun `/64` address, grants, and deny
    /// CIDRs) under its `ctx`, for the tun-broker mesh bus's node-0 handler to resolve callers
    /// against (see [`Shared::tun_filters`]). Removed when the ctx is released ([`Shared::release`]).
    fn register_tun_filter(&self, ctx: u16, config: TunSessionConfig) {
        self.tun_filters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ctx, config);
    }

    /// Build the tun mesh resolver (see [`crate::mesh_bus::SessionResolver`]): map a connecting
    /// `[net.udp]` consumer's `sender_pid` → cgroup → ctx → its registered [`TunSessionConfig`], and
    /// encode the tun `ACCEPT_SESSION`. Fresh each call; the ctx is the authorization (the kennel
    /// opted into `[net.udp]`), so the capability name it asked for is not itself trusted.
    fn tun_resolver(&self) -> crate::mesh_bus::SessionResolver {
        let filters = std::sync::Arc::clone(&self.tun_filters);
        std::sync::Arc::new(move |sender_pid: i32, _name: &str| {
            let ctx = crate::cgroup::pid_to_ctx(sender_pid)?;
            let map = filters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let config = map.get(&ctx)?;
            let payload = kennel_lib_binder::service::tun_broker::encode_accept(
                config.tun_addr,
                &config.grants,
                &config.denies,
            );
            drop(map);
            Some(payload)
        })
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
        // Hard reaper (§7.12.7): a stopped requester takes its spawned siblings with it, so a
        // network-capable tool cannot outlive the agent that asked for it.
        self.reap_children(ctx);
        let cgroup = cgroup::kennel_cgroup(&self.identity.cgroup_base, ctx);
        match cgroup::kill_cgroup(&cgroup) {
            Ok(()) => Response::Stopped,
            Err(e) => Response::Error(format!("could not stop `{name}`: {e}")),
        }
    }

    /// The hard reaper (§7.12.7): `cgroup.kill` every kennel this requester spawned.
    ///
    /// Spawned kennels are named `spawn-<parent-ctx>-<id>` (see [`crate::spawn::spawn_name`]), so the
    /// requester's children are exactly the live registry entries under that prefix. Called when the
    /// requester tears down — explicit `stop`, or its own workload exit / TTL — so a tool that ignores
    /// the soft-reaper `EOF` still dies with the agent that spawned it (the template's TTL is the
    /// independent backstop for the requester-holds-its-session-forever case).
    fn reap_children(&self, parent_ctx: u16) {
        let prefix = crate::spawn::child_name_prefix(parent_ctx);
        let children: Vec<u16> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.kennels
                .iter()
                .filter(|(name, _)| name.starts_with(&prefix))
                .map(|(_, meta)| meta.ctx)
                .collect()
        };
        for child_ctx in children {
            let cgroup = cgroup::kennel_cgroup(&self.identity.cgroup_base, child_ctx);
            if let Err(e) = cgroup::kill_cgroup(&cgroup) {
                eprintln!("kenneld: hard reaper: could not kill spawned ctx {child_ctx}: {e}");
            }
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
                consumed: meta
                    .consumed
                    .iter()
                    .map(|c| control::ConsumedCapability {
                        name: c.name.clone(),
                        shape: c.shape.clone(),
                        required: c.required,
                    })
                    .collect(),
            })
            .collect();
        drop(reg);
        Response::Listing(kennels)
    }

    /// Handle a `Mesh`: snapshot the service catalogue as one row per provider→offered-capability
    /// (`kennel mesh`, §7.13.7). Read-only — the same live catalogue the broker resolves against, so a
    /// flaked or pending provider is visible rather than a silent resolve-miss. The enum-valued fields
    /// go on the wire as their canonical lower-case names.
    fn mesh(&self) -> Response {
        let cat = self
            .catalogue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut providers = Vec::new();
        for (id, p) in cat.entries() {
            for offer in &p.offers {
                providers.push(control::MeshProvider {
                    capability: offer.name.clone(),
                    provider: id.to_owned(),
                    shape: offer.shape.as_str().to_owned(),
                    tier: p.tier.as_str().to_owned(),
                    enablement: p.enablement.as_str().to_owned(),
                    readiness: p.readiness.as_str().to_owned(),
                });
            }
        }
        drop(cat);
        Response::Mesh(providers)
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
    // Autostart the enabled `autorun` providers (§7.13.6) before serving control requests — each in
    // its own supervision thread, lifecycle-coupled to the daemon (the `ondemand` set is socket-
    // activated by the broker on first consume instead).
    // Install the lazy-provider activator first (the back-reference the `ondemand` socket-activation
    // path reaches through), then autostart the eager `autorun` set.
    shared.set_activator(std::sync::Arc::new(crate::supervisor::Activator::new(
        std::sync::Arc::clone(shared),
    )));
    crate::supervisor::autostart(shared);
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
    // W17: the version handshake is the FIRST thing on the connection — before any request or policy
    // is read. A client compiling a settled-policy schema newer than this daemon parses is refused
    // here (the daemon sends the typed verdict and we drop), so a skew surfaces as "restart the
    // daemon", not a cryptic parse error later. A pre-handshake client / malformed preamble drops too.
    match control::server_handshake(
        conn,
        kennel_lib_policy::SETTLED_SCHEMA_VERSION,
        env!("CARGO_PKG_VERSION"),
    ) {
        Ok(true) => {}
        Ok(false) | Err(_) => return,
    }
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
            // early construction failure (§7.12.7). The requester-liveness flag rides with it, so
            // run_kennel can self-terminate this sibling if the requester died mid-build (the
            // async-reaper race close, §7.12.7).
            let parent_alive = Some(slot.parent_liveness());
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
                parent_alive.as_deref(),
                None, // a spawn target is not a mesh provider
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
    shared: &Arc<Shared<P, L>>,
    request: Request,
    fds: Vec<OwnedFd>,
    conn: &mut UnixStream,
    constructor: &Arc<dyn crate::spawn::SpawnConstructor>,
) where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    let response = match request {
        Request::Start(req) => match validate_kennel_name(&req.kennel) {
            Ok(()) => return run_kennel(shared, &req, fds, conn, None, constructor, None, None),
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
        Request::Mesh => shared.mesh(),
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
        // Re-derive the service catalogue from the enablement links on disk (§7.13.6).
        Request::DaemonReload => {
            let catalogued = u32::try_from(shared.rebuild_catalogue()).unwrap_or(u32::MAX);
            Response::Reloaded { catalogued }
        }
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
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn run_kennel<P, L>(
    shared: &Arc<Shared<P, L>>,
    req: &StartRequest,
    fds: Vec<OwnedFd>,
    conn: &mut UnixStream,
    preloaded: Option<kennel_lib_policy::SettledPolicy>,
    constructor: &Arc<dyn crate::spawn::SpawnConstructor>,
    parent_alive: Option<&std::sync::atomic::AtomicBool>,
    // `Some(tier)` when the supervisor brings up a mesh provider (§7.13.6): each af-unix `[[provides]]`
    // gets the host rendezvous directory bound at its in-view `dirname(endpoint)` (§7.13.4b). `None`
    // for a plain `kennel run`, which provides nothing over the mesh.
    provider_tier: Option<crate::catalogue::Tier>,
) where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    let tr = shared.identity.tracer;
    tr.step(&format!("run_kennel: starting `{}`", req.kennel));
    let mut mesh_bus_guard = MeshBusGuard::new(shared);
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
        namespace: shared.identity.scope.namespace(),
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
    // `[fs.cwd]` (§7.9): materialise the invocation cwd into the view. The signed policy
    // declared the slot; here — host-side, in operator context, before the kennel exists —
    // we resolve `req.cwd` under the framework floor and add the bind/Landlock grant. A
    // floor or marker failure REFUSES the run (never a silent no-grant).
    if !loaded.cwd.grant.is_none() {
        match resolve_cwd_grant(&req.cwd, &loaded.cwd.required) {
            Ok(resolved) => {
                let writable = matches!(
                    loaded.cwd.grant,
                    kennel_lib_policy::settled::CwdGrant::Write
                );
                tr.detail(&format!(
                    "run_kennel: [fs.cwd] grant {:?} materialised at {} (writable={writable})",
                    loaded.cwd.grant,
                    resolved.display()
                ));
                loaded.plan.grant_cwd(resolved, writable);
            }
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "fs.cwd", reason),
        }
    }
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
    // A non-interactive run injects the three workload stdio fds (a piped `kennel run`'s controller
    // fds, or a SPAWN channel's spawned ends) onto the workload's 0/1/2 — the raw-channel sibling of
    // the interactive pty path. The fds stay alive in `command` (as its stdin/stdout/stderr) through
    // construction, so these raw numbers are valid when the factory sends them.
    let mut stdio_raw: Option<[std::os::fd::RawFd; 3]> = None;
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
        if let [stdin, stdout, stderr, ..] = fds.as_slice() {
            stdio_raw = Some([stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()]);
        }
        match command_for(&argv, &cwd, fds) {
            Ok(command) => command,
            Err(reason) => return fail(shared, &req.kennel, ctx, conn, "prepare command", reason),
        }
    };
    loaded.plan.stdio_fds = stdio_raw;
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
    let unix = shared.prepare_unix(&loaded.unix, &loaded.consumes, &subst, &shim_root);
    // Record this kennel's consumed capabilities for the W6 idle-reap census (§7.13.6): while this
    // kennel runs, any ondemand provider it consumes is kept alive.
    shared.note_consumes(
        &req.kennel,
        loaded
            .consumes
            .iter()
            .map(|c| ConsumedEntry {
                name: c.name.clone(),
                shape: c.shape.as_str().to_owned(),
                required: c.required,
            })
            .collect(),
    );
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
    // Binder-connector mesh mounts to place in the view via the rendezvous (§7.13.4a): each is a
    // detached binderfs clone fd + its in-view target directory. `kennel-bin-init` `move_mount`s them
    // before forking the workload (and Landlock-grants the device). Collected across the provider and
    // consumer passes below, then handed to `bring_up` on the `Spec`.
    let mut mesh_mounts: Vec<(std::os::fd::OwnedFd, std::path::PathBuf)> = Vec::new();
    // Provider rendezvous points (§7.13.4b): for each af-unix `[[provides]]`, bind the host
    // rendezvous directory `<runtime>/mesh/<tier>/<name>[.key]/` at the in-view `dirname(endpoint)`,
    // so the socket the provider binds at its policy `endpoint` is the inode the broker connects
    // host-side. Built for a supervised mesh provider (`provider_tier`), before the view's binds move
    // into the `Spec`.
    if let Some(tier) = provider_tier {
        if let Some(view) = loaded.plan.view.as_mut() {
            for p in &loaded.provides {
                if p.shape != kennel_lib_policy::settled::Shape::AfUnix {
                    continue;
                }
                let key = p.key.as_deref();
                let host_dir = crate::mesh::host_rp_dir(tier, &p.name, key);
                // kenneld owns the rendezvous directory; create it (0700) and clear any stale socket
                // before construction binds it in and the provider binds afresh at its endpoint.
                if let Err(e) = std::fs::create_dir_all(&host_dir) {
                    eprintln!(
                        "kenneld: provider `{}`: mesh rendezvous dir {}: {e}",
                        req.kennel,
                        host_dir.display()
                    );
                    continue;
                }
                let _ = std::fs::set_permissions(
                    &host_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
                let _ = std::fs::remove_file(crate::mesh::host_rp_socket(
                    tier,
                    &p.name,
                    key,
                    &p.endpoint,
                ));
                // Bind the host directory at the in-view parent of the policy endpoint.
                let Some(target) = std::path::Path::new(&p.endpoint).parent() else {
                    continue;
                };
                view.binds.push(kennel_lib_spawn::plan::BindMount {
                    source: host_dir,
                    target: target.to_path_buf(),
                    writable: true,
                    exclusive: false,
                });
            }
            // Binder-connector `[[provides]]` (§7.13.4a): ensure the mesh bus for this capability
            // and request a movable clone of its binderfs to place at the provider's `endpoint`. The
            // clone rides the mesh rendezvous; `kennel-bin-init` `move_mount`s it into the view, where
            // the provider opens `<endpoint>` (= `<mount-dir>/binder`), `ADD_SERVICE`s, and serves.
            for p in &loaded.provides {
                if p.shape != kennel_lib_policy::settled::Shape::BinderConnector {
                    continue;
                }
                let Some(target_dir) = std::path::Path::new(&p.endpoint).parent() else {
                    continue;
                };
                let key = p.key.as_deref();
                match shared.ensure_mesh_bus(tier, &p.name, key) {
                    Ok(clone_fd) => {
                        mesh_bus_guard.push(tier, p.name.clone(), p.key.clone());
                        mesh_mounts.push((clone_fd, target_dir.to_path_buf()));
                    }
                    Err(e) => {
                        eprintln!(
                            "kenneld: provider `{}`: mesh bus for `{}`: {e}",
                            req.kennel, p.name
                        );
                    }
                }
            }
        }
    }
    // Consumer mesh-bus bind-mounts (§7.13.4a): for each binder-connector `[[consumes]]` with an
    // `at`, resolve the provider's tier from the catalogue, ensure the mesh bus, and bind-mount
    // its binder device at the consumer's `at` path. The consumer opens this device, transacts
    // `SVC_CONNECT` on the mesh bus to get the provider's handle, then transacts directly.
    //
    // Two-phase: collect (tier, name, key, at) under the catalogue lock, then drop it before
    // taking the mesh_buses lock (ensure_mesh_bus), preventing lock-order inversion.
    {
        let mesh_consumer_binds: Vec<(crate::catalogue::Tier, String, Option<String>, String)> = {
            let cat = shared
                .catalogue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loaded
                .consumes
                .iter()
                .filter(|c| c.shape == kennel_lib_policy::settled::Shape::BinderConnector)
                .filter_map(|c| {
                    let at = c.at.as_ref()?;
                    let candidate = cat.resolve(&c.name).into_iter().next()?;
                    Some((candidate.tier, c.name.clone(), c.key.clone(), at.clone()))
                })
                .collect()
        }; // catalogue lock dropped
        for (tier, name, key, at) in &mesh_consumer_binds {
            let Some(target_dir) = std::path::Path::new(at).parent() else {
                continue;
            };
            match shared.ensure_mesh_bus(*tier, name, key.as_deref()) {
                Ok(clone_fd) => {
                    mesh_bus_guard.push(*tier, name.clone(), key.clone());
                    mesh_mounts.push((clone_fd, target_dir.to_path_buf()));
                }
                Err(e) => {
                    eprintln!(
                        "kenneld: consumer `{}`: mesh bus for `{name}`: {e}",
                        req.kennel
                    );
                }
            }
        }
    }

    // Brokered D-Bus is opt-in per the consumer's policy: a kennel routes its D-Bus over the
    // standing broker only when it BOTH enables `[dbus]` AND declares a `[[consumes]]` of a
    // `dbus-name` capability (the service-mesh trigger). `[dbus]` alone keeps the legacy
    // per-consumer host-dbus delegate — so enabling the broker for one kennel does not silently
    // strip another's delegate. (dbus-brokered's consumer.toml documents this two-declaration
    // contract.)
    let consumes_dbus_name = loaded
        .consumes
        .iter()
        .any(|c| c.shape == kennel_lib_policy::settled::Shape::DbusName);

    // Brokered D-Bus consumer (§7.7): such a kennel reaches the standing dbus-broker over the
    // connector mesh bus, so its `facade-dbus` opens the mesh device directly (the per-kennel
    // `SVC_CONNECT(dbus)` hands it this same path). Bind the device into the view — the dbus-name
    // consume is served by the facade, not the binder-connector consumer loop above, so nothing
    // else mounts it. Only when this kennel actually consumes the broker; otherwise D-Bus takes the
    // legacy host-dbus route and needs no mesh device.
    {
        let dbus_enabled = loaded.dbus.session.is_some() || loaded.dbus.system.is_some();
        // Resolve the broker's tier from the catalogue — NOT a hardcoded `Host`. The broker
        // registers its control node on the mesh bus keyed by its *policy-derived* tier (the
        // supervisor activates it with the catalogue candidate's tier); a user-enabled broker is
        // `User`, not `Host`. Keying this consumer's mesh bus by the same resolved tier is what puts
        // both on one binderfs instance — mismatch them and the broker's control node is on a
        // different bus, so `ACCEPT_SESSION` fails closed with no provider found.
        let broker_tier = {
            let cat = shared
                .catalogue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cat.resolve("org.projectkennel.dbus-broker")
                .into_iter()
                .next()
                .map(|c| c.tier)
        };
        if let (true, true, Some(tier)) = (dbus_enabled, consumes_dbus_name, broker_tier) {
            match shared.ensure_mesh_bus(tier, "org.projectkennel.dbus-broker", None) {
                Ok(clone_fd) => {
                    mesh_bus_guard.push(tier, "org.projectkennel.dbus-broker".to_owned(), None);
                    // The device lands at `MESH_DBUS_DEVICE` (`/dev/binderfs-mesh/binder`); its
                    // mount dir is the parent. `facade-dbus` opens that path (the `SVC_CONNECT(dbus)`
                    // reply names it).
                    if let Some(target_dir) =
                        std::path::Path::new(crate::binder::MESH_DBUS_DEVICE).parent()
                    {
                        mesh_mounts.push((clone_fd, target_dir.to_path_buf()));
                    }
                }
                Err(e) => {
                    eprintln!("kenneld: consumer `{}`: dbus mesh bus: {e}", req.kennel);
                }
            }
        }
    }

    // TTL is enforced inside the kennel now (§9.7): `kennel-bin-init` runs the timer and, at
    // expiry, makes the blocking `NOTIFY_TTL_EXPIRED` call that the node-0 handler services
    // (freeze + decide). The ttl_seconds + ttl_action ride the Plan (→ supervision-half /
    // binder Lifecycle), so kenneld no longer polls from out here.
    // Register this kennel's tun session config if it opts into `[net.udp]` and the tun broker is
    // enabled, so the tun-broker mesh bus's node-0 handler can resolve a future facade-tun connect
    // (sender_pid → cgroup → ctx → here) and push its grants/denies over ACCEPT_SESSION.
    if loaded.net.udp {
        let tun_broker_enabled = {
            let cat = shared
                .catalogue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            !cat.resolve("org.projectkennel.tun-broker").is_empty()
        };
        if tun_broker_enabled {
            shared.register_tun_filter(
                ctx,
                tun_session_config(&loaded.net, shared.identity.uid, ctx),
            );
        }
    }

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
        mesh_mounts,
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
                shared.identity.tracer,
            ))
        });
        spec.binder = Some(crate::BinderPrep {
            unix: facade_unix,
            writer,
            init_bin: shared.identity.init_bin.clone(),
            prompt,
            spawn,
            consumes: loaded.consumes,
            catalogue: Some(std::sync::Arc::clone(&shared.catalogue)),
            activator: shared.activator(),
            brokered_dbus: {
                // Brokered only when this kennel actually consumes the broker (a `dbus-name`
                // `[[consumes]]`) AND the broker is enabled in the catalogue. `[dbus]` alone is the
                // legacy host-dbus delegate; gating on the consume keeps enabling the broker for one
                // kennel from stripping another's delegate (the dbus-session-allowed regression).
                let brokered = consumes_dbus_name && {
                    let cat = shared
                        .catalogue
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    !cat.resolve("org.projectkennel.dbus-broker").is_empty()
                };
                // Brokered: record this kennel's filter under its ctx so the D-Bus mesh bus's
                // node-0 handler can resolve a future connect (sender_pid → cgroup → ctx → here)
                // and mint the session. The per-kennel relay then only *locates* the mesh bus.
                if brokered {
                    shared.register_dbus_filter(ctx, loaded.dbus.clone());
                }
                brokered
            },
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
    let mut kennel = match start(&audited, spec, &mut command) {
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

    // D-Bus sessions are brokered lazily: the consumer's filter rides the brokered DbusRelay
    // (resolved at construction), and a session node is minted per SVC_CONNECT(dbus-name) via
    // ACCEPT_SESSION — no standing per-consumer registration at the broker.
    // Hard-reaper race close (§7.12.7): a spawned sibling's construction is async to the SPAWN reply,
    // so the requester can die — and its `reap_children` run — while this build is still in flight,
    // before the cgroup exists for the reaper to `cgroup.kill`. The requester's `SpawnRuntime::Drop`
    // flips `parent_alive` false ahead of that reap; now that the cgroup is live and registered, the
    // two checks interlock: either the reaper sees this cgroup, or this re-check sees the requester
    // gone. If gone, terminate at once — never leave a sibling that outlives the agent that asked for
    // it (which the `max_instances` ceiling alone could not bound across requester restarts). `None`
    // for a top-level `kennel run`, which has no requester to outlive.
    if let Some(alive) = parent_alive {
        if !alive.load(std::sync::atomic::Ordering::Acquire) {
            tr.step("run_kennel: requester gone during async construct — terminating the orphan");
            let _ = kennel.terminate();
        }
    }
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
    // `stop` blocks until the workload exits — delivering its answer (the spawned kennel's stdio
    // closes) — then reclaims: it stamps `teardown: workload exited` at that exit point, stops the
    // binder looper pool, and removes the cgroup. The spinup harness reads the span from that
    // milestone to `teardown complete` below as the teardown cost, distinct from the answer latency
    // the requester observes (`02-10` §7.12.7).
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
    // Hard reaper (§7.12.7): the requester's workload exited, so reap any siblings it spawned — a
    // tool that ignored the soft-reaper EOF dies with the agent (a no-op for a kennel that spawned
    // nothing, including every spawned kennel itself, which is depth-1).
    shared.reap_children(ctx);
    // D-Bus sessions need no explicit teardown: when this consumer's kennel exits, its
    // session-node handles are released and the broker reclaims each on Br::Release.
    shared.deregister_ssh(&req.kennel);
    shared.release(&req.kennel, ctx);
    // Reclaim complete: the cgroup is gone and the registry entry released. For a spawned sibling the
    // `max_instances` slot frees microseconds later when this `run_kennel` returns and the constructor
    // thread drops its `SlotGuard` — so this milestone marks the kennel fully torn down (§7.12.7).
    tr.step(&format!("run_kennel: teardown complete `{}`", req.kennel));
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
/// Resolve and floor-check the invocation cwd for a `[fs.cwd]` grant (§7.9).
///
/// Returns the canonical host directory to bind, or a refusal reason. The framework floor is
/// non-overridable: the path must be a directory, realpath-normalised, owned by the operator,
/// and not the operator's `$HOME`; every `required` marker must be present. Resolution is
/// host-side, in operator context, before the kennel exists — the workload (the adversary) is
/// not yet running, so there is no TOCTOU against it.
fn resolve_cwd_grant(cwd: &Path, required: &[String]) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    // Realpath-normalise: resolve symlinks to the real directory, so the bound path is the
    // canonical owned inode (a symlinked invocation dir resolves to its target, which the
    // ownership check below then vets — a symlink into a non-owned tree is refused there).
    let resolved = std::fs::canonicalize(cwd)
        .map_err(|e| format!("cannot resolve the invocation cwd {}: {e}", cwd.display()))?;
    let meta = std::fs::metadata(&resolved)
        .map_err(|e| format!("cannot stat {}: {e}", resolved.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", resolved.display()));
    }
    let uid = kennel_lib_syscall::unistd::real_uid();
    if meta.uid() != uid {
        return Err(format!(
            "{} is not owned by the operator (uid {uid}); the cwd grant is refused",
            resolved.display()
        ));
    }
    // Never `$HOME`: a whole-home bind is exactly what the persona view exists to prevent. A
    // path *under* the home is fine (a project dir); the home root itself is not.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if std::fs::canonicalize(&home).is_ok_and(|h| h == resolved) {
            return Err(format!(
                "the invocation cwd {} is the operator's $HOME; the cwd grant never binds $HOME",
                resolved.display()
            ));
        }
    }
    // Markers: each required dirent must be present (a trailing slash requires a directory),
    // so the grant applies only to a project the operator has marked for agent use.
    for marker in required {
        let (name, want_dir) = marker
            .strip_suffix('/')
            .map_or((marker.as_str(), false), |n| (n, true));
        let present = std::fs::metadata(resolved.join(name)).is_ok_and(|m| !want_dir || m.is_dir());
        if !present {
            return Err(format!(
                "the invocation cwd {} is missing the required marker `{marker}` — mark the \
                 project for agent use (e.g. `mkdir {name}`) or run from a marked project root",
                resolved.display()
            ));
        }
    }
    Ok(resolved)
}

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
    // Pinned workload that allows argument passthrough: append the request tokens to the
    // pinned argv. The program and base argv stay pinned exactly (the fd-pin/digest binds
    // the program, not the args); the cwd follows the pin (its own, else the request's).
    if workload.pinned && workload.allowed_args {
        let mut argv = workload.argv.clone();
        argv.extend(req.argv.iter().cloned());
        let cwd = workload
            .cwd
            .as_deref()
            .map_or_else(|| req.cwd.clone(), PathBuf::from);
        return Ok((argv, cwd));
    }
    // Request-supplied argv: overrides the policy workload unless it is pinned.
    if workload.pinned && !req.force {
        return Err(format!(
            "policy [workload] is pinned to `{}`; refusing the `-- {}` override \
             (pass --force to override, or set [workload] allowed_args to append)",
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

struct MeshBusGuard<'a, P, L>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    shared: &'a Shared<P, L>,
    buses: Vec<(crate::catalogue::Tier, String, Option<String>)>,
}

impl<'a, P, L> MeshBusGuard<'a, P, L>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    const fn new(shared: &'a Shared<P, L>) -> Self {
        Self {
            shared,
            buses: Vec::new(),
        }
    }

    fn push(&mut self, tier: crate::catalogue::Tier, name: String, key: Option<String>) {
        self.buses.push((tier, name, key));
    }
}

impl<P, L> Drop for MeshBusGuard<'_, P, L>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    fn drop(&mut self) {
        for (tier, name, key) in &self.buses {
            self.shared.release_mesh_bus(*tier, name, key.as_deref());
        }
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

/// Derive the map key for a mesh bus from its `(tier, name, key)` triple.
fn mesh_bus_key(tier: crate::catalogue::Tier, name: &str, key: Option<&str>) -> String {
    key.map_or_else(
        || format!("{}/{name}", tier.as_str()),
        |k| format!("{}/{name}.{k}", tier.as_str()),
    )
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
            allowed_args: false,
            sha256: Vec::new(),
        }
    }

    #[test]
    fn resolve_cwd_grant_accepts_owned_marked_dir_and_refuses_unmarked() {
        let uid = kennel_lib_syscall::unistd::real_uid();
        let base = std::env::temp_dir().join(format!(
            "kennel-cwd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".git")).expect("mk .git");
        std::fs::create_dir_all(base.join(".claude")).expect("mk .claude");
        // Owned dir with both markers present resolves to its canonical path.
        let ok = resolve_cwd_grant(&base, &[".git".to_owned(), ".claude/".to_owned()])
            .expect("marked dir ok");
        assert_eq!(ok, std::fs::canonicalize(&base).expect("canonicalize base"));
        // A missing marker refuses with a naming diagnostic.
        let err =
            resolve_cwd_grant(&base, &["NOPE".to_owned()]).expect_err("missing marker refuses");
        assert!(err.contains("NOPE"), "{err}");
        // A trailing-slash marker that exists only as a file is refused.
        std::fs::write(base.join("marker"), b"x").expect("write file");
        assert!(
            resolve_cwd_grant(&base, &["marker/".to_owned()]).is_err(),
            "file cannot satisfy a dir marker"
        );
        // A non-existent cwd refuses.
        assert!(resolve_cwd_grant(&base.join("does-not-exist"), &[]).is_err());
        let _ = std::fs::remove_dir_all(&base);
        let _ = uid; // real_uid is the ownership anchor the fn checks against.
    }

    #[test]
    fn resolve_cwd_grant_refuses_home() {
        if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
            if home.is_dir() {
                let err = resolve_cwd_grant(&home, &[]).expect_err("$HOME must be refused");
                assert!(err.contains("$HOME"), "{err}");
            }
        }
    }

    #[test]
    fn effective_workload_pinned_allowed_args_appends() {
        let mut w = workload(&["/launcher", "--base"], None, true);
        w.allowed_args = true;
        let (argv, _) = effective_workload(&start_req(&["--extra", "x"], false), &w)
            .expect("allowed_args appends");
        assert_eq!(argv, vec!["/launcher", "--base", "--extra", "x"]);
    }

    #[test]
    fn effective_workload_pinned_allowed_args_no_cli_is_just_the_pin() {
        let mut w = workload(&["/launcher"], None, true);
        w.allowed_args = true;
        let (argv, _) = effective_workload(&start_req(&[], false), &w).expect("bare pin");
        assert_eq!(argv, vec!["/launcher"]);
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
                stdio_fds: None,
                aux: Vec::new(),
                ttl_seconds: None,
                ttl_action: kennel_lib_policy::TtlAction::Exit,
            };
            let net = NetPolicy {
                mode: kennel_lib_policy::NetMode::Constrained,
                udp: false,
                udp_allow_names: Vec::new(),
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
                consumes: Vec::new(),
                provides: Vec::new(),
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
                cwd: kennel_lib_policy::settled::CwdPolicy::default(),
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
                scope: ReservedScope::new(9),
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
    fn no_enablement_means_no_providers_and_no_activator() {
        // With no enablement set (the default loader), both provider accessors are empty and the
        // lazy-provider activator is unset until `serve` wires it — so a `SVC_CONNECT` resolves to no
        // provider and nothing is socket-activated.
        let s = shared();
        assert!(s.autorun_providers().is_empty(), "no autorun set");
        assert!(
            s.ondemand_provider("anything").is_none(),
            "no ondemand provider"
        );
        assert!(
            s.activator().is_none(),
            "no activator until serve() wires it"
        );
    }

    #[test]
    fn prepare_unix_materialises_an_af_unix_consume_as_a_facade_shim() {
        use kennel_lib_policy::settled::Shape;
        let s = shared();
        let subst = RuntimeSubstitutions {
            ctx: 1,
            uid: 1000,
            kennel: "t".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-test".to_owned(),
        };
        let consume = |name: &str, shape: Shape, at: Option<&str>, env: &[&str]| {
            kennel_lib_policy::ConsumeRuntime {
                name: name.to_owned(),
                shape,
                at: at.map(ToOwned::to_owned),
                env: env.iter().copied().map(str::to_owned).collect(),
                key: None,
                required: true,
            }
        };
        let consumes = vec![
            // af-unix + `at` → a facade shim brokered by capability name, plus its env var.
            consume(
                "org.projectkennel.wayland",
                Shape::AfUnix,
                Some("/run/kennel/wl.sock"),
                &["WAYLAND_PROXY"],
            ),
            // A non-af-unix shape is not an af-unix socket → no shim here.
            consume(
                "org.acme.bus",
                Shape::DbusName,
                Some("/run/kennel/bus"),
                &[],
            ),
            // af-unix with no `at` is resolvable-only → no in-view socket.
            consume("org.acme.nowhere", Shape::AfUnix, None, &[]),
        ];
        let prep = s.prepare_unix(
            &kennel_lib_policy::UnixRuntime::default(),
            &consumes,
            &subst,
            &PathBuf::from("/home/dev"),
        );
        assert_eq!(
            prep.shims.len(),
            1,
            "only the af-unix consume with an `at` materialises a shim"
        );
        let shim = prep.shims.first().expect("one shim");
        assert_eq!(shim.name, "org.projectkennel.wayland");
        assert_eq!(shim.shim_path, PathBuf::from("/run/kennel/wl.sock"));
        assert!(
            prep.env
                .contains(&("WAYLAND_PROXY".to_owned(), "/run/kennel/wl.sock".to_owned())),
            "the consume's env var names its `at` socket"
        );
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

    #[test]
    fn mesh_bus_key_includes_tier_name_and_optional_key() {
        use crate::catalogue::Tier;
        assert_eq!(
            super::mesh_bus_key(Tier::User, "org.x.wl", None),
            "user/org.x.wl"
        );
        assert_eq!(
            super::mesh_bus_key(Tier::Host, "org.x.wl", Some("K1")),
            "host/org.x.wl.K1"
        );
    }
}
