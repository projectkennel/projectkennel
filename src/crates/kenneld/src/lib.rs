//! Project Kennel orchestration core.
//!
//! [`start`] brings a kennel up and [`Kennel::stop`] tears it down. The bring-up
//! sequence mirrors `08-enforcement-architecture.md` §8.3, minus the supporting
//! daemons (not built yet):
//!
//! 1. create the kennel's cgroup (kenneld owns its delegated `user@<uid>`
//!    subtree, so this is unprivileged — see §8.5 and the cgroup-join note on
//!    [`kennel_lib_spawn`]);
//! 2. add the per-kennel loopback addresses (privileged — via the helper);
//! 3. load + attach the egress BPF programs to the cgroup (privileged);
//! 4. spawn the workload, which joins the cgroup in its seal.
//!
//! Every privileged step goes through the [`Privileged`] trait, whose production
//! implementation ([`HelperClient`]) drives the setuid privhelper. If any step
//! fails, the partial bring-up is unwound in reverse (`teardown`), so a failed
//! `start` leaves no addresses or cgroup behind.
//!
//! This crate holds no `unsafe` (`#![forbid(unsafe_code)]`): privilege is
//! borrowed transiently through the helper, and the workload syscalls route
//! through `kennel-lib-spawn`/`kennel-lib-syscall`.

#![forbid(unsafe_code)]

pub mod audit;
pub mod bastion;
pub mod binder;
pub mod bpf_audit;
pub mod broker;
pub mod catalogue;
pub mod cgroup;
pub mod ctx;
pub mod dbus;
pub mod enablement;
pub mod etc;
pub mod inbound;
pub mod inet;
pub mod mesh;
pub mod mesh_bus;
pub mod policy;
pub mod prompt;
pub mod proxy;
pub mod pty_broker;
pub mod server;
pub mod spawn;
pub mod ssh;
pub mod sshd;
pub mod supervisor;
pub mod tripwire;

// The control-socket wire protocol now lives in its own crate so the unprivileged
// `kennel` CLI can link it without the daemon's enforcement code. Re-exported here
// so the daemon's `crate::control` / `crate::socket` (and `kenneld::*` from the
// `kenneld`/`kennel-akc` binaries) keep resolving unchanged.
pub use kennel_lib_control::{control, socket};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use kennel_lib_policy::{NetMode, NetPolicy};
use kennel_lib_spawn::{Plan, ProxyEndpoint, SpawnError};
use kennel_lib_syscall::namespace::Namespaces;
use kennel_privhelper::addr::{loopback_v4, loopback_v6, V4_PREFIX, V6_PREFIX};
use kennel_privhelper::validate::ReservedScope;
use kennel_privhelper::wire::{EgressPayload, Response};

/// The default proxy host offset within the kennel's subnet (`…|0001` / `::1`).
///
/// Mirrors what [`kennel_lib_policy::ProxyListen::default`] resolves to; the live
/// offset comes from the signed policy (`net.proxy.offset`). The reference the
/// tests compute against.
pub const PROXY_HOST: u8 = 1;

/// The default TCP port the per-kennel egress proxy listens on.
///
/// Mirrors what [`kennel_lib_policy::ProxyListen::default`] resolves to; the live
/// port comes from the signed policy (`net.proxy.port`).
pub const PROXY_PORT: u16 = 1080;

/// The loopback interface the per-kennel addresses live on.
const LOOPBACK: &str = "lo";

/// Everything that can stop a kennel coming up.
#[derive(Debug)]
pub enum Error {
    /// A filesystem operation (cgroup create/remove) failed.
    Io(io::Error),
    /// The workload could not be spawned.
    Spawn(SpawnError),
    /// The egress dial delegate process could not be launched.
    Proxy(io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cgroup filesystem operation failed: {e}"),
            Self::Spawn(e) => write!(f, "workload spawn failed: {e}"),
            Self::Proxy(e) => write!(f, "egress dial delegate could not be launched: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Proxy(e) => Some(e),
            Self::Spawn(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The privileged operations kenneld borrows from the helper. Abstracted so the
/// orchestration sequence and its unwind are testable without root or the real
/// setuid binary.
pub trait Privileged {
    /// Remove `addr/prefix` on `interface` for kennel `ctx` (teardown). The per-kennel
    /// loopback *adds* and the egress-BPF *attach* are folded into the factory's one
    /// `construct_kennel` op, so the only standalone privileged op left is this teardown del.
    ///
    /// # Errors
    /// An OS error if the helper cannot be invoked or its response is malformed.
    fn del_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response>;

    /// Construct a kennel via the privhelper **factory** (`07-2`): hand it the
    /// `construction_half` bytes and (optionally) the pty socket; receive the long-lived
    /// supervisor [`Child`] and `kennel-bin-init`'s host pid. The privhelper resolves and opens
    /// `kennel-bin-init` itself from root-owned config (never the wire), so it is not passed here.
    ///
    /// Defaults to an error: only the production [`HelperClient`] drives the real factory.
    ///
    /// # Errors
    /// An OS error if the factory cannot be invoked, or [`io::ErrorKind::Unsupported`]
    /// for an impl that does not support construction.
    fn construct_kennel(
        &self,
        _construction_half: &[u8],
        _egress: Option<&[u8]>,
        _pty_fd: Option<std::os::fd::RawFd>,
        _workload_fd: Option<std::os::fd::RawFd>,
        _stdio_fds: Option<[std::os::fd::RawFd; 3]>,
    ) -> io::Result<(Child, i32, std::os::fd::OwnedFd)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "factory construction not supported by this Privileged impl",
        ))
    }

    /// Release (unmount) an exclusive over-mount at `host` (§2.7) — the teardown / `kennel
    /// release` counterpart to the factory's exclusive over-mount. The *mount* rides the
    /// `construct` factory; only the release is a standalone op (it happens at teardown, or on
    /// crash recovery). Defaults to a no-op-`Ok` for impls without a real helper (tests).
    ///
    /// # Errors
    /// An OS error if the helper cannot be invoked or refuses.
    fn release_exclusive(&self, _host: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// The production [`Privileged`] implementation: each call invokes the installed
/// setuid privhelper once.
#[derive(Debug, Clone)]
pub struct HelperClient {
    helper: PathBuf,
}

impl HelperClient {
    /// Use the privhelper at `helper` (resolved from the deployment config by
    /// the daemon; see [`kennel_lib_config::Deployment::privhelper`]).
    pub fn new(helper: impl Into<PathBuf>) -> Self {
        Self {
            helper: helper.into(),
        }
    }
}

impl Privileged for HelperClient {
    fn del_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response> {
        kennel_privhelper::client::del_address(&self.helper, ctx, interface, addr, prefix)
    }

    fn release_exclusive(&self, host: &Path) -> io::Result<()> {
        kennel_privhelper::client::release_exclusive(&self.helper, host)
    }

    fn construct_kennel(
        &self,
        construction_half: &[u8],
        egress: Option<&[u8]>,
        pty_fd: Option<std::os::fd::RawFd>,
        workload_fd: Option<std::os::fd::RawFd>,
        stdio_fds: Option<[std::os::fd::RawFd; 3]>,
    ) -> io::Result<(Child, i32, std::os::fd::OwnedFd)> {
        kennel_privhelper::client::construct_kennel(
            &self.helper,
            construction_half,
            egress,
            pty_fd,
            workload_fd,
            stdio_fds,
        )
    }
}

/// How to launch a kennel's egress proxy.
///
/// The `host-netproxy` binary plus the directory its per-kennel config is
/// written to. `None` in [`Spec::proxy`] skips the proxy entirely (unit tests, or
/// a setup that does not run one).
#[derive(Debug, Clone)]
pub struct ProxySetup {
    /// The `host-netproxy` dial-delegate binary (host side) to launch.
    pub binary: PathBuf,
    /// Directory the per-kennel conduit command socket is bound in.
    pub config_dir: PathBuf,
    /// The `facade-socks5` binary bound into the view and launched by the seal: the workload's
    /// in-kennel SOCKS5 endpoint, which brokers each connect to node 0 as `CONNECT_INET`.
    pub socks5: PathBuf,
    /// The `host-inetd` inbound BIND-delegate binary (host side) to launch for the §7.5.7 mirror:
    /// it binds each policy-mirrored port on the host loopback and pushes accepted conduits back.
    pub inetd: PathBuf,
    /// The `facade-client` binary bound into the view and launched by the seal: the in-kennel end
    /// that pulls inbound conduits (`BIND_INET`) and connects the workload's native listener.
    pub facade_client: PathBuf,
}

/// What the synthetic `/etc` is built from: where to stage it and the workload's
/// identity (the kennel name becomes the hostname). `None` in [`Spec::etc`] skips
/// the synthetic `/etc` (unit tests).
#[derive(Debug, Clone)]
pub struct EtcSetup {
    /// Directory the per-kennel `/etc` files are written to (then bind-mounted).
    pub staging_dir: PathBuf,
    /// The workload's masked user name (`[identity].user`, default `kennel`): the
    /// synthetic `/etc/passwd` account.
    pub account: String,
    /// The workload's masked primary-group name (`[identity].group`, default
    /// `kennel`): the synthetic `/etc/group` name for the primary gid.
    pub account_group: String,
    /// The kennel's hostname (its runtime name).
    pub hostname: String,
    /// The workload's uid.
    pub uid: u32,
    /// The workload's gid.
    pub gid: u32,
    /// The workload's in-kennel home (the shim `$HOME`).
    ///
    /// Written as the `passwd` home field — never the operator's real home, which the
    /// synthetic `/etc` masks along with the account name (`kennel`).
    pub home: PathBuf,
    /// The granted supplementary groups `(name, gid)` (§7.4) — named in `/etc/group`
    /// so they resolve by name; these are the gids the seal `setgroups` to. Empty by
    /// default (the kennel carries no supplementary groups unless policy grants them).
    pub groups: Vec<(String, u32)>,
    /// The kennel's login shell (§7.9.2a) — the `passwd` `pw_shell` field. `/bin/sh`
    /// unless the policy set `[exec].shell`.
    pub shell: String,
    /// Home-relative paths the dotfile seeder must NOT reconstruct (§7.9.2a
    /// `[fs.home].persist`). Empty ⇒ every synthesised dotfile is reconstructed.
    pub home_persist: Vec<String>,
}

/// What kenneld needs to run a kennel's binder context manager (§7.1): the settled
/// binder policy the registry gates against and the audit writer it records
/// `binder.*` decisions through.
pub struct BinderPrep {
    /// The user-defined services this kennel may register / look up.
    pub policy: kennel_lib_policy::BinderRuntime,
    /// The `[[unix.allow]]` grants the af-unix facade resolves and connects (§7.6 via
    /// the binder facade). Empty when the kennel grants no `AF_UNIX` socket.
    pub unix: kennel_lib_policy::UnixRuntime,
    /// The unified audit writer the registry emits through.
    pub writer: std::sync::Arc<kennel_lib_audit::Writer>,
    /// The `kennel-bin-init` binary the privhelper factory `fexecve`s as the kennel's uid-0
    /// PID 1 (`07-2`). When `Some`, `bring_up` constructs the kennel via the factory
    /// (real uid 0, binderfs chowned to the operator); when `None`, it falls back to the
    /// legacy in-process unprivileged spawn (no real uid 0 — the binderfs `EACCES` path).
    pub init_bin: Option<PathBuf>,
    /// The operator-prompt channel (§9.7): a clone of the control connection the TTL `renew`
    /// action prompts over. `None` for a non-interactive run (no operator to ask).
    pub prompt: Option<crate::prompt::PromptPort>,
    /// The `[spawn]` runtime (§7.12): the grant, the trust keys, and the template cascade the node-0
    /// `SPAWN` handler validates against. `None` for a kennel with no `[spawn]` grant (a `SPAWN` from
    /// it is denied). An `Arc` so the binder looper pool shares one immutable copy.
    pub spawn: Option<std::sync::Arc<crate::spawn::SpawnRuntime>>,
    /// This kennel's signed `[[consumes]]` (§7.13.1) — the floor the node-0 `SVC_CONNECT` broker
    /// matches a consume request against (request-don't-author). Empty when the kennel consumes nothing.
    pub consumes: Vec<kennel_lib_policy::ConsumeRuntime>,
    /// The daemon's live service catalogue (§7.13.4) the `SVC_CONNECT` broker resolves a consume
    /// against. `None` for a construction path with no catalogue (a `SVC_CONNECT` then resolves
    /// nothing).
    pub catalogue: Option<std::sync::Arc<std::sync::Mutex<crate::catalogue::Catalogue>>>,
    /// The lazy-provider socket-activator (§7.13.6): the broker activates an `ondemand` provider
    /// through this when a `SVC_CONNECT` resolves to a not-yet-running one. `None` on a construction
    /// path with no activator (a test path) — a `Pending` consume then waits out the deadline.
    pub activator: Option<std::sync::Arc<dyn crate::supervisor::ProviderActivator>>,
    /// Brokered D-Bus transactor for the standing dbus-broker service kennel.
    pub dbus_transactor: Option<std::sync::Arc<dyn crate::dbus::MeshTransactor>>,
}

/// Everything needed to bring one kennel up.
pub struct Spec {
    /// The kennel's runtime id (`<id>` in `07-paths.md`; equal to the kennel name
    /// after substitution). Names the BPF pin dir in the owner's runtime tree
    /// (`/run/user/<uid>/kennel/bpf/<id>/`).
    pub id: String,
    /// The kennel's cgroup, under kenneld's delegated subtree. kenneld creates it
    /// (unprivileged) and the workload joins it; the helper attaches BPF to it.
    pub cgroup: PathBuf,
    /// The kennel's context number (assigned by the daemon's allocator).
    pub ctx: u16,
    /// The caller's reserved scope (tag + ULA GID), used to build the addresses.
    pub scope: ReservedScope,
    /// The verified, substituted enforcement plan. Its `cgroup` is overridden
    /// with [`cgroup`](Self::cgroup) (the runtime path) before spawn.
    pub plan: Plan,
    /// The network policy the per-kennel egress proxy is configured from.
    pub net: NetPolicy,
    /// How to launch the egress proxy, or `None` to skip it.
    pub proxy: Option<ProxySetup>,
    /// How to build the synthetic `/etc`, or `None` to skip it.
    pub etc: Option<EtcSetup>,
    /// The host staging mountpoint the constructed-view seal builds its fresh
    /// tmpfs root on and `pivot_root`s into (under `$XDG_RUNTIME_DIR`, outside
    /// `/tmp`). Used only when [`plan`](Self::plan) carries a shim view; `None`
    /// (or a view-less plan) keeps the in-place fallback seal. kenneld creates it
    /// at bring-up and removes it at teardown.
    pub view_root: Option<PathBuf>,
    /// The prepared SSH egress (§7.10): the synthetic `~/.ssh` binds, the bastion
    /// host-service to allow, and the in-kennel connector to bind in. Empty
    /// ([`SshPrep::default`]) for a kennel with no `[ssh]` grant.
    pub ssh: SshPrep,
    /// The prepared `AF_UNIX` socket shims (§7.6): host sockets to bind into the view
    /// at their shim paths, plus any env vars to set. Empty ([`UnixPrep::default`])
    /// for a kennel with no `[unix]` grant.
    pub unix: UnixPrep,
    /// The prepared D-Bus mediation (§7.7): the enabled buses, their compiled tables, the
    /// in-view facade sockets, and the delegate/facade binaries. Empty ([`DbusPrep::default`])
    /// for a kennel with no `[dbus]` grant.
    pub dbus: DbusPrep,
    /// The prepared binder IPC context manager (§7.1): the settled binder policy and
    /// the audit writer. `None` for a kennel with no `[binder]` grant (no context
    /// manager is run; the seal still mounts no binderfs because the plan's view
    /// `binder` flag is false in that case).
    pub binder: Option<BinderPrep>,
    /// The prepared OCI substrate launch (§7.11): the launcher + image `config.json` to bind
    /// in when the image's own entrypoint is run. Empty ([`OciPrep::default`]) otherwise.
    pub oci: OciPrep,
    /// Spawn-path diagnostic tracer (the `log_level` knob): `bring_up` traces each
    /// step (egress, view, factory construct, boot-sync, proxy, binder node 0) through
    /// it. No-op at the default `info`.
    pub tracer: kennel_lib_config::Tracer,
}

/// One granted `AF_UNIX` socket the in-kennel proxy presents (§7.6).
#[derive(Debug, Clone)]
pub struct UnixShim {
    /// The logical service name (`[[unix.allow]]` `name`) the proxy brokers through the
    /// binder facade; the facade resolves it to the real host socket.
    pub name: String,
    /// The in-view absolute path the proxy listens at, where the application connects.
    pub shim_path: PathBuf,
}

/// The `AF_UNIX` socket shims prepared for one kennel (§7.6 via the binder facade).
///
/// Built by `crate::server::Shared::prepare_unix` (path placeholders resolved) and
/// consumed by the bring-up: the `facade-afunix` proxy is bound into the view and
/// launched by the seal; it listens at each shim path so the application finds the
/// socket where it expects, and on connect brokers to the `org.projectkennel.IAfUnix`
/// binder facade (kenneld), which resolves the name to the real host socket and returns
/// a connected fd (`07-1` §7.1.5). The workload never holds a path into the host
/// `AF_UNIX` namespace. Any named env var is set to the in-kennel shim path. What is not
/// granted is structurally absent (default-deny); abstract-namespace connections are
/// denied by the always-on Landlock scope regardless.
#[derive(Debug, Default, Clone)]
pub struct UnixPrep {
    /// The granted sockets the proxy presents and brokers.
    pub shims: Vec<UnixShim>,
    /// `(env var, value)` pairs set on the workload — the in-kennel shim path the
    /// application reads (e.g. `WAYLAND_DISPLAY`).
    pub env: Vec<(String, String)>,
    /// The host path of `facade-afunix` to bind into the view and launch as the
    /// in-kennel broker (§7.6 via the binder facade). `None` (no deployment binary)
    /// leaves the grants unserved rather than falling back to a host-socket bind mount.
    pub afunix_bin: Option<PathBuf>,
}

/// The D-Bus mediation prepared for one kennel (§7.7).
///
/// Built by `crate::server::Shared::prepare_dbus` and consumed by the bring-up: per enabled bus,
/// `apply_dbus` binds `facade-dbus` into the view (it terminates the workload's bus connection at
/// the in-view `listen_path` and frames typed transactions onto binder node 0) and points the
/// workload's `DBUS_*_BUS_ADDRESS` there; `spawn_dbus_delegates` launches the operator-context
/// `host-dbus` delegate (holding the real bus at `bus_address` and applying the compiled table)
/// and wires its owner-only pipe to the per-kennel [`crate::dbus::DbusRelay`]. Empty
/// ([`DbusPrep::default`]) for a kennel with no `[dbus]` grant.
#[derive(Debug, Default, Clone)]
pub struct DbusPrep {
    /// The session bus, if enabled by policy.
    pub session: Option<DbusBusPrep>,
    /// The system bus, if enabled by policy.
    pub system: Option<DbusBusPrep>,
    /// The host path of `facade-dbus` (in-kennel, bound into the view). `None` ⇒ no facade binary
    /// configured: the grants go unserved (fail-closed, no host bus socket exposed otherwise).
    pub facade_bin: Option<PathBuf>,
    /// The host path of `host-dbus` (the operator-context delegate). `None` ⇒ no delegate: the
    /// relay is not constructed and the membrane denies every D-Bus verb.
    pub host_bin: Option<PathBuf>,
    /// The host directory the per-bus `host-dbus` command sockets are bound in.
    pub cmd_dir: PathBuf,
}

/// One enabled bus's mediation inputs (§7.7).
#[derive(Debug, Clone)]
pub struct DbusBusPrep {
    /// The compiled allow/deny table `host-dbus` enforces (talk/call/broadcast/own/deny-talk).
    pub rules: kennel_lib_policy::DbusBusRuntime,
    /// The operator's real bus address `host-dbus` connects to (e.g. `unix:path=/run/user/<uid>/bus`).
    pub bus_address: String,
    /// The in-view socket path `facade-dbus` binds; the workload's `DBUS_*_BUS_ADDRESS` points here.
    pub listen_path: PathBuf,
}

/// The SSH egress prepared for one kennel (§7.10).
///
/// Built by `crate::server::Shared::register_ssh` and consumed by the bring-up: it
/// carries the synthetic `~/.ssh` to lay into the view, the bastion endpoint to
/// allow through the egress proxy, and the connector binary the kennel's `ssh`
/// invokes as its `ProxyCommand`.
#[derive(Debug, Default, Clone)]
pub struct SshPrep {
    /// `(host source, in-kennel target)` pairs for the synthetic `~/.ssh` files
    /// (`config`, `known_hosts`, the synthetic keys), copied into the constructed view.
    pub file_binds: Vec<(PathBuf, PathBuf)>,
    /// The bastion's loopback endpoint, allowed as a host-loopback service so the
    /// egress proxy forwards the kennel's SSH to it (§7.5 host services).
    pub host_service: Option<SocketAddr>,
    /// The host path of `facade-ssh`, bound into the view (read+execute)
    /// so the synthetic `config`'s `ProxyCommand` can run it. `None` when no SSH.
    pub ssh_bin: Option<PathBuf>,
}

/// The in-view path kenneld binds an OCI image's `config.json` at, and passes the
/// launcher as `argv[1]` (§7.11). Under `/run/kennel/`, the runtime tree the launcher
/// reads from, not the image.
pub const OCI_CONFIG_VIEW_PATH: &str = "/run/kennel/oci-config.json";

/// The prepared OCI substrate launch (§7.11 / T3.8): how kenneld runs the image's own entrypoint.
///
/// Set only when the policy is OCI-model (`[rootfs]`) **and** no explicit argv was given — then
/// the workload-side launcher (`kennel-bin-oci-entry`) is `argv[0]`, bound read-only into the view
/// with the image `config.json`, and parses the config to `execve` the entrypoint in-root. Empty
/// ([`OciPrep::default`]) for a non-OCI run, or an OCI run given an explicit `-- <cmd>`/
/// `[workload].argv` (which runs in-root without the launcher).
#[derive(Debug, Default, Clone)]
pub struct OciPrep {
    /// The host path of the trusted launcher (`kennel-bin-oci-entry`, resolved from the
    /// root-owned config cascade, never the wire), bound at its own path and run as `argv[0]`.
    pub launcher_bin: Option<PathBuf>,
    /// The host path of the store entry's `config.json`, bound read-only at
    /// [`OCI_CONFIG_VIEW_PATH`] for the launcher to read.
    pub config_src: Option<PathBuf>,
}

/// A running kennel: the workload plus what must be torn down when it stops.
#[derive(Debug)]
pub struct Kennel {
    /// `kennel-bin-init`'s host pid. The privhelper factory exits as soon as it has reported
    /// this (it is not a reaper proxy); the orphaned init reparented to kenneld (a
    /// `set_child_subreaper`), so kenneld `waitpid`s this pid directly for the workload's
    /// exit status (`07-2`).
    init_pid: i32,
    cgroup: PathBuf,
    ctx: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// The egress-proxy child, if one was launched. Killed and reaped on teardown.
    proxy: Option<Child>,
    /// The inbound BIND delegate child (`host-inetd`, §7.5.7), if one was launched. Killed and
    /// reaped on teardown — its accept loops and the per-port reader threads end with it.
    inetd: Option<Child>,
    /// The D-Bus mediation delegate children (`host-dbus`, one per enabled bus, §7.7.2b), if any
    /// were launched. Killed and reaped on teardown — kenneld's inbound reader threads end with the
    /// pipes the delegates close.
    dbus: Vec<Child>,
    /// The constructed-view staging mountpoint, if one was created. Removed on
    /// teardown (the tmpfs mounted on it lived in the workload's now-gone mount
    /// namespace, so only the empty host directory remains).
    view_root: Option<PathBuf>,
    /// The per-kennel binder context manager, if the kennel uses binder. Its serve
    /// thread is stopped at teardown (its node-0 fd and mapping go with it; the
    /// binderfs instance itself died with the workload's mount namespace).
    binder: Option<crate::binder::Manager>,
    /// The spawn-path tracer, carried from bring-up so `stop` stamps the teardown
    /// span with the same `[t=<nanos>]` milestones (teardown is a
    /// first-class span; a slow reclaim makes spawn rates teardown-limited).
    tracer: kennel_lib_config::Tracer,
}

impl Kennel {
    /// `kennel-bin-init`'s host process id.
    #[must_use]
    pub fn id(&self) -> u32 {
        u32::try_from(self.init_pid).unwrap_or(0)
    }

    /// The kennel's cgroup path.
    #[must_use]
    pub fn cgroup(&self) -> &Path {
        &self.cgroup
    }

    /// Force the workload to exit (`SIGKILL`), for a forced shutdown. Best-effort
    /// — a workload that has already exited is fine. Follow with [`stop`] to reap
    /// it and release the kennel's resources.
    ///
    /// [`stop`]: Self::stop
    ///
    /// # Errors
    /// An OS error if signalling fails for a reason other than the child being
    /// gone.
    pub fn terminate(&mut self) -> io::Result<()> {
        // Kill via the cgroup first: with the unprivileged spawn the workload is PID
        // 1 of a nested PID namespace behind a double-fork, so `self.child` is the
        // intermediate init — killing it by hand would leave the workload running.
        // `cgroup.kill` reaches every member (the init, the workload, descendants).
        // Best-effort: a pre-5.14 kernel or an already-removed cgroup falls through
        // to signalling the handle (which also covers the no-cgroup unit-test path).
        let via_cgroup = cgroup::kill_cgroup(&self.cgroup).is_ok();
        match kennel_lib_syscall::process::kill_pid(self.init_pid) {
            Ok(()) => Ok(()),
            // The cgroup kill succeeded; a failure to also signal the (already dying) init
            // is not fatal.
            Err(e) if via_cgroup => {
                let _ = e;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check whether the kennel has exited, without blocking. `Some(code)` once it has
    /// (the exit code, or `128 + signal`), `None` while it is still running.
    ///
    /// # Errors
    /// An OS error if the status check fails.
    pub fn try_finished(&mut self) -> io::Result<Option<i32>> {
        kennel_lib_syscall::process::try_wait_pid(self.init_pid)
    }

    /// Wait for the workload to exit, then tear the kennel down: remove the
    /// loopback addresses and the cgroup (which also detaches the egress BPF).
    /// Does not signal the workload — call [`terminate`](Self::terminate) first
    /// for a forced stop. Cleanup is best-effort; returns the workload's exit
    /// status.
    ///
    /// # Errors
    /// An OS error if waiting on the workload fails.
    pub fn stop<P: Privileged>(mut self, privileged: &P) -> io::Result<i32> {
        let status = kennel_lib_syscall::process::wait_pid(self.init_pid)?;
        self.tracer
            .step("teardown: workload exited; stopping binder + reclaiming resources");
        if let Some(manager) = self.binder.take() {
            manager.stop();
        }
        teardown(
            self.tracer,
            privileged,
            self.ctx,
            Some(self.cgroup.as_path()),
            self.v4,
            self.v6,
            self.proxy.take(),
            self.inetd.take(),
            std::mem::take(&mut self.dbus),
            self.view_root.as_deref(),
        );
        Ok(status)
    }

    // TTL is enforced inside the kennel now (§9.7): `kennel-bin-init` runs the timer and makes the
    // blocking `NOTIFY_TTL_EXPIRED` call that kenneld's node-0 handler services (freeze + decide
    // per `ttl_action`). So there is no external poll/reaper here — `stop` is a plain wait, and
    // on the `exit` action the handler kills the frozen cgroup, which that wait observes.
}

/// Kill and reap an egress-proxy child (best-effort; an already-exited proxy is
/// fine). `kill` on a gone process returns `InvalidInput`, which we ignore.
fn reap_proxy(proxy: Option<Child>) {
    if let Some(mut child) = proxy {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// What bring-up has provisioned so far, for unwind.
#[derive(Default)]
struct Provision {
    made_cgroup: bool,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    proxy: Option<Child>,
    inetd: Option<Child>,
    dbus: Vec<Child>,
    view_root: Option<PathBuf>,
    binder: Option<crate::binder::Manager>,
    /// The kennel was built by the privhelper factory (the returned `Child` is the
    /// factory supervisor, not an in-process spawn). Records which path ran, for unwind
    /// and diagnostics.
    factory: bool,
}

/// Bring a kennel up. On any error the partial bring-up is unwound, so no
/// addresses or cgroup are left behind.
///
/// `command` is the (already-confined-by-`plan`) workload to spawn.
///
/// # Errors
/// Returns [`Error`] at the first failing step (filesystem, a refused/failed
/// privileged operation, or the spawn).
pub fn start<P: Privileged + Sync>(
    privileged: &P,
    spec: Spec,
    command: &mut Command,
) -> Result<Kennel, Error> {
    let Spec {
        id,
        cgroup,
        ctx,
        scope,
        mut plan,
        net,
        proxy,
        etc,
        view_root,
        ssh,
        unix,
        dbus,
        binder,
        oci,
        tracer,
    } = spec;
    let mut state = Provision::default();

    match bring_up(
        privileged,
        &id,
        &cgroup,
        ctx,
        &scope,
        &mut plan,
        &net,
        proxy.as_ref(),
        etc.as_ref(),
        view_root.as_deref(),
        &ssh,
        &unix,
        &dbus,
        binder.as_ref(),
        &oci,
        tracer,
        command,
        &mut state,
    ) {
        Ok(init_pid) => Ok(Kennel {
            init_pid,
            cgroup,
            ctx,
            v4: state.v4,
            v6: state.v6,
            proxy: state.proxy,
            inetd: state.inetd,
            dbus: state.dbus,
            view_root: state.view_root,
            binder: state.binder,
            tracer,
        }),
        Err(e) => {
            if let Some(manager) = state.binder.take() {
                manager.stop();
            }
            teardown(
                tracer,
                privileged,
                ctx,
                state.made_cgroup.then_some(cgroup.as_path()),
                state.v4,
                state.v6,
                state.proxy,
                state.inetd,
                std::mem::take(&mut state.dbus),
                state.view_root.as_deref(),
            );
            Err(e)
        }
    }
}

/// The bring-up steps, recording provisioning into `state` as it goes.
// allow: one ordered bring-up sequence (cgroup, addresses, egress, proxy, /etc, ssh,
// unix, view, spawn) whose steps share `state` for the reverse-order unwind.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn bring_up<P: Privileged + Sync>(
    privileged: &P,
    id: &str,
    cgroup: &Path,
    ctx: u16,
    scope: &ReservedScope,
    plan: &mut Plan,
    net: &NetPolicy,
    proxy: Option<&ProxySetup>,
    etc: Option<&EtcSetup>,
    view_root: Option<&Path>,
    ssh: &SshPrep,
    unix: &UnixPrep,
    dbus: &DbusPrep,
    binder: Option<&BinderPrep>,
    oci: &OciPrep,
    tracer: kennel_lib_config::Tracer,
    command: &mut Command,
    state: &mut Provision,
) -> Result<i32, Error> {
    // 1. cgroup (unprivileged: within kenneld's delegated subtree).
    std::fs::create_dir_all(cgroup)?;
    state.made_cgroup = true;
    // Per-kennel process ceiling: bounds a fork-bomb or facade-driven thread explosion to this one
    // kennel. Best-effort — no-ops where the daemon could not delegate the `pids` controller (see
    // cgroup::prepare_delegation); the kenneld.service TasksMax remains the host backstop.
    if let Err(e) = cgroup::write_pids_max(cgroup, cgroup::DEFAULT_PIDS_MAX) {
        eprintln!(
            "kenneld: warning: pids.max not applied to {}: {e}",
            cgroup.display()
        );
    }

    // 2. loopback addresses. The proxy's listen offset + port come from the signed
    //    policy (`net.proxy`); offset 1 / port 1080 by default. v4 only when ctx
    //    fits the 8-bit field it carries; a higher ctx is a v6-only kennel.
    let offset = net.proxy.offset;
    let port = net.proxy.port;
    // Compute the per-kennel loopback addresses — but only for the **proxied** modes, which
    // run a SOCKS facade on a per-kennel loopback alias. `none` (own empty netns, no
    // interfaces) and `open` (host netns, direct egress, no proxy) get no alias. The factory
    // adds them on `lo` itself (folded into the one construct op — it re-validates each against
    // the caller's reserved subnet); here we only collect them for the construction-half and
    // record them in `state` for teardown's `del_address`.
    // `addr6` is always computed (used as the v6 listen/etc address below) but the loopback
    // aliases are only ADDED for the proxied modes, which run a SOCKS facade on them. `none`
    // and `open` add no alias (own empty netns / host netns direct).
    let proxied = matches!(net.mode, NetMode::Constrained | NetMode::Unconstrained);
    // The "do less" provisioning — the egress proxy lives on the kennel's OWN loopback (`127.0.0.1`/`::1`, which
    // the kernel hands `lo` once it is up, isolated by the kennel's net-ns), so the facade, the
    // BPF proxy-reach stamp, and resolv all use it. A per-kennel address is needed ONLY when an
    // inbound bind mirror consumes it (§7.5.7): `[net.bind]`-bound services bind their distinct
    // address so `host-inetd` can expose it host-side. So provision addresses only when there is a
    // bind — the empty-bind-list path (100% of ephemeral tool spawns) gets no address at all.
    let mirror_ports = mirror_bind_ports(net);
    let mut loopback: Vec<kennel_lib_spawn::LoopbackAddr> = Vec::new();
    if proxied && !mirror_ports.is_empty() {
        let addr6 = loopback_v6(scope.ula_gid(), ctx, u64::from(offset));
        if let Ok(c) = u8::try_from(ctx) {
            let addr = loopback_v4(scope.tag(), c, offset);
            loopback.push(kennel_lib_spawn::LoopbackAddr {
                addr: addr.into(),
                prefix: V4_PREFIX,
            });
            state.v4 = Some(addr);
        }
        loopback.push(kennel_lib_spawn::LoopbackAddr {
            addr: addr6.into(),
            prefix: V6_PREFIX,
        });
        state.v6 = Some(addr6);
    }

    // `none` mode: an own empty net namespace (NET unshared in the plan), no interfaces, no
    // proxy, no egress BPF. The entire host-side network bring-up — proxy stamp, BPF payload,
    // loopback adds, delegate launch — is skipped: there is nothing to gate when there is no
    // network. Every INet request is refused (`NetRuntime::denied()`), and the empty
    // `egress_bytes` tells the factory to attach no programs.
    let no_network = net.mode == NetMode::None;

    // The cgroup egress BPF is the PRIMARY egress gate ONLY in `host` mode (shared host stack, no
    // proxy — `07-5` §"cgroup BPF connect"). In `none`/`constrained`/`unconstrained` the per-kennel
    // net-ns IS the boundary: the empty/loopback-only stack already denies every non-shim
    // destination, the inbound mirror is binder-driven (not BPF), and egress audit comes from
    // kenneld's INet path — so the BPF there is pure (optional) defence-in-depth. We skip its attach
    // outside `host`: it costs ~7–10 ms/spawn (almost all of it the `BPF_PROG_LOAD` verifier), and
    // agent spawns never use `host` mode, so they never pay it. `bpf_audit::spawn` no-ops on
    // the now-absent pin.
    let bpf_egress = net.mode == NetMode::Host;

    // Stamp the egress proxy into the plan before deriving the BPF payload — proxied modes
    // only. This adds the flagged allow-entry that lets the workload reach its proxy (and
    // records the proxy in kennel_meta); without it the BPF would deny the proxy too.
    if proxy.is_some() && !no_network {
        // The facade listens on the kennel's own loopback (`127.0.0.1`/`::1`), so the BPF must
        // permit the workload to reach it there — not a per-kennel address.
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(std::net::Ipv4Addr::LOCALHOST),
            v6: std::net::Ipv6Addr::LOCALHOST,
            port,
        });
    }

    // 3. egress BPF. The factory attaches it (folded into the one construct op); here we just
    //    build and encode the payload to ride the construction datagram. The helper pins this
    //    kennel's maps under the owner's `/run/user/<uid>/kennel/bpf/<id>/` so kenneld can
    //    drain the audit ringbuf and the owner can inspect the maps (§02-7). Only `host` mode ships
    //    a payload — every other mode (`none`/`constrained`/`unconstrained`) ships an EMPTY one, so
    //    the factory loads + attaches no programs (the net-ns is the boundary, see `bpf_egress`).
    let egress_bytes = if bpf_egress {
        EgressPayload {
            meta: plan.bpf_meta,
            allow_v4: plan.bpf_allow_v4.clone(),
            deny_v4: plan.bpf_deny_v4.clone(),
            allow_v6: plan.bpf_allow_v6.clone(),
            deny_v6: plan.bpf_deny_v6.clone(),
            bind_allow_v4: plan.bpf_bind_allow_v4.clone(),
            bind_deny_v4: plan.bpf_bind_deny_v4.clone(),
            bind_allow_v6: plan.bpf_bind_allow_v6.clone(),
            bind_deny_v6: plan.bpf_bind_deny_v6.clone(),
            bind_allowed_ports: plan.bind_allowed_ports.clone(),
            pin_id: id.to_owned(),
        }
        .encode()
    } else {
        Vec::new()
    };

    // 3b. The per-kennel egress: the dial delegate's command socket + kenneld's decision runtime.
    //     The delegate launch is deferred to *after* construct (below); here we only fix the socket
    //     path and build the in-process decision runtime from the signed policy. ONLY the proxied
    //     modes (constrained/unconstrained) run a SOCKS delegate + inject HTTPS_PROXY; `open`
    //     (host netns, direct egress, BPF/Landlock-gated) and `none` (no network) run none, so
    //     every INet request is refused for them (the workload egresses directly or not at all).
    let (command_socket, net_runtime): (Option<PathBuf>, crate::inet::NetRuntime) =
        if let (true, Some(setup)) = (proxied, proxy) {
            std::fs::create_dir_all(&setup.config_dir)?;
            // The owner-only kenneld↔delegate conduit command socket (§7.5.2): the delegate binds
            // it; kenneld connects per INet CONNECT to drive the dial.
            let command_socket = setup.config_dir.join(format!("netproxy-cmd-{ctx}.sock"));
            let host_services = ssh
                .host_service
                .iter()
                .copied()
                .collect::<Vec<std::net::SocketAddr>>();
            let net_runtime = crate::inet::NetRuntime::from_policy(
                net,
                host_services,
                Some(command_socket.clone()),
            );
            (Some(command_socket), net_runtime)
        } else {
            (None, crate::inet::NetRuntime::denied())
        };

    // 3b-inbound. The per-kennel inbound BIND mirror (§7.5.7): the runtime kenneld pushes
    //     DELIVER_INET through, plus the set of policy-mirrored ports to bind host-side. The
    //     host-inetd delegate launch + the eager registrations are deferred to *after* construct
    //     (below, beside the egress delegate), so the kennel's loopback alias exists before
    //     host-inetd binds it. The runtime is created unconditionally (no mirror ports ⇒ every
    //     REGISTER_MIRROR refused) so the binder handler always has one to consult. The mirror set
    //     is the registration gate (guard 3), seeded here — before binder::spawn serves the pool —
    //     so a REGISTER_MIRROR can never race an unset gate.
    let inbound_runtime = std::sync::Arc::new(crate::inbound::InboundRuntime::new());
    inbound_runtime.allow_ports(mirror_ports.iter().copied());

    // 3c. render the synthetic /etc (the libc/NSS files) and hand the spawn the
    //     binds that shadow them over the kennel's view. Built here because it
    //     needs the kennel's just-computed primary addresses.
    if let Some(etc) = etc {
        let params = crate::etc::EtcParams {
            hostname: &etc.hostname,
            user: &etc.account,
            group: &etc.account_group,
            uid: etc.uid,
            gid: etc.gid,
            home: &etc.home,
            groups: &etc.groups,
            shell: &etc.shell,
            // The kennel's `localhost` maps to its per-kennel address only when it has one (a bind);
            // otherwise to the standard loopback — a no-bind kennel reaches its own services on
            // `127.0.0.1`/`::1` like any host.
            v4: state.v4,
            v6: state.v6.unwrap_or(std::net::Ipv6Addr::LOCALHOST),
        };
        plan.file_binds = crate::etc::materialize(&etc.staging_dir, &params)?;

        // Grant Landlock read on the synthetic /etc files (passwd/group/hosts/
        // resolv.conf/nsswitch.conf/services/protocols/host.conf). They are copied into
        // the constructed /etc but are *not* in `fs.read`, so without this the workload —
        // and libc NSS — cannot read them: `getpwuid` fails, `id` shows no name, and the
        // identity mask is inert. Grant read on each synthetic file's dir (= /etc),
        // exactly as the dotfiles and synthetic ~/.ssh below do. The constructed /etc
        // holds only framework content (the host /etc is never bound in), so this is safe.
        {
            use kennel_lib_syscall::landlock::AccessFs;
            let mut etc_dirs = std::collections::BTreeSet::new();
            for (_src, target) in &plan.file_binds {
                if let Some(parent) = target.parent() {
                    etc_dirs.insert(parent.to_path_buf());
                }
            }
            for dir in etc_dirs {
                plan.landlock_fs
                    .push((dir, AccessFs::READ_FILE | AccessFs::READ_DIR));
            }
        }

        // Synthesise the user shell-init dotfiles into the kennel home (§7.9.2a):
        // copied into the fresh view root each spawn (reconstructed, non-persistent),
        // skipping any path in `home_persist`. Like the synthetic ~/.ssh, the home
        // subtree is not in `fs.read`, so grant Landlock read on each dotfile's dir.
        let dot_dir = etc.staging_dir.join("home");
        let dot_binds =
            crate::etc::materialize_home_dotfiles(&dot_dir, &etc.home, &etc.home_persist)?;
        if !dot_binds.is_empty() {
            use kennel_lib_syscall::landlock::AccessFs;
            let mut dot_dirs = std::collections::BTreeSet::new();
            for (_src, target) in &dot_binds {
                if let Some(parent) = target.parent() {
                    dot_dirs.insert(parent.to_path_buf());
                }
            }
            for dir in dot_dirs {
                plan.landlock_fs
                    .push((dir, AccessFs::READ_FILE | AccessFs::READ_DIR));
            }
            plan.file_binds.extend(dot_binds);
        }
    }

    // 3c-ssh. Lay the synthetic ~/.ssh into the view (config, known_hosts, the disposable synthetic
    //     keys). The synthetic config's ProxyCommand reaches the bastion via a CONNECT_INET binder
    //     transaction to kenneld (§7.10.4) — the same gateway as all egress, no SOCKS hop.
    //     Empty for a kennel with no [ssh] grant, so nothing changes for it.
    if !ssh.file_binds.is_empty() {
        // Grant Landlock read on the synthetic ~/.ssh dir(s): the files are copied
        // into the view like the synthetic /etc, but unlike /etc the home subtree is
        // not in `fs.read`, so without this `ssh` is denied reading its own config.
        use kennel_lib_syscall::landlock::AccessFs;
        let mut ssh_dirs = std::collections::BTreeSet::new();
        for (_src, target) in &ssh.file_binds {
            if let Some(parent) = target.parent() {
                ssh_dirs.insert(parent.to_path_buf());
            }
        }
        for dir in ssh_dirs {
            plan.landlock_fs
                .push((dir, AccessFs::READ_FILE | AccessFs::READ_DIR));
        }
        plan.file_binds.extend(ssh.file_binds.iter().cloned());
    }

    // 3c-net. The in-kennel SOCKS5 egress shim (§7.5): bind facade-socks5 into the view, launch it
    //     on the kennel's loopback at `port`, and point the workload's proxy env at it. It brokers
    //     each connect to node 0 as CONNECT_INET; kenneld decides + drives the dial delegate. Needs
    //     the constructed view, so it engages only when pivoting and the kennel has egress.
    let net_pivoting = view_root.is_some() && plan.view.is_some();
    if net_pivoting && command_socket.is_some() {
        if let Some(setup) = proxy {
            // The facade listens on the kennel's own loopback: `127.0.0.1`, isolated by the
            // kennel's net-ns, needs no per-kennel address.
            let listen = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port);
            apply_socks5(plan, &setup.socks5, listen, command);
            // 3c-inbound. The in-kennel inbound facade (§7.5.7): when the policy mirrors any bind
            //     ports, bind facade-client into the view and launch it on those ports. It pulls
            //     each inbound conduit (BIND_INET) and connects the workload's native listener.
            if !mirror_ports.is_empty() {
                let kennel_ip = listen.ip();
                apply_facade_client(plan, &setup.facade_client, kennel_ip, &mirror_ports);
            }
        }
    }

    // 3c-unix. AF_UNIX socket shims (§7.6): bind each granted socket into the view at
    //     its shim path, set env vars, and grant Landlock. The shim model needs the
    //     constructed view (a mount namespace), so it engages only when pivoting.
    let unix_pivoting = view_root.is_some() && plan.view.is_some();
    apply_afunix(plan, unix, command, unix_pivoting);

    // 3c-dbus. D-Bus mediation (§7.7): bind facade-dbus into the view, point the workload's
    //     DBUS_*_BUS_ADDRESS at the in-view sockets it presents, and grant the Landlock the facade
    //     needs to bind them. The host-dbus delegate is launched later (after boot-sync), beside the
    //     other host delegates. Needs the constructed view, so it engages only when pivoting.
    apply_dbus(plan, dbus, command, unix_pivoting);

    // 3d. constructed-view wiring (§7.4.5). When the plan carries a shim view and
    //     the daemon gave us a staging mountpoint: point HOME at the shim root,
    //     add the vanilla TLS/linker /etc subtrees the synthetic /etc omits (bound
    //     read-only — distro content, no host specifics), and hand the seal the
    //     new-root staging dir to pivot_root into. Without a view (or staging) the
    //     seal keeps the in-place fallback.
    // An OCI substrate view (§7.11) seeds its own `/etc` from the image, so the
    // host TLS/linker subtrees must not be bound over it; everything else (the ssh
    // dialer, the HOME env) applies the same.
    let oci_view = plan.view.as_ref().is_some_and(|v| v.image.is_some());
    if view_root.is_some() {
        if let Some(view) = plan.view.as_mut() {
            if !oci_view {
                for sub in crate::etc::essential_etc_subtrees() {
                    view.binds.push(kennel_lib_spawn::BindMount {
                        source: sub.clone(),
                        target: sub,
                        writable: false,
                        exclusive: false,
                    });
                }
            }
            // Bind the ssh binder-dialer in at its own path (read-only) so the synthetic
            // ssh config's ProxyCommand can exec it.
            if let Some(bin) = &ssh.ssh_bin {
                view.binds.push(kennel_lib_spawn::BindMount {
                    source: bin.clone(),
                    target: bin.clone(),
                    writable: false,
                    exclusive: false,
                });
            }
            // OCI launcher (§7.11): when the image's own entrypoint is run, bind the trusted
            // launcher in at its own path (= argv[0]) and the image's config.json read-only at
            // the launcher's known in-view path. Both read-only — the workload runs them, never
            // rewrites them.
            if let Some(bin) = &oci.launcher_bin {
                view.binds.push(kennel_lib_spawn::BindMount {
                    source: bin.clone(),
                    target: bin.clone(),
                    writable: false,
                    exclusive: false,
                });
            }
            if let Some(cfg) = &oci.config_src {
                view.binds.push(kennel_lib_spawn::BindMount {
                    source: cfg.clone(),
                    target: PathBuf::from(OCI_CONFIG_VIEW_PATH),
                    writable: false,
                    exclusive: false,
                });
            }
            command.env("HOME", &view.shim_root);
        }
        // Grant Landlock execute on the dialer + its loaders (outside the `view` borrow of plan).
        if let Some(bin) = &ssh.ssh_bin {
            if plan.view.is_some() {
                use kennel_lib_syscall::landlock::AccessFs;
                plan.landlock_fs
                    .push((bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
                let resolution = kennel_lib_policy::libresolve::resolve_loaders(&[bin
                    .to_string_lossy()
                    .into_owned()]);
                for loader in resolution.loaders {
                    plan.landlock_fs.push((
                        PathBuf::from(loader),
                        AccessFs::READ_FILE | AccessFs::EXECUTE,
                    ));
                }
            }
        }
        // Grant Landlock execute on the OCI launcher + its loaders, and read on the bound
        // config.json (outside the `view` borrow). The launcher's exec of the IMAGE entrypoint
        // is gated separately by the policy's own `[exec]` grants.
        if let (Some(bin), true) = (&oci.launcher_bin, plan.view.is_some()) {
            use kennel_lib_syscall::landlock::AccessFs;
            plan.landlock_fs
                .push((bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
            let resolution = kennel_lib_policy::libresolve::resolve_loaders(&[bin
                .to_string_lossy()
                .into_owned()]);
            for loader in resolution.loaders {
                plan.landlock_fs.push((
                    PathBuf::from(loader),
                    AccessFs::READ_FILE | AccessFs::EXECUTE,
                ));
            }
            plan.landlock_fs
                .push((PathBuf::from(OCI_CONFIG_VIEW_PATH), AccessFs::READ_FILE));
        }
    }
    if let Some(view_root) = view_root {
        if plan.view.is_some() {
            std::fs::create_dir_all(view_root)?;
            plan.new_root = Some(view_root.to_path_buf());
            state.view_root = Some(view_root.to_path_buf());
        }
    }

    // 4. Construct the kennel via the privhelper **factory** (`07-2`) — the one privileged op,
    //    which now provisions everything in a single invocation: it adds the loopback addresses
    //    (re-validating each), attaches the egress BPF, clones the namespaces, builds the view +
    //    binderfs (chowned to the operator), and `fexecve`s `kennel-bin-init`. Every kennel runs the
    //    factory + a binder bus, so a `BinderPrep` is required. The privhelper resolves
    //    `kennel-bin-init` from its own root-owned config (never the wire), so kenneld needs none here.
    plan.cgroup = cgroup.to_path_buf();
    let Some(prep) = binder else {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a kennel must be constructed via the factory, which requires a BinderPrep",
        )));
    };
    tracer.step(&format!(
        "bring-up: invoking privhelper factory (ctx {ctx}, {} loopback addr(s), {} egress bytes)",
        loopback.len(),
        egress_bytes.len()
    ));
    // Bring the in-ns `lo` up for proxied modes so the facade's `127.0.0.1`/`::1` are reachable —
    // independent of whether any per-kennel address is added. `none`/`host` keep lo as-is.
    let lo_up = plan.namespaces.contains(Namespaces::NET) && proxied;
    let (mut child, init_pid, sync, supervision_bytes) = construct_via_factory(
        privileged,
        plan,
        command,
        ctx,
        &loopback,
        lo_up,
        &egress_bytes,
        tracer.level_u8(),
        state,
    )?;
    tracer.step(&format!(
        "bring-up: factory returned, kennel-bin-init pid={init_pid}; awaiting boot-sync (exec)"
    ));
    let sync_fd = std::os::fd::AsRawFd::as_raw_fd(&sync);

    // Boot-sync (07-2 §7.2.1a): wait for kennel-bin-init to announce it has execed — only then is its
    // binderfs reachable via /proc/<init>/root. This is what lets node 0 be claimed deterministically
    // (and what the old retry loop was really waiting on). A failure here leaves the kennel up but
    // binder-less; the workload (which it gates) will not start, so surface it.
    kennel_lib_syscall::boot::await_init_ready(sync_fd).map_err(Error::Io)?;
    tracer.step("bring-up: boot-sync received — kennel-bin-init has execed");

    // Launch the egress dial delegate *before* releasing the binder pull (which is what lets
    // kennel-bin-init start the workload), so its command socket is bound before the first INet request.
    if let (Some(setup), Some(sock)) = (proxy, command_socket.as_ref()) {
        tracer.step(&format!(
            "bring-up: spawning egress delegate {}",
            setup.binary.display()
        ));
        state.proxy = Some(crate::proxy::spawn(&setup.binary, sock).map_err(Error::Proxy)?);
    }

    // Launch the inbound BIND delegate (§7.5.7) and eagerly register each policy-mirrored port,
    // also before releasing the binder pull so the host-side listeners are up before the workload
    // runs. The kennel's loopback alias exists now (the factory added it), so host-inetd can bind
    // it. For each registration kenneld starts a reader thread (off the binder pool) that pushes
    // host-inetd's accepted conduits into the kennel (DELIVER_INET) once the facade has registered.
    if let Some(setup) = proxy {
        if !mirror_ports.is_empty() {
            if let Some(kennel_ip) = state
                .v4
                .map(std::net::IpAddr::from)
                .or_else(|| state.v6.map(std::net::IpAddr::from))
            {
                std::fs::create_dir_all(&setup.config_dir)?;
                let inetd_sock = setup.config_dir.join(format!("inetd-cmd-{ctx}.sock"));
                tracer.step(&format!(
                    "bring-up: spawning inbound delegate {} for {} mirror port(s)",
                    setup.inetd.display(),
                    mirror_ports.len()
                ));
                state.inetd =
                    Some(crate::proxy::spawn(&setup.inetd, &inetd_sock).map_err(Error::Proxy)?);
                for &port in &mirror_ports {
                    match crate::inbound::bind_via_delegate(&inetd_sock, kennel_ip, port) {
                        Ok(conn) => {
                            let rt = std::sync::Arc::clone(&inbound_runtime);
                            std::thread::spawn(move || crate::inbound::run_reader(&rt, &conn));
                        }
                        Err(e) => eprintln!(
                            "kenneld: warning: inbound mirror for port {port} not registered: {e}"
                        ),
                    }
                }
            }
        }
    }

    // The per-kennel D-Bus mediation relay (§7.7.2a), passed into the node-0 handler so the DBUS_*
    // verbs reach it. Launch the host-dbus delegate(s) — operator context, one per enabled bus —
    // before releasing the binder pull, so their command sockets are bound before the workload's
    // first D-Bus message. With no delegate (no `[dbus]` grant or no binary) the relay is `None`
    // and the membrane denies every D-Bus verb (fail-closed).
    let dbus_relay = binder.and_then(|b| b.dbus_transactor.as_ref()).map_or_else(
        || match spawn_dbus_delegates(dbus, ctx, &tracer, state) {
            Ok(relay) => relay,
            Err(e) => {
                eprintln!("kenneld: warning: D-Bus mediation delegate not started: {e}");
                None
            }
        },
        |transactor| {
            Some(std::sync::Arc::new(crate::dbus::DbusRelay::new_brokered(
                std::sync::Arc::clone(transactor),
                kennel_lib_binder::ratelimit::RateLimiter::with_defaults(),
            )))
        },
    );

    // Take binder node 0 of the kennel's binderfs and serve the lifecycle (gated on the init pid)
    // so kennel-bin-init can pull its supervision-half. kennel-bin-init has execed (boot-sync above), so
    // the device is reachable via /proc/<init>/root — a single open, no retry.
    if plan.view.as_ref().is_some_and(|v| v.binder) {
        let init_pid_u32 = u32::try_from(init_pid).unwrap_or(0);
        let lifecycle = crate::binder::Lifecycle {
            init_host_pid: Some(init_pid),
            supervision: supervision_bytes,
            // The TTL custodian's inputs: kennel-bin-init's timer fires NOTIFY_TTL_EXPIRED and the
            // node-0 handler freezes/thaws/kills this cgroup per the action (§9.7).
            cgroup: plan.cgroup.clone(),
            ttl_action: plan.ttl_action,
            name: id.to_owned(),
            // The operator-prompt channel for the TTL `renew` action; `None` ⇒ fall back to warn.
            prompt: prep.prompt.clone(),
        };
        tracer.step(&format!(
            "bring-up: acquiring binder node 0 via /proc/{init_pid_u32}/root"
        ));
        match acquire_binder_node0(
            init_pid_u32,
            ctx,
            prep,
            lifecycle,
            net_runtime,
            std::sync::Arc::clone(&inbound_runtime),
            dbus_relay,
        ) {
            Ok(manager) => {
                tracer.step("bring-up: binder node 0 acquired, lifecycle served");
                state.binder = Some(manager);
            }
            Err(e) => eprintln!("kenneld: warning: binder context manager not started: {e}"),
        }
    }

    // Tell kennel-bin-init the bus is live so it pulls its plan and starts the workload (unconditional:
    // it always blocks for this). Then reap the factory parent, which exits the moment it has
    // reported the pid; `kennel-bin-init` has reparented to kenneld (the subreaper), so the `Kennel`
    // handle can `waitpid(init_pid)` for the workload's status with no ECHILD race.
    tracer.step(
        "bring-up: signalling bus-live — kennel-bin-init may pull its plan + start the workload",
    );
    kennel_lib_syscall::boot::signal_bus_live(sync_fd).map_err(Error::Io)?;
    let _ = child.wait();
    Ok(init_pid)
}

/// The set of ports the inbound BIND mirror (§7.5.7) exposes host-side: the explicit
/// `[net.bind].allowed_ports` plus every single-port `[net.bpf].bind.allow` rule. A CIDR/range
/// allow with no explicit port list has no finite eager set, so it is not mirrored here (a future
/// lazy mode could); the eager mirror covers the declared ports. Deduplicated, order-stable.
fn mirror_bind_ports(net: &kennel_lib_policy::NetPolicy) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    let mut push = |p: u16| {
        if p != 0 && !ports.contains(&p) {
            ports.push(p);
        }
    };
    for &p in &net.bind_allowed_ports {
        push(p);
    }
    for rule in &net.bpf_bind_allow {
        if rule.port_min == rule.port_max {
            push(rule.port_min);
        }
    }
    ports
}

/// The factory construction step (`07-2`): build the construction- and supervision-halves and
/// have the privhelper factory provision the kennel — loopback adds, egress attach, the
/// namespace clone, the view, and binderfs — then `fexecve` `kennel-bin-init`. Returns
/// `kennel-bin-init`'s host pid and the encoded supervision-half (the caller serves it over binder
/// node 0). The factory exits as soon as it has reported the pid, so it is reaped here, and the
/// orphaned init has reparented to kenneld (the `set_child_subreaper`) before we return.
#[allow(clippy::similar_names)] // drop_uid / drop_gid are the domain names
#[allow(clippy::too_many_arguments)] // one cohesive factory call; the args are the construction inputs
fn construct_via_factory<P: Privileged + Sync>(
    privileged: &P,
    plan: &Plan,
    command: &Command,
    ctx: u16,
    loopback: &[kennel_lib_spawn::LoopbackAddr],
    lo_up: bool,
    egress_bytes: &[u8],
    log_level: u8,
    state: &mut Provision,
) -> Result<(Child, i32, std::os::fd::OwnedFd, Vec<u8>), Error> {
    let drop_uid = kennel_lib_syscall::unistd::real_uid();
    let drop_gid = kennel_lib_syscall::unistd::real_gid();

    let construction = construction_half_from(plan, ctx, loopback, lo_up);
    let supervision = supervision_from(plan, command, drop_uid, drop_gid, log_level);
    let half_bytes = kennel_lib_spawn::wire::encode_construction(&construction);
    let supervision_bytes = kennel_lib_spawn::wire::encode_supervision(&supervision);

    // The privhelper resolves + opens `kennel-bin-init` from root-owned config (never the wire), so
    // kenneld passes no init fd. For an interactive run it passes the pty return socket (the
    // workload's pty master is sent back over it), re-homed at `PTY_RETURN_FD`; the egress payload
    // rides the same datagram. The pty fd lives in the plan and is kept open by the caller
    // (`run_kennel`'s `return_sock`) for the construction.
    // Returns once `kennel-bin-init` has been `fexecve`'d and the init pid reported, handing back the
    // boot-sync socket: the caller waits on it for kennel-bin-init's "ready", claims binder node 0,
    // then signals "go" (deterministic startup, `07-2` §7.2.1a). The factory exits the moment it
    // reports the pid, so the caller reaps the `Child` after the sync.
    let (child, init_pid, sync) = privileged.construct_kennel(
        &half_bytes,
        Some(egress_bytes),
        plan.interactive_return_fd,
        plan.workload_fd,
        plan.stdio_fds,
    )?;
    state.factory = true;

    Ok((child, init_pid, sync, supervision_bytes))
}

/// Build the construction-half (the privhelper factory's input) from the plan, the kennel's
/// `ctx`, and the per-kennel `loopback` addresses the factory adds on `lo`.
fn construction_half_from(
    plan: &Plan,
    ctx: u16,
    loopback: &[kennel_lib_spawn::LoopbackAddr],
    lo_up: bool,
) -> kennel_lib_spawn::ConstructionHalf {
    kennel_lib_spawn::ConstructionHalf {
        namespaces: plan.namespaces,
        cgroup: plan.cgroup.clone(),
        cgroup_join: plan.cgroup_join,
        view: plan.view.clone(),
        new_root: plan.new_root.clone(),
        file_binds: plan.file_binds.clone(),
        // The granted supplementary gids feed the gid_map after the 0 0 1 + operator
        // lines (the factory adds those); empty ⇒ default drop-all-groups.
        granted_gids: plan.supplementary_groups.clone().unwrap_or_default(),
        // Bring the in-namespace `lo` UP for any proxied kennel so the kernel's `127.0.0.1`/`::1`
        // are reachable for the egress facade — decoupled from addresses: the per-kennel
        // address (if any, bind-only) is added on top, but `lo` is up regardless so a no-bind
        // kennel still has working loopback.
        lo: lo_up,
        ctx,
        loopback: loopback.to_vec(),
        // Tell the factory which inherited fds accompany the datagram (sent pty-then-workload),
        // so it places them at the right fixed numbers. It decodes the half but forwards the
        // supervision-half (which holds the workload flag) opaquely, so the presence must be
        // mirrored here.
        pty_fd_present: plan.interactive_return_fd.is_some(),
        workload_fd_present: plan.workload_fd.is_some(),
        stdio_present: plan.stdio_fds.is_some(),
    }
}

/// Build the supervision-half (what kennel-bin-init pulls) from the plan and the workload
/// `Command`. Reads the program/argv/env/cwd back via the stable `Command` getters, so
/// the command-building in `server.rs` is unchanged by the cutover.
#[allow(clippy::similar_names)] // drop_uid / drop_gid are the domain names
fn supervision_from(
    plan: &Plan,
    command: &Command,
    drop_uid: u32,
    drop_gid: u32,
    log_level: u8,
) -> kennel_lib_spawn::Supervision {
    let program = PathBuf::from(command.get_program());
    let mut argv = vec![command.get_program().to_string_lossy().into_owned()];
    argv.extend(command.get_args().map(|a| a.to_string_lossy().into_owned()));
    let env = command
        .get_envs()
        .filter_map(|(k, v)| {
            v.map(|v| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
        })
        .collect();
    kennel_lib_spawn::Supervision {
        program,
        argv,
        env,
        cwd: command.get_current_dir().map(Path::to_path_buf),
        drop_uid,
        drop_gid,
        // kennel-bin-init runs as the kennel's uid 0 (it holds CAP_SETGID in the userns), so it
        // sets the granted supplementary groups on each child as it drops it to the operator.
        groups: plan.supplementary_groups.clone(),
        landlock_fs: plan.landlock_fs.clone(),
        landlock_net: plan.landlock_net.clone(),
        seccomp_deny: plan.seccomp_deny.clone(),
        seccomp_deny_action: plan.seccomp_deny_action,
        ulimits: plan.ulimits.clone(),
        aux: plan.aux.clone(),
        interactive: plan.interactive_return_fd.is_some(),
        // Set when kenneld opened+hashed the workload binary and passes its fd at WORKLOAD_FD
        // (the sha256 fd-pin); init then fexecves the fd rather than resolving a path.
        workload_fd_pinned: plan.workload_fd.is_some(),
        // Non-interactive run: the three workload stdio fds ride at INJECT_STD*_FD and init dup2s
        // them onto 0/1/2 instead of adopting a controlling tty.
        stdio_injected: plan.stdio_fds.is_some(),
        // kennel-bin-init runs this timer and, at expiry, makes the blocking NOTIFY_TTL_EXPIRED
        // call to kenneld (which freezes + decides). The action is decided kenneld-side.
        ttl_seconds: plan.ttl_seconds,
        // The verbosity kennel-bin-init traces at — it cannot read system.toml post-pivot.
        log_level,
    }
}

/// Take node 0 of a kennel's binderfs instance and run its registry + lifecycle serve
/// thread. The binderfs is mounted inside the kennel (by the spawn seal on the legacy
/// path, or by the factory's construction child); we reach it from the daemon via the
/// process's `/proc/<pid>/root`, which (post-`pivot_root`) is the view.
///
/// `resolve_pid` yields the pid whose `/proc/<pid>/root` holds the device, retried until
/// the device appears (construction runs concurrently with our return). On the legacy
/// path that is the workload (a `/children` walk from the spawn intermediate); on the
/// factory path it is `kennel-bin-init` directly. `lifecycle` carries the init-pid gate +
/// supervision-half kenneld serves over node 0 (disabled on the legacy path).
fn acquire_binder_node0(
    init_pid: u32,
    ctx: u16,
    prep: &BinderPrep,
    lifecycle: crate::binder::Lifecycle,
    net: crate::inet::NetRuntime,
    inbound: std::sync::Arc<crate::inbound::InboundRuntime>,
    dbus: Option<std::sync::Arc<crate::dbus::DbusRelay>>,
) -> io::Result<crate::binder::Manager> {
    use std::os::fd::OwnedFd;

    // Deterministic: the factory has mounted the binderfs and is blocking its child before
    // `fexecve` (it reported the pid only after the device existed), so this is a single open with
    // no retry. The pid is stable across the upcoming `fexecve` (same process becomes kennel-bin-init).
    let dev = format!("/proc/{init_pid}/root/dev/binderfs/binder");
    // std opens files O_CLOEXEC by default on Unix.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dev)
        .map_err(|e| io::Error::new(e.kind(), format!("open kennel binderfs {dev}: {e}")))?;
    crate::binder::spawn(
        OwnedFd::from(file),
        ctx,
        prep.policy.clone(),
        prep.unix.clone(),
        lifecycle,
        net,
        inbound,
        dbus,
        std::sync::Arc::clone(&prep.writer),
        prep.spawn.clone(),
        prep.consumes.clone(),
        prep.catalogue.clone(),
        prep.activator.clone(),
    )
}

/// The workload pid: the first child of the `Command`-spawned intermediate (which
/// double-forks the PID-1 workload). `None` until the child exists.
/// The in-view binder device the af-unix proxy transacts the facade over (the seal
/// mounts the per-kennel binderfs here; §7.1).
const IN_VIEW_BINDER_DEVICE: &str = "/dev/binderfs/binder";

/// Wire the `AF_UNIX` socket facade (§7.6 / `07-1` §7.1.5): launch the in-kennel
/// `facade-afunix` proxy so each granted socket is presented at its in-view path
/// and brokered, on connect, to the `org.projectkennel.IAfUnix` binder facade — which
/// resolves the name to the real host socket and returns a connected fd. No host
/// socket path is ever bound into the view (the bind-mount shim it replaces is gone).
///
/// Sets the env vars the application reads (e.g. `WAYLAND_DISPLAY`), binds the proxy
/// binary into the view with Landlock execute, grants Landlock on each shim path's
/// parent directory so the proxy can `bind(2)` its listener there and the workload can
/// connect, and registers the proxy as a seal-launched auxiliary process.
///
/// A no-op unless `pivoting` (the facade needs the constructed view + its binderfs) and
/// the deployment provides the proxy binary. When grants exist but the binary is absent,
/// it warns and serves nothing — fail-closed, never a silent host-socket bind.
fn apply_afunix(plan: &mut Plan, unix: &UnixPrep, command: &mut Command, pivoting: bool) {
    use kennel_lib_syscall::landlock::AccessFs;
    if unix.shims.is_empty() || !pivoting {
        return;
    }
    let Some(shim_bin) = unix.afunix_bin.clone() else {
        eprintln!(
            "kenneld: warning: kennel grants [unix] sockets but no facade-afunix binary is \
             configured (deployment `afunix`); the sockets will be unserved."
        );
        return;
    };
    for (var, val) in &unix.env {
        command.env(var, val);
    }
    // The proxy `bind(2)`s its listener at each shim path: grant its parent directory
    // the rights to create the socket node (and clear a stale one), and to read/connect
    // it. The path itself does not exist at ruleset-build time, so the grant rides the
    // parent (a Landlock rule covers files created beneath a granted directory).
    for shim in &unix.shims {
        if let Some(parent) = shim.shim_path.parent() {
            plan.landlock_fs.push((
                parent.to_path_buf(),
                AccessFs::READ_FILE
                    | AccessFs::WRITE_FILE
                    | AccessFs::READ_DIR
                    | AccessFs::MAKE_SOCK
                    | AccessFs::REMOVE_FILE,
            ));
        }
    }
    // Bind the proxy binary into the view at its own path (read-only) and grant execute.
    if let Some(view) = plan.view.as_mut() {
        view.binds.push(kennel_lib_spawn::BindMount {
            source: shim_bin.clone(),
            target: shim_bin.clone(),
            writable: false,
            exclusive: false,
        });
    }
    plan.landlock_fs
        .push((shim_bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
    // The proxy is `execv`'d directly by the seal, so it needs FS_EXECUTE on its own dynamic
    // loader too (the kernel opens PT_INTERP `FMODE_EXEC`); the binary itself is granted
    // above. Its shared libraries load via READ from the view's lib dirs and are not
    // execute-gated (07-3-exec). `skip_missing` drops a loader the view omits.
    let resolution =
        kennel_lib_policy::libresolve::resolve_loaders(&[shim_bin.to_string_lossy().into_owned()]);
    for loader in resolution.loaders {
        plan.landlock_fs.push((
            PathBuf::from(loader),
            AccessFs::READ_FILE | AccessFs::EXECUTE,
        ));
    }
    // Register the proxy as a seal-launched aux: `facade-afunix <device>
    // <shim-path>=<name> ...`. It runs inside the sealed view, brokers by logical name
    // (which the facade resolves), and dies with the kennel's PID namespace.
    let mut args = vec![IN_VIEW_BINDER_DEVICE.to_owned()];
    for shim in &unix.shims {
        args.push(format!("{}={}", shim.shim_path.display(), shim.name));
    }
    plan.aux.push(kennel_lib_spawn::AuxProcess {
        path: shim_bin,
        args,
    });
}

/// Bind `facade-socks5` into the view, launch it as a seal aux on the kennel loopback `listen`,
/// and point the workload's proxy env at it.
///
/// `facade-socks5` is the workload's SOCKS5 endpoint: it forwards each connect to binder node 0 as a
/// `CONNECT_INET` transaction, which kenneld decides and dials via the host-side delegate. The
/// `socks5h` scheme keeps name resolution on the proxy side (the kennel holds names, not addresses).
fn apply_socks5(plan: &mut Plan, socks5_bin: &Path, listen: SocketAddr, command: &mut Command) {
    use kennel_lib_syscall::landlock::AccessFs;
    // Bind the binary into the view at its own path (read-only) and grant execute + its loaders.
    if let Some(view) = plan.view.as_mut() {
        view.binds.push(kennel_lib_spawn::BindMount {
            source: socks5_bin.to_path_buf(),
            target: socks5_bin.to_path_buf(),
            writable: false,
            exclusive: false,
        });
    }
    plan.landlock_fs.push((
        socks5_bin.to_path_buf(),
        AccessFs::READ_FILE | AccessFs::EXECUTE,
    ));
    let resolution = kennel_lib_policy::libresolve::resolve_loaders(&[socks5_bin
        .to_string_lossy()
        .into_owned()]);
    for loader in resolution.loaders {
        plan.landlock_fs.push((
            PathBuf::from(loader),
            AccessFs::READ_FILE | AccessFs::EXECUTE,
        ));
    }
    // `facade-socks5 <binder-device> <listen-addr>`, run inside the sealed view.
    plan.aux.push(kennel_lib_spawn::AuxProcess {
        path: socks5_bin.to_path_buf(),
        args: vec![IN_VIEW_BINDER_DEVICE.to_owned(), listen.to_string()],
    });
    // The workload's egress goes through facade-socks5, which serves BOTH SOCKS5 and HTTP-proxy on
    // the one listener. Point the HTTP(S)_PROXY vars at the `http://` form: many runtimes (Go
    // net/http, Node fetch/undici, the JVM, Python requests without the socks extra) accept ONLY an
    // http:// proxy in HTTP_PROXY and ignore/reject a socks5h:// scheme — the http front-end is what
    // makes them egress. ALL_PROXY stays socks5h:// for SOCKS-native clients (and so the name, not a
    // resolved address, crosses to kenneld). Both schemes hit the same endpoint and the same
    // CONNECT_INET decision path.
    let http_url = format!("http://{listen}");
    let socks_url = format!("socks5h://{listen}");
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        command.env(var, &http_url);
    }
    for var in ["ALL_PROXY", "all_proxy"] {
        command.env(var, &socks_url);
    }
}

/// Bind `facade-client` into the view and launch it as a seal aux for the §7.5.7 inbound mirror.
///
/// `facade-client` is the in-kennel end of the mirror: for each `port` it transacts `BIND_INET` to
/// node 0, and on a delivered conduit connects the workload's native listener at `<kennel-ip>:port`
/// and splices. Sets no env (unlike the egress proxy) — the workload's own `bind()` is the trigger,
/// not a client-side proxy setting. Mirrors `apply_socks5`'s view-bind + Landlock + loader grants.
fn apply_facade_client(plan: &mut Plan, client_bin: &Path, kennel_ip: IpAddr, ports: &[u16]) {
    use kennel_lib_syscall::landlock::AccessFs;
    if let Some(view) = plan.view.as_mut() {
        view.binds.push(kennel_lib_spawn::BindMount {
            source: client_bin.to_path_buf(),
            target: client_bin.to_path_buf(),
            writable: false,
            exclusive: false,
        });
    }
    plan.landlock_fs.push((
        client_bin.to_path_buf(),
        AccessFs::READ_FILE | AccessFs::EXECUTE,
    ));
    let resolution = kennel_lib_policy::libresolve::resolve_loaders(&[client_bin
        .to_string_lossy()
        .into_owned()]);
    for loader in resolution.loaders {
        plan.landlock_fs.push((
            PathBuf::from(loader),
            AccessFs::READ_FILE | AccessFs::EXECUTE,
        ));
    }
    // facade-client connects the workload's listener at <kennel-ip>:<port>; Landlock gates connect
    // per port, so each mirrored port needs a CONNECT_TCP grant (the BPF connect ACL is seeded with
    // the loopback /28 separately in stamp_proxy). Without this Landlock denies the in-kennel
    // delivery connect (EPERM) even though the BPF ACL permits it.
    for &port in ports {
        plan.landlock_net
            .push((port, kennel_lib_syscall::landlock::AccessNet::CONNECT_TCP));
    }
    // `facade-client <binder-device> <kennel-ip> <port>...`, run inside the sealed view.
    let mut args = vec![IN_VIEW_BINDER_DEVICE.to_owned(), kennel_ip.to_string()];
    args.extend(ports.iter().map(u16::to_string));
    plan.aux.push(kennel_lib_spawn::AuxProcess {
        path: client_bin.to_path_buf(),
        args,
    });
}

/// Bind `facade-dbus` into the view, point the workload's `DBUS_*_BUS_ADDRESS` at the in-view
/// sockets it presents, and grant the Landlock it needs to create + bind them. Mirrors
/// `apply_socks5`'s view-bind + Landlock + loader grants; the `host-dbus` delegate it pairs with is
/// launched later (after boot-sync) by [`spawn_dbus_delegates`].
///
/// A no-op unless `pivoting` (the facade needs the constructed view + its binderfs) and the kennel
/// enables at least one bus. When a bus is enabled but no facade binary is configured, it warns and
/// serves nothing — fail-closed, never a host bus socket exposed by other means.
fn apply_dbus(plan: &mut Plan, dbus: &DbusPrep, command: &mut Command, pivoting: bool) {
    use kennel_lib_syscall::landlock::AccessFs;
    let buses = [
        (dbus.session.as_ref(), "DBUS_SESSION_BUS_ADDRESS", "session"),
        (dbus.system.as_ref(), "DBUS_SYSTEM_BUS_ADDRESS", "system"),
    ];
    if !pivoting || buses.iter().all(|(b, _, _)| b.is_none()) {
        return;
    }
    let Some(facade_bin) = dbus.facade_bin.clone() else {
        eprintln!(
            "kenneld: warning: kennel grants [dbus] mediation but no facade-dbus binary is \
             configured (deployment `facade_dbus`); the bus(es) will be unserved."
        );
        return;
    };
    // Per enabled bus: point the workload's bus address at the in-view socket facade-dbus presents,
    // grant the facade the Landlock to create the socket's parent dir (it `create_dir_all`s it under
    // $HOME) and bind a socket beneath, and add it to the facade's argv.
    let mut args = vec![IN_VIEW_BINDER_DEVICE.to_owned()];
    let mut grant_dirs = std::collections::BTreeSet::new();
    for (bus, env_var, name) in buses {
        let Some(prep) = bus else { continue };
        command.env(env_var, format!("unix:path={}", prep.listen_path.display()));
        // Grant the existing ancestor (the kennel's writable $HOME): a Landlock rule on a directory
        // covers files+subdirs created beneath it, so this one grant lets the facade create
        // `.kennel-dbus/` and bind the socket inside. (The immediate parent does not exist at
        // ruleset-build time, so the rule must ride an ancestor that does.)
        if let Some(home) = prep.listen_path.parent().and_then(std::path::Path::parent) {
            grant_dirs.insert(home.to_path_buf());
        }
        args.push(format!("{}={}", prep.listen_path.display(), name));
    }
    for dir in grant_dirs {
        plan.landlock_fs.push((
            dir,
            AccessFs::READ_FILE
                | AccessFs::WRITE_FILE
                | AccessFs::READ_DIR
                | AccessFs::MAKE_DIR
                | AccessFs::MAKE_SOCK
                | AccessFs::REMOVE_FILE,
        ));
    }
    // Bind the facade binary into the view (read-only) and grant execute + its loaders.
    if let Some(view) = plan.view.as_mut() {
        view.binds.push(kennel_lib_spawn::BindMount {
            source: facade_bin.clone(),
            target: facade_bin.clone(),
            writable: false,
            exclusive: false,
        });
    }
    plan.landlock_fs
        .push((facade_bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
    let resolution = kennel_lib_policy::libresolve::resolve_loaders(&[facade_bin
        .to_string_lossy()
        .into_owned()]);
    for loader in resolution.loaders {
        plan.landlock_fs.push((
            PathBuf::from(loader),
            AccessFs::READ_FILE | AccessFs::EXECUTE,
        ));
    }
    // `facade-dbus <device> <listen-path>=<bus> ...`, run inside the sealed view.
    plan.aux.push(kennel_lib_spawn::AuxProcess {
        path: facade_bin,
        args,
    });
}

/// Launch the `host-dbus` delegate(s) — one per enabled bus, in the operator's context — and build
/// the per-kennel [`crate::dbus::DbusRelay`] wired to them. Each delegate binds its command socket;
/// kenneld connects once (the owner-only pipe), relays outbound frames through a bounded writer
/// ([`crate::dbus::spawn_pipe_writer`]), and drains inbound frames on a per-bus thread
/// ([`crate::dbus::run_inbound_reader`]).
///
/// Returns `Ok(None)` (mediation off) when no bus is enabled or no `host-dbus` binary is
/// configured; the membrane then denies every D-Bus verb. The spawned children are recorded in
/// `state` for teardown.
fn spawn_dbus_delegates(
    dbus: &DbusPrep,
    ctx: u16,
    tracer: &kennel_lib_config::Tracer,
    state: &mut Provision,
) -> io::Result<Option<std::sync::Arc<crate::dbus::DbusRelay>>> {
    use kennel_lib_binder::dbus::Bus;
    let enabled: Vec<(Bus, &DbusBusPrep, &str)> = [
        (Bus::Session, dbus.session.as_ref(), "session"),
        (Bus::System, dbus.system.as_ref(), "system"),
    ]
    .into_iter()
    .filter_map(|(bus, prep, name)| prep.map(|p| (bus, p, name)))
    .collect();
    if enabled.is_empty() {
        return Ok(None);
    }
    let Some(host_bin) = dbus.host_bin.as_ref() else {
        eprintln!(
            "kenneld: warning: kennel grants [dbus] mediation but no host-dbus binary is \
             configured (deployment `host_dbus`); the bus(es) will be unserved."
        );
        return Ok(None);
    };
    std::fs::create_dir_all(&dbus.cmd_dir)?;
    let mut senders = std::collections::HashMap::new();
    let mut readers: Vec<UnixStream> = Vec::new();
    for (bus, prep, name) in enabled {
        let sock = dbus.cmd_dir.join(format!("dbus-{name}-{ctx}.sock"));
        let _ = std::fs::remove_file(&sock);
        tracer.step(&format!(
            "bring-up: spawning D-Bus delegate {} ({name} bus)",
            host_bin.display()
        ));
        state.dbus.push(spawn_host_dbus(
            host_bin,
            &sock,
            name,
            &prep.bus_address,
            &prep.rules,
        )?);
        // The delegate binds then blocks on accept; connect once (the owner-only pipe). One clone
        // feeds the bounded writer (outbound frames), the original drives the inbound reader.
        let stream = connect_host_dbus(&sock)?;
        senders.insert(bus, crate::dbus::spawn_pipe_writer(stream.try_clone()?));
        readers.push(stream);
    }
    let relay = std::sync::Arc::new(crate::dbus::DbusRelay::new(
        senders,
        kennel_lib_binder::ratelimit::RateLimiter::with_defaults(),
    ));
    for stream in readers {
        let relay = std::sync::Arc::clone(&relay);
        std::thread::spawn(move || crate::dbus::run_inbound_reader(&relay, stream));
    }
    Ok(Some(relay))
}

/// Spawn one `host-dbus` delegate: `host-dbus <command-socket> <session|system> <bus-address>
/// [--talk P]… [--call P]… [--broadcast P]… [--own P]… [--deny-talk P]…`. No inherited stdio.
fn spawn_host_dbus(
    binary: &Path,
    socket: &Path,
    bus: &str,
    bus_address: &str,
    rules: &kennel_lib_policy::DbusBusRuntime,
) -> io::Result<Child> {
    use std::process::Stdio;
    let mut cmd = Command::new(binary);
    cmd.arg(socket).arg(bus).arg(bus_address);
    for pattern in &rules.talk {
        cmd.arg("--talk").arg(pattern);
    }
    for pattern in &rules.call {
        cmd.arg("--call").arg(pattern);
    }
    for pattern in &rules.broadcast {
        cmd.arg("--broadcast").arg(pattern);
    }
    for pattern in &rules.own {
        cmd.arg("--own").arg(pattern);
    }
    for pattern in &rules.deny_talk {
        cmd.arg("--deny-talk").arg(pattern);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).spawn()
}

/// Connect kenneld's end of the owner-only pipe to a just-spawned `host-dbus`, absorbing the
/// bind/accept spawn race with a brief retry. The delegate `chmod`s the socket `0600`, so only the
/// operator (kenneld) can connect.
fn connect_host_dbus(socket: &Path) -> io::Result<UnixStream> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(e);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Best-effort reverse of bring-up: kill the proxy, remove the addresses, then the
/// cgroup (which detaches the egress BPF). Each step is independent so a failure
/// does not skip the rest.
#[allow(clippy::too_many_arguments)] // the reverse-of-bring-up unwind inputs, one per resource
fn teardown<P: Privileged>(
    tracer: kennel_lib_config::Tracer,
    privileged: &P,
    ctx: u16,
    cgroup: Option<&Path>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    proxy: Option<Child>,
    inetd: Option<Child>,
    dbus: Vec<Child>,
    view_root: Option<&Path>,
) {
    reap_proxy(proxy);
    reap_proxy(inetd); // same kill+reap; the inbound delegate's reader threads end with it
    for child in dbus {
        reap_proxy(Some(child)); // host-dbus delegates; kenneld's pipe reader threads end with them
    }
    tracer.step("teardown: proxies + delegates reaped; releasing addresses");
    if let Some(addr) = v6 {
        let _ = privileged.del_address(ctx, LOOPBACK, addr.into(), V6_PREFIX);
    }
    if let Some(addr) = v4 {
        let _ = privileged.del_address(ctx, LOOPBACK, addr.into(), V4_PREFIX);
    }
    if let Some(cg) = cgroup {
        let _ = std::fs::remove_dir(cg);
    }
    // The constructed-view tmpfs lived in the workload's mount namespace (gone
    // with it); only the empty host mountpoint remains to remove.
    if let Some(vr) = view_root {
        let _ = std::fs::remove_dir(vr);
    }
    tracer.step("teardown: complete — addresses, cgroup, view reclaimed");
}
