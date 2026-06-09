//! Project Kennel orchestration core.
//!
//! [`start`] brings a kennel up and [`Kennel::stop`] tears it down. The bring-up
//! sequence mirrors `08-enforcement-architecture.md` §8.3, minus the supporting
//! daemons (not built yet):
//!
//! 1. create the kennel's cgroup (kenneld owns its delegated `user@<uid>`
//!    subtree, so this is unprivileged — see §8.5 and the cgroup-join note on
//!    [`kennel_spawn`]);
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
//! through `kennel-spawn`/`kennel-syscall`.

#![forbid(unsafe_code)]

pub mod audit;
pub mod bastion;
pub mod binder;
pub mod bpf_audit;
pub mod cgroup;
pub mod control;
pub mod ctx;
pub mod etc;
pub mod policy;
pub mod proxy;
pub mod server;
pub mod socket;
pub mod ssh;
pub mod sshd;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use kennel_policy::{NetPolicy, TtlAction};
use kennel_privhelper::addr::{loopback_v4, loopback_v6, V4_PREFIX, V6_PREFIX};
use kennel_privhelper::validate::ReservedScope;
use kennel_privhelper::wire::{EgressPayload, Response, Status};
use kennel_spawn::{Plan, ProxyEndpoint, SpawnError};

/// The default proxy host offset within the kennel's subnet (`…|0001` / `::1`).
///
/// Mirrors what [`kennel_policy::ProxyListen::default`] resolves to; the live
/// offset comes from the signed policy (`net.proxy.offset`). The reference the
/// tests compute against.
pub const PROXY_HOST: u8 = 1;

/// The default TCP port the per-kennel egress proxy listens on.
///
/// Mirrors what [`kennel_policy::ProxyListen::default`] resolves to; the live
/// port comes from the signed policy (`net.proxy.port`).
pub const PROXY_PORT: u16 = 1080;

/// The loopback interface the per-kennel addresses live on.
const LOOPBACK: &str = "lo";

/// Everything that can stop a kennel coming up.
#[derive(Debug)]
pub enum Error {
    /// A filesystem operation (cgroup create/remove) failed.
    Io(io::Error),
    /// A privileged helper operation was refused or failed.
    Privileged {
        /// Which operation failed (for diagnostics/audit).
        op: &'static str,
        /// The helper's response.
        response: Response,
    },
    /// The workload could not be spawned.
    Spawn(SpawnError),
    /// The egress proxy's config could not be derived from the policy.
    ProxyConfig(String),
    /// The egress proxy process could not be launched.
    Proxy(io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cgroup filesystem operation failed: {e}"),
            Self::Privileged { op, response } => {
                write!(f, "privileged operation `{op}` failed: {response:?}")
            }
            Self::Spawn(e) => write!(f, "workload spawn failed: {e}"),
            Self::ProxyConfig(m) => write!(f, "egress proxy config could not be derived: {m}"),
            Self::Proxy(e) => write!(f, "egress proxy could not be launched: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Proxy(e) => Some(e),
            Self::Spawn(e) => Some(e),
            Self::Privileged { .. } | Self::ProxyConfig(_) => None,
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
    /// Add `addr/prefix` on `interface` for kennel `ctx`.
    ///
    /// # Errors
    /// An OS error if the helper cannot be invoked or its response is malformed.
    fn add_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response>;

    /// Remove `addr/prefix` on `interface` for kennel `ctx`.
    ///
    /// # Errors
    /// As [`add_address`](Self::add_address).
    fn del_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response>;

    /// Load, populate, and attach the egress BPF programs to `cgroup`.
    ///
    /// # Errors
    /// As [`add_address`](Self::add_address).
    fn setup_egress(&self, cgroup: &Path, payload: &EgressPayload) -> io::Result<Response>;

    /// Construct a kennel via the privhelper **factory** (`07-2`): hand it the
    /// `construction_half` bytes and (optionally) the pty socket; receive the long-lived
    /// supervisor [`Child`] and `kennel-init`'s host pid. The privhelper resolves and opens
    /// `kennel-init` itself from root-owned config (never the wire), so it is not passed here.
    ///
    /// Defaults to an error: only the production [`HelperClient`] drives the real factory.
    ///
    /// # Errors
    /// An OS error if the factory cannot be invoked, or [`io::ErrorKind::Unsupported`]
    /// for an impl that does not support construction.
    fn construct_kennel(
        &self,
        _construction_half: &[u8],
        _pty_fd: Option<std::os::fd::RawFd>,
    ) -> io::Result<(Child, i32)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "factory construction not supported by this Privileged impl",
        ))
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
    /// the daemon; see [`kennel_config::Deployment::privhelper`]).
    pub fn new(helper: impl Into<PathBuf>) -> Self {
        Self {
            helper: helper.into(),
        }
    }
}

impl Privileged for HelperClient {
    fn add_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response> {
        kennel_privhelper::client::add_address(&self.helper, ctx, interface, addr, prefix)
    }

    fn del_address(
        &self,
        ctx: u16,
        interface: &str,
        addr: IpAddr,
        prefix: u8,
    ) -> io::Result<Response> {
        kennel_privhelper::client::del_address(&self.helper, ctx, interface, addr, prefix)
    }

    fn setup_egress(&self, cgroup: &Path, payload: &EgressPayload) -> io::Result<Response> {
        kennel_privhelper::client::setup_egress(&self.helper, cgroup.to_path_buf(), payload)
    }

    fn construct_kennel(
        &self,
        construction_half: &[u8],
        pty_fd: Option<std::os::fd::RawFd>,
    ) -> io::Result<(Child, i32)> {
        kennel_privhelper::client::construct_kennel(&self.helper, construction_half, pty_fd)
    }
}

/// How to launch a kennel's egress proxy.
///
/// The `kennel-netproxy` binary plus the directory its per-kennel config is
/// written to. `None` in [`Spec::proxy`] skips the proxy entirely (unit tests, or
/// a setup that does not run one).
#[derive(Debug, Clone)]
pub struct ProxySetup {
    /// The `kennel-netproxy` binary to launch.
    pub binary: PathBuf,
    /// Directory the per-kennel `proxy-<ctx>.toml` config is written to.
    pub config_dir: PathBuf,
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
    pub policy: kennel_policy::BinderRuntime,
    /// The `[[unix.allow]]` grants the af-unix facade resolves and connects (§7.6 via
    /// the binder facade). Empty when the kennel grants no `AF_UNIX` socket.
    pub unix: kennel_policy::UnixRuntime,
    /// The unified audit writer the registry emits through.
    pub writer: std::sync::Arc<kennel_audit::Writer>,
    /// The `kennel-init` binary the privhelper factory `fexecve`s as the kennel's uid-0
    /// PID 1 (`07-2`). When `Some`, `bring_up` constructs the kennel via the factory
    /// (real uid 0, binderfs chowned to the operator); when `None`, it falls back to the
    /// legacy in-process unprivileged spawn (no real uid 0 — the binderfs `EACCES` path).
    pub init_bin: Option<PathBuf>,
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
    /// The unified-audit context for the egress proxy (the `[audit]` block, §02-3):
    /// the kennel name, the shared `kennel_uuid`, the per-kennel state dir
    /// (`~/.local/state/kennel/<kennel>/`, where `network.jsonl` lands), and the
    /// sinks/levels. kenneld creates the dir at bring-up; the logs persist across
    /// runs (not removed at teardown — they are audit data). `None` (or no proxy)
    /// leaves the proxy logging egress to stdout.
    pub proxy_audit: Option<crate::proxy::ProxyAudit>,
    /// The prepared SSH egress (§7.10): the synthetic `~/.ssh` binds, the bastion
    /// host-service to allow, and the in-kennel connector to bind in. Empty
    /// ([`SshPrep::default`]) for a kennel with no `[ssh]` grant.
    pub ssh: SshPrep,
    /// The prepared `AF_UNIX` socket shims (§7.6): host sockets to bind into the view
    /// at their shim paths, plus any env vars to set. Empty ([`UnixPrep::default`])
    /// for a kennel with no `[unix]` grant.
    pub unix: UnixPrep,
    /// The prepared binder IPC context manager (§7.1): the settled binder policy and
    /// the audit writer. `None` for a kennel with no `[binder]` grant (no context
    /// manager is run; the seal still mounts no binderfs because the plan's view
    /// `binder` flag is false in that case).
    pub binder: Option<BinderPrep>,
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
/// consumed by the bring-up: the `kennel-afunix-shim` proxy is bound into the view and
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
    /// The host path of `kennel-afunix-shim` to bind into the view and launch as the
    /// in-kennel broker (§7.6 via the binder facade). `None` (no deployment binary)
    /// leaves the grants unserved rather than falling back to a host-socket bind mount.
    pub afunix_shim_bin: Option<PathBuf>,
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
    /// The host path of `kennel-socks-connect`, bound into the view (read+execute)
    /// so the synthetic `config`'s `ProxyCommand` can run it. `None` when no SSH.
    pub socks_connect_bin: Option<PathBuf>,
}

/// A running kennel: the workload plus what must be torn down when it stops.
#[derive(Debug)]
pub struct Kennel {
    child: Child,
    cgroup: PathBuf,
    ctx: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// The egress-proxy child, if one was launched. Killed and reaped on teardown.
    proxy: Option<Child>,
    /// The constructed-view staging mountpoint, if one was created. Removed on
    /// teardown (the tmpfs mounted on it lived in the workload's now-gone mount
    /// namespace, so only the empty host directory remains).
    view_root: Option<PathBuf>,
    /// The per-kennel binder context manager, if the kennel uses binder. Its serve
    /// thread is stopped at teardown (its node-0 fd and mapping go with it; the
    /// binderfs instance itself died with the workload's mount namespace).
    binder: Option<crate::binder::Manager>,
}

impl Kennel {
    /// The workload's process id.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
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
        match self.child.kill() {
            Ok(()) => Ok(()),
            // The handle already exited — fine, especially once cgroup.kill landed.
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(e) if via_cgroup => {
                // The cgroup kill succeeded; a failure to also signal the (already
                // dying) init handle is not fatal.
                let _ = e;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check whether the workload has exited, without blocking. `Some(status)`
    /// once it has, `None` while it is still running.
    ///
    /// # Errors
    /// An OS error if the status check fails.
    pub fn try_finished(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Wait for the workload to exit, then tear the kennel down: remove the
    /// loopback addresses and the cgroup (which also detaches the egress BPF).
    /// Does not signal the workload — call [`terminate`](Self::terminate) first
    /// for a forced stop. Cleanup is best-effort; returns the workload's exit
    /// status.
    ///
    /// # Errors
    /// An OS error if waiting on the workload fails.
    pub fn stop<P: Privileged>(mut self, privileged: &P) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        if let Some(manager) = self.binder.take() {
            manager.stop();
        }
        teardown(
            privileged,
            self.ctx,
            Some(self.cgroup.as_path()),
            self.v4,
            self.v6,
            self.proxy.take(),
            self.view_root.as_deref(),
        );
        Ok(status)
    }

    /// Wait for the workload to exit, arming the TTL reaper (§9.7), then tear down.
    ///
    /// With no `ttl` this is exactly [`stop`](Self::stop) — a single blocking wait.
    /// With a `ttl`, the wait polls so the reaper can act at expiry; `on_event` is
    /// called as each [`TtlEvent`] occurs (kenneld maps them to audit events):
    ///
    /// - [`TtlAction::Exit`] — at expiry, SIGTERM every cgroup member
    ///   ([`TtlEvent::Terminating`]); if the workload is still alive after `grace`,
    ///   SIGKILL the cgroup ([`TtlEvent::Killed`]). This is the only action that ends
    ///   the kennel.
    /// - [`TtlAction::Warn`] — emit [`TtlEvent::Warned`] once and leave it running.
    /// - [`TtlAction::Renew`] — emit [`TtlEvent::RenewRequested`] once and leave it
    ///   running (the interactive session prompt is not yet wired; §8.1).
    ///
    /// The reaper acts on the live handle's own cgroup, so it never races a released
    /// context: teardown runs only after the wait returns.
    ///
    /// # Errors
    /// An OS error if waiting on the workload fails.
    pub fn stop_with_ttl<P: Privileged>(
        mut self,
        privileged: &P,
        ttl: Option<Duration>,
        action: TtlAction,
        grace: Duration,
        mut on_event: impl FnMut(TtlEvent),
    ) -> io::Result<ExitStatus> {
        let status = match ttl {
            None => self.child.wait()?,
            Some(ttl) => self.wait_with_ttl(ttl, action, grace, &mut on_event)?,
        };
        if let Some(manager) = self.binder.take() {
            manager.stop();
        }
        teardown(
            privileged,
            self.ctx,
            Some(self.cgroup.as_path()),
            self.v4,
            self.v6,
            self.proxy.take(),
            self.view_root.as_deref(),
        );
        Ok(status)
    }

    /// The TTL-aware wait loop. Polls the workload while tracking the deadline; for
    /// `Exit`, runs the SIGTERM→(grace)→SIGKILL escalation against the cgroup.
    fn wait_with_ttl(
        &mut self,
        ttl: Duration,
        action: TtlAction,
        grace: Duration,
        on_event: &mut impl FnMut(TtlEvent),
    ) -> io::Result<ExitStatus> {
        /// How often the wait loop wakes to re-check the deadline and the workload.
        const POLL: Duration = Duration::from_millis(200);
        let start = Instant::now();
        let mut fired = false; // warn/renew emitted, or SIGTERM sent
        let mut terminating_since: Option<Instant> = None;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            let expired = start.elapsed() >= ttl;
            match action {
                TtlAction::Warn if expired && !fired => {
                    on_event(TtlEvent::Warned);
                    fired = true;
                }
                TtlAction::Renew if expired && !fired => {
                    on_event(TtlEvent::RenewRequested);
                    fired = true;
                }
                TtlAction::Exit if expired => match terminating_since {
                    None => {
                        on_event(TtlEvent::Terminating);
                        let _ = cgroup::terminate_cgroup(&self.cgroup);
                        terminating_since = Some(Instant::now());
                    }
                    Some(since) if since.elapsed() >= grace => {
                        on_event(TtlEvent::Killed);
                        let _ = cgroup::kill_cgroup(&self.cgroup);
                        // Next iteration's try_wait reaps the now-killed workload.
                    }
                    Some(_) => {}
                },
                _ => {}
            }
            std::thread::sleep(POLL);
        }
    }
}

/// A TTL-reaper milestone (`docs/design/09-policy-lifecycle.md` §9.7), reported by
/// [`Kennel::stop_with_ttl`] so the caller can audit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlEvent {
    /// `warn` action: the TTL elapsed; the workload is left running.
    Warned,
    /// `renew` action: the TTL elapsed; renewal is requested, workload left running.
    RenewRequested,
    /// `exit` action: the TTL elapsed; the workload was sent SIGTERM (grace started).
    Terminating,
    /// `exit` action: the grace period elapsed; the cgroup was `SIGKILL`ed.
    Killed,
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
        proxy_audit,
        ssh,
        unix,
        binder,
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
        proxy_audit.as_ref(),
        &ssh,
        &unix,
        binder.as_ref(),
        command,
        &mut state,
    ) {
        Ok(child) => Ok(Kennel {
            child,
            cgroup,
            ctx,
            v4: state.v4,
            v6: state.v6,
            proxy: state.proxy,
            view_root: state.view_root,
            binder: state.binder,
        }),
        Err(e) => {
            if let Some(manager) = state.binder.take() {
                manager.stop();
            }
            teardown(
                privileged,
                ctx,
                state.made_cgroup.then_some(cgroup.as_path()),
                state.v4,
                state.v6,
                state.proxy,
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
    proxy_audit: Option<&crate::proxy::ProxyAudit>,
    ssh: &SshPrep,
    unix: &UnixPrep,
    binder: Option<&BinderPrep>,
    command: &mut Command,
    state: &mut Provision,
) -> Result<Child, Error> {
    // 1. cgroup (unprivileged: within kenneld's delegated subtree).
    std::fs::create_dir_all(cgroup)?;
    state.made_cgroup = true;

    // 2. loopback addresses. The proxy's listen offset + port come from the signed
    //    policy (`net.proxy`); offset 1 / port 1080 by default. v4 only when ctx
    //    fits the 8-bit field it carries; a higher ctx is a v6-only kennel.
    let offset = net.proxy.offset;
    let port = net.proxy.port;
    if let Ok(c) = u8::try_from(ctx) {
        let addr = loopback_v4(scope.tag(), c, offset);
        expect_ok(
            "add_address v4",
            privileged.add_address(ctx, LOOPBACK, addr.into(), V4_PREFIX),
        )?;
        state.v4 = Some(addr);
    }
    let addr6 = loopback_v6(scope.ula_gid(), ctx, u64::from(offset));
    expect_ok(
        "add_address v6",
        privileged.add_address(ctx, LOOPBACK, addr6.into(), V6_PREFIX),
    )?;
    state.v6 = Some(addr6);

    // Stamp the egress proxy into the plan before deriving the BPF payload: this
    // adds the flagged allow-entry that lets the workload reach its proxy (and
    // records the proxy in kennel_meta). Without it the BPF would deny every
    // connect, the proxy included, so no egress could flow. `state.v4` is the
    // proxy's v4 address (absent for a v6-only kennel); `addr6` its v6.
    plan.stamp_proxy(&ProxyEndpoint {
        v4: state.v4,
        v6: addr6,
        port,
    });

    // 3. egress BPF (privileged: load + attach in the helper).
    let payload = EgressPayload {
        meta: plan.bpf_meta,
        allow_v4: plan.bpf_allow_v4.clone(),
        deny_v4: plan.bpf_deny_v4.clone(),
        allow_v6: plan.bpf_allow_v6.clone(),
        deny_v6: plan.bpf_deny_v6.clone(),
        bind_allowed_ports: plan.bind_allowed_ports.clone(),
        // The helper pins this kennel's maps under the owner's
        // `/run/user/<uid>/kennel/bpf/<id>/` so kenneld can drain the audit ringbuf
        // and the owner can inspect the maps (§02-7).
        pin_id: id.to_owned(),
    };
    expect_ok("setup_egress", privileged.setup_egress(cgroup, &payload))?;

    // 3b. launch the per-kennel egress proxy, before the workload, so it is
    //     listening on the kennel's address when the first connect() lands. The
    //     proxy is unprivileged (kenneld's child, in the host net namespace); the
    //     BPF already permits the workload to reach it. Skipped when no proxy is
    //     configured (unit tests).
    if let Some(setup) = proxy {
        let listen = proxy_listen(state.v4, addr6, port);
        // The per-kennel audit dir persists across runs; create it but never
        // remove it at teardown (it is audit data, not scratch).
        if let Some(audit) = proxy_audit {
            std::fs::create_dir_all(&audit.dir)?;
        }
        let config =
            crate::proxy::config_toml(net, &listen, proxy_audit, ssh.host_service.as_slice())
                .map_err(Error::ProxyConfig)?;
        std::fs::create_dir_all(&setup.config_dir)?;
        let config_path = setup.config_dir.join(format!("proxy-{ctx}.toml"));
        std::fs::write(&config_path, config)?;
        state.proxy = Some(crate::proxy::spawn(&setup.binary, &config_path).map_err(Error::Proxy)?);
    }

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
            v4: state.v4,
            v6: addr6,
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
            use kennel_syscall::landlock::AccessFs;
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
            use kennel_syscall::landlock::AccessFs;
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

    // 3c-ssh. Lay the synthetic ~/.ssh into the view (config, known_hosts, the
    //     disposable synthetic keys) and point the kennel's ssh at its proxy: the
    //     synthetic config's ProxyCommand SOCKS5s through it to the bastion (§7.10.4).
    //     Empty for a kennel with no [ssh] grant, so nothing changes for it.
    if !ssh.file_binds.is_empty() {
        // Grant Landlock read on the synthetic ~/.ssh dir(s): the files are copied
        // into the view like the synthetic /etc, but unlike /etc the home subtree is
        // not in `fs.read`, so without this `ssh` is denied reading its own config.
        use kennel_syscall::landlock::AccessFs;
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
        // The connector connects to the kennel's own proxy address.
        let proxy_addr = state.v4.map_or_else(
            || SocketAddr::new(addr6.into(), port),
            |v4| SocketAddr::new(v4.into(), port),
        );
        command.env("KENNEL_SOCKS_PROXY", proxy_addr.to_string());
    }

    // 3c-unix. AF_UNIX socket shims (§7.6): bind each granted socket into the view at
    //     its shim path, set env vars, and grant Landlock. The shim model needs the
    //     constructed view (a mount namespace), so it engages only when pivoting.
    let unix_pivoting = view_root.is_some() && plan.view.is_some();
    apply_unix_shims(plan, unix, command, unix_pivoting);

    // 3d. constructed-view wiring (§7.4.5). When the plan carries a shim view and
    //     the daemon gave us a staging mountpoint: point HOME at the shim root,
    //     add the vanilla TLS/linker /etc subtrees the synthetic /etc omits (bound
    //     read-only — distro content, no host specifics), and hand the seal the
    //     new-root staging dir to pivot_root into. Without a view (or staging) the
    //     seal keeps the in-place fallback.
    if view_root.is_some() {
        if let Some(view) = plan.view.as_mut() {
            for sub in crate::etc::essential_etc_subtrees() {
                view.binds.push(kennel_spawn::BindMount {
                    source: sub.clone(),
                    target: sub,
                    writable: false,
                });
            }
            // Bind the SOCKS connector in at its own path (read-only) so the synthetic
            // ssh config's ProxyCommand can exec it.
            if let Some(bin) = &ssh.socks_connect_bin {
                view.binds.push(kennel_spawn::BindMount {
                    source: bin.clone(),
                    target: bin.clone(),
                    writable: false,
                });
            }
            command.env("HOME", &view.shim_root);
        }
        // Grant Landlock execute on the connector (outside the `view` borrow of plan).
        if let Some(bin) = &ssh.socks_connect_bin {
            if plan.view.is_some() {
                use kennel_syscall::landlock::AccessFs;
                plan.landlock_fs
                    .push((bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
            }
        }
    }
    if let Some(view_root) = view_root {
        if plan.view.is_some() {
            std::fs::create_dir_all(view_root)?;
            plan.new_root = Some(view_root.to_path_buf());
            state.view_root = Some(view_root.to_path_buf());
        }
    }

    // 4. Construct the kennel via the privhelper **factory** (`07-2`) — the one spawn path:
    //    the privhelper clones a real-uid-0 kennel, builds the view + binderfs (chowned to the
    //    operator), and `fexecve`s `kennel-init`, which pulls its supervision-half over binder
    //    and spawns + confines the workload. Every kennel runs the factory + a binder bus, so a
    //    `BinderPrep` is required. The privhelper resolves `kennel-init` from its own root-owned
    //    config (never the wire), so kenneld needs no kennel-init path of its own here.
    plan.cgroup = cgroup.to_path_buf();
    let Some(prep) = binder else {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a kennel must be constructed via the factory, which requires a BinderPrep",
        )));
    };
    construct_via_factory(privileged, plan, command, ctx, prep, state)
}

/// The factory construction path (`07-2`): split the plan into its construction- and
/// supervision-halves, have the privhelper factory build the kennel and `fexecve`
/// `kennel-init`, then take binder node 0 via the init pid and serve the lifecycle so
/// `kennel-init` can pull the supervision-half. Returns the long-lived factory process
/// (the kennel's supervisor; its exit status is the workload's).
#[allow(clippy::similar_names)] // drop_uid / drop_gid are the domain names
fn construct_via_factory<P: Privileged + Sync>(
    privileged: &P,
    plan: &Plan,
    command: &Command,
    ctx: u16,
    prep: &BinderPrep,
    state: &mut Provision,
) -> Result<Child, Error> {
    // The masked operator identity every child is dropped to — the caller's real ids,
    // which the construction maps identity-map in (never wire-supplied).
    let drop_uid = kennel_syscall::unistd::real_uid();
    let drop_gid = kennel_syscall::unistd::real_gid();

    let construction = construction_half_from(plan);
    let supervision = supervision_from(plan, command, drop_uid, drop_gid);
    let half_bytes = kennel_spawn::wire::encode_construction(&construction);
    let supervision_bytes = kennel_spawn::wire::encode_supervision(&supervision);

    // The privhelper resolves + opens `kennel-init` itself from root-owned config (never the
    // wire), so kenneld passes no init fd. For an interactive run it does pass the pty return
    // socket (the workload's pty master is sent back over it); the construction child re-homes
    // it at `PTY_RETURN_FD` for `kennel-init`. The fd lives in the plan and is kept open by the
    // caller (`run_kennel`'s `return_sock`) for the duration of construction.
    let (child, init_pid) = privileged.construct_kennel(&half_bytes, plan.interactive_return_fd)?;
    state.factory = true;

    // Take binder node 0 of the kennel's binderfs (mounted by the factory) and serve the
    // lifecycle (gated on the init pid) so kennel-init can pull its supervision-half.
    // kennel-init runs as the operator, so kenneld opens the device via /proc/<init>/root.
    // Best-effort: a failure leaves binder inert but the workload still runs.
    if plan.view.as_ref().is_some_and(|v| v.binder) {
        let init_pid_u32 = u32::try_from(init_pid).unwrap_or(0);
        let lifecycle = crate::binder::Lifecycle {
            init_host_pid: Some(init_pid),
            supervision: supervision_bytes,
        };
        match acquire_binder_node0(|| Some(init_pid_u32), ctx, prep, lifecycle) {
            Ok(manager) => state.binder = Some(manager),
            Err(e) => eprintln!("kenneld: warning: binder context manager not started: {e}"),
        }
    }
    Ok(child)
}

/// Build the construction-half (the privhelper factory's input) from the plan.
fn construction_half_from(plan: &Plan) -> kennel_spawn::ConstructionHalf {
    kennel_spawn::ConstructionHalf {
        namespaces: plan.namespaces,
        cgroup: plan.cgroup.clone(),
        cgroup_join: plan.cgroup_join,
        view: plan.view.clone(),
        new_root: plan.new_root.clone(),
        file_binds: plan.file_binds.clone(),
        // The granted supplementary gids feed the gid_map after the 0 0 1 + operator
        // lines (the factory adds those); empty ⇒ default drop-all-groups.
        granted_gids: plan.supplementary_groups.clone().unwrap_or_default(),
        lo: false, // per-kennel net-ns loopback is future work (07-11)
    }
}

/// Build the supervision-half (what kennel-init pulls) from the plan and the workload
/// `Command`. Reads the program/argv/env/cwd back via the stable `Command` getters, so
/// the command-building in `server.rs` is unchanged by the cutover.
#[allow(clippy::similar_names)] // drop_uid / drop_gid are the domain names
fn supervision_from(
    plan: &Plan,
    command: &Command,
    drop_uid: u32,
    drop_gid: u32,
) -> kennel_spawn::Supervision {
    let program = PathBuf::from(command.get_program());
    let mut argv = vec![command.get_program().to_string_lossy().into_owned()];
    argv.extend(command.get_args().map(|a| a.to_string_lossy().into_owned()));
    let env = command
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())))
        .collect();
    kennel_spawn::Supervision {
        program,
        argv,
        env,
        cwd: command.get_current_dir().map(Path::to_path_buf),
        drop_uid,
        drop_gid,
        // kennel-init runs as the kennel's uid 0 (it holds CAP_SETGID in the userns), so it
        // sets the granted supplementary groups on each child as it drops it to the operator.
        groups: plan.supplementary_groups.clone(),
        landlock_fs: plan.landlock_fs.clone(),
        landlock_net: plan.landlock_net.clone(),
        seccomp_deny: plan.seccomp_deny.clone(),
        seccomp_deny_action: plan.seccomp_deny_action,
        ulimits: plan.ulimits.clone(),
        aux: plan.aux.clone(),
        interactive: plan.interactive_return_fd.is_some(),
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
/// factory path it is `kennel-init` directly. `lifecycle` carries the init-pid gate +
/// supervision-half kenneld serves over node 0 (disabled on the legacy path).
fn acquire_binder_node0(
    resolve_pid: impl Fn() -> Option<u32>,
    ctx: u16,
    prep: &BinderPrep,
    lifecycle: crate::binder::Lifecycle,
) -> io::Result<crate::binder::Manager> {
    use std::os::fd::OwnedFd;

    for _ in 0..150 {
        if let Some(pid) = resolve_pid() {
            let dev = format!("/proc/{pid}/root/dev/binderfs/binder");
            // std opens files O_CLOEXEC by default on Unix.
            if let Ok(file) = std::fs::OpenOptions::new().read(true).write(true).open(&dev) {
                return crate::binder::spawn(
                    OwnedFd::from(file),
                    ctx,
                    prep.policy.clone(),
                    prep.unix.clone(),
                    lifecycle,
                    std::sync::Arc::clone(&prep.writer),
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "kennel binderfs device did not appear",
    ))
}

/// The workload pid: the first child of the `Command`-spawned intermediate (which
/// double-forks the PID-1 workload). `None` until the child exists.
/// The in-view binder device the af-unix proxy transacts the facade over (the seal
/// mounts the per-kennel binderfs here; §7.1).
const IN_VIEW_BINDER_DEVICE: &str = "/dev/binderfs/binder";

/// Wire the `AF_UNIX` socket facade (§7.6 / `07-1` §7.1.5): launch the in-kennel
/// `kennel-afunix-shim` proxy so each granted socket is presented at its in-view path
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
fn apply_unix_shims(plan: &mut Plan, unix: &UnixPrep, command: &mut Command, pivoting: bool) {
    use kennel_syscall::landlock::AccessFs;
    if unix.shims.is_empty() || !pivoting {
        return;
    }
    let Some(shim_bin) = unix.afunix_shim_bin.clone() else {
        eprintln!(
            "kenneld: warning: kennel grants [unix] sockets but no kennel-afunix-shim binary is \
             configured (deployment `afunix_shim`); the sockets will be unserved."
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
        view.binds.push(kennel_spawn::BindMount {
            source: shim_bin.clone(),
            target: shim_bin.clone(),
            writable: false,
        });
    }
    plan.landlock_fs
        .push((shim_bin.clone(), AccessFs::READ_FILE | AccessFs::EXECUTE));
    // The proxy is `execv`'d directly by the seal, so it needs FS_EXECUTE on its own dynamic
    // loader too (the kernel opens PT_INTERP `FMODE_EXEC`); the binary itself is granted
    // above. Its shared libraries load via READ from the view's lib dirs and are not
    // execute-gated (07-3-exec). `skip_missing` drops a loader the view omits.
    let resolution =
        kennel_policy::libresolve::resolve_loaders(&[shim_bin.to_string_lossy().into_owned()]);
    for loader in resolution.loaders {
        plan.landlock_fs
            .push((PathBuf::from(loader), AccessFs::READ_FILE | AccessFs::EXECUTE));
    }
    // Register the proxy as a seal-launched aux: `kennel-afunix-shim <device>
    // <shim-path>=<name> ...`. It runs inside the sealed view, brokers by logical name
    // (which the facade resolves), and dies with the kennel's PID namespace.
    let mut args = vec![IN_VIEW_BINDER_DEVICE.to_owned()];
    for shim in &unix.shims {
        args.push(format!("{}={}", shim.shim_path.display(), shim.name));
    }
    plan.aux.push(kennel_spawn::AuxProcess {
        path: shim_bin,
        args,
    });
}

/// Map a helper response into the orchestration result: a non-`Ok` status is an
/// [`Error::Privileged`].
fn expect_ok(op: &'static str, response: io::Result<Response>) -> Result<(), Error> {
    let response = response?;
    if response.status == Status::Ok {
        Ok(())
    } else {
        Err(Error::Privileged { op, response })
    }
}

/// The socket address the egress proxy listens on: the kennel's primary v4
/// loopback address when it has one, else its v6, at `port`. (The current
/// netproxy binds a single listener; a dual-stack kennel funnels through the v4
/// one. Both proxy addresses are BPF-allowed regardless.)
fn proxy_listen(v4: Option<Ipv4Addr>, v6: Ipv6Addr, port: u16) -> Vec<SocketAddr> {
    // Both loopback addresses the kennel owns: the proxy listens on each, so a
    // dual-stack workload reaches it over v4 or v6. v4 is absent for a v6-only
    // kennel (ctx > 255). One TcpListener binds a single family; the netproxy's
    // serve_all accepts on all of them.
    let mut addrs = Vec::with_capacity(2);
    if let Some(addr) = v4 {
        addrs.push(SocketAddr::new(addr.into(), port));
    }
    addrs.push(SocketAddr::new(v6.into(), port));
    addrs
}

/// Best-effort reverse of bring-up: kill the proxy, remove the addresses, then the
/// cgroup (which detaches the egress BPF). Each step is independent so a failure
/// does not skip the rest.
fn teardown<P: Privileged>(
    privileged: &P,
    ctx: u16,
    cgroup: Option<&Path>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    proxy: Option<Child>,
    view_root: Option<&Path>,
) {
    reap_proxy(proxy);
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
}
