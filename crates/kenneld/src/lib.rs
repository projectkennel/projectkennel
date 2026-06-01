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

pub mod cgroup;
pub mod control;
pub mod ctx;
pub mod etc;
pub mod policy;
pub mod proxy;
pub mod server;
pub mod socket;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};

use kennel_policy::NetPolicy;
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
    fn add_address(&self, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> io::Result<Response>;

    /// Remove `addr/prefix` on `interface` for kennel `ctx`.
    ///
    /// # Errors
    /// As [`add_address`](Self::add_address).
    fn del_address(&self, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> io::Result<Response>;

    /// Load, populate, and attach the egress BPF programs to `cgroup`.
    ///
    /// # Errors
    /// As [`add_address`](Self::add_address).
    fn setup_egress(&self, cgroup: &Path, payload: &EgressPayload) -> io::Result<Response>;
}

/// The production [`Privileged`] implementation: each call invokes the installed
/// setuid privhelper once.
#[derive(Debug, Clone)]
pub struct HelperClient {
    helper: PathBuf,
}

impl HelperClient {
    /// Use the privhelper at `helper`.
    pub fn new(helper: impl Into<PathBuf>) -> Self {
        Self { helper: helper.into() }
    }

    /// Use the privhelper at its installed location
    /// ([`kennel_privhelper::client::DEFAULT_HELPER`]).
    #[must_use]
    pub fn installed() -> Self {
        Self { helper: kennel_privhelper::client::default_helper_path().to_path_buf() }
    }
}

impl Privileged for HelperClient {
    fn add_address(&self, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> io::Result<Response> {
        kennel_privhelper::client::add_address(&self.helper, ctx, interface, addr, prefix)
    }

    fn del_address(&self, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> io::Result<Response> {
        kennel_privhelper::client::del_address(&self.helper, ctx, interface, addr, prefix)
    }

    fn setup_egress(&self, cgroup: &Path, payload: &EgressPayload) -> io::Result<Response> {
        kennel_privhelper::client::setup_egress(&self.helper, cgroup.to_path_buf(), payload)
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
    /// The kennel's hostname (its runtime name).
    pub hostname: String,
    /// The synthetic account name for the workload's uid.
    pub username: String,
    /// The workload's uid.
    pub uid: u32,
    /// The workload's gid.
    pub gid: u32,
    /// The workload's home directory.
    pub home: PathBuf,
}

/// Everything needed to bring one kennel up.
pub struct Spec {
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
        match self.child.kill() {
            Ok(()) => Ok(()),
            // The child already exited — nothing to terminate.
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
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
}

/// Bring a kennel up. On any error the partial bring-up is unwound, so no
/// addresses or cgroup are left behind.
///
/// `command` is the (already-confined-by-`plan`) workload to spawn.
///
/// # Errors
/// Returns [`Error`] at the first failing step (filesystem, a refused/failed
/// privileged operation, or the spawn).
pub fn start<P: Privileged>(privileged: &P, spec: Spec, command: &mut Command) -> Result<Kennel, Error> {
    let Spec { cgroup, ctx, scope, mut plan, net, proxy, etc, view_root } = spec;
    let mut state = Provision::default();

    match bring_up(
        privileged,
        &cgroup,
        ctx,
        &scope,
        &mut plan,
        &net,
        proxy.as_ref(),
        etc.as_ref(),
        view_root.as_deref(),
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
        }),
        Err(e) => {
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
#[allow(clippy::too_many_arguments)]
fn bring_up<P: Privileged>(
    privileged: &P,
    cgroup: &Path,
    ctx: u16,
    scope: &ReservedScope,
    plan: &mut Plan,
    net: &NetPolicy,
    proxy: Option<&ProxySetup>,
    etc: Option<&EtcSetup>,
    view_root: Option<&Path>,
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
        expect_ok("add_address v4", privileged.add_address(ctx, LOOPBACK, addr.into(), V4_PREFIX))?;
        state.v4 = Some(addr);
    }
    let addr6 = loopback_v6(scope.ula_gid(), ctx, u64::from(offset));
    expect_ok("add_address v6", privileged.add_address(ctx, LOOPBACK, addr6.into(), V6_PREFIX))?;
    state.v6 = Some(addr6);

    // Stamp the egress proxy into the plan before deriving the BPF payload: this
    // adds the flagged allow-entry that lets the workload reach its proxy (and
    // records the proxy in kennel_meta). Without it the BPF would deny every
    // connect, the proxy included, so no egress could flow. `state.v4` is the
    // proxy's v4 address (absent for a v6-only kennel); `addr6` its v6.
    plan.stamp_proxy(&ProxyEndpoint { v4: state.v4, v6: addr6, port });

    // 3. egress BPF (privileged: load + attach in the helper).
    let payload = EgressPayload {
        meta: plan.bpf_meta,
        allow_v4: plan.bpf_allow_v4.clone(),
        deny_v4: plan.bpf_deny_v4.clone(),
        allow_v6: plan.bpf_allow_v6.clone(),
        deny_v6: plan.bpf_deny_v6.clone(),
    };
    expect_ok("setup_egress", privileged.setup_egress(cgroup, &payload))?;

    // 3b. launch the per-kennel egress proxy, before the workload, so it is
    //     listening on the kennel's address when the first connect() lands. The
    //     proxy is unprivileged (kenneld's child, in the host net namespace); the
    //     BPF already permits the workload to reach it. Skipped when no proxy is
    //     configured (unit tests).
    if let Some(setup) = proxy {
        let listen = proxy_listen(state.v4, addr6, port);
        let config = crate::proxy::config_toml(net, listen, None).map_err(Error::ProxyConfig)?;
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
            username: &etc.username,
            uid: etc.uid,
            gid: etc.gid,
            home: &etc.home,
            v4: state.v4,
            v6: addr6,
        };
        plan.file_binds = crate::etc::materialize(&etc.staging_dir, &params)?;
    }

    // 3d. constructed-view wiring (§7.2.5). When the plan carries a shim view and
    //     the daemon gave us a staging mountpoint: point HOME at the shim root,
    //     add the vanilla TLS/linker /etc subtrees the synthetic /etc omits (bound
    //     read-only — distro content, no host specifics), and hand the seal the
    //     new-root staging dir to pivot_root into. Without a view (or staging) the
    //     seal keeps the in-place fallback.
    if view_root.is_some() {
        if let Some(view) = plan.view.as_mut() {
            for sub in crate::etc::essential_etc_subtrees() {
                view.binds.push(kennel_spawn::BindMount { source: sub.clone(), target: sub, writable: false });
            }
            command.env("HOME", &view.shim_root);
        }
    }
    if let Some(view_root) = view_root {
        if plan.view.is_some() {
            std::fs::create_dir_all(view_root)?;
            plan.new_root = Some(view_root.to_path_buf());
            state.view_root = Some(view_root.to_path_buf());
        }
    }

    // 4. spawn the workload into this cgroup (it joins itself in the seal).
    plan.cgroup = cgroup.to_path_buf();
    kennel_spawn::spawn(plan, command).map_err(Error::Spawn)
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
fn proxy_listen(v4: Option<Ipv4Addr>, v6: Ipv6Addr, port: u16) -> SocketAddr {
    v4.map_or_else(
        || SocketAddr::new(v6.into(), port),
        |addr| SocketAddr::new(addr.into(), port),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use kennel_syscall::landlock::AccessFs;
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;

    /// A recording [`Privileged`] fake: logs each call and can be set to fail at a
    /// chosen operation, so the bring-up order and its unwind are observable
    /// without root or the real helper.
    struct FakePriv {
        calls: RefCell<Vec<String>>,
        fail_on: Option<&'static str>,
        egress: RefCell<Option<EgressPayload>>,
    }

    impl FakePriv {
        fn new(fail_on: Option<&'static str>) -> Self {
            Self { calls: RefCell::new(Vec::new()), fail_on, egress: RefCell::new(None) }
        }
        fn answer(&self, op: &'static str) -> Response {
            self.calls.borrow_mut().push(op.to_owned());
            if self.fail_on == Some(op) {
                Response::refused(1)
            } else {
                Response::ok()
            }
        }
        fn log(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        /// The egress payload captured at the last `setup_egress` call.
        fn egress(&self) -> EgressPayload {
            self.egress.borrow().clone().expect("setup_egress was called")
        }
    }

    impl Privileged for FakePriv {
        fn add_address(&self, _ctx: u16, _iface: &str, addr: IpAddr, _prefix: u8) -> io::Result<Response> {
            Ok(self.answer(if addr.is_ipv4() { "add v4" } else { "add v6" }))
        }
        fn del_address(&self, _ctx: u16, _iface: &str, addr: IpAddr, _prefix: u8) -> io::Result<Response> {
            Ok(self.answer(if addr.is_ipv4() { "del v4" } else { "del v6" }))
        }
        fn setup_egress(&self, _cgroup: &Path, payload: &EgressPayload) -> io::Result<Response> {
            *self.egress.borrow_mut() = Some(payload.clone());
            Ok(self.answer("setup_egress"))
        }
    }

    /// A unique temp path that stands in for the kennel cgroup directory (the
    /// orchestration core only `create_dir`/`remove_dir`s it).
    fn temp_cgroup(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kenneld-test-{tag}-{}", std::process::id()))
    }

    /// A minimal plan that runs `/bin/true` unprivileged: no namespaces, no
    /// seccomp, permissive Landlock, and no cgroup join (the temp dir is not a
    /// real cgroupfs).
    fn trivial_plan(cgroup: &Path) -> Plan {
        Plan {
            namespaces: Namespaces::empty(),
            cgroup: cgroup.to_path_buf(),
            cgroup_join: false,
            view: None,
            new_root: None,
            landlock_fs: vec![(PathBuf::from("/"), AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE)],
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(),
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
            file_binds: Vec::new(),
        }
    }

    fn spec(cgroup: PathBuf, ctx: u16) -> Spec {
        Spec {
            plan: trivial_plan(&cgroup),
            ctx,
            scope: ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-test"),
            cgroup,
            net: NetPolicy {
                mode: kennel_policy::NetMode::Constrained,
                proxy: kennel_policy::ProxyListen::default(),
                allow: Vec::new(),
                allow_names: Vec::new(),
                deny_invariant: Vec::new(),
            },
            proxy: None,
            etc: None,
            view_root: None,
        }
    }

    #[test]
    fn start_brings_up_in_order_then_stop_tears_down() {
        let cgroup = temp_cgroup("ok");
        let _ = std::fs::remove_dir(&cgroup);
        let fake = FakePriv::new(None);

        let kennel = start(&fake, spec(cgroup.clone(), 5), &mut Command::new("/bin/true")).expect("start");
        assert!(cgroup.is_dir(), "the cgroup directory should have been created");
        assert_eq!(fake.log(), ["add v4", "add v6", "setup_egress"], "bring-up order");

        let status = kennel.stop(&fake).expect("stop");
        assert!(status.success(), "the trivial workload should exit 0");
        assert_eq!(
            fake.log(),
            ["add v4", "add v6", "setup_egress", "del v6", "del v4"],
            "teardown removes addresses in reverse"
        );
        assert!(!cgroup.exists(), "the cgroup directory should have been removed");
    }

    #[test]
    fn a_failed_step_unwinds_what_was_provisioned() {
        let cgroup = temp_cgroup("unwind");
        let _ = std::fs::remove_dir(&cgroup);
        // Fail the egress attach: the two addresses are already added and must be
        // rolled back, and the cgroup removed; the workload must not spawn.
        let fake = FakePriv::new(Some("setup_egress"));

        let err = start(&fake, spec(cgroup.clone(), 5), &mut Command::new("/bin/true")).expect_err("must fail");
        assert!(matches!(&err, Error::Privileged { op, .. } if *op == "setup_egress"), "got {err:?}");
        assert_eq!(
            fake.log(),
            ["add v4", "add v6", "setup_egress", "del v6", "del v4"],
            "a mid-sequence failure unwinds the addresses"
        );
        assert!(!cgroup.exists(), "the cgroup directory should have been removed on unwind");
    }

    #[test]
    fn bring_up_stamps_the_proxy_into_the_egress_payload() {
        let cgroup = temp_cgroup("proxy");
        let _ = std::fs::remove_dir(&cgroup);
        let fake = FakePriv::new(None);

        // scope tag 9, ctx 5 → the proxy is at loopback offset PROXY_HOST.
        let kennel = start(&fake, spec(cgroup, 5), &mut Command::new("/bin/true")).expect("start");
        let payload = fake.egress();
        kennel.stop(&fake).expect("stop");

        // The trivial plan had no allow rules; after stamping, the only v4/v6
        // allow entries are the flagged proxy entries for the addresses kenneld
        // added.
        let want_v4 = loopback_v4(9, 5, PROXY_HOST);
        let want_v6 = loopback_v6([0, 0, 0, 0, 1], 5, u64::from(PROXY_HOST));

        let (key_v4, val_v4) = payload.allow_v4.first().expect("a v4 proxy entry");
        assert_eq!(key_v4.get(4..8), Some(&want_v4.octets()[..]), "proxy v4 host key");
        assert_eq!(val_v4.get(5), Some(&0x01u8), "KENNEL_ALLOW_FLAG_PROXY set");
        assert_eq!(val_v4.get(0..2), Some(&PROXY_PORT.to_ne_bytes()[..]), "proxy port (host order)");

        let (key_v6, val_v6) = payload.allow_v6.first().expect("a v6 proxy entry");
        assert_eq!(key_v6.get(4..20), Some(&want_v6.octets()[..]), "proxy v6 host key");
        assert_eq!(val_v6.get(5), Some(&0x01u8), "KENNEL_ALLOW_FLAG_PROXY set");

        // The meta carries the proxy port (network order, offset 12) and v6 (16).
        assert_eq!(payload.meta.get(12..14), Some(&PROXY_PORT.to_be_bytes()[..]), "meta proxy_port");
        assert_eq!(payload.meta.get(16..32), Some(&want_v6.octets()[..]), "meta proxy_addr_v6");
    }

    #[test]
    fn proxy_offset_and_port_come_from_the_policy() {
        let cgroup = temp_cgroup("proxy-policy");
        let _ = std::fs::remove_dir(&cgroup);
        let fake = FakePriv::new(None);

        let mut s = spec(cgroup, 5);
        s.net.proxy = kennel_policy::ProxyListen { offset: 2, port: 8080 };
        let kennel = start(&fake, s, &mut Command::new("/bin/true")).expect("start");
        let payload = fake.egress();
        kennel.stop(&fake).expect("stop");

        // The flagged proxy allow-entry reflects the policy's offset (2) and port
        // (8080), not the 1/1080 default.
        let want_v4 = loopback_v4(9, 5, 2);
        let (key_v4, val_v4) = payload.allow_v4.first().expect("v4 proxy entry");
        assert_eq!(key_v4.get(4..8), Some(&want_v4.octets()[..]), "v4 key at offset 2");
        assert_eq!(val_v4.get(0..2), Some(&8080u16.to_ne_bytes()[..]), "proxy port from policy");
        assert_eq!(payload.meta.get(12..14), Some(&8080u16.to_be_bytes()[..]), "meta proxy_port from policy");
    }

    #[test]
    fn proxy_is_launched_with_a_written_config() {
        let cgroup = temp_cgroup("proxy-launch");
        let _ = std::fs::remove_dir(&cgroup);
        let dir = std::env::temp_dir().join(format!("kenneld-proxycfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fake = FakePriv::new(None);

        let mut s = spec(cgroup, 5);
        // `/bin/true` stands in for the netproxy: it exits at once, which is fine
        // for asserting the config is written and the launch/teardown plumbing
        // works (a real proxy is exercised by the root e2e).
        s.proxy = Some(ProxySetup { binary: PathBuf::from("/bin/true"), config_dir: dir.clone() });
        s.net.allow_names = vec![kennel_policy::NameRule {
            name: "api.example.com".to_owned(),
            ports: vec![443],
            protocol: kennel_policy::Protocol::Tcp,
        }];

        let kennel = start(&fake, s, &mut Command::new("/bin/true")).expect("start");
        // The per-kennel config was written and carries the policy's name rule.
        let cfg = std::fs::read_to_string(dir.join("proxy-5.toml")).expect("config written");
        assert!(cfg.contains("listen"), "config has a listen address");
        assert!(cfg.contains("api.example.com"), "config carries the by-name allow rule");

        kennel.stop(&fake).expect("stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_proxy_setup_skips_the_proxy() {
        // The default spec has `proxy: None`; bring-up must not write a config or
        // launch anything, and still succeed.
        let cgroup = temp_cgroup("no-proxy");
        let _ = std::fs::remove_dir(&cgroup);
        let fake = FakePriv::new(None);
        let kennel = start(&fake, spec(cgroup, 6), &mut Command::new("/bin/true")).expect("start");
        kennel.stop(&fake).expect("stop");
    }

    #[test]
    fn high_ctx_kennel_has_no_v4_address() {
        // ctx beyond the 8-bit v4 field is v6-only: no v4 add, and teardown skips it.
        let cgroup = temp_cgroup("v6only");
        let _ = std::fs::remove_dir(&cgroup);
        let fake = FakePriv::new(None);

        let kennel = start(&fake, spec(cgroup, 300), &mut Command::new("/bin/true")).expect("start");
        assert_eq!(fake.log(), ["add v6", "setup_egress"], "no v4 for a high ctx");
        kennel.stop(&fake).expect("stop");
        assert_eq!(fake.log(), ["add v6", "setup_egress", "del v6"], "teardown removes only v6");
    }
}
