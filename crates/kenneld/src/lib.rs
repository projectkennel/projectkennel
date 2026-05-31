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
pub mod policy;
pub mod server;
pub mod socket;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};

use kennel_privhelper::addr::{loopback_v4, loopback_v6, V4_PREFIX, V6_PREFIX};
use kennel_privhelper::validate::ReservedScope;
use kennel_privhelper::wire::{EgressPayload, Response, Status};
use kennel_spawn::{Plan, SpawnError};

/// Host offset of the kennel's proxy within its subnet (`…|0001` in v4, `::1` in
/// v6). The proxy is where confined egress is funnelled once it lands.
pub const PROXY_HOST: u8 = 1;

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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cgroup filesystem operation failed: {e}"),
            Self::Privileged { op, response } => {
                write!(f, "privileged operation `{op}` failed: {response:?}")
            }
            Self::Spawn(e) => write!(f, "workload spawn failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Spawn(e) => Some(e),
            Self::Privileged { .. } => None,
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
}

/// A running kennel: the workload plus what must be torn down when it stops.
#[derive(Debug)]
pub struct Kennel {
    child: Child,
    cgroup: PathBuf,
    ctx: u16,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
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
        teardown(privileged, self.ctx, Some(self.cgroup.as_path()), self.v4, self.v6);
        Ok(status)
    }
}

/// What bring-up has provisioned so far, for unwind.
#[derive(Default)]
struct Provision {
    made_cgroup: bool,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
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
    let Spec { cgroup, ctx, scope, mut plan } = spec;
    let mut state = Provision::default();

    match bring_up(privileged, &cgroup, ctx, &scope, &mut plan, command, &mut state) {
        Ok(child) => Ok(Kennel { child, cgroup, ctx, v4: state.v4, v6: state.v6 }),
        Err(e) => {
            teardown(privileged, ctx, state.made_cgroup.then_some(cgroup.as_path()), state.v4, state.v6);
            Err(e)
        }
    }
}

/// The bring-up steps, recording provisioning into `state` as it goes.
fn bring_up<P: Privileged>(
    privileged: &P,
    cgroup: &Path,
    ctx: u16,
    scope: &ReservedScope,
    plan: &mut Plan,
    command: &mut Command,
    state: &mut Provision,
) -> Result<Child, Error> {
    // 1. cgroup (unprivileged: within kenneld's delegated subtree).
    std::fs::create_dir_all(cgroup)?;
    state.made_cgroup = true;

    // 2. loopback addresses. v4 only when ctx fits the 8-bit field it carries;
    //    a higher ctx is a v6-only kennel.
    if let Ok(c) = u8::try_from(ctx) {
        let addr = loopback_v4(scope.tag(), c, PROXY_HOST);
        expect_ok("add_address v4", privileged.add_address(ctx, LOOPBACK, addr.into(), V4_PREFIX))?;
        state.v4 = Some(addr);
    }
    let addr6 = loopback_v6(scope.ula_gid(), ctx, u64::from(PROXY_HOST));
    expect_ok("add_address v6", privileged.add_address(ctx, LOOPBACK, addr6.into(), V6_PREFIX))?;
    state.v6 = Some(addr6);

    // 3. egress BPF (privileged: load + attach in the helper).
    let payload = EgressPayload {
        meta: plan.bpf_meta,
        allow_v4: plan.bpf_allow_v4.clone(),
        deny_v4: plan.bpf_deny_v4.clone(),
        allow_v6: plan.bpf_allow_v6.clone(),
        deny_v6: plan.bpf_deny_v6.clone(),
    };
    expect_ok("setup_egress", privileged.setup_egress(cgroup, &payload))?;

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

/// Best-effort reverse of bring-up: remove the addresses, then the cgroup (which
/// detaches the egress BPF). Each step is independent so a failure does not skip
/// the rest.
fn teardown<P: Privileged>(privileged: &P, ctx: u16, cgroup: Option<&Path>, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) {
    if let Some(addr) = v6 {
        let _ = privileged.del_address(ctx, LOOPBACK, addr.into(), V6_PREFIX);
    }
    if let Some(addr) = v4 {
        let _ = privileged.del_address(ctx, LOOPBACK, addr.into(), V4_PREFIX);
    }
    if let Some(cg) = cgroup {
        let _ = std::fs::remove_dir(cg);
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
    }

    impl FakePriv {
        fn new(fail_on: Option<&'static str>) -> Self {
            Self { calls: RefCell::new(Vec::new()), fail_on }
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
    }

    impl Privileged for FakePriv {
        fn add_address(&self, _ctx: u16, _iface: &str, addr: IpAddr, _prefix: u8) -> io::Result<Response> {
            Ok(self.answer(if addr.is_ipv4() { "add v4" } else { "add v6" }))
        }
        fn del_address(&self, _ctx: u16, _iface: &str, addr: IpAddr, _prefix: u8) -> io::Result<Response> {
            Ok(self.answer(if addr.is_ipv4() { "del v4" } else { "del v6" }))
        }
        fn setup_egress(&self, _cgroup: &Path, _payload: &EgressPayload) -> io::Result<Response> {
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
            bind_read: Vec::new(),
            bind_write: Vec::new(),
            landlock_fs: vec![(PathBuf::from("/"), AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE)],
            landlock_net: Vec::new(),
            seccomp_allow: Vec::new(),
            seccomp_default: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
        }
    }

    fn spec(cgroup: PathBuf, ctx: u16) -> Spec {
        Spec {
            plan: trivial_plan(&cgroup),
            ctx,
            scope: ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-test"),
            cgroup,
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
