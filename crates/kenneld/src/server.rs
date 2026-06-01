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
/// per-destination allowlist (`docs/07-3-network.md` §7.3.2), two distinct rule
/// sets from one source.
#[derive(Debug)]
pub struct Loaded {
    /// The kernel-enforcement plan.
    pub plan: Plan,
    /// The network policy the egress proxy enforces.
    pub net: NetPolicy,
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
    /// The user's real gid (for the synthetic `/etc/passwd`/`group`).
    pub gid: u32,
    /// The user's account name (for the synthetic `/etc/passwd`/`group`).
    pub username: String,
    /// The user's home directory (`<home>` substitution).
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
}

impl<P: Privileged + Clone, L: PolicyLoader> Shared<P, L> {
    /// Build the shared state for `identity`.
    #[must_use]
    pub fn new(identity: Identity, privileged: P, loader: L) -> Self {
        Self { identity, privileged, loader, registry: Mutex::new(Registry::default()) }
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
    let id = &shared.identity;
    let etc = id.etc_base.as_ref().map(|base| crate::EtcSetup {
        staging_dir: base.join(format!("etc-{ctx}")),
        hostname: req.kennel.clone(),
        username: id.username.clone(),
        uid: id.uid,
        gid: id.gid,
        home: id.home.clone(),
    });
    let spec = crate::Spec {
        cgroup: cgroup::kennel_cgroup(&id.cgroup_base, ctx),
        ctx,
        scope: id.scope.clone(),
        plan: loaded.plan,
        net: loaded.net,
        proxy: id.proxy.clone(),
        etc,
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
                seccomp_allow: Vec::new(),
                seccomp_default: Action::KillProcess,
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
            Ok(Loaded { plan, net })
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
