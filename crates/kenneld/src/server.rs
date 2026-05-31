//! The daemon's request dispatch: the registry of running kennels and the
//! handling of [`control`](crate::control) requests.
//!
//! A [`Daemon`] owns the per-user state — the context allocator and the map of
//! running kennels — and turns a [`Request`] into a [`Response`], driving the
//! orchestration core ([`crate::start`]) for `Start`. Two collaborators are
//! abstracted so this dispatch is testable without root or real policy crypto:
//! [`Privileged`] (the privhelper) and [`PolicyLoader`] (verify + translate a
//! policy file into a [`Plan`]). The socket accept loop and fd transfer live in
//! the binary; this module is the logic.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kennel_privhelper::validate::ReservedScope;
use kennel_spawn::{Plan, RuntimeSubstitutions};

use crate::control::{KennelInfo, Request, Response, StartRequest};
use crate::ctx::CtxAllocator;
use crate::{cgroup, start, Kennel, Privileged};

/// Translate a policy file into an enforcement [`Plan`].
///
/// Abstracted so the dispatch is testable without signed-policy fixtures; the
/// production implementation verifies the signature and substitutes placeholders.
pub trait PolicyLoader {
    /// Load, verify, and substitute the policy at `path` into a [`Plan`].
    ///
    /// # Errors
    /// A human-readable reason if the policy cannot be loaded, fails
    /// verification, or leaves a placeholder unresolved.
    fn load(&self, path: &Path, subst: &RuntimeSubstitutions) -> Result<Plan, String>;
}

/// The identity and resources of the user this daemon serves.
pub struct Identity {
    /// The user's real uid.
    pub uid: u32,
    /// The user's home directory (`<home>` substitution).
    pub home: PathBuf,
    /// The user's reserved scope (tag, ULA GID, namespace).
    pub scope: ReservedScope,
    /// kenneld's own cgroup; kennel cgroups are created as children of it.
    pub cgroup_base: PathBuf,
}

/// One running kennel in the registry.
struct Entry {
    ctx: u16,
    kennel: Kennel,
}

/// The per-user daemon: registry + context allocator + request dispatch.
pub struct Daemon<P: Privileged, L: PolicyLoader> {
    privileged: P,
    loader: L,
    identity: Identity,
    ctx: CtxAllocator,
    kennels: BTreeMap<String, Entry>,
}

impl<P: Privileged, L: PolicyLoader> Daemon<P, L> {
    /// Build a daemon for `identity`, using `privileged` for helper operations
    /// and `loader` to translate policies.
    pub const fn new(identity: Identity, privileged: P, loader: L) -> Self {
        Self { privileged, loader, identity, ctx: CtxAllocator::new(), kennels: BTreeMap::new() }
    }

    /// The number of running kennels (after the last reap).
    #[must_use]
    pub fn running(&self) -> usize {
        self.kennels.len()
    }

    /// Handle one request. `fds` are the caller's stdio (stdin/stdout/stderr),
    /// passed via `SCM_RIGHTS`; only `Start` consumes them.
    pub fn handle(&mut self, request: Request, fds: Vec<OwnedFd>) -> Response {
        // Clean up any kennels whose workload has already exited, so a freed
        // context (and name) is available before we serve this request.
        self.reap_exited();
        match request {
            Request::Start(req) => self.start_kennel(req, fds),
            Request::Stop { kennel } => self.stop_kennel(&kennel),
            Request::List => self.list(),
        }
    }

    fn start_kennel(&mut self, req: StartRequest, fds: Vec<OwnedFd>) -> Response {
        if self.kennels.contains_key(&req.kennel) {
            return Response::Error(format!("kennel `{}` is already running", req.kennel));
        }
        let Some(ctx) = self.ctx.allocate() else {
            return Response::Error("no free context (the kennel limit is reached)".to_owned());
        };

        let subst = RuntimeSubstitutions {
            ctx,
            uid: self.identity.uid,
            kennel: req.kennel.clone(),
            home: self.identity.home.clone(),
            namespace: self.identity.scope.namespace().to_owned(),
        };
        let plan = match self.loader.load(&req.policy, &subst) {
            Ok(plan) => plan,
            Err(reason) => {
                self.ctx.release(ctx);
                return Response::Error(reason);
            }
        };

        let mut command = match command_for(&req.argv, &req.cwd, fds) {
            Ok(command) => command,
            Err(reason) => {
                self.ctx.release(ctx);
                return Response::Error(reason);
            }
        };
        let spec = crate::Spec {
            cgroup: cgroup::kennel_cgroup(&self.identity.cgroup_base, ctx),
            ctx,
            scope: self.identity.scope.clone(),
            plan,
        };
        match start(&self.privileged, spec, &mut command) {
            Ok(kennel) => {
                let pid = kennel.id();
                self.kennels.insert(req.kennel, Entry { ctx, kennel });
                Response::Started { ctx, pid }
            }
            Err(e) => {
                self.ctx.release(ctx);
                Response::Error(e.to_string())
            }
        }
    }

    fn stop_kennel(&mut self, name: &str) -> Response {
        let Some(entry) = self.kennels.remove(name) else {
            return Response::Error(format!("no kennel named `{name}`"));
        };
        let mut kennel = entry.kennel;
        // Force the workload down, then reap + tear down (both best-effort).
        let _ = kennel.terminate();
        let _ = kennel.stop(&self.privileged);
        self.ctx.release(entry.ctx);
        Response::Stopped
    }

    fn list(&mut self) -> Response {
        let kennels = self
            .kennels
            .iter_mut()
            .map(|(name, entry)| KennelInfo {
                kennel: name.clone(),
                ctx: entry.ctx,
                pid: entry.kennel.id(),
                running: matches!(entry.kennel.try_finished(), Ok(None)),
            })
            .collect();
        Response::Listing(kennels)
    }

    /// Remove kennels whose workload has exited, tearing each one down and
    /// returning its context to the pool.
    fn reap_exited(&mut self) {
        let mut exited: Vec<String> = Vec::new();
        for (name, entry) in &mut self.kennels {
            if matches!(entry.kennel.try_finished(), Ok(Some(_))) {
                exited.push(name.clone());
            }
        }
        for name in exited {
            if let Some(entry) = self.kennels.remove(&name) {
                let _ = entry.kennel.stop(&self.privileged);
                self.ctx.release(entry.ctx);
            }
        }
    }
}

impl<P: Privileged, L: PolicyLoader> Drop for Daemon<P, L> {
    /// On shutdown, force every kennel's workload down and tear it down, so no
    /// addresses or cgroups are left behind. (Session end also stops kenneld's
    /// `user@<uid>` slice, which reaps the workloads via the cgroup, but this
    /// makes an explicit daemon exit clean too.)
    fn drop(&mut self) {
        for (_, entry) in std::mem::take(&mut self.kennels) {
            let mut kennel = entry.kennel;
            let _ = kennel.terminate();
            let _ = kennel.stop(&self.privileged);
            self.ctx.release(entry.ctx);
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
        command.stdin(Stdio::from(stdin)).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr));
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;
    use std::net::IpAddr;

    use kennel_privhelper::wire::{EgressPayload, Response as HelperResponse};
    use kennel_syscall::landlock::AccessFs;
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;

    /// A [`Privileged`] that always succeeds and records nothing (the dispatch
    /// tests care about the registry, not the privileged calls — those are
    /// covered by the orchestration-core tests).
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

    /// A loader yielding a trivial, unprivileged-runnable plan (no namespaces, no
    /// cgroup join, permissive Landlock). Records the names it loaded.
    struct FakeLoader {
        loaded: RefCell<Vec<String>>,
    }
    impl PolicyLoader for FakeLoader {
        fn load(&self, _path: &Path, subst: &RuntimeSubstitutions) -> Result<Plan, String> {
            self.loaded.borrow_mut().push(subst.kennel.clone());
            Ok(Plan {
                namespaces: Namespaces::empty(),
                cgroup: PathBuf::new(),
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
            })
        }
    }

    fn daemon() -> Daemon<OkPriv, FakeLoader> {
        let base = std::env::temp_dir().join(format!("kenneld-server-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base cgroup dir");
        Daemon::new(
            Identity {
                uid: 1000,
                home: PathBuf::from("/home/dev"),
                scope: ReservedScope::new(9, [0, 0, 0, 0, 1], "kennel-test"),
                cgroup_base: base,
            },
            OkPriv,
            FakeLoader { loaded: RefCell::new(Vec::new()) },
        )
    }

    fn start_req(name: &str) -> Request {
        Request::Start(StartRequest {
            policy: PathBuf::from("/dev/null"),
            kennel: name.to_owned(),
            // A long-lived workload so the kennel stays registered for the
            // assertions; the daemon's Drop kills it when the test ends.
            argv: vec!["/bin/sleep".to_owned(), "60".to_owned()],
            cwd: PathBuf::from("/"),
        })
    }

    #[test]
    fn start_registers_and_assigns_a_context() {
        let mut d = daemon();
        let resp = d.handle(start_req("ai-coding"), Vec::new());
        assert!(matches!(resp, Response::Started { ctx: 1, .. }), "first kennel gets ctx 1, got {resp:?}");
        assert_eq!(d.running(), 1);
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let mut d = daemon();
        assert!(matches!(d.handle(start_req("dup"), Vec::new()), Response::Started { .. }));
        let again = d.handle(start_req("dup"), Vec::new());
        assert!(matches!(again, Response::Error(_)), "second start of a live name errors, got {again:?}");
    }

    #[test]
    fn stop_releases_the_name_and_context() {
        let mut d = daemon();
        assert!(matches!(d.handle(start_req("x"), Vec::new()), Response::Started { ctx: 1, .. }));
        assert!(matches!(d.handle(Request::Stop { kennel: "x".to_owned() }, Vec::new()), Response::Stopped));
        assert_eq!(d.running(), 0);
        // ctx 1 is free again, so a fresh kennel reuses it.
        assert!(matches!(d.handle(start_req("y"), Vec::new()), Response::Started { ctx: 1, .. }));
    }

    #[test]
    fn stopping_an_unknown_kennel_errors() {
        let mut d = daemon();
        assert!(matches!(d.handle(Request::Stop { kennel: "ghost".to_owned() }, Vec::new()), Response::Error(_)));
    }

    #[test]
    fn list_reports_running_kennels() {
        let mut d = daemon();
        d.handle(start_req("a"), Vec::new());
        d.handle(start_req("b"), Vec::new());
        let resp = d.handle(Request::List, Vec::new());
        assert!(matches!(&resp, Response::Listing(k) if k.len() == 2), "expected two kennels, got {resp:?}");
        if let Response::Listing(mut kennels) = resp {
            kennels.sort_by(|x, y| x.kennel.cmp(&y.kennel));
            let names: Vec<&str> = kennels.iter().map(|k| k.kennel.as_str()).collect();
            assert_eq!(names, ["a", "b"]);
        }
    }
}
