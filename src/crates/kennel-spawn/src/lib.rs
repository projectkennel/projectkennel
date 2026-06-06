//! Project Kennel spawn orchestration.
//!
//! # Purpose
//!
//! Turn a settled policy into a confined workload. The runtime pipeline is:
//! verify the settled-policy bytes (one signature, schema gate, framework
//! invariants — via [`kennel_policy::verify_settled`]); substitute the
//! per-instance placeholders (`<ctx>`, `<uid>`, `<kennel>`, `<home>`, `<tag>`,
//! `<gid>`, and the masked `<user>`/`<group>`) and refuse any that remain;
//! translate the result into a [`Plan`] of kernel enforcement
//! objects; then apply the plan and exec.
//!
//! This crate holds **no `unsafe`** (`#![forbid(unsafe_code)]`): every syscall
//! routes through `kennel-syscall` and `kennel-bpf`.
//!
//! # Scope of this build
//!
//! The full pipeline is implemented: the pure part (verify → substitute →
//! translate into a [`Plan`], all testable off the spawn path) and the execution
//! step. [`spawn`] applies the irreversible seal in the forked child immediately
//! before `execve` — namespace/mount setup, a fresh `/proc` + private `/tmp`, the
//! synthetic-`/etc` binds, the constructed-`$HOME` `pivot_root`, the Landlock and
//! seccomp seals, and cgroup join — via [`kennel_syscall::spawn::spawn_sealed`], so
//! the post-`fork` `unsafe` stays in the sanctioned crate. Egress BPF is attached by
//! the privhelper out of band. The root e2e exercises the whole vertical.

#![forbid(unsafe_code)]

pub mod plan;

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};

use kennel_policy::{KeySet, PolicyError, SettledPolicy};
use kennel_syscall::landlock::{AccessFs, AccessNet, Ruleset};
use kennel_syscall::namespace::Namespaces;

pub use plan::{BindMount, Plan, ProxyEndpoint, ShimView};

/// The per-instance values the runtime fills into a settled policy's deferred
/// placeholders.
#[derive(Debug, Clone)]
pub struct RuntimeSubstitutions {
    /// The kennel's context number (`<ctx>`), assigned at start. IPv4-enabled
    /// kennels are capped at 255; v6-only kennels may range higher.
    pub ctx: u16,
    /// The user's UID (`<uid>`).
    pub uid: u32,
    /// The kennel's runtime ID (`<kennel>`).
    pub kennel: String,
    /// The user's home directory (`<home>`).
    pub home: PathBuf,
    /// The caller's resource namespace (from `/etc/kennel/subkennel`), under
    /// which this kennel's cgroup lives (`/sys/fs/cgroup/<namespace>/<ctx>`).
    pub namespace: String,
    /// The installation/user tag (`<tag>`) — the 12-bit IPv4 loopback selector from
    /// the caller's scope. A per-user value the daemon already holds; the compiler
    /// defers it here rather than baking an install constant.
    pub tag: u16,
    /// The IPv6 ULA global ID (`<gid>`) — the 40 bits after `0xfd`, from the
    /// caller's scope. Rendered as 10 lowercase hex digits.
    pub ula_gid: [u8; 5],
}

/// Everything that can stop a spawn before exec.
#[derive(Debug)]
pub enum SpawnError {
    /// The settled policy failed verification (signature, schema, invariants).
    Policy(PolicyError),
    /// A placeholder remained after substitution — the policy referenced a
    /// variable the runtime does not provide.
    UnsubstitutedPlaceholder {
        /// The policy field the placeholder was found in.
        field: String,
        /// The offending value.
        value: String,
    },
    /// A syscall during confinement setup or the spawn itself failed.
    Syscall(io::Error),
    /// The settled policy could not be translated into an enforcement plan
    /// (e.g. a malformed CIDR).
    InvalidPolicy(String),
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy verification failed: {e}"),
            Self::UnsubstitutedPlaceholder { field, value } => {
                write!(f, "unsubstituted placeholder in {field}: `{value}`")
            }
            Self::Syscall(e) => write!(f, "confinement/spawn syscall failed: {e}"),
            Self::InvalidPolicy(m) => write!(f, "policy could not be translated: {m}"),
        }
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::Syscall(e) => Some(e),
            Self::UnsubstitutedPlaceholder { .. } | Self::InvalidPolicy(_) => None,
        }
    }
}

impl From<PolicyError> for SpawnError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

/// Replace the deferred placeholders in `s`. `user`/`group` are the policy's own
/// masked identity (`[identity].user`/`.group`, default `kennel`), not runtime
/// context — they are grammar-validated names (§7.2), so safe to splice into paths.
fn substitute_str(s: &str, subst: &RuntimeSubstitutions, user: &str, group: &str) -> String {
    let [g0, g1, g2, g3, g4] = subst.ula_gid;
    let gid = format!("{g0:02x}{g1:02x}{g2:02x}{g3:02x}{g4:02x}");
    s.replace("<ctx>", &subst.ctx.to_string())
        .replace("<uid>", &subst.uid.to_string())
        .replace("<kennel>", &subst.kennel)
        .replace("<home>", &subst.home.to_string_lossy())
        .replace("<tag>", &subst.tag.to_string())
        .replace("<gid>", &gid)
        .replace("<user>", user)
        .replace("<group>", group)
}

/// Error if `value` still contains an unresolved `<…>` placeholder.
fn reject_leftover(field: &str, value: &str) -> Result<(), SpawnError> {
    if value.contains('<') {
        return Err(SpawnError::UnsubstitutedPlaceholder {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Apply the runtime substitutions to a verified settled policy, returning a copy
/// with placeholders filled. Refuses any placeholder that remains unresolved.
///
/// # Errors
///
/// Returns [`SpawnError::UnsubstitutedPlaceholder`] if a path field still
/// contains a `<…>` token after substitution.
pub fn substitute(
    policy: &SettledPolicy,
    subst: &RuntimeSubstitutions,
) -> Result<SettledPolicy, SpawnError> {
    let mut p = policy.clone();
    // The masked identity drives `<user>`/`<group>`; clone before borrowing `fs`.
    let user = p.identity.user.clone();
    let group = p.identity.group.clone();
    let fs = &mut p.effective_policy.fs;

    for path in &mut fs.read {
        *path = substitute_str(path, subst, &user, &group);
        reject_leftover("fs.read", path)?;
    }
    for path in &mut fs.write {
        *path = substitute_str(path, subst, &user, &group);
        reject_leftover("fs.write", path)?;
    }
    for bin in &mut p.effective_policy.exec.allow {
        *bin = substitute_str(bin, subst, &user, &group);
        reject_leftover("exec.allow", bin)?;
    }
    for dir in &mut p.effective_policy.exec.path {
        *dir = substitute_str(dir, subst, &user, &group);
        reject_leftover("exec.path", dir)?;
    }
    {
        let shell = &mut p.effective_policy.exec.shell;
        *shell = substitute_str(shell, subst, &user, &group);
        reject_leftover("exec.shell", shell)?;
    }
    // The synthesised environment (§7.7.2): substitute placeholders in the values
    // (e.g. a HOME under `/home/<user>/…`); keys are fixed var names.
    for value in p.env.vars.values_mut() {
        *value = substitute_str(value, subst, &user, &group);
        reject_leftover("env.set", value)?;
    }

    Ok(p)
}

/// The runtime entry point: verify settled-policy `bytes`, substitute the
/// per-instance placeholders, and produce the enforcement [`Plan`].
///
/// # Errors
///
/// Returns [`SpawnError::Policy`] if verification fails, or
/// [`SpawnError::UnsubstitutedPlaceholder`] if a placeholder is unresolved.
pub fn prepare(
    bytes: &[u8],
    keys: &KeySet,
    subst: &RuntimeSubstitutions,
) -> Result<Plan, SpawnError> {
    let verified = kennel_policy::verify_settled(bytes, keys)?;
    let substituted = substitute(&verified, subst)?;
    Plan::from_policy(&substituted, subst.ctx, &subst.namespace, &subst.home)
}

/// Spawn `command` confined by `plan`.
///
/// Applies the irreversible seal (`no_new_privs`, the seccomp filter, the
/// Landlock ruleset) in the forked child immediately before `execve`, via
/// [`kennel_syscall::spawn::spawn_sealed`].
///
/// The confinement objects are built in the parent (so opens and allocations
/// happen pre-`fork`); the child only issues the sealing syscalls. An empty
/// seccomp denylist means "no seccomp filter" (rely on Landlock + the cgroup BPF);
/// otherwise the denied syscalls get the plan's deny action.
///
/// # Namespaces
///
/// Two paths, selected by whether the plan unshares `USER`:
///
/// * **Unprivileged userns** (the production path): the seal establishes an
///   identity-mapped **user namespace** first ([`establish_identity_userns`]),
///   gaining `CAP_SYS_ADMIN` *within it*, then unshares mount/IPC/PID and forks the
///   PID-1 grandchild ([`fork_into_pid1`]) that builds the view and execs — all with
///   no real privilege. The grandchild is PID 1 of the new PID namespace, which is
///   what lets the constructed view mount a fresh `/proc`.
/// * **Privileged** (no user namespace): `CLONE_NEWPID` is unshared in the
///   **parent** before the `Command` fork so the workload becomes PID 1 (the flag
///   only affects future children); the caller must treat `spawn` as having fork
///   semantics for its own subsequent children. Mount/IPC are unshared in the child
///   seal. Each unshare needs real `CAP_SYS_ADMIN`.
///
/// A caller that wants neither path can pass a plan with no namespaces (the
/// Landlock + seccomp seal stands on its own).
///
/// [`establish_identity_userns`]: kennel_syscall::namespace::establish_identity_userns
/// [`fork_into_pid1`]: kennel_syscall::spawn::fork_into_pid1
///
/// # Scope
///
/// This applies, in the seal: cgroup-join, namespaces, the constructed `pivot_root`
/// view (`$HOME` shadow + a fresh `/proc` and private `/tmp`, hiding non-granted
/// path *names*) when the plan carries one — otherwise an in-place fallback (fresh
/// `/proc` + `/tmp` + single-file shadow binds) — then `no_new_privs`, seccomp, and
/// Landlock. The BPF egress attach is **not** applied here: the privhelper attaches
/// it to the cgroup, separately, before the workload connects.
///
/// # Errors
///
/// Returns [`SpawnError::Syscall`] if a namespace unshare, building the ruleset,
/// the seal, or the spawn fails. A seal failure aborts the spawn fail-closed.
pub fn spawn(plan: &Plan, command: &mut Command) -> Result<Child, SpawnError> {
    spawn_inner(plan, command, None)
}

/// How long the `gid_map` servicer waits between cancellation checks while polling
/// for the spawn child's ready signal.
const HANDSHAKE_TICK_MS: i32 = 100;

/// The closure kenneld supplies to write the workload's userns `gid_map` out of
/// band: given the spawn child's pid, perform the privileged map write (drive the
/// privhelper `set-gid-map` op) and report success/failure.
type GidMapper<'a> = Box<dyn FnOnce(u32) -> io::Result<()> + Send + 'a>;

/// Spawn `command` confined by `plan`, re-granting a supplementary group via a
/// privileged `gid_map` handshake (§7.2.8).
///
/// Identical to [`spawn`] except for the unprivileged userns path: instead of
/// writing the single-line (drop-all) `gid_map` itself, the spawn child
/// establishes its userns with the `gid_map` deferred, signals its pid, and blocks
/// until `map_gids` has written a multi-gid map against that pid. Because
/// `Command::spawn` blocks the calling thread until the child execs, `map_gids` is
/// run on a scoped servicer thread; it is given the child's pid and must perform
/// the privileged write (kenneld drives the privhelper, which holds `CAP_SETGID` in
/// the init userns). A `map_gids` failure aborts the spawn fail-closed: the child
/// receives an abort ack and never execs.
///
/// `map_gids` is only consulted on the userns path; with a non-userns plan this
/// behaves exactly like [`spawn`] and `map_gids` is never called.
///
/// # Errors
///
/// As [`spawn`], plus [`SpawnError::Syscall`] carrying `map_gids`'s error if the
/// privileged map write fails.
pub fn spawn_with_gid_map<F>(
    plan: &Plan,
    command: &mut Command,
    map_gids: F,
) -> Result<Child, SpawnError>
where
    F: FnOnce(u32) -> io::Result<()> + Send,
{
    spawn_inner(plan, command, Some(Box::new(map_gids)))
}

/// Tag a seal-step failure with *which* syscall failed before std collapses the
/// error to a bare errno across its `pre_exec` pipe (an `os error 13` with no name
/// is useless to diagnose). The forked child's stderr is the workload's stderr —
/// the operator's terminal on a foreground `kennel run` — so this is where "which
/// step bombed" actually reaches the user. Logs only on error; success is silent.
fn step<T>(label: &str, r: io::Result<T>) -> io::Result<T> {
    if let Err(e) = &r {
        eprintln!("kennel: spawn seal step `{label}` failed: {e}");
    }
    r
}

/// The shared body of [`spawn`] and [`spawn_with_gid_map`]. With `mapper` `Some`
/// and a userns plan, the spawn child defers its `gid_map` and the handshake runs;
/// otherwise the child writes its own single-line `gid_map` and `mapper` is unused.
// allow: one cohesive seal builder — the pre-fork captures, the two seal closures,
// and the dispatch belong together; splitting them would scatter the post-fork contract.
#[allow(clippy::too_many_lines)]
fn spawn_inner(
    plan: &Plan,
    command: &mut Command,
    mapper: Option<GidMapper<'_>>,
) -> Result<Child, SpawnError> {
    // Build the seccomp filter in the parent (allocation off the seal path). An
    // empty denylist means "no seccomp filter" (rely on Landlock + the cgroup BPF).
    let filter = if plan.seccomp_deny.is_empty() {
        None
    } else {
        Some(plan.seccomp_filter())
    };

    // The constructed-view path (`pivot_root`) engages only with a mount
    // namespace, a policy-derived view, and a runtime staging root. Without all
    // three we keep the in-place fallback seal (fresh `/proc` + private `/tmp` +
    // single-file shadow binds), which is also the unprivileged/no-namespace path.
    let pivoting = plan.namespaces.contains(Namespaces::MOUNT)
        && plan.view.is_some()
        && plan.new_root.is_some();

    // Build the Landlock ruleset in the parent ONLY when not pivoting: there the
    // granted paths resolve to the host inodes the child still sees. When
    // pivoting, the view's inodes (notably the constructed `/etc`, fresh tmpfs
    // inodes a host-opened fd would not match) exist only after `pivot_root`, so
    // the ruleset is built inside the seal, post-pivot.
    let mut parent_ruleset = if pivoting {
        None
    } else {
        Some(
            build_ruleset(&plan.landlock_fs, &plan.landlock_net, false)
                .map_err(SpawnError::Syscall)?,
        )
    };

    // The unprivileged path (production): a plan that unshares USER builds the
    // sandbox via a **user namespace** established in the seal, which grants
    // `CAP_SYS_ADMIN` *inside it* so the mount-namespace work needs no real
    // privilege. The privileged path (no USER, used by the root tests) keeps the
    // parent-side PID unshare so the next fork lands the workload as PID 1.
    let use_userns = plan.namespaces.contains(Namespaces::USER);
    if !use_userns && plan.namespaces.contains(Namespaces::PID) {
        kennel_syscall::namespace::unshare(Namespaces::PID).map_err(SpawnError::Syscall)?;
    }

    // The deferred-gid handshake (§7.2.8) engages only on the userns path and only
    // when a mapper is supplied (a granted supplementary group): the spawn child
    // defers its `gid_map` for the privhelper to write. Two close-on-exec pipes
    // carry the exchange — the child sends "ready, pid=P", then blocks for the
    // servicer's ack. The parent retains the read end of the ready pipe and the
    // write end of the proceed pipe (for the servicer); the child seal keeps the
    // opposite ends.
    let deferred_gid = use_userns && mapper.is_some();
    let (handshake_parent, seal_ready_w, seal_proceed_r) =
        handshake_pipes(deferred_gid).map_err(SpawnError::Syscall)?;
    // USER is established by `establish_identity_userns`, not a plain unshare, so it
    // is always excluded from the seal's unshare set. PID:
    // * userns path — kept in `seal_ns`: the seal unshares it, then forks so the
    //   grandchild is PID 1 (the only way to make the workload PID 1 *and* let it
    //   mount `/proc`; see `kennel_syscall::spawn::fork_into_pid1`).
    // * privileged path — already unshared in the parent above, so excluded here.
    let seal_ns = if use_userns {
        plan.namespaces & !Namespaces::USER
    } else {
        plan.namespaces & !(Namespaces::USER | Namespaces::PID)
    };

    // Captured by the seal closures (clones keep them `'static`).
    let cgroup_join = plan.cgroup_join.then(|| plan.cgroup.clone());
    let file_binds = plan.file_binds.clone();
    let view = plan.view.clone();
    let new_root = plan.new_root.clone();
    let landlock_fs = plan.landlock_fs.clone();
    let landlock_net = plan.landlock_net.clone();
    let supplementary_groups = plan.supplementary_groups.clone();
    let ulimits = plan.ulimits.clone();
    let does_mount = seal_ns.contains(Namespaces::MOUNT);

    // The **inner seal** — the irreversible confinement that must run in the process
    // that ultimately `execve`s the workload: mount/`pivot_root`, the group drop
    // (privileged path only), `no_new_privs`, seccomp, Landlock. On the userns path it
    // runs in the PID-1 grandchild (B, via [`fork_into_pid1`]); on the privileged path it
    // runs inline in the forked child. It must NOT join the cgroup or touch the
    // user/mount/PID namespaces — those are done once, in the outer seal, before the
    // PID-1 fork, so B inherits them.
    //
    // [`fork_into_pid1`]: kennel_syscall::spawn::fork_into_pid1
    let mut inner_seal = move || -> io::Result<()> {
        if does_mount {
            // Detach mount propagation from the host first (`MS_PRIVATE` — stronger
            // than the `MS_SLAVE` of §7.2.10: no propagation in either direction).
            step(
                "make-root-private",
                kennel_syscall::mount::make_root_private(),
            )?;
            if let (Some(v), Some(root)) = (&view, &new_root) {
                // The constructed view: build a fresh root, bind the granted paths
                // into it, construct the synthetic `/etc` + `/dev` + `/proc` +
                // `/tmp`, then `pivot_root` so non-granted path *names* are absent.
                // The fresh `/proc` mount is why this runs as PID 1 on the userns path.
                step(
                    "build-view-and-pivot",
                    build_view_and_pivot(v, root, &file_binds),
                )?;
            } else {
                // Fallback (no view/staging): in-place fresh `/proc` + private
                // `/tmp` + the single-file shadow binds. Landlock still denies
                // access to non-granted paths; only the name-hiding is absent.
                step(
                    "mount-proc",
                    kennel_syscall::mount::mount_special("proc", Path::new("/proc")),
                )?;
                step(
                    "mount-tmp",
                    kennel_syscall::mount::mount_special("tmpfs", Path::new("/tmp")),
                )?;
                step("apply-file-binds", apply_file_binds(&file_binds))?;
            }
        }
        // Drop the inherited host supplementary groups (§7.2). Two regimes:
        //
        // * Privileged path (no USER ns): an explicit `setgroups` to the
        //   granted set — `None` leaves the set untouched, `Some([])` drops all.
        //
        // * Unprivileged userns path: `setgroups` is **denied** by the kernel once
        //   the userns is established (`/proc/self/setgroups` = `deny`, required
        //   before the gid_map). The single-line gid_map maps only the primary gid,
        //   so every inherited supplementary group already collapses to the overflow
        //   gid (`nogroup`) inside the kennel — default drop-all, for free. Calling
        //   `setgroups` here would `EPERM`. Re-granting a *specific* supplementary
        //   group under a userns needs the privhelper (an unprivileged gid_map is
        //   limited to the single effective gid); that is handled out of band.
        if !use_userns {
            if let Some(groups) = &supplementary_groups {
                step(
                    "set-supplementary-groups",
                    kennel_syscall::unistd::set_supplementary_groups(groups),
                )?;
            }
        }
        // no_new_privs next: seccomp requires it (Landlock sets it again, idempotently).
        step(
            "set-no-new-privs",
            kennel_syscall::process::set_no_new_privs(),
        )?;
        if let Some(f) = filter.as_ref() {
            step("install-seccomp", f.install())?;
        }
        // The ruleset: the parent-built one for the fallback path, or built here
        // (post-`pivot_root`, so the fds reference the constructed view's inodes)
        // when pivoting. `skip_missing` drops a grant the view does not contain
        // (vacuous — the path the workload would reach does not exist).
        let rs = match parent_ruleset.take() {
            Some(rs) => rs,
            None => step(
                "build-landlock",
                build_ruleset(&landlock_fs, &landlock_net, true),
            )?,
        };
        step("apply-landlock", rs.restrict_current_process())?;
        // Resource limits last (§7.2): after the Landlock ruleset is built, so
        // lowering `RLIMIT_NOFILE` cannot starve the per-path rule opens, and just
        // before `execve` so the workload inherits exactly the policy's limits.
        for (resource, soft, hard) in &ulimits {
            step(
                "set-rlimit",
                kennel_syscall::process::set_rlimit(*resource, *soft, *hard),
            )?;
        }
        Ok(())
    };

    // The **outer seal** runs in the child std forks. It does the once-only setup
    // that the workload inherits — cgroup join, the user namespace, the
    // mount/IPC/PID unshares — then hands off to the inner seal.
    let seal = move || -> io::Result<()> {
        // Join the cgroup first, before any namespace/mount change: the BPF attached
        // to it only governs members, and cgroup membership inherits across the
        // upcoming PID-1 fork and the exec. The write happens with the host
        // credentials, in the host mount namespace (cgroupfs visible), before the
        // user namespace or Landlock could deny it.
        if let Some(cgroup) = &cgroup_join {
            step("join-cgroup", join_cgroup(cgroup))?;
        }
        if use_userns {
            // The unprivileged foundation: establish an identity-mapped user
            // namespace, gaining `CAP_SYS_ADMIN` *within it* so the unshares and the
            // mount/`pivot_root` need no real privilege. Map our own uid/gid 1:1,
            // read live — this is a fork of kenneld, which runs as the operator.
            let uid = kennel_syscall::unistd::real_uid();
            if let (Some(rw), Some(pr)) = (seal_ready_w.as_ref(), seal_proceed_r.as_ref()) {
                // Granted-supplementary-group path (§7.2.8): establish the userns with
                // the `gid_map` deferred, signal our pid to the servicer, and block
                // until it has written the multi-gid map (via the privhelper, which
                // holds `CAP_SETGID` in the init userns) and acked proceed. An abort
                // (or a closed pipe) fails the seal closed — the workload never execs.
                step(
                    "establish-userns",
                    kennel_syscall::namespace::establish_userns_defer_gid_map(uid),
                )?;
                kennel_syscall::handshake::send_ready(rw.as_fd(), std::process::id())?;
                match kennel_syscall::handshake::recv_ack(pr.as_fd())? {
                    Some(kennel_syscall::handshake::ACK_PROCEED) => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "gid_map handshake aborted: the servicer did not grant proceed",
                        ))
                    }
                }
            } else {
                // Default path: the single-line identity `gid_map` drops every
                // inherited supplementary group to the overflow gid, for free.
                step(
                    "establish-userns",
                    kennel_syscall::namespace::establish_identity_userns(
                        uid,
                        kennel_syscall::unistd::real_gid(),
                    ),
                )?;
            }
            // Unshare mount/IPC/PID here; the PID unshare only takes effect for the
            // next fork, so fork the PID-1 grandchild that runs the inner seal and
            // execs. Returns Ok in the grandchild (std then execs the workload);
            // never returns in this process, which reaps the grandchild and exits.
            if !seal_ns.is_empty() {
                step(
                    "unshare-namespaces",
                    kennel_syscall::namespace::unshare(seal_ns),
                )?;
            }
            kennel_syscall::spawn::fork_into_pid1(&mut inner_seal)
        } else {
            // Privileged path: PID was unshared in the parent, so the child
            // std forked is already in the new PID namespace. No second fork.
            if !seal_ns.is_empty() {
                step(
                    "unshare-namespaces",
                    kennel_syscall::namespace::unshare(seal_ns),
                )?;
            }
            inner_seal()
        }
    };

    match handshake_parent {
        // No handshake: the seal writes its own gid_map (or this is the privileged path).
        None => kennel_syscall::spawn::spawn_sealed(command, seal).map_err(SpawnError::Syscall),
        // Deferred gid_map: service the child's pipe on a thread while the spawn
        // blocks, so the privileged map write lands before the child proceeds.
        Some((ready_r, proceed_w)) => {
            let map_gids = mapper.expect("deferred_gid implies a mapper");
            run_with_gid_map_servicer(command, seal, ready_r, proceed_w, map_gids)
        }
    }
}

/// The handshake pipe ends [`handshake_pipes`] hands out: the parent's
/// `(ready-read, proceed-write)` pair (the servicer's ends), the seal's
/// ready-write end, and the seal's proceed-read end. All `None` when no deferral.
type HandshakePipes = (Option<(OwnedFd, OwnedFd)>, Option<OwnedFd>, Option<OwnedFd>);

/// Create the two close-on-exec handshake pipes when a deferred-gid handshake is
/// needed, returning `(parent ends, child ready-write end, child proceed-read end)`
/// — or all-`None` when `needed` is false. The parent keeps the ready-pipe read end
/// and the proceed-pipe write end (for the servicer); the seal keeps the opposite
/// ends.
///
/// # Errors
///
/// The OS error if a pipe cannot be created.
fn handshake_pipes(needed: bool) -> io::Result<HandshakePipes> {
    if !needed {
        return Ok((None, None, None));
    }
    let (ready_r, ready_w) = kennel_syscall::handshake::pipe_cloexec()?;
    let (proceed_r, proceed_w) = kennel_syscall::handshake::pipe_cloexec()?;
    Ok((Some((ready_r, proceed_w)), Some(ready_w), Some(proceed_r)))
}

/// Spawn `command` with `seal` while a scoped thread services the `gid_map`
/// handshake: it reads the child's pid off `ready_r`, runs `map_gids` (the
/// privileged write), and acks proceed/abort on `proceed_w`.
///
/// `Command::spawn` blocks the calling thread until the child execs, and the child
/// will not exec until the handshake completes — hence the concurrent servicer. If
/// the spawn itself errors (the child failed before signalling), the servicer is
/// cancelled so it does not wait forever (the parent holds a copy of the ready
/// pipe's write end, so EOF alone cannot wake it).
fn run_with_gid_map_servicer<S>(
    command: &mut Command,
    seal: S,
    ready_r: OwnedFd,
    proceed_w: OwnedFd,
    map_gids: GidMapper<'_>,
) -> Result<Child, SpawnError>
where
    S: FnMut() -> io::Result<()> + Send + Sync + 'static,
{
    let cancel = AtomicBool::new(false);
    let cancel_ref = &cancel;
    std::thread::scope(|s| {
        // The closure owns the fds (so they live for, and close at, the handshake's
        // end) and lends borrows to the servicer.
        let servicer = s.spawn(move || {
            gid_map_servicer(ready_r.as_fd(), proceed_w.as_fd(), cancel_ref, map_gids)
        });
        let spawned =
            kennel_syscall::spawn::spawn_sealed(command, seal).map_err(SpawnError::Syscall);
        if spawned.is_err() {
            // Wake the servicer if the child never signalled (it failed early).
            cancel.store(true, Ordering::Relaxed);
        }
        let map_outcome = servicer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("gid_map servicer thread panicked")));
        combine_spawn_and_servicer(spawned, map_outcome)
    })
}

/// The servicer thread body: await the child's pid, perform the privileged map
/// write, and ack. Returns the map-write result; a `BrokenPipe` error marks "the
/// child never signalled" (so the caller prefers the spawn error as the cause).
fn gid_map_servicer(
    ready_r: std::os::fd::BorrowedFd<'_>,
    proceed_w: std::os::fd::BorrowedFd<'_>,
    cancel: &AtomicBool,
    map_gids: GidMapper<'_>,
) -> io::Result<()> {
    use kennel_syscall::handshake;
    let Some(pid) = handshake::recv_ready_cancellable(ready_r, cancel, HANDSHAKE_TICK_MS)? else {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "gid_map handshake: the spawn child never signalled (it failed early or the spawn was cancelled)",
        ));
    };
    match map_gids(pid) {
        Ok(()) => handshake::send_ack(proceed_w, handshake::ACK_PROCEED),
        Err(e) => {
            // Tell the child to abort (best-effort); it fails closed on a non-proceed ack.
            let _ = handshake::send_ack(proceed_w, handshake::ACK_ABORT);
            Err(e)
        }
    }
}

/// Combine the spawn result and the servicer result into one. A running child is
/// success. If the spawn failed: when the servicer reports `BrokenPipe` the child
/// failed before signalling, so the spawn error is the root cause; any other
/// servicer error is a genuine map-write refusal and is the more informative cause.
fn combine_spawn_and_servicer(
    spawned: Result<Child, SpawnError>,
    serviced: io::Result<()>,
) -> Result<Child, SpawnError> {
    match (spawned, serviced) {
        (Ok(child), _) => Ok(child),
        (Err(spawn_err), Ok(())) => Err(spawn_err),
        (Err(spawn_err), Err(map_err)) => {
            if map_err.kind() == io::ErrorKind::BrokenPipe {
                Err(spawn_err)
            } else {
                Err(SpawnError::Syscall(map_err))
            }
        }
    }
}

/// Build (but do not install) a Landlock ruleset from a plan's path and port
/// rules. With `skip_missing`, a path that cannot be opened — absent from the
/// constructed view — is skipped rather than failing the build; a grant for a
/// path the view does not contain is vacuous. The seal builds with `skip_missing`
/// after `pivot_root`; the fallback path builds in the parent without it.
fn build_ruleset(
    fs: &[(PathBuf, AccessFs)],
    net: &[(u16, AccessNet)],
    skip_missing: bool,
) -> io::Result<Ruleset> {
    let mut ruleset = Ruleset::new()?;
    for (path, access) in fs {
        match ruleset.allow_path(path, *access) {
            Ok(()) => {}
            Err(e) if skip_missing && e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    for (port, access) in net {
        ruleset.allow_port(*port, *access);
    }
    Ok(ruleset)
}

/// Construct the kennel's filesystem view in a fresh tmpfs root and `pivot_root`
/// into it (§7.2.5), so non-granted path *names* are absent from the view, not
/// merely access-denied.
///
/// Runs in the forked child's mount-namespace seal, after [`make_root_private`].
/// In order: mount the new root (a tmpfs holding only scaffolding); bind the
/// granted system and `~/…` paths in (same-inode binds, so the post-pivot
/// Landlock rules match, and writable binds resolve to **persistent host
/// inodes** so the work survives teardown); copy the staged synthetic `/etc`
/// (the host `/etc` is never bound in); bind the allowlisted `/dev` nodes;
/// mount a fresh `/proc` and the private `/tmp`; then `pivot_root` and detach the
/// old root.
///
/// [`make_root_private`]: kennel_syscall::mount::make_root_private
fn build_view_and_pivot(
    view: &ShimView,
    new_root: &Path,
    file_binds: &[(PathBuf, PathBuf)],
) -> io::Result<()> {
    use kennel_syscall::mount;

    // Map an absolute in-kennel path to its staging location under `new_root`.
    let under = |abs: &Path| new_root.join(abs.strip_prefix("/").unwrap_or(abs));

    // 1. The new root: a fresh tmpfs (scaffolding only; bound content is host-backed).
    mount::mount_special("tmpfs", new_root)?;

    // 2. Bind the granted system + home paths in. Recursive, so submounts come
    //    along; read-only unless the grant is writable (those resolve to the real
    //    host inode, the persistence guarantee).
    for b in &view.binds {
        let dest = under(&b.target);
        create_bind_target(&b.source, &dest)?;
        mount::bind(&b.source, &dest, true)?;
        if !b.writable {
            mount::remount_readonly(&dest)?;
        }
    }

    // 2b. Merged-usr compat symlinks (`/bin -> usr/bin`, `/lib64 -> usr/lib`, …).
    //    On modern systems these top-level dirs are symlinks into `/usr`; the view's
    //    bound content lives under `/usr`, so without replicating them `/bin/sh`,
    //    `#!/bin/sh` shebangs, and the `/lib64/ld-linux…` loader all `ENOENT`.
    //    Mirror exactly the host's links (only where the host has one and the view
    //    does not already provide the path), so both path resolution and the Landlock
    //    rules on `/bin/…` paths land on the bound `/usr` inodes.
    for link in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] {
        let host = Path::new("/").join(link);
        let Ok(target) = std::fs::read_link(&host) else {
            continue; // not a symlink on this host (non-merged-usr) — nothing to mirror
        };
        let dest = under(&host);
        if dest.symlink_metadata().is_ok() {
            continue; // already present (e.g. bound in by a grant)
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(&target, &dest)?;
    }

    // 3. The synthetic /etc: a fresh dir in the root tmpfs populated with the
    //    staged vanilla files. The host /etc is never bound in (it carries host
    //    specifics). Writes are denied by the Landlock read grant on /etc.
    let etc = under(Path::new("/etc"));
    std::fs::create_dir_all(&etc)?;
    for (source, target) in file_binds {
        let dest = under(target);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, &dest)?;
    }

    // 4. The constructed /dev: a dev-permitting tmpfs with the allowlisted nodes
    //    bind-mounted from the host (same inode, so they function and the Landlock
    //    rules match). nosuid; devices come only from the explicit binds.
    let dev = under(Path::new("/dev"));
    std::fs::create_dir_all(&dev)?;
    mount::mount_tmpfs(&dev, None, Some("0755"), true)?;
    for node in &view.dev_allow {
        let dest = under(node);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A directory dev grant (e.g. `/dev/pts`) is a pty filesystem, not a node:
        // mount a fresh, isolated `devpts` and symlink `/dev/ptmx -> pts/ptmx` so the
        // workload can allocate ptys (the symlink resolves into the Landlock-granted
        // `/dev/pts` subtree). Every other entry is a single node bound from the host.
        if node.is_dir() {
            std::fs::create_dir_all(&dest)?;
            mount::mount_devpts(&dest)?;
            if node == Path::new("/dev/pts") {
                let ptmx = under(Path::new("/dev/ptmx"));
                let _ = std::fs::remove_file(&ptmx);
                std::os::unix::fs::symlink("pts/ptmx", &ptmx)?;
            }
        } else {
            std::fs::File::create(&dest)?;
            mount::bind(node, &dest, false)?;
        }
    }

    // 5. Fresh /proc (reflecting the PID namespace) and the private /tmp.
    let proc = under(Path::new("/proc"));
    std::fs::create_dir_all(&proc)?;
    mount::mount_proc(&proc, view.proc_hidepid)?;
    let tmp = under(Path::new("/tmp"));
    std::fs::create_dir_all(&tmp)?;
    mount::mount_tmpfs(&tmp, Some(view.tmp_size_mib), Some(&view.tmp_mode), false)?;

    // 6. Ensure the shim $HOME exists even if no ~ path was granted, so HOME resolves.
    std::fs::create_dir_all(under(&view.shim_root))?;

    // 7. pivot_root into the new root, then detach the old one.
    let put_old = under(Path::new("/.kennel-oldroot"));
    std::fs::create_dir_all(&put_old)?;
    mount::pivot_root(new_root, &put_old)?;
    std::env::set_current_dir("/")?;
    mount::unmount_detach(Path::new("/.kennel-oldroot"))?;
    let _ = std::fs::remove_dir(Path::new("/.kennel-oldroot"));
    Ok(())
}

/// Create `dest` (and its parent) as the right type to bind `source` over: a
/// directory for a directory source, otherwise an empty file.
fn create_bind_target(source: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if source.is_dir() {
        std::fs::create_dir_all(dest)?;
    } else {
        std::fs::File::create(dest)?;
    }
    Ok(())
}

/// Apply the plan's single-file shadow binds, read-only, in the workload's mount
/// namespace. Each `(source, target)` replaces the kennel's view of `target` with
/// `source` (a bind mount, then a read-only remount). A `target` that does not
/// exist on the host is skipped — there is nothing to bind over, and creating it
/// under a system directory is neither possible (unprivileged) nor wanted.
///
/// Called in the forked child's seal, after the root is made private (so the bind
/// does not propagate to the host) and before Landlock.
fn apply_file_binds(binds: &[(PathBuf, PathBuf)]) -> io::Result<()> {
    for (source, target) in binds {
        if !target.exists() {
            continue;
        }
        kennel_syscall::mount::bind(source, target, false)?;
        kennel_syscall::mount::remount_readonly(target)?;
    }
    Ok(())
}

/// Join the current process into `cgroup` by writing its own pid to
/// `<cgroup>/cgroup.procs`.
///
/// Called in the forked child's seal. The kernel resolves the written pid in the
/// writer's pid namespace, so writing `getpid()` is correct even after the PID
/// namespace has been unshared (the child is pid 1 of the new namespace and the
/// kernel maps it back). The migration is permitted because the destination is a
/// descendant of kenneld's own delegated cgroup subtree.
fn join_cgroup(cgroup: &std::path::Path) -> io::Result<()> {
    let procs = cgroup.join("cgroup.procs");
    std::fs::write(procs, std::process::id().to_string())
}

/// Load the given BPF programs, populate their egress maps, and attach to a cgroup.
///
/// Populates each program's maps from `plan` and attaches it to `cgroup`. Returns
/// the loaded handles, which the caller must keep alive: dropping them closes the
/// map/program fds (and, with the program, the attachment).
///
/// `objects` pairs each program spec with its compiled object bytes (from
/// `kennel_bpf::programs` in production, or compiled in tests). This in-process
/// helper mints each program its own maps and is used by the spawn root tests;
/// the production egress path (the privhelper, `kennel_privhelper::exec`) instead
/// creates one shared map set per kennel (`create_maps` + `load_program_against`)
/// and pins it. Pass the program(s) whose maps you populate (e.g. `connect4` for
/// the v4 egress allowlist).
///
/// # Errors
///
/// Returns [`SpawnError::Syscall`] if loading, map population, or attach fails.
pub fn attach_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
    plan: &Plan,
    objects: &[(&'static kennel_bpf::ProgramSpec, &[u8])],
) -> Result<Vec<kennel_bpf::Loaded>, SpawnError> {
    let mut loaded = Vec::new();
    for (spec, elf) in objects {
        let l = kennel_bpf::load_program(elf, spec, kennel_bpf::KENNEL_MAPS)
            .map_err(SpawnError::Syscall)?;
        populate_egress_maps(&l, plan)?;
        l.attach(cgroup, spec.attach_type)
            .map_err(SpawnError::Syscall)?;
        loaded.push(l);
    }
    Ok(loaded)
}

/// Write the plan's egress entries into whichever of a loaded program's maps it
/// references (`kennel_meta_map`, `allow_v4`, `deny_v4`).
fn populate_egress_maps(loaded: &kennel_bpf::Loaded, plan: &Plan) -> Result<(), SpawnError> {
    use kennel_bpf::sys::BPF_ANY;

    if loaded.maps.contains_key("kennel_meta_map") {
        loaded
            .update_map(
                "kennel_meta_map",
                &0u32.to_ne_bytes(),
                &plan.bpf_meta,
                BPF_ANY,
            )
            .map_err(SpawnError::Syscall)?;
    }
    if loaded.maps.contains_key("allow_v4") {
        for (key, value) in &plan.bpf_allow_v4 {
            loaded
                .update_map("allow_v4", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v4") {
        for (key, value) in &plan.bpf_deny_v4 {
            loaded
                .update_map("deny_v4", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("allow_v6") {
        for (key, value) in &plan.bpf_allow_v6 {
            loaded
                .update_map("allow_v6", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v6") {
        for (key, value) in &plan.bpf_deny_v6 {
            loaded
                .update_map("deny_v6", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_policy::{
        CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, LifecyclePolicy, NetMode,
        NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, SeccompAction,
        SeccompPolicy, SettledPolicy, SigningKey, TmpPolicy, TtlAction,
    };
    use kennel_syscall::landlock::{AccessFs, AccessNet};
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;
    use std::path::Path;

    fn policy_with_placeholders() -> SettledPolicy {
        SettledPolicy {
            settled_schema_version: 1,
            name: "ai-coding".to_owned(),
            deferred_substitutions: vec!["<ctx>".to_owned(), "<home>".to_owned()],
            framework_invariants_asserted: Vec::new(),
            effective_policy: EffectivePolicy {
                net: NetPolicy {
                    mode: NetMode::Constrained,
                    proxy: kennel_policy::ProxyListen::default(),
                    allow: vec![
                        NetRule {
                            cidr: "93.184.216.0".to_owned(),
                            prefix_len: 24,
                            port_min: 443,
                            port_max: 443,
                            protocol: Protocol::Tcp,
                        },
                        NetRule {
                            cidr: "10.1.0.0".to_owned(),
                            prefix_len: 16,
                            port_min: 1024,
                            port_max: 2048,
                            protocol: Protocol::Tcp,
                        },
                    ],
                    allow_names: Vec::new(),
                    deny_invariant: vec![NetRule {
                        cidr: "169.254.169.254".to_owned(),
                        prefix_len: 32,
                        port_min: 0,
                        port_max: 65535,
                        protocol: Protocol::Any,
                    }],
                    bind_port_min: 0,
                    bind_allowed_ports: Vec::new(),
                },
                fs: FsPolicy {
                    home_shadow: true,
                    read: vec!["/usr".to_owned(), "<home>/.config".to_owned()],
                    write: vec!["/run/kennel/<kennel>/home".to_owned()],
                    home_persist: Vec::new(),
                    home_readonly: false,
                    tmp: TmpPolicy {
                        private: true,
                        size_mib: 512,
                        mode: "0700".to_owned(),
                    },
                    dev: DevPolicy {
                        allow: vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()],
                    },
                },
                exec: ExecPolicy {
                    deny_setuid: true,
                    deny_setgid: true,
                    deny_setcap: true,
                    deny_writable: true,
                    allow: vec!["/usr/bin/python3".to_owned()],
                    deny: Vec::new(),
                    path: Vec::new(),
                    shell: "/bin/sh".to_owned(),
                    lib_allow: Vec::new(),
                    lib_deny: Vec::new(),
                    libraries: Vec::new(),
                },
                proc: ProcPolicy {
                    visibility: ProcVisibility::SelfOnly,
                    hidepid: true,
                },
                cap: CapPolicy { no_new_privs: true },
                seccomp: SeccompPolicy {
                    deny_action: SeccompAction::Errno,
                    deny: vec!["bpf".to_owned(), "userfaultfd".to_owned()],
                },
                lifecycle: LifecyclePolicy {
                    ttl_seconds: None,
                    ttl_action: TtlAction::Warn,
                },
            },
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: 1,
                threat_catalogue_version: "0.1".to_owned(),
                leaf_policy_sha256: "00".to_owned(),
                invariant_set_sha256: "00".to_owned(),
                resolved_artifacts: Vec::new(),
            },
            ssh: kennel_policy::SshRuntime::default(),
            unix: kennel_policy::UnixRuntime::default(),
            identity: kennel_policy::IdentityRuntime::default(),
            audit: kennel_policy::AuditRuntime::default(),
            env: kennel_policy::EnvRuntime::default(),
            ulimits: kennel_policy::UlimitsRuntime::default(),
        }
    }

    fn subst() -> RuntimeSubstitutions {
        RuntimeSubstitutions {
            ctx: 7,
            uid: 1000,
            kennel: "ai-coding".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-dev".to_owned(),
            tag: 42,
            ula_gid: [0, 0, 0, 0, 2],
        }
    }

    #[test]
    fn substitution_fills_placeholders() {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        assert_eq!(p.identity.user, "kennel");
        assert_eq!(
            p.effective_policy.fs.read,
            vec!["/usr".to_owned(), "/home/dev/.config".to_owned()]
        );
        assert_eq!(
            p.effective_policy.fs.write,
            vec!["/run/kennel/ai-coding/home".to_owned()]
        );
    }

    #[test]
    fn tag_and_gid_are_filled_from_scope_at_spawn() {
        // <tag>/<gid> are deferred by the compiler and filled here, from the
        // RuntimeSubstitutions the daemon builds from the user's scope.
        let mut p = policy_with_placeholders();
        p.env
            .vars
            .insert("PROXY".to_owned(), "127.<tag>.<ctx>.1".to_owned());
        p.env.vars.insert("ULA".to_owned(), "fd<gid>".to_owned());
        let out = substitute(&p, &subst()).expect("substitute");
        // subst(): tag 42, ctx 7, ula_gid [0,0,0,0,2].
        assert_eq!(
            out.env.vars.get("PROXY").map(String::as_str),
            Some("127.42.7.1")
        );
        assert_eq!(
            out.env.vars.get("ULA").map(String::as_str),
            Some("fd0000000002")
        );
    }

    #[test]
    fn user_and_group_are_filled_from_the_masked_identity() {
        // `<user>`/`<group>` resolve to the policy's own [identity], not runtime
        // context: the default is `kennel`, and an override flows through.
        let mut p = policy_with_placeholders();
        p.identity.user = "claude".to_owned();
        p.identity.group = "staff".to_owned();
        p.effective_policy
            .fs
            .read
            .push("/home/<user>/.cache".to_owned());
        p.env
            .vars
            .insert("WHO".to_owned(), "<user>:<group>".to_owned());
        let out = substitute(&p, &subst()).expect("substitute");
        assert!(out
            .effective_policy
            .fs
            .read
            .contains(&"/home/claude/.cache".to_owned()));
        assert_eq!(
            out.env.vars.get("WHO").map(String::as_str),
            Some("claude:staff")
        );
    }

    #[test]
    fn leftover_placeholder_is_rejected() {
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("<unknown>/x".to_owned());
        let err = substitute(&p, &subst()).expect_err("must reject");
        assert!(
            matches!(&err, SpawnError::UnsubstitutedPlaceholder { field, .. } if field == "fs.read"),
            "got {err:?}"
        );
    }

    #[test]
    fn home_is_writable_by_default_and_readonly_suppresses_the_grant() {
        // shim_root for the default identity (`kennel`).
        let home_root = PathBuf::from("/home/kennel");
        let home_writable = |plan: &Plan| {
            plan.landlock_fs
                .iter()
                .any(|(p, a)| *p == home_root && a.contains(AccessFs::WRITE_FILE))
        };

        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        assert!(
            home_writable(&plan),
            "the constructed home is writable by default"
        );

        let mut ro = policy_with_placeholders();
        ro.effective_policy.fs.home_readonly = true;
        let ro = substitute(&ro, &subst()).expect("substitute");
        let plan = Plan::from_policy(&ro, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        assert!(
            !home_writable(&plan),
            "[fs.home].readonly suppresses the home write grant"
        );
    }

    #[test]
    fn every_ulimit_resource_name_maps_to_a_kernel_resource() {
        // Lock-step with the policy crate's accepted names: a name translate admits
        // must resolve to a Resource here, or a valid policy would fail at spawn.
        for name in kennel_policy::ULIMIT_RESOURCES {
            assert!(
                kennel_syscall::process::resource_by_name(name).is_some(),
                "policy accepts ulimit `{name}` but spawn cannot map it"
            );
        }
    }

    #[test]
    fn ulimits_flow_from_policy_into_the_plan() {
        use kennel_syscall::process::{Resource, RLIM_INFINITY};
        let mut p = policy_with_placeholders();
        p.ulimits
            .limits
            .insert("nofile".to_owned(), "8192".to_owned());
        p.ulimits
            .limits
            .insert("cpu".to_owned(), "unlimited".to_owned());
        p.ulimits
            .limits
            .insert("nproc".to_owned(), "256 512".to_owned());
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let find = |r: Resource| plan.ulimits.iter().find(|(res, _, _)| *res == r).copied();
        assert_eq!(
            find(Resource::RLIMIT_NOFILE),
            Some((Resource::RLIMIT_NOFILE, 8192, 8192))
        );
        assert_eq!(
            find(Resource::RLIMIT_CPU),
            Some((Resource::RLIMIT_CPU, RLIM_INFINITY, RLIM_INFINITY))
        );
        assert_eq!(
            find(Resource::RLIMIT_NPROC),
            Some((Resource::RLIMIT_NPROC, 256, 512))
        );
    }

    #[test]
    fn plan_translates_policy() {
        let mut p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        // The resolved library closure (settled at compile) is what carries EXECUTE for
        // libraries now — not a read-grant heuristic. Seed one to exercise the grant.
        p.effective_policy.exec.libraries = vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned()];
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");

        // Namespaces: user (the unprivileged foundation) + mount/pid/ipc, never net.
        assert_eq!(
            plan.namespaces,
            Namespaces::USER | Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC
        );
        assert!(!plan.namespaces.contains(Namespaces::NET));

        // cgroup lives under the caller's resource namespace, keyed by ctx.
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
        assert!(plan.cgroup_join, "policy-derived plans enter their cgroup");

        // Landlock with the exec allowlist active (exec.allow is non-empty):
        // a read path is read-only and NOT implicitly executable; the
        // allowlisted binary and the loader's lib dirs carry EXECUTE; writes
        // carry write access (§7.1).
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr")
                    && acc.contains(AccessFs::READ_FILE)
                    && !acc.contains(AccessFs::EXECUTE)),
            "with an exec allowlist, a read path must not be executable"
        );
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr/bin/python3")
                    && acc.contains(AccessFs::EXECUTE)),
            "the allowlisted binary gets EXECUTE"
        );
        assert!(
            plan.landlock_fs.iter().any(|(path, acc)| path
                == &PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6")
                && acc.contains(AccessFs::EXECUTE)),
            "a resolved library (settled exec.libraries) gets EXECUTE"
        );
        assert!(
            !plan
                .landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr/lib")
                    && acc.contains(AccessFs::EXECUTE)),
            "a bare read-grant lib dir is NOT executable — only the resolved closure is"
        );
        assert!(plan.landlock_fs.iter().any(|(path, acc)| path
            == &PathBuf::from("/run/kennel/ai-coding/home")
            && acc.contains(AccessFs::WRITE_FILE)));

        // Landlock net: only the single-port (443) TCP rule; the 1024-2048 range
        // is left to BPF.
        assert_eq!(plan.landlock_net, vec![(443u16, AccessNet::CONNECT_TCP)]);

        // Seccomp deny names resolved to numbers, in order.
        assert_eq!(
            plan.seccomp_deny,
            vec![
                kennel_syscall::seccomp::syscall_number("bpf").expect("bpf"),
                kennel_syscall::seccomp::syscall_number("userfaultfd").expect("userfaultfd"),
            ]
        );
        assert_eq!(plan.seccomp_deny_action, Action::Errno(1));

        // The filter builds without panicking.
        let _filter = plan.seccomp_filter();

        // BPF egress: both v4 allow rules encode as (lpm_v4_key, allow_entry).
        // 93.184.216.0/24 :443 TCP -> prefixlen 24, octets, port 443 twice, proto 6.
        assert_eq!(plan.bpf_allow_v4.len(), 2);
        let want_key = {
            let [p0, p1, p2, p3] = 24u32.to_ne_bytes();
            [p0, p1, p2, p3, 93, 184, 216, 0]
        };
        let want_val = {
            let [a, b] = 443u16.to_ne_bytes();
            [a, b, a, b, 6, 0, 0, 0]
        };
        assert_eq!(plan.bpf_allow_v4.first(), Some(&(want_key, want_val)));
        // deny_invariant 169.254.169.254/32 any-proto.
        assert_eq!(plan.bpf_deny_v4.len(), 1);
        // meta: magic "KNEL", abi 1, ctx 7.
        let magic = {
            let [m0, m1, m2, m3] = 0x4B4E_454Cu32.to_ne_bytes();
            [m0, m1, m2, m3]
        };
        assert_eq!(plan.bpf_meta.get(0..4), Some(&magic[..]));
        assert_eq!(plan.bpf_meta.get(6), Some(&7u8), "ctx byte");
    }

    #[test]
    fn empty_exec_allowlist_denies_all_execution() {
        // Deny-by-default: with no exec.allow, a read path is NOT executable — nothing
        // runs. (This is what makes a bare `base-confined` a real floor.)
        let mut p = policy_with_placeholders();
        p.effective_policy.exec.allow.clear();
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        assert!(
            !plan.landlock_fs.iter().any(
                |(path, acc)| path == &PathBuf::from("/usr") && acc.contains(AccessFs::EXECUTE)
            ),
            "with an empty allowlist, read paths must NOT carry EXECUTE"
        );
    }

    #[test]
    fn permissive_exec_wildcard_restores_executable_reads() {
        // The `**` escape hatch (the `permissive-exec` opt-in) restores the open
        // posture: read paths carry EXECUTE again and no per-binary rule is needed.
        let mut p = policy_with_placeholders();
        p.effective_policy.exec.allow = vec!["**".to_owned()];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        assert!(
            plan.landlock_fs.iter().any(
                |(path, acc)| path == &PathBuf::from("/usr") && acc.contains(AccessFs::EXECUTE)
            ),
            "`**` permissive-exec must keep read paths executable"
        );
    }

    #[test]
    fn exec_allow_under_writable_path_is_rejected_when_deny_writable() {
        // deny_writable (§7.1): refuse to make a writable path executable.
        let mut p = policy_with_placeholders(); // deny_writable = true
        p.effective_policy
            .exec
            .allow
            .push("/run/kennel/<kennel>/home/evil".to_owned());
        let err = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect_err("an allowlisted binary under a writable path must be rejected");
        assert!(matches!(err, SpawnError::InvalidPolicy(_)), "got {err:?}");
    }

    #[test]
    fn glob_grants_bind_the_directory_root() {
        // A `/**` or `/*` read/write/dev grant must bind its real directory root, not
        // the literal glob (which has no inode → ENOENT at mount). Regression for the
        // base-confined `/usr/**` / `/dev/pts/**` spawn failures.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("/opt/tools/**".to_owned());
        p.effective_policy.fs.dev.allow = vec!["/dev/pts/**".to_owned()];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan
            .view
            .as_ref()
            .expect("a policy-derived plan carries a view");
        assert!(
            view.binds
                .iter()
                .any(|b| b.source == Path::new("/opt/tools")),
            "a `/opt/tools/**` grant binds the stripped root, got {:?}",
            view.binds
                .iter()
                .map(|b| b.source.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            !view
                .binds
                .iter()
                .any(|b| b.source.to_string_lossy().contains('*')),
            "no bind source may contain a glob"
        );
        assert!(
            view.dev_allow.iter().any(|d| d == Path::new("/dev/pts")),
            "a `/dev/pts/**` dev grant strips to /dev/pts, got {:?}",
            view.dev_allow
        );
    }

    #[test]
    fn view_classifies_system_home_and_etc_paths() {
        // System paths bind at their own location (read-only); paths under the
        // real $HOME remap beneath shim_root; /etc is the constructed synthetic
        // set and is never bound from the host (but still gets a Landlock rule).
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("/etc/ssl".to_owned());
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan
            .view
            .as_ref()
            .expect("a policy-derived plan carries a view");
        assert_eq!(view.shim_root, PathBuf::from("/home/kennel"));

        assert!(
            view.binds.iter().any(|b| b.source == Path::new("/usr")
                && b.target == Path::new("/usr")
                && !b.writable),
            "system path bound at its own location, read-only"
        );
        assert!(
            view.binds
                .iter()
                .any(|b| b.source == Path::new("/home/dev/.config")
                    && b.target == Path::new("/home/kennel/.config")
                    && !b.writable),
            "home path remapped beneath shim_root"
        );
        assert!(
            !view.binds.iter().any(|b| b.source.starts_with("/etc")),
            "no /etc bind: it is constructed"
        );
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, _)| path == &PathBuf::from("/etc/ssl")),
            "the constructed /etc still gets a Landlock rule"
        );
        assert_eq!(
            view.dev_allow,
            vec![PathBuf::from("/dev/null"), PathBuf::from("/dev/urandom")]
        );
        assert!(view.proc_hidepid);
    }

    #[test]
    fn dev_nodes_get_landlock_read_write_ioctl() {
        // Allowlisted devices are Landlock-granted read+write+ioctl (so device
        // ioctls work on them), not merely made visible in the constructed /dev.
        let plan = Plan::from_policy(
            &substitute(&policy_with_placeholders(), &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let want = AccessFs::READ_FILE | AccessFs::WRITE_FILE | AccessFs::IOCTL_DEV;
        for dev in ["/dev/null", "/dev/urandom"] {
            assert!(
                plan.landlock_fs
                    .iter()
                    .any(|(p, a)| p == Path::new(dev) && *a == want),
                "{dev} should carry a read+write+ioctl Landlock rule"
            );
        }
    }

    #[test]
    fn writable_home_grant_binds_to_the_persistent_host_path() {
        // The work an agent writes must outlive the kennel: a writable grant under
        // the real $HOME binds onto the real host inode, not the ephemeral tmpfs.
        let mut p = policy_with_placeholders();
        p.effective_policy
            .fs
            .write
            .push("<home>/projects/foo".to_owned());
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan.view.as_ref().expect("view");
        let bind = view
            .binds
            .iter()
            .find(|b| b.target == Path::new("/home/kennel/projects/foo"))
            .expect("remapped writable bind");
        assert_eq!(
            bind.source,
            PathBuf::from("/home/dev/projects/foo"),
            "writes resolve to the persistent host path"
        );
        assert!(bind.writable);
    }

    #[test]
    fn from_policy_rejects_non_octal_tmp_mode() {
        // A non-octal mode would inject extra comma-separated tmpfs mount options.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.tmp.mode = "0700,size=10G".to_owned();
        let err = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect_err("must reject");
        assert!(matches!(err, SpawnError::InvalidPolicy(_)), "got {err:?}");
    }

    #[test]
    fn from_policy_rejects_dev_paths_that_escape_dev() {
        for bad in ["/etc/shadow", "/dev/../etc/shadow", "/dev"] {
            let mut p = policy_with_placeholders();
            p.effective_policy.fs.dev.allow = vec![bad.to_owned()];
            let err = Plan::from_policy(
                &substitute(&p, &subst()).expect("subst"),
                7,
                "kennel-dev",
                Path::new("/home/dev"),
            )
            .expect_err("must reject");
            assert!(
                matches!(err, SpawnError::InvalidPolicy(_)),
                "{bad} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn v6_rules_encode_to_lpm_v6() {
        let mut p = policy_with_placeholders();
        p.effective_policy.net.allow.push(NetRule {
            cidr: "2606:2800:220::".to_owned(),
            prefix_len: 48,
            port_min: 443,
            port_max: 443,
            protocol: Protocol::Tcp,
        });
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");

        // The two original rules stay v4; the new one lands in v6.
        assert_eq!(plan.bpf_allow_v4.len(), 2);
        assert_eq!(plan.bpf_allow_v6.len(), 1);
        let (key, value) = plan.bpf_allow_v6.first().expect("v6 entry");
        // lpm_v6_key: prefixlen (4 bytes) then the 16 address octets.
        assert_eq!(key.get(0..4), Some(&48u32.to_ne_bytes()[..]));
        let octets = "2606:2800:220::"
            .parse::<std::net::Ipv6Addr>()
            .expect("v6")
            .octets();
        assert_eq!(key.get(4..20), Some(&octets[..]));
        let want_val = {
            let [a, b] = 443u16.to_ne_bytes();
            [a, b, a, b, 6, 0, 0, 0]
        };
        assert_eq!(value, &want_val);
    }

    /// A plan with two v4 allow rules and one deny, from the shared fixture.
    fn fixture_plan() -> Plan {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan")
    }

    #[test]
    fn stamp_proxy_writes_meta_proxy_fields() {
        let mut plan = fixture_plan();
        let v4: std::net::Ipv4Addr = "127.0.144.1".parse().expect("v4");
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(v4),
            v6,
            port: 1080,
        });

        // proxy_addr_v4 @8 (network order = the octets).
        assert_eq!(plan.bpf_meta.get(8..12), Some(&v4.octets()[..]));
        // proxy_port @12 (network order).
        assert_eq!(plan.bpf_meta.get(12..14), Some(&1080u16.to_be_bytes()[..]));
        // _pad0 @14 stays zero.
        assert_eq!(plan.bpf_meta.get(14..16), Some(&[0u8, 0][..]));
        // proxy_addr_v6 @16.
        assert_eq!(plan.bpf_meta.get(16..32), Some(&v6.octets()[..]));
        // The magic/abi/ctx head is untouched.
        assert_eq!(plan.bpf_meta.get(6), Some(&7u8), "ctx byte preserved");
    }

    #[test]
    fn stamp_proxy_adds_a_flagged_allow_entry_v4_and_v6() {
        let mut plan = fixture_plan();
        let before_v4 = plan.bpf_allow_v4.len();
        let before_v6 = plan.bpf_allow_v6.len();
        let v4: std::net::Ipv4Addr = "127.0.144.1".parse().expect("v4");
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(v4),
            v6,
            port: 1080,
        });

        // Exactly one entry appended to each trie; the policy rules are preserved.
        assert_eq!(plan.bpf_allow_v4.len(), before_v4 + 1);
        assert_eq!(plan.bpf_allow_v6.len(), before_v6 + 1);

        // v4 proxy entry: /32 host key + the flagged TCP allow_entry on the port.
        let want_key_v4 = {
            let [p0, p1, p2, p3] = 32u32.to_ne_bytes();
            let [o0, o1, o2, o3] = v4.octets();
            [p0, p1, p2, p3, o0, o1, o2, o3]
        };
        let want_val = {
            let [a, b] = 1080u16.to_ne_bytes();
            [a, b, a, b, 6, 0x01, 0, 0] // port twice (host order), TCP, FLAG_PROXY
        };
        assert_eq!(plan.bpf_allow_v4.last(), Some(&(want_key_v4, want_val)));

        // v6 proxy entry: /128 host key + the same flagged value.
        let (key_v6, val_v6) = plan.bpf_allow_v6.last().expect("v6 proxy entry");
        assert_eq!(key_v6.get(0..4), Some(&128u32.to_ne_bytes()[..]));
        assert_eq!(key_v6.get(4..20), Some(&v6.octets()[..]));
        assert_eq!(val_v6, &want_val);
    }

    #[test]
    fn stamp_proxy_v6_only_kennel_skips_v4() {
        let mut plan = fixture_plan();
        let before_v4 = plan.bpf_allow_v4.len();
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: None,
            v6,
            port: 1080,
        });

        // No v4 entry added, and proxy_addr_v4 in meta stays zero.
        assert_eq!(plan.bpf_allow_v4.len(), before_v4, "no v4 proxy entry");
        assert_eq!(plan.bpf_meta.get(8..12), Some(&[0u8, 0, 0, 0][..]));
        // The v6 entry and meta are still stamped.
        assert_eq!(plan.bpf_meta.get(16..32), Some(&v6.octets()[..]));
        assert_eq!(plan.bpf_meta.get(12..14), Some(&1080u16.to_be_bytes()[..]));
    }

    #[test]
    fn prepare_end_to_end_from_signed_bytes() {
        // Sign the policy, then run the full runtime entry point over its bytes.
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_policy::to_bytes(&doc).expect("bytes");
        let mut ks = KeySet::new();
        ks.insert("k", &key.public_key_bytes()).expect("insert");

        let plan = prepare(&bytes, &ks, &subst()).expect("prepare");
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
        assert_eq!(plan.seccomp_deny.len(), 2, "bpf + userfaultfd resolved");
    }

    #[test]
    fn prepare_rejects_bad_signature() {
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_policy::to_bytes(&doc).expect("bytes");
        let empty = KeySet::new(); // no trusted keys
        let err = prepare(&bytes, &empty, &subst()).expect_err("must reject");
        assert!(matches!(err, SpawnError::Policy(_)), "got {err:?}");
    }

    /// A Landlock-only plan granting read+exec under `read_dirs` and no seccomp.
    fn fs_only_plan(read_dirs: &[&str]) -> Plan {
        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        Plan {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            view: None,
            new_root: None,
            landlock_fs: read_dirs
                .iter()
                .map(|d| (PathBuf::from(*d), access))
                .collect(),
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(), // empty => no seccomp, isolating the Landlock check
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
        }
    }

    /// Paths a dynamically-linked `/bin/sh` + `/bin/cat` need to start.
    const RUNTIME_DIRS: &[&str] = &["/usr", "/bin", "/lib", "/lib64", "/etc"];

    fn landlock_available() -> bool {
        kennel_syscall::landlock::abi_version().is_ok()
    }

    /// Whether the host *forbids* an unprivileged user namespace outright
    /// (`kernel.unprivileged_userns_clone=0` / `user.max_user_namespaces=0`) — the
    /// case where `unshare(CLONE_NEWUSER)` itself fails, distinct from Ubuntu's
    /// capability-stripping restriction (which lets the unshare succeed but denies
    /// the maps with `EACCES`; that one we detect from the spawn error so a loaded
    /// `AppArmor` `userns` profile is correctly observed as "usable").
    fn userns_hard_disabled() -> bool {
        let off = |p: &str| std::fs::read_to_string(p).is_ok_and(|s| s.trim() == "0");
        off("/proc/sys/kernel/unprivileged_userns_clone")
            || off("/proc/sys/user/max_user_namespaces")
    }

    /// Whether `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10+/24.04)
    /// is in force — the restriction a per-binary `AppArmor` `userns` profile lifts.
    fn apparmor_restricts_userns() -> bool {
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|s| s.trim() == "1")
    }

    /// **The foundational premise for the full spawn UNPRIVILEGED:** an ordinary
    /// user builds the complete constructed view — fresh tmpfs root, host binds,
    /// synthetic `/dev`, a fresh `/proc`, private `/tmp`, then `pivot_root` — and
    /// runs a Landlock+seccomp-sealed workload via an identity-mapped user namespace,
    /// with no real privilege. The workload reads a granted `~/…` path through the
    /// shim and finds a non-granted sibling's *name* absent (ENOENT, not merely
    /// denied).
    ///
    /// Runs wherever the host permits an unprivileged user namespace *with
    /// capabilities*; otherwise it **skips with the precise cause** (never a false
    /// pass). Two host conditions cause a skip:
    /// * userns hard-disabled (`unprivileged_userns_clone=0` / `max_user_namespaces=0`);
    /// * Ubuntu's `apparmor_restrict_unprivileged_userns=1` with no `AppArmor`
    ///   profile granting `userns` to this binary (the userns is then
    ///   capability-stripped — surfaces as `PermissionDenied` from the seal).
    ///
    /// To run it under the restriction, load a profile over
    /// `target/debug/deps/kennel_spawn-*` (production ships `dist/apparmor/kenneld`
    /// for the real binary). The PID-1 grandchild ([`fork_into_pid1`]) is what lets
    /// the view mount a fresh `/proc`.
    ///
    /// [`fork_into_pid1`]: kennel_syscall::spawn::fork_into_pid1
    // allow: one cohesive end-to-end proof (stage the view, spawn, assert), kept whole.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn unprivileged_userns_spawn_builds_the_confined_view() {
        use std::io::Read;
        use std::process::Stdio;

        if userns_hard_disabled() {
            eprintln!("SKIP: unprivileged user namespaces are disabled on this host");
            return;
        }
        if !landlock_available() {
            eprintln!("SKIP: kernel without Landlock");
            return;
        }

        // Stage outside the in-kennel /tmp (the seal tmpfs-mounts it): a private
        // base under the system temp dir, with the granted/secret sources and the
        // fresh-root scaffold as siblings (the new root is a tmpfs, so its content
        // comes only from binds whose sources live outside it).
        let base = std::env::temp_dir().join(format!("kennel-userns-spawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real_home = base.join("home");
        let granted = real_home.join("granted");
        let secret = real_home.join("secret");
        std::fs::create_dir_all(&granted).expect("mkdir granted");
        std::fs::create_dir_all(&secret).expect("mkdir secret");
        std::fs::write(granted.join("file"), "GRANTED\n").expect("write granted");
        std::fs::write(secret.join("file"), "SECRET\n").expect("write secret");
        let new_root = base.join("root");
        std::fs::create_dir_all(&new_root).expect("mkdir new_root");

        let shim_root = PathBuf::from("/khome");
        let ro = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let sys = ["/usr", "/bin", "/lib", "/lib64"];
        let mut binds: Vec<BindMount> = sys
            .iter()
            .map(|d| BindMount {
                source: PathBuf::from(*d),
                target: PathBuf::from(*d),
                writable: false,
            })
            .collect();
        binds.push(BindMount {
            source: granted,
            target: shim_root.join("granted"),
            writable: false,
        });

        let mut landlock_fs: Vec<(PathBuf, AccessFs)> =
            sys.iter().map(|d| (PathBuf::from(*d), ro)).collect();
        landlock_fs.push((shim_root.clone(), ro));
        landlock_fs.push((shim_root.join("granted"), ro));

        let plan = Plan {
            // PID is included: the seal unshares it and forks the PID-1 grandchild,
            // which is what lets the constructed view mount a fresh /proc.
            namespaces: Namespaces::USER | Namespaces::MOUNT | Namespaces::IPC | Namespaces::PID,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // isolate the userns/view proof from cgroup delegation
            view: Some(ShimView {
                shim_root: shim_root.clone(),
                binds,
                dev_allow: Vec::new(),
                tmp_size_mib: 64,
                tmp_mode: "0700".to_owned(),
                proc_hidepid: false,
            }),
            new_root: Some(new_root),
            landlock_fs,
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
        };

        // Granted file readable through $HOME; the non-granted sibling's name absent;
        // and /proc is live (a fresh procfs mounted in the user+mount namespace).
        let mut cmd = Command::new("/bin/sh");
        cmd.env("HOME", &shim_root)
            .arg("-c")
            .arg(r#"cat "$HOME/granted/file" && ! test -e "$HOME/secret" && test -r /proc/self/status"#)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let spawned = spawn(&plan, &mut cmd);
        // A userns that was created but capability-stripped surfaces as PermissionDenied
        // from the seal's first privileged step. Not a code defect — this binary has no
        // AppArmor profile granting `userns` (production ships dist/apparmor/kenneld; load
        // an equivalent over the test binary to run this proof). Skip, loudly.
        if let Err(SpawnError::Syscall(e)) = &spawned {
            if e.kind() == io::ErrorKind::PermissionDenied && apparmor_restricts_userns() {
                let _ = std::fs::remove_dir_all(&base);
                eprintln!(
                    "SKIP: kernel.apparmor_restrict_unprivileged_userns=1 and this test binary \
                     has no AppArmor profile granting `userns` (load one over \
                     target/debug/deps/kennel_spawn-* to run this proof): {e}"
                );
                return;
            }
        }
        let mut child = spawned.expect("unprivileged userns spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            status.success(),
            "granted readable, secret name absent, /proc live (got {status:?})"
        );
        assert_eq!(
            out.trim(),
            "GRANTED",
            "the granted file is readable through the shim"
        );
    }

    /// **A `[ulimits]` cap reaches the workload (§7.2.12).** A userns spawn whose plan
    /// carries `RLIMIT_NOFILE = 64` runs `sh -c 'ulimit -n'`; the workload reports the
    /// limit the seal applied (after Landlock, before `execve`). Skips with the precise
    /// cause where the host forbids the userns, exactly like the confined-view proof.
    #[test]
    fn unprivileged_userns_spawn_applies_a_ulimit() {
        use kennel_syscall::process::Resource;
        use std::io::Read;
        use std::process::Stdio;

        if userns_hard_disabled() || !landlock_available() {
            eprintln!("SKIP: unprivileged user namespaces or Landlock unavailable on this host");
            return;
        }

        let base =
            std::env::temp_dir().join(format!("kennel-userns-ulimit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let new_root = base.join("root");
        std::fs::create_dir_all(&new_root).expect("mkdir new_root");

        let shim_root = PathBuf::from("/khome");
        let ro = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let sys = ["/usr", "/bin", "/lib", "/lib64"];
        let binds: Vec<BindMount> = sys
            .iter()
            .map(|d| BindMount {
                source: PathBuf::from(*d),
                target: PathBuf::from(*d),
                writable: false,
            })
            .collect();
        let mut landlock_fs: Vec<(PathBuf, AccessFs)> =
            sys.iter().map(|d| (PathBuf::from(*d), ro)).collect();
        landlock_fs.push((shim_root.clone(), ro));

        let plan = Plan {
            namespaces: Namespaces::USER | Namespaces::MOUNT | Namespaces::IPC | Namespaces::PID,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false,
            view: Some(ShimView {
                shim_root: shim_root.clone(),
                binds,
                dev_allow: Vec::new(),
                tmp_size_mib: 64,
                tmp_mode: "0700".to_owned(),
                proc_hidepid: false,
            }),
            new_root: Some(new_root),
            landlock_fs,
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
            ulimits: vec![(Resource::RLIMIT_NOFILE, 64, 64)],
        };

        let mut cmd = Command::new("/bin/sh");
        cmd.env("HOME", &shim_root)
            .arg("-c")
            .arg("ulimit -n")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let spawned = spawn(&plan, &mut cmd);
        if let Err(SpawnError::Syscall(e)) = &spawned {
            if e.kind() == io::ErrorKind::PermissionDenied && apparmor_restricts_userns() {
                let _ = std::fs::remove_dir_all(&base);
                eprintln!("SKIP: this test binary has no AppArmor profile granting `userns`: {e}");
                return;
            }
        }
        let mut child = spawned.expect("unprivileged userns spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_dir_all(&base);

        assert!(status.success(), "workload ran (got {status:?})");
        assert_eq!(
            out.trim(),
            "64",
            "the workload sees the policy's RLIMIT_NOFILE soft limit"
        );
    }

    /// **The `gid_map` handshake, proven unprivileged (§7.2.8).** A userns spawn goes
    /// through [`spawn_with_gid_map`]: the child defers its `gid_map`, signals its
    /// pid, and blocks; the servicer thread runs the mapper, which writes the child's
    /// `gid_map`, then acks; only then does the workload exec. The mapper here writes
    /// a single identity line for the *operator's own* gid — the one `gid_map` an
    /// unprivileged parent is permitted to write — which stands in for the
    /// privhelper's multi-gid write and keeps the proof root-free. The workload reads
    /// its own `id -g`: it equals the operator gid only if the deferred map was
    /// actually written (an empty deferred map would leave the primary gid at the
    /// overflow gid). Skips with the precise cause where the host forbids the userns,
    /// exactly as [`unprivileged_userns_spawn_builds_the_confined_view`].
    #[test]
    fn unprivileged_userns_spawn_runs_the_gid_map_handshake() {
        use std::io::Read;
        use std::process::Stdio;

        if userns_hard_disabled() || !landlock_available() {
            eprintln!("SKIP: unprivileged user namespaces or Landlock unavailable on this host");
            return;
        }

        let gid = kennel_syscall::unistd::real_gid();
        // The mapper stands in for kenneld driving the privhelper: it writes the
        // deferred gid_map against the child's pid. A single identity line for the
        // caller's own gid is the one an unprivileged parent may write.
        let map_gids = move |pid: u32| {
            std::fs::write(format!("/proc/{pid}/gid_map"), format!("{gid} {gid} 1\n"))
        };

        // A minimal userns plan: USER|MOUNT|IPC|PID with the in-place fallback view
        // (fresh /proc + /tmp), permissive Landlock so `id` can run, no seccomp.
        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let plan = Plan {
            namespaces: Namespaces::USER | Namespaces::MOUNT | Namespaces::IPC | Namespaces::PID,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false,
            view: None,
            new_root: None,
            landlock_fs: vec![(PathBuf::from("/"), access)],
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
            // The setgroups field is unused on the userns path; the handshake carries
            // the group grant instead.
            supplementary_groups: None,
            ulimits: Vec::new(),
        };

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("id -g")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let spawned = spawn_with_gid_map(&plan, &mut cmd, map_gids);
        // A capability-stripped userns (Ubuntu AppArmor) surfaces as PermissionDenied
        // from the seal's first privileged step — skip loudly, as the sibling proof does.
        if let Err(SpawnError::Syscall(e)) = &spawned {
            if e.kind() == io::ErrorKind::PermissionDenied && apparmor_restricts_userns() {
                eprintln!(
                    "SKIP: kernel.apparmor_restrict_unprivileged_userns=1 and this test binary \
                     has no AppArmor profile granting `userns`: {e}"
                );
                return;
            }
        }
        let mut child = spawned.expect("userns spawn with gid_map handshake");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");

        assert!(status.success(), "the workload ran (got {status:?})");
        assert_eq!(
            out.trim(),
            gid.to_string(),
            "the deferred gid_map was written by the mapper before exec, so the primary gid is the operator's, not the overflow gid"
        );
    }

    #[test]
    fn landlock_seal_blocks_an_unlisted_path() {
        if !landlock_available() {
            return; // kernel without Landlock; the seal cannot be exercised here.
        }
        // A readable file whose directory is deliberately NOT in the allowlist.
        let secret = std::env::temp_dir().join("kennel-spawn-landlock-secret");
        std::fs::write(&secret, b"top secret").expect("write secret");

        let plan = fs_only_plan(RUNTIME_DIRS);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("exec cat {}", secret.display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_file(&secret);

        assert!(
            !status.success(),
            "Landlock should have blocked reading the unlisted path (got {status:?})"
        );
    }

    #[test]
    fn landlock_seal_allows_a_listed_path() {
        if !landlock_available() {
            return;
        }
        // /etc/hostname is under /etc, which is in the allowlist.
        let plan = fs_only_plan(RUNTIME_DIRS);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("exec cat /etc/hostname")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "reading an allowed path under the confinement should succeed (got {status:?})"
        );
    }
}

/// Privileged tests (namespace unshare needs `CAP_SYS_ADMIN`). Run with
/// `sudo -E env PATH=$PATH cargo test -p kennel-spawn --features root-tests`.
/// Kept to a single test so its parent-side `CLONE_NEWPID` unshare (which moves
/// the *caller's* future children into a new PID namespace) cannot perturb other
/// tests in the same process.
#[cfg(all(test, feature = "root-tests"))]
mod root_tests {
    use super::*;
    use kennel_syscall::landlock::AccessFs;
    use kennel_syscall::namespace::Namespaces;
    use kennel_syscall::seccomp::Action;
    use std::io::Read;
    use std::process::{Command, Stdio};

    /// Skip a privilege-requiring test with cause on an unprivileged runner (a
    /// skip is not a proof), matching the other crates' root-tests so `cargo test
    /// --all-features` is green for any runner while `sudo … --features
    /// root-tests` still exercises it.
    fn skip_if_unprivileged(test: &str) -> bool {
        let euid = kennel_syscall::unistd::effective_uid();
        if euid != 0 {
            eprintln!("skipping {test}: requires root (euid={euid}) for the privileged spawn");
            return true;
        }
        false
    }

    #[test]
    fn pid_and_mount_namespace_isolate_the_workload() {
        if skip_if_unprivileged("pid_and_mount_namespace_isolate_the_workload") {
            return;
        }
        // mount/pid/ipc isolation, Landlock allowing just enough to run a shell
        // and read /proc, no seccomp. A new PID namespace makes the shell PID 1;
        // the freshly-mounted /proc shows only the namespace's own processes.
        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let dirs = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"];
        let plan = Plan {
            namespaces: Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            view: None,
            new_root: None,
            landlock_fs: dirs.iter().map(|d| (PathBuf::from(*d), access)).collect(),
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
        };

        // Report "<pid>:<number of visible /proc PID dirs>".
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo \"$$:$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)\"")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "the shell should have run (got {status:?})"
        );

        let out = out.trim();
        let (pid, nproc) = out.split_once(':').unwrap_or(("", ""));
        assert_eq!(
            pid, "1",
            "in a new PID namespace the workload is PID 1 (got {out:?})"
        );
        let nproc: usize = nproc.parse().unwrap_or(usize::MAX);
        // Host /proc would show hundreds; the isolated namespace shows a handful.
        assert!(
            nproc < 20,
            "fresh /proc should show only the namespace's processes (saw {nproc})"
        );
    }

    #[test]
    fn file_binds_shadow_targets_in_the_kennel() {
        if skip_if_unprivileged("file_binds_shadow_targets_in_the_kennel") {
            return;
        }
        // Stage a synthetic file and bind it over a target (the /etc-shadow idiom).
        // Outside /tmp, which spawn covers with a fresh tmpfs. A non-existent target
        // is included to prove it is skipped rather than failing the spawn.
        let dir = PathBuf::from(format!("/run/kennel-spawn-binds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir staging");
        let src = dir.join("synthetic");
        let target = dir.join("target");
        std::fs::write(&src, "SYNTHETIC\n").expect("write src");
        std::fs::write(&target, "ORIGINAL\n").expect("write target");
        let missing = dir.join("does-not-exist");

        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let mut landlock_fs: Vec<(PathBuf, AccessFs)> = ["/usr", "/bin", "/lib", "/lib64"]
            .iter()
            .map(|d| (PathBuf::from(*d), access))
            .collect();
        landlock_fs.push((dir.clone(), access));
        let plan = Plan {
            namespaces: Namespaces::MOUNT, // mount ns only: no parent PID unshare
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false,
            view: None,
            new_root: None,
            landlock_fs,
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(),
            seccomp_deny_action: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
            bind_allowed_ports: Vec::new(),
            file_binds: vec![(src.clone(), target.clone()), (src, missing)],
            supplementary_groups: None,
            ulimits: Vec::new(),
        };

        let mut cmd = Command::new("/bin/cat");
        cmd.arg(&target)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "cat should run (got {status:?}); the missing target must be skipped"
        );
        assert_eq!(
            out.trim(),
            "SYNTHETIC",
            "the bound synthetic file shadows the target"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pivot_root_hides_non_granted_names() {
        if skip_if_unprivileged("pivot_root_hides_non_granted_names") {
            return;
        }
        // The constructed view (§7.2.5) must make a non-granted sibling's NAME
        // absent (ENOENT), not merely access-denied, while a granted path stays
        // readable through the shim. Staged outside /tmp (the seal tmpfs-mounts
        // /tmp). namespaces = MOUNT only, so the parent harness is undisturbed.
        let base = PathBuf::from(format!("/run/kennel-spawn-pivot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real_home = base.join("home");
        let granted = real_home.join("granted");
        let secret = real_home.join("secret");
        std::fs::create_dir_all(&granted).expect("mkdir granted");
        std::fs::create_dir_all(&secret).expect("mkdir secret");
        std::fs::write(granted.join("file"), "GRANTED\n").expect("write granted");
        std::fs::write(secret.join("file"), "SECRET\n").expect("write secret");
        let new_root = base.join("root");
        std::fs::create_dir_all(&new_root).expect("mkdir new_root");

        let shim_root = PathBuf::from("/khome");
        let ro = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let sys = ["/usr", "/bin", "/lib", "/lib64"];
        let mut binds: Vec<BindMount> = sys
            .iter()
            .map(|d| BindMount {
                source: PathBuf::from(*d),
                target: PathBuf::from(*d),
                writable: false,
            })
            .collect();
        // The one granted ~ path, remapped beneath the shim root.
        binds.push(BindMount {
            source: granted,
            target: shim_root.join("granted"),
            writable: false,
        });

        // Landlock rules reference the post-pivot targets (built in the seal).
        let mut landlock_fs: Vec<(PathBuf, AccessFs)> =
            sys.iter().map(|d| (PathBuf::from(*d), ro)).collect();
        landlock_fs.push((shim_root.clone(), ro));
        landlock_fs.push((shim_root.join("granted"), ro));

        let plan = Plan {
            namespaces: Namespaces::MOUNT,
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false,
            view: Some(ShimView {
                shim_root: shim_root.clone(),
                binds,
                dev_allow: Vec::new(),
                tmp_size_mib: 64,
                tmp_mode: "0700".to_owned(),
                proc_hidepid: false,
            }),
            new_root: Some(new_root),
            landlock_fs,
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
        };

        // Granted file readable through $HOME, and the non-granted sibling's name
        // absent (`! test -e` is true only when it does not exist).
        let mut cmd = Command::new("/bin/sh");
        cmd.env("HOME", &shim_root)
            .arg("-c")
            .arg(r#"cat "$HOME/granted/file" && ! test -e "$HOME/secret""#)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            status.success(),
            "granted path readable and non-granted name absent (got {status:?})"
        );
        assert_eq!(
            out.trim(),
            "GRANTED",
            "the granted file is readable through the shim"
        );
    }

    use std::net::TcpListener;
    use std::os::fd::AsFd;
    use std::path::Path;

    /// A Landlock/seccomp-free plan that only carries BPF egress data: allow
    /// 127.0.0.1/32 on any protocol/port when `allow_loopback`, else nothing.
    fn egress_plan(allow_loopback: bool) -> Plan {
        let allow = if allow_loopback {
            // 127.0.0.1/32, ports 0..=65535, any protocol.
            vec![(
                {
                    let [p0, p1, p2, p3] = 32u32.to_ne_bytes();
                    [p0, p1, p2, p3, 127, 0, 0, 1]
                },
                {
                    let [hi0, hi1] = u16::MAX.to_ne_bytes();
                    [0, 0, hi0, hi1, 0, 0, 0, 0]
                },
            )]
        } else {
            Vec::new()
        };
        Plan {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::from("/sys/fs/cgroup/kennel/0"),
            cgroup_join: false, // these tests join manually / isolate other layers
            view: None,
            new_root: None,
            landlock_fs: Vec::new(),
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(),
            seccomp_deny_action: Action::KillProcess,
            bpf_allow_v4: allow,
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
            bind_allowed_ports: Vec::new(),
            file_binds: Vec::new(),
            supplementary_groups: None,
            ulimits: Vec::new(),
        }
    }

    /// Connect to `127.0.0.1:port` from inside `cgroup_dir` via a child process
    /// (no `unsafe` here): the child joins the cgroup, then opens a TCP
    /// connection with bash's `/dev/tcp`. Returns whether the connect succeeded.
    fn connect_from_cgroup(cgroup_dir: &Path, port: u16) -> bool {
        let script = format!(
            "echo $$ > {}/cgroup.procs && exec 3<>/dev/tcp/127.0.0.1/{port}",
            cgroup_dir.display()
        );
        Command::new("/bin/bash")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run bash")
            .success()
    }

    /// Attach connect4 to a fresh cgroup with `plan`'s egress maps, run `body`
    /// while attached, then remove the cgroup (which also detaches the program).
    fn with_egress_cgroup(name: &str, plan: &Plan, body: impl FnOnce(&Path)) {
        let cg_path = PathBuf::from(format!("/sys/fs/cgroup/{name}"));
        let _ = std::fs::create_dir(&cg_path);
        let cgfd = std::fs::File::open(&cg_path).expect("open cgroup");
        let elf = kennel_bpf::programs::object("connect4").expect("embedded connect4 object");
        let spec = kennel_bpf::KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        let _loaded = attach_egress(cgfd.as_fd(), plan, &[(spec, elf)]).expect("attach_egress");
        body(&cg_path);
        // The child has exited, so the cgroup is empty; removing it detaches.
        let _ = std::fs::remove_dir(&cg_path);
    }

    #[test]
    fn bpf_egress_enforces_the_allowlist() {
        if skip_if_unprivileged("bpf_egress_enforces_the_allowlist") {
            return;
        }
        // A listener so a permitted connect *succeeds* (vs. a denied one failing
        // with EPERM) — success/failure cleanly distinguishes allow from deny.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("addr").port();

        let mut allowed = false;
        with_egress_cgroup("kennel-spawn-egress-allow", &egress_plan(true), |cg| {
            allowed = connect_from_cgroup(cg, port);
        });

        let mut denied = false;
        with_egress_cgroup("kennel-spawn-egress-deny", &egress_plan(false), |cg| {
            denied = !connect_from_cgroup(cg, port);
        });

        assert!(
            allowed,
            "connect to an allowlisted destination should be permitted"
        );
        assert!(
            denied,
            "connect with an empty allowlist should be denied (fail closed)"
        );
    }

    #[test]
    fn spawn_joins_the_workload_into_its_cgroup() {
        if skip_if_unprivileged("spawn_joins_the_workload_into_its_cgroup") {
            return;
        }
        // The workload, spawned with `cgroup_join`, should write itself into the
        // cgroup in the seal — so its /proc/self/cgroup reports that cgroup. Run
        // as root, which may write any cgroup.procs; the delegated-subtree case
        // (unprivileged migration within user@<uid>) is covered separately.
        let name = "kennel-spawn-join-test";
        let cg_path = PathBuf::from(format!("/sys/fs/cgroup/{name}"));
        let _ = std::fs::remove_dir(&cg_path);
        std::fs::create_dir(&cg_path).expect("create cgroup");

        let access = AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE;
        let plan = Plan {
            namespaces: Namespaces::empty(),
            cgroup: cg_path.clone(),
            cgroup_join: true,
            view: None,
            new_root: None,
            landlock_fs: vec![(PathBuf::from("/"), access)], // permissive: isolate the join
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
        };

        let mut cmd = Command::new("/bin/cat");
        cmd.arg("/proc/self/cgroup")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(&plan, &mut cmd).expect("spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read stdout");
        assert!(
            child.wait().expect("wait").success(),
            "the workload should have run"
        );

        assert!(
            out.contains(name),
            "the workload's /proc/self/cgroup should name its kennel cgroup (got {out:?})"
        );
        let _ = std::fs::remove_dir(&cg_path);
    }
}
