//! `kennel-init` — the kennel's uid-0 PID 1.
//!
//! # Role
//!
//! The privhelper *factory* constructs the kennel (user/mount/PID/IPC namespaces, the
//! `0 0 1`+operator identity maps, the cgroup join, the in-namespace `lo`, the view,
//! the binderfs mount + device chown, and the `pivot_root`) and then `fexecve`s this
//! binary as the kennel's uid-0 PID 1 with **empty argv/envp** (`docs/design/07-2`).
//! So by the time `main` runs the host filesystem is already gone, this process holds
//! uid 0 *only inside the kennel's user namespace* (no ambient host capabilities), and
//! there is nothing on the command line.
//!
//! `kennel-init` is a pure supervisor. It does **not** mount, pivot, provision binderfs,
//! configure the network, join the cgroup, write maps, or evaluate policy — all of that
//! already happened in the factory. It only:
//!
//! 1. **Pulls** its supervision-half over binder (`GET_SANDBOX_PLAN` to node 0), the
//!    in-view binder device being the one the factory mounted. The reply carries the
//!    `kennel-spawn::wire::encode_supervision` bytes (a plain data reply). For an interactive
//!    run the controlling-pty return socket is NOT pulled here — the factory placed it at
//!    `kennel_syscall::pty::PTY_RETURN_FD`, which this process inherited across the `fexecve`.
//! 2. Acts as the **spawn owner**: forks each facade and the workload, dropping every
//!    one to the masked operator identity (`set_gid` → `set_supplementary_groups` →
//!    `set_uid`) before `execve`. Facades exec unconfined (they must reach the bus); the
//!    workload additionally gets the controlling pty, `no_new_privs`, seccomp, Landlock,
//!    and ulimits.
//! 3. **Supervises**: reaps every child (it is PID 1). A crashed facade is re-forked
//!    within a bounded, systemd-style policy (short delay, burst limit per window; past
//!    that it is left down — a failed helper must not take the kennel with it). On the
//!    workload's exit it terminates with the workload's status, which the factory (this
//!    process's parent) relays up the chain to `kenneld`. The workload is never restarted.
//!
//! The crate is `#![forbid(unsafe_code)]`: every fork/exec/drop/wait primitive lives in
//! `kennel-syscall`, every binder primitive in `kennel-binder`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kennel_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_binder::service::lifecycle;
use kennel_spawn::wire::decode_supervision;
use kennel_spawn::{AuxProcess, Supervision};
use kennel_syscall::process::{set_no_new_privs, set_rlimit, wait_any_interruptible, Reaped};
use kennel_syscall::spawn::{fork_drop_exec, fork_drop_exec_confined};

/// The in-view binder device the factory mounts (`07-1` §7.1): a fixed path, because the
/// pull model gives `kennel-init` no argv to carry it.
const IN_VIEW_BINDER_DEVICE: &str = "/dev/binderfs/binder";
/// The binder buffer mapping size for the pull connection.
const MAP_SIZE: usize = 128 * 1024;
/// How many times to retry the plan pull while `kenneld` is still claiming node 0.
const PULL_RETRIES: u32 = 1000;
/// Backoff between pull retries (≈10s total worst case before giving up).
const PULL_BACKOFF: Duration = Duration::from_millis(10);

// --- Facade restart policy (hardcoded, after systemd's defaults — deliberately not a
// per-kennel knob; §7.2 supervision). A crashed facade is re-forked after a short delay,
// up to a bounded burst within a window; past that it is left down (systemd's behaviour —
// a failed helper does not take the rest of the kennel with it). The workload is never
// restarted: its exit is the kennel's exit.
/// Delay before re-forking a crashed facade (≈ systemd `RestartSec`).
const RESTART_DELAY: Duration = Duration::from_millis(100);
/// Max (re)starts of one facade within [`START_LIMIT_INTERVAL`] (systemd `StartLimitBurst`).
const START_LIMIT_BURST: usize = 5;
/// The window the burst is counted over (systemd `StartLimitIntervalSec`).
const START_LIMIT_INTERVAL: Duration = Duration::from_secs(10);

/// Per-facade supervisor state: which `Supervision::aux` entry it runs, and the recent
/// start instants used to enforce the restart burst limit.
struct FacadeState {
    aux: usize,
    starts: Vec<Instant>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("kennel-init: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Open the bus, pull the supervision-half, own the spawn, and supervise to exit.
fn run() -> io::Result<u8> {
    require_kennel_userns()?;
    let conn = open_bus()?;
    let bytes = pull_plan(&conn)?;
    let sup = decode_supervision(&bytes)
        .map_err(|e| io::Error::other(format!("supervision-half decode failed: {e:?}")))?;
    // One synthesised environment, shared by the facades, the workload, and any facade the
    // supervisor re-forks (execve replaces env, so a borrow is enough). Built once here.
    let envp = env_cstrings(&sup.env)?;
    // The interactive pty return socket (when `sup.interactive`) was placed at `PTY_RETURN_FD`
    // by the factory before our `fexecve` — it is not pulled over the bus.
    let (workload_pid, facade_pids) = spawn_all(&conn, &sup, &envp)?;
    supervise(&conn, workload_pid, &sup, &envp, &facade_pids)
}

/// Refuse to run anywhere but a kennel's user namespace.
///
/// `kennel-init` is only ever `fexecve`d by the privhelper factory as PID 1 of a fresh,
/// restricted user namespace whose `uid_map` maps host root as a single id (`0 0 1`, the
/// factory's signature — `07-2`/`construct.rs`). Run in the **initial** user namespace
/// instead (`uid_map` = `0 0 4294967295`) it would be real host root with no kennel to
/// supervise and no confinement context — so fail closed rather than execute privileged and
/// purposeless. The check positively asserts the factory's map (fail-closed if `uid_map` is
/// unreadable or unexpected), not merely "not the initial ns".
fn require_kennel_userns() -> io::Result<()> {
    let map = std::fs::read_to_string("/proc/self/uid_map")
        .map_err(|e| io::Error::new(e.kind(), format!("read /proc/self/uid_map: {e}")))?;
    let first: Vec<&str> = map.split_whitespace().take(3).collect();
    if first != ["0", "0", "1"] {
        return Err(io::Error::other(format!(
            "refusing to run outside a kennel user namespace: /proc/self/uid_map first \
             mapping is {first:?}, expected [\"0\", \"0\", \"1\"] — kennel-init is launched \
             only by the privhelper factory"
        )));
    }
    Ok(())
}

/// Open the in-view binder device and establish a client connection to it.
fn open_bus() -> io::Result<Connection> {
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(IN_VIEW_BINDER_DEVICE)?;
    Connection::open(fd.into(), MAP_SIZE)
}

/// Pull the supervision-half from node 0, retrying while `kenneld` is still claiming the
/// context-manager node (`BR_DEAD_REPLY`). (No fd rides this reply — the interactive pty is
/// inherited at `PTY_RETURN_FD` from the construction channel, not the bus.)
fn pull_plan(conn: &Connection) -> io::Result<Vec<u8>> {
    let mut last = None;
    for _ in 0..PULL_RETRIES {
        match conn.transact(CONTEXT_MANAGER_HANDLE, lifecycle::GET_SANDBOX_PLAN, &[]) {
            Ok(reply) => return Ok(reply),
            Err(e) if is_node0_not_ready(&e) => {
                last = Some(e);
                std::thread::sleep(PULL_BACKOFF);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("plan pull exhausted retries")))
}

/// Whether an error means "node 0 not claimed yet" — worth retrying the pull. The
/// driver reports a transaction to an unowned context manager as `BR_DEAD_REPLY`.
fn is_node0_not_ready(e: &io::Error) -> bool {
    e.to_string().contains("BR_DEAD_REPLY")
}

/// Fork the facades and the workload, dropping each to the operator and confining the
/// workload. Returns the workload's pid for the supervise loop.
fn spawn_all(
    conn: &Connection,
    sup: &Supervision,
    envp: &[CString],
) -> io::Result<(i32, Vec<i32>)> {
    let groups = sup.groups.as_deref();
    let envp_ref = borrow(envp);

    // 1. Facades: dropped to the operator, NOT confined (they must reach the bus). The pids
    //    are returned in `sup.aux` order so the supervisor can map a death back to its spec.
    let mut facade_pids = Vec::with_capacity(sup.aux.len());
    for facade in &sup.aux {
        facade_pids.push(fork_facade(facade, sup, &envp_ref)?);
    }
    // Best-effort lifecycle report: kenneld audits it (the bus, not a reply, is the
    // source of truth, and the verb may be unserved on an older daemon).
    notify(conn, lifecycle::NOTIFY_BOOT_SYNC, &pids_payload(&facade_pids));

    // 2. The workload: dropped to the operator AND confined.
    notify(conn, lifecycle::NOTIFY_WORKLOAD_EXEC, &[]);
    let program = cstr_path(&sup.program)?;
    let argv = to_cstrings(&sup.argv)?;
    let argv_ref = borrow(&argv);
    let interactive = sup.interactive;
    let filter = (!sup.seccomp_deny.is_empty()).then(|| sup.seccomp_filter());

    let seal = || -> io::Result<()> {
        // The workload's working directory (a path inside the view), before confinement.
        if let Some(cwd) = &sup.cwd {
            std::env::set_current_dir(cwd)?;
        }
        // Controlling terminal FIRST, before Landlock/seccomp could gate the ioctls
        // (`07-9` §7.9.2). An interactive run allocates a pty in the view's devpts and returns
        // the master over the return socket the factory placed at `PTY_RETURN_FD`; otherwise
        // adopt stdin.
        if interactive {
            kennel_syscall::pty::setup_view_pty(kennel_syscall::pty::PTY_RETURN_FD)?;
        } else {
            kennel_syscall::pty::adopt_stdin_as_controlling_tty();
        }
        set_no_new_privs()?;
        if let Some(f) = &filter {
            f.install()?;
        }
        // Built post-pivot with skip_missing: a grant for a path absent from the view is
        // vacuous (the name does not resolve), not an error.
        let ruleset = kennel_spawn::build_ruleset(&sup.landlock_fs, &sup.landlock_net, true)?;
        ruleset.restrict_current_process()?;
        // Resource limits last, so lowering RLIMIT_NOFILE cannot starve the rule opens.
        for (resource, soft, hard) in &sup.ulimits {
            set_rlimit(*resource, *soft, *hard)?;
        }
        Ok(())
    };
    let workload_pid = fork_drop_exec_confined(
        &program,
        &argv_ref,
        &envp_ref,
        sup.drop_gid,
        groups,
        sup.drop_uid,
        seal,
    )?;
    Ok((workload_pid, facade_pids))
}

/// Whether a crashed facade may be re-forked: prune `starts` to those within
/// [`START_LIMIT_INTERVAL`] of `now`, then allow a restart iff fewer than
/// [`START_LIMIT_BURST`] remain. Mutating `starts` to the pruned set is what makes the limit
/// a sliding window (stale starts age out). Pure, so the policy is unit-tested without forks.
fn may_restart(starts: &mut Vec<Instant>, now: Instant) -> bool {
    starts.retain(|t| now.duration_since(*t) < START_LIMIT_INTERVAL);
    starts.len() < START_LIMIT_BURST
}

/// Fork one facade: build its argv, drop it to the operator, exec it **unconfined** (it must
/// reach the bus). Shared by the initial [`spawn_all`] and the supervisor's restart path.
fn fork_facade(facade: &AuxProcess, sup: &Supervision, envp_ref: &[&CStr]) -> io::Result<i32> {
    let argv = facade_argv(facade)?;
    let argv_ref = borrow(&argv);
    let path = cstr_path(&facade.path)?;
    fork_drop_exec(
        &path,
        &argv_ref,
        envp_ref,
        sup.drop_gid,
        sup.groups.as_deref(),
        sup.drop_uid,
    )
}

/// Reap children to exit, restarting crashed facades within the bounded policy.
///
/// On the **workload's** death, terminate with its status (the factory relays it up to
/// `kenneld`). A **facade's** death is reported (`NOTIFY_FACADE_CRASH`) and the facade is
/// re-forked after [`RESTART_DELAY`], up to [`START_LIMIT_BURST`] starts per
/// [`START_LIMIT_INTERVAL`]; past that it is left down (a failed helper must not take the
/// kennel with it). The workload is never restarted.
fn supervise(
    conn: &Connection,
    workload_pid: i32,
    sup: &Supervision,
    envp: &[CString],
    facade_pids: &[i32],
) -> io::Result<u8> {
    let envp_ref = borrow(envp);
    // Current facade pid → its supervisor state. The boot start counts toward the limit.
    let mut facades: HashMap<i32, FacadeState> = facade_pids
        .iter()
        .enumerate()
        .map(|(aux, &pid)| {
            (
                pid,
                FacadeState {
                    aux,
                    starts: vec![Instant::now()],
                },
            )
        })
        .collect();

    // TTL (§9.7): arm a one-shot alarm. When it fires it interrupts the reap wait below; we
    // then make the *blocking* NOTIFY_TTL_EXPIRED call to kenneld, which freezes this whole
    // cgroup (suspending us mid-call) and, on resume, thaws + replies so the same call returns.
    if let Some(secs) = sup.ttl_seconds {
        if let Ok(secs) = u32::try_from(secs) {
            if let Err(e) = kennel_syscall::process::arm_ttl_alarm(secs) {
                eprintln!("kennel-init: could not arm the TTL alarm: {e}; running without a TTL");
            }
        }
    }

    loop {
        // The TTL alarm fired: make the blocking call. kenneld freezes the cgroup here, audits,
        // and decides — `warn`/`renew` thaw and the call returns (we carry on); `exit` kills the
        // frozen cgroup, so we simply die here. We carry on regardless of the reply: termination
        // is kenneld's *atomic kill*, not a cooperative action the sandbox could refuse (a
        // compromised PID 1 must not be able to evade its deadline). The freezer can also EINTR
        // the blocked binder ioctl — that, too, just means "resume".
        if kennel_syscall::process::ttl_alarm_fired() {
            let _ = conn.transact(CONTEXT_MANAGER_HANDLE, lifecycle::NOTIFY_TTL_EXPIRED, &[]);
            continue;
        }
        // `None` ⇒ EINTR (e.g. the TTL alarm) — loop back and re-check the alarm flag.
        let Some(reaped) = wait_any_interruptible()? else {
            continue;
        };
        match reaped {
            Reaped::Exited { pid, code } if pid == workload_pid => {
                return Ok(u8::try_from(code & 0xff).unwrap_or(1));
            }
            Reaped::Exited { pid, .. } => {
                notify(conn, lifecycle::NOTIFY_FACADE_CRASH, &pid.to_le_bytes());
                let Some(mut state) = facades.remove(&pid) else {
                    continue; // not a tracked facade (already given up, or a stray)
                };
                // `state.aux` was set from an enumerate over `sup.aux`, so this always hits;
                // `.get` keeps it panic-free regardless.
                let Some(facade) = sup.aux.get(state.aux) else {
                    continue;
                };
                if !may_restart(&mut state.starts, Instant::now()) {
                    eprintln!(
                        "kennel-init: facade {} hit the restart limit ({} starts in {:?}); \
                         leaving it down",
                        facade.path.display(),
                        START_LIMIT_BURST,
                        START_LIMIT_INTERVAL
                    );
                    continue;
                }
                std::thread::sleep(RESTART_DELAY);
                match fork_facade(facade, sup, &envp_ref) {
                    Ok(new_pid) => {
                        state.starts.push(Instant::now());
                        facades.insert(new_pid, state);
                        notify(conn, lifecycle::NOTIFY_FACADE_RESTART, &new_pid.to_le_bytes());
                    }
                    Err(e) => eprintln!(
                        "kennel-init: failed to restart facade {}: {e}; leaving it down",
                        facade.path.display()
                    ),
                }
            }
            // PID 1 with no children left but the workload never observed exiting: the
            // kennel is empty, so wind down with a generic failure.
            Reaped::NoChildren => return Ok(1),
        }
    }
}

/// Send a best-effort lifecycle notification to node 0 (errors are non-fatal: the
/// process chain, not binder, carries the authoritative exit status).
fn notify(conn: &Connection, code: u32, payload: &[u8]) {
    let _ = conn.transact(CONTEXT_MANAGER_HANDLE, code, payload);
}

/// Encode a facade pid list as a length-prefixed little-endian `u32` array.
fn pids_payload(pids: &[i32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(pids.len()).unwrap_or(u32::MAX).to_le_bytes());
    for pid in pids {
        out.extend_from_slice(&pid.to_le_bytes());
    }
    out
}

/// Build the facade's argument vector: `argv[0]` is the binary path (per [`AuxProcess`]),
/// followed by its declared arguments.
fn facade_argv(facade: &AuxProcess) -> io::Result<Vec<CString>> {
    let mut argv = Vec::new();
    argv.push(cstr_path(&facade.path)?);
    for arg in &facade.args {
        argv.push(cstring(arg.as_bytes(), "argument")?);
    }
    Ok(argv)
}

/// Convert a path to a `CString` for `execve`.
fn cstr_path(p: &Path) -> io::Result<CString> {
    cstring(p.as_os_str().as_bytes(), "path")
}

/// Convert each string to a `CString`.
fn to_cstrings(items: &[String]) -> io::Result<Vec<CString>> {
    items.iter().map(|s| cstring(s.as_bytes(), "argument")).collect()
}

/// Convert an environment map to `KEY=VALUE` `CString`s.
fn env_cstrings(env: &[(String, String)]) -> io::Result<Vec<CString>> {
    env.iter()
        .map(|(k, v)| {
            let mut kv = Vec::new();
            kv.extend_from_slice(k.as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(v.as_bytes());
            cstring(&kv, "environment entry")
        })
        .collect()
}

/// `CString::new` with a contextual error (a NUL byte cannot cross `execve`).
fn cstring(bytes: &[u8], what: &str) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other(format!("interior NUL in {what}")))
}

/// Borrow a `[CString]` as the `[&CStr]` the spawn primitives take.
fn borrow(cstrings: &[CString]) -> Vec<&CStr> {
    cstrings.iter().map(CString::as_c_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn may_restart_enforces_the_burst_within_a_sliding_window() {
        let now = Instant::now();
        // A fresh facade (one boot start) is well under the burst → restartable.
        let mut starts = vec![now];
        assert!(may_restart(&mut starts, now));
        // At the burst limit, all within the window → refused.
        let mut starts = vec![now; START_LIMIT_BURST];
        assert!(!may_restart(&mut starts, now));
        // Starts older than the window are pruned, so the budget recovers.
        let stale = now - START_LIMIT_INTERVAL - Duration::from_secs(1);
        let mut starts = vec![stale; START_LIMIT_BURST];
        assert!(may_restart(&mut starts, now));
        assert!(starts.is_empty(), "stale starts are pruned out of the window");
    }

    #[test]
    fn env_cstrings_render_key_equals_value() {
        let env = vec![
            ("HOME".to_owned(), "/home/kennel".to_owned()),
            ("TERM".to_owned(), "xterm".to_owned()),
        ];
        let c = env_cstrings(&env).expect("env");
        assert_eq!(c.first().expect("0").to_bytes(), b"HOME=/home/kennel");
        assert_eq!(c.get(1).expect("1").to_bytes(), b"TERM=xterm");
    }

    #[test]
    fn facade_argv_uses_the_path_as_argv0() {
        let facade = AuxProcess {
            path: PathBuf::from("/usr/libexec/kennel/kennel-afunix-shim"),
            args: vec!["/dev/binderfs/binder".to_owned(), "/run/x.sock=wl".to_owned()],
        };
        let argv = facade_argv(&facade).expect("argv");
        assert_eq!(
            argv.first().expect("0").to_bytes(),
            b"/usr/libexec/kennel/kennel-afunix-shim"
        );
        assert_eq!(argv.get(1).expect("1").to_bytes(), b"/dev/binderfs/binder");
        assert_eq!(argv.get(2).expect("2").to_bytes(), b"/run/x.sock=wl");
    }

    #[test]
    fn interior_nul_is_rejected_not_panicked() {
        let env = vec![("BAD".to_owned(), "a\0b".to_owned())];
        assert!(env_cstrings(&env).is_err());
        assert!(to_cstrings(&["ok".to_owned(), "a\0b".to_owned()]).is_err());
    }

    #[test]
    fn pids_payload_is_length_prefixed() {
        let payload = pids_payload(&[7, 9]);
        assert_eq!(payload.get(0..4), Some(2u32.to_le_bytes().as_slice()));
        assert_eq!(payload.get(4..8), Some(7i32.to_le_bytes().as_slice()));
        assert_eq!(payload.get(8..12), Some(9i32.to_le_bytes().as_slice()));
    }

    /// The pull → decode path round-trips a supervision-half: encode a plan, decode it
    /// the way `run` would, and confirm the workload program survives. (The binder
    /// transport itself is exercised by the kenneld root tests in Stage D/F.)
    #[test]
    fn decode_of_an_encoded_supervision_recovers_the_program() {
        let sup = Supervision {
            program: PathBuf::from("/usr/bin/claude"),
            argv: vec!["claude".to_owned()],
            env: vec![("HOME".to_owned(), "/home/kennel".to_owned())],
            cwd: None,
            drop_uid: 1000,
            drop_gid: 1000,
            groups: Some(vec![1000]),
            landlock_fs: Vec::new(),
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(),
            seccomp_deny_action: kennel_syscall::seccomp::Action::KillProcess,
            ulimits: Vec::new(),
            aux: Vec::new(),
            interactive: false,
            ttl_seconds: None,
        };
        let bytes = kennel_spawn::wire::encode_supervision(&sup);
        let back = decode_supervision(&bytes).expect("decode");
        assert_eq!(back, sup);
    }
}
