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
//!    `kennel-spawn::wire::encode_supervision` bytes and, for an interactive run, the
//!    controlling-pty return socket as a `BINDER_TYPE_FD` object.
//! 2. Acts as the **spawn owner**: forks each facade and the workload, dropping every
//!    one to the masked operator identity (`set_gid` → `set_supplementary_groups` →
//!    `set_uid`) before `execve`. Facades exec unconfined (they must reach the bus); the
//!    workload additionally gets the controlling pty, `no_new_privs`, seccomp, Landlock,
//!    and ulimits.
//! 3. **Supervises**: reaps every child (it is PID 1), reports a facade death, and on
//!    the workload's exit terminates with the workload's status — which the factory
//!    (this process's parent) relays up the chain to `kenneld`.
//!
//! The crate is `#![forbid(unsafe_code)]`: every fork/exec/drop/wait primitive lives in
//! `kennel-syscall`, every binder primitive in `kennel-binder`.

#![forbid(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use kennel_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_binder::service::lifecycle;
use kennel_spawn::wire::decode_supervision;
use kennel_spawn::{AuxProcess, Supervision};
use kennel_syscall::process::{set_no_new_privs, set_rlimit, wait_any, Reaped};
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
    let (bytes, pty_fd) = pull_plan(&conn)?;
    let sup = decode_supervision(&bytes)
        .map_err(|e| io::Error::other(format!("supervision-half decode failed: {e:?}")))?;
    let workload_pid = spawn_all(&conn, &sup, pty_fd.as_ref())?;
    supervise(&conn, workload_pid)
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

/// Pull the supervision-half (and the optional pty fd) from node 0, retrying while
/// `kenneld` is still claiming the context-manager node (`BR_DEAD_REPLY`).
fn pull_plan(conn: &Connection) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut last = None;
    for _ in 0..PULL_RETRIES {
        match conn.transact_with_fd(CONTEXT_MANAGER_HANDLE, lifecycle::GET_SANDBOX_PLAN, &[]) {
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
    pty_fd: Option<&OwnedFd>,
) -> io::Result<i32> {
    let groups = sup.groups.as_deref();
    // One synthesised environment, shared by facades and workload (execve replaces env).
    let envp = env_cstrings(&sup.env)?;
    let envp_ref = borrow(&envp);

    // 1. Facades: dropped to the operator, NOT confined (they must reach the bus).
    let mut facade_pids = Vec::with_capacity(sup.aux.len());
    for facade in &sup.aux {
        let argv = facade_argv(facade)?;
        let argv_ref = borrow(&argv);
        let path = cstr_path(&facade.path)?;
        let pid = fork_drop_exec(&path, &argv_ref, &envp_ref, sup.drop_gid, groups, sup.drop_uid)?;
        facade_pids.push(pid);
    }
    // Best-effort lifecycle report: kenneld audits it (the bus, not a reply, is the
    // source of truth, and the verb may be unserved on an older daemon).
    notify(conn, lifecycle::NOTIFY_BOOT_SYNC, &pids_payload(&facade_pids));

    // 2. The workload: dropped to the operator AND confined.
    notify(conn, lifecycle::NOTIFY_WORKLOAD_EXEC, &[]);
    let program = cstr_path(&sup.program)?;
    let argv = to_cstrings(&sup.argv)?;
    let argv_ref = borrow(&argv);
    let pty_raw: Option<RawFd> = pty_fd.map(AsRawFd::as_raw_fd);
    let filter = (!sup.seccomp_deny.is_empty()).then(|| sup.seccomp_filter());

    let seal = || -> io::Result<()> {
        // The workload's working directory (a path inside the view), before confinement.
        if let Some(cwd) = &sup.cwd {
            std::env::set_current_dir(cwd)?;
        }
        // Controlling terminal FIRST, before Landlock/seccomp could gate the ioctls
        // (`07-9` §7.9.2). The interactive path allocates a pty in the view's devpts and
        // returns the master over the socket the CLI passed; otherwise adopt stdin.
        if let Some(raw) = pty_raw {
            kennel_syscall::pty::setup_view_pty(raw)?;
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
    fork_drop_exec_confined(
        &program,
        &argv_ref,
        &envp_ref,
        sup.drop_gid,
        groups,
        sup.drop_uid,
        seal,
    )
}

/// Reap children to exit. On the workload's death, terminate with its status (the
/// factory relays it up to `kenneld`); a facade death is reported and reaping continues.
fn supervise(conn: &Connection, workload_pid: i32) -> io::Result<u8> {
    loop {
        match wait_any()? {
            Reaped::Exited { pid, code } if pid == workload_pid => {
                return Ok(u8::try_from(code & 0xff).unwrap_or(1));
            }
            Reaped::Exited { pid, .. } => {
                notify(conn, lifecycle::NOTIFY_FACADE_CRASH, &pid.to_le_bytes());
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
        };
        let bytes = kennel_spawn::wire::encode_supervision(&sup);
        let back = decode_supervision(&bytes).expect("decode");
        assert_eq!(back, sup);
    }
}
