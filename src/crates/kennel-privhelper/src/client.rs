//! Client side of the privhelper IPC: invoke the helper binary and exchange one
//! message.
//!
//! `kenneld` (the orchestrator) calls these to perform a privileged operation:
//! it `exec`s the installed setuid helper, writes one [`Request`], reads one
//! [`Response`]. The helper validates against the caller's allocation and exits
//! (`01-process-model.md`: privilege is transient, one op per invocation).

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};

use kennel_lib_syscall::scm::{recv_with_fds, send_with_raw_fds, seqpacket_pair};

use crate::wire::{Op, Request, Response};

/// How many of the factory's most recent stderr lines to retain for a failure diagnostic.
const HELPER_LOG_LINES: usize = 40;

/// A bounded capture of the privhelper factory's stderr (W15).
///
/// `kenneld` cannot see the factory's (or a sub-helper's) precise failure cause — a missing cap,
/// a refused scope, a `uid_map` `EPERM` — when it only inherits the transport symptom (`factory did
/// not return the 4-byte init pid`). This drains the factory's stderr on a background thread that
/// (1) forwards every line to the daemon's own stderr, so the journal is unchanged, and (2) keeps
/// the last `HELPER_LOG_LINES` in a ring the construction-failure path folds into its diagnostic.
/// The thread lives until the pipe closes (the factory exits and the construction child it forked
/// releases its inherited copy), then ends on its own.
#[derive(Clone)]
pub struct HelperStderr {
    recent: Arc<Mutex<VecDeque<String>>>,
}

impl HelperStderr {
    /// A non-capturing handle (no factory stderr to drain — the test/default impls).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            recent: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Drain `stderr` on a background thread: forward each line to the daemon's stderr (journal)
    /// and retain the last `HELPER_LOG_LINES` for a failure diagnostic.
    #[must_use]
    fn drain(stderr: ChildStderr) -> Self {
        use std::io::BufRead as _;
        let recent = Arc::new(Mutex::new(VecDeque::with_capacity(HELPER_LOG_LINES)));
        let ring = Arc::clone(&recent);
        std::thread::spawn(move || {
            for line in io::BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("{line}");
                let mut g = ring
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if g.len() >= HELPER_LOG_LINES {
                    g.pop_front();
                }
                g.push_back(line);
            }
        });
        Self { recent }
    }

    /// The retained recent stderr lines, oldest→newest, joined for a one-line diagnostic — or an
    /// empty string if nothing was captured. A brief settle lets the drain thread flush the failing
    /// helper's last line (it was written just before the helper died) before we read the ring.
    #[must_use]
    pub fn recent(&self) -> String {
        std::thread::sleep(std::time::Duration::from_millis(150));
        let g = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.iter().cloned().collect::<Vec<_>>().join(" | ")
    }
}

/// Invoke the privhelper **factory** to construct a kennel and hand off to `kennel-bin-init`.
///
/// Returns the (short-lived) helper [`Child`], `kennel-bin-init`'s **host pid** (`07-2` §7.2.1), and
/// the **boot-sync socket** — `kenneld` then drives [`kennel_lib_syscall::boot`] on that socket to
/// gate `kennel-bin-init`'s plan pull on node 0 being claimed (deterministic startup, `07-2`
/// §7.2.1a), and reaps this `Child` afterwards (the factory exits once it has reported the pid).
///
/// The factory builds the kennel — including mounting the per-kennel binderfs — `fexecve`s
/// `kennel-bin-init`, and reports the init pid here with the kenneld end of the boot-sync socket as
/// the sole `SCM_RIGHTS` fd. `kennel-bin-init` (post-exec) signals "ready" on its inherited end and
/// blocks; the caller opens the now-reachable binderfs via `/proc/<init>/root`, claims node 0,
/// and signals "go" — at which point `kennel-bin-init`'s first `GET_SANDBOX_PLAN` finds the context
/// manager serving (no retry on either side). kenneld (a `set_child_subreaper`) adopts the
/// orphaned `kennel-bin-init`.
///
/// Spawns `helper construct` with one end of a `SOCK_SEQPACKET` pair as its stdin, sends the
/// `construction_half` bytes (and, for an interactive run, the controlling-pty socket via
/// `SCM_RIGHTS`). The `kennel-bin-init` binary is **not** sent: the privhelper resolves and opens it
/// from its own root-owned config (07-2; sec review).
///
/// # Errors
///
/// Returns the OS error if the socketpair, spawn, send, or receive fails, or
/// [`io::ErrorKind::InvalidData`] if the reply is not the 4-byte pid plus the boot-sync fd.
pub fn construct_kennel(
    helper: &Path,
    construction_half: &[u8],
    egress: Option<&[u8]>,
    pty_fd: Option<RawFd>,
    workload_fd: Option<RawFd>,
    stdio_fds: Option<[RawFd; 3]>,
) -> io::Result<(Child, i32, OwnedFd, HelperStderr)> {
    let (ours, theirs) = seqpacket_pair()?;
    // Capture the factory's stderr (W15) rather than inherit it: a background thread forwards each
    // line to the journal (unchanged) and rings the last lines, so a construction failure can carry
    // the factory's (or a sub-helper's) own words, not just the transport symptom.
    let mut child = Command::new(helper)
        .arg("construct")
        .stdin(Stdio::from(theirs))
        .stderr(Stdio::piped())
        .spawn()?;
    // `theirs` is consumed by the Command (dup'd to the child's stdin); our end stays.
    let helper_stderr = child
        .stderr
        .take()
        .map_or_else(HelperStderr::empty, HelperStderr::drain);

    // One datagram, framed `[u32 ch_len][construction-half][egress]`: the length-prefix lets
    // the factory hand its decoder exactly the construction-half bytes, with the (optional)
    // egress payload as the tail. Up to two SCM fds travel in a FIXED order — the pty return
    // socket (interactive runs) then the sha256-pinned workload binary fd — and the
    // construction-half's `pty_fd_present`/`workload_fd_present` flags tell the factory which
    // is which. Both live as RawFds in the spawn plan, kept open by the caller for this call.
    let mut data = Vec::with_capacity(construction_half.len().saturating_add(4));
    data.extend_from_slice(
        &u32::try_from(construction_half.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    data.extend_from_slice(construction_half);
    if let Some(eg) = egress {
        data.extend_from_slice(eg);
    }
    // FIXED order: pty (if any), workload (if any), then the three injected-stdio fds (if any) —
    // the `pty_fd_present`/`workload_fd_present`/`stdio_present` flags tell the factory which is which.
    let mut fds: Vec<RawFd> = Vec::new();
    fds.extend(pty_fd);
    fds.extend(workload_fd);
    if let Some(s) = stdio_fds {
        fds.extend(s);
    }
    send_with_raw_fds(ours.as_fd(), &data, &fds)?;

    // The reply is the 4-byte init pid plus the kenneld end of the boot-sync socket as the sole
    // SCM fd.
    let mut buf = [0u8; 4];
    let (n, mut reply_fds) = recv_with_fds(ours.as_fd(), &mut buf)?;
    if n != 4 {
        // The factory died before reporting (a missing cap, a sub-helper refusal, the BPF attach):
        // fold its captured stderr into the cause so the operator does not have to `strace`.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            with_cause("factory did not return the 4-byte init pid", &helper_stderr),
        ));
    }
    if reply_fds.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            with_cause(
                "factory did not return the boot-sync socket",
                &helper_stderr,
            ),
        ));
    }
    let sync = reply_fds.remove(0);
    Ok((child, i32::from_le_bytes(buf), sync, helper_stderr))
}

/// Append the factory's captured stderr (if any) to a transport-level `symptom` (W15).
fn with_cause(symptom: &str, stderr: &HelperStderr) -> String {
    let cause = stderr.recent();
    if cause.is_empty() {
        symptom.to_owned()
    } else {
        format!("{symptom}: {cause}")
    }
}

/// Invoke `helper`, send `request`, and return the decoded response.
///
/// # Errors
///
/// Returns an OS error if the helper cannot be spawned or the exchange fails, or
/// `InvalidData` if the helper's response is malformed.
pub fn invoke(helper: &Path, request: &Request) -> io::Result<Response> {
    exchange(helper, &request.encode())
}

/// Spawn `helper`, write `bytes` to its stdin (closing the pipe so it sees EOF),
/// and return the decoded response.
fn exchange(helper: &Path, bytes: &[u8]) -> io::Result<Response> {
    let mut child = Command::new(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    {
        use std::io::Write as _;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("privhelper stdin unavailable"))?;
        stdin.write_all(bytes)?;
        // `stdin` drops here, closing the helper's stdin so it sees EOF.
    }
    let out = child.wait_with_output()?;
    Response::decode(&out.stdout).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed privhelper response: {e:?}"),
        )
    })
}

/// Ask the helper to remove `addr/prefix` on `interface` for kennel `ctx` (teardown).
///
/// The address *add* and the egress-BPF *attach* are folded into the `construct_kennel` op, so
/// this is the only standalone one-shot op left.
///
/// # Errors
///
/// As [`invoke`].
pub fn del_address(
    helper: &Path,
    ctx: u16,
    interface: &str,
    addr: IpAddr,
    prefix: u8,
) -> io::Result<Response> {
    invoke(
        helper,
        &addr_request(Op::DelAddr, ctx, interface, addr, prefix),
    )
}

/// Invoke the privhelper to release (unmount) an exclusive over-mount at `host` (§2.7).
///
/// The teardown / `kennel release` counterpart to the factory's exclusive over-mount. A
/// subcommand op (argv), not the fixed-request wire; success is exit 0.
///
/// # Errors
/// An OS error if the helper cannot be spawned, or a non-zero exit (refused / unmount failed).
pub fn release_exclusive(helper: &Path, host: &Path) -> io::Result<()> {
    let status = Command::new(helper)
        .arg("exclusive-unmount")
        .arg(host)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "kennel-privhelper exclusive-unmount {} exited with {:?}",
            host.display(),
            status.code()
        )))
    }
}

fn addr_request(op: Op, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> Request {
    Request {
        op,
        ctx,
        addr,
        prefix,
        interface: interface.to_owned(),
    }
}
