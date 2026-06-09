//! Client side of the privhelper IPC: invoke the helper binary and exchange one
//! message.
//!
//! `kenneld` (the orchestrator) calls these to perform a privileged operation:
//! it `exec`s the installed setuid helper, writes one [`Request`], reads one
//! [`Response`]. The helper validates against the caller's allocation and exits
//! (`01-process-model.md`: privilege is transient, one op per invocation).

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use kennel_syscall::scm::{recv_with_fds, seqpacket_pair, send_with_raw_fds};

use crate::wire::{Op, Request, Response};

/// Invoke the privhelper **factory** to construct a kennel and hand off to `kennel-init`.
///
/// Returns the (short-lived) helper [`Child`] and `kennel-init`'s **host pid** (`07-2`
/// §7.2.1). The helper exits as soon as it has reported the pid — it is not a reaper proxy;
/// kenneld (a `set_child_subreaper`) adopts the orphaned `kennel-init` and waits it for the
/// workload's exit status. The caller reaps this `Child` (it has already exited). kennel-init
/// runs as the operator, so `kenneld` opens the kennel's binderfs device itself via
/// `/proc/<init>/root` — no fd needs to come back here.
///
/// Spawns `helper construct` with one end of a `SOCK_SEQPACKET` pair as its stdin, sends the
/// `construction_half` bytes (and, for an interactive run, the controlling-pty socket via
/// `SCM_RIGHTS`), and reads back the init host pid. The `kennel-init` binary is **not** sent:
/// the privhelper resolves and opens it from its own root-owned config (07-2; sec review).
///
/// # Errors
///
/// Returns the OS error if the socketpair, spawn, send, or pid receive fails, or
/// [`io::ErrorKind::InvalidData`] if the reply is not the 4-byte pid.
pub fn construct_kennel(
    helper: &Path,
    construction_half: &[u8],
    egress: Option<&[u8]>,
    pty_fd: Option<RawFd>,
) -> io::Result<(Child, i32)> {
    let (ours, theirs) = seqpacket_pair()?;
    let child = Command::new(helper)
        .arg("construct")
        .stdin(Stdio::from(theirs))
        .spawn()?;
    // `theirs` is consumed by the Command (dup'd to the child's stdin); our end stays.

    // One datagram, framed `[u32 ch_len][construction-half][egress]`: the length-prefix lets
    // the factory hand its decoder exactly the construction-half bytes, with the (optional)
    // egress payload as the tail. The pty return socket (interactive runs) travels as the sole
    // SCM fd; it lives as a RawFd in the spawn plan, kept open by the caller for this call.
    let mut data = Vec::with_capacity(construction_half.len().saturating_add(4));
    data.extend_from_slice(&u32::try_from(construction_half.len()).unwrap_or(u32::MAX).to_le_bytes());
    data.extend_from_slice(construction_half);
    if let Some(eg) = egress {
        data.extend_from_slice(eg);
    }
    let fds: Vec<RawFd> = pty_fd.into_iter().collect();
    send_with_raw_fds(ours.as_fd(), &data, &fds)?;

    let mut buf = [0u8; 4];
    let (n, _none) = recv_with_fds(ours.as_fd(), &mut buf)?;
    if n != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "factory did not return the 4-byte init pid",
        ));
    }
    Ok((child, i32::from_le_bytes(buf)))
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

fn addr_request(op: Op, ctx: u16, interface: &str, addr: IpAddr, prefix: u8) -> Request {
    Request {
        op,
        ctx,
        addr,
        prefix,
        interface: interface.to_owned(),
        cgroup_path: PathBuf::new(),
    }
}
