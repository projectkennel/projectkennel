//! Client side of the privhelper IPC: invoke the helper binary and exchange one
//! message.
//!
//! `kenneld` (the orchestrator) calls these to perform a privileged operation:
//! it `exec`s the installed setuid helper, writes one [`Request`], reads one
//! [`Response`]. The helper validates against the caller's allocation and exits
//! (`01-process-model.md`: privilege is transient, one op per invocation).

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use kennel_syscall::scm::{recv_with_fds, seqpacket_pair, send_with_fds};

use crate::wire::{EgressPayload, GidMapPayload, Op, Request, Response};

/// Invoke the privhelper **factory** to construct a kennel and hand off to `kennel-init`.
///
/// Returns the long-lived helper process (the kennel's supervisor — wait it for the
/// workload's exit status) and `kennel-init`'s **host pid** (`07-11` §7.2.1). kennel-init
/// runs as the operator, so `kenneld` opens the kennel's binderfs device itself via
/// `/proc/<init>/root` — no fd needs to come back here.
///
/// Spawns `helper construct` with one end of a `SOCK_SEQPACKET` pair as its stdin, sends
/// the `construction_half` bytes plus the `kennel-init` binary fd and (optionally) the
/// controlling-pty socket via `SCM_RIGHTS`, and reads back the init host pid.
///
/// # Errors
///
/// Returns the OS error if the socketpair, spawn, send, or pid receive fails, or
/// [`io::ErrorKind::InvalidData`] if the reply is not the 4-byte pid.
pub fn construct_kennel(
    helper: &Path,
    construction_half: &[u8],
    init_fd: BorrowedFd<'_>,
    pty_fd: Option<BorrowedFd<'_>>,
) -> io::Result<(Child, i32)> {
    let (ours, theirs) = seqpacket_pair()?;
    let child = Command::new(helper)
        .arg("construct")
        .stdin(Stdio::from(theirs))
        .spawn()?;
    // `theirs` is consumed by the Command (dup'd to the child's stdin); our end stays.

    let mut fds = vec![init_fd];
    if let Some(pty) = pty_fd {
        fds.push(pty);
    }
    send_with_fds(ours.as_fd(), construction_half, &fds)?;

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

/// Load, populate, and attach the egress BPF programs to a kennel's cgroup.
///
/// Asks the helper to attach the egress programs to the cgroup at `cgroup`;
/// `payload` carries the resolved map contents (built from the spawn `Plan`).
///
/// # Errors
///
/// As [`invoke`].
pub fn setup_egress(
    helper: &Path,
    cgroup: PathBuf,
    payload: &EgressPayload,
) -> io::Result<Response> {
    let mut bytes = cgroup_request(Op::SetupEgress, cgroup).encode();
    bytes.extend_from_slice(&payload.encode());
    exchange(helper, &bytes)
}

/// Ask the helper to write process `pid`'s user-namespace `gid_map` (§7.4.8).
///
/// The map identity-maps `gids` — the workload's primary gid plus each granted
/// supplementary group — so the workload keeps those groups; an unprivileged
/// process could map only its own primary gid. The helper re-checks the caller is
/// a member of every gid and owns `pid` before writing.
///
/// # Errors
///
/// As [`invoke`].
pub fn set_gid_map(helper: &Path, pid: u32, gids: &[u32]) -> io::Result<Response> {
    let mut bytes = gidmap_request().encode();
    bytes.extend_from_slice(
        &GidMapPayload {
            pid,
            gids: gids.to_vec(),
        }
        .encode(),
    );
    exchange(helper, &bytes)
}

/// Ask the helper to add `addr/prefix` on `interface` for kennel `ctx`.
///
/// # Errors
///
/// As [`invoke`].
pub fn add_address(
    helper: &Path,
    ctx: u16,
    interface: &str,
    addr: IpAddr,
    prefix: u8,
) -> io::Result<Response> {
    invoke(
        helper,
        &addr_request(Op::AddAddr, ctx, interface, addr, prefix),
    )
}

/// Ask the helper to remove `addr/prefix` on `interface` for kennel `ctx`.
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

/// A bare `SetGidMap` request: the operation lives entirely in the appended
/// [`GidMapPayload`] tail, so the fixed fields are unused placeholders.
const fn gidmap_request() -> Request {
    Request {
        op: Op::SetGidMap,
        ctx: 0,
        addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        prefix: 0,
        interface: String::new(),
        cgroup_path: PathBuf::new(),
    }
}

const fn cgroup_request(op: Op, path: PathBuf) -> Request {
    Request {
        op,
        ctx: 0,
        addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        prefix: 0,
        interface: String::new(),
        cgroup_path: path,
    }
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
