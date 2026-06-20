//! In-kennel inbound BIND facade: register callback nodes and deliver pushed connections.
//!
//! # Purpose
//!
//! The reverse of `facade-socks5` (`docs/design/07-5-network.md` §7.5.7). The workload `bind()`s a
//! port natively in the kennel net-ns (gated by the `[net.bpf].bind` cgroup ACL); `host-inetd`
//! mirrors that port on the host loopback and accepts. This facade is the in-kennel end that
//! delivers each accepted connection to the workload's listener.
//!
//! **Push, not poll.** For every mirrored port the facade registers a binder **callback node** with
//! node 0 ([`REGISTER_MIRROR`], via [`Connection::transact_node`]) and then **sleeps in a binder
//! server loop** — zero CPU, no re-arm. On each host-side accept kenneld pushes a one-way
//! [`DELIVER_INET`] to the node carrying the conduit fd; the kernel wakes the facade, which
//! `connect()`s the workload's native listener at `<kennel-ip>:<port>` and splices the conduit to
//! it. The conduit fd flows **out** of the TCB (kenneld → kennel); no fd ever flows in.
//!
//! # Invocation
//!
//! `facade-client <binder-device> <kennel-ip> <port>...`, spawned by kenneld into the kennel's view.
//! `<binder-device>` is `/dev/binderfs/binder`; `<kennel-ip>` is the kennel's own loopback alias;
//! each `<port>` is a policy-mirrored bind port.
//!
//! # Non-goals
//!
//! No policy, no resolver, no listener: the `[net.bpf].bind` ACL already gated the bind and kenneld
//! brokers the host-side accept. This process only registers nodes and splices pushed conduits.
//!
//! [`REGISTER_MIRROR`]: kennel_lib_binder::service::verb::REGISTER_MIRROR
//! [`DELIVER_INET`]: kennel_lib_binder::service::verb::DELIVER_INET

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::net::{IpAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

use kennel_lib_binder::client::{Connection, Incoming, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::proto::FLAT_BINDER_FLAG_ACCEPTS_FDS;
use kennel_lib_binder::service::{inet, status, transport, verb};

/// The binder buffer mapping size for the facade's client (matches `facade-socks5`).
const MAP_SIZE: usize = 128 * 1024;
/// Poll quantum for the server loop. The facade sleeps in the kernel between transactions; this
/// only bounds how promptly a torn-down binder connection is noticed (an idle mirror costs nothing).
const POLL_MS: i32 = 1000;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(device), Some(kennel_ip)) = (args.next(), args.next()) else {
        eprintln!("facade-client: usage: <binder-device> <kennel-ip> <port>...");
        return ExitCode::FAILURE;
    };
    let Ok(kennel_ip) = kennel_ip.parse::<IpAddr>() else {
        eprintln!("facade-client: bad kennel ip `{kennel_ip}`");
        return ExitCode::FAILURE;
    };
    let ports: Vec<u16> = args.filter_map(|a| a.parse::<u16>().ok()).collect();
    if ports.is_empty() {
        eprintln!("facade-client: no mirrored ports to service");
        return ExitCode::FAILURE;
    }

    // One binder connection serves every port: each port gets its own callback node, all read on
    // this one connection's server loop.
    let conn = match open_connection(&device) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("facade-client: binder open error: {e}");
            return ExitCode::FAILURE;
        }
    };
    for &port in &ports {
        if let Err(e) = register(&conn, port) {
            eprintln!("facade-client: REGISTER_MIRROR :{port} error: {e}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = serve(&conn, kennel_ip) {
        eprintln!("facade-client: server loop ended: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Open one binder connection to the kennel's node 0.
fn open_connection(device: &str) -> io::Result<Connection> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    Connection::open(fd.into(), MAP_SIZE)
}

/// A distinct, opaque node identity per mirrored port (binder never dereferences it; it only
/// identifies the node). Kept off zero so it is never mistaken for a null object.
fn node_ptr(port: u16) -> u64 {
    0x1000_0000 | u64::from(port)
}

/// Register a callback node for `port` with node 0 ([`REGISTER_MIRROR`](verb::REGISTER_MIRROR)). The node is flagged
/// `ACCEPTS_FDS` so kenneld may push the conduit fd to it. kenneld replies [`status::OK`] (or
/// [`status::DENIED`] for a port outside the policy mirror set).
fn register(conn: &Connection, port: u16) -> io::Result<()> {
    let payload = inet::encode_bind_request(transport::TCP, port);
    let reply = conn.transact_node(
        CONTEXT_MANAGER_HANDLE,
        verb::REGISTER_MIRROR,
        &payload,
        node_ptr(port),
        u64::from(port),
        FLAT_BINDER_FLAG_ACCEPTS_FDS,
    )?;
    match reply.first() {
        Some(&status::OK) => Ok(()),
        Some(&status::DENIED) => Err(io::Error::other(format!(
            "kenneld refused mirror registration for :{port} (not in the policy mirror set)"
        ))),
        _ => Err(io::Error::other(format!(
            "unexpected REGISTER_MIRROR reply for :{port}"
        ))),
    }
}

/// Sleep in the binder server loop, delivering each pushed `DELIVER_INET` to the workload. Returns
/// only on a binder transport error (the connection died / the kennel is tearing down).
fn serve(conn: &Connection, kennel_ip: IpAddr) -> io::Result<()> {
    conn.enter_looper()?;
    loop {
        if !conn.poll(POLL_MS)? {
            continue; // idle: slept in the kernel, no work
        }
        for mut incoming in conn.recv()? {
            if incoming.code == verb::DELIVER_INET {
                deliver(&mut incoming, kennel_ip);
            }
            // One-way: no reply carries the free, so release the buffer explicitly. The conduit fd
            // was already taken above and survives the free.
            let _ = conn.free_buffer(&incoming);
        }
    }
}

/// Handle one pushed `DELIVER_INET`: take the conduit fd, read the port, and splice it to the
/// workload's native listener on a short-lived thread (so the server loop returns at once).
fn deliver(incoming: &mut Incoming, kennel_ip: IpAddr) {
    let Some((_transport, port)) = inet::decode_port_prefix(&incoming.data) else {
        eprintln!("facade-client: malformed DELIVER_INET payload");
        return;
    };
    let Some(conduit) = incoming.fds.pop() else {
        eprintln!("facade-client: DELIVER_INET :{port} carried no conduit fd");
        return;
    };
    let conduit = UnixStream::from(conduit);
    thread::spawn(move || deliver_conduit(conduit, kennel_ip, port));
}

/// Connect the workload's native in-kennel listener at `<kennel-ip>:<port>` and splice the conduit
/// to it. A connect failure (the workload isn't listening yet) drops the conduit — the external
/// client sees the connection close, the same as connecting to a down service.
fn deliver_conduit(conduit: UnixStream, kennel_ip: IpAddr, port: u16) {
    let upstream = match TcpStream::connect((kennel_ip, port)) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("facade-client: workload {kennel_ip}:{port} not reachable: {e}");
            return;
        }
    };
    // Bidirectionally splice the conduit (the kennel end of kenneld's socketpair) against the
    // workload's TCP connection. The bidirectional relay is shared (`kennel_lib_scm::splice`).
    kennel_lib_scm::splice::splice(conduit, upstream);
}
