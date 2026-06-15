//! In-kennel inbound BIND facade: pull host-side connections and deliver them to the workload.
//!
//! # Purpose
//!
//! The reverse of `facade-socks5` (`docs/design/07-5-network.md` §7.5.7). The workload `bind()`s a
//! port natively in the kennel net-ns (gated by the `[net.bpf].bind` cgroup ACL); `host-inetd`
//! mirrors that port on the host loopback and accepts. This facade is the in-kennel end that
//! delivers each accepted connection to the workload's listener: for every mirrored port it
//! transacts a [`BIND_INET`] to node 0 and blocks for a conduit; on a hit it `connect()`s the
//! workload's native listener at `<kennel-ip>:<port>` and splices the conduit to it; on
//! [`AGAIN`] it backs off and re-arms.
//!
//! Pull-based, the exact symmetric of `CONNECT`: where `facade-socks5` pulls outbound conduits and
//! the workload drives them, this pulls inbound conduits that kenneld minted on `host-inetd`'s
//! accept. kenneld mints both socketpair ends, so the only fd crossing into the kennel is a benign
//! socketpair end — no daemon-pushed fd, no callback node.
//!
//! # Invocation
//!
//! `facade-client <binder-device> <kennel-ip> <port>...`, spawned by kenneld into the kennel's view.
//! `<binder-device>` is `/dev/binderfs/binder`; `<kennel-ip>` is the kennel's own loopback alias;
//! each `<port>` is a policy-mirrored bind port. One thread per port.
//!
//! # Non-goals
//!
//! No policy, no resolver, no listener: the `[net.bpf].bind` ACL already gated the bind and kenneld
//! brokers the host-side accept. This process only pulls conduits and splices bytes.
//!
//! [`BIND_INET`]: kennel_lib_binder::service::verb::BIND_INET
//! [`AGAIN`]: kennel_lib_binder::service::status::AGAIN

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{inet, status, transport, verb};

/// The binder buffer mapping size for the facade's client (matches `facade-socks5`).
const MAP_SIZE: usize = 128 * 1024;
/// Backoff between `BIND_INET` re-arms when no inbound connection is pending (`status::AGAIN`).
/// Short enough to keep latency low, long enough that an idle port is not a busy-loop.
const REARM_BACKOFF: Duration = Duration::from_millis(50);

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

    // One thread per mirrored port; each owns its binder connection and pull loop.
    let mut handles = Vec::new();
    for port in ports {
        let device = device.clone();
        handles.push(thread::spawn(move || {
            service_port(&device, kennel_ip, port)
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    ExitCode::SUCCESS
}

/// Service one mirrored port forever: pull each inbound conduit and deliver it to the workload.
fn service_port(device: &str, kennel_ip: IpAddr, port: u16) {
    loop {
        match pull_inbound(device, port) {
            Ok(Some(conduit)) => {
                // Deliver this connection to the workload on its own thread so the pull loop
                // re-arms immediately for the next inbound connection.
                thread::spawn(move || deliver(conduit, kennel_ip, port));
            }
            // AGAIN (nothing pending) or a transient binder error: back off, then re-arm.
            Ok(None) | Err(_) => thread::sleep(REARM_BACKOFF),
        }
    }
}

/// Transact one `BIND_INET` to node 0. `Ok(Some(fd))` = a host-side connection's conduit;
/// `Ok(None)` = `status::AGAIN` (re-arm); `Err` = a binder/transport error (retry).
fn pull_inbound(device: &str, port: u16) -> io::Result<Option<UnixStream>> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let request = inet::encode_bind_request(transport::TCP, port);
    let (data, fd) = conn.transact_with_fd(CONTEXT_MANAGER_HANDLE, verb::BIND_INET, &request)?;
    match fd {
        Some(fd) => Ok(Some(UnixStream::from(fd))),
        None if data.first() == Some(&status::AGAIN) => Ok(None),
        None => Err(io::Error::other(
            "BIND_INET reply carried neither a conduit nor AGAIN",
        )),
    }
}

/// Connect the workload's native in-kennel listener at `<kennel-ip>:<port>` and splice the conduit
/// to it. A connect failure (the workload isn't listening yet) drops the conduit — the external
/// client sees the connection close, the same as connecting to a down service.
fn deliver(conduit: UnixStream, kennel_ip: IpAddr, port: u16) {
    let Ok(upstream) = TcpStream::connect((kennel_ip, port)) else {
        return;
    };
    splice(conduit, upstream);
}

/// Bidirectionally splice the conduit (the kennel-end of kenneld's socketpair) against the
/// workload's TCP connection, one thread per direction, propagating half-close. Mirrors
/// `facade-socks5::splice` (both stream types implement `Read`/`Write` on `&T`).
fn splice(conduit: UnixStream, upstream: TcpStream) {
    let (Ok(conduit_r), Ok(upstream_r)) = (conduit.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = io::copy(&mut &upstream_r, &mut &conduit);
        let _ = conduit.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut &conduit_r, &mut &upstream);
    let _ = upstream.shutdown(Shutdown::Write);
    let _ = up.join();
    drop(upstream); // own the connection to its close (the splice's end of life)
}
