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
use std::net::{IpAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{inet, status, transport, verb};

/// The binder buffer mapping size for the facade's client (matches `facade-socks5`).
const MAP_SIZE: usize = 128 * 1024;
/// The shortest re-arm gap after an active hit: low enough to keep delivery latency small.
const REARM_BACKOFF_MIN: Duration = Duration::from_millis(50);
/// The longest re-arm gap an idle port backs off to. An idle mirror should not transact 20×/s
/// forever — kenneld replies `AGAIN` and wakes a looper each time — so back off geometrically toward
/// this ceiling while idle, and snap back to [`REARM_BACKOFF_MIN`] the moment a connection arrives.
const REARM_BACKOFF_MAX: Duration = Duration::from_secs(1);

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
            service_port(&device, kennel_ip, port);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    ExitCode::SUCCESS
}

/// Service one mirrored port forever: pull each inbound conduit and deliver it to the workload.
///
/// The binder connection is opened **once** and reused for every re-arm — an idle port must not
/// churn a fresh binderfs open + 128 KiB `mmap` 20×/s. The re-arm gap backs off geometrically while
/// idle (toward [`REARM_BACKOFF_MAX`]) and snaps back to [`REARM_BACKOFF_MIN`] on a hit, so an idle
/// mirror settles to ~1 wake/s instead of 20 while keeping delivery latency low under load.
fn service_port(device: &str, kennel_ip: IpAddr, port: u16) {
    let mut backoff = REARM_BACKOFF_MIN;
    loop {
        // (Re)establish the binder connection, reused across the inner pull loop below. A transport
        // error breaks back out to here to reopen it.
        let conn = match open_connection(device) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("facade-client: binder open :{port} error: {e}");
                thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(REARM_BACKOFF_MAX);
                continue;
            }
        };
        loop {
            match pull_inbound(&conn, port) {
                Ok(Some(conduit)) => {
                    // Active: deliver on its own thread so the pull loop re-arms immediately, and
                    // reset the backoff so the next pull is prompt.
                    backoff = REARM_BACKOFF_MIN;
                    thread::spawn(move || deliver(conduit, kennel_ip, port));
                }
                Ok(None) => {
                    // Idle (`AGAIN`): wait, then ease off toward the ceiling.
                    thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(REARM_BACKOFF_MAX);
                }
                Err(e) => {
                    eprintln!("facade-client: BIND_INET :{port} error: {e}");
                    thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(REARM_BACKOFF_MAX);
                    break; // reopen the binder connection
                }
            }
        }
    }
}

/// Open one binder connection to the kennel's node 0.
fn open_connection(device: &str) -> io::Result<Connection> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    Connection::open(fd.into(), MAP_SIZE)
}

/// Transact one `BIND_INET` over the reused `conn`. `Ok(Some(fd))` = a host-side connection's
/// conduit; `Ok(None)` = `status::AGAIN` (re-arm); `Err` = a binder/transport error (reopen).
fn pull_inbound(conn: &Connection, port: u16) -> io::Result<Option<UnixStream>> {
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
    let upstream = match TcpStream::connect((kennel_ip, port)) {
        Ok(u) => u,
        Err(e) => {
            // The workload isn't listening (yet, or at all) — drop the conduit; the external client
            // sees the connection close, the same as connecting to a down service. Logged because a
            // silent drop here looks like the mirror "not working".
            eprintln!("facade-client: workload {kennel_ip}:{port} not reachable: {e}");
            return;
        }
    };
    splice(conduit, upstream);
}

/// Bidirectionally splice the conduit (the kennel end of kenneld's socketpair) against the
/// workload's TCP connection. The bidirectional relay is shared (`kennel_lib_scm::splice`).
fn splice(conduit: UnixStream, upstream: TcpStream) {
    kennel_lib_scm::splice::splice(conduit, upstream);
}
