//! `tun-broker`: the standing L3-egress mediation service kennel (§8 / W2 Part D).
//!
//! A long-running service on the connector mesh bus — the host-side, kenneld-absent half of tun
//! egress. It runs inside its own kennel and decides nothing: kenneld is the only authority. UDP is
//! the first transport it mediates; the same session mechanism carries TCP later.
//!
//! **Control plane (kenneld → broker):** kenneld owns node 0 of the mesh bus and reaches the
//! broker's **control node** (registered via `ADD_SERVICE`). When a `[net.udp]` consumer connects,
//! kenneld resolves that consumer's grants + deny CIDRs + tun `/64` *in its own namespace* and sends
//! one [`tun_broker::ACCEPT_SESSION`] to the control node. The broker mints the session's data
//! channel — a connected `AF_UNIX` datagram pair — spawns the flow mediation ([`serve::run`]) on the
//! broker end, and **replies with the consumer end's fd**, which kenneld forwards to the consumer's
//! `facade-tun`.
//!
//! **Data plane (facade-tun → broker, kenneld absent):** whole L3 frames flow over that datagram
//! channel. The broker's per-session [`Broker`] runs the DNS naming shim, the flow forwarder, the
//! resolve-check-dial, and the `ICMPv6` synthesis — all already built. There is **no session table
//! and no teardown verb**: the socketpair close (the consumer's kennel exiting) ends the session's
//! `recv`, so its mediation thread returns and every flow socket it held closes with it.
//!
//! ```text
//! kenneld(node 0) ──ACCEPT_SESSION(grants,denies,tun)──▶ broker control node
//!        │                                                    │ mints socketpair, spawns serve::run
//!        └──forwards session fd──▶ facade-tun ◀──datagram L3 frames──▶ broker end
//! ```

#![forbid(unsafe_code)]

use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::service::{status, tun_broker, verb};
use kennel_lib_policy::settled::{NameRule, NetRule, Protocol};
use kennel_lib_syscall::poll::Poller;

use kennel_tun_broker::flow::DenyList;
use kennel_tun_broker::serve::{self, Broker, Ceilings};
use kennel_tun_broker::shim::Allowlist;

/// The mesh binder device path — the `[[provides]]` endpoint, bind-mounted by `kenneld`.
const MESH_DEVICE: &str = "/dev/binderfs-mesh/binder";

/// The control service registered on the mesh bus via `ADD_SERVICE`. kenneld reaches this node to
/// push `ACCEPT_SESSION`; consumers are never handed it.
const SERVICE_NAME: &str = "org.projectkennel.tun-broker";

/// The mmap size for the broker's binder connection. Control transactions are small (grants + a few
/// CIDRs); no frame data crosses binder.
const MAP_SIZE: usize = 256 * 1024;

/// Poll timeout for the binder serve loop (milliseconds).
const POLL_MS: i32 = 5000;

/// The control node's local pointer and cookie on the mesh bus.
const CONTROL_NODE_PTR: u64 = 1;
const CONTROL_NODE_COOKIE: u64 = 1;

/// Per-session ceilings (all bound the consuming kennel itself). A spray saturates only that
/// session's flows.
const MAX_FLOWS: usize = 512;
const NEW_FLOW_BURST: u32 = 64;
const NEW_FLOW_PER_SEC: u32 = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The epoll readiness capacity per session loop (the facade channel plus in-flight flow sockets).
const POLL_EVENTS: usize = 64;

/// Accept one session kenneld has authorized: mint the data channel, start its mediation, and reply
/// with the consumer's end.
fn accept_session(conn: &Connection, incoming: &Incoming) {
    let Some(acc) = tun_broker::decode_accept(&incoming.data) else {
        let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
        return;
    };
    let kennel_addr = Ipv6Addr::from(acc.tun_addr);
    let allow = Allowlist::new(acc.grants.into_iter().map(|g| NameRule {
        name: g.name,
        ports: g.ports,
        protocol: protocol_from_ordinal(g.protocol),
    }));
    let deny_rules: Vec<NetRule> = acc
        .denies
        .into_iter()
        .map(|d| NetRule {
            cidr: d.cidr,
            prefix_len: d.prefix_len,
            port_min: d.port_min,
            port_max: d.port_max,
            protocol: protocol_from_ordinal(d.protocol),
        })
        .collect();
    let deny = DenyList::from_rules(deny_rules.iter());

    let (Ok((broker_end, consumer_end)), Ok(poller)) =
        (UnixDatagram::pair(), Poller::new(POLL_EVENTS))
    else {
        let _ = conn.reply_and_free(incoming, &[status::UNAVAILABLE]);
        return;
    };

    let broker = Broker::new(
        kennel_addr,
        allow,
        deny,
        Ceilings {
            max_flows: MAX_FLOWS,
            new_flow_burst: NEW_FLOW_BURST,
            new_flow_per_sec: NEW_FLOW_PER_SEC,
            idle_timeout: IDLE_TIMEOUT,
        },
        Instant::now(),
    );
    // The mediation owns the broker end; the session lives exactly as long as the consumer holds the
    // other end. A dropped consumer end closes this recv, the thread returns, and its flows close.
    std::thread::spawn(move || {
        let _ = serve::run(broker, &broker_end, poller);
    });

    if conn.reply_with_fd(incoming, consumer_end.as_fd()).is_err() {
        // The consumer end never left; dropping it here HUPs the mediation, which unwinds cleanly.
        eprintln!("tun-broker: failed to hand back session fd; session torn down");
    }
}

/// Map the settled protocol ordinal on the wire (`0` any, `1` tcp, `2` udp) back to the enum.
const fn protocol_from_ordinal(ordinal: u8) -> Protocol {
    match ordinal {
        1 => Protocol::Tcp,
        2 => Protocol::Udp,
        _ => Protocol::Any,
    }
}

fn run() -> std::io::Result<()> {
    eprintln!("tun-broker: starting");

    let device_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(MESH_DEVICE)?;
    let conn = Connection::open(device_fd.into(), MAP_SIZE)?;

    let name_bytes = kennel_lib_binder::service::mesh::encode_add_service(SERVICE_NAME);
    conn.transact_node(
        0,
        verb::ADD_SERVICE,
        &name_bytes,
        CONTROL_NODE_PTR,
        CONTROL_NODE_COOKIE,
        0,
    )?;
    eprintln!("tun-broker: registered control service `{SERVICE_NAME}` on mesh bus");

    conn.enter_looper()?;
    loop {
        if !conn.poll(POLL_MS)? {
            continue;
        }
        for incoming in conn.recv_batch()?.transactions {
            // The control node honours only ACCEPT_SESSION; consumers never hold this node, so
            // reaching it is itself the authorization.
            if incoming.code == tun_broker::ACCEPT_SESSION {
                accept_session(&conn, &incoming);
            } else {
                let _ = conn.reply_and_free(&incoming, &[status::BAD_REQUEST]);
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tun-broker: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
