//! The per-session UDP-egress flow mediator (§8 / W2 Part D): one process per consumer.
//!
//! `tun-broker` spawns this for each egress session. The broker-end `SOCK_DGRAM` socket arrives on
//! stdin (fd 0); the session's grants + tun `/64` arrive hex-encoded in argv (the
//! `DELIVER_TUN_SESSION` payload). It runs the flow loop over the socket and exits when the
//! consumer's kennel drops the peer end.
//!
//! One process per consumer: the egress forwarder parses genuinely hostile workload L3 frames (the
//! crate's fuzz target), so a memory-corruption exploit is contained to its own session — it never
//! reaches another consumer's grants or the broker's control channel.

#![forbid(unsafe_code)]

use std::net::Ipv6Addr;
use std::os::fd::RawFd;
use std::os::unix::net::UnixDatagram;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kennel_lib_binder::service::tun_broker;
use kennel_lib_policy::settled::{NameRule, Protocol};
use kennel_lib_syscall::fd::adopt;
use kennel_tun_broker::poll::Poller;
use kennel_tun_broker::serve::{self, Broker, Ceilings};
use kennel_tun_broker::shim::Allowlist;

/// Per-session ceilings (all bound the consuming kennel itself, so a spray saturates only its own
/// session's flows).
const MAX_FLOWS: usize = 512;
const NEW_FLOW_BURST: u32 = 64;
const NEW_FLOW_PER_SEC: u32 = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The epoll readiness capacity per session loop (the facade channel plus in-flight flow sockets).
const POLL_EVENTS: usize = 64;

/// The inherited fd the broker-end socket arrives on — the mediator's stdin, placed there by
/// `tun-broker` at spawn.
const BROKER_FD: RawFd = 0;

fn main() -> ExitCode {
    let Some(grants_hex) = std::env::args().nth(1) else {
        eprintln!("tun-flow: usage: <grants-hex> (broker socket on stdin)");
        return ExitCode::FAILURE;
    };
    let Some(payload) = kennel_tun_broker::from_hex(&grants_hex) else {
        eprintln!("tun-flow: malformed grants payload");
        return ExitCode::FAILURE;
    };
    let Some(acc) = tun_broker::decode_accept(&payload) else {
        eprintln!("tun-flow: undecodable grants payload");
        return ExitCode::FAILURE;
    };
    // The broker-end socket is our stdin (`tun-broker` set the child's fd 0 to it at spawn).
    let broker_end = UnixDatagram::from(adopt(BROKER_FD));
    let kennel_addr = Ipv6Addr::from(acc.tun_addr);
    let allow = Allowlist::new(acc.grants.into_iter().map(|g| NameRule {
        name: g.name,
        ports: g.ports,
        protocol: protocol_from_ordinal(g.protocol),
    }));
    let Ok(poller) = Poller::new(POLL_EVENTS) else {
        eprintln!("tun-flow: epoll create failed");
        return ExitCode::FAILURE;
    };
    let broker = Broker::new(
        kennel_addr,
        allow,
        Ceilings {
            max_flows: MAX_FLOWS,
            new_flow_burst: NEW_FLOW_BURST,
            new_flow_per_sec: NEW_FLOW_PER_SEC,
            idle_timeout: IDLE_TIMEOUT,
        },
        Instant::now(),
    );
    match serve::run(broker, &broker_end, poller) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tun-flow: {e}");
            ExitCode::FAILURE
        }
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
