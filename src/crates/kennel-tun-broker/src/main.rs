//! `tun-broker`: the standing UDP-egress mediation service kennel (§8 / W2 Part D).
//!
//! A long-running service that `[[provides]]` the af-unix capability `org.projectkennel.tun-udp`. It
//! decides nothing — kenneld is the only authority — and does almost nothing itself: it is a dumb
//! router that hands each consumer's egress session to a fresh per-session mediator.
//!
//! **Control (kenneld → broker, per-kennel bus):** the broker registers one **sink node** with
//! kenneld ([`verb::REGISTER_TUN_SINK`]) at startup. When a `[net.udp]` consumer connects its
//! `[[consumes]]`, kenneld resolves that consumer's grants + tun `/64` *in its own namespace* and
//! pushes them to the sink ([`verb::DELIVER_TUN_SESSION`], the [`tun_broker`] payload). The broker
//! mints a fresh `SOCK_SEQPACKET` socketpair, spawns a [`tun-flow`](../bin/tun-flow.rs)
//! mediator process on one end with those grants, and **replies with the other end's fd** — which
//! kenneld hands to the consumer's `facade-tun` as its af-unix connection.
//!
//! **Data (facade-tun ↔ mediator, kenneld absent):** whole L3 frames flow over that socketpair,
//! datagram-framed (one frame per packet, no length prefix). The mediator runs the DNS naming shim,
//! the flow forwarder, the resolve-check-dial, and the `ICMPv6` synthesis. One socketpair + one
//! mediator per consumer: separation, never a shared listener to multiplex.
//!
//! ```text
//! kenneld ──REGISTER_TUN_SINK◀── broker (once, per-kennel bus)
//! kenneld ──DELIVER_TUN_SESSION(grants,tun/64)──▶ broker ──mints socketpair, spawns tun-flow──┐
//!        ◀────────────── reply: consumer-end fd ──────────────────────────────────────────────┘
//!        └──forwards fd──▶ facade-tun ◀──datagram L3 frames──▶ tun-flow mediator
//! ```

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::service::{status, tun_broker, verb};
use kennel_tun_broker::session::{self, Sessions, Slot, MAX_SESSIONS, MAX_SESSIONS_PER_KENNEL};

/// The sink node's local pointer and cookie on the per-kennel bus.
const SINK_NODE_PTR: u64 = 1;
const SINK_NODE_COOKIE: u64 = 1;

/// The mmap size for the broker's per-kennel-bus connection. Control transactions are small (the
/// grants); no frame data crosses binder.
const MAP_SIZE: usize = 256 * 1024;

/// Poll timeout for the binder serve loop (milliseconds).
const POLL_MS: i32 = 5000;

/// How often the reaper looks for mediators that have exited.
const REAP_INTERVAL: Duration = Duration::from_millis(250);

/// A running mediator and the ledger place it holds until it is reaped.
type Live = (Child, Slot);

/// Reap mediators as they exit, giving each one's place back to the ledger.
///
/// One thread for every session, not one each: it takes new mediators from `spawned` and polls the
/// ones it holds. It ends when the broker's main loop drops the sending end.
fn reap(spawned: &Receiver<Live>) {
    let mut live: Vec<Live> = Vec::new();
    loop {
        match spawned.recv_timeout(REAP_INTERVAL) {
            Ok(entry) => live.push(entry),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        // A mediator whose state cannot be read is kept, and so is its place: the ceiling must not
        // loosen on an error.
        live.retain_mut(|(child, _slot)| !matches!(child.try_wait(), Ok(Some(_))));
    }
}

fn run(device: &str, mediator: &str) -> std::io::Result<()> {
    eprintln!("tun-broker: starting");

    let device_fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(device_fd.into(), MAP_SIZE)?;

    // Register the egress sink node on node 0 (kenneld) of the per-kennel bus. Every consumer's
    // session is delivered here.
    conn.transact_node(
        0,
        verb::REGISTER_TUN_SINK,
        &[],
        SINK_NODE_PTR,
        SINK_NODE_COOKIE,
        0,
    )?;
    eprintln!("tun-broker: registered egress sink on the per-kennel bus");

    let sessions = Sessions::new(MAX_SESSIONS_PER_KENNEL, MAX_SESSIONS);
    let (spawned, exited) = mpsc::channel::<Live>();
    thread::Builder::new()
        .name("reaper".to_owned())
        .spawn(move || reap(&exited))?;

    conn.enter_looper()?;
    loop {
        if !conn.poll(POLL_MS)? {
            continue;
        }
        for incoming in conn.recv_batch()?.transactions {
            // The sink node honours only DELIVER_TUN_SESSION; consumers never hold it (it is
            // kenneld-only), so reaching it is itself the authorization.
            if incoming.code == verb::DELIVER_TUN_SESSION {
                deliver(&conn, &incoming, mediator, &sessions, &spawned);
            } else {
                let _ = conn.reply_and_free(&incoming, &[status::BAD_REQUEST]);
            }
        }
    }
}

/// Mint one egress session: a `SOCK_SEQPACKET` socketpair, a fresh `tun-flow` mediator on the broker
/// end with the delivered grants, and a reply carrying the consumer end's fd for kenneld to forward.
///
/// A kennel at its session ceiling, or a full broker, is answered [`status::CEILING_FULL`] and gets
/// no mediator.
fn deliver(
    conn: &Connection,
    incoming: &Incoming,
    mediator: &str,
    sessions: &Sessions,
    spawned: &Sender<Live>,
) {
    // Fail closed on a payload that does not decode (kenneld built it, but the broker never trusts a
    // shape it cannot read).
    let Some(accept) = tun_broker::decode_accept(&incoming.data) else {
        let _ = conn.reply_and_free(incoming, &[status::BAD_REQUEST]);
        return;
    };
    let Some(slot) = sessions.open(accept.tun_addr) else {
        eprintln!("tun-broker: session refused: the kennel or the broker is at its ceiling");
        let _ = conn.reply_and_free(incoming, &[status::CEILING_FULL]);
        return;
    };
    let Ok((broker_end, consumer_end)) = session::channel() else {
        let _ = conn.reply_and_free(incoming, &[status::UNAVAILABLE]);
        return;
    };

    // Spawn the per-session mediator: the broker-end socket as its stdin (fd 0), the grants payload
    // hex-encoded on its argv. `stdout`/`stderr` are left to the broker's own so a stray write can
    // never reach the frame socket.
    let grants_hex = kennel_tun_broker::to_hex(&incoming.data);
    match Command::new(mediator)
        .arg(&grants_hex)
        .stdin(Stdio::from(OwnedFd::from(broker_end)))
        .spawn()
    {
        Ok(child) => {
            // Hand the mediator to the reaper, which holds its place until it exits. The mediator
            // exits when the consumer end closes, wherever that end is by then.
            if let Err(mpsc::SendError((mut child, _slot))) = spawned.send((child, slot)) {
                // No reaper to account for it: end the session rather than run it uncounted.
                let _ = child.kill();
                let _ = child.wait();
                let _ = conn.reply_and_free(incoming, &[status::UNAVAILABLE]);
                return;
            }
            if conn.reply_with_fd(incoming, consumer_end.as_fd()).is_err() {
                // The consumer end never left; dropping it here hangs up the mediator, which exits.
                eprintln!("tun-broker: failed to hand back session fd; session torn down");
            }
        }
        Err(e) => {
            eprintln!("tun-broker: spawning mediator `{mediator}`: {e}");
            let _ = conn.reply_and_free(incoming, &[status::UNAVAILABLE]);
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(device), Some(mediator)) = (args.next(), args.next()) else {
        eprintln!("tun-broker: usage: <binder-device> <mediator-path>");
        return ExitCode::FAILURE;
    };
    match run(&device, &mediator) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tun-broker: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
