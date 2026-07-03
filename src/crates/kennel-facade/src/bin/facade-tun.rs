//! In-kennel UDP-egress L3 forwarder: copy whole IPv6 frames between the kennel's tun and the
//! fenced flow broker, behind a symmetric shape predicate (W2 Part C).
//!
//! # Purpose
//!
//! The UDP-egress facade (Kennel book Vol 2 ch.8 (The Network)): a `[net.udp]` workload's raw UDP
//! (QUIC/h3, DNS, …) leaves its net-ns over the `tun` the factory built. `facade-tun` holds the tun
//! fd and one `SOCK_SEQPACKET` channel to the broker, and copies **whole L3 frames** both ways —
//! originating nothing, keeping no flow state. Each frame passes the direction's
//! [`shape check`](kennel_facade::tun) first; a frame that fails is dropped (counted, never an ICMP).
//! The egress direction parses genuinely hostile workload input, so the predicate is the crate's
//! fuzz target. All resolution, dialing, and the naming shim are the broker's — this process is a
//! stateless L3 predicate, not a codec.
//!
//! # Invocation
//!
//! `facade-tun <kennel-tun-addr>`, spawned by `kennel-bin-init` into the kennel's view. The tun fd
//! and the broker channel arrive at the fixed inherited slots
//! [`TUN_FD`](kennel_lib_syscall::boot::TUN_FD) /
//! [`BROKER_FD`](kennel_lib_syscall::boot::BROKER_FD); `<kennel-tun-addr>` is the tun's own IPv6
//! address (its `/64` is the synthetic pool + resolver).
//!
//! # Non-goals
//!
//! No DNS, no resolver, no policy, no host socket: a query to the resolver address is just another
//! UDP frame it forwards. The broker decides, resolves, and dials.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram;
use std::process::ExitCode;
use std::thread;

use kennel_facade::tun::{egress_ok, ingress_ok};
use kennel_lib_syscall::boot::{BROKER_FD, TUN_FD};
use kennel_lib_syscall::fd::adopt;

/// The frame buffer: the tun's MTU is 1280 (the IPv6 minimum); a little headroom over that bounds
/// any single read without ever truncating a legal frame.
const FRAME_CAP: usize = 2048;

fn main() -> ExitCode {
    let Some(addr) = std::env::args().nth(1) else {
        eprintln!("facade-tun: usage: <kennel-tun-addr>");
        return ExitCode::FAILURE;
    };
    let Ok(kennel_addr) = addr.parse::<Ipv6Addr>() else {
        eprintln!("facade-tun: `{addr}` is not an IPv6 address");
        return ExitCode::FAILURE;
    };
    // SAFETY-contract of `adopt`: `facade-tun` is the sole owner of the two inherited slots, wrapped
    // exactly once each here (`kennel-bin-init` routed them to this process alone).
    let tun = File::from(adopt(TUN_FD));
    let broker = UnixDatagram::from(adopt(BROKER_FD));
    match serve(tun, broker, kennel_addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("facade-tun: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run both copy loops until either side closes: egress (tun → broker) on a worker thread, ingress
/// (broker → tun) on this thread. The `/64` prefix the predicate matches on is the tun address's.
fn serve(tun: File, broker: UnixDatagram, kennel_addr: Ipv6Addr) -> io::Result<()> {
    let prefix = prefix64(kennel_addr);
    let tun_rx = tun.try_clone()?;
    let tun_tx = tun;
    let broker_tx = broker.try_clone()?;
    let broker_rx = broker;
    let egress = thread::spawn(move || pump_egress(tun_rx, &broker_tx, kennel_addr, prefix));
    pump_ingress(&broker_rx, tun_tx, kennel_addr, prefix);
    // A copy loop only returns when its side closed (kennel teardown / broker HUP); either ending
    // takes the facade down, and the supervisor decides whether to re-fork.
    let _ = egress.join();
    Ok(())
}

/// The `/64` prefix (first eight octets) of an address.
const fn prefix64(addr: Ipv6Addr) -> [u8; 8] {
    let o = addr.octets();
    [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
}

/// Egress: read one frame from the tun, and — iff it passes the egress shape check — send it whole
/// to the broker. A failed check or a send error drops the frame (the broker channel is
/// message-preserving, so one read maps to one send). Returns when the tun read returns 0/errors.
fn pump_egress(mut tun: File, broker: &UnixDatagram, kennel_addr: Ipv6Addr, prefix: [u8; 8]) {
    let mut buf = [0u8; FRAME_CAP];
    loop {
        let Ok(n) = tun.read(&mut buf) else { return };
        if n == 0 {
            return;
        }
        let Some(frame) = buf.get(..n) else { return };
        if egress_ok(frame, kennel_addr, prefix) && broker.send(frame).is_err() {
            return;
        }
    }
}

/// Ingress: receive one frame from the broker, and — iff it passes the ingress shape check — write
/// it whole to the tun. Returns when the broker recv returns 0/errors.
fn pump_ingress(broker: &UnixDatagram, mut tun: File, kennel_addr: Ipv6Addr, prefix: [u8; 8]) {
    let mut buf = [0u8; FRAME_CAP];
    loop {
        let Ok(n) = broker.recv(&mut buf) else { return };
        if n == 0 {
            return;
        }
        let Some(frame) = buf.get(..n) else { return };
        if ingress_ok(frame, kennel_addr, prefix) && tun.write_all(frame).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn kennel() -> Ipv6Addr {
        "fd6b:6e9c:691c:8001::1".parse().expect("addr")
    }

    /// A minimal well-formed egress UDP frame (workload → `dst` in the pool).
    fn egress_udp(dst: &str) -> Vec<u8> {
        let mut f = vec![0x60, 0, 0, 0]; // v6, flow 0
        f.extend_from_slice(&8u16.to_be_bytes()); // payload len = one UDP header
        f.push(17); // next header = UDP
        f.push(64); // hop limit
        f.extend_from_slice(&kennel().octets());
        f.extend_from_slice(&dst.parse::<Ipv6Addr>().expect("dst").octets());
        f.extend_from_slice(&[0u8; 8]); // UDP header
        f
    }

    #[test]
    fn egress_forwards_valid_frames_and_drops_the_rest() {
        // `tun_ext`/`broker_ext` are the test's ends; the facade drives the other ends.
        let (tun_ext, tun_facade) = UnixDatagram::pair().expect("tun pair");
        let (broker_ext, broker_facade) = UnixDatagram::pair().expect("broker pair");
        broker_ext
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let prefix = prefix64(kennel());
        let facade = File::from(std::os::fd::OwnedFd::from(tun_facade));
        // The loop runs on a worker; we do NOT join — a connected DGRAM pair does not unblock a
        // blocked `read` on peer close the way the real tun/SEQPACKET does. The worker ends when
        // `tun_ext` drops at scope exit; the assertions below are the property under test.
        let _worker = thread::spawn(move || pump_egress(facade, &broker_facade, kennel(), prefix));

        // A valid frame is forwarded whole and unchanged.
        let good = egress_udp("fd6b:6e9c:691c:8001::abcd");
        tun_ext.send(&good).expect("send good");
        let mut buf = [0u8; FRAME_CAP];
        let n = broker_ext.recv(&mut buf).expect("forwarded");
        assert_eq!(
            buf.get(..n),
            Some(good.as_slice()),
            "frame forwarded intact"
        );

        // A frame that fails the shape check (dst outside the /64) is dropped, not forwarded.
        tun_ext.send(&egress_udp("2001:db8::1")).expect("send bad");
        assert!(
            broker_ext.recv(&mut buf).is_err(),
            "an off-/64 frame must be dropped, not forwarded"
        );
    }
}
