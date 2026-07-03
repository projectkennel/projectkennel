//! The broker's event loop (W2 Part D): fold the facade channel and per-flow sockets into one loop.
//!
//! [`Broker`] holds the per-kennel state — the allowlist, the synthetic [`Pool`], the
//! [`FlowTable`] and its ceilings — and turns each frame from `facade-tun` into an action:
//!
//! - a DNS query to the reserved resolver address → the shim's AAAA/NODATA reply, sent back;
//! - an egress datagram to a live synthetic → the flow's pinned socket (dialled once, reused after),
//!   or an `ICMPv6` admin-prohibited when the destination is not permitted;
//! - a reply arriving on a flow socket → an ingress datagram to the workload, or an `ICMPv6`
//!   port-unreachable translated from a connected socket's `ECONNREFUSED`.
//!
//! Dispatch is factored from I/O: [`Broker::on_egress`] and [`Broker::on_flow_readable`] return an
//! [`Egress`] / [`Ingress`] the [`run`] loop carries out (send to the facade, register a new flow's
//! socket in the poller, evict a refused flow). That keeps the decision logic unit-testable while
//! the loop owns the epoll set and the flow-token bookkeeping.
//!
//! **Resolution** is inline on the loop thread — the concurrency bound is currently one. A slow
//! resolver therefore stalls only *this* kennel's new-flow dials (established flows keep flowing),
//! which is self-contained per the isolation model; a bounded resolver worker pool is the perf
//! refinement the roadmap flags (`recvmmsg`/off-loop resolution "if it ever matters").

use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

use crate::poll::Poller;

use crate::flow::{dial, FlowError};
use crate::icmp::{build_dest_unreachable, CODE_ADMIN_PROHIBITED, CODE_PORT_UNREACHABLE};
use crate::shim::{Allowlist, Pool};
use crate::table::{FlowKey, FlowTable};
use crate::{forward, shim};

/// IPv6 `next_header` for UDP.
const NEXT_UDP: u8 = 17;
/// The reserved resolver host suffix in the tun `/64` (`::2`): a UDP datagram to this address is a
/// DNS query for the shim, never a flow.
const RESOLVER_HOST: u128 = 2;
/// The port the shim answers DNS replies from (the reserved resolver's port). The workload's stub
/// resolver addresses `resolver:53`; the reply's source port must match.
const DNS_PORT: u16 = 53;
/// Buffer for a frame from the facade: the tun MTU is 1280, a little headroom bounds a read.
const FACADE_CAP: usize = 2048;
/// Buffer for a reply datagram from a real host on a flow socket. A datagram larger than the tun
/// MTU cannot be delivered (the MTU is pinned, no PMTUD) and is dropped downstream; a generous
/// buffer avoids truncating one that *does* fit.
const FLOW_CAP: usize = 65_536;

/// The facade channel's epoll token; flow sockets take monotonic tokens from `1`.
const FACADE_TOKEN: u64 = 0;
/// How often the loop wakes to expire idle flows when otherwise quiet.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The per-kennel broker state and the decision logic over it.
pub struct Broker {
    /// The tun interface address (`::1` in the `/64`) — the kennel's own address, the source/dest of
    /// the L3 frames the workload exchanges with the broker.
    kennel_addr: Ipv6Addr,
    /// The reserved resolver address (`::2`), where DNS queries arrive.
    resolver_addr: Ipv6Addr,
    allow: Allowlist,
    pool: Pool,
    table: FlowTable,
    bucket: crate::table::TokenBucket,
}

/// What the loop should do with an egress frame's outcome.
pub enum Egress {
    /// Nothing to emit (the datagram went out a pinned socket, or was dropped).
    Nothing,
    /// Send these bytes to the facade (a shim reply, or an `ICMPv6` error).
    ToFacade(Vec<u8>),
    /// A new flow was dialled: register its `socket` and admit it under `key`, having already sent
    /// the first datagram out.
    NewFlow {
        /// The flow key to admit under.
        key: FlowKey,
        /// The dialled, connected socket to register with the poller.
        socket: UdpSocket,
    },
}

/// What the loop should do with a flow socket's readiness.
pub enum Ingress {
    /// Nothing to emit.
    Nothing,
    /// Send these bytes to the facade (an ingress datagram).
    ToFacade(Vec<u8>),
    /// Send these bytes (an `ICMPv6` port-unreachable) and evict the flow (its host refused).
    ToFacadeAndEvict(Vec<u8>),
}

/// The per-kennel ceilings a broker enforces (all bound the kennel itself, so a spray saturates only
/// its own egress).
#[derive(Clone, Copy, Debug)]
pub struct Ceilings {
    /// The concurrent-flow cap.
    pub max_flows: usize,
    /// The new-flow token bucket's burst capacity.
    pub new_flow_burst: u32,
    /// The new-flow token bucket's steady rate (tokens per second).
    pub new_flow_per_sec: u32,
    /// How long a flow may sit idle before it is expired.
    pub idle_timeout: Duration,
}

impl Broker {
    /// Assemble a broker over the tun `kennel_addr` (`::1`), with the allowlist and ceilings. The
    /// synthetic pool and the reserved resolver address are derived from the address's `/64`. The
    /// deny-CIDR floor is the delegate's cgroup BPF filter, not broker state.
    #[must_use]
    pub fn new(kennel_addr: Ipv6Addr, allow: Allowlist, ceilings: Ceilings, now: Instant) -> Self {
        let prefix = prefix64(kennel_addr);
        let resolver_addr = suffix(prefix, RESOLVER_HOST);
        Self {
            kennel_addr,
            resolver_addr,
            allow,
            pool: Pool::new(prefix),
            table: FlowTable::new(ceilings.max_flows, ceilings.idle_timeout),
            bucket: crate::table::TokenBucket::new(
                ceilings.new_flow_burst,
                ceilings.new_flow_per_sec,
                now,
            ),
        }
    }

    /// Decide an egress frame from the facade. The frame already passed the facade's egress shape
    /// check (v6, UDP, src == kennel, dst ∈ pool); this reads the routing fields and acts.
    pub fn on_egress(&mut self, frame: &[u8], now: Instant) -> Egress {
        // A UDP datagram to the reserved resolver address is a DNS query, not a flow.
        if is_udp_to(frame, self.resolver_addr) {
            return self.on_query(frame);
        }
        let Some(route) = forward::route(frame, &self.pool) else {
            // Not a live synthetic (should not happen for a workload that got its AAAA from us) —
            // drop.
            return Egress::Nothing;
        };
        let key = FlowKey {
            synthetic: route_synthetic(frame).unwrap_or(self.kennel_addr),
            dst_port: route.dst_port,
            src_port: route.src_port,
        };
        // Reuse the pinned socket for an established flow.
        if let Some(sock) = self.table.touch(key, now) {
            let _ = sock.send(route.payload);
            return Egress::Nothing;
        }
        // A new flow: spend a token, then dial (resolve → re-vet → connect).
        if !self.bucket.try_take(now) {
            return Egress::Nothing; // new-flow rate exceeded; drop
        }
        match dial(&self.allow, &route.name, route.dst_port) {
            Ok(socket) => {
                let _ = socket.send(route.payload);
                Egress::NewFlow { key, socket }
            }
            Err(FlowError::NotAllowed | FlowError::Unresolved | FlowError::Dial(_)) => {
                // Not permitted, unreachable, or refused by the BPF deny floor (connect EPERM):
                // fast-fail with admin-prohibited, quoting the frame that triggered it.
                Egress::ToFacade(build_dest_unreachable(
                    key.synthetic,
                    self.kennel_addr,
                    CODE_ADMIN_PROHIBITED,
                    frame,
                ))
            }
            Err(FlowError::Resolve(_)) => Egress::Nothing, // transient resolver failure; drop
        }
    }

    /// Answer a DNS query addressed to the resolver: the shim's AAAA/NODATA reply, wrapped back into
    /// an ingress datagram from `resolver:53` to the querying `kennel:src_port`.
    fn on_query(&mut self, frame: &[u8]) -> Egress {
        let Some((payload, src_port)) = udp_payload_and_src_port(frame) else {
            return Egress::Nothing;
        };
        let Some(reply) = shim::respond(payload, &self.allow, &mut self.pool) else {
            return Egress::Nothing; // malformed query: dropped, never answered
        };
        forward::build_udp_datagram(
            self.resolver_addr,
            self.kennel_addr,
            DNS_PORT,
            src_port,
            &reply,
        )
        .map_or(Egress::Nothing, Egress::ToFacade)
    }

    /// Decide a flow socket's readiness: read the reply and wrap it back to the workload, or turn a
    /// connected socket's `ECONNREFUSED` into a port-unreachable and evict the flow.
    pub fn on_flow_readable(&mut self, key: FlowKey, now: Instant) -> Ingress {
        // Heap buffer: a datagram can be up to 64 KiB, too large for the stack.
        let mut buf = vec![0u8; FLOW_CAP];
        let Some(sock) = self.table.touch(key, now) else {
            return Ingress::Nothing;
        };
        match sock.recv(&mut buf) {
            Ok(n) => {
                let payload = buf.get(..n).unwrap_or(&[]);
                // The reply appears to come from the synthetic:dst_port back to the workload's
                // src_port — the flow it opened is the flow it hears back from.
                forward::build_udp_datagram(
                    key.synthetic,
                    self.kennel_addr,
                    key.dst_port,
                    key.src_port,
                    payload,
                )
                .map_or(Ingress::Nothing, Ingress::ToFacade)
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                // The host refused the port. Quote a reconstruction of the invoking datagram's
                // header (kennel:src_port → synthetic:dst_port) so the workload's kernel matches the
                // error to its socket, then evict — a fresh datagram re-dials and re-checks policy.
                let invoking = forward::build_udp_datagram(
                    self.kennel_addr,
                    key.synthetic,
                    key.src_port,
                    key.dst_port,
                    &[],
                )
                .unwrap_or_default();
                Ingress::ToFacadeAndEvict(build_dest_unreachable(
                    key.synthetic,
                    self.kennel_addr,
                    CODE_PORT_UNREACHABLE,
                    &invoking,
                ))
            }
            Err(_) => Ingress::Nothing,
        }
    }

    /// The concurrent-flow cap admit, exposed for the loop after it registers the socket.
    ///
    /// # Errors
    ///
    /// [`crate::table::AtCapacity`] when the flow cap is reached (the loop then drops the flow).
    pub fn admit(
        &mut self,
        key: FlowKey,
        socket: UdpSocket,
        now: Instant,
    ) -> Result<(), crate::table::AtCapacity> {
        self.table.admit(key, socket, now)
    }

    /// Expire idle flows, returning the evicted keys for token cleanup.
    pub fn sweep(&mut self, now: Instant) -> Vec<FlowKey> {
        self.table.sweep(now)
    }

    /// Evict one flow (after a port-unreachable).
    pub fn remove(&mut self, key: FlowKey) {
        self.table.remove(key);
    }
}

/// Run the broker loop over the `facade` channel until it closes (kennel teardown / broker HUP).
///
/// Folds the facade channel and every per-flow socket into one `epoll` set; resolves and dials
/// inline. Returns `Ok(())` on a clean shutdown.
///
/// # Errors
///
/// An `epoll` or socket-registration OS error the loop cannot recover from.
pub fn run(mut broker: Broker, facade: &UnixDatagram, mut poller: Poller) -> io::Result<()> {
    poller.add(facade, FACADE_TOKEN)?;
    let mut next_token: u64 = 1;
    let mut token_key: HashMap<u64, FlowKey> = HashMap::new();
    let mut key_token: HashMap<FlowKey, u64> = HashMap::new();
    let mut fbuf = [0u8; FACADE_CAP];

    loop {
        let ready = poller.wait(Some(SWEEP_INTERVAL))?;
        let now = Instant::now();
        for r in &ready {
            if r.token == FACADE_TOKEN {
                if r.hangup {
                    return Ok(());
                }
                match facade.recv(&mut fbuf) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        let frame = fbuf.get(..n).unwrap_or(&[]);
                        match broker.on_egress(frame, now) {
                            Egress::Nothing => {}
                            Egress::ToFacade(bytes) => {
                                let _ = facade.send(&bytes);
                            }
                            Egress::NewFlow { key, socket } => {
                                let token = next_token;
                                next_token = next_token.saturating_add(1);
                                if poller.add(&socket, token).is_ok()
                                    && broker.admit(key, socket, now).is_ok()
                                {
                                    token_key.insert(token, key);
                                    key_token.insert(key, token);
                                }
                                // If admit fails (cap) or registration fails, the socket drops here
                                // and closes, auto-removed from the poller.
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Ok(()),
                }
            } else if let Some(&key) = token_key.get(&r.token) {
                match broker.on_flow_readable(key, now) {
                    Ingress::Nothing => {}
                    Ingress::ToFacade(bytes) => {
                        let _ = facade.send(&bytes);
                    }
                    Ingress::ToFacadeAndEvict(bytes) => {
                        let _ = facade.send(&bytes);
                        broker.remove(key);
                        if let Some(token) = key_token.remove(&key) {
                            token_key.remove(&token);
                        }
                    }
                }
            }
        }
        // Expire idle flows and release their bookkeeping (the sockets close on eviction, so epoll
        // drops them automatically).
        for key in broker.sweep(now) {
            if let Some(token) = key_token.remove(&key) {
                token_key.remove(&token);
            }
        }
    }
}

/// The `/64` prefix (first eight octets) of an address.
const fn prefix64(addr: Ipv6Addr) -> [u8; 8] {
    let o = addr.octets();
    [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
}

/// The `/64` address for host suffix `host` under `prefix`.
fn suffix(prefix: [u8; 8], host: u128) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    if let Some(p) = octets.get_mut(..8) {
        p.copy_from_slice(&prefix);
    }
    let low = host.to_be_bytes();
    if let (Some(dst), Some(src)) = (octets.get_mut(8..16), low.get(8..16)) {
        dst.copy_from_slice(src);
    }
    Ipv6Addr::from(octets)
}

/// Whether `frame` is a UDP datagram whose destination address is `addr` (bounds-checked).
fn is_udp_to(frame: &[u8], addr: Ipv6Addr) -> bool {
    frame.get(6) == Some(&NEXT_UDP) && route_synthetic(frame) == Some(addr)
}

/// The destination address (octets 24..40) of an IPv6 frame, bounds-checked.
fn route_synthetic(frame: &[u8]) -> Option<Ipv6Addr> {
    let dst = frame.get(24..40)?;
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(dst).ok()?))
}

/// The UDP payload and source port of a query frame (the first eight octets after the IPv6 header
/// are the UDP header; the payload follows), bounds-checked.
fn udp_payload_and_src_port(frame: &[u8]) -> Option<(&[u8], u16)> {
    let src_port = u16::from_be_bytes(<[u8; 2]>::try_from(frame.get(40..42)?).ok()?);
    let payload = frame.get(48..)?;
    Some((payload, src_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::settled::{NameRule, Protocol};

    const PREFIX: [u8; 8] = [0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01];

    fn kennel() -> Ipv6Addr {
        suffix(PREFIX, 1)
    }
    fn resolver() -> Ipv6Addr {
        suffix(PREFIX, 2)
    }

    fn grant(name: &str) -> NameRule {
        NameRule {
            name: name.to_owned(),
            ports: Vec::new(),
            protocol: Protocol::Udp,
        }
    }

    fn broker(grants: Vec<NameRule>) -> Broker {
        Broker::new(
            kennel(),
            Allowlist::new(grants),
            Ceilings {
                max_flows: 64,
                new_flow_burst: 32,
                new_flow_per_sec: 16,
                idle_timeout: Duration::from_secs(30),
            },
            Instant::now(),
        )
    }

    /// The `ToFacade` bytes of an egress outcome, or `None` for any other outcome.
    fn facade_bytes(e: Egress) -> Option<Vec<u8>> {
        match e {
            Egress::ToFacade(b) => Some(b),
            _ => None,
        }
    }

    /// A DNS query frame (workload kennel:sport → resolver:53) carrying `query_bytes`.
    fn dns_frame(sport: u16, query_bytes: &[u8]) -> Vec<u8> {
        udp_frame(kennel(), resolver(), sport, DNS_PORT, query_bytes)
    }

    fn udp_frame(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        forward::build_udp_datagram(src, dst, sport, dport, payload).expect("frame")
    }

    fn dns_query(name: &str) -> Vec<u8> {
        use simple_dns::{Name, Packet, Question, CLASS, QCLASS, QTYPE, TYPE};
        let mut p = Packet::new_query(0x1234);
        p.questions.push(Question::new(
            Name::new(name).expect("name"),
            QTYPE::TYPE(TYPE::AAAA),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.build_bytes_vec().expect("query")
    }

    #[test]
    fn an_allowed_aaaa_query_gets_a_synthetic_reply_from_the_resolver() {
        let mut b = broker(vec![grant("example.com")]);
        let frame = dns_frame(40000, &dns_query("example.com"));
        let reply = facade_bytes(b.on_egress(&frame, Instant::now())).expect("a DNS reply");
        // The reply is v6/UDP from resolver:53 to kennel:40000.
        assert_eq!(reply.get(6), Some(&NEXT_UDP));
        assert_eq!(route_synthetic(&reply), Some(kennel()), "to the kennel");
        assert_eq!(&reply.get(8..24).expect("src"), &resolver().octets());
        // It carries an AAAA answer with a synthetic in the pool.
        let dns = reply.get(48..).expect("dns");
        let parsed = simple_dns::Packet::parse(dns).expect("parse");
        assert_eq!(
            parsed.answers.len(),
            1,
            "one AAAA answer for the allowed name"
        );
    }

    #[test]
    fn a_denied_name_query_is_nodata_no_synthetic() {
        let mut b = broker(vec![grant("example.com")]);
        let frame = dns_frame(40000, &dns_query("evil.test"));
        let reply = facade_bytes(b.on_egress(&frame, Instant::now())).expect("a NODATA reply");
        let dns = reply.get(48..).expect("dns");
        let parsed = simple_dns::Packet::parse(dns).expect("parse");
        assert_eq!(
            parsed.answers.len(),
            0,
            "NODATA: no answer for a denied name"
        );
    }

    #[test]
    fn an_egress_to_an_unminted_synthetic_is_dropped() {
        // Without a prior AAAA the synthetic was never minted, so route() misses → nothing emitted.
        let mut b = broker(vec![grant("example.com")]);
        let frame = udp_frame(kennel(), suffix(PREFIX, 0x99), 5000, 443, b"x");
        assert!(matches!(
            b.on_egress(&frame, Instant::now()),
            Egress::Nothing
        ));
    }

    #[test]
    fn an_egress_on_a_disallowed_port_gets_admin_prohibited() {
        // A synthetic minted for an allowed name, but the flow's port is not in the grant: the flow
        // gate refuses it (before any resolution) with admin-prohibited. The deny-CIDR floor itself
        // is the delegate's cgroup BPF filter (a connect EPERM), exercised in e2e, not here.
        let mut b = broker(vec![NameRule {
            name: "example.com".to_owned(),
            ports: vec![443],
            protocol: Protocol::Udp,
        }]);
        let q = dns_frame(40000, &dns_query("example.com"));
        let reply = facade_bytes(b.on_egress(&q, Instant::now())).expect("query reply");
        let dns = reply.get(48..).expect("dns");
        let parsed = simple_dns::Packet::parse(dns).expect("parse");
        let synth = parsed
            .answers
            .iter()
            .find_map(|rr| match &rr.rdata {
                simple_dns::rdata::RData::AAAA(a) => Some(Ipv6Addr::from(a.address)),
                _ => None,
            })
            .expect("a synthetic was minted");
        // Egress to that synthetic on port 53 (not in the [443] grant) → admin-prohibited.
        let frame = udp_frame(kennel(), synth, 5000, 53, b"query");
        let icmp = facade_bytes(b.on_egress(&frame, Instant::now())).expect("admin-prohibited");
        assert_eq!(icmp.get(6), Some(&58), "ICMPv6");
        assert_eq!(icmp.get(40), Some(&1), "type 1 dest-unreachable");
        assert_eq!(icmp.get(41), Some(&CODE_ADMIN_PROHIBITED), "code 1");
    }
}
