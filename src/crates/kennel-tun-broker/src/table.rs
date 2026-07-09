//! The broker's flow table and ceilings (W2 Part D): observed flows, capped and idle-expired.
//!
//! UDP is many cheap flows, not few long conduits, so each flow is just a key and its connected
//! socket — no per-flow process. The key is **observed, never predicted**: the first datagram to a
//! synthetic names the `(synthetic, dst_port, src_port)` tuple, the flow is dialled once, and every
//! later datagram of that tuple reuses the pinned socket.
//!
//! Three ceilings keep a spraying workload saturating only itself (all per-kennel by construction):
//!
//! - a **concurrent-flow cap** ([`FlowTable::admit`] refuses a new flow past it),
//! - a **new-flow token bucket** ([`TokenBucket`]) rate-limiting flow creation, and
//! - a resolution-concurrency bound (the event loop's, not here — this module holds no sockets open
//!   during a lookup).
//!
//! Teardown is idle expiry (RFC 4787): [`FlowTable::sweep`] drops flows unseen for the idle timeout,
//! closing their sockets. Kennel death is a separate signal (the socketpair HUP) the event loop
//! handles; this module is time-driven only.

use std::collections::HashMap;
use std::net::{Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

/// A flow as observed from the tun: the synthetic destination, the destination port, and the
/// workload's source port. The tuple is read off the datagram, never guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// The synthetic destination address the workload addressed.
    pub synthetic: Ipv6Addr,
    /// The destination port (the real service port, once dialled).
    pub dst_port: u16,
    /// The workload's source port — where the reply must return.
    pub src_port: u16,
}

/// One live flow: its pinned connected socket and the last time a datagram was seen on it.
struct Flow {
    socket: UdpSocket,
    last_seen: Instant,
}

/// The per-kennel flow table with its concurrent-flow cap and idle-expiry teardown.
pub struct FlowTable {
    max_flows: usize,
    idle_timeout: Duration,
    flows: HashMap<FlowKey, Flow>,
}

/// A new flow could not be admitted because the concurrent-flow cap is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtCapacity;

impl FlowTable {
    /// A table capped at `max_flows` concurrent flows, expiring flows idle for `idle_timeout`.
    #[must_use]
    pub fn new(max_flows: usize, idle_timeout: Duration) -> Self {
        Self {
            max_flows,
            idle_timeout,
            flows: HashMap::new(),
        }
    }

    /// The pinned socket for an existing flow, marking it seen at `now`; `None` if the flow is not
    /// yet in the table (the caller then dials and [`admit`](Self::admit)s it).
    pub fn touch(&mut self, key: FlowKey, now: Instant) -> Option<&UdpSocket> {
        self.flows.get_mut(&key).map(|flow| {
            flow.last_seen = now;
            &flow.socket
        })
    }

    /// Admit a newly dialled flow, or refuse it if the concurrent-flow cap is reached.
    ///
    /// # Errors
    ///
    /// [`AtCapacity`] when the table already holds `max_flows` flows — the caller drops the datagram
    /// (a spray saturates only itself). Re-admitting an existing key replaces it and never counts
    /// against the cap.
    pub fn admit(
        &mut self,
        key: FlowKey,
        socket: UdpSocket,
        now: Instant,
    ) -> Result<(), AtCapacity> {
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            return Err(AtCapacity);
        }
        self.flows.insert(
            key,
            Flow {
                socket,
                last_seen: now,
            },
        );
        Ok(())
    }

    /// Drop every flow unseen for at least the idle timeout as of `now`, closing its socket. Returns
    /// the evicted keys so the caller can release any per-flow bookkeeping (epoll token, maps).
    pub fn sweep(&mut self, now: Instant) -> Vec<FlowKey> {
        let idle = self.idle_timeout;
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| now.saturating_duration_since(flow.last_seen) >= idle)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.flows.remove(key);
        }
        expired
    }

    /// Drop a single flow, closing its socket. Returns whether a flow was present (e.g. after a
    /// connection-refused, the caller evicts the flow it just answered with a port-unreachable).
    pub fn remove(&mut self, key: FlowKey) -> bool {
        self.flows.remove(&key).is_some()
    }

    /// The set of synthetic destinations with a live flow — what the pool's rotating
    /// window must never evict (W8). Recomputed per DNS query; flows are few (`max_flows`).
    #[must_use]
    pub fn live_synthetics(&self) -> std::collections::HashSet<Ipv6Addr> {
        self.flows.keys().map(|k| k.synthetic).collect()
    }

    /// The number of live flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether the table holds no flows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

/// A token bucket rate-limiting new-flow creation: `capacity` tokens, refilled at `refill_per_sec`.
///
/// One token is spent per new flow ([`try_take`](Self::try_take)); a burst up to `capacity` passes,
/// then the rate settles to `refill_per_sec`. Millisecond-resolution refill, integer-only (no float
/// arithmetic), advancing the clock only by the whole tokens actually credited so no fractional
/// token is lost.
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_per_sec: u32,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket of `capacity` tokens refilling at `refill_per_sec`, as of `now`.
    #[must_use]
    pub const fn new(capacity: u32, refill_per_sec: u32, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: now,
        }
    }

    /// Take one token if available (a new flow may be created), refilling first. `false` means the
    /// new-flow rate is exceeded and the caller drops the datagram.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if let Some(remaining) = self.tokens.checked_sub(1) {
            self.tokens = remaining;
            true
        } else {
            false
        }
    }

    /// Credit whole tokens for the time elapsed since the last refill, capped at `capacity`, and
    /// advance the clock only by the time those whole tokens represent (keeping the remainder).
    fn refill(&mut self, now: Instant) {
        if self.refill_per_sec == 0 {
            return;
        }
        let elapsed_ms = now.saturating_duration_since(self.last).as_millis();
        let credited = elapsed_ms.saturating_mul(u128::from(self.refill_per_sec)) / 1000;
        if credited == 0 {
            return;
        }
        let credited = u32::try_from(credited).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(credited).min(self.capacity);
        // Advance `last` by the time the credited tokens represent, so a sub-token remainder carries
        // to the next call rather than being discarded.
        let consumed_ms = u64::from(credited)
            .saturating_mul(1000)
            .checked_div(u64::from(self.refill_per_sec))
            .unwrap_or(0);
        self.last = self
            .last
            .checked_add(Duration::from_millis(consumed_ms))
            .unwrap_or(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src_port: u16) -> FlowKey {
        FlowKey {
            synthetic: "fd6b:6e9c:691c:8001::10".parse().expect("addr"),
            dst_port: 443,
            src_port,
        }
    }

    fn socket() -> UdpSocket {
        UdpSocket::bind("[::1]:0").expect("bind")
    }

    #[test]
    fn admit_touch_and_reuse() {
        let mut table = FlowTable::new(4, Duration::from_secs(30));
        let now = Instant::now();
        assert!(table.touch(key(1000), now).is_none(), "absent before admit");
        table.admit(key(1000), socket(), now).expect("admit");
        assert_eq!(table.len(), 1);
        assert!(table.touch(key(1000), now).is_some(), "present after admit");
    }

    #[test]
    fn the_concurrent_cap_refuses_a_new_flow_but_not_a_readmit() {
        let mut table = FlowTable::new(2, Duration::from_secs(30));
        let now = Instant::now();
        table.admit(key(1), socket(), now).expect("first");
        table.admit(key(2), socket(), now).expect("second");
        assert_eq!(
            table.admit(key(3), socket(), now),
            Err(AtCapacity),
            "third over cap"
        );
        // Re-admitting an existing key replaces it and does not count against the cap.
        table
            .admit(key(1), socket(), now)
            .expect("re-admit existing");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn sweep_evicts_only_idle_flows() {
        let mut table = FlowTable::new(8, Duration::from_secs(30));
        let t0 = Instant::now();
        table.admit(key(1), socket(), t0).expect("old");
        let later = t0 + Duration::from_secs(20);
        table.admit(key(2), socket(), later).expect("fresh");
        // At t0+40s, key(1) is 40s idle (evicted), key(2) is 20s idle (kept).
        let evicted = table.sweep(t0 + Duration::from_secs(40));
        assert_eq!(evicted, vec![key(1)]);
        assert_eq!(table.len(), 1);
        assert!(table.touch(key(2), t0 + Duration::from_secs(40)).is_some());
    }

    #[test]
    fn remove_drops_one_flow() {
        let mut table = FlowTable::new(4, Duration::from_secs(30));
        let now = Instant::now();
        table.admit(key(1), socket(), now).expect("admit");
        assert!(table.remove(key(1)), "present");
        assert!(!table.remove(key(1)), "already gone");
        assert!(table.is_empty());
    }

    #[test]
    fn the_token_bucket_bursts_then_throttles() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(3, 1, t0); // burst 3, then 1/sec
        assert!(bucket.try_take(t0), "burst 1");
        assert!(bucket.try_take(t0), "burst 2");
        assert!(bucket.try_take(t0), "burst 3");
        assert!(!bucket.try_take(t0), "empty after the burst");
        // One second later, exactly one token has refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(bucket.try_take(t1), "one refilled");
        assert!(!bucket.try_take(t1), "and only one");
    }

    #[test]
    fn a_sub_token_remainder_carries_across_calls() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(1, 1, t0);
        assert!(bucket.try_take(t0), "the initial token");
        // Two 600ms steps: neither alone yields a whole token, but together they cross one second.
        assert!(
            !bucket.try_take(t0 + Duration::from_millis(600)),
            "0.6 token"
        );
        assert!(
            bucket.try_take(t0 + Duration::from_millis(1200)),
            "the remainder carried, so 1.2s yields a token"
        );
    }
}
