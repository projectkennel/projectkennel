//! A token-bucket rate limiter for messages crossing the D-Bus mediation boundary.
//!
//! # Why this exists
//!
//! Per-message D-Bus rides the binder gateway: the facade transacts each message to node 0 and
//! **kenneld is the membrane** (§7.7.2a) — it relays the opaque frame to the operator-context
//! `host-dbus` delegate over an owner-only pipe. Because that relay hop is a pipe rather than a
//! binder-node transaction, it does not get binder's implicit per-transaction enforcement, so the
//! membrane re-derives the bounds explicitly: message *size* ([`crate::dbus::MAX_FRAME`]) and, here,
//! *rate*.
//!
//! The cap is enforced at the **membrane** — kenneld spends a token per control/data verb
//! (`DBUS_SEND`/`DBUS_CLOSE` at the broker's session gateway) and sheds a flood before it reaches
//! `host-dbus` at all. It can also be applied at the delegate (defence in depth: `host-dbus` runs
//! in the operator's context, off the kennel's cgroup, so an unbounded flood there would amplify
//! into operator CPU/memory and **real-bus traffic**).
//!
//! # Clock injection
//!
//! [`RateLimiter::allow`] takes the current monotonic time in milliseconds rather than reading a
//! clock, so the bucket is deterministically testable; the binaries pass
//! `Instant::now()`-derived millis.

/// The default sustained rate (messages per second) a kennel may send across the conduit.
///
/// A legitimate client is chatty in bursts at startup (`Hello`, `AddMatch`, `GetNameOwner`…)
/// but settles well under this; a flood is bounded here.
pub const DEFAULT_PER_SECOND: u32 = 200;

/// The default burst (bucket capacity) — startup chatter without tripping the limit.
pub const DEFAULT_BURST: u32 = 400;

/// One token in milli-token units, so the bucket refills smoothly with integer arithmetic.
const TOKEN: u64 = 1000;

/// A token bucket: `per_second` tokens accrue each second up to `burst`, one spent per message.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Bucket capacity in milli-tokens (`burst * TOKEN`).
    capacity: u64,
    /// Current fill in milli-tokens.
    tokens: u64,
    /// Refill in milli-tokens per millisecond (`per_second`, since `per_second * TOKEN` per
    /// second is `per_second` milli-tokens per millisecond).
    refill_per_ms: u64,
    /// The monotonic millisecond timestamp of the last [`RateLimiter::allow`] call.
    last_ms: u64,
    /// Whether `last_ms` has been seeded (the first call sets the baseline without refilling).
    started: bool,
}

impl RateLimiter {
    /// A limiter admitting `per_second` messages sustained with a `burst` bucket. A `per_second`
    /// of 0 admits nothing; the bucket starts full so a legitimate startup burst passes.
    #[must_use]
    pub fn new(per_second: u32, burst: u32) -> Self {
        let capacity = u64::from(burst).saturating_mul(TOKEN);
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: u64::from(per_second),
            last_ms: 0,
            started: false,
        }
    }

    /// The default limiter ([`DEFAULT_PER_SECOND`] / [`DEFAULT_BURST`]).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_PER_SECOND, DEFAULT_BURST)
    }

    /// Refill for the elapsed time and try to spend one token. Returns `true` if the message is
    /// admitted, `false` if the bucket is empty (over-rate). Monotonic `now_ms` must not go
    /// backwards within one limiter; a non-monotonic step simply refills nothing.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        if self.started {
            let elapsed = now_ms.saturating_sub(self.last_ms);
            let refill = self.refill_per_ms.saturating_mul(elapsed);
            self.tokens = self.capacity.min(self.tokens.saturating_add(refill));
        } else {
            self.started = true;
        }
        self.last_ms = now_ms;
        if self.tokens >= TOKEN {
            self.tokens = self.tokens.saturating_sub(TOKEN);
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_passes_then_bucket_empties() {
        // A burst of `burst` at t=0 passes; the next is refused until time advances.
        let mut rl = RateLimiter::new(100, 5);
        for _ in 0..5 {
            assert!(rl.allow(0), "the burst should pass");
        }
        assert!(!rl.allow(0), "the 6th in the same instant is over-rate");
    }

    #[test]
    fn tokens_refill_over_time() {
        let mut rl = RateLimiter::new(100, 1); // 100/s, burst 1
        assert!(rl.allow(0));
        assert!(!rl.allow(0), "bucket empty");
        // 100/s = one token per 10ms; after 10ms one more is admitted.
        assert!(!rl.allow(5), "5ms < 10ms, still empty");
        assert!(rl.allow(10), "10ms refills exactly one token");
        assert!(!rl.allow(10));
    }

    #[test]
    fn refill_caps_at_burst() {
        let mut rl = RateLimiter::new(100, 3);
        // Idle a long time; the bucket cannot exceed its capacity of 3.
        let _ = rl.allow(0);
        assert!(rl.allow(1_000_000));
        assert!(rl.allow(1_000_000));
        assert!(rl.allow(1_000_000));
        assert!(
            !rl.allow(1_000_000),
            "capacity is 3 even after a long idle, not unbounded"
        );
    }

    #[test]
    fn zero_rate_only_admits_the_initial_burst() {
        let mut rl = RateLimiter::new(0, 2);
        assert!(rl.allow(0));
        assert!(rl.allow(0));
        assert!(!rl.allow(0));
        assert!(!rl.allow(1_000_000), "no refill ever");
    }

    #[test]
    fn non_monotonic_time_refills_nothing() {
        let mut rl = RateLimiter::new(100, 1);
        assert!(rl.allow(100));
        assert!(!rl.allow(100));
        // Time going backwards must not over-refill (saturating_sub → 0 elapsed).
        assert!(!rl.allow(50));
    }
}
