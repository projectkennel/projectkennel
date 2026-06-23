//! The service-kennel readiness state machine (`07-13-service-catalog.md` §7.13.7).
//!
//! # Purpose
//!
//! An enabled provider (§7.13.6) is, at any moment, in exactly one of three readiness states. This
//! module is the **contract** for that machine: the states, the supervision events, and which
//! transitions are legal. The catalogue (the projection of enabled providers) and the topology
//! surface (`kennel ps`) both read readiness, so the machine is defined **once**, here, and asserted
//! by tests — the supervisor in `kenneld` *drives* the transitions but does not get to invent them.
//!
//! # Why here
//!
//! Readiness is a cross-process status vocabulary shared by the daemon and the CLI — exactly what
//! this crate already carries for the wire protocol. It is a pure value type with no dependencies
//! (no `serde`, in keeping with this crate's TCB discipline); the wire encoding that reports it to
//! `kennel ps` is the topology surface's, layered on top, not part of this contract.

/// The readiness of an enabled provider (§7.13.7). Exactly one holds at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// **declared-but-pending** — enabled and catalogued, construction not yet complete: an
    /// `autorun` provider between daemon start and a successful seal, or an `ondemand` provider a
    /// consume has just triggered. Its name *resolves* (a `required = true` consumer's
    /// construction-time check passes), but a connect waits on [`Ready`](Self::Ready).
    Pending,
    /// **declared-and-ready** — construction succeeded and the capability is reachable; a consumer's
    /// connect bridges straight through.
    Ready,
    /// **declared-but-failed** — construction or supervision gave up: `max_attempts` exhausted, or a
    /// `restart = never` provider that exited non-zero. **Sticky**: the name stays catalogued (it is
    /// still *enabled*) so the failure is visible rather than a silent resolve-miss, and only an
    /// operator act (fix and `daemon-reload`, or re-enable) clears it — no supervision event does.
    Failed,
}

/// A supervision event that may drive a [`Readiness`] transition (§7.13.7). The supervisor in
/// `kenneld` raises these; [`Readiness::on`] is the single place that says what each one means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Construction sealed successfully.
    ConstructionSucceeded,
    /// Construction itself failed (the seal did not complete).
    ConstructionFailed,
    /// A running provider died and is being restarted under its `[service]` policy — the same
    /// restart that invalidates live connectors (§7.13.4).
    Restarting,
    /// An idle `ondemand` provider was reaped. Not a failure: it returns to resolvable-but-not-running.
    IdleReaped,
    /// The crash-loop bound (`max_attempts`) was exhausted — whether before a first ready or after.
    CrashLoopExhausted,
}

impl Readiness {
    /// The state this `event` drives `self` to, or `None` if the transition is **illegal** from
    /// `self` (the caller treats `None` as a no-op-and-audit, never a silent state change).
    ///
    /// The legal transitions, and only these (§7.13.7):
    ///
    /// - [`Pending`](Self::Pending) → [`Ready`](Self::Ready) on [`ConstructionSucceeded`](Event::ConstructionSucceeded)
    /// - [`Pending`](Self::Pending) → [`Failed`](Self::Failed) on [`ConstructionFailed`](Event::ConstructionFailed) or [`CrashLoopExhausted`](Event::CrashLoopExhausted) (a crash loop before a first ready)
    /// - [`Ready`](Self::Ready) → [`Pending`](Self::Pending) on [`Restarting`](Event::Restarting) or [`IdleReaped`](Event::IdleReaped)
    /// - [`Ready`](Self::Ready) → [`Failed`](Self::Failed) on [`CrashLoopExhausted`](Event::CrashLoopExhausted) (a restart loop after a prior ready)
    ///
    /// [`Failed`](Self::Failed) is **terminal**: no event leaves it, so a failure is sticky and
    /// observable until an operator intervenes (outside this machine).
    #[must_use]
    pub const fn on(self, event: Event) -> Option<Self> {
        match (self, event) {
            (Self::Pending, Event::ConstructionSucceeded) => Some(Self::Ready),
            (Self::Pending, Event::ConstructionFailed | Event::CrashLoopExhausted) => {
                Some(Self::Failed)
            }
            (Self::Ready, Event::Restarting | Event::IdleReaped) => Some(Self::Pending),
            (Self::Ready, Event::CrashLoopExhausted) => Some(Self::Failed),
            _ => None,
        }
    }

    /// Whether this is the terminal [`Failed`](Self::Failed) state (no event transitions out of it).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Whether this readiness satisfies a **consume-with-wait** (§7.13.4a): the broker hands a
    /// connector over **only** when the resolved provider is [`Ready`](Self::Ready).
    ///
    /// This is the cycle-safety pivot of the `SVC_CONNECT` wire contract. A
    /// [`Pending`](Self::Pending) provider — *including one blocked on its own consume* — does not
    /// serve a waiter, so a mutual consume (sidecar A consumes B, B consumes A) cannot bootstrap
    /// itself: each waiter blocks on the other's never-arriving [`Ready`](Self::Ready), both hit the
    /// consume-with-wait deadline, and both land [`Failed`](Self::Failed) — a loud, observable
    /// double-timeout rather than a deadlock. A [`Failed`](Self::Failed) provider never serves (its
    /// consume is denied-and-audited as `UNAVAILABLE`, distinct from an unresolved name).
    #[must_use]
    pub const fn serves(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_becomes_ready_on_construction_success() {
        assert_eq!(
            Readiness::Pending.on(Event::ConstructionSucceeded),
            Some(Readiness::Ready)
        );
    }

    #[test]
    fn pending_becomes_failed_on_construction_failure_or_crash_loop() {
        assert_eq!(
            Readiness::Pending.on(Event::ConstructionFailed),
            Some(Readiness::Failed)
        );
        assert_eq!(
            Readiness::Pending.on(Event::CrashLoopExhausted),
            Some(Readiness::Failed)
        );
    }

    #[test]
    fn ready_returns_to_pending_on_restart_or_idle_reap() {
        assert_eq!(
            Readiness::Ready.on(Event::Restarting),
            Some(Readiness::Pending)
        );
        assert_eq!(
            Readiness::Ready.on(Event::IdleReaped),
            Some(Readiness::Pending)
        );
    }

    #[test]
    fn ready_becomes_failed_on_crash_loop_exhaustion() {
        assert_eq!(
            Readiness::Ready.on(Event::CrashLoopExhausted),
            Some(Readiness::Failed)
        );
    }

    #[test]
    fn failed_is_terminal_for_every_event() {
        let every = [
            Event::ConstructionSucceeded,
            Event::ConstructionFailed,
            Event::Restarting,
            Event::IdleReaped,
            Event::CrashLoopExhausted,
        ];
        for e in every {
            assert_eq!(
                Readiness::Failed.on(e),
                None,
                "no event leaves Failed: {e:?}"
            );
        }
        assert!(Readiness::Failed.is_terminal());
        assert!(!Readiness::Pending.is_terminal());
        assert!(!Readiness::Ready.is_terminal());
    }

    #[test]
    fn only_ready_serves_a_consume_with_wait() {
        // The cycle-safety pivot (§7.13.4a): a connector is brokered only to a Ready provider, so a
        // provider blocked on its own consume (Pending) cannot satisfy a waiter, and a Failed one
        // never does.
        assert!(Readiness::Ready.serves());
        assert!(!Readiness::Pending.serves());
        assert!(!Readiness::Failed.serves());
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        // A construction-success event is meaningless once already ready or constructing-failed.
        assert_eq!(Readiness::Ready.on(Event::ConstructionSucceeded), None);
        // A pending provider is not yet running, so it cannot be "restarting" or "idle-reaped".
        assert_eq!(Readiness::Pending.on(Event::Restarting), None);
        assert_eq!(Readiness::Pending.on(Event::IdleReaped), None);
        // A ready provider did not just fail *construction* — that event belongs to pending.
        assert_eq!(Readiness::Ready.on(Event::ConstructionFailed), None);
    }
}
