//! The sidecar supervisor's restart decision (`07-13-service-catalog.md` §7.13.7): what to do when a
//! supervised provider exits.
//!
//! This is the pure decision the runtime supervisor applies on each provider exit — it *executes* the
//! signed `[service]` discipline, never invents one (the policy is the author's, §7.13.7). It pairs
//! with the W2 readiness machine ([`kennel_lib_control::readiness`]): the [`RestartAction`] this
//! returns drives the catalogue's per-provider readiness — a restart is a `Ready → Pending`
//! transition, a give-up is the `CrashLoopExhausted → Failed` one.
//!
//! The three `restart` disciplines (§7.13.7):
//! - **`always`** — restart on any exit (a long-running service expected to stay up); a clean exit is
//!   still a restart.
//! - **`on-failure`** (default) — restart only on a non-zero exit or signal; a clean exit is *done*.
//! - **`never`** — run once; a clean exit is done, a non-zero exit is failed.
//!
//! A wanted restart happens only while attempts remain within `max_attempts`; exhausting them drives
//! the provider **declared-but-failed**. Backoff doubles each attempt (to a cap) so a provider that
//! crashes on start does not spin the supervisor.

use std::time::Duration;

use kennel_lib_policy::settled::{RestartPolicy, ServiceRuntime};

/// The cap on a restart backoff, however many attempts have doubled it (§7.13.7, "to a cap").
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// What the supervisor does on a provider exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartAction {
    /// Restart after this backoff — still within the crash-loop budget (readiness `Ready → Pending`).
    RestartAfter(Duration),
    /// A clean exit the policy does not restart (`on-failure`/`never` succeeding) — *done*, not a
    /// failure; the provider stays down without being marked declared-but-failed.
    Done,
    /// Give up: the policy forbids a restart on this exit, or the crash-loop budget is exhausted →
    /// declared-but-failed (readiness → `Failed`).
    Fail,
}

/// Decide what to do when a supervised provider exits.
///
/// `clean_exit` is true for a zero exit code and no terminating signal. `restarts_so_far` is how many
/// times this provider has already been restarted within the current crash-loop window (0 on the
/// first exit); the next restart is permitted only while it is below `max_attempts`.
#[must_use]
pub fn on_exit(service: &ServiceRuntime, clean_exit: bool, restarts_so_far: u32) -> RestartAction {
    let wants_restart = match service.restart {
        RestartPolicy::Always => true,
        RestartPolicy::OnFailure => !clean_exit,
        RestartPolicy::Never => false,
    };
    if !wants_restart {
        // Not restarting: a clean exit is *done*; a non-restartable failure is declared-but-failed.
        return if clean_exit {
            RestartAction::Done
        } else {
            RestartAction::Fail
        };
    }
    if restarts_so_far >= service.max_attempts {
        return RestartAction::Fail; // crash-loop budget exhausted
    }
    RestartAction::RestartAfter(backoff(service.backoff_ms, restarts_so_far))
}

/// The backoff before the `restarts_so_far`-th restart: the initial delay doubled once per prior
/// attempt, capped at [`BACKOFF_CAP`]. Saturating, so a huge initial or attempt count cannot overflow.
fn backoff(initial_ms: u64, restarts_so_far: u32) -> Duration {
    let doubled = initial_ms.saturating_mul(1u64.checked_shl(restarts_so_far).unwrap_or(u64::MAX));
    Duration::from_millis(doubled).min(BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(restart: RestartPolicy, backoff_ms: u64, max_attempts: u32) -> ServiceRuntime {
        ServiceRuntime {
            restart,
            backoff_ms,
            max_attempts,
        }
    }

    #[test]
    fn always_restarts_any_exit_within_budget() {
        let s = service(RestartPolicy::Always, 500, 3);
        // Clean exit still restarts (a long-running service is expected to stay up).
        assert_eq!(
            on_exit(&s, true, 0),
            RestartAction::RestartAfter(Duration::from_millis(500))
        );
        assert_eq!(
            on_exit(&s, false, 1),
            RestartAction::RestartAfter(Duration::from_secs(1))
        );
        // Budget exhausted → declared-but-failed.
        assert_eq!(on_exit(&s, false, 3), RestartAction::Fail);
    }

    #[test]
    fn on_failure_restarts_a_crash_but_is_done_on_a_clean_exit() {
        let s = service(RestartPolicy::OnFailure, 500, 5);
        assert_eq!(on_exit(&s, true, 0), RestartAction::Done); // succeeded
        assert_eq!(
            on_exit(&s, false, 0),
            RestartAction::RestartAfter(Duration::from_millis(500))
        );
        assert_eq!(on_exit(&s, false, 5), RestartAction::Fail); // exhausted
    }

    #[test]
    fn never_is_done_on_clean_and_failed_on_a_crash() {
        let s = service(RestartPolicy::Never, 500, 5);
        assert_eq!(on_exit(&s, true, 0), RestartAction::Done);
        assert_eq!(on_exit(&s, false, 0), RestartAction::Fail);
    }

    #[test]
    fn backoff_doubles_each_attempt_and_caps() {
        let s = service(RestartPolicy::Always, 1000, 100);
        assert_eq!(
            on_exit(&s, false, 0),
            RestartAction::RestartAfter(Duration::from_secs(1))
        );
        assert_eq!(
            on_exit(&s, false, 1),
            RestartAction::RestartAfter(Duration::from_secs(2))
        );
        assert_eq!(
            on_exit(&s, false, 2),
            RestartAction::RestartAfter(Duration::from_secs(4))
        );
        // Far enough out, the doubling saturates against the cap rather than overflowing.
        assert_eq!(
            on_exit(&s, false, 64),
            RestartAction::RestartAfter(BACKOFF_CAP)
        );
        assert_eq!(
            on_exit(&s, false, 99),
            RestartAction::RestartAfter(BACKOFF_CAP)
        );
    }
}
