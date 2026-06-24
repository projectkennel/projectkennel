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

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use kennel_lib_control::readiness::Event;
use kennel_lib_policy::settled::{RestartPolicy, ServiceRuntime};

use crate::catalogue::EnabledProvider;
use crate::control::{recv_response, Response, StartRequest};
use crate::server::{run_kennel, PolicyLoader, Shared};
use crate::Privileged;

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

/// Autostart the enabled `autorun` providers (§7.13.6): each runs in its own supervision thread,
/// constructed at daemon start and kept up per its signed `[service]` discipline.
///
/// Lifecycle-coupled to the daemon, not to any consumer (the `ondemand` set is socket-activated by the
/// broker instead). Each thread drives that provider's catalogue readiness — `Ready` once constructed,
/// `Pending` while restarting, `Failed` on crash-loop exhaustion.
pub fn autostart<P, L>(shared: &Arc<Shared<P, L>>)
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    for prov in shared.autorun_providers() {
        let shared = Arc::clone(shared);
        std::thread::spawn(move || supervise_provider(&shared, prov));
    }
}

/// Socket-activate a lazy (`ondemand`) provider on first consume (§7.13.6).
///
/// Starts the provider's supervision so it comes up, then is supervised exactly like an eager one.
/// Type-erased so the binder broker (which erases the daemon's `P`/`L`) can hold it — the same move as
/// the spawn `Constructor`.
pub trait ProviderActivator: Send + Sync {
    /// Bring `provider` up if it is an enabled `ondemand` provider not already activated — idempotent,
    /// so repeated consumes do not double-start it. A no-op for an unknown or already-running provider.
    fn activate(&self, provider: &str);

    /// Whether any running kennel's settled `[[consumes]]` names one of `capabilities` — the W6
    /// idle-reap keep-alive (§7.13.6): the TTL handler reaps an ondemand provider only when this
    /// returns `false`.
    fn has_running_consumer(&self, capabilities: &[String]) -> bool;

    /// Mark `provider` idle-reaped (§7.13.6) — the TTL handler calls this just before killing the
    /// cgroup, so the supervisor reads the kill as a reap (→ declared-but-pending, re-activatable) and
    /// the next consume can socket-activate it afresh.
    fn mark_idle_reaped(&self, provider: &str);
}

/// The daemon-backed [`ProviderActivator`]: starts a provider's supervision thread, deduped.
pub struct Activator<P: Privileged, L: PolicyLoader> {
    shared: Arc<Shared<P, L>>,
    started: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl<P: Privileged, L: PolicyLoader> Activator<P, L> {
    /// An activator bound to the daemon state.
    #[must_use]
    pub const fn new(shared: Arc<Shared<P, L>>) -> Self {
        Self {
            shared,
            started: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<P, L> ProviderActivator for Activator<P, L>
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    fn activate(&self, provider: &str) {
        // Dedup: start each provider's supervision at most once for the daemon's life (the
        // consume-with-wait poll handles the window between activation and ready).
        {
            let mut started = self
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !started.insert(provider.to_owned()) {
                return;
            }
        }
        // Only an enabled `ondemand` provider is socket-activated; an `autorun` one is already being
        // brought up by `autostart`, and an unknown name resolves to nothing.
        if let Some(prov) = self.shared.ondemand_provider(provider) {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || supervise_provider(&shared, prov));
        }
    }

    fn has_running_consumer(&self, capabilities: &[String]) -> bool {
        self.shared.any_running_consumer(capabilities)
    }

    fn mark_idle_reaped(&self, provider: &str) {
        // Record the reap for the supervisor (which reads it when the killed provider exits), and clear
        // the activation dedup so the next consume re-activates this provider from cold.
        self.shared.mark_idle_reaped(provider);
        self.started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(provider);
    }
}

/// Run and supervise one provider for the daemon's life: construct it, drive its readiness, and
/// restart it per its `[service]` discipline ([`on_exit`]) until the discipline gives up or it is done.
fn supervise_provider<P, L>(shared: &Arc<Shared<P, L>>, prov: EnabledProvider)
where
    P: Privileged + Clone + Send + Sync + 'static,
    L: PolicyLoader + Send + Sync + 'static,
{
    let id = prov.provider;
    let tier = prov.tier;
    let mut restarts: u32 = 0;
    loop {
        // Construct the provider on a sub-thread — `run_kennel` blocks until the provider exits, like
        // a `kennel run`, with its status responses going to a throwaway sink (no operator socket).
        let req = StartRequest {
            policy: prov.policy_path.clone(),
            kennel: id.clone(),
            argv: Vec::new(),
            cwd: std::path::PathBuf::from("/"),
            term: String::new(),
            interactive: false,
            force: false,
            watch_paths: Vec::new(),
            oci_config: None,
        };
        let Ok((mut client, mut sink)) = UnixStream::pair() else {
            eprintln!("kenneld: supervisor: `{id}`: could not make a construction sink");
            return;
        };
        let run_shared = Arc::clone(shared);
        let run = std::thread::spawn(move || {
            run_kennel(
                &run_shared,
                &req,
                Vec::new(),
                &mut sink,
                None,
                &crate::spawn::noop_constructor(),
                None,
                Some(tier),
            );
        });
        // Read the construction outcome from the sink to drive readiness: `Started` → ready, then park
        // until the provider exits (`Exited`) or construction fails.
        let mut clean = false;
        loop {
            match recv_response(&mut client) {
                Ok(Response::Started { .. }) => {
                    shared.note_provider_ready(&id);
                }
                Ok(Response::Exited { code }) => {
                    clean = code == 0;
                    break;
                }
                Ok(Response::Error(msg)) => {
                    eprintln!("kenneld: supervisor: `{id}` construction failed: {msg}");
                    break;
                }
                Ok(_) => {}      // other responses are irrelevant to a headless provider
                Err(_) => break, // the sink closed when run_kennel returned
            }
        }
        let _ = run.join();
        // An idle reap (§7.13.6) is not a crash: the TTL custodian killed the cgroup because no consumer
        // kennel runs. Return the provider to declared-but-pending and stop supervising — the next consume
        // re-activates it from cold — rather than feeding the kill through the `[service]` restart discipline.
        if shared.take_idle_reaped(&id) {
            shared.note_provider_event(&id, Event::IdleReaped);
            return;
        }
        match on_exit(&prov.service, clean, restarts) {
            RestartAction::RestartAfter(delay) => {
                shared.note_provider_event(&id, Event::Restarting);
                std::thread::sleep(delay);
                restarts = restarts.saturating_add(1);
            }
            RestartAction::Fail => {
                eprintln!("kenneld: supervisor: `{id}` declared-but-failed (crash-loop / never)");
                shared.note_provider_event(&id, Event::CrashLoopExhausted);
                return;
            }
            RestartAction::Done => {
                shared.note_provider_event(&id, Event::IdleReaped);
                return;
            }
        }
    }
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
