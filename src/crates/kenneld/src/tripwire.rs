//! The live workspace-trigger tripwire (§2.5, T2.8).
//!
//! While a kennel runs, `kenneld` watches each writable bind's pinned triggers and trigger
//! directories on the host — in the operator's own context, **unprivileged**, notify-only via
//! [`kennel_lib_syscall::inotify`]. A write to one is the workload's (the start surface was
//! verified clean, §4.5), so `kenneld` records an `fs.mutation` and applies the
//! `[trust].on_change` disposition through the cgroup it already owns: `warn` (audit only),
//! `freeze` (suspend the workload for the operator), or `kill` (terminate it).
//!
//! The watch is **best-effort** — inotify can miss a delete-and-recreate or overflow, and a
//! newly-created top-level trigger is not watched until the next run. The authoritative
//! backstop is the host-side teardown review (`kennel review`), which re-scans the full
//! catalogue. So a missed event is still caught at the door; the tripwire's job is the *live*
//! reaction (freeze/kill) the teardown cannot give.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use kennel_lib_audit::Writer;
use kennel_lib_policy::OnChangeAction;
use kennel_lib_syscall::inotify::Watcher;

use crate::audit::fs_mutation;

/// How often the watcher thread drains queued events and re-checks its stop flag. The
/// tripwire is best-effort, so a sub-second cadence is ample; it keeps the thread idle.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// A running tripwire: the watcher thread plus its stop flag.
pub struct Tripwire {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Tripwire {
    /// Start watching `paths` (host file/dir paths) for mutations, applying `action` to
    /// `cgroup` and auditing through `writer`.
    ///
    /// Returns `None` — no tripwire — when there is nothing to watch or inotify is
    /// unavailable; the teardown review remains the authoritative backstop, so a `None` here
    /// is a quiet degradation, never a failure.
    #[must_use]
    pub fn start(
        paths: &[PathBuf],
        action: OnChangeAction,
        cgroup: PathBuf,
        writer: Arc<Writer>,
    ) -> Option<Self> {
        if paths.is_empty() {
            return None;
        }
        let watcher = Watcher::new().ok()?;
        let mut added = 0usize;
        for path in paths {
            // A path that cannot be watched (absent, racing teardown) is skipped — the watch
            // set is best-effort.
            if watcher.add(path).is_ok() {
                added = added.saturating_add(1);
            }
        }
        if added == 0 {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            watch_loop(&watcher, action, &cgroup, &writer, &stop_thread);
        });
        Some(Self {
            stop,
            handle: Some(handle),
        })
    }

    /// Stop the watcher thread and join it (best-effort). Called at workload exit.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Drain events on a timer until stopped, applying the disposition to each mutation.
fn watch_loop(
    watcher: &Watcher,
    action: OnChangeAction,
    cgroup: &Path,
    writer: &Writer,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Acquire) {
        let Ok(events) = watcher.read() else {
            return; // the inotify fd errored — give up (teardown still covers it)
        };
        for event in events {
            let path = event.name.unwrap_or_default();
            let enforced = apply(action, cgroup);
            writer.emit(&fs_mutation(&path, action_name(action), enforced));
            // After a kill the cgroup is gone; nothing left to watch.
            if matches!(action, OnChangeAction::Kill) {
                return;
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Apply the disposition to the cgroup. Returns whether the workload was acted on (an
/// enforcement, for the audit outcome) — `warn` is audit-only, `freeze`/`kill` enforce.
fn apply(action: OnChangeAction, cgroup: &Path) -> bool {
    match action {
        OnChangeAction::Warn => false,
        OnChangeAction::Freeze => {
            let _ = crate::cgroup::freeze_cgroup(cgroup);
            true
        }
        OnChangeAction::Kill => {
            let _ = crate::cgroup::kill_cgroup(cgroup);
            true
        }
    }
}

const fn action_name(action: OnChangeAction) -> &'static str {
    match action {
        OnChangeAction::Warn => "warn",
        OnChangeAction::Freeze => "freeze",
        OnChangeAction::Kill => "kill",
    }
}
