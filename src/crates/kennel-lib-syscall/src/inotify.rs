//! A minimal `inotify` wrapper for the workspace-trigger tripwire (§2.5, T2.8).
//!
//! `kenneld` watches each writable bind's pinned triggers (and trigger directories) on the
//! host, in the operator's own context — **unprivileged**, notify-only. A write to one
//! during the run is the workload's, and `kenneld` acts on it via the cgroup it already owns.
//! This is the in-model alternative to a standing privileged `fanotify` watcher: it observes
//! and reacts, it does not pre-block.
//!
//! The instance is non-blocking; the caller polls [`Watcher::read`] on its own cadence and
//! checks its stop flag between drains, so no fd-close race is needed to shut it down.

use std::io;
use std::path::Path;

use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};

/// One observed mutation. `name` is the affected entry for a directory watch (a freshly
/// planted `.git/hooks/post-commit`), or `None` for an event on a watched file itself.
#[derive(Debug, Clone)]
pub struct Event {
    /// The entry name within a watched directory, if any.
    pub name: Option<String>,
}

/// An `inotify` instance watching a fixed set of paths for content mutation.
pub struct Watcher {
    inner: Inotify,
}

/// The events that count as a trigger mutation, for both file and directory watches: content
/// writes, metadata/mode changes, and creation / move / deletion of a watched entry.
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_MODIFY
        | AddWatchFlags::IN_ATTRIB
        | AddWatchFlags::IN_CLOSE_WRITE
        | AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVE_SELF
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_DELETE_SELF
}

fn into_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

impl Watcher {
    /// Create a non-blocking, close-on-exec inotify instance.
    ///
    /// # Errors
    /// The OS error if `inotify_init1` fails.
    pub fn new() -> io::Result<Self> {
        let inner =
            Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).map_err(into_io)?;
        Ok(Self { inner })
    }

    /// Add `path` to the watch set (a file or a directory). A path that cannot be watched
    /// (e.g. it does not exist) returns an error the caller may ignore — the watch set is
    /// best-effort.
    ///
    /// # Errors
    /// The OS error if `inotify_add_watch` fails.
    pub fn add(&self, path: &Path) -> io::Result<()> {
        self.inner
            .add_watch(path, watch_mask())
            .map(|_| ())
            .map_err(into_io)
    }

    /// Drain the queued events. Returns `Ok(empty)` when none are pending (non-blocking), so
    /// the caller can poll on a timer and check its stop flag between drains.
    ///
    /// # Errors
    /// The OS error if the read fails for a reason other than "no events pending".
    pub fn read(&self) -> io::Result<Vec<Event>> {
        match self.inner.read_events() {
            Ok(events) => Ok(events
                .into_iter()
                .map(|e| Event {
                    name: e.name.and_then(|n| n.into_string().ok()),
                })
                .collect()),
            Err(nix::errno::Errno::EAGAIN) => Ok(Vec::new()),
            Err(e) => Err(into_io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_planted_file_in_a_watched_directory() {
        let dir = std::env::temp_dir().join(format!("kennel-inotify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let watcher = Watcher::new().expect("init");
        watcher.add(&dir).expect("add watch");
        // Plant a hook-like file; the non-blocking watcher should surface it within a few polls.
        std::fs::write(dir.join("post-commit"), b"#!/bin/sh\n").expect("plant");
        let mut names = Vec::new();
        for _ in 0..100 {
            for ev in watcher.read().expect("read") {
                if let Some(name) = ev.name {
                    names.push(name);
                }
            }
            if names.iter().any(|n| n == "post-commit") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            names.iter().any(|n| n == "post-commit"),
            "the planted file should be observed; saw {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
