//! A non-blocking sink wrapper that bounds how long emitting can stall the writer.
//!
//! `02-3` requires each sink not to block the writer past a configured
//! timeout". [`TimeoutSink`] realises that by handing each event to a dedicated
//! worker thread over a *bounded* channel: the writer's `write` is a non-blocking
//! channel hand-off, and the worker performs the possibly-blocking I/O. If the
//! worker falls behind (a wedged syslogd, journald under pressure) the buffer
//! fills and further events are dropped — the back-pressure equivalent of the
//! timeout — with `write` returning an error the writer reports to the other
//! sinks. On drop the channel closes and the worker is joined, so buffered events
//! (e.g. `lifecycle.kennel-exit`) flush before teardown.

use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Mutex;
use std::thread::JoinHandle;

use crate::render::Record;
use crate::writer::{Sink, SinkError};

/// Default number of events buffered per sink before new events are dropped.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Wraps a [`Sink`] so emitting never blocks the writer on the sink's I/O.
pub struct TimeoutSink {
    name: &'static str,
    tx: Mutex<Option<SyncSender<Record>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl TimeoutSink {
    /// Wrap `inner` with the default buffer capacity.
    #[must_use]
    pub fn new(inner: Box<dyn Sink>) -> Self {
        Self::with_capacity(inner, DEFAULT_CAPACITY)
    }

    /// Wrap `inner` with an explicit buffer capacity (at least 1).
    #[must_use]
    pub fn with_capacity(inner: Box<dyn Sink>, capacity: usize) -> Self {
        let name = inner.name();
        let (tx, rx) = sync_channel::<Record>(capacity.max(1));
        let worker = std::thread::spawn(move || {
            // The worker owns `inner` and performs the blocking write. The inner
            // error is swallowed here (off the writer's thread); the reported
            // failure mode is the drop-on-full in `write` below.
            for record in rx {
                let _ = inner.write(&record);
            }
        });
        Self {
            name,
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
        }
    }

    fn err(&self, message: &str) -> SinkError {
        SinkError {
            sink: self.name,
            message: message.to_owned(),
        }
    }
}

impl Sink for TimeoutSink {
    fn name(&self) -> &'static str {
        self.name
    }

    fn write(&self, record: &Record) -> Result<(), SinkError> {
        // Clone the sender out under the lock, then release it before sending so
        // the brief critical section is just the clone (a cheap Arc bump).
        let tx = {
            let guard = self.tx.lock().map_err(|_| self.err("sender poisoned"))?;
            match guard.as_ref() {
                Some(tx) => tx.clone(),
                None => return Err(self.err("sink closed")),
            }
        };
        match tx.try_send(record.clone()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(self.err("buffer full; event dropped")),
            Err(TrySendError::Disconnected(_)) => Err(self.err("worker gone")),
        }
    }
}

impl Drop for TimeoutSink {
    fn drop(&mut self) {
        // Drop the sender first so the worker's loop ends, then join so any
        // buffered events are written before we return.
        if let Ok(mut guard) = self.tx.lock() {
            guard.take();
        }
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Outcome, Resource};
    use crate::render::Rendered;
    use std::sync::Arc;

    #[derive(Default)]
    struct CaptureSink {
        count: Mutex<usize>,
    }
    impl CaptureSink {
        fn count(&self) -> usize {
            self.count.lock().map_or(0, |c| *c)
        }
    }
    impl Sink for CaptureSink {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, _record: &Record) -> Result<(), SinkError> {
            if let Ok(mut c) = self.count.lock() {
                *c = c.saturating_add(1);
            }
            Ok(())
        }
    }

    // Forwards to a shared CaptureSink so the test keeps a handle.
    struct Shared(Arc<CaptureSink>);
    impl Sink for Shared {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn write(&self, record: &Record) -> Result<(), SinkError> {
            self.0.write(record)
        }
    }

    fn rec() -> Record {
        Record {
            resource: Resource::Lifecycle,
            event_type: "lifecycle.kennel-start",
            outcome: Outcome::Info,
            fields: vec![("schema_version", Rendered::Uint(1))],
        }
    }

    #[test]
    fn name_delegates_to_inner() {
        let cap = Arc::new(CaptureSink::default());
        let sink = TimeoutSink::new(Box::new(Shared(cap)));
        assert_eq!(sink.name(), "capture");
    }

    #[test]
    fn flushes_all_buffered_events_on_drop() {
        let cap = Arc::new(CaptureSink::default());
        let sink = TimeoutSink::new(Box::new(Shared(Arc::clone(&cap))));
        for _ in 0..5 {
            sink.write(&rec()).expect("enqueue");
        }
        drop(sink); // joins the worker → everything written
        assert_eq!(cap.count(), 5);
    }

    // A sink whose write blocks until the test releases a mutex.
    struct Blocking(Arc<Mutex<()>>);
    impl Sink for Blocking {
        fn name(&self) -> &'static str {
            "blocking"
        }
        fn write(&self, _record: &Record) -> Result<(), SinkError> {
            // Block until the test releases the gate, then return.
            if let Ok(guard) = self.0.lock() {
                drop(guard);
            }
            Ok(())
        }
    }

    #[test]
    fn drops_when_the_worker_is_blocked_and_the_buffer_fills() {
        let gate = Arc::new(Mutex::new(()));
        let guard = gate.lock().expect("lock gate"); // worker will block on this
        let sink = TimeoutSink::with_capacity(Box::new(Blocking(Arc::clone(&gate))), 1);
        // The worker dequeues the first record and blocks; the bounded buffer
        // then fills and a subsequent enqueue must fail.
        let mut saw_drop = false;
        for _ in 0..50 {
            if sink.write(&rec()).is_err() {
                saw_drop = true;
                break;
            }
        }
        assert!(saw_drop, "a full buffer behind a blocked worker must drop");
        drop(guard); // release the worker so drop()'s join completes
        drop(sink);
    }
}
