//! The per-session channel between a consumer's `facade-tun` and its `tun-flow` mediator, and the
//! broker's count of live sessions.
//!
//! The channel is a `SOCK_SEQPACKET` pair: it keeps frame boundaries as a datagram socket does, and
//! unlike a connected `SOCK_DGRAM` pair it tells each end when the other closed (a hang-up, and a
//! zero-length read). That signal is what ends a mediator whose consumer is gone.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex, PoisonError};

/// Live sessions one consuming kennel may hold. Its `facade-tun` needs one; the second covers a
/// restarted facade overlapping the session it replaces.
pub const MAX_SESSIONS_PER_KENNEL: usize = 2;

/// Live sessions across every consumer: the bound on mediator processes under one broker.
pub const MAX_SESSIONS: usize = 256;

/// Mint one session's connected socket pair: `(mediator end, consumer end)`.
///
/// Both ends are typed [`UnixDatagram`] for its `send`/`recv`, which are the plain `send(2)` and
/// `recv(2)` a `SOCK_SEQPACKET` socket takes.
///
/// # Errors
///
/// The OS error if `socketpair(2)` fails.
pub fn channel() -> io::Result<(UnixDatagram, UnixDatagram)> {
    let (mediator, consumer) = kennel_lib_scm::seqpacket_pair()?;
    Ok((UnixDatagram::from(mediator), UnixDatagram::from(consumer)))
}

/// How many sessions are live, in total and for each consuming kennel.
#[derive(Default)]
struct Counts {
    total: usize,
    by_kennel: HashMap<[u8; 16], usize>,
}

/// The broker's ledger of live sessions, with a ceiling for each kennel and one overall.
///
/// Any process in a `[net.udp]` kennel can ask for a session, and each one costs the broker a
/// mediator process with its own flow table and rate bucket. Without a ceiling one kennel multiplies
/// its per-session limits by opening more sessions.
#[derive(Clone)]
pub struct Sessions {
    counts: Arc<Mutex<Counts>>,
    per_kennel: usize,
    total: usize,
}

/// One live session's place in the ledger; dropping it gives the place back.
pub struct Slot {
    counts: Arc<Mutex<Counts>>,
    kennel: [u8; 16],
}

impl Sessions {
    /// A ledger admitting at most `per_kennel` live sessions for one kennel and `total` overall.
    #[must_use]
    pub fn new(per_kennel: usize, total: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(Counts::default())),
            per_kennel,
            total,
        }
    }

    /// Take a place for a session of the kennel whose tun address is `kennel`, or `None` when that
    /// kennel or the broker is at its ceiling. kenneld writes the address into the session payload,
    /// so a consumer cannot choose it.
    #[must_use]
    pub fn open(&self, kennel: [u8; 16]) -> Option<Slot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let held = counts.by_kennel.get(&kennel).copied().unwrap_or(0);
        if counts.total >= self.total || held >= self.per_kennel {
            return None;
        }
        counts.total = counts.total.saturating_add(1);
        counts.by_kennel.insert(kennel, held.saturating_add(1));
        drop(counts);
        Some(Slot {
            counts: Arc::clone(&self.counts),
            kennel,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        match counts.by_kennel.get(&self.kennel).copied() {
            Some(held) if held > 1 => {
                counts.by_kennel.insert(self.kennel, held.saturating_sub(1));
            }
            _ => {
                counts.by_kennel.remove(&self.kennel);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::Poller;
    use std::time::Duration;

    #[test]
    fn the_mediator_end_learns_that_the_consumer_end_closed() {
        // A mediator that is never told its consumer went away lives for ever, with its flows.
        let (mediator, consumer) = channel().expect("pair");
        let mut poller = Poller::new(2).expect("poller");
        poller.add(&mediator, 7).expect("add");
        drop(consumer);
        let ready = poller.wait(Some(Duration::from_millis(500))).expect("wait");
        assert!(
            ready.iter().any(|r| r.token == 7 && r.hangup),
            "closing the consumer end must hang up the mediator end, got {ready:?}"
        );
    }

    #[test]
    fn the_channel_keeps_frame_boundaries() {
        let (mediator, consumer) = channel().expect("pair");
        consumer.send(b"one").expect("send");
        consumer.send(b"three").expect("send");
        let mut buf = [0u8; 16];
        assert_eq!(mediator.recv(&mut buf).expect("recv"), 3);
        assert_eq!(mediator.recv(&mut buf).expect("recv"), 5);
    }

    #[test]
    fn a_kennel_is_held_to_its_own_ceiling() {
        let sessions = Sessions::new(2, 8);
        let first = sessions.open([1; 16]).expect("first");
        let _second = sessions.open([1; 16]).expect("second");
        assert!(sessions.open([1; 16]).is_none(), "a third is refused");
        assert!(sessions.open([2; 16]).is_some(), "another kennel is not");
        drop(first);
        assert!(
            sessions.open([1; 16]).is_some(),
            "an ended session frees its place"
        );
    }

    #[test]
    fn the_broker_is_held_to_its_overall_ceiling() {
        let sessions = Sessions::new(2, 2);
        let _a = sessions.open([1; 16]).expect("a");
        let b = sessions.open([2; 16]).expect("b");
        assert!(sessions.open([3; 16]).is_none(), "the broker is full");
        drop(b);
        assert!(sessions.open([3; 16]).is_some());
    }
}
