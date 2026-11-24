//! The per-session channel between a consumer's `facade-tun` and its `tun-flow` mediator.

use std::io;
use std::os::unix::net::UnixDatagram;

/// Mint one session's connected socket pair: `(mediator end, consumer end)`.
///
/// # Errors
///
/// The OS error if `socketpair(2)` fails.
pub fn channel() -> io::Result<(UnixDatagram, UnixDatagram)> {
    UnixDatagram::pair()
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
}
