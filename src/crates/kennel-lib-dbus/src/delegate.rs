//! The delegate's mediation core (§7.7.2b), I/O-free so it is unit-testable like the facade
//! engine: `host-dbus` wraps it with the real bus connection and the conduit poll loop.
//!
//! It holds the compiled [`crate::filter::Filter`] and the serial map. A typed
//! [`crate::wire::Call`] off the conduit is filtered ([`Delegate::on_conduit_call`]); a pass is
//! reconstructed with a fresh **bus** serial and the `kennel_serial ↔ bus_serial` pairing is
//! recorded so the reply can be matched back (the kennel's and the bus's serials are different
//! namespaces, §7.7.2b); a fail is refused straight back to the facade as `AccessDenied`,
//! never touching the bus. Bus replies ([`Delegate::on_bus_reply`]) are demultiplexed by the
//! recorded serial; bus signals ([`Delegate::on_bus_signal`]) pass the match-rule allowlist
//! before forwarding (§7.7.4) — outbound and inbound are different paths, and only the outbound
//! call is reconstructed and sent to the bus.

use std::collections::HashMap;

use crate::filter::{pattern_admits, BusRules, Filter};
use crate::message::{self, MessageError};
use crate::wire::{Bus, Call, ErrorReply, Frame, Reply, Signal};

/// The D-Bus error a denied call returns to the workload.
const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";

/// What the delegate wants done with a conduit call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Reconstructed message bytes to send on the bus (the call passed the filter).
    ToBus(Vec<u8>),
    /// A frame to return to the facade without touching the bus (a deny `AccessDenied`).
    ToConduit(Frame),
}

/// One in-flight call awaiting its bus reply.
#[derive(Debug, Clone, Copy)]
struct Pending {
    /// The kennel-side serial to put in the reply frame's `reply_serial`.
    kennel_serial: u32,
}

/// The I/O-free mediation state for one delegate ↔ conduit pairing.
pub struct Delegate {
    filter: Filter,
    pending: HashMap<u32, Pending>,
    next_bus_serial: u32,
}

impl Delegate {
    /// A fresh delegate applying `filter`. Bus serials start at 2 — the host-dbus bin sends its
    /// own `Hello` as serial 1 when it connects, so the mediated calls start after it.
    #[must_use]
    pub fn new(filter: Filter) -> Self {
        Self {
            filter,
            pending: HashMap::new(),
            next_bus_serial: 2,
        }
    }

    /// Filter a call off the conduit. A pass is reconstructed for the bus (and recorded for the
    /// reply); a fail returns an `AccessDenied` error frame to the facade.
    ///
    /// # Errors
    ///
    /// [`MessageError`] if an approved call cannot be reconstructed (e.g. a big-endian body).
    pub fn on_conduit_call(&mut self, call: &Call) -> Result<Outbound, MessageError> {
        match self.filter.decide(call) {
            crate::filter::Decision::Deny(reason) => Ok(Outbound::ToConduit(Frame::Error(
                ErrorReply {
                    reply_serial: call.serial,
                    name: ACCESS_DENIED.to_owned(),
                    message: reason,
                },
            ))),
            crate::filter::Decision::Allow => {
                let bus_serial = self.take_bus_serial();
                let bytes = message::reconstruct_call(call, bus_serial)?;
                self.pending.insert(
                    bus_serial,
                    Pending {
                        kennel_serial: call.serial,
                    },
                );
                Ok(Outbound::ToBus(bytes))
            }
        }
    }

    /// Demultiplex a bus reply by its `reply_serial`. Returns the frame to send back to the
    /// facade, or `None` if the reply matches no in-flight mediated call (e.g. the delegate's
    /// own `Hello` reply, which the bin handles, or a stray reply).
    #[must_use]
    pub fn on_bus_reply(&mut self, reply: BusReply<'_>) -> Option<Frame> {
        let pending = self.pending.remove(&reply.reply_serial)?;
        let frame = reply.error_name.map_or_else(
            || {
                Frame::Reply(Reply {
                    reply_serial: pending.kennel_serial,
                    signature: reply.signature.to_owned(),
                    body_endian: reply.body_endian,
                    body: reply.body.to_vec(),
                })
            },
            |name| {
                Frame::Error(ErrorReply {
                    reply_serial: pending.kennel_serial,
                    name: name.to_owned(),
                    message: reply.error_message.unwrap_or_default().to_owned(),
                })
            },
        );
        Some(frame)
    }

    /// Filter a bus signal through the match-rule allowlist (§7.7.4) and, on a pass, build the
    /// `Signal` frame to forward. `None` drops it — a signal from a service the kennel may not
    /// receive is never delivered (this is what stops passive session monitoring).
    #[must_use]
    pub fn on_bus_signal(&self, sig: BusSignal<'_>) -> Option<Frame> {
        let rules = match sig.bus {
            Bus::Session => self.filter.session.as_ref()?,
            Bus::System => self.filter.system.as_ref()?,
        };
        if !signal_allowed(rules, sig.interface) {
            return None;
        }
        Some(Frame::Signal(Signal {
            bus: sig.bus,
            path: sig.path.to_owned(),
            interface: sig.interface.to_owned(),
            member: sig.member.to_owned(),
            signature: sig.signature.to_owned(),
            body_endian: sig.body_endian,
            body: sig.body.to_vec(),
        }))
    }

    /// Whether any mediated calls are still awaiting a bus reply (for shutdown accounting).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn take_bus_serial(&mut self) -> u32 {
        let s = self.next_bus_serial;
        // Serials are non-zero; wrap past u32::MAX back to 2 (1 is the bin's Hello).
        self.next_bus_serial = self.next_bus_serial.checked_add(1).unwrap_or(2);
        s
    }
}

/// A decoded bus reply handed to [`Delegate::on_bus_reply`] (decoupled from `mini-sansio-dbus`'s
/// borrow so the bin can extract owned-enough fields).
#[derive(Debug, Clone, Copy)]
pub struct BusReply<'a> {
    /// The bus serial this reply answers (matched against the recorded mapping).
    pub reply_serial: u32,
    /// `Some(name)` if this is an `Error` reply; `None` for a `MethodReturn`.
    pub error_name: Option<&'a str>,
    /// The error message body, if any (for an `Error`).
    pub error_message: Option<&'a str>,
    /// The reply body signature (for a `MethodReturn`).
    pub signature: &'a str,
    /// The reply body's endianness flag.
    pub body_endian: u8,
    /// The reply body bytes.
    pub body: &'a [u8],
}

/// A decoded bus signal handed to [`Delegate::on_bus_signal`].
#[derive(Debug, Clone, Copy)]
pub struct BusSignal<'a> {
    /// The bus the signal arrived on.
    pub bus: Bus,
    /// Emitting object path.
    pub path: &'a str,
    /// Signal interface.
    pub interface: &'a str,
    /// Signal member.
    pub member: &'a str,
    /// Body signature.
    pub signature: &'a str,
    /// Body endianness flag.
    pub body_endian: u8,
    /// Body bytes.
    pub body: &'a [u8],
}

/// Whether a signal on `interface` is allowed through to the kennel.
///
/// A signal is delivered only if its interface is on the bus's `broadcast` allowlist or its
/// `talk` allowlist (the kennel may receive signals from a service it may call). This is a
/// coarse, default-drop filter on the interface; the finer per-subscription match-rule tracking
/// (e.g. signals for the kennel's *own* notifications) is a refinement layered on `AddMatch`.
fn signal_allowed(rules: &BusRules, interface: &str) -> bool {
    rules
        .broadcast
        .iter()
        .chain(rules.talk.iter())
        .any(|p| pattern_admits(p, interface))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(dest: &str, serial: u32) -> Call {
        Call {
            bus: Bus::Session,
            serial,
            no_reply: false,
            destination: dest.to_owned(),
            path: "/x".to_owned(),
            interface: "org.freedesktop.Notifications".to_owned(),
            member: "Notify".to_owned(),
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        }
    }

    fn notifications_delegate() -> Delegate {
        Delegate::new(Filter {
            session: Some(BusRules {
                talk: vec!["org.freedesktop.Notifications".to_owned()],
                broadcast: vec!["org.freedesktop.Notifications".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        })
    }

    #[test]
    fn allowed_call_goes_to_the_bus_and_records_the_serial() {
        let mut d = notifications_delegate();
        let out = d
            .on_conduit_call(&call("org.freedesktop.Notifications", 7))
            .expect("ok");
        assert!(matches!(out, Outbound::ToBus(_)));
        assert_eq!(d.pending_count(), 1);
    }

    #[test]
    fn denied_call_is_refused_to_the_conduit_not_the_bus() {
        let mut d = notifications_delegate();
        let out = d
            .on_conduit_call(&call("org.freedesktop.UDisks2", 8))
            .expect("ok");
        let Outbound::ToConduit(Frame::Error(e)) = out else {
            unreachable!("expected an AccessDenied error frame");
        };
        assert_eq!(e.reply_serial, 8);
        assert_eq!(e.name, ACCESS_DENIED);
        assert_eq!(d.pending_count(), 0); // never touched the bus
    }

    #[test]
    fn reply_is_demuxed_back_to_the_kennel_serial() {
        let mut d = notifications_delegate();
        // Send a call (kennel serial 7) → it gets bus serial 2 (the first mediated serial).
        let _ = d.on_conduit_call(&call("org.freedesktop.Notifications", 7));
        let frame = d.on_bus_reply(BusReply {
            reply_serial: 2,
            error_name: None,
            error_message: None,
            signature: "u",
            body_endian: b'l',
            body: &[1, 0, 0, 0],
        });
        let Some(Frame::Reply(r)) = frame else {
            unreachable!("expected a Reply frame");
        };
        assert_eq!(r.reply_serial, 7); // mapped back to the kennel serial
        assert_eq!(d.pending_count(), 0); // mapping consumed
    }

    #[test]
    fn bus_error_reply_becomes_an_error_frame() {
        let mut d = notifications_delegate();
        let _ = d.on_conduit_call(&call("org.freedesktop.Notifications", 7));
        let frame = d.on_bus_reply(BusReply {
            reply_serial: 2,
            error_name: Some("org.freedesktop.DBus.Error.Failed"),
            error_message: Some("nope"),
            signature: "",
            body_endian: b'l',
            body: &[],
        });
        let Some(Frame::Error(e)) = frame else {
            unreachable!("expected an Error frame");
        };
        assert_eq!(e.reply_serial, 7);
        assert_eq!(e.name, "org.freedesktop.DBus.Error.Failed");
    }

    #[test]
    fn unmatched_reply_is_dropped() {
        let mut d = notifications_delegate();
        let frame = d.on_bus_reply(BusReply {
            reply_serial: 999, // never sent
            error_name: None,
            error_message: None,
            signature: "",
            body_endian: b'l',
            body: &[],
        });
        assert!(frame.is_none());
    }

    #[test]
    fn allowed_signal_is_forwarded_disallowed_is_dropped() {
        let d = notifications_delegate();
        let allowed = d.on_bus_signal(BusSignal {
            bus: Bus::Session,
            path: "/org/freedesktop/Notifications",
            interface: "org.freedesktop.Notifications",
            member: "NotificationClosed",
            signature: "uu",
            body_endian: b'l',
            body: &[],
        });
        assert!(matches!(allowed, Some(Frame::Signal(_))));

        let dropped = d.on_bus_signal(BusSignal {
            bus: Bus::Session,
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "NameOwnerChanged",
            signature: "sss",
            body_endian: b'l',
            body: &[],
        });
        assert!(dropped.is_none()); // not on the allowlist — no passive monitoring
    }

    #[test]
    fn signal_on_a_disabled_bus_is_dropped() {
        let d = notifications_delegate(); // system bus is None
        let dropped = d.on_bus_signal(BusSignal {
            bus: Bus::System,
            path: "/x",
            interface: "org.freedesktop.Notifications",
            member: "X",
            signature: "",
            body_endian: b'l',
            body: &[],
        });
        assert!(dropped.is_none());
    }
}
