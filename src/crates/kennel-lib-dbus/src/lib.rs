//! Project Kennel D-Bus mediation library (§7.7).
//!
//! D-Bus is mediated through the binder gateway, never granted as a direct socket: an
//! in-kennel facade parses the adversarial D-Bus wire and emits a *typed* transaction; an
//! operator-context delegate filters it against the compiled `[dbus]` table and reconstructs
//! a well-formed call for the real bus. This crate is the shared machinery between the two
//! processes — the typed transaction [`wire`] format that crosses the conduit, and the
//! server-side handshake/message-loop the facade runs.
//!
//! The crate is depended on by `facade-dbus` (in-kennel, untrusted side) and `host-dbus`
//! (operator context). It is **outside the daemon TCB** — kenneld's only D-Bus role is
//! construction (spawn the pair, mint the conduit, hand over the compiled table), and it
//! depends on none of this.
//!
//! # Trust split
//!
//! The sole parser of adversarial *D-Bus* wire is the facade's server loop; that decode is
//! `mini-sansio-dbus` (`#![forbid(unsafe_code)]`). The [`wire`] frame that crosses the conduit
//! is a small, flat, length-prefixed format — its decoder is still bounds-checked and fuzzed
//! because the delegate reads frames from the untrusted facade, but it is not the D-Bus grammar.

#![forbid(unsafe_code)]

pub mod delegate;
pub mod filter;
pub mod message;
pub mod sasl;
pub mod server;

// The conduit TLV and the token-bucket rate limiter live in `kennel-lib-binder` — the node-0
// service wire, which kenneld already links — so kenneld can frame, rate-limit, and relay the
// conduit without the D-Bus marshaller reaching the daemon TCB. Re-exported here under the names
// the engine and the binaries already use (`kennel_lib_dbus::wire`, `::ratelimit`).
pub use kennel_lib_binder::dbus as wire;
pub use kennel_lib_binder::ratelimit;
