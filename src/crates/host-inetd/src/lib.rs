//! `host-inetd`: the per-kennel inbound **BIND delegate** (the reverse of `host-netproxy`).
//!
//! # What this is
//!
//! `kenneld` owns the bind decision (`docs/design/07-5-network.md` §7.5.7): the `[net.bpf].bind`
//! cgroup ACL already decided, at the workload's `bind()`, which ports the kennel may listen on.
//! This delegate is what exposes one of those ports back on the host. It is the mirror image of the
//! egress dialer: where `host-netproxy` *dials* a pinned address and hands the connected fd into the
//! kennel, `host-inetd` *binds* a policy-mirrored `ip:port` on the host loopback, `accept()`s, and
//! hands each accepted connection's fd back to `kenneld`.
//!
//! All the logic is in [`listen`]; `main` binds the owner-only command socket and serves.
//!
//! # Protocol (two directions over the kenneld↔delegate `AF_UNIX` socket)
//!
//! - **kenneld → host-inetd, a registration:** `[tag:u8 | addr | port:u16 BE]` — bind
//!   `<addr>:<port>` on the host loopback and accept on it. One registration per mirrored port;
//!   `kenneld` holds the connection open.
//! - **host-inetd → kenneld, a notification:** for each `accept()`, the accepted connection's fd
//!   via `SCM_RIGHTS` plus the 2-byte `[port:u16 BE]` it belongs to, written back on the *same*
//!   connection. `kenneld` mints a socketpair, splices the accepted fd to one end, and pushes the
//!   other end into the kennel for `facade-client` to collect (`BIND_INET`).
//!
//! # Invariants (upheld by `kenneld`, not here)
//!
//! The delegate binds only an `ip:port` `kenneld` registered over the owner-only socket — the same
//! `ip:port` the workload was already allowed to bind. It makes no policy decision: the gate is the
//! `bind4`/`bind6` cgroup ACL, enforced before any registration reaches this process. No resolver,
//! no allowlist, no config file — the command-socket path is the binary's sole argument.

#![forbid(unsafe_code)]

pub mod listen;
