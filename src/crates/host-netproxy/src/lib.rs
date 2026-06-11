//! `host-netproxy`: the per-kennel egress **dial delegate** (a glorified `netcat(1)`).
//!
//! # What this is
//!
//! `kenneld` owns the entire egress decision (`docs/design/07-5-network.md` §7.5): it reads the
//! signed kennel policy, runs the allow/deny ruleset, resolves names under policy, re-checks the
//! resolved address, and **pins** the vetted IPs — all in-process (`kenneld::inet`). The workload
//! speaks SOCKS to `facade-socks5` inside its own net-ns, which forwards each request as a
//! `CONNECT_INET` binder transaction to `kenneld`. None of that lives here any more.
//!
//! What's left is the one thing `kenneld` cannot do without crossing the net-ns boundary: put a
//! connected socket on a file descriptor. This crate is that delegate. It is a single module,
//! [`conduit`]: it listens on one owner-only `AF_UNIX` command socket, receives `(port, pinned IPs)`
//! plus a conduit fd over `SCM_RIGHTS`, dials the pinned address from the host stack, and splices.
//! No TCP listener, no SOCKS5/HTTP server, no resolver, no policy, **no config file** — the command
//! socket path is the binary's sole argument.
//!
//! # Invariants (upheld by `kenneld`, not here)
//!
//! The delegate only ever dials an already-pinned IP it was handed over the owner-only socket. It
//! makes no decision: fail-closed, deny-before-allow, and "the kennel holds names not addresses"
//! are all `kenneld`'s, enforced before a command ever reaches this process. The net-ns boundary is
//! the egress gate; this delegate is the only path across it.

#![forbid(unsafe_code)]

pub mod conduit;
