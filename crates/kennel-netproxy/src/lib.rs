//! Project Kennel per-kennel egress broker (the SOCKS5 / HTTP proxy).
//!
//! # Purpose
//!
//! Every outbound connection from a kennel terminates here; direct `connect()`
//! to anything else is denied at the kernel level by cgroup BPF
//! (`docs/07-3-network.md` §7.3.2). This crate is where the *expressive* half of
//! the egress story lives: per-destination allow/deny by name or CIDR, DNS
//! resolution under policy (the kennel never resolves names itself, so DNS
//! rebinding is structurally impossible), and a structured audit record per
//! request. The kernel enforces the trivial rule ("you may only talk to your
//! broker"); the interesting policy is here, in user-space code Project Kennel
//! controls.
//!
//! One listener serves all clients. The first byte of a connection disambiguates
//! the protocol with no ambiguity: SOCKS5 opens with the version byte `0x05`
//! (a control byte), HTTP always opens with an uppercase ASCII method letter
//! (`C`ONNECT, `G`ET, ...). So a single `MSG_PEEK` picks the handler, and the
//! standard `ALL_PROXY` / `HTTP_PROXY` / `HTTPS_PROXY` environment variables make
//! every common client (`curl`, `git`, `pip`, `npm`, `cargo`) work without
//! anyone choosing a protocol.
//!
//! # Invariants
//!
//! - **Fail closed.** A request that does not match an allow rule is denied. A
//!   parse error, an unresolved name, or a resolved address matching a
//!   categorical deny rule is denied. There is no path from "uncertain" to
//!   "connected".
//! - **Deny is evaluated before allow.** The categorical deny rules (cloud
//!   metadata, link-local, the host loopback) are checked first and override any
//!   allow rule, including on the *resolved* address of an allowed name — a
//!   name that resolves to `169.254.169.254` is still refused.
//! - **The kennel holds names, not addresses.** Resolution happens here, under
//!   the DNS policy, after the name clears the allowlist. The workload cannot
//!   pre-resolve and connect to a raw address (the BPF egress rules forbid every
//!   destination but this proxy).
//!
//! # Threat bearing
//!
//! Defends against T8 (exfiltration via an allowed destination — the audit
//! record and the per-destination allowlist are the mitigation surface), the DNS
//! rebinding class (resolution is here, not in the kennel), and the
//! terminal-injection class on the audit/error path (every untrusted string —
//! requested host, error detail — passes through `kennel-text` on the way out,
//! §10.3/§10.4).
//!
//! # Non-goals
//!
//! - This crate does not enforce the kernel-level "talk only to the proxy" rule
//!   (that is cgroup BPF, set up by `kennel-spawn`/`kennel-privhelper`).
//! - It does not perform TLS inspection. That is an explicit `open question`
//!   (`docs/11-open-questions.md`) and is off in v1.
//! - It does not load or verify the signed policy (that is `kennel-policy`); it
//!   consumes an already-resolved allowlist.
//!
//! # Deviation from `03-crate-decomposition.md`
//!
//! The decomposition document describes this crate as "uses the async runtime".
//! It does not: per a maintainer decision (2026-05-31), the proxy is blocking
//! and thread-per-connection, matching `kenneld`'s server (which the same
//! document also describes as async but which was likewise built blocking) and
//! the OpenSSH bar this project holds. The benefit is no async-runtime
//! dependency — no `tokio`/`mio` tree through the §5.5 supply-chain gate — and a
//! smaller TCB. A SOCKS5/HTTP egress broker is bounded by policy, not by the
//! c10k problem. The decomposition document is stale on this point; see
//! `CODING-STANDARDS.md` Appendix A.

#![forbid(unsafe_code)]

pub mod allow;
pub mod audit;
pub mod config;
pub mod dns;
pub mod http;
pub mod protocol;
pub mod server;
pub mod socks5;
