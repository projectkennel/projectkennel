//! `kennel-privhelper-net` — the bind-mirror network sub-helper.
//!
//! Adds or removes a kennel's per-instance loopback address on the **host** `lo`,
//! so `host-inetd` can mirror a bound listening port host-side (§7.5.7). This is
//! the *only* construction step that needs `CAP_NET_ADMIN`, and it runs *only*
//! when a policy binds mirrored ports (`[net.bind]`) — so the common
//! `kennel-privhelper` factory carries no network capability at all (the in-ns
//! `lo`, with its free `127.0.0.1`/`::1`, is brought up inside the userns where
//! caps come for nothing).
//!
//! Invoked **only** by the main `kennel-privhelper`'s construct orchestration
//! (never by `kenneld` directly): the construction sequence is load-bearing and
//! lives in one place. It carries its own `cap_net_admin` file capability, so the
//! orchestrator — which holds only the identity-map caps — gains it across the
//! `exec` without holding it itself.
//!
//! Gating (boundary 1): like every privileged op it requires the caller to hold a
//! `/etc/kennel/subkennel` allocation, and it re-validates the address against the
//! caller's reserved subnet (`validate_addr`) before the netlink syscall — so
//! holding `cap_net_admin` here grants only this one scoped job, not arbitrary
//! address configuration.

#![forbid(unsafe_code)]

use std::ffi::CString;
use std::net::IpAddr;
use std::process::ExitCode;

use kennel_lib_syscall::netlink;
use kennel_lib_syscall::unistd::real_uid;
use kennel_privhelper::alloc;
use kennel_privhelper::validate::{validate_addr, AddrRequest};

/// The loopback interface the mirror address is added to (`lo`).
const LOOPBACK: &str = "lo";

/// Exit codes (mirroring the helper wire contract: 0 ok, 1 refused, 2 protocol,
/// 3 internal).
const OK: u8 = 0;
const REFUSED: u8 = 1;
const PROTOCOL: u8 = 2;
const INTERNAL: u8 = 3;

fn main() -> ExitCode {
    // Scrub the inherited environment first: the helper runs privileged and takes
    // no decision from the environment — identity is the kernel-stamped real uid
    // and trust comes from root-owned config — so a caller variable must not steer
    // it nor leak onward. `vars_os` is a snapshot, so removing during iteration is
    // sound.
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(key);
    }

    ExitCode::from(match run() {
        Ok(()) => OK,
        Err(code) => code,
    })
}

/// Parse `{add|del} <ctx> <addr> <prefix>`, gate on the allocation, validate the
/// address against the caller's reserved subnet, and perform the netlink op.
fn run() -> Result<(), u8> {
    let args: Vec<String> = std::env::args().collect();
    let (op, ctx, addr, prefix) = parse_args(&args)?;

    // Gate on the caller's subkennel allocation (its real uid is the trusted
    // identity), exactly as every privileged op is gated. No allocation ⇒ no op.
    let Some(scope) = alloc::load(real_uid()) else {
        eprintln!("kennel-privhelper-net: caller has no /etc/kennel/subkennel allocation");
        return Err(REFUSED);
    };

    // Re-validate against the reserved subnet: the orchestrator supplies the
    // address but this helper does not trust it — one outside the per-kennel
    // subnet is refused before any netlink syscall.
    let req = AddrRequest {
        ctx,
        interface: LOOPBACK.to_owned(),
        addr,
        prefix,
    };
    if let Err(refusal) = validate_addr(&req, &scope) {
        eprintln!("kennel-privhelper-net: address {addr} refused: {refusal}");
        return Err(REFUSED);
    }

    let cname = CString::new(LOOPBACK).map_err(|_| PROTOCOL)?;
    let ifindex = netlink::if_index(&cname).map_err(|e| {
        eprintln!("kennel-privhelper-net: resolve {LOOPBACK}: {e}");
        INTERNAL
    })?;

    let result = match op {
        Op::Add => netlink::add_address(ifindex, addr, prefix),
        Op::Del => netlink::del_address(ifindex, addr, prefix),
    };
    result.map_err(|e| {
        eprintln!("kennel-privhelper-net: {op} {addr}/{prefix} on {LOOPBACK}: {e}");
        INTERNAL
    })
}

/// The two operations: add the mirror address (at construction) or remove it (at
/// teardown).
#[derive(Clone, Copy)]
enum Op {
    Add,
    Del,
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Add => "add",
            Self::Del => "del",
        })
    }
}

/// Parse `argv` as `{add|del} <ctx:u16> <addr:IpAddr> <prefix:u8>`.
fn parse_args(args: &[String]) -> Result<(Op, u16, IpAddr, u8), u8> {
    let usage = || {
        eprintln!("usage: kennel-privhelper-net {{add|del}} <ctx> <addr> <prefix>");
        PROTOCOL
    };
    let op = match args.get(1).map(String::as_str) {
        Some("add") => Op::Add,
        Some("del") => Op::Del,
        _ => return Err(usage()),
    };
    let ctx: u16 = args
        .get(2)
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| usage())?;
    let addr: IpAddr = args
        .get(3)
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| usage())?;
    let prefix: u8 = args
        .get(4)
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| usage())?;
    Ok((op, ctx, addr, prefix))
}
