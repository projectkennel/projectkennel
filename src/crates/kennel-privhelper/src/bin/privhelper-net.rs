// SPDX-License-Identifier: Apache-2.0

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
//! Gating (boundary 1): like every privileged op it re-validates the address against
//! the caller's uid-derived reserved subnet (`validate_addr`) before the netlink
//! syscall — so holding `cap_net_admin` here grants only this one scoped job, not
//! arbitrary address configuration.

#![forbid(unsafe_code)]
// The helper never panics on a failed assumption in shipped code (CODING-STANDARDS.md §8.3, §12.2).
#![cfg_attr(not(test), deny(clippy::expect_used))]

use std::ffi::CString;
use std::net::IpAddr;
use std::process::ExitCode;

use kennel_lib_syscall::netlink;
use kennel_lib_syscall::unistd::real_uid;
use kennel_privhelper::validate::{validate_addr, AddrRequest, ReservedScope};

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

/// Parse `{add|del} <ctx> <addr> <prefix>`, validate the address against the caller's
/// uid-derived reserved subnet, and perform the netlink op.
fn run() -> Result<(), u8> {
    let args: Vec<String> = std::env::args().collect();
    let (op, ctx, addr, prefix) = parse_args(&args)?;

    // The caller's real uid is the trusted identity; its reserved v6 subnet derives from it.
    let scope = ReservedScope::new(real_uid());

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

    // Each address is kernel memory on the host's loopback, and the 64-bit host part of the
    // reserved subnet makes the space of valid addresses effectively unlimited. kenneld adds a
    // handful per kennel; a caller driving this helper directly must not be able to add them
    // without bound.
    if matches!(op, Op::Add) {
        // An unreadable table is not an empty one: without the count there is no cap, so the
        // add is refused.
        let table = std::fs::read_to_string("/proc/net/if_inet6").map_err(|e| {
            eprintln!(
                "kennel-privhelper-net: cannot count the addresses already on {LOOPBACK} \
                 (/proc/net/if_inet6: {e}); refusing to add more"
            );
            REFUSED
        })?;
        let held = reserved_addresses(&table, kennel_privhelper::validate::reserved_prefix(&scope));
        if held >= MAX_RESERVED_ADDRESSES {
            eprintln!(
                "kennel-privhelper-net: {held} addresses of this user's reserved subnet are \
                 already on {LOOPBACK} (limit {MAX_RESERVED_ADDRESSES}); refusing to add more"
            );
            return Err(REFUSED);
        }
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

/// The most addresses of one user's reserved subnet this helper will put on the loopback.
const MAX_RESERVED_ADDRESSES: usize = 1024;

/// How many addresses in `/proc/net/if_inet6` text are on the loopback and start with `prefix`.
/// Each line is `<32 hex digits> <ifindex> <prefix len> <scope> <flags> <ifname>`.
fn reserved_addresses(table: &str, prefix: [u8; 6]) -> usize {
    use std::fmt::Write as _;
    let mut want = String::with_capacity(12);
    for byte in prefix {
        let _ = write!(want, "{byte:02x}");
    }
    table
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let addr = fields.next().unwrap_or_default();
            addr.starts_with(&want) && fields.last() == Some(LOOPBACK)
        })
        .count()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_users_loopback_addresses_are_counted() {
        let table = "\
fd4b4e0000010001000000000000000001 01 80 00 80       lo
fd4b4e0000010002000000000000000001 01 80 00 80       lo
fd4b4e0000020001000000000000000001 01 80 00 80       lo
fd4b4e0000010001000000000000000002 02 80 00 80     eth0
00000000000000000000000000000001 01 80 10 80       lo
";
        // Two addresses of this user's subnet are on the loopback; one more is on another
        // interface and one belongs to another user.
        assert_eq!(
            reserved_addresses(table, [0xfd, 0x4b, 0x4e, 0x00, 0x00, 0x01]),
            2
        );
        assert_eq!(
            reserved_addresses(table, [0xfd, 0x4b, 0x4e, 0x00, 0x00, 0x09]),
            0
        );
    }
}
