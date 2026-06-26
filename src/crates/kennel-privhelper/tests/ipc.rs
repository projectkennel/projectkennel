//! Integration tests that drive the privhelper binary over stdin/stdout, the
//! way the spawner invokes it. The reserved scope is per-user (the
//! `/etc/kennel/subkennel` allocation file, keyed by the caller's real UID).

use std::path::Path;

use kennel_privhelper::client;
use kennel_privhelper::wire::{Op, Request, Response, Status};

/// Send `req` to a fresh privhelper process (via the client) and return its
/// response — exercising `client::invoke` against the real binary.
fn run(req: &Request) -> Response {
    client::invoke(Path::new(env!("CARGO_BIN_EXE_kennel-privhelper")), req)
        .expect("invoke privhelper")
}

fn bare_request(op: Op) -> Request {
    Request {
        op,
        ctx: 0,
        addr: "0.0.0.0".parse().expect("placeholder addr"),
        prefix: 0,
        interface: String::new(),
    }
}

#[test]
fn an_unallocated_user_is_refused() {
    // The test user has no /etc/kennel/subkennel allocation, so every operation
    // is refused before any privileged syscall — no privilege needed to verify.
    let resp = run(&bare_request(Op::DelAddr));
    assert_eq!(
        resp.status,
        Status::Refused,
        "an unallocated user must be refused"
    );
}

// --- Privileged tests. Run as root (uid 0); they provision uid 0's allocation. ---

#[cfg(feature = "e2e")]
const ROOT_ALLOCATION: &str = "0:9:0000000001:kennel-root\n";

/// Skip a privilege-requiring test with cause on an unprivileged runner (a skip
/// is not a proof), matching the other crates' e2e so `cargo test
/// --all-features` is green for any runner while `sudo … --features e2e`
/// still exercises it.
#[cfg(feature = "e2e")]
fn skip_if_unprivileged(test: &str) -> bool {
    let euid = kennel_lib_syscall::unistd::effective_uid();
    if euid != 0 {
        eprintln!("skipping {test}: requires root (euid={euid}) for privileged privhelper ops");
        return true;
    }
    false
}

#[cfg(feature = "e2e")]
fn provision_root_allocation() {
    std::fs::create_dir_all("/etc/kennel").expect("mkdir /etc/kennel");
    std::fs::write("/etc/kennel/subkennel", ROOT_ALLOCATION).expect("write allocation");
}

#[cfg(feature = "e2e")]
fn lo_has(addr: &str) -> bool {
    let out = std::process::Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

/// Build a v4 loopback address: 127 | tag(12) | ctx(8) | host(4).
#[cfg(feature = "e2e")]
fn v4(tag: u16, ctx: u16, host: u8) -> std::net::Ipv4Addr {
    let suffix = u32::from(tag).wrapping_shl(12) | u32::from(ctx).wrapping_shl(4) | u32::from(host);
    std::net::Ipv4Addr::from(0x7F00_0000 | suffix)
}

#[cfg(feature = "e2e")]
#[test]
fn removes_an_in_scope_address_and_refuses_out_of_scope() {
    if skip_if_unprivileged("removes_an_in_scope_address_and_refuses_out_of_scope") {
        return;
    }
    provision_root_allocation();
    // In scope for tag=9, ctx=5, /28. The factory adds loopback addresses now (folded into
    // `construct`); the standalone `DelAddr` op is the teardown delete, tested here. Place the
    // alias with `ip` to model an address the factory added, then delete it via the op.
    let addr = v4(9, 5, 1);
    let addr_str = addr.to_string();
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{addr_str}/28"), "dev", "lo"])
        .status();

    let mut req = bare_request(Op::DelAddr);
    req.ctx = 5;
    req.addr = addr.into();
    req.prefix = 28;
    req.interface = "lo".to_owned();

    assert_eq!(
        run(&req).status,
        Status::Ok,
        "in-scope address removal should succeed"
    );
    assert!(!lo_has(&addr_str), "the loopback alias should be gone");

    // An out-of-scope address (wrong tag) must be refused, before any syscall.
    req.addr = v4(1, 5, 1).into(); // tag 1 != 9
    assert_eq!(
        run(&req).status,
        Status::Refused,
        "out-of-scope address must be refused"
    );
}
