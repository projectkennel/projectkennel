//! Integration tests that drive the privhelper binary over stdin/stdout, the
//! way the spawner invokes it. The reserved scope is per-user, derived from the
//! caller's kernel-trusted real UID (no allocation file).

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
fn a_v4_address_is_refused_before_any_syscall() {
    // Addressing is v6-only: any IPv4 address is out of scope and refused during
    // validation, before any privileged syscall — so this needs no privilege.
    let mut req = bare_request(Op::DelAddr);
    req.addr = "127.0.0.1".parse().expect("v4 addr");
    req.prefix = 64;
    req.interface = "lo".to_owned();
    assert_eq!(
        run(&req).status,
        Status::Refused,
        "a v4 address must be refused (v6-only)"
    );
}

// --- Privileged tests. Run as root (uid 0); the scope derives from real uid 0. ---

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
fn lo_has(addr: &str) -> bool {
    let out = std::process::Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

#[cfg(feature = "e2e")]
#[test]
fn removes_an_in_scope_address_and_refuses_out_of_scope() {
    if skip_if_unprivileged("removes_an_in_scope_address_and_refuses_out_of_scope") {
        return;
    }
    // The privhelper derives its scope from the caller's real uid; run as root, that is 0.
    // Build an in-scope /64 address for uid 0, ctx 5, and place it on `lo` with `ip` to model
    // an address the factory added — then delete it via the standalone teardown `DelAddr` op.
    let uid = kennel_lib_syscall::unistd::real_uid();
    let addr = kennel_privhelper::addr::loopback_v6(uid, 5, 1);
    let addr_str = addr.to_string();
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{addr_str}/64"), "dev", "lo"])
        .status();

    let mut req = bare_request(Op::DelAddr);
    req.ctx = 5;
    req.addr = addr.into();
    req.prefix = 64;
    req.interface = "lo".to_owned();

    assert_eq!(
        run(&req).status,
        Status::Ok,
        "in-scope address removal should succeed"
    );
    assert!(!lo_has(&addr_str), "the loopback alias should be gone");

    // An address in a FOREIGN uid's subnet must be refused, before any syscall.
    req.addr = kennel_privhelper::addr::loopback_v6(uid.wrapping_add(1), 5, 1).into();
    assert_eq!(
        run(&req).status,
        Status::Refused,
        "out-of-scope (foreign-uid subnet) address must be refused"
    );
}
