//! Integration tests that drive the privhelper binary over stdin/stdout, the
//! way the spawner invokes it. The reserved scope is per-user (the
//! `/etc/kennel/subkennel` allocation file, keyed by the caller's real UID).

use std::path::Path;

use kennel_privhelper::client;
use kennel_privhelper::wire::{Op, Request, Response, Status};

/// Send `req` to a fresh privhelper process (via the client) and return its
/// response — exercising `client::invoke` against the real binary.
fn run(req: &Request) -> Response {
    client::invoke(Path::new(env!("CARGO_BIN_EXE_kennel-privhelper")), req).expect("invoke privhelper")
}

fn cgroup_request(op: Op, path: &str) -> Request {
    Request {
        op,
        ctx: 0,
        addr: "0.0.0.0".parse().expect("placeholder addr"),
        prefix: 0,
        interface: String::new(),
        cgroup_path: path.into(),
    }
}

#[test]
fn an_unallocated_user_is_refused() {
    // The test user has no /etc/kennel/subkennel allocation, so every operation
    // is refused before any privileged syscall — no privilege needed to verify.
    let resp = run(&cgroup_request(Op::CreateCgroup, "/sys/fs/cgroup/kennel/x"));
    assert_eq!(resp.status, Status::Refused, "an unallocated user must be refused");
}

// --- Privileged tests. Run as root (uid 0); they provision uid 0's allocation. ---

#[cfg(feature = "root-tests")]
const ROOT_ALLOCATION: &str = "0:9:0000000001:kennel-root\n";

#[cfg(feature = "root-tests")]
fn provision_root_allocation() {
    std::fs::create_dir_all("/etc/kennel").expect("mkdir /etc/kennel");
    std::fs::write("/etc/kennel/subkennel", ROOT_ALLOCATION).expect("write allocation");
}

#[cfg(feature = "root-tests")]
fn lo_has(addr: &str) -> bool {
    let out = std::process::Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

#[cfg(feature = "root-tests")]
#[test]
fn creates_and_deletes_a_cgroup_in_the_users_namespace() {
    provision_root_allocation();
    // Under the allocated namespace `kennel-root`.
    let path = "/sys/fs/cgroup/kennel-root/ipc-test";

    assert_eq!(run(&cgroup_request(Op::CreateCgroup, path)).status, Status::Ok);
    assert!(std::path::Path::new(path).is_dir(), "cgroup directory should exist");

    assert_eq!(run(&cgroup_request(Op::DeleteCgroup, path)).status, Status::Ok);
    assert!(!std::path::Path::new(path).exists(), "cgroup directory should be gone");

    // A cgroup outside the user's namespace is refused.
    let other = run(&cgroup_request(Op::CreateCgroup, "/sys/fs/cgroup/kennel-other/x"));
    assert_eq!(other.status, Status::Refused, "another namespace must be refused");
}

#[cfg(feature = "root-tests")]
#[test]
fn adds_and_removes_an_in_scope_loopback_address() {
    provision_root_allocation();
    // In scope for tag=9, ctx=5: 127.9.5.0/24.
    let addr = "127.9.5.1";
    let mut req = cgroup_request(Op::AddAddr, "");
    req.ctx = 5;
    req.addr = addr.parse().expect("v4");
    req.prefix = 24;
    req.interface = "lo".to_owned();

    assert_eq!(run(&req).status, Status::Ok, "in-scope address add should succeed");
    assert!(lo_has(addr), "the loopback alias should be present");

    req.op = Op::DelAddr;
    assert_eq!(run(&req).status, Status::Ok, "address removal should succeed");
    assert!(!lo_has(addr), "the loopback alias should be gone");

    // An out-of-scope address (wrong tag) must be refused, no syscall.
    req.op = Op::AddAddr;
    req.addr = "127.1.5.1".parse().expect("v4"); // tag 1 != 9
    assert_eq!(run(&req).status, Status::Refused, "out-of-scope address must be refused");
}
