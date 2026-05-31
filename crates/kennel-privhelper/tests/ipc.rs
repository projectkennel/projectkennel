//! Integration tests that drive the privhelper binary over stdin/stdout, the
//! way the spawner invokes it.

use std::io::Write as _;
use std::process::{Command, Stdio};

use kennel_privhelper::wire::{Op, Request, Response, Status};

/// Send `req` to a fresh privhelper process and return its decoded response.
fn run(req: &Request) -> Response {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kennel-privhelper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn privhelper");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&req.encode())
        .expect("write request");
    let out = child.wait_with_output().expect("wait for privhelper");
    Response::decode(&out.stdout).expect("decode response")
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
fn refuses_a_cgroup_outside_the_reserved_prefix() {
    // No privilege needed: the helper validates and refuses before any syscall.
    let resp = run(&cgroup_request(Op::CreateCgroup, "/etc/evil"));
    assert_eq!(resp.status, Status::Refused, "out-of-scope cgroup must be refused");
}

#[test]
fn refuses_a_traversal_path() {
    let resp = run(&cgroup_request(
        Op::CreateCgroup,
        "/sys/fs/cgroup/kennel/../../../etc",
    ));
    assert_eq!(resp.status, Status::Refused, "a `..` path must be refused");
}

#[cfg(feature = "root-tests")]
fn lo_has(addr: &str) -> bool {
    let out = Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .expect("run ip");
    String::from_utf8_lossy(&out.stdout).contains(addr)
}

#[cfg(feature = "root-tests")]
#[test]
fn adds_and_removes_an_in_scope_loopback_address() {
    // Provision the trusted scope file: tag = 9, ULA GID = 00:00:00:00:01.
    std::fs::create_dir_all("/etc/kennel").expect("mkdir /etc/kennel");
    std::fs::write("/etc/kennel/scope", [9u8, 0, 0, 0, 0, 1]).expect("write scope");

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

    let _ = std::fs::remove_file("/etc/kennel/scope");
}

#[cfg(feature = "root-tests")]
#[test]
fn creates_and_deletes_an_in_scope_cgroup() {
    let path = "/sys/fs/cgroup/kennel/privhelper-ipc-test";

    let created = run(&cgroup_request(Op::CreateCgroup, path));
    assert_eq!(created.status, Status::Ok, "in-scope create should succeed");
    assert!(std::path::Path::new(path).is_dir(), "cgroup directory should exist");

    let deleted = run(&cgroup_request(Op::DeleteCgroup, path));
    assert_eq!(deleted.status, Status::Ok, "in-scope delete should succeed");
    assert!(!std::path::Path::new(path).exists(), "cgroup directory should be gone");
}
