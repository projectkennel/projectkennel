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

/// Build a v4 loopback address: 127 | tag(12) | ctx(8) | host(4).
#[cfg(feature = "root-tests")]
fn v4(tag: u16, ctx: u16, host: u8) -> std::net::Ipv4Addr {
    let suffix = u32::from(tag).wrapping_shl(12) | u32::from(ctx).wrapping_shl(4) | u32::from(host);
    std::net::Ipv4Addr::from(0x7F00_0000 | suffix)
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
    // In scope for tag=9, ctx=5, /28.
    let addr = v4(9, 5, 1);
    let addr_str = addr.to_string();
    let mut req = cgroup_request(Op::AddAddr, "");
    req.ctx = 5;
    req.addr = addr.into();
    req.prefix = 28;
    req.interface = "lo".to_owned();

    assert_eq!(run(&req).status, Status::Ok, "in-scope address add should succeed");
    assert!(lo_has(&addr_str), "the loopback alias {addr_str} should be present");

    req.op = Op::DelAddr;
    assert_eq!(run(&req).status, Status::Ok, "address removal should succeed");
    assert!(!lo_has(&addr_str), "the loopback alias should be gone");

    // An out-of-scope address (wrong tag) must be refused, no syscall.
    req.op = Op::AddAddr;
    req.addr = v4(1, 5, 1).into(); // tag 1 != 9
    assert_eq!(run(&req).status, Status::Refused, "out-of-scope address must be refused");
}

/// Build a `/32` `allow_v4` LPM entry permitting any port to `addr` (network
/// order). Key/value layouts match `bpf/maps.h`.
#[cfg(feature = "root-tests")]
fn allow_v4_any(addr: [u8; 4]) -> kennel_privhelper::wire::V4Entry {
    let [a, b, c, d] = addr;
    let [p0, p1, p2, p3] = 32u32.to_ne_bytes(); // prefixlen
    let key = [p0, p1, p2, p3, a, b, c, d];
    // allow_entry: port_min=0, port_max=65535, protocol=0 (any), flags=0, pad.
    let [lo0, lo1] = 0u16.to_ne_bytes();
    let [hi0, hi1] = u16::MAX.to_ne_bytes();
    let value = [lo0, lo1, hi0, hi1, 0, 0, 0, 0];
    (key, value)
}

#[cfg(feature = "root-tests")]
#[test]
fn loads_and_attaches_egress_to_a_users_cgroup() {
    use kennel_privhelper::wire::{EgressPayload, META_LEN};

    provision_root_allocation();
    let helper = Path::new(env!("CARGO_BIN_EXE_kennel-privhelper"));
    let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-root/egress-test");

    // The cgroup must exist before BPF can attach to it.
    assert_eq!(run(&cgroup_request(Op::CreateCgroup, cgroup.to_str().expect("utf8"))).status, Status::Ok);

    let payload = EgressPayload {
        meta: [0u8; META_LEN],
        allow_v4: vec![allow_v4_any([127, 0, 0, 1])],
        deny_v4: Vec::new(),
        allow_v6: Vec::new(),
        deny_v6: Vec::new(),
    };
    let resp = client::setup_egress(helper, cgroup.clone(), &payload).expect("invoke setup_egress");
    assert_eq!(resp.status, Status::Ok, "egress setup should load+attach all programs (errno {})", resp.errno);

    // Cleanup detaches by removing the cgroup.
    assert_eq!(run(&cgroup_request(Op::DeleteCgroup, cgroup.to_str().expect("utf8"))).status, Status::Ok);
}

#[cfg(feature = "root-tests")]
#[test]
fn egress_to_a_foreign_namespace_is_refused() {
    use kennel_privhelper::wire::EgressPayload;

    provision_root_allocation();
    let helper = Path::new(env!("CARGO_BIN_EXE_kennel-privhelper"));
    // A cgroup outside the caller's `kennel-root` namespace must be refused before
    // any BPF syscall — the map contents are never even consulted.
    let payload = EgressPayload {
        meta: [0u8; kennel_privhelper::wire::META_LEN],
        allow_v4: Vec::new(),
        deny_v4: Vec::new(),
        allow_v6: Vec::new(),
        deny_v6: Vec::new(),
    };
    let resp = client::setup_egress(helper, std::path::PathBuf::from("/sys/fs/cgroup/kennel-other/x"), &payload)
        .expect("invoke setup_egress");
    assert_eq!(resp.status, Status::Refused, "egress to a foreign namespace must be refused");
}
