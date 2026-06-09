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
    let resp = run(&cgroup_request(Op::DelAddr, ""));
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
    let euid = kennel_syscall::unistd::effective_uid();
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

    let mut req = cgroup_request(Op::DelAddr, "");
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

/// Build a `/32` `allow_v4` LPM entry permitting any port to `addr` (network
/// order). Key/value layouts match `bpf/maps.h`.
#[cfg(feature = "e2e")]
const fn allow_v4_any(addr: [u8; 4]) -> kennel_privhelper::wire::V4Entry {
    let [a, b, c, d] = addr;
    let [p0, p1, p2, p3] = 32u32.to_ne_bytes(); // prefixlen
    let key = [p0, p1, p2, p3, a, b, c, d];
    // allow_entry: port_min=0, port_max=65535, protocol=0 (any), flags=0, pad.
    let [lo0, lo1] = 0u16.to_ne_bytes();
    let [hi0, hi1] = u16::MAX.to_ne_bytes();
    let value = [lo0, lo1, hi0, hi1, 0, 0, 0, 0];
    (key, value)
}

/// An empty `EgressPayload` (no map entries) — enough to exercise load + attach.
#[cfg(feature = "e2e")]
const fn empty_payload() -> kennel_privhelper::wire::EgressPayload {
    kennel_privhelper::wire::EgressPayload {
        meta: [0u8; kennel_privhelper::wire::META_LEN],
        allow_v4: Vec::new(),
        deny_v4: Vec::new(),
        allow_v6: Vec::new(),
        deny_v6: Vec::new(),
        bind_allowed_ports: Vec::new(),
        pin_id: String::new(),
    }
}

#[cfg(feature = "e2e")]
#[test]
fn loads_and_attaches_egress_to_an_owned_cgroup() {
    use kennel_privhelper::wire::{EgressPayload, META_LEN};

    if skip_if_unprivileged("loads_and_attaches_egress_to_an_owned_cgroup") {
        return;
    }
    // Model the delegated-subtree flow: kenneld (here, the test running as the
    // caller) creates the cgroup itself; it is owned by the caller's uid.
    let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-egress-test");
    let _ = std::fs::remove_dir(&cgroup);
    std::fs::create_dir(&cgroup).expect("create cgroup");

    let payload = EgressPayload {
        meta: [0u8; META_LEN],
        allow_v4: vec![allow_v4_any([127, 0, 0, 1])],
        deny_v4: Vec::new(),
        allow_v6: Vec::new(),
        deny_v6: Vec::new(),
        bind_allowed_ports: Vec::new(),
        pin_id: String::new(),
    };
    let resp = kennel_privhelper::exec::attach_egress_programs(&cgroup, &payload);
    assert_eq!(
        resp.status,
        Status::Ok,
        "egress setup should load+attach all programs (errno {})",
        resp.errno
    );

    // Removing the cgroup detaches the programs.
    std::fs::remove_dir(&cgroup).expect("remove cgroup");
}

/// With a `pin_id`, the helper pins the kennel's shared maps under the caller's
/// XDG runtime dir `/run/user/<uid>/kennel/bpf/<id>/` (item 10 + the audit-drain
/// prerequisite). Proves the pins land owner-only with the right modes; reopening
/// the ringbuf to drain is the kenneld e2e. (Runs as root, so uid 0.)
#[cfg(feature = "e2e")]
#[test]
fn pins_the_shared_maps_in_the_xdg_runtime_dir() {
    use kennel_privhelper::wire::{EgressPayload, META_LEN};
    use std::os::unix::fs::PermissionsExt as _;

    if skip_if_unprivileged("pins_the_shared_maps_in_the_xdg_runtime_dir") {
        return;
    }
    let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-egress-pin-test");
    let _ = std::fs::remove_dir(&cgroup);
    std::fs::create_dir(&cgroup).expect("create cgroup");

    let pin_id = "kennel-pintest";
    // Pins live in the caller's XDG runtime dir (root here, so /run/user/0).
    let uid = kennel_syscall::unistd::real_uid();
    let pin_dir = std::path::PathBuf::from(format!("/run/user/{uid}/kennel/bpf")).join(pin_id);
    let _ = std::fs::remove_dir_all(&pin_dir);

    let payload = EgressPayload {
        meta: [0u8; META_LEN],
        allow_v4: vec![allow_v4_any([127, 0, 0, 1])],
        deny_v4: Vec::new(),
        allow_v6: Vec::new(),
        deny_v6: Vec::new(),
        bind_allowed_ports: Vec::new(),
        pin_id: pin_id.to_owned(),
    };
    let resp = kennel_privhelper::exec::attach_egress_programs(&cgroup, &payload);
    assert_eq!(
        resp.status,
        Status::Ok,
        "egress setup (errno {})",
        resp.errno
    );

    // The audit ringbuf and the data maps are pinned (obj_pin only succeeds on bpffs,
    // so their presence proves the bpffs was mounted and the pin worked).
    for map in [
        "audit_ringbuf",
        "kennel_meta_map",
        "allow_v4",
        "bind_subnet_map",
    ] {
        let pin = pin_dir.join(map);
        assert!(pin.exists(), "expected pinned map at {}", pin.display());
        let mode = std::fs::metadata(&pin)
            .expect("stat pin")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "pin {map} should be mode 0600, got {mode:o}");
    }
    let dir_mode = std::fs::metadata(&pin_dir)
        .expect("stat pin dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "pin dir should be owner-only 0700, got {dir_mode:o}"
    );

    // Cleanup: unlink the pins + dir, detach by removing the cgroup. Leave the bpffs
    // mounted (idempotent across runs).
    let _ = std::fs::remove_dir_all(&pin_dir);
    std::fs::remove_dir(&cgroup).expect("remove cgroup");
}

#[cfg(feature = "e2e")]
#[test]
fn egress_to_a_cgroup_not_owned_by_caller_is_refused() {
    use kennel_privhelper::exec::REFUSAL_CGROUP_NOT_OWNED;

    if skip_if_unprivileged("egress_to_a_cgroup_not_owned_by_caller_is_refused") {
        return;
    }
    // A cgroup owned by a *different* uid must be refused before any BPF syscall —
    // the delegation boundary. (Run as root, so chowning to a foreign uid is possible.)
    let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kennel-foreign-test");
    let _ = std::fs::remove_dir(&cgroup);
    std::fs::create_dir(&cgroup).expect("create cgroup");
    std::os::unix::fs::chown(&cgroup, Some(12345), None).expect("chown to foreign uid");

    let resp = kennel_privhelper::exec::attach_egress_programs(&cgroup, &empty_payload());
    assert_eq!(
        resp.status,
        Status::Refused,
        "a cgroup not owned by the caller must be refused"
    );
    assert_eq!(
        resp.refusal, REFUSAL_CGROUP_NOT_OWNED,
        "refusal should name the ownership boundary"
    );

    std::fs::remove_dir(&cgroup).expect("remove cgroup");
}
