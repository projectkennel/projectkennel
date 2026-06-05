//! End-to-end proof of the BPF audit ring-buffer drain (`02-5-bpf-abi.md`,
//! `08-as-built-notes.md` §8.1, item 11).
//!
//! Builds the production drain path in-process under root: create the shared map
//! set, load+attach `connect4`, pin the `audit_ringbuf` to a bpffs, then run the
//! real [`kenneld::bpf_audit::spawn`] drain against the pin while a child in the
//! cgroup attempts a (fail-closed) denied connect. Asserts the canonical
//! `net.connect-deny` event with `source: bpf` lands in the writer's
//! `network.jsonl` — proving privhelper-pins → kenneld `obj_get` → drain thread →
//! parse → unified writer end to end.
//!
//! Run via `sudo`: build the gated binary with
//! `cargo test -p kenneld --features root-tests --no-run`, then run it as root.

#![cfg(feature = "root-tests")]

use std::ffi::CString;
use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kennel_policy::{AuditRuntime, AuditSinkKind};

/// Skip with cause on an unprivileged runner (a skip is not a proof). BPF load,
/// the bpffs mount, and cgroup attach all need privilege.
fn skip_if_unprivileged(test: &str) -> bool {
    // SAFETY: geteuid() reads the calling process's euid; no args, cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("skipping {test}: requires root (euid={euid})");
        return true;
    }
    false
}

#[test]
fn drains_a_denied_connect_event_through_the_writer() {
    if skip_if_unprivileged("drains_a_denied_connect_event_through_the_writer") {
        return;
    }

    // 1. Shared map set; load connect4 against it (the production load path).
    let maps = kennel_bpf::create_maps(kennel_bpf::KENNEL_MAPS).expect("create shared maps");
    let spec = kennel_bpf::KENNEL_PROGRAMS
        .iter()
        .find(|p| p.name == "connect4")
        .expect("connect4 spec");
    let elf = kennel_bpf::programs::object("connect4").expect("embedded connect4 object");
    let prog = kennel_bpf::load_program_against(elf, spec, &maps).expect("load connect4");

    // 2. Pin the shared audit_ringbuf on a bpffs, exactly as the privhelper does.
    let bpffs = Path::new("/run/kennel/bpf");
    std::fs::create_dir_all(bpffs).expect("mkdir /run/kennel/bpf");
    if !kennel_syscall::mount::is_bpffs(bpffs).unwrap_or(false) {
        kennel_syscall::mount::mount_bpffs(bpffs).expect("mount bpffs");
    }
    let pin_dir = bpffs.join("kennel-draintest");
    let _ = std::fs::remove_dir_all(&pin_dir);
    std::fs::create_dir(&pin_dir).expect("create pin dir");
    let rb_pin = pin_dir.join("audit_ringbuf");
    let cpin = CString::new(rb_pin.as_os_str().as_encoded_bytes()).expect("pin path");
    let rb_fd = maps.get("audit_ringbuf").expect("shared ringbuf");
    kennel_bpf::sys::obj_pin(rb_fd.as_fd(), &cpin).expect("pin ringbuf to bpffs");

    // 3. Attach connect4 to a fresh cgroup (empty maps ⇒ fail closed ⇒ deny).
    let cg = Path::new("/sys/fs/cgroup/kennel-draintest");
    let _ = std::fs::create_dir(cg);
    let cgfd = std::fs::File::open(cg).expect("open cgroup");
    kennel_bpf::sys::prog_attach_cgroup(cgfd.as_fd(), prog.as_fd(), spec.attach_type)
        .expect("attach connect4");

    // 4. A file-sink writer to a temp state dir (net events → network.jsonl).
    let state = std::env::temp_dir().join("kennel-draintest-audit");
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).expect("create state dir");
    let runtime = AuditRuntime {
        sinks: vec![AuditSinkKind::File],
        ..AuditRuntime::default()
    };
    let writer = Arc::new(kenneld::audit::build_writer(
        "draintest",
        &state,
        &runtime,
        "uuid-draintest".to_owned(),
    ));

    // 5. The real drain: obj_get the pin and spawn the per-kennel drain thread.
    //    The all-zero meta means events carry ctx_byte 0, so drain with ctx 0.
    let drain = kenneld::bpf_audit::spawn(pin_dir, 0, Arc::clone(&writer))
        .expect("spawn drain (obj_get + thread)");

    // 6. Denied connect from inside the cgroup, producing an audit event.
    let denied = connect_denied_in_cgroup(cg);

    // 7. Give the drain (200ms poll) time to consume, then stop it (final sweep +
    //    pin cleanup).
    std::thread::sleep(Duration::from_millis(600));
    drain.stop();

    // 8. Detach by removing the cgroup.
    let _ = std::fs::remove_dir(cg);

    // 9. Assert the canonical BPF-sourced event reached the file sink.
    let net = std::fs::read_to_string(state.join("network.jsonl")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&state);
    assert!(denied, "precondition: the connect should be BPF-denied");
    assert!(
        net.contains(r#""event":"net.connect-deny""#),
        "expected a net.connect-deny line, got: {net}"
    );
    assert!(
        net.contains(r#""source":"bpf""#),
        "the drained event must be source:bpf, got: {net}"
    );
    assert!(
        net.contains(r#""port":9"#),
        "expected the connect target port 9, got: {net}"
    );
}

/// Fork a child that joins `cg`, attempts one connect to 127.0.0.1:9, and `_exit`s
/// with the verdict. Returns true iff the BPF verdict denied the connect.
fn connect_denied_in_cgroup(cg: &Path) -> bool {
    // SAFETY: fork(); the child only joins the cgroup, attempts one connect, and
    // _exit()s — never returning to the harness.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        let pid = std::process::id().to_string();
        let _ = std::fs::write(cg.join("cgroup.procs"), &pid);
        let denied = connect_denied();
        // SAFETY: _exit without unwinding/atexit after fork.
        unsafe { libc::_exit(i32::from(denied)) };
    }
    let mut status = 0;
    // SAFETY: waitpid on our child with a valid status pointer.
    unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 1
}

/// Try to connect to 127.0.0.1:9; true iff denied with EPERM/EACCES (the cgroup
/// BPF verdict), false if it was permitted.
fn connect_denied() -> bool {
    // SAFETY: a standard socket()/connect() with a stack sockaddr_in valid for the
    // length passed; errno is read immediately after.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if s < 0 {
            return false;
        }
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
        addr.sin_port = 9u16.to_be();
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let len = u32::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap_or(16);
        let rc = libc::connect(s, std::ptr::from_ref(&addr).cast::<libc::sockaddr>(), len);
        let err = io::Error::last_os_error().raw_os_error();
        libc::close(s);
        rc < 0 && matches!(err, Some(libc::EPERM | libc::EACCES))
    }
}
