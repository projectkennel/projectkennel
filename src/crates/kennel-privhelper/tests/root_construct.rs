//! Root-gated e2e for the privhelper **factory** skeleton (`07-2` §7.2.1).
//!
//! Proves the construction transport + the clone/maps/fexecve/relay core, ahead of the
//! full view/binderfs construction: acting as `kenneld`, the test hands the helper a
//! `SOCK_SEQPACKET` socket as stdin, sends a `ConstructionHalf` plus the **real
//! `kennel-init` ELF** as the init fd, reads back the construction child's host pid, and
//! asserts the helper relays the init's exit status. With no reachable binder bus (the
//! skeleton clones USER|PID only, no view), `kennel-init` fails to open its device and
//! exits 1 — so a `1` out the far end means: the child cloned with a real uid 0 (its maps
//! were written), `fexecve`d the real ELF *with empty argv* (the production hand-off), and
//! the status rode init→privhelper back to us.
//!
//! ```text
//! cargo test -p kennel-privhelper --features root-tests --test root_construct --no-run
//! sudo ./target/debug/deps/root_construct-<hash>
//! ```

#![cfg(feature = "root-tests")]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kennel_spawn::wire::encode_construction;
use kennel_spawn::ConstructionHalf;
use kennel_syscall::namespace::Namespaces;
use kennel_syscall::scm::{recv_with_fds, seqpacket_pair};

/// kennel-init with no reachable bus exits with a generic failure (1).
const INIT_NO_BUS_EXIT: i32 = 1;

/// Locate the `kennel-init` binary beside the test binary (built into the same
/// `target/<profile>/` dir). `cargo build -p kennel-init` must have run first.
fn kennel_init_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // .../target/debug/deps/root_construct-<hash> -> .../target/debug/kennel-init
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("deps dir parent");
    let bin = dir.join("kennel-init");
    assert!(
        bin.exists(),
        "build kennel-init first (cargo build -p kennel-init): {}",
        bin.display()
    );
    bin
}

/// Effective uid from `/proc/self/status` (the `Uid:` line's second field). Pure std,
/// so the test needs no extra dep just to gate itself.
fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().nth(1))
                .and_then(|euid| euid.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

#[test]
fn factory_clones_maps_and_relays_the_init_exit_status() {
    // Runs as real root (op_uid 0) OR as the operator with a file-capped privhelper
    // (the production posture). `KENNEL_FACTORY_OPERATOR=1` allows the non-root run.
    let operator_ok = std::env::var("KENNEL_FACTORY_OPERATOR").as_deref() == Ok("1");
    if effective_uid() != 0 && !operator_ok {
        eprintln!("SKIP: factory_clones_maps_and_relays needs root or KENNEL_FACTORY_OPERATOR=1");
        return;
    }

    // The real kennel-init ELF as the init fd: fexecve of an ELF works with a CLOEXEC fd
    // and empty argv (a script would not — the kernel cannot re-open a CLOEXEC fd for the
    // interpreter), which is exactly the production hand-off.
    let init = std::fs::File::open(kennel_init_binary()).expect("open kennel-init");

    // Act as kenneld: one socket end becomes the helper's stdin, we keep the other.
    let (ours, theirs) = seqpacket_pair().expect("socketpair");
    let helper = Path::new(env!("CARGO_BIN_EXE_kennel-privhelper"));
    let mut child = Command::new(helper)
        .arg("construct")
        .stdin(Stdio::from(theirs))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the factory");

    // Send the construction-half + the init fd. The full namespace set with no view
    // exercises the fallback construction (make_root_private + fresh /proc + /tmp) and the
    // maps (a real uid 0); the view + binderfs path is proven by the Stage F vertical e2e.
    let half = ConstructionHalf {
        namespaces: Namespaces::USER | Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC,
        cgroup: std::path::PathBuf::new(),
        cgroup_join: false,
        view: None,
        new_root: None,
        file_binds: Vec::new(),
        granted_gids: Vec::new(),
        lo: false,
    };
    kennel_syscall::scm::send_with_fds(ours.as_fd(), &encode_construction(&half), &[init.as_fd()])
        .expect("send construction request");

    // The factory replies with the construction child's host pid.
    let mut buf = [0u8; 64];
    let (n, _fds) = recv_with_fds(ours.as_fd(), &mut buf).expect("recv init pid");
    let pid_bytes: [u8; 4] = buf.get(..4).and_then(|s| s.try_into().ok()).expect("4-byte pid");
    let init_pid = i32::from_le_bytes(pid_bytes);
    assert_eq!(n, 4, "the reply should be the 4-byte init pid");
    assert!(init_pid > 1, "the init host pid should be a real pid: {init_pid}");

    // The helper stays as the construction child's parent and exits with its status.
    let status = child.wait().expect("await the factory");
    assert_eq!(
        status.code(),
        Some(INIT_NO_BUS_EXIT),
        "the factory must relay the init's exit status (clone+maps+fexecve+relay)"
    );
}
