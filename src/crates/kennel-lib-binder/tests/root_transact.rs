//! Root-gated transaction round-trip across **two processes** (binder forbids the
//! context manager's own process from calling it): a child process becomes the
//! context manager (node 0); the parent is a client and does a real transaction —
//! client `transact` → looper `recv` → handler → `reply` → client receives bytes.
//! This proves `ctxmgr` + `client` end to end against the kernel.
//!
//! The child is this same test binary re-spawned in "manager" mode (no unsafe
//! `fork`); it inherits the parent's private mount namespace, so it sees the
//! binderfs instance the parent mounted.
//!
//! ```text
//! cargo test -p kennel-lib-binder --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_transact-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::ctxmgr::ContextManager;

const MAP_SIZE: usize = 128 * 1024;
const POLL_MS: i32 = 200;
const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";

#[test]
fn transaction_round_trip_through_node_zero() {
    // A skip is not a proof: this test needs root + a private mount namespace for the privileged
    // operation, so on an unprivileged runner (`cargo test --all-features` in CI) it skips with
    // cause rather than failing. `sudo unshare -m <test-binary>` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "skipping transaction_round_trip_through_node_zero: requires root + a private mount ns"
        );
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child role: take node 0, signal readiness, serve exactly one transaction.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let fd = binderfs::open_binder_device(&dir).expect("manager: open binder device");
    let cm = ContextManager::new(fd, MAP_SIZE).expect("manager: become context manager");
    // Signal readiness on a sibling path (binderfs itself permits only binder
    // devices, so a regular file cannot live inside the mount).
    std::fs::File::create(dir.with_extension("ready")).expect("manager: write ready file");

    let stop = AtomicBool::new(false);
    cm.serve(POLL_MS, &stop, |incoming, _conn| {
        assert_eq!(incoming.code, 42, "manager: unexpected transaction code");
        let mut reply = b"reply:".to_vec();
        reply.extend_from_slice(&incoming.data);
        stop.store(true, Ordering::Release); // one-shot: exit after this reply
        kennel_lib_binder::ctxmgr::Reply::Data(reply)
    })
    .expect("manager: serve loop");
}

/// Parent role: mount the instance, spawn the manager child, transact, assert.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-lib-binder-tx-{}", std::process::id()));
    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "transaction_round_trip_through_node_zero",
            "--nocapture",
        ])
        .env(ROLE_ENV, "manager")
        .env(DIR_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn manager child");

    let ready = dir.with_extension("ready");
    for _ in 0..50 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready.exists(), "manager child did not become ready");

    let fd = binderfs::open_binder_device(&dir).expect("client open");
    let client = Connection::open(fd, MAP_SIZE).expect("client connection");
    let reply = client
        .transact(CONTEXT_MANAGER_HANDLE, 42, b"hello")
        .expect("client transaction");
    assert_eq!(reply, b"reply:hello", "round-trip payload mismatch");

    let status = child.wait().expect("await manager child");
    assert!(status.success(), "manager child exited with {status}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(dir.with_extension("ready"));
}
