//! Root-gated fd-passing e2e: a manager replies to a transaction with a connected
//! socket fd (`reply_with_fd`), the client receives it (`transact_fd`) and reads a
//! byte the manager wrote through it. Proves `BINDER_TYPE_FD` passing end to end —
//! the mechanism the af-unix facade returns a connected socket through.
//!
//! Two processes (binder forbids the context manager's own process from calling it);
//! the manager is this test binary re-spawned, sharing the parent's mount namespace.
//!
//! ```text
//! cargo test -p kennel-lib-binder --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_fd-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::ctxmgr::ContextManager;

const MAP_SIZE: usize = 128 * 1024;
const POLL_MS: i32 = 200;
const CONNECT: u32 = 1;
const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";

#[test]
fn fd_passing_round_trip() {
    // A skip is not a proof: this test needs root + a private mount namespace for the privileged
    // operation, so on an unprivileged runner (`cargo test --all-features` in CI) it skips with
    // cause rather than failing. `sudo unshare -m <test-binary>` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping fd_passing_round_trip: requires root + a private mount ns");
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: own node 0; on each transaction, reply with one end of a socketpair after
/// writing a sentinel byte to the other end.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let cm = ContextManager::new(
        binderfs::open_binder_device(&dir).expect("manager: open device"),
        MAP_SIZE,
    )
    .expect("manager: become context manager");
    let conn = cm.connection();
    std::fs::File::create(dir.with_extension("ready")).expect("manager: ready file");

    let stop = dir.with_extension("stop");
    while !stop.exists() {
        if conn.poll(POLL_MS).expect("manager: poll") {
            for incoming in conn.recv().expect("manager: recv") {
                let (mut ours, theirs) = UnixStream::pair().expect("socketpair");
                ours.write_all(b"K").expect("write sentinel");
                conn.reply_with_fd(&incoming, theirs.as_fd())
                    .expect("reply with fd");
                // `ours`/`theirs` drop here: the byte stays buffered for the client's
                // dup of `theirs` to read; the kernel already dup'd it into the caller.
            }
        }
    }
}

/// Parent: spawn the manager child, transact for an fd, read the sentinel through it.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-lib-binder-fd-{}", std::process::id()));
    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(exe)
        .args(["--exact", "fd_passing_round_trip", "--nocapture"])
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

    let client = Connection::open(
        binderfs::open_binder_device(&dir).expect("client open"),
        MAP_SIZE,
    )
    .expect("client connection");
    let fd = client
        .transact_fd(CONTEXT_MANAGER_HANDLE, CONNECT, b"x")
        .expect("transact for fd");

    let mut stream = UnixStream::from(fd);
    let mut buf = [0u8; 1];
    stream
        .read_exact(&mut buf)
        .expect("read sentinel through passed fd");
    assert_eq!(&buf, b"K", "fd did not carry a working connected socket");

    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = child.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}
