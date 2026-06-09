//! Root-gated e2e for the `kennel-init` lifecycle pull over binder node 0.
//!
//! Proves the novel **data-and-fd** reply path (`Reply::DataAndFd` /
//! `reply_with_data_and_fd` ↔ `transact_with_fd`, `07-2` §7.2.3): a child holds node 0
//! with a populated [`binder::Lifecycle`] (init pid = the client's pid, a supervision
//! blob, and a pty return socket), and the client transacts `GET_SANDBOX_PLAN` and gets
//! back the exact supervision bytes plus a working fd. The padding/length-prefix/offset
//! encoding is what this exercises; the authorisation *decision* is unit-tested in
//! `binder.rs`.
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_lifecycle-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use kennel_binder::binderfs;
use kennel_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_binder::service::lifecycle;
use kennel_policy::{AuditRuntime, BinderRuntime, UnixRuntime};
use kenneld::binder;

const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";
const INIT_PID_ENV: &str = "KENNEL_INIT_PID";
const MAP_SIZE: usize = 128 * 1024;
/// A supervision blob whose length (13) is deliberately not 8-aligned, so the reply
/// must pad before the fd object — exercising the alignment path.
const SUPERVISION: &[u8] = b"sup-half-13!!";
/// The marker the manager writes through its retained pty-socket end; the client must
/// read it back through the fd it received, proving the fd was transferred.
const PTY_MARKER: &[u8] = b"PTY!";

#[test]
fn init_pulls_the_supervision_half_and_pty_fd() {
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: own node 0 with a lifecycle gated on the client's pid, serving the
/// supervision blob and a pty socket.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let init_pid: i32 = std::env::var(INIT_PID_ENV)
        .expect("manager: missing init-pid env")
        .parse()
        .expect("manager: init-pid parse");
    let audit_dir = dir.with_extension("audit");
    std::fs::create_dir_all(&audit_dir).expect("manager: audit dir");
    let writer = std::sync::Arc::new(kenneld::audit::build_writer(
        "lifecycle-e2e",
        &audit_dir,
        &AuditRuntime::default(),
        "uuid-e2e".to_owned(),
    ));

    // A socketpair: keep `mine`, hand `theirs` to the kennel as the pty return socket.
    // Write the marker now; it stays buffered for the client to read through the fd.
    let (mut mine, theirs) = UnixStream::pair().expect("manager: socketpair");
    mine.write_all(PTY_MARKER).expect("manager: write pty marker");

    let lifecycle = binder::Lifecycle {
        init_host_pid: Some(init_pid),
        supervision: SUPERVISION.to_vec(),
        pty_fd: Some(OwnedFd::from(theirs)),
    };

    let fd = binderfs::open_binder_device(&dir).expect("manager: open device");
    let manager = binder::spawn(
        fd,
        7,
        BinderRuntime::default(),
        UnixRuntime::default(),
        lifecycle,
        writer,
    )
    .expect("manager: become context manager");
    std::fs::File::create(dir.with_extension("ready")).expect("manager: ready file");

    let stop = dir.with_extension("stop");
    for _ in 0..100 {
        if stop.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(mine); // signal EOF after the buffered marker
    manager.stop();
}

/// Parent: mount binderfs, run the manager child gated on *this* process's pid, and
/// pull the plan, asserting both the bytes and the fd.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-lifecycle-{}", std::process::id()));

    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    let exe = std::env::current_exe().expect("current_exe");
    let mut manager = std::process::Command::new(&exe)
        .args(["--exact", "init_pulls_the_supervision_half_and_pty_fd", "--nocapture"])
        .env(ROLE_ENV, "manager")
        .env(DIR_ENV, &dir)
        // The gate matches the transactor's host pid: ours, since we share the pid ns.
        .env(INIT_PID_ENV, std::process::id().to_string())
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

    // Pull: GET_SANDBOX_PLAN returns the supervision bytes and the pty fd.
    let device = dir.join("binder");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device)
        .expect("open binder device");
    let conn = Connection::open(file.into(), MAP_SIZE).expect("client connection");
    let (bytes, fd) = conn
        .transact_with_fd(CONTEXT_MANAGER_HANDLE, lifecycle::GET_SANDBOX_PLAN, &[])
        .expect("pull the supervision-half");

    assert_eq!(bytes, SUPERVISION, "the supervision bytes did not round-trip");
    let mut pty = UnixStream::from(fd.expect("an interactive pull must return a pty fd"));
    let mut marker = [0u8; PTY_MARKER.len()];
    pty.read_exact(&mut marker)
        .expect("read the marker through the transferred fd");
    assert_eq!(&marker, PTY_MARKER, "the transferred fd was not the pty socket");

    // Teardown.
    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = manager.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(dir.with_extension("audit"));
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}
