//! Root-gated e2e for the `kennel-bin-init` lifecycle pull over binder node 0.
//!
//! A child holds node 0 with a populated [`binder::Lifecycle`] (init pid = the client's
//! pid + a supervision blob); the client transacts `GET_SANDBOX_PLAN` and gets back the
//! exact supervision bytes as a plain data reply (`07-2` §7.2.3). The length-prefix/offset
//! encoding is what this exercises; the authorisation *decision* is unit-tested in
//! `binder.rs`, and the data-**and-fd** reply path is exercised by the af-unix tests. The
//! interactive pty no longer rides this reply — it travels on the construction channel
//! (`interactive_pty` in `tests/e2e.rs`).
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_lifecycle-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::lifecycle;
use kennel_lib_policy::{AuditRuntime, UnixRuntime};
use kenneld::binder;

const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";
const INIT_PID_ENV: &str = "KENNEL_INIT_PID";
const MAP_SIZE: usize = 128 * 1024;
/// A supervision blob whose length (13) is deliberately not 8-aligned, so the reply
/// must pad before the fd object — exercising the alignment path.
const SUPERVISION: &[u8] = b"sup-half-13!!";

#[test]
fn init_pulls_the_supervision_half() {
    // A skip is not a proof: this test needs root for the privileged operation, so on an
    // unprivileged runner (`cargo test --all-features` in CI) it skips with cause rather than
    // failing. `sudo … --features e2e` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "skipping init_pulls_the_supervision_half: requires root for the privileged operation"
        );
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: own node 0 with a lifecycle gated on the client's pid, serving the supervision blob (no pty).
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

    let lifecycle = binder::Lifecycle {
        init_host_pid: Some(init_pid),
        supervision: SUPERVISION.to_vec(),
        cgroup: std::path::PathBuf::new(),
        ttl_action: kennel_lib_policy::TtlAction::Exit,
        name: "e2e".to_owned(),
        prompt: None,
    };

    let fd = binderfs::open_binder_device(&dir).expect("manager: open device");
    let manager = binder::spawn(
        fd,
        7,
        UnixRuntime::default(),
        lifecycle,
        kenneld::inet::NetRuntime::denied(),
        std::sync::Arc::new(kenneld::inbound::InboundRuntime::new()),
        false,
        writer,
        None,
        Vec::new(),
        None,
        None,
        kenneld::tun_sink::TunSink::new(),
        None,
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
    manager.stop();
}

/// Parent: mount binderfs, run the manager child gated on *this* process's pid, and
/// pull the plan, asserting the supervision bytes.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-lifecycle-{}", std::process::id()));

    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    let exe = std::env::current_exe().expect("current_exe");
    let mut manager = std::process::Command::new(&exe)
        .args(["--exact", "init_pulls_the_supervision_half", "--nocapture"])
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

    // Pull: GET_SANDBOX_PLAN returns the supervision bytes as a plain data reply. (The
    // interactive pty rides the construction channel now — kennel-bin-init inherits the return
    // socket at PTY_RETURN_FD — not this reply; see interactive_pty in tests/e2e.rs.)
    let device = dir.join("binder");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device)
        .expect("open binder device");
    let conn = Connection::open(file.into(), MAP_SIZE).expect("client connection");
    let bytes = conn
        .transact(CONTEXT_MANAGER_HANDLE, lifecycle::GET_SANDBOX_PLAN, &[])
        .expect("pull the supervision-half");
    assert_eq!(
        bytes, SUPERVISION,
        "the supervision bytes did not round-trip"
    );

    // Teardown.
    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = manager.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(dir.with_extension("audit"));
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}
