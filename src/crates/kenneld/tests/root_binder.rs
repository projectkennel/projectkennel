//! Root-gated e2e for `kenneld::binder`: the policy-gated service registry served
//! over the real binder transport, across two processes.
//!
//! A child process is the context manager (kenneld's role) for a binderfs instance,
//! with a settled `[binder]` policy granting `provide = ["svc"]`. The parent is an
//! in-kennel client that transacts the registry verbs to node 0 and asserts the
//! gate's status replies: a provided name registers and resolves, an undeclared
//! lookup is denied, and a reserved-namespace registration is refused.
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_binder-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_policy::{AuditRuntime, BinderProvideRuntime, BinderRuntime, UnixRuntime};
use kenneld::binder::{self, status, verb};

const MAP_SIZE: usize = 128 * 1024;
const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";

#[test]
fn registry_gate_over_the_binder_transport() {
    // A skip is not a proof: this test needs root for the privileged operation, so on an
    // unprivileged runner (`cargo test --all-features` in CI) it skips with cause rather than
    // failing. `sudo … --features e2e` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping registry_gate_over_the_binder_transport: requires root for the privileged operation");
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: take node 0, serve the registry gated by `provide = ["svc"]`, until the
/// parent drops a stop file.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let audit_dir = dir.with_extension("audit");
    std::fs::create_dir_all(&audit_dir).expect("manager: audit dir");

    let policy = BinderRuntime {
        provide: vec![BinderProvideRuntime {
            name: "svc".to_owned(),
            accept_from: Vec::new(),
        }],
        consume: Vec::new(),
    };
    let writer = Arc::new(kenneld::audit::build_writer(
        "binder-e2e",
        &audit_dir,
        &AuditRuntime::default(),
        "uuid-e2e".to_owned(),
    ));

    let fd = binderfs::open_binder_device(&dir).expect("manager: open binder device");
    let manager = binder::spawn(
        fd,
        7,
        policy,
        UnixRuntime::default(),
        binder::Lifecycle::default(),
        kenneld::inet::NetRuntime::denied(),
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
    manager.stop();
}

/// Parent: mount the instance, spawn the manager child, transact the verbs, assert
/// the gate's replies.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-lib-binder-reg-{}", std::process::id()));
    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "registry_gate_over_the_binder_transport",
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

    let st = |verb: u32, name: &[u8]| -> u8 {
        let reply = client
            .transact(CONTEXT_MANAGER_HANDLE, verb, name)
            .expect("client transaction");
        *reply.first().expect("reply has a status byte")
    };

    // A provided service registers, then resolves locally.
    assert_eq!(st(verb::ADD_SERVICE, b"svc"), status::OK, "register svc");
    assert_eq!(st(verb::GET_SERVICE, b"svc"), status::OK, "resolve svc");
    // An undeclared lookup is denied; an undeclared registration is denied.
    assert_eq!(
        st(verb::GET_SERVICE, b"other"),
        status::DENIED,
        "deny lookup"
    );
    assert_eq!(
        st(verb::ADD_SERVICE, b"other"),
        status::DENIED,
        "deny register"
    );
    // A reserved-namespace registration is refused outright.
    assert_eq!(
        st(verb::ADD_SERVICE, b"org.projectkennel.IAfUnix/default"),
        status::REFUSED_RESERVED,
        "refuse reserved",
    );

    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = child.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(dir.with_extension("audit"));
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}
