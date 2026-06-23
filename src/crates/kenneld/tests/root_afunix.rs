//! Root-gated e2e for the af-unix facade: a granted `[[unix.allow]]` socket reached
//! through binder. A child manager (kenneld's role) gates `CONNECT_AFUNIX` against a
//! `UnixRuntime` and connects the real host socket; the parent client receives the
//! connected fd via `transact_fd` and a byte round-trips over it to the host
//! listener. A non-granted request returns no fd (denied).
//!
//! Two processes (binder forbids the context manager's own process from calling it),
//! sharing the parent's mount namespace.
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_afunix-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_policy::{AuditRuntime, BinderRuntime, UnixRuntime, UnixSocket};
use kenneld::binder::{self, verb};

const MAP_SIZE: usize = 128 * 1024;
const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";
const REAL_ENV: &str = "KENNEL_AFUNIX_REAL";
const SHIM: &str = "svc.sock";

#[test]
fn afunix_facade_connects_a_granted_socket() {
    // A skip is not a proof: this test needs root for the privileged operation, so on an
    // unprivileged runner (`cargo test --all-features` in CI) it skips with cause rather than
    // failing. `sudo … --features e2e` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "skipping afunix_facade_connects_a_granted_socket: requires root for the privileged operation"
        );
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: own node 0, gating `CONNECT_AFUNIX` against one granted socket whose `shim`
/// is `svc.sock` and whose `real` is the host listener path.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let real = PathBuf::from(std::env::var_os(REAL_ENV).expect("manager: missing real env"));
    let audit_dir = dir.with_extension("audit");
    std::fs::create_dir_all(&audit_dir).expect("manager: audit dir");

    let unix = UnixRuntime {
        sockets: vec![UnixSocket {
            name: "svc".to_owned(),
            real: real.to_string_lossy().into_owned(),
            shim: SHIM.to_owned(),
            env: None,
        }],
    };
    let writer = std::sync::Arc::new(kenneld::audit::build_writer(
        "afunix-e2e",
        &audit_dir,
        &AuditRuntime::default(),
        "uuid-e2e".to_owned(),
    ));

    let fd = binderfs::open_binder_device(&dir).expect("manager: open device");
    let manager = binder::spawn(
        fd,
        7,
        BinderRuntime::default(),
        unix,
        binder::Lifecycle::default(),
        kenneld::inet::NetRuntime::denied(),
        std::sync::Arc::new(kenneld::inbound::InboundRuntime::new()),
        None,
        writer,
        None,
        Vec::new(),
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

/// Parent: host listener + manager child; receive a connected fd through the facade
/// and round-trip a byte over it; confirm a non-granted request yields no fd.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-afunix-{}", std::process::id()));
    let real = dir.with_extension("sock");
    let _ = std::fs::remove_file(&real);
    let listener = std::os::unix::net::UnixListener::bind(&real).expect("bind host listener");

    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    // Accept the manager's connect (it dials `real` on CONNECT_AFUNIX) and echo-read.
    let accepter = std::thread::spawn(move || {
        let (mut server, _) = listener.accept().expect("accept the facade connection");
        let mut buf = [0u8; 1];
        server
            .read_exact(&mut buf)
            .expect("read the byte the client sent");
        buf
    });

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "afunix_facade_connects_a_granted_socket",
            "--nocapture",
        ])
        .env(ROLE_ENV, "manager")
        .env(DIR_ENV, &dir)
        .env(REAL_ENV, &real)
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

    // A non-granted socket: no fd is returned (the facade denied it).
    assert!(
        client
            .transact_fd(CONTEXT_MANAGER_HANDLE, verb::CONNECT_AFUNIX, b"nope.sock")
            .is_err(),
        "a non-granted af-unix request must not return an fd",
    );

    // The granted socket: a connected fd comes back; a byte round-trips to the host.
    let fd = client
        .transact_fd(
            CONTEXT_MANAGER_HANDLE,
            verb::CONNECT_AFUNIX,
            SHIM.as_bytes(),
        )
        .expect("facade returned a connected fd for the granted socket");
    let mut stream = std::os::unix::net::UnixStream::from(fd);
    stream
        .write_all(b"P")
        .expect("write over the facade socket");
    drop(stream);

    assert_eq!(
        accepter.join().expect("accepter thread"),
        *b"P",
        "the facade fd was not connected to the granted host socket",
    );

    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = child.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(dir.with_extension("audit"));
    let _ = std::fs::remove_file(&real);
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}
