//! Root-gated e2e for the real `facade-afunix` proxy binary brokering an
//! `AF_UNIX` socket through the binder facade.
//!
//! Where `root_afunix` exercises the facade at the binder-client level, this drives
//! the actual proxy binary the seal launches: a child holds binder node 0 (kenneld's
//! role) gating `CONNECT_AFUNIX` for one granted name, the parent runs the proxy
//! (`facade-afunix <device> <shim-path>=<name>`), and an application connects to
//! the proxy's listener and round-trips a byte to the real host socket. This proves the
//! listener-present-at-the-shim-path + broker-by-name + fd-splice path of the proxy.
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_afunix_proxy-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use kennel_lib_binder::binderfs;
use kennel_lib_policy::{AuditRuntime, BinderRuntime, UnixRuntime, UnixSocket};
use kenneld::binder;

const ROLE_ENV: &str = "KENNEL_BINDER_ROLE";
const DIR_ENV: &str = "KENNEL_BINDER_DIR";
const REAL_ENV: &str = "KENNEL_AFUNIX_REAL";
const SERVICE: &str = "echo";

#[test]
fn afunix_proxy_brokers_a_granted_socket() {
    // A skip is not a proof: this test needs root for the privileged operation, so on an
    // unprivileged runner (`cargo test --all-features` in CI) it skips with cause rather than
    // failing. `sudo … --features e2e` still exercises it.
    // SAFETY: geteuid is always-safe FFI (no args, no error path).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "skipping afunix_proxy_brokers_a_granted_socket: requires root for the privileged operation"
        );
        return;
    }
    if std::env::var(ROLE_ENV).as_deref() == Ok("manager") {
        run_manager();
    } else {
        run_client();
    }
}

/// Child: own node 0, gating `CONNECT_AFUNIX` for one granted socket whose `name` is
/// `echo` and whose `real` is the host listener path.
fn run_manager() {
    let dir = PathBuf::from(std::env::var_os(DIR_ENV).expect("manager: missing dir env"));
    let real = std::env::var(REAL_ENV).expect("manager: missing real env");
    let audit_dir = dir.with_extension("audit");
    std::fs::create_dir_all(&audit_dir).expect("manager: audit dir");

    let unix = UnixRuntime {
        sockets: vec![UnixSocket {
            name: SERVICE.to_owned(),
            real,
            shim: format!("/unused/{SERVICE}.sock"),
            env: None,
        }],
    };
    let writer = std::sync::Arc::new(kenneld::audit::build_writer(
        "afunix-proxy-e2e",
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

/// Parent: host listener + manager child + the real proxy binary; connect to the
/// proxy's listener and round-trip a byte to the granted host socket.
fn run_client() {
    let dir = std::env::temp_dir().join(format!("kennel-afunix-proxy-{}", std::process::id()));
    let real = dir.with_extension("real.sock");
    let shim = dir.with_extension("shim.sock");
    let _ = std::fs::remove_file(&real);
    let _ = std::fs::remove_file(&shim);
    let listener = std::os::unix::net::UnixListener::bind(&real).expect("bind host listener");

    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");
    binderfs::add_binder_device(&dir).expect("allocate the binder device");

    // The host echo service: read "ping", write "pong".
    let accepter = std::thread::spawn(move || {
        let (mut server, _) = listener.accept().expect("accept the brokered connection");
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("read ping");
        assert_eq!(&buf, b"ping", "the proxy spliced the wrong bytes");
        server.write_all(b"pong").expect("write pong");
    });

    // The manager child (kenneld's node 0).
    let exe = std::env::current_exe().expect("current_exe");
    let mut manager = std::process::Command::new(&exe)
        .args([
            "--exact",
            "afunix_proxy_brokers_a_granted_socket",
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

    // The real proxy binary: present `echo` at the shim path, broker to node 0.
    let device = dir.join("binder");
    let proxy_bin = proxy_binary();
    let mut proxy = std::process::Command::new(&proxy_bin)
        .arg(&device)
        .arg(format!("{}={SERVICE}", shim.display()))
        .spawn()
        .expect("spawn facade-afunix proxy");

    // Wait for the proxy to bind its listener at the shim path.
    for _ in 0..50 {
        if shim.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        shim.exists(),
        "the proxy did not present a listener at the shim path"
    );

    // The application connects to the proxy and round-trips through the facade.
    let mut app = std::os::unix::net::UnixStream::connect(&shim).expect("connect to the proxy");
    app.write_all(b"ping").expect("send ping to the proxy");
    let mut reply = [0u8; 4];
    app.read_exact(&mut reply)
        .expect("read pong back through the proxy");
    assert_eq!(
        &reply, b"pong",
        "the proxy did not broker to the granted host socket"
    );
    drop(app);

    accepter.join().expect("host echo thread");

    // Teardown.
    let _ = proxy.kill();
    let _ = proxy.wait();
    std::fs::File::create(dir.with_extension("stop")).expect("stop file");
    let exit = manager.wait().expect("await manager child");
    assert!(exit.success(), "manager child exited with {exit}");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(dir.with_extension("audit"));
    let _ = std::fs::remove_file(&real);
    let _ = std::fs::remove_file(&shim);
    let _ = std::fs::remove_file(dir.with_extension("ready"));
    let _ = std::fs::remove_file(dir.with_extension("stop"));
}

/// Locate the `facade-afunix` binary beside the test binary.
fn proxy_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // .../target/debug/deps/root_afunix_proxy-<hash> -> .../target/debug/facade-afunix
    let dir = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("deps dir parent");
    let bin = dir.join("facade-afunix");
    assert!(
        bin.exists(),
        "build facade-afunix first (cargo build -p facade-afunix): {}",
        bin.display()
    );
    bin
}
