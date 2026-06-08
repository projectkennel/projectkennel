//! Root-gated end-to-end proof of the production key source (§7.10.7): **stock
//! OpenSSH, configured with the root-owned `AuthorizedKeysCommand`, authorises
//! exactly the synthetic key bound to a live edge — by querying the running daemon**.
//!
//! The chain exercised is the real one:
//!
//! ```text
//!   ssh (synthetic key) --> bastion sshd (kenneld::sshd config, AuthSource::Command)
//!       --> kennel-akc (root-owned binary, %t %k) --> control socket
//!       --> Bastion::authorized_keys_for --> the restrict,pty,command=… line
//!       --> sshd authorises --> the forced command runs
//! ```
//!
//! The only stand-in is the control *server* loop: it calls the very same
//! `Bastion::authorized_keys_for` that `kenneld::server`'s dispatch does (the
//! dispatch itself is unit-tested), so the daemon-side answer is real code.
//!
//! Why root: OpenSSH's safe-path check requires the `AuthorizedKeysCommand` binary to
//! be **root-owned** — which is exactly the privilege Project Kennel installs with
//! (the setuid privhelper). Chowning `kennel-akc` to root is the one privileged step;
//! the bastion `sshd` and `kennel-akc` then run as the ordinary bastion user, as in
//! production. Built/run like the other root test:
//!
//! ```text
//! cargo test -p kenneld --features root-tests --no-run
//! sudo -E ./target/debug/deps/akc_openssh-<hash>
//! ```

#![cfg(feature = "root-tests")]

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kenneld::bastion::{Akc, Bastion, BastionConfig, Edge};
use kenneld::control::{self, Request, Response};

type SharedBastion = Arc<Mutex<Bastion>>;

#[test]
fn stock_openssh_authorises_via_the_root_owned_akc_querying_kenneld() {
    let Some(login_user) = preflight() else {
        return;
    };

    // Stage on an exec, root-owned, world-traversable filesystem: the AKC binary and
    // the forced-command script must be executable (rules out noexec /run), every
    // ancestor must be root-owned and not group/world-writable (rules out /tmp), and
    // the login user must be able to traverse it to run the forced command (rules out
    // 0700 /root). /opt satisfies all three.
    let stage = PathBuf::from("/opt").join(format!("kennel-akc-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("bin")).expect("stage/bin");
    chmod(&stage, 0o755);
    chmod(&stage.join("bin"), 0o755);

    // The one privileged step: install kennel-akc root-owned (safe-path check).
    let akc = install_root_owned_akc(&stage);

    // A marker forced command (ignores the --dest/--key args the binding appends):
    // a successful auth runs it and the client sees the marker.
    let reorigin = stage.join("reorigin.sh");
    std::fs::write(&reorigin, "#!/bin/sh\necho AKC_OK\n").expect("write reorigin");
    chmod(&reorigin, 0o755);

    // Keys: the synthetic edge key + an unauthorised rogue key; a throwaway "real" key
    // supplies a well-formed fingerprint for the binding.
    let synthetic_pub = keygen(&stage.join("synthetic"), "synthetic-edge");
    keygen(&stage.join("rogue"), "rogue-key");
    let real_fp = fingerprint(&keygen_path(&stage.join("real"), "real-user-key"));

    // The control socket the AKC will reach (it resolves /run/user/0 once sshd scrubs
    // its environment; preflight dropped XDG_RUNTIME_DIR so we bind the same path).
    let sock = kenneld::socket::socket_path();

    // The real bastion: AuthSource::Command (the AKC), spawned by Bastion::register.
    let port = free_port();
    let bastion: SharedBastion = Arc::new(Mutex::new(Bastion::new(BastionConfig {
        dir: stage.join("bastion"),
        reorigin_bin: reorigin,
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        agent_sock: None,
        akc: Some(Akc {
            command: akc,
            user: "root".to_owned(),
        }),
    })));
    let host_pub = register_edge(&bastion, &synthetic_pub, real_fp);

    spawn_responder(&sock, &bastion);
    assert!(
        wait_listening(port),
        "the bastion sshd did not come up (privsep/config?)"
    );

    // The client pins the bastion host key (as the synthetic ~/.ssh/known_hosts would)
    // and logs in as the ordinary user — the forced command runs there.
    let known_hosts = stage.join("client_known_hosts");
    std::fs::write(&known_hosts, format!("[127.0.0.1]:{port} {host_pub}\n")).expect("known_hosts");

    let ok = run_client(&stage, "synthetic", port, &known_hosts, &login_user);
    let ok_out = String::from_utf8_lossy(&ok.stdout).into_owned();
    let authorised = ok.status.success() && ok_out.contains("AKC_OK");

    let denied = run_client(&stage, "rogue", port, &known_hosts, &login_user);
    let rogue_refused =
        !denied.status.success() && !String::from_utf8_lossy(&denied.stdout).contains("AKC_OK");

    // Teardown before asserting, so a failure still cleans up.
    bastion.lock().expect("lock").stop();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&stage);

    assert!(
        authorised,
        "stock sshd should authorise the synthetic key via the root-owned AKC querying kenneld \
         (status {:?}, stdout {ok_out:?}, stderr {:?})",
        ok.status,
        String::from_utf8_lossy(&ok.stderr),
    );
    assert!(
        rogue_refused,
        "an unregistered (rogue) key must be refused — the AKC vends no line for it"
    );
}

/// Check every precondition; return the ordinary login user, or `None` (printing a
/// reason) when the proof cannot run here. Also prepares the privsep dir and pins the
/// control-socket path to /run/user/0 (where the env-scrubbed AKC will look).
fn preflight() -> Option<String> {
    if kennel_syscall::unistd::real_uid() != 0 {
        eprintln!("SKIP: must run as root (sudo) — the AKC binary must be root-owned");
        return None;
    }
    for tool in ["/usr/sbin/sshd", "ssh", "ssh-keygen"] {
        if !have(tool) {
            eprintln!("SKIP: {tool} not found");
            return None;
        }
    }
    // The bastion sshd and forced command run as the user (its config denies root
    // login); under `sudo -E` that is $SUDO_USER.
    let login_user = std::env::var_os("SUDO_USER")?
        .to_string_lossy()
        .into_owned();
    if login_user == "root" {
        eprintln!("SKIP: $SUDO_USER is root; need an ordinary user to log in as");
        return None;
    }
    if !Command::new("id")
        .arg("sshd")
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("SKIP: the `sshd` privilege-separation user is absent");
        return None;
    }
    let _ = std::fs::create_dir_all("/run/sshd");
    let _ = std::fs::set_permissions("/run/sshd", std::fs::Permissions::from_mode(0o755));

    // sshd scrubs the AKC environment, so kennel-akc (run as root) resolves
    // /run/user/0/kennel/control.sock; drop XDG_RUNTIME_DIR so we bind the same path.
    std::env::remove_var("XDG_RUNTIME_DIR");
    let sock = kenneld::socket::socket_path();
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).expect("control socket dir");
    }
    let _ = std::fs::remove_file(&sock);
    Some(login_user)
}

/// Install `kennel-akc` root-owned and `0755` under `stage/bin` — what OpenSSH's
/// safe-path check demands of an `AuthorizedKeysCommand`. Returns its path.
fn install_root_owned_akc(stage: &Path) -> PathBuf {
    let src = sibling_binary("kennel-akc");
    assert!(
        src.exists(),
        "build kennel-akc: cargo build -p kenneld --bin kennel-akc"
    );
    let dst = stage.join("bin/kennel-akc");
    std::fs::copy(&src, &dst).expect("install kennel-akc");
    chmod(&dst, 0o755);
    assert_eq!(
        owner_uid(&dst),
        0,
        "the AKC binary must be root-owned for sshd's safe-path check"
    );
    dst
}

/// Register the synthetic edge with the bastion (writing the AKC `sshd_config`, no
/// `authorized_keys` file) and start the bastion `sshd`; return its host-key line.
fn register_edge(bastion: &SharedBastion, synthetic_pub: &str, real_fp: String) -> String {
    let mut b = bastion.lock().expect("lock");
    b.register(Edge {
        kennel: "akc-e2e".to_owned(),
        dest: "127.0.0.1".to_owned(),
        real_fp,
        synthetic_pub: synthetic_pub.to_owned(),
    })
    .expect("register edge (start bastion sshd)");
    b.host_pub().expect("bastion host key").to_owned()
}

/// The control responder: stands in for kenneld's serve loop, answering the AKC's
/// `AuthorizedKeys` query from the live `Bastion` edges (the same method the daemon's
/// dispatch calls). Bound before any client connects; detached (process exit reaps it).
fn spawn_responder(sock: &Path, bastion: &SharedBastion) {
    let listener = UnixListener::bind(sock).expect("bind control socket");
    chmod(sock, 0o666);
    let bastion = Arc::clone(bastion);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let Ok(Request::AuthorizedKeys { key }) = control::recv_request(&mut conn) else {
                continue;
            };
            let lines = bastion.lock().expect("lock").authorized_keys_for(&key);
            let _ = control::send_response(&mut conn, &Response::AuthorizedKeys { lines });
        }
    });
}

/// One client login: offers only `identity`, pins the bastion host key, logs in as
/// `login_user` (the forced command runs there).
fn run_client(
    stage: &Path,
    identity: &str,
    port: u16,
    known_hosts: &Path,
    login_user: &str,
) -> Output {
    Command::new("ssh")
        .args(["-F", "none", "-p", &port.to_string()])
        .args(["-o", "IdentitiesOnly=yes", "-i"])
        .arg(stage.join(identity))
        .args(["-o", "StrictHostKeyChecking=yes", "-o"])
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args([
            "-o",
            "BatchMode=yes",
            "-l",
            login_user,
            "127.0.0.1",
            "anything",
        ])
        .output()
        .expect("run ssh")
}

// --- small helpers ---

fn sibling_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    exe.parent()
        .and_then(Path::parent)
        .expect("profile dir")
        .join(name)
}

fn have(path: &str) -> bool {
    Path::new(path).exists()
        || Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {path}"))
            .status()
            .is_ok_and(|s| s.success())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("addr")
        .port()
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn owner_uid(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).expect("stat").uid()
}

/// `ssh-keygen` an ed25519 key at `path`; return its public-key line.
fn keygen(path: &Path, comment: &str) -> String {
    std::fs::read_to_string(keygen_path(path, comment).with_extension("pub"))
        .expect("read pub")
        .trim()
        .to_owned()
}

/// As [`keygen`] but returns the public-key *path* (`<path>.pub`).
fn keygen_path(path: &Path, comment: &str) -> PathBuf {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed for {}", path.display());
    path.to_path_buf()
}

/// The `SHA256:` fingerprint of the key whose private half is at `path`.
fn fingerprint(path: &Path) -> String {
    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(path.with_extension("pub"))
        .output()
        .expect("fingerprint");
    let fp = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    assert!(fp.starts_with("SHA256:"), "fingerprint: {fp}");
    fp
}

fn wait_listening(port: u16) -> bool {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    for _ in 0..50 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}
