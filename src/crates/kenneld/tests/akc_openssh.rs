//! Root-gated proof of the production key source (§7.10.7): the **root-owned
//! `kennel-akc` binary, invoked exactly as OpenSSH's `AuthorizedKeysCommand` invokes it
//! (`%t %k` argv), vends the forced-command line for a synthetic key bound to a live
//! edge — by querying the running daemon — and nothing for an unregistered key.**
//!
//! This tests `kennel-akc` the way `sshd` uses it: `sshd` runs
//! `AuthorizedKeysCommand <akc> %t %k` (the offered key's type + base64 blob as argv) and
//! reads the `authorized_keys` line(s) from the helper's stdout. So the test runs the
//! real binary with that argv and checks its stdout — no live `sshd`, no client login.
//! The full `ssh → bastion → forced command → destination` chain is proven separately by
//! the `kennel run`-driven SSH egress suite case (`src/tools/policy-e2e.sh`).
//!
//! The chain exercised here is the real daemon-side answer:
//!
//! ```text
//!   kennel-akc (root-owned binary, `%t %k`) --> control socket
//!       --> Bastion::authorized_keys_for --> the restrict,pty,command=… line --> stdout
//! ```
//!
//! The only stand-in is the control *server* loop: it calls the very same
//! `Bastion::authorized_keys_for` that `kenneld::server`'s dispatch does (the dispatch
//! itself is unit-tested), so the daemon-side answer is real code.
//!
//! Why root: OpenSSH's safe-path check requires the `AuthorizedKeysCommand` binary to be
//! **root-owned** — exactly the privilege Project Kennel installs with. Chowning
//! `kennel-akc` to root is the one privileged step. Built/run like the other root test:
//!
//! ```text
//! cargo test -p kenneld --features e2e --no-run
//! sudo -E ./target/debug/deps/akc_openssh-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use kenneld::bastion::{Akc, Bastion, BastionConfig, Edge};
use kenneld::control::{self, Request, Response};

type SharedBastion = Arc<Mutex<Bastion>>;

#[test]
fn root_owned_akc_vends_the_forced_command_for_a_registered_key() {
    if !preflight() {
        return;
    }

    // Stage on a root-owned, world-traversable, exec filesystem: the AKC binary must be
    // executable and root-owned with no group/world-writable ancestor (sshd's safe-path
    // check). /opt satisfies this; /tmp and /run do not.
    let stage = PathBuf::from("/opt").join(format!("kennel-akc-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("bin")).expect("stage/bin");
    chmod(&stage, 0o755);
    chmod(&stage.join("bin"), 0o755);

    // The one privileged step: install kennel-akc root-owned (safe-path check).
    let akc = install_root_owned_akc(&stage);

    // The synthetic edge key + an unauthorised rogue key.
    let synthetic_pub = keygen(&stage.join("synthetic"), "synthetic-edge");
    let rogue_pub = keygen(&stage.join("rogue"), "rogue-key");

    // The control socket the AKC reaches (it resolves /run/user/0 once sshd would scrub
    // its environment; preflight dropped XDG_RUNTIME_DIR so we bind the same path).
    let sock = kenneld::socket::socket_path();

    // A real bastion with one live edge, behind the same responder kenneld's dispatch uses.
    let bastion: SharedBastion = Arc::new(Mutex::new(Bastion::new(BastionConfig {
        dir: stage.join("bastion"),
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        akc: Some(Akc {
            command: akc.clone(),
            user: "root".to_owned(),
        }),
    })));
    register_edge(&bastion, &synthetic_pub);
    spawn_responder(&sock, &bastion);

    // Invoke the AKC exactly as sshd does: `<akc> <type> <base64>` — the offered key's two
    // whitespace fields, no comment. The registered (synthetic) key yields its forced
    // command on stdout; the rogue key yields nothing (sshd then refuses it).
    let want = bastion
        .lock()
        .expect("lock")
        .authorized_keys_for(&key_argv(&synthetic_pub))
        .first()
        .cloned()
        .expect("a vended line for the registered key");
    let ok = run_akc(&akc, &synthetic_pub);
    let rogue = run_akc(&akc, &rogue_pub);

    // Teardown before asserting so a failure still cleans up.
    bastion.lock().expect("lock").stop();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&stage);

    assert!(ok.status.success(), "akc must exit 0 for a registered key");
    assert_eq!(
        String::from_utf8_lossy(&ok.stdout),
        want,
        "the AKC prints exactly the forced-command line the live bastion vends"
    );
    // The vended line is the new model: `ssh <options> -- <dest> "$SSH_ORIGINAL_COMMAND"`.
    assert!(
        want.starts_with("restrict,pty,command=\"ssh ")
            && want.contains("-- 'git@github.com'")
            && want.contains("$SSH_ORIGINAL_COMMAND"),
        "unexpected forced-command shape: {want}"
    );
    assert!(
        !rogue.status.success() && rogue.stdout.is_empty(),
        "an unregistered (rogue) key must vend no line and fail closed"
    );
}

/// Every precondition; `false` (printing a reason) when the proof cannot run here. Also
/// pins the control-socket path to /run/user/0 (where the env-scrubbed AKC will look).
fn preflight() -> bool {
    if kennel_lib_syscall::unistd::real_uid() != 0 {
        eprintln!("SKIP: must run as root (sudo) — the AKC binary must be root-owned");
        return false;
    }
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not found");
        return false;
    }
    // The AKC (run as root) resolves /run/user/0/kennel/control.sock; drop XDG_RUNTIME_DIR
    // so we bind the same path it will look at.
    std::env::remove_var("XDG_RUNTIME_DIR");
    let sock = kenneld::socket::socket_path();
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).expect("control socket dir");
    }
    let _ = std::fs::remove_file(&sock);
    true
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
        std::fs::metadata(&dst).expect("stat akc").uid(),
        0,
        "the AKC binary must be root-owned for sshd's safe-path check"
    );
    dst
}

/// Register the synthetic edge with the bastion (no `sshd` started — we only need the
/// edge state behind the responder).
fn register_edge(bastion: &SharedBastion, synthetic_pub: &str) {
    bastion.lock().expect("lock").push_edge_for_test(Edge {
        kennel: "akc-e2e".to_owned(),
        dest: "git@github.com".to_owned(),
        options: Vec::new(),
        synthetic_pub: synthetic_pub.to_owned(),
    });
}

/// The control responder: stands in for kenneld's serve loop, answering the AKC's
/// `AuthorizedKeys` query from the live `Bastion` edges (the same method the daemon's
/// dispatch calls). Bound before the AKC runs; detached (process exit reaps it).
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

/// Run `kennel-akc <type> <base64>` — the `%t %k` argv sshd hands its
/// `AuthorizedKeysCommand` (no comment field).
fn run_akc(akc: &Path, pubkey_line: &str) -> std::process::Output {
    let mut fields = pubkey_line.split_whitespace();
    let key_type = fields.next().unwrap_or_default();
    let blob = fields.next().unwrap_or_default();
    Command::new(akc)
        .args([key_type, blob])
        .output()
        .expect("run kennel-akc")
}

/// The `<type> <base64>` form (no comment) the responder matches an offered key by.
fn key_argv(pubkey_line: &str) -> String {
    pubkey_line
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

// --- small helpers ---

fn sibling_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let dir = exe.parent().and_then(Path::parent).expect("profile dir");
    dir.join(name)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .status()
        .is_ok_and(|s| s.success())
}

/// Mint a throwaway ed25519 keypair at `path`; return the public-key line.
fn keygen(path: &Path, comment: &str) -> String {
    let _ = std::fs::remove_file(path);
    let pub_path = {
        let mut p = path.to_path_buf().into_os_string();
        p.push(".pub");
        PathBuf::from(p)
    };
    let _ = std::fs::remove_file(&pub_path);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
    std::fs::read_to_string(&pub_path)
        .expect("read pubkey")
        .trim()
        .to_owned()
}
