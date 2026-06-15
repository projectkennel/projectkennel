//! The `kennel-akc` helper speaks the control protocol (§7.10.7): given an offered
//! public key it asks the daemon over the control socket and prints the
//! forced-command line(s) sshd authorises with. Root-free — a hand-rolled control
//! server stands in for the running `kenneld`, exercising the real installed binary
//! end to end (argv → request → response → stdout, and fail-closed on no daemon).

use std::os::unix::net::UnixListener;
use std::process::Command;

use kenneld::control::{self, Request, Response};

/// One forced-command line, exactly as the bastion would vend it.
const WANT: &str = "restrict,pty,command=\"ssh -- 'git@github.com' \\\"$SSH_ORIGINAL_COMMAND\\\"\" ssh-ed25519 AAAASYN ka\n";

#[test]
fn kennel_akc_queries_kenneld_and_prints_the_forced_command_line() {
    let dir = std::env::temp_dir().join(format!("kennel-akc-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("control.sock");

    let listener = UnixListener::bind(&sock).expect("bind");
    // Server: accept one connection, expect the AuthorizedKeys query for our key
    // (comment-free, as sshd's `%t %k` would hand it), reply with the canned line.
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let req = control::recv_request(&mut conn).expect("recv request");
        assert_eq!(
            req,
            Request::AuthorizedKeys {
                key: "ssh-ed25519 AAAASYN".to_owned()
            }
        );
        control::send_response(
            &mut conn,
            &Response::AuthorizedKeys {
                lines: vec![WANT.to_owned()],
            },
        )
        .expect("send response");
    });

    let out = Command::new(env!("CARGO_BIN_EXE_kennel-akc"))
        .env("KENNEL_CONTROL_SOCK", &sock)
        .args(["ssh-ed25519", "AAAASYN"])
        .output()
        .expect("run kennel-akc");

    server.join().expect("server thread");
    assert!(
        out.status.success(),
        "akc should exit 0 (status {:?})",
        out.status
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        WANT,
        "the forced-command line is printed verbatim"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kennel_akc_fails_closed_when_no_daemon_is_listening() {
    // A socket path with nothing bound ⇒ connect fails ⇒ non-zero, no stdout, so sshd
    // authorises nothing.
    let sock = std::env::temp_dir().join(format!("kennel-akc-absent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let out = Command::new(env!("CARGO_BIN_EXE_kennel-akc"))
        .env("KENNEL_CONTROL_SOCK", &sock)
        .args(["ssh-ed25519", "AAAASYN"])
        .output()
        .expect("run kennel-akc");
    assert!(!out.status.success(), "must fail closed with no daemon");
    assert!(out.stdout.is_empty(), "no authorized_keys line on failure");
}

#[test]
fn kennel_akc_fails_closed_on_empty_argv() {
    // No key offered at all ⇒ refuse before even connecting.
    let out = Command::new(env!("CARGO_BIN_EXE_kennel-akc"))
        .output()
        .expect("run kennel-akc");
    assert!(
        !out.status.success(),
        "must fail closed with no key offered"
    );
    assert!(out.stdout.is_empty());
}
