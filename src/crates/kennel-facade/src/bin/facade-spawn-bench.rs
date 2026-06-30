//! `facade-spawn-bench` — the in-kennel **spinup bench** driver (`02-10` §7.12, the "one layer down" spinup profile).
//!
//! Run as the workload of a single, long-lived **control kennel**, this times two ways of running the
//! same payload `count` times in a row, from inside that one kennel's lifetime — no per-run CLI launch,
//! no per-run policy compile, so the numbers are the spinup itself and nothing else:
//!
//!   • `direct` — the control kennel `fork`/`exec`s the payload itself (`/bin/true`, `python3 -c …`)
//!                and reaps it. The process-spinup floor: the work, with no new kennel around it.
//!   • `spawn`  — the control kennel transacts `verb::SPAWN` for the payload's signed template, so
//!                `kenneld` mints a scoped **ephemeral sibling kennel** to run it; the bench reads the
//!                sibling's channel to EOF (it has run and exited). The full isolated-kennel spinup.
//!
//! The per-iteration wall (a monotonic delta around each whole run, reaped) is printed one per line —
//! `direct <nanos>` / `spawn <nanos>` — on stdout, which a plain `kennel run` returns to the harness
//! (`tools/spawn-spinup.sh`). The delta between the two distributions is what wrapping each run in its
//! own fresh kennel costs. `kenneld`'s `[t=<nanos>]` trace stream additionally breaks the `spawn` side
//! into its in-daemon phases (handler validate→mint, construct), for the harness to read alongside.
//!
//! Serialization: the `spawn` loop reads each sibling's channel to EOF before the next SPAWN, so at
//! most one sibling is ever live and the `max_instances` ceiling is never the limiter. Exit 0 iff every
//! direct run and every spawn succeeded.
//!
//! Usage: `facade-spawn-bench <count> <template> <direct-cmd> [direct-args...]`
//!   e.g. `facade-spawn-bench 20 true-tool /bin/true`
//!        `facade-spawn-bench 20 pyhello-tool /usr/bin/python3 -c "print('hello')"`

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{spawn, status, verb};

/// The binder buffer mapping size for the bench's node-0 client.
const MAP_SIZE: usize = 128 * 1024;
/// The in-view binder device (the seal mounts the per-kennel binderfs here; §7.1).
const DEVICE: &str = "/dev/binderfs/binder";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let count: u32 = match args.next().and_then(|s| s.parse().ok()) {
        Some(n) if n > 0 => n,
        _ => return usage(),
    };
    let Some(template) = args.next() else {
        return usage();
    };
    let Some(direct_cmd) = args.next() else {
        return usage();
    };
    let direct_args: Vec<String> = args.collect();

    match bench(count, &template, &direct_cmd, &direct_args) {
        Ok(()) => {
            // A trailing summary line (after the per-iteration data) confirms a clean run for the
            // policy-suite exit-0 contract; the harness keys on the `direct`/`spawn` lines above it.
            println!("facade-spawn-bench: {count}× direct + {count}× spawn of `{template}` OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("facade-spawn-bench: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: facade-spawn-bench <count> <template> <direct-cmd> [direct-args...]");
    ExitCode::FAILURE
}

/// Run the `direct` loop then the `spawn` loop, printing `<kind> <nanos>` per iteration on stdout.
fn bench(count: u32, template: &str, direct_cmd: &str, direct_args: &[String]) -> io::Result<()> {
    let out = io::stdout();

    // 1. `direct`: fork/exec the payload itself, reaped, count times. Child stdio → null so only the
    //    bench's own `direct <ns>` lines reach stdout.
    for i in 0..count {
        let nth = i.saturating_add(1);
        let t = Instant::now();
        let status = Command::new(direct_cmd)
            .args(direct_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| io::Error::other(format!("direct {nth}: exec `{direct_cmd}`: {e}")))?;
        let ns = t.elapsed().as_nanos();
        if !status.success() {
            return Err(io::Error::other(format!(
                "direct {nth}: `{direct_cmd}` exited {status}"
            )));
        }
        writeln!(&out, "direct {ns}")?;
    }

    // 2. `spawn`: ask kenneld to mint an ephemeral sibling kennel for the same payload, reaped (read
    //    to EOF) before the next, count times.
    let request = spawn::encode_request(template, &[]);
    let fd = OpenOptions::new().read(true).write(true).open(DEVICE)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    for i in 0..count {
        let nth = i.saturating_add(1);
        let t = Instant::now();
        spawn_once(&conn, &request).map_err(|e| io::Error::other(format!("spawn {nth}: {e}")))?;
        let ns = t.elapsed().as_nanos();
        writeln!(&out, "spawn {ns}")?;
    }
    Ok(())
}

/// One SPAWN: transact, then read the channel to EOF — the sibling has run and exited by the time the
/// read returns, which serializes the loop without a timer (the slot is free for the next spawn).
fn spawn_once(conn: &Connection, request: &[u8]) -> io::Result<()> {
    let (reply, mut fds) = conn.transact_with_fds(CONTEXT_MANAGER_HANDLE, verb::SPAWN, request)?;

    let code = reply
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("empty SPAWN reply"))?;
    if code != status::OK {
        return Err(io::Error::other(format!(
            "SPAWN refused: status {code} (grant/pin/eligibility/ceiling — see kenneld audit)"
        )));
    }
    if fds.len() != 2 {
        return Err(io::Error::other(format!(
            "expected 2 channel fds, got {}",
            fds.len()
        )));
    }
    // fds: [0] socketpair local (the sibling's stdin+stdout), [1] stderr pipe read. The stderr end is
    // dropped (these payloads write none); reading the socketpair to EOF waits for the sibling to exit.
    let rpc = UnixStream::from(fds.swap_remove(0));
    drop(fds); // close the stderr read end
    let mut sink = Vec::new();
    (&rpc).read_to_end(&mut sink)?;
    Ok(())
}
