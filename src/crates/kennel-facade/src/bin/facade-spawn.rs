//! `facade-spawn` — the usable in-kennel `SPAWN` client (`02-10` §7.12).
//!
//! Where `facade-spawn-probe`/`-bench` are fixed test drivers, this is the client a confined workload
//! (an agent) actually uses to reach its delegated-spawn capability:
//!
//! - **`facade-spawn caps`** interrogates this kennel's `[spawn]` grant (`verb::SPAWN_QUERY`): which
//!   `name@version` templates it may instantiate, the mutable manifest fields it may write (narrowed to
//!   this requester) and their bounds, and the `max_instances`/live ceiling. So the workload discovers
//!   *what it may ask for* instead of probing `SPAWN` by trial.
//! - **`facade-spawn run <template> [field=value]…`** transacts `verb::SPAWN` for the chosen template,
//!   applying the given mutable-field writes, then wires **this process's stdio to the sibling's
//!   channel** — our stdin → the tool's stdin, the tool's stdout → our stdout, the tool's stderr → our
//!   stderr — so the operator/agent talks to the spawned tool directly. `kenneld` brokers the fds and
//!   steps out of the byte path; no host privilege, no JSON in the daemon.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{spawn, status, verb};

/// The binder buffer mapping size for the node-0 client.
const MAP_SIZE: usize = 128 * 1024;
/// The in-view binder device (the seal mounts the per-kennel binderfs here; §7.1).
const DEVICE: &str = "/dev/binderfs/binder";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("caps") => caps(),
        Some("run") => run(args.get(1..).unwrap_or(&[])),
        _ => {
            eprintln!("usage: facade-spawn <caps | run <template@version> [field=value]…>");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("facade-spawn: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Open a node-0 client connection over the in-view binder device.
fn connect() -> io::Result<Connection> {
    let fd = OpenOptions::new().read(true).write(true).open(DEVICE)?;
    Connection::open(fd.into(), MAP_SIZE)
}

/// `caps` — print this kennel's `[spawn]` grant listing (the read-only `SPAWN_QUERY`).
fn caps() -> io::Result<ExitCode> {
    let conn = connect()?;
    // A plain byte reply (no fds), so the plain transaction decode — not the fd-passing one.
    let reply = conn.transact(CONTEXT_MANAGER_HANDLE, verb::SPAWN_QUERY, &[])?;
    let (status_byte, body) = reply
        .split_first()
        .ok_or_else(|| io::Error::other("empty SPAWN_QUERY reply"))?;
    print!("{}", String::from_utf8_lossy(body));
    io::stdout().flush()?;
    if *status_byte == status::OK {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

/// `run <template> [field=value]…` — spawn the template with the given mutable-field patch and connect
/// this process's stdio to the sibling's channel.
fn run(args: &[String]) -> io::Result<ExitCode> {
    let (template, rest) = args.split_first().ok_or_else(|| {
        io::Error::other("usage: facade-spawn run <template@version> [field=value]…")
    })?;
    let mut patch: Vec<(&str, &str)> = Vec::with_capacity(rest.len());
    for a in rest {
        let pair = a
            .split_once('=')
            .ok_or_else(|| io::Error::other(format!("`{a}` is not field=value")))?;
        patch.push(pair);
    }
    let request = spawn::encode_request(template, &patch);

    let conn = connect()?;
    let (reply, mut fds) = conn.transact_with_fds(CONTEXT_MANAGER_HANDLE, verb::SPAWN, &request)?;
    let code = reply
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("empty SPAWN reply"))?;
    if code != status::OK {
        return Err(io::Error::other(format!(
            "SPAWN refused: status {code} — run `facade-spawn caps` to see what this grant allows"
        )));
    }
    if fds.len() != 2 {
        return Err(io::Error::other(format!(
            "expected 2 channel fds in the reply, got {}",
            fds.len()
        )));
    }
    // fds: [0] socketpair local (the tool's stdin+stdout), [1] the tool's stderr pipe read end.
    let rpc = UnixStream::from(fds.swap_remove(0));
    let stderr_read = fds.swap_remove(0);

    // The tool's stderr → our stderr.
    let mut stderr_in = std::fs::File::from(stderr_read);
    let err_pump = thread::spawn(move || {
        let _ = io::copy(&mut stderr_in, &mut io::stderr());
    });

    // Our stdin → the tool's stdin (the socketpair); half-close on EOF so a `cat`-like tool sees it.
    let mut rpc_w = rpc.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut rpc_w);
        let _ = rpc_w.shutdown(Shutdown::Write);
    });

    // The tool's stdout (the socketpair) → our stdout. Returns when the tool closes its end (exits).
    let mut rpc_r = rpc;
    io::copy(&mut rpc_r, &mut io::stdout().lock())?;
    let _ = err_pump.join();
    Ok(ExitCode::SUCCESS)
}
