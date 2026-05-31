//! The `kennel` command-line client.
//!
//! Talks to the per-user kenneld daemon over its control socket (socket-activated
//! on first use). Subcommands:
//!
//! ```text
//! kennel run <policy> <name> -- <cmd> [args...]   # run cmd confined, foreground
//! kennel stop <name>                              # stop a running kennel
//! kennel list                                     # list running kennels
//! ```
//!
//! `run` is foreground: the daemon spawns the workload attached to this
//! terminal (the three stdio fds are passed over `SCM_RIGHTS`), and this process
//! blocks until it exits, then exits with the same code.

#![forbid(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use kenneld::control::{self, Request, Response, StartRequest};
use kenneld::socket;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("kennel: {message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<ExitCode, String> {
    match args.split_first() {
        Some((cmd, rest)) if cmd == "run" => run(rest),
        Some((cmd, rest)) if cmd == "stop" => stop(rest),
        Some((cmd, _)) if cmd == "list" => list(),
        _ => Err("usage: kennel run <policy> <name> -- <cmd...> | kennel stop <name> | kennel list".to_owned()),
    }
}

/// `kennel run <policy> <name> -- <argv...>`
fn run(args: &[String]) -> Result<ExitCode, String> {
    // policy, name, then "--", then the command.
    let sep = args.iter().position(|a| a == "--").ok_or("run needs `-- <cmd...>`")?;
    let head = args.get(..sep).unwrap_or(&[]);
    let command = args.get(sep.saturating_add(1)..).unwrap_or(&[]);
    let [policy, name] = head else {
        return Err("usage: kennel run <policy> <name> -- <cmd...>".to_owned());
    };
    if command.is_empty() {
        return Err("no command given after `--`".to_owned());
    }
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let request = Request::Start(StartRequest {
        policy: policy.into(),
        kennel: name.clone(),
        argv: command.to_vec(),
        cwd,
    });

    let mut conn = connect()?;
    // Pass this terminal's stdio so the workload is attached to it.
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let fds: [BorrowedFd<'_>; 3] = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
    send(&conn, &request, &fds)?;

    // First the daemon confirms the launch, then (when the workload exits) the code.
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Started { ctx, pid } => eprintln!("kennel `{name}` started (ctx {ctx}, pid {pid})"),
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Exited { code } => Ok(exit_code(code)),
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `kennel stop <name>`
fn stop(args: &[String]) -> Result<ExitCode, String> {
    let [name] = args else {
        return Err("usage: kennel stop <name>".to_owned());
    };
    let mut conn = connect()?;
    send(&conn, &Request::Stop { kennel: name.clone() }, &[])?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Stopped => {
            eprintln!("kennel `{name}` stopped");
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `kennel list`
fn list() -> Result<ExitCode, String> {
    let mut conn = connect()?;
    send(&conn, &Request::List, &[])?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Listing(kennels) => {
            if kennels.is_empty() {
                println!("no running kennels");
            } else {
                println!("{:<20} {:>5} {:>8}  STATE", "NAME", "CTX", "PID");
                for k in kennels {
                    let state = if k.running { "running" } else { "starting" };
                    println!("{:<20} {:>5} {:>8}  {state}", k.kennel, k.ctx, k.pid);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Connect to the daemon's control socket.
fn connect() -> Result<UnixStream, String> {
    let path = socket::socket_path();
    UnixStream::connect(&path).map_err(|e| {
        format!("cannot reach kenneld at {} ({e}); is the kenneld.socket user unit enabled?", path.display())
    })
}

/// Send `request` (with any `fds`) as one framed `SCM_RIGHTS` message.
fn send(conn: &UnixStream, request: &Request, fds: &[BorrowedFd<'_>]) -> Result<(), String> {
    let mut framed = Vec::new();
    control::write_frame(&mut framed, &request.encode()).map_err(|e| format!("encoding request: {e}"))?;
    kennel_syscall::scm::send_with_fds(conn.as_fd(), &framed, fds).map_err(|e| format!("sending request: {e}"))?;
    Ok(())
}

/// Map a daemon-reported exit code to a process `ExitCode` (clamped to a byte).
fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
