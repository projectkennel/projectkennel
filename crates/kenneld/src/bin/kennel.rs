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
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_policy::settled::InstallConstants;
use kennel_policy::TemplateSource;
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
        Some((cmd, rest)) if cmd == "compile" => compile(rest),
        _ => Err("usage: kennel run <policy> <name> -- <cmd...> | kennel stop <name> | kennel list | kennel compile <policy> [--key K | --unsigned]".to_owned()),
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

// ---- `kennel compile` ----------------------------------------------------------

/// A filesystem-backed [`TemplateSource`]: searches each directory for a flat
/// `<name>@<version>.toml` (the installed layout) and then `<name>/policy.toml`
/// (the in-tree source layout), so the same resolver serves both.
struct FsTemplateSource {
    dirs: Vec<PathBuf>,
}

impl TemplateSource for FsTemplateSource {
    fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
        for dir in &self.dirs {
            let flat = dir.join(format!("{name}@{version}.toml"));
            if let Ok(bytes) = std::fs::read(&flat) {
                return Some(bytes);
            }
            let nested = dir.join(name).join("policy.toml");
            if let Ok(bytes) = std::fs::read(&nested) {
                return Some(bytes);
            }
        }
        None
    }
}

/// `kennel compile <policy> [--output-path P] [--key K] [--unsigned] [--template-dir D]...`
///
/// Resolves a source policy fully and writes a settled policy. Stateless: it never
/// contacts the daemon. Exit codes follow `02-1-cli.md` (3 = validation/resolution,
/// 6 = signature).
fn compile(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_path: Option<&str> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut key_path: Option<&str> = None;
    let mut unsigned = false;
    let mut template_dirs: Vec<PathBuf> = Vec::new();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--output-path" => {
                output_path = Some(it.next().ok_or("--output-path needs a value")?.into());
            }
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--unsigned" => unsigned = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value => {
                if policy_path.is_some() {
                    return Err("only one <policy> may be given".to_owned());
                }
                policy_path = Some(value);
            }
        }
    }

    let policy_path = policy_path.ok_or(
        "usage: kennel compile <policy> [--output-path P] [--key K | --unsigned] [--template-dir D]...",
    )?;
    if key_path.is_some() && unsigned {
        return Err("--key and --unsigned are mutually exclusive".to_owned());
    }
    if key_path.is_none() && !unsigned {
        return Err("provide --key <path> to sign, or --unsigned for a development build".to_owned());
    }
    add_default_template_dirs(&mut template_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    let entry = match kennel_policy::parse_source(&bytes) {
        Ok(entry) => entry,
        Err(e) => {
            eprintln!("kennel: {e}");
            return Ok(ExitCode::from(3));
        }
    };

    // Installation constants are fixed at install time; until an install-config
    // reader exists they take the documented defaults (tag 42, ULA fd00::).
    let install = InstallConstants { tag: 42, ula_gid: "fd00::".to_owned() };
    let source = FsTemplateSource { dirs: template_dirs };
    let policy =
        match kennel_policy::compile(&entry, &source, &install, env!("CARGO_PKG_VERSION")) {
            Ok(policy) => policy,
            Err(e) => {
                eprintln!("kennel: {e}");
                return Ok(ExitCode::from(policy_error_code(&e)));
            }
        };

    let doc = if unsigned {
        kennel_policy::seal_unsigned(&policy)
    } else {
        let key = load_signing_key(key_path.ok_or("internal: key path lost")?)?;
        kennel_policy::sign_settled(&policy, &key).map_err(|e| format!("signing: {e}"))?
    };
    let out_bytes = kennel_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))?;
    let out = output_path.unwrap_or_else(|| default_settled_path(policy_path, &policy.name));
    std::fs::write(&out, &out_bytes).map_err(|e| format!("writing {}: {e}", out.display()))?;

    let note = if unsigned { " (unsigned development build)" } else { "" };
    eprintln!("compiled `{}` -> {}{note}", policy.name, out.display());
    Ok(ExitCode::SUCCESS)
}

/// Map a compile-time [`kennel_policy::PolicyError`] to a CLI exit code (`02-1`).
const fn policy_error_code(err: &kennel_policy::PolicyError) -> u8 {
    use kennel_policy::PolicyError as E;
    match err {
        E::Signature(_) => 6,
        E::Parse(_)
        | E::Canonical(_)
        | E::UnsupportedSchemaVersion { .. }
        | E::InvariantViolations(_)
        | E::SourceValidation(_)
        | E::Resolution(_)
        | E::Translation(_) => 3,
    }
}

/// Append the default template search directories (user, then system).
fn add_default_template_dirs(dirs: &mut Vec<PathBuf>) {
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config/kennel/templates"));
    }
    dirs.push(PathBuf::from("/etc/kennel/templates"));
}

/// Default settled-policy path: `<policy-dir>/<name>.settled.toml`.
fn default_settled_path(policy_path: &str, name: &str) -> PathBuf {
    let dir = Path::new(policy_path).parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("{name}.settled.toml"))
}

/// Load a signing key from a file holding the base64 of a 32-byte Ed25519 seed.
/// The key id is the file stem, mirroring the `.pub` trust-store convention.
fn load_signing_key(path: &str) -> Result<kennel_policy::SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading key {path}: {e}"))?;
    let seed = kennel_policy::b64::decode(text.trim().as_bytes())
        .ok_or_else(|| format!("key {path} is not valid base64"))?;
    let key_id = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("cannot derive a key id from {path}"))?;
    kennel_policy::SigningKey::from_seed(key_id, &seed)
        .map_err(|e| format!("loading key {path}: {e}"))
}
