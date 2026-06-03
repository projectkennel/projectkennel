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
        Some((cmd, rest)) if cmd == "validate" => validate(rest),
        Some((cmd, rest)) if cmd == "sign" => sign(rest),
        _ => Err("usage: kennel run <policy> <name> -- <cmd...> | kennel stop <name> | kennel list | kennel compile <policy> [--key K | --unsigned] | kennel validate <policy> | kennel sign <template> --key K".to_owned()),
    }
}

/// `kennel run <policy> <name> -- <argv...>`
fn run(args: &[String]) -> Result<ExitCode, String> {
    // policy, name, then "--", then the command.
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("run needs `-- <cmd...>`")?;
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
        Response::Started { ctx, pid } => {
            eprintln!("kennel `{name}` started (ctx {ctx}, pid {pid})");
        }
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
    send(
        &conn,
        &Request::Stop {
            kennel: name.clone(),
        },
        &[],
    )?;
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
        format!(
            "cannot reach kenneld at {} ({e}); is the kenneld.socket user unit enabled?",
            path.display()
        )
    })
}

/// Send `request` (with any `fds`) as one framed `SCM_RIGHTS` message.
fn send(conn: &UnixStream, request: &Request, fds: &[BorrowedFd<'_>]) -> Result<(), String> {
    let mut framed = Vec::new();
    control::write_frame(&mut framed, &request.encode())
        .map_err(|e| format!("encoding request: {e}"))?;
    kennel_syscall::scm::send_with_fds(conn.as_fd(), &framed, fds)
        .map_err(|e| format!("sending request: {e}"))?;
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
// allow: one cohesive arg-parse + compile + write/sign sequence for the CLI subcommand.
#[allow(clippy::too_many_lines)]
fn compile(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_path: Option<&str> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut key_path: Option<&str> = None;
    let mut unsigned = false;
    let mut require_signed = false;
    let mut no_lock = false;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--output-path" => {
                output_path = Some(it.next().ok_or("--output-path needs a value")?.into());
            }
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--unsigned" => unsigned = true,
            "--require-signed" => require_signed = true,
            "--no-lock" => no_lock = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => {
                trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into());
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
        return Err(
            "provide --key <path> to sign, or --unsigned for a development build".to_owned(),
        );
    }
    add_default_template_dirs(&mut template_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;

    // Installation constants are fixed at install time; until an install-config
    // reader exists they take the documented defaults (tag 42, ULA fd00::).
    let install = InstallConstants {
        tag: 42,
        ula_gid: "fd00::".to_owned(),
    };
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let version = env!("CARGO_PKG_VERSION");

    // Build the trust context: `--require-signed` refuses unsigned templates and
    // verifies against the trust store (`--trust-dir`, else the default key dirs);
    // otherwise unsigned templates resolve (development), still verifying any present
    // signature against whatever keys are loaded.
    add_default_trust_dirs(&mut trust_dirs);
    let keys = load_trust_store(&trust_dirs)?;
    let trust = if require_signed {
        kennel_policy::Trust::require(&keys)
    } else {
        kennel_policy::Trust::allow_unsigned(Some(&keys))
    };

    let compiled = match build_settled(&bytes, &source, &trust, &install, version) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("kennel: {e}");
            return Ok(ExitCode::from(policy_error_code(&e)));
        }
    };
    let policy = &compiled.policy;

    let out = output_path.unwrap_or_else(|| default_settled_path(policy_path, &policy.name));

    // Byte-pin the resolved references: check the fresh lockfile against any prior
    // `<name>.lock` beside the output, then (re)write it. A re-tagged/re-signed
    // reference is an integrity failure (exit 6).
    if !no_lock {
        let lock_path = lock_path_for(&out, &policy.name);
        if let Ok(prev_bytes) = std::fs::read(&lock_path) {
            let previous = kennel_policy::Lockfile::parse(&prev_bytes)
                .map_err(|e| format!("reading {}: {e}", lock_path.display()))?;
            if let Err(e) = compiled.lock.verify_against(&previous) {
                eprintln!("kennel: {e}");
                return Ok(ExitCode::from(6));
            }
        }
        let lock_bytes = compiled
            .lock
            .to_bytes()
            .map_err(|e| format!("lockfile: {e}"))?;
        std::fs::write(&lock_path, &lock_bytes)
            .map_err(|e| format!("writing {}: {e}", lock_path.display()))?;
    }

    let doc = if unsigned {
        kennel_policy::seal_unsigned(policy)
    } else {
        let key = load_signing_key(key_path.ok_or("internal: key path lost")?)?;
        kennel_policy::sign_settled(policy, &key).map_err(|e| format!("signing: {e}"))?
    };
    let out_bytes = kennel_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))?;
    std::fs::write(&out, &out_bytes).map_err(|e| format!("writing {}: {e}", out.display()))?;

    let note = if unsigned {
        " (unsigned development build)"
    } else {
        ""
    };
    eprintln!("compiled `{}` -> {}{note}", policy.name, out.display());
    Ok(ExitCode::SUCCESS)
}

/// The `<name>.lock` path beside the settled output.
fn lock_path_for(output: &Path, name: &str) -> PathBuf {
    output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{name}.lock"))
}

/// Compile policy `bytes` (a template/direct policy parses as a `SourcePolicy`; a
/// leaf in the delta form does not, so fall back to the leaf parser). On a
/// double parse failure the source parse error is returned.
fn build_settled(
    bytes: &[u8],
    source: &FsTemplateSource,
    trust: &kennel_policy::Trust<'_>,
    install: &InstallConstants,
    version: &str,
) -> Result<kennel_policy::Compiled, kennel_policy::PolicyError> {
    match kennel_policy::parse_source(bytes) {
        Ok(entry) => kennel_policy::compile(&entry, source, trust, install, version),
        Err(source_err) => kennel_policy::parse_leaf(bytes).map_or(Err(source_err), |leaf| {
            kennel_policy::compile_leaf(&leaf, source, trust, install, version)
        }),
    }
}

/// `kennel validate <policy> [--template-dir D] [--require-signed] [--trust-dir D]`
///
/// Resolve and check a policy (chain, signatures, deltas, includes, invariants)
/// without emitting a settled artefact. Exit 0 if valid; otherwise the same code
/// `compile` would return.
fn validate(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_path: Option<&str> = None;
    let mut require_signed = false;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--require-signed" => require_signed = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if policy_path.is_none() => policy_path = Some(value),
            _ => return Err("only one <policy> may be given".to_owned()),
        }
    }
    let policy_path = policy_path
        .ok_or("usage: kennel validate <policy> [--template-dir D] [--require-signed]")?;
    add_default_template_dirs(&mut template_dirs);
    add_default_trust_dirs(&mut trust_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    let install = InstallConstants {
        tag: 42,
        ula_gid: "fd00::".to_owned(),
    };
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let keys = load_trust_store(&trust_dirs)?;
    let trust = if require_signed {
        kennel_policy::Trust::require(&keys)
    } else {
        kennel_policy::Trust::allow_unsigned(Some(&keys))
    };

    match build_settled(&bytes, &source, &trust, &install, env!("CARGO_PKG_VERSION")) {
        Ok(compiled) => {
            eprintln!(
                "valid: `{}` resolves cleanly ({} references, {} deferred substitutions)",
                compiled.policy.name,
                compiled.lock.entries.len(),
                compiled.policy.deferred_substitutions.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("invalid: {e}");
            Ok(ExitCode::from(policy_error_code(&e)))
        }
    }
}

/// `kennel sign <template> --key <key> [--output <path>]`
///
/// Sign a source template/fragment with an ed25519 key, **appending** a
/// `[signature]` block to the file so its comments are preserved (the signature
/// covers the canonical re-serialisation, not the raw bytes). Prints the public key
/// to install in the trust store as `<key_id>.pub`. Leaf policies may stay unsigned.
fn sign(args: &[String]) -> Result<ExitCode, String> {
    let mut path: Option<&str> = None;
    let mut key_path: Option<&str> = None;
    let mut output: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--output" => output = Some(it.next().ok_or("--output needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if path.is_none() => path = Some(value),
            _ => return Err("only one <template> may be given".to_owned()),
        }
    }
    let path = path.ok_or("usage: kennel sign <template> --key <key> [--output <path>]")?;
    let key_path = key_path.ok_or("sign needs --key <path>")?;

    let bytes = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    let policy = kennel_policy::parse_source(&bytes).map_err(|e| {
        format!("{path} is not a signable source template/fragment ({e}); leaf policies may stay unsigned")
    })?;
    if policy.signature.is_some() {
        return Err(format!(
            "{path} already carries a [signature]; remove it before re-signing"
        ));
    }

    let key = load_signing_key(key_path)?;
    let signed = kennel_policy::sign_source(&policy, &key).map_err(|e| format!("signing: {e}"))?;
    let env = signed.signature.ok_or("internal: signature not produced")?;
    // Append the signature as a new top-level table, preserving the original text.
    let block = format!(
        "\n[signature]\nalgorithm = \"{}\"\nkey_id = \"{}\"\nsignature = \"{}\"\n",
        env.algorithm, env.key_id, env.signature
    );
    let mut out_bytes = bytes;
    out_bytes.extend_from_slice(block.as_bytes());
    let out = output.unwrap_or_else(|| PathBuf::from(path));
    std::fs::write(&out, &out_bytes).map_err(|e| format!("writing {}: {e}", out.display()))?;

    eprintln!("signed {} with key `{}`", out.display(), key.key_id());
    eprintln!(
        "install this public key in the trust store as `{}.pub`:\n{}",
        key.key_id(),
        kennel_policy::b64::encode(&key.public_key_bytes())
    );
    Ok(ExitCode::SUCCESS)
}

/// Map a compile-time [`kennel_policy::PolicyError`] to a CLI exit code (`02-1`).
const fn policy_error_code(err: &kennel_policy::PolicyError) -> u8 {
    use kennel_policy::PolicyError as E;
    match err {
        E::Signature(_) | E::LockMismatch(_) => 6,
        E::Parse(_)
        | E::Canonical(_)
        | E::UnsupportedSchemaVersion { .. }
        | E::InvariantViolations(_)
        | E::SourceValidation(_)
        | E::Resolution(_)
        | E::Translation(_)
        | E::IncludeConflict(_) => 3,
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
    let dir = Path::new(policy_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    dir.join(format!("{name}.settled.toml"))
}

/// Append the default trust-store directories (user, then system).
fn add_default_trust_dirs(dirs: &mut Vec<PathBuf>) {
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config/kennel/keys"));
    }
    dirs.push(PathBuf::from("/etc/kennel/keys"));
}

/// Load a trust store: every `<key_id>.pub` (base64 32-byte public key) under each
/// directory. Missing directories are skipped; a malformed key file is an error.
fn load_trust_store(dirs: &[PathBuf]) -> Result<kennel_policy::KeySet, String> {
    let mut keys = kennel_policy::KeySet::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            let Some(key_id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            keys.insert_b64(key_id, contents.trim())
                .map_err(|e| format!("key {}: {e}", path.display()))?;
        }
    }
    Ok(keys)
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
