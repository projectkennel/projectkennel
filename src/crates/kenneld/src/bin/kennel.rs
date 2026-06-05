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
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
        Some((cmd, rest)) if cmd == "keygen" => keygen(rest),
        Some((cmd, rest)) if cmd == "audit" => audit(rest),
        _ => Err("usage: kennel run <policy> <name> -- <cmd...> | kennel stop <name> | kennel list | kennel compile <policy> [--key K | --unsigned] | kennel validate <policy> | kennel sign <template> --key K | kennel keygen <key-id> [--dir D] [--force] | kennel audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]".to_owned()),
    }
}

/// `kennel run <policy> <name> [--key K] [--template-dir D]... [--trust-dir D]... -- <argv...>`
///
/// `<policy>` is either a pre-compiled **settled** artefact (used as-is, the
/// production path) or a **source** policy (template/leaf), which is compiled and
/// signed *in memory* before the run — the §9.10 local-dev loop, so an author need
/// not run `kennel compile` between edits. The in-memory build needs `--key` (kenneld
/// verifies the settled signature against its trust store); the settled bytes are
/// written to a short-lived temp file that is removed when the run returns.
fn run(args: &[String]) -> Result<ExitCode, String> {
    // <head...> then "--" then the command.
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("run needs `-- <cmd...>`")?;
    let head = args.get(..sep).unwrap_or(&[]);
    let command = args.get(sep.saturating_add(1)..).unwrap_or(&[]);

    let mut policy_path: Option<&str> = None;
    let mut name: Option<&str> = None;
    let mut key_path: Option<&str> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut it = head.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if policy_path.is_none() => policy_path = Some(v),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let policy_path = policy_path
        .ok_or("usage: kennel run <policy> <name> [--key K] [--template-dir D]... -- <cmd...>")?;
    let name = name.ok_or("usage: kennel run <policy> <name> -- <cmd...>")?;
    if command.is_empty() {
        return Err("no command given after `--`".to_owned());
    }

    // Auto-compile dev path: a source policy is compiled+signed in memory; a settled
    // artefact is passed straight through. `_temp` keeps the on-disk settled file
    // alive for the daemon to read, and removes it when this function returns.
    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    // Held only for its `Drop` (removes the temp settled file when the run returns);
    // never read, hence the allow.
    #[allow(clippy::collection_is_never_read)]
    let _temp;
    let effective_policy: PathBuf = if is_source_policy(&bytes) {
        let key_path = key_path.ok_or(
            "`<policy>` is a source policy: pass `--key <path>` to compile-and-sign it in \
             memory for this run, or pre-compile it with `kennel compile`",
        )?;
        add_default_template_dirs(&mut template_dirs);
        add_default_trust_dirs(&mut trust_dirs);
        let source = FsTemplateSource {
            dirs: template_dirs,
        };
        let keys = load_trust_store(&trust_dirs)?;
        let trust = kennel_policy::Trust::allow_unsigned(Some(&keys));
        let compiled = build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
            .map_err(|e| format!("compiling {policy_path}: {e}"))?;
        print_warnings(&compiled.warnings);
        let key = load_signing_key(key_path)?;
        let doc = kennel_policy::sign_settled(&compiled.policy, &key)
            .map_err(|e| format!("signing: {e}"))?;
        let out = kennel_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))?;
        let temp = TempSettled::write(name, &out)?;
        let path = temp.path().to_path_buf();
        eprintln!("kennel: compiled `{policy_path}` in memory for this run");
        _temp = Some(temp);
        path
    } else {
        _temp = None;
        PathBuf::from(policy_path)
    };

    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let request = Request::Start(StartRequest {
        policy: effective_policy,
        kennel: name.to_owned(),
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

/// The per-class JSONL file stems the audit CLI knows about (`02-3` §Sink: JSONL).
const AUDIT_STEMS: &[&str] = &[
    "network",
    "filesystem",
    "exec",
    "unix",
    "dbus",
    "priv",
    "lifecycle",
];

/// `kennel audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]`
///
/// Read the per-kennel JSONL audit files (`$XDG_STATE_HOME/kennel/<name>/<class>.jsonl`,
/// §02-3) directly — no daemon round-trip, queryable from a fresh shell. `--resource`
/// limits to one class (`net`/`fs`/`exec`/`unix`/`dbus`/`priv`/`lifecycle`); `--since`
/// keeps only events newer than e.g. `1h`/`30m`/`2d`; `--novel-only` collapses repeats
/// (lines identical but for their timestamp) to their first occurrence; `--follow`
/// streams new events; `--print-journalctl-command` emits the equivalent `journalctl`
/// invocation instead (for journald-only deployments).
fn audit(args: &[String]) -> Result<ExitCode, String> {
    let mut kennel: Option<&str> = None;
    let mut resource: Option<&str> = None;
    let mut since: Option<&str> = None;
    let mut novel_only = false;
    let mut follow = false;
    let mut journalctl = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--resource" => resource = Some(it.next().ok_or("--resource needs a value")?),
            "--since" => since = Some(it.next().ok_or("--since needs a value")?),
            "--novel-only" => novel_only = true,
            "--follow" => follow = true,
            "--print-journalctl-command" => journalctl = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if kennel.is_none() => kennel = Some(v),
            _ => return Err("only one <name> may be given".to_owned()),
        }
    }
    let kennel = kennel.ok_or("usage: kennel audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]")?;
    // The name becomes a directory component — refuse path traversal.
    if kennel.is_empty() || kennel.contains('/') || kennel.contains("..") {
        return Err(format!("invalid kennel name `{kennel}`"));
    }
    let stem = match resource {
        None => None,
        Some(tok) => Some(resource_stem(tok).ok_or_else(|| {
            format!("unknown --resource `{tok}` (net/fs/exec/unix/dbus/priv/lifecycle)")
        })?),
    };

    if journalctl {
        print_journalctl_command(kennel, resource, since);
        return Ok(ExitCode::SUCCESS);
    }

    // The `--since` cutoff as an RFC3339 string directly comparable to each line's
    // `ts` (the writer emits RFC3339-UTC, which is lexically ordered).
    let cutoff = match since {
        None => None,
        Some(s) => {
            let secs = parse_duration_secs(s)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock: {e}"))?
                .as_secs();
            let cut = i64::try_from(now.saturating_sub(secs)).unwrap_or(i64::MAX);
            Some(kennel_audit::format_rfc3339_micros(cut, 0))
        }
    };

    let dir = audit_dir(kennel);
    let files: Vec<PathBuf> = stem.map_or_else(
        || {
            AUDIT_STEMS
                .iter()
                .map(|s| dir.join(format!("{s}.jsonl")))
                .collect()
        },
        |s| vec![dir.join(format!("{s}.jsonl"))],
    );
    let files: Vec<PathBuf> = files.into_iter().filter(|p| p.exists()).collect();
    if files.is_empty() {
        eprintln!(
            "kennel: no audit logs for `{kennel}` under {} (none yet, or a different sink)",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    run_audit(&files, cutoff.as_deref(), novel_only, follow)
        .map_err(|e| format!("reading audit logs: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

/// The state-home directory a kennel's JSONL audit files live under (§02-3):
/// `$XDG_STATE_HOME/kennel/<name>/`, falling back to `~/.local/state/kennel/<name>/`.
fn audit_dir(kennel: &str) -> PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME").map_or_else(
        || {
            std::env::var_os("HOME")
                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                .join(".local/state")
        },
        PathBuf::from,
    );
    state.join("kennel").join(kennel)
}

/// Map a `--resource` token to its JSONL file stem, or `None` if unknown.
fn resource_stem(token: &str) -> Option<&'static str> {
    AUDIT_STEMS
        .iter()
        .copied()
        .zip(["net", "fs", "exec", "unix", "dbus", "priv", "lifecycle"])
        .find_map(|(stem, tok)| (tok == token).then_some(stem))
}

/// Parse a human duration (`90s`/`30m`/`2h`/`7d`, bare number = seconds) to seconds.
fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = [('s', 1u64), ('m', 60), ('h', 3_600), ('d', 86_400)]
        .into_iter()
        .find_map(|(suffix, mult)| s.strip_suffix(suffix).map(|n| (n, mult)))
        .unwrap_or((s, 1));
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid --since duration `{s}` (try 90s, 30m, 2h, 7d)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("--since duration `{s}` overflows"))
}

/// Print the `journalctl` invocation equivalent to this query, for journald-only
/// deployments (the file sink is the default; this is the escape hatch, §02-3).
fn print_journalctl_command(kennel: &str, resource: Option<&str>, since: Option<&str>) {
    use std::fmt::Write as _;
    let mut cmd = format!("journalctl --user KENNEL_KENNEL={kennel}");
    if let Some(r) = resource {
        let _ = write!(cmd, " KENNEL_RESOURCE={r}");
    }
    if let Some(s) = since {
        let _ = write!(cmd, " --since \"{s} ago\"");
    }
    println!("{cmd}");
}

/// Extract the `ts` field's value from a JSONL line (`"ts":"…"`), if present.
fn extract_ts(line: &str) -> Option<&str> {
    let start = line.find(r#""ts":""#)?.checked_add(6)?;
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// A dedup key for `--novel-only`: the line with its `ts` *value* removed, so two
/// events identical but for their timestamp collapse to one.
fn novel_key(line: &str) -> String {
    if let Some(s) = line.find(r#""ts":""#) {
        if let Some(val_start) = s.checked_add(6) {
            if let Some(rest) = line.get(val_start..) {
                if let Some(end) = rest.find('"') {
                    let mut key = String::with_capacity(line.len());
                    key.push_str(line.get(..val_start).unwrap_or(""));
                    key.push_str(rest.get(end..).unwrap_or(""));
                    return key;
                }
            }
        }
    }
    line.to_owned()
}

/// Read, filter, sort-by-`ts`, optionally dedup, and print the audit `files`; with
/// `follow`, then poll for appended events forever. Lines are JSON objects, printed
/// verbatim. `cutoff` (if set) drops events older than it.
fn run_audit(
    files: &[PathBuf],
    cutoff: Option<&str>,
    novel_only: bool,
    follow: bool,
) -> io::Result<()> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut offsets: Vec<u64> = vec![0; files.len()];

    emit_batch(files, &mut offsets, cutoff, novel_only, &mut seen)?;
    if !follow {
        return Ok(());
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        emit_batch(files, &mut offsets, cutoff, novel_only, &mut seen)?;
    }
}

/// Read everything appended to each file past its recorded offset, filter/sort/dedup
/// it, print it, and advance the offsets. A file that shrank (rotation) is re-read
/// from the start.
fn emit_batch(
    files: &[PathBuf],
    offsets: &mut [u64],
    cutoff: Option<&str>,
    novel_only: bool,
    seen: &mut std::collections::HashSet<String>,
) -> io::Result<()> {
    use std::io::Write as _;
    let mut batch: Vec<String> = Vec::new();
    for (path, offset) in files.iter().zip(offsets.iter_mut()) {
        let (lines, new_len) = read_lines_from(path, *offset)?;
        *offset = new_len;
        batch.extend(lines);
    }
    // Chronological across the (interleaved) class files.
    batch.sort_by(|a, b| extract_ts(a).cmp(&extract_ts(b)));
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in batch {
        if let Some(cut) = cutoff {
            if extract_ts(&line).is_some_and(|ts| ts < cut) {
                continue;
            }
        }
        if novel_only && !seen.insert(novel_key(&line)) {
            continue;
        }
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// Read the lines of `path` starting at byte `offset`; return them and the file's new
/// length. A missing file yields no lines; a file shorter than `offset` (rotated) is
/// re-read from 0.
fn read_lines_from(path: &Path, offset: u64) -> io::Result<(Vec<String>, u64)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let start = if len < offset { 0 } else { offset };
    file.seek(SeekFrom::Start(start))?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let lines = text.lines().map(str::to_owned).collect();
    Ok((lines, len))
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

    // No installation constants here: `<tag>`/`<gid>` are deferred to spawn, where
    // the daemon fills them from the user's scope (`/etc/kennel/subkennel`). The CLI
    // neither knows nor needs them.
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

    let compiled = match build_settled(&bytes, &source, &trust, version) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("kennel: {e}");
            return Ok(ExitCode::from(policy_error_code(&e)));
        }
    };
    print_warnings(&compiled.warnings);
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

/// Whether `bytes` is a **source** policy (a template or a leaf) rather than a
/// compiled settled artefact. A source policy parses as a `SourcePolicy` or
/// `LeafPolicy`; a settled document carries fields (`settled_schema_version`,
/// `[signature]`, …) those `deny_unknown_fields` schemas reject, so the two parses
/// are mutually exclusive. Used by `kennel run` to decide whether to compile.
fn is_source_policy(bytes: &[u8]) -> bool {
    kennel_policy::parse_source(bytes).is_ok() || kennel_policy::parse_leaf(bytes).is_ok()
}

/// A short-lived on-disk settled policy produced by `kennel run`'s in-memory
/// compile. The daemon reads the path during bring-up; the file is removed when this
/// guard drops (the run returns or errors out).
struct TempSettled {
    path: PathBuf,
}

impl TempSettled {
    /// Write `bytes` to a unique, safe-owned path (under `$XDG_RUNTIME_DIR` when set,
    /// else the temp dir) keyed by kennel name and pid.
    fn write(name: &str, bytes: &[u8]) -> Result<Self, String> {
        let dir =
            std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let path = dir.join(format!("kennel-run-{name}-{}.settled", std::process::id()));
        std::fs::write(&path, bytes)
            .map_err(|e| format!("writing temp settled policy {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempSettled {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Print compile-time policy warnings to stderr, one `kennel: warning:` line each.
///
/// These are footgun grants the policy is allowed to keep (e.g. shimming a real
/// ssh-agent socket via `[[unix.allow]]`) — loud, but not fatal. `kenneld` re-derives
/// and logs the same warnings at spawn, so an operator who skips the compile step
/// still sees them.
fn print_warnings(warnings: &[String]) {
    for w in warnings {
        eprintln!("kennel: warning: {w}");
    }
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
    version: &str,
) -> Result<kennel_policy::Compiled, kennel_policy::PolicyError> {
    match kennel_policy::parse_source(bytes) {
        Ok(entry) => kennel_policy::compile(&entry, source, trust, version),
        Err(source_err) => kennel_policy::parse_leaf(bytes).map_or(Err(source_err), |leaf| {
            kennel_policy::compile_leaf(&leaf, source, trust, version)
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
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let keys = load_trust_store(&trust_dirs)?;
    let trust = if require_signed {
        kennel_policy::Trust::require(&keys)
    } else {
        kennel_policy::Trust::allow_unsigned(Some(&keys))
    };

    match build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION")) {
        Ok(compiled) => {
            print_warnings(&compiled.warnings);
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

/// `kennel keygen <key-id> [--dir DIR] [--force]`
///
/// Generate an Ed25519 signing key and write it into the user key dir (default
/// `$XDG_CONFIG_HOME/kennel/keys`, else `~/.config/kennel/keys`). `<key-id>.key` is
/// the private seed (mode `0600`) you pass to `--key` (`sign`/`compile`/`run`);
/// `<key-id>.pub` is the public key the daemon must trust. Refuses to overwrite an
/// existing seed without `--force` — replacing a signing key invalidates everything
/// signed with the old one. The `<key-id>` is both the filename and the signature
/// `key_id`, so it is restricted to a safe character set.
fn keygen(args: &[String]) -> Result<ExitCode, String> {
    let mut key_id: Option<&str> = None;
    let mut dir: Option<PathBuf> = None;
    let mut force = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dir" => dir = Some(it.next().ok_or("--dir needs a value")?.into()),
            "--force" => force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if key_id.is_none() => key_id = Some(value),
            _ => return Err("only one <key-id> may be given".to_owned()),
        }
    }
    let key_id = key_id.ok_or("usage: kennel keygen <key-id> [--dir DIR] [--force]")?;
    if !is_valid_key_id(key_id) {
        return Err(format!(
            "invalid key id `{key_id}`: 1-64 chars of letters, digits, `.`, `-`, `_` \
             (it is both a filename and the signature key_id)"
        ));
    }
    let dir = dir.unwrap_or_else(default_key_dir);
    let key_path = dir.join(format!("{key_id}.key"));
    let pub_path = dir.join(format!("{key_id}.pub"));
    if key_path.exists() && !force {
        return Err(format!(
            "{} already exists; refusing to overwrite a signing key \
             (pass --force to replace it, which invalidates everything signed with the old key)",
            key_path.display()
        ));
    }

    // 32 bytes from the OS CSPRNG (`getrandom`) → the Ed25519 seed.
    let mut seed = [0u8; 32];
    kennel_syscall::random::fill(&mut seed).map_err(|e| format!("reading OS randomness: {e}"))?;
    let key = kennel_policy::SigningKey::from_seed(key_id, &seed)
        .map_err(|e| format!("deriving key: {e}"))?;

    // The key dir holds secret seeds: 0700.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_secret(&key_path, &kennel_policy::b64::encode(&seed), 0o600)
        .map_err(|e| format!("writing {}: {e}", key_path.display()))?;
    write_secret(
        &pub_path,
        &kennel_policy::b64::encode(&key.public_key_bytes()),
        0o644,
    )
    .map_err(|e| format!("writing {}: {e}", pub_path.display()))?;

    eprintln!("generated Ed25519 signing key `{key_id}`:");
    eprintln!(
        "  private seed : {}   (0600 — keep secret; pass to --key)",
        key_path.display()
    );
    eprintln!("  public key   : {}   (0644)", pub_path.display());
    eprintln!();
    eprintln!("To let the daemon trust policies you sign with this key, install the *public* key");
    eprintln!("into the root-owned system trust store, then compile/run:");
    eprintln!(
        "  sudo install -m 0644 {} /etc/kennel/keys/{key_id}.pub",
        pub_path.display()
    );
    eprintln!(
        "  kennel run <policy> <name> --key {} -- <cmd...>",
        key_path.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// A key id is both a filename and the signature `key_id`; restrict it to a safe,
/// portable set so it cannot escape the key dir or smuggle odd bytes into a policy.
fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The default user key directory: `$XDG_CONFIG_HOME/kennel/keys`, else
/// `~/.config/kennel/keys` (matching the CLI's default key search).
fn default_key_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("kennel").join("keys")
}

/// Write base64 `text` (plus a trailing newline) to `path`, creating it with `mode`
/// and enforcing `mode` even if it already existed (`.mode` only applies on create).
fn write_secret(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(text.as_bytes())?;
    f.write_all(b"\n")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
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

/// Append the default template search directories: the user `config.toml`'s
/// `template_dirs` if set, else the built-in default (user config dir, then
/// system). A malformed user config falls back to the built-in default.
fn add_default_template_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_config::User::load()
            .unwrap_or_default()
            .template_dirs(),
    );
}

/// Default settled-policy path: `<policy-dir>/<name>.settled.toml`.
fn default_settled_path(policy_path: &str, name: &str) -> PathBuf {
    let dir = Path::new(policy_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    dir.join(format!("{name}.settled.toml"))
}

/// Append the default trust-store (authoring) directories: the user
/// `config.toml`'s `key_dirs` if set, else the built-in default (user config
/// dir, then system). This is the CLI's *authoring* trust store; the daemon
/// re-verifies against its own locked [`kennel_config::Deployment::trust_dir`].
fn add_default_trust_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(kennel_config::User::load().unwrap_or_default().key_dirs());
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

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CONFINED: &[u8] =
        include_bytes!("../../../../../templates/base-confined/policy.toml");

    #[test]
    fn a_template_is_detected_as_a_source_policy() {
        // The `kennel run` dev path compiles a source policy; a shipped template
        // must be recognised as one.
        assert!(is_source_policy(BASE_CONFINED));
    }

    #[test]
    fn a_settled_document_is_not_a_source_policy() {
        // A settled artefact carries `settled_schema_version` / `[signature]`, which
        // the source schemas reject — so it is passed through, not recompiled.
        let settled = br#"
settled_schema_version = 2
name = "demo"
[signature]
algorithm = "none"
key_id = ""
signature = ""
signed_fields = []
"#;
        assert!(!is_source_policy(settled));
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration_secs("90s").expect("90s"), 90);
        assert_eq!(parse_duration_secs("30m").expect("30m"), 1_800);
        assert_eq!(parse_duration_secs("2h").expect("2h"), 7_200);
        assert_eq!(parse_duration_secs("7d").expect("7d"), 604_800);
        assert_eq!(parse_duration_secs("45").expect("bare"), 45); // bare = seconds
        assert!(parse_duration_secs("soon").is_err());
    }

    #[test]
    fn resource_token_maps_to_file_stem() {
        assert_eq!(resource_stem("net"), Some("network"));
        assert_eq!(resource_stem("fs"), Some("filesystem"));
        assert_eq!(resource_stem("lifecycle"), Some("lifecycle"));
        assert_eq!(resource_stem("bogus"), None);
    }

    #[test]
    fn extract_ts_and_novel_key() {
        let line = r#"{"schema_version":1,"ts":"2026-06-05T11:30:50.000000Z","event":"net.connect-deny","resource":"net"}"#;
        assert_eq!(extract_ts(line), Some("2026-06-05T11:30:50.000000Z"));
        // Two events identical but for the timestamp share a novel key.
        let later = r#"{"schema_version":1,"ts":"2026-06-05T12:00:00.000000Z","event":"net.connect-deny","resource":"net"}"#;
        assert_eq!(novel_key(line), novel_key(later));
        // A different event does not.
        let other = r#"{"schema_version":1,"ts":"2026-06-05T11:30:50.000000Z","event":"net.connect-allow","resource":"net"}"#;
        assert_ne!(novel_key(line), novel_key(other));
        // A line with no ts is its own key (no panic).
        assert_eq!(novel_key("{}"), "{}");
        assert_eq!(extract_ts("{}"), None);
    }

    #[test]
    fn temp_settled_is_removed_on_drop() {
        let path = {
            let temp = TempSettled::write("unit-test", b"x").expect("write temp");
            let p = temp.path().to_path_buf();
            assert!(p.exists(), "temp settled file should exist while held");
            p
        };
        assert!(
            !path.exists(),
            "temp settled file should be removed on drop"
        );
    }
}
