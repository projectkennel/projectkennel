//! The `kennel` command-line client.
//!
//! Talks to the per-user kenneld daemon over its control socket (socket-activated
//! on first use). Subcommands:
//!
//! ```text
//! kennel run <policy> <name> -- <cmd> [args...]   # run cmd confined, foreground
//! kennel attach <name>                            # reattach a terminal to a running kennel
//! kennel stop <name>                              # stop a running kennel
//! kennel list                                     # list running kennels
//! ```
//!
//! `run` is foreground but **detachable**: for an interactive workload the daemon owns
//! the controlling pty and proxies it to this terminal over one `SCM_RIGHTS` socket;
//! `Ctrl-\ d` detaches without ending the workload, and `kennel attach <name>`
//! reconnects later. A non-interactive `run` passes the three stdio fds and blocks to
//! the workload's exit code, as before.

#![forbid(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_control::control::{self, Request, Response};
use kennel_lib_control::socket;

mod oci;
mod policy;
mod review;
mod run;

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

/// One CLI command, for both dispatch help and `--help`. The single source of truth:
/// the top-level help renders from this table, so it cannot drift from what exists.
pub(crate) struct CommandSpec {
    /// The verb (`run`, `stop`, `policy`, …).
    name: &'static str,
    /// One-line summary for the command list.
    summary: &'static str,
    /// The full usage line (`kennel ` is prepended when shown).
    usage: &'static str,
}

/// Top-level commands. `policy` is a noun group with its own sub-verbs (see `POLICY_VERBS`).
const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "run",
        summary: "run a workload confined by a policy, in the foreground",
        usage: "run <policy> [<name>] [--key K] [--force] [--template-dir D]... [--trust-dir D]... [-- <cmd...>]",
    },
    CommandSpec {
        name: "attach",
        summary: "reattach a terminal to a running kennel (Ctrl-\\ d to detach)",
        usage: "attach <name>",
    },
    CommandSpec {
        name: "review",
        summary: "review a workspace's trust manifest: re-pin legitimate edits, or --revert tampering",
        usage: "review <policy> [--yes] [--revert]",
    },
    CommandSpec {
        name: "release",
        summary: "release a leaked exclusive over-mount (fs.exclusive crash recovery)",
        usage: "release <policy>",
    },
    CommandSpec {
        name: "stop",
        summary: "stop a running kennel",
        usage: "stop <name>",
    },
    CommandSpec {
        name: "list",
        summary: "list running kennels",
        usage: "list",
    },
    CommandSpec {
        name: "policy",
        summary: "author, inspect, sign, and check policies",
        usage: "policy <list|show|edit|generate|compile|validate|sign|lint|risks|diff|upgrade> [...]",
    },
    CommandSpec {
        name: "keygen",
        summary: "generate a policy-signing key",
        usage: "keygen <key-id> [--dir DIR] [--force]",
    },
    CommandSpec {
        name: "subkennel",
        summary: "manage /etc/kennel/subkennel allocations",
        usage: "subkennel <add|check> [--uid N] [--namespace NS] [--tag N] [--file PATH]",
    },
    CommandSpec {
        name: "audit",
        summary: "show a kennel's audit log",
        usage: "audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]",
    },
    CommandSpec {
        name: "oci",
        summary: "build and run an OCI image as a confined kennel substrate (§7.11)",
        usage: "oci <build|run|revert|update> <name> [--image <ref>] [--key K] [--force] [-- <cmd...>]",
    },
];

/// Sub-verbs of `kennel policy`.
pub(crate) const POLICY_VERBS: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        summary: "list policies and templates in the search path",
        usage: "policy list",
    },
    CommandSpec {
        name: "show",
        summary: "show what a policy resolves to (the effective policy)",
        usage: "policy show <policy> [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "edit",
        summary: "edit a policy's source in $EDITOR",
        usage: "policy edit <name>",
    },
    CommandSpec {
        name: "generate",
        summary: "scaffold a new leaf policy",
        usage: "policy generate <name> [--from <template>]",
    },
    CommandSpec {
        name: "compile",
        summary: "compile a source policy into a signed settled artefact",
        usage: "policy compile <policy> [--output P] [--key K | --unsigned] [--require-signed] [--no-lock] [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "validate",
        summary: "resolve and check a policy without writing an artefact",
        usage: "policy validate <policy> [--require-signed] [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "sign",
        summary: "sign a source template/fragment with a key",
        usage: "policy sign <template> --key <key> [--output <path>]",
    },
    CommandSpec {
        name: "lint",
        summary: "check the shipped template corpus for incoherences",
        usage: "policy lint [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "risks",
        summary: "evaluate a policy against the threat catalogue (exposures, residuals)",
        usage: "policy risks <policy> [--template-dir D]... [--trust-dir D]... [--json]",
    },
    CommandSpec {
        name: "diff",
        summary: "interpreted grant delta between a policy and its baseline (or another policy)",
        usage: "policy diff <policy> [<other>] [--template-dir D]... [--trust-dir D]... [--json]",
    },
    CommandSpec {
        name: "upgrade",
        summary: "re-pin a policy's template to a newer version (with review)",
        usage: "policy upgrade <name> [--yes] [--template-dir D]... [--trust-dir D]...",
    },
];

/// Render the top-level help (the command list) to stdout.
fn print_help() {
    println!("usage: kennel <command> [args...]\n\ncommands:");
    let width = COMMANDS.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in COMMANDS {
        println!("  {:<width$}  {}", c.name, c.summary, width = width);
    }
    println!("\nrun `kennel <command> --help` for a command's usage.");
}

/// Render `kennel policy` help (its sub-verb list) to stdout.
fn print_policy_help() {
    println!("usage: kennel policy <verb> [args...]\n\nverbs:");
    let width = POLICY_VERBS.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in POLICY_VERBS {
        println!("  {:<width$}  {}", c.name, c.summary, width = width);
    }
}

/// Whether `args` contains a help request (`--help`/`-h`).
fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// The usage line for `verb` from a spec table, as a `kennel …` error string.
pub(crate) fn usage_of(table: &[CommandSpec], verb: &str) -> String {
    table.iter().find(|c| c.name == verb).map_or_else(
        || format!("unknown command `{verb}` — run `kennel --help`"),
        |c| format!("usage: kennel {}", c.usage),
    )
}

fn dispatch(args: &[String]) -> Result<ExitCode, String> {
    let Some((cmd, rest)) = args.split_first() else {
        print_help();
        return Ok(ExitCode::SUCCESS);
    };
    if cmd == "help" || cmd == "--help" || cmd == "-h" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    // `kennel <verb> --help` prints that verb's usage (the `policy` group handles its own).
    if cmd != "policy" && wants_help(rest) && COMMANDS.iter().any(|c| c.name == cmd) {
        println!("{}", usage_of(COMMANDS, cmd));
        return Ok(ExitCode::SUCCESS);
    }
    match cmd.as_str() {
        "run" => run::run(rest),
        "attach" => run::attach(rest),
        "review" => review::review(rest),
        "release" => review::release(rest),
        "oci" => oci::dispatch(rest),
        "stop" => stop(rest),
        "list" => list(),
        "policy" => dispatch_policy(rest),
        "keygen" => keygen(rest),
        "subkennel" => subkennel(rest),
        "audit" => audit(rest),
        other => Err(format!("unknown command `{other}` — run `kennel --help`")),
    }
}

/// Dispatch `kennel policy <verb>`.
fn dispatch_policy(args: &[String]) -> Result<ExitCode, String> {
    let Some((verb, rest)) = args.split_first() else {
        print_policy_help();
        return Ok(ExitCode::SUCCESS);
    };
    if verb == "help" || verb == "--help" || verb == "-h" {
        print_policy_help();
        return Ok(ExitCode::SUCCESS);
    }
    if wants_help(rest) && POLICY_VERBS.iter().any(|c| c.name == verb) {
        println!("{}", usage_of(POLICY_VERBS, verb));
        return Ok(ExitCode::SUCCESS);
    }
    match verb.as_str() {
        "list" => policy::policy_list(rest),
        "show" => policy::policy_show(rest),
        "edit" => policy::policy_edit(rest),
        "generate" => policy::policy_generate(rest),
        "compile" => policy::compile(rest),
        "validate" => policy::validate(rest),
        "sign" => policy::sign(rest),
        "lint" => policy::policy_lint(rest),
        "risks" => policy::policy_risks(rest),
        "diff" => policy::policy_diff(rest),
        "upgrade" => policy::upgrade(rest),
        other => Err(format!(
            "unknown policy verb `{other}` — run `kennel policy --help`"
        )),
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
                print_topology(&kennels);
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// A spawned kennel's parent context, parsed from its `spawn-<parent-ctx>-<id>` registry name
/// (§7.12.7). `None` for a top-level kennel. The parent ctx ties an ephemeral SPAWN sibling back to
/// the kennel that requested it — the topology the `list` tree renders without any daemon-side change.
fn spawn_parent_ctx(name: &str) -> Option<u16> {
    name.strip_prefix("spawn-")?.split_once('-')?.0.parse().ok()
}

/// One rendered topology row: the kennel, its tree-connector prefix (`""` root, `"├─ "`/`"└─ "`
/// nested), and whether it is an orphan spawn (a spawn whose requester has already torn down).
type Row<'a> = (&'a control::KennelInfo, &'static str, bool);

/// Order the running kennels as a **what-spawned-what** tree (W20): top-level kennels at the root
/// (sorted by ctx), each ephemeral SPAWN sibling nested under the kennel that spawned it. Spawns are
/// depth-1 (a spawn target holds no `[spawn]` grant), so the tree is two levels; an orphan spawn whose
/// parent has already torn down renders at the root, flagged. Pure (testable); the caller prints it.
fn topology_rows(kennels: &[control::KennelInfo]) -> Vec<Row<'_>> {
    use std::collections::{BTreeMap, HashSet};
    let present: HashSet<u16> = kennels.iter().map(|k| k.ctx).collect();
    // parent ctx -> its spawned children (only when the parent is itself in the listing).
    let mut children: BTreeMap<u16, Vec<&control::KennelInfo>> = BTreeMap::new();
    let mut roots: Vec<&control::KennelInfo> = Vec::new();
    for k in kennels {
        match spawn_parent_ctx(&k.kennel).filter(|p| present.contains(p)) {
            Some(parent) => children.entry(parent).or_default().push(k),
            None => roots.push(k),
        }
    }
    roots.sort_by_key(|k| k.ctx);
    for kids in children.values_mut() {
        kids.sort_by_key(|k| k.ctx);
    }
    let mut rows: Vec<Row<'_>> = Vec::with_capacity(kennels.len());
    for root in roots {
        let orphan = spawn_parent_ctx(&root.kennel).is_some(); // a spawn whose parent is gone
        rows.push((root, "", orphan));
        if let Some(kids) = children.get(&root.ctx) {
            let last = kids.len().saturating_sub(1);
            for (i, kid) in kids.iter().enumerate() {
                rows.push((kid, if i == last { "└─ " } else { "├─ " }, false));
            }
        }
    }
    rows
}

/// Render the running kennels as the what-spawned-what tree (W20).
fn print_topology(kennels: &[control::KennelInfo]) {
    println!(
        "{:<32} {:>5} {:>8}  {:<8} CLIENT",
        "NAME", "CTX", "PID", "STATE"
    );
    for (k, prefix, orphan) in topology_rows(kennels) {
        print_row(k, prefix, orphan);
    }
}

/// Print one kennel row, the `prefix` carrying the tree connector for a nested spawn.
fn print_row(k: &control::KennelInfo, prefix: &str, orphan: bool) {
    // The terminal-attachment state of an interactive kennel: a detached kennel keeps running,
    // reattachable with `kennel attach`.
    let state = if k.running { "running" } else { "starting" };
    let client = if k.attached { "attached" } else { "detached" };
    let name = format!("{prefix}{}", k.kennel);
    let tail = if orphan { "  (orphan spawn)" } else { "" };
    println!(
        "{name:<32} {:>5} {:>8}  {state:<8} {client}{tail}",
        k.ctx, k.pid
    );
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
            Some(kennel_lib_audit::format_rfc3339_micros(cut, 0))
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
pub(crate) fn connect() -> Result<UnixStream, String> {
    let path = socket::socket_path();
    UnixStream::connect(&path).map_err(|e| {
        format!(
            "cannot reach kenneld at {} ({e}); is the kenneld.socket user unit enabled?",
            path.display()
        )
    })
}

/// Send `request` (with any `fds`) as one framed `SCM_RIGHTS` message.
pub(crate) fn send(
    conn: &UnixStream,
    request: &Request,
    fds: &[BorrowedFd<'_>],
) -> Result<(), String> {
    let mut framed = Vec::new();
    control::write_frame(&mut framed, &request.encode())
        .map_err(|e| format!("encoding request: {e}"))?;
    kennel_lib_syscall::scm::send_with_fds(conn.as_fd(), &framed, fds)
        .map_err(|e| format!("sending request: {e}"))?;
    Ok(())
}

/// Map a daemon-reported exit code to a process `ExitCode` (clamped to a byte).
pub(crate) fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Read the next required value for `flag` from a lexopt parser.
fn lexopt_value(p: &mut lexopt::Parser, flag: &str) -> Result<PathBuf, String> {
    p.value()
        .map(PathBuf::from)
        .map_err(|_| format!("{flag} needs a value"))
}

/// Format an unexpected lexopt arg into a usage error for `verb`.
fn lexopt_unexpected(arg: &lexopt::Arg<'_>, table: &[CommandSpec], verb: &str) -> String {
    let what = match arg {
        lexopt::Arg::Long(s) => format!("unknown flag `--{s}`"),
        lexopt::Arg::Short(c) => format!("unknown flag `-{c}`"),
        lexopt::Arg::Value(v) => format!("unexpected argument `{}`", v.to_string_lossy()),
    };
    format!("{what}\n{}", usage_of(table, verb))
}

/// `kennel sign <template> --key <key> [--output <path>]`
///
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
    kennel_lib_syscall::random::fill(&mut seed)
        .map_err(|e| format!("reading OS randomness: {e}"))?;
    let key = kennel_lib_policy::SigningKey::from_seed(key_id, &seed)
        .map_err(|e| format!("deriving key: {e}"))?;

    // The key dir holds secret seeds: 0700.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_secret(&key_path, &kennel_lib_policy::b64::encode(&seed), 0o600)
        .map_err(|e| format!("writing {}: {e}", key_path.display()))?;
    write_secret(
        &pub_path,
        &kennel_lib_policy::b64::encode(&key.public_key_bytes()),
        0o644,
    )
    .map_err(|e| format!("writing {}: {e}", pub_path.display()))?;

    eprintln!("generated Ed25519 signing key `{key_id}`:");
    eprintln!(
        "  private seed : {}   (0600 — keep secret; the signing key)",
        key_path.display()
    );
    eprintln!("  public key   : {}   (0644)", pub_path.display());
    eprintln!();
    eprintln!("The daemon already trusts this key for your own run policies (it reads");
    eprintln!("~/.config/kennel/keys), so no further setup is needed. Compile a policy once,");
    eprintln!("then run it — neither command needs --key while this is your only key:");
    eprintln!("  kennel compile <name>          # signs policies/<name>/<name>.settled.toml");
    eprintln!("  kennel run <name> -- <cmd...>  # runs the settled policy (no key to run)");
    eprintln!();
    eprintln!("Only to let *other* users or a fleet trust policies you sign — or to sign");
    eprintln!("*templates* (which verify against system keys only) — install the public key");
    eprintln!("into the root-owned system trust store:");
    eprintln!(
        "  sudo install -m 0644 {} /etc/kennel/keys/{key_id}.pub",
        pub_path.display()
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

/// The system per-user allocation file.
const SUBKENNEL_FILE: &str = "/etc/kennel/subkennel";

/// Largest valid `tag` — the 12-bit IPv4 `/20` selector. Tag 0 is reserved (its
/// `/20`, `127.0.0.0/20`, contains `127.0.0.1`). Mirrors
/// `kennel-privhelper::validate::TAG_MAX`; the format is `kennel-privhelper::alloc`.
const SUBKENNEL_TAG_MAX: u16 = 0x0FFF;

/// One parsed `/etc/kennel/subkennel` allocation (`uid:tag:gid:namespace`).
struct Alloc {
    uid: u32,
    tag: u16,
    gid_hex: String,
    namespace: String,
}

/// `kennel subkennel <add|check> ...` — manage the per-user allocation file. A user
/// with no (or a malformed) line cannot start kenneld, so `add` generates a
/// provably-valid line (collision-free `tag`/`gid`) and `check` validates the file.
fn subkennel(args: &[String]) -> Result<ExitCode, String> {
    match args.split_first() {
        Some((cmd, rest)) if cmd == "add" => subkennel_add(rest),
        Some((cmd, rest)) if cmd == "check" => subkennel_check(rest),
        _ => Err("usage: kennel subkennel add [--uid N] [--namespace NS] [--tag N] [--file PATH] | kennel subkennel check [--uid N] [--file PATH]".to_owned()),
    }
}

/// Parse a subkennel line into an [`Alloc`], matching `kennel-privhelper::alloc`
/// (first four `:`-separated fields; extra fields ignored, as the daemon does).
fn parse_alloc_line(line: &str) -> Result<Alloc, String> {
    let mut f = line.split(':');
    let uid = f
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or("field 1 (uid) is not a number")?;
    let tag = f
        .next()
        .ok_or("missing field 2 (tag)")?
        .parse::<u16>()
        .map_err(|_| "field 2 (tag) is not a number".to_owned())?;
    if tag > SUBKENNEL_TAG_MAX {
        return Err(format!(
            "tag {tag} exceeds the 12-bit max {SUBKENNEL_TAG_MAX}"
        ));
    }
    let gid_hex = f.next().ok_or("missing field 3 (gid)")?;
    if gid_hex.len() != 10 || u64::from_str_radix(gid_hex, 16).is_err() {
        return Err("field 3 (gid) must be exactly 10 hex digits".to_owned());
    }
    let namespace = f.next().ok_or("missing field 4 (namespace)")?;
    if namespace.is_empty() {
        return Err("field 4 (namespace) is empty".to_owned());
    }
    Ok(Alloc {
        uid,
        tag,
        gid_hex: gid_hex.to_owned(),
        namespace: namespace.to_owned(),
    })
}

/// Parse a subkennel file: the valid allocations, and the malformed lines (with
/// their 1-based line number and reason) for `check` to report.
fn parse_subkennel(text: &str) -> (Vec<Alloc>, Vec<(usize, String, String)>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_alloc_line(line) {
            Ok(a) => ok.push(a),
            Err(reason) => bad.push((i.saturating_add(1), raw.to_owned(), reason)),
        }
    }
    (ok, bad)
}

/// The username for the default namespace (`kennel-<user>`). The CLI is not setuid,
/// so reading `$USER` is fine here (the privhelper, which is, never does this — the
/// namespace is stored in the file precisely so the helper needs no lookup). Falls
/// back to the uid when `$USER` is unset/unusable.
fn default_user_label(uid: u32) -> String {
    std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty() && !s.contains(':'))
        .unwrap_or_else(|| uid.to_string())
}

/// `kennel subkennel add [--uid N] [--namespace NS] [--tag N] [--file PATH]`
///
/// Generate a valid allocation line for a user (default: the current uid). The
/// namespace defaults to `kennel-<user>`; `--namespace` only overrides it. The `tag`
/// is the lowest free 12-bit value (from 1; 0 is reserved) unless `--tag` is given,
/// and the `gid` is a fresh random 40-bit ULA id — both checked against existing
/// lines so two users never collide. Prints the line plus the exact `sudo` command
/// to append it (the file is root-owned, so the CLI never writes it itself).
fn subkennel_add(args: &[String]) -> Result<ExitCode, String> {
    let mut uid: Option<u32> = None;
    let mut namespace: Option<String> = None;
    let mut tag_override: Option<u16> = None;
    let mut file = PathBuf::from(SUBKENNEL_FILE);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--uid" => {
                uid = Some(
                    it.next()
                        .ok_or("--uid needs a value")?
                        .parse()
                        .map_err(|_| "--uid must be a number".to_owned())?,
                );
            }
            "--namespace" => {
                namespace = Some(it.next().ok_or("--namespace needs a value")?.clone());
            }
            "--tag" => {
                tag_override = Some(
                    it.next()
                        .ok_or("--tag needs a value")?
                        .parse()
                        .map_err(|_| {
                            format!("--tag must be a number in 1..={SUBKENNEL_TAG_MAX}")
                        })?,
                );
            }
            "--file" => file = it.next().ok_or("--file needs a value")?.into(),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            _ => return Err("kennel subkennel add takes no positional arguments".to_owned()),
        }
    }
    let uid = uid.unwrap_or_else(kennel_lib_syscall::unistd::real_uid);

    // Existing allocations (an absent file just means none yet).
    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    let (allocs, _bad) = parse_subkennel(&existing);
    if let Some(a) = allocs.iter().find(|a| a.uid == uid) {
        return Err(format!(
            "uid {uid} already has an allocation in {} (`{}:{}:{}:{}`); kenneld uses the first \
             line for a uid, so edit that line instead of adding another",
            file.display(),
            a.uid,
            a.tag,
            a.gid_hex,
            a.namespace
        ));
    }
    let used_tags: std::collections::BTreeSet<u16> = allocs.iter().map(|a| a.tag).collect();
    let tag = match tag_override {
        Some(0) => return Err("tag 0 is reserved (its /20 contains 127.0.0.1)".to_owned()),
        Some(t) if t > SUBKENNEL_TAG_MAX => {
            return Err(format!(
                "tag {t} exceeds the 12-bit max {SUBKENNEL_TAG_MAX}"
            ))
        }
        Some(t) if used_tags.contains(&t) => {
            return Err(format!("tag {t} is already allocated to another user"))
        }
        Some(t) => t,
        None => (1..=SUBKENNEL_TAG_MAX)
            .find(|t| !used_tags.contains(t))
            .ok_or("no free tag remains (all 4095 are allocated)")?,
    };

    // A fresh random 40-bit ULA id, not colliding with an existing one.
    let used_gids: std::collections::BTreeSet<&str> =
        allocs.iter().map(|a| a.gid_hex.as_str()).collect();
    let gid_hex = loop {
        let mut g = [0u8; 5];
        kennel_lib_syscall::random::fill(&mut g)
            .map_err(|e| format!("reading OS randomness: {e}"))?;
        if g == [0u8; 5] {
            continue; // avoid the degenerate all-zero ULA id
        }
        let hex = format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}",
            g[0], g[1], g[2], g[3], g[4]
        );
        if !used_gids.contains(hex.as_str()) {
            break hex;
        }
    };

    let namespace = namespace.unwrap_or_else(|| format!("kennel-{}", default_user_label(uid)));
    if namespace.is_empty() || namespace.contains(':') {
        return Err("namespace must be non-empty and contain no `:`".to_owned());
    }

    let line = format!("{uid}:{tag}:{gid_hex}:{namespace}");
    // The line we emit must parse back identically — a guard against a future format slip.
    parse_alloc_line(&line)
        .map_err(|e| format!("internal: generated a line that does not parse ({e})"))?;

    eprintln!("allocation for uid {uid}: tag {tag}, gid {gid_hex}, namespace `{namespace}`");
    println!("{line}");
    eprintln!();
    eprintln!("Install it into the root-owned allocation file, then (re)start the daemon:");
    eprintln!(
        "  echo '{line}' | sudo tee -a {} >/dev/null",
        file.display()
    );
    eprintln!("  systemctl --user restart kenneld.socket");
    Ok(ExitCode::SUCCESS)
}

/// `kennel subkennel check [--uid N] [--file PATH]`
///
/// Validate the allocation file: report every malformed line and any duplicate
/// `uid`/`tag`/`gid` (which would silently shadow or collide), then the named user's
/// status. Exits non-zero if that user has no valid allocation — i.e. kenneld would
/// refuse to start for them.
fn subkennel_check(args: &[String]) -> Result<ExitCode, String> {
    let mut uid: Option<u32> = None;
    let mut file = PathBuf::from(SUBKENNEL_FILE);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--uid" => {
                uid = Some(
                    it.next()
                        .ok_or("--uid needs a value")?
                        .parse()
                        .map_err(|_| "--uid must be a number".to_owned())?,
                );
            }
            "--file" => file = it.next().ok_or("--file needs a value")?.into(),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            _ => return Err("kennel subkennel check takes no positional arguments".to_owned()),
        }
    }
    let uid = uid.unwrap_or_else(kennel_lib_syscall::unistd::real_uid);
    let text = std::fs::read_to_string(&file).map_err(|e| {
        format!(
            "reading {}: {e} (run `kennel subkennel add`)",
            file.display()
        )
    })?;
    let (allocs, bad) = parse_subkennel(&text);

    for (n, raw, reason) in &bad {
        eprintln!("line {n}: MALFORMED — {reason}: {raw}");
    }
    // Duplicates: the daemon takes the first line per uid; collisions break isolation.
    report_dups("uid", allocs.iter().map(|a| a.uid.to_string()));
    report_dups("tag", allocs.iter().map(|a| a.tag.to_string()));
    report_dups("gid", allocs.iter().map(|a| a.gid_hex.clone()));

    eprintln!(
        "{}: {} valid allocation(s), {} malformed line(s)",
        file.display(),
        allocs.len(),
        bad.len()
    );
    allocs.iter().find(|a| a.uid == uid).map_or_else(
        || {
            Err(format!(
                "uid {uid}: NO valid allocation — kenneld will refuse to start for this user; \
                 run `kennel subkennel add`"
            ))
        },
        |a| {
            eprintln!(
                "uid {uid}: OK — tag {}, gid {}, namespace `{}`",
                a.tag, a.gid_hex, a.namespace
            );
            Ok(ExitCode::SUCCESS)
        },
    )
}

/// Warn about repeated values in `field` (uid/tag/gid).
fn report_dups(field: &str, values: impl Iterator<Item = String>) {
    let mut seen = std::collections::BTreeSet::new();
    let mut dup = std::collections::BTreeSet::new();
    for v in values {
        if !seen.insert(v.clone()) {
            dup.insert(v);
        }
    }
    for v in dup {
        eprintln!("warning: duplicate {field} `{v}` — only the first line is used; the rest are dead or collide");
    }
}

/// Map a compile-time [`kennel_lib_policy::PolicyError`] to a CLI exit code (`02-1`).
const fn policy_error_code(err: &kennel_lib_policy::PolicyError) -> u8 {
    use kennel_lib_policy::PolicyError as E;
    match err {
        E::Signature(_) | E::LockMismatch(_) => 6,
        E::Parse(_)
        | E::Canonical(_)
        | E::UnsupportedSchemaVersion { .. }
        | E::InvariantViolations(_)
        | E::SourceValidation(_)
        | E::Resolution(_)
        | E::Translation(_)
        | E::IncludeConflict(_)
        | E::Patch(_)
        | E::Spawn(_) => 3,
    }
}

/// Append the default template search directories: the user `config.toml`'s
/// `template_dirs` if set, else the built-in default (user config dir, then
/// system). A malformed user config falls back to the built-in default.
pub(crate) fn add_default_template_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .template_dirs(),
    );
}

/// Resolve a `<policy>` argument to a file path plus a default kennel/policy name.
/// An argument that names an **existing file** is used verbatim (its name derived
/// from the path); otherwise it is a **policy name** searched in the `policies/`
/// cascade (`~/.config/kennel`, `/etc/kennel`, `/usr/lib/kennel`).
///
/// Within a `<name>/` folder there are two candidates: the compiled
/// `<name>.settled.toml` and the source `policy.toml`. `prefer_settled` picks the
/// order — `kennel run` prefers the settled artefact (the production path), while
/// `kennel compile` prefers the source it is about to compile. The returned name
/// doubles as the default kennel instance name (`07-paths`, resolve-by-name).
/// `kennel policy upgrade <name> [--yes] [--template-dir D]... [--trust-dir D]...` — re-pin a
/// policy's template to a newer published version, with review and consent.
///
/// Detects whether the policy's `template_base` has a newer version available in
/// the template search path, shows the source diff between the pinned and the new
pub(crate) fn resolve_policy(arg: &str, prefer_settled: bool) -> Result<(PathBuf, String), String> {
    let literal = Path::new(arg);
    if literal.exists() {
        return Ok((literal.to_path_buf(), policy_name_from_path(literal)));
    }
    if !is_valid_policy_name(arg) {
        return Err(format!(
            "`{arg}` is not an existing file, and not a valid policy name (no `/`, `..`, or whitespace)"
        ));
    }
    for dir in kennel_lib_config::User::load()
        .unwrap_or_default()
        .policy_dirs()
    {
        let base = dir.join(arg);
        let settled = base.join(format!("{arg}.settled.toml"));
        let source = base.join("policy.toml");
        let ordered = if prefer_settled {
            [settled, source]
        } else {
            [source, settled]
        };
        for candidate in ordered {
            if candidate.is_file() {
                return Ok((candidate, arg.to_owned()));
            }
        }
    }
    Err(format!(
        "no policy named `{arg}` (searched `policies/` under ~/.config/kennel, /etc/kennel, \
         /usr/lib/kennel); pass a path, or compile one with `kennel compile`"
    ))
}

/// Derive a kennel name from a policy file path: `policies/<name>/policy.toml` and
/// `policies/<name>/<name>.settled.toml` both yield `<name>`; any other file yields
/// its stem with a trailing `.settled` stripped.
fn policy_name_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("kennel");
    if stem == "policy" {
        if let Some(parent) = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
        {
            return parent.to_owned();
        }
    }
    stem.strip_suffix(".settled").unwrap_or(stem).to_owned()
}

/// A policy name is a single safe path component: non-empty, no `/`, no `..`, no
/// whitespace (it is joined into the trust-rooted `policies/` cascade and also
/// defaults the kennel instance name).
fn is_valid_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name != ".."
        && !name.contains('/')
        && !name.contains("..")
        && !name.chars().any(char::is_whitespace)
}

/// Default settled-policy path: `<policy-dir>/<name>.settled.toml`.
fn default_settled_path(policy_path: &Path, name: &str) -> PathBuf {
    let dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("{name}.settled.toml"))
}

/// Append the default **template-trust** directories: the system stores only
/// (`/etc/kennel/keys`, then the vendor `/usr/lib/kennel/keys`), or the user
/// `config.toml`'s `key_dirs` override if set. Templates are the security baseline
/// (the framework invariants + confinement floor) and must be org/vendor-signed —
/// never a user's own `~/.config/kennel/keys` (the trust split, `07-paths`). The
/// daemon separately trusts the user's own keys for **settled run** policies.
/// `--trust-dir` flags still append, so an operator can add an org key dir.
pub(crate) fn add_system_trust_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .system_key_dirs(),
    );
}

/// Load a trust store: every `<key_id>.pub` (base64 32-byte public key) under each
/// directory. Missing directories are skipped; a malformed key file is an error.
pub(crate) fn load_trust_store(dirs: &[PathBuf]) -> Result<kennel_lib_policy::KeySet, String> {
    let mut keys = kennel_lib_policy::KeySet::new();
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
pub(crate) fn load_signing_key(path: &Path) -> Result<kennel_lib_policy::SigningKey, String> {
    let shown = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading key {shown}: {e}"))?;
    let seed = kennel_lib_policy::b64::decode(text.trim().as_bytes())
        .ok_or_else(|| format!("key {shown} is not valid base64"))?;
    let key_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("cannot derive a key id from {shown}"))?;
    kennel_lib_policy::SigningKey::from_seed(key_id, &seed)
        .map_err(|e| format!("loading key {shown}: {e}"))
}

/// The signing key to use when an operation must sign (`compile`, or `run`'s
/// in-memory compile-and-sign) and `--key` was omitted: the **sole** `*.key` in
/// the user key dir (`default_key_dir`). Signing is deliberate, so we auto-pick
/// only when there is exactly one candidate; zero or several is an error asking
/// the user to be explicit. The matching `.pub` is trusted for run policies, so
/// the single-key dev case needs no `--key` at all.
pub(crate) fn default_signing_key() -> Result<PathBuf, String> {
    let dir = default_key_dir();
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("key"))
                .collect()
        },
    );
    found.sort();
    match found.as_slice() {
        [] => Err(format!(
            "no signing key in {} — generate one with `kennel keygen <key-id>`, or pass --key <path>",
            dir.display()
        )),
        [only] => Ok(only.clone()),
        many => {
            let ids: Vec<&str> = many
                .iter()
                .filter_map(|p| p.file_stem().and_then(|s| s.to_str()))
                .collect();
            Err(format!(
                "multiple signing keys in {} ({}); pass --key <path> to choose",
                dir.display(),
                ids.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        is_source_policy, newest_template_version, policy_kind, rewrite_template_base, TempSettled,
    };

    const BASE_CONFINED: &[u8] = include_bytes!("../../../../templates/base-confined/policy.toml");

    #[test]
    fn spawn_parent_ctx_parses_the_topology_name() {
        // `spawn-<parent-ctx>-<id>` ties an ephemeral sibling to its requester's ctx.
        assert_eq!(spawn_parent_ctx("spawn-5-0000000abcde"), Some(5));
        assert_eq!(spawn_parent_ctx("spawn-42-deadbeef0000"), Some(42));
        // A top-level kennel (any non-spawn name) has no parent.
        for top in [
            "my-agent",
            "echo-tool",
            "spawn",
            "spawnish",
            "spawn-",
            "spawn-x-1",
        ] {
            assert_eq!(
                spawn_parent_ctx(top),
                None,
                "`{top}` should have no parent ctx"
            );
        }
    }

    #[test]
    fn topology_nests_spawns_under_their_requester() {
        let ki = |name: &str, ctx: u16| control::KennelInfo {
            kennel: name.to_owned(),
            ctx,
            pid: 100 + u32::from(ctx),
            running: true,
            attached: false,
        };
        // Two top-level kennels (ctx 7, 3), one child of 7, and an orphan spawn whose parent (99)
        // is not in the listing. Input order is deliberately scrambled.
        let kennels = vec![
            ki("spawn-7-00000000aaaa", 11),
            ki("agent", 7),
            ki("spawn-99-00000000bbbb", 20), // orphan: parent ctx 99 absent
            ki("builder", 3),
        ];
        let shape: Vec<(&str, &str, bool)> = topology_rows(&kennels)
            .iter()
            .map(|(k, p, o)| (k.kennel.as_str(), *p, *o))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("builder", "", false),                 // root ctx 3
                ("agent", "", false),                   // root ctx 7
                ("spawn-7-00000000aaaa", "└─ ", false), // nested under its requester (ctx 7)
                ("spawn-99-00000000bbbb", "", true),    // orphan at root, flagged
            ],
            "roots sorted by ctx, spawn nested under its parent, orphan flagged at root"
        );
    }

    #[test]
    fn rewrite_template_base_replaces_only_the_reference() {
        let src = "name = \"x\"\ntemplate_base = \"demo@v1\"\n[exec]\nallow = []\n";
        let out = rewrite_template_base(src, "demo@v1", "demo@v2").expect("rewrite");
        assert!(out.contains("template_base = \"demo@v2\""));
        assert!(out.contains("[exec]"), "rest of the file is preserved");
        assert!(!out.contains("@v1"), "the old reference is gone");
    }

    #[test]
    fn rewrite_template_base_errors_when_reference_absent() {
        let err = rewrite_template_base("template_base = \"other@v1\"\n", "demo@v1", "demo@v2")
            .expect_err("must not silently no-op");
        assert!(err.contains("could not find"), "got {err}");
    }

    #[test]
    fn newest_template_version_picks_the_highest_flat_file() {
        let dir = std::env::temp_dir().join(format!("kennel-upg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        for v in ["v1", "v2", "v10", "v2.3"] {
            std::fs::write(dir.join(format!("demo@{v}.toml")), b"x").expect("write");
        }
        // A different template must not interfere.
        std::fs::write(dir.join("other@v99.toml"), b"x").expect("write");
        let newest = newest_template_version(std::slice::from_ref(&dir), "demo");
        assert_eq!(newest.as_deref(), Some("v10"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_diff_marks_added_and_removed_lines() {
        // Captured indirectly: the function prints; here we assert the set logic via
        // its building blocks by re-deriving what it would emit. (print_source_diff
        // writes to stdout; we exercise the add/remove classification.)
        let old = "a = 1\nb = 2\n";
        let new = "a = 1\nc = 3\n";
        let old_lines: Vec<&str> = old.lines().collect();
        let new_lines: Vec<&str> = new.lines().collect();
        let added: Vec<&&str> = new_lines
            .iter()
            .filter(|l| !old_lines.contains(l))
            .collect();
        let removed: Vec<&&str> = old_lines
            .iter()
            .filter(|l| !new_lines.contains(l))
            .collect();
        assert_eq!(added, vec![&"c = 3"]);
        assert_eq!(removed, vec![&"b = 2"]);
    }

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
    fn policy_name_derives_from_the_path_shape() {
        // policies/<name>/policy.toml and policies/<name>/<name>.settled.toml -> <name>.
        assert_eq!(
            policy_name_from_path(Path::new("/c/policies/ai-coding/policy.toml")),
            "ai-coding"
        );
        assert_eq!(
            policy_name_from_path(Path::new("/c/policies/ai-coding/ai-coding.settled.toml")),
            "ai-coding"
        );
        // A loose file falls back to its stem, minus a trailing `.settled`.
        assert_eq!(
            policy_name_from_path(Path::new("/tmp/demo.settled.toml")),
            "demo"
        );
        assert_eq!(policy_name_from_path(Path::new("/tmp/demo.toml")), "demo");
    }

    #[test]
    fn policy_kind_distinguishes_template_leaf_and_fragment() {
        let dir = std::env::temp_dir().join(format!("kennel-kind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).expect("write");
            p
        };
        // A SourcePolicy with template_name is a template; with name, a leaf.
        let tmpl = write("t.toml", "template_name = \"x\"\n[exec]\nallow = []\n");
        assert_eq!(policy_kind(&tmpl), "template");
        let leaf_src = write("l.toml", "name = \"k\"\n[exec]\nallow = []\n");
        assert_eq!(policy_kind(&leaf_src), "leaf");
        // Leaf-delta syntax, additive-only, not anchored to a non-base parent: a fragment.
        let frag = write(
            "f.toml",
            "name = \"lang-x\"\n[[exec.allow.add]]\npath = \"/usr/bin/x\"\nreason = \"r\"\n",
        );
        assert_eq!(policy_kind(&frag), "fragment");
        // Leaf-delta syntax anchored to a real template chain: an ordinary leaf kennel.
        let chained = write(
            "c.toml",
            "name = \"k\"\ntemplate_base = \"ai-coding-strict@v1\"\n[[fs.read.add]]\npath = \"~/p/**\"\nreason = \"r\"\n",
        );
        assert_eq!(policy_kind(&chained), "leaf");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_names_reject_traversal_and_separators() {
        assert!(is_valid_policy_name("ai-coding"));
        assert!(is_valid_policy_name("my_policy.v2"));
        assert!(!is_valid_policy_name(""));
        assert!(!is_valid_policy_name(".."));
        assert!(!is_valid_policy_name("a/b"));
        assert!(!is_valid_policy_name("../escape"));
        assert!(!is_valid_policy_name("has space"));
    }

    #[test]
    fn resolve_policy_uses_a_literal_path_verbatim() {
        // An existing file is used as-is and bypasses name resolution.
        let dir = std::env::temp_dir().join(format!("kennel-resolve-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("loose.settled.toml");
        std::fs::write(&file, b"x").expect("write");
        let (path, name) = resolve_policy(file.to_str().expect("utf8"), true).expect("resolve");
        assert_eq!(path, file);
        assert_eq!(name, "loose");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_policy_rejects_an_unknown_name() {
        // A name that resolves nowhere (and is not a path) is an error, not a panic.
        let err = resolve_policy("definitely-no-such-policy-xyz", true).expect_err("must fail");
        assert!(err.contains("no policy named"), "got {err}");
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

    /// The manpage generator keeps its own copy of the command tables
    /// (`gen_man::pages::SYNC_*`), so `man kennel`/`man kennel-policy` stay exact.
    /// This test fails the build if a CLI command's name/summary/usage changes
    /// without the matching edit to `src/tools/gen-man/src/pages.rs` — the drift
    /// guard that makes "generate the pages from a table" trustworthy.
    #[test]
    fn man_pages_in_sync_with_cli_tables() {
        let live: Vec<(&str, &str, &str)> = COMMANDS
            .iter()
            .map(|c| (c.name, c.summary, c.usage))
            .collect();
        assert_eq!(
            live,
            gen_man::pages::SYNC_COMMANDS.to_vec(),
            "COMMANDS drifted from gen-man SYNC_COMMANDS — update src/tools/gen-man/src/pages.rs and regenerate man/"
        );

        let live_policy: Vec<(&str, &str, &str)> = POLICY_VERBS
            .iter()
            .map(|c| (c.name, c.summary, c.usage))
            .collect();
        assert_eq!(
            live_policy,
            gen_man::pages::SYNC_POLICY.to_vec(),
            "POLICY_VERBS drifted from gen-man SYNC_POLICY — update src/tools/gen-man/src/pages.rs and regenerate man/"
        );
    }
}
