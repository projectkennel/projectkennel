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
use std::io::IsTerminal as _;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_policy::TemplateSource;
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

/// One CLI command, for both dispatch help and `--help`. The single source of truth:
/// the top-level help renders from this table, so it cannot drift from what exists.
struct CommandSpec {
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
        summary: "author, inspect, and compile policies (see `kennel policy --help`)",
        usage: "policy <list|show|edit|generate|compile|validate|sign|lint> [...]",
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
];

/// Sub-verbs of `kennel policy`.
const POLICY_VERBS: &[CommandSpec] = &[
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
        usage: "policy compile <policy> [--output-path P] [--key K | --unsigned] [--require-signed] [--no-lock] [--template-dir D]... [--trust-dir D]...",
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
fn usage_of(table: &[CommandSpec], verb: &str) -> String {
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
        "run" => run(rest),
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
        "list" => policy_list(rest),
        "show" => policy_show(rest),
        "edit" => policy_edit(rest),
        "generate" => policy_generate(rest),
        "compile" => compile(rest),
        "validate" => validate(rest),
        "sign" => sign(rest),
        "lint" => policy_lint(rest),
        other => Err(format!(
            "unknown policy verb `{other}` — run `kennel policy --help`"
        )),
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
// allow(too_many_lines): one cohesive arg-parse → resolve → (maybe compile+sign) → start
// sequence for the `run` subcommand; the lexopt CLI overhaul folds this into the shared
// parser table.
#[allow(clippy::too_many_lines)]
fn run(args: &[String]) -> Result<ExitCode, String> {
    // <head...> optionally then "--" then the command. The `--` is OPTIONAL: with no
    // command the daemon runs the policy's embedded [workload] (§7.4); with a command it
    // overrides the policy workload (unless pinned — then --force is required).
    let (head, command) = args
        .iter()
        .position(|a| a == "--")
        .map_or((args, &[][..]), |sep| {
            (
                args.get(..sep).unwrap_or(&[]),
                args.get(sep.saturating_add(1)..).unwrap_or(&[]),
            )
        });

    let mut policy_arg: Option<&str> = None;
    let mut name_arg: Option<&str> = None;
    let mut key_path: Option<&str> = None;
    let mut force = false;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut it = head.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--force" => force = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if policy_arg.is_none() => policy_arg = Some(v),
            v if name_arg.is_none() => name_arg = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let policy_arg = policy_arg.ok_or(
        "usage: kennel run <policy> [<name>] [--key K] [--force] [--template-dir D]... [-- <cmd...>]",
    )?;
    // `<policy>` is a literal path if it exists, else a **name** resolved from the
    // `policies/` cascade (`~/.config/kennel`, `/etc/kennel`, `/usr/lib/kennel`,
    // preferring the settled artefact). The kennel instance `<name>` is optional and
    // defaults to the resolved policy name (`07-paths`, resolve-by-name).
    let (policy_file, default_name) = resolve_policy(policy_arg, true)?;
    let name = name_arg.map_or(default_name, str::to_owned);

    // Auto-compile dev path: a source policy is compiled+signed in memory; a settled
    // artefact is passed straight through. `_temp` keeps the on-disk settled file
    // alive for the daemon to read, and removes it when this function returns.
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;
    // Held only for its `Drop` (removes the temp settled file when the run returns);
    // never read, hence the allow.
    #[allow(clippy::collection_is_never_read)]
    let _temp;
    let effective_policy: PathBuf = if is_source_policy(&bytes) {
        // A source leaf is compiled-and-signed in memory (the §9.10 dev loop). That
        // needs a *signing* (private) key; with `--key` omitted we default to the
        // sole key in the user key dir. A pre-compiled settled artefact takes the
        // `else` branch and needs no key at all (the daemon verifies its signature).
        let key_path: PathBuf = match key_path {
            Some(p) => PathBuf::from(p),
            None => default_signing_key()?,
        };
        add_default_template_dirs(&mut template_dirs);
        add_system_trust_dirs(&mut trust_dirs);
        let source = FsTemplateSource {
            dirs: template_dirs,
        };
        let keys = load_trust_store(&trust_dirs)?;
        let trust = kennel_lib_policy::Trust::allow_unsigned(Some(&keys));
        let mut compiled = build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
            .map_err(|e| format!("compiling {}: {e}", policy_file.display()))?;
        print_warnings(&compiled.warnings);
        print_warnings(&kennel_lib_policy::resolve_settled_loaders(
            &mut compiled.policy,
        ));
        // Mint/reuse the SSH synthetic keypairs beside the source policy (its dir), pinning
        // the public halves into the settled grants before signing — same as the `compile`
        // verb, so an in-memory `kennel run` of an `[ssh]` policy is signed over its keys too.
        let ssh_dir = policy_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("ssh");
        let minted = mint_ssh_keys(&mut compiled.policy, &ssh_dir)?;
        let key = load_signing_key(&key_path)?;
        let doc = kennel_lib_policy::sign_settled(&compiled.policy, &key)
            .map_err(|e| format!("signing: {e}"))?;
        let out = kennel_lib_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))?;
        // When SSH keys were minted, the daemon resolves them at `<settled>.parent()/ssh`,
        // so the temp settled MUST sit beside that `ssh/` dir (the source policy's dir).
        // Without SSH there is no such coupling — stage under the runtime dir as usual.
        let temp = if minted {
            TempSettled::write_in(
                policy_file.parent().unwrap_or_else(|| Path::new(".")),
                &name,
                &out,
            )?
        } else {
            TempSettled::write(&name, &out)?
        };
        let path = temp.path().to_path_buf();
        eprintln!(
            "kennel: compiled `{}` in memory for this run",
            policy_file.display()
        );
        _temp = Some(temp);
        path
    } else {
        _temp = None;
        policy_file
    };

    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let request = Request::Start(StartRequest {
        policy: effective_policy,
        kennel: name.clone(),
        argv: command.to_vec(),
        cwd,
        // Forward the caller's terminal type so an interactive workload renders; the
        // rest of the workload env is synthesised by the daemon, not inherited.
        term: std::env::var("TERM").unwrap_or_default(),
        // Interactive when stdin is a terminal: the seal allocates the workload's own
        // pty (job control) and hands its master back for us to proxy.
        interactive: io::stdin().is_terminal(),
        // Force an override of a pinned policy [workload] (only meaningful with a `--` cmd).
        force,
    });

    let mut conn = connect()?;
    if io::stdin().is_terminal() {
        return run_interactive(conn, &request);
    }
    // Non-interactive (piped/redirected): pass our stdio straight through.
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

/// Restores the terminal to its saved (pre-raw) settings when dropped — on every
/// return path of an interactive run, including errors and `?` early-returns.
struct RawGuard {
    prev: kennel_lib_syscall::pty::Termios,
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = kennel_lib_syscall::pty::restore(io::stdin().as_fd(), &self.prev);
    }
}

/// Interactive `kennel run`: the workload's controlling pty is allocated by the spawn
/// seal inside the kennel's *own* devpts (so `ttyname(3)`/`tty` resolve it), and the
/// seal hands its master back to us over a socketpair. We put this terminal in raw
/// mode and proxy bytes both ways until the workload exits. The workload's shell then
/// has real job control (`^Z`/`fg`/`bg`); the terminal is restored on exit.
fn run_interactive(mut conn: UnixStream, request: &Request) -> Result<ExitCode, String> {
    use kennel_lib_syscall::pty;
    let real_in = io::stdin();
    // Raw mode now; the guard restores the terminal on every return below.
    let prev = pty::make_raw(real_in.as_fd()).map_err(|e| format!("setting raw mode: {e}"))?;
    let _restore = RawGuard { prev };
    // Block SIGWINCH before the relay thread is spawned so it can `sigwait` it.
    let _ = pty::block_winch();

    // A socketpair the seal returns the pty master over: we keep `ours`, the daemon
    // passes `theirs` (over SCM_RIGHTS) down into the workload's pre-exec seal.
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    send(&conn, request, &[theirs.as_fd()])?;
    drop(theirs);

    // The daemon confirms the launch (or reports a bring-up failure). On success the
    // seal has, by now, sent the master over `ours`; reading the response first means a
    // failed bring-up does not leave us blocking on a master that will never arrive.
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Started { .. } => {}
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    let master = recv_pty_master(&ours)?;
    // Size the workload's terminal to ours, then proxy until it exits.
    if let Ok(ws) = pty::get_winsize(real_in.as_fd()) {
        let _ = pty::set_winsize(master.as_fd(), &ws);
    }
    proxy_terminal(&master, real_in.as_fd())?;
    // Block until the workload exits; `_restore` then puts the terminal back.
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Exited { code } => Ok(exit_code(code)),
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Receive the workload's controlling-pty master, sent by the spawn seal over `sock`
/// as a single `SCM_RIGHTS` fd (with a one-byte payload).
fn recv_pty_master(sock: &UnixStream) -> Result<OwnedFd, String> {
    let mut buf = [0u8; 1];
    let (_, mut fds) = kennel_lib_syscall::scm::recv_with_fds(sock.as_fd(), &mut buf)
        .map_err(|e| format!("receiving the workload pty: {e}"))?;
    fds.pop()
        .ok_or_else(|| "the workload did not return a controlling terminal".to_owned())
}

/// Spawn the background copies between this terminal and the pty `master`: stdin →
/// master, master → stdout, and a SIGWINCH relay for live resizes. Each thread owns
/// dup'd fds, so they outlive these borrows and are reaped when the process exits.
fn proxy_terminal(master: &OwnedFd, real_in: BorrowedFd<'_>) -> Result<(), String> {
    let dup = |fd: BorrowedFd<'_>| fd.try_clone_to_owned().map_err(|e| format!("fd dup: {e}"));
    let to_workload = master.try_clone().map_err(|e| format!("pty dup: {e}"))?;
    let from_workload = master.try_clone().map_err(|e| format!("pty dup: {e}"))?;
    let winch_master = master.try_clone().map_err(|e| format!("pty dup: {e}"))?;
    let stdin_dup = dup(real_in)?;
    let stdout_dup = dup(io::stdout().as_fd())?;
    let winch_in = dup(real_in)?;
    // stdin → master
    std::thread::spawn(move || {
        let mut r = std::fs::File::from(stdin_dup);
        let mut w = std::fs::File::from(to_workload);
        let _ = std::io::copy(&mut r, &mut w);
    });
    // master → stdout
    std::thread::spawn(move || {
        let mut r = std::fs::File::from(from_workload);
        let mut w = std::fs::File::from(stdout_dup);
        let _ = std::io::copy(&mut r, &mut w);
    });
    // SIGWINCH → propagate the new window size to the workload
    std::thread::spawn(move || kennel_lib_syscall::pty::relay_winch(winch_in, winch_master));
    Ok(())
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
    kennel_lib_syscall::scm::send_with_fds(conn.as_fd(), &framed, fds)
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

    let policy_arg = policy_path.ok_or(
        "usage: kennel compile <policy> [--output-path P] [--key K | --unsigned] [--template-dir D]...",
    )?;
    // `<policy>` is a path or a name resolved from the `policies/` cascade,
    // preferring the source `policy.toml` (the artefact we are about to compile).
    let (policy_path, _name) = resolve_policy(policy_arg, false)?;
    if key_path.is_some() && unsigned {
        return Err("--key and --unsigned are mutually exclusive".to_owned());
    }
    // Sign with the given `--key`, else the sole key in the user key dir; `--unsigned`
    // opts out entirely (a development build). `default_signing_key` errors helpfully
    // if there is no key or several to choose from.
    let signing_key: Option<PathBuf> = if unsigned {
        None
    } else {
        Some(match key_path {
            Some(p) => PathBuf::from(p),
            None => default_signing_key()?,
        })
    };
    add_default_template_dirs(&mut template_dirs);

    let bytes = std::fs::read(&policy_path)
        .map_err(|e| format!("reading {}: {e}", policy_path.display()))?;

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
    add_system_trust_dirs(&mut trust_dirs);
    let keys = load_trust_store(&trust_dirs)?;
    let trust = if require_signed {
        kennel_lib_policy::Trust::require(&keys)
    } else {
        kennel_lib_policy::Trust::allow_unsigned(Some(&keys))
    };

    let mut compiled = match build_settled(&bytes, &source, &trust, version) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("kennel: {e}");
            return Ok(ExitCode::from(policy_error_code(&e)));
        }
    };
    print_warnings(&compiled.warnings);
    // Resolve the shared-library closure of the allowlist into the settled artefact
    // (reads the binaries from disk; deny-by-default execution, 07-3) before signing.
    print_warnings(&kennel_lib_policy::resolve_settled_loaders(
        &mut compiled.policy,
    ));

    let out =
        output_path.unwrap_or_else(|| default_settled_path(&policy_path, &compiled.policy.name));

    // Mint the per-destination SSH synthetic keypairs into `<artefact-dir>/ssh/` and pin
    // each public half into the settled `[ssh]` grants BEFORE signing, so the signature
    // covers the keys the bastion will trust (§7.10.3). Idempotent: an existing keypair is
    // reused (persisted across recompiles), so the kennel's `~/.ssh` is stable.
    let ssh_dir = out.parent().unwrap_or_else(|| Path::new(".")).join("ssh");
    let _ = mint_ssh_keys(&mut compiled.policy, &ssh_dir)?;
    let policy = &compiled.policy;

    // Byte-pin the resolved references: check the fresh lockfile against any prior
    // `<name>.lock` beside the output, then (re)write it. A re-tagged/re-signed
    // reference is an integrity failure (exit 6).
    if !no_lock {
        let lock_path = lock_path_for(&out, &policy.name);
        if let Ok(prev_bytes) = std::fs::read(&lock_path) {
            let previous = kennel_lib_policy::Lockfile::parse(&prev_bytes)
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

    let doc = if let Some(key_path) = &signing_key {
        let key = load_signing_key(key_path)?;
        kennel_lib_policy::sign_settled(policy, &key).map_err(|e| format!("signing: {e}"))?
    } else {
        kennel_lib_policy::seal_unsigned(policy)
    };
    let out_bytes = kennel_lib_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))?;
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
    kennel_lib_policy::parse_source(bytes).is_ok() || kennel_lib_policy::parse_leaf(bytes).is_ok()
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
        Self::write_in(&dir, name, bytes)
    }

    /// Write `bytes` to a unique path **in `dir`**, keyed by kennel name and pid. Used when
    /// the settled artefact must sit beside a sibling the daemon resolves relative to it
    /// (the `ssh/` minted-key dir) — so `<settled>.parent()/ssh` finds the keys.
    fn write_in(dir: &Path, name: &str, bytes: &[u8]) -> Result<Self, String> {
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

/// Mint (or reuse) one synthetic ed25519 keypair per `[ssh]` destination under
/// `ssh_dir`, recording each public half + key-file basename into the settled grant.
///
/// The synthetic key is the capability the kennel authenticates to the bastion with; it
/// is NOT a real key and holds no access on its own (the bastion's forced command, keyed
/// to this public half, runs `ssh <options> -- <dest>` as the operator host-side). Minting
/// at compile time and pinning the public half into the signed artefact means the akc
/// trusts only a key the signature covers. Idempotent: an existing `<key_id>` keypair is
/// reused, so the kennel's `~/.ssh` is stable across recompiles (the keys persist beside
/// the artefact in the policy dir).
/// Returns whether any key was minted (i.e. the policy has `[ssh]` grants) — the caller
/// uses this to keep the settled artefact beside the `ssh/` dir the daemon resolves from.
fn mint_ssh_keys(
    policy: &mut kennel_lib_policy::SettledPolicy,
    ssh_dir: &Path,
) -> Result<bool, String> {
    if policy.ssh.grants.is_empty() {
        return Ok(false);
    }
    std::fs::create_dir_all(ssh_dir).map_err(|e| format!("creating {}: {e}", ssh_dir.display()))?;
    for grant in &mut policy.ssh.grants {
        let key_id = grant.key_id();
        let key_path = ssh_dir.join(&key_id);
        let pub_path = ssh_dir.join(format!("{key_id}.pub"));
        if !key_path.exists() || !pub_path.exists() {
            // Mint a fresh disposable keypair. `-N ""` (no passphrase): the kennel reads the
            // private key non-interactively, and it is a capability token, not a secret of value.
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", ""])
                .arg("-C")
                .arg(format!("kennel-ssh {}", grant.dest))
                .arg("-f")
                .arg(&key_path)
                .status()
                .map_err(|e| format!("running ssh-keygen: {e}"))?;
            if !status.success() {
                return Err(format!("ssh-keygen failed for `{}`", grant.dest));
            }
        }
        let pub_line = std::fs::read_to_string(&pub_path)
            .map_err(|e| format!("reading {}: {e}", pub_path.display()))?;
        pub_line.trim().clone_into(&mut grant.public_key);
        grant.key_file = key_id;
    }
    Ok(true)
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
    trust: &kennel_lib_policy::Trust<'_>,
    version: &str,
) -> Result<kennel_lib_policy::Compiled, kennel_lib_policy::PolicyError> {
    match kennel_lib_policy::parse_source(bytes) {
        Ok(entry) => kennel_lib_policy::compile(&entry, source, trust, version),
        Err(source_err) => kennel_lib_policy::parse_leaf(bytes).map_or(Err(source_err), |leaf| {
            kennel_lib_policy::compile_leaf(&leaf, source, trust, version)
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
    add_system_trust_dirs(&mut trust_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let keys = load_trust_store(&trust_dirs)?;
    let trust = if require_signed {
        kennel_lib_policy::Trust::require(&keys)
    } else {
        kennel_lib_policy::Trust::allow_unsigned(Some(&keys))
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

/// `kennel policy list` — enumerate policies and templates in the search path.
///
/// Walks the `policies/` and `templates/` cascades (`~/.config/kennel`,
/// `/etc/kennel`, `/usr/lib/kennel`) and prints each artefact's name, kind, and the
/// directory it was found in. A read-only survey; touches no daemon.
fn policy_list(args: &[String]) -> Result<ExitCode, String> {
    if !args.is_empty() {
        return Err(usage_of(POLICY_VERBS, "list"));
    }
    let user = kennel_lib_config::User::load().unwrap_or_default();
    let mut found = false;
    for (label, dirs) in [
        ("policies", user.policy_dirs()),
        ("templates", user.template_dirs()),
    ] {
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut names: Vec<(String, &'static str)> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let kind = if path.join(format!("{name}.settled.toml")).is_file() {
                    "settled"
                } else if path.join("policy.toml").is_file() {
                    policy_kind(&path.join("policy.toml"))
                } else {
                    continue;
                };
                names.push((name.to_owned(), kind));
            }
            if names.is_empty() {
                continue;
            }
            found = true;
            names.sort();
            println!("{label}: {}", dir.display());
            for (name, kind) in names {
                println!("  {name}  ({kind})");
            }
        }
    }
    if !found {
        println!("no policies or templates found in the search path");
    }
    Ok(ExitCode::SUCCESS)
}

/// Classify a `policy.toml` as a `template` (has `template_name`) or `leaf` (has `name`),
/// by a cheap parse. Unparseable or ambiguous files report `source`.
fn policy_kind(path: &Path) -> &'static str {
    let Ok(bytes) = std::fs::read(path) else {
        return "source";
    };
    kennel_lib_policy::parse_source(&bytes).map_or("source", |p| {
        if p.template_name.is_some() {
            "template"
        } else if p.name.is_some() {
            "leaf"
        } else {
            "source"
        }
    })
}

/// `kennel policy show <policy>` — resolve a policy and print what it actually means.
///
/// Compiles a source policy in memory (or reads a settled artefact) and prints the
/// effective policy in human-readable form: the network posture (mode + whether an
/// egress proxy stands up), filesystem grants, the exec allowlist, the embedded
/// workload, and the TTL. This is the tool to catch "the template says X but resolves
/// to Y" — e.g. a `mode = open` policy that still carries a proxy listener.
fn policy_show(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_arg: Option<String> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut p = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = p.next().map_err(|e| e.to_string())? {
        match arg {
            lexopt::Arg::Long("template-dir") => {
                template_dirs.push(lexopt_value(&mut p, "--template-dir")?);
            }
            lexopt::Arg::Long("trust-dir") => {
                trust_dirs.push(lexopt_value(&mut p, "--trust-dir")?);
            }
            lexopt::Arg::Value(v) if policy_arg.is_none() => {
                policy_arg = Some(v.to_string_lossy().into_owned());
            }
            other => return Err(lexopt_unexpected(&other, POLICY_VERBS, "show")),
        }
    }
    let policy_arg = policy_arg.ok_or_else(|| usage_of(POLICY_VERBS, "show"))?;
    let (policy_file, _name) = resolve_policy(&policy_arg, false)?;
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;

    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let policy = if is_source_policy(&bytes) {
        let source = FsTemplateSource {
            dirs: template_dirs,
        };
        let keys = load_trust_store(&trust_dirs)?;
        let trust = kennel_lib_policy::Trust::allow_unsigned(Some(&keys));
        let mut compiled = build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
            .map_err(|e| format!("compiling {}: {e}", policy_file.display()))?;
        print_warnings(&compiled.warnings);
        print_warnings(&kennel_lib_policy::resolve_settled_loaders(
            &mut compiled.policy,
        ));
        compiled.policy
    } else {
        let keys = load_trust_store(&trust_dirs)?;
        kennel_lib_policy::verify_settled(&bytes, &keys)
            .map_err(|e| format!("verifying {}: {e}", policy_file.display()))?
    };
    print_effective_policy(&policy);
    Ok(ExitCode::SUCCESS)
}

/// Print the effective policy in a human-readable summary (the `policy show` body).
fn print_effective_policy(policy: &kennel_lib_policy::SettledPolicy) {
    use kennel_lib_policy::NetMode;
    let ep = &policy.effective_policy;
    println!("policy `{}`", policy.name);

    // Network: the mode AND whether an egress proxy stands up. The daemon launches the
    // SOCKS proxy for a constrained kennel; an `open` kennel egresses directly. So an
    // `open` policy is INCOHERENT today if it still constrains egress through the proxy —
    // exactly the `interactive` bug Thread 6 fixes. Report the mode and flag that case.
    let mode = match ep.net.mode {
        NetMode::None => "none (no network)",
        NetMode::Constrained => "constrained (egress proxy, default-deny)",
        NetMode::Unconstrained => "unconstrained (egress proxy, default-allow + invariant denies)",
        NetMode::Host => {
            "host (host netns, direct egress, BPF/Landlock allowlist; reinstates T1.6)"
        }
    };
    println!("  network: {mode}");
    if !ep.net.allow.is_empty() || !ep.net.allow_names.is_empty() {
        println!(
            "    allow: {} cidr rule(s), {} name rule(s)",
            ep.net.allow.len(),
            ep.net.allow_names.len()
        );
    }
    if !ep.net.deny_invariant.is_empty() {
        println!("    invariant denies: {}", ep.net.deny_invariant.len());
    }

    // Filesystem grants.
    if !ep.fs.read.is_empty() {
        println!("  fs.read: {}", ep.fs.read.join(", "));
    }
    if !ep.fs.write.is_empty() {
        println!("  fs.write: {}", ep.fs.write.join(", "));
    }

    // Exec allowlist.
    if ep.exec.allow.is_empty() {
        println!("  exec: deny-all (no exec.allow)");
    } else {
        println!("  exec.allow: {} entry(ies)", ep.exec.allow.len());
    }

    // Workload (the [workload] feature).
    if !policy.workload.is_empty() {
        let pin = if policy.workload.pinned {
            " [pinned]"
        } else {
            ""
        };
        let sha = if policy.workload.sha256.is_empty() {
            String::new()
        } else {
            format!(" [{} sha256 pin(s)]", policy.workload.sha256.len())
        };
        println!("  workload: {}{pin}{sha}", policy.workload.argv.join(" "));
    }

    // TTL.
    if let Some(ttl) = ep.lifecycle.ttl_seconds {
        println!("  ttl: {ttl}s ({:?})", ep.lifecycle.ttl_action);
    }
}

/// The user's own `policies/` dir (`$XDG_CONFIG_HOME/kennel/policies`, else
/// `~/.config/kennel/policies`) — where `generate` writes and `edit` copies into. Mirrors
/// `default_key_dir`'s base resolution so the two agree on the user-config root.
fn user_policies_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("kennel").join("policies")
}

/// `kennel policy edit <name>` — open the policy's source in `$EDITOR`.
///
/// Resolves `<name>` to its source `policy.toml`. If that source lives in a read-only
/// system dir (`/etc/kennel`, `/usr/lib/kennel`), it is copied into the user's
/// `policies/<name>/` first (copy-on-write) so edits never try to mutate the system copy;
/// the user copy then shadows the system one in the cascade. `$EDITOR` (then `$VISUAL`,
/// else `vi`) is launched on the resulting path.
fn policy_edit(args: &[String]) -> Result<ExitCode, String> {
    let [name] = args else {
        return Err(usage_of(POLICY_VERBS, "edit"));
    };
    if !is_valid_policy_name(name) {
        return Err(format!("`{name}` is not a valid policy name"));
    }
    let (source, _) = resolve_policy(name, false)?;
    // A source under a system dir is copied into the user config first (COW), unless a
    // user copy already shadows it.
    let target = if is_under_system_dir(&source) {
        let dest = user_policies_dir().join(name).join("policy.toml");
        if !dest.is_file() {
            let dest_dir = dest.parent().unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(dest_dir)
                .map_err(|e| format!("creating {}: {e}", dest_dir.display()))?;
            std::fs::copy(&source, &dest)
                .map_err(|e| format!("copying {} to {}: {e}", source.display(), dest.display()))?;
            eprintln!(
                "kennel: copied system policy into {} for editing",
                dest.display()
            );
        }
        dest
    } else {
        source
    };
    let editor = std::env::var_os("EDITOR")
        .or_else(|| std::env::var_os("VISUAL"))
        .unwrap_or_else(|| "vi".into());
    let status = std::process::Command::new(&editor)
        .arg(&target)
        .status()
        .map_err(|e| format!("launching editor {}: {e}", editor.to_string_lossy()))?;
    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(format!("editor exited with {status}"))
    }
}

/// Whether `path` lives under a read-only system policy/template dir.
fn is_under_system_dir(path: &Path) -> bool {
    path.starts_with("/etc/kennel") || path.starts_with("/usr/lib/kennel")
}

/// `kennel policy generate <name> [--from <template>]` — scaffold a new leaf policy.
///
/// Writes `~/.config/kennel/policies/<name>/policy.toml`: a minimal leaf that inherits
/// `--from` (default `base-confined@v1`), with a commented `[workload]` stub to fill in.
/// Refuses to overwrite an existing policy. Prints next steps (`policy show`/`compile`).
fn policy_generate(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<String> = None;
    let mut from = "base-confined@v1".to_owned();
    let mut p = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = p.next().map_err(|e| e.to_string())? {
        match arg {
            lexopt::Arg::Long("from") => {
                from = p
                    .value()
                    .map_err(|_| "--from needs a value")?
                    .to_string_lossy()
                    .into_owned();
            }
            lexopt::Arg::Value(v) if name.is_none() => {
                name = Some(v.to_string_lossy().into_owned());
            }
            other => return Err(lexopt_unexpected(&other, POLICY_VERBS, "generate")),
        }
    }
    let name = name.ok_or_else(|| usage_of(POLICY_VERBS, "generate"))?;
    if !is_valid_policy_name(&name) {
        return Err(format!("`{name}` is not a valid policy name"));
    }
    // `--from` must be a `<template>@v<ver>` reference (the leaf's template_base).
    if !from.contains('@') {
        return Err(format!(
            "--from `{from}` must be a versioned reference, e.g. `base-confined@v1`"
        ));
    }
    let dir = user_policies_dir().join(&name);
    let dest = dir.join("policy.toml");
    if dest.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite",
            dest.display()
        ));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let scaffold = format!(
        "# Leaf policy `{name}` — see `kennel policy show {name}` for what it resolves to.\n\
         name = \"{name}\"\n\
         template_base = \"{from}\"\n\
         \n\
         # The command this kennel runs (optional — omit to pass `-- <cmd>` at run time).\n\
         # [workload]\n\
         # argv = [\"/bin/bash\"]\n\
         # pinned = false          # refuse a `-- <cmd>` override unless --force\n\
         # sha256 = []             # accepted binary digests (empty = no pin)\n"
    );
    std::fs::write(&dest, scaffold).map_err(|e| format!("writing {}: {e}", dest.display()))?;
    eprintln!("generated {}", dest.display());
    eprintln!("next: `kennel policy show {name}`, then `kennel policy compile {name}`");
    Ok(ExitCode::SUCCESS)
}

/// `kennel policy lint` — check the templates in the search path for incoherences.
///
/// Compiles every `<name>/policy.toml` found in the template cascade (in memory, dev trust)
/// and runs `lint_settled` on the resolved policy, reporting any finding — settings that
/// contradict the resolved net mode, or grants the mode makes vacuous. Exit 0 if all clean,
/// 7 if any template lints with a finding (a CI-friendly distinct code).
fn policy_lint(args: &[String]) -> Result<ExitCode, String> {
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut p = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = p.next().map_err(|e| e.to_string())? {
        match arg {
            lexopt::Arg::Long("template-dir") => {
                template_dirs.push(lexopt_value(&mut p, "--template-dir")?);
            }
            lexopt::Arg::Long("trust-dir") => {
                trust_dirs.push(lexopt_value(&mut p, "--trust-dir")?);
            }
            other => return Err(lexopt_unexpected(&other, POLICY_VERBS, "lint")),
        }
    }
    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let keys = load_trust_store(&trust_dirs)?;
    let trust = kennel_lib_policy::Trust::allow_unsigned(Some(&keys));
    let source = FsTemplateSource {
        dirs: template_dirs.clone(),
    };

    // Enumerate template names across the cascade (deduped — a closer dir shadows a farther).
    let mut seen: Vec<String> = Vec::new();
    for dir in &template_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.join("policy.toml").is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !seen.iter().any(|s| s == name) {
                    seen.push(name.to_owned());
                }
            }
        }
    }
    seen.sort();

    let mut total = 0usize;
    let mut linted = 0usize;
    for name in &seen {
        let Some(bytes) = source.fetch(name, "v1") else {
            continue;
        };
        let mut compiled = match build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION")) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{name}: did not compile: {e}");
                total = total.saturating_add(1);
                continue;
            }
        };
        print_warnings(&kennel_lib_policy::resolve_settled_loaders(
            &mut compiled.policy,
        ));
        let findings = kennel_lib_policy::lint_settled(&compiled.policy);
        linted = linted.saturating_add(1);
        for f in &findings {
            println!("{name}: {f}");
            total = total.saturating_add(1);
        }
    }
    if total == 0 {
        eprintln!("lint: {linted} template(s) clean");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("lint: {total} finding(s) across {linted} template(s)");
        Ok(ExitCode::from(7))
    }
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
    let policy = kennel_lib_policy::parse_source(&bytes).map_err(|e| {
        format!("{path} is not a signable source template/fragment ({e}); leaf policies may stay unsigned")
    })?;
    if policy.signature.is_some() {
        return Err(format!(
            "{path} already carries a [signature]; remove it before re-signing"
        ));
    }

    let key = load_signing_key(Path::new(key_path))?;
    let signed =
        kennel_lib_policy::sign_source(&policy, &key).map_err(|e| format!("signing: {e}"))?;
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
        kennel_lib_policy::b64::encode(&key.public_key_bytes())
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
        | E::IncludeConflict(_) => 3,
    }
}

/// Append the default template search directories: the user `config.toml`'s
/// `template_dirs` if set, else the built-in default (user config dir, then
/// system). A malformed user config falls back to the built-in default.
fn add_default_template_dirs(dirs: &mut Vec<PathBuf>) {
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
fn resolve_policy(arg: &str, prefer_settled: bool) -> Result<(PathBuf, String), String> {
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
fn add_system_trust_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .system_key_dirs(),
    );
}

/// Load a trust store: every `<key_id>.pub` (base64 32-byte public key) under each
/// directory. Missing directories are skipped; a malformed key file is an error.
fn load_trust_store(dirs: &[PathBuf]) -> Result<kennel_lib_policy::KeySet, String> {
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
fn load_signing_key(path: &Path) -> Result<kennel_lib_policy::SigningKey, String> {
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
fn default_signing_key() -> Result<PathBuf, String> {
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
}
