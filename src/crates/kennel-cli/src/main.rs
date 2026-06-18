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
use std::io::IsTerminal as _;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_compile::TemplateSource;
use kennel_lib_control::control::{self, Request, Response, StartRequest};
use kennel_lib_control::socket;

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
        "attach" => attach(rest),
        "review" => review(rest),
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
        "risks" => policy_risks(rest),
        "diff" => policy_diff(rest),
        "upgrade" => upgrade(rest),
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
        let trust = kennel_lib_compile::Trust::allow_unsigned(Some(&keys));
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

    // Pre-flight: ensure a `.trust-manifest.json` at each writable workspace root before
    // the kennel boots (mirrors SSH-key provisioning). The kennel will mask the manifest
    // invisible, so the agent cannot forge the integrity pins host tooling trusts (T2.8).
    // Read from the settled bytes we hold; host-side, never contacts kenneld.
    let settled_bytes = std::fs::read(&effective_policy)
        .map_err(|e| format!("reading {} for pre-flight: {e}", effective_policy.display()))?;
    ensure_workspace_manifests(&settled_bytes);
    // Resolve the host paths kenneld's live tripwire should watch (§2.5) — computed here,
    // CLI-side, because the catalogue lives in this crate; the daemon just watches the list.
    let watch_paths = workspace_watch_paths(&settled_bytes);

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
        watch_paths,
    });

    let mut conn = connect()?;
    if io::stdin().is_terminal() {
        return run_interactive(conn, &request, &name);
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

/// Ensure a masked-workspace manifest at the root of each writable host path the settled
/// policy grants (§7.4, T2.8) — the CLI pre-flight half of the feature. Best-effort: a
/// parse or generation failure warns and is skipped (it must never block a run; the worst
/// case is a missing manifest, which the host IDE simply treats as "no trust marker").
///
/// Reads `fs.write` from the settled policy, expands the home prefix (`~`/`$HOME` → the
/// operator's real home — the same expansion the spawn does to get the bind *source*),
/// strips any `/**` glob, and for each existing directory writes a baseline manifest if
/// one is absent. An existing manifest is left untouched — refreshing pins is the explicit
/// `kennel review` step, never an implicit side effect of `run` (else it would launder an
/// agent's edits).
fn ensure_workspace_manifests(settled_bytes: &[u8]) {
    let policy = match kennel_lib_policy::parse_settled_unverified(settled_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kennel: skipping workspace manifests (cannot read settled policy: {e})");
            return;
        }
    };
    if !policy.effective_policy.trust.manifest {
        return; // [trust].manifest = false: the operator opted out.
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("kennel: skipping workspace manifests (HOME is not set)");
        return;
    };
    let generator = format!("kennel {}", env!("CARGO_PKG_VERSION"));
    for entry in &policy.effective_policy.fs.write {
        let Some(root) = writable_root(entry, &home) else {
            continue; // not a home-or-absolute path we can resolve to a host dir
        };
        if !root.is_dir() {
            continue; // a writable file (not a workspace dir) gets no manifest
        }
        let path = kennel_lib_manifest::manifest_path(&root);
        if path.exists() {
            continue; // leave it — refresh is `kennel review`, not `run`
        }
        let (manifest, errors) =
            kennel_lib_manifest::generate(&root, &generator, &kennel_lib_manifest::Catalogue::load());
        for e in &errors {
            eprintln!(
                "kennel: manifest trigger skipped under {}: {e}",
                root.display()
            );
        }
        match manifest.to_json() {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    eprintln!("kennel: could not write {}: {e}", path.display());
                } else {
                    eprintln!("kennel: wrote trust manifest {}", path.display());
                }
            }
            Err(e) => eprintln!("kennel: could not serialise {}: {e}", path.display()),
        }
    }
}

/// Resolve the host paths kenneld's live tripwire should watch (§2.5): each writable
/// workspace root's existing catalogue trigger files plus its existing trigger directories.
///
/// Host paths — the writable bind maps them to the same inodes the workload writes, so an
/// inotify on the host catches the workload's writes; watching the trigger directories
/// catches a freshly planted hook. Empty when `[trust].manifest = false`.
fn workspace_watch_paths(settled_bytes: &[u8]) -> Vec<PathBuf> {
    let Ok(policy) = kennel_lib_policy::parse_settled_unverified(settled_bytes) else {
        return Vec::new();
    };
    if !policy.effective_policy.trust.manifest {
        return Vec::new();
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let catalogue = kennel_lib_manifest::Catalogue::load();
    let mut paths = Vec::new();
    for entry in &policy.effective_policy.fs.write {
        let Some(root) = writable_root(entry, &home) else {
            continue;
        };
        if !root.is_dir() {
            continue;
        }
        for rel in kennel_lib_manifest::enumerate_triggers(&root, &catalogue) {
            paths.push(root.join(rel));
        }
        for dir in &catalogue.dirs {
            let abs = root.join(dir);
            if abs.is_dir() {
                paths.push(abs);
            }
        }
    }
    paths
}

/// `kennel review <policy> [--yes]` — the operator's sign-off on a workspace's trust
/// manifest after legitimate edits (T2.8). The confined workload cannot update the manifest
/// (it is masked), so changed/added execution triggers stay flagged until a human re-pins
/// them here, host-side.
///
/// Resolves `<policy>` to its settled artefact (like `run`, preferring the compiled
/// `<name>.settled.toml`), reads each writable root's `.trust-manifest.json`, and shows a
/// unified diff of modified / removed / new triggers. The default sign-off **re-pins**
/// (adopts the on-disk state, so the host IDE unlocks); `--revert` instead **restores** each
/// trigger to its pinned baseline and removes planted ones (the §2.5 teardown disposition).
/// `--yes` skips the per-root confirmation.
fn review(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_arg: Option<&str> = None;
    let mut assume_yes = false;
    let mut do_revert = false;
    for a in args {
        match a.as_str() {
            "--yes" | "-y" => assume_yes = true,
            // Restore each divergent trigger to its pinned baseline instead of re-pinning
            // (the `revert` teardown disposition, §2.5): a tampered/deleted trigger is rebuilt
            // from its blob, a planted (unpinned) one is removed.
            "--revert" => do_revert = true,
            other if other.starts_with('-') => {
                return Err(format!("kennel review: unknown flag `{other}`"));
            }
            other => {
                if policy_arg.replace(other).is_some() {
                    return Err("usage: kennel review <policy> [--yes] [--revert]".to_owned());
                }
            }
        }
    }
    let policy_arg = policy_arg.ok_or("usage: kennel review <policy> [--yes] [--revert]")?;
    let (policy_file, _name) = resolve_policy(policy_arg, true)?;
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;
    if is_source_policy(&bytes) {
        return Err(format!(
            "`{}` is a source policy — compile it first (`kennel policy compile {policy_arg}`), then review the settled artefact",
            policy_file.display()
        ));
    }
    let policy = kennel_lib_policy::parse_settled_unverified(&bytes)
        .map_err(|e| format!("reading settled policy {}: {e}", policy_file.display()))?;
    if !policy.effective_policy.trust.manifest {
        eprintln!("kennel: `[trust].manifest = false` for this policy — nothing to review");
        return Ok(ExitCode::SUCCESS);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let generator = format!("kennel {}", env!("CARGO_PKG_VERSION"));

    let mut roots_reviewed = 0usize;
    let mut total_divergences = 0usize;
    for entry in &policy.effective_policy.fs.write {
        let Some(root) = writable_root(entry, &home) else {
            continue;
        };
        let (reviewed, divergences) = review_one_root(&root, &generator, assume_yes, do_revert)?;
        if reviewed {
            roots_reviewed = roots_reviewed.saturating_add(1);
        }
        total_divergences = total_divergences.saturating_add(divergences);
    }

    if roots_reviewed == 0 {
        eprintln!("kennel: no trust manifests found for `{policy_arg}` (none generated yet?)");
    } else if total_divergences == 0 {
        eprintln!("kennel: all trust manifests are clean");
    }
    Ok(ExitCode::SUCCESS)
}

/// Review one writable root's manifest: show divergences (with diffs), then revert to
/// baseline (`--revert`) or re-pin per the flags. Returns `(reviewed, divergences)` —
/// `reviewed` is false when the root has no manifest yet.
fn review_one_root(
    root: &Path,
    generator: &str,
    assume_yes: bool,
    do_revert: bool,
) -> Result<(bool, usize), String> {
    let manifest_path = kennel_lib_manifest::manifest_path(root);
    if !manifest_path.is_file() {
        return Ok((false, 0)); // no manifest at this root (e.g. not generated yet)
    }
    let raw = std::fs::read(&manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    let mut manifest = kennel_lib_manifest::Manifest::from_json(&raw)
        .map_err(|e| format!("parsing {}: {e}", manifest_path.display()))?;
    let changes = kennel_lib_manifest::review(&manifest, root, &kennel_lib_manifest::Catalogue::load())
        .map_err(|e| format!("reviewing {}: {e}", root.display()))?;
    let divergences: Vec<_> = changes.iter().filter(|c| c.is_divergence()).collect();
    if divergences.is_empty() {
        println!("{}: no changes", root.display());
        return Ok((true, 0));
    }
    println!("{}:", root.display());
    for change in &divergences {
        print_trigger_change(change);
        show_trigger_diff(root, change);
    }
    if do_revert {
        if assume_yes || prompt_yes(&format!("revert {} trigger(s) to baseline?", divergences.len()))? {
            for change in &divergences {
                match kennel_lib_manifest::revert(root, change) {
                    Ok(()) => println!("  reverted {}", change_path_of(change)),
                    Err(e) => eprintln!("  warning: revert {}: {e}", change_path_of(change)),
                }
            }
        } else {
            println!("  left unchanged");
        }
        return Ok((true, divergences.len()));
    }
    if assume_yes || prompt_yes(&format!("re-pin {}?", manifest_path.display()))? {
        let errs = kennel_lib_manifest::apply_review(&mut manifest, root, &changes, generator);
        for e in &errs {
            eprintln!("  warning: {e}");
        }
        let json = manifest
            .to_json()
            .map_err(|e| format!("serialising {}: {e}", manifest_path.display()))?;
        std::fs::write(&manifest_path, json)
            .map_err(|e| format!("writing {}: {e}", manifest_path.display()))?;
        // GC the blob store down to the freshly re-pinned baseline (§3, steer 6).
        kennel_lib_manifest::prune_store(root, &manifest);
        println!("  re-pinned {}", manifest_path.display());
    } else {
        println!("  left unchanged");
    }
    Ok((true, divergences.len()))
}

/// Print one `git diff`-style line for a trigger change.
fn print_trigger_change(change: &kennel_lib_manifest::TriggerChange) {
    use kennel_lib_manifest::TriggerChange;
    match change {
        TriggerChange::Modified { path, .. } => println!("  ~ {path} (modified)"),
        TriggerChange::Removed { path, .. } => println!("  - {path} (removed)"),
        TriggerChange::New { path, .. } => println!("  + {path} (new, unpinned)"),
        TriggerChange::Unchanged { .. } => {}
    }
}

/// The relative path a [`kennel_lib_manifest::TriggerChange`] concerns.
fn change_path_of(change: &kennel_lib_manifest::TriggerChange) -> &str {
    use kennel_lib_manifest::TriggerChange;
    match change {
        TriggerChange::Unchanged { path }
        | TriggerChange::Removed { path, .. }
        | TriggerChange::Modified { path, .. }
        | TriggerChange::New { path, .. } => path,
    }
}

/// Show a unified diff of a `Modified` content trigger — the pinned baseline (from its blob)
/// against the tampered file on disk — via the system `diff` (as the manifest hashes via the
/// system `sha256sum`; no in-tree differ). Best-effort: a binary trigger or a missing blob
/// simply prints nothing extra.
fn show_trigger_diff(root: &Path, change: &kennel_lib_manifest::TriggerChange) {
    use kennel_lib_manifest::{TriggerChange, TriggerKind};
    let TriggerChange::Modified { path, entry, .. } = change else {
        return;
    };
    if entry.kind != TriggerKind::Content {
        return;
    }
    let Ok(pinned) = kennel_lib_manifest::read_blob(root, &entry.sha256) else {
        return;
    };
    // Stage the pinned bytes in a temp file and diff the live file against it.
    let tmp = std::env::temp_dir().join(format!("kennel-pin-{}-{}", std::process::id(), entry.sha256.replace(':', "_")));
    if std::fs::write(&tmp, &pinned).is_err() {
        return;
    }
    if let Ok(out) = std::process::Command::new("diff")
        .arg("-u")
        .arg("--label")
        .arg(format!("{path} (pinned)"))
        .arg("--label")
        .arg(format!("{path} (on disk)"))
        .arg(&tmp)
        .arg(root.join(path))
        .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            println!("    {line}");
        }
    }
    let _ = std::fs::remove_file(&tmp);
}

/// Prompt `question` on stderr and read a `y`/`n` answer from stdin. Non-`y` (incl. EOF) is
/// "no". A non-terminal stdin defaults to "no" — an unattended `review` never auto-re-pins
/// (use `--yes` to opt into that explicitly).
fn prompt_yes(question: &str) -> Result<bool, String> {
    use std::io::Write as _;
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush().map_err(|e| format!("stderr: {e}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Resolve a settled `fs.write` entry to its host directory root: expand a leading
/// `~`/`$HOME` to the operator's real `home`, strip a trailing `/**` or `/*` glob. Returns
/// `None` for an entry that does not name a home-relative or absolute path (nothing the
/// host can place a manifest under).
fn writable_root(entry: &str, home: &Path) -> Option<PathBuf> {
    let trimmed = entry
        .strip_suffix("/**")
        .or_else(|| entry.strip_suffix("/*"))
        .unwrap_or(entry);
    for tok in ["~", "$HOME"] {
        if trimmed == tok {
            return Some(home.to_path_buf());
        }
        if let Some(rest) = trimmed.strip_prefix(tok).and_then(|r| r.strip_prefix('/')) {
            return Some(home.join(rest));
        }
    }
    let path = Path::new(trimmed);
    path.is_absolute().then(|| path.to_path_buf())
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

/// Interactive `kennel run`: kenneld owns the workload's controlling pty (allocated by
/// the spawn seal inside the kennel's own devpts, so `ttyname(3)`/`tty` resolve it) and
/// brokers it to us. We pass one connected socket; the daemon's PTY broker fans the
/// kennel's filtered output to it and forwards our input to the master. We put this
/// terminal in raw mode and proxy bytes both ways. `Ctrl-\ d` **detaches** without
/// ending the workload (reattach with `kennel attach <name>`); the terminal is restored
/// on detach and on exit.
fn run_interactive(
    mut conn: UnixStream,
    request: &Request,
    name: &str,
) -> Result<ExitCode, String> {
    use kennel_lib_syscall::pty;
    let real_in = io::stdin();
    // Raw mode now; the guard restores the terminal on every return below.
    let prev = pty::make_raw(real_in.as_fd()).map_err(|e| format!("setting raw mode: {e}"))?;
    let _restore = RawGuard { prev };
    let _ = pty::block_winch();

    // One socket pair: the daemon's broker proxies the kennel's pty over `theirs`; we
    // keep `ours`. (Before, the seal sent the *master* fd to us; now the master stays in
    // kenneld and only bytes cross.)
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    send(&conn, request, &[theirs.as_fd()])?;
    drop(theirs);

    // The daemon confirms the launch (or reports a bring-up failure).
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Started { .. } => {}
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    proxy_session(conn, ours, name)
}

/// `kennel attach <name>`: reconnect a terminal to a still-running kennel's pty. The
/// daemon's broker takes over from any current client (the prior terminal gets a clean
/// "detached: another client attached"). Same raw-mode proxy and `Ctrl-\ d` detach as
/// an interactive `run`.
fn attach(args: &[String]) -> Result<ExitCode, String> {
    use kennel_lib_syscall::pty;
    let [name] = args else {
        return Err("usage: kennel attach <name>".to_owned());
    };
    if !io::stdin().is_terminal() {
        return Err("kennel attach needs a terminal on stdin".to_owned());
    }
    let real_in = io::stdin();
    let prev = pty::make_raw(real_in.as_fd()).map_err(|e| format!("setting raw mode: {e}"))?;
    let _restore = RawGuard { prev };
    let _ = pty::block_winch();

    let mut conn = connect()?;
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    send(
        &conn,
        &Request::Attach {
            kennel: name.clone(),
        },
        &[theirs.as_fd()],
    )?;
    drop(theirs);
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Attached { .. } => {}
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    proxy_session(conn, ours, name)
}

/// `Ctrl-\` (FS, `0x1c`) then `d`: the detach sequence (rarer in shell use than
/// docker's `Ctrl-p Ctrl-q`). Watched in the stdin path before bytes reach the broker.
const DETACH_LEAD: u8 = 0x1c;
const DETACH_KEY: u8 = b'd';

/// How a proxied terminal session ended.
enum SessionEnd {
    /// The operator pressed the detach key (`Ctrl-\ d`) — the workload keeps running.
    Detached,
    /// The control-connection reader received the daemon's final word and resolved the
    /// session to an exit code (or an error).
    Outcome(Result<ExitCode, String>),
}

/// Read the control connection for the whole session (§9.7): handle an operator-prompt
/// [`Response::Prompt`] inline — surface it on the now-quiet terminal (the workload is
/// frozen while a prompt is outstanding), capture the operator's single-key answer from the
/// stdin pump, and reply — then deliver the daemon's final `Exited`/`Detached`/`Error` as a
/// [`SessionEnd::Outcome`]. The sole reader and writer of `conn`, so prompt replies never
/// race the main thread.
// Runs as a `'static` thread body, so it must own its channel ends and the flag — the
// `Receiver` in particular cannot be borrowed across the thread boundary.
#[allow(clippy::needless_pass_by_value)]
fn control_reader(
    mut conn: UnixStream,
    mut term: std::fs::File,
    prompt_active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    answer_rx: std::sync::mpsc::Receiver<u8>,
    tx: std::sync::mpsc::Sender<SessionEnd>,
) {
    use std::io::Write as _;
    use std::sync::atomic::Ordering;
    let outcome = loop {
        match control::recv_response(&mut conn) {
            Ok(Response::Prompt { id, prompt }) => {
                let _ = write!(term, "\r\n{prompt} ");
                let _ = term.flush();
                prompt_active.store(true, Ordering::SeqCst);
                // The stdin pump diverts the next keypress here; a closed channel (pump
                // gone) reads as a decline.
                let key = answer_rx.recv().unwrap_or(b'n');
                let affirmative = key == b'y' || key == b'Y';
                let answer = if affirmative { "y" } else { "n" };
                let _ = write!(term, "{answer}\r\n");
                let _ = term.flush();
                let _ = control::send_request(
                    &mut conn,
                    &Request::PromptReply {
                        id,
                        answer: answer.to_owned(),
                    },
                );
            }
            Ok(Response::Exited { code }) => break Ok(exit_code(code)),
            Ok(Response::Detached { reason }) => {
                let _ = write!(term, "\r\ndetached: {reason}\r\n");
                break Ok(ExitCode::SUCCESS);
            }
            Ok(Response::Error(message)) => break Err(message),
            Ok(other) => break Err(format!("unexpected response: {other:?}")),
            Err(e) => break Err(format!("daemon: {e}")),
        }
    };
    let _ = tx.send(SessionEnd::Outcome(outcome));
}

/// Proxy this terminal to the kennel over the broker socket `ours` until detach or the
/// workload ends. Three background pumps: stdin → broker (scanning for the detach
/// sequence), broker → stdout, and a `SIGWINCH` → [`Request::Resize`] relay (the broker
/// holds the master, so we relay the size rather than `ioctl` it). On a local detach we
/// restore the terminal and exit 0; on a remote end we read the daemon's final
/// `Exited`/`Detached` over `conn`.
fn proxy_session(conn: UnixStream, ours: UnixStream, name: &str) -> Result<ExitCode, String> {
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Arc};
    // Tell the broker our initial size, then relay every later SIGWINCH.
    send_resize(name);
    let (tx, rx) = mpsc::channel::<SessionEnd>();
    // Set by the control reader while an operator prompt (§9.7) is outstanding; the stdin
    // pump then diverts the next keypress to `answer_tx` as the answer instead of the broker.
    let prompt_active = Arc::new(AtomicBool::new(false));
    let (answer_tx, answer_rx) = mpsc::channel::<u8>();

    // stdin → broker, watching for the `Ctrl-\ d` detach sequence and renew answers.
    let in_sock = ours.try_clone().map_err(|e| format!("socket dup: {e}"))?;
    let stdin_dup = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("stdin dup: {e}"))?;
    let tx_in = tx.clone();
    let pa_in = Arc::clone(&prompt_active);
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        let mut r = std::fs::File::from(stdin_dup);
        let mut w = in_sock;
        let mut buf = [0u8; 4096];
        // `armed` means we forwarded nothing yet for a held DETACH_LEAD byte and are
        // awaiting the next byte: DETACH_KEY → detach; anything else → emit the held
        // lead then the byte. A lead at end-of-read stays held into the next read.
        let mut armed = false;
        loop {
            use std::io::{Read as _, Write as _};
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut out: Vec<u8> = Vec::with_capacity(n.saturating_add(1));
            let mut detached = false;
            for &b in buf.get(..n).unwrap_or(&[]) {
                if pa_in.swap(false, Ordering::SeqCst) {
                    // A prompt is outstanding: this keypress is the answer, not workload
                    // input. Divert it and do not forward it.
                    let _ = answer_tx.send(b);
                } else if armed {
                    armed = false;
                    if b == DETACH_KEY {
                        detached = true;
                        break;
                    }
                    out.push(DETACH_LEAD); // the held lead was literal
                    out.push(b);
                } else if b == DETACH_LEAD {
                    armed = true; // hold it back, decide on the next byte
                } else {
                    out.push(b);
                }
            }
            if !out.is_empty() && w.write_all(&out).is_err() {
                break;
            }
            if detached {
                let _ = tx_in.send(SessionEnd::Detached);
                return;
            }
        }
    });

    // broker → stdout. Write to a `File` over the raw stdout fd, NOT `io::stdout()`: the
    // latter is a `LineWriter` against a terminal, which holds any bytes after the last
    // newline — so a shell prompt (`$ `, no trailing newline) would sit buffered until the
    // next newline echoed, making every prompt invisible until you hit Enter. A `File` is
    // unbuffered, so each chunk the broker sends reaches the terminal immediately.
    let stdout_dup = io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("stdout dup: {e}"))?;
    let mut out_sock = ours.try_clone().map_err(|e| format!("socket dup: {e}"))?;
    std::thread::spawn(move || {
        let mut w = std::fs::File::from(stdout_dup);
        let _ = std::io::copy(&mut out_sock, &mut w);
    });

    // Control connection reader: handles operator prompts inline and resolves the outcome.
    let term_dup = io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("stdout dup: {e}"))?;
    std::thread::spawn(move || {
        control_reader(
            conn,
            std::fs::File::from(term_dup),
            prompt_active,
            answer_rx,
            tx,
        );
    });

    // SIGWINCH → Resize relay.
    let resize_name = name.to_owned();
    std::thread::spawn(move || winch_resize_relay(&resize_name));

    // Whichever of the detach pump or the control reader resolves first ends the session.
    match rx.recv() {
        Ok(SessionEnd::Detached) => {
            // Close our end so the broker drops us; the workload keeps running.
            drop(ours);
            eprintln!("\r\ndetached from `{name}` (workload still running; `kennel attach {name}` to reconnect)");
            Ok(ExitCode::SUCCESS)
        }
        Ok(SessionEnd::Outcome(res)) => {
            drop(ours);
            res
        }
        Err(_) => {
            drop(ours);
            Err("session ended without an outcome".to_owned())
        }
    }
}

/// Relay terminal-resize events to the daemon: `sigwait` `SIGWINCH`, read this
/// terminal's new size, and send a [`Request::Resize`] for `name`. Runs after
/// `block_winch`; returns on a `sigwait` error.
fn winch_resize_relay(name: &str) {
    while kennel_lib_syscall::pty::wait_winch().is_ok() {
        send_resize(name);
    }
}

/// Read this terminal's window size and send it to the daemon as a [`Request::Resize`]
/// on a throwaway control connection (fire-and-forget; the broker `ioctl`s the master).
fn send_resize(name: &str) {
    use kennel_lib_syscall::pty;
    let Ok(ws) = pty::get_winsize(io::stdin().as_fd()) else {
        return;
    };
    let Ok(conn) = connect() else { return };
    let _ = send(
        &conn,
        &Request::Resize {
            kennel: name.to_owned(),
            rows: ws.ws_row,
            cols: ws.ws_col,
        },
        &[],
    );
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
                println!(
                    "{:<20} {:>5} {:>8}  {:<8} CLIENT",
                    "NAME", "CTX", "PID", "STATE"
                );
                for k in kennels {
                    let state = if k.running { "running" } else { "starting" };
                    // The terminal-attachment state of an interactive kennel: a
                    // detached kennel keeps running, reattachable with `kennel attach`.
                    let client = if k.attached { "attached" } else { "detached" };
                    println!(
                        "{:<20} {:>5} {:>8}  {state:<8} {client}",
                        k.kennel, k.ctx, k.pid
                    );
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

/// `kennel compile <policy> [--output P] [--key K] [--unsigned] [--template-dir D]...`
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
            "--output" => {
                output_path = Some(it.next().ok_or("--output needs a value")?.into());
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
        "usage: kennel compile <policy> [--output P] [--key K | --unsigned] [--template-dir D]...",
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
        kennel_lib_compile::Trust::require(&keys)
    } else {
        kennel_lib_compile::Trust::allow_unsigned(Some(&keys))
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
            let previous = kennel_lib_compile::Lockfile::parse(&prev_bytes)
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
        kennel_lib_compile::seal_unsigned(policy)
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
    kennel_lib_compile::parse_source(bytes).is_ok() || kennel_lib_compile::parse_leaf(bytes).is_ok()
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
    trust: &kennel_lib_compile::Trust<'_>,
    version: &str,
) -> Result<kennel_lib_compile::Compiled, kennel_lib_policy::PolicyError> {
    match kennel_lib_compile::parse_source(bytes) {
        Ok(entry) => kennel_lib_compile::compile(&entry, source, trust, version),
        Err(source_err) => kennel_lib_compile::parse_leaf(bytes).map_or(Err(source_err), |leaf| {
            kennel_lib_compile::compile_leaf(&leaf, source, trust, version)
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
        kennel_lib_compile::Trust::require(&keys)
    } else {
        kennel_lib_compile::Trust::allow_unsigned(Some(&keys))
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

/// `kennel policy risks <policy> [--template-dir D]... [--trust-dir D]... [--json]`
///
/// Evaluate a policy against the threat catalogue and report what its grants
/// **expose** and **mitigate**, each with the granting site, its documented reason,
/// and the catalogue residual. Source-driven (threat tags live only in the source +
/// compile-time derivation, never the settled artefact). Read-only; no daemon.
fn policy_risks(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_path: Option<&str> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut json = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if policy_path.is_none() => policy_path = Some(value),
            _ => return Err("only one <policy> may be given".to_owned()),
        }
    }
    let policy_path = policy_path.ok_or(
        "usage: kennel policy risks <policy> [--template-dir D]... [--trust-dir D]... [--json]",
    )?;
    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let keys = load_trust_store(&trust_dirs)?;
    let trust = kennel_lib_compile::Trust::allow_unsigned(Some(&keys));

    // The risk engine reads the resolved *source* (threats survive only there).
    // `effective_source` folds either form — a template/source document or a
    // delta-leaf (`[[fs.read.add]]`, …) — so the report works on a leaf policy too.
    let effective = kennel_lib_compile::effective_source(&bytes, &source, &trust)
        .map_err(|e| format!("resolving {policy_path}: {e}"))?;
    let catalogue = kennel_lib_compile::threats::Catalogue::load(catalogue_path().as_deref())
        .map_err(|e| format!("threat catalogue: {e}"))?;
    let report = kennel_lib_compile::risks::evaluate(&effective, &catalogue);

    let name = effective.name.as_deref().unwrap_or(policy_path);
    if json {
        print_risks_json(name, &report);
    } else {
        print_risks_human(name, &report);
    }
    Ok(ExitCode::SUCCESS)
}

/// `kennel policy diff <policy> [<other>]` — the interpreted grant delta.
///
/// With one argument, diffs the policy against its **template baseline** (the
/// template it inherits, resolved with none of the leaf's own deltas) — the "what
/// does my policy add over the template" view (§5.13). With two, diffs `<policy>`
/// → `<other>`: an org baseline against a user policy, or before/after a version
/// bump. Each grant change is annotated with the threats it exposes/mitigates plus
/// a net threat-posture delta — the semantic counterpart of `policy upgrade`'s raw
/// source line diff (`05-templates.md` §5.11).
fn policy_diff(args: &[String]) -> Result<ExitCode, String> {
    let mut positionals: Vec<&str> = Vec::new();
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut json = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if positionals.len() < 2 => positionals.push(value),
            _ => return Err("at most two policies may be given".to_owned()),
        }
    }
    let primary = *positionals.first().ok_or(
        "usage: kennel policy diff <policy> [<other>] [--template-dir D]... [--trust-dir D]... [--json]",
    )?;
    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let keys = load_trust_store(&trust_dirs)?;

    // The primary's *declared* identity (its own `name`/`template_base`, before the
    // fold loses them) drives the label and the one-arg baseline.
    let (primary_name, primary_base) = declared_meta(primary)?;
    let primary_eff = resolve_effective(primary, &template_dirs, &keys)?;
    let primary_label = primary_name.unwrap_or_else(|| primary.to_owned());

    // One arg: baseline → policy (what the leaf adds over its template). Two args:
    // <primary> → <other> (primary is the "before", other the "after").
    let (old_eff, old_label, new_eff, new_label) = if let Some(other) = positionals.get(1) {
        let (other_name, _) = declared_meta(other)?;
        let other_eff = resolve_effective(other, &template_dirs, &keys)?;
        let other_label = other_name.unwrap_or_else(|| (*other).to_owned());
        (primary_eff, primary_label, other_eff, other_label)
    } else {
        let reference = primary_base.ok_or_else(|| {
            format!(
                "`{primary_label}` has no `template_base` to diff against; \
                 pass a second policy to compare two"
            )
        })?;
        let baseline = resolve_template_baseline(&reference, &template_dirs, &keys)?;
        (
            baseline,
            format!("{reference} (baseline)"),
            primary_eff,
            primary_label,
        )
    };

    let catalogue = kennel_lib_compile::threats::Catalogue::load(catalogue_path().as_deref())
        .map_err(|e| format!("threat catalogue: {e}"))?;
    let d = kennel_lib_compile::diff::diff(&old_eff, &new_eff, &catalogue);

    if json {
        print_diff_json(&old_label, &new_label, &d);
    } else {
        print_diff_human(&old_label, &new_label, &d);
    }
    Ok(ExitCode::SUCCESS)
}

/// The policy's *declared* `(name, template_base)` from its raw source, before the
/// fold drops them. Works for both the template/source and the delta-leaf forms.
fn declared_meta(arg: &str) -> Result<(Option<String>, Option<String>), String> {
    let (path, _) = resolve_policy(arg, false)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if let Ok(src) = kennel_lib_compile::parse_source(&bytes) {
        return Ok((src.name.or(src.template_name), src.template_base));
    }
    if let Ok(leaf) = kennel_lib_compile::parse_leaf(&bytes) {
        return Ok((leaf.name, leaf.template_base));
    }
    Ok((None, None))
}

/// Resolve a policy argument (a name in the search path or a literal path) to its
/// folded effective *source* policy — the honest input for the diff/risk engines
/// (threat tags survive only in source). Handles both the template/source and the
/// delta-leaf forms.
fn resolve_effective(
    arg: &str,
    template_dirs: &[PathBuf],
    keys: &kennel_lib_policy::KeySet,
) -> Result<kennel_lib_compile::SourcePolicy, String> {
    let (path, _) = resolve_policy(arg, false)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let source = FsTemplateSource {
        dirs: template_dirs.to_vec(),
    };
    let trust = kennel_lib_compile::Trust::allow_unsigned(Some(keys));
    kennel_lib_compile::effective_source(&bytes, &source, &trust)
        .map_err(|e| format!("resolving {}: {e}", path.display()))
}

/// Resolve a template reference (`<name>@v<n>`) as a standalone effective policy —
/// the baseline a leaf's own deltas are measured against.
fn resolve_template_baseline(
    reference: &str,
    template_dirs: &[PathBuf],
    keys: &kennel_lib_policy::KeySet,
) -> Result<kennel_lib_compile::SourcePolicy, String> {
    let (name, version) = kennel_lib_compile::parse_reference(reference)
        .map_err(|e| format!("`template_base`: {e}"))?;
    let source = FsTemplateSource {
        dirs: template_dirs.to_vec(),
    };
    let bytes = source.fetch(&name, &version).ok_or_else(|| {
        format!("cannot read `{reference}` to diff against (pass --template-dir)")
    })?;
    let trust = kennel_lib_compile::Trust::allow_unsigned(Some(keys));
    kennel_lib_compile::effective_source(&bytes, &source, &trust)
        .map_err(|e| format!("resolving `{reference}`: {e}"))
}

/// Human-readable interpreted diff. Policy-sourced strings (carrier, detail,
/// reason, threat ids, the labels) are adversarial (§10) and pass through
/// `sanitise_for_log` before reaching the terminal; the catalogue title/residual
/// and our own note text are trusted.
fn print_diff_human(old_label: &str, new_label: &str, d: &kennel_lib_compile::diff::PolicyDiff) {
    use kennel_lib_compile::diff::ChangeKind;
    use kennel_lib_text::sanitise_for_log as s;
    println!(
        "diff {} \u{2192} {}  (threat catalogue v{})",
        s(old_label),
        s(new_label),
        d.catalogue_version
    );

    if d.is_empty() {
        println!("\nNo capability changes.");
    } else {
        println!("\nGrant changes ({}):", d.changes.len());
        for c in &d.changes {
            let sign = match c.kind {
                ChangeKind::Added => '+',
                ChangeKind::Removed => '-',
                ChangeKind::Modified => '~',
            };
            let widen = if c.widening { "  (widens reach)" } else { "" };
            println!("  {sign} {}{widen}", s(&c.carrier));
            if !c.detail.is_empty() {
                println!("      {}", s(&c.detail));
            }
            if let Some(r) = &c.reason {
                println!("      reason: {}", s(r));
            }
            for t in &c.exposed {
                println!("      exposes {}", threat_oneline(t));
            }
            for t in &c.mitigated {
                println!("      mitigates {}", threat_oneline(t));
            }
            if let Some(n) = &c.note {
                println!("      \u{26a0} {n}");
            }
        }
    }

    let sum = &d.summary;
    if sum.is_empty() {
        println!("\nThreat posture: unchanged.");
    } else {
        println!("\nThreat posture delta:");
        for t in &sum.newly_exposed {
            println!("  \u{26a0} now exposes {}", threat_oneline(t));
        }
        for t in &sum.no_longer_exposed {
            println!("  \u{2713} no longer exposes {}", threat_oneline(t));
        }
        for t in &sum.newly_mitigated {
            println!("  \u{2713} now mitigates {}", threat_oneline(t));
        }
        for t in &sum.no_longer_mitigated {
            println!("  \u{26a0} no longer mitigates {}", threat_oneline(t));
        }
    }
    println!("\nFull threat definitions and residuals: docs/design/THREATS.md");
}

/// `T1.6 — <title> (<residual>)` for the terminal. The `id` is policy-sourced
/// (untrusted for an uncatalogued tag) and sanitised; `title`/`residual` are the
/// trusted catalogue.
fn threat_oneline(t: &kennel_lib_compile::diff::ThreatRef) -> String {
    let id = kennel_lib_text::sanitise_for_log(&t.id);
    match (&t.title, t.residual.is_empty()) {
        (Some(title), false) => format!("{id} \u{2014} {title} ({})", t.residual),
        (Some(title), true) => format!("{id} \u{2014} {title}"),
        (None, _) => format!("{id} (uncatalogued)"),
    }
}

/// JSON interpreted diff, via `serde_json` (a real serialiser — §10.3 — so control
/// characters in any policy-sourced field are escaped, not emitted raw). The diff
/// types derive `Serialize`; this wraps them with the two labels.
fn print_diff_json(old_label: &str, new_label: &str, d: &kennel_lib_compile::diff::PolicyDiff) {
    #[derive(serde::Serialize)]
    struct DiffJson<'a> {
        old: &'a str,
        new: &'a str,
        #[serde(flatten)]
        diff: &'a kennel_lib_compile::diff::PolicyDiff,
    }
    let out = DiffJson {
        old: old_label,
        new: new_label,
        diff: d,
    };
    // Serialising a fixed in-memory structure of strings/vecs cannot fail.
    match serde_json::to_string(&out) {
        Ok(j) => println!("{j}"),
        Err(e) => eprintln!("kennel: emitting json: {e}"),
    }
}

/// The on-disk threat catalogue path, if a cascade copy exists (`/etc/kennel` wins
/// over the vendor `/usr/lib/kennel`). `None` ⇒ the CLI uses the embedded copy.
fn catalogue_path() -> Option<PathBuf> {
    for dir in ["/etc/kennel", "/usr/lib/kennel"] {
        let p = Path::new(dir).join("threats").join("catalogue.toml");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Human-readable risk report.
fn print_risks_human(name: &str, report: &kennel_lib_compile::risks::RiskReport) {
    use kennel_lib_compile::risks::Origin;
    println!(
        "Risk overview for `{name}`  (threat catalogue v{})",
        report.catalogue_version
    );
    if let Some(pv) = &report.policy_catalogue_version {
        if pv != &report.catalogue_version {
            println!(
                "  note: policy authored against threat catalogue v{pv} (now v{})",
                report.catalogue_version
            );
        }
    }

    let print_findings = |heading: &str, findings: &[kennel_lib_compile::risks::Finding]| {
        println!("\n{heading} ({}):", findings.len());
        for f in findings {
            let title = f.title.as_deref().unwrap_or("(uncatalogued)");
            let derived = if f.origin == Origin::Derived {
                "  (derived)"
            } else {
                ""
            };
            println!("  {:<6} {title}{derived}", f.threat_id);
            println!("         via {}", f.carrier);
            if let Some(r) = &f.reason {
                println!("         reason: {r}");
            }
            if !f.residual.is_empty() {
                println!("         residual: {}", f.residual);
            }
        }
        if findings.is_empty() {
            println!("  (none)");
        }
    };

    print_findings("EXPOSES", &report.exposures);
    print_findings("MITIGATES", &report.mitigations);

    if !report.unknown_tags.is_empty() {
        println!(
            "\n\u{26a0} {} threat tag(s) not in catalogue v{} (typo?):",
            report.unknown_tags.len(),
            report.catalogue_version
        );
        for (tag, carrier) in &report.unknown_tags {
            println!("  {tag}  via {carrier}");
        }
    }
    println!("\nFull threat definitions and residuals: docs/design/THREATS.md");
}

/// JSON risk report (stable-ish shape for CI/tooling). Hand-rolled (no `serde_json`
/// dep): the structure is small and fixed.
fn print_risks_json(name: &str, report: &kennel_lib_compile::risks::RiskReport) {
    use kennel_lib_compile::risks::{Finding, Origin};
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let finding_json = |f: &Finding| {
        format!(
            "{{\"id\":\"{}\",\"title\":\"{}\",\"carrier\":\"{}\",\"reason\":{},\"residual\":\"{}\",\"derived\":{}}}",
            esc(&f.threat_id),
            esc(f.title.as_deref().unwrap_or_default()),
            esc(&f.carrier),
            f.reason.as_ref().map_or_else(|| "null".to_owned(), |r| format!("\"{}\"", esc(r))),
            esc(&f.residual),
            f.origin == Origin::Derived,
        )
    };
    let arr = |fs: &[Finding]| fs.iter().map(finding_json).collect::<Vec<_>>().join(",");
    let unknown = report
        .unknown_tags
        .iter()
        .map(|(t, c)| format!("{{\"tag\":\"{}\",\"carrier\":\"{}\"}}", esc(t), esc(c)))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"policy\":\"{}\",\"catalogue_version\":\"{}\",\"exposures\":[{}],\"mitigations\":[{}],\"unknown_tags\":[{}]}}",
        esc(name),
        esc(&report.catalogue_version),
        arr(&report.exposures),
        arr(&report.mitigations),
        unknown,
    );
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
    kennel_lib_compile::parse_source(&bytes).map_or("source", |p| {
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
        let trust = kennel_lib_compile::Trust::allow_unsigned(Some(&keys));
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

    // Network: the mode + the two enforcement planes (§7.5.4). `[net.proxy]` is the
    // user-space egress policy (by-name+cidr, resolve-and-pin) the SOCKS delegate runs in the
    // proxied modes; `[net.bpf]` is the kernel ACL (cidr+ports, deny-first) the cgroup BPF +
    // Landlock enforce. Each is annotated with whether it is LIVE in this mode, so the reader
    // sees which rules actually gate the workload (host = BPF only; proxied = both).
    let net = &ep.net;
    let proxied = matches!(net.mode, NetMode::Constrained | NetMode::Unconstrained);
    let mode = match net.mode {
        NetMode::None => "none (own empty netns, no network)",
        NetMode::Constrained => "constrained (own netns, egress proxy, default-deny)",
        NetMode::Unconstrained => "unconstrained (own netns, egress proxy, default-allow + denies)",
        NetMode::Host => "host (host netns, direct egress, BPF/Landlock gate; reinstates T1.6)",
    };
    println!("  network: {mode}");

    // [net.proxy] — live only in the proxied modes.
    if !net.allow.is_empty() || !net.allow_names.is_empty() || !net.deny_author.is_empty() {
        let live = if proxied {
            "live"
        } else {
            "NOT enforced — no proxy in this mode"
        };
        println!("  [net.proxy] ({live}):");
        if !net.allow.is_empty() || !net.allow_names.is_empty() {
            println!(
                "    allow: {} cidr, {} name",
                net.allow.len(),
                net.allow_names.len()
            );
        }
        if !net.deny_author.is_empty() {
            println!("    deny.policy: {} rule(s)", net.deny_author.len());
        }
    }
    if !net.deny_invariant.is_empty() {
        // The invariant floor is re-checked by the proxy AND encoded into the BPF deny map,
        // so it is enforced deny-first in every mode.
        println!(
            "  [net.proxy.deny.invariant]: {} rule(s) (enforced in every mode)",
            net.deny_invariant.len()
        );
    }

    // [net.bpf] — the kernel ACL: the gate in host mode, defence-in-depth otherwise.
    let bpf_nonempty = !net.bpf_connect_allow.is_empty()
        || !net.bpf_connect_deny.is_empty()
        || !net.bpf_bind_allow.is_empty()
        || !net.bpf_bind_deny.is_empty();
    if bpf_nonempty {
        let role = if net.mode == NetMode::Host {
            "the egress gate"
        } else {
            "defence-in-depth"
        };
        println!("  [net.bpf] ({role}):");
        if !net.bpf_connect_allow.is_empty() || !net.bpf_connect_deny.is_empty() {
            println!(
                "    connect: {} allow, {} deny (cidr+ports)",
                net.bpf_connect_allow.len(),
                net.bpf_connect_deny.len()
            );
        }
        if !net.bpf_bind_allow.is_empty() || !net.bpf_bind_deny.is_empty() {
            println!(
                "    bind: {} allow, {} deny (cidr+ports)",
                net.bpf_bind_allow.len(),
                net.bpf_bind_deny.len()
            );
        }
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
    let trust = kennel_lib_compile::Trust::allow_unsigned(Some(&keys));
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
        let findings = kennel_lib_compile::lint_settled(&compiled.policy);
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
    let policy = kennel_lib_compile::parse_source(&bytes).map_err(|e| {
        format!("{path} is not a signable source template/fragment ({e}); leaf policies may stay unsigned")
    })?;
    if policy.signature.is_some() {
        return Err(format!(
            "{path} already carries a [signature]; remove it before re-signing"
        ));
    }

    let key = load_signing_key(Path::new(key_path))?;
    let signed =
        kennel_lib_compile::sign_source(&policy, &key).map_err(|e| format!("signing: {e}"))?;
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
/// `kennel policy upgrade <name> [--yes] [--template-dir D]... [--trust-dir D]...` — re-pin a
/// policy's template to a newer published version, with review and consent.
///
/// Detects whether the policy's `template_base` has a newer version available in
/// the template search path, shows the source diff between the pinned and the new
/// version, asks for consent, and on yes rewrites `template_base` and recompiles so
/// `kennel.lock` re-pins. This is the sanctioned way to change a locked entry
/// (`05-templates.md` §5.11): the lock is otherwise immutable, a mismatch being a
/// hard error. The semantic threat-impact delta is `kennel diff`'s job (roadmap);
/// this shows the honest source diff and never migrates without consent.
fn upgrade(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut assume_yes = false;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    // The user-supplied --template-dir values, forwarded verbatim to the recompile
    // so it resolves the new template version from the same search path we did.
    let mut user_template_args: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--yes" | "-y" => assume_yes = true,
            "--template-dir" => {
                let dir = it.next().ok_or("--template-dir needs a value")?;
                template_dirs.push(dir.into());
                user_template_args.push("--template-dir".to_owned());
                user_template_args.push(dir.clone());
            }
            "--trust-dir" => {
                // Not used by the diff (source-only), but forwarded to the recompile
                // so the new template version's signature verifies against it.
                let dir = it.next().ok_or("--trust-dir needs a value")?;
                user_template_args.push("--trust-dir".to_owned());
                user_template_args.push(dir.clone());
            }
            flag if flag.starts_with('-') => return Err(format!("unknown flag `{flag}`")),
            value => {
                if name.is_some() {
                    return Err("only one <name> may be given".to_owned());
                }
                name = Some(value);
            }
        }
    }
    let name = name.ok_or(
        "usage: kennel policy upgrade <name> [--yes] [--template-dir D]... [--trust-dir D]...",
    )?;
    add_default_template_dirs(&mut template_dirs);

    // The leaf policy source (never the settled artefact — we rewrite the source).
    let (policy_path, _) = resolve_policy(name, false)?;
    let bytes = std::fs::read(&policy_path)
        .map_err(|e| format!("reading {}: {e}", policy_path.display()))?;
    let source = kennel_lib_compile::source::parse(&bytes)
        .map_err(|e| format!("parsing {}: {e}", policy_path.display()))?;
    let reference = source
        .template_base
        .ok_or_else(|| format!("`{name}` has no `template_base` to upgrade"))?;
    let (tmpl, current) = kennel_lib_compile::parse_reference(&reference)
        .map_err(|e| format!("`template_base`: {e}"))?;

    // Find the newest version of `tmpl` available in the search path.
    let src = FsTemplateSource {
        dirs: template_dirs,
    };
    let Some(newest) = newest_template_version(&src.dirs, &tmpl) else {
        return Err(format!(
            "template `{tmpl}` not found in the search path (pass --template-dir)"
        ));
    };
    if !kennel_lib_compile::version_is_newer(&newest, &current) {
        println!("`{name}` is already on the latest `{tmpl}` ({current}).");
        return Ok(ExitCode::SUCCESS);
    }

    // Show the source diff between the pinned and the new template version.
    println!("{tmpl} {current} \u{2192} {newest}\n");
    let old_src = src.fetch(&tmpl, &current);
    let new_src = src
        .fetch(&tmpl, &newest)
        .ok_or_else(|| format!("cannot read `{tmpl}@{newest}` to diff"))?;
    print_source_diff(old_src.as_deref(), &new_src);
    println!(
        "\nThis re-points `{name}` to `{tmpl}@{newest}` and recompiles so kennel.lock re-pins.\n\
         Review the diff above (the semantic threat-impact view is `kennel diff`, roadmap)."
    );

    if !assume_yes {
        if !io::stdin().is_terminal() {
            return Err(
                "refusing to migrate without a terminal to confirm at; pass --yes to proceed"
                    .to_owned(),
            );
        }
        print!("Migrate? [y/N] ");
        io::Write::flush(&mut io::stdout()).map_err(|e| format!("stdout: {e}"))?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|e| format!("stdin: {e}"))?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("Not migrated. `{name}` stays on `{tmpl}@{current}`.");
            return Ok(ExitCode::SUCCESS);
        }
    }

    // Rewrite the single `template_base` line and recompile to re-pin the lock.
    let updated = rewrite_template_base(
        &String::from_utf8(bytes).map_err(|_| "policy is not UTF-8".to_owned())?,
        &reference,
        &format!("{tmpl}@{newest}"),
    )?;
    std::fs::write(&policy_path, updated.as_bytes())
        .map_err(|e| format!("writing {}: {e}", policy_path.display()))?;
    println!("Re-pointed `{name}` to `{tmpl}@{newest}`. Recompiling to re-pin the lock\u{2026}");
    // Recompile via the existing path (re-pins kennel.lock; signs with the default key),
    // forwarding the same --template-dir search path we resolved the new version from.
    let mut compile_args = vec![policy_path.to_string_lossy().into_owned()];
    compile_args.extend(user_template_args);
    compile(&compile_args)
}

/// Scan the template search dirs for the newest available version of `name`.
/// Recognises the flat `name@vX.toml` layout and the nested `name/policy.toml`
/// (whose `template_version` supplies the version). Returns the newest `vX`.
fn newest_template_version(dirs: &[PathBuf], name: &str) -> Option<String> {
    let mut newest: Option<String> = None;
    let mut consider = |candidate: String| {
        if newest
            .as_deref()
            .is_none_or(|cur| kennel_lib_compile::version_is_newer(&candidate, cur))
        {
            newest = Some(candidate);
        }
    };
    for dir in dirs {
        // Flat: <name>@vX.toml
        let prefix = format!("{name}@");
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let fname = entry.file_name();
                let Some(fname) = fname.to_str() else {
                    continue;
                };
                if let Some(rest) = fname.strip_prefix(&prefix) {
                    if let Some(ver) = rest.strip_suffix(".toml") {
                        if ver.starts_with('v') {
                            consider(ver.to_owned());
                        }
                    }
                }
            }
        }
        // Nested: <name>/policy.toml carrying template_version = "N".
        let nested = dir.join(name).join("policy.toml");
        if let Ok(b) = std::fs::read(&nested) {
            if let Ok(p) = kennel_lib_compile::source::parse(&b) {
                if let Some(v) = p.template_version {
                    consider(format!("v{v}"));
                }
            }
        }
    }
    newest
}

/// Replace exactly the `template_base = "<old>"` value with `<new>`, preserving the
/// rest of the file. Errors if the old reference is not found verbatim (so we never
/// silently write a no-op or corrupt an unexpected layout).
fn rewrite_template_base(text: &str, old: &str, new: &str) -> Result<String, String> {
    let needle = format!("\"{old}\"");
    if !text.contains(&needle) {
        return Err(format!(
            "could not find `template_base = \"{old}\"` to rewrite (edit the policy by hand)"
        ));
    }
    Ok(text.replacen(&needle, &format!("\"{new}\""), 1))
}

/// Print a minimal line-oriented diff of two template sources (added/removed lines),
/// honest about content without claiming a semantic threat-impact analysis.
fn print_source_diff(old: Option<&[u8]>, new: &[u8]) {
    let old_text = old.and_then(|b| std::str::from_utf8(b).ok()).unwrap_or("");
    let new_text = std::str::from_utf8(new).unwrap_or("");
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    // Lines in new but not old (added), and in old but not new (removed). A set
    // difference, not an LCS diff — enough to review a template bump at a glance.
    for line in &new_lines {
        if !old_lines.contains(line) && !line.trim().is_empty() {
            println!("  + {line}");
        }
    }
    for line in &old_lines {
        if !new_lines.contains(line) && !line.trim().is_empty() {
            println!("  - {line}");
        }
    }
}

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

    const BASE_CONFINED: &[u8] = include_bytes!("../../../../templates/base-confined/policy.toml");

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
