//! `kennel run` (foreground confined run of a settled artefact) and `kennel attach`, plus the
//! interactive PTY proxy machinery they share. Split out of `main.rs`.
//!
//! `run` is the operating house: it reads a **settled** artefact by **name** from the three
//! policy repos and nothing else. Templates, includes, source policies, and signing keys are
//! compile-side material (`kennel policy …`); the trust-manifest and exclusive-bind helpers
//! live in `review`.

use std::io::{self, IsTerminal as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_control::control::{self, Request, Response, StartRequest};

use crate::policy::is_source_policy;
use crate::review;
use crate::{connect, exit_code, send};

/// `kennel run <policy> [<name>] [--force] [-- <argv...>]`
///
/// `<policy>` is a **name** resolving to a settled artefact (`<name>.settled.toml`) in one of
/// the three policy repos (`~/.config/kennel/policies`, `/etc/kennel/policies`,
/// `/usr/lib/kennel/policies`) — nothing else. A source policy is compiled first
/// (`kennel policy compile`), a received file is placed first (`kennel policy install`); the
/// daemon verifies the settled signature against its trust store, so `run` needs no key.
///
/// # Errors
///
/// Returns a message if a flag is missing its value or is unknown, if no `<policy>`
/// argument is given, if the name does not resolve to a settled artefact (the refusal
/// names what was found instead and the real next step), or if [`launch`] fails.
pub fn run(args: &[String]) -> Result<ExitCode, String> {
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
    let mut force = false;
    for arg in head {
        match arg.as_str() {
            "--force" => force = true,
            // The compile-house flags `run` carried before 0.7.0 refuse with the real home.
            f @ ("--key" | "--key-id" | "--template-dir" | "--trust-dir") => {
                return Err(format!(
                    "`{f}` is a compile-side flag; `kennel run` runs a settled artefact by name \
                     and needs no key (the daemon verifies it). Compile first: `kennel policy \
                     compile <policy> --key <key>`, then `kennel run <name>`"
                ));
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if policy_arg.is_none() => policy_arg = Some(v),
            v if name_arg.is_none() => name_arg = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let policy_arg =
        policy_arg.ok_or("usage: kennel run <policy> [<name>] [--force] [-- <cmd...>]")?;
    // `<policy>` is a NAME resolving to a settled artefact in the three policy repos — never a
    // path, never source. The kennel instance `<name>` is optional and defaults to the policy
    // name (`07-paths`, resolve-by-name).
    let policy_file = resolve_settled_for_run(policy_arg)?;
    let name = name_arg.map_or_else(|| policy_arg.to_owned(), str::to_owned);
    launch(policy_file, &name, command, force, None, policy_arg)
}

/// Resolve `arg` to a settled artefact in the three policy repos — the ONLY thing `run` reads.
///
/// Anything else refuses with the object named and the real next step: a path (the form died
/// with 0.7.0 — place the artefact in a repo), a source policy (compile it), a template name
/// (derive a leaf from it), or nothing at all (list/compile).
fn resolve_settled_for_run(arg: &str) -> Result<PathBuf, String> {
    let user = kennel_lib_config::User::load().unwrap_or_default();
    if arg.contains('/') || Path::new(arg).exists() {
        return Err(
            "`kennel run` takes a policy NAME resolved from the policy repos \
             (~/.config/kennel/policies, /etc/kennel/policies, /usr/lib/kennel/policies), not a \
             path. Compile your source into a repo first (`kennel policy compile <policy> --key \
             <key>` writes the settled artefact beside it), then `kennel run <name>`"
                .to_owned(),
        );
    }
    if !crate::is_valid_policy_name(arg) {
        return Err(format!(
            "`{arg}` is not a valid policy name (no `/`, `..`, or whitespace)"
        ));
    }
    let mut source_hit: Option<PathBuf> = None;
    for dir in user.policy_dirs() {
        let base = dir.join(arg);
        let settled = base.join(format!("{arg}.settled.toml"));
        if settled.is_file() {
            return Ok(settled);
        }
        let source = base.join("policy.toml");
        if source_hit.is_none() && source.is_file() {
            source_hit = Some(source);
        }
    }
    // Nothing runnable. Say what WAS found and the real next step.
    if let Some(source) = source_hit {
        return Err(format!(
            "`{arg}` is a source policy ({}) with no compiled artefact — compile it first: \
             `kennel policy compile {arg} --key <key>`, then re-run",
            source.display()
        ));
    }
    for tdir in user.template_dirs() {
        if tdir.join(arg).join("policy.toml").is_file() {
            return Err(format!(
                "`{arg}` is a template — a shared base, not a runnable policy. Derive a leaf \
                 from it (`kennel policy generate --from {arg}`), then `kennel policy compile` \
                 and `kennel run` the leaf"
            ));
        }
    }
    Err(format!(
        "no policy named `{arg}` (searched `policies/` under ~/.config/kennel, /etc/kennel, \
         /usr/lib/kennel — `kennel policy list` shows what is there); author one with \
         `kennel policy generate`, then `kennel policy compile {arg} --key <key>`"
    ))
}

/// The shared launch core for `kennel run` and `kennel oci run`: pre-flight the settled
/// artefact and drive the daemon to the workload's exit.
///
/// The policy is a **settled** artefact — the daemon verifies its signature against the trust
/// store, so no key material appears here. A source policy refuses toward
/// `kennel policy compile` (the callers' resolvers make this unreachable in the normal flow;
/// the check holds the house boundary regardless).
///
/// `oci_digest` is the [grammar partition](crate::oci) gate: `kennel run` passes `None` and
/// refuses an `[rootfs]` policy; `kennel oci run` passes `Some(<recorded digest>)` (it has
/// resolved the named store entry), which both permits `[rootfs]` and asserts the signed
/// `[rootfs].image` equals that digest before boot. `display` is the operator-facing name of
/// the policy for diagnostics (a repo or store `<name>`).
///
/// # Errors
///
/// Returns a message if the policy file cannot be read or is not a settled artefact, if a
/// non-OCI run is handed an `[rootfs]` policy or an OCI digest does not match the signed
/// image, if the exclusive-ownership pre-flight fails, if the daemon cannot be reached or
/// the request/response exchange fails, or if the daemon reports an error.
#[allow(clippy::too_many_lines)]
pub fn launch(
    policy_file: PathBuf,
    name: &str,
    command: &[String],
    force: bool,
    oci_digest: Option<&str>,
    display: &str,
) -> Result<ExitCode, String> {
    let allow_oci = oci_digest.is_some();
    // For an OCI run the launcher reads the store entry's `config.json` (the sibling of the
    // entry's settled policy); kenneld binds it into the view.
    let oci_config =
        oci_digest.and_then(|_| policy_file.parent().map(|dir| dir.join("config.json")));
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;
    if is_source_policy(&bytes) {
        return Err(format!(
            "`{display}` is a source policy — the run house takes only settled artefacts. \
             Compile it first: `kennel policy compile {display} --key <key>`"
        ));
    }
    let effective_policy = policy_file;

    // Pre-flight: ensure a `.trust-manifest.json` at each writable workspace root before
    // the kennel boots (mirrors SSH-key provisioning). The kennel will mask the manifest
    // invisible, so the agent cannot forge the integrity pins host tooling trusts (T2.8).
    // Read from the settled bytes we hold; host-side, never contacts kenneld.
    let settled_bytes = bytes;
    // Grammar partition (§7.11 / arch 02-9): `[rootfs]` is the OCI substrate model and is
    // valid only under `kennel oci run`, which resolves the named store entry and verifies
    // `[rootfs].image` against the recorded digest. `kennel run` refuses it rather than boot
    // an image without that provenance check.
    if !allow_oci && crate::oci::policy_is_oci(&settled_bytes) {
        return Err(format!(
            "`{display}` is an OCI-model policy ([rootfs] set); run it with `kennel oci run <name>`"
        ));
    }
    if let Some(expected) = oci_digest {
        // Provenance check (§7.11): the signed `[rootfs].image` must equal the digest the
        // build recorded for this store entry, so a swapped image is refused even with a
        // valid signature on the policy. The signature is verified daemon-side at Start.
        let declared = crate::oci::policy_image(&settled_bytes);
        if declared.as_deref() != Some(expected) {
            return Err(format!(
                "image mismatch for `{display}`: policy [rootfs].image is {}, store digest is `{expected}`",
                declared.map_or_else(|| "absent".to_owned(), |d| format!("`{d}`"))
            ));
        }
    }
    ensure_workspace_manifests(&settled_bytes);
    // An exclusive bind blind-mounts the host side with the privhelper's privilege (§2.7); refuse
    // early if the operator does not own a host path it would shadow (the privhelper refuses too).
    review::verify_exclusive_ownership(&settled_bytes)?;
    // Resolve the host paths kenneld's live tripwire should watch (§2.5) — computed here,
    // CLI-side, because the catalogue lives in this crate; the daemon just watches the list.
    let watch_paths = workspace_watch_paths(&settled_bytes);

    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let request = Request::Start(StartRequest {
        policy: effective_policy,
        kennel: name.to_owned(),
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
        oci_config,
    });

    let mut conn = connect()?;
    if io::stdin().is_terminal() {
        return run_interactive(conn, &request, name);
    }
    // Non-interactive (piped/redirected): pass our stdio straight through.
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let fds: [BorrowedFd<'_>; 3] = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
    send(&conn, &request, &fds)?;

    // First the daemon confirms the launch, then (when the workload exits) the code.
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        // Non-interactive (piped) launch: stdio passes straight through, no proxied
        // terminal, so `filter_escapes` does not apply here.
        Response::Started { ctx, pid, .. } => {
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
    // No compiled-in default (§2.6): the trigger set lives entirely in the config cascade. An
    // empty catalogue with `[trust].manifest = on` is almost always a missing vendor file, not a
    // deliberate choice — warn loudly rather than silently watch nothing (T2.8).
    let catalogue = kennel_lib_manifest::Catalogue::load();
    if catalogue.is_empty() {
        eprintln!(
            "kennel: warning: the trust-trigger catalogue is empty — no `triggers.catalog` found \
             under /usr/lib/kennel, /etc/kennel, or ~/.config/kennel. Execution triggers will not \
             be pinned or watched (T2.8). Install the package default or set `[trust].manifest = \
             false` to opt out explicitly."
        );
    }
    let generator = format!("kennel {}", env!("CARGO_PKG_VERSION"));
    for entry in &policy.effective_policy.fs.write {
        let Some(root) = review::writable_root(entry, &home) else {
            continue; // not a home-or-absolute path we can resolve to a host dir
        };
        if !root.is_dir() {
            continue; // a writable file (not a workspace dir) gets no manifest
        }
        let path = kennel_lib_manifest::manifest_path(&root);
        if path.exists() {
            continue; // leave it — refresh is `kennel review`, not `run`
        }
        let (manifest, errors) = kennel_lib_manifest::generate(&root, &generator, &catalogue);
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
        let Some(root) = review::writable_root(entry, &home) else {
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

    // The daemon confirms the launch (or reports a bring-up failure) and tells us whether
    // to filter the workload's terminal escapes client-side (§4.8 — the broker routes raw).
    let filter_escapes =
        match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
            Response::Started { filter_escapes, .. } => filter_escapes,
            Response::Error(message) => return Err(message),
            other => return Err(format!("unexpected response: {other:?}")),
        };
    proxy_session(conn, ours, name, filter_escapes)
}

/// `kennel attach <name>`: reconnect a terminal to a still-running kennel's pty.
///
/// The daemon's broker takes over from any current client (the prior terminal gets a clean
/// "detached: another client attached"). Same raw-mode proxy and `Ctrl-\ d` detach as
/// an interactive `run`.
///
/// # Errors
///
/// Returns a message if the arguments are not a single `<name>`, if stdin is not a
/// terminal, if raw mode or the socketpair cannot be set up, if the daemon cannot be
/// reached or the request/response exchange fails, or if the daemon reports an error.
pub fn attach(args: &[String]) -> Result<ExitCode, String> {
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
    let filter_escapes =
        match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
            Response::Attached { filter_escapes, .. } => filter_escapes,
            Response::Error(message) => return Err(message),
            other => return Err(format!("unexpected response: {other:?}")),
        };
    proxy_session(conn, ours, name, filter_escapes)
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
///
/// When `filter_escapes` is set (the `[tty]` policy decision the daemon conveyed in
/// `Response::Started`/`Attached`), the broker → stdout pump runs the workload's output
/// through the `kennel-lib-term` escape filter **here** — the daemon broker is a raw
/// router and keeps the `vte` parser of workload-controlled bytes out of its TCB (§4.8).
/// The detach-key scan stays on the *input* path: those are operator-controlled bytes,
/// not workload output, so no workload-controlled parser runs CLI-side either way.
fn proxy_session(
    conn: UnixStream,
    ours: UnixStream,
    name: &str,
    filter_escapes: bool,
) -> Result<ExitCode, String> {
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
    let out_sock = ours.try_clone().map_err(|e| format!("socket dup: {e}"))?;
    std::thread::spawn(move || {
        output_pump(out_sock, std::fs::File::from(stdout_dup), filter_escapes);
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

/// The broker → terminal pump: copy the kennel's output socket to the real terminal
/// (`out`), filtering dangerous escapes client-side when `filter_escapes` is set.
///
/// The daemon's broker is a raw-byte router (§4.8) — it never parses workload output —
/// so the `kennel-lib-term` `vte` filter runs here, keeping that parser of
/// workload-controlled bytes out of the daemon TCB. One `Filter` spans the whole received
/// stream (ring replay + live), so a sequence split across reads, or truncated at the
/// replayed ring head, is tracked by the parser state machine (an incomplete escape is
/// dropped). Without filtering it is a plain raw copy.
fn output_pump<W: std::io::Write>(mut out_sock: UnixStream, mut out: W, filter_escapes: bool) {
    use std::io::Read as _;
    if !filter_escapes {
        let _ = std::io::copy(&mut out_sock, &mut out);
        return;
    }
    let mut filter = kennel_lib_term::Filter::new(kennel_lib_term::FilterPolicy::default());
    let mut buf = [0u8; 4096];
    loop {
        let n = match out_sock.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let filtered = filter.feed(buf.get(..n).unwrap_or_default());
        if !filtered.is_empty() && out.write_all(&filtered).is_err() {
            break;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `output_pump` over a socketpair: buffer `input` on the broker end and close
    /// it, then run the pump (to EOF) on this thread into a `Vec` writer and return what
    /// reached the "terminal". `filter_escapes` selects the filtering vs raw-copy path.
    fn pump_through(input: &[u8], filter_escapes: bool) -> Vec<u8> {
        let (broker_end, client_end) = UnixStream::pair().expect("socketpair");
        {
            use std::io::Write as _;
            let mut w = broker_end;
            w.write_all(input).expect("write input");
            // Drop closes the socket so the pump reads the buffered bytes then sees EOF.
        }
        let mut got = Vec::new();
        output_pump(client_end, &mut got, filter_escapes);
        got
    }

    #[test]
    fn output_pump_filters_escapes_client_side() {
        // The dangerous OSC-52 clipboard write is dropped on the way to the terminal; the
        // surrounding benign bytes survive. This is the client-side half of the escape-filter split —
        // the daemon broker routes raw and never runs this parser (§4.8).
        let got = pump_through(b"hi\x1b]52;c;cGF5bG9hZA==\x07bye", true);
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("hi") && text.contains("bye"), "{text:?}");
        assert!(!text.contains("52;"), "clipboard escape dropped: {text:?}");
    }

    #[test]
    fn output_pump_passes_raw_when_filtering_disabled() {
        // `[tty].filter_terminal_escapes = false` ⇒ the daemon sends filter_escapes=false
        // and the pump is a verbatim copy (the operator opted out, footgun-warn-not-forbid).
        let raw = b"hi\x1b]52;c;cGF5bG9hZA==\x07bye";
        assert_eq!(pump_through(raw, false).as_slice(), raw);
    }
}
