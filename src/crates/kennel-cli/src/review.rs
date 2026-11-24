// SPDX-License-Identifier: Apache-2.0

//! `kennel review` and `kennel release` — host-side trust-manifest sign-off (T2.8) and
//! exclusive-bind crash recovery (§2.7). Split out of `main.rs`.
//!
//! `writable_root`, `verify_exclusive_ownership`, and `check_exclusive_ownership` are reused by
//! `run` and `policy compile`, so they are `pub(crate)`; the shared policy resolvers
//! (`resolve_policy`, `is_source_policy`) stay in the crate root.

use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::policy::is_source_policy;
use crate::resolve_policy;

/// `kennel review <policy> [--yes]` — the operator's sign-off on a workspace's trust manifest.
///
/// After legitimate edits (T2.8). The confined workload cannot update the manifest
/// (it is masked), so changed/added execution triggers stay flagged until a human re-pins
/// them here, host-side.
///
/// Resolves `<policy>` to its settled artefact (like `run`, preferring the compiled
/// `<name>.settled.toml`), reads each writable root's `.trust-manifest.json`, and shows a
/// unified diff of modified / removed / new triggers. The default sign-off **re-pins**
/// (adopts the on-disk state, so the host IDE unlocks); `--revert` instead **restores** each
/// trigger to its pinned baseline and removes planted ones (the §2.5 teardown disposition).
/// `--yes` skips the per-root confirmation.
///
/// # Errors
///
/// Returns a message on an unknown flag or missing `<policy>` argument, if `HOME` is unset,
/// if the policy cannot be resolved or read, if it is still a source policy (uncompiled) or
/// fails to parse as a settled artefact, or if reviewing any writable root fails.
pub fn review(args: &[String]) -> Result<ExitCode, String> {
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
    let cwd = std::env::current_dir().ok();
    for root in writable_roots(&policy, &home, cwd.as_deref()) {
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
    let changes =
        kennel_lib_manifest::review(&manifest, root, &kennel_lib_manifest::Catalogue::load())
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
        if assume_yes
            || prompt_yes(&format!(
                "revert {} trigger(s) to baseline?",
                divergences.len()
            ))?
        {
            for change in &divergences {
                match kennel_lib_manifest::revert(root, change) {
                    Ok(()) => println!("  reverted {}", clean(change_path_of(change))),
                    Err(e) => {
                        eprintln!("  warning: revert {}: {e}", clean(change_path_of(change)));
                    }
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
        // A trigger's path is a file name in a workspace the workload writes.
        TriggerChange::Modified { path, .. } => println!("  ~ {} (modified)", clean(path)),
        TriggerChange::Removed { path, .. } => println!("  - {} (removed)", clean(path)),
        TriggerChange::New { path, .. } => println!("  + {} (new, unpinned)", clean(path)),
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
    // The file on disk is the workload's: only a regular file is shown (never a link's target,
    // a device or a pipe), and what it contains is sanitised before it reaches the terminal.
    let live = root.join(path);
    if !std::fs::symlink_metadata(&live).is_ok_and(|m| m.is_file()) {
        println!("    (not a regular file on disk; not shown)");
        return;
    }
    // The pinned bytes go to `diff` on its standard input; nothing is staged in a temp file.
    let Ok(mut child) = std::process::Command::new("diff")
        .arg("-u")
        .arg("--label")
        .arg(format!("{path} (pinned)"))
        .arg("--label")
        .arg(format!("{path} (on disk)"))
        .arg("-")
        .arg(&live)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return;
    };
    // Feed stdin from its own thread: `diff` may fill the output pipe before it has read all
    // of its input.
    let feeder = child.stdin.take().map(|mut stdin| {
        std::thread::spawn(move || {
            use std::io::Write as _;
            let _ = stdin.write_all(&pinned);
        })
    });
    if let Ok(out) = child.wait_with_output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            println!("    {}", clean(line));
        }
    }
    if let Some(feeder) = feeder {
        let _ = feeder.join();
    }
}

/// Neutralise terminal control sequences in text that came from a workspace.
fn clean(text: &str) -> String {
    kennel_lib_text::sanitise_for_log(text)
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

/// `kennel release <policy>` — release leaked exclusive over-mounts (§2.7 recovery).
///
/// The teardown release is automatic, but a crashed kennel can leave an `fs.exclusive` path
/// shadowed (the operator locked out of their own directory). This resolves the policy's
/// exclusive host paths and invokes the privhelper to unmount each — **directly**, not through
/// `kenneld`, so it works even when the daemon is down. Idempotent: a path that is not (or no
/// longer) shadowed is skipped.
///
/// # Errors
///
/// Returns a message if no `<policy>` argument is given, if `HOME` is unset, if the policy
/// cannot be resolved or read, if it is still a source policy or fails to parse as a settled
/// artefact, if the deployment config cannot be loaded, or if spawning the privhelper fails.
pub fn release(args: &[String]) -> Result<ExitCode, String> {
    let policy_arg = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or("usage: kennel release <policy>")?;
    let (policy_file, name) = resolve_policy(policy_arg, true)?;
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;
    if is_source_policy(&bytes) {
        return Err(format!(
            "`{}` is a source policy — compile it first, then release the settled artefact",
            policy_file.display()
        ));
    }
    let policy = kennel_lib_policy::parse_settled_unverified(&bytes)
        .map_err(|e| format!("reading settled policy {}: {e}", policy_file.display()))?;
    if policy.effective_policy.fs.exclusive.is_empty() {
        eprintln!("kennel: `{name}` declares no exclusive binds — nothing to release");
        return Ok(ExitCode::SUCCESS);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set (needed to resolve fs.exclusive host paths)")?;
    let privhelper = kennel_lib_config::Deployment::load()
        .map_err(|e| format!("loading deployment config: {e}"))?
        .privhelper();
    let mut released = 0usize;
    let mut failed = 0usize;
    for ex in &policy.effective_policy.fs.exclusive {
        let Some(host) = writable_root(ex, &home) else {
            continue;
        };
        let status = std::process::Command::new(&privhelper)
            .arg("exclusive-unmount")
            .arg(&host)
            .status()
            .map_err(|e| format!("spawning {}: {e}", privhelper.display()))?;
        match status.code() {
            Some(0) => {
                println!("released {}", host.display());
                released = released.saturating_add(1);
            }
            // 1 = refused: not (or no longer) a kennel exclusive over-mount — nothing to do.
            Some(1) => {}
            other => {
                eprintln!(
                    "kennel: could not release {} (privhelper exit {other:?})",
                    host.display()
                );
                failed = failed.saturating_add(1);
            }
        }
    }
    if failed > 0 {
        return Ok(ExitCode::FAILURE);
    }
    eprintln!("kennel: released {released} exclusive over-mount(s) for `{name}`");
    Ok(ExitCode::SUCCESS)
}

/// Verify the operator owns the host path behind each `fs.exclusive` grant (§2.7).
///
/// An exclusive bind blind-mounts the host side with the privhelper's privilege; doing that
/// over a path the operator does not **own** would be overreach, so it is refused here (early
/// feedback at compile/run) and again in the privhelper (the authoritative real-uid check).
/// Plain `fs.write` on a non-owned path is *fine* — the kernel still gates the workload's
/// writes by the operator's uid — so only `exclusive` paths are checked, and the test is
/// ownership, not write-access.
///
/// # Errors
///
/// Returns a message if any `fs.exclusive` path cannot be resolved to a host path, does not
/// exist, or is not owned by the real uid. An unparseable artefact is not an error here (the
/// caller reports it).
pub fn verify_exclusive_ownership(settled_bytes: &[u8]) -> Result<(), String> {
    let Ok(policy) = kennel_lib_policy::parse_settled_unverified(settled_bytes) else {
        return Ok(()); // an unparseable artefact is reported by the caller, not here
    };
    check_exclusive_ownership(&policy.effective_policy.fs.exclusive)
}

/// The ownership test behind [`verify_exclusive_ownership`], over the resolved `exclusive` list.
///
/// # Errors
///
/// Returns a message if `HOME` is unset, or if any `fs.exclusive` path cannot be resolved to
/// a host path, does not exist, or is not owned by the real uid.
pub fn check_exclusive_ownership(exclusive: &[String]) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    if exclusive.is_empty() {
        return Ok(());
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set (needed to resolve fs.exclusive host paths)")?;
    let uid = kennel_lib_syscall::unistd::real_uid();
    for ex in exclusive {
        let Some(host) = writable_root(ex, &home) else {
            return Err(format!(
                "fs.exclusive `{ex}`: cannot resolve to a host path"
            ));
        };
        match std::fs::symlink_metadata(&host) {
            Ok(meta) if meta.uid() == uid => {}
            Ok(_) => {
                return Err(format!(
                    "fs.exclusive `{ex}` ({}) is not owned by you (uid {uid}). An exclusive bind \
                     blind-mounts the host side with privilege, and the privhelper will not \
                     over-mount a path you do not own (overreach). Drop `exclusive` for this path \
                     (`fs.write` alone is fine), or use a path you own.",
                    host.display()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "fs.exclusive `{ex}` ({}): {e} — an exclusive path must exist and be owned by you",
                    host.display()
                ));
            }
        }
    }
    Ok(())
}

/// Every host directory the policy lets the workload write as a workspace.
///
/// That is the root of each `fs.write` grant and, when the policy grants `[fs.cwd] write`, the
/// directory the command is run from — the workspace that grant makes writable.
///
/// The manifest pre-flight, the live tripwire and `kennel review` all walk this one list, so a
/// project reached through the cwd grant is pinned, watched and reviewed like one named in
/// `fs.write`. `cwd` is the invocation directory (`None` if it cannot be read).
#[must_use]
pub fn writable_roots(
    policy: &kennel_lib_policy::SettledPolicy,
    home: &Path,
    cwd: Option<&Path>,
) -> Vec<PathBuf> {
    let fs = &policy.effective_policy.fs;
    let mut roots: Vec<PathBuf> = fs
        .write
        .iter()
        .filter_map(|entry| writable_root(entry, home))
        .collect();
    if matches!(fs.cwd.grant, kennel_lib_policy::settled::CwdGrant::Write) {
        if let Some(cwd) = cwd {
            if !roots.iter().any(|r| r == cwd) {
                roots.push(cwd.to_path_buf());
            }
        }
    }
    roots
}

/// Derive the writable root directory from a glob-like `fs.write` entry, expanding
/// `~` and `$HOME` relative to `home`.
#[must_use]
pub fn writable_root(entry: &str, home: &Path) -> Option<PathBuf> {
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
