//! The `kennel key` house: tier-bound signing-key management.
//!
//! A key's tier is where it lives, and that is the only level it signs at: user keys
//! (`~/.config/kennel/keys`) sign user objects, the host key (`/etc/kennel/keys`) signs
//! host objects, and the maintainer key never appears in shipped tooling. `generate`
//! derives the tier from context (root → host, else user); `trust`/`untrust` exist only
//! at host level — the user tier needs no trust list, because `kennel policy install`
//! re-signs foreign objects under the user's own key (that re-signing IS user-level
//! trust, per object). `rotate` is the supervised ceremony that replaces a key's
//! material and drives the re-sign/re-pin cascade the old manual ritual required.
//!
//! Every check here is a ceremony courtesy: enforcement stays with kenneld's signature
//! verification, the compiler's gates, and filesystem permission on the tier dirs (W9).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{default_key_dir, is_valid_key_id, tier_of_path};

/// The host trust dir from the deployment cascade (default `/etc/kennel/keys`).
fn host_key_dir() -> PathBuf {
    kennel_lib_config::Deployment::load()
        .unwrap_or_else(|_| kennel_lib_config::Deployment::defaults())
        .trust_dir()
        .to_path_buf()
}

/// Whether this invocation operates at host tier (the `generate`/`rotate` context rule).
fn invoked_as_root() -> bool {
    kennel_lib_syscall::unistd::effective_uid() == 0
}

// ─── generate ────────────────────────────────────────────────────────────────

/// `kennel key generate <name> [--force]`
///
/// Generate an Ed25519 signing key pair at the invoking tier: as a user, into the user
/// key dir (`~/.config/kennel/keys`, created 0700); as root, into the host trust store
/// (`/etc/kennel/keys`). The private key is `<name>` (0600), the public `<name>.pub`
/// (0644); the daemon trusts every `.pub` in the tier stores, so the key signs
/// immediately at its own level — and only there.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, the name collides without `--force`,
/// the key dir cannot be created, or `ssh-keygen` is missing or fails.
pub fn generate(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut force = false;
    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("only one <name> may be given".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel key generate <name> [--force]")?;
    if !is_valid_key_id(name) {
        return Err(format!(
            "invalid key name `{name}`: 1-64 chars of letters, digits, `.`, `-`, `_` \
             (it is both a filename and the signature key_id)"
        ));
    }
    let host = invoked_as_root();
    let dir = if host {
        host_key_dir()
    } else {
        default_key_dir()
    };
    generate_keypair(&dir, name, force, host)?;
    let tier = if host { "host" } else { "user" };
    eprintln!("generated Ed25519 signing key `{name}` at the {tier} tier:");
    eprintln!(
        "  private key : {}   (0600 — keep secret)",
        dir.join(name).display()
    );
    eprintln!(
        "  public key  : {}   (the daemon trusts every .pub here)",
        dir.join(format!("{name}.pub")).display()
    );
    eprintln!();
    if host {
        eprintln!("This key signs HOST-tier objects (policies and templates under /etc/kennel).");
        eprintln!("It is now trusted by every user on this host — host acceptance is");
        eprintln!("downward-inclusive, so user-tier copies of host-signed artefacts verify too.");
    } else {
        eprintln!("Compile a policy once, then run it — neither command needs --key while");
        eprintln!("this is your only key:");
        eprintln!("  kennel policy compile <name>   # signs policies/<name>/<name>.settled.toml");
        eprintln!("  kennel run <name> -- <cmd...>  # runs the settled policy (no key to run)");
    }
    Ok(ExitCode::SUCCESS)
}

/// Mint an Ed25519 pair `<name>`/`<name>.pub` in `dir` via `ssh-keygen`.
///
/// The user key dir is created 0700 (it holds secret seeds); the host trust dir is
/// created 0755 — its `.pub` halves are read by every user's compile for `key_id`
/// resolution, and the private halves carry their own 0600.
fn generate_keypair(dir: &Path, name: &str, force: bool, host: bool) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    let key_path = dir.join(name);
    let pub_path = dir.join(format!("{name}.pub"));
    if key_path.exists() && !force {
        return Err(format!(
            "{} already exists; refusing to overwrite a signing key. To replace the \
             material AND re-sign everything it signs, use `kennel key rotate {name}`; \
             --force overwrites blind (invalidating everything signed with the old key)",
            key_path.display()
        ));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(if host { 0o755 } else { 0o700 })
        .create(dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if force {
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&pub_path);
    }
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&key_path)
        .arg("-q")
        .status()
        .map_err(|e| format!("invoking ssh-keygen: {e} (is openssh-client installed?)"))?;
    if !status.success() {
        return Err(format!(
            "ssh-keygen exited with status {} — check its output above",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

// ─── the tier walk (list / show / untrust / rotate all read the same facts) ──

/// One key as it sits in a tier store.
struct TierKey {
    name: String,
    tier: &'static str,
    dir: PathBuf,
    /// Whether the private half sits beside the `.pub` (a key that can sign here).
    mine: bool,
}

/// Every `.pub` across the three tier stores, vendor → host → user (the daemon's own
/// search order).
fn all_keys() -> Vec<TierKey> {
    let mut out = Vec::new();
    let user_dir = kennel_lib_config::user_key_dir();
    let stores: Vec<(PathBuf, &'static str)> = vec![
        (kennel_lib_config::vendor_key_dir(), "vendor"),
        (host_key_dir(), "host"),
    ]
    .into_iter()
    .chain(user_dir.into_iter().map(|d| (d, "user")))
    .collect();
    for (dir, tier) in stores {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension().and_then(|x| x.to_str()) == Some("pub"))
                    .then(|| p.file_stem()?.to_str().map(str::to_owned))
                    .flatten()
            })
            .collect();
        names.sort();
        for name in names {
            let mine = dir.join(&name).is_file();
            out.push(TierKey {
                name,
                tier,
                dir: dir.clone(),
                mine,
            });
        }
    }
    out
}

/// The `SHA256:…` fingerprint of a `.pub`, via `ssh-keygen -lf` (the same tool the
/// signing path shells to — no in-tree hash).
fn fingerprint(pub_path: &Path) -> String {
    std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(pub_path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()?
                .split_whitespace()
                .nth(1)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "(fingerprint unavailable)".to_owned())
}

/// One signed object found in the repos: what carries a signature or pin by `key_id`.
struct SignedRef {
    /// `settled`, `template`, or `lock pin`.
    kind: &'static str,
    /// The object's display name.
    name: String,
    /// The file carrying the signature/pin.
    path: PathBuf,
    /// The signing key id it references.
    key_id: String,
}

/// Scan the policy and template cascades for everything carrying a signature or a
/// lockfile pin: settled artefacts (`[signature] key_id`), source templates/fragments
/// (the appended `[signature]`), and lock entries (`signing_key_id`).
fn signed_refs() -> Vec<SignedRef> {
    let mut out = Vec::new();
    let user = kennel_lib_config::User::load().unwrap_or_default();
    for dir in user.policy_dirs() {
        scan_policy_dir(&dir, 0, &mut out);
    }
    for dir in user.template_dirs() {
        scan_template_dir(&dir, &mut out);
    }
    out
}

/// Walk a policies dir (one nesting level deep — `providers/` under the vendor tier)
/// for `*.settled.toml` and `*.lock` files.
fn scan_policy_dir(dir: &Path, depth: u8, out: &mut Vec<SignedRef>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth < 2 {
                scan_policy_dir(&path, depth.saturating_add(1), out);
            }
            continue;
        }
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stem) = fname.strip_suffix(".settled.toml") {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if let Ok(doc) = kennel_lib_policy::parse_signed_settled_unverified(&bytes) {
                if !doc.signature.key_id.is_empty() {
                    out.push(SignedRef {
                        kind: "settled",
                        name: stem.to_owned(),
                        path: path.clone(),
                        key_id: doc.signature.key_id,
                    });
                }
            }
        } else if let Some(stem) = fname.strip_suffix(".lock") {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if let Ok(lock) = kennel_lib_compile::Lockfile::parse(&bytes) {
                for e in lock.entries {
                    if !e.signing_key_id.is_empty() {
                        out.push(SignedRef {
                            kind: "lock pin",
                            name: format!("{stem} → {}", e.name),
                            path: path.clone(),
                            key_id: e.signing_key_id,
                        });
                    }
                }
            }
        }
    }
}

/// Walk a templates dir (`<name>/policy.toml` nested and `<name>.toml` flat — the
/// `FsTemplateSource` layout) for source `[signature]` blocks.
fn scan_template_dir(dir: &Path, out: &mut Vec<SignedRef>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let source = if path.is_dir() {
            path.join("policy.toml")
        } else if path.extension().and_then(|x| x.to_str()) == Some("toml") {
            path.clone()
        } else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&source) else {
            continue;
        };
        let Ok(parsed) = kennel_lib_compile::parse_source(&bytes) else {
            continue;
        };
        if let Some(sig) = parsed.signature {
            let name = parsed
                .template_name
                .or(parsed.name)
                .unwrap_or_else(|| "?".to_owned());
            out.push(SignedRef {
                kind: "template",
                name,
                path: source,
                key_id: sig.key_id,
            });
        }
    }
}

// ─── list / show ─────────────────────────────────────────────────────────────

/// `kennel key list` — every key across the tiers in one view.
///
/// # Errors
///
/// Returns a message on unexpected arguments.
pub fn list(args: &[String]) -> Result<ExitCode, String> {
    if let Some(arg) = args.first() {
        return Err(format!(
            "unexpected argument `{arg}` — usage: kennel key list"
        ));
    }
    let keys = all_keys();
    if keys.is_empty() {
        eprintln!("no keys in any tier store — generate one with `kennel key generate <name>`");
        return Ok(ExitCode::SUCCESS);
    }
    for k in &keys {
        let role = if k.mine {
            "mine (signs here)"
        } else {
            "trusted (public only)"
        };
        let fp = fingerprint(&k.dir.join(format!("{}.pub", k.name)));
        println!("{:<24} [{:<6}] {:<22} {}", k.name, k.tier, role, fp);
    }
    Ok(ExitCode::SUCCESS)
}

/// `kennel key show <name>` — fingerprint plus the signed-object inventory.
///
/// # Errors
///
/// Returns a message if no `<name>` is given or no tier store carries the key.
pub fn show(args: &[String]) -> Result<ExitCode, String> {
    let name = match args {
        [one] => one.as_str(),
        _ => return Err("usage: kennel key show <name>".to_owned()),
    };
    let keys: Vec<TierKey> = all_keys().into_iter().filter(|k| k.name == name).collect();
    if keys.is_empty() {
        return Err(format!(
            "no key `{name}` in any tier store — `kennel key list` shows what exists"
        ));
    }
    for k in &keys {
        let pub_path = k.dir.join(format!("{}.pub", k.name));
        println!("{} [{} tier] {}", k.name, k.tier, fingerprint(&pub_path));
        println!("  public : {}", pub_path.display());
        if k.mine {
            println!(
                "  private: {} (this key signs at the {} tier)",
                k.dir.join(&k.name).display(),
                k.tier
            );
        }
    }
    let refs: Vec<SignedRef> = signed_refs()
        .into_iter()
        .filter(|r| r.key_id == name)
        .collect();
    if refs.is_empty() {
        println!("\nsigns nothing in the policy/template repos");
    } else {
        println!("\nsigns {} object(s):", refs.len());
        for r in &refs {
            println!(
                "  {:<9} {:<28} [{} tier] {}",
                r.kind,
                r.name,
                tier_of_path(&r.path),
                r.path.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ─── trust / untrust (host level only) ───────────────────────────────────────

/// `kennel key trust <file.pub> [--force]` — public key into the host trust store.
///
/// Host level only: the user tier needs no trust list (`kennel policy install`
/// re-signs foreign objects under your own key — that IS user-level trust, per object).
///
/// # Errors
///
/// Returns a message if not root, the file is not an OpenSSH Ed25519 public key, or the
/// key id collides without `--force`.
pub fn trust(args: &[String]) -> Result<ExitCode, String> {
    let mut file: Option<&str> = None;
    let mut force = false;
    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if file.is_none() => file = Some(v),
            _ => return Err("only one <file.pub> may be given".to_owned()),
        }
    }
    let file = file.ok_or("usage: kennel key trust <file.pub> [--force]")?;
    if !invoked_as_root() {
        return Err(
            "`key trust` operates on the host trust store (/etc/kennel/keys) and needs root. \
             The user tier has no trust list: to run someone else's policy, `kennel policy \
             install <file.toml>` re-signs it under your own key — that is user-level trust, \
             per object"
                .to_owned(),
        );
    }
    let contents = std::fs::read_to_string(file).map_err(|e| format!("reading {file}: {e}"))?;
    if !kennel_lib_policy::openssh::is_openssh_public(&contents) {
        return Err(format!(
            "{file} is not an OpenSSH ed25519 public key (the `ssh-ed25519 …` line \
             `kennel key generate` writes)"
        ));
    }
    let name = Path::new(file)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("cannot derive a key id from `{file}`"))?
        .to_owned();
    if !is_valid_key_id(&name) {
        return Err(format!("`{name}` is not a valid key id"));
    }
    let dest = host_key_dir().join(format!("{name}.pub"));
    if dest.exists() && !force {
        return Err(format!(
            "{} already exists — pass --force to replace it (this changes which key \
             `{name}` signatures verify against)",
            dest.display()
        ));
    }
    std::fs::write(&dest, contents.as_bytes())
        .map_err(|e| format!("writing {}: {e}", dest.display()))?;
    eprintln!(
        "trusted `{name}` at the host tier ({}) — artefacts it signs now verify for \
         every user on this host",
        dest.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// `kennel key untrust <name> [--yes]` — remove a key from the host trust store.
///
/// The impact report comes first: everything that stops verifying is named before the
/// mutation. The scan spans the host tier AND the user tiers below it: acceptance is
/// downward-inclusive, so untrusting a host key also orphans user-level artefacts
/// riding its signature.
///
/// # Errors
///
/// Returns a message if not root, the key is not in the host trust store (vendor keys
/// are package payload; user keys need no untrust), or the impact is unconfirmed.
pub fn untrust(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("only one <name> may be given".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel key untrust <name> [--yes]")?;
    if !invoked_as_root() {
        return Err(
            "`key untrust` operates on the host trust store (/etc/kennel/keys) and needs root"
                .to_owned(),
        );
    }
    let pub_path = host_key_dir().join(format!("{name}.pub"));
    if !pub_path.is_file() {
        if kennel_lib_config::vendor_key_dir()
            .join(format!("{name}.pub"))
            .is_file()
        {
            return Err(format!(
                "`{name}` is a vendor-tier key — package payload, managed by the installer, \
                 not the host trust store"
            ));
        }
        return Err(format!(
            "no key `{name}` in the host trust store ({})",
            host_key_dir().display()
        ));
    }

    // The impact report BEFORE the mutation — trust-store changes are never silent.
    let orphaned: Vec<SignedRef> = signed_refs()
        .into_iter()
        .filter(|r| r.key_id == name)
        .collect();
    if orphaned.is_empty() {
        eprintln!("`{name}` signs nothing in the policy/template repos.");
    } else {
        eprintln!(
            "untrusting `{name}` orphans {} object(s) — they stop verifying:",
            orphaned.len()
        );
        for r in &orphaned {
            eprintln!(
                "  {:<9} {:<28} [{} tier] {}",
                r.kind,
                r.name,
                tier_of_path(&r.path),
                r.path.display()
            );
        }
    }
    if !yes {
        eprintln!("\nnothing removed — re-run with --yes to proceed");
        return Ok(ExitCode::from(1));
    }
    std::fs::remove_file(&pub_path).map_err(|e| format!("removing {}: {e}", pub_path.display()))?;
    eprintln!("untrusted `{name}` ({} removed)", pub_path.display());
    let private = host_key_dir().join(name);
    if private.is_file() {
        eprintln!(
            "note: the private half remains at {} — its location confers no authority, \
             but remove it if the key is retired for good",
            private.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ─── rotate ──────────────────────────────────────────────────────────────────

/// The rotation work list for one key, split by what the ceremony can drive itself.
struct RotationPlan {
    /// Source templates/fragments signed by the key (re-sign with the successor).
    templates: Vec<SignedRef>,
    /// Settled leaves signed by the key, with a resolved recompile job each.
    leaves: Vec<LeafJob>,
    /// Settled leaves with no resolvable source — unrotatable, named in the report.
    orphans: Vec<SignedRef>,
    /// Objects outside the key's own tier (report-only: the owner recompiles).
    foreign: Vec<SignedRef>,
}

/// One leaf recompile in a rotation: which source, to which output, with what lock mode.
struct LeafJob {
    settled: SignedRef,
    /// The source to recompile — beside the artefact, or resolved through the policy
    /// cascade (a host-compiled artefact's source may live in the vendor tree, the
    /// reference-policy layout).
    source: PathBuf,
    /// The artefact's own path: the compile is pinned back onto it, never beside a
    /// cascade-resolved source in another tier's tree.
    output: PathBuf,
    /// `--no-lock` when the artefact carried no lock (the reference-policy compile mode);
    /// a rotation never introduces pin state the installer does not manage.
    no_lock: bool,
}

/// `kennel key rotate <name> [--yes]` — the supervised rotation ceremony.
///
/// Same key id, new material: retire the old pair (`.retired` suffixes — a retired
/// public half must NOT stay a `.pub`, or the trust store keeps trusting it), mint a
/// successor under the same name, re-sign every template the key signs, and recompile
/// every leaf it signs (removing a lockfile whose pinned template was re-signed, so the
/// re-pin is driven, not folklore). Objects at other tiers riding the old signature are
/// named as owed work — a host rotation cannot re-sign user-owned leaves.
///
/// # Errors
///
/// Returns a message if the key is not at the invoking tier (root rotates the host
/// tier, a user their own; the maintainer key rotates upstream, never here), a previous
/// rotation's retired pair is still in place, or a ceremony step fails.
pub fn rotate(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("only one <name> may be given".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel key rotate <name> [--yes]")?;
    let host = invoked_as_root();
    let tier = if host { "host" } else { "user" };
    let dir = if host {
        host_key_dir()
    } else {
        default_key_dir()
    };
    let key_path = dir.join(name);
    if !key_path.is_file() {
        if kennel_lib_config::vendor_key_dir()
            .join(format!("{name}.pub"))
            .is_file()
        {
            return Err(format!(
                "`{name}` is the vendor tier's — the maintainer key is the project's affair \
                 and rotates upstream, never on a host"
            ));
        }
        return Err(format!(
            "no private key `{name}` at the {tier} tier ({}) — a key rotates only at the \
             level it lives at{}",
            dir.display(),
            if host {
                ""
            } else {
                "; rotating the host key needs root"
            }
        ));
    }

    let plan = rotation_plan(name, tier);
    print_plan(name, tier, &plan);
    if !yes {
        eprintln!("\nnothing rotated — re-run with --yes to proceed");
        return Ok(ExitCode::from(1));
    }

    // Retire the old pair. The public half must leave the `.pub` namespace: the trust
    // store loads every `.pub`, and a still-loaded old key would defeat the rotation.
    let retired_key = dir.join(format!("{name}.retired"));
    let retired_pub = dir.join(format!("{name}.pub.retired"));
    if retired_key.exists() || retired_pub.exists() {
        return Err(format!(
            "a previous rotation's retired pair is still at {} — remove it first",
            retired_key.display()
        ));
    }
    let pub_path = dir.join(format!("{name}.pub"));
    std::fs::rename(&key_path, &retired_key)
        .map_err(|e| format!("retiring {}: {e}", key_path.display()))?;
    if let Err(e) = std::fs::rename(&pub_path, &retired_pub) {
        // Roll the private half back so the store is unchanged on failure.
        let _ = std::fs::rename(&retired_key, &key_path);
        return Err(format!("retiring {}: {e}", pub_path.display()));
    }

    // Mint the successor under the same name; on failure restore the old pair.
    if let Err(e) = generate_keypair(&dir, name, false, host) {
        let _ = std::fs::rename(&retired_key, &key_path);
        let _ = std::fs::rename(&retired_pub, &pub_path);
        return Err(format!(
            "minting the successor failed ({e}); old key restored"
        ));
    }
    eprintln!("successor minted: {}", fingerprint(&pub_path));

    let failures = drive_cascade(&plan, &key_path);
    eprintln!();
    if failures == 0 {
        eprintln!(
            "rotated `{name}` at the {tier} tier: {} template(s) re-signed, {} leaf(s) \
             recompiled under the successor key",
            plan.templates.len(),
            plan.leaves.len()
        );
    } else {
        eprintln!(
            "rotation of `{name}` finished with {failures} failure(s) — the objects named \
             above still ride the RETIRED key and no longer verify; fix and re-sign them"
        );
    }
    eprintln!(
        "old key retired to {} / {} — remove both once nothing needs forensics",
        retired_key.display(),
        retired_pub.display()
    );
    report_owed(&plan);
    if failures == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

/// Re-sign and recompile everything in the plan with the successor key, returning the
/// failure count. Failures are reported and counted, never silently skipped — the
/// operator sees exactly what still rides the retired key.
fn drive_cascade(plan: &RotationPlan, successor: &Path) -> usize {
    let key_arg = successor.to_string_lossy().into_owned();
    let mut failures = 0usize;
    let mut resigned_templates: Vec<String> = Vec::new();
    for t in &plan.templates {
        match resign_template(&t.path, &key_arg) {
            Ok(()) => {
                eprintln!("re-signed template {}", t.path.display());
                resigned_templates.push(t.name.clone());
            }
            Err(e) => {
                eprintln!("FAILED to re-sign {}: {e}", t.path.display());
                failures = failures.saturating_add(1);
            }
        }
    }
    for job in &plan.leaves {
        // A lockfile pinning a just-re-signed template would hard-fail the recompile
        // (the pin is doing its job); remove it so the compile writes the fresh pin.
        if let Some(lock) = lock_pinning(&job.output, &resigned_templates) {
            let _ = std::fs::remove_file(&lock);
            eprintln!(
                "re-pinning {} (pinned a re-signed template)",
                lock.display()
            );
        }
        let mut compile_args = vec![
            job.source.to_string_lossy().into_owned(),
            "--key".to_owned(),
            key_arg.clone(),
            // Pin the output onto the artefact's own path: a cascade-resolved source
            // (the reference-policy layout) must never grow a settled sibling in
            // another tier's tree.
            "--output".to_owned(),
            job.output.to_string_lossy().into_owned(),
        ];
        if job.no_lock {
            compile_args.push("--no-lock".to_owned());
        }
        match crate::policy::compile(&compile_args) {
            Ok(code) if code == ExitCode::SUCCESS => {
                eprintln!("recompiled {}", job.settled.path.display());
            }
            Ok(_) | Err(_) => {
                eprintln!("FAILED to recompile {}", job.source.display());
                failures = failures.saturating_add(1);
            }
        }
    }
    failures
}

/// Build the work list: what the old key signs, split into what this ceremony drives
/// (own-tier templates and recompilable leaves) and what it can only report.
fn rotation_plan(name: &str, tier: &'static str) -> RotationPlan {
    let mut plan = RotationPlan {
        templates: Vec::new(),
        leaves: Vec::new(),
        orphans: Vec::new(),
        foreign: Vec::new(),
    };
    for r in signed_refs() {
        if r.key_id != name {
            continue;
        }
        let obj_tier = tier_of_path(&r.path);
        // Lock pins re-pin as a side effect of the leaf recompile / are the leaf
        // owner's to re-pin; they are not standalone work items.
        if r.kind == "lock pin" {
            if obj_tier != tier {
                plan.foreign.push(r);
            }
            continue;
        }
        if obj_tier != tier {
            plan.foreign.push(r);
            continue;
        }
        match r.kind {
            "template" => plan.templates.push(r),
            "settled" => match leaf_job(r) {
                Ok(job) => plan.leaves.push(job),
                Err(orphan) => plan.orphans.push(orphan),
            },
            _ => {}
        }
    }
    plan
}

/// Resolve a settled artefact's recompile job, or give it back as an orphan.
///
/// The source is the sibling `policy.toml` when present; else the artefact's name is
/// resolved through the policy cascade — a host-compiled reference artefact's source
/// ships in the vendor tree, not beside it. Either way the compile output is pinned
/// back onto the artefact's own path, and an artefact that carried no lock recompiles
/// `--no-lock` (the installer's reference mode) rather than growing new pin state.
fn leaf_job(settled: SignedRef) -> Result<LeafJob, SignedRef> {
    let dir = settled.path.parent();
    let sibling = dir.map(|d| d.join("policy.toml")).filter(|p| p.is_file());
    let Some(source) = sibling.or_else(|| cascade_source_for(&settled.path)) else {
        return Err(settled);
    };
    let no_lock = !dir
        .map(|d| d.join(format!("{}.lock", settled.name)))
        .is_some_and(|l| l.is_file());
    let output = settled.path.clone();
    Ok(LeafJob {
        settled,
        source,
        output,
        no_lock,
    })
}

/// Print what the ceremony will do, before it does it.
fn print_plan(name: &str, tier: &str, plan: &RotationPlan) {
    eprintln!("rotating `{name}` at the {tier} tier — the plan:");
    eprintln!("  1. retire the old pair (`.retired` suffixes), mint a successor `{name}`");
    if plan.templates.is_empty() && plan.leaves.is_empty() {
        eprintln!("  2. nothing signed by this key at the {tier} tier — no re-sign work");
    }
    for t in &plan.templates {
        eprintln!("  - re-sign template  {}", t.path.display());
    }
    for job in &plan.leaves {
        eprintln!(
            "  - recompile leaf    {} (from {}; lock re-pins as needed)",
            job.settled.path.display(),
            job.source.display()
        );
    }
    for o in &plan.orphans {
        eprintln!(
            "  ! cannot rotate     {} — settled artefact whose source resolves nowhere in \
             the cascade; it will stop verifying",
            o.path.display()
        );
    }
}

/// Name the out-of-tier objects the rotation orphans — owed work for their owners.
fn report_owed(plan: &RotationPlan) {
    if plan.foreign.is_empty() && plan.orphans.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("owed elsewhere (this ceremony cannot sign for other tiers/owners):");
    for r in plan.foreign.iter().chain(&plan.orphans) {
        eprintln!(
            "  {:<9} {:<28} [{} tier] {} — recompile/re-pin under a key that signs there",
            r.kind,
            r.name,
            tier_of_path(&r.path),
            r.path.display()
        );
    }
}

/// A settled artefact's source, resolved through the policy cascade by its path below
/// its `policies` root.
///
/// The reference layout: install.sh compiles `/usr/lib/kennel/policies/<rel>/policy.toml`
/// into `/etc/kennel/policies/<rel>/<name>.settled.toml` with no source beside it — so
/// the same `<rel>` (which may carry a `providers/` segment) is looked up under every
/// policy root, source form only.
fn cascade_source_for(settled: &Path) -> Option<PathBuf> {
    let comps: Vec<std::path::Component<'_>> = settled.parent()?.components().collect();
    let pos = comps.iter().rposition(|c| c.as_os_str() == "policies")?;
    let rel: PathBuf = comps.get(pos.saturating_add(1)..)?.iter().collect();
    kennel_lib_config::User::load()
        .unwrap_or_default()
        .policy_dirs()
        .into_iter()
        .map(|root| root.join(&rel).join("policy.toml"))
        .find(|p| p.is_file())
}

/// The lockfile beside `artefact` (its dir's `<name>.lock`), if it exists and pins any
/// of `template_names`.
fn lock_pinning(artefact: &Path, template_names: &[String]) -> Option<PathBuf> {
    if template_names.is_empty() {
        return None;
    }
    let dir = artefact.parent()?;
    let name = dir.file_name()?.to_str()?;
    let lock = dir.join(format!("{name}.lock"));
    let bytes = std::fs::read(&lock).ok()?;
    let parsed = kennel_lib_compile::Lockfile::parse(&bytes).ok()?;
    parsed
        .entries
        .iter()
        .any(|e| template_names.contains(&e.name))
        .then_some(lock)
}

/// Strip the appended `[signature]` block from a source template and re-sign it.
///
/// `template sign` appends the block at the end of the file, so the strip cuts from the
/// last `[signature]` header to EOF — then proves the remainder is the same object,
/// unsigned, before writing anything. A hand-moved `[signature]` refuses rather than
/// guesses.
fn resign_template(path: &Path, key: &str) -> Result<(), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let idx = text
        .rfind("\n[signature]\n")
        .map(|i| i.saturating_add(1))
        .or_else(|| text.starts_with("[signature]\n").then_some(0))
        .ok_or("carries no [signature] block to replace")?;
    // The cut tail must be EXACTLY the appended block (its three keys, nothing else) —
    // a `[signature]` sitting mid-file would otherwise take innocent trailing tables
    // with it. Anything unexpected refuses rather than guesses.
    let tail = &text[idx..];
    let tail_is_pure_block = tail
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .all(|l| {
            l.starts_with("algorithm = ") || l.starts_with("key_id = ")
                || l.starts_with("signature = ")
        });
    if !tail_is_pure_block {
        return Err(
            "its [signature] is not the appended-last block `template sign` writes — \
             remove it by hand and re-sign"
                .to_owned(),
        );
    }
    let stripped = &text[..idx];
    let parsed = kennel_lib_compile::parse_source(stripped.as_bytes()).map_err(|e| {
        format!(
            "stripping the [signature] block broke the source ({e}) — \
             remove it by hand and re-sign"
        )
    })?;
    if parsed.signature.is_some() {
        return Err(
            "still carries a [signature] after the strip — remove it by hand and re-sign"
                .to_owned(),
        );
    }
    std::fs::write(path, stripped.as_bytes())
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    let sign_args = [
        path.to_string_lossy().into_owned(),
        "--key".to_owned(),
        key.to_owned(),
    ];
    match crate::policy::template_sign(&sign_args) {
        Ok(code) if code == ExitCode::SUCCESS => Ok(()),
        Ok(_) => Err("the sign step failed".to_owned()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature strip takes exactly the appended-last block and leaves a parseable,
    /// unsigned source — the invariant `resign_template` rests on.
    #[test]
    fn signature_strip_finds_the_appended_block() {
        let body = "template_name = \"t\"\n# a comment kept\n[exec]\nallow = []\n";
        let signed = format!(
            "{body}\n[signature]\nalgorithm = \"sshsig\"\nkey_id = \"k\"\nsignature = \"s\"\n"
        );
        let idx = signed
            .rfind("\n[signature]\n")
            .map(|i| i + 1)
            .expect("finds the block");
        let stripped = &signed[..idx];
        let parsed = kennel_lib_compile::parse_source(stripped.as_bytes()).expect("parses");
        assert!(parsed.signature.is_none());
        assert_eq!(parsed.template_name.as_deref(), Some("t"));
        assert!(stripped.contains("# a comment kept"));
    }

    /// A lockfile pinning one of the re-signed templates is found; one pinning none is not.
    #[test]
    fn lock_pinning_matches_only_referenced_templates() {
        let dir = std::env::temp_dir().join(format!("kennel-key-lock-{}", std::process::id()));
        let leaf = dir.join("myjob");
        std::fs::create_dir_all(&leaf).expect("mkdir");
        let source = leaf.join("policy.toml");
        std::fs::write(&source, b"name = \"myjob\"\n").expect("write");
        std::fs::write(
            leaf.join("myjob.lock"),
            b"[[locked]]\nname = \"base-x\"\nsigning_key_id = \"host\"\nsignature = \"sig\"\n",
        )
        .expect("write lock");
        let hit = lock_pinning(&source, &["base-x".to_owned()]);
        assert!(hit.is_some(), "pins base-x");
        let miss = lock_pinning(&source, &["other".to_owned()]);
        assert!(miss.is_none(), "pins nothing re-signed");
        assert!(lock_pinning(&source, &[]).is_none(), "no re-signs, no work");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
