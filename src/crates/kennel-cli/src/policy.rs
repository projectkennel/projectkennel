//! The `kennel policy <verb>` command group.
//!
//! Author, inspect, sign, diff, lint, and check policies — plus the compile machinery
//! shared with `run`'s in-memory dev loop (`build_settled`, `FsTemplateSource`,
//! `TempSettled`, `mint_ssh_keys`, `is_source_policy`). Split out of `main.rs`.
//!
//! Path/name resolvers, the template/trust-dir cascade, and key loading stay in the crate root
//! (shared across modules); `review::check_exclusive_ownership` gates `compile`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_compile::TemplateSource;

use crate::review;
use crate::{
    add_default_template_dirs, add_system_trust_dirs, default_settled_path, default_signing_key,
    is_valid_policy_name, lexopt_unexpected, lexopt_value, policy_error_code, resolve_key_arg,
    resolve_policy, resolve_template, settled_with_sshsig, signing_trust_dirs, sshsig_sign,
    usage_of, TrustContext, POLICY_VERBS,
};

// ---- `kennel policy compile` ---------------------------------------------------

/// A filesystem-backed [`TemplateSource`].
///
/// Searches each directory for a flat `<name>@<version>.toml` (the installed layout)
/// and then `<name>/policy.toml` (the in-tree source layout), so the same resolver
/// serves both.
pub struct FsTemplateSource {
    /// The template search directories (the template cascade).
    pub dirs: Vec<PathBuf>,
}

impl TemplateSource for FsTemplateSource {
    fn fetch(&self, name: &str) -> Option<Vec<u8>> {
        for dir in &self.dirs {
            let flat = dir.join(format!("{name}.toml"));
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

    fn fetch_settled(&self, name: &str) -> Option<Vec<u8>> {
        for dir in &self.dirs {
            // The installed flat layout, then the in-tree `<name>/<name>.settled.toml` beside source.
            let flat = dir.join(format!("{name}.settled.toml"));
            if let Ok(bytes) = std::fs::read(&flat) {
                return Some(bytes);
            }
            let nested = dir.join(name).join(format!("{name}.settled.toml"));
            if let Ok(bytes) = std::fs::read(&nested) {
                return Some(bytes);
            }
        }
        None
    }
}

/// `kennel policy compile <policy> [--output P] [--key K] [--unsigned] [--template-dir D]...`
///
/// Resolves a source policy fully and writes a settled policy. Stateless: it never
/// contacts the daemon. Exit codes follow `02-1-cli.md` (3 = validation/resolution,
/// 6 = signature).
///
/// # Errors
///
/// Returns a message if the arguments are invalid, the policy cannot be resolved or
/// read, the signing key cannot be loaded, an exclusive bind targets an unowned host
/// path, the lockfile mismatches a prior pin, or writing the settled artefact fails.
// allow: one cohesive arg-parse + compile + write/sign sequence for the CLI subcommand.
#[allow(clippy::too_many_lines)]
pub fn compile(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_path: Option<&str> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut key_path: Option<&str> = None;
    let mut key_id: Option<&str> = None;
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
            "--key-id" => key_id = Some(it.next().ok_or("--key-id needs a value")?),
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
        "usage: kennel policy compile <policy> [--output P] [--key K | --unsigned] [--key-id ID] \
         [--require-signed] [--no-lock] [--template-dir D]... [--trust-dir D]...",
    )?;
    // `<policy>` is a path or a name resolved from the `policies/` cascade,
    // preferring the source `policy.toml` (the artefact we are about to compile).
    let (policy_path, _name) = resolve_policy(policy_arg, false)?;
    if key_path.is_some() && unsigned {
        return Err("--key and --unsigned are mutually exclusive".to_owned());
    }
    if key_id.is_some() && unsigned {
        return Err("--key-id and --unsigned are mutually exclusive".to_owned());
    }
    add_default_template_dirs(&mut template_dirs);

    let bytes = std::fs::read(&policy_path)
        .map_err(|e| format!("reading {}: {e}", policy_path.display()))?;

    // No installation constants here: per-kennel loopback addressing is derived at spawn from
    // the caller's uid (v6-only ULA), never baked into the compiled policy. The CLI has no part in it.
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let version = env!("CARGO_PKG_VERSION");

    // Build the trust context: `--require-signed` refuses unsigned templates and
    // verifies against the trust store (`--trust-dir`, else the default key dirs);
    // otherwise unsigned templates resolve (development), still verifying any present
    // signature against whatever keys are loaded.
    add_system_trust_dirs(&mut trust_dirs);
    let tc = TrustContext::load(&trust_dirs)?;
    let trust = if require_signed {
        tc.require()
    } else {
        tc.allow_unsigned()
    };

    let mut compiled = match build_settled(&bytes, &source, &trust, version) {
        Ok(compiled) => compiled,
        Err(e) => {
            eprintln!("kennel: {e}");
            return Ok(ExitCode::from(policy_error_code(&e)));
        }
    };
    print_warnings(&compiled.warnings);
    // Refuse an exclusive bind on a host path the operator does not own (§2.7) — the privhelper
    // would otherwise be asked to blind-mount over a path you have no ownership of (overreach).
    review::check_exclusive_ownership(&compiled.policy.effective_policy.fs.exclusive)
        .map_err(|e| format!("kennel: {e}"))?;
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

    // Sign via `ssh-keygen -Y sign` with `--key` (else the sole key in the user key
    // dir); `--unsigned` opts out entirely (a development build). The stamped `key_id`
    // comes from where the matching `*.pub` is placed in the trust store, not from the
    // signing key's filename — so the key may live in `~/.ssh`, an agent, or a token,
    // away from the public keys.
    let doc = if unsigned {
        kennel_lib_compile::seal_unsigned(policy)
    } else {
        let key = match key_path {
            Some(p) => resolve_key_arg(p)?.to_string_lossy().into_owned(),
            None => default_signing_key()?.to_string_lossy().into_owned(),
        };
        let canonical =
            kennel_lib_policy::canonical::canonical_bytes(policy).map_err(|e| e.to_string())?;
        let (key_id, armor) = sshsig_sign(&canonical, &key, key_id, &signing_trust_dirs())?;
        settled_with_sshsig(policy, key_id, armor)
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
/// compiled settled artefact.
///
/// A source policy parses as a `SourcePolicy` (a template or a leaf — the one type); a settled
/// document carries fields (`settled_schema_version`, `[signature]`, …) that schema's
/// `deny_unknown_fields` rejects, so the two parses are mutually exclusive. Used by `kennel run` to
/// decide whether to compile.
#[must_use]
pub fn is_source_policy(bytes: &[u8]) -> bool {
    kennel_lib_compile::parse_source(bytes).is_ok()
}

/// A short-lived on-disk settled policy produced by `kennel run`'s in-memory
/// compile. The daemon reads the path during bring-up; the file is removed when this
/// guard drops (the run returns or errors out).
pub struct TempSettled {
    path: PathBuf,
}

impl TempSettled {
    /// Write `bytes` to a unique, safe-owned path (under `$XDG_RUNTIME_DIR` when set,
    /// else the temp dir) keyed by kennel name and pid.
    ///
    /// # Errors
    ///
    /// Returns a message if the file cannot be written to the chosen directory.
    pub fn write(name: &str, bytes: &[u8]) -> Result<Self, String> {
        let dir =
            std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        Self::write_in(&dir, name, bytes)
    }

    /// Write `bytes` to a unique path **in `dir`**, keyed by kennel name and pid. Used when
    /// the settled artefact must sit beside a sibling the daemon resolves relative to it
    /// (the `ssh/` minted-key dir) — so `<settled>.parent()/ssh` finds the keys.
    ///
    /// # Errors
    ///
    /// Returns a message if the file cannot be written into `dir`.
    pub fn write_in(dir: &Path, name: &str, bytes: &[u8]) -> Result<Self, String> {
        let path = dir.join(format!("kennel-run-{name}-{}.settled", std::process::id()));
        std::fs::write(&path, bytes)
            .map_err(|e| format!("writing temp settled policy {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    /// The path to the temporary settled file.
    #[must_use]
    pub fn path(&self) -> &Path {
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
pub fn print_warnings(warnings: &[String]) {
    for w in warnings {
        eprintln!("kennel: warning: {w}");
    }
}

/// Compile and sign a source policy to settled bytes — the compile house's in-process
/// ceremony, for verbs that generate a leaf and boot it in one flow (`kennel oci build`'s
/// confined fetch).
///
/// `source_dir` anchors source-relative material (the `[ssh]` synthetic keys mint at
/// `<source_dir>/ssh`). The run house never calls this: `kennel run`/`kennel oci run` boot
/// only pre-compiled artefacts.
///
/// # Errors
///
/// Returns a message if the compile, key resolution, signing, or serialisation fails.
pub fn compile_and_sign(
    bytes: &[u8],
    source_dir: &Path,
    key: Option<&str>,
    key_id: Option<&str>,
    mut template_dirs: Vec<PathBuf>,
    mut trust_dirs: Vec<PathBuf>,
) -> Result<Vec<u8>, String> {
    crate::add_default_template_dirs(&mut template_dirs);
    crate::add_system_trust_dirs(&mut trust_dirs);
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let tc = TrustContext::load(&trust_dirs)?;
    let trust = tc.allow_unsigned();
    let mut compiled = build_settled(bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
        .map_err(|e| format!("compiling: {e}"))?;
    print_warnings(&compiled.warnings);
    print_warnings(&kennel_lib_policy::resolve_settled_loaders(
        &mut compiled.policy,
    ));
    let _minted = mint_ssh_keys(&mut compiled.policy, &source_dir.join("ssh"))?;
    let key = match key {
        Some(p) => p.to_owned(),
        None => crate::default_signing_key()?.to_string_lossy().into_owned(),
    };
    let canonical = kennel_lib_policy::canonical::canonical_bytes(&compiled.policy)
        .map_err(|e| format!("canonical form: {e}"))?;
    let (resolved_id, armor) =
        crate::sshsig_sign(&canonical, &key, key_id, &crate::signing_trust_dirs())?;
    let doc = crate::settled_with_sshsig(&compiled.policy, resolved_id, armor);
    kennel_lib_policy::to_bytes(&doc).map_err(|e| format!("serialising: {e}"))
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
///
/// # Errors
///
/// Returns a message if the `ssh_dir` cannot be created, `ssh-keygen` cannot be run or
/// fails, or a generated public key cannot be read back.
pub fn mint_ssh_keys(
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

/// Compile policy `bytes` into a settled artefact.
///
/// A template and a leaf are the one `SourcePolicy` type — list fields replace (a bare sequence) or
/// increment (`[[….add]]`) at the same key, and the chain fold applies the entry's own increments —
/// so a single parse-and-compile handles both.
///
/// # Errors
///
/// Returns a `PolicyError` if `bytes` does not parse as a source policy, or if resolving and
/// compiling it fails.
pub fn build_settled(
    bytes: &[u8],
    source: &FsTemplateSource,
    trust: &kennel_lib_compile::Trust<'_>,
    version: &str,
) -> Result<kennel_lib_compile::Compiled, kennel_lib_policy::PolicyError> {
    let entry = kennel_lib_compile::parse_source(bytes)?;
    kennel_lib_compile::compile(&entry, source, trust, version)
}

/// `kennel policy validate <policy> [--template-dir D] [--require-signed] [--trust-dir D]`
///
/// Resolve and check a policy (chain, signatures, deltas, includes, invariants)
/// without emitting a settled artefact. Exit 0 if valid; otherwise the same code
/// `compile` would return.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no policy is given, the policy file
/// cannot be read, or the trust store cannot be loaded. A policy that resolves but is
/// invalid is reported via the exit code, not an error.
pub fn validate(args: &[String]) -> Result<ExitCode, String> {
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
        .ok_or("usage: kennel policy validate <policy> [--template-dir D] [--require-signed]")?;
    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);

    let bytes = std::fs::read(policy_path).map_err(|e| format!("reading {policy_path}: {e}"))?;
    let source = FsTemplateSource {
        dirs: template_dirs,
    };
    let tc = TrustContext::load(&trust_dirs)?;
    let trust = if require_signed {
        tc.require()
    } else {
        tc.allow_unsigned()
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
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no policy is given, the policy file
/// cannot be read, the trust store cannot be loaded, the source cannot be resolved, or
/// the threat catalogue cannot be loaded.
pub fn policy_risks(args: &[String]) -> Result<ExitCode, String> {
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
    let tc = TrustContext::load(&trust_dirs)?;
    let trust = tc.allow_unsigned();

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
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no policy is given, the trust store
/// cannot be loaded, a policy cannot be resolved or read, the one-argument form has no
/// `template_base` to diff against, or the threat catalogue cannot be loaded.
pub fn policy_diff(args: &[String]) -> Result<ExitCode, String> {
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
    let tc = TrustContext::load(&trust_dirs)?;

    // The primary's *declared* identity (its own `name`/`template_base`, before the
    // fold loses them) drives the label and the one-arg baseline.
    let (primary_name, primary_base) = declared_meta(primary)?;
    let primary_eff = resolve_effective(primary, &template_dirs, &tc)?;
    let primary_label = primary_name.unwrap_or_else(|| primary.to_owned());

    // One arg: baseline → policy (what the leaf adds over its template). Two args:
    // <primary> → <other> (primary is the "before", other the "after").
    let (old_eff, old_label, new_eff, new_label) = if let Some(other) = positionals.get(1) {
        let (other_name, _) = declared_meta(other)?;
        let other_eff = resolve_effective(other, &template_dirs, &tc)?;
        let other_label = other_name.unwrap_or_else(|| (*other).to_owned());
        (primary_eff, primary_label, other_eff, other_label)
    } else {
        let reference = primary_base.ok_or_else(|| {
            format!(
                "`{primary_label}` has no `template_base` to diff against; \
                 pass a second policy to compare two"
            )
        })?;
        let baseline = resolve_template_baseline(&reference, &template_dirs, &tc)?;
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
    Ok((None, None))
}

/// Resolve a policy argument (a name in the search path or a literal path) to its
/// folded effective *source* policy — the honest input for the diff/risk engines
/// (threat tags survive only in source). A template and a leaf are the one source type.
fn resolve_effective(
    arg: &str,
    template_dirs: &[PathBuf],
    tc: &TrustContext,
) -> Result<kennel_lib_compile::SourcePolicy, String> {
    let (path, _) = resolve_policy(arg, false)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let source = FsTemplateSource {
        dirs: template_dirs.to_vec(),
    };
    let trust = tc.allow_unsigned();
    kennel_lib_compile::effective_source(&bytes, &source, &trust)
        .map_err(|e| format!("resolving {}: {e}", path.display()))
}

/// Resolve a template reference (a bare `<name>`) as a standalone effective policy —
/// the baseline a leaf's own deltas are measured against.
fn resolve_template_baseline(
    reference: &str,
    template_dirs: &[PathBuf],
    tc: &TrustContext,
) -> Result<kennel_lib_compile::SourcePolicy, String> {
    let source = FsTemplateSource {
        dirs: template_dirs.to_vec(),
    };
    let bytes = source.fetch(reference).ok_or_else(|| {
        format!("cannot read `{reference}` to diff against (pass --template-dir)")
    })?;
    let trust = tc.allow_unsigned();
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
    println!("\nFull threat definitions and residuals: docs/reference/THREATS.md");
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
    println!("\nFull threat definitions and residuals: docs/reference/THREATS.md");
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
///
/// # Errors
///
/// Returns a usage message if any arguments are given (the verb takes none).
pub fn policy_list(args: &[String]) -> Result<ExitCode, String> {
    if !args.is_empty() {
        return Err(usage_of(POLICY_VERBS, "list"));
    }
    let user = kennel_lib_config::User::load().unwrap_or_default();
    if !list_house("policies", &user.policy_dirs()) {
        println!("no policies found in the search path (`kennel template list` shows the bases)");
    }
    Ok(ExitCode::SUCCESS)
}

/// `kennel template list` — the template house's half of the old combined listing.
///
/// # Errors
///
/// Returns the usage line on extra arguments.
pub fn template_list(args: &[String]) -> Result<ExitCode, String> {
    if !args.is_empty() {
        return Err(crate::usage_of(crate::TEMPLATE_VERBS, "list"));
    }
    let user = kennel_lib_config::User::load().unwrap_or_default();
    if !list_house("templates", &user.template_dirs()) {
        println!("no templates found in the search path");
    }
    Ok(ExitCode::SUCCESS)
}

/// List one house's search dirs (`<dir>/<name>/…`, kind-classified), with provenance.
///
/// Two facts per entry, shown where they carry information (W3): the **placement tier** (the
/// dir block's tier) and, for a settled artefact, the **signing tier** where it differs from
/// placement — a vendor-signed artefact copied down to user space reads `[vendor-signed]`,
/// distinct from a user-signed clone. A name repeated across the cascade is marked on both
/// sides: the earlier (higher-priority) entry `shadows` the later tier, the later one is
/// `shadowed by` the winner — resolution is first-dir-wins, so the earlier entry is what runs.
/// Returns whether anything was printed.
fn list_house(label: &str, dirs: &[PathBuf]) -> bool {
    // Pass 1: collect every entry per dir, in cascade order.
    type Entry = (String, &'static str, PathBuf);
    let mut blocks: Vec<(&PathBuf, &'static str, Vec<Entry>)> = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut names: Vec<Entry> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let settled = path.join(format!("{name}.settled.toml"));
            let kind = if settled.is_file() {
                "settled"
            } else if path.join("policy.toml").is_file() {
                policy_kind(&path.join("policy.toml"))
            } else {
                continue;
            };
            names.push((name.to_owned(), kind, settled));
        }
        if names.is_empty() {
            continue;
        }
        names.sort();
        blocks.push((dir, crate::tier_of_path(dir), names));
    }
    // Pass 2: print, marking shadow relations across the cascade (earlier dir wins).
    // Every (block-index, tier) a name occurs at, so block i can ask "does this name
    // occur in any LATER block?" without a same-block self-match.
    let mut occurrences: std::collections::BTreeMap<&str, Vec<(usize, &'static str)>> =
        std::collections::BTreeMap::new();
    for (i, (_, tier, names)) in blocks.iter().enumerate() {
        for (name, _, _) in names {
            occurrences
                .entry(name.as_str())
                .or_default()
                .push((i, tier));
        }
    }
    let mut seen: std::collections::BTreeMap<String, &'static str> =
        std::collections::BTreeMap::new();
    for (i, (dir, tier, names)) in blocks.iter().enumerate() {
        println!("{label}: {} [{tier} tier]", dir.display());
        for (name, kind, settled) in names {
            let mut notes: Vec<String> = Vec::new();
            // Signing provenance, where it differs from placement (settled artefacts only).
            if *kind == "settled" {
                match settled_key_id(settled).map(|id| (crate::tier_of_key_id(&id), id)) {
                    Some((Some(kt), _)) if kt != *tier => notes.push(format!("{kt}-signed")),
                    Some((None, id)) => notes.push(format!("signed by unknown key `{id}`")),
                    _ => {}
                }
            }
            if let Some(winner) = seen.get(name.as_str()) {
                notes.push(format!("shadowed by {winner}"));
            } else {
                if let Some(occ) = occurrences.get(name.as_str()) {
                    if let Some((_, t)) = occ.iter().find(|(j, _)| *j > i) {
                        notes.push(format!("shadows {t}"));
                    }
                }
                seen.insert(name.clone(), tier);
            }
            if notes.is_empty() {
                println!("  {name}  ({kind})");
            } else {
                println!("  {name}  ({kind})  [{}]", notes.join(", "));
            }
        }
    }
    !blocks.is_empty()
}

/// The `key_id` a settled artefact is signed with, parsed without verification (display only).
fn settled_key_id(settled: &Path) -> Option<String> {
    let bytes = std::fs::read(settled).ok()?;
    let doc = kennel_lib_policy::parse_signed_settled_unverified(&bytes).ok()?;
    Some(doc.signature.key_id)
}

/// Classify a `policy.toml` as a `template` (has `template_name`) or `leaf` (has `name`),
/// by a cheap parse. Unparseable or ambiguous files report `source`.
#[must_use]
pub fn policy_kind(path: &Path) -> &'static str {
    let Ok(bytes) = std::fs::read(path) else {
        return "source";
    };
    // One `SourcePolicy` type carries all three roles, told apart by identity: a `template_name` is a
    // template; a `name` + `template_base` is a runnable leaf; a `name` with no `template_base` is a
    // composable fragment (additive-only, included by reference).
    let Ok(p) = kennel_lib_compile::parse_source(&bytes) else {
        return "source";
    };
    if p.template_name.is_some() {
        "template"
    } else if p.name.is_some() {
        let anchored_to_chain = p
            .template_base
            .as_deref()
            .is_some_and(|b| !b.starts_with("base-confined@"));
        if p.template_base.is_none() && p.is_additive_only() && !anchored_to_chain {
            "fragment"
        } else {
            "leaf"
        }
    } else {
        "source"
    }
}

/// `kennel policy show <policy>` — resolve a policy and print what it actually means.
///
/// Compiles a source policy in memory (or reads a settled artefact) and prints the
/// effective policy in human-readable form: the network posture (mode + whether an
/// egress proxy stands up), filesystem grants, the exec allowlist, the embedded
/// workload, and the TTL. This is the tool to catch "the template says X but resolves
/// to Y" — e.g. a `mode = open` policy that still carries a proxy listener.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no policy is given, the policy
/// cannot be resolved or read, the trust store cannot be loaded, or the policy fails
/// to compile (source form) or verify (settled form).
pub fn policy_show(args: &[String]) -> Result<ExitCode, String> {
    let (policy_arg, template_dirs, trust_dirs) = parse_show_args(args, POLICY_VERBS)?;
    let policy_file = match resolve_policy(&policy_arg, false) {
        Ok((file, _name)) => file,
        // Cross-house courtesy: a template name misses the policies cascade; say what it is.
        Err(e) => match resolve_template(&policy_arg) {
            Ok(_) => {
                return Err(format!(
                    "`{policy_arg}` is a template — the shared-base house; show it with \
                     `kennel template show {policy_arg}`"
                ));
            }
            Err(_) => return Err(e),
        },
    };
    // Origin provenance (W3): which tier's object is being shown, so "which claude" is
    // answered here and not by ls-ing three trees.
    eprintln!(
        "kennel: `{policy_arg}` from the {} tier ({})",
        crate::tier_of_path(&policy_file),
        policy_file.display()
    );
    show_file(&policy_file, template_dirs, trust_dirs)
}

/// `kennel template show <template>` — resolve a template and print its effective floor.
///
/// The same renderer as `policy show`, entered through the template cascade: the fold is the
/// template's own chain + includes, so the output is the floor a deriving leaf inherits.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no template is given, the name does not
/// resolve in the template cascade (a leaf name points back at `policy show`), the trust
/// store cannot be loaded, or the template fails to compile.
pub fn template_show(args: &[String]) -> Result<ExitCode, String> {
    let (template_arg, template_dirs, trust_dirs) = parse_show_args(args, crate::TEMPLATE_VERBS)?;
    let template_file = match resolve_template(&template_arg) {
        Ok((file, _name)) => file,
        // Cross-house courtesy: a leaf/policy name misses the template cascade; say what it is.
        Err(e) => match resolve_policy(&template_arg, false) {
            Ok(_) => {
                return Err(format!(
                    "`{template_arg}` is a policy, not a template — show it with \
                     `kennel policy show {template_arg}`"
                ));
            }
            Err(_) => return Err(e),
        },
    };
    eprintln!(
        "kennel: `{template_arg}` from the {} tier ({})",
        crate::tier_of_path(&template_file),
        template_file.display()
    );
    show_file(&template_file, template_dirs, trust_dirs)
}

/// Parse the `show` argv shape shared by both houses: one positional plus repeatable
/// `--template-dir`/`--trust-dir`. The `table` names the house for usage/unknown-flag errors.
fn parse_show_args(
    args: &[String],
    table: &[kennel_lib_cli::CommandSpec],
) -> Result<(String, Vec<PathBuf>, Vec<PathBuf>), String> {
    let mut positional: Option<String> = None;
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
            lexopt::Arg::Value(v) if positional.is_none() => {
                positional = Some(v.to_string_lossy().into_owned());
            }
            other => return Err(lexopt_unexpected(&other, table, "show")),
        }
    }
    let positional = positional.ok_or_else(|| usage_of(table, "show"))?;
    Ok((positional, template_dirs, trust_dirs))
}

/// The shared `show` body: read `policy_file`, compile (source) or verify (settled), render.
fn show_file(
    policy_file: &Path,
    mut template_dirs: Vec<PathBuf>,
    mut trust_dirs: Vec<PathBuf>,
) -> Result<ExitCode, String> {
    let bytes = std::fs::read(policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;

    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let policy = if is_source_policy(&bytes) {
        let source = FsTemplateSource {
            dirs: template_dirs,
        };
        let tc = TrustContext::load(&trust_dirs)?;
        let trust = tc.allow_unsigned();
        let mut compiled = build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
            .map_err(|e| format!("compiling {}: {e}", policy_file.display()))?;
        print_warnings(&compiled.warnings);
        print_warnings(&kennel_lib_policy::resolve_settled_loaders(
            &mut compiled.policy,
        ));
        compiled.policy
    } else {
        let tc = TrustContext::load(&trust_dirs)?;
        kennel_lib_policy::verify_settled(&bytes, tc.keys())
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
///
/// # Errors
///
/// Returns a message if the arguments are invalid, the name is not a valid policy name,
/// the policy cannot be resolved, the copy-on-write into the user config fails, the
/// editor cannot be launched, or the editor exits non-zero.
pub fn policy_edit(args: &[String]) -> Result<ExitCode, String> {
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
/// `--from` (default `base-confined`), with a commented `[workload]` stub to fill in.
/// Refuses to overwrite an existing policy. Prints next steps (`policy show`/`compile`).
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no name is given, the name is not a
/// valid policy name, `--from` is not a valid template name, a policy of that name
/// already exists, or the scaffold directory or file cannot be written.
pub fn policy_generate(args: &[String]) -> Result<ExitCode, String> {
    let mut name: Option<String> = None;
    let mut from = "base-confined".to_owned();
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
    // `--from` is the leaf's `template_base`: a bare template name (versioned references were
    // removed). Validate it with the compiler's own rule so a scaffold can never carry a
    // `template_base` that `kennel policy compile` would then reject as malformed.
    kennel_lib_compile::source::validate_reference(&from)
        .map_err(|d| format!("--from `{from}` is not a valid template name: {d}"))?;
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

/// `kennel template lint` — check the templates in the search path for incoherences.
///
/// Compiles every `<name>/policy.toml` found in the template cascade (in memory, dev trust)
/// and runs `lint_settled` on the resolved policy, reporting any finding — settings that
/// contradict the resolved net mode, or grants the mode makes vacuous. Exit 0 if all clean,
/// 7 if any template lints with a finding (a CI-friendly distinct code).
///
/// # Errors
///
/// Returns a message if the arguments are invalid or the trust store cannot be loaded.
/// A template that fails to compile is reported and counted, not returned as an error.
pub fn template_lint(args: &[String]) -> Result<ExitCode, String> {
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
            other => return Err(lexopt_unexpected(&other, crate::TEMPLATE_VERBS, "lint")),
        }
    }
    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let tc = TrustContext::load(&trust_dirs)?;
    let trust = tc.allow_unsigned();
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
        let Some(bytes) = source.fetch(name) else {
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
/// Sign a source **template or fragment** — a shared base other policies inherit — with a key.
///
/// **Appends** a `[signature]` block to the file so its comments are preserved (the
/// signature covers the canonical re-serialisation, not the raw bytes). Prints the
/// public key to install in the trust store as `<key_id>.pub`.
///
/// This is NOT how a leaf policy is signed: a leaf is signed when it is compiled
/// (`kennel policy compile`), so a leaf handed here is refused with a pointer to `compile`.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no template or `--key` is given, the
/// argument is a leaf policy (not a template), the file cannot be read, the key cannot be
/// loaded, the file already carries a `[signature]`, the file is not a signable source
/// template or fragment, signing fails, or the output cannot be written.
pub fn template_sign(args: &[String]) -> Result<ExitCode, String> {
    let mut path: Option<&str> = None;
    let mut key_path: Option<&str> = None;
    let mut key_id: Option<&str> = None;
    let mut output: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--key-id" => key_id = Some(it.next().ok_or("--key-id needs a value")?),
            "--output" => output = Some(it.next().ok_or("--output needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            value if path.is_none() => path = Some(value),
            _ => return Err("only one <template> may be given".to_owned()),
        }
    }
    let path_arg = path.ok_or(
        "usage: kennel template sign <template> --key <key> [--key-id <id>] [--output <path>]",
    )?;
    // Resolve the template by NAME from the template cascade (user ~/.config/kennel/templates
    // first), or take a path — the same smart resolution `compile` gives a policy.
    let (path, _tname) = resolve_template(path_arg)?;

    let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    // A template (`[fs] read = [...]`) and a composable fragment (`[[fs.read.add]]`) are the one
    // `SourcePolicy` type, so this covers both through a single parse (Kennel book Vol 2, templates).
    // We need the canonical bytes the signature covers, which the signer then signs.
    let policy = kennel_lib_compile::parse_source(&bytes).map_err(|e| {
        format!(
            "{} is not a signable source template/fragment ({e})",
            path.display()
        )
    })?;
    // A leaf is not signed here — it is signed when compiled. Point the way (BEFORE demanding a key)
    // rather than append a meaningless source signature to a policy only ever run as a settled artefact.
    if policy.is_leaf() {
        return Err(format!(
            "{} is a leaf policy, not a template — sign it by compiling it: \
             `kennel policy compile {} --key <key>`",
            path.display(),
            policy.name.as_deref().unwrap_or(path_arg)
        ));
    }
    let key_arg = key_path.ok_or("template sign needs --key <name-or-path>")?;
    let key_path = resolve_key_arg(key_arg)?;
    if policy.signature.is_some() {
        return Err(format!(
            "{} already carries a [signature]; remove it before re-signing",
            path.display()
        ));
    }
    let payload =
        kennel_lib_compile::canonical_source(&policy).map_err(|e| format!("signing: {e}"))?;

    // Templates are the security baseline: only a system/vendor key may sign one, so
    // the `key_id` resolves against the system trust dirs — never the user's keys. The
    // private key itself may live in `~/.ssh`, an agent, or a token (ssh-keygen).
    let mut trust_dirs = Vec::new();
    add_system_trust_dirs(&mut trust_dirs);
    let (key_id, armor) = sshsig_sign(&payload, &key_path.to_string_lossy(), key_id, &trust_dirs)?;

    // Append the signature as a new top-level table, preserving the original text. The
    // multi-line SSHSIG armor is stored as a single-line basic string with escaped
    // newlines (what the serde serialiser would emit for the settled artefact too).
    let escaped = armor.replace('\\', "\\\\").replace('\n', "\\n");
    let block = format!(
        "\n[signature]\nalgorithm = \"sshsig\"\nkey_id = \"{key_id}\"\nsignature = \"{escaped}\"\n"
    );
    let mut out_bytes = bytes;
    out_bytes.extend_from_slice(block.as_bytes());
    let out = output.unwrap_or(path);
    std::fs::write(&out, &out_bytes).map_err(|e| format!("writing {}: {e}", out.display()))?;

    eprintln!("signed {} with key `{key_id}`", out.display());
    Ok(ExitCode::SUCCESS)
}

// ---- `kennel policy inspect` ---------------------------------------------------

/// `kennel policy inspect <policy> --unix [--template-dir D]... [--trust-dir D]...`
///
/// Load a settled (or compilable source) policy and render its grants.
/// Currently supports `--unix` (`AF_UNIX` socket grants, §7.6).
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no policy is given, no grant filter
/// (`--unix`) is selected, the policy cannot be resolved or read, the trust store
/// cannot be loaded, or the policy fails to compile (source form) or verify (settled
/// form).
pub fn policy_inspect(args: &[String]) -> Result<ExitCode, String> {
    let mut policy_arg: Option<String> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut show_unix = false;
    let mut p = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = p.next().map_err(|e| e.to_string())? {
        match arg {
            lexopt::Arg::Long("unix") => show_unix = true,
            lexopt::Arg::Long("template-dir") => {
                template_dirs.push(lexopt_value(&mut p, "--template-dir")?);
            }
            lexopt::Arg::Long("trust-dir") => {
                trust_dirs.push(lexopt_value(&mut p, "--trust-dir")?);
            }
            lexopt::Arg::Value(v) if policy_arg.is_none() => {
                policy_arg = Some(v.to_string_lossy().into_owned());
            }
            other => return Err(lexopt_unexpected(&other, POLICY_VERBS, "inspect")),
        }
    }
    let policy_arg = policy_arg.ok_or_else(|| usage_of(POLICY_VERBS, "inspect"))?;
    if !show_unix {
        return Err("no grant filter specified — use --unix to inspect AF_UNIX grants".to_owned());
    }

    let (policy_file, _name) = resolve_policy(&policy_arg, true)?;
    let bytes = std::fs::read(&policy_file)
        .map_err(|e| format!("reading {}: {e}", policy_file.display()))?;

    add_default_template_dirs(&mut template_dirs);
    add_system_trust_dirs(&mut trust_dirs);
    let policy = if is_source_policy(&bytes) {
        let source = FsTemplateSource {
            dirs: template_dirs,
        };
        let tc = TrustContext::load(&trust_dirs)?;
        let trust = tc.allow_unsigned();
        let compiled = build_settled(&bytes, &source, &trust, env!("CARGO_PKG_VERSION"))
            .map_err(|e| format!("compiling {}: {e}", policy_file.display()))?;
        compiled.policy
    } else {
        let tc = TrustContext::load(&trust_dirs)?;
        kennel_lib_policy::verify_settled(&bytes, tc.keys())
            .map_err(|e| format!("verifying {}: {e}", policy_file.display()))?
    };

    if show_unix {
        print_unix_grants(&policy);
    }
    Ok(ExitCode::SUCCESS)
}

/// Render the `AF_UNIX` grants from a settled policy's `UnixRuntime` (§7.6).
fn print_unix_grants(policy: &kennel_lib_policy::SettledPolicy) {
    let unix = &policy.unix;
    if unix.is_empty() {
        println!("no AF_UNIX grants");
        return;
    }
    println!(
        "AF_UNIX grants ({} socket{}):\n",
        unix.sockets.len(),
        if unix.sockets.len() == 1 { "" } else { "s" },
    );
    for sock in &unix.sockets {
        println!("  {}", sock.name);
        println!("    real:  {}", sock.real);
        println!("    shim:  {}", sock.shim);
        if let Some(env) = &sock.env {
            println!("    env:   {env}");
        }
        println!();
    }
}

// ---- `kennel policy|template install` + `clone` (the W3 ceremonies) ------------

/// Which house an `install`/`clone` ceremony was invoked from; each refuses the
/// other's material with a pointer across.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum House {
    /// `kennel policy …` — leaves and fragments-as-policy-material.
    Policy,
    /// `kennel template …` — shared bases (templates and fragments).
    Template,
}

impl House {
    const fn noun(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Template => "template",
        }
    }
    const fn repo_leaf(self) -> &'static str {
        match self {
            Self::Policy => "policies",
            Self::Template => "templates",
        }
    }
}

/// The reserved-namespace pre-flight the ceremonies run: every `[[provides]]` name in
/// `source` must be claimable at `declaring` tier, per the compiler's own rule
/// ([`kennel_lib_compile::mesh::ReservedAuthority::required_tier`] — one implementation,
/// never a hand-copied list). Returns the offending names.
fn reserved_violations(
    source: &kennel_lib_compile::SourcePolicy,
    declaring: kennel_lib_compile::source_sig::Tier,
) -> Vec<String> {
    let deployment = kennel_lib_config::Deployment::load()
        .unwrap_or_else(|_| kennel_lib_config::Deployment::defaults());
    let authority = kennel_lib_compile::mesh::ReservedAuthority {
        enforce: true,
        declaring_tier: Some(declaring),
        reserved: deployment.reserved(),
    };
    source
        .provides
        .iter()
        .filter_map(|p| {
            let name = p.name.as_str();
            authority
                .required_tier(name)
                .is_some_and(|req| req > declaring)
                .then(|| name.to_owned())
        })
        .collect()
}

/// `kennel policy install <file.toml> [--host] [--force] [--key K]`.
///
/// # Errors
///
/// See [`install_object`].
pub fn policy_install(args: &[String]) -> Result<ExitCode, String> {
    install_object(args, House::Policy)
}

/// `kennel template install <file.toml> [--host] [--force] [--key K]`.
///
/// # Errors
///
/// See [`install_object`].
pub fn template_install(args: &[String]) -> Result<ExitCode, String> {
    install_object(args, House::Template)
}

/// The install ceremony: classify, gate, place, and sign a source `.toml` at the invoking
/// tier — receive → install → run, one verb.
///
/// The whole object must be signable at the destination tier: a `[[provides]]` name in a
/// reserved family refuses at user tier (and `org.projectkennel.*` refuses at every install
/// level — the vendor tier is package payload, never an install target). The check is a
/// courtesy pre-flight of the compiler's own gate, never the enforcement (W9).
///
/// # Errors
///
/// Returns a message on: bad arguments; a settled artefact (a higher-tier signature just
/// works when copied — install signs SOURCE); the other house's material; a reserved
/// `[[provides]]` claim the tier cannot sign; `--host` without root or without the host
/// key; a name collision without `--force`; or a placement/signing failure.
#[allow(clippy::too_many_lines)]
fn install_object(args: &[String], house: House) -> Result<ExitCode, String> {
    use kennel_lib_compile::source_sig::Tier;
    let mut file: Option<&str> = None;
    let mut host = false;
    let mut force = false;
    let mut key: Option<&str> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--host" => host = true,
            "--force" => force = true,
            "--key" => key = Some(it.next().ok_or("--key needs a value")?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if file.is_none() => file = Some(v),
            _ => return Err("only one <file.toml> may be given".to_owned()),
        }
    }
    let file = file.ok_or_else(|| {
        format!(
            "usage: kennel {} install <file.toml> [--host] [--force] [--key K]",
            house.noun()
        )
    })?;
    let bytes = std::fs::read(file).map_err(|e| format!("reading {file}: {e}"))?;

    // A settled artefact is not install material: acceptance is downward-inclusive, so a
    // vendor-/host-signed artefact just works wherever it is placed — plain `cp` it. The
    // ceremony exists to sign SOURCE at this tier. "Actually settled" and "malformed
    // source" are distinguished, so a typo gets the parser's real diagnostic, not the
    // copy note.
    if kennel_lib_policy::parse_signed_settled_unverified(&bytes).is_ok() {
        return Err(format!(
            "{file} is a compiled (settled) artefact, not source. A higher-tier-signed \
             artefact verifies wherever it is placed — copy it into a `policies/` repo \
             directly. `install` places and signs SOURCE at your tier"
        ));
    }
    let source = kennel_lib_compile::parse_source(&bytes)
        .map_err(|e| format!("{file} is not a source policy/template: {e}"))?;

    // Classify + cross-house refusal: the object's identity says which house owns it.
    let is_template = source.template_name.is_some();
    match (house, is_template) {
        (House::Policy, true) => {
            return Err(format!(
                "{file} is a template (a shared base) — install it with `kennel template \
                 install {file}`"
            ));
        }
        (House::Template, false) if source.is_leaf() => {
            return Err(format!(
                "{file} is a leaf policy — install it with `kennel policy install {file}`"
            ));
        }
        _ => {}
    }
    let name = source
        .template_name
        .clone()
        .or_else(|| source.name.clone())
        .ok_or_else(|| format!("{file} has no `name`/`template_name`"))?;
    if !crate::is_valid_policy_name(&name) {
        return Err(format!("`{name}` is not a valid object name"));
    }

    // Tier + authority gate, the ceremony half (the compiler re-enforces at compile).
    let tier = if host { Tier::Host } else { Tier::User };
    let violations = reserved_violations(&source, tier);
    if !violations.is_empty() {
        let at = if host { "host" } else { "user" };
        return Err(format!(
            "{file} carries reserved [[provides]] claims a {at}-tier key cannot sign \
             ({}) — reserved names belong to the tier that owns them; derive from the \
             signed base instead (`kennel policy generate --from <template>`)",
            violations.join(", ")
        ));
    }
    if host && kennel_lib_syscall::unistd::effective_uid() != 0 {
        return Err("`--host` installs into /etc/kennel and needs root".to_owned());
    }

    // Destination: the tier's canonical layout. Collision refuses (an admin edit is never
    // silently clobbered); --force replaces.
    let repo_root = if host {
        PathBuf::from("/etc/kennel").join(house.repo_leaf())
    } else {
        // The user config root, derived from the pub key-dir accessor (its parent).
        kennel_lib_config::user_key_dir()
            .as_deref()
            .and_then(Path::parent)
            .map(|d| d.join(house.repo_leaf()))
            .ok_or("cannot resolve ~/.config/kennel (HOME unset)")?
    };
    let dest_dir = repo_root.join(&name);
    let created_fresh = !dest_dir.exists();
    if !created_fresh && !force {
        return Err(format!(
            "`{name}` already exists at {} — pass --force to replace it",
            dest_dir.display()
        ));
    }
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("creating {}: {e}", dest_dir.display()))?;
    let placed = dest_dir.join("policy.toml");
    std::fs::write(&placed, &bytes).map_err(|e| format!("writing {}: {e}", placed.display()))?;

    // Sign at the tier's level: a leaf compiles (which signs), a template/fragment is
    // source-signed. The host tier's key is the installer-provisioned `kennel-host`.
    let tier_key: String = match key {
        Some(k) => k.to_owned(),
        None if host => {
            let deployment = kennel_lib_config::Deployment::load()
                .unwrap_or_else(|_| kennel_lib_config::Deployment::defaults());
            let host_key = deployment.trust_dir().join("kennel-host");
            if !host_key.is_file() {
                return Err(format!(
                    "no host signing key at {} (install.sh provisions it); pass --key",
                    host_key.display()
                ));
            }
            host_key.to_string_lossy().into_owned()
        }
        None => crate::default_signing_key()?.to_string_lossy().into_owned(),
    };
    let sign_args = [
        placed.to_string_lossy().into_owned(),
        "--key".to_owned(),
        tier_key,
    ];
    let result = if is_template || !source.is_leaf() {
        template_sign(&sign_args)
    } else {
        compile(&sign_args)
    };
    // The ceremony is place+sign, atomically from the operator's view: a failed sign must
    // not leave a half-installed object (source with no artefact) in the repo.
    let rollback = |result: &str| {
        if created_fresh {
            let _ = std::fs::remove_dir_all(&dest_dir);
            eprintln!(
                "kennel: install rolled back ({result}); {} removed",
                dest_dir.display()
            );
        } else {
            eprintln!(
                "kennel: {result}; `{name}` at {} was replaced but not re-signed — fix and \
                 re-run install",
                dest_dir.display()
            );
        }
    };
    match result {
        Ok(code) if code == ExitCode::SUCCESS => {}
        Ok(code) => {
            rollback("the sign step failed");
            return Ok(code); // the sign/compile step's own diagnostic already printed
        }
        Err(e) => {
            rollback("the sign step failed");
            return Err(e);
        }
    }

    let tier_word = if host { "host" } else { "user" };
    eprintln!(
        "kennel: installed `{name}` at the {tier_word} tier ({})",
        dest_dir.display()
    );
    if is_template || !source.is_leaf() {
        eprintln!("  next: derive a leaf from it — `kennel policy generate --from {name}`");
    } else {
        eprintln!("  next: `kennel run {name}`");
    }
    Ok(ExitCode::SUCCESS)
}

/// `kennel policy clone <name> [<new-name>] [--key K]`.
///
/// # Errors
///
/// See [`clone_object`].
pub fn policy_clone(args: &[String]) -> Result<ExitCode, String> {
    clone_object(args, House::Policy)
}

/// `kennel template clone <name> [<new-name>] [--key K]`.
///
/// # Errors
///
/// See [`clone_object`].
pub fn template_clone(args: &[String]) -> Result<ExitCode, String> {
    clone_object(args, House::Template)
}

/// The clone ceremony: fork a higher-tier object into the user house — your copy, your
/// name, your key, no inherited floor (vs `generate --from`, which *derives*).
///
/// Copies **source form only** (a settled artefact is a derived object carrying the old
/// authority's signature; a lock likewise). The authority gate is content-total and renaming
/// is no escape: an object whose `[[provides]]` claims a reserved family is not clonable to
/// user space at all — the claim lives in the content, and a user key cannot re-sign it
/// under any name. Default keeps the name (the user copy shadows the original, user-first);
/// the optional second argument clones to a different name.
///
/// # Errors
///
/// Returns a message on: bad arguments; a name that does not resolve to SOURCE in this
/// house's cascade (a settled-only entry names where the source lives); a reserved
/// `[[provides]]` claim; a user-house collision; or a placement/signing failure.
fn clone_object(args: &[String], house: House) -> Result<ExitCode, String> {
    use kennel_lib_compile::source_sig::Tier;
    let mut src_arg: Option<&str> = None;
    let mut new_name: Option<&str> = None;
    let mut key: Option<&str> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key = Some(it.next().ok_or("--key needs a value")?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if src_arg.is_none() => src_arg = Some(v),
            v if new_name.is_none() => new_name = Some(v),
            _ => return Err("at most <name> and <new-name> may be given".to_owned()),
        }
    }
    let src_arg = src_arg.ok_or_else(|| {
        format!(
            "usage: kennel {} clone <name> [<new-name>] [--key K]",
            house.noun()
        )
    })?;
    if src_arg.contains('/') {
        return Err(format!(
            "`clone` takes an object NAME from the {} cascade, not a path — `install` places \
             a file you already hold",
            house.repo_leaf()
        ));
    }

    // Resolve SOURCE form across this house's cascade (a settled-only tier is skipped: its
    // artefact is derived; the source is the clonable thing, wherever it ships).
    let (src_file, src_tier) = match house {
        House::Template => {
            let (f, _) = resolve_template(src_arg)?;
            let t = crate::tier_of_path(&f);
            (f, t)
        }
        House::Policy => resolve_clonable_policy_source(src_arg)?,
    };
    let bytes =
        std::fs::read(&src_file).map_err(|e| format!("reading {}: {e}", src_file.display()))?;
    let source = kennel_lib_compile::parse_source(&bytes)
        .map_err(|e| format!("{} is not clonable source ({e})", src_file.display()))?;

    // The content-total authority gate: renaming is no escape.
    let violations = reserved_violations(&source, Tier::User);
    if !violations.is_empty() {
        return Err(format!(
            "`{src_arg}` carries reserved [[provides]] claims ({}) — the claim lives in the \
             content, and a user key cannot re-sign it under any name. Not clonable; derive \
             from it where it stands instead: `kennel policy generate --from {src_arg}`",
            violations.join(", ")
        ));
    }

    // The clone's name: default keeps it (the copy shadows the original user-first).
    let target = new_name.unwrap_or(src_arg);
    if !crate::is_valid_policy_name(target) {
        return Err(format!("`{target}` is not a valid object name"));
    }
    let renamed = if target == src_arg {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        rename_source_object(&bytes, target)?
    };

    // Compose on the install backend at user tier: stage the (possibly renamed) source to a
    // temp file, then run the same place+sign ceremony.
    let staging =
        std::env::temp_dir().join(format!("kennel-clone-{target}-{}.toml", std::process::id()));
    std::fs::write(&staging, renamed.as_bytes()).map_err(|e| format!("staging the clone: {e}"))?;
    let mut install_args: Vec<String> = vec![staging.to_string_lossy().into_owned()];
    if let Some(k) = key {
        install_args.extend(["--key".to_owned(), k.to_owned()]);
    }
    let result = install_object(&install_args, house);
    let _ = std::fs::remove_file(&staging);
    result?;

    if src_tier != "user" && target == src_arg {
        eprintln!(
            "  note: your clone shadows the {src_tier} `{src_arg}` for your user \
             (resolution is user-first; `kennel {} list` marks it)",
            house.noun()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Rewrite the top-level `name`/`template_name` line to `target`, preserving every other
/// byte (comments included). Exactly one identity line must match.
fn rename_source_object(bytes: &[u8], target: &str) -> Result<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut replaced = false;
    let out: Vec<String> = text
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if !replaced
                && (trimmed.starts_with("name =") || trimmed.starts_with("template_name ="))
            {
                replaced = true;
                let field = if trimmed.starts_with("template_name") {
                    "template_name"
                } else {
                    "name"
                };
                format!("{field} = \"{target}\"")
            } else {
                line.to_owned()
            }
        })
        .collect();
    if !replaced {
        return Err("no top-level `name`/`template_name` line to rename".to_owned());
    }
    Ok(out.join("\n") + "\n")
}

/// Walk the policies cascade for `name`'s SOURCE (`<dir>/<name>/policy.toml`), skipping
/// settled-only tiers — the clone resolver. Returns the source path and its tier.
///
/// # Errors
///
/// Returns a message when no tier ships source: naming the settled-only artefact if one
/// exists (derived, not clonable), else the plain not-found with the `list` pointer.
fn resolve_clonable_policy_source(name: &str) -> Result<(PathBuf, &'static str), String> {
    let user = kennel_lib_config::User::load().unwrap_or_default();
    let mut settled_hit: Option<PathBuf> = None;
    for dir in user.policy_dirs() {
        let base = dir.join(name);
        let src = base.join("policy.toml");
        if src.is_file() {
            let tier = crate::tier_of_path(&src);
            return Ok((src, tier));
        }
        let settled = base.join(format!("{name}.settled.toml"));
        if settled_hit.is_none() && settled.is_file() {
            settled_hit = Some(settled);
        }
    }
    settled_hit.map_or_else(
        || {
            Err(format!(
                "no policy named `{name}` in the policies cascade (`kennel policy list` shows \
                 what is there)"
            ))
        },
        |s| {
            Err(format!(
                "`{name}` exists only as compiled artefacts (e.g. {}) — a settled artefact is \
                 derived, not clonable source, and no tier in the cascade ships this policy's \
                 source",
                s.display()
            ))
        },
    )
}
