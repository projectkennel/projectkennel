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
    is_valid_policy_name, lexopt_unexpected, lexopt_value, policy_error_code, resolve_policy,
    settled_with_sshsig, signing_trust_dirs, sshsig_sign, usage_of, TrustContext, POLICY_VERBS,
};

// ---- `kennel compile` ----------------------------------------------------------

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

/// `kennel compile <policy> [--output P] [--key K] [--unsigned] [--template-dir D]...`
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
        "usage: kennel compile <policy> [--output P] [--key K | --unsigned] [--template-dir D]...",
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
            Some(p) => p.to_owned(),
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

/// `kennel validate <policy> [--template-dir D] [--require-signed] [--trust-dir D]`
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
        .ok_or("usage: kennel validate <policy> [--template-dir D] [--require-signed]")?;
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
///
/// # Errors
///
/// Returns a usage message if any arguments are given (the verb takes none).
pub fn policy_list(args: &[String]) -> Result<ExitCode, String> {
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
/// valid policy name, `--from` is not a versioned reference, a policy of that name
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
    // `--from` must be a `<template>@v<ver>` reference (the leaf's template_base).
    if !from.contains('@') {
        return Err(format!(
            "--from `{from}` must be a versioned reference, e.g. `base-confined`"
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
///
/// # Errors
///
/// Returns a message if the arguments are invalid or the trust store cannot be loaded.
/// A template that fails to compile is reported and counted, not returned as an error.
pub fn policy_lint(args: &[String]) -> Result<ExitCode, String> {
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
/// Sign a source template/fragment with an ed25519 key.
///
/// **Appends** a `[signature]` block to the file so its comments are preserved (the
/// signature covers the canonical re-serialisation, not the raw bytes). Prints the
/// public key to install in the trust store as `<key_id>.pub`. Leaf policies may stay
/// unsigned.
///
/// # Errors
///
/// Returns a message if the arguments are invalid, no template or `--key` is given, the
/// file cannot be read, the key cannot be loaded, the file already carries a
/// `[signature]`, the file is not a signable source template or fragment, signing
/// fails, or the output cannot be written.
pub fn sign(args: &[String]) -> Result<ExitCode, String> {
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
    let path =
        path.ok_or("usage: kennel sign <template> --key <key> [--key-id <id>] [--output <path>]")?;
    let key_path = key_path.ok_or("sign needs --key <path>")?;

    let bytes = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    // A template (`[fs] read = [...]`) and a composable fragment (`[[fs.read.add]]`) are the one
    // `SourcePolicy` type, so `policy sign` covers both through a single parse (05-templates §5.10).
    // We need the canonical bytes the signature covers, which the signer then signs.
    let policy = kennel_lib_compile::parse_source(&bytes)
        .map_err(|e| format!("{path} is not a signable source template/fragment ({e})"))?;
    if policy.signature.is_some() {
        return Err(format!(
            "{path} already carries a [signature]; remove it before re-signing"
        ));
    }
    let payload =
        kennel_lib_compile::canonical_source(&policy).map_err(|e| format!("signing: {e}"))?;

    // Templates are the security baseline: only a system/vendor key may sign one, so
    // the `key_id` resolves against the system trust dirs — never the user's keys. The
    // private key itself may live in `~/.ssh`, an agent, or a token (ssh-keygen).
    let mut trust_dirs = Vec::new();
    add_system_trust_dirs(&mut trust_dirs);
    let (key_id, armor) = sshsig_sign(&payload, key_path, key_id, &trust_dirs)?;

    // Append the signature as a new top-level table, preserving the original text. The
    // multi-line SSHSIG armor is stored as a single-line basic string with escaped
    // newlines (what the serde serialiser would emit for the settled artefact too).
    let escaped = armor.replace('\\', "\\\\").replace('\n', "\\n");
    let block = format!(
        "\n[signature]\nalgorithm = \"sshsig\"\nkey_id = \"{key_id}\"\nsignature = \"{escaped}\"\n"
    );
    let mut out_bytes = bytes;
    out_bytes.extend_from_slice(block.as_bytes());
    let out = output.unwrap_or_else(|| PathBuf::from(path));
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
