//! Shared helpers for all host-side CLI binaries.
//!
//! Daemon connection, key loading, policy/template/trust-store resolution,
//! exit-code mapping, lexopt helpers, and the command tables.

use std::collections::BTreeSet;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// The command tables live with the surface grammar in `kennel-lib-cli` (one
// definition for dispatch, `--help`, and the generated man pages); re-exported
// so the verb modules keep addressing them through `shared`.
use kennel_lib_cli::{render_commands, CommandSpec};
pub use kennel_lib_cli::{COMMANDS, POLICY_VERBS};
use kennel_lib_control::control::{self, Request};
use kennel_lib_control::socket;

// ─── Help rendering ──────────────────────────────────────────────────────────

/// Render the top-level help (the command list) to stdout.
pub fn print_help() {
    println!("usage: kennel <command> [args...]\n\ncommands:");
    print!("{}", render_commands(COMMANDS));
    println!("\nrun `kennel <command> --help` for a command's usage.");
}

/// Render `kennel policy` help (its sub-verb list) to stdout.
pub fn print_policy_help() {
    println!("usage: kennel policy <verb> [args...]\n\nverbs:");
    print!("{}", render_commands(POLICY_VERBS));
}

/// Whether `args` contains a help request (`--help`/`-h`).
#[must_use]
pub fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// The usage line for `verb` from a spec table, as a `kennel …` error string.
#[must_use]
pub fn usage_of(table: &[CommandSpec], verb: &str) -> String {
    table.iter().find(|c| c.name == verb).map_or_else(
        || format!("unknown command `{verb}` — run `kennel --help`"),
        |c| format!("usage: kennel {}", c.usage),
    )
}

// ─── Daemon connection ───────────────────────────────────────────────────────

/// Connect to the daemon's control socket and run the version handshake.
///
/// # Errors
///
/// Returns a message if the control socket cannot be reached or the version
/// handshake with the daemon fails.
pub fn connect() -> Result<UnixStream, String> {
    let path = socket::socket_path();
    let mut conn = UnixStream::connect(&path).map_err(|e| {
        format!(
            "cannot reach kenneld at {} ({e}); is the kenneld.socket user unit enabled?",
            path.display()
        )
    })?;
    control::client_handshake(
        &mut conn,
        kennel_lib_policy::SETTLED_SCHEMA_VERSION,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Send `request` (with any `fds`) as one framed `SCM_RIGHTS` message.
///
/// # Errors
///
/// Returns a message if encoding the request frame fails or the `SCM_RIGHTS`
/// send on the socket fails.
pub fn send(conn: &UnixStream, request: &Request, fds: &[BorrowedFd<'_>]) -> Result<(), String> {
    let mut framed = Vec::new();
    control::write_frame(&mut framed, &request.encode())
        .map_err(|e| format!("encoding request: {e}"))?;
    kennel_lib_syscall::scm::send_with_fds(conn.as_fd(), &framed, fds)
        .map_err(|e| format!("sending request: {e}"))?;
    Ok(())
}

/// Map a daemon-reported exit code to a process `ExitCode` (clamped to a byte).
#[must_use]
pub fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

// ─── Lexopt helpers ──────────────────────────────────────────────────────────

/// Read the next required value for `flag` from a lexopt parser.
///
/// # Errors
///
/// Returns a message if `flag` has no following value.
pub fn lexopt_value(p: &mut lexopt::Parser, flag: &str) -> Result<PathBuf, String> {
    p.value()
        .map(PathBuf::from)
        .map_err(|_| format!("{flag} needs a value"))
}

/// Format an unexpected lexopt arg into a usage error for `verb`.
#[must_use]
pub fn lexopt_unexpected(arg: &lexopt::Arg<'_>, table: &[CommandSpec], verb: &str) -> String {
    let what = match arg {
        lexopt::Arg::Long(s) => format!("unknown flag `--{s}`"),
        lexopt::Arg::Short(c) => format!("unknown flag `-{c}`"),
        lexopt::Arg::Value(v) => format!("unexpected argument `{}`", v.to_string_lossy()),
    };
    format!("{what}\n{}", usage_of(table, verb))
}

// ─── Policy resolution ───────────────────────────────────────────────────────

/// Resolve a `<policy>` argument to a file path plus a default kennel/policy name.
///
/// # Errors
///
/// Returns a message if `arg` is neither an existing file nor a valid policy
/// name, or if no matching policy file is found under any policy directory.
pub fn resolve_policy(arg: &str, prefer_settled: bool) -> Result<(PathBuf, String), String> {
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

/// Resolve a `--key` value: a key **name** in the user key dir (where `keygen` puts it), else a path.
///
/// Keys are name-addressed everywhere else — `keygen` writes `<key-id>` by name, the daemon trusts
/// by name — so `--key remco-dev` finds `~/.config/kennel/keys/remco-dev`. Only if no such key
/// exists is the argument treated as a filesystem path (a key held elsewhere: `~/.ssh/id_ed25519`,
/// an agent/token public key).
///
/// # Errors
///
/// Returns a message naming the keys that ARE in the key dir if the argument is neither a key there
/// nor an existing file.
pub fn resolve_key_arg(arg: &str) -> Result<PathBuf, String> {
    // Where `keygen` puts keys: the user key dir, by name. Look here first.
    let in_key_dir = default_key_dir().join(arg);
    if in_key_dir.is_file() {
        return Ok(in_key_dir);
    }
    // Otherwise a filesystem path to a key held elsewhere.
    let literal = PathBuf::from(arg);
    if literal.is_file() {
        return Ok(literal);
    }
    // Neither: name the keys that ARE present, so the fix is obvious.
    let dir = default_key_dir();
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for p in entries.flatten().map(|e| e.path()) {
            if p.extension().and_then(|x| x.to_str()) == Some("pub") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_owned());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    let avail = if names.is_empty() {
        "none — generate one with `kennel keygen <key-id>`".to_owned()
    } else {
        names.join(", ")
    };
    Err(format!(
        "no signing key `{arg}`: not a key in {} and not a file (available: {avail})",
        dir.display()
    ))
}

/// Resolve a template/fragment argument: a **name** in the template cascade (user
/// `~/.config/kennel/templates/<name>` first), else a filesystem path.
///
/// The template counterpart of [`resolve_policy`], so `sign-template base-mine` finds
/// `~/.config/kennel/templates/base-mine/policy.toml` (or `base-mine.toml`) without the caller
/// spelling out the path — mirroring the [`FsTemplateSource`](crate::policy::FsTemplateSource)
/// layout the compiler resolves against.
///
/// # Errors
///
/// Returns a message if the argument is neither an existing file nor a valid name resolving in the
/// template dirs.
pub fn resolve_template(arg: &str) -> Result<(PathBuf, String), String> {
    let literal = Path::new(arg);
    if literal.exists() {
        return Ok((literal.to_path_buf(), policy_name_from_path(literal)));
    }
    if !is_valid_policy_name(arg) {
        return Err(format!(
            "`{arg}` is not an existing file, and not a valid template name (no `/`, `..`, or whitespace)"
        ));
    }
    let mut dirs = Vec::new();
    add_default_template_dirs(&mut dirs);
    for dir in dirs {
        // FsTemplateSource layout: flat `<name>.toml`, then nested `<name>/policy.toml`.
        for candidate in [
            dir.join(format!("{arg}.toml")),
            dir.join(arg).join("policy.toml"),
        ] {
            if candidate.is_file() {
                return Ok((candidate, arg.to_owned()));
            }
        }
    }
    Err(format!(
        "no template named `{arg}` (searched `templates/` under ~/.config/kennel, /etc/kennel, \
         /usr/lib/kennel); pass a path to a template file"
    ))
}

/// Derive a kennel name from a policy file path.
pub fn policy_name_from_path(path: &Path) -> String {
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

/// A policy name is a single safe path component.
pub fn is_valid_policy_name(name: &str) -> bool {
    !name.is_empty()
        && name != ".."
        && !name.contains('/')
        && !name.contains("..")
        && !name.chars().any(char::is_whitespace)
}

/// Default settled-policy path: `<policy-dir>/<name>.settled.toml`.
#[must_use]
pub fn default_settled_path(policy_path: &Path, name: &str) -> PathBuf {
    let dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("{name}.settled.toml"))
}

// ─── Template / trust-store cascade ──────────────────────────────────────────

/// Append the default template search directories.
pub fn add_default_template_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .template_dirs(),
    );
}

/// Append the default template-trust directories (system keys only — no user keys).
pub fn add_system_trust_dirs(dirs: &mut Vec<PathBuf>) {
    dirs.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .system_key_dirs(),
    );
}

/// Whether `text` is the removed legacy key format: bare base64 of 32 raw bytes.
///
/// Both halves of the legacy pair were that shape (`.pub` = public key, `.key` =
/// seed), so one detector serves every refusal diagnostic.
fn is_legacy_raw_b64(text: &str) -> bool {
    kennel_lib_policy::b64::decode(text.trim().as_bytes()).is_some_and(|b| b.len() == 32)
}

/// Load a trust store: every `<key_id>.pub` under each directory.
///
/// Each file must be an OpenSSH public-key line — `ssh-ed25519 <base64-blob>
/// [comment]`, the format `ssh-keygen` and `kennel keygen` write. The key id is
/// the file stem; the comment is informational. The raw-base64 legacy format was
/// removed in 0.6.0; a file still in it is refused with a diagnostic naming the
/// migration.
///
/// # Errors
///
/// Returns a message if a `.pub` file cannot be read, is not an OpenSSH
/// Ed25519 public key, or cannot be inserted into the key set.
pub fn load_trust_store(dirs: &[PathBuf]) -> Result<kennel_lib_policy::KeySet, String> {
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
            if kennel_lib_policy::openssh::is_openssh_public(&contents) {
                let (pubkey_bytes, _comment) =
                    kennel_lib_policy::openssh::parse_public_key(&contents)
                        .map_err(|e| format!("key {}: {e}", path.display()))?;
                keys.insert(key_id, &pubkey_bytes)
                    .map_err(|e| format!("key {}: {e}", path.display()))?;
            } else if is_legacy_raw_b64(&contents) {
                return Err(format!(
                    "key {}: legacy raw-base64 public key (format removed in 0.6.0) — \
                     regenerate with `kennel keygen`, or convert the pair once with \
                     0.5.x's `kennel keygen migrate`",
                    path.display()
                ));
            } else {
                return Err(format!(
                    "key {}: not an OpenSSH ed25519 public key",
                    path.display()
                ));
            }
        }
    }
    Ok(keys)
}

/// The vendor- and host-tier key-id sets for the reserved-namespace gate (§7.13.5).
///
/// A key's tier is *which trust dir loads it* — vendor = `/usr/lib/kennel/keys`, host =
/// `/etc/kennel/keys`. Any key at a tier is equivalent; this maps each tier to the set of key-ids
/// whose `*.pub` sits in its dir.
fn trust_tier_sets() -> (BTreeSet<String>, BTreeSet<String>) {
    fn key_ids_in(dir: &Path) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("pub") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        ids.insert(stem.to_owned());
                    }
                }
            }
        }
        ids
    }
    let vendor_dir = kennel_lib_config::vendor_key_dir();
    let host_dir = kennel_lib_config::User::load()
        .unwrap_or_default()
        .system_key_dirs()
        .into_iter()
        .find(|d| *d != vendor_dir);
    let vendor = key_ids_in(&vendor_dir);
    let host = host_dir.as_deref().map(key_ids_in).unwrap_or_default();
    (vendor, host)
}

/// A loaded, tier-aware trust context (§7.13.5).
///
/// The trust store plus the vendor/host tier sets and the host `[[reserved]]` table the compiler's
/// reserved-namespace gate resolves a declaring tier against. Holds the owned data so a borrowed
/// [`kennel_lib_compile::Trust`] can reference it.
pub struct TrustContext {
    keys: kennel_lib_policy::KeySet,
    vendor: BTreeSet<String>,
    host: BTreeSet<String>,
    reserved: Vec<kennel_lib_config::ReservedNamespace>,
}

impl TrustContext {
    /// Load the trust store from `dirs` and the tier/reserved context from the deployment cascade.
    ///
    /// # Errors
    ///
    /// Returns a message if a `.pub` file under `dirs` cannot be read or parsed.
    pub fn load(dirs: &[PathBuf]) -> Result<Self, String> {
        let keys = load_trust_store(dirs)?;
        let (vendor, host) = trust_tier_sets();
        let reserved = kennel_lib_config::Deployment::load()
            .map(|d| d.reserved().to_vec())
            .unwrap_or_default();
        Ok(Self {
            keys,
            vendor,
            host,
            reserved,
        })
    }

    /// The underlying trust store (for `verify_settled`, which checks a settled signature directly).
    #[must_use]
    pub const fn keys(&self) -> &kennel_lib_policy::KeySet {
        &self.keys
    }

    fn tiered<'a>(&'a self, base: kennel_lib_compile::Trust<'a>) -> kennel_lib_compile::Trust<'a> {
        base.with_tiers(&self.vendor, &self.host)
            .with_reserved(&self.reserved)
    }

    /// A `require`-mode tier-aware trust context (attested: refuse unsigned ancestors).
    #[must_use]
    pub fn require(&self) -> kennel_lib_compile::Trust<'_> {
        self.tiered(kennel_lib_compile::Trust::require(&self.keys))
    }

    /// An `allow_unsigned` tier-aware trust context (development: resolve unsigned ancestors).
    #[must_use]
    pub fn allow_unsigned(&self) -> kennel_lib_compile::Trust<'_> {
        self.tiered(kennel_lib_compile::Trust::allow_unsigned(Some(&self.keys)))
    }
}

// ─── Signing keys ────────────────────────────────────────────────────────────
//
// Signing itself shells out to `ssh-keygen -Y sign` (sshsig_sign below), which
// reads the private key — so a legacy raw-base64 seed already fails there, in
// ssh-keygen's own words. The CLI's only key-file parsing is the trust store
// (`.pub`, above) and the default-key discovery here.

/// The signing key to use when `--key` was omitted.
///
/// The sole OpenSSH private key in the user key dir (no extension, PEM
/// content). Legacy `<id>.key` files (the raw-base64 layout removed in 0.6.0)
/// are never selected; if only those exist, the error names the migration.
///
/// # Errors
///
/// Returns a message if the user key dir contains no signing key, or more than
/// one (the caller must then pass `--key` to disambiguate).
pub fn default_signing_key() -> Result<PathBuf, String> {
    let dir = default_key_dir();
    let mut found: Vec<PathBuf> = Vec::new();
    let mut legacy: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for p in entries.flatten().map(|e| e.path()) {
            if p.extension().and_then(|x| x.to_str()) == Some("key") {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    legacy.push(name.to_owned());
                }
                continue;
            }
            // OpenSSH: files with no extension that are not .pub and are files.
            // Quick content check: must start with the PEM marker.
            if p.extension().is_none()
                && p.is_file()
                && std::fs::read_to_string(&p)
                    .is_ok_and(|head| kennel_lib_policy::openssh::is_openssh_private(&head))
            {
                found.push(p);
            }
        }
    }
    found.sort();
    legacy.sort();
    match found.as_slice() {
        [] if !legacy.is_empty() => Err(format!(
            "no OpenSSH signing key in {}, only legacy raw-base64 key(s) ({}) — the format \
             was removed in 0.6.0: regenerate with `kennel keygen <key-id>`, or convert \
             once with 0.5.x's `kennel keygen migrate`",
            dir.display(),
            legacy.join(", ")
        )),
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
                "multiple signing keys in {} ({}); pass --key <name> to choose one of them",
                dir.display(),
                ids.join(", ")
            ))
        }
    }
}

// ─── Signing: SSHSIG via ssh-keygen, key_id resolved by public key ───────────
//
// The operator-facing signing path shells out to `ssh-keygen -Y sign`, so a key in a
// file, an ssh-agent, or a hardware token are all transparent — we write no agent
// client. The public half lives in the trust store (where trust is conferred, §15.2);
// the private half may live anywhere, since its location confers no authority. The
// in-process SSHSIG signer (`kennel_lib_policy::sshsig`) is used only by tests and the
// library's own `sign_settled`.

/// Find the trust-store `key_id` whose public key matches `pubkey`, searching `dirs`
/// in order (first directory, then alphabetical within it; first match wins).
///
/// This is the inverse of the trust store: it maps a signing key back to the name
/// under which its public half is trusted, so the `key_id` stamped at signing time
/// comes from where the `*.pub` is *placed*, not from the private key's filename.
#[must_use]
pub fn resolve_key_id(dirs: &[PathBuf], pubkey: &[u8; 32]) -> Option<String> {
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            // A `.pub` that is not an OpenSSH line (e.g. the removed legacy raw-base64
            // format) simply never matches — this is a search, not a loader.
            let bytes = kennel_lib_policy::openssh::parse_public_key(&contents)
                .ok()
                .map(|(b, _)| b);
            if bytes.as_ref() == Some(pubkey) {
                return Some(stem.to_owned());
            }
        }
    }
    None
}

/// Sign `canonical` with `ssh-keygen -Y sign`, returning the trust-store `key_id` and
/// the armored SSHSIG to stamp into the `[signature]` envelope.
///
/// `key` is the `--key` value: a path to a private key file, or to a public key whose
/// private half is held by an ssh-agent or a hardware token — `ssh-keygen` handles all
/// three. The stamped `key_id` is `key_id_override` (`--key-id`) if given, else the
/// trust-store `*.pub` whose public key matches the signer's (the SSHSIG embeds the
/// public key, so the match is read straight back out of the armor). `trust_dirs` is
/// the set to resolve against — all layers for `run`/`compile`, system-only for
/// templates.
///
/// # Errors
///
/// Returns a message if `ssh-keygen` is missing or fails, the produced signature
/// cannot be parsed, the signer is a hardware key (not yet supported for signing
/// here), or no `key_id` can be determined without a trust-store match or override.
pub fn sshsig_sign(
    canonical: &[u8],
    key: &str,
    key_id_override: Option<&str>,
    trust_dirs: &[PathBuf],
) -> Result<(String, String), String> {
    let dir = std::env::temp_dir().join(format!("kennel-sign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating sign scratch dir: {e}"))?;
    let guard = ScratchDir(dir);
    let msg = guard.0.join("canonical");
    std::fs::write(&msg, canonical).map_err(|e| format!("staging canonical bytes: {e}"))?;

    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-Y",
            "sign",
            "-q",
            "-n",
            kennel_lib_policy::sshsig::NAMESPACE,
            "-f",
        ])
        .arg(key)
        .arg(&msg)
        .status()
        .map_err(|e| format!("invoking ssh-keygen: {e} (is openssh-client installed?)"))?;
    if !status.success() {
        return Err(format!("ssh-keygen -Y sign failed for key `{key}`"));
    }
    let sig_path = guard.0.join("canonical.sig");
    let armor =
        std::fs::read_to_string(&sig_path).map_err(|e| format!("reading the signature: {e}"))?;

    // The SSHSIG embeds the public key; read it back to resolve the trust-store name.
    let parsed = kennel_lib_policy::sshsig::SshSig::parse_armored(&armor)
        .map_err(|e| format!("parsing the signature ssh-keygen produced: {e}"))?;
    if parsed.key_kind != kennel_lib_policy::sshsig::KeyKind::Ed25519 {
        return Err(
            "hardware (sk-) signing keys are not yet supported for signing; use an Ed25519 key"
                .to_owned(),
        );
    }
    let matched = resolve_key_id(trust_dirs, &parsed.pubkey);
    let key_id = match (key_id_override, matched) {
        (Some(id), found) => {
            if let Some(found) = found {
                if found != id {
                    eprintln!(
                        "warning: --key-id `{id}`, but this key is trusted as `{found}` in the trust store"
                    );
                }
            }
            id.to_owned()
        }
        (None, Some(found)) => found,
        (None, None) => {
            return Err(format!(
                "the signing key's public half is not in any trust dir, so its key_id cannot be \
                 resolved; install its `.pub` in a trust dir or pass --key-id <id> (key: `{key}`)"
            ));
        }
    };
    Ok((key_id, armor))
}

/// A scratch directory removed when dropped.
struct ScratchDir(PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Assemble a signed settled document from an SSHSIG armor and the resolved `key_id`.
#[must_use]
pub fn settled_with_sshsig(
    policy: &kennel_lib_policy::SettledPolicy,
    key_id: String,
    armor: String,
) -> kennel_lib_policy::SignedSettledPolicy {
    kennel_lib_policy::SignedSettledPolicy {
        signature: kennel_lib_policy::SignatureEnvelope {
            algorithm: kennel_lib_policy::signature::SSHSIG_ALGORITHM.to_owned(),
            key_id,
            signature: armor,
            signed_fields: Vec::new(),
        },
        policy: policy.clone(),
    }
}

/// The trust dirs a `run`/`compile` signature's `key_id` is resolved against — all
/// layers, including the user's own keys (a user may sign a leaf with their own key).
#[must_use]
pub fn signing_trust_dirs() -> Vec<PathBuf> {
    kennel_lib_config::User::load()
        .unwrap_or_default()
        .key_dirs()
}

/// The default user key directory.
pub fn default_key_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("kennel").join("keys")
}

// ─── Error codes ─────────────────────────────────────────────────────────────

/// Map a compile-time [`kennel_lib_policy::PolicyError`] to a CLI exit code.
#[must_use]
pub const fn policy_error_code(err: &kennel_lib_policy::PolicyError) -> u8 {
    use kennel_lib_policy::PolicyError as E;
    match err {
        E::Signature(_) | E::LockMismatch(_) => 6,
        E::Parse(_)
        | E::Canonical(_)
        | E::UnsupportedSchemaVersion { .. }
        | E::ObsoleteSchemaVersion { .. }
        | E::InvariantViolations(_)
        | E::SourceValidation(_)
        | E::Resolution(_)
        | E::Translation(_)
        | E::IncludeConflict(_)
        | E::Patch(_)
        | E::Spawn(_) => 3,
    }
}

// ─── Key ID validation ───────────────────────────────────────────────────────

/// A key id is both a filename and the signature `key_id`.
#[must_use]
pub fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod signer_tests {
    use super::*;

    /// A scratch trust dir under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("kennel-w5-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }
        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, contents).expect("write scratch file");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The OpenSSH `ssh-ed25519 <blob> <comment>` public-key line for `pubkey`.
    fn openssh_pub_line(pubkey: &[u8; 32], comment: &str) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(pubkey);
        format!(
            "ssh-ed25519 {} {comment}",
            kennel_lib_policy::b64::encode(&blob)
        )
    }

    fn signing_key(seed: u8) -> kennel_lib_policy::SigningKey {
        kennel_lib_policy::SigningKey::from_seed("seed", &[seed; 32]).expect("32-byte seed")
    }

    #[test]
    fn resolve_key_id_matches_openssh_only() {
        let scratch = Scratch::new("resolve");
        let key = signing_key(1);
        let pubkey = key.public_key_bytes();
        // OpenSSH-format public key, trusted under the stem `maintainer`.
        scratch.write("maintainer.pub", &openssh_pub_line(&pubkey, "person@host"));
        // A `.pub` in the removed legacy raw-base64 format never matches.
        let other = signing_key(2).public_key_bytes();
        scratch.write("legacy.pub", &kennel_lib_policy::b64::encode(&other));

        let dirs = [scratch.0.clone()];
        assert_eq!(
            resolve_key_id(&dirs, &pubkey).as_deref(),
            Some("maintainer")
        );
        assert_eq!(resolve_key_id(&dirs, &other), None);
        // A key with no `.pub` present resolves to nothing.
        assert_eq!(
            resolve_key_id(&dirs, &signing_key(3).public_key_bytes()),
            None
        );
    }

    /// A trust-store `.pub` still in the removed raw-base64 format is refused, and
    /// the diagnostic points at the migration (the W5 exit criterion).
    #[test]
    fn legacy_pub_refused_with_migration_pointer() {
        let scratch = Scratch::new("legacy-pub");
        let pubkey = signing_key(4).public_key_bytes();
        scratch.write("old.pub", &kennel_lib_policy::b64::encode(&pubkey));

        let err = load_trust_store(std::slice::from_ref(&scratch.0))
            .map_or_else(|e| e, |_| "load unexpectedly succeeded".to_owned());
        assert!(err.contains("raw-base64"), "names the format: {err}");
        assert!(err.contains("kennel keygen"), "names the migration: {err}");
    }

    /// A `.pub` that is neither OpenSSH nor the legacy shape gets the plain parse error.
    #[test]
    fn garbage_pub_refused_without_migration_pointer() {
        let scratch = Scratch::new("garbage-pub");
        scratch.write("junk.pub", "not a key at all");
        let err = load_trust_store(std::slice::from_ref(&scratch.0))
            .map_or_else(|e| e, |_| "load unexpectedly succeeded".to_owned());
        assert!(err.contains("not an OpenSSH"), "plain parse error: {err}");
        assert!(
            !err.contains("raw-base64"),
            "no false migration hint: {err}"
        );
    }

    #[test]
    fn key_id_comes_from_trust_store_not_filename() {
        let scratch = Scratch::new("decouple");
        let pubkey = signing_key(7).public_key_bytes();
        // The public half is trusted as `release-key`, wherever the private half lives.
        scratch.write("release-key.pub", &openssh_pub_line(&pubkey, "rel@host"));
        // The stamped key_id is read back from the signer's public key (which a real
        // SSHSIG embeds) against the trust store, not from any filename.
        assert_eq!(
            resolve_key_id(std::slice::from_ref(&scratch.0), &pubkey).as_deref(),
            Some("release-key")
        );
    }
}
