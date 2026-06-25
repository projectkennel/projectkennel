//! Shared helpers for all host-side CLI binaries.
//!
//! Daemon connection, key loading, policy/template/trust-store resolution,
//! exit-code mapping, lexopt helpers, and the command tables. Previously
//! in `main.rs`; extracted for the W10 split.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_cli::{render_commands, CommandSpec, RUN, RUN_SUMMARY};
use kennel_lib_control::control::{self, Request};
use kennel_lib_control::socket;

// ─── Command tables ──────────────────────────────────────────────────────────

/// Top-level commands (the unified help surface).
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: RUN,
        summary: RUN_SUMMARY,
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
        summary: "list running kennels and the cross-kennel service mesh",
        usage: "list",
    },
    CommandSpec {
        name: "daemon-reload",
        summary: "re-derive the service catalogue from the enablement links",
        usage: "daemon-reload",
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
pub const POLICY_VERBS: &[CommandSpec] = &[
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
pub fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// The usage line for `verb` from a spec table, as a `kennel …` error string.
pub fn usage_of(table: &[CommandSpec], verb: &str) -> String {
    table.iter().find(|c| c.name == verb).map_or_else(
        || format!("unknown command `{verb}` — run `kennel --help`"),
        |c| format!("usage: kennel {}", c.usage),
    )
}

// ─── Daemon connection ───────────────────────────────────────────────────────

/// Connect to the daemon's control socket and run the version handshake.
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
pub fn send(
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
pub fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

// ─── Lexopt helpers ──────────────────────────────────────────────────────────

/// Read the next required value for `flag` from a lexopt parser.
pub fn lexopt_value(p: &mut lexopt::Parser, flag: &str) -> Result<PathBuf, String> {
    p.value()
        .map(PathBuf::from)
        .map_err(|_| format!("{flag} needs a value"))
}

/// Format an unexpected lexopt arg into a usage error for `verb`.
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

/// Load a trust store: every `<key_id>.pub` under each directory.
///
/// Accepts two formats per file (W4):
/// - **OpenSSH**: `ssh-ed25519 <base64-blob> [comment]` — the standard format
///   produced by `ssh-keygen`. The key id is the file stem; the comment is
///   informational.
/// - **Legacy**: raw base64 of the 32-byte Ed25519 public key (the pre-W4 format).
///
/// Detection: if the file starts with `ssh-ed25519 `, parse OpenSSH; else try
/// raw base64.
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
            } else {
                // Legacy raw base64 format.
                keys.insert_b64(key_id, contents.trim())
                    .map_err(|e| format!("key {}: {e}", path.display()))?;
            }
        }
    }
    Ok(keys)
}

// ─── Signing keys ────────────────────────────────────────────────────────────

/// Load a signing key from a file.
///
/// Accepts two formats (W4):
/// - **OpenSSH**: `-----BEGIN OPENSSH PRIVATE KEY-----` PEM envelope (the standard
///   format produced by `ssh-keygen -t ed25519`). Must be unencrypted.
/// - **Legacy**: raw base64 of the 32-byte Ed25519 seed (the pre-W4 format).
///
/// The key id is derived from the file stem in both cases.
pub fn load_signing_key(path: &Path) -> Result<kennel_lib_policy::SigningKey, String> {
    let shown = path.display();
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading key {shown}: {e}"))?;
    let key_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("cannot derive a key id from {shown}"))?;
    if kennel_lib_policy::openssh::is_openssh_private(&text) {
        let (seed, _comment) = kennel_lib_policy::openssh::parse_private_key(&text)
            .map_err(|e| format!("key {shown}: {e}"))?;
        kennel_lib_policy::SigningKey::from_seed(key_id, &seed)
            .map_err(|e| format!("loading key {shown}: {e}"))
    } else {
        // Legacy raw base64 format.
        let seed = kennel_lib_policy::b64::decode(text.trim().as_bytes())
            .ok_or_else(|| format!("key {shown} is not valid base64"))?;
        kennel_lib_policy::SigningKey::from_seed(key_id, &seed)
            .map_err(|e| format!("loading key {shown}: {e}"))
    }
}

/// The signing key to use when `--key` was omitted: the sole signing key in the
/// user key dir. Searches for both OpenSSH private keys (no extension, PEM
/// content) and legacy `*.key` files (raw base64 seed).
pub fn default_signing_key() -> Result<PathBuf, String> {
    let dir = default_key_dir();
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    // Legacy: *.key files.
                    if p.extension().and_then(|x| x.to_str()) == Some("key") {
                        return true;
                    }
                    // OpenSSH: files with no extension that are not .pub and are files.
                    if p.extension().is_none() && p.is_file() {
                        // Quick content check: must start with the PEM marker.
                        if let Ok(head) = std::fs::read_to_string(p) {
                            return kennel_lib_policy::openssh::is_openssh_private(&head);
                        }
                    }
                    false
                })
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
pub const fn policy_error_code(err: &kennel_lib_policy::PolicyError) -> u8 {
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

// ─── Key ID validation ───────────────────────────────────────────────────────

/// A key id is both a filename and the signature `key_id`.
pub fn is_valid_key_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Write base64 `text` (plus a trailing newline) to `path`, creating it with `mode`.
pub fn write_secret(path: &Path, text: &str, mode: u32) -> io::Result<()> {
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
