//! Miscellaneous verbs: `keygen`, `audit`.
//!
//! The smaller operator verbs that do not fit the run/policy/oci groups.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{default_key_dir, is_valid_key_id, write_secret};

// ─── keygen ──────────────────────────────────────────────────────────────────

/// `kennel keygen <key-id> [--dir DIR] [--force]`
///
/// Generate an Ed25519 signing key by invoking `ssh-keygen -t ed25519`. The
/// key pair is written into the user key dir (default `$XDG_CONFIG_HOME/kennel/keys`,
/// else `~/.config/kennel/keys`) as `<key-id>` (private, mode 0600) and
/// `<key-id>.pub` (public, mode 0644).
///
/// The comment field in the public key is set to `<key-id>` — so `authorized_keys`-style
/// listings and `ssh-keygen -l` show which kennel policy key this is.
///
/// `kennel keygen migrate [--dir DIR]` converts legacy raw-base64 key pairs to
/// OpenSSH format in place.
///
/// # Errors
///
/// Returns a message if the arguments are invalid (unknown flag, bad key id,
/// duplicate key id), if the target key already exists without `--force`, if the
/// key directory cannot be created, or if `ssh-keygen` is missing or exits
/// non-zero.
pub fn keygen(args: &[String]) -> Result<ExitCode, String> {
    // Sub-command dispatch: `keygen migrate` is separate.
    if args.first().is_some_and(|a| a == "migrate") {
        return keygen_migrate(args.get(1..).unwrap_or_default());
    }

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
    // ssh-keygen uses no extension for the private key and .pub for public.
    // We keep the same convention: <key-id> (private) and <key-id>.pub (public).
    let key_path = dir.join(key_id);
    let pub_path = dir.join(format!("{key_id}.pub"));
    if key_path.exists() && !force {
        return Err(format!(
            "{} already exists; refusing to overwrite a signing key \
             (pass --force to replace it, which invalidates everything signed with the old key)",
            key_path.display()
        ));
    }

    // The key dir holds secret seeds: 0700.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;

    // Remove existing key if --force (ssh-keygen -y prompts otherwise, and
    // -f with an existing file appends to known_hosts on some versions).
    if force {
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&pub_path);
    }

    // Invoke ssh-keygen: -t ed25519, -N "" (no passphrase), -C <key-id> (comment),
    // -f <path> (output path). The -q flag suppresses the randomart.
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", key_id, "-f"])
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

    eprintln!("generated Ed25519 signing key `{key_id}` (OpenSSH format):");
    eprintln!(
        "  private key : {}   (0600 — keep secret)",
        key_path.display()
    );
    eprintln!("  public key  : {}   (0644)", pub_path.display());
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

/// `kennel keygen migrate [--dir DIR]`
///
/// Convert legacy raw-base64 key pairs (`<id>.key` + `<id>.pub`) to OpenSSH
/// format in place. Each `.key` file holding raw base64 is loaded, then
/// re-written as an OpenSSH private key via `ssh-keygen`, and the corresponding
/// `.pub` is regenerated.
fn keygen_migrate(args: &[String]) -> Result<ExitCode, String> {
    let mut dir: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dir" => dir = Some(it.next().ok_or("--dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            _ => return Err("kennel keygen migrate takes no positional arguments".to_owned()),
        }
    }
    let dir = dir.unwrap_or_else(default_key_dir);
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;

    let mut migrated = 0u32;
    for entry in entries.flatten() {
        let path = entry.path();
        // Only look at .key files (the legacy private key extension).
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        // Skip files already in OpenSSH format.
        if kennel_lib_policy::openssh::is_openssh_private(&contents) {
            continue;
        }
        // Try to parse as legacy raw base64 seed.
        let seed = match kennel_lib_policy::b64::decode(contents.trim().as_bytes()) {
            Some(s) if s.len() == 32 => s,
            _ => continue, // Not a recognisable legacy key — skip.
        };

        let key_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("cannot derive key id from {}", path.display()))?;

        // Derive the full keypair so we can write both files.
        let signing_key = kennel_lib_policy::SigningKey::from_seed(key_id, &seed)
            .map_err(|e| format!("loading {}: {e}", path.display()))?;

        // Write a temporary raw seed file, then use ssh-keygen to convert.
        // Actually, ssh-keygen cannot import a raw seed. Instead, we generate
        // the OpenSSH format ourselves and write it out. But the user asked
        // to invoke ssh-keygen... For migration, we need to produce the
        // OpenSSH format from the existing seed. ssh-keygen -y can extract
        // the public key from a private key, but can't import a raw seed.
        //
        // The practical approach: write the new private key in OpenSSH wire
        // format (the format is fixed-layout for unencrypted ed25519), then
        // use `ssh-keygen -y -f <private>` to regenerate the .pub.
        let pubkey = signing_key.public_key_bytes();
        let openssh_private = build_openssh_private(&seed, &pubkey, key_id)?;

        // Write the private key (mode 0600).
        // The new format uses no extension (ssh-keygen convention).
        let new_key_path = dir.join(key_id);
        write_secret(&new_key_path, &openssh_private, 0o600)
            .map_err(|e| format!("writing {}: {e}", new_key_path.display()))?;

        // Regenerate the .pub via ssh-keygen -y.
        let pub_path = dir.join(format!("{key_id}.pub"));
        let output = std::process::Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&new_key_path)
            .output()
            .map_err(|e| format!("invoking ssh-keygen -y: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "ssh-keygen -y failed for {}: {}",
                new_key_path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        // Append the comment (ssh-keygen -y doesn't include it).
        let mut pub_line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !pub_line.is_empty() {
            pub_line.push(' ');
            pub_line.push_str(key_id);
        }
        std::fs::write(&pub_path, format!("{pub_line}\n"))
            .map_err(|e| format!("writing {}: {e}", pub_path.display()))?;

        // Remove the old .key file (the new private key has no extension).
        if path != new_key_path {
            let _ = std::fs::remove_file(&path);
        }

        eprintln!("migrated: {key_id} → OpenSSH format");
        migrated = migrated.saturating_add(1);
    }

    if migrated == 0 {
        eprintln!("no legacy keys found in {}", dir.display());
    } else {
        eprintln!("\n{migrated} key(s) migrated to OpenSSH format.");
        eprintln!("Private keys are now at <key-id> (no .key extension).");
        eprintln!("Public keys regenerated as <key-id>.pub (ssh-ed25519 format).");
    }
    Ok(ExitCode::SUCCESS)
}

/// Build an unencrypted OpenSSH private key file (PEM format) from a raw
/// Ed25519 seed + public key + comment.
///
/// The format is documented in `PROTOCOL.key` of the OpenSSH source. For
/// unencrypted ed25519, every field is fixed-size — no ASN.1, no variable
/// crypto parameters.
fn build_openssh_private(seed: &[u8], pubkey: &[u8; 32], comment: &str) -> Result<String, String> {
    if seed.len() != 32 {
        return Err("seed must be 32 bytes".to_owned());
    }

    let key_type = b"ssh-ed25519";

    // Build the public key blob (for the outer "public key" field).
    let mut pubblob = Vec::new();
    write_string(&mut pubblob, key_type);
    write_string(&mut pubblob, pubkey);

    // Build the private key section.
    // Use a deterministic check value (from the seed) — same as OpenSSH's
    // arc4random for the check bytes, but any matching pair works.
    let mut check = [0u8; 4];
    kennel_lib_syscall::random::fill(&mut check)
        .map_err(|e| format!("reading OS randomness: {e}"))?;
    let check_val = u32::from_be_bytes(check);

    let mut priv_section = Vec::new();
    priv_section.extend_from_slice(&check_val.to_be_bytes()); // check1
    priv_section.extend_from_slice(&check_val.to_be_bytes()); // check2
    write_string(&mut priv_section, key_type);
    write_string(&mut priv_section, pubkey); // ed25519 public key
                                             // ed25519 "private key" = seed ‖ pubkey (64 bytes)
    let mut privkey = Vec::with_capacity(64);
    privkey.extend_from_slice(seed);
    privkey.extend_from_slice(pubkey);
    write_string(&mut priv_section, &privkey);
    write_string(&mut priv_section, comment.as_bytes());
    // Padding: 1, 2, 3, ... up to block size (8 for "none" cipher).
    let block_size = 8usize;
    let pad_len = block_size.saturating_sub(priv_section.len() % block_size);
    let pad_len = if pad_len == block_size { 0 } else { pad_len };
    for i in 1..=pad_len {
        // `pad_len` is at most `block_size` (8), so the index fits in a `u8`.
        priv_section.push(u8::try_from(i).unwrap_or(0));
    }

    // Assemble the full payload.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"openssh-key-v1\0"); // AUTH_MAGIC
    write_string(&mut payload, b"none"); // ciphername
    write_string(&mut payload, b"none"); // kdfname
    write_string(&mut payload, b""); // kdfoptions
    payload.extend_from_slice(&1u32.to_be_bytes()); // number of keys
    write_string(&mut payload, &pubblob); // public key blob
    write_string(&mut payload, &priv_section); // private section

    // PEM-encode.
    let b64_payload = kennel_lib_policy::b64::encode(&payload);
    let mut pem = String::new();
    pem.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64_payload.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----");
    Ok(pem)
}

/// Write a length-prefixed SSH string (u32 big-endian length + bytes).
fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    // SSH strings are u32-length-prefixed. Every caller here passes a small,
    // fixed-size field (key type, 32-byte key, short comment), so the length
    // always fits in a `u32`; clamp defensively rather than truncate.
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

// ─── audit ───────────────────────────────────────────────────────────────────

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
/// # Errors
///
/// Returns a message if the arguments are invalid (unknown flag, missing flag
/// value, bad kennel name, unknown `--resource`, unparseable `--since`
/// duration), the system clock is before the Unix epoch, or an audit log file
/// cannot be read.
pub fn audit(args: &[String]) -> Result<ExitCode, String> {
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

fn resource_stem(token: &str) -> Option<&'static str> {
    AUDIT_STEMS
        .iter()
        .copied()
        .zip(["net", "fs", "exec", "unix", "dbus", "priv", "lifecycle"])
        .find_map(|(stem, tok)| (tok == token).then_some(stem))
}

/// Parse a human duration to seconds.
///
/// # Errors
///
/// Returns a message if the numeric part does not parse, or if the value times
/// its unit multiplier overflows `u64`.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
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

fn extract_ts(line: &str) -> Option<&str> {
    let start = line.find(r#""ts":""#)?.checked_add(6)?;
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration_secs("90s").expect("90s"), 90);
        assert_eq!(parse_duration_secs("30m").expect("30m"), 1_800);
        assert_eq!(parse_duration_secs("2h").expect("2h"), 7_200);
        assert_eq!(parse_duration_secs("7d").expect("7d"), 604_800);
        assert_eq!(parse_duration_secs("45").expect("bare"), 45);
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
        let later = r#"{"schema_version":1,"ts":"2026-06-05T12:00:00.000000Z","event":"net.connect-deny","resource":"net"}"#;
        assert_eq!(novel_key(line), novel_key(later));
        let other = r#"{"schema_version":1,"ts":"2026-06-05T11:30:50.000000Z","event":"net.connect-allow","resource":"net"}"#;
        assert_ne!(novel_key(line), novel_key(other));
        assert_eq!(novel_key("{}"), "{}");
        assert_eq!(extract_ts("{}"), None);
    }
}
