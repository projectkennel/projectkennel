//! Miscellaneous verbs: `keygen`, `subkennel`, `audit`.
//!
//! These are the verbs that belong to `kennel-misc` — smaller verbs without
//! their own binary yet. They graduate out as they grow (W10 roadmap).

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{default_key_dir, is_valid_key_id, write_secret};

// ─── keygen ──────────────────────────────────────────────────────────────────

/// `kennel keygen <key-id> [--dir DIR] [--force]`
pub fn keygen(args: &[String]) -> Result<ExitCode, String> {
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

// ─── subkennel ───────────────────────────────────────────────────────────────

/// The system per-user allocation file.
const SUBKENNEL_FILE: &str = "/etc/kennel/subkennel";

/// Largest valid `tag` — the 12-bit IPv4 `/20` selector.
const SUBKENNEL_TAG_MAX: u16 = 0x0FFF;

/// One parsed `/etc/kennel/subkennel` allocation.
struct Alloc {
    uid: u32,
    tag: u16,
    gid_hex: String,
    namespace: String,
}

/// `kennel subkennel <add|check> ...`
pub fn subkennel(args: &[String]) -> Result<ExitCode, String> {
    match args.split_first() {
        Some((cmd, rest)) if cmd == "add" => subkennel_add(rest),
        Some((cmd, rest)) if cmd == "check" => subkennel_check(rest),
        _ => Err("usage: kennel subkennel add [--uid N] [--namespace NS] [--tag N] [--file PATH] | kennel subkennel check [--uid N] [--file PATH]".to_owned()),
    }
}

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

fn default_user_label(uid: u32) -> String {
    std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty() && !s.contains(':'))
        .unwrap_or_else(|| uid.to_string())
}

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

    let used_gids: std::collections::BTreeSet<&str> =
        allocs.iter().map(|a| a.gid_hex.as_str()).collect();
    let gid_hex = loop {
        let mut g = [0u8; 5];
        kennel_lib_syscall::random::fill(&mut g)
            .map_err(|e| format!("reading OS randomness: {e}"))?;
        if g == [0u8; 5] {
            continue;
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
