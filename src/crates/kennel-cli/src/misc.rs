//! Miscellaneous verbs: `version`, `audit`.
//!
//! The smaller operator verbs that do not fit the run/policy/key/oci groups.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ─── version ─────────────────────────────────────────────────────────────────

/// `kennel version` (also `kennel --version`) — the whole-stack skew report.
///
/// One number is not the interesting output; the *skew set* is: this CLI's build and
/// settled-schema range, the **daemon's, queried live** (which instantly surfaces the
/// old-binary-still-serving-after-reinstall trap), and the privhelper facts (present,
/// and whether the bpf-egress sub-helper shipped — that feature is a separate binary,
/// so its presence is a filesystem fact, no privileged probe). Always exits 0: the
/// report is the product, skew included.
///
/// # Errors
///
/// Returns a message only on unexpected arguments — every stack fact, including an
/// unreachable or older daemon, is reported, not errored.
pub fn version(args: &[String]) -> Result<ExitCode, String> {
    if let Some(arg) = args.first() {
        return Err(format!(
            "unexpected argument `{arg}` — usage: kennel version"
        ));
    }
    let cli_build = env!("CARGO_PKG_VERSION");
    println!(
        "kennel CLI     : {cli_build} — settled schema v{} (min v{})",
        kennel_lib_policy::SETTLED_SCHEMA_VERSION,
        kennel_lib_policy::MIN_SETTLED_SCHEMA_VERSION
    );
    let skew = report_daemon(cli_build);
    report_privhelper();
    match skew {
        Some(note) => println!("skew           : {note}"),
        None => println!("skew           : none — CLI and daemon builds match"),
    }
    Ok(ExitCode::SUCCESS)
}

/// Query the live daemon and print its line; `Some(note)` if the stack is skewed.
///
/// Three degraded shapes, each still a report: unreachable (socket unit off), the
/// handshake's typed refusal (a daemon too old to parse this CLI's schema), and a
/// daemon that predates [`Request::Version`] (it drops the connection on the unknown
/// tag — the additive-request contract).
///
/// [`Request::Version`]: kennel_lib_control::control::Request::Version
fn report_daemon(cli_build: &str) -> Option<String> {
    use kennel_lib_control::control::{self, HandshakeError, Request, Response};
    use kennel_lib_control::socket;

    let path = socket::socket_path();
    let mut conn = match std::os::unix::net::UnixStream::connect(&path) {
        Ok(c) => c,
        Err(e) => {
            println!("kenneld        : unreachable at {} ({e})", path.display());
            return Some(
                "daemon unreachable — is the kenneld.socket user unit enabled?".to_owned(),
            );
        }
    };
    match control::client_handshake(
        &mut conn,
        kennel_lib_policy::SETTLED_SCHEMA_VERSION,
        cli_build,
    ) {
        Ok(()) => {}
        Err(HandshakeError::Skew(s)) => {
            println!(
                "kenneld (live) : {} — settled schema v{} (older than this CLI's v{})",
                s.daemon_build, s.daemon_schema, s.client_schema
            );
            return Some(
                "the daemon is an older build — restart it to pick up the installed one: \
                 `systemctl --user restart kenneld.service`"
                    .to_owned(),
            );
        }
        Err(HandshakeError::Io(e)) => {
            println!("kenneld        : handshake failed ({e})");
            return Some("the daemon spoke no control handshake — a pre-0.4 build?".to_owned());
        }
    }
    if crate::send(&conn, &Request::Version, &[]).is_err() {
        println!("kenneld (live) : version query failed to send");
        return Some("the daemon dropped the version query".to_owned());
    }
    match control::recv_response(&mut conn) {
        Ok(Response::Version {
            build,
            schema_version,
            min_schema_version,
        }) => {
            println!(
                "kenneld (live) : {build} — settled schema v{schema_version} (min v{min_schema_version})"
            );
            (build != cli_build).then(|| {
                format!(
                    "CLI {cli_build} vs daemon {build} — restart the daemon to pick up the \
                     installed binary: `systemctl --user restart kenneld.service`"
                )
            })
        }
        // A pre-0.7.0 daemon drops the connection on the unknown request tag; the handshake
        // above already succeeded, so the daemon is alive — it just predates the query.
        Ok(other) => {
            println!("kenneld (live) : unexpected response ({other:?})");
            Some("the daemon answered the version query with the wrong shape".to_owned())
        }
        Err(_) => {
            println!("kenneld (live) : predates the version query (a pre-0.7.0 build)");
            Some(
                "the running daemon predates `kennel version` — restart it to pick up the \
                 installed binary: `systemctl --user restart kenneld.service`"
                    .to_owned(),
            )
        }
    }
}

/// Print the privhelper facts: the factory and its capability-split sub-helpers, by
/// presence at the deployment paths. The bpf-egress feature builds a separate
/// `kennel-privhelper-bpf` binary, so "was it shipped" is exactly "is it on disk".
fn report_privhelper() {
    let d = kennel_lib_config::Deployment::load()
        .unwrap_or_else(|_| kennel_lib_config::Deployment::defaults());
    let present = |p: &Path| if p.is_file() { "present" } else { "ABSENT" };
    let factory = d.privhelper();
    println!(
        "privhelper     : {} ({})",
        present(&factory),
        factory.display()
    );
    println!(
        "  sub-helpers  : mounts {}, net {}, bpf-egress {}",
        present(&d.privhelper_mounts()),
        present(&d.privhelper_net()),
        present(&d.privhelper_bpf())
    );
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
