//! `kennel-ssh-reorigin` binary: the thin IO shell around the re-origination core.
//!
//! All decision logic lives in the library (`kennel_ssh_reorigin`), which is pure and
//! unit-tested. `main` only performs the IO the bastion environment dictates: read
//! `$SSH_USER_AUTH`, enumerate the agent's keys, write the selected public key to a
//! private temp file, then `execvp` the outbound `ssh`. Every failure is fail-closed
//! — it prints a refusal and exits non-zero, so the bastion session ends without a
//! connection.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitCode, Stdio};

use kennel_ssh_reorigin::{
    outbound_argv, parse_args, parse_user_auth, select_identity, LoadedKey, Outbound,
    ReoriginError, SCRUB_ENV,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS, // unreachable: run() execs on success
        Err(e) => {
            eprintln!("kennel-ssh-reorigin: denied: {e}");
            ExitCode::from(1)
        }
    }
}

/// Assemble and `exec` the outbound `ssh`. Returns only on error (success replaces
/// this process image).
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let req = parse_args(args)?;

    // 1. Confirm a publickey method authenticated to the bastion (defence in depth:
    //    the forced command already guarantees the right synthetic key, but we refuse
    //    to proceed on anything but publickey).
    let auth_path = std::env::var_os("SSH_USER_AUTH")
        .ok_or_else(|| ReoriginError::Auth("$SSH_USER_AUTH is not set".to_owned()))?;
    let auth_contents = std::fs::read_to_string(&auth_path)
        .map_err(|e| ReoriginError::Auth(format!("cannot read $SSH_USER_AUTH: {e}")))?;
    let auth = parse_user_auth(&auth_contents)?;
    // Audit trail: which synthetic key the bastion accepted, and the fixed destination.
    eprintln!(
        "kennel-ssh-reorigin: re-originating to {dest} (key {key}); synthetic {ktype} authenticated",
        dest = req.dest,
        key = req.key,
        ktype = auth.key_type,
    );

    // 2. Select the real key K from the agent and pin it to a private file.
    let loaded = agent_keys()?;
    let pubkey_line = select_identity(&loaded, &req.key)?;
    let identity_file = write_identity(pubkey_line)?;

    // 3. Build the outbound argv and exec ssh.
    let known_hosts = std::env::var("KENNEL_SSH_KNOWN_HOSTS").ok();
    let config_file = std::env::var("KENNEL_SSH_CONFIG").ok();
    let original = std::env::var("SSH_ORIGINAL_COMMAND").ok();
    let ssh_argv = outbound_argv(&Outbound {
        dest: &req.dest,
        identity_file: &identity_file,
        known_hosts_file: known_hosts.as_deref(),
        config_file: config_file.as_deref(),
        original_command: original.as_deref(),
    });

    let (program, rest) = ssh_argv
        .split_first()
        .expect("outbound_argv is never empty");
    let mut cmd = Command::new(program);
    cmd.args(rest);
    for var in SCRUB_ENV {
        cmd.env_remove(var);
    }
    // execvp: replace this process. If it returns, the exec itself failed.
    Err(Box::new(cmd.exec()))
}

/// Enumerate the agent's loaded keys as `(fingerprint, public-key line)` pairs.
///
/// `ssh-add -L` prints one full public key per line; each is fingerprinted with
/// `ssh-keygen -lf -` (robust to agent ordering). A key the agent cannot list, or an
/// empty agent, yields an empty set — and `select_identity` then fails closed.
fn agent_keys() -> Result<Vec<LoadedKey>, Box<dyn std::error::Error>> {
    let listing = Command::new("ssh-add")
        .arg("-L")
        .stderr(Stdio::null())
        .output()?;
    if !listing.status.success() {
        return Err(Box::new(ReoriginError::NoIdentity(
            "`ssh-add -L` failed (no agent, or no identities)".to_owned(),
        )));
    }
    let text = String::from_utf8_lossy(&listing.stdout);
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(fp) = fingerprint_of(line)? {
            keys.push(LoadedKey {
                fingerprint: fp,
                pubkey_line: line.to_owned(),
            });
        }
    }
    Ok(keys)
}

/// The `SHA256:…` fingerprint of one public-key line, via `ssh-keygen -lf -`.
fn fingerprint_of(pubkey_line: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut child = Command::new("ssh-keygen")
        .args(["-l", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(pubkey_line.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Ok(None);
    }
    // Output: "<bits> SHA256:<b64> <comment> (<TYPE>)" — take the SHA256 token.
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_owned))
}

/// Write the selected public key to a private (`0600`) temp file for `ssh -i`.
///
/// Only the *public* key is written — the private half stays in the agent. The file
/// lives under `$XDG_RUNTIME_DIR` (a user-private tmpfs) when set, else `/tmp`, and is
/// named by pid; `ssh` reads it before any connection, so its brief lifetime is fine.
fn write_identity(pubkey_line: &str) -> Result<String, Box<dyn std::error::Error>> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || std::path::PathBuf::from("/tmp"),
        std::path::PathBuf::from,
    );
    let path = dir.join(format!("kennel-reorigin-{}.pub", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(f, "{pubkey_line}")?;
    Ok(path.to_string_lossy().into_owned())
}
