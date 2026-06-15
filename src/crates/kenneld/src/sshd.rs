//! The per-kennel SSH re-origination bastion (`kennel-sshd`): config and launch.
//!
//! Per-kennel SSH leaves the kennel only through a managed instance of stock
//! OpenSSH `sshd` (`docs/design/07-10-ssh.md` §7.10). It holds no keys; it is a
//! forced-command router. `kenneld` owns its lifecycle and key state, exactly as it
//! owns the egress proxy (`proxy.rs`): this module writes the hardened `sshd_config`
//! and the per-key forced-command `authorized_keys` lines from the resolved `[ssh]`
//! policy, and launches the daemon as a per-user child.
//!
//! # The lockdown (§7.10.6)
//!
//! The generated config denies everything but a publickey login that runs the forced
//! command with a pty: no password/kbd-interactive, no TCP/X11/agent forwarding, no
//! tunnels, `PermitOpen none`, and SFTP wired to `/bin/false`. Combined with the
//! per-key `restrict,pty` option set, SFTP/scp/port-forwarding are out of scope by
//! construction for the first cut. The forced command itself is just `ssh <options> --
//! <dest> "$SSH_ORIGINAL_COMMAND"`, baked per synthetic key by the `AuthorizedKeysCommand`
//! and run as the operator — no agent, no helper binary, no key material on this hop.
//!
//! # `AuthorizedKeys` source (§7.10.7)
//!
//! Production vends keys through an `AuthorizedKeysCommand` that queries `kenneld` —
//! and that helper must be **root-owned** (OpenSSH's safe-path check rejects an AKC
//! owned by the unprivileged user `sshd` runs as). The rootless bastion only invokes
//! it. A static `AuthorizedKeysFile` is the other supported source (the prototype's,
//! and what the e2e test drives): a file the bastion-running user owns, `0600`, on a
//! safe-owned path — never world-writable `/tmp`.
//!
//! Config generation is pure and unit-tested; [`spawn`] launches the daemon.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The installed `sshd` binary used for the bastion (stock OpenSSH).
pub const DEFAULT_SSHD_BIN: &str = "/usr/sbin/sshd";

/// The `HostKeyAlias`/`known_hosts` name the kennel's synthetic `~/.ssh` pins the
/// bastion under — kept in step with [`crate::ssh::BASTION_ALIAS`].
pub const BASTION_ALIAS: &str = crate::ssh::BASTION_ALIAS;

/// Where the bastion reads its `authorized_keys` from.
#[derive(Debug, Clone)]
pub enum AuthSource {
    /// A static `AuthorizedKeysFile` the bastion-running user owns (`0600`, safe
    /// path). The prototype/e2e source.
    File(PathBuf),
    /// An `AuthorizedKeysCommand` (root-owned, per the safe-path finding) run as
    /// `user`, that queries `kenneld` for the live forced-command bindings.
    Command {
        /// The absolute path to the root-owned helper.
        command: PathBuf,
        /// The user the helper runs as (its owner; e.g. `root`).
        user: String,
    },
}

/// What the bastion's `sshd_config` is rendered from.
#[derive(Debug, Clone)]
pub struct SshdParams<'a> {
    /// The loopback address the bastion listens on (the egress proxy forwards here).
    pub listen: IpAddr,
    /// The bastion's TCP port.
    pub port: u16,
    /// The bastion's host private key (its public half is pinned in the kennel's
    /// synthetic `known_hosts` under [`BASTION_ALIAS`]).
    pub host_key: &'a Path,
    /// The pid file path (under a safe-owned runtime dir).
    pub pid_file: &'a Path,
    /// Where authorised keys come from.
    pub auth: AuthSource,
}

/// Render the bastion's hardened `sshd_config` (§7.10.6).
#[must_use]
pub fn sshd_config(p: &SshdParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = String::from(
        "# kennel-sshd — per-kennel SSH re-origination bastion (generated, read-only).\n\
         # Denies everything but a publickey login running the forced command with a\n\
         # pty; SFTP/scp/forwarding are out of scope by construction (07-10-ssh.md §7.10.6).\n",
    );
    let _ = write!(
        s,
        "\nListenAddress {listen}\n\
         Port {port}\n\
         HostKey {host_key}\n\
         PidFile {pid}\n",
        listen = p.listen,
        port = p.port,
        host_key = p.host_key.display(),
        pid = p.pid_file.display(),
    );
    // Expose which (synthetic) key authenticated to the forced command.
    s.push_str("\nExposeAuthInfo yes\n");
    // No agent is handed to the forced command: the outbound `ssh` runs as the operator
    // and signs with whatever the operator's own `options` (`-i …`) name from their own
    // host-side key store. An exposed agent socket would be the destination-blind signing
    // oracle the bastion exists to prevent (§7.10.1) — so there is deliberately no
    // `SetEnv SSH_AUTH_SOCK` here.
    // Publickey only.
    s.push_str(
        "\nPubkeyAuthentication yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PermitRootLogin no\n\
         PermitEmptyPasswords no\n\
         UsePAM no\n",
    );
    match &p.auth {
        AuthSource::File(path) => {
            let _ = write!(s, "\nAuthorizedKeysFile {}\n", path.display());
        }
        AuthSource::Command { command, user } => {
            // Hand the helper the offered key as `%t %k` (type + base64 blob); it asks
            // kenneld for that key's forced-command line. The helper is root-owned (the
            // safe-path finding); the bindings live in the daemon, not a file.
            let _ = write!(
                s,
                "\nAuthorizedKeysFile none\n\
                 AuthorizedKeysCommand {} %t %k\n\
                 AuthorizedKeysCommandUser {user}\n",
                command.display(),
            );
        }
    }
    // Lock the session down to the forced command + a pty (§7.10.6).
    s.push_str(
        "\nAllowTcpForwarding no\n\
         X11Forwarding no\n\
         AllowAgentForwarding no\n\
         PermitTunnel no\n\
         GatewayPorts no\n\
         PermitOpen none\n\
         AllowStreamLocalForwarding no\n\
         Subsystem sftp /bin/false\n",
    );
    s
}

/// Build one `authorized_keys` line binding `synthetic_pubkey` to a forced command that
/// runs `ssh <options…> -- <dest> "$SSH_ORIGINAL_COMMAND"` **as the operator** (§7.10.3).
///
/// `restrict,pty` is the per-key option set: it denies forwarding/X11/agent/user-rc
/// while keeping a tty. The destination and its host-side `ssh` options are baked in, so
/// the workload — holding only the synthetic private key — reaches exactly this one
/// destination and cannot redirect: it controls only `$SSH_ORIGINAL_COMMAND` (the remote
/// command), forwarded as a single argument. There is no agent and no key material on
/// either side of this hop; the operator's `options` (e.g. `-i ~/.ssh/id_x`) name which
/// real key the host-side `ssh` signs with, in the operator's own key store.
///
/// `dest` and each `option` are shell-quoted into the forced command (sshd runs it via
/// the login shell), so an awkward character cannot break out; `$SSH_ORIGINAL_COMMAND` is
/// expanded by that shell and passed as one argument. `synthetic_pubkey` is one
/// whitespace-normalised public-key line (`ssh-ed25519 AAAA… [comment]`).
#[must_use]
pub fn authorized_keys_line(dest: &str, options: &[String], synthetic_pubkey: &str) -> String {
    let mut cmd = String::from("ssh");
    for opt in options {
        cmd.push(' ');
        cmd.push_str(&shell_quote(opt));
    }
    cmd.push_str(" -- ");
    cmd.push_str(&shell_quote(dest));
    // The remote command the workload sent, forwarded as a single argument. sshd sets
    // $SSH_ORIGINAL_COMMAND in the forced command's environment (it is never concatenated
    // into the command line), and the double quotes keep it one argv token. Those inner
    // double quotes are escaped (`\"`) because the whole forced command is itself written
    // inside the authorized_keys `command="…"` field — OpenSSH unescapes `\"` to `"`.
    cmd.push_str(" \\\"$SSH_ORIGINAL_COMMAND\\\"");
    format!(
        "restrict,pty,command=\"{cmd}\" {pubkey}\n",
        cmd = cmd,
        pubkey = synthetic_pubkey.trim(),
    )
}

/// Single-quote a token for safe inclusion in the forced command's shell string. A
/// single-quoted shell word is literal except for `'` itself, escaped as `'\''`.
fn shell_quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len().saturating_add(2));
    q.push('\'');
    for c in s.chars() {
        if c == '\'' {
            q.push_str("'\\''");
        } else {
            q.push(c);
        }
    }
    q.push('\'');
    q
}

/// Launch the bastion `sshd` in the foreground (`-D`), logging to stderr (`-e`),
/// reading `config_path`.
///
/// Spawned as a per-user child, like the netproxy: the caller owns the returned
/// [`Child`] and must reap/kill it on teardown. `-e` keeps logs off syslog and on the
/// daemon's stderr for diagnostics; `-D` stops sshd from forking away so the child
/// handle tracks the real process.
///
/// # Errors
///
/// An OS error if the daemon cannot be spawned.
pub fn spawn(sshd_bin: &Path, config_path: &Path) -> io::Result<Child> {
    Command::new(sshd_bin)
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
}

/// Generate a fresh ed25519 host key for the bastion at `path` (via stock
/// `ssh-keygen`), returning its public-key line for the synthetic `known_hosts`.
///
/// Uses `ssh-keygen` rather than minting in-process: the on-disk format is then
/// exactly what `sshd`/`ssh` expect, and no key serialisation is hand-rolled. A
/// pre-existing `path` is removed first (the bastion's host key is disposable,
/// regenerated on (re)start — the kennel pins whatever is current).
///
/// # Errors
///
/// An OS error if `ssh-keygen` cannot run, or it exits non-zero / its `.pub` cannot
/// be read.
pub fn generate_host_key(path: &Path) -> io::Result<String> {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("pub"));
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "kennel-sshd-bastion", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "ssh-keygen failed to generate the bastion host key",
        ));
    }
    let pub_line = std::fs::read_to_string(path.with_extension("pub"))?;
    Ok(pub_line.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn params(auth: AuthSource) -> SshdParams<'static> {
        SshdParams {
            listen: IpAddr::V4(Ipv4Addr::new(127, 0, 42, 1)),
            port: 7022,
            host_key: Path::new("/run/kennel/bastion/host_key"),
            pid_file: Path::new("/run/kennel/bastion/sshd.pid"),
            auth,
        }
    }

    #[test]
    fn config_locks_down_forwarding_and_exposes_auth_info() {
        let c = sshd_config(&params(AuthSource::File(PathBuf::from(
            "/run/kennel/bastion/authorized_keys",
        ))));
        assert!(
            c.contains("ExposeAuthInfo yes"),
            "forced command needs $SSH_USER_AUTH"
        );
        assert!(
            !c.contains("SSH_AUTH_SOCK"),
            "no agent is handed to the forced command (the banned signing oracle, §7.10.1)"
        );
        assert!(c.contains("ListenAddress 127.0.42.1"));
        assert!(c.contains("Port 7022"));
        for denied in [
            "AllowTcpForwarding no",
            "X11Forwarding no",
            "AllowAgentForwarding no",
            "PermitTunnel no",
            "PermitOpen none",
            "AllowStreamLocalForwarding no",
            "Subsystem sftp /bin/false",
            "PasswordAuthentication no",
            "PermitRootLogin no",
        ] {
            assert!(c.contains(denied), "config must contain `{denied}`");
        }
    }

    #[test]
    fn config_uses_a_static_file_or_root_owned_command() {
        let file = sshd_config(&params(AuthSource::File(PathBuf::from(
            "/safe/authorized_keys",
        ))));
        assert!(file.contains("AuthorizedKeysFile /safe/authorized_keys"));
        assert!(!file.contains("AuthorizedKeysCommand"));

        let cmd = sshd_config(&params(AuthSource::Command {
            command: PathBuf::from("/opt/kennel/bin/kennel-akc"),
            user: "root".to_owned(),
        }));
        assert!(
            cmd.contains("AuthorizedKeysCommand /opt/kennel/bin/kennel-akc %t %k"),
            "AKC gets the offered key"
        );
        assert!(
            cmd.contains("AuthorizedKeysCommandUser root"),
            "AKC must be root-owned (safe-path finding)"
        );
        assert!(cmd.contains("AuthorizedKeysFile none"));
    }

    #[test]
    fn authorized_keys_line_bakes_in_the_ssh_command_with_restrict_pty() {
        let line = authorized_keys_line(
            "git@github.com",
            &["-i".to_owned(), "~/.ssh/id_gh".to_owned()],
            "ssh-ed25519 AAAASYNTHETIC synthetic-github\n",
        );
        assert!(
            line.starts_with("restrict,pty,command=\""),
            "restrict,pty per-key option set"
        );
        // The forced command runs `ssh <options> -- <dest> "$SSH_ORIGINAL_COMMAND"` (the
        // options and dest shell-quoted; the inner double quotes escaped for the
        // authorized_keys `command="…"` field). No agent, no fingerprint.
        assert!(
            line.contains("command=\"ssh '-i' '~/.ssh/id_gh' -- 'git@github.com' \\\"$SSH_ORIGINAL_COMMAND\\\"\""),
            "got {line}"
        );
        assert!(
            line.trim_end()
                .ends_with("ssh-ed25519 AAAASYNTHETIC synthetic-github"),
            "the synthetic pubkey"
        );
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn authorized_keys_line_shell_quotes_to_prevent_breakout() {
        // An option carrying a single quote / shell metacharacters is single-quoted, so it
        // cannot break out of the forced command (operator-signed, but defence in depth).
        let line = authorized_keys_line(
            "evil';rm -rf ~;'@host",
            &["-o".to_owned(), "ProxyCommand=touch /tmp/x".to_owned()],
            "ssh-ed25519 AAAA k\n",
        );
        // The dangerous tokens appear only inside single quotes; no bare `;` splits them.
        assert!(
            line.contains("'evil'\\'';rm -rf ~;'\\''@host'"),
            "got {line}"
        );
        assert!(
            line.contains("'-o' 'ProxyCommand=touch /tmp/x'"),
            "got {line}"
        );
    }

    #[test]
    fn generate_host_key_produces_a_usable_ed25519_key() {
        // Exercises stock ssh-keygen; skip if it is not installed.
        if Command::new("ssh-keygen")
            .arg("-?")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let dir = std::env::temp_dir().join(format!("kenneld-sshd-hostkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let key = dir.join("host_key");
        let pub_line = generate_host_key(&key).expect("generate host key");
        assert!(key.exists(), "private key written");
        assert!(
            pub_line.starts_with("ssh-ed25519 "),
            "public line: {pub_line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
