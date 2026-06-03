//! The per-kennel SSH re-origination bastion (`kennel-sshd`): config and launch.
//!
//! Per-kennel SSH leaves the kennel only through a managed instance of stock
//! OpenSSH `sshd` (`docs/design/07-8-ssh.md` §7.8). It holds no keys; it is a
//! forced-command router. `kenneld` owns its lifecycle and key state, exactly as it
//! owns the egress proxy (`proxy.rs`): this module writes the hardened `sshd_config`
//! and the per-key forced-command `authorized_keys` lines from the resolved `[ssh]`
//! policy, and launches the daemon as a per-user child.
//!
//! # The lockdown (§7.8.6)
//!
//! The generated config denies everything but a publickey login that runs the forced
//! command with a pty: no password/kbd-interactive, no TCP/X11/agent forwarding, no
//! tunnels, `PermitOpen none`, and SFTP wired to `/bin/false`. Combined with the
//! per-key `restrict,pty` option set, SFTP/scp/port-forwarding are out of scope by
//! construction for the first cut. `ExposeAuthInfo yes` writes `$SSH_USER_AUTH` so
//! the forced command (`kennel-ssh-reorigin`) can confirm which synthetic key
//! authenticated.
//!
//! # `AuthorizedKeys` source (§7.8.7)
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
    /// The agent socket the forced command signs the *outbound* connection with —
    /// the user's host-side agent holding the granted real keys (§7.8.7). Emitted as
    /// a server-side `SetEnv SSH_AUTH_SOCK=…` so `kennel-ssh-reorigin` inherits it
    /// (sshd otherwise hands a session no agent unless forwarding, which is denied).
    /// `None` leaves it unset (the helper then finds no key and fails closed).
    pub agent_sock: Option<&'a Path>,
    /// Where authorised keys come from.
    pub auth: AuthSource,
}

/// Render the bastion's hardened `sshd_config` (§7.8.6).
#[must_use]
pub fn sshd_config(p: &SshdParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = String::from(
        "# kennel-sshd — per-kennel SSH re-origination bastion (generated, read-only).\n\
         # Denies everything but a publickey login running the forced command with a\n\
         # pty; SFTP/scp/forwarding are out of scope by construction (07-8-ssh.md §7.8.6).\n",
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
    // Hand the forced command the host-side agent that holds the real keys, so the
    // outbound ssh can sign — sshd gives a session no agent otherwise (forwarding is
    // denied). Server-side SetEnv, not anything the kennel client can influence.
    if let Some(sock) = p.agent_sock {
        let _ = writeln!(s, "SetEnv SSH_AUTH_SOCK={}", sock.display());
    }
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
    // Lock the session down to the forced command + a pty (§7.8.6).
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

/// Build one `authorized_keys` line binding `synthetic_pubkey` to a forced command
/// that re-originates to `dest` with the real key `real_fp` (§7.8.3).
///
/// `restrict,pty` is the per-key option set: it denies forwarding/X11/agent/user-rc
/// while keeping a tty. The destination and real-key fingerprint are baked in, so the
/// workload — holding only the synthetic private key — can reach exactly this one
/// `(host, key)` edge and cannot redirect the command.
///
/// `synthetic_pubkey` is one whitespace-normalised public-key line (`ssh-ed25519
/// AAAA… [comment]`); `reorigin_bin` is the absolute path to `kennel-ssh-reorigin`.
/// `dest` and `real_fp` MUST already be policy-validated (`kennel_policy::ssh`); they
/// are emitted verbatim inside the quoted command.
#[must_use]
pub fn authorized_keys_line(
    reorigin_bin: &Path,
    dest: &str,
    real_fp: &str,
    synthetic_pubkey: &str,
) -> String {
    format!(
        "restrict,pty,command=\"{bin} --dest {dest} --key {key}\" {pubkey}\n",
        bin = reorigin_bin.display(),
        dest = dest,
        key = real_fp,
        pubkey = synthetic_pubkey.trim(),
    )
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
            agent_sock: Some(Path::new("/run/user/1000/kennel-ssh-agent.sock")),
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
            c.contains("SetEnv SSH_AUTH_SOCK=/run/user/1000/kennel-ssh-agent.sock"),
            "agent reaches the forced command"
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
    fn authorized_keys_line_bakes_in_dest_and_key_with_restrict_pty() {
        let line = authorized_keys_line(
            Path::new("/opt/kennel/bin/kennel-ssh-reorigin"),
            "github.com",
            "SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt",
            "ssh-ed25519 AAAASYNTHETIC synthetic-github\n",
        );
        assert!(
            line.starts_with("restrict,pty,command=\""),
            "restrict,pty per-key option set"
        );
        assert!(line.contains("--dest github.com"), "destination baked in");
        assert!(line.contains("--key SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt"));
        assert!(
            line.trim_end()
                .ends_with("ssh-ed25519 AAAASYNTHETIC synthetic-github"),
            "the synthetic pubkey"
        );
        assert!(line.ends_with('\n'));
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
