//! The per-kennel SSH re-origination bastion (`kennel-sshd`): config and launch.
//!
//! Per-kennel SSH leaves the kennel only through a managed instance of stock
//! OpenSSH `sshd` (Kennel book Vol 2 ch.10 (Cryptographic Services)). It holds no keys; it is a
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

/// The leaf filename of the surfaced bastion `sshd_config` template in the root-owned cascade.
pub const SSHD_CONFIG_LEAF: &str = "kennel-sshd.conf";

/// The compiled-in default bastion `sshd_config` template — byte-identical to the vendor file
/// `install.sh` ships (`dist/kennel-sshd.conf` → `/usr/lib/kennel/kennel-sshd.conf`), so the daemon
/// renders the same hardened config even before anything is installed. The cascade override
/// (`/etc/kennel/...` then `/usr/lib/kennel/...`) takes precedence when present.
const DEFAULT_SSHD_TEMPLATE: &str = include_str!("../../../../dist/kennel-sshd.conf");

/// Render the bastion's hardened `sshd_config` (§7.10.6) from the surfaced template.
///
/// The template is resolved from the **root-owned** cascade — `/etc/kennel/kennel-sshd.conf` (admin
/// override) over `/usr/lib/kennel/kennel-sshd.conf` (vendor) — with the compiled-in default as the
/// fallback. There is no user layer: the lockdown must not be weakenable by an unprivileged
/// workload (it reads a root-owned file or the baked-in default; it cannot write `/etc/kennel`). The
/// per-bastion values are substituted into the template's `@PLACEHOLDER@` lines.
#[must_use]
pub fn sshd_config(p: &SshdParams<'_>) -> String {
    let template = kennel_lib_config::read_system_config(SSHD_CONFIG_LEAF)
        .unwrap_or_else(|| DEFAULT_SSHD_TEMPLATE.to_owned());
    render_sshd_config(&template, p)
}

/// Substitute the per-bastion values into a resolved `sshd_config` template. Pure (testable); the
/// substituted values are kenneld-derived (loopback address, port, runtime-dir paths, the AKC),
/// never workload input, so a placeholder cannot be forged from the kennel.
#[must_use]
fn render_sshd_config(template: &str, p: &SshdParams<'_>) -> String {
    let auth = match &p.auth {
        AuthSource::File(path) => format!("AuthorizedKeysFile {}", path.display()),
        // Hand the helper the offered key as `%t %k` (type + base64 blob); it asks kenneld for that
        // key's forced-command line. The helper is root-owned (the safe-path finding).
        AuthSource::Command { command, user } => format!(
            "AuthorizedKeysFile none\nAuthorizedKeysCommand {} %t %k\nAuthorizedKeysCommandUser {user}",
            command.display(),
        ),
    };
    template
        .replace("@LISTEN@", &p.listen.to_string())
        .replace("@PORT@", &p.port.to_string())
        .replace("@HOST_KEY@", &p.host_key.display().to_string())
        .replace("@PID_FILE@", &p.pid_file.display().to_string())
        .replace("@AUTHORIZED_KEYS@", &auth)
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
    fn render_uses_the_surfaced_template_verbatim() {
        // The config is the TEMPLATE's, not hardcoded: an admin override (a different cascade file)
        // renders as written, with only the @PLACEHOLDER@ lines substituted.
        let custom = "Port @PORT@\nListenAddress @LISTEN@\nHostKey @HOST_KEY@\n\
                      PidFile @PID_FILE@\n@AUTHORIZED_KEYS@\n# admin tuned: MaxStartups 3\n";
        let out = render_sshd_config(
            custom,
            &params(AuthSource::File(PathBuf::from("/safe/keys"))),
        );
        assert_eq!(
            out,
            "Port 7022\nListenAddress 127.0.42.1\nHostKey /run/kennel/bastion/host_key\n\
             PidFile /run/kennel/bastion/sshd.pid\nAuthorizedKeysFile /safe/keys\n\
             # admin tuned: MaxStartups 3\n"
        );
    }

    #[test]
    fn compiled_default_template_is_the_shipped_vendor_file() {
        // The fallback baked into the daemon is byte-identical to dist/kennel-sshd.conf (what
        // install.sh ships to the vendor dir), so the surfaced file is the single source of truth.
        assert_eq!(
            DEFAULT_SSHD_TEMPLATE,
            include_str!("../../../../dist/kennel-sshd.conf")
        );
        // It is a real template (carries the placeholders the renderer fills).
        for ph in [
            "@LISTEN@",
            "@PORT@",
            "@HOST_KEY@",
            "@PID_FILE@",
            "@AUTHORIZED_KEYS@",
        ] {
            assert!(DEFAULT_SSHD_TEMPLATE.contains(ph), "template needs {ph}");
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
