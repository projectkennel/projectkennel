//! A kennel's synthetic `~/.ssh`: the re-origination bastion's client view.
//!
//! Per-kennel SSH leaves the kennel only through the re-origination bastion
//! (`kennel-sshd`, `docs/design/07-10-ssh.md` §7.10). A confined workload that runs
//! `git push` or `ssh -T git@github.com` needs a `~/.ssh` for the stock client to
//! read — but it must contain **nothing real**: not the user's keys, not their
//! `config`, not their `known_hosts`. This module renders the synthetic substitute
//! (§7.10.5):
//!
//! - `config` — one stanza per granted host, every one routing `HostName` to the
//!   bastion endpoint with `HostKeyAlias kennel-bastion`, the matching disposable
//!   synthetic key as the sole `IdentityFile` (`IdentitiesOnly yes`), and
//!   `StrictHostKeyChecking yes`. The destination the workload types selects which
//!   synthetic key authenticates; the bastion's forced command — keyed to that
//!   synthetic key — fixes the real destination (§7.10.3). The config leaks nothing:
//!   it is derived entirely from already-granted policy.
//! - `known_hosts` — only the bastion's host key, under the alias `kennel-bastion`.
//!   Every granted host verifies against this one pin; a real host's key never
//!   appears (the kennel never talks to a real host directly).
//!
//! The disposable synthetic private keys themselves are minted by `kenneld` (stock
//! `ssh-keygen`, so the on-disk format is exactly what the client expects) into the
//! same directory before [`materialize`] runs; this module renders the two text
//! files, fixes the `0700`/`0600` modes, and returns the binds. Rendering is pure
//! and unit-tested.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The `HostKeyAlias` the bastion's host key is pinned under.
///
/// Every generated `config` stanza verifies against this one alias in the synthetic
/// `known_hosts`: a single host-key pin backs every granted destination, because the
/// kennel only ever connects to the bastion.
pub const BASTION_ALIAS: &str = "kennel-bastion";

/// The generated text files this module renders into `~/.ssh`.
pub const FILES: &[&str] = &["config", "known_hosts"];

/// One granted `(host, synthetic-key)` edge the kennel may reach.
#[derive(Debug, Clone)]
pub struct HostGrant<'a> {
    /// The destination hostname as the workload names it (`ssh github.com`).
    pub host: &'a str,
    /// The synthetic private-key filename within `~/.ssh` (e.g. `id_github.com`),
    /// minted by `kenneld` and referenced as this stanza's sole `IdentityFile`.
    pub key_file: &'a str,
}

/// What the synthetic `~/.ssh` is rendered from: the bastion endpoint, its host
/// key, the granted host edges, and how the kennel's `ssh` reaches the proxy.
#[derive(Debug, Clone)]
pub struct SshParams<'a> {
    /// The bastion endpoint the kennel's `ssh` connects to — the bastion's
    /// allowlisted loopback address, which the egress proxy forwards (§7.10.4).
    pub bastion_host: &'a str,
    /// The bastion's listening port.
    pub bastion_port: u16,
    /// The bastion's public host-key line (`ssh-ed25519 AAAA…`), pinned under
    /// [`BASTION_ALIAS`] so `StrictHostKeyChecking` passes for the bastion and
    /// nothing else.
    pub bastion_host_key: &'a str,
    /// The in-kennel path of the `facade-ssh-connect` binary, used as each stanza's
    /// `ProxyCommand`: a kennel has no network path off its loopback (its own net-ns), so `ssh`
    /// reaches the bastion by an `INet` `CONNECT_INET` transaction to kenneld over binder (§7.5),
    /// receiving the connection fd and splicing it to stdin/stdout.
    pub ssh_connect_bin: &'a str,
    /// The granted host edges — one `config` stanza each. Empty means the kennel has
    /// no SSH grant: `config` is then a header-only file and no host resolves.
    pub hosts: &'a [HostGrant<'a>],
}

/// `~/.ssh/config` — one stanza per granted host, all routed to the bastion.
///
/// `~` is left literal: OpenSSH expands `IdentityFile` against the invoking user's
/// home, which inside the kennel is the constructed `$HOME` this `~/.ssh` lives in.
#[must_use]
pub fn config(p: &SshParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = String::from(
        "# Project Kennel synthetic ssh config — generated, read-only.\n\
         # Every granted host routes to the re-origination bastion; the real key is\n\
         # used host-side, and the destination is fixed by the bastion's forced\n\
         # command (docs/design/07-10-ssh.md §7.10). No other host is reachable.\n",
    );
    for h in p.hosts {
        let _ = write!(
            s,
            "\nHost {host}\n\
             \tHostName {bastion}\n\
             \tPort {port}\n\
             \tHostKeyAlias {alias}\n\
             \tProxyCommand {connect} %h %p\n\
             \tIdentityFile ~/.ssh/{key}\n\
             \tIdentitiesOnly yes\n\
             \tStrictHostKeyChecking yes\n",
            host = h.host,
            bastion = p.bastion_host,
            port = p.bastion_port,
            alias = BASTION_ALIAS,
            connect = p.ssh_connect_bin,
            key = h.key_file,
        );
    }
    s
}

/// `~/.ssh/known_hosts` — the bastion's host key, pinned under [`BASTION_ALIAS`].
///
/// Just the one line: the kennel only ever connects to the bastion (every granted
/// `config` stanza carries `HostKeyAlias kennel-bastion`), so this is the only host
/// key it needs and the only one it is allowed to trust.
#[must_use]
pub fn known_hosts(p: &SshParams<'_>) -> String {
    format!(
        "{alias} {key}\n",
        alias = BASTION_ALIAS,
        key = p.bastion_host_key.trim()
    )
}

/// Render the file named `name` (one of [`FILES`]) for `p`, or `None` for an
/// unknown name.
#[must_use]
pub fn render(name: &str, p: &SshParams<'_>) -> Option<String> {
    match name {
        "config" => Some(config(p)),
        "known_hosts" => Some(known_hosts(p)),
        _ => None,
    }
}

/// Materialise the synthetic `~/.ssh` into `dir`, returning the `(source, target)`
/// binds the spawn maps under the kennel's `<home>/.ssh`.
///
/// `dir` is the host staging directory; `ssh_dir` is the in-kennel `~/.ssh` path the
/// targets are rooted at. The disposable synthetic private keys named by
/// [`HostGrant::key_file`] must already have been minted into `dir` (by `kenneld`,
/// via `ssh-keygen`); this writes the generated `config`/`known_hosts` and clamps
/// every file to `0600` and the directory to `0700` — a permissive mode makes
/// OpenSSH refuse the key, and these hold a (disposable) private key.
///
/// # Errors
///
/// An OS error if `dir` cannot be created, a file cannot be written, a mode cannot
/// be set, or a named key file is missing from `dir`.
pub fn materialize(
    dir: &Path,
    ssh_dir: &Path,
    p: &SshParams<'_>,
) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

    let mut binds = Vec::with_capacity(FILES.len().saturating_add(p.hosts.len()));
    for name in FILES {
        let body =
            render(name, p).ok_or_else(|| io::Error::other(format!("no renderer for {name}")))?;
        let source = dir.join(name);
        std::fs::write(&source, body)?;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))?;
        binds.push((source, ssh_dir.join(name)));
    }
    // The synthetic private keys are minted into `dir` ahead of this call; bind each
    // and clamp its mode. A missing key file is a wiring bug — fail loudly.
    for h in p.hosts {
        let source = dir.join(h.key_file);
        if !source.exists() {
            return Err(io::Error::other(format!(
                "synthetic key `{}` for host `{}` was not minted into {}",
                h.key_file,
                h.host,
                dir.display()
            )));
        }
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))?;
        binds.push((source, ssh_dir.join(h.key_file)));
    }
    Ok(binds)
}

/// `ssh-keygen`'s public-key path for a private-key `path`: `<path>.pub`, appended
/// (not `Path::with_extension`, which would mangle a name like `id_github.com`).
fn pub_path_of(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf().into_os_string();
    p.push(".pub");
    PathBuf::from(p)
}

/// Mint a disposable synthetic ed25519 keypair into `dir` as `key_file` (private)
/// and `key_file.pub`, returning the public-key line (§7.10.3).
///
/// The private half goes into the kennel's constructed `~/.ssh` (this `dir`); the
/// returned public line is what the bastion binds to a forced command in its
/// `authorized_keys` (`crate::bastion`). Minting with stock `ssh-keygen` keeps the
/// on-disk format exactly what `ssh` expects and hand-rolls no key serialisation. A
/// pre-existing key at the path is removed first — these are disposable, one per
/// `(real-key, host)` edge, regenerated freely.
///
/// # Errors
///
/// An OS error if `ssh-keygen` cannot run, exits non-zero, or its `.pub` is unreadable.
pub fn mint_synthetic_key(dir: &Path, key_file: &str, comment: &str) -> io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(key_file);
    // ssh-keygen writes the public half at "<path>.pub" — append, never
    // `with_extension` (a key_file like "id_github.com" has a misleading extension).
    let pub_path = pub_path_of(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&pub_path);
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "ssh-keygen failed to mint synthetic key `{key_file}`"
        )));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(std::fs::read_to_string(&pub_path)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SshParams<'static> {
        SshParams {
            bastion_host: "127.0.42.1",
            bastion_port: 7022,
            bastion_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestbastionhostkey",
            ssh_connect_bin: "/opt/kennel/bin/facade-ssh-connect",
            hosts: &[
                HostGrant {
                    host: "github.com",
                    key_file: "id_github.com",
                },
                HostGrant {
                    host: "git.internal",
                    key_file: "id_git.internal",
                },
            ],
        }
    }

    #[test]
    fn config_routes_every_granted_host_to_the_bastion() {
        let c = config(&params());
        assert!(c.contains("Host github.com\n"), "github stanza present");
        assert!(c.contains("Host git.internal\n"), "internal stanza present");
        assert!(
            c.contains("HostName 127.0.42.1"),
            "routed to the bastion host"
        );
        assert!(c.contains("Port 7022"), "routed to the bastion port");
        // Each stanza pins the alias, its own synthetic key, and locks the client down.
        assert_eq!(c.matches("HostKeyAlias kennel-bastion").count(), 2);
        // Each stanza routes through the binder dialer (the kennel's only path off its loopback).
        assert_eq!(
            c.matches("ProxyCommand /opt/kennel/bin/facade-ssh-connect %h %p")
                .count(),
            2
        );
        assert!(c.contains("IdentityFile ~/.ssh/id_github.com"));
        assert!(c.contains("IdentityFile ~/.ssh/id_git.internal"));
        assert_eq!(c.matches("IdentitiesOnly yes").count(), 2);
        assert_eq!(c.matches("StrictHostKeyChecking yes").count(), 2);
    }

    #[test]
    fn no_grant_yields_a_header_only_config_with_no_routes() {
        let p = SshParams {
            hosts: &[],
            ..params()
        };
        let c = config(&p);
        assert!(!c.contains("Host "), "no host stanza: {c}");
        assert!(
            c.starts_with("# Project Kennel"),
            "still a valid, commented file"
        );
    }

    #[test]
    fn known_hosts_pins_only_the_bastion_under_the_alias() {
        let kh = known_hosts(&params());
        assert_eq!(
            kh,
            "kennel-bastion ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestbastionhostkey\n"
        );
        // No real hostname ever appears — the kennel trusts only the bastion.
        assert!(!kh.contains("github"), "no real host key leaked");
    }

    #[test]
    fn render_is_none_for_an_unknown_file() {
        assert!(render("authorized_keys", &params()).is_none());
        assert!(render("id_rsa", &params()).is_none());
    }

    #[test]
    fn materialize_writes_text_files_clamps_modes_and_binds_keys() {
        let dir = std::env::temp_dir().join(format!("kenneld-ssh-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk dir");
        // Pretend kenneld already minted the two synthetic keys.
        for kf in ["id_github.com", "id_git.internal"] {
            std::fs::write(dir.join(kf), b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
                .expect("mint");
            std::fs::set_permissions(dir.join(kf), std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }

        let ssh_dir = Path::new("/home/dev/.ssh");
        let binds = materialize(&dir, ssh_dir, &params()).expect("materialize");

        // config + known_hosts + 2 keys.
        assert_eq!(binds.len(), 4);
        let dir_mode = std::fs::metadata(&dir)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the ~/.ssh dir is private");
        for (source, target) in &binds {
            assert!(source.exists(), "{} written", source.display());
            assert!(
                target.starts_with(ssh_dir),
                "target under ~/.ssh: {}",
                target.display()
            );
            let mode = std::fs::metadata(source)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{} clamped to 0600 (even the pre-minted key)",
                source.display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mint_synthetic_key_writes_a_private_key_and_returns_its_public_line() {
        if Command::new("ssh-keygen")
            .arg("-?")
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            return; // ssh-keygen not installed
        }
        let dir = std::env::temp_dir().join(format!("kenneld-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pub_line =
            mint_synthetic_key(&dir, "id_github.com", "kennel synthetic github").expect("mint");
        assert!(
            pub_line.starts_with("ssh-ed25519 "),
            "public line: {pub_line}"
        );
        let priv_path = dir.join("id_github.com");
        assert!(priv_path.exists(), "private key written");
        let mode = std::fs::metadata(&priv_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "private key is 0600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn materialize_fails_loudly_if_a_synthetic_key_is_missing() {
        let dir = std::env::temp_dir().join(format!("kenneld-ssh-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // No keys minted — materialize must refuse rather than bind a nonexistent key.
        let err =
            materialize(&dir, Path::new("/home/dev/.ssh"), &params()).expect_err("missing key");
        assert!(err.to_string().contains("was not minted"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
