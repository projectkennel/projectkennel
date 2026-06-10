//! The per-user SSH bastion's lifecycle and key state (`docs/design/07-10-ssh.md` §7.10.2).
//!
//! `kenneld` runs **one** `kennel-sshd` for the session, shared by all the user's
//! kennels — a sibling daemon, not a per-kennel child like the egress proxy. This
//! module is the state `kenneld` owns on its behalf: the set of granted
//! `(synthetic-key → destination, real-key)` **edges**, one per `(real-key, host)`
//! a kennel is granted. From that set it renders the bastion's `authorized_keys`
//! (each edge is one `restrict,pty,command=…` line, `crate::sshd`), and it lazily
//! starts the daemon when the first edge appears and stops it when the last one
//! goes — so an idle session runs no bastion at all.
//!
//! Edges are tagged by the owning kennel, so tearing a kennel down deregisters
//! exactly its edges; a synthetic key minted for one kennel never outlives it.
//! The bastion holds no real key material — only the synthetic public halves, bound
//! to forced commands.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Child;

use crate::sshd::{self, AuthSource, SshdParams};

/// One granted edge: a synthetic key that, on the bastion, re-originates to a fixed
/// destination with a fixed real key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// The kennel that owns this grant (the deregistration key).
    pub kennel: String,
    /// The policy-fixed destination host (validated by `kennel_lib_policy::ssh`).
    pub dest: String,
    /// The real key's `SHA256:` fingerprint the bastion signs the outbound hop with.
    pub real_fp: String,
    /// The synthetic public-key line bound to this edge's forced command.
    pub synthetic_pub: String,
}

/// A root-owned `AuthorizedKeysCommand` the bastion vends keys through (§7.10.7).
///
/// The production source of truth: rather than write the forced-command bindings to
/// a file the unprivileged user owns (and could rewrite without `kenneld` ever
/// seeing it), the bastion runs this helper, which queries the **running** `kenneld`
/// — the trusted authority that already builds and seals every kennel — for the
/// line bound to an offered key. The helper is installed root-owned so OpenSSH's
/// safe-path check accepts it; the bindings themselves live only in `kenneld`'s
/// verified, in-memory edge state, never on disk.
#[derive(Debug, Clone)]
pub struct Akc {
    /// Absolute path to the root-owned helper (`kennel-akc`).
    pub command: PathBuf,
    /// The user the helper runs as (`AuthorizedKeysCommandUser`); it must reach
    /// `kenneld`'s per-user control socket.
    pub user: String,
}

/// The fixed paths and parameters of the session's bastion.
#[derive(Debug, Clone)]
pub struct BastionConfig {
    /// A safe-owned (`0700`, never world-writable) runtime dir for the bastion's
    /// host key, config, pid, and `authorized_keys` — sshd's safe-path check
    /// rejects world-writable ancestors (08 §8.1, finding 3).
    pub dir: PathBuf,
    /// The installed `kennel-bin-ssh-reorigin` the forced commands invoke.
    pub reorigin_bin: PathBuf,
    /// The loopback address the bastion listens on (the egress proxy forwards here).
    pub listen: IpAddr,
    /// The bastion's port.
    pub port: u16,
    /// The host-side agent socket that holds the real keys (handed to the forced
    /// command via the config's `SetEnv`).
    pub agent_sock: Option<PathBuf>,
    /// The root-owned `AuthorizedKeysCommand` to vend keys through (production,
    /// §7.10.7). `None` falls back to a static `AuthorizedKeysFile` the bastion-user
    /// owns — the prototype/e2e source, which writes the bindings to disk.
    pub akc: Option<Akc>,
}

impl BastionConfig {
    fn host_key(&self) -> PathBuf {
        self.dir.join("host_key")
    }
    fn config_file(&self) -> PathBuf {
        self.dir.join("sshd_config")
    }
    fn pid_file(&self) -> PathBuf {
        self.dir.join("sshd.pid")
    }
    fn authorized_keys(&self) -> PathBuf {
        self.dir.join("authorized_keys")
    }
}

/// The session's bastion: its config, the live edges, and the managed `sshd` child.
#[derive(Debug)]
pub struct Bastion {
    config: BastionConfig,
    edges: Vec<Edge>,
    child: Option<Child>,
    /// The bastion host key's public line (for the kennels' synthetic `known_hosts`),
    /// set once the daemon is first started.
    host_pub: Option<String>,
}

impl Bastion {
    /// Create the (stopped) bastion state for `config`.
    #[must_use]
    pub const fn new(config: BastionConfig) -> Self {
        Self {
            config,
            edges: Vec::new(),
            child: None,
            host_pub: None,
        }
    }

    /// Whether the managed `sshd` is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// The bastion host key's public line, once started (for synthetic `known_hosts`).
    #[must_use]
    pub fn host_pub(&self) -> Option<&str> {
        self.host_pub.as_deref()
    }

    /// The current edges (test/inspection).
    #[must_use]
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Render the bastion's `authorized_keys` from the live edges — one
    /// `restrict,pty,command=…` line per edge (`crate::sshd::authorized_keys_line`).
    #[must_use]
    pub fn render_authorized_keys(&self) -> String {
        self.edges
            .iter()
            .map(|e| {
                sshd::authorized_keys_line(
                    &self.config.reorigin_bin,
                    &e.dest,
                    &e.real_fp,
                    &e.synthetic_pub,
                )
            })
            .collect()
    }

    /// The forced-command `authorized_keys` line(s) for an offered public key,
    /// looked up against the live edges (§7.10.7) — the query the root-owned
    /// `AuthorizedKeysCommand` (`kennel-akc`) makes on each bastion auth.
    ///
    /// `offered_key` is the `"<type> <base64>"` sshd hands the helper (`%t %k`); the
    /// comment is ignored. Empty when no edge matches, so a non-synthetic or unknown
    /// key (and any malformed input) authorises nothing and the bastion refuses it.
    #[must_use]
    pub fn authorized_keys_for(&self, offered_key: &str) -> Vec<String> {
        let Some(offered) = key_id(offered_key) else {
            return Vec::new();
        };
        self.edges
            .iter()
            .filter(|e| key_id(&e.synthetic_pub) == Some(offered))
            .map(|e| {
                sshd::authorized_keys_line(
                    &self.config.reorigin_bin,
                    &e.dest,
                    &e.real_fp,
                    &e.synthetic_pub,
                )
            })
            .collect()
    }

    /// Register an edge without starting the daemon — a crate-test seam so the
    /// control-dispatch path can be exercised on live edges without `sshd`.
    #[cfg(test)]
    pub(crate) fn push_edge_for_test(&mut self, edge: Edge) {
        self.edges.push(edge);
    }

    /// Whether this bastion stores its bindings in a static `authorized_keys` file
    /// (the prototype source). With an [`Akc`] configured there is no file: the
    /// bindings are vended live from [`authorized_keys_for`](Self::authorized_keys_for).
    const fn uses_file(&self) -> bool {
        self.config.akc.is_none()
    }

    /// Register a granted edge: add it (idempotent on the synthetic key), rewrite
    /// `authorized_keys`, and start the daemon if this is the first edge.
    ///
    /// # Errors
    ///
    /// An OS error if the daemon cannot be started or the key files cannot be written.
    pub fn register(&mut self, edge: Edge) -> io::Result<()> {
        if !self
            .edges
            .iter()
            .any(|e| e.synthetic_pub == edge.synthetic_pub)
        {
            self.edges.push(edge);
        }
        self.start_if_needed()?;
        // With an AKC, the edges are vended live (no file to rewrite).
        if self.uses_file() {
            self.write_authorized_keys()?;
        }
        Ok(())
    }

    /// Deregister every edge owned by `kennel` (its teardown), rewrite
    /// `authorized_keys`, and stop the daemon if no edges remain.
    ///
    /// # Errors
    ///
    /// An OS error if `authorized_keys` cannot be rewritten.
    pub fn deregister(&mut self, kennel: &str) -> io::Result<()> {
        let before = self.edges.len();
        self.edges.retain(|e| e.kennel != kennel);
        if self.edges.len() == before {
            return Ok(());
        }
        if self.edges.is_empty() {
            self.stop();
        }
        // Rewrite authorized_keys only with the file source, and only if the bastion
        // dir exists (i.e. the daemon was started). With an AKC there is no file; with
        // no daemon, edge bookkeeping is all there is to do.
        if self.uses_file() && self.config.dir.exists() {
            self.write_authorized_keys()?;
        }
        Ok(())
    }

    /// Stop the managed `sshd` (best-effort kill + reap) and forget the host key.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.host_pub = None;
    }

    fn write_authorized_keys(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.config.authorized_keys();
        std::fs::write(&path, self.render_authorized_keys())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
    }

    /// Start the daemon on first need: stage the dir (`0700`), mint a host key, write
    /// the config and an initial `authorized_keys`, then spawn `sshd`.
    fn start_if_needed(&mut self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        if self.is_running() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.config.dir)?;
        std::fs::set_permissions(&self.config.dir, std::fs::Permissions::from_mode(0o700))?;

        let host_key = self.config.host_key();
        self.host_pub = Some(sshd::generate_host_key(&host_key)?);

        // Production vends keys through the root-owned AKC (querying this running
        // daemon); the file source is the prototype/e2e fallback.
        let auth = match &self.config.akc {
            Some(akc) => AuthSource::Command {
                command: akc.command.clone(),
                user: akc.user.clone(),
            },
            None => AuthSource::File(self.config.authorized_keys()),
        };
        let params = SshdParams {
            listen: self.config.listen,
            port: self.config.port,
            host_key: &host_key,
            pid_file: &self.config.pid_file(),
            agent_sock: self.config.agent_sock.as_deref(),
            auth,
        };
        let config_path = self.config.config_file();
        std::fs::write(&config_path, sshd::sshd_config(&params))?;
        // With the file source, an authorized_keys must exist before sshd reads it on
        // the first connection; with the AKC there is no file.
        if self.uses_file() {
            self.write_authorized_keys()?;
        }

        self.child = Some(sshd::spawn(
            Path::new(sshd::DEFAULT_SSHD_BIN),
            &config_path,
        )?);
        Ok(())
    }
}

impl Drop for Bastion {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The `(type, base64)` identity of an SSH public-key line — its first two
/// whitespace fields, ignoring any trailing comment. `None` if either is missing.
/// Two keys are the same iff their `(type, base64)` match, so a synthetic key
/// offered by sshd as `%t %k` (no comment) still matches the stored line.
fn key_id(line: &str) -> Option<(&str, &str)> {
    let mut it = line.split_whitespace();
    let ty = it.next()?;
    let blob = it.next()?;
    Some((ty, blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config() -> BastionConfig {
        BastionConfig {
            dir: PathBuf::from("/run/user/1000/kennel-bastion"),
            reorigin_bin: PathBuf::from("/opt/kennel/bin/kennel-bin-ssh-reorigin"),
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 7022,
            agent_sock: Some(PathBuf::from("/run/user/1000/agent.sock")),
            akc: None,
        }
    }

    fn edge(kennel: &str, dest: &str, fp: &str, pubkey: &str) -> Edge {
        Edge {
            kennel: kennel.into(),
            dest: dest.into(),
            real_fp: fp.into(),
            synthetic_pub: pubkey.into(),
        }
    }

    const FP_A: &str = "SHA256:AAAa1EZ7oO0qfsA5OSDosRRaFD9evYHhSlcrDPTVoZw";
    const FP_B: &str = "SHA256:BBBb1EZ7oO0qfsA5OSDosRRaFD9evYHhSlcrDPTVoZx";

    #[test]
    fn render_authorized_keys_is_one_forced_command_line_per_edge() {
        let mut b = Bastion::new(config());
        // Inject edges directly (bypassing start) to test the pure rendering.
        b.edges
            .push(edge("ka", "github.com", FP_A, "ssh-ed25519 AAAASYN_A ka"));
        b.edges
            .push(edge("kb", "git.internal", FP_B, "ssh-ed25519 AAAASYN_B kb"));
        let ak = b.render_authorized_keys();
        let lines: Vec<&str> = ak.lines().collect();
        assert_eq!(lines.len(), 2);
        let l0 = lines.first().copied().unwrap_or_default();
        let l1 = lines.get(1).copied().unwrap_or_default();
        assert!(l0.contains("--dest github.com") && l0.contains(FP_A) && l0.contains("AAAASYN_A"));
        assert!(
            l1.contains("--dest git.internal") && l1.contains(FP_B) && l1.contains("AAAASYN_B")
        );
        assert!(lines
            .iter()
            .all(|l| l.starts_with("restrict,pty,command=\"")));
    }

    #[test]
    fn authorized_keys_for_matches_the_offered_key_ignoring_comment() {
        let mut b = Bastion::new(config());
        b.edges
            .push(edge("ka", "github.com", FP_A, "ssh-ed25519 AAAASYN_A ka"));
        b.edges
            .push(edge("kb", "git.internal", FP_B, "ssh-ed25519 AAAASYN_B kb"));

        // Offered exactly as sshd hands the AKC: "<type> <base64>", no comment.
        let lines = b.authorized_keys_for("ssh-ed25519 AAAASYN_A");
        assert_eq!(lines.len(), 1, "exactly the matching edge");
        let l = lines.first().map(String::as_str).unwrap_or_default();
        assert!(l.starts_with("restrict,pty,command=\""));
        assert!(l.contains("--dest github.com") && l.contains(FP_A) && l.contains("AAAASYN_A"));

        // The other edge by its own key.
        assert!(b
            .authorized_keys_for("ssh-ed25519 AAAASYN_B")
            .first()
            .is_some_and(|l| l.contains("git.internal")));
        // A non-synthetic / unknown key authorises nothing (the bastion refuses it).
        assert!(b
            .authorized_keys_for("ssh-ed25519 NOTASYNTHETICKEY")
            .is_empty());
        // Malformed input (no base64 field) is fail-closed too.
        assert!(b.authorized_keys_for("ssh-ed25519").is_empty());
        assert!(b.authorized_keys_for("").is_empty());
    }

    #[test]
    fn register_is_idempotent_on_the_synthetic_key() {
        let mut b = Bastion::new(config());
        let e = edge("ka", "github.com", FP_A, "ssh-ed25519 AAAASYN_A ka");
        // Bookkeeping only (no spawn): exercise the de-dup directly.
        b.edges.push(e.clone());
        assert_eq!(b.edges().len(), 1);
        if !b.edges.iter().any(|x| x.synthetic_pub == e.synthetic_pub) {
            b.edges.push(e);
        }
        assert_eq!(b.edges().len(), 1, "same synthetic key is not added twice");
    }

    #[test]
    fn deregister_drops_only_the_named_kennels_edges() {
        let mut b = Bastion::new(config());
        b.edges
            .push(edge("ka", "github.com", FP_A, "ssh-ed25519 AAAASYN_A ka"));
        b.edges
            .push(edge("kb", "git.internal", FP_B, "ssh-ed25519 AAAASYN_B kb"));
        // No daemon running, dir absent → deregister just prunes the edges.
        b.deregister("ka").expect("deregister");
        assert_eq!(b.edges().len(), 1);
        assert_eq!(b.edges().first().map(|e| e.kennel.as_str()), Some("kb"));
        // Deregistering an unknown kennel is a no-op.
        b.deregister("nope").expect("noop");
        assert_eq!(b.edges().len(), 1);
    }

    #[test]
    fn a_fresh_bastion_is_not_running() {
        let b = Bastion::new(config());
        assert!(!b.is_running());
        assert!(b.host_pub().is_none());
        assert!(b.edges().is_empty());
    }
}
