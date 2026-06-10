//! Project Kennel's layered configuration.
//!
//! No install-specific path is baked into a binary. Deployment paths (the
//! privhelper, the helper binaries, the daemon's trust store) are expressed in
//! TOML, resolved through a cascade, with compiled-in fallback defaults so a
//! host with no config files still runs.
//!
//! # Two trust levels, two files, two search paths
//!
//! * [`Deployment`] (`system.toml`) — integrity-sensitive: binary locations and
//!   the daemon's signing-key trust store. Resolved from **root-owned** dirs
//!   only — `/usr/lib/kennel` (vendor baseline) then `/etc/kennel` (admin) —
//!   and **never** from the user's `~/.config`. `kenneld` runs as the user, so
//!   letting the user redirect the trust store would defeat policy signing
//!   (they could trust their own key); the deployment cascade deliberately
//!   excludes any user-writable location and honours no environment override.
//! * [`User`] (`config.toml`) — conveniences for the `kennel` CLI (template and
//!   key *search* dirs). Resolved from `~/.config/kennel` then `/etc/kennel`
//!   then `/usr/lib/kennel`. Safe to be user-writable: it only steers where the
//!   CLI looks while authoring; the daemon re-verifies against the locked
//!   [`Deployment::trust_dir`] at run time.
//!
//! # Cascade semantics
//!
//! Layers are read lowest-priority first; a higher layer overrides a lower one
//! **per key** (a present value wins). Anything left unset falls back to the
//! compiled defaults ([`Deployment::trust_dir`] → `/etc/kennel/keys`, helper
//! binaries → `/usr/libexec/kennel/<name>`). The vendor `system.toml` normally
//! supplies these, so the compiled defaults are a last resort, not the contract.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

/// The vendor (package-shipped) config dir: lowest-priority layer.
const VENDOR_DIR: &str = "/usr/lib/kennel";
/// The system (admin) config dir.
const SYSTEM_DIR: &str = "/etc/kennel";
/// The deployment (integrity-sensitive) config filename.
const SYSTEM_FILE: &str = "system.toml";
/// The user-convenience config filename.
const USER_FILE: &str = "config.toml";

/// Last-resort default for the helper-binary directory (D4: the documented
/// `/usr/libexec/kennel`). The vendor `system.toml` normally sets this.
const DEFAULT_LIBEXEC_DIR: &str = "/usr/libexec/kennel";
/// Last-resort default for the daemon trust store (the system signing keys).
const DEFAULT_TRUST_DIR: &str = "/etc/kennel/keys";
/// Last-resort default for the host `sshd` the SSH bastion launches.
const DEFAULT_SSHD: &str = "/usr/sbin/sshd";

/// A config file larger than this is rejected unread (defensive bound, §10).
const MAX_CONFIG: u64 = 256 * 1024;

/// A failure loading or parsing a config layer.
#[derive(Debug)]
pub enum ConfigError {
    /// The file existed but could not be read (not counting "not found", which
    /// is a skipped layer, not an error).
    Read {
        /// The offending path.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was larger than the `MAX_CONFIG` size bound.
    TooLarge {
        /// The offending path.
        path: PathBuf,
        /// Its size in bytes.
        size: u64,
    },
    /// The file did not parse as the expected TOML schema.
    Parse {
        /// The offending path.
        path: PathBuf,
        /// The parser's message.
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::TooLarge { path, size } => {
                write!(f, "{} is too large ({size} bytes)", path.display())
            }
            Self::Parse { path, message } => write!(f, "parsing {}: {message}", path.display()),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::TooLarge { .. } | Self::Parse { .. } => None,
        }
    }
}

/// Read and parse one config file, or `Ok(None)` if it does not exist.
fn read_layer<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, ConfigError> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if meta.len() > MAX_CONFIG {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            size: meta.len(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    basic_toml::from_str(&text)
        .map(Some)
        .map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

/// The user's config dir (`$XDG_CONFIG_HOME/kennel`, else `$HOME/.config/kennel`),
/// or `None` if neither is set.
fn user_config_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("kennel"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/kennel"))
}

// ---- Deployment config -----------------------------------------------------

/// The raw, all-optional `system.toml` schema (one parsed layer).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeployment {
    libexec_dir: Option<PathBuf>,
    trust_dir: Option<PathBuf>,
    sshd: Option<PathBuf>,
    privhelper: Option<PathBuf>,
    netproxy: Option<PathBuf>,
    ssh_reorigin: Option<PathBuf>,
    ssh_connect: Option<PathBuf>,
    akc: Option<PathBuf>,
    afunix_shim: Option<PathBuf>,
    netshim: Option<PathBuf>,
    init: Option<PathBuf>,
}

impl RawDeployment {
    /// Overlay `higher` onto `self` per key (a present value in `higher` wins).
    fn overlay(self, higher: Self) -> Self {
        Self {
            libexec_dir: higher.libexec_dir.or(self.libexec_dir),
            trust_dir: higher.trust_dir.or(self.trust_dir),
            sshd: higher.sshd.or(self.sshd),
            privhelper: higher.privhelper.or(self.privhelper),
            netproxy: higher.netproxy.or(self.netproxy),
            ssh_reorigin: higher.ssh_reorigin.or(self.ssh_reorigin),
            ssh_connect: higher.ssh_connect.or(self.ssh_connect),
            akc: higher.akc.or(self.akc),
            afunix_shim: higher.afunix_shim.or(self.afunix_shim),
            netshim: higher.netshim.or(self.netshim),
            init: higher.init.or(self.init),
        }
    }

    /// Apply compiled defaults to produce a resolved [`Deployment`].
    fn resolve(self) -> Deployment {
        Deployment {
            libexec_dir: self
                .libexec_dir
                .unwrap_or_else(|| PathBuf::from(DEFAULT_LIBEXEC_DIR)),
            trust_dir: self
                .trust_dir
                .unwrap_or_else(|| PathBuf::from(DEFAULT_TRUST_DIR)),
            sshd: self.sshd.unwrap_or_else(|| PathBuf::from(DEFAULT_SSHD)),
            privhelper: self.privhelper,
            netproxy: self.netproxy,
            ssh_reorigin: self.ssh_reorigin,
            ssh_connect: self.ssh_connect,
            akc: self.akc,
            afunix_shim: self.afunix_shim,
            netshim: self.netshim,
            init: self.init,
        }
    }
}

/// Resolved deployment paths. Helper binaries default to
/// `<libexec_dir>/<name>` unless explicitly overridden.
#[derive(Debug, Clone)]
pub struct Deployment {
    libexec_dir: PathBuf,
    trust_dir: PathBuf,
    sshd: PathBuf,
    privhelper: Option<PathBuf>,
    netproxy: Option<PathBuf>,
    ssh_reorigin: Option<PathBuf>,
    ssh_connect: Option<PathBuf>,
    akc: Option<PathBuf>,
    afunix_shim: Option<PathBuf>,
    netshim: Option<PathBuf>,
    init: Option<PathBuf>,
}

impl Deployment {
    /// Resolve from the root-owned cascade: `/usr/lib/kennel` then `/etc/kennel`.
    ///
    /// Deliberately consults no user-writable location and no environment
    /// override (see the module docs): the daemon runs as the user, so these
    /// keys must come only from dirs the user cannot write.
    ///
    /// # Errors
    /// [`ConfigError`] if a present layer is unreadable, oversized, or malformed.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_dirs(&[PathBuf::from(VENDOR_DIR), PathBuf::from(SYSTEM_DIR)])
    }

    /// Resolve from explicit dirs, **lowest-priority first** (tests, relocation).
    /// Each dir is searched for `system.toml`; missing files are skipped.
    ///
    /// # Errors
    /// [`ConfigError`] if a present layer is unreadable, oversized, or malformed.
    pub fn load_from_dirs(dirs: &[PathBuf]) -> Result<Self, ConfigError> {
        let mut raw = RawDeployment::default();
        for dir in dirs {
            if let Some(layer) = read_layer::<RawDeployment>(&dir.join(SYSTEM_FILE))? {
                raw = raw.overlay(layer);
            }
        }
        Ok(raw.resolve())
    }

    /// The compiled defaults, with no config files consulted.
    #[must_use]
    pub fn defaults() -> Self {
        RawDeployment::default().resolve()
    }

    /// The helper-binary directory.
    #[must_use]
    pub fn libexec_dir(&self) -> &Path {
        &self.libexec_dir
    }

    /// The daemon's signing-key trust store.
    #[must_use]
    pub fn trust_dir(&self) -> &Path {
        &self.trust_dir
    }

    /// The host `sshd` the SSH bastion launches.
    #[must_use]
    pub fn sshd(&self) -> &Path {
        &self.sshd
    }

    /// The setuid privhelper.
    #[must_use]
    pub fn privhelper(&self) -> PathBuf {
        self.resolve_bin(self.privhelper.as_deref(), "kennel-privhelper")
    }

    /// The per-kennel egress proxy.
    #[must_use]
    pub fn netproxy(&self) -> PathBuf {
        self.resolve_bin(self.netproxy.as_deref(), "kennel-netproxy")
    }

    /// The SSH bastion's forced-command re-originator.
    #[must_use]
    pub fn ssh_reorigin(&self) -> PathBuf {
        self.resolve_bin(self.ssh_reorigin.as_deref(), "kennel-ssh-reorigin")
    }

    /// The in-kennel SOCKS connector the bastion's `ProxyCommand` invokes.
    #[must_use]
    pub fn ssh_connect(&self) -> PathBuf {
        self.resolve_bin(self.ssh_connect.as_deref(), "kennel-ssh-connect")
    }

    /// The bastion's root-owned `AuthorizedKeysCommand`.
    #[must_use]
    pub fn akc(&self) -> PathBuf {
        self.resolve_bin(self.akc.as_deref(), "kennel-akc")
    }

    /// The in-kennel `AF_UNIX` proxy bound into the view and launched by the seal to
    /// broker granted sockets through the binder facade (`07-1` §7.1.5).
    #[must_use]
    pub fn afunix_shim(&self) -> PathBuf {
        self.resolve_bin(self.afunix_shim.as_deref(), "kennel-afunix-shim")
    }

    /// The in-kennel SOCKS5 egress shim bound into the view and launched by the seal: it
    /// brokers each outbound connect to node 0 as a `CONNECT_INET` transaction (`07-5` §7.5).
    #[must_use]
    pub fn netshim(&self) -> PathBuf {
        self.resolve_bin(self.netshim.as_deref(), "kennel-netshim")
    }

    /// The trusted root-owned `kennel-init` the privhelper factory `fexecve`s as the
    /// kennel's uid-0 PID 1 (`07-2`).
    #[must_use]
    pub fn kennel_init(&self) -> PathBuf {
        self.resolve_bin(self.init.as_deref(), "kennel-init")
    }

    /// An explicit override, else `<libexec_dir>/<name>`.
    fn resolve_bin(&self, override_path: Option<&Path>, name: &str) -> PathBuf {
        override_path.map_or_else(|| self.libexec_dir.join(name), Path::to_path_buf)
    }
}

// ---- User config -----------------------------------------------------------

/// The raw, all-optional `config.toml` schema (one parsed layer).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
// The `_dirs` suffix is the TOML key (`template_dirs` etc.), not noise to strip.
#[allow(clippy::struct_field_names)]
struct RawUser {
    template_dirs: Option<Vec<PathBuf>>,
    key_dirs: Option<Vec<PathBuf>>,
    policy_dirs: Option<Vec<PathBuf>>,
}

impl RawUser {
    fn overlay(self, higher: Self) -> Self {
        Self {
            template_dirs: higher.template_dirs.or(self.template_dirs),
            key_dirs: higher.key_dirs.or(self.key_dirs),
            policy_dirs: higher.policy_dirs.or(self.policy_dirs),
        }
    }
}

/// Resolved user conveniences for the `kennel` CLI.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_field_names)] // `_dirs` is the field's meaning, not a shared noise suffix.
pub struct User {
    template_dirs: Option<Vec<PathBuf>>,
    key_dirs: Option<Vec<PathBuf>>,
    policy_dirs: Option<Vec<PathBuf>>,
}

impl User {
    /// Resolve from the cascade: vendor, then system, then the user's config dir
    /// (`$XDG_CONFIG_HOME/kennel` or `$HOME/.config/kennel`).
    ///
    /// # Errors
    /// [`ConfigError`] if a present layer is unreadable, oversized, or malformed.
    pub fn load() -> Result<Self, ConfigError> {
        let mut dirs = vec![PathBuf::from(VENDOR_DIR), PathBuf::from(SYSTEM_DIR)];
        if let Some(user) = user_config_dir() {
            dirs.push(user);
        }
        Self::load_from_dirs(&dirs)
    }

    /// Resolve from explicit dirs, **lowest-priority first** (tests).
    ///
    /// # Errors
    /// [`ConfigError`] if a present layer is unreadable, oversized, or malformed.
    pub fn load_from_dirs(dirs: &[PathBuf]) -> Result<Self, ConfigError> {
        let mut raw = RawUser::default();
        for dir in dirs {
            if let Some(layer) = read_layer::<RawUser>(&dir.join(USER_FILE))? {
                raw = raw.overlay(layer);
            }
        }
        Ok(Self {
            template_dirs: raw.template_dirs,
            key_dirs: raw.key_dirs,
            policy_dirs: raw.policy_dirs,
        })
    }

    /// Template search dirs: the configured list, else the built-in default
    /// (`<user-config>/templates`, `/etc/kennel/templates`, `/usr/lib/kennel/templates`).
    #[must_use]
    pub fn template_dirs(&self) -> Vec<PathBuf> {
        self.template_dirs
            .clone()
            .unwrap_or_else(|| default_search_dirs("templates"))
    }

    /// Key search dirs (all layers): the configured list, else the built-in default
    /// (`<user-config>/keys`, `/etc/kennel/keys`, `/usr/lib/kennel/keys`). Used to
    /// verify artefacts a user may legitimately sign (run policies), so it includes
    /// the user's own keys — unlike [`Self::system_key_dirs`].
    #[must_use]
    pub fn key_dirs(&self) -> Vec<PathBuf> {
        self.key_dirs
            .clone()
            .unwrap_or_else(|| default_search_dirs("keys"))
    }

    /// **System-only** key search dirs (`/etc/kennel/keys`, `/usr/lib/kennel/keys`) —
    /// the user's `~/.config/kennel/keys` is deliberately excluded. Templates (the
    /// security baseline) must be signed by a system/vendor key; a user key may not
    /// sign a template. Honours a configured `key_dirs` only for its non-user entries.
    #[must_use]
    pub fn system_key_dirs(&self) -> Vec<PathBuf> {
        self.key_dirs
            .as_ref()
            .map_or_else(|| system_search_dirs("keys"), Clone::clone)
    }

    /// Policy search dirs (all layers): the configured list, else the built-in default
    /// (`<user-config>/policies`, `/etc/kennel/policies`, `/usr/lib/kennel/policies`).
    /// Where `kennel run` resolves a policy named (not pathed) on the command line.
    #[must_use]
    pub fn policy_dirs(&self) -> Vec<PathBuf> {
        self.policy_dirs
            .clone()
            .unwrap_or_else(|| default_search_dirs("policies"))
    }
}

/// The built-in CLI search-dir default for `leaf` (`templates`/`keys`/`policies`):
/// the user config dir first, then the system dir, then the vendor dir (highest
/// priority first).
fn default_search_dirs(leaf: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(user) = user_config_dir() {
        dirs.push(user.join(leaf));
    }
    dirs.extend(system_search_dirs(leaf));
    dirs
}

/// The system (root-owned) search dirs for `leaf`: `/etc/kennel/<leaf>` then the
/// vendor `/usr/lib/kennel/<leaf>`. No user layer — the trust baseline for templates.
fn system_search_dirs(leaf: &str) -> Vec<PathBuf> {
    vec![
        PathBuf::from(SYSTEM_DIR).join(leaf),
        PathBuf::from(VENDOR_DIR).join(leaf),
    ]
}

/// The calling user's signing-key dir, or `None` if neither env var is set.
///
/// `$XDG_CONFIG_HOME/kennel/keys`, else `$HOME/.config/kennel/keys`. The daemon adds
/// this to its **settled-policy** trust store so a user can run a policy signed with
/// their own key (the trust split, `07-paths`); it is **not** consulted for template
/// trust.
#[must_use]
pub fn user_key_dir() -> Option<PathBuf> {
    user_config_dir().map(|d| d.join("keys"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write config");
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kennel-config-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn defaults_are_the_documented_paths() {
        let d = Deployment::defaults();
        assert_eq!(d.trust_dir(), Path::new("/etc/kennel/keys"));
        assert_eq!(
            d.privhelper(),
            Path::new("/usr/libexec/kennel/kennel-privhelper")
        );
        assert_eq!(
            d.netproxy(),
            Path::new("/usr/libexec/kennel/kennel-netproxy")
        );
        assert_eq!(d.akc(), Path::new("/usr/libexec/kennel/kennel-akc"));
        assert_eq!(d.sshd(), Path::new("/usr/sbin/sshd"));
    }

    #[test]
    fn higher_layer_overrides_per_key() {
        let vendor = tmp("vendor");
        let system = tmp("system");
        // Vendor sets libexec_dir; system overrides only the trust dir.
        write(&vendor, SYSTEM_FILE, "libexec_dir = \"/vendor/libexec\"\n");
        write(
            &system,
            SYSTEM_FILE,
            "trust_dir = \"/etc/kennel/admin-keys\"\n",
        );
        let d = Deployment::load_from_dirs(&[vendor, system]).expect("load");
        // system override wins for trust_dir...
        assert_eq!(d.trust_dir(), Path::new("/etc/kennel/admin-keys"));
        // ...vendor's libexec_dir survives and drives binary resolution...
        assert_eq!(
            d.privhelper(),
            Path::new("/vendor/libexec/kennel-privhelper")
        );
        // ...and unset keys fall back to compiled defaults.
        assert_eq!(d.sshd(), Path::new("/usr/sbin/sshd"));
    }

    #[test]
    fn explicit_binary_override_beats_libexec_dir() {
        let system = tmp("override");
        write(
            &system,
            SYSTEM_FILE,
            "libexec_dir = \"/opt/k/libexec\"\nnetproxy = \"/custom/np\"\n",
        );
        let d = Deployment::load_from_dirs(&[system]).expect("load");
        assert_eq!(d.netproxy(), Path::new("/custom/np"));
        assert_eq!(
            d.privhelper(),
            Path::new("/opt/k/libexec/kennel-privhelper")
        );
    }

    #[test]
    fn missing_files_yield_defaults() {
        let empty = tmp("empty");
        let d = Deployment::load_from_dirs(&[empty]).expect("load");
        assert_eq!(d.trust_dir(), Path::new("/etc/kennel/keys"));
    }

    #[test]
    fn unknown_key_is_rejected() {
        let bad = tmp("bad");
        write(&bad, SYSTEM_FILE, "trust_dir = \"/x\"\nbogus = 1\n");
        let err = Deployment::load_from_dirs(&[bad]).expect_err("must reject unknown key");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn user_config_replaces_search_dirs() {
        let user = tmp("user");
        write(&user, USER_FILE, "template_dirs = [\"/srv/templates\"]\n");
        let u = User::load_from_dirs(&[user]).expect("load");
        assert_eq!(u.template_dirs(), vec![PathBuf::from("/srv/templates")]);
    }

    #[test]
    fn default_search_dirs_are_three_layer() {
        // The vendor layer is always present; the user layer is present iff a config
        // dir resolves. The last two are the system + vendor dirs in priority order.
        let dirs = default_search_dirs("policies");
        let tail = dirs
            .get(dirs.len().saturating_sub(2)..)
            .expect("at least the two system layers");
        assert_eq!(
            tail,
            [
                PathBuf::from("/etc/kennel/policies"),
                PathBuf::from("/usr/lib/kennel/policies"),
            ]
        );
    }

    #[test]
    fn system_key_dirs_exclude_the_user_layer() {
        // Templates verify only against system/vendor keys — never ~/.config.
        let u = User::default();
        assert_eq!(
            u.system_key_dirs(),
            vec![
                PathBuf::from("/etc/kennel/keys"),
                PathBuf::from("/usr/lib/kennel/keys"),
            ]
        );
        // The all-layers key_dirs always contains the system store too (plus, when a
        // config dir resolves, the user layer that system_key_dirs omits).
        assert!(u.key_dirs().contains(&PathBuf::from("/etc/kennel/keys")));
        assert!(u
            .key_dirs()
            .contains(&PathBuf::from("/usr/lib/kennel/keys")));
    }

    #[test]
    fn user_key_override_drives_system_key_dirs() {
        // An explicit key_dirs override is honoured even for the system-only view
        // (an operator pointing trust at an org key dir).
        let user = tmp("keyoverride");
        write(&user, USER_FILE, "key_dirs = [\"/org/keys\"]\n");
        let u = User::load_from_dirs(&[user]).expect("load");
        assert_eq!(u.system_key_dirs(), vec![PathBuf::from("/org/keys")]);
    }
}
