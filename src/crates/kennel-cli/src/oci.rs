//! The OCI named-image store (§7.11, arch `02-9-oci.md`).
//!
//! `kennel oci build <name>` populates an operator-owned store entry; `kennel oci run <name>`
//! resolves it. The store is per-operator under the data dir (`$XDG_DATA_HOME/kennel/images`,
//! else `~/.local/share/kennel/images`) — the per-user `0700` home is the isolation boundary, so
//! there is no shared store. One entry per `<name>`:
//!
//! ```text
//! <store>/<name>/
//!   rootfs/        the unpacked image filesystem
//!   config.json    the image's runtime config (OCI image-config blob)
//!   digest         the resolved image@sha256 the build pulled from
//!   policy.toml    the scaffolded run policy (operator completes + signs)
//! ```
//!
//! `rootfs/` + `config.json` + `digest` are the integrity unit (the launcher trusts the config
//! for the entrypoint/env); `policy.toml` is outside it, signature-covered separately.

use std::path::{Path, PathBuf};

/// The store root: `$XDG_DATA_HOME/kennel/images`, else `~/.local/share/kennel/images`.
///
/// # Errors
///
/// Fails if neither `XDG_DATA_HOME` nor `HOME` is set (no resolvable data dir).
pub fn store_root() -> Result<PathBuf, String> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("kennel/images"));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "neither XDG_DATA_HOME nor HOME is set; cannot locate the image store".to_owned())?;
    Ok(PathBuf::from(home).join(".local/share/kennel/images"))
}

/// Validate a store-entry name: a single, safe path component. Rejects anything that could escape
/// the store dir (`/`, `.`, `..`, empty, control/space) so `<name>` is always one directory under
/// the store root.
///
/// # Errors
///
/// Returns a message naming the violation if `name` is not a safe single component.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("image name is empty".to_owned());
    }
    if name == "." || name == ".." {
        return Err(format!("image name `{name}` is not a valid entry"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!("image name `{name}` must be a single path component (no `/`)"));
    }
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\0')
    {
        return Err(format!("image name `{name}` contains control or whitespace characters"));
    }
    // A leading dot would hide the entry and risks colliding with dotfiles; disallow.
    if name.starts_with('.') {
        return Err(format!("image name `{name}` must not start with `.`"));
    }
    Ok(())
}

/// One named store entry. Construct via [`Store::entry`]; the paths are derived, not probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    /// The entry directory, `<store>/<name>`.
    dir: PathBuf,
}

impl StoreEntry {
    /// The entry directory `<store>/<name>`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The unpacked image rootfs (`<entry>/rootfs`).
    #[must_use]
    pub fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }

    /// The image runtime config (`<entry>/config.json`).
    #[must_use]
    pub fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    /// The recorded provenance digest (`<entry>/digest`).
    #[must_use]
    pub fn digest_path(&self) -> PathBuf {
        self.dir.join("digest")
    }

    /// The scaffolded run policy (`<entry>/policy.toml`).
    #[must_use]
    pub fn policy(&self) -> PathBuf {
        self.dir.join("policy.toml")
    }

    /// Read the recorded `image@sha256:…` digest, trimmed.
    ///
    /// # Errors
    ///
    /// Fails if the `digest` file is missing or unreadable.
    pub fn read_digest(&self) -> Result<String, String> {
        let p = self.digest_path();
        std::fs::read_to_string(&p)
            .map(|s| s.trim().to_owned())
            .map_err(|e| format!("reading {}: {e}", p.display()))
    }

    /// Record the resolved `image@sha256:…` the build pulled from.
    ///
    /// # Errors
    ///
    /// Fails if the entry directory cannot be created or the file cannot be written.
    pub fn write_digest(&self, image: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("creating {}: {e}", self.dir.display()))?;
        let p = self.digest_path();
        std::fs::write(&p, format!("{}\n", image.trim()))
            .map_err(|e| format!("writing {}: {e}", p.display()))
    }

    /// Whether the entry has been populated (the rootfs exists).
    #[must_use]
    pub fn exists(&self) -> bool {
        self.rootfs().is_dir()
    }
}

/// The image store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open the default per-operator store.
    ///
    /// # Errors
    ///
    /// Fails if no data dir is resolvable (see [`store_root`]).
    pub fn open() -> Result<Self, String> {
        Ok(Self {
            root: store_root()?,
        })
    }

    /// Open a store at an explicit root (for tests and `--store` overrides).
    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The store root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `<name>` to its entry, validating the name.
    ///
    /// # Errors
    ///
    /// Fails if `name` is not a safe single path component.
    pub fn entry(&self, name: &str) -> Result<StoreEntry, String> {
        validate_name(name)?;
        Ok(StoreEntry {
            dir: self.root.join(name),
        })
    }
}

/// Render the scaffolded run policy for a freshly built entry: the confined default plus the
/// `[rootfs]` block (path + recorded image + a `reason` the operator completes and signs).
///
/// The operator edits `reason` and signs; `kennel oci run` then verifies the signature like any
/// policy. Returned as text (the caller writes it) so this stays pure and testable.
#[must_use]
pub fn scaffold_policy(name: &str, rootfs_path: &Path, image: &str) -> String {
    format!(
        "# Scaffolded by `kennel oci build {name}`. Complete `reason`, then sign:\n\
         #   kennel policy sign {name} --key <key>\n\
         name = \"{name}\"\n\
         template_base = \"base-confined@v1\"\n\
         \n\
         [rootfs]\n\
         path   = \"{path}\"\n\
         image  = \"{image}\"\n\
         reason = \"TODO: why this image is trusted as the kennel substrate\"\n\
         \n\
         # Additive grants bind on top of the image, e.g.:\n\
         # [fs]\n\
         # write = [\"~/code/{name}/**\"]\n\
         \n\
         # No [workload]: the entrypoint comes from the image config via the launcher.\n\
         # (Add an explicit argv + sha256 to override and pin it instead.)\n",
        name = name,
        path = rootfs_path.display(),
        image = image,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_must_be_safe_single_components() {
        for bad in ["", ".", "..", "a/b", "a\\b", "/abs", ".hidden", "x\ty", "x y", "a\nb"] {
            assert!(validate_name(bad).is_err(), "`{bad}` should be rejected");
        }
        for ok in ["my-app", "app_1", "node20", "a.b.c"] {
            assert!(validate_name(ok).is_ok(), "`{ok}` should be accepted");
        }
    }

    #[test]
    fn entry_paths_are_derived_under_the_root() {
        let store = Store::at(PathBuf::from("/store"));
        let e = store.entry("my-app").expect("valid name");
        assert_eq!(e.dir(), Path::new("/store/my-app"));
        assert_eq!(e.rootfs(), Path::new("/store/my-app/rootfs"));
        assert_eq!(e.config(), Path::new("/store/my-app/config.json"));
        assert_eq!(e.digest_path(), Path::new("/store/my-app/digest"));
        assert_eq!(e.policy(), Path::new("/store/my-app/policy.toml"));
    }

    #[test]
    fn entry_rejects_a_traversing_name() {
        let store = Store::at(PathBuf::from("/store"));
        assert!(store.entry("../escape").is_err());
    }

    #[test]
    fn digest_round_trips() {
        let dir = std::env::temp_dir().join(format!("kennel-oci-test-{}", std::process::id()));
        let store = Store::at(dir.clone());
        let e = store.entry("img").expect("name");
        e.write_digest("ghcr.io/o/a@sha256:abc").expect("write");
        assert_eq!(e.read_digest().expect("read"), "ghcr.io/o/a@sha256:abc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scaffold_contains_the_loud_grant_fields() {
        let p = scaffold_policy("my-app", Path::new("/store/my-app/rootfs"), "ghcr.io/o/a@sha256:abc");
        assert!(p.contains("[rootfs]"));
        assert!(p.contains("/store/my-app/rootfs"));
        assert!(p.contains("ghcr.io/o/a@sha256:abc"));
        assert!(p.contains("reason ="));
        assert!(p.contains("name = \"my-app\""));
    }
}
