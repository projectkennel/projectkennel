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
        .ok_or_else(|| {
            "neither XDG_DATA_HOME nor HOME is set; cannot locate the image store".to_owned()
        })?;
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
        return Err(format!(
            "image name `{name}` must be a single path component (no `/`)"
        ));
    }
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\0')
    {
        return Err(format!(
            "image name `{name}` contains control or whitespace characters"
        ));
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
    // Read by the daemon launcher binding (bound at `/run/kennel/oci-config.json`); part of the
    // store-layout contract today, consumed once that wiring lands.
    #[allow(dead_code)]
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
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("creating {}: {e}", self.dir.display()))?;
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
    #[allow(dead_code)] // test + future `--store`; the production path uses `open()`
    #[must_use]
    pub const fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The store root directory.
    #[allow(dead_code)] // store-API surface; not yet read on the production path
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
         # persistence = \"discard\"  # discard (default) | readonly | persist\n\
         \n\
         # Additive grants bind on top of the image, e.g.:\n\
         # [fs]\n\
         # write = [\"~/code/{name}/**\"]\n\
         \n\
         # Entrypoint comes from the image config via the launcher.\n\
         # [workload] is not valid in an OCI policy — the digest is the provenance anchor.\n",
        name = name,
        path = rootfs_path.display(),
        image = image,
    )
}

/// Whether settled-policy bytes are the OCI substrate model: a non-empty `[rootfs].path`.
/// The grammar partition (§7.11) keys on this — `kennel run` refuses it, `kennel oci run`
/// requires it. A parse failure is treated as not-OCI (the daemon rejects a bad policy anyway).
#[must_use]
pub fn policy_is_oci(settled_bytes: &[u8]) -> bool {
    kennel_lib_policy::parse_settled_unverified(settled_bytes)
        .is_ok_and(|p| !p.rootfs.path.is_empty())
}

/// The signed `[rootfs].image` provenance string, if the policy is OCI-model. Compared against
/// the store entry's recorded `digest` before boot (`kennel oci run`).
#[must_use]
pub fn policy_image(settled_bytes: &[u8]) -> Option<String> {
    kennel_lib_policy::parse_settled_unverified(settled_bytes)
        .ok()
        .map(|p| p.rootfs.image)
        .filter(|s| !s.is_empty())
}

/// `kennel oci <build|run> …` — the OCI substrate verb group (§7.11). A noun group like
/// `kennel policy`, kept distinct from `kennel run` so `[rootfs]` is valid under exactly one
/// verb (the grammar partition) and the run path always does the digest provenance check.
///
/// # Errors
///
/// Returns a usage or operational error message (the caller prints it).
pub fn dispatch(args: &[String]) -> Result<std::process::ExitCode, String> {
    let (verb, rest) = args
        .split_first()
        .ok_or("usage: kennel oci <build|run> <name> [...]")?;
    match verb.as_str() {
        "build" => build(rest),
        "run" => run(rest),
        "revert" => revert(rest),
        "update" => update(rest),
        other => Err(format!(
            "unknown `kennel oci` verb `{other}` (expected build|run|revert|update)"
        )),
    }
}

/// Refuse a store-mutating verb (`revert`/`update`) while a kennel of the same `<name>` is
/// running — its overlay has the store entry mounted live, and mutating `upper/`/`rootfs/`
/// underneath it would corrupt the running view. A kenneld we cannot reach means nothing is
/// running, so the op proceeds.
fn refuse_if_running(name: &str) -> Result<(), String> {
    use kennel_lib_control::control::{self, Request, Response};
    let Ok(conn) = crate::connect() else {
        return Ok(()); // no daemon ⇒ nothing running
    };
    crate::send(&conn, &Request::List, &[])?;
    let mut conn = conn;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Listing(kennels) => {
            if kennels.iter().any(|k| k.kennel == name) {
                return Err(format!(
                    "kennel `{name}` is running; stop it (`kennel stop {name}`) before this operation"
                ));
            }
            Ok(())
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `kennel oci revert <name>` — obliterate the managed overlay upper (and its workdir) so the
/// next run's merged root is the lowers plus a clean layer. A no-op for a `discard`/`readonly`
/// entry (no managed upper exists). Refused while the entry is running; the image lower is never
/// touched (revert returns the *mutable* state to empty, it does not re-attest the image).
///
/// # Errors
///
/// Returns an error if the name is invalid, the entry is not built, the kennel is running, or the
/// upper cannot be removed.
pub fn revert(args: &[String]) -> Result<std::process::ExitCode, String> {
    let name = single_name(args, "revert")?;
    let store = Store::open()?;
    let entry = store.entry(name)?;
    if !entry.exists() {
        return Err(format!("store entry `{name}` is not built"));
    }
    refuse_if_running(name)?;
    let upper = entry.dir().join("upper");
    let work = entry.dir().join("work");
    let had = upper.exists() || work.exists();
    for d in [&upper, &work] {
        if d.exists() {
            std::fs::remove_dir_all(d).map_err(|e| format!("removing {}: {e}", d.display()))?;
        }
    }
    if had {
        eprintln!(
            "kennel: reverted the persisted overlay upper for `{name}` (mutable state cleared)"
        );
    } else {
        eprintln!("kennel: `{name}` has no persisted upper (discard/readonly) — nothing to revert");
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// `kennel oci update <name> -- <new-image-ref>` — replace the assured (image) layer.
///
/// Records the new provenance digest and discards the managed upper by default (a stale copy-up
/// over the old image would shadow the new one's patched binaries); `--keep-state` preserves it.
/// Refused while running; refuses an absent `<name>` (as `build` refuses a present one).
///
/// The confined fetch + unpack of the new `rootfs/`/`config.json`, the `[rootfs].image` bump, and
/// the signature-clear (so the operator re-signs — `update` never auto-signs) land with the vetted
/// builder path (W17c); until then this records the digest and prepares the entry, reporting the
/// remaining step.
///
/// # Errors
///
/// Returns an error if the name is invalid, `<new-image-ref>` is missing, the entry is absent, the
/// kennel is running, or the store cannot be written.
pub fn update(args: &[String]) -> Result<std::process::ExitCode, String> {
    let (head, tail) = args
        .iter()
        .position(|a| a == "--")
        .map_or((args, &[][..]), |sep| {
            (
                args.get(..sep).unwrap_or(&[]),
                args.get(sep.saturating_add(1)..).unwrap_or(&[]),
            )
        });
    let mut name: Option<&str> = None;
    let mut keep_state = false;
    for arg in head {
        match arg.as_str() {
            "--keep-state" => keep_state = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel oci update <name> [--keep-state] -- <new-image-ref>")?;
    let new_ref = tail
        .first()
        .ok_or("`kennel oci update` needs `-- <new-image-ref>`")?;

    let store = Store::open()?;
    let entry = store.entry(name)?;
    if !entry.exists() {
        return Err(format!(
            "store entry `{name}` does not exist; use `kennel oci build {name}` to create it"
        ));
    }
    refuse_if_running(name)?;
    entry.write_digest(new_ref)?;
    if !keep_state {
        for d in [entry.dir().join("upper"), entry.dir().join("work")] {
            if d.exists() {
                std::fs::remove_dir_all(&d)
                    .map_err(|e| format!("removing {}: {e}", d.display()))?;
            }
        }
    }
    let state_note = if keep_state {
        " (kept the persisted upper — review for a rebase hazard against the new image)"
    } else {
        " (discarded the persisted upper)"
    };
    eprintln!("kennel: recorded `{new_ref}` for `{name}`{state_note}");
    eprintln!(
        "  remaining (W17c): re-fetch rootfs/ + config.json confined, bump [rootfs].image, and \
         clear the policy signature so you re-sign ({})",
        entry.policy().display()
    );
    Ok(std::process::ExitCode::SUCCESS)
}

/// Parse a lone `<name>` argument for a single-arg verb.
fn single_name<'a>(args: &'a [String], verb: &str) -> Result<&'a str, String> {
    match args {
        [name] if !name.starts_with('-') => Ok(name),
        _ => Err(format!("usage: kennel oci {verb} <name>")),
    }
}

/// `kennel oci build <name> --image <ref>` — provision a named store entry's metadata: record
/// the provenance digest and scaffold the run policy the operator completes and signs.
///
/// The confined fetch+unpack of `rootfs/` + `config.json` (running `skopeo`/`umoci` under the
/// Kennel-shipped vetted fetch policy, §7.11.7) is W17c; until it lands, this prepares the entry
/// and reports the remaining step. Populating `rootfs/`/`config.json` out of band (e.g. a test
/// harness) is supported — the entry layout is the contract.
///
/// # Errors
///
/// Returns an error if the name is invalid, `--image` is missing, or the entry cannot be written.
pub fn build(args: &[String]) -> Result<std::process::ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut image: Option<&str> = None;
    let mut force = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--image" => image = Some(it.next().ok_or("--image needs a value")?),
            "--force" => force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel oci build <name> --image <ref> [--force]")?;
    let image = image.ok_or("`kennel oci build` needs --image <ref> (the image@sha256 to pin)")?;

    let store = Store::open()?;
    let entry = store.entry(name)?;
    if entry.exists() && !force {
        return Err(format!(
            "store entry `{name}` already exists at {}; pass --force to overwrite",
            entry.dir().display()
        ));
    }
    std::fs::create_dir_all(entry.rootfs())
        .map_err(|e| format!("creating {}: {e}", entry.rootfs().display()))?;
    entry.write_digest(image)?;
    let policy = entry.policy();
    if !policy.exists() || force {
        std::fs::write(&policy, scaffold_policy(name, &entry.rootfs(), image))
            .map_err(|e| format!("writing {}: {e}", policy.display()))?;
    }
    eprintln!(
        "kennel: prepared store entry `{name}` at {}",
        entry.dir().display()
    );
    eprintln!("  digest: {image}");
    eprintln!(
        "  policy: {} (complete `reason`, then `kennel policy sign`)",
        policy.display()
    );
    eprintln!(
        "  rootfs: {} — populate via the confined fetch (W17c) or a local unpack",
        entry.rootfs().display()
    );
    Ok(std::process::ExitCode::SUCCESS)
}

/// `kennel oci run <name> [-- <cmd...>]` — boot a named store entry under its signed policy.
///
/// Resolves `<name>`, asserts the entry is populated, then drives the standard run path with
/// the recorded digest as the provenance gate: [`crate::run::launch`] permits `[rootfs]` and
/// refuses unless the signed `[rootfs].image` equals the digest. The daemon's OCI spawn-path
/// branch (W18) boots the image as an overlay root. A `-- <cmd>` override pins an explicit
/// in-root argv; with no override the image entrypoint is used (via the launcher).
///
/// # Errors
///
/// Returns an error if the name is invalid, the entry is not built, the digest is unreadable,
/// or the run fails.
pub fn run(args: &[String]) -> Result<std::process::ExitCode, String> {
    let (head, command) = args
        .iter()
        .position(|a| a == "--")
        .map_or((args, &[][..]), |sep| {
            (
                args.get(..sep).unwrap_or(&[]),
                args.get(sep.saturating_add(1)..).unwrap_or(&[]),
            )
        });
    let mut name: Option<&str> = None;
    let mut key_path: Option<&str> = None;
    let mut force = false;
    let mut it = head.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--force" => force = true,
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel oci run <name> [--key K] [--force] [-- <cmd...>]")?;

    let store = Store::open()?;
    let entry = store.entry(name)?;
    if !entry.exists() {
        return Err(format!(
            "store entry `{name}` is not built (no rootfs at {}); run `kennel oci build {name} …` first",
            entry.rootfs().display()
        ));
    }
    let digest = entry.read_digest()?;
    crate::run::launch(
        entry.policy(),
        name,
        command,
        force,
        key_path,
        Vec::new(),
        Vec::new(),
        Some(&digest),
        name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_must_be_safe_single_components() {
        for bad in [
            "", ".", "..", "a/b", "a\\b", "/abs", ".hidden", "x\ty", "x y", "a\nb",
        ] {
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
        let p = scaffold_policy(
            "my-app",
            Path::new("/store/my-app/rootfs"),
            "ghcr.io/o/a@sha256:abc",
        );
        assert!(p.contains("[rootfs]"));
        assert!(p.contains("/store/my-app/rootfs"));
        assert!(p.contains("ghcr.io/o/a@sha256:abc"));
        assert!(p.contains("reason ="));
        assert!(p.contains("name = \"my-app\""));
    }
}
