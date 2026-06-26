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

/// Validate a store-entry name: a single, safe path component.
///
/// Rejects anything that could escape the store dir (`/`, `.`, `..`, empty, control/space) so
/// `<name>` is always one directory under the store root.
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

    /// The image runtime config (`<entry>/config.json`): the launcher's entrypoint/env source
    /// (bound at `/run/kennel/oci-config.json`) and the build-time closure-lock derivation's
    /// `config.User` source.
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

/// The `[env].deny` globs the OCI run-policy scaffold emits — a declarative mirror of the
/// `kennel-bin-oci-entry` launcher's `env_strip` denylist (the `AT_SECURE`-equivalent
/// loader/runtime/shell-injection set). The launcher strips these from the image `Env`
/// unconditionally; emitting them as `[env].deny` makes the posture visible in the signed run
/// policy and also denies them on any `[env].pass` an operator adds (defence in depth, §7.11.6).
/// Keep in sync with `kennel-bin-oci-entry`'s `env_strip` (the enforcing source of truth).
const SCAFFOLD_ENV_DENY: &[&str] = &[
    "LD_*",
    "GLIBC_*",
    "GCONV_PATH",
    "GETCONF_DIR",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_TRACE",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TZDIR",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "RUBYLIB",
    "RUBYOPT",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
];

/// Render the scaffolded run policy for a freshly built entry: the confined default plus the
/// `[rootfs]` block (path + recorded image + a `reason` the operator completes and signs).
///
/// The operator edits `reason` and signs; `kennel oci run` then verifies the signature like any
/// policy. Returned as text (the caller writes it) so this stays pure and testable.
///
/// `readonly` is the build-derived closure-lock set (§7.11.4c); emitted as `[rootfs].readonly` for
/// the operator to review and sign (empty ⇒ no lock line, an all-root image's writable substrate).
#[must_use]
pub fn scaffold_policy(name: &str, rootfs_path: &Path, image: &str, readonly: &[String]) -> String {
    let readonly_line = if readonly.is_empty() {
        // All-root image: no closure-lock (the writable substrate is the image's own posture).
        "# readonly = [\"/usr\", \"/lib\"]   # closure-lock: build derived none (all-root image)\n"
            .to_owned()
    } else {
        let list = readonly
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("readonly = [{list}]   # closure-lock (build-derived, §7.11.4c); review + sign\n")
    };
    let env_deny = SCAFFOLD_ENV_DENY
        .iter()
        .map(|g| format!("\"{g}\""))
        .collect::<Vec<_>>()
        .join(", ");
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
         {readonly_line}\
         # persistence = \"discard\"  # discard (default) | persist\n\
         # writable = [\"/usr/lib/python3.12\"]  # carve a hole back out of readonly (loud)\n\
         \n\
         # Loader/runtime/shell-injection env denied (mirrors the launcher's env_strip, §7.11.6):\n\
         # the launcher strips these from the image Env; denying them here also covers any\n\
         # [env].pass you add. The image's own benign Env still merges (sanitised) via the launcher.\n\
         [env]\n\
         deny = [{env_deny}]\n\
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

/// The FHS-coarse executable closure (§7.11.4c): locking `/usr` and `/lib*` covers the merged-usr
/// symlinks (`/bin → /usr/bin`, `/lib → /usr/lib`), which resolve into these locked targets; `/bin`
/// and `/sbin` are listed too for a non-merged-usr image where they are real directories.
const FHS_CLOSURE: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32",
];

/// Derive the closure-lock `readonly` set from the image's effective runtime user (`config.User`).
///
/// Best-effort and high-level (§7.11.4c): a non-root `User` means the author intended `/usr`
/// off-limits to the app, so lock the FHS closure; an all-root image (no non-root `User`) gets no
/// lock — a flat image intends a writable substrate (and root-running `pip -g`/`apt` work). KNOWN
/// GAPS: an image that drops privilege in its entrypoint (`gosu`/`su-exec`) keeps `config.User = 0`
/// and reads as all-root; app code outside `/usr|/lib` (e.g. `/app`, `/opt`) stays writable. The
/// `writable` carve-out handles over-reach; under-reach is the operator's to lock by hand.
#[must_use]
pub fn derive_closure_readonly(config_user: Option<&str>) -> Vec<String> {
    let runs_nonroot = config_user
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .is_some_and(|u| {
            // OCI `User` is `uid`, `uid:gid`, `user`, or `user:group`; non-root iff the user part
            // is neither `0` nor `root`.
            let user = u.split(':').next().unwrap_or(u);
            user != "0" && user != "root"
        });
    if runs_nonroot {
        FHS_CLOSURE.iter().map(|s| (*s).to_owned()).collect()
    } else {
        Vec::new()
    }
}

/// Read `config.User` from an image config blob (`config.json`), if the file exists and carries it.
fn read_image_user(config_path: &Path) -> Option<String> {
    let bytes = std::fs::read(config_path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("config")?.get("User")?.as_str().map(str::to_owned)
}

/// Whether settled-policy bytes are the OCI substrate model: a non-empty `[rootfs].path`.
///
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

/// `kennel oci <build|run> …` — the OCI substrate verb group (§7.11).
///
/// A noun group like `kennel policy`, kept distinct from `kennel run` so `[rootfs]` is valid under
/// exactly one verb (the grammar partition) and the run path always does the digest provenance
/// check.
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

/// `kennel oci revert <name> [--list] [-- <path>…]` — restore the managed overlay upper toward the
/// image lower (§7.11.4b).
///
/// The image lower is the **pin** (content-addressed by its `digest`), the
/// upper's copy-ups and whiteouts are the **diff against the pin**, and removing an upper entry is
/// **restore-from-pin** (the lower shows back through) — the OCI instantiation of the same pin /
/// diff-against-pin / restore-from-pin mechanism as the trust-manifest store (§7.4, `02-9`):
///
/// - **`--list`** prints the diff against the pin: each persisted change (`M` a copy-up/added file,
///   `D` a whiteout deleting a lower file). Read-only; allowed even while running.
/// - **`-- <path>…`** is **selective** restore: each named in-image path's upper entry is removed, so
///   the lower shows through. Refused while running.
/// - **no `--list` / no paths** is the **total** case: obliterate the whole upper (and workdir) — the
///   blunt end of selective revert. A no-op for a `discard`/`readonly` entry. Refused while running.
///
/// The image lower is never touched; revert returns the *mutable* state toward the pin, it does not
/// re-attest the image (the integrity ladder's job).
///
/// # Errors
///
/// Returns an error if the name is invalid, the entry is not built, a path escapes the upper, the
/// kennel is running (for a mutating mode), or the upper cannot be read/removed.
pub fn revert(args: &[String]) -> Result<std::process::ExitCode, String> {
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
    let mut list = false;
    for arg in head {
        match arg.as_str() {
            "--list" => list = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument before `--`".to_owned()),
        }
    }
    let name = name.ok_or("usage: kennel oci revert <name> [--list] [-- <path>…]")?;
    let store = Store::open()?;
    let entry = store.entry(name)?;
    if !entry.exists() {
        return Err(format!("store entry `{name}` is not built"));
    }
    let upper = entry.dir().join("upper");

    if list {
        return list_upper(name, &upper); // read-only inspection
    }
    refuse_if_running(name)?; // the mutating modes below
    if !tail.is_empty() {
        return revert_paths(name, &upper, tail);
    }
    revert_total(name, entry.dir())
}

/// The total revert: obliterate the whole managed upper (and workdir) so the next run's merged root
/// is the lowers plus a clean layer — the blunt end of selective revert.
fn revert_total(name: &str, entry_dir: &Path) -> Result<std::process::ExitCode, String> {
    let upper = entry_dir.join("upper");
    let work = entry_dir.join("work");
    let had = upper.exists() || work.exists();
    for d in [&upper, &work] {
        if d.exists() {
            std::fs::remove_dir_all(d).map_err(|e| format!("removing {}: {e}", d.display()))?;
        }
    }
    if had {
        eprintln!(
            "kennel: reverted the entire persisted upper for `{name}` (mutable state cleared)"
        );
    } else {
        eprintln!("kennel: `{name}` has no persisted upper (discard/readonly) — nothing to revert");
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Print the diff against the pin: every persisted change in the upper (`M` a copy-up/added file,
/// `D` a whiteout deleting a lower file). Container directories holding only copy-ups are not listed.
fn list_upper(name: &str, upper: &Path) -> Result<std::process::ExitCode, String> {
    if !upper.exists() {
        eprintln!("kennel: `{name}` has no persisted upper (discard/readonly) — nothing persisted");
        return Ok(std::process::ExitCode::SUCCESS);
    }
    let mut changes: Vec<(String, char)> = Vec::new();
    walk_upper(upper, upper, &mut changes)?;
    if changes.is_empty() {
        eprintln!("kennel: `{name}` upper is empty — the merged root equals the image");
        return Ok(std::process::ExitCode::SUCCESS);
    }
    changes.sort();
    eprintln!("kennel: persisted changes in `{name}` (the diff against the image pin):");
    for (path, marker) in &changes {
        eprintln!("  {marker} {path}");
    }
    eprintln!(
        "  restore some: kennel oci revert {name} -- <path>…    all: kennel oci revert {name}"
    );
    Ok(std::process::ExitCode::SUCCESS)
}

/// Recursively collect the upper's deviations from the lower. A whiteout (overlayfs marks a deleted
/// lower file as a `char` device `0:0`) is `D`; a regular/other file is `M`; a directory is recursed
/// (a plain container for copy-ups is not itself a change).
fn walk_upper(root: &Path, dir: &Path, out: &mut Vec<(String, char)>) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let rd = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for ent in rd {
        let ent = ent.map_err(|e| format!("reading {}: {e}", dir.display()))?;
        let path = ent.path();
        let ft = ent
            .file_type()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let in_image = format!("/{}", rel.display());
        if ft.is_char_device() {
            let rdev = std::fs::symlink_metadata(&path).map_or(0, |m| m.rdev());
            // overlayfs whiteout = char device 0:0; a copied-up real device is rare and shown as `M`.
            out.push((in_image, if rdev == 0 { 'D' } else { 'M' }));
        } else if ft.is_dir() {
            walk_upper(root, &path, out)?;
        } else {
            out.push((in_image, 'M'));
        }
    }
    Ok(())
}

/// Selective restore: remove each named in-image path's upper entry so the lower shows through. A
/// path not in the upper is already at the image and skipped; a `..`/escape is refused.
fn revert_paths(
    name: &str,
    upper: &Path,
    paths: &[String],
) -> Result<std::process::ExitCode, String> {
    if !upper.exists() {
        return Err(format!(
            "`{name}` has no persisted upper (discard/readonly) — nothing to revert"
        ));
    }
    let mut restored = 0_u32;
    for raw in paths {
        let rel = sanitize_rel(raw)?;
        let target = upper.join(&rel);
        // Defence in depth against a symlinked component: the resolved target must stay under upper.
        if !target.starts_with(upper) {
            return Err(format!("`{raw}` escapes the upper"));
        }
        match std::fs::symlink_metadata(&target) {
            Ok(md) => {
                if md.is_dir() {
                    std::fs::remove_dir_all(&target)
                        .map_err(|e| format!("removing {}: {e}", target.display()))?;
                } else {
                    std::fs::remove_file(&target)
                        .map_err(|e| format!("removing {}: {e}", target.display()))?;
                }
                eprintln!("  restored /{} to the image", rel.display());
                restored = restored.saturating_add(1);
            }
            Err(_) => eprintln!(
                "  /{} is not persisted (already at the image) — skipped",
                rel.display()
            ),
        }
    }
    eprintln!("kennel: reverted {restored} path(s) in `{name}` toward the image pin");
    Ok(std::process::ExitCode::SUCCESS)
}

/// Normalise an operator-given in-image path to a safe relative path under the upper: strip a leading
/// `/`, drop `.`, and **refuse** `..` (no escape out of the upper).
///
/// # Errors
///
/// Returns an error if the path contains a `..` component or normalises to empty.
fn sanitize_rel(raw: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let mut rel = PathBuf::new();
    for c in Path::new(raw).components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::Normal(s) => rel.push(s),
            Component::ParentDir => return Err(format!("`{raw}` must not contain `..`")),
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(format!("`{raw}` is not a path within the image"));
    }
    Ok(rel)
}

/// `kennel oci update <name> [--keep-state] [--no-fetch] [--key K] -- <new-image-ref>` — replace
/// the assured (image) layer (§7.11.4b).
///
/// Fetches and unpacks the new image **confined** (the same vetted builder path as `build`), swaps
/// `rootfs/`/`config.json`/`digest`, bumps `[rootfs].image`, and **re-derives the base closure lock**
/// from the new image while **preserving the operator's hand-added carve-outs** — the `writable` list
/// verbatim and any `readonly` entry the old base did not derive — then surfaces the before/after diff
/// (§7.11.4c, `02-9`). It **clears the `[signature]`** (the policy was signed against the old digest),
/// leaving the entry in the operator-reviews-and-re-signs state a fresh build does: a fetch silently
/// changing what a signed policy authorises is exactly what the signature prevents. The managed upper
/// is **discarded by default** (a copy-up over the old image would shadow the new one's patched
/// binaries); `--keep-state` preserves it with a rebase-hazard note. `--no-fetch` records the ref and
/// re-derives against the already-swapped entry (out-of-band population / tests). Refused while running.
///
/// # Errors
///
/// Returns an error if the name is invalid, `<new-image-ref>` is missing, the entry is absent or has
/// no readable `[rootfs]` policy, the kennel is running, the fetch fails, or the store cannot be written.
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
    let mut no_fetch = false;
    let mut key_path: Option<&str> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut it = head.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--keep-state" => keep_state = true,
            "--no-fetch" => no_fetch = true,
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
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

    // 1. Capture the closure baseline BEFORE the fetch overwrites config.json: the current policy's
    //    `[rootfs]` carve-outs and the base the *old* image derived (so we can tell operator-added
    //    `readonly` entries from build-derived ones — §7.11.4c).
    let policy_path = entry.policy();
    let policy_text = std::fs::read_to_string(&policy_path)
        .map_err(|e| format!("reading {}: {e}", policy_path.display()))?;
    let source = kennel_lib_compile::parse_source(policy_text.as_bytes())
        .map_err(|e| format!("parsing {}: {e}", policy_path.display()))?;
    let rootfs = source.rootfs.ok_or_else(|| {
        format!(
            "{} has no [rootfs] — not an OCI entry",
            policy_path.display()
        )
    })?;
    let old_image = rootfs.image.unwrap_or_default();
    let old_readonly = rootfs.readonly.unwrap_or_default();
    let writable = rootfs.writable.unwrap_or_default(); // preserved verbatim
    let reason = rootfs.reason;
    let persistence = rootfs.persistence;
    let path = rootfs
        .path
        .unwrap_or_else(|| entry.rootfs().display().to_string());
    let old_base = derive_closure_readonly(read_image_user(&entry.config()).as_deref());

    // 2. Fetch the new image confined (or trust an out-of-band swap with `--no-fetch`).
    if no_fetch {
        entry.write_digest(new_ref)?;
    } else {
        let opts = FetchOpts {
            key: key_path,
            template_dirs,
            trust_dirs,
        };
        confined_fetch(name, &entry, new_ref, &opts)?;
    }
    let recorded = entry.read_digest().unwrap_or_else(|_| new_ref.to_owned());

    let baseline = Baseline {
        old_image,
        old_readonly,
        writable,
        reason,
        persistence,
        path,
        old_base,
    };
    finish_update(
        &entry,
        name,
        &policy_path,
        &policy_text,
        &baseline,
        &recorded,
        keep_state,
    )
}

/// The pre-update `[rootfs]` state captured before the fetch overwrites `config.json`: the operator's
/// carve-outs and the base the *old* image derived (to tell operator-added `readonly` from build-derived).
struct Baseline {
    old_image: String,
    old_readonly: Vec<String>,
    writable: Vec<String>,
    reason: Option<String>,
    persistence: Option<String>,
    path: String,
    old_base: Vec<String>,
}

/// The re-derived closure lock (§7.11.4c): the new image's base plus the operator's hand-added
/// `readonly` entries (those the old base did not derive), in base-then-carve-out order. The `writable`
/// list is preserved verbatim by the caller; this is the `readonly` half.
fn preserve_closure(
    old_readonly: &[String],
    old_base: &[String],
    new_base: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = new_base.to_vec();
    for p in old_readonly {
        if !old_base.contains(p) && !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

/// Finish an `update` once the new image is in place: re-derive the base closure, preserve the
/// operator's carve-outs, rewrite the policy (clearing the signature), handle the managed upper, and
/// surface the diff the re-sign reviews (§7.11.4b/c).
fn finish_update(
    entry: &StoreEntry,
    name: &str,
    policy_path: &Path,
    policy_text: &str,
    base: &Baseline,
    recorded: &str,
    keep_state: bool,
) -> Result<std::process::ExitCode, String> {
    let new_base = derive_closure_readonly(read_image_user(&entry.config()).as_deref());
    let new_readonly = preserve_closure(&base.old_readonly, &base.old_base, &new_base);

    let render = RootfsRender {
        path: base.path.clone(),
        image: recorded.to_owned(),
        reason: base.reason.clone(),
        persistence: base.persistence.clone(),
        readonly: new_readonly.clone(),
        writable: base.writable.clone(),
    };
    let new_text = rewrite_oci_policy(policy_text, &render)?;
    std::fs::write(policy_path, new_text)
        .map_err(|e| format!("writing {}: {e}", policy_path.display()))?;

    if keep_state {
        eprintln!("kennel: kept the persisted upper for `{name}` — review for a rebase hazard against the new image");
    } else {
        for d in [entry.dir().join("upper"), entry.dir().join("work")] {
            if d.exists() {
                std::fs::remove_dir_all(&d)
                    .map_err(|e| format!("removing {}: {e}", d.display()))?;
            }
        }
    }

    print_update_diff(
        name,
        &base.old_image,
        recorded,
        &base.old_readonly,
        &new_readonly,
        &base.writable,
    );
    eprintln!("  signature CLEARED — review the policy and re-sign:");
    eprintln!(
        "    kennel policy sign {} --key <key>",
        policy_path.display()
    );
    Ok(std::process::ExitCode::SUCCESS)
}

/// The fields a regenerated `[rootfs]` block carries: the build-managed `image`/`readonly` (recomputed
/// on update) plus the operator-owned `path`/`reason`/`persistence`/`writable` (preserved as data).
struct RootfsRender {
    path: String,
    image: String,
    reason: Option<String>,
    persistence: Option<String>,
    readonly: Vec<String>,
    writable: Vec<String>,
}

/// Escape a string for a double-quoted TOML value (`\` and `"`); the policy values here are paths and
/// operator reason text, never control bytes.
fn toml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Render a `[rootfs]` table from [`RootfsRender`]. The build-managed `image`/`readonly` are emitted
/// fresh; `path`/`reason`/`persistence`/`writable` are the operator's, preserved verbatim.
fn render_rootfs_block(r: &RootfsRender) -> String {
    use std::fmt::Write as _;
    let quoted_list = |v: &[String]| {
        v.iter()
            .map(|p| toml_quote(p))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = String::from(
        "[rootfs]\n\
         # Regenerated by `kennel oci update`: closure-lock re-derived from the new image, operator\n\
         # carve-outs preserved (§7.11.4c). Review the diff, then re-sign.\n",
    );
    let reason = r
        .reason
        .as_deref()
        .unwrap_or("TODO: why this image is trusted");
    // `write!` to a String is infallible.
    let _ = writeln!(out, "path   = {}", toml_quote(&r.path));
    let _ = writeln!(out, "image  = {}", toml_quote(&r.image));
    let _ = writeln!(out, "reason = {}", toml_quote(reason));
    if r.readonly.is_empty() {
        out.push_str("# readonly = []   # closure-lock: build-derived none (all-root image)\n");
    } else {
        let _ = writeln!(
            out,
            "readonly = [{}]   # closure-lock (build-derived + preserved carve-outs, §7.11.4c)",
            quoted_list(&r.readonly)
        );
    }
    if let Some(p) = r.persistence.as_deref().filter(|s| !s.is_empty()) {
        let _ = writeln!(out, "persistence = {}", toml_quote(p));
    }
    if !r.writable.is_empty() {
        let _ = writeln!(
            out,
            "writable = [{}]   # operator carve-out, preserved",
            quoted_list(&r.writable)
        );
    }
    out
}

/// Rewrite an OCI run policy for `update`: replace the build-managed `[rootfs]` table in place and drop
/// any `[signature]` block, preserving every other section (and the operator's comments) byte-for-byte.
///
/// Section boundaries are top-level `[header]` lines at column 0 — the form `oci build`'s scaffold and
/// `policy sign` emit. `[rootfs]` is replaced with [`render_rootfs_block`]; `[signature]` (always the
/// trailing appended block) is excised so the entry returns to the unsigned, operator-reviews state.
///
/// # Errors
///
/// Returns an error if the policy has no `[rootfs]` table to rewrite.
fn rewrite_oci_policy(text: &str, render: &RootfsRender) -> Result<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    let is_header = |l: &str| l.starts_with('[') && !l.starts_with("[[");
    let rootfs_start = lines
        .iter()
        .position(|l| l.trim_end() == "[rootfs]")
        .ok_or("the policy has no [rootfs] table to rewrite")?;
    let after_rootfs = rootfs_start.saturating_add(1);
    let next_header = lines
        .iter()
        .enumerate()
        .skip(after_rootfs)
        .find(|(_, l)| is_header(l))
        .map_or(lines.len(), |(i, _)| i);
    // End the rewrite at the table's last assignment, not the next header — so trailing comments and
    // blank lines (a comment ahead of the next table belongs to *it*, not `[rootfs]`) are preserved.
    let mut content_end = after_rootfs;
    for (i, line) in lines
        .iter()
        .enumerate()
        .take(next_header)
        .skip(after_rootfs)
    {
        let t = line.trim_start();
        if !t.is_empty() && !t.starts_with('#') && t.contains('=') {
            content_end = i.saturating_add(1);
        }
    }

    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    out_lines.extend(
        lines
            .get(..rootfs_start)
            .unwrap_or_default()
            .iter()
            .map(|s| (*s).to_owned()),
    );
    out_lines.extend(render_rootfs_block(render).lines().map(str::to_owned));
    out_lines.extend(
        lines
            .get(content_end..)
            .unwrap_or_default()
            .iter()
            .map(|s| (*s).to_owned()),
    );

    // Excise a `[signature]` block (header → next header or EOF), wherever it sits.
    if let Some(sig_start) = out_lines.iter().position(|l| l.trim_end() == "[signature]") {
        let sig_end = out_lines
            .iter()
            .enumerate()
            .skip(sig_start.saturating_add(1))
            .find(|(_, l)| is_header(l))
            .map_or(out_lines.len(), |(i, _)| i);
        out_lines.drain(sig_start..sig_end);
        // Trim a trailing blank line left where the signature was.
        while out_lines.last().is_some_and(|l| l.trim().is_empty()) {
            out_lines.pop();
        }
    }

    let mut out = out_lines.join("\n");
    out.push('\n');
    Ok(out)
}

/// Print the before/after diff `update` re-signs against (§7.11.4c): the image bump, and the
/// closure-lock entries added (the new image's base) or removed (the old base, gone), with operator
/// carve-outs noted as preserved.
fn print_update_diff(
    name: &str,
    old_image: &str,
    new_image: &str,
    old_readonly: &[String],
    new_readonly: &[String],
    writable: &[String],
) {
    eprintln!("kennel: updated `{name}`");
    eprintln!("  image:  {old_image}");
    eprintln!("       -> {new_image}");
    let added: Vec<&String> = new_readonly
        .iter()
        .filter(|p| !old_readonly.contains(p))
        .collect();
    let removed: Vec<&String> = old_readonly
        .iter()
        .filter(|p| !new_readonly.contains(p))
        .collect();
    if added.is_empty() && removed.is_empty() {
        eprintln!("  closure-lock (readonly): unchanged");
    } else {
        eprintln!("  closure-lock (readonly):");
        for p in &added {
            eprintln!("    + {p}");
        }
        for p in &removed {
            eprintln!("    - {p}");
        }
    }
    if !writable.is_empty() {
        eprintln!("  writable carve-outs preserved: {}", writable.join(", "));
    }
}

/// Options for the confined fetch, threaded from `build`'s flags into [`crate::run::launch`].
struct FetchOpts<'a> {
    key: Option<&'a str>,
    template_dirs: Vec<PathBuf>,
    trust_dirs: Vec<PathBuf>,
}

/// The fetch+unpack the confined kennel runs (§7.11.7), an `sh -c` program with positional args
/// `ref entry-path` (`$1`, `$2`).
///
/// `skopeo` pulls into a local OCI layout, the image config blob is captured for the launcher
/// (`skopeo inspect --config`), and `umoci unpack --rootless` applies the layers into a bundle
/// rootfs — rootless, so every inode lands owned by the persona uid (the single-uid flatten
/// closure-lock repairs, §7.11.4c). The resolved digest is recorded as a pinned reference.
/// `--insecure-policy` declines skopeo's own signature policy — Kennel's trust layer is the digest
/// pin and the run-policy signature, not skopeo's `/etc/containers/policy.json` (absent from the
/// kennel view). All writes land in the entry dir (the only `fs.write` the per-build leaf grants);
/// egress is the vetted registry allowlist of `oci-fetch@v1`. Each tool's stderr is captured to
/// `.fetch.err` so a failure (offline, denied registry, bad ref) surfaces to the operator.
const FETCH_SCRIPT: &str = r#"
ref="$1"; entry="$2"
layout="$entry/.layout"; bundle="$entry/.bundle"; err="$entry/.fetch.err"
rm -rf "$layout" "$bundle"
if ! skopeo copy --insecure-policy --digestfile "$entry/.digest" "docker://$ref" "oci:$layout:img" 2>"$err"; then exit 1; fi
if ! skopeo inspect --insecure-policy --config "oci:$layout:img" >"$entry/config.json" 2>>"$err"; then exit 1; fi
if ! umoci unpack --rootless --image "$layout:img" "$bundle" 2>>"$err"; then exit 1; fi
rm -rf "$entry/rootfs"
mv "$bundle/rootfs" "$entry/rootfs"
dig=$(cat "$entry/.digest")
case "$ref" in
  *@*) printf '%s\n' "$ref" > "$entry/digest" ;;
  *) printf '%s@%s\n' "$ref" "$dig" > "$entry/digest" ;;
esac
rm -rf "$layout" "$bundle" "$entry/.digest" "$err"
"#;

/// Run the confined image fetch+unpack (§7.11.7): `skopeo` pull + `umoci` rootless unpack into the
/// store entry, under the vendor-signed `oci-fetch@v1` policy plus a per-build leaf that grants only
/// `fs.write` to this entry (the vetted broad egress lives in the template, never operator-authored).
/// Populates `rootfs/`, `config.json`, and the pinned `digest`.
///
/// # Errors
///
/// Returns an error if the leaf cannot be staged, the fetch kennel cannot run, or the entry was not
/// populated (skopeo/umoci failed inside the kennel — needs both on the host).
fn confined_fetch(
    name: &str,
    entry: &StoreEntry,
    image: &str,
    opts: &FetchOpts<'_>,
) -> Result<(), String> {
    // The entry's path inside the fetch kennel's view. The store lives under the operator's $HOME,
    // so the `fs.write` grant canonicalises to `~/…` and the spawn remaps `~` to the persona home
    // (/home/kennel); the script writes that remapped path. A store outside $HOME (XDG_DATA_HOME
    // elsewhere) is granted and seen at its own absolute path.
    let home = std::env::var("HOME")
        .map_err(|_| "HOME is not set; cannot run the confined fetch".to_owned())?;
    let (fs_write, view) = entry.dir().strip_prefix(&home).map_or_else(
        |_| {
            let abs = entry.dir().display().to_string();
            (abs.clone(), abs)
        },
        |rel| {
            (
                format!("~/{}", rel.display()),
                format!("/home/kennel/{}", rel.display()),
            )
        },
    );
    let leaf = format!(
        "name = \"{name}-fetch\"\ntemplate_base = \"oci-fetch@v1\"\n[fs]\nwrite = [\"{fs_write}\"]\n"
    );
    let leaf_path = std::env::temp_dir().join(format!(
        "kennel-oci-fetch-{name}-{}.toml",
        std::process::id()
    ));
    std::fs::write(&leaf_path, leaf).map_err(|e| format!("staging the fetch leaf: {e}"))?;

    let inst = format!("{name}-fetch");
    let argv = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        FETCH_SCRIPT.to_owned(),
        "sh".to_owned(), // $0 for `sh -c`; image/view become $1/$2
        image.to_owned(),
        view,
    ];
    eprintln!("kennel: fetching `{image}` confined under oci-fetch@v1 …");
    let res = crate::run::launch(
        leaf_path.clone(),
        &inst,
        &argv,
        false,
        opts.key,
        opts.template_dirs.clone(),
        opts.trust_dirs.clone(),
        None,
        &inst,
    );
    let _ = std::fs::remove_file(&leaf_path);
    // A launch error (compile/daemon) propagates; a fetch failure surfaces as an unpopulated entry
    // (the workload exit code is folded into the returned ExitCode, so the post-condition is the gate).
    res?;
    if !entry.rootfs().is_dir() || !entry.config().exists() || !entry.digest_path().exists() {
        // The fetch program writes the precise cause to `.fetch.err` (skopeo/unpack stderr); surface it.
        let errf = entry.dir().join(".fetch.err");
        let detail = std::fs::read_to_string(&errf).unwrap_or_default();
        let _ = std::fs::remove_file(&errf);
        let detail = detail.trim();
        let hint = if detail.is_empty() {
            "skopeo/umoci failed inside the kennel (the host needs both, and the registry must be in oci-fetch@v1's allowlist)".to_owned()
        } else {
            detail.to_owned()
        };
        return Err(format!(
            "the confined fetch did not populate `{name}` — {hint}"
        ));
    }
    let _ = std::fs::remove_file(entry.dir().join(".fetch.err"));
    Ok(())
}

/// `kennel oci build <name> --image <ref>` — fetch an image into a named store entry, confined.
///
/// Runs the `skopeo`/`umoci` pull+unpack inside a kennel under the vendor-signed `oci-fetch@v1`
/// policy (§7.11.7), populating `rootfs/` + `config.json` + the pinned `digest`, then derives the
/// closure-lock from the image's `config.User` and scaffolds the run policy the operator completes
/// and signs. `--no-fetch` skips the fetch and records `--image` as-is (out-of-band population, e.g.
/// a local unpack or a test harness — the entry layout is the contract). `--key`/`--template-dir`/
/// `--trust-dir` thread to the fetch kennel's in-memory compile.
///
/// # Errors
///
/// Returns an error if the name is invalid, `--image` is missing, the fetch fails, or the entry
/// cannot be written.
pub fn build(args: &[String]) -> Result<std::process::ExitCode, String> {
    let mut name: Option<&str> = None;
    let mut image: Option<&str> = None;
    let mut force = false;
    let mut no_fetch = false;
    let mut key_path: Option<&str> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--image" => image = Some(it.next().ok_or("--image needs a value")?),
            "--force" => force = true,
            "--no-fetch" => no_fetch = true,
            "--key" => key_path = Some(it.next().ok_or("--key needs a value")?),
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            v if name.is_none() => name = Some(v),
            _ => return Err("unexpected extra argument".to_owned()),
        }
    }
    let name = name
        .ok_or("usage: kennel oci build <name> --image <ref> [--no-fetch] [--force] [--key K]")?;
    let image =
        image.ok_or("`kennel oci build` needs --image <ref> (the image[@sha256] to pull)")?;

    let store = Store::open()?;
    let entry = store.entry(name)?;
    if entry.exists() && !force {
        return Err(format!(
            "store entry `{name}` already exists at {}; pass --force to overwrite",
            entry.dir().display()
        ));
    }
    std::fs::create_dir_all(entry.dir())
        .map_err(|e| format!("creating {}: {e}", entry.dir().display()))?;

    if no_fetch {
        // Out-of-band population (a local unpack / test harness): record the digest as given.
        std::fs::create_dir_all(entry.rootfs())
            .map_err(|e| format!("creating {}: {e}", entry.rootfs().display()))?;
        entry.write_digest(image)?;
    } else {
        let opts = FetchOpts {
            key: key_path,
            template_dirs,
            trust_dirs,
        };
        confined_fetch(name, &entry, image, &opts)?;
    }

    // The scaffold's `[rootfs].image` must equal the recorded digest (the confined fetch resolved
    // the tag to a pinned `…@sha256:` reference) — `kennel oci run` asserts they match before boot.
    let recorded = entry.read_digest().unwrap_or_else(|_| image.to_owned());
    // Closure-lock (§7.11.4c): derive the readonly set from the fetched image's config.User. A
    // non-root image gets the FHS executable closure locked; an all-root image gets nothing. The
    // derived set goes into the scaffolded policy, where the operator reviews and signs it.
    let readonly = derive_closure_readonly(read_image_user(&entry.config()).as_deref());
    let policy = entry.policy();
    if !policy.exists() || force {
        std::fs::write(
            &policy,
            scaffold_policy(name, &entry.rootfs(), &recorded, &readonly),
        )
        .map_err(|e| format!("writing {}: {e}", policy.display()))?;
    }
    eprintln!(
        "kennel: built store entry `{name}` at {}",
        entry.dir().display()
    );
    eprintln!("  digest: {recorded}");
    eprintln!(
        "  policy: {} (complete `reason`, then `kennel policy sign`)",
        policy.display()
    );
    eprintln!("  rootfs: {}", entry.rootfs().display());
    Ok(std::process::ExitCode::SUCCESS)
}

/// `kennel oci run <name> [-- <cmd...>]` — boot a named store entry under its signed policy.
///
/// Resolves `<name>`, asserts the entry is populated, then drives the standard run path with
/// the recorded digest as the provenance gate: [`crate::run::launch`] permits `[rootfs]` and
/// refuses unless the signed `[rootfs].image` equals the digest. The daemon's OCI spawn-path
/// branch boots the image as an overlay root. A `-- <cmd>` override pins an explicit
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
            &["/usr".to_owned(), "/lib".to_owned()],
        );
        assert!(p.contains("[rootfs]"));
        assert!(p.contains("/store/my-app/rootfs"));
        assert!(p.contains("ghcr.io/o/a@sha256:abc"));
        assert!(p.contains("reason ="));
        assert!(p.contains("name = \"my-app\""));
        // A derived closure-lock is emitted as a live `readonly =` line, not a comment.
        assert!(p.contains("readonly = [\"/usr\", \"/lib\"]"));
    }

    #[test]
    fn closure_derives_for_nonroot_user_only() {
        // Non-root User (uid or name, with/without group) ⇒ the FHS closure.
        for u in ["1000", "1000:1000", "app", "app:app"] {
            let ro = derive_closure_readonly(Some(u));
            assert!(ro.contains(&"/usr".to_owned()), "{u} should lock /usr");
            assert!(ro.contains(&"/lib".to_owned()));
        }
        // Root (uid 0, name root, or unset) ⇒ no lock — the writable substrate.
        for u in [Some("0"), Some("root"), Some("0:0"), Some("  "), None] {
            assert!(
                derive_closure_readonly(u).is_empty(),
                "{u:?} should not lock"
            );
        }
    }

    #[test]
    fn scaffold_all_root_emits_a_commented_lock_hint() {
        let p = scaffold_policy("a", Path::new("/s/a/rootfs"), "img@sha256:x", &[]);
        assert!(
            p.contains("# readonly ="),
            "all-root scaffold should hint, not lock"
        );
        assert!(
            !p.contains("\nreadonly ="),
            "all-root scaffold must not emit a live lock"
        );
    }

    /// A signed OCI policy with a `[rootfs]`, an operator-edited `[env]` section (with a comment), and
    /// an appended `[signature]` — the shape `update` rewrites.
    const SIGNED_OCI_POLICY: &str = "\
name = \"my-app\"
template_base = \"base-confined@v1\"

[rootfs]
path   = \"/store/my-app/rootfs\"
image  = \"ghcr.io/o/a@sha256:OLD\"
reason = \"vendored app image\"
readonly = [\"/usr\", \"/lib\", \"/opt/app\"]
writable = [\"/usr/lib/python3.12\"]

# operator note: this app needs egress to the model API
[env]
deny = [\"LD_*\"]

[signature]
algorithm = \"ed25519\"
key_id = \"kennel-maint-2026\"
signature = \"abc123\"
";

    #[test]
    fn update_rewrite_preserves_carveouts_other_sections_and_clears_signature() {
        // Old base was the FHS closure (non-root image); the operator hand-added `/opt/app` to
        // readonly and a `/usr/lib/python3.12` writable hole. The new image is all-root (base empties).
        let render = RootfsRender {
            path: "/store/my-app/rootfs".to_owned(),
            image: "ghcr.io/o/a@sha256:NEW".to_owned(),
            reason: Some("vendored app image".to_owned()),
            persistence: None,
            // base (none) ∪ operator-added (`/opt/app`) — `/usr`,`/lib` (old base) drop out.
            readonly: vec!["/opt/app".to_owned()],
            writable: vec!["/usr/lib/python3.12".to_owned()],
        };
        let out = rewrite_oci_policy(SIGNED_OCI_POLICY, &render).expect("rewrite");

        // New image recorded; old image gone.
        assert!(out.contains("ghcr.io/o/a@sha256:NEW"));
        assert!(!out.contains("sha256:OLD"));
        // Signature cleared entirely.
        assert!(!out.contains("[signature]"), "signature must be cleared");
        assert!(!out.contains("kennel-maint-2026"));
        // Operator carve-outs preserved.
        assert!(out.contains("\"/opt/app\""), "operator readonly preserved");
        assert!(
            out.contains("\"/usr/lib/python3.12\""),
            "writable preserved"
        );
        // The old build-derived base dropped (new image is all-root).
        assert!(!out.contains("\"/usr\""), "old base /usr re-derived away");
        // The operator's OTHER section + its comment preserved byte-for-byte.
        assert!(out.contains("# operator note: this app needs egress to the model API"));
        assert!(out.contains("[env]\ndeny = [\"LD_*\"]"));
        // Still parses as a source policy (and now carries no signature).
        let reparsed = kennel_lib_compile::parse_source(out.as_bytes()).expect("reparse");
        assert!(reparsed.signature.is_none());
        let rf = reparsed.rootfs.expect("rootfs");
        assert_eq!(rf.image.as_deref(), Some("ghcr.io/o/a@sha256:NEW"));
        assert_eq!(rf.readonly.as_deref(), Some(&["/opt/app".to_owned()][..]));
        assert_eq!(
            rf.writable.as_deref(),
            Some(&["/usr/lib/python3.12".to_owned()][..])
        );
    }

    #[test]
    fn sanitize_rel_strips_root_and_refuses_escape() {
        // Leading `/` and `.` are stripped; the path is relative under the upper.
        assert_eq!(
            sanitize_rel("/etc/hostname").expect("test setup"),
            PathBuf::from("etc/hostname")
        );
        assert_eq!(
            sanitize_rel("etc/./hostname").expect("test setup"),
            PathBuf::from("etc/hostname")
        );
        // `..` in any position is refused — no escape out of the upper.
        for bad in ["../x", "/etc/../../x", "a/../../b", ".."] {
            assert!(sanitize_rel(bad).is_err(), "`{bad}` must be refused");
        }
        // An empty / root-only path normalises to nothing — refused.
        for empty in ["/", "", "."] {
            assert!(sanitize_rel(empty).is_err(), "`{empty}` must be refused");
        }
    }

    #[test]
    fn walk_upper_classifies_copyups_and_whiteouts() {
        use std::os::unix::fs::symlink;
        let upper = std::env::temp_dir().join(format!("kennel-oci-upper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&upper);
        std::fs::create_dir_all(upper.join("etc")).expect("test setup");
        std::fs::create_dir_all(upper.join("opt/app")).expect("test setup");
        // A copy-up / added file (M) nested under a container dir.
        std::fs::write(upper.join("etc/hostname"), b"box\n").expect("test setup");
        std::fs::write(upper.join("opt/app/data"), b"x").expect("test setup");
        // A symlink is an "other" file → M (we cannot mknod a 0:0 whiteout without privilege in a
        // unit test, so whiteout *rdev* classification is covered by the rdev==0 branch directly).
        symlink("/bin/sh", upper.join("etc/alias")).expect("test setup");

        let mut changes = Vec::new();
        walk_upper(&upper, &upper, &mut changes).expect("test setup");
        changes.sort();
        let paths: Vec<&str> = changes.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            paths.contains(&"/etc/hostname"),
            "copy-up listed: {paths:?}"
        );
        assert!(paths.contains(&"/opt/app/data"), "nested copy-up listed");
        assert!(paths.contains(&"/etc/alias"), "symlink listed");
        // Container dirs are not themselves changes.
        assert!(!paths.contains(&"/etc"), "container dir not listed");
        assert!(!paths.contains(&"/opt"), "container dir not listed");
        assert!(changes.iter().all(|(_, m)| *m == 'M'), "no whiteouts here");
        let _ = std::fs::remove_dir_all(&upper);
    }

    #[test]
    fn update_rewrite_all_root_image_emits_commented_lock() {
        let render = RootfsRender {
            path: "/s/a/rootfs".to_owned(),
            image: "img@sha256:x".to_owned(),
            reason: None,
            persistence: None,
            readonly: Vec::new(), // no base, no operator carve-out
            writable: Vec::new(),
        };
        let block = render_rootfs_block(&render);
        assert!(block.contains("# readonly ="), "all-root ⇒ commented hint");
        assert!(!block.contains("\nreadonly ="), "no live lock line");
    }
}
