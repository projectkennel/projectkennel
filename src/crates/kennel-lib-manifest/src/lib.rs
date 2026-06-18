//! The masked workspace manifest (`.trust-manifest.json`) — host-side types and logic.
//!
//! A confined workload with `fs.write` to a project can edit a host-side **execution
//! trigger** (a `Makefile`, `package.json`, `.vscode/tasks.json`, a `.git/hooks/*`
//! script) that host tooling *outside* the kennel later runs — threat **T2.8
//! (workspace-trigger tampering)**. The manifest is a cryptographic diode against this:
//! it pins the SHA-256 of each known trigger and lists untrusted-path globs, lives at the
//! root of every writable workspace, and is read natively by host IDEs (VS Code,
//! `JetBrains`) against the published schema.
//!
//! The mask is **structural**, not in this crate: the kennel's view omits/over-mounts the
//! manifest path so the workload cannot see or rewrite it (`07-4` / `05`). The agent can
//! still rewrite a `Makefile`, but cannot re-pin its hash — so the host IDE sees the
//! on-disk hash diverge from the pin and drops the workspace to Restricted Mode.
//!
//! This crate owns the **host-side** half: the serde types (mirroring
//! `docs/schemas/trust-manifest-v2.json`, `deny_unknown_fields` so a typo can't silently
//! bypass a boundary), baseline [`generate`], trigger [`hash_file`] (via the system
//! `sha256sum`, like kenneld's workload pin — no in-crate crypto), and the [`review`]
//! diff the operator signs off. kenneld never links this; generation is CLI pre-flight
//! and `kennel review` is host-side.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

/// The schema version this crate emits and accepts.
///
/// v2 carries a per-trigger record (kind + mode + provenance) and a content-addressed blob
/// store beside the index, so `kennel review` can *show* a diff and `revert` can restore a
/// tampered trigger — neither possible from the v1 hash alone. Pre-1.0, so no v1 compat shim
/// ([[no-legacy-compat-prerelease]]): a v1 manifest is re-generated, not migrated.
pub const SCHEMA_VERSION: &str = "2.0";

/// The published JSON Schema `$id` host IDEs validate against (served from the repo's
/// `docs/schemas/`).
pub const SCHEMA_ID: &str = "https://projectkennel.org/schemas/trust-manifest-v2.json";

/// The manifest filename, at the root of every writable/persistent workspace.
pub const MANIFEST_FILENAME: &str = ".trust-manifest.json";

/// The content-addressed blob store beside the manifest (`<root>/.trust-manifest.d/<hex>`).
///
/// Holds the pinned bytes of each `content` trigger — the manifest is the index, this is the
/// bytes. Content-addressed ⇒ dedup; operator-owned `0700`; masked from the workload beside
/// the manifest itself (`07-4`). `review` diffs the live file against its pinned blob;
/// `revert` copies the blob back.
pub const STORE_DIRNAME: &str = ".trust-manifest.d";

/// The per-layer catalogue filename on the deployment cascade (§2.6).
pub const CATALOGUE_FILENAME: &str = "triggers.catalog";

/// The effective trigger catalogue (§2.6): which paths are execution triggers.
///
/// There is **no compiled-in default** — a baked-in trigger list is a footgun, since the
/// operator cannot see or fully control the watched set by reading the config. The default
/// ships as the package's **vendor** file (`/usr/lib/kennel/triggers.catalog`), and the set is
/// composed **additively** up the standard config cascade — vendor, then `/etc/kennel`
/// (admin), then `~/.config/kennel` (user). Each layer adds patterns, or prunes one with a
/// leading `-` (the only subtractive op). The effective set is exactly what those files say;
/// the hard disable is the `[trust].manifest` policy toggle. An empty catalogue (no layer
/// installed) watches nothing — callers warn when that coincides with `[trust].manifest = on`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalogue {
    /// File triggers: a relative path that is a trigger when it exists (`Makefile`).
    pub files: Vec<String>,
    /// Directory triggers: every immediate file beneath is a trigger (`.git/hooks`).
    pub dirs: Vec<String>,
}

impl Catalogue {
    /// Load the effective catalogue from the config cascade only (vendor → system → user).
    /// A missing layer file is skipped; with no layer installed the catalogue is empty.
    #[must_use]
    pub fn load() -> Self {
        let mut cat = Self::default();
        for path in catalogue_layer_paths() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                cat.apply_layer(&text);
            }
        }
        cat
    }

    /// Whether the catalogue is empty — nothing to watch. Used to warn when this coincides
    /// with `[trust].manifest = on` (a missing vendor file, not a deliberate disable).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty()
    }

    /// Apply one line-oriented layer: a `pattern` adds, a `-pattern` prunes, a trailing `/`
    /// marks a directory trigger, `#` starts a comment, blank lines are ignored.
    pub fn apply_layer(&mut self, text: &str) {
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (remove, body) = line
                .strip_prefix('-')
                .map_or((false, line), |rest| (true, rest.trim()));
            let (is_dir, name) = body
                .strip_suffix('/')
                .map_or((false, body), |dir| (true, dir));
            if name.is_empty() {
                continue;
            }
            let set = if is_dir { &mut self.dirs } else { &mut self.files };
            if remove {
                set.retain(|p| p != name);
            } else if !set.iter().any(|p| p == name) {
                set.push(name.to_owned());
            }
        }
    }
}

/// The catalogue cascade paths, lowest priority first: the vendor dir (`$KENNEL_VENDOR_DIR`,
/// default `/usr/lib/kennel` — where the package ships the default), then the system dir
/// (`$KENNEL_ETC_DIR`, default `/etc/kennel`), then the per-user config dir (`$XDG_CONFIG_HOME`,
/// else `$HOME/.config`) — the project's standard config cascade ([[no-hardcoded-paths-config-cascade]]).
fn catalogue_layer_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let vendor = std::env::var_os("KENNEL_VENDOR_DIR")
        .map_or_else(|| PathBuf::from("/usr/lib/kennel"), PathBuf::from);
    paths.push(vendor.join(CATALOGUE_FILENAME));
    let etc = std::env::var_os("KENNEL_ETC_DIR")
        .map_or_else(|| PathBuf::from("/etc/kennel"), PathBuf::from);
    paths.push(etc.join(CATALOGUE_FILENAME));
    let user = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    if let Some(cfg) = user {
        paths.push(cfg.join("kennel").join(CATALOGUE_FILENAME));
    }
    paths
}

/// A top-level `.trust-manifest.json`. Mirrors `docs/schemas/trust-manifest-v2.json`;
/// `deny_unknown_fields` so an unknown key is a hard error, never a silent bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema version (`"2.0"`).
    pub version: String,
    /// The tool that generated or last updated this manifest.
    pub generator: String,
    /// What host tooling is allowed to execute.
    pub execution: Execution,
}

/// The `execution` block: pinned triggers + negative-trust boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    /// Relative file path → its pinned record ([`TriggerEntry`]). Host tools refuse to
    /// execute a listed file whose on-disk hash differs from the entry's `sha256`. A
    /// `BTreeMap` so the serialized order is deterministic (stable diffs, reproducible bytes).
    pub triggers: BTreeMap<String, TriggerEntry>,
    /// Negative trust spaces — host tools treat these paths/globs as no-exec.
    pub boundaries: Boundaries,
}

/// What a pinned trigger is — a regular file whose bytes are pinned, or a symlink whose
/// target is pinned (an escaping link is itself a trigger class, §2.1 / W2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    /// A regular file: `sha256` pins its content (a blob lives in the store).
    #[default]
    Content,
    /// A symlink: `target` pins where it points; `sha256` is unused (no content blob).
    Symlink,
}

/// One pinned trigger's record (schema v2).
///
/// Carries what diff/restore/symlink need beyond the bare hash: the kind, the file mode (so a
/// `revert` cannot silently drop a setuid/setgid/sticky bit), the catalogue entry that
/// matched (provenance), and whether the pin came from a `compile` or a `review`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerEntry {
    /// Whether this is a content file or an escaping symlink.
    pub kind: TriggerKind,
    /// `content`: the pinned content hash `sha256:<64-hex>` (the blob's address in the
    /// store). `symlink`: the empty string (the link has no content blob).
    pub sha256: String,
    /// `symlink`: the pinned link target. Absent for a `content` trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The file mode as octal (`"0644"`, `"0755"`). Preserved across a revert — the
    /// setuid/setgid/sticky bits are security-relevant and must never be lost.
    pub mode: String,
    /// Which catalogue entry matched this path (provenance); `"builtin"` for the compiled
    /// default set.
    pub pattern: String,
    /// How this pin was established: `"compile"` or `"review"`.
    pub pinned: String,
}

/// The `boundaries` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundaries {
    /// Relative paths or globs that are strictly untrusted.
    pub untrusted_paths: Vec<String>,
}

/// Errors generating, parsing, or reviewing a manifest.
#[derive(Debug)]
pub enum Error {
    /// A filesystem read/write failed.
    Io(std::io::Error),
    /// The manifest is not valid JSON or violates the schema shape.
    Parse(serde_json::Error),
    /// `sha256sum` was unavailable or failed on a trigger file.
    Hash(String),
    /// The parsed manifest carries an unexpected `version`.
    Version(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "manifest io: {e}"),
            Self::Parse(e) => write!(f, "manifest parse: {e}"),
            Self::Hash(m) => write!(f, "manifest hash: {m}"),
            Self::Version(v) => write!(
                f,
                "unsupported manifest version `{v}` (want `{SCHEMA_VERSION}`)"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e)
    }
}

impl Manifest {
    /// Serialize to the canonical on-disk JSON (pretty, trailing newline) — what host IDEs
    /// read and what `kennel review` writes back.
    ///
    /// # Errors
    /// [`Error::Parse`] if serialization fails (it does not for these types in practice).
    pub fn to_json(&self) -> Result<String, Error> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Parse a manifest from JSON bytes, rejecting an unexpected schema version.
    ///
    /// # Errors
    /// [`Error::Parse`] for malformed JSON / unknown fields; [`Error::Version`] for a
    /// version this crate does not understand.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let m: Self = serde_json::from_slice(bytes)?;
        if m.version != SCHEMA_VERSION {
            return Err(Error::Version(m.version));
        }
        Ok(m)
    }
}

/// Compute `sha256:<64-hex>` for a file via the system `sha256sum`, exactly as kenneld's
/// workload-pin verify does (no in-crate crypto; cf. `no-hand-rolled-crypto`).
///
/// # Errors
/// [`Error::Hash`] if `sha256sum` is unavailable, exits non-zero, or prints no digest.
pub fn hash_file(path: &Path) -> Result<String, Error> {
    let out = Command::new("sha256sum")
        .arg("-b")
        .arg(path)
        .output()
        .map_err(|e| Error::Hash(format!("running sha256sum on {}: {e}", path.display())))?;
    if !out.status.success() {
        return Err(Error::Hash(format!(
            "sha256sum failed on {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let hex = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Hash(format!(
            "sha256sum gave an unexpected digest for {}: {hex:?}",
            path.display()
        )));
    }
    Ok(format!("sha256:{hex}"))
}

/// Enumerate the execution triggers present beneath `root`, per the effective `catalogue`.
///
/// Each catalogue file-trigger that exists, plus every immediate file under each catalogue
/// directory-trigger. Returns relative paths (forward-slash), sorted, deduplicated.
#[must_use]
pub fn enumerate_triggers(root: &Path, catalogue: &Catalogue) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for name in &catalogue.files {
        if root.join(name).is_file() {
            found.push(name.clone());
        }
    }
    for dir in &catalogue.dirs {
        let abs = root.join(dir);
        let Ok(entries) = std::fs::read_dir(&abs) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    found.push(format!("{dir}/{name}"));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Bounds on the escaping-symlink walk so a hostile/huge tree cannot make enumeration
/// unbounded — best-effort beyond these (the teardown review re-walks each run).
const MAX_WALK_DEPTH: u32 = 64;
const MAX_WALK_ENTRIES: u32 = 100_000;

/// Lexically normalise a path (fold `.` and `..` without touching the filesystem), so an
/// escape check does not depend on the target existing.
fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<Component<'_>> = Vec::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                if !matches!(out.last(), Some(Component::RootDir) | None) {
                    out.pop();
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out.iter().collect()
}

/// Whether the symlink at `link` points outside `root` — an absolute target elsewhere, or a
/// relative one that climbs above `root`. Lexical (no target follow); `link` and `root` share
/// the same (walk-root) base, so the comparison needs no canonicalisation.
fn symlink_escapes(link: &Path, root: &Path) -> bool {
    let Ok(target) = std::fs::read_link(link) else {
        return false;
    };
    let resolved = if target.is_absolute() {
        target
    } else {
        link.parent().unwrap_or(root).join(&target)
    };
    !lexical_normalize(&resolved).starts_with(lexical_normalize(root))
}

/// Find symlinks beneath `root` whose target escapes the writable boundary (§2.1, T2.8).
///
/// A planted escaping link is a persistence / exfiltration trigger: the host later follows it
/// out of the project. Returns relative paths (forward-slash), sorted, deduplicated.
///
/// A **bounded** walk (depth + entry caps); a tree larger than the caps is covered
/// best-effort, like the rest of the live watch, with the teardown review as the backstop.
/// The blob store (`.trust-manifest.d`) is skipped.
#[must_use]
pub fn enumerate_escaping_symlinks(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    let mut budget = MAX_WALK_ENTRIES;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_WALK_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 {
                break;
            }
            budget = budget.saturating_sub(1);
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_symlink() {
                if symlink_escapes(&path, root) {
                    if let Ok(rel) = path.strip_prefix(root) {
                        found.push(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            } else if file_type.is_dir() && entry.file_name() != STORE_DIRNAME {
                stack.push((path, depth.saturating_add(1)));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The full on-disk trigger set: catalogue triggers plus escaping symlinks (§2.1).
#[must_use]
pub fn enumerate_all_triggers(root: &Path, catalogue: &Catalogue) -> Vec<String> {
    let mut all = enumerate_triggers(root, catalogue);
    all.extend(enumerate_escaping_symlinks(root));
    all.sort();
    all.dedup();
    all
}

/// The blob store directory for a workspace `root` (`<root>/.trust-manifest.d`).
#[must_use]
pub fn store_dir(root: &Path) -> PathBuf {
    root.join(STORE_DIRNAME)
}

/// The store filename (hex content-address) of a `sha256:<hex>` pin.
fn blob_name(sha: &str) -> &str {
    sha.strip_prefix("sha256:").unwrap_or(sha)
}

/// Create the blob store dir `0700` (operator-only) if absent.
fn create_store_dir(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

/// Store `path`'s bytes as a content-addressed blob, returning the `sha256:<hex>` pin.
///
/// Idempotent — an existing blob with the same address is identical bytes, so it is left as
/// is (content-addressed dedup).
///
/// # Errors
/// [`Error::Hash`] if the file cannot be hashed, [`Error::Io`] if the store write fails.
pub fn store_blob(root: &Path, path: &Path) -> Result<String, Error> {
    let sha = hash_file(path)?;
    let dir = store_dir(root);
    create_store_dir(&dir)?;
    let blob = dir.join(blob_name(&sha));
    if !blob.exists() {
        std::fs::copy(path, &blob)?;
    }
    Ok(sha)
}

/// Read the pinned blob `sha` from `root`'s store.
///
/// # Errors
/// [`Error::Io`] if the blob is missing or unreadable.
pub fn read_blob(root: &Path, sha: &str) -> Result<Vec<u8>, Error> {
    Ok(std::fs::read(store_dir(root).join(blob_name(sha)))?)
}

/// GC the blob store: remove every blob not referenced by a current `content` trigger.
///
/// Called after the index is (re)written (§3, steer 6), so the store holds exactly the
/// trusted baseline's blobs — bounded, no unreferenced accumulation, no prior history.
pub fn prune_store(root: &Path, manifest: &Manifest) {
    let dir = store_dir(root);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let keep: std::collections::BTreeSet<&str> = manifest
        .execution
        .triggers
        .values()
        .filter(|e| e.kind == TriggerKind::Content)
        .map(|e| blob_name(&e.sha256))
        .collect();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if !keep.contains(name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// The octal mode (`"0644"`, perm + setuid/setgid/sticky) of `path`, not following a symlink.
fn file_mode(path: &Path) -> Result<String, Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::symlink_metadata(path)?.permissions().mode() & 0o7777;
    Ok(format!("{mode:04o}"))
}

/// Pin one trigger `rel` under `root` into a [`TriggerEntry`]: a symlink records its target;
/// a regular file is hashed and its bytes stored as a blob. `pattern` is the matching
/// catalogue id (provenance), `pinned_by` is `"compile"` or `"review"`.
fn pin_entry(root: &Path, rel: &str, pattern: &str, pinned_by: &str) -> Result<TriggerEntry, Error> {
    let abs = root.join(rel);
    let mode = file_mode(&abs)?;
    if std::fs::symlink_metadata(&abs)?.file_type().is_symlink() {
        let target = std::fs::read_link(&abs)?.to_string_lossy().into_owned();
        Ok(TriggerEntry {
            kind: TriggerKind::Symlink,
            sha256: String::new(),
            target: Some(target),
            mode,
            pattern: pattern.to_owned(),
            pinned: pinned_by.to_owned(),
        })
    } else {
        Ok(TriggerEntry {
            kind: TriggerKind::Content,
            sha256: store_blob(root, &abs)?,
            target: None,
            mode,
            pattern: pattern.to_owned(),
            pinned: pinned_by.to_owned(),
        })
    }
}

/// Pin each relative trigger path under `root` into the `(path → entry)` map. A trigger that
/// cannot be pinned is skipped (rather than aborting the whole generation) — `errors`
/// collects the per-file failures for the caller to report.
fn pin_triggers(
    root: &Path,
    triggers: &[String],
    pinned_by: &str,
) -> (BTreeMap<String, TriggerEntry>, Vec<Error>) {
    let mut pinned = BTreeMap::new();
    let mut errors = Vec::new();
    for rel in triggers {
        match pin_entry(root, rel, "builtin", pinned_by) {
            Ok(entry) => {
                pinned.insert(rel.clone(), entry);
            }
            Err(e) => errors.push(e),
        }
    }
    (pinned, errors)
}

/// Build a baseline manifest for `root`.
///
/// Enumerate and pin the present execution triggers, seed the standard untrusted-path
/// boundaries, stamp `generator`. The returned `errors` are per-trigger hash failures
/// (the manifest is still usable without them).
#[must_use]
pub fn generate(root: &Path, generator: &str, catalogue: &Catalogue) -> (Manifest, Vec<Error>) {
    let triggers = enumerate_all_triggers(root, catalogue);
    // The baseline is the compile-time pin (the operator's `kennel compile`/`generate` step).
    let (pinned, errors) = pin_triggers(root, &triggers, "compile");
    let manifest = Manifest {
        version: SCHEMA_VERSION.to_owned(),
        generator: generator.to_owned(),
        execution: Execution {
            triggers: pinned,
            // The default negative-trust set: the catalogue's directory triggers, whose
            // contents are most dangerous to auto-execute.
            boundaries: Boundaries {
                untrusted_paths: catalogue.dirs.iter().map(|d| format!("{d}/**")).collect(),
            },
        },
    };
    (manifest, errors)
}

/// One trigger's state when reviewing a workspace against its manifest.
///
/// The divergent variants carry the pinned [`TriggerEntry`] so the caller can show a diff
/// (against the pinned blob) and [`revert`] can restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerChange {
    /// A pinned trigger whose on-disk hash still matches.
    Unchanged {
        /// Relative path.
        path: String,
    },
    /// A pinned trigger whose on-disk hash diverged (the host IDE would lock on this).
    Modified {
        /// Relative path.
        path: String,
        /// The pinned record (its `sha256` addresses the baseline blob to diff/restore).
        entry: TriggerEntry,
        /// The hash on disk now.
        current: String,
    },
    /// A pinned trigger that no longer exists on disk.
    Removed {
        /// Relative path.
        path: String,
        /// The pinned record — [`revert`] recreates the file from its blob.
        entry: TriggerEntry,
    },
    /// An execution trigger present on disk but absent from the manifest (created after
    /// generation — unpinned, the T2.8 residual `kennel review` surfaces). A planted one;
    /// [`revert`] removes it.
    New {
        /// Relative path.
        path: String,
        /// Its current hash.
        current: String,
    },
}

impl TriggerChange {
    /// Whether this change needs operator attention (anything but `Unchanged`).
    #[must_use]
    pub const fn is_divergence(&self) -> bool {
        !matches!(self, Self::Unchanged { .. })
    }
}

/// Compare the manifest's pins against the triggers on disk under `root`.
///
/// Returns every trigger's state (modified, removed, new, unchanged). This is what
/// `kennel review` renders as a diff and, on approval, folds back via [`apply_review`].
///
/// # Errors
/// [`Error::Hash`] if a present trigger cannot be hashed.
pub fn review(
    manifest: &Manifest,
    root: &Path,
    catalogue: &Catalogue,
) -> Result<Vec<TriggerChange>, Error> {
    let mut changes = Vec::new();
    // Pinned triggers: matched, modified, or removed. A content trigger compares its content
    // hash; a symlink trigger compares its link target.
    for (path, entry) in &manifest.execution.triggers {
        match disk_signature(&root.join(path))? {
            None => changes.push(TriggerChange::Removed {
                path: path.clone(),
                entry: entry.clone(),
            }),
            Some(current) => {
                let pinned = match entry.kind {
                    TriggerKind::Content => entry.sha256.clone(),
                    TriggerKind::Symlink => entry.target.clone().unwrap_or_default(),
                };
                if current == pinned {
                    changes.push(TriggerChange::Unchanged { path: path.clone() });
                } else {
                    changes.push(TriggerChange::Modified {
                        path: path.clone(),
                        entry: entry.clone(),
                        current,
                    });
                }
            }
        }
    }
    // Triggers on disk that the manifest never pinned (created after generation).
    for rel in enumerate_all_triggers(root, catalogue) {
        if !manifest.execution.triggers.contains_key(&rel) {
            if let Some(current) = disk_signature(&root.join(&rel))? {
                changes.push(TriggerChange::New { path: rel, current });
            }
        }
    }
    changes.sort_by(|a, b| change_path(a).cmp(change_path(b)));
    Ok(changes)
}

/// The on-disk signature of a trigger at `abs`: a regular file's content hash, or a symlink's
/// link target. `None` if it is absent (or a directory where a trigger was).
fn disk_signature(abs: &Path) -> Result<Option<String>, Error> {
    let Ok(meta) = abs.symlink_metadata() else {
        return Ok(None);
    };
    if meta.file_type().is_symlink() {
        Ok(Some(
            std::fs::read_link(abs)?.to_string_lossy().into_owned(),
        ))
    } else if meta.is_file() {
        Ok(Some(hash_file(abs)?))
    } else {
        Ok(None)
    }
}

/// The relative path a [`TriggerChange`] concerns (for stable ordering).
fn change_path(c: &TriggerChange) -> &str {
    match c {
        TriggerChange::Unchanged { path }
        | TriggerChange::Removed { path, .. }
        | TriggerChange::Modified { path, .. }
        | TriggerChange::New { path, .. } => path,
    }
}

/// Fold a reviewed set of changes back into the manifest (the operator's sign-off).
///
/// Re-pin every `Modified`/`New` trigger (re-hash + store its blob, stamped `"review"`), drop
/// every `Removed` pin, leave `Unchanged`, and bump the `generator`. Mutates `manifest` in
/// place.
///
/// Returns any per-trigger re-pin errors; the caller then writes [`Manifest::to_json`] and
/// [`prune_store`]s the now-unreferenced blobs.
pub fn apply_review(
    manifest: &mut Manifest,
    root: &Path,
    changes: &[TriggerChange],
    generator: &str,
) -> Vec<Error> {
    let mut errors = Vec::new();
    for change in changes {
        match change {
            TriggerChange::Modified { path, .. } | TriggerChange::New { path, .. } => {
                match pin_entry(root, path, "builtin", "review") {
                    Ok(entry) => {
                        manifest.execution.triggers.insert(path.clone(), entry);
                    }
                    Err(e) => errors.push(e),
                }
            }
            TriggerChange::Removed { path, .. } => {
                manifest.execution.triggers.remove(path);
            }
            TriggerChange::Unchanged { .. } => {}
        }
    }
    generator.clone_into(&mut manifest.generator);
    errors
}

/// Restore a divergent trigger to its pinned baseline (the `revert` teardown disposition, §2.5).
///
/// A `Modified`/`Removed` trigger is rewritten from its pinned blob (and a symlink re-pointed
/// at its pinned target), mode preserved; a `New` (unpinned, planted) trigger is removed.
/// Scoped to the one path — the rest of the tree is left untouched.
///
/// # Errors
/// [`Error::Io`] if the blob is missing or the filesystem write fails.
pub fn revert(root: &Path, change: &TriggerChange) -> Result<(), Error> {
    match change {
        TriggerChange::Modified { path, entry, .. } | TriggerChange::Removed { path, entry } => {
            restore_entry(root, path, entry)
        }
        TriggerChange::New { path, .. } => {
            // A catalogue-matching file with no pin is a planted trigger — remove it.
            std::fs::remove_file(root.join(path))?;
            Ok(())
        }
        TriggerChange::Unchanged { .. } => Ok(()),
    }
}

/// Recreate `path` from its pinned [`TriggerEntry`] — blob bytes + mode for a content
/// trigger, the pinned link target for a symlink.
fn restore_entry(root: &Path, path: &str, entry: &TriggerEntry) -> Result<(), Error> {
    let abs = root.join(path);
    match entry.kind {
        TriggerKind::Content => {
            let bytes = read_blob(root, &entry.sha256)?;
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&abs, bytes)?;
            set_mode(&abs, &entry.mode)?;
        }
        TriggerKind::Symlink => {
            if abs.symlink_metadata().is_ok() {
                std::fs::remove_file(&abs)?;
            }
            std::os::unix::fs::symlink(entry.target.as_deref().unwrap_or(""), &abs)?;
        }
    }
    Ok(())
}

/// Apply an octal mode string (`"0755"`) to `path`.
fn set_mode(path: &Path, mode: &str) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let bits = u32::from_str_radix(mode, 8)
        .map_err(|e| Error::Hash(format!("bad mode `{mode}`: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))?;
    Ok(())
}

/// The absolute path of the manifest at a workspace `root`.
#[must_use]
pub fn manifest_path(root: &Path) -> PathBuf {
    root.join(MANIFEST_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-contained trigger set for the tests (no dependency on the shipped default).
    fn sample_catalogue() -> Catalogue {
        let mut cat = Catalogue::default();
        cat.apply_layer("Makefile\nJustfile\npackage.json\n.git/hooks/\n");
        cat
    }

    fn content_entry(fill: char) -> TriggerEntry {
        TriggerEntry {
            kind: TriggerKind::Content,
            sha256: format!("sha256:{}", String::from(fill).repeat(64)),
            target: None,
            mode: "0644".to_owned(),
            pattern: "builtin".to_owned(),
            pinned: "compile".to_owned(),
        }
    }

    fn sample() -> Manifest {
        let mut triggers = BTreeMap::new();
        triggers.insert("Makefile".to_owned(), content_entry('a'));
        Manifest {
            version: SCHEMA_VERSION.to_owned(),
            generator: "kennel-test".to_owned(),
            execution: Execution {
                triggers,
                boundaries: Boundaries {
                    untrusted_paths: vec![".git/hooks/**".to_owned()],
                },
            },
        }
    }

    #[test]
    fn round_trips_through_json() {
        let m = sample();
        let json = m.to_json().expect("serialize");
        let back = Manifest::from_json(json.as_bytes()).expect("parse");
        assert_eq!(m, back);
        assert!(
            json.ends_with('\n'),
            "canonical form has a trailing newline"
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = br#"{"version":"1.0","generator":"x","execution":{"triggers":{},"boundaries":{"untrusted_paths":[]}},"rogue":1}"#;
        let err = Manifest::from_json(json).expect_err("unknown field must fail");
        assert!(matches!(err, Error::Parse(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let json = br#"{"version":"9.9","generator":"x","execution":{"triggers":{},"boundaries":{"untrusted_paths":[]}}}"#;
        let err = Manifest::from_json(json).expect_err("bad version must fail");
        assert!(
            matches!(err, Error::Version(ref v) if v == "9.9"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_a_missing_required_block() {
        // No `boundaries` — the schema requires it.
        let json = br#"{"version":"1.0","generator":"x","execution":{"triggers":{}}}"#;
        assert!(matches!(Manifest::from_json(json), Err(Error::Parse(_))));
    }

    #[test]
    fn generate_pins_present_triggers_and_seeds_boundaries() {
        let dir = tmpdir();
        std::fs::write(dir.join("Makefile"), b"all:\n\techo hi\n").expect("write");
        std::fs::write(dir.join("README.md"), b"not a trigger\n").expect("write");
        let (m, errors) = generate(&dir, "kennel-test", &sample_catalogue());
        assert!(errors.is_empty(), "hashing should succeed: {errors:?}");
        assert!(
            m.execution.triggers.contains_key("Makefile"),
            "the Makefile is pinned"
        );
        assert!(
            m.execution
                .triggers
                .get("Makefile")
                .is_some_and(|e| e.sha256.starts_with("sha256:") && e.kind == TriggerKind::Content),
            "pin is a content sha256: hash"
        );
        let makefile = m.execution.triggers.get("Makefile").expect("pinned");
        assert!(
            store_dir(&dir).join(blob_name(&makefile.sha256)).is_file(),
            "the pinned content is stored as a blob"
        );
        assert!(
            !m.execution.triggers.contains_key("README.md"),
            "a non-trigger is not pinned"
        );
        assert!(m
            .execution
            .boundaries
            .untrusted_paths
            .iter()
            .any(|p| p == ".git/hooks/**"));
        cleanup(&dir);
    }

    #[test]
    fn review_flags_modified_removed_and_new_triggers() {
        let dir = tmpdir();
        std::fs::write(dir.join("Makefile"), b"original\n").expect("write");
        std::fs::write(dir.join("Justfile"), b"recipe\n").expect("write");
        let (mut m, _) = generate(&dir, "kennel-test", &sample_catalogue());
        // Modify the Makefile, remove the Justfile, add a package.json (a new trigger).
        std::fs::write(dir.join("Makefile"), b"TAMPERED\n").expect("write");
        std::fs::remove_file(dir.join("Justfile")).expect("rm");
        std::fs::write(dir.join("package.json"), b"{}\n").expect("write");

        let changes = review(&m, &dir, &sample_catalogue()).expect("review");
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::Modified { path, .. } if path == "Makefile")),
            "the tampered Makefile shows Modified: {changes:?}"
        );
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::Removed { path, .. } if path == "Justfile")),
            "the deleted Justfile shows Removed"
        );
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::New { path, .. } if path == "package.json")),
            "the new package.json shows New"
        );

        // Operator sign-off: re-pin everything; a fresh review is then all-clean.
        let errs = apply_review(&mut m, &dir, &changes, "kennel-review");
        assert!(errs.is_empty(), "re-pin should succeed: {errs:?}");
        let after = review(&m, &dir, &sample_catalogue()).expect("review again");
        assert!(
            after.iter().all(|c| !c.is_divergence()),
            "after sign-off every trigger is Unchanged: {after:?}"
        );
        assert_eq!(m.generator, "kennel-review");
        cleanup(&dir);
    }

    #[test]
    fn revert_restores_a_tampered_trigger_and_removes_a_planted_one() {
        let dir = tmpdir();
        std::fs::write(dir.join("Makefile"), b"all:\n\techo trusted\n").expect("write");
        let (m, errors) = generate(&dir, "kennel-test", &sample_catalogue());
        assert!(errors.is_empty(), "{errors:?}");

        // The "workload" tampers the Makefile and plants a new package.json.
        std::fs::write(dir.join("Makefile"), b"all:\n\techo PWNED\n").expect("tamper");
        std::fs::write(dir.join("package.json"), b"{\"evil\":true}\n").expect("plant");

        let changes = review(&m, &dir, &sample_catalogue()).expect("review");
        for change in &changes {
            revert(&dir, change).expect("revert");
        }

        assert_eq!(
            std::fs::read(dir.join("Makefile")).expect("read"),
            b"all:\n\techo trusted\n",
            "the tampered Makefile is restored to its pinned content"
        );
        assert!(
            !dir.join("package.json").exists(),
            "the planted (unpinned) trigger is removed"
        );
        cleanup(&dir);
    }

    #[test]
    fn revert_preserves_an_executable_hooks_mode_and_recreates_a_deletion() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let hooks = dir.join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("mkdir hooks");
        let hook = hooks.join("post-commit");
        std::fs::write(&hook, b"#!/bin/sh\necho ok\n").expect("write hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let (m, errors) = generate(&dir, "kennel-test", &sample_catalogue());
        assert!(errors.is_empty(), "{errors:?}");

        // Delete the pinned hook; revert must recreate it with its 0755 mode.
        std::fs::remove_file(&hook).expect("rm hook");
        let changes = review(&m, &dir, &sample_catalogue()).expect("review");
        for change in &changes {
            revert(&dir, change).expect("revert");
        }
        let mode = std::fs::metadata(&hook).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "the executable bit survives the revert (got {mode:o})");
        cleanup(&dir);
    }

    #[test]
    fn prune_store_drops_unreferenced_blobs() {
        let dir = tmpdir();
        std::fs::write(dir.join("Makefile"), b"v1\n").expect("write");
        let (mut m, _) = generate(&dir, "kennel-test", &sample_catalogue());
        // A new content version leaves the old blob behind until pruned.
        std::fs::write(dir.join("Makefile"), b"v2\n").expect("rewrite");
        let changes = review(&m, &dir, &sample_catalogue()).expect("review");
        apply_review(&mut m, &dir, &changes, "kennel-review");
        let blobs = || std::fs::read_dir(store_dir(&dir)).expect("ls").count();
        assert_eq!(blobs(), 2, "both the v1 and v2 blobs exist before pruning");
        prune_store(&dir, &m);
        assert_eq!(blobs(), 1, "only the referenced (v2) blob survives");
        cleanup(&dir);
    }

    #[test]
    fn escaping_symlinks_are_detected_pinned_and_reverted() {
        let dir = tmpdir();
        std::fs::write(dir.join("real.txt"), b"x").expect("write");
        // An in-tree link does not escape; an absolute and a climbing link do.
        std::os::unix::fs::symlink("real.txt", dir.join("inside.lnk")).expect("inside");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("escape.lnk")).expect("abs escape");
        std::os::unix::fs::symlink("../../../etc/hosts", dir.join("climb.lnk")).expect("climb");

        let escaping = enumerate_escaping_symlinks(&dir);
        assert!(escaping.iter().any(|p| p == "escape.lnk"), "abs escape: {escaping:?}");
        assert!(escaping.iter().any(|p| p == "climb.lnk"), "climb escape: {escaping:?}");
        assert!(!escaping.iter().any(|p| p == "inside.lnk"), "in-tree link not flagged");

        // generate pins the escaping links as symlink-kind entries.
        let (m, _) = generate(&dir, "t", &sample_catalogue());
        assert!(
            m.execution
                .triggers
                .get("escape.lnk")
                .is_some_and(|e| e.kind == TriggerKind::Symlink && e.target.as_deref() == Some("/etc/passwd")),
            "the escaping link is pinned as a symlink with its target"
        );

        // A NEW escaping link planted after generation shows as New; revert removes it.
        std::os::unix::fs::symlink("/root/.bashrc", dir.join("planted.lnk")).expect("plant");
        let changes = review(&m, &dir, &sample_catalogue()).expect("review");
        let planted = changes
            .iter()
            .find(|c| matches!(c, TriggerChange::New { path, .. } if path == "planted.lnk"))
            .expect("planted link shows New");
        revert(&dir, planted).expect("revert");
        assert!(
            dir.join("planted.lnk").symlink_metadata().is_err(),
            "the planted escaping link is removed"
        );
        // The pinned escaping link survives a clean review (Unchanged).
        let after = review(&m, &dir, &sample_catalogue()).expect("review2");
        assert!(
            after
                .iter()
                .any(|c| matches!(c, TriggerChange::Unchanged { path } if path == "escape.lnk")),
            "the pinned escaping link compares Unchanged by target"
        );
        cleanup(&dir);
    }

    #[test]
    fn catalogue_layers_are_additive_with_prune() {
        let mut cat = sample_catalogue();
        assert!(cat.files.iter().any(|f| f == "Makefile"));
        // A system layer widens the set (a file + a dir trigger); a comment is ignored.
        cat.apply_layer("# widen\n.envrc\nbuild/hooks/\n");
        assert!(cat.files.iter().any(|f| f == ".envrc"), "added a file trigger");
        assert!(cat.dirs.iter().any(|d| d == "build/hooks"), "added a dir trigger");
        let files_before = cat.files.len();
        // Re-adding an existing pattern is a no-op (additive union, not duplication).
        cat.apply_layer("Makefile\n");
        assert_eq!(cat.files.len(), files_before, "no duplicate on re-add");
        // A per-user layer prunes one entry with a leading `-`.
        cat.apply_layer("-Makefile\n-build/hooks/\n");
        assert!(!cat.files.iter().any(|f| f == "Makefile"), "pruned the file");
        assert!(!cat.dirs.iter().any(|d| d == "build/hooks"), "pruned the dir");
        // An empty layer changes nothing (no "empty = off").
        let snapshot = cat.clone();
        cat.apply_layer("\n  \n# only comments\n");
        assert_eq!(cat, snapshot, "an empty/comment-only layer is a no-op");
    }

    // --- tiny tmpdir helpers (no external dev-dep; std-only) ---

    fn tmpdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        // A unique-enough name without Math::random (forbidden in some contexts): pid + a
        // monotonic counter.
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir();
        let dir = base.join(format!(
            "kennel-manifest-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
