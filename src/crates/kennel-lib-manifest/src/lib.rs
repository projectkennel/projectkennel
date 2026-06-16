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
//! `docs/schemas/trust-manifest-v1.json`, `deny_unknown_fields` so a typo can't silently
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
pub const SCHEMA_VERSION: &str = "1.0";

/// The published JSON Schema `$id` host IDEs validate against (served from the repo's
/// `docs/schemas/`).
pub const SCHEMA_ID: &str = "https://projectkennel.org/schemas/trust-manifest-v1.json";

/// The manifest filename, at the root of every writable/persistent workspace.
pub const MANIFEST_FILENAME: &str = ".trust-manifest.json";

/// The standard execution triggers [`generate`] enumerates and pins.
///
/// A host tool refuses to execute one of these whose on-disk hash diverges from its pin.
/// The list is deliberately fixed and documented (extensible later) — a baseline, not
/// exhaustive.
pub const KNOWN_TRIGGERS: &[&str] = &[
    "Makefile",
    "makefile",
    "GNUmakefile",
    "Justfile",
    "justfile",
    "Taskfile.yml",
    "Taskfile.yaml",
    "package.json",
    ".vscode/tasks.json",
    ".vscode/launch.json",
];

/// The directory prefixes whose immediate entries are treated as triggers (each file
/// beneath is hashed) — e.g. every script in `.git/hooks/`.
pub const KNOWN_TRIGGER_DIRS: &[&str] = &[".git/hooks"];

/// A top-level `.trust-manifest.json`. Mirrors `docs/schemas/trust-manifest-v1.json`;
/// `deny_unknown_fields` so an unknown key is a hard error, never a silent bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Schema version (`"1.0"`).
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
    /// Relative file path → expected hash (`sha256:<64-hex>`). Host tools refuse to
    /// execute a listed file whose on-disk hash differs. A `BTreeMap` so the serialized
    /// order is deterministic (stable diffs, reproducible bytes).
    pub triggers: BTreeMap<String, String>,
    /// Negative trust spaces — host tools treat these paths/globs as no-exec.
    pub boundaries: Boundaries,
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

/// Enumerate the execution triggers present beneath `root`.
///
/// Each [`KNOWN_TRIGGERS`] file that exists, plus every immediate file under each
/// [`KNOWN_TRIGGER_DIRS`] directory. Returns relative paths (forward-slash), sorted,
/// deduplicated.
#[must_use]
pub fn enumerate_triggers(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for name in KNOWN_TRIGGERS {
        if root.join(name).is_file() {
            found.push((*name).to_owned());
        }
    }
    for dir in KNOWN_TRIGGER_DIRS {
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

/// Hash each relative trigger path under `root` into the pinned `(path → sha256:…)` map.
/// A trigger that cannot be hashed is skipped (it is not pinned rather than aborting the
/// whole generation) — `errors` collects the per-file failures for the caller to report.
fn pin_triggers(root: &Path, triggers: &[String]) -> (BTreeMap<String, String>, Vec<Error>) {
    let mut pinned = BTreeMap::new();
    let mut errors = Vec::new();
    for rel in triggers {
        match hash_file(&root.join(rel)) {
            Ok(hash) => {
                pinned.insert(rel.clone(), hash);
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
pub fn generate(root: &Path, generator: &str) -> (Manifest, Vec<Error>) {
    let triggers = enumerate_triggers(root);
    let (pinned, errors) = pin_triggers(root, &triggers);
    let manifest = Manifest {
        version: SCHEMA_VERSION.to_owned(),
        generator: generator.to_owned(),
        execution: Execution {
            triggers: pinned,
            // The default negative-trust set: the directories whose contents are most
            // dangerous to auto-execute. The operator can extend this in the file.
            boundaries: Boundaries {
                untrusted_paths: KNOWN_TRIGGER_DIRS
                    .iter()
                    .map(|d| format!("{d}/**"))
                    .collect(),
            },
        },
    };
    (manifest, errors)
}

/// One trigger's state when reviewing a workspace against its manifest.
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
        /// The hash the manifest pins.
        pinned: String,
        /// The hash on disk now.
        current: String,
    },
    /// A pinned trigger that no longer exists on disk.
    Removed {
        /// Relative path.
        path: String,
    },
    /// An execution trigger present on disk but absent from the manifest (created after
    /// generation — unpinned, the T2.8 residual `kennel review` surfaces).
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
pub fn review(manifest: &Manifest, root: &Path) -> Result<Vec<TriggerChange>, Error> {
    let mut changes = Vec::new();
    // Pinned triggers: matched, modified, or removed.
    for (path, pinned) in &manifest.execution.triggers {
        let abs = root.join(path);
        if abs.is_file() {
            let current = hash_file(&abs)?;
            if &current == pinned {
                changes.push(TriggerChange::Unchanged { path: path.clone() });
            } else {
                changes.push(TriggerChange::Modified {
                    path: path.clone(),
                    pinned: pinned.clone(),
                    current,
                });
            }
        } else {
            changes.push(TriggerChange::Removed { path: path.clone() });
        }
    }
    // Triggers on disk that the manifest never pinned (created after generation).
    for rel in enumerate_triggers(root) {
        if !manifest.execution.triggers.contains_key(&rel) {
            let current = hash_file(&root.join(rel.clone()))?;
            changes.push(TriggerChange::New { path: rel, current });
        }
    }
    changes.sort_by(|a, b| change_path(a).cmp(change_path(b)));
    Ok(changes)
}

/// The relative path a [`TriggerChange`] concerns (for stable ordering).
fn change_path(c: &TriggerChange) -> &str {
    match c {
        TriggerChange::Unchanged { path }
        | TriggerChange::Removed { path }
        | TriggerChange::Modified { path, .. }
        | TriggerChange::New { path, .. } => path,
    }
}

/// Fold a reviewed set of changes back into the manifest (the operator's sign-off).
///
/// Adopt every `Modified`/`New` hash, drop every `Removed` pin, leave `Unchanged` and bump
/// the `generator`. Mutates `manifest` in place; the caller then writes
/// [`Manifest::to_json`].
pub fn apply_review(manifest: &mut Manifest, changes: &[TriggerChange], generator: &str) {
    for change in changes {
        match change {
            TriggerChange::Modified { path, current, .. }
            | TriggerChange::New { path, current } => {
                manifest
                    .execution
                    .triggers
                    .insert(path.clone(), current.clone());
            }
            TriggerChange::Removed { path } => {
                manifest.execution.triggers.remove(path);
            }
            TriggerChange::Unchanged { .. } => {}
        }
    }
    generator.clone_into(&mut manifest.generator);
}

/// The absolute path of the manifest at a workspace `root`.
#[must_use]
pub fn manifest_path(root: &Path) -> PathBuf {
    root.join(MANIFEST_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        let mut triggers = BTreeMap::new();
        triggers.insert("Makefile".to_owned(), format!("sha256:{}", "a".repeat(64)));
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
        let (m, errors) = generate(&dir, "kennel-test");
        assert!(errors.is_empty(), "hashing should succeed: {errors:?}");
        assert!(
            m.execution.triggers.contains_key("Makefile"),
            "the Makefile is pinned"
        );
        assert!(
            m.execution
                .triggers
                .get("Makefile")
                .is_some_and(|h| h.starts_with("sha256:")),
            "pin is a sha256: hash"
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
        let (mut m, _) = generate(&dir, "kennel-test");
        // Modify the Makefile, remove the Justfile, add a package.json (a new trigger).
        std::fs::write(dir.join("Makefile"), b"TAMPERED\n").expect("write");
        std::fs::remove_file(dir.join("Justfile")).expect("rm");
        std::fs::write(dir.join("package.json"), b"{}\n").expect("write");

        let changes = review(&m, &dir).expect("review");
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::Modified { path, .. } if path == "Makefile")),
            "the tampered Makefile shows Modified: {changes:?}"
        );
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::Removed { path } if path == "Justfile")),
            "the deleted Justfile shows Removed"
        );
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, TriggerChange::New { path, .. } if path == "package.json")),
            "the new package.json shows New"
        );

        // Operator sign-off: re-pin everything; a fresh review is then all-clean.
        apply_review(&mut m, &changes, "kennel-review");
        let after = review(&m, &dir).expect("review again");
        assert!(
            after.iter().all(|c| !c.is_divergence()),
            "after sign-off every trigger is Unchanged: {after:?}"
        );
        assert_eq!(m.generator, "kennel-review");
        cleanup(&dir);
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
