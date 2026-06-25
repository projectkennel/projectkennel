//! Compute the crate inventory from the workspace itself (std-only).
//!
//! The inventory that `03-crate-decomposition.md` documents drifts on every crate-graph change
//! (a new crate, a vendored dep, a moved edge). Rather than hand-maintain it, this derives every
//! mechanical fact from the tree:
//!
//! - **SLOC** — a `#[cfg(test)]`-stripped, comment-and-blank-excluding line count per crate
//!   ([`sloc`]); the method matches the doc's prior hand counts exactly on unchanged crates.
//! - **`unsafe`** — whether the crate actually uses the `unsafe` keyword (not the
//!   `#![forbid(unsafe_code)]` attribute).
//! - **TCB membership** — the transitive first-party dependency closure of the three trusted
//!   binaries (`kenneld`, `kennel-privhelper`, `kennel-bin-init`); a crate is in the TCB iff its
//!   compromise could break confinement.
//! - **Consumers / external deps** — the reverse first-party edges, and each crate's non-Project
//!   external (vendored) dependencies, both read from the crates' `[dependencies]` tables.
//!
//! [`Inventory::compute`] is the entry point; [`crate::render`] turns it into the markdown table and
//! [`crate::json`] into the committed source-of-truth artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub mod json;
pub mod render;
pub mod sloc;

/// The three trusted binaries whose dependency closure defines the runtime TCB. (The privhelper's
/// capability-split sub-helpers are extra binaries of the `kennel-privhelper` crate, so their code
/// is counted within it.)
pub const TCB_ROOTS: [&str; 3] = ["kenneld", "kennel-privhelper", "kennel-bin-init"];

/// One crate's mechanical facts.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// The package name (`name` in `[package]`).
    pub name: String,
    /// SLOC excluding `#[cfg(test)]` modules, comments, and blanks.
    pub sloc: usize,
    /// Whether the crate uses the `unsafe` keyword (the §4 quarantine marker).
    pub uses_unsafe: bool,
    /// Whether the crate is in the daemon TCB (the closure of [`TCB_ROOTS`]).
    pub in_tcb: bool,
    /// First-party (`kennel-*`) crates that depend on this one, short-named, sorted.
    pub consumers: Vec<String>,
    /// The crate's `[[bin]]` target names (or the package name when it has a bare `src/main.rs`).
    pub bins: Vec<String>,
    /// First-party crates this one depends on (full names).
    pub fp_deps: Vec<String>,
    /// External (non-`kennel-*`) dependency names, sorted.
    pub ext_deps: Vec<String>,
}

/// The whole workspace inventory plus the totals the doc reports.
#[derive(Debug, Clone)]
pub struct Inventory {
    /// Every crate, sorted by SLOC descending (the table order).
    pub crates: Vec<CrateInfo>,
    /// Total number of crates.
    pub crate_count: usize,
    /// Sum of every crate's SLOC.
    pub total_sloc: usize,
    /// Number of crates in the daemon TCB closure.
    pub tcb_count: usize,
    /// Sum of the TCB crates' SLOC.
    pub tcb_sloc: usize,
}

impl Inventory {
    /// Compute the inventory from the crates under `crates_dir` (e.g. `src/crates`).
    ///
    /// # Errors
    /// An I/O error if a crate directory or its `Cargo.toml` cannot be read.
    pub fn compute(crates_dir: &Path) -> std::io::Result<Self> {
        // 1. Discover each crate: name, deps (first-party vs external), bins, SLOC, unsafe.
        let mut raw: Vec<CrateInfo> = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(crates_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        entries.sort();
        for dir in &entries {
            let manifest = dir.join("Cargo.toml");
            if !manifest.is_file() {
                continue;
            }
            let toml = std::fs::read_to_string(&manifest)?;
            let name = package_name(&toml).unwrap_or_else(|| dir_name(dir));
            let (fp_deps, ext_deps) = parse_deps(&toml);
            let bins = bin_targets(&toml, dir, &name);
            let src = dir.join("src");
            raw.push(CrateInfo {
                name,
                sloc: sloc::count_dir(&src)?,
                uses_unsafe: sloc::uses_unsafe(&src)?,
                in_tcb: false,         // filled below
                consumers: Vec::new(), // filled below
                bins,
                fp_deps,
                ext_deps,
            });
        }

        // 2. First-party edge map → TCB closure (BFS from the roots) and reverse edges (consumers).
        let names: BTreeSet<&str> = raw.iter().map(|c| c.name.as_str()).collect();
        let edges: BTreeMap<&str, Vec<&str>> = raw
            .iter()
            .map(|c| {
                let deps = c
                    .fp_deps
                    .iter()
                    .map(String::as_str)
                    .filter(|d| names.contains(d))
                    .collect();
                (c.name.as_str(), deps)
            })
            .collect();

        let tcb: BTreeSet<String> = tcb_closure(&edges)
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut consumers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for c in &raw {
            for dep in &c.fp_deps {
                if names.contains(dep.as_str()) {
                    consumers
                        .entry(dep.clone())
                        .or_default()
                        .insert(short_name(&c.name));
                }
            }
        }
        // `edges`/`names` borrow `raw`; drop them before the mutation below.
        drop(edges);
        drop(names);

        for c in &mut raw {
            c.in_tcb = tcb.contains(&c.name);
            c.consumers = consumers
                .get(&c.name)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
        }

        // 3. Sort by SLOC descending (ties broken by name for determinism) and total.
        raw.sort_by(|a, b| b.sloc.cmp(&a.sloc).then_with(|| a.name.cmp(&b.name)));
        let crate_count = raw.len();
        let total_sloc = raw.iter().map(|c| c.sloc).sum();
        let tcb_count = raw.iter().filter(|c| c.in_tcb).count();
        let tcb_sloc = raw.iter().filter(|c| c.in_tcb).map(|c| c.sloc).sum();
        Ok(Self {
            crates: raw,
            crate_count,
            total_sloc,
            tcb_count,
            tcb_sloc,
        })
    }
}

/// The transitive first-party dependency closure of [`TCB_ROOTS`] over `edges`.
fn tcb_closure<'a>(edges: &BTreeMap<&'a str, Vec<&'a str>>) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<&str> = TCB_ROOTS
        .iter()
        .filter(|r| edges.contains_key(**r))
        .copied()
        .collect();
    while let Some(n) = stack.pop() {
        if !seen.insert(n) {
            continue;
        }
        if let Some(deps) = edges.get(n) {
            stack.extend(deps.iter().copied());
        }
    }
    seen
}

/// The package `name` from a `Cargo.toml`'s `[package]` table.
fn package_name(toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package {
            if let Some(v) = t.strip_prefix("name") {
                if let Some(q) = v.trim_start().strip_prefix('=') {
                    return Some(q.trim().trim_matches('"').to_owned());
                }
            }
        }
    }
    None
}

/// Parse the `[dependencies]` table into `(first-party kennel-* deps, external deps)`.
///
/// Only the `[dependencies]` table is read — not `[dev-dependencies]` or `[build-dependencies]`
/// (a dev/build dep is not linked into the shipped binary, so it is not part of the runtime graph).
/// Each entry is one line `name = …`; comments and blanks are skipped; the table ends at the next
/// `[section]`.
fn parse_deps(toml: &str) -> (Vec<String>, Vec<String>) {
    let mut fp = Vec::new();
    let mut ext = Vec::new();
    let mut in_deps = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((name, _)) = t.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"').to_owned();
        if name.is_empty() {
            continue;
        }
        if name.starts_with("kennel-") {
            fp.push(name);
        } else {
            ext.push(name);
        }
    }
    fp.sort();
    ext.sort();
    (fp, ext)
}

/// The crate's binary-target names: explicit `[[bin]]` `name`s, plus Cargo's auto-discovered
/// targets — `src/bin/*.rs` (each file a binary) and a bare `src/main.rs` (the package name).
fn bin_targets(toml: &str, dir: &Path, package: &str) -> Vec<String> {
    let mut bins = BTreeSet::new();
    let mut explicit = false;
    let mut in_bin = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_bin = t == "[[bin]]";
            continue;
        }
        if in_bin {
            if let Some(v) = t.strip_prefix("name") {
                if let Some(q) = v.trim_start().strip_prefix('=') {
                    bins.insert(q.trim().trim_matches('"').to_owned());
                    explicit = true;
                }
            }
        }
    }
    // `src/bin/<name>.rs` always auto-discovers a binary, even alongside `[[bin]]`.
    if let Ok(entries) = std::fs::read_dir(dir.join("src/bin")) {
        for path in entries.filter_map(Result::ok).map(|e| e.path()) {
            if path.extension().is_some_and(|e| e == "rs") {
                if let Some(stem) = path.file_stem() {
                    bins.insert(stem.to_string_lossy().into_owned());
                }
            }
        }
    }
    // `src/main.rs` auto-discovers a binary named after the package — but an explicit `[[bin]]`
    // (which points at `src/main.rs`) renames it, so only add the package name when none was given.
    if !explicit && dir.join("src/main.rs").is_file() {
        bins.insert(package.to_owned());
    }
    bins.into_iter().collect()
}

/// The directory's basename as a fallback crate name.
fn dir_name(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A crate's short name for the consumers column: strip the `kennel-lib-` / `kennel-` prefix.
#[must_use]
pub fn short_name(name: &str) -> String {
    name.strip_prefix("kennel-lib-")
        .or_else(|| name.strip_prefix("kennel-"))
        .unwrap_or(name)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_name() {
        let toml = "[package]\nname = \"kennel-lib-dbus\"\nedition = \"2021\"\n";
        assert_eq!(package_name(toml).as_deref(), Some("kennel-lib-dbus"));
    }

    #[test]
    fn splits_first_party_from_external_deps() {
        let toml = "\
[package]
name = \"x\"
[dependencies]
kennel-lib-dbus = { path = \"../kennel-lib-dbus\" }
# a comment
mini-sansio-dbus = \"=5.0.1\"
nix = { version = \"=0.31.3\" }
[dev-dependencies]
tempfile = \"1\"
";
        let (fp, ext) = parse_deps(toml);
        assert_eq!(fp, vec!["kennel-lib-dbus"]);
        assert_eq!(ext, vec!["mini-sansio-dbus", "nix"]); // dev-deps excluded
    }

    #[test]
    fn tcb_closure_follows_first_party_edges() {
        let edges = BTreeMap::from([
            ("kenneld", vec!["kennel-lib-binder"]),
            ("kennel-lib-binder", vec!["kennel-lib-scm"]),
            ("kennel-lib-scm", vec![]),
            ("kennel-cli", vec!["kennel-lib-term"]), // not reachable from a root
            ("kennel-lib-term", vec![]),
            ("kennel-privhelper", vec![]),
            ("kennel-bin-init", vec![]),
        ]);
        let tcb = tcb_closure(&edges);
        assert!(tcb.contains("kenneld"));
        assert!(tcb.contains("kennel-lib-binder"));
        assert!(tcb.contains("kennel-lib-scm"));
        assert!(!tcb.contains("kennel-cli"));
        assert!(!tcb.contains("kennel-lib-term"));
    }

    #[test]
    fn short_name_strips_the_prefix() {
        assert_eq!(short_name("kennel-lib-spawn"), "spawn");
        assert_eq!(short_name("kennel-bin-init"), "bin-init");
        assert_eq!(short_name("kenneld"), "kenneld");
    }
}
