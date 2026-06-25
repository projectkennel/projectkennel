// Template/fragment discovery for Mode B (interactive composer).
//
// Templates and fragments live on the live system in the standard cascade:
//
//   1. ~/.config/kennel/templates/   (user — highest priority)
//   2. /etc/kennel/templates/        (system admin)
//   3. /usr/lib/kennel/templates/    (vendor — lowest priority)
//
// Same pattern for fragments (sibling directories in the cascade).
//
// kennel-lib-config::User::load().template_dirs() already implements this
// cascade (including honouring the user's config.toml override). We reuse
// it rather than inventing our own search paths.
//
// Each template/fragment is a subdirectory containing `policy.toml`. We parse
// it with `kennel_lib_compile::parse_source()` or `parse_leaf()` — the same
// parsers every other tool uses. The `meta.toml` (name, version, description)
// is parsed minimally for display purposes only.

use std::path::{Path, PathBuf};

/// A discovered template or fragment on the live system.
#[derive(Debug)]
pub struct TemplateEntry {
    /// Name (from meta.toml or policy.toml).
    pub name: String,
    /// Version (from meta.toml).
    pub version: String,
    /// Description (from meta.toml).
    pub description: String,
    /// Whether this is a fragment (vs a full template).
    pub is_fragment: bool,
}

impl TemplateEntry {
    /// The versioned reference (e.g. "base-confined@v1").
    pub fn reference(&self) -> String {
        format!("{}@v{}", self.name, self.version)
    }
}

/// Discover all templates visible on this system.
pub fn discover_templates(extra_dirs: &[PathBuf]) -> Vec<TemplateEntry> {
    let mut search = extra_dirs.to_vec();
    search.extend(
        kennel_lib_config::User::load()
            .unwrap_or_default()
            .template_dirs(),
    );
    scan_all(&search, false)
}

/// Discover all fragments visible on this system.
pub fn discover_fragments(extra_dirs: &[PathBuf]) -> Vec<TemplateEntry> {
    let template_dirs = {
        let mut search = extra_dirs.to_vec();
        search.extend(
            kennel_lib_config::User::load()
                .unwrap_or_default()
                .template_dirs(),
        );
        search
    };

    // Fragments live as siblings: replace "templates" leaf with "fragments".
    let fragment_dirs: Vec<PathBuf> = template_dirs
        .iter()
        .map(|d| {
            let parent = d.parent().unwrap_or(d);
            parent.join("fragments")
        })
        .collect();

    scan_all(&fragment_dirs, true)
}

/// Scan all directories and return discovered entries, deduplicating by name
/// (first occurrence wins — higher-priority dir shadows lower).
fn scan_all(dirs: &[PathBuf], is_fragment: bool) -> Vec<TemplateEntry> {
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in dirs {
        let Ok(read) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Use meta.toml for display info; verify the policy.toml exists.
            let policy_path = path.join("policy.toml");
            let meta_path = path.join("meta.toml");
            if !policy_path.is_file() {
                continue;
            }
            if let Some(te) = parse_entry(&path, &meta_path, is_fragment) {
                if seen.insert(te.name.clone()) {
                    entries.push(te);
                }
            }
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Parse an entry from its meta.toml (for display: name, version, description).
/// Falls back to the directory name if meta.toml is absent or unparseable.
fn parse_entry(dir: &Path, meta_path: &Path, is_fragment: bool) -> Option<TemplateEntry> {
    let dir_name = dir.file_name()?.to_str()?.to_owned();

    let (name, version, description) = if let Ok(content) = std::fs::read_to_string(meta_path) {
        let mut n = String::new();
        let mut v = String::new();
        let mut d = String::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"');
                match key {
                    "name" => n = val.to_owned(),
                    "version" => v = val.to_owned(),
                    "description" => d = val.to_owned(),
                    _ => {}
                }
            }
        }
        (
            if n.is_empty() { dir_name } else { n },
            if v.is_empty() { "1".to_owned() } else { v },
            d,
        )
    } else {
        (dir_name, "1".to_owned(), String::new())
    };

    Some(TemplateEntry {
        name,
        version,
        description,
        is_fragment,
    })
}
