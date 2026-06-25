// Template/fragment discovery for Mode B (interactive composer).
//
// Templates and fragments live on the live system in the standard cascade:
//
//   1. ~/.config/kennel/templates/   (user — highest priority)
//   2. /etc/kennel/templates/        (system admin)
//   3. /usr/lib/kennel/templates/    (vendor — lowest priority)
//
// Same pattern for fragments (substituting "fragments" for "templates").
//
// kennel-lib-config::User::load().template_dirs() already implements this
// cascade (including honouring the user's config.toml override). We reuse
// it rather than inventing our own search paths.
//
// Each template/fragment is a subdirectory containing at least:
//   meta.toml   — name, version, description, template_base
//   policy.toml — the policy rules
//
// --template-dir flags prepend extra directories (CLI-specified first).

use std::path::{Path, PathBuf};

/// A discovered template or fragment on the live system.
#[derive(Debug)]
pub struct TemplateEntry {
    /// The directory containing this template/fragment.
    pub dir: PathBuf,
    /// Name from meta.toml (e.g. "base-confined").
    pub name: String,
    /// Version from meta.toml (e.g. "1").
    pub version: String,
    /// Description from meta.toml.
    pub description: String,
    /// template_base from meta.toml (empty for root templates).
    pub template_base: String,
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
///
/// Searches the standard cascade (`~/.config/kennel/templates/`,
/// `/etc/kennel/templates/`, `/usr/lib/kennel/templates/`) plus any
/// extra directories from `--template-dir` flags.
///
/// The cascade order is: CLI extra dirs → user → system → vendor.
/// A template that appears in a higher-priority dir shadows one with the
/// same name in a lower-priority dir.
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
///
/// Same cascade as templates but under `fragments/` subdirectories.
/// Fragments are additive-only policy bundles; the `is_fragment` flag
/// is set so the emitter renders them as `include = [...]` entries.
pub fn discover_fragments(extra_dirs: &[PathBuf]) -> Vec<TemplateEntry> {
    // Fragments live beside templates in the same cascade roots, just under
    // a different leaf ("fragments" instead of "templates"). We derive the
    // fragment dirs from the template dirs by replacing the leaf.
    let template_dirs = {
        let mut search = extra_dirs.to_vec();
        search.extend(
            kennel_lib_config::User::load()
                .unwrap_or_default()
                .template_dirs(),
        );
        search
    };

    let fragment_dirs: Vec<PathBuf> = template_dirs
        .iter()
        .map(|d| {
            // Replace "templates" with "fragments" in the path. If the path
            // doesn't end in "templates", append "../fragments" as a sibling.
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
            let meta_path = path.join("meta.toml");
            if !meta_path.is_file() {
                continue;
            }
            if let Some(te) = parse_meta(&path, &meta_path, is_fragment) {
                if seen.insert(te.name.clone()) {
                    entries.push(te);
                }
            }
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Parse a meta.toml into a TemplateEntry. Minimal line-by-line parse — the
/// format is flat `key = "value"`. No TOML library needed for this.
fn parse_meta(dir: &Path, meta_path: &Path, is_fragment: bool) -> Option<TemplateEntry> {
    let content = std::fs::read_to_string(meta_path).ok()?;
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();
    let mut template_base = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, val)) = parse_kv(line) {
            match key {
                "name" => name = val,
                "version" => version = val,
                "description" => description = val,
                "template_base" => template_base = val,
                _ => {}
            }
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(TemplateEntry {
        dir: dir.to_owned(),
        name,
        version,
        description,
        template_base,
        is_fragment,
    })
}

fn parse_kv(line: &str) -> Option<(&str, String)> {
    let (key, rest) = line.split_once('=')?;
    let key = key.trim();
    let val = rest.trim().trim_matches('"');
    Some((key, val.to_owned()))
}
