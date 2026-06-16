//! Template version ordering (`docs/design/05-templates.md` §5.2, §5.11).
//!
//! A version is `v` followed by a semver core: `v4`, `v4.2`, `v2.33.2` (the leading
//! `v` is required; `source::validate_ref_version` enforces the grammar). Ordering
//! is numeric per component, shorter cores treated as zero-padded (`v4` == `v4.0.0`
//! < `v4.1`). `kennel upgrade` uses this to detect a newer published template.

use crate::resolve::split_reference;
use crate::PolicyError;

/// Parse a `<name>@<version>` reference into its parts (public wrapper over the
/// resolver's validated split, for callers outside the crate such as the CLI's
/// `kennel upgrade`).
///
/// # Errors
///
/// Returns [`PolicyError::Resolution`] if the reference is missing its `@version`
/// or carries a malformed name or version.
pub fn parse_reference(reference: &str) -> Result<(String, String), PolicyError> {
    split_reference(reference)
}

/// The numeric components of a version core (without the leading `v`). An unparsable
/// component is treated as `0`, but callers should validate the grammar first
/// (`source::validate_ref_version`); this is ordering, not validation.
fn components(version: &str) -> Vec<u64> {
    version
        .strip_prefix('v')
        .unwrap_or(version)
        .split('.')
        .map(|c| c.parse::<u64>().unwrap_or(0))
        .collect()
}

/// `true` if `candidate` is a strictly newer version than `current`. Compares
/// component-by-component, zero-padding the shorter core (`v4` < `v4.1`,
/// `v4.2` > `v4`, `v4.2` == `v4.2` → not newer).
#[must_use]
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (a, b) = (components(candidate), components(current));
    let len = a.len().max(b.len());
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av != bv {
            return av > bv;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_by_major_minor_patch() {
        assert!(is_newer("v5", "v4"));
        assert!(is_newer("v4.1", "v4"));
        assert!(is_newer("v4.2", "v4.1"));
        assert!(is_newer("v2.33.2", "v2.33.1"));
    }

    #[test]
    fn equal_or_older_is_not_newer() {
        assert!(!is_newer("v4", "v4"));
        assert!(!is_newer("v4", "v4.0.0"));
        assert!(!is_newer("v4.0", "v4.1"));
        assert!(!is_newer("v3", "v10"));
    }

    #[test]
    fn parse_reference_splits_name_and_version() {
        let (name, version) = parse_reference("ai-coding-strict@v4").expect("valid");
        assert_eq!(name, "ai-coding-strict");
        assert_eq!(version, "v4");
        assert!(parse_reference("no-version").is_err());
    }
}
