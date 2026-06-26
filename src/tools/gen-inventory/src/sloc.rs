//! Source-line counting: test-cfg-stripped, comment-and-blank-excluding (std-only).
//!
//! Reproduces the method `03-crate-decomposition.md` used by hand — verified to match its prior
//! counts exactly on crates that did not change. A line counts when, after dropping every
//! test-only `#[cfg(...)]` item's block (`#[cfg(test)]` or `#[cfg(all(test, ...))]`), it is
//! non-blank and not a `//` / `/* … */` / `*` comment line.

use std::path::Path;

/// Total non-test SLOC across every `.rs` file under `src_dir` (recursively).
///
/// # Errors
/// An I/O error if a file under `src_dir` cannot be read.
pub fn count_dir(src_dir: &Path) -> std::io::Result<usize> {
    let mut total = 0usize;
    for file in rust_files(src_dir)? {
        total = total.saturating_add(count_file(&std::fs::read_to_string(&file)?));
    }
    Ok(total)
}

/// Whether any `.rs` file under `src_dir` actually *uses* the `unsafe` keyword — `unsafe { … }`,
/// `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern` — on a non-comment line.
///
/// Matching the keyword in a use position (not the bare word) avoids the false positives that
/// fooled the previous hand counts' tooling: the `unsafe_code` lint name, identifiers like
/// `unsafe_section` / `UnsafeSection`, and string literals such as `rename = "unsafe"` or the
/// policy `"[unsafe.ptrace]"` section — none of which is a use of the keyword.
///
/// # Errors
/// An I/O error if a file under `src_dir` cannot be read.
pub fn uses_unsafe(src_dir: &Path) -> std::io::Result<bool> {
    for file in rust_files(src_dir)? {
        let text = std::fs::read_to_string(&file)?;
        if text.lines().any(line_uses_unsafe) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether one source line is a *use* of the `unsafe` keyword (not a comment, identifier, or
/// string mention).
fn line_uses_unsafe(line: &str) -> bool {
    const USES: [&str; 5] = [
        "unsafe {",
        "unsafe fn",
        "unsafe impl",
        "unsafe trait",
        "unsafe extern",
    ];
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
        return false;
    }
    USES.iter().any(|u| line.contains(u))
}

/// Count non-test code lines in one file's source.
fn count_file(text: &str) -> usize {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    let mut total = 0usize;
    while let Some(line) = lines.get(i) {
        // A test-only `#[cfg(...)]` item: skip from here to the close of the block it guards.
        if is_test_cfg(line) {
            i = skip_block(&lines, i);
            continue;
        }
        let t = line.trim();
        let is_comment =
            t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with("*/");
        if !t.is_empty() && !is_comment {
            total = total.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    total
}

/// Whether `line` is a **test-only** `#[cfg(...)]` attribute whose guarded block is excluded.
///
/// Matches bare `#[cfg(test)]` and `#[cfg(all(test, ...))]` (both require `test`, so the block
/// compiles only under `cargo test`). `#[cfg(any(test, ...))]` and feature-only gates are real
/// code and are kept. Whitespace is normalised so rustfmt's `all(test, feature = "e2e")` matches.
fn is_test_cfg(line: &str) -> bool {
    let compact: String = line.split_whitespace().collect();
    compact.starts_with("#[cfg(test)]") || compact.starts_with("#[cfg(all(test,")
}

/// Given `lines[start]` is a test-only `#[cfg(...)]` attribute, return the index just past the
/// guarded block's closing brace (tracking brace depth from the first `{`).
fn skip_block(lines: &[&str], start: usize) -> usize {
    let mut depth: i32 = 0;
    let mut started = false;
    let mut j = start;
    while let Some(line) = lines.get(j) {
        depth = depth
            .saturating_add(count(line, '{'))
            .saturating_sub(count(line, '}'));
        if line.contains('{') {
            started = true;
        }
        if started && depth <= 0 {
            return j.saturating_add(1);
        }
        j = j.saturating_add(1);
    }
    j
}

fn count(line: &str, ch: char) -> i32 {
    i32::try_from(line.matches(ch).count()).unwrap_or(i32::MAX)
}

/// Every `.rs` file under `dir`, recursively (sorted for determinism).
fn rust_files(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                out.extend(rust_files(&path)?);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_tests_comments_and_blanks() {
        let src = "\
//! a doc comment
use std::io;

fn real() {
    let x = 1; // trailing comment counts (the line has code)
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() { assert!(true); }
}
";
        // Counted: `use std::io;`, `fn real() {`, `let x = 1; …`, `}` = 4. The doc comment, the
        // blanks, and the whole `#[cfg(test)]` module are excluded.
        assert_eq!(count_file(src), 4);
    }

    #[test]
    fn excludes_all_test_cfg_but_keeps_real_cfg() {
        // `#[cfg(all(test, feature = "e2e"))]` is test-only → its block is excluded; a feature-only
        // or `any(test, ...)` gate is real code → kept. Whitespace in the attribute is normalised.
        assert!(is_test_cfg("#[cfg(test)]"));
        assert!(is_test_cfg("    #[cfg(all(test, feature = \"e2e\"))]"));
        assert!(!is_test_cfg("#[cfg(feature = \"e2e\")]"));
        assert!(!is_test_cfg("#[cfg(any(test, feature = \"e2e\"))]"));
        let src = "\
fn real() {}
#[cfg(all(test, feature = \"e2e\"))]
mod e2e {
    #[test]
    fn t() { assert!(true); }
}
#[cfg(feature = \"e2e\")]
fn kept() {}
";
        // Counted: `fn real() {}`, `#[cfg(feature = \"e2e\")]`, `fn kept() {}` = 3. The whole
        // `all(test, ...)` module is excluded; the feature-only item and its attribute are kept.
        assert_eq!(count_file(src), 3);
    }

    #[test]
    fn detects_unsafe_use_not_mentions() {
        assert!(super::line_uses_unsafe(
            "    let r = unsafe { ptr.read() };"
        ));
        assert!(super::line_uses_unsafe("unsafe fn raw() {}"));
        assert!(super::line_uses_unsafe("unsafe impl Send for X {}"));
        // Mentions, not uses — must not flag:
        assert!(!super::line_uses_unsafe("#![forbid(unsafe_code)]"));
        assert!(!super::line_uses_unsafe(
            "    pub unsafe_section: UnsafeSection,"
        ));
        assert!(!super::line_uses_unsafe("        \"[unsafe.ptrace]\","));
        assert!(!super::line_uses_unsafe(
            "    /// the [unsafe] section uses unsafe { } sometimes"
        ));
    }
}
