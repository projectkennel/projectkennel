//! Path canonicalisation: the one place that resolves `realpath`-equivalent.
//!
//! # Purpose
//!
//! Turn an untrusted path into a canonical [`PathBuf`] that is *proven* to lie
//! within an explicit allowed prefix, or refuse it. This is the helper named by
//! CODING-STANDARDS.md §10.3 ("path construction from untrusted input goes
//! through the canonicalising helper of §11.3, which verifies the result is
//! within an explicit allowed prefix") and §11.3 ("the only place that performs
//! `realpath`-equivalent resolution. Comparisons happen on canonicalised
//! values"). Nothing else in the workspace calls [`std::fs::canonicalize`].
//!
//! # Invariants
//!
//! - The input is rejected outright if it contains a `..` component (§10.2:
//!   "path traversal is rejected at parse"). We do not normalise it away.
//! - Resolution is `realpath`-equivalent: symlinks and `.` are resolved against
//!   the live filesystem, so a symlink that points outside the prefix is caught
//!   by the containment check rather than slipping through a lexical compare.
//! - Containment is component-aware ([`Path::starts_with`]), not a string
//!   prefix, so an allowed prefix of `/srv/kennel` does not admit
//!   `/srv/kennel-evil`.
//! - The prefix itself is the trusted allowed root; a path that resolves to
//!   exactly the prefix is within scope.
//!
//! # Threat bearing
//!
//! T6 (lateral movement) and T2 (confused deputy): an untrusted path that
//! escapes the prefix — via an absolute path elsewhere, a `..` sequence, or a
//! symlink — is refused before any caller acts on it.

use std::io;
use std::path::{Component, Path, PathBuf};

/// Why a path could not be accepted.
///
/// The variants distinguish a refusal (the path is well-formed but out of
/// scope) from an I/O failure (the path or the prefix could not be resolved),
/// so the caller can react and the audit log can record which happened.
///
/// `Display` deliberately does **not** interpolate the offending path: a
/// resolved path may carry attacker-influenced bytes, and per §10.4 those are
/// sanitised by the caller (via `kennel-text`) before they reach a terminal.
/// The structured [`CanonicaliseError::Escapes::resolved`] field is available
/// for a caller that wants to sanitise and show it.
#[derive(Debug)]
pub enum CanonicaliseError {
    /// The input path contains a `..` component and is rejected unresolved.
    Traversal,
    /// The allowed prefix could not itself be resolved (missing, not a
    /// directory, or unreadable). Carries the underlying I/O error.
    Prefix(io::Error),
    /// The input path could not be resolved (does not exist, a symlink loop, a
    /// non-directory component, or unreadable). Carries the I/O error.
    Input(io::Error),
    /// The input resolved successfully but lies outside the allowed prefix.
    Escapes {
        /// The canonical path the input resolved to. Untrusted for display
        /// purposes (see the type-level note).
        resolved: PathBuf,
    },
}

impl std::fmt::Display for CanonicaliseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Traversal => {
                write!(f, "path must not contain `..` components")
            }
            Self::Prefix(e) => {
                write!(f, "allowed prefix could not be resolved: {e}")
            }
            Self::Input(e) => {
                write!(f, "path could not be resolved: {e}")
            }
            Self::Escapes { .. } => {
                write!(f, "path resolves outside the allowed prefix")
            }
        }
    }
}

impl std::error::Error for CanonicaliseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Prefix(e) | Self::Input(e) => Some(e),
            Self::Traversal | Self::Escapes { .. } => None,
        }
    }
}

/// Resolve `p` to a canonical path proven to lie within `prefix`.
///
/// `prefix` is the trusted allowed root. If `p` is relative it is interpreted
/// against the canonical `prefix`; if absolute it is taken as given. Either
/// way the result is `realpath`-resolved (symlinks and `.` collapsed against
/// the live filesystem) and then checked for component-wise containment in the
/// canonical prefix.
///
/// Both `p` and the location it names must exist, because resolution touches
/// the filesystem; this is a validator for paths that are about to be used, not
/// a lexical normaliser for paths that may not exist yet.
///
/// # Errors
///
/// - [`CanonicaliseError::Traversal`] if `p` contains a `..` component.
/// - [`CanonicaliseError::Prefix`] if `prefix` cannot be resolved.
/// - [`CanonicaliseError::Input`] if `p` (joined onto the prefix when relative)
///   cannot be resolved.
/// - [`CanonicaliseError::Escapes`] if `p` resolves outside `prefix`.
pub fn canonicalise_path(p: &Path, prefix: &Path) -> Result<PathBuf, CanonicaliseError> {
    // Scaffold: the resolving implementation lands in the feat: commit. Until
    // then the contract is unmet — every input is reported as escaping, so the
    // positive tests below fail red while the crate already compiles and the
    // error/type surface is fixed.
    Err(CanonicaliseError::Escapes {
        resolved: prefix.join(p),
    })
}

/// Reject a path that carries a `..` component. Pulled out so the rejection is
/// a single named check shared by the doc comment and the implementation.
#[allow(dead_code)] // used by the feat: implementation
fn rejects_traversal(p: &Path) -> bool {
    p.components().any(|c| matches!(c, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A unique temp directory, canonicalised (so comparisons hold even when
    /// the system temp root is itself a symlink), removed on drop. std-only: no
    /// `tempfile` dependency.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir();
            let dir = base.join(format!("kennel-syscall-test-{}-{n}", process::id()));
            fs::create_dir_all(&dir).expect("create temp dir");
            let path = fs::canonicalize(&dir).expect("canonicalise temp dir");
            Self { path }
        }

        fn join(&self, rel: &str) -> PathBuf {
            self.path.join(rel)
        }

        /// Create a directory (and parents) under the temp root.
        fn mkdir(&self, rel: &str) -> PathBuf {
            let p = self.join(rel);
            fs::create_dir_all(&p).expect("mkdir");
            p
        }

        /// Create an empty file (and parent dirs) under the temp root.
        fn touch(&self, rel: &str) -> PathBuf {
            let p = self.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).expect("mkdir parent");
            }
            fs::File::create(&p).expect("touch");
            p
        }

        /// Create a symlink at `link` pointing at `target`.
        fn symlink(&self, link: &str, target: &Path) -> PathBuf {
            let l = self.join(link);
            if let Some(parent) = l.parent() {
                fs::create_dir_all(parent).expect("mkdir parent");
            }
            std::os::unix::fs::symlink(target, &l).expect("symlink");
            l
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // ---- success ----

    #[test]
    fn child_file_within_prefix_resolves() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let file = t.touch("root/sub/file");
        let got = canonicalise_path(&file, &prefix).expect("within prefix");
        assert_eq!(got, fs::canonicalize(&file).expect("canonicalise file"));
    }

    #[test]
    fn relative_input_is_resolved_against_the_prefix() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        t.touch("root/sub/file");
        let got =
            canonicalise_path(Path::new("sub/file"), &prefix).expect("relative within prefix");
        assert_eq!(
            got,
            fs::canonicalize(t.join("root/sub/file")).expect("canonicalise file")
        );
    }

    #[test]
    fn the_prefix_itself_is_within_scope() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let got = canonicalise_path(&prefix, &prefix).expect("prefix is in scope");
        assert_eq!(got, prefix);
    }

    #[test]
    fn a_symlink_that_stays_inside_the_prefix_is_accepted() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let real = t.touch("root/real");
        let link = t.symlink("root/link", &real);
        let got = canonicalise_path(&link, &prefix).expect("contained symlink");
        assert_eq!(got, fs::canonicalize(&real).expect("canonicalise real"));
    }

    // ---- refusals: traversal ----

    #[test]
    fn relative_parent_traversal_is_refused() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        assert!(matches!(
            canonicalise_path(Path::new("../escape"), &prefix),
            Err(CanonicaliseError::Traversal)
        ));
    }

    #[test]
    fn absolute_path_with_dotdot_is_refused_before_touching_the_fs() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        // Note the `..`: rejected on sight, even though the leaf need not exist.
        let p = t.join("root/../root/nonexistent");
        assert!(matches!(
            canonicalise_path(&p, &prefix),
            Err(CanonicaliseError::Traversal)
        ));
    }

    // ---- refusals: escape ----

    #[test]
    fn absolute_path_outside_the_prefix_escapes() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let outside = t.touch("outside/file");
        assert!(matches!(
            canonicalise_path(&outside, &prefix),
            Err(CanonicaliseError::Escapes { .. })
        ));
    }

    #[test]
    fn a_symlink_pointing_outside_the_prefix_escapes() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let outside = t.mkdir("outside");
        let link = t.symlink("root/link", &outside);
        // The lexical path is inside root/, but realpath resolution lands outside.
        assert!(matches!(
            canonicalise_path(&link, &prefix),
            Err(CanonicaliseError::Escapes { .. })
        ));
    }

    #[test]
    fn sibling_with_shared_string_prefix_escapes() {
        // Bug bait: `/…/root-evil` shares the *string* prefix `/…/root` but is a
        // different directory. Component-aware containment must refuse it.
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let evil = t.touch("root-evil/file");
        assert!(matches!(
            canonicalise_path(&evil, &prefix),
            Err(CanonicaliseError::Escapes { .. })
        ));
    }

    // ---- refusals: I/O ----

    #[test]
    fn nonexistent_input_is_an_input_error() {
        let t = TempDir::new();
        let prefix = t.mkdir("root");
        let missing = t.join("root/nope");
        assert!(matches!(
            canonicalise_path(&missing, &prefix),
            Err(CanonicaliseError::Input(_))
        ));
    }

    #[test]
    fn nonexistent_prefix_is_a_prefix_error() {
        let t = TempDir::new();
        let prefix = t.join("does-not-exist");
        let p = t.join("does-not-exist/child");
        assert!(matches!(
            canonicalise_path(&p, &prefix),
            Err(CanonicaliseError::Prefix(_))
        ));
    }
}
