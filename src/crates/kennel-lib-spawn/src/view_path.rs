// SPDX-License-Identifier: Apache-2.0

//! A path inside the kennel's view, as a type (CODING-STANDARDS.md §11.1).

use std::path::{Component, Path, PathBuf};

/// A path as seen inside the kennel, after `pivot_root`: absolute, with no `..` component.
///
/// The factory creates a bind's target under the new root and mounts on it. A relative target,
/// or one that climbs with `..`, names somewhere other than what the plan's author meant. The
/// view build already resolves targets inside the root by descriptor; this type states the rule
/// where the plan is built and where it is decoded, so a plan that breaks it is refused before
/// anything is mounted. It can only be built by [`ViewPath::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ViewPath(PathBuf);

/// Why a path is not a [`ViewPath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewPathError {
    /// The path does not start at the root.
    Relative(PathBuf),
    /// The path has a `..` component.
    ParentDir(PathBuf),
}

impl ViewPath {
    /// Check `path` and take it.
    ///
    /// # Errors
    /// The [`ViewPathError`] if `path` is relative or has a `..` component.
    pub fn parse(path: impl Into<PathBuf>) -> Result<Self, ViewPathError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(ViewPathError::Relative(path));
        }
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(ViewPathError::ParentDir(path));
        }
        Ok(Self(path))
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for ViewPath {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for ViewPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl PartialEq<Path> for ViewPath {
    fn eq(&self, other: &Path) -> bool {
        self.0 == other
    }
}

impl PartialEq<&Path> for ViewPath {
    fn eq(&self, other: &&Path) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for ViewPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relative(p) => write!(f, "in-view path {} is not absolute", p.display()),
            Self::ParentDir(p) => write!(f, "in-view path {} has a `..` component", p.display()),
        }
    }
}

impl std::error::Error for ViewPathError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_path_without_dot_dot_is_accepted() {
        for ok in ["/", "/usr", "/home/kennel/.config", "/a/./b", "/a//b/"] {
            let path = ViewPath::parse(ok).expect(ok);
            assert_eq!(path.as_path(), Path::new(ok));
            assert!(path == Path::new(ok));
        }
    }

    #[test]
    fn a_relative_or_climbing_path_is_refused() {
        for relative in ["", "usr", "./usr", "../etc"] {
            assert_eq!(
                ViewPath::parse(relative),
                Err(ViewPathError::Relative(PathBuf::from(relative)))
            );
        }
        for climbing in ["/..", "/home/../etc", "/home/kennel/.."] {
            assert_eq!(
                ViewPath::parse(climbing),
                Err(ViewPathError::ParentDir(PathBuf::from(climbing)))
            );
        }
        assert_eq!(
            ViewPathError::ParentDir(PathBuf::from("/a/..")).to_string(),
            "in-view path /a/.. has a `..` component"
        );
    }
}
