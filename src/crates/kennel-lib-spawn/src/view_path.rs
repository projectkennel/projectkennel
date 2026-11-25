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

/// A host path a bind takes its content from: absolute, with no `..` component.
///
/// The factory opens a bind's source with the operator's identity and without following
/// symlinks, so a source that climbs is already contained. This type states the rule where the
/// plan is built and where it is decoded: a source that is relative, or that names its target
/// by climbing, is refused before anything is opened. It can only be built by
/// [`HostPath::parse`], or from a [`ViewPath`] for a bind whose source and target are the same
/// path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPath(PathBuf);

/// Why a path is not a [`HostPath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPathError {
    /// The path does not start at the root.
    Relative(PathBuf),
    /// The path has a `..` component.
    ParentDir(PathBuf),
}

impl HostPath {
    /// Check `path` and take it.
    ///
    /// # Errors
    /// The [`HostPathError`] if `path` is relative or has a `..` component.
    pub fn parse(path: impl Into<PathBuf>) -> Result<Self, HostPathError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(HostPathError::Relative(path));
        }
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(HostPathError::ParentDir(path));
        }
        Ok(Self(path))
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

// A bind that shows a host path at the same place in the view: the two rules are the same, so
// a checked target is a checked source.
impl From<&ViewPath> for HostPath {
    fn from(path: &ViewPath) -> Self {
        Self(path.0.clone())
    }
}

/// Why a bind could not be described: its target or its source breaks its rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindPathError {
    /// The in-view target.
    Target(ViewPathError),
    /// The host source.
    Source(HostPathError),
}

impl From<ViewPathError> for BindPathError {
    fn from(e: ViewPathError) -> Self {
        Self::Target(e)
    }
}

impl From<HostPathError> for BindPathError {
    fn from(e: HostPathError) -> Self {
        Self::Source(e)
    }
}

impl std::fmt::Display for BindPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target(e) => write!(f, "{e}"),
            Self::Source(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BindPathError {}

/// The conversions both checked path types offer: they read as the `Path` they hold.
macro_rules! reads_as_path {
    ($t:ty) => {
        impl std::ops::Deref for $t {
            type Target = Path;
            fn deref(&self) -> &Path {
                &self.0
            }
        }

        impl AsRef<Path> for $t {
            fn as_ref(&self) -> &Path {
                &self.0
            }
        }

        impl PartialEq<Path> for $t {
            fn eq(&self, other: &Path) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<PathBuf> for $t {
            fn eq(&self, other: &PathBuf) -> bool {
                &self.0 == other
            }
        }

        impl PartialEq<&Path> for $t {
            fn eq(&self, other: &&Path) -> bool {
                self.0 == *other
            }
        }
    };
}

reads_as_path!(ViewPath);
reads_as_path!(HostPath);

impl std::fmt::Display for HostPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relative(p) => write!(f, "host path {} is not absolute", p.display()),
            Self::ParentDir(p) => write!(f, "host path {} has a `..` component", p.display()),
        }
    }
}

impl std::error::Error for HostPathError {}

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

    #[test]
    fn a_host_path_follows_the_same_rule() {
        let path = HostPath::parse("/srv/data").expect("absolute");
        assert_eq!(path.as_path(), Path::new("/srv/data"));
        assert!(path == Path::new("/srv/data"));
        assert_eq!(
            HostPath::parse("srv/data"),
            Err(HostPathError::Relative(PathBuf::from("srv/data")))
        );
        assert_eq!(
            HostPath::parse("/srv/../etc"),
            Err(HostPathError::ParentDir(PathBuf::from("/srv/../etc")))
        );
        assert_eq!(
            HostPathError::Relative(PathBuf::from("a")).to_string(),
            "host path a is not absolute"
        );
        // A checked target is a checked source for a bind of a path onto itself.
        let view = ViewPath::parse("/usr").expect("view");
        assert_eq!(
            HostPath::from(&view),
            HostPath::parse("/usr").expect("host")
        );
        // A bind's error says which side broke the rule.
        assert_eq!(
            BindPathError::from(HostPathError::Relative(PathBuf::from("a"))).to_string(),
            "host path a is not absolute"
        );
    }
}
