// SPDX-License-Identifier: Apache-2.0

//! Why a kennel's view could not be built.
//!
//! The view build runs as host root in the privileged factory. Its failures were `io::Error`s
//! with formatted text. [`ViewError`] separates the two things a caller needs to tell apart:
//! a **refusal** — the factory declined an OCI image directory, with the rule it broke as a
//! value ([`ImageRefusal`]) — and a **failure**, which names the [`Phase`] of the build it
//! happened in and keeps the OS error.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// A view-construction failure.
#[derive(Debug)]
pub enum ViewError {
    /// The OCI image directory, or a directory inside it, may not be used as the overlay's lower.
    Image {
        /// The image path, or the path inside the image, that the rule is about.
        path: PathBuf,
        /// The rule it breaks.
        refusal: ImageRefusal,
    },
    /// A step of the build failed.
    Failed {
        /// The part of the build it belongs to.
        phase: Phase,
        /// The OS error, with the step and path in its message where the build names them.
        source: io::Error,
    },
}

/// The rule an OCI image directory breaks (see the `image` module for why each exists).
#[derive(Debug)]
pub enum ImageRefusal {
    /// The caller cannot list the directory.
    CannotRead(io::Error),
    /// The caller cannot search the directory.
    CannotSearch(io::Error),
    /// A directory inside the image could not be examined with the caller's identity.
    Unexaminable(io::Error),
    /// The directory belongs to a uid that is neither the caller nor root.
    ForeignOwner {
        /// The directory's owner.
        owner: u32,
        /// The caller.
        caller: u32,
    },
    /// A root-owned image was combined with a persistent, caller-owned upper.
    RootOwnedWithPersistentUpper,
    /// A root-owned image is writable by group or other.
    RootOwnedWritable,
    /// A root-owned image is not beneath a system location.
    NotASystemLocation,
}

/// The part of the view build a failure belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Switching between the operator's filesystem identity and root's.
    Identity,
    /// Mounting the new root and placing its top-level scaffolding.
    Root,
    /// Binding the granted host paths in.
    Binds,
    /// Building the synthetic `/etc` and its overlays.
    Etc,
    /// Assembling the OCI overlay: its layers, the mount, the closure lock.
    Image,
    /// The constructed `/dev`: its nodes, devpts, `/dev/shm`, and the per-kennel binderfs.
    Dev,
    /// The fresh `/proc` and its curation.
    Proc,
    /// The private `/tmp`.
    Tmp,
    /// The workload's home directory.
    Home,
    /// The trust-manifest masks.
    Masks,
    /// `pivot_root` and detaching the old root.
    Pivot,
    /// Handing the scaffolding to the kennel's uid 0 after the pivot.
    Scaffolding,
}

impl ViewError {
    /// A failure in `phase`.
    #[must_use]
    pub const fn failed(phase: Phase, source: io::Error) -> Self {
        Self::Failed { phase, source }
    }

    /// An image refusal about `path`.
    #[must_use]
    pub fn image(path: impl Into<PathBuf>, refusal: ImageRefusal) -> Self {
        Self::Image {
            path: path.into(),
            refusal,
        }
    }

    /// Whether the factory declined its input, as opposed to failing to act on input it accepted.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(self, Self::Image { .. })
    }
}

/// Tag an `io::Result` with the phase of the view build it belongs to.
pub trait InPhase<T> {
    /// Name the phase this result came from.
    ///
    /// # Errors
    ///
    /// The original error, as [`ViewError::Failed`].
    fn phase(self, phase: Phase) -> Result<T, ViewError>;
}

impl<T> InPhase<T> for io::Result<T> {
    fn phase(self, phase: Phase) -> Result<T, ViewError> {
        self.map_err(|source| ViewError::Failed { phase, source })
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identity => "filesystem identity",
            Self::Root => "new root",
            Self::Binds => "binds",
            Self::Etc => "synthetic /etc",
            Self::Image => "image overlay",
            Self::Dev => "/dev",
            Self::Proc => "/proc",
            Self::Tmp => "/tmp",
            Self::Home => "home",
            Self::Masks => "trust-manifest masks",
            Self::Pivot => "pivot",
            Self::Scaffolding => "scaffolding",
        })
    }
}

impl fmt::Display for ImageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotRead(e) => write!(f, "the caller cannot read it ({e})"),
            Self::CannotSearch(e) => write!(f, "the caller cannot search it ({e})"),
            Self::Unexaminable(e) => write!(f, "inside the image, cannot be examined ({e})"),
            Self::ForeignOwner { owner, caller } => write!(
                f,
                "owned by uid {owner}, neither the caller ({caller}) nor root"
            ),
            Self::RootOwnedWithPersistentUpper => {
                f.write_str("a root-owned image cannot be combined with a persistent rootfs")
            }
            Self::RootOwnedWritable => f.write_str("root-owned but writable by group or other"),
            Self::NotASystemLocation => f.write_str(
                "a root-owned image must sit beneath /usr, /var, /etc, /lib, /lib64 or /opt",
            ),
        }
    }
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image { path, refusal } => write!(f, "image {}: {refusal}", path.display()),
            Self::Failed { phase, source } => write!(f, "{phase}: {source}"),
        }
    }
}

impl std::error::Error for ViewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed { source, .. } => Some(source),
            Self::Image { refusal, .. } => match refusal {
                ImageRefusal::CannotRead(e)
                | ImageRefusal::CannotSearch(e)
                | ImageRefusal::Unexaminable(e) => Some(e),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_told_apart_from_a_failure() {
        let refused = ViewError::image("/root", ImageRefusal::NotASystemLocation);
        assert!(refused.is_refusal());
        let failed = Err::<(), _>(io::Error::from_raw_os_error(1))
            .phase(Phase::Pivot)
            .expect_err("tagged");
        assert!(!failed.is_refusal());
        assert!(matches!(
            failed,
            ViewError::Failed {
                phase: Phase::Pivot,
                ..
            }
        ));
    }

    #[test]
    fn messages_name_the_image_and_the_rule_or_the_phase() {
        assert_eq!(
            ViewError::image(
                "/srv/img",
                ImageRefusal::ForeignOwner {
                    owner: 1001,
                    caller: 1000
                }
            )
            .to_string(),
            "image /srv/img: owned by uid 1001, neither the caller (1000) nor root"
        );
        let failed = ViewError::failed(Phase::Dev, io::Error::other("mount /dev tmpfs: no"));
        assert_eq!(failed.to_string(), "/dev: mount /dev tmpfs: no");
    }
}
