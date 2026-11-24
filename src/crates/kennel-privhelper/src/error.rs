// SPDX-License-Identifier: Apache-2.0

//! Why a kennel could not be constructed.
//!
//! The factory's failures used to be `io::Error`s carrying formatted text, so a caller — and a
//! test — could tell them apart only by reading the message. [`ConstructError`] names each
//! one: a refusal (the request, a granted gid, the init binary, an exclusive bind) is a
//! different variant from a system call that failed, and a failed call says which [`Step`] it
//! was. The text each prints is what the journal showed before.

use std::fmt;
use std::io;
use std::path::PathBuf;

use kennel_lib_spawn::wire::PlanWireError;

/// A construction failure.
#[derive(Debug)]
pub enum ConstructError {
    /// The caller's request was malformed: a framing field or a declared descriptor is missing.
    Request(String),
    /// The construction-half did not decode.
    Decode(PlanWireError),
    /// A granted gid is not one of the caller's own groups (or is gid 0).
    GrantedGid(u32),
    /// The root-owned deployment configuration could not be read, so `what` cannot be located.
    Deployment {
        /// The binary being located.
        what: &'static str,
        /// The configuration loader's error.
        reason: String,
    },
    /// The init binary the configuration names is not a file only root controls.
    UntrustedInit {
        /// The configured path.
        path: PathBuf,
        /// What is wrong with it.
        fault: InitFault,
    },
    /// The binder filesystem is not registered with the kernel.
    BinderfsMissing,
    /// A capability sub-helper ran and reported failure.
    Helper(String),
    /// An exclusive bind's host source could not be shadowed, so the kennel is not started.
    ExclusiveBind(PathBuf),
    /// A system call failed.
    Step {
        /// Which step of the construction.
        step: Step,
        /// The OS error.
        source: io::Error,
    },
}

/// What is wrong with a configured init binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitFault {
    /// It is not a regular file.
    NotRegularFile,
    /// It is owned by this uid, not root.
    NotRootOwned(u32),
    /// Its mode (given) lets group or other write it.
    GroupOrOtherWritable(u32),
}

/// A step of the construction that is a system call (or a short run of them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Marking the request channel close-on-exec.
    Channel,
    /// Receiving the construction datagram.
    Receive,
    /// Opening the trusted init binary.
    OpenInit(PathBuf),
    /// Reading the init binary's metadata.
    StatInit,
    /// Creating a handshake pipe.
    Pipe,
    /// Creating a handshake socket pair.
    Socket,
    /// Opening the kennel's cgroup directory.
    OpenCgroup(PathBuf),
    /// Raising the effective uid to 0 so the user namespace is root-owned.
    RaiseEuid,
    /// Setting the filesystem uid back to the operator's.
    SetFsuid(u32),
    /// Cloning the kennel's PID 1.
    Clone,
    /// Taking gid 0 to write the identity maps.
    RootGid,
    /// Taking uid 0 to write the identity maps.
    RootUid,
    /// Writing the child's `uid_map` (the text written is given).
    UidMap(String),
    /// Writing the child's `gid_map` (the text written is given).
    GidMap(String),
    /// Releasing the construction child once its maps are written.
    ReleaseChild,
    /// Dropping the factory's gid to the operator's.
    DropGid(u32),
    /// Dropping the factory's uid to the operator's.
    DropUid(u32),
    /// Reporting the init pid and descriptors to the daemon.
    Report,
    /// Running a capability sub-helper.
    ExecHelper(PathBuf),
    /// Bringing up loopback inside the kennel's network namespace.
    Loopback,
    /// Setting the kennel's hostname.
    Hostname,
    /// Creating and addressing the kennel's tun device.
    Tun,
    /// Making the mount tree private.
    RootPrivate,
    /// Building the view and pivoting into it.
    BuildView,
    /// Handing `/tmp` or the binder device to the operator.
    HandOver,
    /// Mounting `/proc` and `/tmp` for a kennel without a constructed view.
    FallbackMounts,
}

impl ConstructError {
    /// A failed system call at `step`.
    #[must_use]
    pub const fn step(step: Step, source: io::Error) -> Self {
        Self::Step { step, source }
    }

    /// Whether this is a refusal — the factory declining what it was asked — rather than a
    /// failure to carry out something it accepted.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::Request(_)
                | Self::Decode(_)
                | Self::GrantedGid(_)
                | Self::UntrustedInit { .. }
                | Self::ExclusiveBind(_)
        )
    }
}

/// Tag an `io::Result` with the construction step it belongs to.
pub trait At<T> {
    /// Name the step this result came from.
    ///
    /// # Errors
    ///
    /// The original error, as [`ConstructError::Step`].
    fn at(self, step: Step) -> Result<T, ConstructError>;
}

impl<T> At<T> for io::Result<T> {
    fn at(self, step: Step) -> Result<T, ConstructError> {
        self.map_err(|source| ConstructError::Step { step, source })
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel => f.write_str("mark the factory channel close-on-exec"),
            Self::Receive => f.write_str("receive the construction datagram"),
            Self::OpenInit(p) => write!(f, "open trusted kennel-bin-init {}", p.display()),
            Self::StatInit => f.write_str("stat kennel-bin-init"),
            Self::Pipe => f.write_str("create a handshake pipe"),
            Self::Socket => f.write_str("create a handshake socket"),
            Self::OpenCgroup(p) => write!(f, "open cgroup {}", p.display()),
            Self::RaiseEuid => f.write_str("factory seteuid(0)"),
            Self::SetFsuid(uid) => write!(f, "factory setfsuid({uid})"),
            Self::Clone => f.write_str("clone the kennel's PID 1"),
            Self::RootGid => f.write_str("factory setgid(0)"),
            Self::RootUid => f.write_str("factory setuid(0)"),
            Self::UidMap(map) => write!(f, "uid_map write ({map:?})"),
            Self::GidMap(map) => write!(f, "gid_map write ({map:?})"),
            Self::ReleaseChild => f.write_str("release the construction child"),
            Self::DropGid(gid) => write!(f, "factory drop setgid({gid})"),
            Self::DropUid(uid) => write!(f, "factory drop setuid({uid})"),
            Self::Report => f.write_str("report the init pid to the daemon"),
            Self::ExecHelper(p) => write!(f, "exec {}", p.display()),
            Self::Loopback => f.write_str("bring up loopback in the kennel"),
            Self::Hostname => f.write_str("set the kennel's hostname"),
            Self::Tun => f.write_str("create the kennel's tun device"),
            Self::RootPrivate => f.write_str("make_root_private"),
            Self::BuildView => f.write_str("build_view_and_pivot"),
            Self::HandOver => f.write_str("hand /tmp and the binder device to the operator"),
            Self::FallbackMounts => f.write_str("mount /proc and /tmp"),
        }
    }
}

impl fmt::Display for ConstructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(why) | Self::Helper(why) => f.write_str(why),
            Self::Decode(e) => write!(f, "construction-half decode: {e:?}"),
            Self::GrantedGid(gid) => {
                write!(f, "granted gid {gid} is not one of the caller's own groups")
            }
            Self::Deployment { what, reason } => {
                write!(f, "resolve {what} from deployment config: {reason}")
            }
            Self::UntrustedInit { path, fault } => {
                write!(f, "kennel-bin-init {} ", path.display())?;
                match fault {
                    InitFault::NotRegularFile => f.write_str("is not a regular file"),
                    InitFault::NotRootOwned(uid) => {
                        write!(f, "is not owned by root (owner uid {uid})")
                    }
                    InitFault::GroupOrOtherWritable(mode) => {
                        write!(f, "is writable by group or other (mode {mode:o})")
                    }
                }
            }
            Self::BinderfsMissing => f.write_str(
                "binder filesystem not registered: load the `binder_linux` module \
                 (install.sh loads it and writes /etc/modules-load.d/kennel.conf for boot)",
            ),
            Self::ExclusiveBind(path) => write!(
                f,
                "exclusive bind could not be enforced for {}; refusing to start the kennel",
                path.display()
            ),
            Self::Step { step, source } => write!(f, "{step}: {source}"),
        }
    }
}

impl std::error::Error for ConstructError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Step { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_told_apart_from_a_failed_step() {
        assert!(ConstructError::GrantedGid(6).is_refusal());
        assert!(ConstructError::ExclusiveBind("/srv/x".into()).is_refusal());
        assert!(ConstructError::UntrustedInit {
            path: "/usr/lib/kennel/init".into(),
            fault: InitFault::NotRootOwned(1000),
        }
        .is_refusal());
        let failed = ConstructError::step(Step::Clone, io::Error::from_raw_os_error(1));
        assert!(!failed.is_refusal());
        assert!(!ConstructError::BinderfsMissing.is_refusal());
    }

    #[test]
    fn a_failed_step_names_the_step_and_keeps_the_os_error() {
        let e = Err::<(), _>(io::Error::from_raw_os_error(13))
            .at(Step::SetFsuid(1000))
            .expect_err("tagged");
        let text = e.to_string();
        assert!(text.starts_with("factory setfsuid(1000): "), "{text}");
        assert!(
            matches!(&e, ConstructError::Step { step, source }
                if *step == Step::SetFsuid(1000) && source.raw_os_error() == Some(13)),
            "{e:?}"
        );
    }

    #[test]
    fn the_messages_are_the_ones_the_journal_showed() {
        assert_eq!(
            ConstructError::GrantedGid(6).to_string(),
            "granted gid 6 is not one of the caller's own groups"
        );
        assert_eq!(
            ConstructError::UntrustedInit {
                path: "/x/init".into(),
                fault: InitFault::GroupOrOtherWritable(0o775),
            }
            .to_string(),
            "kennel-bin-init /x/init is writable by group or other (mode 775)"
        );
        assert_eq!(
            ConstructError::Deployment {
                what: "kennel-bin-init",
                reason: "no file".to_owned(),
            }
            .to_string(),
            "resolve kennel-bin-init from deployment config: no file"
        );
    }
}
