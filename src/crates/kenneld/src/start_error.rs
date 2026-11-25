// SPDX-License-Identifier: Apache-2.0

//! Why a kennel's start was refused, as types (CODING-STANDARDS.md §8.1).
//!
//! One enum per decision the start path makes before anything privileged runs: the invocation
//! cwd grant, the Landlock floor, the workload to run and its digest pin, and the SSH egress
//! registration. Each `Display` is the text that reaches the journal and the
//! `lifecycle.kennel-start-refused` record.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why the invocation cwd cannot be granted into the view (`[fs.cwd]`, §7.9).
#[derive(Debug)]
pub enum CwdError {
    /// The cwd could not be resolved to a real path.
    Resolve {
        /// The cwd the request named.
        cwd: PathBuf,
        /// What the resolution returned.
        source: io::Error,
    },
    /// The resolved path could not be examined.
    Stat {
        /// The resolved path.
        path: PathBuf,
        /// What the stat returned.
        source: io::Error,
    },
    /// The resolved path is not a directory.
    NotADirectory(PathBuf),
    /// The directory is not owned by the operator.
    NotOwned {
        /// The resolved path.
        path: PathBuf,
        /// The operator's uid.
        uid: u32,
    },
    /// The directory is writable by every host user.
    WorldWritable {
        /// The resolved path.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The operator's `$HOME` could not be resolved, so the path cannot be shown not to be it.
    HomeUnresolvable(PathBuf),
    /// The directory is the operator's `$HOME`.
    IsHome(PathBuf),
    /// A marker the policy requires is not present in the directory.
    MissingMarker {
        /// The resolved path.
        path: PathBuf,
        /// The marker as the policy wrote it (a trailing `/` requires a directory).
        marker: String,
    },
}

impl fmt::Display for CwdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve { cwd, source } => write!(
                f,
                "cannot resolve the invocation cwd {}: {source}",
                cwd.display()
            ),
            Self::Stat { path, source } => write!(f, "cannot stat {}: {source}", path.display()),
            Self::NotADirectory(path) => write!(f, "{} is not a directory", path.display()),
            Self::NotOwned { path, uid } => write!(
                f,
                "{} is not owned by the operator (uid {uid}); the cwd grant is refused",
                path.display()
            ),
            Self::WorldWritable { path, mode } => write!(
                f,
                "{} is world-writable ({mode:04o}); the cwd grant refuses a bind any host user \
                 can write",
                path.display()
            ),
            Self::HomeUnresolvable(path) => write!(
                f,
                "cannot resolve the operator's $HOME to floor-check the cwd grant for {} — \
                 refusing (set HOME, or run from a resolvable project dir)",
                path.display()
            ),
            Self::IsHome(path) => write!(
                f,
                "the invocation cwd {} is the operator's $HOME; the cwd grant never binds $HOME",
                path.display()
            ),
            Self::MissingMarker { path, marker } => {
                let name = marker.strip_suffix('/').unwrap_or(marker);
                write!(
                    f,
                    "the invocation cwd {} is missing the required marker `{marker}` — mark the \
                     project for agent use (e.g. `mkdir {name}`) or run from a marked project root",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for CwdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve { source, .. } | Self::Stat { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Why a policy that depends on Landlock scoping cannot run on this kernel.
#[derive(Debug)]
pub enum LandlockFloorError {
    /// The kernel's Landlock ABI is older than the one that introduced scoping.
    TooOld {
        /// The ABI the policy needs.
        needed: u32,
        /// The ABI this kernel provides.
        abi: u32,
    },
    /// The kernel's Landlock ABI could not be read.
    Unreadable {
        /// The ABI the policy needs.
        needed: u32,
        /// What the query returned.
        source: io::Error,
    },
}

impl fmt::Display for LandlockFloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooOld { needed, abi } => write!(
                f,
                "net.mode = \"host\" needs Landlock ABI {needed} (Linux 6.12) to keep the \
                 workload off the host's abstract unix sockets; this kernel provides ABI {abi}"
            ),
            Self::Unreadable { needed, source } => write!(
                f,
                "net.mode = \"host\" needs Landlock ABI {needed}, and the kernel's Landlock ABI \
                 could not be read: {source}"
            ),
        }
    }
}

impl std::error::Error for LandlockFloorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            Self::TooOld { .. } => None,
        }
    }
}

/// Why the workload to run could not be settled, pinned or prepared (§7.4).
#[derive(Debug)]
pub enum WorkloadError {
    /// Neither the policy nor the request names a command.
    NoWorkload,
    /// The policy pins its workload and the request tried to replace it without `--force`.
    PinnedOverride {
        /// The pinned argv.
        pinned: Vec<String>,
        /// The argv the request gave.
        given: Vec<String>,
    },
    /// The policy pins a digest but the argv to run is empty.
    PinWithoutProgram,
    /// The program is a bare name that is not on the policy's `PATH`.
    NotOnPath(String),
    /// The program could not be opened to pin it.
    Open {
        /// The resolved program.
        path: PathBuf,
        /// What the open returned.
        source: io::Error,
    },
    /// `sha256sum` could not be run.
    Hasher(io::Error),
    /// `sha256sum` ran and failed.
    HashFailed {
        /// The resolved program.
        path: PathBuf,
        /// What `sha256sum` wrote to its standard error.
        stderr: String,
    },
    /// The program's digest is not one the policy accepts.
    DigestNotAccepted {
        /// The resolved program.
        path: PathBuf,
        /// The digest computed.
        digest: String,
    },
    /// The argv to build a command from is empty.
    EmptyArgv,
}

impl fmt::Display for WorkloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkload => f.write_str(
                "no workload: the policy has no [workload] and no command was given \
                 (kennel run … -- <cmd>)",
            ),
            Self::PinnedOverride { pinned, given } => write!(
                f,
                "policy [workload] is pinned to `{}`; refusing the `-- {}` override \
                 (pass --force to override, or set [workload] allowed_args to append)",
                pinned.join(" "),
                given.join(" ")
            ),
            Self::PinWithoutProgram => {
                f.write_str("workload sha256 pin set but the workload argv is empty")
            }
            Self::NotOnPath(program) => write!(
                f,
                "workload `{program}` not found on the policy PATH to hash it"
            ),
            Self::Open { path, source } => {
                write!(f, "opening workload {} to pin it: {source}", path.display())
            }
            Self::Hasher(e) => write!(f, "running sha256sum on the workload fd: {e}"),
            Self::HashFailed { path, stderr } => write!(
                f,
                "sha256sum failed on workload {}: {stderr}",
                path.display()
            ),
            Self::DigestNotAccepted { path, digest } => write!(
                f,
                "workload {} sha256 {digest} is not in the policy's accepted set",
                path.display()
            ),
            Self::EmptyArgv => f.write_str("empty argv"),
        }
    }
}

impl std::error::Error for WorkloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Hasher(source) => Some(source),
            _ => None,
        }
    }
}

/// Why a kennel's SSH egress could not be registered with the bastion (§7.10).
#[derive(Debug)]
pub enum SshEgressError {
    /// A grant carries no minted key: the policy was not compiled with one.
    NoMintedKey {
        /// The grant's destination.
        dest: String,
    },
    /// The bastion did not start: it has no host key.
    NoHostKey,
    /// The bastion started but reported no bound port.
    NoPort,
    /// Staging a key, registering an edge or writing the kennel's `~/.ssh` failed.
    Io(io::Error),
}

impl fmt::Display for SshEgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMintedKey { dest } => write!(
                f,
                "ssh grant for `{dest}` has no minted key (recompile the policy with `kennel \
                 policy compile`)"
            ),
            Self::NoHostKey => f.write_str("bastion failed to start (no host key)"),
            Self::NoPort => f.write_str("bastion started but reported no bound port"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SshEgressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of each refusal is what the journal and the audit record carried before these
    /// were types.
    #[test]
    fn the_messages_are_the_ones_in_use() {
        let p = PathBuf::from("/srv/proj");
        assert_eq!(
            CwdError::NotADirectory(p.clone()).to_string(),
            "/srv/proj is not a directory"
        );
        assert_eq!(
            CwdError::NotOwned {
                path: p.clone(),
                uid: 1000
            }
            .to_string(),
            "/srv/proj is not owned by the operator (uid 1000); the cwd grant is refused"
        );
        assert_eq!(
            CwdError::WorldWritable {
                path: p.clone(),
                mode: 0o777
            }
            .to_string(),
            "/srv/proj is world-writable (0777); the cwd grant refuses a bind any host user can \
             write"
        );
        assert_eq!(
            CwdError::IsHome(p.clone()).to_string(),
            "the invocation cwd /srv/proj is the operator's $HOME; the cwd grant never binds $HOME"
        );
        assert_eq!(
            CwdError::MissingMarker {
                path: p.clone(),
                marker: ".claude/".to_owned()
            }
            .to_string(),
            "the invocation cwd /srv/proj is missing the required marker `.claude/` — mark the \
             project for agent use (e.g. `mkdir .claude`) or run from a marked project root"
        );
        assert_eq!(
            LandlockFloorError::TooOld { needed: 6, abi: 5 }.to_string(),
            "net.mode = \"host\" needs Landlock ABI 6 (Linux 6.12) to keep the workload off the \
             host's abstract unix sockets; this kernel provides ABI 5"
        );
        assert_eq!(
            WorkloadError::PinnedOverride {
                pinned: vec!["run.sh".to_owned(), "-x".to_owned()],
                given: vec!["bash".to_owned()]
            }
            .to_string(),
            "policy [workload] is pinned to `run.sh -x`; refusing the `-- bash` override (pass \
             --force to override, or set [workload] allowed_args to append)"
        );
        assert_eq!(
            WorkloadError::DigestNotAccepted {
                path: p,
                digest: "ab".to_owned()
            }
            .to_string(),
            "workload /srv/proj sha256 ab is not in the policy's accepted set"
        );
        assert_eq!(
            SshEgressError::NoMintedKey {
                dest: "git@github.com".to_owned()
            }
            .to_string(),
            "ssh grant for `git@github.com` has no minted key (recompile the policy with `kennel \
             policy compile`)"
        );
    }
}
