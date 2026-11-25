// SPDX-License-Identifier: Apache-2.0

//! The error every `kennel` verb returns (CODING-STANDARDS.md §8.1).
//!
//! The CLI's errors have one consumer: `main` prints the message and exits non-zero. So the
//! type sorts failures by kind, not by message. A caller, or a test, can tell a wrong command
//! line from a file that could not be read, from the daemon saying no; the text for the
//! operator is carried inside.

use std::fmt;
use std::path::{Path, PathBuf};

/// Why a `kennel` command did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// The command line is wrong: an unknown flag, a missing value, a malformed name.
    Usage(String),
    /// An operation on a named file or directory failed.
    File {
        /// What was being done, as the message starts: `reading`, `writing`, `creating`.
        verb: &'static str,
        /// The file or directory.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The daemon could not be reached, or it answered with an error or something unexpected.
    Daemon(String),
    /// A step the command depends on failed: a system call, a helper program, a library call.
    Failed(String),
    /// The command declines: what was asked for does not exist, is not allowed, or is not safe.
    Refused(String),
}

impl CliError {
    /// A [`CliError::Usage`] carrying `message`.
    #[must_use]
    pub fn usage(message: &str) -> Self {
        Self::Usage(message.to_owned())
    }

    /// A [`CliError::Usage`] for a flag the verb does not take.
    #[must_use]
    pub fn unknown_flag(flag: &str) -> Self {
        Self::Usage(format!("unknown flag `{flag}`"))
    }

    /// A [`CliError::Usage`] for a flag given without its value.
    #[must_use]
    pub fn missing_value(flag: &str) -> Self {
        Self::Usage(format!("{flag} needs a value"))
    }

    /// A [`CliError::File`] for `verb` on `path`.
    pub fn file(verb: &'static str, path: impl AsRef<Path>, reason: impl fmt::Display) -> Self {
        Self::File {
            verb,
            path: path.as_ref().to_path_buf(),
            reason: reason.to_string(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(m) | Self::Daemon(m) | Self::Failed(m) | Self::Refused(m) => f.write_str(m),
            Self::File { verb, path, reason } => {
                write!(f, "{verb} {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_error_reads_as_verb_path_reason() {
        let err = CliError::file("reading", "/etc/kennel/x.toml", "permission denied");
        assert_eq!(
            err.to_string(),
            "reading /etc/kennel/x.toml: permission denied"
        );
        assert!(matches!(
            err,
            CliError::File {
                verb: "reading",
                ..
            }
        ));
    }

    #[test]
    fn the_helpers_build_usage_errors_with_the_text_in_use() {
        assert_eq!(
            CliError::missing_value("--key"),
            CliError::Usage("--key needs a value".to_owned())
        );
        assert_eq!(
            CliError::unknown_flag("--nope"),
            CliError::Usage("unknown flag `--nope`".to_owned())
        );
        assert_eq!(CliError::usage("x"), CliError::Usage("x".to_owned()));
    }

    #[test]
    fn the_other_kinds_print_their_message_unchanged() {
        assert_eq!(
            CliError::missing_value("--key").to_string(),
            "--key needs a value"
        );
        assert_eq!(
            CliError::Daemon("daemon: no".to_owned()).to_string(),
            "daemon: no"
        );
    }
}
