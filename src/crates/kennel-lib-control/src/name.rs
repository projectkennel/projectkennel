// SPDX-License-Identifier: Apache-2.0

//! A kennel's name, as a type.
//!
//! A kennel name arrives as untrusted text on the control socket and becomes path components
//! (the cgroup, the runtime and audit directories), a D-Bus and mesh identifier, and the
//! kennel's synthetic hostname. [`KennelName`] can only be built by [`KennelName::parse`], so
//! holding one is evidence the grammar was checked (CODING-STANDARDS.md §11.1): a function that
//! takes `&KennelName` cannot be handed a string nobody validated.

use std::fmt;

/// The longest kennel name (`[a-z0-9][a-z0-9-]{0,63}`).
pub const MAX_KENNEL_NAME: usize = 64;

/// A kennel name that satisfies the grammar `[a-z0-9][a-z0-9-]{0,63}`.
///
/// It therefore contains no `/`, no `.`, no NUL, no whitespace and no control character: it is
/// one path component that is neither `.` nor `..`, and a valid hostname label.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KennelName(String);

/// Why a string is not a kennel name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// The name is empty.
    Empty,
    /// The name is longer than [`MAX_KENNEL_NAME`] (its length is given).
    TooLong(usize),
    /// The first character is not a lowercase letter or a digit.
    BadStart,
    /// The name contains this character, which is outside `[a-z0-9-]`.
    BadCharacter(char),
}

impl KennelName {
    /// Check `name` against the grammar and wrap it.
    ///
    /// # Errors
    ///
    /// The [`NameError`] for the first rule `name` breaks.
    pub fn parse(name: &str) -> Result<Self, NameError> {
        let Some(first) = name.chars().next() else {
            return Err(NameError::Empty);
        };
        if name.len() > MAX_KENNEL_NAME {
            return Err(NameError::TooLong(name.len()));
        }
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(NameError::BadStart);
        }
        if let Some(bad) = name
            .chars()
            .find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-')
        {
            return Err(NameError::BadCharacter(bad));
        }
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for KennelName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KennelName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<std::path::Path> for KennelName {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

impl fmt::Display for KennelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("kennel name must not be empty"),
            Self::TooLong(len) => write!(
                f,
                "kennel name is too long ({len} chars; the limit is {MAX_KENNEL_NAME})"
            ),
            Self::BadStart => f.write_str(
                "kennel name must start with a lowercase letter or digit \
                 (the grammar is [a-z0-9][a-z0-9-]{0,63})",
            ),
            Self::BadCharacter(bad) => write!(
                f,
                "kennel name contains the illegal character {bad:?} \
                 (only [a-z0-9-] are allowed, so it cannot traverse a path or inject a hostname)"
            ),
        }
    }
}

impl std::error::Error for NameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_in_the_grammar_are_accepted() {
        for ok in [
            "a",
            "0",
            "ai-coding",
            "x-1-y",
            "spawn-7-compute",
            &"a".repeat(64),
        ] {
            assert_eq!(
                KennelName::parse(ok).map(|n| n.to_string()).as_deref(),
                Ok(ok)
            );
        }
    }

    #[test]
    fn each_rule_has_its_own_error() {
        assert_eq!(KennelName::parse(""), Err(NameError::Empty));
        assert_eq!(
            KennelName::parse(&"a".repeat(65)),
            Err(NameError::TooLong(65))
        );
        assert_eq!(KennelName::parse("-a"), Err(NameError::BadStart));
        assert_eq!(KennelName::parse("Ab"), Err(NameError::BadStart));
        assert_eq!(KennelName::parse("a/b"), Err(NameError::BadCharacter('/')));
        assert_eq!(KennelName::parse("a.b"), Err(NameError::BadCharacter('.')));
        assert_eq!(KennelName::parse("a b"), Err(NameError::BadCharacter(' ')));
        assert_eq!(
            KennelName::parse("a\0b"),
            Err(NameError::BadCharacter('\0'))
        );
        assert_eq!(KennelName::parse("aé"), Err(NameError::BadCharacter('é')));
    }

    #[test]
    fn a_name_is_one_safe_path_component() {
        // What the grammar buys: nothing that parses can leave a directory it is joined to.
        for bad in [".", "..", "../x", "/etc", "a/..", "a\n"] {
            assert!(KennelName::parse(bad).is_err(), "{bad:?}");
        }
        let name = KennelName::parse("ai-coding").expect("valid");
        let joined = std::path::Path::new("/run/user/1000/kennel").join(&name);
        assert_eq!(
            joined,
            std::path::Path::new("/run/user/1000/kennel/ai-coding")
        );
    }
}
