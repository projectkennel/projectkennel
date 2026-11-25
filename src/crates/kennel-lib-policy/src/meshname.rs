// SPDX-License-Identifier: Apache-2.0

//! The grammar of a mesh capability `name` and `key` (`[[provides]]` / `[[consumes]]`).
//!
//! `kenneld` joins a provider's `name` (and `key`) into a host path — the rendezvous directory it
//! creates, chmods and binds into the provider. So these are not free-form labels: each must be a
//! single, safe path component. The compiler enforces this, the settled-policy invariants
//! re-assert it at load (a directly signed artefact never went through the compiler), and the
//! daemon's path builder refuses anything else.

/// The longest capability name accepted (a directory entry is at most 255 bytes).
pub const MAX_NAME: usize = 200;
/// The longest key accepted.
pub const MAX_KEY: usize = 48;

/// Whether `name` is a well-formed capability name.
///
/// A reverse-DNS style identifier of ASCII letters, digits, `.`, `-` and `_`, starting with a
/// letter or digit, with no empty label (no leading or trailing `.`, no `..`), at most
/// [`MAX_NAME`] bytes.
#[must_use]
pub fn name_ok(name: &str) -> bool {
    token_ok(name, MAX_NAME)
}

/// Whether `key` is a well-formed private match token.
///
/// The same alphabet and shape as a name, at most [`MAX_KEY`] bytes.
#[must_use]
pub fn key_ok(key: &str) -> bool {
    token_ok(key, MAX_KEY)
}

/// A mesh capability name that satisfies the grammar ([`name_ok`]).
///
/// The daemon joins it into a host path it creates and binds. It can only be built by
/// [`MeshName::parse`], so a function that takes `&MeshName` cannot be handed a string that
/// would walk out of the directory it is joined to (CODING-STANDARDS.md §11.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MeshName(String);

/// A mesh capability's private key that satisfies the grammar ([`key_ok`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MeshKey(String);

/// A string that is not a well-formed capability name or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not a capability name.
    Name,
    /// Not a capability key.
    Key,
}

impl MeshName {
    /// Check `name` against the grammar and wrap it.
    ///
    /// # Errors
    ///
    /// [`TokenError::Name`] if `name` is not a well-formed capability name.
    pub fn parse(name: &str) -> Result<Self, TokenError> {
        if name_ok(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(TokenError::Name)
        }
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl MeshKey {
    /// Check `key` against the grammar and wrap it.
    ///
    /// # Errors
    ///
    /// [`TokenError::Key`] if `key` is not a well-formed capability key.
    pub fn parse(key: &str) -> Result<Self, TokenError> {
        if key_ok(key) {
            Ok(Self(key.to_owned()))
        } else {
            Err(TokenError::Key)
        }
    }

    /// The key as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for MeshName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::fmt::Display for MeshKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Name => "not a well-formed mesh capability name",
            Self::Key => "not a well-formed mesh capability key",
        })
    }
}

impl core::error::Error for TokenError {}

fn token_ok(s: &str, max: usize) -> bool {
    let bytes = s.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= max
        && first.is_ascii_alphanumeric()
        && *last != b'.'
        && !s.contains("..")
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_names_are_accepted() {
        for n in [
            "org.projectkennel.dbus-broker",
            "org.projectkennel.wayland-session",
            "test.mesh.echo",
            "a",
            "x_1.y-2",
        ] {
            assert!(name_ok(n), "{n}");
        }
        assert!(key_ok("k1") && key_ok("team-a.v2"));
    }

    #[test]
    fn anything_that_is_not_one_safe_path_component_is_refused() {
        for n in [
            "",
            "/home/alice/.ssh",
            "x/../../../../home/alice/.ssh",
            "..",
            ".",
            ".hidden",
            "a..b",
            "trailing.",
            "a/b",
            "a b",
            "a\0b",
            "caf\u{e9}",
            "-leading-dash",
        ] {
            assert!(!name_ok(n), "{n:?} must be refused");
            assert!(!key_ok(n), "{n:?} must be refused as a key");
        }
        assert!(!name_ok(&"a".repeat(MAX_NAME + 1)));
        assert!(!key_ok(&"a".repeat(MAX_KEY + 1)));
    }

    #[test]
    fn the_types_accept_exactly_what_the_predicates_accept() {
        for ok in ["org.example.Service", "a", "x-1_y.z"] {
            assert_eq!(
                MeshName::parse(ok).map(|n| n.to_string()).as_deref(),
                Ok(ok)
            );
            assert_eq!(MeshKey::parse(ok).map(|k| k.to_string()).as_deref(), Ok(ok));
        }
        for bad in [
            "", ".", "..", "a..b", "a/b", "/etc", "a.", ".a", "a b", "a\0",
        ] {
            assert_eq!(MeshName::parse(bad), Err(TokenError::Name), "{bad:?}");
            assert_eq!(MeshKey::parse(bad), Err(TokenError::Key), "{bad:?}");
        }
        // A key is held to its own, shorter limit.
        let long = "k".repeat(MAX_KEY + 1);
        assert!(MeshName::parse(&long).is_ok());
        assert_eq!(MeshKey::parse(&long), Err(TokenError::Key));
    }
}
