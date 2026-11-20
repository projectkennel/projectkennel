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
}
