//! The host-owned rendezvous point for `af-unix` mesh providers (§7.13.4b).
//!
//! A provider listens at its policy `endpoint` inside its own view. kenneld derives the host
//! location of that socket from the signed-catalogue triple `(tier, name, key)` and binds a
//! per-capability directory at the in-view `dirname(endpoint)` during construction, so the socket
//! the provider binds is the inode the broker connects to host-side.

use std::path::{Path, PathBuf};

use crate::catalogue::Tier;

/// The per-capability directory component: `<name>`, or `<name>.<key>` when a private key is set.
///
/// `key` is appended when present (§7.13.4b). Both inputs are filesystem-safe single components by
/// compile validation (§7.13.3): `name` is a reverse-DNS identifier, `key` a filesystem-safe token.
fn component(name: &str, key: Option<&str>) -> String {
    key.map_or_else(|| name.to_owned(), |k| format!("{name}.{k}"))
}

/// The host directory `kenneld` holds for a capability's rendezvous point.
///
/// Under `kenneld`'s runtime root. Construction binds it at the in-view `dirname(endpoint)`, and the
/// broker resolves the same directory to connect.
#[must_use]
pub fn host_rp_dir(tier: Tier, name: &str, key: Option<&str>) -> PathBuf {
    kennel_lib_control::socket::runtime_dir()
        .join("mesh")
        .join(tier.as_str())
        .join(component(name, key))
}

/// The host socket the broker connects.
///
/// The rendezvous directory plus the basename of the provider's policy `endpoint` — the leaf the
/// provider binds, seen host-side.
#[must_use]
pub fn host_rp_socket(tier: Tier, name: &str, key: Option<&str>, endpoint: &str) -> PathBuf {
    let leaf = Path::new(endpoint)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("sock"));
    host_rp_dir(tier, name, key).join(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_appended_iff_present() {
        assert_eq!(component("org.x.wl", None), "org.x.wl");
        assert_eq!(component("org.x.wl", Some("K1")), "org.x.wl.K1");
    }

    #[test]
    fn host_socket_is_the_rp_dir_plus_the_policy_endpoint_basename() {
        let s = host_rp_socket(Tier::User, "org.x.wl", Some("K1"), "/run/mesh/wayland-0");
        assert!(s.ends_with("mesh/user/org.x.wl.K1/wayland-0"));
    }

    #[test]
    fn tier_distinguishes_a_per_user_from_a_per_host_directory() {
        let user = host_rp_dir(Tier::User, "org.x.wl", None);
        let host = host_rp_dir(Tier::Host, "org.x.wl", None);
        assert_ne!(user, host);
        assert!(user.ends_with("mesh/user/org.x.wl"));
        assert!(host.ends_with("mesh/host/org.x.wl"));
    }
}
