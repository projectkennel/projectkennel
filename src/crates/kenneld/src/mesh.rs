// SPDX-License-Identifier: Apache-2.0

//! The host-owned rendezvous point for `af-unix` mesh providers (§7.13.4b).
//!
//! A provider listens at its policy `endpoint` inside its own view. kenneld derives the host
//! location of that socket from the signed-catalogue triple `(tier, name, key)` and binds a
//! per-capability directory at the in-view `dirname(endpoint)` during construction, so the socket
//! the provider binds is the inode the broker connects to host-side.

use std::path::{Path, PathBuf};

use kennel_lib_policy::meshname::{MeshKey, MeshName};

use crate::catalogue::Tier;

/// A capability's name and optional key, checked against their grammar.
///
/// `None` if either is malformed. Every path below is built from the checked types, so a name
/// that could walk out of the mesh directory cannot reach a `join`.
#[must_use]
pub fn capability(name: &str, key: Option<&str>) -> Option<(MeshName, Option<MeshKey>)> {
    let name = MeshName::parse(name).ok()?;
    let key = match key {
        Some(k) => Some(MeshKey::parse(k).ok()?),
        None => None,
    };
    Some((name, key))
}

/// The per-capability directory component: `<name>`, or `<name>.<key>` when a private key is set.
///
/// Both inputs are single, safe path components by construction (§7.13.3, §7.13.4b).
fn component(name: &MeshName, key: Option<&MeshKey>) -> String {
    key.map_or_else(
        || name.as_str().to_owned(),
        |k| format!("{}.{}", name.as_str(), k.as_str()),
    )
}

/// The host directory `kenneld` holds for a capability's rendezvous point.
///
/// Under `kenneld`'s runtime root. Construction binds it at the in-view `dirname(endpoint)`, and the
/// broker resolves the same directory to connect.
#[must_use]
pub fn host_rp_dir(tier: Tier, name: &MeshName, key: Option<&MeshKey>) -> PathBuf {
    kennel_lib_control::socket::runtime_dir()
        .join("mesh")
        .join(tier.as_str())
        .join(component(name, key))
}

/// The rendezvous directory and the socket's leaf name inside it, for a connect that must not
/// leave that directory (see `binder::connect` — the provider can write the directory).
#[must_use]
pub fn host_rp_parts(
    tier: Tier,
    name: &MeshName,
    key: Option<&MeshKey>,
    endpoint: &str,
) -> (PathBuf, std::ffi::OsString) {
    let leaf = Path::new(endpoint)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("sock"));
    (host_rp_dir(tier, name, key), leaf.to_owned())
}

/// The host socket the broker connects.
///
/// The rendezvous directory plus the basename of the provider's policy `endpoint` — the leaf the
/// provider binds, seen host-side.
#[must_use]
pub fn host_rp_socket(
    tier: Tier,
    name: &MeshName,
    key: Option<&MeshKey>,
    endpoint: &str,
) -> PathBuf {
    let leaf = Path::new(endpoint)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("sock"));
    host_rp_dir(tier, name, key).join(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &str, key: Option<&str>) -> (MeshName, Option<MeshKey>) {
        capability(name, key).expect("a well-formed capability")
    }

    #[test]
    fn key_is_appended_iff_present() {
        let (name, none) = cap("org.x.wl", None);
        assert_eq!(component(&name, none.as_ref()), "org.x.wl");
        let (name, key) = cap("org.x.wl", Some("K1"));
        assert_eq!(component(&name, key.as_ref()), "org.x.wl.K1");
    }

    #[test]
    fn a_malformed_name_or_key_never_becomes_a_path() {
        for (name, key) in [
            ("../escape", None),
            ("/etc", None),
            ("a/b", None),
            ("", None),
            ("org.x.wl", Some("../k")),
            ("org.x.wl", Some("")),
        ] {
            assert!(capability(name, key).is_none(), "{name:?} {key:?}");
        }
    }

    #[test]
    fn host_socket_is_the_rp_dir_plus_the_policy_endpoint_basename() {
        let (name, key) = cap("org.x.wl", Some("K1"));
        let s = host_rp_socket(Tier::User, &name, key.as_ref(), "/run/mesh/wayland-0");
        assert!(s.ends_with("mesh/user/org.x.wl.K1/wayland-0"));
    }

    #[test]
    fn tier_distinguishes_a_per_user_from_a_per_host_directory() {
        let (name, _) = cap("org.x.wl", None);
        let user = host_rp_dir(Tier::User, &name, None);
        let host = host_rp_dir(Tier::Host, &name, None);
        assert_ne!(user, host);
        assert!(user.ends_with("mesh/user/org.x.wl"));
        assert!(host.ends_with("mesh/host/org.x.wl"));
    }
}
