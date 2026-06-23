//! The enablement scan (`07-13-service-catalog.md` §7.13.6): the catalogue's membership.
//!
//! Installing a provider (its signed policy in the cascade) and *enabling* one are distinct: a
//! provider is inert until the operator links it into an `autorun/` (eager) or `ondemand/` (lazy)
//! directory, at the per-user or per-host layer. This module walks those directories
//! ([`kennel_lib_config::enablement_dirs`], per-user first), verifies each linked settled policy, and
//! produces the [`EnabledProvider`] set the [`Catalogue`](crate::catalogue::Catalogue) projects.
//!
//! The set is the **links on disk**, re-read on every scan (daemon start, `daemon-reload`) — never
//! standing authored state, so a restart cannot lose it. A link that does not resolve to a verifiable
//! provider policy is reported and skipped, not fatal.

use std::collections::BTreeSet;
use std::path::Path;

use kennel_lib_config::EnablementDir;
use kennel_lib_policy::settled::ProvideRuntime;
use kennel_lib_policy::KeySet;

use crate::catalogue::{EnabledProvider, Enablement, Tier};

/// Scan the enablement directories and build the enabled-provider set.
///
/// `dirs` is in precedence order (per-user first, [`kennel_lib_config::enablement_dirs`]); the **first**
/// directory that enables a given provider name wins, so a per-user link overrides a per-host one for
/// the same provider. Each enabled link is its provider's settled policy: it is verified against
/// `keys` and its `[[provides]]` read off. A link that cannot be read, fails verification, or provides
/// nothing is passed to `warn` and skipped (the provider is simply absent from the catalogue). A
/// missing directory is silently absent.
pub fn scan(
    dirs: &[EnablementDir],
    keys: &KeySet,
    mut warn: impl FnMut(String),
) -> Vec<EnabledProvider> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir.path) else {
            continue; // a missing/unreadable enablement dir is absent, not an error
        };
        // Stable order within a directory (independent of `read_dir` order).
        let mut links: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        links.sort();
        for link in &links {
            let Some(provider) = link.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if seen.contains(provider) {
                continue; // an earlier (preferred) directory already enabled this provider
            }
            match load_provider(link, keys) {
                Ok(Some((signing_key_id, offers))) => {
                    seen.insert(provider.to_owned());
                    out.push(EnabledProvider {
                        provider: provider.to_owned(),
                        signing_key_id,
                        tier: if dir.per_user { Tier::User } else { Tier::Host },
                        enablement: if dir.eager {
                            Enablement::Autorun
                        } else {
                            Enablement::Ondemand
                        },
                        provides: offers,
                    });
                }
                Ok(None) => warn(format!(
                    "enablement {}: provides nothing — ignored",
                    link.display()
                )),
                Err(e) => warn(format!("enablement {}: {e} — ignored", link.display())),
            }
        }
    }
    out
}

/// Read and verify one enabled link's settled policy, returning its signing key id and `[[provides]]`,
/// or `Ok(None)` if it provides nothing.
fn load_provider(
    link: &Path,
    keys: &KeySet,
) -> Result<Option<(String, Vec<ProvideRuntime>)>, String> {
    let bytes = std::fs::read(link).map_err(|e| format!("cannot read: {e}"))?;
    let (settled, key_id) =
        kennel_lib_policy::verify_settled_signed(&bytes, keys).map_err(|e| e.to_string())?;
    if settled.mesh.provides.is_empty() {
        return Ok(None);
    }
    Ok(Some((key_id, settled.mesh.provides)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::settled::{sample_settled, ProvideRuntime, Shape};
    use kennel_lib_policy::SigningKey;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("kennel-enablement-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// Write a signed provider policy offering `name` into `dir/<provider>`.
    fn enable(dir: &Path, provider: &str, name: &str, key: &SigningKey) {
        let mut policy = sample_settled();
        policy.mesh.provides = vec![ProvideRuntime {
            name: name.to_owned(),
            shape: Shape::AfUnix,
            endpoint: "/run/x".to_owned(),
            key: None,
        }];
        let signed = kennel_lib_policy::sign_settled(&policy, key).expect("sign");
        let bytes = kennel_lib_policy::to_bytes(&signed).expect("bytes");
        std::fs::write(dir.join(provider), bytes).expect("write link");
    }

    fn keyset(key: &SigningKey) -> KeySet {
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");
        ks
    }

    #[test]
    fn scan_finds_an_enabled_provider_with_its_tier_and_posture() {
        let key = SigningKey::from_seed("alice", &[1u8; 32]).expect("key");
        let host_autorun = tmp("host-autorun");
        enable(&host_autorun, "cache", "doe.john.cache", &key);
        let dirs = vec![EnablementDir {
            path: host_autorun.clone(),
            per_user: false,
            eager: true,
        }];
        let mut warnings = Vec::new();
        let providers = scan(&dirs, &keyset(&key), |w| warnings.push(w));
        assert!(warnings.is_empty());
        assert_eq!(providers.len(), 1);
        let p = providers.first().expect("one");
        assert_eq!(p.provider, "cache");
        assert_eq!(p.tier, Tier::Host);
        assert_eq!(p.enablement, Enablement::Autorun);
        assert_eq!(p.signing_key_id, "alice");
        assert_eq!(p.provides.len(), 1);
        let _ = std::fs::remove_dir_all(&host_autorun);
    }

    #[test]
    fn per_user_enablement_shadows_per_host_for_the_same_provider() {
        let key = SigningKey::from_seed("alice", &[1u8; 32]).expect("key");
        let user = tmp("user-ondemand");
        let host = tmp("host-autorun2");
        // Both layers enable a provider named "cache" — the user link must win.
        enable(&user, "cache", "doe.john.cache", &key);
        enable(&host, "cache", "doe.john.cache", &key);
        // Precedence order: user first.
        let dirs = vec![
            EnablementDir {
                path: user.clone(),
                per_user: true,
                eager: false,
            },
            EnablementDir {
                path: host.clone(),
                per_user: false,
                eager: true,
            },
        ];
        let providers = scan(&dirs, &keyset(&key), |_| {});
        assert_eq!(providers.len(), 1, "the same provider is enabled once");
        let p = providers.first().expect("one");
        assert_eq!(p.tier, Tier::User, "per-user wins");
        assert_eq!(
            p.enablement,
            Enablement::Ondemand,
            "the user link's posture"
        );
        let _ = std::fs::remove_dir_all(&user);
        let _ = std::fs::remove_dir_all(&host);
    }

    #[test]
    fn an_unverifiable_link_is_warned_and_skipped() {
        let key = SigningKey::from_seed("alice", &[1u8; 32]).expect("key");
        let dir = tmp("bad");
        std::fs::write(dir.join("junk"), b"not a signed policy").expect("write");
        let mut warnings = Vec::new();
        let providers = scan(
            &[EnablementDir {
                path: dir.clone(),
                per_user: false,
                eager: true,
            }],
            &keyset(&key),
            |w| warnings.push(w),
        );
        assert!(providers.is_empty());
        assert_eq!(warnings.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_dir_is_absent_not_an_error() {
        let mut warnings = Vec::new();
        let providers = scan(
            &[EnablementDir {
                path: std::path::PathBuf::from("/no/such/enablement/dir"),
                per_user: false,
                eager: true,
            }],
            &KeySet::new(),
            |w| warnings.push(w),
        );
        assert!(providers.is_empty());
        assert!(
            warnings.is_empty(),
            "a missing dir is absent, not a warning"
        );
    }
}
