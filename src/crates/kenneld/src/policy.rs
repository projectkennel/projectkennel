//! Loading and verifying policies against a trust store.
//!
//! The daemon's production [`crate::server::PolicyLoader`]. The
//! trust store is a directory of Ed25519 public keys — one `*.pub` file per
//! signer, the file stem its key id and the contents its base64-encoded 32-byte
//! public key — root-managed, like `/etc/kennel/subkennel`. Default location
//! `/etc/kennel/trust/`, overridable with `$KENNEL_TRUST_DIR` (for tests and
//! non-standard installs). Loading a policy reads the file, verifies its single
//! signature against the trust store, substitutes the per-instance placeholders,
//! and translates the result into a [`Plan`] — all via
//! [`kennel_spawn::prepare`].

use std::path::{Path, PathBuf};

use kennel_policy::KeySet;
use kennel_spawn::{Plan, RuntimeSubstitutions};

use crate::server::{Loaded, PolicyLoader};

/// The default trust-store directory.
pub const DEFAULT_TRUST_DIR: &str = "/etc/kennel/trust";
/// The environment variable that overrides the trust-store directory.
pub const TRUST_DIR_ENV: &str = "KENNEL_TRUST_DIR";

/// The configured trust-store directory: `$KENNEL_TRUST_DIR` if set, else
/// [`DEFAULT_TRUST_DIR`].
#[must_use]
pub fn trust_dir() -> PathBuf {
    std::env::var_os(TRUST_DIR_ENV).map_or_else(|| PathBuf::from(DEFAULT_TRUST_DIR), PathBuf::from)
}

/// A [`PolicyLoader`] backed by a trust store of public keys.
pub struct TrustStoreLoader {
    keys: KeySet,
}

impl TrustStoreLoader {
    /// Build a loader from the public keys in `dir` (each `*.pub` file).
    ///
    /// # Errors
    /// An OS error if the directory cannot be read, or `InvalidData` if a `*.pub`
    /// file's contents are not a valid base64 Ed25519 public key.
    pub fn from_dir(dir: &Path) -> std::io::Result<Self> {
        let mut keys = KeySet::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            let Some(key_id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let contents = std::fs::read_to_string(&path)?;
            keys.insert_b64(key_id, contents.trim()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad key {key_id}: {e:?}"),
                )
            })?;
        }
        Ok(Self { keys })
    }

    /// Build a loader from an in-memory [`KeySet`] (for tests/embedding).
    #[must_use]
    pub const fn from_keys(keys: KeySet) -> Self {
        Self { keys }
    }

    /// The number of trusted keys.
    #[must_use]
    pub const fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl PolicyLoader for TrustStoreLoader {
    fn load(&self, path: &Path, subst: &RuntimeSubstitutions) -> Result<Loaded, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
        // Verify + substitute once; derive both artefacts from the one policy
        // (the same steps `kennel_spawn::prepare` runs, kept open here so the net
        // section is available to configure the egress proxy).
        let verified =
            kennel_policy::verify_settled(&bytes, &self.keys).map_err(|e| e.to_string())?;
        let substituted = kennel_spawn::substitute(&verified, subst).map_err(|e| e.to_string())?;
        let mut plan = Plan::from_policy(&substituted, subst.ctx, &subst.namespace, &subst.home)
            .map_err(|e| e.to_string())?;
        // Resolve the policy's supplementary groups to GIDs and membership-check them
        // (§7.2): kenneld runs as the operator, so a group the operator is not in is
        // refused — the privileged seal could otherwise over-grant. The kennel always
        // drops to exactly this set (empty ⇒ no supplementary groups at all).
        let groups = resolve_groups(&substituted.identity.groups)?;
        plan.supplementary_groups = Some(groups.iter().map(|(_, gid)| *gid).collect());
        let net = substituted.effective_policy.net;
        let ssh = substituted.ssh;
        let unix = substituted.unix;
        let audit = substituted.audit;
        Ok(Loaded {
            plan,
            net,
            ssh,
            unix,
            groups,
            audit,
        })
    }
}

/// Resolve the policy's supplementary group names to `(name, gid)` pairs, refusing
/// any the operator is not a member of (§7.2).
///
/// kenneld runs as the operator, so its own group set is the operator's. A name that
/// does not resolve, or resolves to a group the operator does not hold, is a
/// fail-closed error: the privileged seal `setgroups` could otherwise grant a group
/// the operator lacks (privilege escalation). De-duplicated, order-preserving.
fn resolve_groups(names: &[String]) -> Result<Vec<(String, u32)>, String> {
    use kennel_syscall::unistd;
    let real_gid = unistd::real_gid();
    let held = unistd::supplementary_groups();
    let mut out: Vec<(String, u32)> = Vec::new();
    for name in names {
        let gid = unistd::group_gid(name)
            .map_err(|e| format!("[identity] resolving group `{name}`: {e}"))?
            .ok_or_else(|| format!("[identity] group `{name}` does not exist on this host"))?;
        if gid != real_gid && !held.contains(&gid) {
            return Err(format!(
                "[identity] group `{name}` (gid {gid}): the user is not a member; refusing to grant it into the kennel"
            ));
        }
        if !out.iter().any(|(_, g)| *g == gid) {
            out.push((name.clone(), gid));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_policy::SigningKey;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kenneld-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir trust");
        dir
    }

    fn subst() -> RuntimeSubstitutions {
        RuntimeSubstitutions {
            ctx: 1,
            uid: 1000,
            kennel: "t".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-test".to_owned(),
        }
    }

    /// Write a signer's public key as a `<key_id>.pub` base64 file in `dir`.
    fn write_pubkey(dir: &Path, key: &SigningKey) {
        let b64 = kennel_policy::b64::encode(&key.public_key_bytes());
        std::fs::write(dir.join(format!("{}.pub", key.key_id())), b64).expect("write pubkey");
    }

    #[test]
    fn from_dir_loads_pub_keys() {
        let dir = temp_dir("keys");
        let key = SigningKey::from_seed("maint-2026", &[7u8; 32]).expect("key");
        write_pubkey(&dir, &key);
        // A non-.pub file is ignored.
        std::fs::write(dir.join("README"), "ignore me").expect("write");

        let loader = TrustStoreLoader::from_dir(&dir).expect("from_dir");
        assert_eq!(loader.key_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_dir_rejects_a_malformed_key() {
        let dir = temp_dir("bad");
        std::fs::write(dir.join("broken.pub"), "not base64!!!").expect("write");
        assert!(TrustStoreLoader::from_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_reports_a_missing_policy_file() {
        let loader = TrustStoreLoader::from_keys(KeySet::new());
        let err = loader
            .load(Path::new("/nonexistent/policy"), &subst())
            .expect_err("must fail");
        assert!(err.contains("cannot read policy"), "got {err}");
    }

    #[test]
    fn load_rejects_unsigned_garbage() {
        let dir = temp_dir("garbage");
        let policy = dir.join("p.policy");
        std::fs::write(&policy, b"this is not a signed policy").expect("write");
        let key = SigningKey::from_seed("maint-2026", &[7u8; 32]).expect("key");
        let mut keys = KeySet::new();
        keys.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");

        let loader = TrustStoreLoader::from_keys(keys);
        assert!(
            loader.load(&policy, &subst()).is_err(),
            "garbage must not verify"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_dir_defaults_when_unset() {
        // env is process-global; only assert the default when the override is unset.
        if std::env::var_os(TRUST_DIR_ENV).is_none() {
            assert_eq!(trust_dir().as_path(), Path::new(DEFAULT_TRUST_DIR));
        }
    }
}
