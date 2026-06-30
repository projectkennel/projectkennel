//! The lockfile (`kennel.lock`) — byte-pinning resolved references.
//!
//! # Purpose
//!
//! A reference names *which* artefact; the lockfile constrains *what bytes* live under
//! that name. It records, for every reference resolved while loading a policy, the
//! signing-key id and the artefact's ed25519 signature. On every later load the resolver
//! recomputes the chain and compares: a `name` that resolved to a *different* signature
//! than was locked is a hard error, not a warning.
//!
//! # Why the signature is the commitment
//!
//! The maintainer's decision is to use ed25519 for everything rather than carry a
//! second hash (no `sha2` dependency). An ed25519 signature is deterministic
//! (RFC 8032) and bound to the exact canonical bytes it covers, so the signature
//! *is* a content commitment: re-pointing a name at different bytes — even
//! re-signed by another trusted key — changes the recorded signature and is caught.
//!
//! # I/O-free
//!
//! This module parses, serialises, and compares lockfiles; the CLI reads and writes
//! `kennel.lock` on disk.

use crate::resolve::ChainLink;
use kennel_lib_policy::PolicyError;
use serde::{Deserialize, Serialize};

/// One locked reference: a `name` pinned to its signer and signature.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockEntry {
    /// The artefact name.
    pub name: String,
    /// The signing-key id the signature verified against (empty if unsigned).
    #[serde(default)]
    pub signing_key_id: String,
    /// The artefact's ed25519 signature, base64 (empty if unsigned) — the content
    /// commitment.
    #[serde(default)]
    pub signature: String,
}

/// A lockfile: the set of references pinned for one leaf policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    /// One entry per resolved reference (the inheritance chain and includes).
    #[serde(default, rename = "locked", skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<LockEntry>,
}

impl Lockfile {
    /// Build a lockfile from a resolved chain.
    #[must_use]
    pub fn from_chain(chain: &[ChainLink]) -> Self {
        let entries = chain
            .iter()
            .map(|link| LockEntry {
                name: link.name.clone(),
                signing_key_id: link.signing_key_id.clone().unwrap_or_default(),
                signature: link.signature.clone().unwrap_or_default(),
            })
            .collect();
        Self { entries }
    }

    /// Verify this (freshly resolved) lockfile against a `previous` one read from
    /// disk: every reference present in both must carry the same signature.
    ///
    /// References new to this resolution (absent from `previous`) are first-use and
    /// accepted; references in `previous` no longer resolved are ignored. A present
    /// reference whose signature changed is a [`PolicyError::LockMismatch`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::LockMismatch`] naming the first reference whose pinned
    /// signature does not match.
    pub fn verify_against(&self, previous: &Self) -> Result<(), PolicyError> {
        for entry in &self.entries {
            if let Some(prev) = previous.entries.iter().find(|p| p.name == entry.name) {
                if prev.signature != entry.signature {
                    return Err(PolicyError::LockMismatch(format!(
                        "`{}` resolved to different bytes than the lockfile pins \
                         (the template was re-pointed or re-signed); re-pin by recompiling",
                        entry.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// Parse lockfile TOML.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Parse`] if the bytes are not a valid lockfile.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// Serialise to lockfile TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Canonical`] if serialisation fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        basic_toml::to_string(self)
            .map(String::into_bytes)
            .map_err(|e| PolicyError::Canonical(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, sig: &str) -> ChainLink {
        ChainLink {
            name: name.to_owned(),
            signing_key_id: Some("kennel-maint-2026".to_owned()),
            signature: Some(sig.to_owned()),
        }
    }

    #[test]
    fn from_chain_round_trips_through_toml() {
        let lock = Lockfile::from_chain(&[
            link("base-confined", "AAAA"),
            link("ai-coding-strict", "BBBB"),
        ]);
        let bytes = lock.to_bytes().expect("serialise");
        let back = Lockfile::parse(&bytes).expect("parse");
        assert_eq!(lock, back);
        assert_eq!(back.entries.len(), 2);
    }

    #[test]
    fn matching_signature_verifies() {
        let prev = Lockfile::from_chain(&[link("base-confined", "AAAA")]);
        let now = Lockfile::from_chain(&[link("base-confined", "AAAA")]);
        assert!(now.verify_against(&prev).is_ok());
    }

    #[test]
    fn changed_signature_is_a_mismatch() {
        let prev = Lockfile::from_chain(&[link("base-confined", "AAAA")]);
        let now = Lockfile::from_chain(&[link("base-confined", "ZZZZ")]);
        let err = now.verify_against(&prev).expect_err("re-signed must fail");
        assert!(matches!(err, PolicyError::LockMismatch(_)), "got {err}");
    }

    #[test]
    fn first_use_reference_is_accepted() {
        let prev = Lockfile::default();
        let now = Lockfile::from_chain(&[link("base-confined", "AAAA")]);
        assert!(
            now.verify_against(&prev).is_ok(),
            "no prior pin = trust-on-first-use"
        );
    }

    #[test]
    fn dropped_reference_does_not_block() {
        let prev =
            Lockfile::from_chain(&[link("base-confined", "AAAA"), link("corp-egress", "CCCC")]);
        let now = Lockfile::from_chain(&[link("base-confined", "AAAA")]);
        assert!(
            now.verify_against(&prev).is_ok(),
            "no longer using corp-egress is fine"
        );
    }
}
