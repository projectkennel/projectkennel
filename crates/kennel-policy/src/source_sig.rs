//! Ed25519 signing and verification of **source** artefacts (templates, fragments).
//!
//! # Purpose
//!
//! The settled policy is ed25519-signed; the same mechanism secures the source
//! templates a settled policy is compiled from (`02-2-config-schema.md` §Signatures,
//! `docs/05-templates.md` §5.10). A versioned reference resolves to bytes only if
//! those bytes carry a `[signature]` that verifies against the trust store — so
//! re-tagging a version to different content is caught: the deterministic ed25519
//! signature over the canonical source *is* the content commitment, which is why no
//! separate content hash (and no `sha2` dependency) is needed.
//!
//! # Canonical form
//!
//! The signature covers the artefact's canonical serialisation with the
//! `[signature]` table itself excluded — exactly the [`crate::canonical`] approach
//! for settled policies, applied to a [`SourcePolicy`]. Because the same
//! implementation produces and checks these bytes, a fixed-field-order TOML
//! serialisation is reproducible without a canonicaliser.
//!
//! # Trust modes
//!
//! [`SignatureMode::Require`] (attested deployments) refuses an unsigned or
//! unverifiable artefact; [`SignatureMode::AllowUnsigned`] (local development)
//! resolves unsigned artefacts so the in-tree, not-yet-signed templates remain
//! usable while authoring. A *present* signature is always checked when a trust
//! store is supplied, in either mode.

use crate::keys::{KeySet, SigningKey};
use crate::signature::{verify_signature, SignatureEnvelope, SignatureError};
use crate::source::SourcePolicy;
use crate::PolicyError;

/// Whether unsigned source artefacts are tolerated during resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    /// Refuse any unsigned or unverifiable ancestor (attested deployments).
    Require,
    /// Resolve unsigned ancestors (local development); still verify any present
    /// signature when a trust store is supplied.
    AllowUnsigned,
}

/// The trust context resolution verifies ancestors against.
/// (No `Debug`: [`KeySet`] holds opaque key material and does not implement it.)
#[derive(Clone, Copy)]
pub struct Trust<'a> {
    keys: Option<&'a KeySet>,
    mode: SignatureMode,
}

impl<'a> Trust<'a> {
    /// Require every ancestor to be signed and verify against `keys`.
    #[must_use]
    pub const fn require(keys: &'a KeySet) -> Self {
        Self { keys: Some(keys), mode: SignatureMode::Require }
    }

    /// Allow unsigned ancestors; verify any present signature against `keys` (if any).
    #[must_use]
    pub const fn allow_unsigned(keys: Option<&'a KeySet>) -> Self {
        Self { keys, mode: SignatureMode::AllowUnsigned }
    }

    /// The development default: no trust store, unsigned artefacts permitted.
    #[must_use]
    pub const fn dev() -> Self {
        Self { keys: None, mode: SignatureMode::AllowUnsigned }
    }

    /// Whether this context requires signatures ([`SignatureMode::Require`]).
    #[must_use]
    pub const fn requires_signatures(&self) -> bool {
        matches!(self.mode, SignatureMode::Require)
    }

    /// Verify one ancestor against this trust context, returning the verified
    /// signing-key id (if a signature was checked).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Resolution`] when [`SignatureMode::Require`] and the
    /// artefact is unsigned or no trust store is configured, or
    /// [`PolicyError::Signature`] when a present signature fails to verify.
    pub fn check(&self, name: &str, policy: &SourcePolicy) -> Result<Option<String>, PolicyError> {
        match (&policy.signature, self.keys) {
            (Some(env), Some(keys)) => {
                let key_id = verify_source(policy, env, keys)?;
                Ok(Some(key_id))
            }
            (Some(_), None) => {
                if self.mode == SignatureMode::Require {
                    Err(require_err(name, "no trust store is configured to verify its signature"))
                } else {
                    Ok(None) // signed, but dev mode with no keys: nothing to check against
                }
            }
            (None, _) => {
                if self.mode == SignatureMode::Require {
                    Err(require_err(name, "it is unsigned and signatures are required"))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

fn require_err(name: &str, why: &str) -> PolicyError {
    PolicyError::Resolution(format!("template `{name}` cannot be trusted: {why}"))
}

/// The canonical bytes a source artefact's signature covers: its TOML
/// serialisation with the `[signature]` table excluded.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if serialisation fails.
pub fn canonical_source(policy: &SourcePolicy) -> Result<Vec<u8>, PolicyError> {
    let mut bare = policy.clone();
    bare.signature = None;
    basic_toml::to_string(&bare).map(String::into_bytes).map_err(|e| PolicyError::Canonical(e.to_string()))
}

/// Sign a source artefact, returning a copy with its `[signature]` set.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if the canonical form cannot be produced.
pub fn sign_source(policy: &SourcePolicy, key: &SigningKey) -> Result<SourcePolicy, PolicyError> {
    let canonical = canonical_source(policy)?;
    let sig = key.sign(&canonical);
    let mut signed = policy.clone();
    signed.signature = Some(SignatureEnvelope {
        algorithm: "ed25519".to_owned(),
        key_id: key.key_id().to_owned(),
        signature: crate::b64::encode(&sig),
        signed_fields: Vec::new(),
    });
    Ok(signed)
}

/// Verify a source artefact's signature envelope against `keys`, returning the
/// verified signing-key id.
///
/// # Errors
///
/// Returns [`PolicyError::Signature`] if the signature does not verify, or
/// [`PolicyError::Canonical`] if the canonical form cannot be produced.
pub fn verify_source(
    policy: &SourcePolicy,
    envelope: &SignatureEnvelope,
    keys: &KeySet,
) -> Result<String, PolicyError> {
    let canonical = canonical_source(policy)?;
    verify_signature(&canonical, envelope, keys).map_err(PolicyError::Signature)?;
    Ok(envelope.key_id.clone())
}

/// Convenience: verify a source artefact that carries its own signature.
///
/// # Errors
///
/// Returns [`PolicyError::Signature`] (including [`SignatureError::MalformedSignature`]
/// when unsigned) if verification fails.
pub fn verify_self(policy: &SourcePolicy, keys: &KeySet) -> Result<String, PolicyError> {
    let env = policy
        .signature
        .as_ref()
        .ok_or(PolicyError::Signature(SignatureError::MalformedSignature))?;
    verify_source(policy, env, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse;

    const BASE_CONFINED: &str = include_str!("../../../templates/base-confined/policy.toml");

    fn keypair() -> (SigningKey, KeySet) {
        let key = SigningKey::from_seed("kennel-maint-2026", &[3u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes()).expect("insert");
        (key, ks)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let (key, ks) = keypair();
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let signed = sign_source(&pol, &key).expect("sign");
        assert_eq!(verify_self(&signed, &ks).expect("verify"), "kennel-maint-2026");
    }

    #[test]
    fn tampering_after_signing_is_detected() {
        let (key, ks) = keypair();
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let mut signed = sign_source(&pol, &key).expect("sign");
        // Mutate a substantive field after signing.
        signed.threat_catalogue_version = Some("tampered".to_owned());
        assert!(verify_self(&signed, &ks).is_err(), "tamper must fail verification");
    }

    #[test]
    fn require_mode_refuses_unsigned() {
        let (_key, ks) = keypair();
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse"); // unsigned
        let trust = Trust::require(&ks);
        assert!(trust.check("base-confined", &pol).is_err(), "Require refuses unsigned");
    }

    #[test]
    fn dev_mode_allows_unsigned() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        assert_eq!(Trust::dev().check("base-confined", &pol).expect("dev ok"), None);
    }

    #[test]
    fn require_mode_verifies_a_present_signature() {
        let (key, ks) = keypair();
        let signed = sign_source(&parse(BASE_CONFINED.as_bytes()).expect("parse"), &key).expect("sign");
        let trust = Trust::require(&ks);
        assert_eq!(
            trust.check("base-confined", &signed).expect("verify"),
            Some("kennel-maint-2026".to_owned())
        );
    }

    #[test]
    fn wrong_key_is_rejected_in_require_mode() {
        let (key, _ks) = keypair();
        let signed = sign_source(&parse(BASE_CONFINED.as_bytes()).expect("parse"), &key).expect("sign");
        // A trust store that does not contain the signer.
        let other = SigningKey::from_seed("other", &[9u8; 32]).expect("key");
        let mut ks = KeySet::new();
        ks.insert(other.key_id(), &other.public_key_bytes()).expect("insert");
        assert!(Trust::require(&ks).check("base-confined", &signed).is_err(), "unknown signer rejected");
    }
}
