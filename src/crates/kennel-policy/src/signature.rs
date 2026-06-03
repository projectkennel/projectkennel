//! The signature envelope and its verification.
//!
//! A signature is a plain Ed25519 signature over the canonical-form bytes of the
//! artefact (`docs/architecture/02-2-config-schema.md` §Signatures). The algorithm is
//! fixed at `ed25519`; anything else is a categorical error.

use ed25519_compact::Signature;
use serde::{Deserialize, Serialize};

use crate::keys::KeySet;

/// Why a signature could not be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The `algorithm` field is not in the supported set (`ed25519`).
    UnsupportedAlgorithm(String),
    /// No key with the envelope's `key_id` is in the trust store.
    UnknownKey(String),
    /// A public or signing key was not valid Ed25519 key material.
    MalformedKey,
    /// The `signature` field is not valid Base64 of a 64-byte signature.
    MalformedSignature,
    /// The signature did not verify against the canonical bytes and key.
    Verification,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "unsupported signature algorithm `{a}` (only ed25519)")
            }
            Self::UnknownKey(id) => write!(f, "no trusted key with key_id `{id}`"),
            Self::MalformedKey => write!(f, "malformed Ed25519 key material"),
            Self::MalformedSignature => write!(f, "malformed signature (bad Base64 or length)"),
            Self::Verification => write!(f, "signature did not verify"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The `[signature]` envelope carried by a signed artefact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    /// Signature algorithm. Must be `"ed25519"`.
    pub algorithm: String,
    /// Identifies the signing key in the trust store.
    pub key_id: String,
    /// Base64-encoded 64-byte Ed25519 signature over the canonical bytes.
    pub signature: String,
    /// The top-level fields the signature covers (every field except
    /// `[signature]`). Recorded for source artefacts; for the settled policy the
    /// canonical form is the whole body, so this may be empty.
    #[serde(default)]
    pub signed_fields: Vec<String>,
}

/// Verify `envelope`'s signature over `canonical` against the trust store.
///
/// # Errors
///
/// Returns a [`SignatureError`] if the algorithm is unsupported, the `key_id` is
/// unknown, the signature is malformed, or verification fails.
pub fn verify_signature(
    canonical: &[u8],
    envelope: &SignatureEnvelope,
    keys: &KeySet,
) -> Result<(), SignatureError> {
    if envelope.algorithm != "ed25519" {
        return Err(SignatureError::UnsupportedAlgorithm(
            envelope.algorithm.clone(),
        ));
    }
    let key = keys
        .get(&envelope.key_id)
        .ok_or_else(|| SignatureError::UnknownKey(envelope.key_id.clone()))?;
    let sig_bytes = crate::b64::decode(envelope.signature.as_bytes())
        .ok_or(SignatureError::MalformedSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| SignatureError::MalformedSignature)?;
    key.verify(canonical, &signature)
        .map_err(|_| SignatureError::Verification)
}
