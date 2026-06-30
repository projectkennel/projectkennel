//! The signature envelope and its verification.
//!
//! A signature is an SSHSIG (OpenSSH detached signature, [`crate::sshsig`]) over the
//! canonical-form bytes of the artefact, produced by `ssh-keygen -Y sign` and verified
//! in-process for Ed25519 keys. The algorithm field is fixed at `sshsig`; anything else
//! is a categorical error.

use serde::{Deserialize, Serialize};

use crate::keys::KeySet;

/// The `algorithm` value a kennel signature carries: an SSHSIG (OpenSSH detached
/// signature) over the canonical bytes. The underlying primitive is Ed25519.
pub const SSHSIG_ALGORITHM: &str = "sshsig";

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
    /// The SSHSIG armor or binary structure could not be parsed.
    MalformedSshsig(String),
    /// The SSHSIG `namespace` is not the kennel-policy domain (domain-separation
    /// guard — a signature minted for another protocol must not verify here).
    NamespaceMismatch(String),
    /// The key embedded in the SSHSIG is not the one the trust store holds under
    /// the envelope's `key_id` (the store is the authority; the embedded key is a
    /// claim that must agree).
    KeyMismatch,
    /// The signer is a hardware (`sk-`) key: its signature is non-deterministic and
    /// must be verified out-of-process via `ssh-keygen -Y verify`, off the hot path.
    HardwareKeyRequiresExternalVerify,
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
            Self::MalformedSshsig(m) => write!(f, "malformed SSHSIG: {m}"),
            Self::NamespaceMismatch(n) => {
                write!(f, "SSHSIG namespace `{n}` is not the kennel-policy domain")
            }
            Self::KeyMismatch => write!(
                f,
                "SSHSIG-embedded key does not match the trust-store key for this key_id"
            ),
            Self::HardwareKeyRequiresExternalVerify => write!(
                f,
                "hardware (sk-) signer requires out-of-process verification via ssh-keygen"
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The `[signature]` envelope carried by a signed artefact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SignatureEnvelope {
    /// Signature algorithm. Must be `"sshsig"` ([`SSHSIG_ALGORITHM`]).
    pub algorithm: String,
    /// Identifies the signing key in the trust store. The SSHSIG also embeds the
    /// public key; the two must agree, and the store is the authority.
    pub key_id: String,
    /// The armored SSHSIG (`-----BEGIN SSH SIGNATURE-----` …) over the canonical
    /// bytes, stored verbatim — the content commitment lifted into the lockfile.
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
    if envelope.algorithm != SSHSIG_ALGORITHM {
        return Err(SignatureError::UnsupportedAlgorithm(
            envelope.algorithm.clone(),
        ));
    }
    // The trust store is the authority: resolve the `key_id` to the key we trust, then
    // require the SSHSIG-embedded key to match it (checked inside `SshSig::verify`).
    let key = keys
        .get(&envelope.key_id)
        .ok_or_else(|| SignatureError::UnknownKey(envelope.key_id.clone()))?;
    let sig = crate::sshsig::SshSig::parse_armored(&envelope.signature)?;
    sig.verify(canonical, key)
}
