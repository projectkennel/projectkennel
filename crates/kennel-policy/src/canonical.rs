//! Canonical-form serialisation: the exact bytes a signature covers.
//!
//! The signature on a settled policy is computed over the canonical form of its
//! body (the [`SettledPolicy`], excluding the `[signature]` envelope, which is a
//! sibling table in the document). Because the signer and verifier both derive
//! the bytes the same way — a deterministic `basic-toml` serialisation of the
//! body struct in declaration order — they agree byte-for-byte.
//!
//! This pins the canonical form *for this build*. The architecture's canonical
//! JSON form (`02-2-config-schema.md`) is the eventual interop format; adopting
//! it is deferred with the JSON serialiser (see `settled` module docs).

use crate::error::PolicyError;
use crate::settled::SettledPolicy;

/// The canonical bytes for `policy` — the input to signing and verification.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if the body cannot be serialised (which
/// would indicate a struct shape the TOML serialiser rejects, caught in tests).
pub fn canonical_bytes(policy: &SettledPolicy) -> Result<Vec<u8>, PolicyError> {
    basic_toml::to_string(policy)
        .map(String::into_bytes)
        .map_err(|e| PolicyError::Canonical(e.to_string()))
}
