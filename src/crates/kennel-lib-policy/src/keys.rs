//! The trust store: Ed25519 public keys identified by `key_id`, plus the
//! signing-key wrapper used by the compiler and tests.
//!
//! `kennel-lib-policy` performs no I/O (the architecture makes file reading the
//! caller's job): a [`KeySet`] is built in memory from `(key_id, key_bytes)`
//! pairs the caller has already read from `~/.config/kennel/keys/` and
//! `/etc/kennel/keys/`.

use ed25519_compact::{KeyPair, PublicKey, Seed};

use crate::signature::SignatureError;

/// A set of trusted Ed25519 public keys, looked up by `key_id`.
#[derive(Default, Clone)]
pub struct KeySet {
    keys: Vec<(String, PublicKey)>,
}

impl KeySet {
    /// An empty trust store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a trusted key from its 32 raw public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::MalformedKey`] if `key_bytes` is not a valid
    /// 32-byte Ed25519 public key.
    pub fn insert(
        &mut self,
        key_id: impl Into<String>,
        key_bytes: &[u8],
    ) -> Result<(), SignatureError> {
        let pk = PublicKey::from_slice(key_bytes).map_err(|_| SignatureError::MalformedKey)?;
        self.keys.push((key_id.into(), pk));
        Ok(())
    }

    /// Insert a trusted key from its Base64-encoded public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::MalformedKey`] if the Base64 is invalid or does
    /// not decode to a 32-byte key.
    pub fn insert_b64(
        &mut self,
        key_id: impl Into<String>,
        key_b64: &str,
    ) -> Result<(), SignatureError> {
        let bytes = crate::b64::decode(key_b64.as_bytes()).ok_or(SignatureError::MalformedKey)?;
        self.insert(key_id, &bytes)
    }

    /// Insert a trusted key from a trust-store `.pub` file's contents.
    ///
    /// Accepts the OpenSSH public-key line the keygen writes
    /// (`ssh-ed25519 <base64-blob> [comment]`) and, for legacy stores predating the SSHSIG
    /// format, a bare base64 of the 32 raw key bytes. The `key_id` is the caller's (the trust dir
    /// keys by file stem), independent of any OpenSSH comment.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::MalformedKey`] if the contents are neither a valid OpenSSH
    /// Ed25519 public key nor base64 that decodes to a 32-byte key.
    pub fn insert_pub_line(
        &mut self,
        key_id: impl Into<String>,
        contents: &str,
    ) -> Result<(), SignatureError> {
        let trimmed = contents.trim();
        if let Ok((bytes, _comment)) = crate::openssh::parse_public_key(trimmed) {
            return self.insert(key_id, &bytes);
        }
        self.insert_b64(key_id, trimmed)
    }

    /// Look up a trusted public key by its `key_id`.
    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.keys
            .iter()
            .find(|(id, _)| id == key_id)
            .map(|(_, pk)| pk)
    }

    /// Number of keys in the store.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// An Ed25519 signing key plus its `key_id`. Used by the compiler (`sign_settled`)
/// and tests; never needed on the runtime verification path.
#[derive(Clone)]
pub struct SigningKey {
    key_id: String,
    keypair: KeyPair,
}

impl SigningKey {
    /// Derive a signing key deterministically from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::MalformedKey`] if `seed` is not 32 bytes.
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self, SignatureError> {
        let seed = Seed::from_slice(seed).map_err(|_| SignatureError::MalformedKey)?;
        Ok(Self {
            key_id: key_id.into(),
            keypair: KeyPair::from_seed(seed),
        })
    }

    /// This key's `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The corresponding public key bytes (32 bytes), e.g. to register in a
    /// [`KeySet`].
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.keypair.pk
    }

    /// Sign `message`, returning the 64-byte detached Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        *self.keypair.sk.sign(message, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the OpenSSH public-key line the keygen writes, for a known 32-byte key.
    fn openssh_line(pubkey: &[u8; 32], comment: &str) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(pubkey);
        format!("ssh-ed25519 {} {comment}", crate::b64::encode(&blob))
    }

    /// The trust loader accepts an OpenSSH public-key line (the keygen format) and resolves it to
    /// the same key the raw bytes do — keyed by the caller's `key_id`, not the OpenSSH comment.
    #[test]
    fn insert_pub_line_reads_openssh_format() {
        let signer = SigningKey::from_seed("k", &[7u8; 32]).expect("signer");
        let bytes = signer.public_key_bytes();
        let line = openssh_line(&bytes, "a-comment");

        let mut ks = KeySet::new();
        ks.insert_pub_line("trusted-id", &line)
            .expect("openssh line loads");
        assert!(ks.get("trusted-id").is_some());
        assert!(
            ks.get("a-comment").is_none(),
            "key_id is the caller's, not the OpenSSH comment"
        );
    }

    /// Legacy stores (bare base64 of the 32 raw bytes) still load — the maintainer key shipped that
    /// way before the SSHSIG format.
    #[test]
    fn insert_pub_line_reads_legacy_base64() {
        let signer = SigningKey::from_seed("k", &[9u8; 32]).expect("signer");
        let b64 = crate::b64::encode(&signer.public_key_bytes());
        let mut ks = KeySet::new();
        ks.insert_pub_line("legacy-id", &b64)
            .expect("legacy b64 loads");
        assert!(ks.get("legacy-id").is_some());
    }

    #[test]
    fn insert_pub_line_rejects_garbage() {
        let mut ks = KeySet::new();
        assert!(ks.insert_pub_line("x", "not a key").is_err());
    }
}
