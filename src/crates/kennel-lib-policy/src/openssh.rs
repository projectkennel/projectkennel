// SPDX-License-Identifier: Apache-2.0

//! OpenSSH Ed25519 key format parsing and generation.
//!
//! Handles:
//! - Public keys: `ssh-ed25519 <base64-blob> [comment]`
//!   The blob is the SSH wire format: `\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20<32-byte-pubkey>`.
//!
//! - Private keys: `-----BEGIN OPENSSH PRIVATE KEY-----` PEM envelope containing
//!   an unencrypted ed25519 key. Encrypted keys are rejected (the operator should
//!   use `ssh-keygen -p` to remove the passphrase, or generate without one).
//!
//! The wire format is fixed-layout for unencrypted Ed25519 — no ASN.1, no
//! variable-length parsing beyond the 4-byte length-prefixed strings. The entire
//! parser is ~130 lines.
//!
//! References:
//! - Public key wire format: RFC 4253 §6.6
//! - Private key format: `PROTOCOL.key` in the OpenSSH source tree

use crate::b64;

/// The SSH key type string for Ed25519.
const KEY_TYPE: &[u8] = b"ssh-ed25519";

/// The `AUTH_MAGIC` header in the private key binary payload.
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// The PEM markers.
/// Why a key file's contents are not an OpenSSH Ed25519 key this parser accepts.
///
/// The contents are untrusted (CODING-STANDARDS.md §8.6), so each way they can be wrong is a
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyParseError {
    /// The public key line is empty.
    Empty,
    /// The public key line names a key type other than `ssh-ed25519`.
    UnsupportedType(String),
    /// The public key line has no base64 blob.
    MissingBlob,
    /// The public key's blob is not base64.
    PublicBase64,
    /// The private key's PEM body is not base64.
    PrivateBase64,
    /// The named field ends before its declared length.
    Truncated(&'static str),
    /// The public key blob names a key type other than `ssh-ed25519`.
    BlobType(String),
    /// The public key is not 32 bytes.
    PublicKeyLength(usize),
    /// The text is not an OpenSSH private key PEM; the string says which marker is wrong.
    NotPem(&'static str),
    /// The private key does not start with the OpenSSH magic.
    BadMagic,
    /// The private key is encrypted.
    Encrypted,
    /// An unencrypted private key names a KDF.
    UnexpectedKdf,
    /// The private key file holds a number of keys other than one.
    KeyCount(u32),
    /// The two check integers differ: the key is corrupted or encrypted.
    CheckMismatch,
    /// The private section names a key type other than `ssh-ed25519`.
    PrivateType(String),
    /// The public key inside the private section is not 32 bytes.
    EmbeddedPublicLength(usize),
    /// The private key is not 64 bytes.
    PrivateKeyLength(usize),
}

impl std::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty public key"),
            Self::UnsupportedType(t) => {
                write!(
                    f,
                    "unsupported key type `{t}` (only ssh-ed25519 is supported)"
                )
            }
            Self::MissingBlob => f.write_str("missing base64 blob in public key"),
            Self::PublicBase64 => f.write_str("invalid base64 in public key"),
            Self::PrivateBase64 => f.write_str("invalid base64 in private key PEM"),
            Self::Truncated(what) => write!(f, "truncated {what}"),
            Self::BlobType(t) => {
                write!(
                    f,
                    "unexpected key type in blob: expected ssh-ed25519, got {t}"
                )
            }
            Self::PublicKeyLength(n) => {
                write!(f, "ed25519 public key must be 32 bytes, got {n}")
            }
            Self::NotPem(why) => write!(f, "not an OpenSSH private key ({why})"),
            Self::BadMagic => f.write_str("invalid OpenSSH private key (bad magic)"),
            Self::Encrypted => f.write_str(
                "encrypted OpenSSH private key — decrypt it first with `ssh-keygen -p -f <key>`",
            ),
            Self::UnexpectedKdf => f.write_str("unexpected kdf in unencrypted key"),
            Self::KeyCount(n) => write!(f, "expected 1 key, found {n}"),
            Self::CheckMismatch => {
                f.write_str("check integers do not match (corrupted or encrypted key)")
            }
            Self::PrivateType(t) => {
                write!(
                    f,
                    "unsupported key type: {t} (only ssh-ed25519 is supported)"
                )
            }
            Self::EmbeddedPublicLength(n) => write!(f, "ed25519 pubkey must be 32 bytes, got {n}"),
            Self::PrivateKeyLength(n) => write!(
                f,
                "ed25519 private key must be 64 bytes (seed‖pubkey), got {n}"
            ),
        }
    }
}

impl std::error::Error for KeyParseError {}

const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";

// ─── Public key ──────────────────────────────────────────────────────────────

/// Parse an OpenSSH public key line: `ssh-ed25519 <base64-blob> [comment]`.
///
/// Returns `(32-byte-pubkey, comment)` on success. The comment is empty if absent.
///
/// # Errors
///
/// Returns a message if the format is wrong or the key type is not ed25519.
pub fn parse_public_key(line: &str) -> Result<([u8; 32], String), KeyParseError> {
    let line = line.trim();
    let mut parts = line.splitn(3, char::is_whitespace);
    let key_type = parts.next().ok_or(KeyParseError::Empty)?;
    if key_type != "ssh-ed25519" {
        return Err(KeyParseError::UnsupportedType(key_type.to_owned()));
    }
    let blob_b64 = parts.next().ok_or(KeyParseError::MissingBlob)?;
    let comment = parts.next().unwrap_or("").trim().to_owned();

    let blob = b64::decode(blob_b64.as_bytes()).ok_or(KeyParseError::PublicBase64)?;
    let pubkey = parse_pubkey_blob(&blob)?;
    Ok((pubkey, comment))
}

/// Extract the 32-byte Ed25519 public key from the SSH wire-format blob.
fn parse_pubkey_blob(blob: &[u8]) -> Result<[u8; 32], KeyParseError> {
    let (key_type, rest) = read_string(blob).ok_or(KeyParseError::Truncated("key type in blob"))?;
    if key_type != KEY_TYPE {
        return Err(KeyParseError::BlobType(
            String::from_utf8_lossy(key_type).into_owned(),
        ));
    }
    let (pubkey, _) = read_string(rest).ok_or(KeyParseError::Truncated("public key in blob"))?;
    if pubkey.len() != 32 {
        return Err(KeyParseError::PublicKeyLength(pubkey.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(pubkey);
    Ok(out)
}

// ─── Private key ─────────────────────────────────────────────────────────────

/// Parse an OpenSSH PEM-encoded private key file.
///
/// Returns `(32-byte-seed, key_id)` on success, where `key_id` is the comment
/// embedded in the private key (defaulting to the filename stem if empty).
///
/// Only unencrypted Ed25519 keys are supported. Encrypted keys or other key
/// types are rejected with a clear error.
///
/// # Errors
///
/// Returns a message describing the failure.
pub fn parse_private_key(pem: &str) -> Result<([u8; 32], String), KeyParseError> {
    // Extract the base64 payload between the PEM markers.
    let start = pem
        .find(PEM_BEGIN)
        .ok_or(KeyParseError::NotPem("missing BEGIN marker"))?
        .saturating_add(PEM_BEGIN.len());
    let end = pem
        .find(PEM_END)
        .ok_or(KeyParseError::NotPem("missing END marker"))?;
    // `get`, not an index: a file whose END marker comes before its BEGIN marker gives
    // `start > end`, and slicing that would panic on input the caller does not control.
    let b64_body: String = pem
        .get(start..end)
        .ok_or(KeyParseError::NotPem("END marker before BEGIN marker"))?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let payload = b64::decode(b64_body.as_bytes()).ok_or(KeyParseError::PrivateBase64)?;

    parse_private_payload(&payload)
}

/// Parse the binary payload of an OpenSSH private key.
///
/// Layout (PROTOCOL.key):
/// ```text
/// AUTH_MAGIC ("openssh-key-v1\0")
/// string ciphername   ("none" for unencrypted)
/// string kdfname      ("none" for unencrypted)
/// string kdfoptions   (empty for "none")
/// u32    number of keys (1)
/// string public key blob
/// string private key section (padded)
///   u32  check1
///   u32  check2
///   string keytype ("ssh-ed25519")
///   string ed25519 public key (32 bytes)
///   string ed25519 private key (64 bytes = seed‖pubkey)
///   string comment
///   padding (1..blocksize)
/// ```
fn parse_private_payload(data: &[u8]) -> Result<([u8; 32], String), KeyParseError> {
    if !data.starts_with(AUTH_MAGIC) {
        return Err(KeyParseError::BadMagic);
    }
    let rest = data.get(AUTH_MAGIC.len()..).unwrap_or_default();

    // ciphername
    let (cipher, rest) = read_string(rest).ok_or(KeyParseError::Truncated("ciphername"))?;
    if cipher != b"none" {
        return Err(KeyParseError::Encrypted);
    }

    // kdfname
    let (kdf, rest) = read_string(rest).ok_or(KeyParseError::Truncated("kdfname"))?;
    if kdf != b"none" {
        return Err(KeyParseError::UnexpectedKdf);
    }

    // kdfoptions (should be empty for "none")
    let (_kdfopts, rest) = read_string(rest).ok_or(KeyParseError::Truncated("kdfoptions"))?;

    // number of keys
    let (nkeys, rest) = read_u32(rest).ok_or(KeyParseError::Truncated("key count"))?;
    if nkeys != 1 {
        return Err(KeyParseError::KeyCount(nkeys));
    }

    // public key blob (skip — we extract the key from the private section)
    let (_pubblob, rest) = read_string(rest).ok_or(KeyParseError::Truncated("public key blob"))?;

    // private key section
    let (priv_section, _) =
        read_string(rest).ok_or(KeyParseError::Truncated("private key section"))?;

    // check ints
    let (check1, priv_rest) = read_u32(priv_section).ok_or(KeyParseError::Truncated("check1"))?;
    let (check2, priv_rest) = read_u32(priv_rest).ok_or(KeyParseError::Truncated("check2"))?;
    if check1 != check2 {
        return Err(KeyParseError::CheckMismatch);
    }

    // keytype
    let (keytype, priv_rest) = read_string(priv_rest).ok_or(KeyParseError::Truncated("keytype"))?;
    if keytype != KEY_TYPE {
        return Err(KeyParseError::PrivateType(
            String::from_utf8_lossy(keytype).into_owned(),
        ));
    }

    // ed25519 public key (32 bytes) — skip, we use the seed
    let (pubkey, priv_rest) =
        read_string(priv_rest).ok_or(KeyParseError::Truncated("ed25519 pubkey"))?;
    if pubkey.len() != 32 {
        return Err(KeyParseError::EmbeddedPublicLength(pubkey.len()));
    }

    // ed25519 "private key" (64 bytes = seed‖pubkey)
    let (privkey, priv_rest) =
        read_string(priv_rest).ok_or(KeyParseError::Truncated("ed25519 privkey"))?;
    if privkey.len() != 64 {
        return Err(KeyParseError::PrivateKeyLength(privkey.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(
        privkey
            .get(..32)
            .ok_or(KeyParseError::Truncated("ed25519 seed"))?,
    );

    // comment
    let (comment_bytes, _) = read_string(priv_rest).ok_or(KeyParseError::Truncated("comment"))?;
    let comment = String::from_utf8_lossy(comment_bytes).into_owned();

    Ok((seed, comment))
}

// ─── Wire-format primitives ──────────────────────────────────────────────────

/// Read a 4-byte big-endian u32 from the front of `data`.
fn read_u32(data: &[u8]) -> Option<(u32, &[u8])> {
    let (bytes, rest) = data.split_at_checked(4)?;
    let val = u32::from_be_bytes(bytes.try_into().ok()?);
    Some((val, rest))
}

/// Read a length-prefixed SSH string (u32 length + bytes) from the front of `data`.
fn read_string(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = read_u32(data)?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Detect whether a key file contains an OpenSSH public key (`ssh-ed25519 ...`).
#[must_use]
pub fn is_openssh_public(text: &str) -> bool {
    text.trim_start().starts_with("ssh-ed25519 ")
}

/// Detect whether a key file contains an OpenSSH private key (PEM envelope).
#[must_use]
pub fn is_openssh_private(text: &str) -> bool {
    text.trim_start().starts_with(PEM_BEGIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_in_the_wrong_order_are_an_error_not_a_panic() {
        let pem = format!("{PEM_END}\nAAAA\n{PEM_BEGIN}\n");
        let err = parse_private_key(&pem).expect_err("refused");
        assert_eq!(err, KeyParseError::NotPem("END marker before BEGIN marker"));
        assert_eq!(
            err.to_string(),
            "not an OpenSSH private key (END marker before BEGIN marker)"
        );
    }

    #[test]
    fn round_trip_pubkey_blob() {
        // Construct a valid SSH wire-format blob for a known 32-byte key.
        let pubkey = [42u8; 32];
        let mut blob = Vec::new();
        // key type string
        blob.extend_from_slice(
            &u32::try_from(KEY_TYPE.len())
                .expect("KEY_TYPE len fits u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(KEY_TYPE);
        // public key
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&pubkey);

        let parsed = parse_pubkey_blob(&blob).expect("valid blob");
        assert_eq!(parsed, pubkey);
    }

    #[test]
    fn parse_public_key_with_comment() {
        let pubkey = [7u8; 32];
        let mut blob = Vec::new();
        blob.extend_from_slice(
            &u32::try_from(KEY_TYPE.len())
                .expect("KEY_TYPE len fits u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(KEY_TYPE);
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&pubkey);

        let b64_blob = b64::encode(&blob);
        let line = format!("ssh-ed25519 {b64_blob} my-key-id@kennel");

        let (parsed_key, comment) = parse_public_key(&line).expect("valid public key");
        assert_eq!(parsed_key, pubkey);
        assert_eq!(comment, "my-key-id@kennel");
    }

    #[test]
    fn parse_public_key_without_comment() {
        let pubkey = [1u8; 32];
        let mut blob = Vec::new();
        blob.extend_from_slice(
            &u32::try_from(KEY_TYPE.len())
                .expect("KEY_TYPE len fits u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(KEY_TYPE);
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&pubkey);

        let b64_blob = b64::encode(&blob);
        let line = format!("ssh-ed25519 {b64_blob}");

        let (parsed_key, comment) = parse_public_key(&line).expect("valid public key");
        assert_eq!(parsed_key, pubkey);
        assert_eq!(comment, "");
    }

    #[test]
    fn rejects_wrong_key_type() {
        let err = parse_public_key("ssh-rsa AAAA== comment").expect_err("must fail");
        assert_eq!(err, KeyParseError::UnsupportedType("ssh-rsa".to_owned()));
        assert_eq!(
            err.to_string(),
            "unsupported key type `ssh-rsa` (only ssh-ed25519 is supported)"
        );
        assert_eq!(
            parse_public_key("ssh-ed25519").expect_err("no blob"),
            KeyParseError::MissingBlob
        );
        assert_eq!(
            parse_public_key("ssh-ed25519 !!!").expect_err("not base64"),
            KeyParseError::PublicBase64
        );
        assert_eq!(
            KeyParseError::Truncated("comment").to_string(),
            "truncated comment"
        );
    }

    #[test]
    fn detects_openssh_format() {
        assert!(is_openssh_public("ssh-ed25519 AAAA== comment"));
        assert!(!is_openssh_public("AAAA=="));
        assert!(is_openssh_private(
            "-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----"
        ));
        assert!(!is_openssh_private("AAAA=="));
    }
}
