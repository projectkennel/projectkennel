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
pub fn parse_public_key(line: &str) -> Result<([u8; 32], String), String> {
    let line = line.trim();
    let mut parts = line.splitn(3, char::is_whitespace);
    let key_type = parts.next().ok_or("empty public key")?;
    if key_type != "ssh-ed25519" {
        return Err(format!(
            "unsupported key type `{key_type}` (only ssh-ed25519 is supported)"
        ));
    }
    let blob_b64 = parts.next().ok_or("missing base64 blob in public key")?;
    let comment = parts.next().unwrap_or("").trim().to_owned();

    let blob = b64::decode(blob_b64.as_bytes()).ok_or("invalid base64 in public key")?;
    let pubkey = parse_pubkey_blob(&blob)?;
    Ok((pubkey, comment))
}

/// Extract the 32-byte Ed25519 public key from the SSH wire-format blob.
fn parse_pubkey_blob(blob: &[u8]) -> Result<[u8; 32], String> {
    let (key_type, rest) = read_string(blob).ok_or("truncated key type in blob")?;
    if key_type != KEY_TYPE {
        return Err(format!(
            "unexpected key type in blob: expected ssh-ed25519, got {}",
            String::from_utf8_lossy(key_type)
        ));
    }
    let (pubkey, _) = read_string(rest).ok_or("truncated public key in blob")?;
    if pubkey.len() != 32 {
        return Err(format!(
            "ed25519 public key must be 32 bytes, got {}",
            pubkey.len()
        ));
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
pub fn parse_private_key(pem: &str) -> Result<([u8; 32], String), String> {
    // Extract the base64 payload between the PEM markers.
    let start = pem
        .find(PEM_BEGIN)
        .ok_or("not an OpenSSH private key (missing BEGIN marker)")?
        .saturating_add(PEM_BEGIN.len());
    let end = pem
        .find(PEM_END)
        .ok_or("not an OpenSSH private key (missing END marker)")?;
    let b64_body: String = pem[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let payload = b64::decode(b64_body.as_bytes()).ok_or("invalid base64 in private key PEM")?;

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
fn parse_private_payload(data: &[u8]) -> Result<([u8; 32], String), String> {
    if !data.starts_with(AUTH_MAGIC) {
        return Err("invalid OpenSSH private key (bad magic)".to_owned());
    }
    let rest = data.get(AUTH_MAGIC.len()..).unwrap_or_default();

    // ciphername
    let (cipher, rest) = read_string(rest).ok_or("truncated ciphername")?;
    if cipher != b"none" {
        return Err(
            "encrypted OpenSSH private key — decrypt it first with `ssh-keygen -p -f <key>`"
                .to_owned(),
        );
    }

    // kdfname
    let (kdf, rest) = read_string(rest).ok_or("truncated kdfname")?;
    if kdf != b"none" {
        return Err("unexpected kdf in unencrypted key".to_owned());
    }

    // kdfoptions (should be empty for "none")
    let (_kdfopts, rest) = read_string(rest).ok_or("truncated kdfoptions")?;

    // number of keys
    let (nkeys, rest) = read_u32(rest).ok_or("truncated key count")?;
    if nkeys != 1 {
        return Err(format!("expected 1 key, found {nkeys}"));
    }

    // public key blob (skip — we extract the key from the private section)
    let (_pubblob, rest) = read_string(rest).ok_or("truncated public key blob")?;

    // private key section
    let (priv_section, _) = read_string(rest).ok_or("truncated private key section")?;

    // check ints
    let (check1, priv_rest) = read_u32(priv_section).ok_or("truncated check1")?;
    let (check2, priv_rest) = read_u32(priv_rest).ok_or("truncated check2")?;
    if check1 != check2 {
        return Err("check integers do not match (corrupted or encrypted key)".to_owned());
    }

    // keytype
    let (keytype, priv_rest) = read_string(priv_rest).ok_or("truncated keytype")?;
    if keytype != KEY_TYPE {
        return Err(format!(
            "unsupported key type: {} (only ssh-ed25519 is supported)",
            String::from_utf8_lossy(keytype)
        ));
    }

    // ed25519 public key (32 bytes) — skip, we use the seed
    let (pubkey, priv_rest) = read_string(priv_rest).ok_or("truncated ed25519 pubkey")?;
    if pubkey.len() != 32 {
        return Err(format!(
            "ed25519 pubkey must be 32 bytes, got {}",
            pubkey.len()
        ));
    }

    // ed25519 "private key" (64 bytes = seed‖pubkey)
    let (privkey, priv_rest) = read_string(priv_rest).ok_or("truncated ed25519 privkey")?;
    if privkey.len() != 64 {
        return Err(format!(
            "ed25519 private key must be 64 bytes (seed‖pubkey), got {}",
            privkey.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(privkey.get(..32).ok_or("truncated ed25519 seed")?);

    // comment
    let (comment_bytes, _) = read_string(priv_rest).ok_or("truncated comment")?;
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
        assert!(err.contains("unsupported key type"), "got: {err}");
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
