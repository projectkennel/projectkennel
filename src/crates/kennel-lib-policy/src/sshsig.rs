//! SSHSIG: the OpenSSH detached-signature format (`PROTOCOL.sshsig`).
//!
//! A kennel signature is an SSHSIG produced by `ssh-keygen -Y sign` and verified
//! here, in-process, for Ed25519 keys. The format is recognizable: a skeptic can run
//! `ssh-keygen -Y verify` against the same artefact and it passes, so the ceremony we
//! point at is OpenSSH's, not our own.
//!
//! What an SSHSIG signs is not the message but a domain-separated preimage over its
//! hash:
//!
//! ```text
//! "SSHSIG" ‖ string namespace ‖ string reserved ‖ string hash_alg ‖ string H(message)
//! ```
//!
//! The `namespace` ([`NAMESPACE`]) is the domain separation: a signature minted for
//! SSH authentication or git commits carries a different namespace and cannot be
//! replayed as a kennel-policy signature, even with the same key.
//!
//! Hardware (`sk-`) keys are detected structurally and rejected here — their
//! signatures are non-deterministic (an authenticator counter rides inside the blob),
//! so they cannot be reconstructed in-process and must be verified out-of-process,
//! off the hot path.

use ed25519_compact::{PublicKey, Signature};

use crate::keys::SigningKey;
use crate::signature::SignatureError;

/// The SSHSIG namespace binding a signature to kennel-policy use.
pub const NAMESPACE: &str = "policy.v1@projectkennel.org";

/// The 6-byte SSHSIG magic preamble (not length-prefixed).
const MAGIC: &[u8] = b"SSHSIG";

/// The only SSHSIG structure version this build understands.
const SIG_VERSION: u32 = 1;

/// The SSH key-type name for a software Ed25519 key.
const ED25519: &[u8] = b"ssh-ed25519";

/// The SSH key-type name for a FIDO/hardware Ed25519 key.
const SK_ED25519: &[u8] = b"sk-ssh-ed25519@openssh.com";

/// The hash algorithm `ssh-keygen` uses for an Ed25519 SSHSIG.
const HASH_ALG_SHA512: &[u8] = b"sha512";

/// The PEM armor lines wrapping the base64 SSHSIG blob.
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

/// An upper bound on a de-armored SSHSIG blob, so a malformed armor cannot make us
/// allocate without limit. A real Ed25519 SSHSIG is a few hundred bytes.
const MAX_BLOB: usize = 16 * 1024;

/// The signer's key kind, branched structurally before any cryptography.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A software Ed25519 key — verified in-process.
    Ed25519,
    /// A FIDO/hardware Ed25519 key — verified out-of-process (off the hot path).
    HardwareSk,
}

/// A parsed SSHSIG: the fields recovered from the armored blob, structurally
/// validated but not yet cryptographically verified.
pub struct SshSig {
    /// The signer key kind.
    pub key_kind: KeyKind,
    /// The 32-byte Ed25519 public key embedded in the signature (a *claim* — the
    /// trust store, not this, is the authority on what is trusted).
    pub pubkey: [u8; 32],
    /// The signature's declared namespace.
    pub namespace: String,
    /// The opaque `reserved` field bytes (echoed verbatim into the preimage).
    reserved: Vec<u8>,
    /// The declared hash algorithm name.
    hash_alg: Vec<u8>,
    /// The raw 64-byte Ed25519 signature (present only for [`KeyKind::Ed25519`]).
    ed25519_sig: Option<[u8; 64]>,
}

impl SshSig {
    /// Parse an armored SSHSIG (`-----BEGIN SSH SIGNATURE-----` … `END`).
    ///
    /// Structurally validates the blob and extracts the embedded key, namespace, and
    /// (for Ed25519) the raw signature. Does **not** verify; call [`Self::verify`].
    ///
    /// # Errors
    ///
    /// [`SignatureError::MalformedSshsig`] if the armor or binary structure is
    /// malformed or carries an unknown key/structure version.
    pub fn parse_armored(armor: &str) -> Result<Self, SignatureError> {
        let blob = dearmor(armor)?;
        let mut r = Reader::new(&blob);

        let magic = r.take(MAGIC.len()).ok_or_else(|| bad("truncated magic"))?;
        if magic != MAGIC {
            return Err(bad("not an SSHSIG (bad magic)"));
        }
        let version = r.u32().ok_or_else(|| bad("truncated version"))?;
        if version != SIG_VERSION {
            return Err(SignatureError::MalformedSshsig(format!(
                "unsupported SSHSIG version {version}"
            )));
        }

        let publickey = r.string().ok_or_else(|| bad("truncated public key"))?;
        let namespace = r.string().ok_or_else(|| bad("truncated namespace"))?;
        let reserved = r.string().ok_or_else(|| bad("truncated reserved"))?;
        let hash_alg = r.string().ok_or_else(|| bad("truncated hash algorithm"))?;
        let sig_blob = r.string().ok_or_else(|| bad("truncated signature"))?;
        if !r.is_empty() {
            return Err(bad("trailing bytes after SSHSIG signature"));
        }

        let (key_kind, pubkey) = parse_public_key(publickey)?;
        let ed25519_sig = match key_kind {
            KeyKind::Ed25519 => Some(parse_ed25519_sig(sig_blob)?),
            KeyKind::HardwareSk => None,
        };

        Ok(Self {
            key_kind,
            pubkey,
            namespace: String::from_utf8_lossy(namespace).into_owned(),
            reserved: reserved.to_vec(),
            hash_alg: hash_alg.to_vec(),
            ed25519_sig,
        })
    }

    /// Verify this signature over `message` against `trusted` (the public key the
    /// trust store holds for this signer).
    ///
    /// Enforces, in order: the kennel-policy namespace; that the embedded key equals
    /// the trusted key; the SHA-512 hash algorithm; then the Ed25519 check over the
    /// reconstructed SSHSIG preimage. A hardware (`sk-`) signer is refused here with
    /// [`SignatureError::HardwareKeyRequiresExternalVerify`] — the caller breaks out.
    ///
    /// # Errors
    ///
    /// A [`SignatureError`] for any failed check.
    pub fn verify(&self, message: &[u8], trusted: &PublicKey) -> Result<(), SignatureError> {
        if self.namespace != NAMESPACE {
            return Err(SignatureError::NamespaceMismatch(self.namespace.clone()));
        }
        // The store is the authority: the embedded key is only a claim and must match
        // the key trusted under this key_id.
        if self.pubkey != **trusted {
            return Err(SignatureError::KeyMismatch);
        }
        let sig = match self.key_kind {
            KeyKind::Ed25519 => self.ed25519_sig.ok_or(SignatureError::MalformedSignature)?,
            KeyKind::HardwareSk => return Err(SignatureError::HardwareKeyRequiresExternalVerify),
        };
        if self.hash_alg != HASH_ALG_SHA512 {
            return Err(SignatureError::MalformedSshsig(format!(
                "unexpected hash algorithm `{}`",
                String::from_utf8_lossy(&self.hash_alg)
            )));
        }
        let digest = hmac_sha512::Hash::hash(message);
        let preimage = self.preimage(&digest);
        let signature = Signature::new(sig);
        trusted
            .verify(&preimage, &signature)
            .map_err(|_| SignatureError::Verification)
    }

    /// Rebuild the exact bytes the signature covers: the magic preamble, then the
    /// namespace, reserved, hash-algorithm, and message-hash, each length-prefixed.
    fn preimage(&self, digest: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC
                .len()
                .saturating_add(self.reserved.len())
                .saturating_add(digest.len())
                .saturating_add(32),
        );
        out.extend_from_slice(MAGIC);
        put_string(&mut out, self.namespace.as_bytes());
        put_string(&mut out, &self.reserved);
        put_string(&mut out, &self.hash_alg);
        put_string(&mut out, digest);
        out
    }
}

/// Produce an armored Ed25519 SSHSIG over `message`, signing in-process with `key`.
///
/// Used by the library's signing helpers (and tests/fixtures); the operator-facing CLI
/// signs via `ssh-keygen -Y sign` instead, so agent and hardware keys are transparent.
/// The output is byte-identical to what `ssh-keygen` would emit for the same key and
/// message, and verifies under both `ssh-keygen -Y verify` and [`SshSig::verify`].
#[must_use]
pub fn sign_ed25519(key: &SigningKey, message: &[u8]) -> String {
    let digest = hmac_sha512::Hash::hash(message);

    // The preimage the signature covers (no version field — that is blob-only).
    let mut preimage = Vec::new();
    preimage.extend_from_slice(MAGIC);
    put_string(&mut preimage, NAMESPACE.as_bytes());
    put_string(&mut preimage, b""); // reserved
    put_string(&mut preimage, HASH_ALG_SHA512);
    put_string(&mut preimage, &digest);
    let sig = key.sign(&preimage);

    // The wrapped public-key and signature sub-blobs.
    let pubkey = key.public_key_bytes();
    let mut pub_blob = Vec::new();
    put_string(&mut pub_blob, ED25519);
    put_string(&mut pub_blob, &pubkey);
    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, ED25519);
    put_string(&mut sig_blob, &sig);

    // The outer SSHSIG blob.
    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&SIG_VERSION.to_be_bytes());
    put_string(&mut blob, &pub_blob);
    put_string(&mut blob, NAMESPACE.as_bytes());
    put_string(&mut blob, b""); // reserved
    put_string(&mut blob, HASH_ALG_SHA512);
    put_string(&mut blob, &sig_blob);

    armor(&blob)
}

/// Wrap a binary SSHSIG blob in the PEM armor, base64 at 70 columns (the OpenSSH
/// convention; whitespace is insignificant to any verifier).
fn armor(blob: &[u8]) -> String {
    let b64 = crate::b64::encode(blob);
    let mut out = String::with_capacity(
        b64.len()
            .saturating_add(ARMOR_BEGIN.len())
            .saturating_add(ARMOR_END.len())
            .saturating_add(16),
    );
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out
}

/// Strip the PEM armor and base64-decode the inner SSHSIG blob.
fn dearmor(armor: &str) -> Result<Vec<u8>, SignatureError> {
    let start = armor
        .find(ARMOR_BEGIN)
        .ok_or_else(|| bad("missing BEGIN SSH SIGNATURE"))?
        .checked_add(ARMOR_BEGIN.len())
        .ok_or_else(|| bad("armor overflow"))?;
    let rest = armor.get(start..).ok_or_else(|| bad("armor truncated"))?;
    let end = rest
        .find(ARMOR_END)
        .ok_or_else(|| bad("missing END SSH SIGNATURE"))?;
    let body: String = rest
        .get(..end)
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let blob = crate::b64::decode(body.as_bytes()).ok_or_else(|| bad("invalid base64 in armor"))?;
    if blob.is_empty() || blob.len() > MAX_BLOB {
        return Err(bad("implausible SSHSIG blob length"));
    }
    Ok(blob)
}

/// Parse an SSH public-key blob: `string keytype` then the key body. Recognizes
/// `ssh-ed25519` (32-byte key) and `sk-ssh-ed25519@openssh.com` (key + application).
fn parse_public_key(blob: &[u8]) -> Result<(KeyKind, [u8; 32]), SignatureError> {
    let mut r = Reader::new(blob);
    let keytype = r.string().ok_or_else(|| bad("truncated key type"))?;
    if keytype == ED25519 {
        let pk = r.string().ok_or_else(|| bad("truncated Ed25519 key"))?;
        let pubkey = <[u8; 32]>::try_from(pk).map_err(|_| bad("Ed25519 key is not 32 bytes"))?;
        Ok((KeyKind::Ed25519, pubkey))
    } else if keytype == SK_ED25519 {
        let pk = r.string().ok_or_else(|| bad("truncated sk-Ed25519 key"))?;
        let pubkey = <[u8; 32]>::try_from(pk).map_err(|_| bad("sk-Ed25519 key is not 32 bytes"))?;
        Ok((KeyKind::HardwareSk, pubkey))
    } else {
        Err(SignatureError::MalformedSshsig(format!(
            "unsupported key type `{}`",
            String::from_utf8_lossy(keytype)
        )))
    }
}

/// Parse an Ed25519 signature blob: `string sigtype` (`ssh-ed25519`) then the raw
/// 64-byte signature.
fn parse_ed25519_sig(blob: &[u8]) -> Result<[u8; 64], SignatureError> {
    let mut r = Reader::new(blob);
    let sigtype = r.string().ok_or_else(|| bad("truncated signature type"))?;
    if sigtype != ED25519 {
        return Err(SignatureError::MalformedSshsig(format!(
            "signature type `{}` is not ssh-ed25519",
            String::from_utf8_lossy(sigtype)
        )));
    }
    let sig = r.string().ok_or_else(|| bad("truncated signature body"))?;
    <[u8; 64]>::try_from(sig).map_err(|_| bad("Ed25519 signature is not 64 bytes"))
}

/// Build a [`SignatureError::MalformedSshsig`] from a static reason.
fn bad(reason: &str) -> SignatureError {
    SignatureError::MalformedSshsig(reason.to_owned())
}

/// Append an SSH `string` (big-endian `u32` length, then bytes) to `out`.
fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    // SSHSIG fields here are bounded (namespace, a 6-byte alg name, a 64-byte hash),
    // so the length always fits a u32; clamp defensively rather than panic.
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

/// A bounds-checked cursor over SSH wire bytes: every read returns `None` rather than
/// panicking on a short buffer (`parse-dont-validate`).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let slice = self.take(4)?;
        Some(u32::from_be_bytes(slice.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}
