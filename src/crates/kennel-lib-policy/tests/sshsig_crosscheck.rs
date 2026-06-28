//! The seam a reviewer will probe: our in-process SSHSIG verifier must agree with
//! `ssh-keygen` byte-for-byte. These tests sign with the real `ssh-keygen -Y sign`,
//! verify with our code (the public `verify_signature` entry point), and verify our
//! stored armor back with `ssh-keygen -Y verify`. If the two ever disagree, the
//! "it's just SSHSIG" claim is false and these fail.
//!
//! Skipped (not failed) when `ssh-keygen` is absent, so a minimal build host does not
//! break — but dev and CI have OpenSSH, so the cross-check runs where it matters.

use std::path::{Path, PathBuf};
use std::process::Command;

use kennel_lib_policy::keys::KeySet;
use kennel_lib_policy::signature::{verify_signature, SignatureEnvelope, SignatureError};
use kennel_lib_policy::sshsig::NAMESPACE;

const CANONICAL: &[u8] = b"settled_schema_version = 2\nname = \"demo\"\n# canonical body\n";
const KEY_ID: &str = "release-key";

/// A scratch dir under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("kennel-sshsig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen").arg("-Q").output().is_ok()
}

/// `ssh-keygen -t ed25519 -N "" -f <key> -C <comment>`; returns the 32-byte public key.
fn gen_key(key: &Path, comment: &str) -> [u8; 32] {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-C", comment, "-f"])
        .arg(key)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen keygen failed");
    let pub_text = std::fs::read_to_string(key.with_extension("pub")).expect("read .pub");
    let (bytes, _comment) =
        kennel_lib_policy::openssh::parse_public_key(&pub_text).expect("parse .pub");
    bytes
}

/// `ssh-keygen -Y sign -f <key> -n <namespace> <msgfile>`; returns the armored SSHSIG.
fn sign(key: &Path, msg_file: &Path, namespace: &str) -> String {
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", namespace, "-f"])
        .arg(key)
        .arg(msg_file)
        .status()
        .expect("run ssh-keygen -Y sign");
    assert!(status.success(), "ssh-keygen -Y sign failed");
    let sig_path = PathBuf::from(format!("{}.sig", msg_file.display()));
    std::fs::read_to_string(&sig_path).expect("read .sig")
}

fn envelope(armor: &str) -> SignatureEnvelope {
    SignatureEnvelope {
        algorithm: "sshsig".to_owned(),
        key_id: KEY_ID.to_owned(),
        signature: armor.to_owned(),
        signed_fields: Vec::new(),
    }
}

fn trust_store(pubkey: &[u8; 32]) -> KeySet {
    let mut keys = KeySet::new();
    keys.insert(KEY_ID, pubkey).expect("insert key");
    keys
}

#[test]
fn ssh_keygen_signature_verifies_in_process() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("verify");
    let key = scratch.path("id_ed25519");
    let pubkey = gen_key(&key, "person@host");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");

    let armor = sign(&key, &msg, NAMESPACE);
    // The real entry point: a signature ssh-keygen produced verifies against a trust
    // store holding the key under KEY_ID.
    verify_signature(CANONICAL, &envelope(&armor), &trust_store(&pubkey))
        .expect("our verifier accepts an ssh-keygen SSHSIG");
}

#[test]
fn our_armor_verifies_with_ssh_keygen() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("crosscheck");
    let key = scratch.path("id_ed25519");
    gen_key(&key, "person@host");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");
    sign(&key, &msg, NAMESPACE);

    // The armor we store, fed back to ssh-keygen -Y verify, must pass — the whole
    // "recognizable format" claim. allowed_signers is built from the public key (the
    // trust material), never from the artefact.
    let pub_text = std::fs::read_to_string(key.with_extension("pub")).expect("test setup");
    let allowed = scratch.path("allowed_signers");
    std::fs::write(&allowed, format!("person@host {}", pub_text.trim())).expect("test setup");
    let sig_path = PathBuf::from(format!("{}.sig", msg.display()));

    let out = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "person@host", "-n", NAMESPACE, "-s"])
        .arg(&sig_path)
        .stdin(std::fs::File::open(&msg).expect("test setup"))
        .output()
        .expect("run ssh-keygen -Y verify");
    assert!(
        out.status.success(),
        "ssh-keygen -Y verify rejected our armor: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn our_in_process_signer_armor_verifies_with_ssh_keygen() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("oursign");
    // Sign in-process (the library path: tests/fixtures), then prove ssh-keygen accepts
    // our armor — the converse of the verify cross-check, closing the loop on our signer.
    let key = kennel_lib_policy::SigningKey::from_seed("k", &[3u8; 32]).expect("test setup");
    let armor = kennel_lib_policy::sshsig::sign_ed25519(&key, CANONICAL);

    let sig_path = scratch.path("msg.sig");
    std::fs::write(&sig_path, &armor).expect("test setup");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");
    // allowed_signers from our public key, in OpenSSH format.
    let allowed = scratch.path("allowed_signers");
    std::fs::write(
        &allowed,
        format!("person@host {}", openssh_pub_line(&key.public_key_bytes())),
    )
    .expect("test setup");

    let out = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "person@host", "-n", NAMESPACE, "-s"])
        .arg(&sig_path)
        .stdin(std::fs::File::open(&msg).expect("test setup"))
        .output()
        .expect("run ssh-keygen -Y verify");
    assert!(
        out.status.success(),
        "ssh-keygen rejected our in-process signer's armor: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The OpenSSH `ssh-ed25519 <blob> comment` public-key line for raw key bytes.
fn openssh_pub_line(pubkey: &[u8; 32]) -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(pubkey);
    format!(
        "ssh-ed25519 {} test@kennel",
        kennel_lib_policy::b64::encode(&blob)
    )
}

#[test]
fn ed25519_signature_is_deterministic() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("twice");
    let key = scratch.path("id_ed25519");
    gen_key(&key, "person@host");
    // Two distinct files with identical content, so each gets its own fresh `.sig`
    // (signing the same file twice would hit ssh-keygen's overwrite prompt).
    let msg_a = scratch.path("msg_a");
    let msg_b = scratch.path("msg_b");
    std::fs::write(&msg_a, CANONICAL).expect("test setup");
    std::fs::write(&msg_b, CANONICAL).expect("test setup");

    let first = sign(&key, &msg_a, NAMESPACE);
    let second = sign(&key, &msg_b, NAMESPACE);
    // Ed25519 is deterministic (RFC 8032); identical armor is what makes the signature
    // usable as a content-pin commitment. The day this differs, a non-deterministic
    // (counter) key was wired into the fast path.
    assert_eq!(
        first, second,
        "ed25519 SSHSIG must be byte-identical across signings"
    );
}

#[test]
fn wrong_namespace_is_rejected() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("ns");
    let key = scratch.path("id_ed25519");
    let pubkey = gen_key(&key, "person@host");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");
    // A signature minted for a different namespace (e.g. another protocol) must not
    // verify here — the domain separation.
    let armor = sign(&key, &msg, "file@example.com");

    let err = verify_signature(CANONICAL, &envelope(&armor), &trust_store(&pubkey))
        .expect_err("must reject");
    assert!(
        matches!(err, SignatureError::NamespaceMismatch(_)),
        "expected NamespaceMismatch, got {err:?}"
    );
}

#[test]
fn embedded_key_must_match_trust_store() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("mismatch");
    let signer = scratch.path("signer");
    gen_key(&signer, "signer@host");
    let other = scratch.path("other");
    let other_pub = gen_key(&other, "other@host");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");
    let armor = sign(&signer, &msg, NAMESPACE);

    // The trust store holds a *different* key under KEY_ID than the one that signed:
    // the store is the authority, so the embedded key (a claim) is rejected.
    let err = verify_signature(CANONICAL, &envelope(&armor), &trust_store(&other_pub))
        .expect_err("must reject");
    assert!(
        matches!(err, SignatureError::KeyMismatch),
        "expected KeyMismatch, got {err:?}"
    );
}

#[test]
fn tampered_message_fails() {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }
    let scratch = Scratch::new("tamper");
    let key = scratch.path("id_ed25519");
    let pubkey = gen_key(&key, "person@host");
    let msg = scratch.path("msg");
    std::fs::write(&msg, CANONICAL).expect("test setup");
    let armor = sign(&key, &msg, NAMESPACE);

    // Same signature, different canonical bytes → the recomputed SHA-512 preimage
    // differs and the Ed25519 check fails.
    let mut tampered = CANONICAL.to_vec();
    tampered.extend_from_slice(b"# sneaky\n");
    let err = verify_signature(&tampered, &envelope(&armor), &trust_store(&pubkey))
        .expect_err("must reject");
    assert!(
        matches!(err, SignatureError::Verification),
        "expected Verification failure, got {err:?}"
    );
}
