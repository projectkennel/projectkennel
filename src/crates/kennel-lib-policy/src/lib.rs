//! Project Kennel policy crate.
//!
//! # Purpose
//!
//! This crate owns the **settled policy** — the flat, signed, runtime artefact a
//! kennel is spawned from — and its trust surface.
//!
//! That trust surface is the canonical-form serialisation, Ed25519 signature
//! verification against a trust store, and framework-invariant re-assertion.
//! [`verify_settled`] is the single entry point `kennel-lib-spawn` calls on the
//! hot path: one signature check, a schema version gate, and an invariant
//! re-assertion.
//!
//! The crate is pure and I/O-free (`docs/architecture/03-crate-decomposition.md`):
//! callers read bytes from disk and pass them in; key material is supplied to a
//! [`KeySet`] in memory.
//!
//! # Scope of this crate
//!
//! This is the **runtime** half only: parse a settled artefact, verify its
//! signature against a trust store, re-assert the framework invariants, and hand
//! the [`SettledPolicy`] to the spawn. It also owns [`sign_settled`]/[`to_bytes`]
//! (the settled-artefact crypto/serialisation, symmetric with verification) and
//! [`parse_audit_defaults`] (the `audit.toml` reader `kenneld` needs at runtime).
//!
//! The **compiler** — the `source` schema, template `resolve`ution, `leaf` deltas,
//! `translate`ion, source signing, the `lock`file, `lint`/`risks` — lives in the
//! separate `kennel-lib-compile` crate, which depends on this one and is linked
//! only by the CLI. Splitting it keeps the compiler (and its heavier parsing) out
//! of the daemon's TCB (CODING-STANDARDS.md §3/§5).

#![forbid(unsafe_code)]

pub mod audit;
pub mod b64;
pub mod canonical;
pub mod error;
pub mod invariant;
pub mod keys;
pub mod libresolve;
pub mod patch;
pub mod settled;
pub mod signature;
pub mod spawn;
pub mod variant;

pub use audit::parse_audit_defaults;
pub use error::PolicyError;
pub use invariant::{validate, InvariantViolation};
pub use keys::{KeySet, SigningKey};
pub use settled::{
    AuditFileConfig, AuditRuntime, AuditSinkKind, BinderConsumeRuntime, BinderProvideRuntime,
    BinderRuntime, CapPolicy, ConsumeRuntime, DbusBusRuntime, DbusRuntime, DevPolicy,
    EffectivePolicy, EnvRuntime, ExecPolicy, FsPolicy, IdentityRuntime, LifecyclePolicy,
    MeshRuntime, NameRule, NetMode, NetPolicy, NetRule, OnChangeAction, ProcPolicy, ProcVisibility,
    Protocol, Provenance, ProvideRuntime, ProxyListen, ResolvedArtifact, SeccompAction,
    SeccompPolicy, SettledPolicy, Shape, SignedSettledPolicy, SpawnGrant, SpawnTemplate, SshGrant,
    SshRuntime, TmpPolicy, TrustPolicy, TtlAction, TtyPolicy, UlimitsRuntime, UnixRuntime,
    UnixSocket, WorkloadRuntime, RESERVED_PREFIX, ULIMIT_RESOURCES,
};
pub use signature::{verify_signature, SignatureEnvelope, SignatureError};
pub use spawn::spawn_eligible;

/// The newest `settled_schema_version` this build accepts.
pub const SETTLED_SCHEMA_VERSION: u32 = 1;

/// Verify a settled-policy document and return its body.
///
/// Parses `bytes`, checks the schema version, verifies the single signature over
/// the canonical form against `keys`, and re-asserts the framework invariants.
/// This is the runtime trust gate; on success the returned [`SettledPolicy`] is
/// safe to enforce.
///
/// # Errors
///
/// Returns a [`PolicyError`] if parsing fails, the schema version is too new, the
/// signature does not verify, or any framework invariant is violated.
pub fn verify_settled(bytes: &[u8], keys: &KeySet) -> Result<SettledPolicy, PolicyError> {
    let doc: SignedSettledPolicy =
        basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))?;
    verify_doc(doc, keys)
}

/// Verify a settled-policy document **and** confirm it is the exact artefact a `[spawn]` grant
/// pinned (the content-pin, §7.12.8).
///
/// `kenneld` calls this at `SPAWN` on a template it re-resolved from the *mutable* trust store: the
/// document's `[signature]` must carry the `expected_key_id`/`expected_signature` the spawner
/// recorded at its compile, **and** verify cryptographically against `keys`. A deterministic ed25519
/// signature over canonical content is the content commitment, so a re-signed-in-place template
/// resolves to a different signature and is caught here — fail-closed against a mutable trust store,
/// no `sha2`. The pin equality is checked first, so tampering reads as a clear pin mismatch rather
/// than a generic signature failure.
///
/// # Errors
///
/// [`PolicyError::Spawn`] on a pin mismatch; otherwise the same errors as [`verify_settled`]
/// (parse, schema version, signature, invariants).
pub fn verify_pinned(
    bytes: &[u8],
    keys: &KeySet,
    expected_key_id: &str,
    expected_signature: &str,
) -> Result<SettledPolicy, PolicyError> {
    let doc: SignedSettledPolicy =
        basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))?;
    if doc.signature.key_id != expected_key_id || doc.signature.signature != expected_signature {
        return Err(PolicyError::Spawn(
            "template content-pin mismatch — the trust store resolved a different signed artefact \
             than the spawner pinned (re-signed in place?); fail-closed (§7.12.8)"
                .to_owned(),
        ));
    }
    verify_doc(doc, keys)
}

/// The shared tail of [`verify_settled`] / [`verify_pinned`]: schema-version gate, signature
/// verification over the canonical body, and framework-invariant re-assertion.
fn verify_doc(doc: SignedSettledPolicy, keys: &KeySet) -> Result<SettledPolicy, PolicyError> {
    if doc.policy.settled_schema_version > SETTLED_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedSchemaVersion {
            found: doc.policy.settled_schema_version,
            max: SETTLED_SCHEMA_VERSION,
        });
    }
    let canonical = canonical::canonical_bytes(&doc.policy)?;
    verify_signature(&canonical, &doc.signature, keys)?;
    validate(&doc.policy).map_err(PolicyError::InvariantViolations)?;
    Ok(doc.policy)
}

/// Parse a settled artefact **without** verifying its signature or invariants.
///
/// For host-side tooling that needs to *read* a settled policy it already holds — e.g. the
/// CLI's pre-flight manifest generation reading `fs.write` — where the daemon, not the CLI,
/// is the trust boundary (it re-verifies the signature before honouring the policy). Do
/// **not** use this where the policy is untrusted input; use [`verify_settled`] there.
///
/// # Errors
/// [`PolicyError::Parse`] if the bytes are not a well-formed settled artefact, or
/// [`PolicyError::UnsupportedSchemaVersion`] if its schema is too new.
pub fn parse_settled_unverified(bytes: &[u8]) -> Result<SettledPolicy, PolicyError> {
    Ok(parse_signed_settled_unverified(bytes)?.policy)
}

/// Parse a settled artefact into its **full document** — the body and its `[signature]` envelope —
/// **without** verifying the signature.
///
/// For the spawn compiler, which records a target template's signature commitment (the content-pin)
/// at the spawner's compile: it needs the envelope's `key_id`/`signature`, not just the body. The
/// daemon re-verifies that commitment at `SPAWN` ([`verify_pinned`]); this is the authoring-side read.
///
/// # Errors
/// [`PolicyError::Parse`] if the bytes are not a well-formed settled artefact, or
/// [`PolicyError::UnsupportedSchemaVersion`] if its schema is too new.
pub fn parse_signed_settled_unverified(bytes: &[u8]) -> Result<SignedSettledPolicy, PolicyError> {
    let doc: SignedSettledPolicy =
        basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))?;
    if doc.policy.settled_schema_version > SETTLED_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedSchemaVersion {
            found: doc.policy.settled_schema_version,
            max: SETTLED_SCHEMA_VERSION,
        });
    }
    Ok(doc)
}

/// Resolve and fill the settled policy's dynamic-loader `EXECUTE` grant set.
///
/// Fills [`settled::ExecPolicy::loaders`] with each allowlisted dynamic binary's `PT_INTERP`
/// (`ld.so`), reading the binaries from disk ([`libresolve`]). Call this at compile time —
/// after the compiler's `compile` / `compile_leaf` and **before** signing — so the loader set is part
/// of the signed artefact and the runtime never re-resolves. Returns the resolver's
/// advisories (binaries it could not read). Idempotent. Libraries are deliberately *not*
/// resolved or granted: they load via `READ` and Landlock cannot gate their `mmap`
/// (`07-3-exec`).
pub fn resolve_settled_loaders(policy: &mut SettledPolicy) -> Vec<String> {
    let resolution = libresolve::resolve_loaders(&policy.effective_policy.exec.allow);
    policy.effective_policy.exec.loaders = resolution.loaders;
    resolution.warnings
}

/// Sign a settled policy, producing the on-disk document. Used by the compiler
/// (`kennel compile`) and tests; not part of the runtime path.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if the body cannot be serialised.
pub fn sign_settled(
    policy: &SettledPolicy,
    key: &SigningKey,
) -> Result<SignedSettledPolicy, PolicyError> {
    let canonical = canonical::canonical_bytes(policy)?;
    let sig = key.sign(&canonical);
    let envelope = SignatureEnvelope {
        algorithm: "ed25519".to_owned(),
        key_id: key.key_id().to_owned(),
        signature: b64::encode(&sig),
        signed_fields: Vec::new(),
    };
    Ok(SignedSettledPolicy {
        signature: envelope,
        policy: policy.clone(),
    })
}

/// Serialise a signed settled-policy document to its on-disk TOML bytes.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if serialisation fails.
pub fn to_bytes(doc: &SignedSettledPolicy) -> Result<Vec<u8>, PolicyError> {
    basic_toml::to_string(doc)
        .map(String::into_bytes)
        .map_err(|e| PolicyError::Canonical(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> SettledPolicy {
        settled::sample_settled()
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_seed("kennel-maint-2026-01", &[7u8; 32]).expect("seed")
    }

    fn keyset_for(key: &SigningKey) -> KeySet {
        let mut ks = KeySet::new();
        ks.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");
        ks
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let key = signing_key();
        let doc = sign_settled(&sample_policy(), &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(verified, sample_policy());
    }

    #[test]
    fn a_spawn_grant_round_trips_and_is_signature_bound() {
        let key = signing_key();
        let mut policy = sample_policy();
        policy.spawn = Some(settled::SpawnGrant {
            max_instances: 8,
            allow: vec![settled::SpawnTemplate {
                template: "net-fetch@v1".to_owned(),
                signing_key_id: "kennel-maint-2026".to_owned(),
                signature: "Zm9vYmFy".to_owned(),
                mutable_narrow: vec!["net.proxy.allow".to_owned()],
            }],
        });

        // The grant survives sign → serialise → verify (the `[spawn]`/`[[spawn.allow]]` tables
        // serialise before the trailing `manifest` array-of-tables — the canonical-form ordering).
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(verified.spawn, policy.spawn);

        // …and it is inside the signed canonical form (tampering breaks it).
        let canon =
            String::from_utf8(canonical::canonical_bytes(&policy).expect("canon")).expect("utf8");
        assert!(canon.contains("[spawn]") && canon.contains("[[spawn.allow]]"));
    }

    #[test]
    fn verify_pinned_accepts_the_committed_signature_and_rejects_a_mismatch() {
        let key = signing_key();
        let doc = sign_settled(&sample_policy(), &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let keys = keyset_for(&key);
        // The recorded pin = the artefact's own signature → verifies and returns the body.
        let ok = verify_pinned(
            &bytes,
            &keys,
            &doc.signature.key_id,
            &doc.signature.signature,
        );
        assert_eq!(ok.expect("pinned verify"), sample_policy());
        // A pin naming a different signature is a fail-closed mismatch (the re-signed-in-place case).
        let bad = verify_pinned(&bytes, &keys, &doc.signature.key_id, "AAAA");
        assert!(matches!(bad, Err(PolicyError::Spawn(_))));
    }

    #[test]
    fn by_name_allow_rules_round_trip_and_are_signature_bound() {
        let key = signing_key();
        let mut policy = sample_policy();
        policy.effective_policy.net.allow_names = vec![
            NameRule {
                name: "api.example.com".to_owned(),
                ports: vec![443],
                protocol: Protocol::Tcp,
            },
            NameRule {
                name: ".internal.example".to_owned(),
                ports: Vec::new(),
                protocol: Protocol::Any,
            },
        ];

        // The name rules survive a sign → serialise → verify round trip…
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(
            verified.effective_policy.net.allow_names,
            policy.effective_policy.net.allow_names
        );

        // …and they are inside the signed canonical form (tampering breaks it).
        let canon =
            String::from_utf8(canonical::canonical_bytes(&policy).expect("canon")).expect("utf8");
        assert!(
            canon.contains("api.example.com"),
            "name rule is in the canonical form"
        );

        let mut tampered = doc;
        if let Some(rule) = tampered.policy.effective_policy.net.allow_names.first_mut() {
            rule.name = "evil.example.com".to_owned();
        }
        let bytes = to_bytes(&tampered).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("tamper must fail");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn ulimits_round_trip_and_are_signature_bound() {
        let key = signing_key();
        let mut policy = sample_policy();
        policy
            .ulimits
            .limits
            .insert("nofile".to_owned(), "8192".to_owned());
        policy
            .ulimits
            .limits
            .insert("nproc".to_owned(), "256 512".to_owned());

        // The limits survive a sign → serialise → verify round trip…
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(verified.ulimits, policy.ulimits);

        // …and they are inside the signed canonical form (tampering breaks it).
        let canon =
            String::from_utf8(canonical::canonical_bytes(&policy).expect("canon")).expect("utf8");
        assert!(canon.contains("nofile"), "ulimit is in the canonical form");

        let mut tampered = doc;
        tampered
            .policy
            .ulimits
            .limits
            .insert("nofile".to_owned(), "999999".to_owned());
        let bytes = to_bytes(&tampered).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("tamper must fail");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn fs_tmp_dev_and_proc_hidepid_round_trip_and_are_signature_bound() {
        let key = signing_key();
        let mut policy = sample_policy();
        policy.effective_policy.fs.tmp = TmpPolicy {
            private: true,
            size_mib: 256,
            mode: "0750".to_owned(),
        };
        policy.effective_policy.fs.dev = DevPolicy {
            allow: vec![
                "/dev/null".to_owned(),
                "/dev/zero".to_owned(),
                "/dev/tty".to_owned(),
            ],
        };
        policy.effective_policy.proc.hidepid = true;

        // The new filesystem knobs survive a sign -> serialise -> verify round trip.
        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(
            verified.effective_policy.fs.tmp,
            policy.effective_policy.fs.tmp
        );
        assert_eq!(
            verified.effective_policy.fs.dev,
            policy.effective_policy.fs.dev
        );
        assert!(verified.effective_policy.proc.hidepid);

        // They are inside the signed canonical form: tampering with the device
        // allowlist (e.g. smuggling in /dev/mem) breaks the signature.
        let canon =
            String::from_utf8(canonical::canonical_bytes(&policy).expect("canon")).expect("utf8");
        assert!(
            canon.contains("size_mib") && canon.contains("/dev/tty"),
            "new fields are in the canonical form"
        );

        let mut tampered = doc;
        tampered
            .policy
            .effective_policy
            .fs
            .dev
            .allow
            .push("/dev/mem".to_owned());
        let bytes = to_bytes(&tampered).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("tamper must fail");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn proxy_listen_round_trips_and_is_signature_bound() {
        let key = signing_key();
        let mut policy = sample_policy();
        policy.effective_policy.net.proxy = ProxyListen {
            offset: 3,
            port: 8443,
        };

        let doc = sign_settled(&policy, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let verified = verify_settled(&bytes, &keyset_for(&key)).expect("verify");
        assert_eq!(
            verified.effective_policy.net.proxy,
            ProxyListen {
                offset: 3,
                port: 8443
            }
        );

        // Tampering with the resolved offset/port breaks the signature.
        let mut tampered = doc;
        tampered.policy.effective_policy.net.proxy.port = 1080;
        let bytes = to_bytes(&tampered).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("tamper must fail");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn an_empty_allow_names_is_omitted_from_the_canonical_form() {
        // The skip-if-empty keeps a name-free policy's bytes identical to before
        // the field existed, so existing signatures stay valid.
        let canon = String::from_utf8(canonical::canonical_bytes(&sample_policy()).expect("canon"))
            .expect("utf8");
        assert!(
            !canon.contains("allow_names"),
            "empty allow_names must not serialise"
        );
    }

    #[test]
    fn canonical_form_is_signature_excluded_and_stable() {
        // The canonical bytes are derived from the body only; re-deriving them on
        // the verify side must reproduce exactly what was signed.
        let p = sample_policy();
        let a = canonical::canonical_bytes(&p).expect("canon a");
        let b = canonical::canonical_bytes(&p).expect("canon b");
        assert_eq!(a, b, "canonical form must be deterministic");
        let text = String::from_utf8(a).expect("utf8");
        assert!(
            !text.contains("[signature]"),
            "signature must not be in the canonical form"
        );
    }

    #[test]
    fn tampered_body_fails_verification() {
        let key = signing_key();
        let mut doc = sign_settled(&sample_policy(), &key).expect("sign");
        // Flip an enforced value the attacker would want changed.
        doc.policy.effective_policy.net.mode = NetMode::Host;
        let bytes = to_bytes(&doc).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("must reject");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let key = signing_key();
        let doc = sign_settled(&sample_policy(), &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let empty = KeySet::new();
        let err = verify_settled(&bytes, &empty).expect_err("must reject");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::UnknownKey(_))),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = signing_key();
        let doc = sign_settled(&sample_policy(), &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        // A different keypair registered under the same key_id.
        let imposter = SigningKey::from_seed("kennel-maint-2026-01", &[9u8; 32]).expect("seed");
        let err = verify_settled(&bytes, &keyset_for(&imposter)).expect_err("must reject");
        assert!(
            matches!(err, PolicyError::Signature(SignatureError::Verification)),
            "got {err:?}"
        );
    }

    #[test]
    fn invariant_violation_is_rejected() {
        let key = signing_key();
        let mut p = sample_policy();
        p.effective_policy.cap.no_new_privs = false; // weaken an invariant
        let doc = sign_settled(&p, &key).expect("sign"); // validly signed but unsafe
        let bytes = to_bytes(&doc).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("must reject");
        assert!(
            matches!(&err, PolicyError::InvariantViolations(vs) if vs.iter().any(|v| v.id == "cap.no_new_privs")),
            "expected a cap.no_new_privs invariant violation, got {err:?}"
        );
    }

    #[test]
    fn newer_schema_version_is_rejected() {
        let key = signing_key();
        let mut p = sample_policy();
        p.settled_schema_version = SETTLED_SCHEMA_VERSION + 1;
        let doc = sign_settled(&p, &key).expect("sign");
        let bytes = to_bytes(&doc).expect("serialise");
        let err = verify_settled(&bytes, &keyset_for(&key)).expect_err("must reject");
        assert!(
            matches!(err, PolicyError::UnsupportedSchemaVersion { .. }),
            "got {err:?}"
        );
    }
}
