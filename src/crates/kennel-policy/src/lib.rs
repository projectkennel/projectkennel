//! Project Kennel policy crate.
//!
//! # Purpose
//!
//! This crate owns the **settled policy** — the flat, signed, runtime artefact a
//! kennel is spawned from — and its trust surface: the canonical-form
//! serialisation, Ed25519 signature verification against a trust store, and
//! framework-invariant re-assertion. [`verify_settled`] is the single entry
//! point `kennel-spawn` calls on the hot path: one signature check, a schema
//! version gate, and an invariant re-assertion.
//!
//! The crate is pure and I/O-free (`docs/architecture/03-crate-decomposition.md`):
//! callers read bytes from disk and pass them in; key material is supplied to a
//! [`KeySet`] in memory.
//!
//! # Scope of this build
//!
//! Both halves are implemented. The runtime verification core ([`verify_settled`])
//! is the spawn hot path. The compile-time front end is the rest: the [`source`]
//! schema and validation, template-chain [`resolve`](mod@crate::resolve)ution and
//! folding, [`leaf`] `+=`/`-=` deltas, [`translate`](mod@crate::translate)ion +
//! substitution to the settled form, ed25519 [`source_sig`]nature verification, the
//! [`lock`]file, and the [`compile`](mod@crate::compile)
//! orchestrator that ties them together. The CLI (`kennel compile`/`validate`/`sign`)
//! drives this crate.

#![forbid(unsafe_code)]

pub mod b64;
pub mod canonical;
pub mod compile;
pub mod dev;
pub mod error;
pub mod identity;
pub mod invariant;
pub mod keys;
pub mod leaf;
pub mod lock;
pub mod resolve;
pub mod settled;
pub mod signature;
pub mod source;
pub mod source_sig;
pub mod ssh;
pub mod translate;
pub mod unix;

pub use compile::{compile, compile_leaf, seal_unsigned, Compiled};
pub use error::PolicyError;
pub use invariant::{validate, InvariantViolation};
pub use keys::{KeySet, SigningKey};
pub use leaf::{parse as parse_leaf, LeafPolicy};
pub use lock::{LockEntry, Lockfile};
pub use resolve::{resolve, resolve_verified, ChainLink, ResolvedChain, TemplateSource};
pub use settled::{
    AuditFileConfig, AuditRuntime, AuditSinkKind, CapPolicy, DevPolicy, EffectivePolicy,
    ExecPolicy, FsPolicy, IdentityRuntime, InstallConstants, LifecyclePolicy, NameRule, NetMode,
    NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, Provenance, ProxyListen,
    ResolvedArtifact, SeccompAction, SeccompPolicy, SettledPolicy, SignedSettledPolicy, SshGrant,
    SshKnownHostPin, SshRuntime, TmpPolicy, TtlAction, UnixRuntime, UnixSocket,
};
pub use signature::{verify_signature, SignatureEnvelope, SignatureError};
pub use source::{parse as parse_source, SourcePolicy};
pub use source_sig::{
    sign_leaf, sign_source, verify_self, verify_source, Signable, SignatureMode, Trust,
};
pub use translate::{parse_audit_defaults, translate, Translated};

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
        SettledPolicy {
            settled_schema_version: 1,
            name: "ai-coding".to_owned(),
            deferred_substitutions: vec!["<ctx>".to_owned(), "<uid>".to_owned()],
            framework_invariants_asserted: vec!["cap.no_new_privs".to_owned()],
            effective_policy: EffectivePolicy {
                net: NetPolicy {
                    mode: NetMode::Constrained,
                    proxy: ProxyListen::default(),
                    allow: vec![NetRule {
                        cidr: "93.184.216.0".to_owned(),
                        prefix_len: 24,
                        port_min: 443,
                        port_max: 443,
                        protocol: Protocol::Tcp,
                    }],
                    allow_names: Vec::new(),
                    deny_invariant: vec![NetRule {
                        cidr: "169.254.169.254".to_owned(),
                        prefix_len: 32,
                        port_min: 0,
                        port_max: 65535,
                        protocol: Protocol::Any,
                    }],
                },
                fs: FsPolicy {
                    home_shadow: true,
                    shim_root: "/run/kennel/ai-coding".to_owned(),
                    read: vec!["/usr".to_owned()],
                    write: vec!["/run/kennel/ai-coding/home".to_owned()],
                    tmp: TmpPolicy {
                        private: true,
                        size_mib: 512,
                        mode: "0700".to_owned(),
                    },
                    dev: DevPolicy {
                        allow: vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()],
                    },
                },
                exec: ExecPolicy {
                    deny_setuid: true,
                    deny_setgid: true,
                    deny_setcap: true,
                    deny_writable: true,
                    allow: vec!["/usr/bin/python3".to_owned()],
                },
                proc: ProcPolicy {
                    visibility: ProcVisibility::SelfOnly,
                    hidepid: true,
                },
                cap: CapPolicy { no_new_privs: true },
                seccomp: SeccompPolicy {
                    deny_action: SeccompAction::Errno,
                    deny: vec!["bpf".to_owned()],
                },
                lifecycle: LifecyclePolicy {
                    ttl_seconds: Some(3600),
                    ttl_action: TtlAction::Stop,
                },
            },
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: 1,
                threat_catalogue_version: "0.1".to_owned(),
                leaf_policy_sha256: "00".to_owned(),
                invariant_set_sha256: "00".to_owned(),
                install_constants: InstallConstants {
                    tag: 42,
                    ula_gid: "fd00::".to_owned(),
                },
                resolved_artifacts: vec![ResolvedArtifact {
                    name: "base-confined".to_owned(),
                    version: "v3".to_owned(),
                    content_sha256: "ab".to_owned(),
                    signing_key_id: "kennel-maint-2026-01".to_owned(),
                }],
            },
            ssh: settled::SshRuntime::default(),
            unix: settled::UnixRuntime::default(),
            identity: settled::IdentityRuntime::default(),
            audit: settled::AuditRuntime::default(),
        }
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
        doc.policy.effective_policy.net.mode = NetMode::Open;
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
