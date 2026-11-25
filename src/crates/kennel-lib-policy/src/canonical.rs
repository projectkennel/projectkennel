// SPDX-License-Identifier: Apache-2.0

//! Canonical-form serialisation: the exact bytes a signature covers.
//!
//! The signature on a settled policy is computed over the canonical form of its
//! body (the [`SettledPolicy`], excluding the `[signature]` envelope, which is a
//! sibling table in the document). Because the signer and verifier both derive
//! the bytes the same way — a deterministic `kennel-lib-toml` serialisation of the
//! body struct in declaration order — they agree byte-for-byte.
//!
//! This pins the canonical form: a deterministic `kennel-lib-toml` serialisation of
//! the body in struct-field order. JSON's canonicalisation (sorted keys,
//! normalised numbers) buys nothing here — we control both ends, and the schema
//! has no floats (`02-2-config-schema.md` §Format).

use crate::error::PolicyError;
use crate::settled::SettledPolicy;

/// The canonical bytes for `policy` — the input to signing and verification.
///
/// The bytes must describe **exactly** the policy that will be honoured. The canonical form omits
/// a section it considers empty (a `[workload]` with no `argv`, a `[rootfs]` with no `path`, a
/// `[dbus]` with no bus), so a section that is empty by that test yet carries other fields would
/// be parsed and acted on without being covered by the signature. The body is therefore read back
/// from its own canonical form and must compare equal; signer and verifier both pass through here,
/// so such a policy can neither be signed nor loaded.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if the body cannot be serialised, or if it carries content
/// its canonical form leaves out.
pub fn canonical_bytes(policy: &SettledPolicy) -> Result<Vec<u8>, PolicyError> {
    let bytes = kennel_lib_toml::to_string(policy)
        .map(String::into_bytes)
        .map_err(|e| PolicyError::Canonical(e.to_string()))?;
    let covered: SettledPolicy = kennel_lib_toml::from_slice(&bytes)
        .map_err(|e| PolicyError::Canonical(format!("canonical form does not read back: {e}")))?;
    if &covered != policy {
        return Err(PolicyError::Canonical(format!(
            "the policy carries content its signature would not cover{}; a section is honoured \
             only when its defining field is set (`[workload].argv`, `[rootfs].path`, an enabled \
             `[dbus]` bus)",
            uncovered_sections(policy, &covered)
        )));
    }
    Ok(bytes)
}

/// Name the sections that differ between `policy` and what its canonical form `covered`, for the
/// error text. Empty when the difference is somewhere this list does not know about.
fn uncovered_sections(policy: &SettledPolicy, covered: &SettledPolicy) -> String {
    let mut names = Vec::new();
    if policy.workload != covered.workload {
        names.push("[workload]");
    }
    if policy.rootfs != covered.rootfs {
        names.push("[rootfs]");
    }
    if policy.dbus != covered.dbus {
        names.push("[dbus]");
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" (in {})", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_bytes;
    use crate::settled::sample_settled;

    /// The canonical form is what a signature covers. If these bytes change, every policy signed
    /// before the change stops verifying, so a change has to be a decision and not a side effect
    /// of touching the serialiser or the policy struct.
    ///
    /// The golden file is the canonical form of [`sample_settled`]. To accept a deliberate
    /// change, run this test once with `KENNEL_BLESS=1` and commit the file.
    #[test]
    fn the_canonical_form_of_the_sample_policy_is_the_committed_bytes() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/golden/sample-settled.canonical"
        );
        let bytes = canonical_bytes(&sample_settled()).expect("canonical form");
        if std::env::var_os("KENNEL_BLESS").is_some() {
            std::fs::write(path, &bytes).expect("write the golden file");
        }
        let golden = std::fs::read(path).expect("read the golden file (KENNEL_BLESS=1 writes it)");
        assert!(
            bytes == golden,
            "the canonical form of the sample policy changed; signatures made before this change \
             will not verify. If that is intended, re-run with KENNEL_BLESS=1 and commit {path}"
        );
    }
}
