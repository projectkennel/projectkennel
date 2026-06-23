//! The service catalogue's reserved-namespace gate (`07-13-service-catalog.md` §7.13.4/§7.13.5).
//!
//! The catalogue is a derived projection of the enabled providers' `[[provides]]`, and it is the
//! **authoritative reserved-namespace gate**: a reserved capability name is admitted only when an
//! *authorized* key signed the providing policy. This module is that gate — the runtime backstop the
//! compile-time check (W1, `kennel-lib-compile`) fails fast for. The catalogue's *membership*
//! projection (which providers are enabled) and the broker that resolves against it land with the
//! supervision and broker work; what is settled here is the load-bearing question "who may *provide*
//! a reserved name."
//!
//! **Two reserved tiers, one rule** — only an authorized key may *provide* a reserved name:
//! - the built-in `org.projectkennel.*` namespace (§7.13.5) is the project's, claimable only by a
//!   **vendor-provenance** key: a trusted key loaded from the vendor key dir (`/usr/lib/kennel/keys`),
//!   where the project maintainer key lives. It is **not host-redefinable**, so a host `[[reserved]]`
//!   entry that overlaps `org.projectkennel.` cannot grant it;
//! - a **host-declared** namespace (§7.13.5a, the root-owned `system.toml` `[[reserved]]` table) is
//!   claimable by exactly the key-ids that entry authorizes.
//!
//! An *unreserved* name (`doe.john.cache`) falls under neither and needs no authorization — any
//! trusted signing key, exactly like an ordinary run policy.

use std::collections::BTreeSet;

use kennel_lib_config::ReservedNamespace;
use kennel_lib_policy::settled::{ProvideRuntime, RESERVED_PREFIX};

/// Whether a settled policy signed by `signing_key_id` may **provide** the capability `name`.
///
/// `vendor_key_ids` is the set of trusted key-ids loaded from the vendor key dir — the authority for
/// the built-in `org.projectkennel.*` namespace; `reserved` is the host-declared `[[reserved]]` table.
/// The signing key is already known-trusted (the policy verified against the store before this gate);
/// the question here is the *additional* one of whether that particular key may speak for this name.
#[must_use]
pub fn provide_authorized(
    name: &str,
    signing_key_id: &str,
    vendor_key_ids: &BTreeSet<String>,
    reserved: &[ReservedNamespace],
) -> bool {
    // The built-in project namespace is checked FIRST and is **not host-redefinable**: a host
    // `[[reserved]]` entry overlapping `org.projectkennel.` cannot grant it (§7.13.5a). Only a
    // vendor-provenance key (the maintainer key in the vendor trust dir) may claim it.
    if name.starts_with(RESERVED_PREFIX) {
        return vendor_key_ids.contains(signing_key_id);
    }
    // Otherwise the longest-matching host-declared namespace governs (the most specific reservation
    // wins when prefixes nest); a name under none is unreserved and free to any trusted key.
    reserved
        .iter()
        .filter(|ns| name.starts_with(&ns.prefix))
        .max_by_key(|ns| ns.prefix.len())
        .is_none_or(|ns| ns.authorizes(signing_key_id))
}

/// The first `[[provides]]` name this policy is **not** authorized to claim, if any.
///
/// The runtime reserved-namespace refusal (§7.13.4: the catalogue is where a self-signed reserved
/// provide is finally refused, closing the provider-name-spoofing channel). `None` means every
/// provide is authorized for `signing_key_id`.
#[must_use]
pub fn first_unauthorized_provide<'a>(
    provides: &'a [ProvideRuntime],
    signing_key_id: &str,
    vendor_key_ids: &BTreeSet<String>,
    reserved: &[ReservedNamespace],
) -> Option<&'a str> {
    provides
        .iter()
        .map(|p| p.name.as_str())
        .find(|name| !provide_authorized(name, signing_key_id, vendor_key_ids, reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vendor(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    fn ns(prefix: &str, keys: &[&str]) -> ReservedNamespace {
        ReservedNamespace {
            prefix: prefix.to_owned(),
            keys: keys.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn unreserved_name_is_free_to_any_trusted_key() {
        // No built-in prefix, no host-declared namespace governs → any trusted signature.
        assert!(provide_authorized(
            "doe.john.cache",
            "alice-key",
            &vendor(&["kennel-maint-2026"]),
            &[]
        ));
    }

    #[test]
    fn builtin_namespace_admits_only_a_vendor_provenance_key() {
        let vendor = vendor(&["kennel-maint-2026"]);
        // The maintainer (vendor) key may claim org.projectkennel.*.
        assert!(provide_authorized(
            "org.projectkennel.wayland",
            "kennel-maint-2026",
            &vendor,
            &[]
        ));
        // An admin or user key — trusted enough to sign a run policy, but NOT vendor-provenance —
        // is refused. This is the provider-name-spoofing block.
        assert!(!provide_authorized(
            "org.projectkennel.wayland",
            "admin-key",
            &vendor,
            &[]
        ));
        assert!(!provide_authorized(
            "org.projectkennel.wayland",
            "alice-key",
            &vendor,
            &[]
        ));
    }

    #[test]
    fn builtin_namespace_is_not_host_redefinable() {
        // A malicious/over-eager host declares a [[reserved]] entry overlapping the project's own
        // namespace and authorises its own key. It must NOT be able to claim org.projectkennel.* —
        // the built-in check runs first and ignores the host entry (§7.13.5a).
        let host = [ns("org.projectkennel.", &["admin-key"])];
        assert!(!provide_authorized(
            "org.projectkennel.wayland",
            "admin-key",
            &vendor(&["kennel-maint-2026"]),
            &host
        ));
    }

    #[test]
    fn host_declared_namespace_admits_only_its_authorized_keys() {
        let host = [ns("com.acme.", &["acme-platform-2026"])];
        let v = vendor(&["kennel-maint-2026"]);
        // The authorised org key may claim its own namespace…
        assert!(provide_authorized(
            "com.acme.build-cache",
            "acme-platform-2026",
            &v,
            &host
        ));
        // …but neither a random user key nor even the project maintainer key may.
        assert!(!provide_authorized(
            "com.acme.build-cache",
            "alice-key",
            &v,
            &host
        ));
        assert!(!provide_authorized(
            "com.acme.build-cache",
            "kennel-maint-2026",
            &v,
            &host
        ));
    }

    #[test]
    fn an_undeclared_prefix_is_unreserved() {
        // com.acme.* is reserved, but org.example.* is declared by no one → unreserved, any key.
        let host = [ns("com.acme.", &["acme-platform-2026"])];
        assert!(provide_authorized(
            "org.example.thing",
            "alice-key",
            &vendor(&[]),
            &host
        ));
    }

    #[test]
    fn the_longest_matching_reservation_wins() {
        // A nested reservation: com.acme.* (any acme key) and a tighter com.acme.secret.* (locked to
        // a single key). The most specific prefix governs the name under it.
        let host = [
            ns("com.acme.", &["acme-platform-2026"]),
            ns("com.acme.secret.", &["acme-secrets-key"]),
        ];
        let v = vendor(&[]);
        // Under the tighter prefix, only the secrets key qualifies — the broad acme key does not.
        assert!(provide_authorized(
            "com.acme.secret.vault",
            "acme-secrets-key",
            &v,
            &host
        ));
        assert!(!provide_authorized(
            "com.acme.secret.vault",
            "acme-platform-2026",
            &v,
            &host
        ));
        // Outside the tighter prefix, the broad acme key still governs.
        assert!(provide_authorized(
            "com.acme.build-cache",
            "acme-platform-2026",
            &v,
            &host
        ));
    }

    #[test]
    fn first_unauthorized_provide_finds_the_offender_or_none() {
        let v = vendor(&["kennel-maint-2026"]);
        let provides = |names: &[&str]| -> Vec<ProvideRuntime> {
            names
                .iter()
                .map(|n| ProvideRuntime {
                    name: (*n).to_owned(),
                    shape: kennel_lib_policy::settled::Shape::AfUnix,
                    endpoint: "/run/x".to_owned(),
                    key: None,
                })
                .collect()
        };
        // A user-signed policy with an unreserved provide AND a stolen reserved one: the reserved
        // claim is the offender returned.
        let mixed = provides(&["doe.john.cache", "org.projectkennel.wayland"]);
        assert_eq!(
            first_unauthorized_provide(&mixed, "alice-key", &v, &[]),
            Some("org.projectkennel.wayland")
        );
        // The maintainer key claiming the same set is fully authorised.
        assert_eq!(
            first_unauthorized_provide(&mixed, "kennel-maint-2026", &v, &[]),
            None
        );
        // No provides at all is trivially authorised.
        assert_eq!(first_unauthorized_provide(&[], "alice-key", &v, &[]), None);
    }
}
