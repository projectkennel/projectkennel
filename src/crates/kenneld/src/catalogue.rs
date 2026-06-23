//! The service catalogue: a derived projection of the enabled providers' `[[provides]]`
//! (`07-13-service-catalog.md` §7.13.4), and the **authoritative reserved-namespace gate** (§7.13.5).
//!
//! The catalogue is a projection, never authored state: [`Catalogue::project`] reads the
//! `[[provides]]` of the enabled providers and resolves a capability `name` to a single provider
//! ([`Catalogue::resolve`]), carrying the [`Readiness`] state every reader sees (§7.13.7). It is also
//! the **authoritative gate**: a reserved name is admitted only when an *authorized* key signed the
//! providing policy ([`provide_authorized`]) — the runtime backstop the compile-time check (W1) fails
//! fast for, closing the provider-name-spoofing channel. The broker that resolves against the
//! catalogue (W5) and the supervisor that drives readiness (W6) build on this; its *membership* is the
//! operator's enabled set (§7.13.6).
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

use std::collections::{BTreeMap, BTreeSet};

use kennel_lib_config::ReservedNamespace;
use kennel_lib_control::readiness::Readiness;
use kennel_lib_policy::settled::{ProvideRuntime, Shape, RESERVED_PREFIX};

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

/// The operator's enablement posture for a provider (§7.13.6): which directory links it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enablement {
    /// `autorun/` — eager: started at daemon start, supervised for the daemon's life.
    Autorun,
    /// `ondemand/` — lazy: resolvable from enablement, socket-activated on first consume.
    Ondemand,
}

/// One enabled provider feeding the catalogue: its identity, who signed it, its posture, and what it
/// offers. The membership the enablement scan produces from the enabled set (§7.13.6).
#[derive(Debug, Clone)]
pub struct EnabledProvider {
    /// The provider's identifier — the enablement link name, i.e. the kennel the broker (W5)
    /// resolves to and socket-activates.
    pub provider: String,
    /// The key that signed the provider's settled policy — the reserved-namespace gate's input.
    pub signing_key_id: String,
    /// Eager (`autorun`) or lazy (`ondemand`).
    pub enablement: Enablement,
    /// The capabilities the provider offers (`[[provides]]`).
    pub provides: Vec<ProvideRuntime>,
}

/// One resolved catalogue entry: a capability `name` mapped to the single provider that offers it,
/// plus the readiness a consumer's connect waits on (§7.13.4/§7.13.7).
#[derive(Debug, Clone)]
pub struct CatalogueEntry {
    /// The typed transport the broker delivers (§7.13.2).
    pub shape: Shape,
    /// Where the capability is exposed, in the provider's own view.
    pub endpoint: String,
    /// The optional private match token (§7.13.1) — never advertised, matched broker-side.
    pub key: Option<String>,
    /// The provider kennel that offers this name.
    pub provider: String,
    /// The provider's enablement posture (eager vs lazy bring-up).
    pub enablement: Enablement,
    /// The provider's current readiness — a connect bridges only at [`Readiness::Ready`] (§7.13.4a).
    pub readiness: Readiness,
}

/// The service catalogue: a name → provider projection over the enabled set (§7.13.4).
///
/// Derived, never authored: rebuilt by [`project`](Self::project) on daemon start and `daemon-reload`
/// from the enablement links on disk, so a restart cannot lose it or a bug desync it.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    entries: BTreeMap<String, CatalogueEntry>,
}

impl Catalogue {
    /// Project the catalogue from the enabled providers, applying the reserved-namespace gate and
    /// resolving each name to a **single** provider.
    ///
    /// A `[[provides]]` is admitted only if [`provide_authorized`] passes (an unauthorized reserved
    /// claim is dropped — the spoofing backstop). A name offered by **more than one** authorized
    /// provider is **ambiguous** and admitted from none of them: deny-by-default fails closed rather
    /// than silently broker a consumer to one of several claimants (§7.13.4 resolves to a *single*
    /// provider; cross-provider duplicates have no defined winner, so none wins). Every dropped or
    /// conflicted name is reported via `audit` for the caller to log; the returned catalogue contains
    /// only the cleanly-resolved entries, each [`Readiness::Pending`] until construction reports in.
    pub fn project(
        providers: &[EnabledProvider],
        vendor_key_ids: &BTreeSet<String>,
        reserved: &[ReservedNamespace],
        mut audit: impl FnMut(CatalogueRejection<'_>),
    ) -> Self {
        // First pass: gather every authorized (name → provider) claim.
        let mut claims: BTreeMap<&str, Vec<&EnabledProvider>> = BTreeMap::new();
        for prov in providers {
            for offer in &prov.provides {
                if provide_authorized(&offer.name, &prov.signing_key_id, vendor_key_ids, reserved) {
                    claims.entry(&offer.name).or_default().push(prov);
                } else {
                    audit(CatalogueRejection::Unauthorized {
                        name: &offer.name,
                        provider: &prov.provider,
                    });
                }
            }
        }
        // Second pass: admit names with exactly one claimant; a contested name resolves to none.
        let mut entries = BTreeMap::new();
        for (name, owners) in claims {
            let [owner] = owners.as_slice() else {
                audit(CatalogueRejection::Conflict {
                    name,
                    providers: owners.iter().map(|o| o.provider.as_str()).collect(),
                });
                continue;
            };
            // The owner's own offer for this name (it is present — that is why it claimed it).
            if let Some(offer) = owner.provides.iter().find(|pr| pr.name == name) {
                entries.insert(
                    name.to_owned(),
                    CatalogueEntry {
                        shape: offer.shape,
                        endpoint: offer.endpoint.clone(),
                        key: offer.key.clone(),
                        provider: owner.provider.clone(),
                        enablement: owner.enablement,
                        readiness: Readiness::Pending,
                    },
                );
            }
        }
        Self { entries }
    }

    /// Resolve a capability `name` to its provider entry, or `None` if no enabled provider cleanly
    /// offers it (unresolved / conflicted) — the deny-on-no-match the broker (W5) audits (§7.13.4).
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&CatalogueEntry> {
        self.entries.get(name)
    }

    /// Update the readiness of the entry for `name`, returning the new state, or `None` if no such
    /// entry — the hook the supervisor (W6) drives construction status through (§7.13.7).
    pub fn set_readiness(&mut self, name: &str, readiness: Readiness) -> Option<Readiness> {
        self.entries.get_mut(name).map(|e| {
            e.readiness = readiness;
            readiness
        })
    }

    /// The catalogued capability names (the topology surface reads this, §7.13.7).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// The number of resolved entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalogue resolves nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a `[[provides]]` did not enter the catalogue — reported by [`Catalogue::project`] for the
/// caller to audit (§7.13.4: a refusal is denied-**and-audited**, never silent).
#[derive(Debug)]
pub enum CatalogueRejection<'a> {
    /// A reserved name whose signing key is not authorized for the namespace (spoofing attempt).
    Unauthorized {
        /// The reserved capability name that was refused.
        name: &'a str,
        /// The provider that tried to claim it.
        provider: &'a str,
    },
    /// A name offered by more than one authorized provider — ambiguous, so admitted from none.
    Conflict {
        /// The contested capability name.
        name: &'a str,
        /// The providers that each claimed it.
        providers: Vec<&'a str>,
    },
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

    fn provide(name: &str, shape: Shape, endpoint: &str, key: Option<&str>) -> ProvideRuntime {
        ProvideRuntime {
            name: name.to_owned(),
            shape,
            endpoint: endpoint.to_owned(),
            key: key.map(ToOwned::to_owned),
        }
    }

    fn enabled(
        who: &str,
        key_id: &str,
        en: Enablement,
        offers: Vec<ProvideRuntime>,
    ) -> EnabledProvider {
        EnabledProvider {
            provider: who.to_owned(),
            signing_key_id: key_id.to_owned(),
            enablement: en,
            provides: offers,
        }
    }

    /// Project, collecting rejections into a vec for assertion.
    fn project_with_rejections(
        providers: &[EnabledProvider],
        vendor_key_ids: &BTreeSet<String>,
        reserved: &[ReservedNamespace],
    ) -> (Catalogue, Vec<String>) {
        let mut rejected = Vec::new();
        let cat = Catalogue::project(providers, vendor_key_ids, reserved, |r| match r {
            CatalogueRejection::Unauthorized { name, provider } => {
                rejected.push(format!("unauthorized:{name}:{provider}"));
            }
            CatalogueRejection::Conflict { name, providers } => {
                rejected.push(format!("conflict:{name}:{}", providers.join(",")));
            }
        });
        (cat, rejected)
    }

    #[test]
    fn project_resolves_an_authorized_provide_with_its_shape_and_pending_readiness() {
        let providers = [enabled(
            "build-cache",
            "alice-key",
            Enablement::Ondemand,
            vec![provide(
                "doe.john.cache",
                Shape::AfUnix,
                "$XDG_RUNTIME_DIR/cache.sock",
                Some("tok"),
            )],
        )];
        let (cat, rejected) = project_with_rejections(&providers, &vendor(&[]), &[]);
        assert!(rejected.is_empty());
        let e = cat.resolve("doe.john.cache").expect("resolves");
        assert_eq!(e.shape, Shape::AfUnix);
        assert_eq!(e.endpoint, "$XDG_RUNTIME_DIR/cache.sock");
        assert_eq!(e.key.as_deref(), Some("tok"));
        assert_eq!(e.provider, "build-cache");
        assert_eq!(e.enablement, Enablement::Ondemand);
        assert_eq!(e.readiness, Readiness::Pending); // resolvable before it is running
        assert_eq!(cat.len(), 1);
        assert!(cat.resolve("nope").is_none()); // deny-on-no-match
    }

    #[test]
    fn project_admits_a_reserved_name_only_from_a_vendor_key() {
        let wayland = || {
            vec![provide(
                "org.projectkennel.wayland",
                Shape::AfUnix,
                "$XDG_RUNTIME_DIR/wayland-0",
                None,
            )]
        };
        // The maintainer (vendor) key: admitted.
        let (cat, rej) = project_with_rejections(
            &[enabled(
                "gui",
                "kennel-maint-2026",
                Enablement::Autorun,
                wayland(),
            )],
            &vendor(&["kennel-maint-2026"]),
            &[],
        );
        assert!(cat.resolve("org.projectkennel.wayland").is_some());
        assert!(rej.is_empty());
        // A self-signed impostor: dropped, and the name resolves to nothing (spoofing backstop).
        let (cat, rej) = project_with_rejections(
            &[enabled("evil", "alice-key", Enablement::Autorun, wayland())],
            &vendor(&["kennel-maint-2026"]),
            &[],
        );
        assert!(cat.resolve("org.projectkennel.wayland").is_none());
        assert_eq!(rej, vec!["unauthorized:org.projectkennel.wayland:evil"]);
    }

    #[test]
    fn project_fails_closed_on_a_cross_provider_name_conflict() {
        // Two authorized providers claim the same unreserved name → ambiguous → admitted from none.
        let p = |who: &str| {
            enabled(
                who,
                "alice-key",
                Enablement::Ondemand,
                vec![provide("doe.john.cache", Shape::AfUnix, "/run/x", None)],
            )
        };
        let (cat, rejected) =
            project_with_rejections(&[p("cache-a"), p("cache-b")], &vendor(&[]), &[]);
        assert!(
            cat.resolve("doe.john.cache").is_none(),
            "a contested name resolves to no provider"
        );
        assert_eq!(rejected.len(), 1);
        let r = rejected.first().expect("one rejection");
        assert!(r.starts_with("conflict:doe.john.cache:"));
        assert!(r.contains("cache-a") && r.contains("cache-b"));
    }

    #[test]
    fn set_readiness_drives_an_entry_and_no_op_on_a_missing_name() {
        let mut cat = project_with_rejections(
            &[enabled(
                "svc",
                "k",
                Enablement::Autorun,
                vec![provide("x.y", Shape::BinderConnector, "node", None)],
            )],
            &vendor(&[]),
            &[],
        )
        .0;
        assert_eq!(
            cat.set_readiness("x.y", Readiness::Ready),
            Some(Readiness::Ready)
        );
        assert_eq!(
            cat.resolve("x.y").expect("entry").readiness,
            Readiness::Ready
        );
        assert_eq!(cat.set_readiness("absent", Readiness::Ready), None);
    }

    #[test]
    fn an_empty_enabled_set_yields_an_empty_catalogue() {
        let (cat, rej) = project_with_rejections(&[], &vendor(&[]), &[]);
        assert!(cat.is_empty() && rej.is_empty());
        assert_eq!(cat.names().count(), 0);
    }
}
