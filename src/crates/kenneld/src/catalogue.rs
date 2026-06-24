//! The service catalogue: a derived projection of the enabled providers' `[[provides]]`
//! (`07-13-service-catalog.md` §7.13.4), and the **authoritative reserved-namespace gate** (§7.13.5).
//!
//! The catalogue is a projection, never authored state: [`Catalogue::project`] reads the
//! `[[provides]]` of the enabled providers and resolves a capability `name` to its candidate
//! provider(s) ([`Catalogue::resolve`]) — never collapsed, since the optional `key` (§7.13.1) lets a
//! consumer bind to a *specific* provider of a shared public name, and collapsing would let one
//! provider revoke another's name. It carries the [`Readiness`] every reader sees (§7.13.7). It is also
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

impl Enablement {
    /// The lower-case wire/display name (`autorun` / `ondemand`), for the topology surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Autorun => "autorun",
            Self::Ondemand => "ondemand",
        }
    }
}

/// The enablement **tier** a provider was enabled at (§7.13.6) — the resolution preference when two
/// providers offer the same name and are otherwise equivalent (no `key` to tell them apart).
///
/// `User` precedes `Host` (the [`Ord`] derive's variant order) because per-user enablement wins over
/// per-host, the same direction as the config cascade — a user's own provider wins the name on the
/// user's kennels. There is no vendor tier: a vendor ships a provider but cannot enable it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// `~/.config/kennel/{autorun,ondemand}/` — the per-user operator layer (preferred).
    User,
    /// `/etc/kennel/{autorun,ondemand}/` — the per-host (admin) operator layer.
    Host,
}

impl Tier {
    /// The lower-case wire/display name (`user` / `host`), for the topology surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Host => "host",
        }
    }
}

/// One enabled provider feeding the catalogue: its identity, who signed it, its tier + posture, and
/// what it offers. The membership the enablement scan produces from the enabled set (§7.13.6).
#[derive(Debug, Clone)]
pub struct EnabledProvider {
    /// The provider's identifier — the enablement link name, i.e. the kennel the broker (W5)
    /// resolves to and socket-activates.
    pub provider: String,
    /// The key that signed the provider's settled policy — the reserved-namespace gate's input.
    pub signing_key_id: String,
    /// The tier it was enabled at (per-user preferred over per-host).
    pub tier: Tier,
    /// Eager (`autorun`) or lazy (`ondemand`).
    pub enablement: Enablement,
    /// The capabilities the provider offers (`[[provides]]`).
    pub provides: Vec<ProvideRuntime>,
    /// The enablement link's target — the signed policy path the supervisor (W6) runs to bring the
    /// provider up. (The catalogue projection ignores it; the autostart runtime reads it.)
    pub policy_path: std::path::PathBuf,
    /// The provider's supervision discipline (`[service]`, §7.13.7) — the restart policy the
    /// supervisor executes. The default discipline when the policy declares no `[service]`.
    pub service: kennel_lib_policy::settled::ServiceRuntime,
}

/// A provider in the catalogue: who signed it, its tier/posture, its readiness, and what it offers.
///
/// Readiness is **per provider** — one kennel is `Ready` or not as a whole, across every name it
/// offers (§7.13.7).
#[derive(Debug, Clone)]
pub struct CatalogueProvider {
    /// The key that signed the provider's settled policy (the reserved-gate provenance).
    pub signing_key_id: String,
    /// The tier it was enabled at (per-user preferred over per-host on an equivalent tie).
    pub tier: Tier,
    /// Eager (`autorun`) or lazy (`ondemand`) bring-up.
    pub enablement: Enablement,
    /// The provider's readiness — a connect bridges only at [`Readiness::Ready`] (§7.13.4a).
    pub readiness: Readiness,
    /// The running provider's host pid, set by the supervisor when construction seals (§7.13.6) —
    /// `Some` exactly when [`Readiness::Ready`]. The broker reaches the provider's endpoint socket
    /// through `/proc/<pid>/root` to hand the consumer a connector (§7.13.4a). `None` when not running.
    pub pid: Option<u32>,
    /// The capabilities this provider offers, post-gate.
    pub offers: Vec<ProvideRuntime>,
}

/// One candidate provider for a resolved `name`: what the broker (W5) needs to select and connect.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// The provider kennel offering the name.
    pub provider: &'a str,
    /// The typed transport (§7.13.2).
    pub shape: Shape,
    /// Where the capability is exposed, in the provider's own view.
    pub endpoint: &'a str,
    /// The optional private match token (§7.13.1) — the broker matches a consumer's key against it.
    pub key: Option<&'a str>,
    /// The tier the provider was enabled at (candidates are ordered user-tier first).
    pub tier: Tier,
    /// The provider's bring-up posture.
    pub enablement: Enablement,
    /// The provider's current readiness.
    pub readiness: Readiness,
    /// The running provider's host pid (`Some` exactly when `Ready`) — the broker reaches its endpoint
    /// socket through `/proc/<pid>/root` for the connector handoff (§7.13.4a).
    pub pid: Option<u32>,
}

/// The service catalogue: a name → provider(s) projection over the enabled set (§7.13.4).
///
/// Derived, never authored: rebuilt by [`project`](Self::project) on daemon start and `daemon-reload`
/// from the enablement links on disk, so a restart cannot lose it or a bug desync it. A capability
/// `name` maps to **all** the enabled providers that offer it — never collapsed to one — because the
/// optional private `key` (§7.13.1) is what a consumer uses to bind to a *specific* provider of a
/// shared public name; collapsing would let one provider knock out another by claiming its name.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    /// Provider id → its state and offers.
    providers: BTreeMap<String, CatalogueProvider>,
    /// Capability name → the provider ids that offer it (the candidates), sorted for determinism.
    by_name: BTreeMap<String, Vec<String>>,
}

impl Catalogue {
    /// Project the catalogue from the enabled providers, applying the reserved-namespace gate.
    ///
    /// A `[[provides]]` is admitted only if [`provide_authorized`] passes — an unauthorized reserved
    /// claim is dropped (the spoofing backstop) and reported via `audit_unauthorized(name, provider)`
    /// for the caller to log. **A name offered by more than one authorized provider is kept from
    /// *all* of them** as candidates, never collapsed: the broker (W5) selects by the consumer's
    /// `key` (§7.13.1), so a second provider claiming a name *adds* a candidate and can never revoke
    /// the name another provider serves (no denial-of-service by name-claim). Every provider starts
    /// [`Readiness::Pending`] until construction reports in.
    pub fn project(
        providers: &[EnabledProvider],
        vendor_key_ids: &BTreeSet<String>,
        reserved: &[ReservedNamespace],
        mut audit_unauthorized: impl FnMut(&str, &str),
    ) -> Self {
        let mut prov_map = BTreeMap::new();
        let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for prov in providers {
            let mut offers = Vec::new();
            for offer in &prov.provides {
                if provide_authorized(&offer.name, &prov.signing_key_id, vendor_key_ids, reserved) {
                    by_name
                        .entry(offer.name.clone())
                        .or_default()
                        .push(prov.provider.clone());
                    offers.push(offer.clone());
                } else {
                    audit_unauthorized(&offer.name, &prov.provider);
                }
            }
            if !offers.is_empty() {
                prov_map.insert(
                    prov.provider.clone(),
                    CatalogueProvider {
                        signing_key_id: prov.signing_key_id.clone(),
                        tier: prov.tier,
                        enablement: prov.enablement,
                        readiness: Readiness::Pending,
                        pid: None,
                        offers,
                    },
                );
            }
        }
        // Order candidates by tier (per-user before per-host — the equivalent-tie preference),
        // then by provider id for a stable order independent of scan/`read_dir` order; one provider
        // listed once.
        for ids in by_name.values_mut() {
            ids.sort_by(|a, b| {
                let tier = |id: &String| prov_map.get(id).map(|p| p.tier);
                tier(a).cmp(&tier(b)).then_with(|| a.cmp(b))
            });
            ids.dedup();
        }
        Self {
            providers: prov_map,
            by_name,
        }
    }

    /// The candidate providers offering `name` — empty if no enabled provider offers it (the
    /// deny-on-no-match the broker, W5, audits, §7.13.4). More than one candidate means a shared
    /// public name the broker disambiguates by the consumer's `key`.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Vec<Candidate<'_>> {
        let Some(ids) = self.by_name.get(name) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| {
                let p = self.providers.get(id)?;
                let offer = p.offers.iter().find(|o| o.name == name)?;
                Some(Candidate {
                    provider: id,
                    shape: offer.shape,
                    endpoint: &offer.endpoint,
                    key: offer.key.as_deref(),
                    tier: p.tier,
                    enablement: p.enablement,
                    readiness: p.readiness,
                    pid: p.pid,
                })
            })
            .collect()
    }

    /// Update a **provider's** readiness (one state across all its names), returning the new state,
    /// or `None` if no such provider — the hook the supervisor (W6) drives construction through.
    pub fn set_readiness(&mut self, provider: &str, readiness: Readiness) -> Option<Readiness> {
        self.providers.get_mut(provider).map(|p| {
            p.readiness = readiness;
            readiness
        })
    }

    /// Drive a provider's readiness through the W2 state machine (§7.13.7): apply `event` to its
    /// current state and store the result, returning the new readiness.
    ///
    /// `None` if there is no such provider **or** the transition is illegal from the current state —
    /// a no-op-and-audit, never a silent forced change (`Failed` is sticky, etc.). The supervisor
    /// raises the events; the machine ([`kennel_lib_control::readiness::Readiness::on`]) decides what
    /// each means. This is the event-driven counterpart of the direct [`set_readiness`](Self::set_readiness).
    pub fn apply_event(
        &mut self,
        provider: &str,
        event: kennel_lib_control::readiness::Event,
    ) -> Option<Readiness> {
        let p = self.providers.get_mut(provider)?;
        let next = p.readiness.on(event)?;
        p.readiness = next;
        if next != Readiness::Ready {
            p.pid = None; // a non-running provider has no live pid for the broker to reach
        }
        Some(next)
    }

    /// Record a provider's running host pid and drive it `Pending → Ready` (§7.13.6): the supervisor
    /// calls this when construction seals. Returns the new readiness, or `None` if there is no such
    /// provider or it was not pending. The pid is what the broker reaches the endpoint through.
    pub fn note_constructed(&mut self, provider: &str, pid: u32) -> Option<Readiness> {
        let p = self.providers.get_mut(provider)?;
        let next = p
            .readiness
            .on(kennel_lib_control::readiness::Event::ConstructionSucceeded)?;
        p.readiness = next;
        p.pid = Some(pid);
        Some(next)
    }

    /// The catalogued capability names (the topology surface reads this, §7.13.7).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    /// The enabled provider ids in the catalogue.
    pub fn providers(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }

    /// The catalogued providers as `(id, provider)` pairs — the topology surface (`kennel mesh`,
    /// §7.13.7) reads this to project one row per offered capability with its readiness.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &CatalogueProvider)> {
        self.providers.iter().map(|(id, p)| (id.as_str(), p))
    }

    /// The number of distinct catalogued capability names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the catalogue resolves nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
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
        tier: Tier,
        en: Enablement,
        offers: Vec<ProvideRuntime>,
    ) -> EnabledProvider {
        EnabledProvider {
            provider: who.to_owned(),
            signing_key_id: key_id.to_owned(),
            tier,
            enablement: en,
            provides: offers,
            policy_path: std::path::PathBuf::new(),
            service: kennel_lib_policy::settled::ServiceRuntime {
                restart: kennel_lib_policy::settled::RestartPolicy::OnFailure,
                backoff_ms: 500,
                max_attempts: 5,
            },
        }
    }

    /// Project, collecting the unauthorized rejections (name:provider) for assertion.
    fn project_with_rejections(
        providers: &[EnabledProvider],
        vendor_key_ids: &BTreeSet<String>,
        reserved: &[ReservedNamespace],
    ) -> (Catalogue, Vec<String>) {
        let mut rejected = Vec::new();
        let cat = Catalogue::project(providers, vendor_key_ids, reserved, |name, provider| {
            rejected.push(format!("unauthorized:{name}:{provider}"));
        });
        (cat, rejected)
    }

    #[test]
    fn project_resolves_an_authorized_provide_with_its_shape_and_pending_readiness() {
        let providers = [enabled(
            "build-cache",
            "alice-key",
            Tier::User,
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
        let cands = cat.resolve("doe.john.cache");
        assert_eq!(cands.len(), 1);
        let e = cands.first().expect("one candidate");
        assert_eq!(e.shape, Shape::AfUnix);
        assert_eq!(e.endpoint, "$XDG_RUNTIME_DIR/cache.sock");
        assert_eq!(e.key, Some("tok"));
        assert_eq!(e.provider, "build-cache");
        assert_eq!(e.enablement, Enablement::Ondemand);
        assert_eq!(e.readiness, Readiness::Pending); // resolvable before it is running
        assert_eq!(cat.len(), 1);
        assert!(cat.resolve("nope").is_empty()); // deny-on-no-match
    }

    #[test]
    fn entries_projects_each_provider_with_its_offers_for_the_topology_surface() {
        // `kennel mesh` reads `entries()`: one provider, every capability it offers, its readiness.
        let providers = [enabled(
            "build-cache",
            "alice-key",
            Tier::User,
            Enablement::Ondemand,
            vec![
                provide("doe.john.cache", Shape::AfUnix, "/tmp/cache.sock", None),
                provide("doe.john.build", Shape::AfUnix, "/tmp/build.sock", None),
            ],
        )];
        let (cat, rejected) = project_with_rejections(&providers, &vendor(&[]), &[]);
        assert!(rejected.is_empty());

        let entries: Vec<(&str, &CatalogueProvider)> = cat.entries().collect();
        assert_eq!(entries.len(), 1, "one catalogued provider");
        let (id, p) = entries.first().expect("one entry");
        assert_eq!(*id, "build-cache");
        assert_eq!(p.tier, Tier::User);
        assert_eq!(p.enablement, Enablement::Ondemand);
        assert_eq!(p.readiness, Readiness::Pending); // catalogued but not yet running
        assert_eq!(p.pid, None);
        assert_eq!(p.offers.len(), 2);
        assert!(p.offers.iter().any(|o| o.name == "doe.john.cache"));
        assert!(p.offers.iter().any(|o| o.name == "doe.john.build"));

        // the canonical lower-case strings the topology surface puts on the wire
        assert_eq!(p.tier.as_str(), "user");
        assert_eq!(p.enablement.as_str(), "ondemand");
        assert_eq!(p.readiness.as_str(), "pending");
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
                Tier::Host,
                Enablement::Autorun,
                wayland(),
            )],
            &vendor(&["kennel-maint-2026"]),
            &[],
        );
        assert!(!cat.resolve("org.projectkennel.wayland").is_empty());
        assert!(rej.is_empty());
        // A self-signed impostor: dropped, and the name resolves to nothing (spoofing backstop).
        let (cat, rej) = project_with_rejections(
            &[enabled(
                "evil",
                "alice-key",
                Tier::User,
                Enablement::Autorun,
                wayland(),
            )],
            &vendor(&["kennel-maint-2026"]),
            &[],
        );
        assert!(cat.resolve("org.projectkennel.wayland").is_empty());
        assert_eq!(rej, vec!["unauthorized:org.projectkennel.wayland:evil"]);
    }

    #[test]
    fn a_shared_name_keeps_every_provider_no_dos() {
        // Two authorized providers claim the same unreserved name. Neither is revoked: the name keeps
        // BOTH as candidates (a second claim cannot knock out the first — no denial-of-service).
        let cache = |who: &str, tier: Tier| {
            enabled(
                who,
                "alice-key",
                tier,
                Enablement::Ondemand,
                vec![provide("doe.john.cache", Shape::AfUnix, "/run/x", None)],
            )
        };
        let (cat, rejected) = project_with_rejections(
            &[cache("zzz-host", Tier::Host), cache("aaa-user", Tier::User)],
            &vendor(&[]),
            &[],
        );
        assert!(rejected.is_empty(), "a shared name is not a rejection");
        let cands = cat.resolve("doe.john.cache");
        assert_eq!(cands.len(), 2, "both providers are kept");
        // Equivalent (no key divergence) → the per-USER provider is preferred (ordered first),
        // even though "zzz-host" sorts after "aaa-user" by id — tier wins over id.
        assert_eq!(cands.first().expect("first").provider, "aaa-user");
        assert_eq!(cands.first().expect("first").tier, Tier::User);
        assert_eq!(cands.get(1).expect("second").provider, "zzz-host");
    }

    #[test]
    fn set_readiness_drives_a_provider_across_its_names() {
        // Readiness is per-provider: one provider offering two names goes Ready for both at once.
        let mut cat = project_with_rejections(
            &[enabled(
                "svc",
                "k",
                Tier::Host,
                Enablement::Autorun,
                vec![
                    provide("x.y", Shape::BinderConnector, "node", None),
                    provide("x.z", Shape::AfUnix, "/run/z", None),
                ],
            )],
            &vendor(&[]),
            &[],
        )
        .0;
        assert_eq!(
            cat.set_readiness("svc", Readiness::Ready),
            Some(Readiness::Ready)
        );
        assert_eq!(
            cat.resolve("x.y").first().expect("y").readiness,
            Readiness::Ready
        );
        assert_eq!(
            cat.resolve("x.z").first().expect("z").readiness,
            Readiness::Ready
        );
        assert_eq!(cat.set_readiness("absent", Readiness::Ready), None);
    }

    #[test]
    fn apply_event_drives_readiness_through_the_machine() {
        use kennel_lib_control::readiness::Event;
        let mut cat = project_with_rejections(
            &[enabled(
                "svc",
                "k",
                Tier::Host,
                Enablement::Autorun,
                vec![provide("x.y", Shape::AfUnix, "/run/x", None)],
            )],
            &vendor(&[]),
            &[],
        )
        .0;
        // Pending → Ready on a sealed construction; Ready → Pending on a restart.
        assert_eq!(
            cat.apply_event("svc", Event::ConstructionSucceeded),
            Some(Readiness::Ready)
        );
        assert_eq!(
            cat.apply_event("svc", Event::Restarting),
            Some(Readiness::Pending)
        );
        // An illegal transition is a no-op (Pending cannot be "restarting"); a missing provider too.
        assert_eq!(cat.apply_event("svc", Event::Restarting), None);
        assert_eq!(
            cat.resolve("x.y").first().expect("y").readiness,
            Readiness::Pending
        );
        assert_eq!(
            cat.apply_event("absent", Event::ConstructionSucceeded),
            None
        );
        // Crash-loop exhaustion is sticky-Failed thereafter.
        assert_eq!(
            cat.apply_event("svc", Event::CrashLoopExhausted),
            Some(Readiness::Failed)
        );
        assert_eq!(cat.apply_event("svc", Event::ConstructionSucceeded), None);
    }

    #[test]
    fn an_empty_enabled_set_yields_an_empty_catalogue() {
        let (cat, rej) = project_with_rejections(&[], &vendor(&[]), &[]);
        assert!(cat.is_empty() && rej.is_empty());
        assert_eq!(cat.names().count(), 0);
        assert_eq!(cat.providers().count(), 0);
    }
}
