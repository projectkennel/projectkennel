//! The service-connector broker decision (`07-13-service-catalog.md` §7.13.4): resolve a consume
//! against the catalogue and pick the single provider to connect.
//!
//! This is the pure decision half of the `SVC_CONNECT` broker (§7.13.4a) — given the caller's signed
//! `[[consumes]]` and the catalogue, it decides *whether* and *to whom* a connector is brokered. The
//! handler ([`crate::binder`]) maps the [`Decision`] to a reply status and, on [`Decision::Ready`],
//! performs the connector handoff; the consume-with-wait + socket-activation of a [`Decision::Pending`]
//! provider is the supervisor's (W6).
//!
//! Three rules, all from §7.13.4:
//! - **Request-don't-author.** The caller reaches a capability only if its own signed policy declares
//!   a `[[consumes]]` for the name; otherwise [`Decision::NoGrant`] (no widening at runtime).
//! - **Match, don't search.** The expected `shape` must agree and the optional private `key` must
//!   match *exactly* — if either side sets a key, both must hold the identical one (§7.13.1); a
//!   candidate failing either is not eligible.
//! - **No silent fallback.** The eligible candidates are ordered by the catalogue (per-user before
//!   per-host); the broker selects the **first** and reports *its* readiness — it never falls back to a
//!   different provider because the preferred one is down (failover is an explicit non-goal).

use kennel_lib_control::readiness::Readiness;
use kennel_lib_policy::settled::{ConsumeRuntime, Shape};

use crate::catalogue::{Catalogue, Tier};

/// The provider the broker selected for a consume — what the connector handoff needs.
///
/// It resolves the host rendezvous point: the triple `(tier, name, key)` for the directory and the
/// policy `endpoint` for the socket leaf (§7.13.4b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The provider kennel to connect to (and, when lazy, socket-activate).
    pub provider: String,
    /// The transport to broker.
    pub shape: Shape,
    /// The tier the provider was enabled at — part of the host rendezvous directory (§7.13.4b).
    pub tier: Tier,
    /// The optional private key — appended to the rendezvous directory when set (§7.13.4b).
    pub key: Option<String>,
    /// The provider's policy-authored in-view `endpoint`; its basename is the rendezvous socket leaf
    /// the provider binds and the broker connects (§7.13.4b).
    pub endpoint: String,
}

/// The broker's decision for one `SVC_CONNECT` (§7.13.4a). The handler maps each to a reply status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The caller signed no `[[consumes]]` for this name — request-don't-author refusal (`DENIED`).
    NoGrant,
    /// No enabled provider offers the name in the consumer's shape with a compatible key (`NOT_FOUND`).
    NoProvider,
    /// The selected provider exists but is not serving — `Failed` (`UNAVAILABLE`). No fallback to
    /// another provider (§7.13.4).
    NotServing,
    /// The selected provider is `Pending`: it must be socket-activated and waited on (consume-with-wait,
    /// W6). The handler blocks until it is ready or the deadline fires (§7.13.4a).
    Pending(Selected),
    /// The selected provider is `Ready` — broker the connector now.
    Ready(Selected),
}

/// Decide a `SVC_CONNECT` for `name` from a caller whose signed consumes are `consumes`.
#[must_use]
pub fn decide(consumes: &[ConsumeRuntime], catalogue: &Catalogue, name: &str) -> Decision {
    // Request-don't-author: the caller must have signed a `[[consumes]]` for this name.
    let Some(consume) = consumes.iter().find(|c| c.name == name) else {
        return Decision::NoGrant;
    };
    // Select the first eligible candidate — the catalogue orders them per-user before per-host, and
    // there is no fallback past the preferred one (§7.13.4). Eligible = shape agrees and the keys
    // match exactly — equal, or both absent (§7.13.1).
    let candidates = catalogue.resolve(name);
    let Some(cand) = candidates
        .iter()
        .find(|c| c.shape == consume.shape && key_compatible(consume.key.as_deref(), c.key))
    else {
        return Decision::NoProvider;
    };
    let selected = Selected {
        provider: cand.provider.to_owned(),
        shape: cand.shape,
        tier: cand.tier,
        key: cand.key.map(ToOwned::to_owned),
        endpoint: cand.endpoint.to_owned(),
    };
    match cand.readiness {
        Readiness::Ready => Decision::Ready(selected),
        Readiness::Pending => Decision::Pending(selected),
        Readiness::Failed => Decision::NotServing,
    }
}

/// Whether a consumer's optional key matches a provider's. The key is a private **discriminator**:
/// if **either** side sets one, the other must hold the **identical** key to match (§7.13.4 step 3) —
/// strict equality, not a permissive fallback. Both keyless → match (no discriminator in play);
/// one keyed and one keyless → **no** match (the keyed side demanded a specific peer the other is
/// not). This is the whole point of the key: a keyed consumer is never brokered to a keyless
/// (generic) provider, so a generic provider cannot silently swallow traffic a key was set to bind.
fn key_compatible(consume_key: Option<&str>, provider_key: Option<&str>) -> bool {
    consume_key == provider_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{Catalogue, EnabledProvider, Enablement, Tier};
    use kennel_lib_policy::settled::ProvideRuntime;

    fn consume(name: &str, shape: Shape, key: Option<&str>) -> ConsumeRuntime {
        ConsumeRuntime {
            name: name.to_owned(),
            shape,
            at: None,
            env: Vec::new(),
            key: key.map(ToOwned::to_owned),
            required: true,
        }
    }

    fn provider(
        who: &str,
        tier: Tier,
        name: &str,
        shape: Shape,
        key: Option<&str>,
    ) -> EnabledProvider {
        EnabledProvider {
            provider: who.to_owned(),
            signing_key_id: "k".to_owned(),
            tier,
            enablement: Enablement::Ondemand,
            provides: vec![ProvideRuntime {
                name: name.to_owned(),
                shape,
                endpoint: format!("/run/{who}.sock"),
                key: key.map(ToOwned::to_owned),
            }],
            policy_path: std::path::PathBuf::new(),
            service: kennel_lib_policy::settled::ServiceRuntime {
                restart: kennel_lib_policy::settled::RestartPolicy::OnFailure,
                backoff_ms: 500,
                max_attempts: 5,
            },
        }
    }

    fn catalogue(providers: &[EnabledProvider]) -> Catalogue {
        Catalogue::project(providers)
    }

    fn ready(mut cat: Catalogue, who: &str) -> Catalogue {
        cat.set_readiness(who, Readiness::Ready);
        cat
    }

    #[test]
    fn no_signed_consume_is_denied() {
        // The catalogue offers the name, but the caller never declared a consume for it.
        let cat = catalogue(&[provider("p", Tier::Host, "x.cap", Shape::AfUnix, None)]);
        assert_eq!(decide(&[], &cat, "x.cap"), Decision::NoGrant);
        // A consume for a *different* name does not grant this one.
        let other = [consume("y.cap", Shape::AfUnix, None)];
        assert_eq!(decide(&other, &cat, "x.cap"), Decision::NoGrant);
    }

    #[test]
    fn a_granted_name_with_no_provider_is_not_found() {
        let cat = catalogue(&[]);
        let c = [consume("x.cap", Shape::AfUnix, None)];
        assert_eq!(decide(&c, &cat, "x.cap"), Decision::NoProvider);
    }

    #[test]
    fn a_shape_mismatch_is_not_found() {
        // The provider offers the name but as dbus-name; the consumer expects af-unix.
        let cat = catalogue(&[provider("p", Tier::Host, "x.cap", Shape::DbusName, None)]);
        let c = [consume("x.cap", Shape::AfUnix, None)];
        assert_eq!(decide(&c, &cat, "x.cap"), Decision::NoProvider);
    }

    #[test]
    fn key_matches_iff_consumer_and_provider_keys_are_equal() {
        let p = |key| catalogue(&[provider("p", Tier::Host, "x.cap", Shape::AfUnix, key)]);
        // Both set, equal → eligible.
        assert!(matches!(
            decide(
                &[consume("x.cap", Shape::AfUnix, Some("k1"))],
                &ready(p(Some("k1")), "p"),
                "x.cap"
            ),
            Decision::Ready(_)
        ));
        // Both set, differ → no eligible provider.
        assert_eq!(
            decide(
                &[consume("x.cap", Shape::AfUnix, Some("k1"))],
                &p(Some("k2")),
                "x.cap"
            ),
            Decision::NoProvider
        );
        // Only the consumer keyed (provider keyless) → NO match: a keyed consumer demands that exact
        // keyed provider and is never brokered to a generic one (§7.13.4, strict equality).
        assert_eq!(
            decide(
                &[consume("x.cap", Shape::AfUnix, Some("k1"))],
                &ready(p(None), "p"),
                "x.cap"
            ),
            Decision::NoProvider
        );
        // Only the provider keyed (consumer keyless) → NO match either: the key binds both ways.
        assert_eq!(
            decide(
                &[consume("x.cap", Shape::AfUnix, None)],
                &ready(p(Some("k1")), "p"),
                "x.cap"
            ),
            Decision::NoProvider
        );
        // Neither keyed → match (no discriminator in play).
        assert!(matches!(
            decide(
                &[consume("x.cap", Shape::AfUnix, None)],
                &ready(p(None), "p"),
                "x.cap"
            ),
            Decision::Ready(_)
        ));
    }

    #[test]
    fn a_keyless_consumer_binds_the_keyless_provider_when_both_exist() {
        // A keyless consumer gets nothing from a keyed-*only* catalogue (asserted above), but when the
        // name is offered by *both* a keyed and a keyless provider, it binds the keyless one — the only
        // candidate whose key matches (None == None). The keyed provider is skipped, not preferred.
        let both = catalogue(&[
            provider("keyed", Tier::Host, "x.cap", Shape::AfUnix, Some("k1")),
            provider("plain", Tier::Host, "x.cap", Shape::AfUnix, None),
        ]);
        let c = [consume("x.cap", Shape::AfUnix, None)];
        let decision = decide(&c, &ready(both, "plain"), "x.cap");
        assert!(
            matches!(&decision, Decision::Ready(s) if s.provider == "plain"),
            "expected the keyless provider, got {decision:?}"
        );
    }

    #[test]
    fn readiness_maps_to_the_decision_and_carries_the_endpoint() {
        let c = [consume("x.cap", Shape::AfUnix, None)];
        // Pending (the default after projection) → Pending(selected).
        let cat = catalogue(&[provider("p", Tier::Host, "x.cap", Shape::AfUnix, None)]);
        assert_eq!(
            decide(&c, &cat, "x.cap"),
            Decision::Pending(Selected {
                provider: "p".to_owned(),
                shape: Shape::AfUnix,
                tier: Tier::Host,
                key: None,
                endpoint: "/run/p.sock".to_owned(),
            })
        );
        // Ready → Ready(selected).
        assert!(matches!(
            decide(&c, &ready(cat, "p"), "x.cap"),
            Decision::Ready(_)
        ));
        // Failed → NotServing.
        let mut failed = catalogue(&[provider("p", Tier::Host, "x.cap", Shape::AfUnix, None)]);
        failed.set_readiness("p", Readiness::Failed);
        assert_eq!(decide(&c, &failed, "x.cap"), Decision::NotServing);
    }

    #[test]
    fn the_preferred_provider_is_selected_with_no_fallback() {
        let c = [consume("x.cap", Shape::AfUnix, None)];
        // Two providers offer the same unkeyed name: per-user "u" and per-host "h".
        let providers = [
            provider("h", Tier::Host, "x.cap", Shape::AfUnix, None),
            provider("u", Tier::User, "x.cap", Shape::AfUnix, None),
        ];
        // Both ready → the per-USER provider is selected (the tiebreak).
        let mut both = catalogue(&providers);
        both.set_readiness("u", Readiness::Ready);
        both.set_readiness("h", Readiness::Ready);
        assert!(
            matches!(decide(&c, &both, "x.cap"), Decision::Ready(sel) if sel.provider == "u"),
            "per-user preferred"
        );
        // The preferred (user) provider is Failed while the host one is Ready: NO fallback — the
        // result is NotServing, not a silent switch to the host provider (§7.13.4).
        let mut user_down = catalogue(&providers);
        user_down.set_readiness("u", Readiness::Failed);
        user_down.set_readiness("h", Readiness::Ready);
        assert_eq!(
            decide(&c, &user_down, "x.cap"),
            Decision::NotServing,
            "the preferred provider is down — no fallback to another"
        );
    }
}
