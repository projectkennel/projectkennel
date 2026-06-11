//! DNS resolution seam and policy.
//!
//! The kennel never resolves names itself — the proxy resolves on its behalf
//! (`docs/design/07-5-network.md` §7.5.2), so DNS rebinding is structurally defeated
//! (the workload never holds an address) and every resolved address is re-checked
//! against policy before the proxy connects.
//!
//! **We do not hand-roll DNS and we do not vendor a resolver.** Parsing the wire
//! format by hand is a known footgun (compression pointers, cache-poisoning
//! surface); the available resolver crates are heavyweight (per a 2026-05-31
//! evaluation, `hickory-resolver` pulls ~85 transitive crates incl. tokio +
//! idna/url/icu, and `domain` with its `resolv` feature ~34 incl. tokio + jiff).
//! Per a maintainer decision we instead let the **operating system** resolve
//! (`getaddrinfo` via [`std::net::ToSocketAddrs`]) and **vet the answers by
//! policy**. The OS owns both the wire parsing and the resolution loop; we own
//! the policy check on what comes back.
//!
//! # Policy vetting (where the security lives)
//!
//! The system resolver will happily answer for internal zones and can be lied
//! to. That is fine here because the *answer* is policed, not trusted:
//!
//! - the name must already have cleared the allowlist
//!   ([`crate::inet::allow::Ruleset::decide_request`]) before we resolve it at all;
//! - each resolved address is re-checked against the deny rules
//!   ([`crate::inet::allow::Ruleset::decide_resolved`]); and
//! - a resolved address in special-use space (RFC1918 / ULA / loopback / ...) is
//!   refused unless policy opts in ([`crate::inet::allow::is_special_use`]).
//!
//! So a public name that resolves into private space — whether through a hostile
//! resolver or system DNS answering for an internal zone — does not become a
//! reachable destination by default, and internal topology is not silently
//! reachable just because the host's resolver knows it.
//!
//! # Limitation
//!
//! `getaddrinfo` has no per-query timeout, so a slow resolver ties up the one
//! connection thread that issued the lookup (it does not affect other
//! connections — one thread each). Pinning a specific resolver (e.g. `9.9.9.9`)
//! or a query timeout would require a resolver crate through the §5.5 gate; that
//! is deliberately deferred.
//!
//! # Threat bearing
//!
//! T1.8 and the DNS-rebinding class: resolution happens here on the workload's
//! behalf, never in the workload, and the resolved address is policed (deny
//! rules plus the special-use refusal) before any connection.

use std::net::{IpAddr, ToSocketAddrs};

/// Why a resolution attempt did not yield usable addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The name did not resolve to any address (NXDOMAIN, or an empty answer).
    NotFound,
    /// The resolver backend reported a failure (the message is for diagnostics
    /// only and is never logged, since it may quote the untrusted name).
    Backend(String),
}

/// Resolves names to addresses on the kennel's behalf.
///
/// The proxy server is generic over this trait. The production implementation is
/// [`SystemResolver`]; tests use fakes. Keeping it a trait isolates the resolver
/// choice and lets the network-free pipeline be tested without one.
pub trait Resolver: Send + Sync {
    /// Resolve `name` to its addresses.
    ///
    /// # Errors
    ///
    /// [`ResolveError::NotFound`] if the name does not resolve;
    /// [`ResolveError::Backend`] if the resolver itself failed.
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError>;
}

/// The operating-system resolver (`getaddrinfo`).
///
/// Delegates the wire format and the resolution loop to the OS; the proxy vets
/// the returned addresses by policy (see the module docs). Holds no state.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        // Port 0: we only want the addresses. `getaddrinfo` does the lookup
        // (consulting /etc/hosts, nsswitch, and the configured resolvers).
        match (name, 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                if addrs.is_empty() {
                    Err(ResolveError::NotFound)
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => Err(ResolveError::Backend(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_resolver_resolves_localhost_offline() {
        // `localhost` resolves via /etc/hosts without touching the network, so
        // this is a hermetic check that the seam reaches getaddrinfo.
        let addrs = SystemResolver
            .resolve("localhost")
            .expect("localhost resolves");
        assert!(
            !addrs.is_empty(),
            "localhost should resolve to at least one address"
        );
        assert!(
            addrs.iter().all(IpAddr::is_loopback),
            "localhost resolves to loopback only, got {addrs:?}"
        );
    }
}
