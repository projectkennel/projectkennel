//! DNS resolution seam and policy.
//!
//! The kennel never resolves names itself — the proxy resolves on its behalf
//! (`docs/07-3-network.md` §7.3.2), so DNS rebinding is structurally defeated
//! (the workload never holds an address) and every resolved address is re-checked
//! against policy before the proxy connects.
//!
//! **We do not hand-roll the DNS wire format.** Parsing DNS by hand (compression
//! pointers, the cache-poisoning surface, resolver quirks) is a known footgun;
//! per a maintainer directive, resolution is delegated to a vendored resolver
//! crate behind the [`Resolver`] trait. The rest of the proxy depends only on the
//! trait, so the crate choice is isolated to one wrapper.
//!
//! # Policy surface
//!
//! Resolution is a policy decision, not a mechanical lookup (§7.3.4 `[net.dns]`):
//!
//! - [`DnsServers`] chooses *where* queries go — the host's system resolvers
//!   (convenient, but the workload can probe internal names and queries leak to
//!   whatever the host uses) or an explicit set of external resolvers (no
//!   internal-name resolution, no topology leak). There is deliberately no silent
//!   default; a policy states its choice.
//! - Whether a resolved address in special-use space (RFC1918 / ULA /
//!   link-local / loopback / CGNAT) is acceptable is enforced by the allowlist
//!   evaluator ([`crate::allow::is_special_use`]); the default is to refuse, so a
//!   public name that resolves into private space cannot be reached unless policy
//!   opts in.
//!
//! # Owed
//!
//! The concrete [`Resolver`] implementation wraps a vendored resolver crate that
//! must clear the §5.5 supply-chain gate (a maintainer decision: resolver crates
//! have large dependency trees and async cores). Until it lands, only test fakes
//! implement the trait; the proxy can serve literal-address requests but a name
//! request resolves to [`ResolveError::Unavailable`].
//!
//! # Threat bearing
//!
//! T8 and the DNS-rebinding class: resolution happens here under policy, never in
//! the workload, and the resolved address is re-checked (deny rules plus the
//! special-use refusal) before any connection.

use std::net::IpAddr;

/// Where the proxy sends DNS queries (the `[net.dns]` resolver opinion, §7.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsServers {
    /// Use the host's configured resolvers (`/etc/resolv.conf`). Convenient, but
    /// the workload can probe internal domain names and the queries leak to
    /// whatever the host is configured to use. Opt-in only.
    System,
    /// Send queries only to these explicit resolvers (e.g. `9.9.9.9`, `1.1.1.1`).
    /// Preferred: no internal-name resolution and no leak of internal topology.
    Servers(Vec<IpAddr>),
}

/// Why a resolution attempt did not yield usable addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The name does not resolve (NXDOMAIN, or an empty answer).
    NotFound,
    /// The resolver did not answer within the policy timeout.
    Timeout,
    /// No resolver backend is wired yet (the vendored crate is owed).
    Unavailable,
    /// The resolver backend reported a failure.
    Backend(String),
}

/// Resolves names to addresses on the kennel's behalf.
///
/// Implemented by the vendored-resolver wrapper (owed) and by test fakes. The
/// proxy server is generic over this trait, so the resolver crate is the only
/// place that touches DNS wire format or a network resolver.
pub trait Resolver: Send + Sync {
    /// Resolve `name` to its `A`/`AAAA` addresses, honouring the configured
    /// [`DnsServers`].
    ///
    /// # Errors
    ///
    /// [`ResolveError`] if the name does not resolve, the resolver times out, the
    /// backend fails, or no backend is available yet.
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError>;
}
