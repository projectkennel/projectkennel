//! The egress allowlist evaluator (Kennel book Vol 2 ch.8 (The Network)).
//!
//! Pure, network-free policy logic: given a destination the client asked for,
//! decide whether the proxy may connect to it. The evaluator is split from the
//! server (`src/server.rs`) so it can be exhaustively unit-tested without a
//! socket, and so the one place egress decisions are made is small and
//! auditable.
//!
//! # Two-phase evaluation
//!
//! A client presents either a literal address (SOCKS5 `ATYP` v4/v6) or a name
//! (SOCKS5 `socks5h`, HTTP `CONNECT`/absolute-form host). A literal address is
//! decided in one step. A name is decided in two:
//!
//! 1. [`Ruleset::decide_request`] checks the name against the allow rules. If it
//!    clears, the result is [`RequestDecision::Resolve`] — resolve the name under
//!    DNS policy, *then*
//! 2. [`Ruleset::decide_resolved`] re-checks each resolved address against the
//!    categorical deny rules before the proxy connects.
//!
//! The second step is the rebinding defence: a permitted name that resolves to a
//! denied address (cloud metadata, link-local, host loopback) is still refused.
//!
//! # Threat bearing
//!
//! T1.8 (exfiltration via an allowed destination): the per-destination allowlist is
//! the surface that constrains where an allowed workload may reach. The
//! deny-before-allow ordering and the resolved-address re-check are what stop a
//! permissive allow rule, or a hostile resolver, from reaching an
//! infrastructure-sensitive address.

use std::net::IpAddr;

/// Transport of an actual proxied request. A live request is always concrete TCP
/// or UDP; the `any` wildcard exists only on rules (see [`RuleProtocol`]), never
/// on a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP (SOCKS5 `UDP ASSOCIATE`).
    Udp,
}

/// The protocol selector on a rule: a specific transport, or `any`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleProtocol {
    /// Matches any transport.
    Any,
    /// Matches TCP only.
    Tcp,
    /// Matches UDP only.
    Udp,
}

impl RuleProtocol {
    /// Whether this selector admits `transport`.
    #[must_use]
    pub fn admits(self, transport: Transport) -> bool {
        match self {
            Self::Any => true,
            Self::Tcp => transport == Transport::Tcp,
            Self::Udp => transport == Transport::Udp,
        }
    }
}

/// The destination as the client presented it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// A DNS name (`socks5h`, HTTP host). Resolved by the proxy under DNS policy
    /// after it clears the name allowlist; the resolved address is re-checked.
    Name(String),
    /// A literal address the client connected to directly (SOCKS5 `ATYP` v4/v6).
    Addr(IpAddr),
}

/// An IP network: a base address and a prefix length.
///
/// Matching is byte-wise and shares no arithmetic with the BPF LPM encoder in
/// `kennel-lib-spawn`; the two are independent implementations of the same notion,
/// which is deliberate (the BPF rules and the proxy rules are enforced by
/// different mechanisms and must each be correct on their own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix_len: u8,
}

/// Error constructing a [`Cidr`]: the prefix length exceeds the address family's
/// maximum (32 for IPv4, 128 for IPv6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixTooLong {
    /// The maximum prefix length for the address family.
    pub max: u8,
    /// The prefix length that was supplied.
    pub got: u8,
}

impl std::fmt::Display for PrefixTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prefix length {} exceeds the maximum {} for the address family",
            self.got, self.max
        )
    }
}

impl std::error::Error for PrefixTooLong {}

impl Cidr {
    /// Construct a CIDR from a base address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixTooLong`] if `prefix_len` exceeds 32 for an IPv4 base or
    /// 128 for an IPv6 base.
    pub const fn new(base: IpAddr, prefix_len: u8) -> Result<Self, PrefixTooLong> {
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(PrefixTooLong {
                max,
                got: prefix_len,
            });
        }
        Ok(Self { base, prefix_len })
    }

    /// Whether `addr` falls within this network. A family mismatch (v4 address
    /// against a v6 network, or vice versa) is never a match.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(base), IpAddr::V4(other)) => {
                octets_match(&base.octets(), &other.octets(), self.prefix_len)
            }
            (IpAddr::V6(base), IpAddr::V6(other)) => {
                octets_match(&base.octets(), &other.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Whether the top `prefix_len` bits of `base` and `addr` are equal. The two
/// slices must be the same length (both 4 or both 16 octets); a length mismatch
/// compares only the shared prefix and is never reached for real addresses.
fn octets_match(base: &[u8], addr: &[u8], prefix_len: u8) -> bool {
    let mut bits_remaining = u32::from(prefix_len);
    for (b, a) in base.iter().zip(addr.iter()) {
        if bits_remaining == 0 {
            return true;
        }
        if bits_remaining >= 8 {
            if b != a {
                return false;
            }
            bits_remaining = bits_remaining.saturating_sub(8);
        } else {
            let mask = top_bits_mask(bits_remaining);
            return (b & mask) == (a & mask);
        }
    }
    true
}

/// A byte mask selecting the top `n` bits, for `n` in `1..=7`. Built by lookup
/// rather than by shifting, so the function shares no arithmetic that the
/// `arithmetic_side_effects` lint would flag.
const fn top_bits_mask(n: u32) -> u8 {
    match n {
        1 => 0b1000_0000,
        2 => 0b1100_0000,
        3 => 0b1110_0000,
        4 => 0b1111_0000,
        5 => 0b1111_1000,
        6 => 0b1111_1100,
        7 => 0b1111_1110,
        _ => 0b0000_0000,
    }
}

/// The destination clause of an allow rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// Match a DNS name, compared case-insensitively (ASCII). A name request
    /// matches; a literal-address request does not.
    Name(String),
    /// Match any address within a network. A literal-address request matches if
    /// the address is inside; a name request is matched only after resolution.
    Cidr(Cidr),
}

/// One allow rule (`[[net.allow]]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// What destinations this rule covers.
    pub matcher: Matcher,
    /// Permitted ports. Empty means "any port".
    pub ports: Vec<u16>,
    /// Permitted transport.
    pub protocol: RuleProtocol,
}

/// What a deny rule forbids: a network, or a domain pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyMatcher {
    /// Any address within a network. Checked against a literal-address request
    /// and against every resolved address (the rebinding defence).
    Cidr(Cidr),
    /// A domain pattern (the dot-convention of [`name_matches`]). Checked against
    /// a *name* request before resolution — a blacklisted name is refused outright
    /// in every mode, so it never reaches the resolver or the allow rules.
    Name(String),
}

/// One categorical deny rule (`[[net.deny]]`), evaluated before any allow rule.
/// A network or a domain pattern, with an optional port set (empty means "all
/// ports").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenyRule {
    /// What this rule forbids.
    pub matcher: DenyMatcher,
    /// Ports the rule applies to. Empty means all ports.
    pub ports: Vec<u16>,
}

/// The kennel's relationship to the network, as the egress proxy sees it
/// (Kennel book Vol 2 ch.8 (The Network)).
///
/// Only the proxied policy modes reach the proxy; the host-netns `open` and the no-network
/// `none` never run a delegate, so they collapse to `None` here (deny-all) — they are
/// enforced by BPF/Landlock or by having no netns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetMode {
    /// No egress through the proxy (a no-network or non-proxied kennel).
    None,
    /// Egress only to allowlisted destinations (policy `constrained`, default-deny).
    Constrained,
    /// Egress to anywhere not categorically denied (policy `unconstrained`, default-allow).
    Unconstrained,
}

/// The resolved egress allowlist the proxy enforces: a mode plus the allow and
/// deny rules. This is what `src/server.rs` consults for every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ruleset {
    /// The network mode.
    pub mode: NetMode,
    /// Allow rules (consulted only after the deny rules in `Constrained`).
    pub allow: Vec<Rule>,
    /// Categorical deny rules (consulted first, in every mode but `None`).
    pub deny: Vec<DenyRule>,
}

/// Why a request was denied. Carried into the audit record and the client-facing
/// error so a refusal is actionable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// Network mode is `none`: no egress at all.
    ModeNone,
    /// The destination matched a categorical deny rule.
    DeniedByRule,
    /// No allow rule matched (`Constrained` mode).
    NotAllowed,
}

/// The outcome of evaluating a request the proxy may connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Permitted; connect.
    Allow,
    /// Denied, with the reason.
    Deny(DenyReason),
}

/// The outcome of evaluating a client request, before any DNS resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    /// A literal-address (or otherwise fully decided) request is permitted.
    Allow,
    /// A named request is authorised by name. Resolve it under DNS policy, then
    /// re-check each resolved address with [`Ruleset::decide_resolved`].
    Resolve,
    /// Denied, with the reason.
    Deny(DenyReason),
}

impl Ruleset {
    /// Decide a request as the client presented it.
    ///
    /// For a literal address this is the final decision. For a name, a
    /// [`RequestDecision::Resolve`] means "the name is authorised; resolve it,
    /// then call [`Self::decide_resolved`] on each address".
    #[must_use]
    pub fn decide_request(
        &self,
        dest: &Destination,
        port: u16,
        transport: Transport,
    ) -> RequestDecision {
        if self.mode == NetMode::None {
            return RequestDecision::Deny(DenyReason::ModeNone);
        }
        match dest {
            // A literal address is decided in full now: deny rules first, then
            // (in constrained mode) the allow CIDRs; open mode allows anything
            // the deny rules did not catch.
            Destination::Addr(addr) => {
                if self.denied_addr(*addr, port) {
                    return RequestDecision::Deny(DenyReason::DeniedByRule);
                }
                match self.mode {
                    NetMode::Unconstrained => RequestDecision::Allow,
                    NetMode::Constrained if self.allow_addr_match(*addr, port, transport) => {
                        RequestDecision::Allow
                    }
                    _ => RequestDecision::Deny(DenyReason::NotAllowed),
                }
            }
            // A name is deny-checked against the domain blacklist first (so a
            // blacklisted name never reaches the resolver), then authorised by
            // name. Its resolved addresses are re-checked by decide_resolved
            // against the CIDR deny rules before connecting.
            Destination::Name(name) => {
                if self.name_denied(name, port) {
                    return RequestDecision::Deny(DenyReason::DeniedByRule);
                }
                match self.mode {
                    NetMode::Unconstrained => RequestDecision::Resolve,
                    NetMode::Constrained if self.allow_name_match(name, port, transport) => {
                        RequestDecision::Resolve
                    }
                    _ => RequestDecision::Deny(DenyReason::NotAllowed),
                }
            }
        }
    }

    /// Decide a single resolved address for a name that already cleared
    /// [`Self::decide_request`]. The categorical deny rules always apply here;
    /// this is the rebinding defence. The name already authorised the
    /// connection, so a resolved address that clears the deny rules is allowed.
    #[must_use]
    pub fn decide_resolved(&self, addr: IpAddr, port: u16, _transport: Transport) -> Decision {
        // Transport is accepted for API symmetry with decide_request; deny rules
        // are CIDR+port only (§7.5.4), so it does not affect the decision today.
        if self.denied_addr(addr, port) {
            Decision::Deny(DenyReason::DeniedByRule)
        } else {
            Decision::Allow
        }
    }

    /// Whether any CIDR deny rule covers `(addr, port)`. A rule with an empty port
    /// set applies to every port; name deny rules do not apply to an address.
    fn denied_addr(&self, addr: IpAddr, port: u16) -> bool {
        self.deny.iter().any(|rule| {
            matches!(&rule.matcher, DenyMatcher::Cidr(cidr) if cidr.contains(addr))
                && port_matches(&rule.ports, port)
        })
    }

    /// Whether any domain deny rule (the blacklist) covers `(name, port)`. CIDR
    /// deny rules do not apply to a name.
    fn name_denied(&self, name: &str, port: u16) -> bool {
        self.deny.iter().any(|rule| {
            matches!(&rule.matcher, DenyMatcher::Name(pattern) if name_matches(pattern, name))
                && port_matches(&rule.ports, port)
        })
    }

    /// Whether any allow rule admits a literal `(addr, port, transport)`. Only
    /// CIDR matchers apply to a literal address; name matchers never do.
    fn allow_addr_match(&self, addr: IpAddr, port: u16, transport: Transport) -> bool {
        self.allow.iter().any(|rule| {
            matches!(&rule.matcher, Matcher::Cidr(cidr) if cidr.contains(addr))
                && rule.protocol.admits(transport)
                && port_matches(&rule.ports, port)
        })
    }

    /// Whether any allow rule admits a `(name, port, transport)`. Only name
    /// matchers apply, by the dot-convention of [`name_matches`].
    fn allow_name_match(&self, name: &str, port: u16, transport: Transport) -> bool {
        self.allow.iter().any(|rule| {
            matches!(&rule.matcher, Matcher::Name(pattern) if name_matches(pattern, name))
                && rule.protocol.admits(transport)
                && port_matches(&rule.ports, port)
        })
    }
}

/// Whether a domain `pattern` matches a requested `name`, case-insensitively
/// (ASCII).
///
/// The convention follows the common no-proxy / cookie-domain form:
///
/// - A plain pattern (`example.com`) matches that name **exactly**.
/// - A leading dot (`.example.com`) matches the apex **and** any subdomain
///   (`example.com`, `api.example.com`), on a label boundary — so it does not
///   match `notexample.com`.
///
/// Exact-by-default is the safe choice for a whitelist (an allow of
/// `example.com` does not silently admit every subdomain); the leading dot is
/// the explicit opt-in, and is the natural form for a blacklist entry.
#[must_use]
pub fn name_matches(pattern: &str, name: &str) -> bool {
    pattern.strip_prefix('.').map_or_else(
        || pattern.eq_ignore_ascii_case(name),
        |apex| name.eq_ignore_ascii_case(apex) || ends_with_label(name, pattern),
    )
}

/// Whether `name` ends with the dotted `suffix` (e.g. `.example.com`) on a label
/// boundary, case-insensitively. `suffix` includes its leading dot, so the match
/// is inherently label-aligned.
fn ends_with_label(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len()
        && name
            .get(name.len().saturating_sub(suffix.len())..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// Whether `port` is permitted by a rule's port set. An empty set means "any
/// port" (Kennel book Vol 2 ch.8 (The Network) omits `ports` for portless rules).
fn port_matches(ports: &[u16], port: u16) -> bool {
    ports.is_empty() || ports.contains(&port)
}

// The special-use classification lives in `kennel_lib_policy::netaddr` so the TCP CONNECT decision
// here and the UDP flow dial in the tun broker share ONE definition (a drift between them would be a
// rebinding hole). Re-exported so this module's callers and tests are unchanged.
pub use kennel_lib_policy::netaddr::is_special_use;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("v4 literal"))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().expect("v6 literal"))
    }

    fn cidr(addr: &str, prefix: u8) -> Cidr {
        Cidr::new(addr.parse::<IpAddr>().expect("addr literal"), prefix).expect("valid cidr")
    }

    // ---- is_special_use ----

    #[test]
    fn special_use_v4_ranges() {
        for s in [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ] {
            assert!(is_special_use(v4(s)), "{s} should be special-use");
        }
    }

    #[test]
    fn public_v4_is_not_special_use() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
        ] {
            assert!(!is_special_use(v4(s)), "{s} should be public");
        }
    }

    #[test]
    fn special_use_v6_ranges() {
        for s in ["::1", "::", "fd00::1", "fc00::1", "fe80::1", "ff02::1"] {
            assert!(is_special_use(v6(s)), "{s} should be special-use");
        }
    }

    #[test]
    fn public_v6_is_not_special_use() {
        // A global unicast address and a Quad9/Cloudflare-style public resolver.
        for s in ["2606:4700:4700::1111", "2620:fe::fe"] {
            assert!(!is_special_use(v6(s)), "{s} should be public");
        }
    }

    // ---- Cidr (structure) ----

    #[test]
    fn cidr_rejects_overlong_prefix() {
        assert_eq!(
            Cidr::new(v4("10.0.0.0"), 33),
            Err(PrefixTooLong { max: 32, got: 33 })
        );
        assert_eq!(
            Cidr::new(v6("fd00::"), 129),
            Err(PrefixTooLong { max: 128, got: 129 })
        );
    }

    #[test]
    fn cidr_accepts_boundary_prefixes() {
        assert!(Cidr::new(v4("10.0.0.0"), 32).is_ok());
        assert!(Cidr::new(v4("0.0.0.0"), 0).is_ok());
        assert!(Cidr::new(v6("fd00::"), 128).is_ok());
    }

    #[test]
    fn cidr_v4_contains_within_and_excludes_outside() {
        let net = cidr("10.1.2.0", 24);
        assert!(net.contains(v4("10.1.2.0")));
        assert!(net.contains(v4("10.1.2.255")));
        assert!(!net.contains(v4("10.1.3.0")));
        assert!(!net.contains(v4("10.1.1.255")));
    }

    #[test]
    fn cidr_host_route_matches_only_itself() {
        let net = cidr("169.254.169.254", 32);
        assert!(net.contains(v4("169.254.169.254")));
        assert!(!net.contains(v4("169.254.169.253")));
    }

    #[test]
    fn cidr_default_route_matches_everything_in_family() {
        let net = cidr("0.0.0.0", 0);
        assert!(net.contains(v4("8.8.8.8")));
        assert!(net.contains(v4("192.168.0.1")));
        // ...but not the other family.
        assert!(!net.contains(v6("fd00::1")));
    }

    #[test]
    fn cidr_v6_prefix_matches() {
        let net = cidr("fd00:ec2::", 32);
        assert!(net.contains(v6("fd00:ec2::254")));
        assert!(!net.contains(v6("fd00:ec3::1")));
    }

    #[test]
    fn cidr_family_mismatch_never_matches() {
        assert!(!cidr("10.0.0.0", 8).contains(v6("fd00::1")));
        assert!(!cidr("fd00::", 8).contains(v4("10.0.0.1")));
    }

    // ---- helpers to build a ruleset ----

    fn name_rule(name: &str, ports: &[u16]) -> Rule {
        Rule {
            matcher: Matcher::Name(name.to_owned()),
            ports: ports.to_vec(),
            protocol: RuleProtocol::Tcp,
        }
    }

    fn cidr_rule(addr: &str, prefix: u8, ports: &[u16]) -> Rule {
        Rule {
            matcher: Matcher::Cidr(cidr(addr, prefix)),
            ports: ports.to_vec(),
            protocol: RuleProtocol::Tcp,
        }
    }

    fn deny(addr: &str, prefix: u8) -> DenyRule {
        DenyRule {
            matcher: DenyMatcher::Cidr(cidr(addr, prefix)),
            ports: Vec::new(),
        }
    }

    fn deny_name(pattern: &str) -> DenyRule {
        DenyRule {
            matcher: DenyMatcher::Name(pattern.to_owned()),
            ports: Vec::new(),
        }
    }

    const METADATA: &str = "169.254.169.254";

    // ---- mode none ----

    #[test]
    fn mode_none_denies_a_name() {
        let rs = Ruleset {
            mode: NetMode::None,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.openai.com".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Deny(DenyReason::ModeNone)
        );
    }

    #[test]
    fn mode_none_denies_a_literal_address() {
        let rs = Ruleset {
            mode: NetMode::None,
            allow: vec![],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("8.8.8.8")), 443, Transport::Tcp),
            RequestDecision::Deny(DenyReason::ModeNone)
        );
    }

    // ---- constrained ----

    #[test]
    fn constrained_allowlisted_name_resolves() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.openai.com".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    #[test]
    fn constrained_name_match_is_case_insensitive() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("API.OpenAI.COM".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    #[test]
    fn constrained_unlisted_name_denied() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("evil.example".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn constrained_name_wrong_port_denied() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.openai.com".to_owned()),
                8080,
                Transport::Tcp
            ),
            RequestDecision::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn constrained_name_wrong_protocol_denied() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.openai.com".to_owned()),
                443,
                Transport::Udp
            ),
            RequestDecision::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn constrained_empty_ports_means_any_port() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("git.example", &[])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("git.example".to_owned()),
                22,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    #[test]
    fn constrained_literal_in_allow_cidr_is_allowed() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![cidr_rule("10.0.0.0", 24, &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("10.0.0.5")), 443, Transport::Tcp),
            RequestDecision::Allow
        );
    }

    #[test]
    fn constrained_literal_outside_allow_cidr_denied() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![cidr_rule("10.0.0.0", 24, &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("10.0.1.5")), 443, Transport::Tcp),
            RequestDecision::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn constrained_literal_name_rule_does_not_match_an_address() {
        // A name rule must not authorise a literal-address request.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("8.8.8.8")), 443, Transport::Tcp),
            RequestDecision::Deny(DenyReason::NotAllowed)
        );
    }

    // ---- deny-before-allow ----

    #[test]
    fn deny_overrides_allow_for_a_literal_address() {
        // The same /24 is both allowed and (more specifically) denied.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![cidr_rule("10.0.0.0", 24, &[443])],
            deny: vec![deny("10.0.0.254", 32)],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("10.0.0.254")), 443, Transport::Tcp),
            RequestDecision::Deny(DenyReason::DeniedByRule)
        );
        // a sibling address in the allow range, not denied, still allowed.
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("10.0.0.5")), 443, Transport::Tcp),
            RequestDecision::Allow
        );
    }

    // ---- open ----

    #[test]
    fn open_allows_an_undenied_literal() {
        let rs = Ruleset {
            mode: NetMode::Unconstrained,
            allow: vec![],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("8.8.8.8")), 443, Transport::Tcp),
            RequestDecision::Allow
        );
    }

    #[test]
    fn open_denies_a_denied_literal() {
        let rs = Ruleset {
            mode: NetMode::Unconstrained,
            allow: vec![],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4(METADATA)), 80, Transport::Tcp),
            RequestDecision::Deny(DenyReason::DeniedByRule)
        );
    }

    #[test]
    fn open_name_resolves() {
        let rs = Ruleset {
            mode: NetMode::Unconstrained,
            allow: vec![],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("anything.example".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    // ---- name_matches (the dot-convention) ----

    #[test]
    fn plain_pattern_matches_exactly_only() {
        assert!(name_matches("example.com", "example.com"));
        assert!(
            name_matches("example.com", "EXAMPLE.COM"),
            "case-insensitive"
        );
        assert!(
            !name_matches("example.com", "api.example.com"),
            "no implicit subdomain"
        );
        assert!(!name_matches("example.com", "notexample.com"));
    }

    #[test]
    fn dotted_pattern_matches_apex_and_subdomains_on_a_label_boundary() {
        assert!(name_matches(".example.com", "example.com"), "apex");
        assert!(name_matches(".example.com", "api.example.com"), "subdomain");
        assert!(
            name_matches(".example.com", "a.b.example.com"),
            "deep subdomain"
        );
        assert!(
            !name_matches(".example.com", "notexample.com"),
            "label boundary"
        );
        assert!(!name_matches(".example.com", "example.com.evil.net"));
    }

    // ---- domain blacklist (name deny) ----

    #[test]
    fn open_mode_blacklisted_name_is_denied() {
        let rs = Ruleset {
            mode: NetMode::Unconstrained,
            allow: vec![],
            deny: vec![deny_name(".tracker.example")],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("a.tracker.example".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Deny(DenyReason::DeniedByRule)
        );
        // A name outside the blacklist still resolves in open mode.
        assert_eq!(
            rs.decide_request(
                &Destination::Name("good.example".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    #[test]
    fn blacklist_overrides_allowlist_in_constrained_mode() {
        // The name is on the allowlist but also blacklisted: deny wins, and it is
        // refused before any resolution.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.example.com", &[443])],
            deny: vec![deny_name("api.example.com")],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.example.com".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Deny(DenyReason::DeniedByRule)
        );
    }

    #[test]
    fn name_deny_does_not_affect_a_literal_address() {
        // A domain blacklist entry must not match a literal-address request.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![cidr_rule("10.0.0.0", 24, &[443])],
            deny: vec![deny_name(".example.com")],
        };
        assert_eq!(
            rs.decide_request(&Destination::Addr(v4("10.0.0.5")), 443, Transport::Tcp),
            RequestDecision::Allow
        );
    }

    #[test]
    fn dotted_allow_admits_subdomains() {
        // A whitelist entry with a leading dot admits the apex and subdomains.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule(".example.com", &[443])],
            deny: vec![],
        };
        assert_eq!(
            rs.decide_request(
                &Destination::Name("api.example.com".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
        assert_eq!(
            rs.decide_request(
                &Destination::Name("example.com".to_owned()),
                443,
                Transport::Tcp
            ),
            RequestDecision::Resolve
        );
    }

    // ---- decide_resolved (the rebinding defence) ----

    #[test]
    fn resolved_address_passing_deny_is_allowed() {
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_resolved(v4("203.0.113.5"), 443, Transport::Tcp),
            Decision::Allow
        );
    }

    #[test]
    fn resolved_metadata_address_is_denied_even_for_an_allowed_name() {
        // The name cleared decide_request, but it resolved to a denied address.
        let rs = Ruleset {
            mode: NetMode::Constrained,
            allow: vec![name_rule("api.openai.com", &[443])],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_resolved(v4(METADATA), 443, Transport::Tcp),
            Decision::Deny(DenyReason::DeniedByRule)
        );
    }

    #[test]
    fn resolved_address_in_open_mode_only_checks_deny() {
        let rs = Ruleset {
            mode: NetMode::Unconstrained,
            allow: vec![],
            deny: vec![deny(METADATA, 32)],
        };
        assert_eq!(
            rs.decide_resolved(v4("8.8.8.8"), 443, Transport::Tcp),
            Decision::Allow
        );
        assert_eq!(
            rs.decide_resolved(v4(METADATA), 80, Transport::Tcp),
            Decision::Deny(DenyReason::DeniedByRule)
        );
    }
}
