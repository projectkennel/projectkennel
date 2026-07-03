//! The broker's flow gate (W2 Part D): re-vet a resolved address, then dial its connected socket.
//!
//! The forwarder's [`route`](crate::forward::route) turned an egress frame into a `(name, port)` it
//! is permitted to reach. This is the second half of "resolve-check-pin-dial host-side": resolve the
//! real name on the host, **re-check** each answer against the categorical deny CIDRs and non-public
//! space (the rebinding / SSRF defence — a permitted name that resolves inward is still refused),
//! and connect a UDP socket to the first address that clears. The connect pins the peer: the kernel
//! then drops any datagram not from it, so a compromised resolver cannot redirect a live flow, and
//! DNS rebinding is closed at the socket, not merely at the answer.
//!
//! The check-then-resolve ordering is load-bearing: the port allow-check ([`Allowlist::allows`])
//! runs **before** any resolution, and the deny re-check runs **after**, on the concrete address —
//! the invariant denies can never be compiled away, so this re-vet is the broker's own gate, not a
//! restatement of the compiler's.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

use kennel_lib_policy::settled::{NetPolicy, NetRule, Protocol};
use kennel_lib_policy::{is_special_use, Cidr};

use crate::shim::Allowlist;

/// The resolved-address deny set: the categorical CIDRs a dialled address must clear.
///
/// Built from the settled invariant denies (`deny_invariant` — cloud metadata, link-local,
/// `RFC1918`, never removable) and the author denylist (`deny_author`), the same deny-first CIDRs the egress
/// proxy re-checks. A resolved address is refused if it falls in any of them **or** in special-use
/// space ([`is_special_use`], the rebinding backstop) — the broker is fail-closed on a name that
/// resolves into non-public space, with no private-address opt-in in this cut.
pub struct DenyList {
    rules: Vec<DenyCidr>,
}

/// One parsed deny CIDR with its port range (host order); an empty policy range is the full range.
struct DenyCidr {
    cidr: Cidr,
    port_min: u16,
    port_max: u16,
}

impl DenyList {
    /// Build the deny set from a settled net policy: the invariant denies plus the author denylist,
    /// keeping only UDP-applicable rules (protocol `udp` or `any`). A rule whose CIDR does not parse
    /// is dropped — it can only ever *fail to deny*, and the invariant denies are compiler-produced,
    /// so an unparseable one is a compile bug, not a runtime opening.
    #[must_use]
    pub fn from_settled(net: &NetPolicy) -> Self {
        Self::from_rules(net.deny_invariant.iter().chain(&net.deny_author))
    }

    /// The primitive [`from_settled`](Self::from_settled) builds on: parse each UDP-applicable rule
    /// into a [`DenyCidr`].
    fn from_rules<'r>(rules: impl Iterator<Item = &'r NetRule>) -> Self {
        let rules = rules
            .filter(|r| admits_udp(r.protocol))
            .filter_map(|r| {
                let base = r.cidr.parse::<IpAddr>().ok()?;
                let cidr = Cidr::new(base, r.prefix_len).ok()?;
                Some(DenyCidr {
                    cidr,
                    port_min: r.port_min,
                    port_max: r.port_max,
                })
            })
            .collect();
        Self { rules }
    }

    /// Whether `(addr, port)` is denied: in special-use space, or covered by a deny CIDR whose port
    /// range includes `port`.
    #[must_use]
    pub fn denied(&self, addr: IpAddr, port: u16) -> bool {
        is_special_use(addr)
            || self
                .rules
                .iter()
                .any(|r| r.cidr.contains(addr) && port >= r.port_min && port <= r.port_max)
    }
}

/// Whether a deny/allow rule's protocol applies to a UDP flow.
const fn admits_udp(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Udp | Protocol::Any)
}

/// Why a flow could not be dialled.
#[derive(Debug)]
pub enum FlowError {
    /// `(name, port)` is not covered by any UDP grant — the flow-time allow-check failed. The caller
    /// answers `ICMPv6` admin-prohibited.
    NotAllowed,
    /// The name resolved to no addresses at all.
    Unresolved,
    /// Every resolved address was denied (rebinding into denied / non-public space). The caller
    /// answers `ICMPv6` admin-prohibited.
    Denied,
    /// Host resolution (`getaddrinfo`) failed.
    Resolve(io::Error),
    /// A vetted address was chosen but the connected socket could not be opened.
    Dial(io::Error),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => write!(f, "destination not permitted by any UDP grant"),
            Self::Unresolved => write!(f, "name resolved to no addresses"),
            Self::Denied => write!(f, "every resolved address is in denied or non-public space"),
            Self::Resolve(e) => write!(f, "resolution failed: {e}"),
            Self::Dial(e) => write!(f, "dial failed: {e}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Resolve `name`, keep the addresses that clear `deny`, and connect a UDP socket to the first — the
/// flow's dedicated connected socket (the kernel then filters the return path to the pinned peer).
///
/// `(name, port)` is allow-checked **before** resolution; the deny re-check runs **after**, on each
/// concrete answer.
///
/// # Errors
///
/// [`FlowError`]: `NotAllowed` if the grant does not cover `(name, port)`; `Resolve` if
/// `getaddrinfo` errors; `Unresolved` / `Denied` if nothing resolved or nothing cleared the deny
/// set; `Dial` if the connected socket cannot be opened.
pub fn dial(
    allow: &Allowlist,
    deny: &DenyList,
    name: &str,
    port: u16,
) -> Result<UdpSocket, FlowError> {
    if !allow.allows(name, port) {
        return Err(FlowError::NotAllowed);
    }
    let resolved: Vec<SocketAddr> = (name, port)
        .to_socket_addrs()
        .map_err(FlowError::Resolve)?
        .collect();
    let vetted = vet(&resolved, deny);
    if vetted.is_empty() {
        return Err(if resolved.is_empty() {
            FlowError::Unresolved
        } else {
            FlowError::Denied
        });
    }
    let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
    for peer in vetted {
        match connect_udp(peer) {
            Ok(sock) => return Ok(sock),
            Err(e) => last = e,
        }
    }
    Err(FlowError::Dial(last))
}

/// Keep only the resolved addresses that clear the deny set.
fn vet(addrs: &[SocketAddr], deny: &DenyList) -> Vec<SocketAddr> {
    addrs
        .iter()
        .copied()
        .filter(|sa| !deny.denied(sa.ip(), sa.port()))
        .collect()
}

/// Bind an ephemeral socket in `peer`'s family and connect it, pinning `peer` as the sole peer.
fn connect_udp(peer: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(peer)?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().expect("v4")
    }

    fn deny_rule(cidr: &str, prefix_len: u8, port_min: u16, port_max: u16) -> NetRule {
        NetRule {
            cidr: cidr.to_owned(),
            prefix_len,
            port_min,
            port_max,
            protocol: Protocol::Any,
        }
    }

    fn grant(name: &str, ports: &[u16]) -> kennel_lib_policy::settled::NameRule {
        kennel_lib_policy::settled::NameRule {
            name: name.to_owned(),
            ports: ports.to_vec(),
            protocol: Protocol::Udp,
        }
    }

    #[test]
    fn special_use_is_always_denied_even_with_no_rules() {
        let deny = DenyList::from_rules([].iter());
        assert!(deny.denied(v4("10.0.0.1"), 53), "RFC1918 is non-public");
        assert!(
            deny.denied(v4("169.254.169.254"), 80),
            "link-local metadata"
        );
        assert!(
            !deny.denied(v4("93.184.216.34"), 443),
            "a public address clears"
        );
    }

    #[test]
    fn a_public_address_in_a_deny_cidr_is_denied_on_its_ports() {
        let rules = [deny_rule("93.184.216.0", 24, 0, 65535)];
        let deny = DenyList::from_rules(rules.iter());
        assert!(
            deny.denied(v4("93.184.216.34"), 443),
            "inside the deny CIDR"
        );
        assert!(!deny.denied(v4("8.8.8.8"), 443), "outside the deny CIDR");
    }

    #[test]
    fn a_deny_rule_port_range_is_respected() {
        let rules = [deny_rule("93.184.216.0", 24, 80, 80)];
        let deny = DenyList::from_rules(rules.iter());
        assert!(
            deny.denied(v4("93.184.216.34"), 80),
            "port in the deny range"
        );
        assert!(
            !deny.denied(v4("93.184.216.34"), 443),
            "port outside the deny range"
        );
    }

    #[test]
    fn a_tcp_only_deny_rule_does_not_apply_to_udp() {
        let rules = [NetRule {
            cidr: "93.184.216.0".to_owned(),
            prefix_len: 24,
            port_min: 0,
            port_max: 65535,
            protocol: Protocol::Tcp,
        }];
        let deny = DenyList::from_rules(rules.iter());
        assert!(
            !deny.denied(v4("93.184.216.34"), 443),
            "a TCP-only deny is not a UDP deny"
        );
    }

    #[test]
    fn vet_drops_denied_and_keeps_cleared() {
        let deny = DenyList::from_rules([].iter());
        let addrs = [
            "93.184.216.34:443".parse().expect("addr"), // public → kept
            "10.0.0.5:443".parse().expect("addr"),      // private → dropped
        ];
        let kept = vet(&addrs, &deny);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept.first().map(SocketAddr::ip), Some(v4("93.184.216.34")));
    }

    #[test]
    fn dial_refuses_a_destination_no_grant_covers_before_resolving() {
        // No grant for this name → NotAllowed, and no resolution is attempted (the literal is never
        // looked up). Offline-safe: the allow-check short-circuits.
        let allow = Allowlist::new([grant("example.com", &[443])]);
        let deny = DenyList::from_rules([].iter());
        let err = dial(&allow, &deny, "8.8.8.8", 53).expect_err("not granted");
        assert!(matches!(err, FlowError::NotAllowed), "got {err:?}");
    }

    #[test]
    fn dial_denies_a_granted_name_that_resolves_into_non_public_space() {
        // "10.0.0.1" is a granted name that resolves (as a literal, no DNS) to RFC1918 space, which
        // the deny re-check refuses — the rebinding shape, exercised without a network.
        let allow = Allowlist::new([grant("10.0.0.1", &[53])]);
        let deny = DenyList::from_rules([].iter());
        let err = dial(&allow, &deny, "10.0.0.1", 53).expect_err("resolves inward");
        assert!(matches!(err, FlowError::Denied), "got {err:?}");
    }

    #[test]
    fn a_connected_socket_pins_its_peer() {
        // Connecting to loopback sends nothing (UDP connect is local) and always succeeds; the pin
        // is observable as the socket's peer address.
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let sock = connect_udp(peer).expect("connect");
        assert_eq!(sock.peer_addr().expect("peer"), peer);
    }

    #[test]
    fn allowlist_ports_gate_the_flow_check() {
        let allow = Allowlist::new([grant("example.com", &[443])]);
        assert!(allow.allows("example.com", 443));
        assert!(!allow.allows("example.com", 53), "port not in the grant");
        assert!(!allow.allows("other.test", 443), "name not granted");
    }
}
