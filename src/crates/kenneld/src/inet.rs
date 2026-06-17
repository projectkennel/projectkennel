//! The `INet` egress decision: kenneld as the policy decision point for outbound
//! connections (`docs/design/07-5-network.md` §7.5.2).
//!
//! `facade-socks5` (inside the kennel) transacts a [`verb::CONNECT_INET`] request to node 0;
//! kenneld decides it here against the signed policy's [`Ruleset`] ([`allow`]), resolves the name
//! under policy ([`dns`]), re-checks every resolved address, and **pins** the vetted set. The pinned
//! address never crosses back into the kennel (the kennel holds only a name), so DNS rebinding is
//! structurally impossible. Approved, kenneld mints a socketpair, hands the dial delegate one end
//! plus the pinned address, and returns the other end into the kennel over binder.
//!
//! [`verb::CONNECT_INET`]: kennel_lib_binder::service::verb::CONNECT_INET

pub mod allow;
pub mod dns;

use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use kennel_lib_binder::service::transport;
use kennel_lib_policy::{NameRule, NetPolicy, NetRule, Protocol};

use allow::{
    is_special_use, Cidr, Decision, DenyMatcher, DenyRule, Destination, Matcher, NetMode,
    RequestDecision, Rule, RuleProtocol, Ruleset, Transport,
};
use dns::Resolver;

/// The egress policy inputs for the `INet` decision.
#[derive(Clone, Debug)]
pub struct NetRuntime {
    /// The resolved egress allow/deny ruleset.
    ruleset: Ruleset,
    /// Whether a name may connect to a resolved special-use (private/loopback) address.
    accept_private_resolved: bool,
    /// Sanctioned host-loopback services: exact `addr:port` literals reachable despite the
    /// host-loopback invariant deny (the SSH bastion, §7.10.4).
    host_services: Vec<SocketAddr>,
    /// The per-kennel `kenneld`↔delegate command socket the conduit dial is driven over (the path
    /// the dial delegate binds). `None` when the kennel runs no egress delegate.
    command_socket: Option<PathBuf>,
}

impl NetRuntime {
    /// Build the decision runtime directly from the signed policy's [`NetPolicy`].
    ///
    /// The allowlist is the union of the by-address (`net.allow`) and by-name (`net.allow_names`)
    /// rules; the denylist is the invariant deny CIDRs, re-checked against every resolved address.
    /// `host_services` are the sanctioned host-loopback literals; `command_socket` is the delegate's
    /// dial socket. `accept_private_resolved` is `false` — a name may not resolve into special-use
    /// space.
    #[must_use]
    pub fn from_policy(
        net: &NetPolicy,
        host_services: Vec<SocketAddr>,
        command_socket: Option<PathBuf>,
    ) -> Self {
        let mut allow: Vec<Rule> = net.allow.iter().filter_map(rule_from_cidr).collect();
        allow.extend(net.allow_names.iter().map(rule_from_name));
        // Deny-first: the non-removable invariant floor PLUS the author's optional
        // `[net.proxy].deny.policy` (`deny_author`). Both are re-checked against every resolved
        // address, so a name that resolves into denied space is refused even in `unconstrained`.
        let deny: Vec<DenyRule> = net
            .deny_invariant
            .iter()
            .chain(net.deny_author.iter())
            .filter_map(deny_from_cidr)
            .collect();
        Self {
            ruleset: Ruleset {
                mode: net_mode(net.mode),
                allow,
                deny,
            },
            accept_private_resolved: false,
            host_services,
            command_socket,
        }
    }

    /// The conduit command socket, if the kennel has an egress delegate.
    #[must_use]
    pub fn command_socket(&self) -> Option<&Path> {
        self.command_socket.as_deref()
    }

    /// A deny-all runtime (network mode `none`): every `INet` request is refused. Used when the
    /// kennel runs no egress proxy.
    #[must_use]
    pub const fn denied() -> Self {
        Self {
            ruleset: Ruleset {
                mode: NetMode::None,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            accept_private_resolved: false,
            host_services: Vec::new(),
            command_socket: None,
        }
    }

    /// Whether `addr:port` is a sanctioned host-loopback service (an exact literal match).
    fn is_host_service(&self, addr: IpAddr, port: u16) -> bool {
        self.host_services
            .iter()
            .any(|s| s.ip() == addr && s.port() == port)
    }
}

/// Map a policy net mode to the proxy-runtime mode. Only the proxied policy modes
/// (`constrained`/`unconstrained`) run a delegate that consults this; `none` (no network)
/// and `host` (host-netns, direct, BPF/Landlock-enforced) never reach the proxy, so they
/// collapse to `None` (deny-all) defensively.
const fn net_mode(mode: kennel_lib_policy::NetMode) -> NetMode {
    match mode {
        kennel_lib_policy::NetMode::Constrained => NetMode::Constrained,
        kennel_lib_policy::NetMode::Unconstrained => NetMode::Unconstrained,
        kennel_lib_policy::NetMode::None | kennel_lib_policy::NetMode::Host => NetMode::None,
    }
}

const fn rule_protocol(protocol: Protocol) -> RuleProtocol {
    match protocol {
        Protocol::Any => RuleProtocol::Any,
        Protocol::Tcp => RuleProtocol::Tcp,
        Protocol::Udp => RuleProtocol::Udp,
    }
}

/// A port *range* as the ruleset's discrete port set: the full range is "any port" (empty); a
/// single port is `[p]`; a sub-range is enumerated.
fn ports_for(port_min: u16, port_max: u16) -> Vec<u16> {
    if port_min == 0 && port_max == u16::MAX {
        Vec::new()
    } else {
        (port_min..=port_max).collect()
    }
}

fn rule_from_cidr(rule: &NetRule) -> Option<Rule> {
    Some(Rule {
        matcher: Matcher::Cidr(cidr_of(rule)?),
        ports: ports_for(rule.port_min, rule.port_max),
        protocol: rule_protocol(rule.protocol),
    })
}

fn rule_from_name(rule: &NameRule) -> Rule {
    Rule {
        matcher: Matcher::Name(rule.name.clone()),
        ports: rule.ports.clone(),
        protocol: rule_protocol(rule.protocol),
    }
}

fn deny_from_cidr(rule: &NetRule) -> Option<DenyRule> {
    Some(DenyRule {
        matcher: DenyMatcher::Cidr(cidr_of(rule)?),
        ports: ports_for(rule.port_min, rule.port_max),
    })
}

/// A policy CIDR (`cidr` literal + `prefix_len`) as a ruleset [`Cidr`], or `None` if the literal
/// does not parse (a malformed signed policy — dropped rather than admitting a wrong match).
fn cidr_of(rule: &NetRule) -> Option<Cidr> {
    Cidr::new(rule.cidr.parse::<IpAddr>().ok()?, rule.prefix_len).ok()
}

/// The outcome of an `INet` decision. `Pinned` carries the vetted address set (in resolver order)
/// the dial may use; the kennel never sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InetDecision {
    /// Approved: dial one of these vetted, pinned addresses (each already cleared the deny rules
    /// and the special-use gate).
    Pinned(Vec<IpAddr>),
    /// Refused by policy.
    Denied,
    /// Authorised but unusable: the name did not resolve, or no resolved address cleared the
    /// re-check.
    Unreachable,
}

/// Decode a [`verb::CONNECT_INET`] payload: `[transport: u8 | port: u16 big-endian | host: UTF-8]`.
/// `None` for a short, unknown-transport, empty/oversized, or non-UTF-8 payload (all untrusted).
///
/// [`verb::CONNECT_INET`]: kennel_lib_binder::service::verb::CONNECT_INET
#[must_use]
pub fn decode_request(data: &[u8], max_host: usize) -> Option<(Transport, u16, Destination)> {
    // The byte layout is the shared node-0 convention; map its raw output to the policy types.
    let (transport_byte, port, host) =
        kennel_lib_binder::service::inet::decode_request(data, max_host)?;
    let transport = match transport_byte {
        transport::TCP => Transport::Tcp,
        transport::UDP => Transport::Udp,
        _ => return None,
    };
    // A literal address is decided as-is; anything else is a name to resolve under policy.
    let dest = host
        .parse::<IpAddr>()
        .map_or_else(|_| Destination::Name(host.to_owned()), Destination::Addr);
    Some((transport, port, dest))
}

/// Decide an `INet` request, **pinning** the vetted addresses instead of dialling.
///
/// The host-service exception first (an exact loopback literal), then `decide_request`, then (for a
/// name) resolve + per-address `decide_resolved` + the special-use gate. The dial itself is the
/// delegate's job ([`dial_via_delegate`]).
#[must_use]
pub fn decide(
    rt: &NetRuntime,
    resolver: &dyn Resolver,
    dest: &Destination,
    port: u16,
    transport: Transport,
) -> InetDecision {
    // Sanctioned host-loopback services are an explicit allow-exception, checked ahead of the
    // ruleset's deny-before-allow (a literal bastion address would be caught by the host-loopback
    // invariant deny). Only an exact literal addr:port qualifies — never a name.
    if let Destination::Addr(addr) = dest {
        if rt.is_host_service(*addr, port) {
            return InetDecision::Pinned(vec![*addr]);
        }
        // A literal special-use address (loopback, ULA, RFC1918, link-local, …) is refused
        // here, mirroring the resolved-name gate below. This closes the by-address path the
        // ruleset alone would admit (an `unconstrained` mode, or a by-address `[net.allow]`):
        // without it a workload could egress-dial a per-kennel inbound-mirror alias
        // (`127.<tag>.<ctx>.x` / `fd<gid>:<tag>:<ctx>::`, §7.5.7) — looping a host-side *inbound*
        // mirror port back into egress, and reaching a *sibling* kennel's alias is cross-kennel
        // lateral movement across the net-ns boundary the mirror is meant to respect. The SSH
        // bastion is the one sanctioned host-loopback literal and was already returned above.
        if !rt.accept_private_resolved && is_special_use(*addr) {
            return InetDecision::Denied;
        }
    }
    match rt.ruleset.decide_request(dest, port, transport) {
        RequestDecision::Deny(_) => InetDecision::Denied,
        // decide_request only yields Allow for a literal address.
        RequestDecision::Allow => match dest {
            Destination::Addr(addr) => InetDecision::Pinned(vec![*addr]),
            Destination::Name(_) => InetDecision::Unreachable,
        },
        // decide_request only yields Resolve for a name.
        RequestDecision::Resolve => match dest {
            Destination::Name(name) => {
                let Ok(addrs) = resolver.resolve(name) else {
                    return InetDecision::Unreachable;
                };
                let pinned: Vec<IpAddr> = addrs
                    .into_iter()
                    .filter(|addr| {
                        rt.ruleset.decide_resolved(*addr, port, transport) == Decision::Allow
                            && (rt.accept_private_resolved || !is_special_use(*addr))
                    })
                    .collect();
                if pinned.is_empty() {
                    InetDecision::Unreachable
                } else {
                    InetDecision::Pinned(pinned)
                }
            }
            Destination::Addr(_) => InetDecision::Unreachable,
        },
    }
}

/// Drive the conduit dial, returning the kennel-facing socketpair end for the binder reply.
///
/// Mint the socketpair, hand the delegate one end plus the pinned addresses over its command
/// socket, and return the other end. The delegate dials a pinned address and splices its end to the
/// upstream; kenneld touches no payload byte and never re-enters the data path.
///
/// # Errors
///
/// The OS error if the socketpair, the connect to the delegate, or the command send fails.
pub fn dial_via_delegate(
    command_socket: &Path,
    port: u16,
    pinned: &[IpAddr],
) -> io::Result<UnixStream> {
    let (delegate_end, kennel_end) = UnixStream::pair()?;
    let command = UnixStream::connect(command_socket)?;
    let payload = kennel_host_delegate::netproxy::conduit::encode_command(port, pinned);
    kennel_lib_syscall::scm::send_with_fds(command.as_fd(), &payload, &[delegate_end.as_fd()])?;
    // `delegate_end` drops here; the delegate holds its received copy via SCM_RIGHTS.
    Ok(kennel_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::ResolveError;
    use std::net::Ipv4Addr;

    /// A resolver that returns a fixed answer (or an error), so the decision is exercised without
    /// the OS resolver.
    struct FakeResolver(Result<Vec<IpAddr>, ()>);
    impl Resolver for FakeResolver {
        fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            self.0.clone().map_err(|()| ResolveError::NotFound)
        }
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("v4"))
    }

    fn constrained(name: &str) -> NetRuntime {
        NetRuntime {
            ruleset: Ruleset {
                mode: NetMode::Constrained,
                allow: vec![Rule {
                    matcher: Matcher::Name(name.to_owned()),
                    ports: Vec::new(),
                    protocol: RuleProtocol::Tcp,
                }],
                deny: Vec::new(),
            },
            accept_private_resolved: false,
            host_services: Vec::new(),
            command_socket: None,
        }
    }

    #[test]
    fn decodes_a_well_formed_name_request() {
        // tcp, port 443, "api.openai.com"
        let mut data = vec![transport::TCP, 0x01, 0xBB];
        data.extend_from_slice(b"api.openai.com");
        let (t, port, dest) = decode_request(&data, 255).expect("decode");
        assert_eq!(t, Transport::Tcp);
        assert_eq!(port, 443);
        assert_eq!(dest, Destination::Name("api.openai.com".to_owned()));
    }

    #[test]
    fn decodes_a_literal_address_as_addr() {
        let mut data = vec![transport::TCP, 0x00, 0x50];
        data.extend_from_slice(b"8.8.8.8");
        let (_, port, dest) = decode_request(&data, 255).expect("decode");
        assert_eq!(port, 80);
        assert_eq!(dest, Destination::Addr(v4("8.8.8.8")));
    }

    #[test]
    fn rejects_short_unknown_transport_oversized_and_non_utf8() {
        assert!(decode_request(&[transport::TCP, 0x01], 255).is_none()); // short
        assert!(decode_request(&[9, 0x01, 0xBB, b'x'], 255).is_none()); // unknown transport
        assert!(decode_request(&[transport::TCP, 0x01, 0xBB], 255).is_none()); // empty host
        assert!(decode_request(&[transport::TCP, 0x01, 0xBB, b'a', b'a'], 1).is_none()); // oversized
        assert!(decode_request(&[transport::TCP, 0x01, 0xBB, 0xFF, 0xFE], 255).is_none());
        // !utf8
    }

    #[test]
    fn allowed_name_pins_the_vetted_resolved_addresses() {
        let rt = constrained("api.openai.com");
        // Genuinely public addresses (TEST-NET ranges are special-use and would be dropped).
        let resolver = FakeResolver(Ok(vec![v4("93.184.216.34"), v4("93.184.216.35")]));
        let dest = Destination::Name("api.openai.com".to_owned());
        assert_eq!(
            decide(&rt, &resolver, &dest, 443, Transport::Tcp),
            InetDecision::Pinned(vec![v4("93.184.216.34"), v4("93.184.216.35")])
        );
    }

    #[test]
    fn unallowed_name_is_denied_before_resolving() {
        let rt = constrained("api.openai.com");
        let resolver = FakeResolver(Err(())); // must not be consulted
        let dest = Destination::Name("evil.example".to_owned());
        assert_eq!(
            decide(&rt, &resolver, &dest, 443, Transport::Tcp),
            InetDecision::Denied
        );
    }

    #[test]
    fn rebinding_into_private_space_is_caught_at_the_resolved_recheck() {
        // The name clears the allowlist, but resolves into RFC1918 — refused (no accept_private).
        let rt = constrained("api.openai.com");
        let resolver = FakeResolver(Ok(vec![v4("10.0.0.5")]));
        let dest = Destination::Name("api.openai.com".to_owned());
        assert_eq!(
            decide(&rt, &resolver, &dest, 443, Transport::Tcp),
            InetDecision::Unreachable
        );
    }

    #[test]
    fn a_resolved_address_matching_a_deny_rule_is_dropped() {
        let mut rt = constrained("api.openai.com");
        rt.ruleset.deny.push(DenyRule {
            matcher: DenyMatcher::Cidr(Cidr::new(v4("93.184.216.0"), 24).expect("cidr")),
            ports: Vec::new(),
        });
        let resolver = FakeResolver(Ok(vec![v4("93.184.216.34"), v4("8.8.8.8")]));
        let dest = Destination::Name("api.openai.com".to_owned());
        // The denied 93.184.216.34 drops; the clean 8.8.8.8 survives.
        assert_eq!(
            decide(&rt, &resolver, &dest, 443, Transport::Tcp),
            InetDecision::Pinned(vec![v4("8.8.8.8")])
        );
    }

    #[test]
    fn mode_none_denies_everything() {
        let rt = NetRuntime::denied();
        let resolver = FakeResolver(Ok(vec![v4("203.0.113.5")]));
        let dest = Destination::Name("api.openai.com".to_owned());
        assert_eq!(
            decide(&rt, &resolver, &dest, 443, Transport::Tcp),
            InetDecision::Denied
        );
    }

    #[test]
    fn a_host_service_literal_is_an_allow_exception() {
        let mut rt = NetRuntime::denied();
        rt.host_services
            .push(SocketAddr::new(v4("127.0.0.1"), 2222));
        let resolver = FakeResolver(Err(()));
        let dest = Destination::Addr(v4("127.0.0.1"));
        assert_eq!(
            decide(&rt, &resolver, &dest, 2222, Transport::Tcp),
            InetDecision::Pinned(vec![v4("127.0.0.1")])
        );
    }

    /// A runtime that allows any literal address the deny rules do not catch (`unconstrained`),
    /// with no host-service carve-out — the worst case for the by-address special-use gate.
    fn unconstrained() -> NetRuntime {
        NetRuntime {
            ruleset: Ruleset {
                mode: NetMode::Unconstrained,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            accept_private_resolved: false,
            host_services: Vec::new(),
            command_socket: None,
        }
    }

    #[test]
    fn a_literal_mirror_alias_is_denied_even_in_unconstrained() {
        // §7.5.7 per-kennel inbound-mirror alias `127.<tag>.<ctx>.x`. Without the by-address
        // special-use gate, `unconstrained` would dial it (looping inbound back into egress, or
        // reaching a sibling kennel's alias — cross-kennel lateral movement). It must be denied.
        let rt = unconstrained();
        let resolver = FakeResolver(Err(())); // a literal never resolves
        assert_eq!(
            decide(
                &rt,
                &resolver,
                &Destination::Addr(v4("127.42.7.1")),
                8080,
                Transport::Tcp
            ),
            InetDecision::Denied,
            "an unconstrained workload must not egress-dial a host-loopback mirror alias"
        );
        // A v6 ULA mirror alias (`fd<gid>:<tag>:<ctx>::`) is likewise refused.
        let ula = IpAddr::V6("fd00:0:0:42::1".parse().expect("v6"));
        assert_eq!(
            decide(
                &rt,
                &resolver,
                &Destination::Addr(ula),
                8080,
                Transport::Tcp
            ),
            InetDecision::Denied,
            "an unconstrained workload must not egress-dial a ULA mirror alias"
        );
        // A genuinely public literal is still allowed in unconstrained mode.
        assert_eq!(
            decide(
                &rt,
                &resolver,
                &Destination::Addr(v4("93.184.216.34")),
                443,
                Transport::Tcp
            ),
            InetDecision::Pinned(vec![v4("93.184.216.34")]),
            "a public literal is unaffected by the special-use gate"
        );
    }

    #[test]
    fn a_by_address_allow_of_a_mirror_alias_is_still_denied() {
        // Even an explicit by-address `[net.allow]` for a loopback alias is refused — the gate
        // sits ahead of the allow match, so a footgun policy cannot open the lateral hole.
        let mut rt = constrained("unused.example");
        rt.ruleset.allow.push(Rule {
            matcher: Matcher::Cidr(Cidr::new(v4("127.42.7.1"), 32).expect("cidr")),
            ports: Vec::new(),
            protocol: RuleProtocol::Tcp,
        });
        let resolver = FakeResolver(Err(()));
        assert_eq!(
            decide(
                &rt,
                &resolver,
                &Destination::Addr(v4("127.42.7.1")),
                8080,
                Transport::Tcp
            ),
            InetDecision::Denied
        );
    }

    #[test]
    fn accept_private_resolved_opts_a_literal_loopback_back_in() {
        // The escape hatch: a policy that genuinely wants loopback egress sets
        // `accept_private_resolved`, which also un-gates a literal special-use address. (The
        // bastion does not need this — it rides the exact-literal host_services carve-out.)
        let mut rt = unconstrained();
        rt.accept_private_resolved = true;
        let resolver = FakeResolver(Err(()));
        assert_eq!(
            decide(
                &rt,
                &resolver,
                &Destination::Addr(v4("127.0.0.1")),
                9000,
                Transport::Tcp
            ),
            InetDecision::Pinned(vec![v4("127.0.0.1")])
        );
    }

    #[test]
    fn dial_via_delegate_round_trips_bytes_through_the_conduit() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};
        use std::os::unix::net::UnixListener;

        // An echo upstream the delegate dials.
        let echo = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = echo.accept() {
                let mut b = [0u8; 64];
                if let Ok(n) = s.read(&mut b) {
                    let _ = s.write_all(b.get(..n).unwrap_or_default());
                }
            }
        });

        // The real delegate conduit server on a per-kennel command socket.
        let sock =
            std::env::temp_dir().join(format!("kennel-inet-dial-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind cmd socket");
        std::thread::spawn(move || {
            kennel_host_delegate::netproxy::conduit::serve_conduit(&listener)
        });

        // kenneld's side: dial via the delegate, get the kennel-facing conduit end back.
        let mut end = dial_via_delegate(&sock, echo_addr.port(), &[echo_addr.ip()]).expect("dial");
        end.write_all(b"ping").expect("write");
        end.shutdown(Shutdown::Write).expect("half-close");
        let mut got = Vec::new();
        end.read_to_end(&mut got).expect("read echo");
        assert_eq!(got, b"ping");
        let _ = std::fs::remove_file(&sock);
    }
}
