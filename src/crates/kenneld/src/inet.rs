//! The `INet` egress decision: kenneld as the policy decision point for outbound
//! connections (`docs/design/07-5-network.md` §7.5.2).
//!
//! `kennel-netshim` (inside the kennel) transacts a [`verb::CONNECT_INET`] request to node 0;
//! kenneld decides it here — exactly as the `kennel-netproxy` server would, reusing that crate's
//! [`Ruleset`] and resolver seam so the two never drift — and **pins** the vetted address. The
//! pinned address never crosses back into the kennel (the kennel holds only a name), so DNS
//! rebinding is structurally impossible: kenneld resolves and re-checks under policy on every
//! request. Driving the dial and minting the socketpair conduit is the next increment (N1.2); this
//! module is the decision, unit-tested in isolation against a fake resolver.
//!
//! [`verb::CONNECT_INET`]: kennel_binder::service::verb::CONNECT_INET

use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use kennel_binder::service::transport;
use kennel_netproxy::allow::{
    is_special_use, Decision, Destination, NetMode, RequestDecision, Ruleset, Transport,
};
use kennel_netproxy::dns::Resolver;

/// The egress policy inputs for the `INet` decision.
///
/// The same trio the `kennel-netproxy` server snapshots per request, built here from the very
/// config the netproxy reads so the decision point and the proxy's reader stay in lockstep
/// (`from_toml`).
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
    /// `kennel-netproxy` binds). `None` when the kennel runs no egress proxy.
    command_socket: Option<PathBuf>,
}

impl NetRuntime {
    /// Build the decision runtime from the per-kennel proxy config TOML kenneld already generates
    /// for `kennel-netproxy`, parsed through that crate's own reader (the round-trip the proxy
    /// writer is validated against — one source of truth for the allow/deny mapping).
    ///
    /// # Errors
    ///
    /// The parser's error string if the TOML does not parse (it is kenneld's own output, so this is
    /// a build bug, surfaced rather than silently denying).
    pub fn from_toml(toml: &str, command_socket: Option<PathBuf>) -> Result<Self, String> {
        let cfg = kennel_netproxy::config::from_toml_str(toml).map_err(|e| e.to_string())?;
        Ok(Self {
            ruleset: cfg.ruleset,
            accept_private_resolved: cfg.accept_private_resolved,
            host_services: cfg.host_services,
            command_socket,
        })
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
/// [`verb::CONNECT_INET`]: kennel_binder::service::verb::CONNECT_INET
#[must_use]
pub fn decode_request(data: &[u8], max_host: usize) -> Option<(Transport, u16, Destination)> {
    let [t, hi, lo, host @ ..] = data else {
        return None;
    };
    let transport = match *t {
        transport::TCP => Transport::Tcp,
        transport::UDP => Transport::Udp,
        _ => return None,
    };
    if host.is_empty() || host.len() > max_host {
        return None;
    }
    let host = std::str::from_utf8(host).ok()?;
    let port = u16::from_be_bytes([*hi, *lo]);
    // A literal address is decided as-is; anything else is a name to resolve under policy.
    let dest = host.parse::<IpAddr>().map_or_else(
        |_| Destination::Name(host.to_owned()),
        Destination::Addr,
    );
    Some((transport, port, dest))
}

/// Decide an `INet` request, **pinning** the vetted addresses instead of dialling.
///
/// Mirrors `kennel_netproxy::server`'s `resolve_and_connect` exactly — host-service exception, then
/// `decide_request`, then (for a name) resolve + per-address `decide_resolved` + the special-use
/// gate. The dial is kenneld's delegate's job (N1.2).
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
    let payload = kennel_netproxy::conduit::encode_command(port, pinned);
    kennel_syscall::scm::send_with_fds(command.as_fd(), &payload, &[delegate_end.as_fd()])?;
    // `delegate_end` drops here; the delegate holds its received copy via SCM_RIGHTS.
    Ok(kennel_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_netproxy::allow::{Cidr, DenyMatcher, DenyRule, Matcher, Rule, RuleProtocol};
    use kennel_netproxy::dns::ResolveError;
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
        assert!(decode_request(&[transport::TCP, 0x01, 0xBB, 0xFF, 0xFE], 255).is_none()); // !utf8
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
        rt.host_services.push(SocketAddr::new(v4("127.0.0.1"), 2222));
        let resolver = FakeResolver(Err(()));
        let dest = Destination::Addr(v4("127.0.0.1"));
        assert_eq!(
            decide(&rt, &resolver, &dest, 2222, Transport::Tcp),
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
        let sock = std::env::temp_dir().join(format!("kennel-inet-dial-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind cmd socket");
        std::thread::spawn(move || kennel_netproxy::conduit::serve_conduit(&listener));

        // kenneld's side: dial via the delegate, get the kennel-facing conduit end back.
        let mut end =
            dial_via_delegate(&sock, echo_addr.port(), &[echo_addr.ip()]).expect("dial");
        end.write_all(b"ping").expect("write");
        end.shutdown(Shutdown::Write).expect("half-close");
        let mut got = Vec::new();
        end.read_to_end(&mut got).expect("read echo");
        assert_eq!(got, b"ping");
        let _ = std::fs::remove_file(&sock);
    }
}
