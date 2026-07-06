//! The broker's flow gate (W2 Part D): allow-check, then dial via host-netproxy's UDP mode.
//!
//! The broker **never resolves**. It checks a flow's `(name, port)` against the grant, then hands the
//! name to `host-netproxy`'s decoupled [`resolve`](kennel_host_delegate::netproxy::udp::resolve) and
//! [`connect_udp`](kennel_host_delegate::netproxy::udp::connect_udp) — the operator-context
//! resolve-and-dial, reused exactly as `dbus-broker` reuses `host-dbus::mediate`.
//!
//! Two things gate the dial, both in the dialer (the cgroup BPF floor still kernel-enforces the
//! cloud-metadata invariant separately):
//!
//! - **Non-routable rebinding gate.** A resolved address a name should never point at for egress —
//!   loopback, link-local, unspecified, multicast, broadcast — is dropped, via
//!   [`is_nonroutable_egress`](kennel_lib_policy::netaddr::is_nonroutable_egress). A public/enterprise
//!   name pointed there through a hostile or misconfigured DNS zone is a leak, and the host-netns
//!   broker dialling one would pivot into host-local/link space. RFC1918 / CGNAT / ULA are **not**
//!   dropped here — constrained UDP legitimately reaches private/internal endpoints (enterprise
//!   data-sync, QUIC to a private host); a deployment that wants them refused adds them to
//!   `[net.bpf].connect.deny`.
//! - **DNS/mDNS port deny.** Destination ports **53** and **5353** are refused regardless of grant —
//!   a UDP flow to a resolver on *any* address (public included, which the address gate above leaves
//!   reachable) is the DNS-exfil axis, and name resolution is the shim's job, never a `[net.udp]`
//!   destination. This is what closes the resolver reach now that private space is dialable.

use std::io;
use std::net::UdpSocket;

use kennel_host_delegate::netproxy::udp;

use crate::shim::Allowlist;

/// Why a flow could not be dialled.
#[derive(Debug)]
pub enum FlowError {
    /// `(name, port)` is not covered by any UDP grant. The caller answers `ICMPv6` admin-prohibited.
    NotAllowed,
    /// The name resolved to no addresses.
    Unresolved,
    /// Every resolved address is non-routable for egress (loopback / link-local / unspecified /
    /// multicast / broadcast) — a name rebound to host-local/link space. Refused before dial
    /// (rebinding defence); the caller answers `ICMPv6` admin-prohibited.
    Rebound,
    /// Host resolution (`getaddrinfo`) failed.
    Resolve(io::Error),
    /// Every resolved address failed to connect — unreachable, or refused by the BPF deny floor
    /// (`EPERM`). The caller answers `ICMPv6` admin-prohibited.
    Dial(io::Error),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => write!(f, "destination not permitted by any UDP grant"),
            Self::Unresolved => write!(f, "name resolved to no addresses"),
            Self::Rebound => write!(f, "name resolved only into special-use space (rebinding)"),
            Self::Resolve(e) => write!(f, "resolution failed: {e}"),
            Self::Dial(e) => write!(f, "dial failed: {e}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Allow-check `(name, port)`, then resolve and connect via host-netproxy's UDP mode.
///
/// The allow-check runs **before** any resolution; resolution and the connected dial are the
/// delegate's (the broker owns neither). The first resolved address that connects wins.
///
/// # Errors
///
/// [`FlowError`]: `NotAllowed` if the grant does not cover `(name, port)`; `Resolve`/`Unresolved` if
/// the name does not resolve; `Dial` if no resolved address could be connected (unreachable, or the
/// BPF floor refused it).
pub fn dial(allow: &Allowlist, name: &str, port: u16) -> Result<UdpSocket, FlowError> {
    if !allow.allows(name, port) {
        return Err(FlowError::NotAllowed);
    }
    // Default-deny the DNS/mDNS ports regardless of grant: a UDP flow to `:53` or `:5353` would let a
    // workload reach a DNS resolver — at ANY address, including a public one that the special-use
    // filter below would miss (Azure `168.63.129.16`, a bare `8.8.8.8`) — or multicast DNS. That is
    // the DNS-exfil axis constrained mode forbids; `[net.udp]` is for QUIC/game/VoIP, and name
    // resolution is the shim's job, so a UDP dial to 53/5353 is never a legitimate destination.
    if matches!(port, 53 | 5353) {
        return Err(FlowError::NotAllowed);
    }
    let addrs = udp::resolve(name).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FlowError::Unresolved
        } else {
            FlowError::Resolve(e)
        }
    })?;
    // Rebinding defence (see the module header): drop any resolved address a name should never point
    // at for egress — loopback, link-local, unspecified, multicast, broadcast. A public/enterprise
    // name pointed there (hostile or misconfigured DNS zone) is a leak, and the host-netns broker
    // dialling one would pivot into host-local/link space. RFC1918 / CGNAT / ULA are NOT dropped here
    // — constrained UDP legitimately reaches private/internal endpoints (enterprise data-sync, QUIC
    // to a private host); a policy that wants them denied uses `[net.bpf].connect.deny`. If nothing
    // dialable remains, the whole flow is a rebind and refused.
    let addrs: Vec<_> = addrs
        .into_iter()
        .filter(|a| !kennel_lib_policy::netaddr::is_nonroutable_egress(*a))
        .collect();
    if addrs.is_empty() {
        return Err(FlowError::Rebound);
    }
    let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
    for addr in addrs {
        match udp::connect_udp(addr, port) {
            Ok(sock) => return Ok(sock),
            Err(e) => last = e,
        }
    }
    Err(FlowError::Dial(last))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::settled::{NameRule, Protocol};

    fn grant(name: &str, ports: &[u16]) -> NameRule {
        NameRule {
            name: name.to_owned(),
            ports: ports.to_vec(),
            protocol: Protocol::Udp,
        }
    }

    #[test]
    fn dial_refuses_a_destination_no_grant_covers_before_resolving() {
        // No grant → NotAllowed, and no resolution is attempted. Offline-safe.
        let allow = Allowlist::new([grant("example.com", &[443])]);
        let err = dial(&allow, "other.test", 53).expect_err("not granted");
        assert!(matches!(err, FlowError::NotAllowed), "got {err:?}");
    }

    #[test]
    fn dial_default_denies_the_dns_and_mdns_ports_even_when_granted() {
        // A grant that permits port 53/5353 does NOT open a DNS/mDNS dial: the default port-deny
        // fires before resolution, so a rebound-or-not name can never reach a resolver (any address)
        // or mDNS. Offline-safe (refused before resolve).
        let allow = Allowlist::new([grant("example.com", &[53, 5353, 443])]);
        assert!(matches!(
            dial(&allow, "example.com", 53).expect_err("53"),
            FlowError::NotAllowed
        ));
        assert!(matches!(
            dial(&allow, "example.com", 5353).expect_err("5353"),
            FlowError::NotAllowed
        ));
    }

    #[test]
    fn dial_refuses_a_granted_name_that_resolves_into_special_use_space() {
        // Rebinding defence (W8): `localhost` resolves to loopback via /etc/hosts. Even with the
        // port granted, the flow is refused BEFORE connect — a hostname-only UDP grant can never
        // legitimately reach loopback, and the host-netns broker would otherwise pivot into
        // host-local space (e.g. the resolver on 127.0.0.53). Hermetic (no network; the real
        // public happy path is the `tun-egress` e2e suite case).
        let allow = Allowlist::new([grant("localhost", &[9])]);
        let err = dial(&allow, "localhost", 9).expect_err("loopback is rebound");
        assert!(matches!(err, FlowError::Rebound), "got {err:?}");
    }

    #[test]
    fn the_grant_ports_gate_the_flow() {
        let allow = Allowlist::new([grant("localhost", &[9])]);
        assert!(matches!(
            dial(&allow, "localhost", 53).expect_err("wrong port"),
            FlowError::NotAllowed
        ));
    }
}
