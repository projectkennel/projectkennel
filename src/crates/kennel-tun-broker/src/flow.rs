//! The broker's flow gate (W2 Part D): allow-check, then dial via host-netproxy's UDP mode.
//!
//! The broker **never resolves**. It checks a flow's `(name, port)` against the grant, then hands the
//! name to `host-netproxy`'s decoupled [`resolve`](kennel_host_delegate::netproxy::udp::resolve) and
//! [`connect_udp`](kennel_host_delegate::netproxy::udp::connect_udp) — the operator-context
//! resolve-and-dial, reused exactly as `dbus-broker` reuses `host-dbus::mediate`.
//!
//! The categorical deny-CIDR floor is **not** re-checked here: it is the cgroup BPF filter on the
//! delegate's `net.mode = host` cgroup. A denied destination fails at `connect()` (`EPERM`), which
//! the broker turns into `ICMPv6` admin-prohibited.

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
    let addrs = udp::resolve(name).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FlowError::Unresolved
        } else {
            FlowError::Resolve(e)
        }
    })?;
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
    fn dial_resolves_and_connects_a_granted_name() {
        // `localhost` resolves via /etc/hosts and a UDP connect to loopback is local — hermetic.
        let allow = Allowlist::new([grant("localhost", &[9])]);
        let sock = dial(&allow, "localhost", 9).expect("dialled");
        assert!(sock.peer_addr().expect("peer").ip().is_loopback());
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
