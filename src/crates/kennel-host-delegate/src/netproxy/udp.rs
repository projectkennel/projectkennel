//! `host-netproxy`'s UDP mode: resolve a name and open a connected UDP socket (W2).
//!
//! The operator-context resolve-and-dial half of UDP egress, reused by the tun broker exactly as the
//! `dbus-broker` reuses `host-dbus::mediate`: the broker mediates frames but **never resolves** — it
//! calls [`resolve`] and [`connect_udp`] here, in the delegate that runs `net.mode = host` with the
//! real `/etc` name-resolution artefacts, so `getaddrinfo` reaches the real resolver.
//!
//! The two abilities are **decoupled**: [`resolve`] turns a name into addresses, [`connect_udp`]
//! pins one as a connected socket's peer. The categorical deny-CIDR floor is **not** enforced here —
//! it is the cgroup BPF filter on the delegate's `net.mode = host` cgroup; a connect to a denied CIDR
//! fails at the kernel (`EPERM`), which the broker turns into `ICMPv6` admin-prohibited.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

/// Resolve `name` to its addresses via the OS resolver (`getaddrinfo`, consulting `/etc/hosts`,
/// `nsswitch.conf`, and the configured resolvers).
///
/// Returns the addresses in resolver order. This is the delegate's own resolution — the broker never
/// resolves; it runs `net.mode = host` with the real `/etc`, so this reaches the real resolver.
///
/// # Errors
///
/// The OS error if the lookup fails; [`io::ErrorKind::NotFound`] if the name resolves to nothing.
pub fn resolve(name: &str) -> io::Result<Vec<IpAddr>> {
    // Port 0: we only want the addresses.
    let addrs: Vec<IpAddr> = (name, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "name resolved to no addresses",
        ));
    }
    Ok(addrs)
}

/// Open a UDP socket connected to `(addr, port)`, pinning it as the sole peer (kernel-enforced
/// return-path filtering).
///
/// The categorical deny floor is the cgroup BPF filter, not this call: a `connect` to a denied CIDR
/// returns `EPERM` from the kernel, and the caller (the broker) treats that dial failure as
/// admin-prohibited.
///
/// # Errors
///
/// The OS error if the ephemeral bind or the connect fails (including `EPERM` from the BPF floor).
pub fn connect_udp(addr: IpAddr, port: u16) -> io::Result<UdpSocket> {
    let bind: SocketAddr = match addr {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(SocketAddr::new(addr, port))?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_localhost_offline() {
        // `localhost` resolves via /etc/hosts without touching the network — a hermetic check that
        // this reaches getaddrinfo.
        let addrs = resolve("localhost").expect("localhost resolves");
        assert!(
            addrs.iter().any(IpAddr::is_loopback),
            "localhost includes a loopback address, got {addrs:?}"
        );
    }

    #[test]
    fn connect_udp_pins_the_peer() {
        // UDP connect is local (no datagram sent); connecting to loopback always succeeds and the
        // pin is observable as the socket's peer.
        let peer = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let sock = connect_udp(peer, 9).expect("connect");
        assert_eq!(sock.peer_addr().expect("peer").ip(), peer);
    }
}
