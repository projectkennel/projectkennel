//! Hand-rolled `rtnetlink` for interface-address management.
//!
//! The privileged helper adds the per-kennel loopback addresses (a `127.x.y.0/24`
//! IPv4 alias and an IPv6 ULA) so the workload's egress can be pinned to the
//! local proxy. We do this over a raw `NETLINK_ROUTE` socket rather than:
//!
//! - the `rtnetlink` crate (a large async/`tokio` tree, MIT-only);
//! - `ioctl` (`SIOCSIFADDR` *replaces* the primary address — it would clobber
//!   `127.0.0.1` — and there is no `ioctl` to add an IPv6 address at all);
//! - shelling out to `ip` (an external dependency in the privileged path).
//!
//! The message is built as a plain byte buffer (no `transmute`); the socket
//! itself goes through nix's safe `socket`/`sendto`/`recv`/`NetlinkAddr` wrappers
//! (`CODING-STANDARDS.md` §4 — prefer a vetted crate to our own `unsafe`), so this
//! module carries none of its own. The netlink constants are the stable kernel
//! UAPI values (`<linux/rtnetlink.h>`, `<linux/netlink.h>`), defined here as we
//! define the Landlock ones.

use std::ffi::CStr;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;

use nix::sys::socket::{
    recv, sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

// netlink message types and flags (`<linux/netlink.h>`, `<linux/rtnetlink.h>`).
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWLINK: u16 = 16;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
/// `IFF_UP` (`<net/if.h>`): the admin-up flag we set on `lo` inside the kennel net-ns.
const IFF_UP: u32 = 0x1;
// `ifaddrmsg` route attributes (`<linux/if_addr.h>`).
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

/// `nlmsghdr` is 16 bytes; we prepend it once the body length is known.
const NLMSGHDR_LEN: u32 = 16;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Resolve an interface name (e.g. `c"lo"`) to its index.
///
/// # Errors
///
/// Returns the OS error if no interface has that name.
pub fn if_index(name: &CStr) -> io::Result<u32> {
    // nix wraps `if_nametoindex` safely (it reads the `&CStr` and returns the index
    // or an errno).
    Ok(nix::net::if_::if_nametoindex(name)?)
}

/// Add `addr/prefix_len` to the interface `ifindex` (`RTM_NEWADDR`).
///
/// Idempotent: if the address is already present (`EEXIST`) this succeeds — a kennel
/// that reused this ctx and crashed before teardown can leave its loopback address
/// behind, and that leak must not block the next spawn.
///
/// # Errors
///
/// Returns the OS error if the kernel rejects the request for any reason other than
/// the address already existing.
pub fn add_address(ifindex: u32, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    /// `EEXIST` — re-adding an address already on the interface (idempotent add).
    const EEXIST: i32 = 17;
    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    match request(RTM_NEWADDR, flags, ifindex, addr, prefix_len) {
        Err(e) if e.raw_os_error() == Some(EEXIST) => Ok(()),
        other => other,
    }
}

/// Remove `addr/prefix_len` from the interface `ifindex` (`RTM_DELADDR`).
///
/// # Errors
///
/// Returns the OS error if the address is not present or the kernel rejects the
/// request.
pub fn del_address(ifindex: u32, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    let flags = NLM_F_REQUEST | NLM_F_ACK;
    request(RTM_DELADDR, flags, ifindex, addr, prefix_len)
}

/// Bring the interface `ifindex` administratively up (`RTM_NEWLINK`, `IFF_UP`).
///
/// A fresh network namespace starts with `lo` DOWN; the per-kennel net-ns must bring it up before
/// the workload (and `kennel-netshim`) can bind/connect on the loopback addresses. Unprivileged
/// within the kennel's own user+network namespace (the construction child holds `CAP_NET_ADMIN`
/// there). Idempotent: re-upping an already-up interface is a no-op ack.
///
/// # Errors
///
/// Returns the OS error if the kernel rejects the request.
pub fn set_link_up(ifindex: u32) -> io::Result<()> {
    let msg = build_link_up_msg(ifindex)?;
    netlink_round_trip(&msg)
}

/// Serialise an `nlmsghdr` + `ifinfomsg` setting `IFF_UP` (no rtattrs).
///
/// `ifinfomsg` is `{ u8 family; u8 pad; u16 type; i32 index; u32 flags; u32 change }` — 16 bytes,
/// already 4-byte aligned. `change = IFF_UP` masks the update to just the up bit.
fn build_link_up_msg(ifindex: u32) -> io::Result<Vec<u8>> {
    let index = i32::try_from(ifindex).map_err(|_| invalid("ifindex too large"))?;
    let mut body: Vec<u8> = Vec::with_capacity(16);
    body.push(0u8); // ifi_family = AF_UNSPEC
    body.push(0u8); // pad
    body.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type (ignored on set)
    body.extend_from_slice(&index.to_ne_bytes()); // ifi_index
    body.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_flags
    body.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change (only the up bit)

    let total = u32::try_from(body.len())
        .ok()
        .and_then(|b| b.checked_add(NLMSGHDR_LEN))
        .ok_or_else(|| invalid("message too long"))?;
    let mut msg = Vec::with_capacity(body.len().wrapping_add(NLMSGHDR_LEN as usize));
    msg.extend_from_slice(&total.to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes()); // nlmsg_type
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
    msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (to the kernel)
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Build and send one `RTM_*ADDR` request, returning the kernel's ack result.
fn request(
    rtm_type: u16,
    flags: u16,
    ifindex: u32,
    addr: IpAddr,
    prefix_len: u8,
) -> io::Result<()> {
    // `ifa_scope`: 127/8 lives at host scope, everything else at universe scope.
    let (family, octets, scope): (u8, Vec<u8>, u8) = match addr {
        IpAddr::V4(a) => {
            let scope = if a.is_loopback() {
                libc::RT_SCOPE_HOST
            } else {
                libc::RT_SCOPE_UNIVERSE
            };
            (
                u8::try_from(libc::AF_INET).unwrap_or(2),
                a.octets().to_vec(),
                scope,
            )
        }
        IpAddr::V6(a) => (
            u8::try_from(libc::AF_INET6).unwrap_or(10),
            a.octets().to_vec(),
            libc::RT_SCOPE_UNIVERSE,
        ),
    };
    let msg = build_addr_msg(rtm_type, flags, family, prefix_len, scope, ifindex, &octets)?;
    netlink_round_trip(&msg)
}

/// Serialise an `nlmsghdr` + `ifaddrmsg` + `IFA_LOCAL`/`IFA_ADDRESS` message.
/// Built with `extend_from_slice` (no indexing); address lengths of 4 or 16 keep
/// every field 4-byte aligned, so no `rtattr` padding is needed.
fn build_addr_msg(
    rtm_type: u16,
    flags: u16,
    family: u8,
    prefix_len: u8,
    scope: u8,
    ifindex: u32,
    addr: &[u8],
) -> io::Result<Vec<u8>> {
    // body: ifaddrmsg (family, prefixlen, flags=0, scope, ifindex) then the two
    // address attributes.
    let mut body: Vec<u8> = vec![family, prefix_len, 0u8, scope];
    body.extend_from_slice(&ifindex.to_ne_bytes());
    let rta_len =
        u16::try_from(addr.len().wrapping_add(4)).map_err(|_| invalid("address too long"))?;
    for rta_type in [IFA_LOCAL, IFA_ADDRESS] {
        body.extend_from_slice(&rta_len.to_ne_bytes());
        body.extend_from_slice(&rta_type.to_ne_bytes());
        body.extend_from_slice(addr);
    }

    let total = u32::try_from(body.len())
        .ok()
        .and_then(|b| b.checked_add(NLMSGHDR_LEN))
        .ok_or_else(|| invalid("message too long"))?;

    let mut msg = Vec::with_capacity(body.len().wrapping_add(NLMSGHDR_LEN as usize));
    msg.extend_from_slice(&total.to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&rtm_type.to_ne_bytes()); // nlmsg_type
    msg.extend_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
    msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (to the kernel)
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Open a `NETLINK_ROUTE` socket, send `msg` to the kernel, and interpret the ack.
fn netlink_round_trip(msg: &[u8]) -> io::Result<()> {
    let sock = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;

    // Destination: the kernel — pid 0, no multicast groups.
    let dst = NetlinkAddr::new(0, 0);
    sendto(sock.as_raw_fd(), msg, &dst, MsgFlags::empty())?;

    let mut buf = [0u8; 4096];
    let n = recv(sock.as_raw_fd(), &mut buf, MsgFlags::empty())?;
    parse_ack(buf.get(..n).unwrap_or(&[]))
}

/// Interpret a netlink reply: an `NLMSG_ERROR` whose `error` field is 0 is the
/// success ack; non-zero is `-errno`.
fn parse_ack(reply: &[u8]) -> io::Result<()> {
    // nlmsghdr.nlmsg_type is at byte offset 4..6.
    let ty = reply
        .get(4..6)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_ne_bytes)
        .ok_or_else(|| invalid("short netlink reply"))?;
    if ty != NLMSG_ERROR {
        // The only reply to an ACK'd RTM_*ADDR is NLMSG_ERROR; anything else
        // carries no error to report.
        return Ok(());
    }
    // nlmsgerr.error (i32) follows the 16-byte header.
    let err = reply
        .get(16..20)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(i32::from_ne_bytes)
        .ok_or_else(|| invalid("short netlink error"))?;
    if err == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err.wrapping_neg()))
    }
}

#[cfg(all(test, feature = "e2e"))]
mod root_tests {
    //! `sudo -E env PATH=$PATH cargo test -p kennel-syscall --features e2e`.
    use super::*;
    use std::process::Command;

    fn lo_has(addr: &str) -> bool {
        let out = Command::new("ip")
            .args(["addr", "show", "dev", "lo"])
            .output()
            .expect("run ip");
        String::from_utf8_lossy(&out.stdout).contains(addr)
    }

    #[test]
    fn add_and_remove_loopback_v4_and_v6() {
        if crate::unistd::skip_if_unprivileged("add_and_remove_loopback_v4_and_v6") {
            return;
        }
        let lo = if_index(c"lo").expect("lo index");
        let v4: IpAddr = "127.9.9.1".parse().expect("v4");
        let v6: IpAddr = "fd00:9:9::1".parse().expect("v6");

        add_address(lo, v4, 24).expect("add v4");
        add_address(lo, v6, 64).expect("add v6");
        assert!(lo_has("127.9.9.1"), "v4 alias should be present on lo");
        assert!(lo_has("fd00:9:9::1"), "v6 ULA should be present on lo");

        // Adding the same v4 again must conflict (NLM_F_EXCL).
        assert_eq!(
            add_address(lo, v4, 24)
                .expect_err("re-add should fail")
                .raw_os_error(),
            Some(libc::EEXIST)
        );

        del_address(lo, v4, 24).expect("del v4");
        del_address(lo, v6, 64).expect("del v6");
        assert!(!lo_has("127.9.9.1"), "v4 alias should be gone");
        assert!(!lo_has("fd00:9:9::1"), "v6 ULA should be gone");
    }
}
