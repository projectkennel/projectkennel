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
//! The message is built as a plain byte buffer (no `transmute`); the only
//! `unsafe` is the three socket syscalls, each §4-commented. The netlink
//! constants are the stable kernel UAPI values (`<linux/rtnetlink.h>`,
//! `<linux/netlink.h>`), defined here as we define the Landlock ones.

use std::ffi::CStr;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// netlink message types and flags (`<linux/netlink.h>`, `<linux/rtnetlink.h>`).
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
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
    // SAFETY: `name` is a valid NUL-terminated C string for the duration of the
    // call; `if_nametoindex` only reads it and returns the index or 0 on error.
    // INVARIANTS UPHELD: pointer comes from a live `&CStr`.
    // FAILURE MODE: unknown name returns 0; we map that to the last OS error.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

/// Add `addr/prefix_len` to the interface `ifindex` (`RTM_NEWADDR`).
///
/// # Errors
///
/// Returns the OS error if the address already exists (`EEXIST`) or the kernel
/// otherwise rejects the request.
pub fn add_address(ifindex: u32, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    request(RTM_NEWADDR, flags, ifindex, addr, prefix_len)
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
    // SAFETY: socket() with constant, valid arguments returns a new fd or -1.
    // FAILURE MODE: -1 → last_os_error; otherwise we own the fd via OwnedFd.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, exclusively-owned fd the kernel just returned.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };

    // Destination: the kernel (pid 0).
    // SAFETY: zeroed sockaddr_nl is a valid all-zero address; we set the family.
    let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst.nl_family = u16::try_from(libc::AF_NETLINK).unwrap_or(16);

    // SAFETY: `msg` is valid for `msg.len()` bytes; `dst` is a live, fully
    // initialised sockaddr_nl of the given size. sendto only reads them.
    // FAILURE MODE: short/!= write or -1 is surfaced as an error.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            msg.as_ptr().cast(),
            msg.len(),
            0,
            std::ptr::from_ref(&dst).cast(),
            u32::try_from(size_of::<libc::sockaddr_nl>()).unwrap_or(12),
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 4096];
    // SAFETY: `buf` is a live, writable 4096-byte buffer; recv writes at most
    // that many bytes and returns the count or -1.
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = usize::try_from(n).unwrap_or(0);
    parse_ack(buf.get(..len).unwrap_or(&[]))
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

#[cfg(all(test, feature = "root-tests"))]
mod root_tests {
    //! `sudo -E env PATH=$PATH cargo test -p kennel-syscall --features root-tests`.
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
