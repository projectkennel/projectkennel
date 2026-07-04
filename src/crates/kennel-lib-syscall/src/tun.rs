//! TUN-device creation for the UDP-egress L3 facade (W2).
//!
//! The construction child creates the kennel's `tun` interface inside its own network
//! namespace, pre-pivot, where it holds `CAP_NET_ADMIN`: [`create`] opens `/dev/net/tun`
//! and issues `TUNSETIFF(IFF_TUN | IFF_NO_PI)` for a headerless layer-3 tunnel. The returned
//! fd **is** the capability the facade reads and writes frames over; `/dev/net/tun` never
//! enters the kennel view, so there is no path to a second queue on the interface even for
//! in-namespace root.
//!
//! `nix` has no `TUNSETIFF` wrapper, so — as [`pty`](crate::pty) does for `TIOCSCTTY` — the one
//! raw `ioctl` here is the minimal `unsafe`, over a byte buffer sized to the kernel's `ifreq`.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

/// Create a layer-3 `tun` interface, returning its packet fd and the kernel-assigned name.
///
/// Opens `/dev/net/tun` and issues `TUNSETIFF(IFF_TUN | IFF_NO_PI)`: an `IFF_TUN` (L3 — IP
/// frames, not `IFF_TAP` L2) tunnel with `IFF_NO_PI` (no 4-byte `tun_pi` prefix, so a `read`
/// yields a bare IP packet). `ifr_name` is left empty, so the kernel assigns the next free
/// `tunN` and writes it back. `IFF_MULTI_QUEUE` is deliberately NOT set: a single queue plus
/// the absence of `/dev/net/tun` from the view means no second writer can attach to the
/// interface, even for in-namespace root.
///
/// Needs `CAP_NET_ADMIN` in the current network namespace — the construction child holds it in
/// the kennel's own net-ns.
///
/// # Errors
///
/// Returns the OS error if `/dev/net/tun` cannot be opened (the `tun` module is absent, or no
/// permission) or `TUNSETIFF` fails, or if the kernel returns an unterminated interface name.
pub fn create() -> io::Result<(OwnedFd, String)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    // `struct ifreq`: `char ifr_name[IFNAMSIZ]` then the `ifr_ifru` union whose first member is
    // `short ifr_flags`. A zeroed buffer sized to the kernel's `ifreq` leaves the name empty (the
    // kernel assigns one) and places the flags at offset `IFNAMSIZ`.
    let mut ifr = [0u8; std::mem::size_of::<libc::ifreq>()];
    let flags = u16::try_from(libc::IFF_TUN | libc::IFF_NO_PI)
        .map_err(|_| io::Error::other("tun flags"))?;
    ifr[libc::IFNAMSIZ..libc::IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

    // SAFETY: `ifr` is a correctly-sized, zeroed `struct ifreq` for `TUNSETIFF` on a fd we own;
    // the kernel reads `ifr_flags`, creates the interface, and writes the assigned name back into
    // `ifr_name` (offset 0). The ioctl touches only `ifr`.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, ifr.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let name = CStr::from_bytes_until_nul(&ifr[..libc::IFNAMSIZ])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tun name not terminated"))?
        .to_string_lossy()
        .into_owned();
    Ok((OwnedFd::from(file), name))
}

#[cfg(all(test, feature = "e2e"))]
mod root_tests {
    //! `sudo -E env PATH=$PATH cargo test -p kennel-lib-syscall --features e2e`.
    use super::*;

    #[test]
    fn creates_a_named_l3_tun() {
        if crate::unistd::skip_if_unprivileged("creates_a_named_l3_tun") {
            return;
        }
        let (fd, name) = create().expect("create tun");
        assert!(
            name.starts_with("tun"),
            "kernel assigns a `tunN` name, got {name:?}"
        );
        assert!(fd.as_raw_fd() >= 0, "the tun packet fd is valid");
        // Dropping `fd` destroys the (non-persistent) interface.
    }
}
