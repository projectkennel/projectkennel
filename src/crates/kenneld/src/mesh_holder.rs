//! The unprivileged connector mesh-bus mount holder (§7.13.4a): a **forked, not exec'd** child of
//! kenneld that mounts a shared binderfs in its own user namespace and serves movable clones of it.
//!
//! # Unprivileged, and why fork-not-exec
//!
//! Every step — create a userns, write a single-uid map, mount binderfs, add the device, and
//! `open_tree(CLONE)` a movable copy — is unprivileged *inside the holder's own user namespace*: the
//! userns confers `CAP_SYS_ADMIN` within itself (so `FS_USERNS_MOUNT` permits the binderfs mount and
//! the clone), and a `0 <kenneld-uid> 1` self-map is unprivileged to write (no `cap_setuid`). No
//! privilege, no privhelper.
//!
//! Two things force fork-not-exec. kenneld's `AppArmor` profile carries the `userns` grant that the
//! host-wide `apparmor_restrict_unprivileged_userns` would otherwise deny — and that grant follows a
//! **fork** (the child stays under the same profile) but NOT an **exec** (a re-exec'd holder's map
//! write is EPERM). And the self-map maps userns-0 to **kenneld's** uid, so the binderfs nodes —
//! owned by uid-0-of-the-mounting-userns — are owned by kenneld, which opens node 0 directly via
//! `/proc/<holder>/root`.
//!
//! # Why a serve loop, not a path bind
//!
//! The binderfs lives only in the holder's private mount namespace. A kennel cannot reach it by path
//! (the construction has its own PID namespace, so `/proc/<holder>/root` does not resolve there), and
//! only the holder — the namespace that *has* the mount — may `open_tree(CLONE)` it. So the holder
//! serves: on each request `kenneld` makes, it clones a fresh detached binderfs and hands the fd back
//! over `SCM_RIGHTS`; `kenneld` relays that fd into the kennel, where `kennel-bin-init` `move_mount`s
//! it into the view. The `fork`/socket/clone mechanics live in
//! [`kennel_lib_syscall::namespace::fork_mount_holder`] (this crate is `#![forbid(unsafe_code)]`); the
//! mount work below is the `setup` closure it runs in the child.

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use kennel_lib_syscall::namespace::{fork_mount_holder, unshare, Namespaces};

/// Fork an unprivileged holder that mounts the mesh binderfs at `mount_dir` and serves clones of it.
///
/// Returns the holder's pid and the kenneld-side control socket: a one-byte write on that socket
/// makes the holder `open_tree(CLONE)` a fresh detached mount and SCM-send the fd back (see
/// [`kennel_lib_syscall::namespace::fork_mount_holder`]). kenneld serves node 0 by opening the device
/// at `/proc/<pid>/root/<mount_dir>/binder` (nodes owned by kenneld's own uid); closing the socket
/// (or `SIGKILL`ing the pid) tears the bus down.
///
/// # Errors
///
/// The OS error if the fork fails, or if the in-child mount sequence fails (userns grant missing,
/// binderfs unavailable, …).
pub fn spawn(mount_dir: &Path) -> io::Result<(i32, std::os::fd::OwnedFd)> {
    let uid = kennel_lib_syscall::unistd::real_uid();
    let gid = kennel_lib_syscall::unistd::real_gid();
    let dir = mount_dir.to_owned();
    fork_mount_holder(
        move || {
            // A user namespace, self-mapped `0 <kenneld-uid> 1`: unprivileged (the grant is in
            // kenneld's profile, carried across this fork), and it makes the binderfs nodes kenneld's.
            unshare(Namespaces::USER)?;
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"));
            // A private mount namespace, then the binderfs + its device.
            unshare(Namespaces::MOUNT)?;
            kennel_lib_syscall::mount::make_root_private()?;
            kennel_lib_binder::binderfs::mount_instance(&dir, 1)?;
            kennel_lib_binder::binderfs::add_binder_device(&dir)?;
            // Nodes are kenneld's uid (the self-map); 0666 also lets a kennel (host-root-mapped in its
            // own userns) open the move-mounted node. Access control is kenneld's `SVC_CONNECT` gate.
            let _ = std::fs::set_permissions(
                dir.join(kennel_lib_binder::binderfs::BINDER_DEVICE),
                std::fs::Permissions::from_mode(0o666),
            );
            Ok(())
        },
        mount_dir,
    )
}
