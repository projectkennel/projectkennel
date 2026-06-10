//! Root-gated binderfs e2e: mount an instance, allocate the standard `binder`
//! device, open it, check the protocol version, and become its context manager
//! (a second attempt must fail `EBUSY`, confirming the per-instance singleton).
//!
//! This is the kernel-observable proof of `crate::sys` + `crate::binderfs`. It
//! needs `CAP_SYS_ADMIN` in a private mount namespace and a kernel with
//! `CONFIG_ANDROID_BINDERFS`. Build and run it directly (not via `sudo cargo`,
//! which leaves root-owned files in `target/`):
//!
//! ```text
//! cargo test -p kennel-lib-binder --features e2e --no-run
//! sudo unshare -m ./target/debug/deps/root_binderfs-<hash>
//! ```

#![cfg(feature = "e2e")]

use std::os::fd::AsFd;

use kennel_lib_binder::{binderfs, proto, sys};

/// The binder buffer mapping size for the test (ample for the empty round-trip).
const MAP_SIZE: usize = 128 * 1024;

#[test]
fn binderfs_mount_alloc_and_context_mgr() {
    let dir = std::env::temp_dir().join(format!("kennel-lib-binder-root-{}", std::process::id()));

    binderfs::mount_instance(&dir, binderfs::DEFAULT_MAX_DEVICES)
        .expect("mount binderfs (run under: sudo unshare -m <test-binary>)");

    let (major, _minor) = binderfs::add_binder_device(&dir).expect("allocate the binder device");
    assert_ne!(major, 0, "expected a real character-device major");

    let fd = binderfs::open_binder_device(&dir).expect("open /dev/binderfs/binder");

    assert_eq!(
        sys::version(fd.as_fd()).expect("BINDER_VERSION"),
        proto::PROTOCOL_VERSION,
        "binder protocol version mismatch",
    );

    sys::set_context_mgr(fd.as_fd()).expect("become context manager");
    assert!(
        sys::set_context_mgr(fd.as_fd()).is_err(),
        "a second BINDER_SET_CONTEXT_MGR must fail (one manager per instance)",
    );

    let map = sys::map(fd.as_fd(), MAP_SIZE).expect("mmap the binder buffer");
    assert_ne!(map.base(), 0, "mmap returned a null base");
    assert_eq!(map.len(), MAP_SIZE);

    let _ = std::fs::remove_dir_all(&dir);
}
