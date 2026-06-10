//! binderfs instance lifecycle: mount, named-device allocation, device open.
//!
//! A per-kennel binderfs instance is an independent mount (like devpts/tmpfs).
//! kenneld mounts one inside the kennel's namespaces (`FS_USERNS_MOUNT`, so no
//! real privilege — `02-4-binder.md` §Mount sequencing), allocates the standard
//! `binder` device on its control node, and opens that device to become the
//! instance's context manager. These are the safe orchestration steps over the
//! ioctl/mount primitives in [`crate::sys`]; no `unsafe` lives here.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use std::os::fd::AsFd;

/// The standard binderfs control device, present in every instance.
pub const CONTROL_DEVICE: &str = "binder-control";

/// The standard binder device name (the libbinder default; `02-4-binder.md`
/// §Device naming). One `binder` context per kennel instance.
pub const BINDER_DEVICE: &str = "binder";

/// Default per-instance device cap (`max=`), a denial-of-service bound on device
/// allocation.
pub const DEFAULT_MAX_DEVICES: u32 = 256;

/// Mount a fresh binderfs instance at `dir`, creating the directory first.
///
/// # Errors
///
/// Returns the OS error if `dir` cannot be created, its path is not C-encodable,
/// or the mount fails (`CAP_SYS_ADMIN` in the namespace, binder fs availability).
pub fn mount_instance(dir: &Path, max: u32) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let cpath = cstring(dir)?;
    crate::sys::mount_binderfs(&cpath, max)
}

/// Allocate the standard `binder` device on this instance's control node,
/// returning its `(major, minor)`. The device then appears at `dir/binder`.
///
/// # Errors
///
/// Returns the OS error if the control device cannot be opened or `BINDER_CTL_ADD`
/// fails (the device cap is reached, or `binder` already exists).
pub fn add_binder_device(dir: &Path) -> io::Result<(u32, u32)> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(dir.join(CONTROL_DEVICE))?;
    crate::sys::ctl_add(control.as_fd(), BINDER_DEVICE)
}

/// Open the `binder` device of the instance at `dir` for read/write.
///
/// # Errors
///
/// Returns the OS error if the device node is absent (not yet allocated) or
/// cannot be opened.
pub fn open_binder_device(dir: &Path) -> io::Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(dir.join(BINDER_DEVICE))?;
    Ok(OwnedFd::from(file))
}

/// C-encode a filesystem path for the mount syscall.
fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contained NUL"))
}
