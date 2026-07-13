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

/// Ensure this instance holds exactly the standard `binder` device, returning its
/// `(major, minor)`. The device then appears at `dir/binder`.
///
/// Normally `BINDER_CTL_ADD` allocates it. On a kernel whose non-empty
/// `CONFIG_ANDROID_BINDER_DEVICES` (or `binder.devices=` module parameter) names the
/// standard set — now the upstream default `"binder,hwbinder,vndbinder"`, shipped by
/// current Fedora/Arch kernels — the kernel pre-creates those devices in *every*
/// binderfs instance at mount time (per-instance since Linux 5.4), so the add returns
/// `EEXIST`. binderfs devices are per-instance, so the pre-created `binder` is this
/// instance's own and is adopted. Any surplus pre-created devices are then removed, so
/// a kennel's binderfs holds the single `binder` context on every kernel — no unused
/// context is left reachable in the view. A kernel with an empty devices list (older
/// Debian/Ubuntu) pre-creates nothing, so the add succeeds and the sweep is a no-op.
///
/// # Errors
///
/// Returns the OS error if the control device cannot be opened, `BINDER_CTL_ADD`
/// fails for any reason other than a pre-existing `binder`, the adopted device
/// cannot be stat'd, or a surplus device cannot be removed.
pub fn add_binder_device(dir: &Path) -> io::Result<(u32, u32)> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(dir.join(CONTROL_DEVICE))?;
    let device = match crate::sys::ctl_add(control.as_fd(), BINDER_DEVICE) {
        Ok(device) => device,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            device_numbers(&dir.join(BINDER_DEVICE))?
        }
        Err(e) => return Err(e),
    };
    remove_surplus_devices(dir)?;
    Ok(device)
}

/// The `(major, minor)` of an existing device node (the `EEXIST`-adopt path).
fn device_numbers(node: &Path) -> io::Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    let rdev = std::fs::metadata(node)?.rdev();
    Ok((libc::major(rdev), libc::minor(rdev)))
}

/// Remove every device the kernel pre-created beyond `binder`/`binder-control`, so a
/// kennel's binderfs matches an empty-`CONFIG_ANDROID_BINDER_DEVICES` kernel exactly.
///
/// A no-op where nothing was pre-created (the empty-config kernels). `features` is a
/// directory, not a device, and is left untouched.
fn remove_surplus_devices(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt as _;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == BINDER_DEVICE || name == CONTROL_DEVICE {
            continue;
        }
        if entry.file_type()?.is_char_device() {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
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
