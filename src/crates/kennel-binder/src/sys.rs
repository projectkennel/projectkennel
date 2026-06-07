//! The binder ioctl / `mmap` / binderfs-mount surface — the crate's only `unsafe`.
//!
//! Thin wrappers over `ioctl(2)`, `mmap(2)`/`munmap(2)`, and `mount(2)` for the
//! binder driver and its binderfs control device (`<linux/android/binder.h>`,
//! `<linux/android/binderfs.h>`). Argument structs are `#[repr(C)]` matching the
//! UAPI; the kernel reads/writes exactly the struct it is handed and does not
//! retain the pointers past each call. Every wrapper validates fds and lengths
//! before the call and maps failure to `io::Error`.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Wrap a raw fd the binder driver just transferred into this process (the
/// translated fd of a received `BINDER_TYPE_FD` object) as an [`OwnedFd`].
///
/// # Safety
///
/// `raw` must be a valid, currently-open fd that this process exclusively owns —
/// which holds for a fd the kernel just dup'd into us delivering a transaction. The
/// caller must check `raw >= 0` first.
#[must_use]
pub fn own_fd(raw: i32) -> OwnedFd {
    // SAFETY: the binder driver dup'd `raw` into this process when it delivered the
    // BINDER_TYPE_FD object, so we are its sole owner; wrapping transfers that
    // ownership for RAII close. The caller has checked `raw >= 0`.
    //
    // INVARIANTS UPHELD: exactly one OwnedFd is created per received fd.
    //
    // FAILURE MODE: a negative/closed `raw` would be unsound — prevented by the
    // caller's `>= 0` check and the kernel's transfer contract.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

/// Encode an ioctl request number as `<asm-generic/ioctl.h>` does.
const fn ioc(dir: libc::c_ulong, ty: u8, nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    (dir << 30) | ((size & 0x3fff) << 16) | ((ty as libc::c_ulong) << 8) | nr
}

const DIR_WRITE: libc::c_ulong = 1;
const DIR_RW: libc::c_ulong = 3; // _IOWR = _IOC_READ | _IOC_WRITE

// Sizes of the ioctl argument structs (UAPI).
const SZ_WRITE_READ: libc::c_ulong = 48; // 6 * binder_size_t
const SZ_VERSION: libc::c_ulong = 4; // __s32
const SZ_S32: libc::c_ulong = 4;
const SZ_U32: libc::c_ulong = 4;
const SZ_BINDERFS_DEVICE: libc::c_ulong = 264; // [u8;256] + 2 * u32

const BINDER_WRITE_READ: libc::c_ulong = ioc(DIR_RW, b'b', 1, SZ_WRITE_READ);
const BINDER_SET_MAX_THREADS: libc::c_ulong = ioc(DIR_WRITE, b'b', 5, SZ_U32);
const BINDER_SET_CONTEXT_MGR: libc::c_ulong = ioc(DIR_WRITE, b'b', 7, SZ_S32);
const BINDER_VERSION: libc::c_ulong = ioc(DIR_RW, b'b', 9, SZ_VERSION);
const BINDER_GET_EXTENDED_ERROR: libc::c_ulong = ioc(DIR_RW, b'b', 17, 12);
/// `BINDER_CTL_ADD` (`<linux/android/binderfs.h>`): allocate a named device.
const BINDER_CTL_ADD: libc::c_ulong = ioc(DIR_RW, b'b', 1, SZ_BINDERFS_DEVICE);

/// `BINDERFS_MAX_NAME` + 1: the `name` field width in `struct binderfs_device`.
const BINDERFS_NAME_CAP: usize = 256;

/// `struct binder_write_read`: the `BINDER_WRITE_READ` argument. All fields are
/// `binder_size_t`/`binder_uintptr_t` (`u64` on a 64-bit kernel).
#[repr(C)]
#[derive(Default)]
pub struct BinderWriteRead {
    /// Bytes of `BC_*` commands to consume from `write_buffer`.
    pub write_size: u64,
    /// Bytes the driver consumed from `write_buffer` (out).
    pub write_consumed: u64,
    /// Pointer to the `BC_*` command buffer.
    pub write_buffer: u64,
    /// Capacity of `read_buffer` for `BR_*` commands.
    pub read_size: u64,
    /// Bytes the driver wrote into `read_buffer` (out).
    pub read_consumed: u64,
    /// Pointer to the `BR_*` output buffer.
    pub read_buffer: u64,
}

/// `struct binderfs_device`: the `BINDER_CTL_ADD` argument.
#[repr(C)]
struct BinderfsDevice {
    name: [u8; BINDERFS_NAME_CAP],
    major: u32,
    minor: u32,
}

/// A `mmap`ped binder buffer region. Binder writes inbound transaction data here;
/// userspace reads it and frees each buffer with `BC_FREE_BUFFER`. Unmapped on drop.
pub struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mapping {
    /// The mapping's base address as the `u64` binder uses in `binder_write_read`.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.ptr as u64
    }

    /// The mapping length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the mapping is empty (a zero-length region; never true in practice).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read `len` bytes of inbound transaction data at absolute address `addr`
    /// (a `buffer` pointer from a `BR_TRANSACTION`), bounds-checked to lie within
    /// this mapping.
    ///
    /// # Errors
    ///
    /// Returns `None` if `[addr, addr+len)` is not wholly inside the mapping.
    #[must_use]
    pub fn read_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let base = self.base();
        let off = usize::try_from(addr.checked_sub(base)?).ok()?;
        let end = off.checked_add(len)?;
        if end > self.len {
            return None;
        }
        // SAFETY: `off`/`end` are bounds-checked against the mapping length, the
        // region is mapped PROT_READ for `self.len` bytes, and `&self` borrows it
        // for the returned slice's lifetime so it cannot be unmapped meanwhile.
        //
        // INVARIANTS UPHELD: the returned slice never aliases outside the mapping.
        //
        // FAILURE MODE: an out-of-range addr/len returns None above, before any
        // pointer is formed.
        let p = unsafe { self.ptr.cast::<u8>().add(off) };
        // SAFETY: `p` points `off` bytes into a `PROT_READ` mapping of `self.len`
        // bytes and `len <= self.len - off`, so the slice is valid and readable.
        Some(unsafe { std::slice::from_raw_parts(p, len) })
    }
}

// SAFETY: a `Mapping` owns its mmap region exclusively (the only pointer to it),
// and every access is through `&self`/`&mut self` on the owning thread. Moving it to
// another thread transfers that sole ownership with no aliasing, so it is sound to
// send. It is deliberately **not** `Sync`: concurrent access is not provided for.
unsafe impl Send for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` are exactly what `mmap` returned and we have not
        // unmapped them before; `munmap` releases the region. Errors are ignored
        // (nothing actionable at drop).
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// `mmap` a binder buffer of `len` bytes (`PROT_READ`, `MAP_PRIVATE`) on `fd`.
///
/// # Errors
///
/// Returns the OS error if `mmap` fails (e.g. the device is not a binder fd or
/// `len` exceeds the driver's limit).
pub fn map(fd: BorrowedFd<'_>, len: usize) -> io::Result<Mapping> {
    // SAFETY: a fresh anonymous-address mmap (addr null) of `len` bytes, read-only
    // and private, against the binder device `fd`. The kernel owns the contents;
    // we only read. The returned Mapping munmaps on drop.
    //
    // INVARIANTS UPHELD: `ptr` is either MAP_FAILED (handled) or a valid mapping
    // of exactly `len` bytes.
    //
    // FAILURE MODE: mmap returns MAP_FAILED + errno; we surface it and map nothing.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping { ptr, len })
}

/// Read the binder protocol version of `fd` (`BINDER_VERSION`).
///
/// # Errors
///
/// Returns the OS error if the ioctl fails (e.g. `fd` is not a binder device).
pub fn version(fd: BorrowedFd<'_>) -> io::Result<i32> {
    let mut v: i32 = 0;
    // SAFETY: BINDER_VERSION writes a single `__s32` (the protocol version) into
    // `v`, which is a live, correctly-sized stack int. No pointer is retained.
    //
    // INVARIANTS UPHELD: `v` is initialised before and read only after success.
    //
    // FAILURE MODE: a non-binder fd returns -1 + errno; `v` is then unchanged.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), BINDER_VERSION, std::ptr::from_mut(&mut v)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(v)
}

/// Register the calling process as context manager of `fd` (`BINDER_SET_CONTEXT_MGR`).
///
/// # Errors
///
/// Returns the OS error if the ioctl fails (notably `EBUSY` if the instance
/// already has a context manager).
pub fn set_context_mgr(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut zero: i32 = 0;
    // SAFETY: BINDER_SET_CONTEXT_MGR reads a single `__s32` (0) from `zero`, a live
    // stack int. The kernel does not retain the pointer.
    //
    // INVARIANTS UPHELD: `zero` outlives the call.
    //
    // FAILURE MODE: already-set or unprivileged returns -1 + errno.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            BINDER_SET_CONTEXT_MGR,
            std::ptr::from_mut(&mut zero),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set the binder thread-pool ceiling for `fd` (`BINDER_SET_MAX_THREADS`).
///
/// # Errors
///
/// Returns the OS error if the ioctl fails.
pub fn set_max_threads(fd: BorrowedFd<'_>, max: u32) -> io::Result<()> {
    let mut n = max;
    // SAFETY: BINDER_SET_MAX_THREADS reads a single `__u32` from `n`, a live stack
    // int; not retained.
    //
    // INVARIANTS UPHELD: `n` outlives the call.
    //
    // FAILURE MODE: -1 + errno on a non-binder fd.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            BINDER_SET_MAX_THREADS,
            std::ptr::from_mut(&mut n),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read the last extended-error `param` (a negative errno) for `fd`
/// (`BINDER_GET_EXTENDED_ERROR`), to explain a `BR_FAILED_REPLY`.
///
/// # Errors
///
/// Returns the OS error if the ioctl fails (e.g. an older kernel without it).
pub fn extended_error(fd: BorrowedFd<'_>) -> io::Result<i32> {
    #[repr(C)]
    struct ExtendedError {
        id: u32,
        command: u32,
        param: i32,
    }
    let mut ee = ExtendedError {
        id: 0,
        command: 0,
        param: 0,
    };
    // SAFETY: BINDER_GET_EXTENDED_ERROR writes a `binder_extended_error` into `ee`,
    // a live, correctly-sized struct; not retained past the call.
    //
    // INVARIANTS UPHELD: `ee` outlives the call.
    //
    // FAILURE MODE: -1 + errno on a kernel without the command.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            BINDER_GET_EXTENDED_ERROR,
            std::ptr::from_mut(&mut ee),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ee.param)
}

/// Wait up to `timeout_ms` for `fd` to be readable (`POLLIN`).
///
/// Returns whether it became readable (so a `BINDER_WRITE_READ` will have work),
/// letting a looper wake periodically to check a stop flag instead of blocking
/// forever.
///
/// # Errors
///
/// Returns the OS error if `poll(2)` fails for a reason other than `EINTR` (which
/// is reported as "not readable" so the caller loops).
pub fn poll_in(fd: BorrowedFd<'_>, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a single live, initialised pollfd; `poll` reads/writes it
    // and the count (1) matches. No pointer retained.
    //
    // INVARIANTS UPHELD: exactly one pollfd is described to the kernel.
    //
    // FAILURE MODE: -1 + errno; EINTR is mapped to "not ready" so the caller retries.
    let ret = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(pfd.revents & libc::POLLIN != 0)
}

/// Run one `BINDER_WRITE_READ`.
///
/// On success `bwr.write_consumed`/`read_consumed` are updated by the driver.
/// `write_buffer`/`read_buffer` must point at live buffers of at least
/// `write_size`/`read_size` bytes.
///
/// # Errors
///
/// Returns the OS error if the ioctl fails. `EINTR` is surfaced to the caller to
/// retry.
pub fn write_read(fd: BorrowedFd<'_>, bwr: &mut BinderWriteRead) -> io::Result<()> {
    // SAFETY: BINDER_WRITE_READ reads/updates the `binder_write_read` at `bwr` and
    // reads `write_size` bytes from `write_buffer` / writes up to `read_size` bytes
    // to `read_buffer`. The caller guarantees those pointers are live for the
    // lengths given (see the doc contract); the kernel retains none past the call.
    //
    // INVARIANTS UPHELD: `bwr` is a live, correctly-sized struct; the buffer
    // pointers and sizes inside it were set by the caller from owned buffers.
    //
    // FAILURE MODE: -1 + errno (e.g. EINTR, EFAULT on a bad buffer pointer); no
    // memory unsafety because the kernel honours the sizes it is given.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), BINDER_WRITE_READ, std::ptr::from_mut(bwr)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Allocate a named binder device on a binderfs control fd (`BINDER_CTL_ADD`),
/// returning its `(major, minor)`. The device then appears at `<mount>/<name>`.
///
/// # Errors
///
/// Returns the OS error if `name` is too long for `binderfs_device.name`, or the
/// ioctl fails (e.g. the per-instance device cap is reached, or the name exists).
pub fn ctl_add(control: BorrowedFd<'_>, name: &str) -> io::Result<(u32, u32)> {
    let bytes = name.as_bytes();
    if bytes.len() >= BINDERFS_NAME_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "binderfs device name too long",
        ));
    }
    let mut dev = BinderfsDevice {
        name: [0u8; BINDERFS_NAME_CAP],
        major: 0,
        minor: 0,
    };
    if let Some(dst) = dev.name.get_mut(..bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    // SAFETY: BINDER_CTL_ADD reads the NUL-terminated `name` and writes `major`/
    // `minor` into `dev`, a live, correctly-sized `binderfs_device`. `name` is
    // NUL-terminated because the trailing bytes are zero and `name.len() <
    // BINDERFS_NAME_CAP`. Not retained past the call.
    //
    // INVARIANTS UPHELD: `dev` outlives the call; `name` carries a terminator.
    //
    // FAILURE MODE: -1 + errno (ENOSPC at the device cap, EEXIST on a dup name).
    let ret = unsafe {
        libc::ioctl(
            control.as_raw_fd(),
            BINDER_CTL_ADD,
            std::ptr::from_mut(&mut dev),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((dev.major, dev.minor))
}

/// Mount a fresh binderfs instance at `path` with a per-instance device cap of
/// `max` (`mount("binder", path, "binder", 0, "max=<max>")`).
///
/// Requires `CAP_SYS_ADMIN` in the mounting namespace; binderfs is
/// `FS_USERNS_MOUNT`, so the kennel's child user namespace suffices.
///
/// # Errors
///
/// Returns the OS error if the mount fails (e.g. the binder filesystem is not
/// available, or the caller lacks `CAP_SYS_ADMIN` in its namespace).
pub fn mount_binderfs(path: &CStr, max: u32) -> io::Result<()> {
    let opts = std::ffi::CString::new(format!("max={max}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount option contained NUL"))?;
    let fstype = c"binder";
    let source = c"binder";
    // SAFETY: all four string pointers are NUL-terminated and live for the call;
    // `mount(2)` copies what it needs and retains nothing. flags = 0.
    //
    // INVARIANTS UPHELD: `path`/`opts`/`fstype`/`source` outlive the call.
    //
    // FAILURE MODE: -1 + errno (ENODEV without the binder fs, EPERM without
    // CAP_SYS_ADMIN in the namespace).
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            path.as_ptr(),
            fstype.as_ptr(),
            0,
            opts.as_ptr().cast(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
