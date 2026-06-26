//! The `bpf(2)` syscall surface — the crate's only `unsafe`.
//!
//! `bpf_attr` is a UNION; the kernel reads `size` bytes of it and zero-fills the
//! rest, so we pass a `#[repr(C)]` struct holding exactly the prefix each command
//! needs (values taken from `<linux/bpf.h>`). Pointer/length fields are validated
//! by the caller; the kernel does not retain the pointers past the call.

use std::ffi::CStr;
use std::io;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

// bpf commands (enum bpf_cmd).
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_OBJ_PIN: libc::c_int = 6;
const BPF_OBJ_GET: libc::c_int = 7;
const BPF_MAP_FREEZE: libc::c_int = 27;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;

/// `map_update` flag: create or overwrite the element (`BPF_ANY`).
pub const BPF_ANY: u64 = 0;

/// `BPF_PSEUDO_MAP_FD`: the `src_reg` value marking an `ld_imm64` whose immediate
/// is a map file descriptor (set during relocation patching).
pub const BPF_PSEUDO_MAP_FD: u8 = 1;

/// Length of an eBPF instruction in bytes (an `ld_imm64` is two of these).
pub const INSN_SIZE: usize = 8;

#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

// The anonymous BPF_MAP_*_ELEM struct. `__aligned_u64` forces 8-byte alignment,
// which repr(C) reproduces by padding after `map_fd` — so `size_of` is 32, the
// size the kernel reads.
#[repr(C)]
#[derive(Default)]
struct MapElemAttr {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

// The anonymous BPF_OBJ_* struct (pin/get). `pathname` is first (`__aligned_u64`)
// so there is no leading pad; size_of == 16.
#[repr(C)]
#[derive(Default)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// `bpf(cmd, attr, size)`. `attr` must point at `size` initialised bytes laid out
/// for `cmd`.
unsafe fn bpf(cmd: libc::c_int, attr: *const libc::c_void, size: usize) -> i64 {
    // SAFETY: `bpf(2)` reads `size` bytes from `attr` (a valid, fully-initialised
    // command struct supplied by the safe wrappers below) and returns a new fd or
    // a non-negative result, or -1 with errno. It does not retain `attr`.
    //
    // INVARIANTS UPHELD: each caller passes `size_of` of the matching repr(C)
    // struct, whose field offsets follow <linux/bpf.h>.
    //
    // FAILURE MODE: an invalid request returns -1 + errno; no memory unsafety is
    // reachable because the kernel only reads, and only `size` bytes.
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

fn owned_fd(ret: i64) -> io::Result<OwnedFd> {
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = RawFd::try_from(ret)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bpf fd out of range"))?;
    // SAFETY: the kernel just returned `raw` as a fresh fd we exclusively own;
    // wrapping it transfers ownership for RAII close. raw >= 0 is checked.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Create a BPF map (`BPF_MAP_CREATE`).
///
/// # Errors
///
/// Returns the OS error if the kernel rejects the map parameters or capability.
pub fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> io::Result<OwnedFd> {
    let attr = MapCreateAttr {
        map_type,
        key_size,
        value_size,
        max_entries,
        map_flags,
    };
    // SAFETY: `attr` is a live, fully-initialised MapCreateAttr; we pass its
    // address and exact size. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_MAP_CREATE,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<MapCreateAttr>(),
        )
    };
    owned_fd(ret)
}

/// Insert or overwrite one element of a map (`BPF_MAP_UPDATE_ELEM`).
///
/// # Safety
///
/// `key` must be at least the map's `key_size` bytes and `value` at least its `value_size`
/// bytes — the kernel reads exactly those many from each pointer, so a shorter slice is an
/// out-of-bounds read (undefined behaviour). The caller must know the target map's geometry.
///
/// # Errors
///
/// Returns the OS error if the fd is out of range or the kernel rejects the
/// update (e.g. the map is read-only).
pub unsafe fn map_update(
    map: BorrowedFd<'_>,
    key: &[u8],
    value: &[u8],
    flags: u64,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = MapElemAttr {
        map_fd: u32::try_from(map.as_raw_fd())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd out of range"))?,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
        flags,
    };
    // SAFETY: `attr` is fully initialised; `key`/`value` outlive the call and are
    // valid for reads of the map's key_size/value_size bytes (the caller passes
    // slices at least that long — see the doc contract). The kernel only reads.
    let ret = unsafe {
        bpf(
            BPF_MAP_UPDATE_ELEM,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<MapElemAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Load a program (`BPF_PROG_LOAD`). `insns` is the (already relocation-patched)
/// instruction byte stream; `license` is the program's license string.
///
/// On failure the kernel verifier log is captured into `log` (truncated to its
/// length); the returned error message is the OS error.
///
/// # Errors
///
/// Returns the OS error if the program fails to load or verify.
pub fn prog_load(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[u8],
    license: &CStr,
    log: &mut [u8],
) -> io::Result<OwnedFd> {
    let insn_cnt = u32::try_from(insns.len() / INSN_SIZE)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many instructions"))?;
    let attr = ProgLoadAttr {
        prog_type,
        insn_cnt,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: u32::from(!log.is_empty()),
        log_size: u32::try_from(log.len()).unwrap_or(0),
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type,
    };
    // SAFETY: `attr` is fully initialised; `insns`/`license`/`log` outlive the
    // call and are valid for the lengths given to the kernel (insns: insn_cnt*8
    // bytes; license: NUL-terminated; log: log_size bytes, written by the kernel).
    let ret = unsafe {
        bpf(
            BPF_PROG_LOAD,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<ProgLoadAttr>(),
        )
    };
    owned_fd(ret)
}

/// Attach a loaded program to a cgroup (`BPF_PROG_ATTACH`, exclusive).
///
/// # Errors
///
/// Returns the OS error if the attach is rejected.
pub fn prog_attach_cgroup(
    cgroup: BorrowedFd<'_>,
    prog: BorrowedFd<'_>,
    attach_type: u32,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "fd out of range");
    let attr = ProgAttachAttr {
        target_fd: u32::try_from(cgroup.as_raw_fd()).map_err(|_| bad())?,
        attach_bpf_fd: u32::try_from(prog.as_raw_fd()).map_err(|_| bad())?,
        attach_type,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: `attr` is fully initialised with two valid fds (BorrowedFd) and the
    // attach type; we pass its address and size. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_PROG_ATTACH,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<ProgAttachAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Detach the program of `attach_type` from a cgroup (`BPF_PROG_DETACH`). For an
/// exclusively-attached program the cgroup and attach type identify it.
///
/// # Errors
///
/// Returns the OS error if nothing is attached or the fd is out of range.
pub fn prog_detach_cgroup(cgroup: BorrowedFd<'_>, attach_type: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = ProgAttachAttr {
        target_fd: u32::try_from(cgroup.as_raw_fd())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd out of range"))?,
        attach_bpf_fd: 0,
        attach_type,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    // SAFETY: `attr` is fully initialised with a valid cgroup fd and the attach
    // type; we pass its address and size. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_PROG_DETACH,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<ProgAttachAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Pin a program or map fd to a bpffs `path` (`BPF_OBJ_PIN`), so it outlives the
/// process. `path` must be NUL-terminated and on a mounted bpffs.
///
/// # Errors
///
/// Returns the OS error if the fd is out of range or the kernel rejects the pin
/// (e.g. the path exists, or its directory is not bpffs).
pub fn obj_pin(fd: BorrowedFd<'_>, path: &CStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = ObjAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: u32::try_from(fd.as_raw_fd())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd out of range"))?,
        file_flags: 0,
    };
    // SAFETY: `attr` is fully initialised; `path` outlives the call and is
    // NUL-terminated, so the kernel reads a valid C string. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_OBJ_PIN,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<ObjAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Open a pinned object by bpffs `path` (`BPF_OBJ_GET`), returning a fresh fd.
///
/// # Errors
///
/// Returns the OS error if the path does not exist or is not a pinned object.
pub fn obj_get(path: &CStr) -> io::Result<OwnedFd> {
    let attr = ObjAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    // SAFETY: `attr` is fully initialised; `path` outlives the call and is
    // NUL-terminated. The kernel returns a fresh fd we own, or -1. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_OBJ_GET,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<ObjAttr>(),
        )
    };
    owned_fd(ret)
}

/// Freeze a map (`BPF_MAP_FREEZE`) so neither userspace nor BPF programs can update it.
///
/// A map created with `BPF_F_RDONLY_PROG` already prevents BPF-side writes; freezing
/// additionally prevents userspace writes.
///
/// # Errors
///
/// Returns the OS error if the fd is not a map, the map is already frozen, or the
/// caller lacks the required capability.
pub fn map_freeze(map: BorrowedFd<'_>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = MapElemAttr {
        map_fd: u32::try_from(map.as_raw_fd())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd out of range"))?,
        ..MapElemAttr::default()
    };
    // SAFETY: `attr` is fully initialised (map_fd set, rest zeroed); the kernel reads
    // only `map_fd` for BPF_MAP_FREEZE. See `bpf`.
    let ret = unsafe {
        bpf(
            BPF_MAP_FREEZE,
            std::ptr::from_ref(&attr).cast(),
            std::mem::size_of::<MapElemAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
