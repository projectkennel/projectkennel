//! Landlock filesystem/network sandboxing — hand-rolled bindings.
//!
//! # Purpose
//!
//! Apply a Landlock ruleset that confines the workload's filesystem and TCP
//! access (the design's primary filesystem-and-exec enforcement, `docs/08`).
//! Landlock is three syscalls and a few packed structs from the kernel UAPI
//! (`uapi/linux/landlock.h`); small enough that owning the `unsafe` is preferable
//! to the `landlock` crate's transitive cost (`syn` + the first proc-macros in
//! the privileged dependency tree). These definitions are taken from the kernel
//! ABI — facts about the kernel interface — not derived from the `landlock`
//! crate's source.
//!
//! # `unsafe`
//!
//! The `unsafe` is confined to the four raw syscall wrappers (this module is the
//! reason the crate carries `#![allow(unsafe_code)]`); each carries the §4
//! `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment. Opening rule
//! paths goes through `std` (`O_PATH`), and `no_new_privs` through nix — both
//! safe. Landlock is unprivileged: `restrict_self` needs no capabilities.
//!
//! # Kernel support
//!
//! The project floor is 6.10, which is Landlock ABI 5. [`abi_version`] queries
//! the running kernel so callers can refuse an unsupported one and mask the
//! requested access rights to what that ABI defines (requesting an unknown bit
//! is `EINVAL`). ABI history: 1 = filesystem (5.13), 2 = `REFER` (5.19),
//! 3 = `TRUNCATE` (6.2), 4 = TCP network (6.7), 5 = `IOCTL_DEV` (6.10).

use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use bitflags::bitflags;

/// `flags` value that turns `landlock_create_ruleset` into an ABI-version probe
/// (`LANDLOCK_CREATE_RULESET_VERSION`, `uapi/linux/landlock.h`).
const CREATE_RULESET_VERSION: libc::c_uint = 1;

/// `landlock_add_rule` rule types (`enum landlock_rule_type`).
const RULE_PATH_BENEATH: libc::c_uint = 1;
const RULE_NET_PORT: libc::c_uint = 2;

bitflags! {
    /// Filesystem access rights (`LANDLOCK_ACCESS_FS_*`). A ruleset "handles" a
    /// set of these; a path rule then "allows" a subset beneath a directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessFs: u64 {
        /// Execute a file.
        const EXECUTE = 0x1;
        /// Open a file with write access.
        const WRITE_FILE = 0x2;
        /// Open a file with read access.
        const READ_FILE = 0x4;
        /// Open a directory or list its contents.
        const READ_DIR = 0x8;
        /// Remove an empty directory or move it out.
        const REMOVE_DIR = 0x10;
        /// Unlink a file or move it out.
        const REMOVE_FILE = 0x20;
        /// Create a character device.
        const MAKE_CHAR = 0x40;
        /// Create a (sub)directory.
        const MAKE_DIR = 0x80;
        /// Create a regular file.
        const MAKE_REG = 0x100;
        /// Create a UNIX-domain socket.
        const MAKE_SOCK = 0x200;
        /// Create a named pipe.
        const MAKE_FIFO = 0x400;
        /// Create a block device.
        const MAKE_BLOCK = 0x800;
        /// Create a symbolic link.
        const MAKE_SYM = 0x1000;
        /// Link or rename a file across directories (ABI 2).
        const REFER = 0x2000;
        /// Truncate a file (ABI 3).
        const TRUNCATE = 0x4000;
        /// `ioctl(2)` on a character or block device (ABI 5).
        const IOCTL_DEV = 0x8000;
    }
}

bitflags! {
    /// TCP network access rights (`LANDLOCK_ACCESS_NET_*`, ABI 4).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessNet: u64 {
        /// `bind(2)` a TCP socket to a port.
        const BIND_TCP = 0x1;
        /// `connect(2)` a TCP socket to a port.
        const CONNECT_TCP = 0x2;
    }
}

/// `struct landlock_ruleset_attr`. `handled_access_net` exists from ABI 4; the
/// kernel accepts the full struct on older ABIs as long as the unknown trailing
/// bytes are zero, which they are when `supported_net` masks the field empty.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

/// `struct landlock_path_beneath_attr` — packed, per the UAPI.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// `struct landlock_net_port_attr`.
#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

/// Query the Landlock ABI version supported by the running kernel.
///
/// # Errors
///
/// Returns the OS error if the kernel lacks Landlock (`ENOSYS`) or has it
/// disabled (`EOPNOTSUPP`), or [`io::ErrorKind::InvalidData`] in the
/// can't-happen case of an implausibly large version.
pub fn abi_version() -> io::Result<u32> {
    // SAFETY: `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
    // is the kernel's documented ABI-probe form (uapi/linux/landlock.h): with a
    // NULL attr pointer and zero size it dereferences nothing and returns the
    // supported ABI version as a non-negative integer.
    //
    // INVARIANTS UPHELD: the (pointer, size) pair is exactly (NULL, 0), the
    // contract for the version query; no memory we own is read or written.
    //
    // FAILURE MODE: on a kernel without Landlock the syscall returns -1 and sets
    // errno (ENOSYS / EOPNOTSUPP), surfaced below as Err. No memory unsafety is
    // reachable on any path.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(ret).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "implausible Landlock ABI version",
        )
    })
}

/// The filesystem access rights an `abi` kernel understands. Requesting a bit
/// outside this set in a ruleset is `EINVAL`, so callers mask to it.
#[must_use]
pub fn supported_fs(abi: u32) -> AccessFs {
    // ABI 1 defines EXECUTE..=MAKE_SYM (bits 0..=12).
    let mut fs = AccessFs::EXECUTE
        | AccessFs::WRITE_FILE
        | AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::REMOVE_DIR
        | AccessFs::REMOVE_FILE
        | AccessFs::MAKE_CHAR
        | AccessFs::MAKE_DIR
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_SOCK
        | AccessFs::MAKE_FIFO
        | AccessFs::MAKE_BLOCK
        | AccessFs::MAKE_SYM;
    if abi >= 2 {
        fs |= AccessFs::REFER;
    }
    if abi >= 3 {
        fs |= AccessFs::TRUNCATE;
    }
    if abi >= 5 {
        fs |= AccessFs::IOCTL_DEV;
    }
    fs
}

/// The TCP network access rights an `abi` kernel understands (none before ABI 4).
#[must_use]
pub fn supported_net(abi: u32) -> AccessNet {
    if abi >= 4 {
        AccessNet::BIND_TCP | AccessNet::CONNECT_TCP
    } else {
        AccessNet::empty()
    }
}

/// Create a ruleset fd governing the handled access rights in `attr`.
fn create_ruleset(attr: &RulesetAttr) -> io::Result<OwnedFd> {
    // SAFETY: `attr` is a fully initialised RulesetAttr that outlives the call;
    // we pass its address and exact byte size, the contract for
    // landlock_create_ruleset, which reads `size` bytes through the pointer and
    // returns a new ruleset fd (or -1/errno).
    //
    // INVARIANTS UPHELD: pointer and size describe the same live struct; flags 0.
    //
    // FAILURE MODE: a bad/unsupported request returns -1 + errno (surfaced as
    // Err); no memory unsafety is reachable.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::from_ref(attr),
            size_of::<RulesetAttr>(),
            0_u32,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = RawFd::try_from(ret)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ruleset fd out of range"))?;
    // SAFETY: `raw` is a fresh fd the kernel just returned and that nothing else
    // owns; wrapping it transfers ownership to the OwnedFd for RAII close.
    //
    // INVARIANTS UPHELD: `raw >= 0` (checked) and is exclusively ours.
    //
    // FAILURE MODE: none — construction cannot fail.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Add a "allow `access` beneath `parent`" rule to `ruleset`.
fn add_path_rule(
    ruleset: BorrowedFd<'_>,
    access: AccessFs,
    parent: BorrowedFd<'_>,
) -> io::Result<()> {
    let attr = PathBeneathAttr {
        allowed_access: access.bits(),
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `attr` is a live, fully initialised PathBeneathAttr passed by
    // address; the kernel reads it (read-only) for the duration of the call.
    // `ruleset` is a valid Landlock ruleset fd (BorrowedFd guarantees it is open).
    //
    // INVARIANTS UPHELD: rule type matches the attr struct (PATH_BENEATH); flags 0.
    //
    // FAILURE MODE: an invalid access bit or fd returns -1 + errno (Err); no
    // memory unsafety is reachable.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            std::ptr::from_ref(&attr),
            0_u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Add a "allow `access` on TCP `port`" rule to `ruleset`.
fn add_net_rule(ruleset: BorrowedFd<'_>, access: AccessNet, port: u16) -> io::Result<()> {
    let attr = NetPortAttr {
        allowed_access: access.bits(),
        port: u64::from(port),
    };
    // SAFETY: as add_path_rule, with a NetPortAttr and the NET_PORT rule type.
    //
    // INVARIANTS UPHELD: rule type matches the attr struct (NET_PORT); flags 0.
    //
    // FAILURE MODE: invalid access/port (or pre-ABI-4 kernel) returns -1 + errno.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_NET_PORT,
            std::ptr::from_ref(&attr),
            0_u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Irreversibly restrict the calling process to `ruleset`. Requires
/// `no_new_privs` to already be set (the caller does this).
fn restrict_self(ruleset: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `ruleset` is a valid open Landlock ruleset fd (BorrowedFd). The
    // syscall reads no user memory; it enrolls the calling thread group under
    // the ruleset.
    //
    // INVARIANTS UPHELD: flags 0; no_new_privs is set by the caller beforehand
    // (else the kernel returns EPERM rather than any unsafe behaviour).
    //
    // FAILURE MODE: missing no_new_privs or a bad fd returns -1 + errno (Err).
    // The effect, on success, is irreversible for this process — by design.
    let ret =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0_u32) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Open `path` as an `O_PATH` handle to anchor a Landlock path rule. Safe: the
/// open goes through `std`, needing no `unsafe` of ours.
fn open_o_path(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
}

/// A Landlock ruleset under construction.
///
/// [`Ruleset::new`] handles (denies by default) every access right the running
/// kernel supports; [`Ruleset::allow_path`] / [`Ruleset::allow_port`] punch
/// specific exceptions; [`Ruleset::restrict_current_process`] applies it. The
/// ruleset is inherited across `execve`, so a spawn path builds it and seals
/// just before exec.
pub struct Ruleset {
    handled_fs: AccessFs,
    handled_net: AccessNet,
    path_rules: Vec<(File, AccessFs)>,
    net_rules: Vec<(u16, AccessNet)>,
}

impl Ruleset {
    /// A ruleset that handles every access right the running kernel's Landlock
    /// ABI defines — i.e. denies everything until [`Ruleset::allow_path`] /
    /// [`Ruleset::allow_port`] grant exceptions.
    ///
    /// # Errors
    ///
    /// Propagates [`abi_version`]'s error if Landlock is unavailable.
    pub fn new() -> io::Result<Self> {
        let abi = abi_version()?;
        Ok(Self {
            handled_fs: supported_fs(abi),
            handled_net: supported_net(abi),
            path_rules: Vec::new(),
            net_rules: Vec::new(),
        })
    }

    /// Allow `access` (masked to the handled set) beneath `path`.
    ///
    /// # Errors
    ///
    /// Returns the OS error if `path` cannot be opened.
    pub fn allow_path(&mut self, path: &Path, access: AccessFs) -> io::Result<()> {
        let file = open_o_path(path)?;
        self.path_rules.push((file, access & self.handled_fs));
        Ok(())
    }

    /// Allow `access` (masked to the handled set) on TCP `port`.
    pub fn allow_port(&mut self, port: u16, access: AccessNet) {
        self.net_rules.push((port, access & self.handled_net));
    }

    /// Create the kernel ruleset and install every rule. Does not restrict the
    /// process (so it is safe to call in tests); [`Ruleset::restrict_current_process`]
    /// is the sealing step.
    fn build_fd(&self) -> io::Result<OwnedFd> {
        let attr = RulesetAttr {
            handled_access_fs: self.handled_fs.bits(),
            handled_access_net: self.handled_net.bits(),
        };
        let ruleset = create_ruleset(&attr)?;
        for (file, access) in &self.path_rules {
            if !access.is_empty() {
                add_path_rule(ruleset.as_fd(), *access, file.as_fd())?;
            }
        }
        for (port, access) in &self.net_rules {
            if !access.is_empty() {
                add_net_rule(ruleset.as_fd(), *access, *port)?;
            }
        }
        Ok(ruleset)
    }

    /// Seal: install the rules, set `no_new_privs`, and restrict the current
    /// process to this ruleset. **Irreversible** — and inherited by `execve`'d
    /// children.
    ///
    /// # Errors
    ///
    /// Returns the OS error if ruleset creation, `no_new_privs`, or
    /// `restrict_self` fails.
    pub fn restrict_current_process(self) -> io::Result<()> {
        let ruleset = self.build_fd()?;
        crate::process::set_no_new_privs()?;
        restrict_self(ruleset.as_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_reported_by_the_kernel() {
        // This crate's test hosts (dev + CI) run Landlock-enabled kernels; if
        // Landlock were absent the call would Err. Either way it must not panic
        // or return a nonsense version.
        match abi_version() {
            Ok(v) => assert!(v >= 1, "Landlock ABI version should be >= 1, got {v}"),
            Err(e) => assert!(
                matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)),
                "unexpected error probing Landlock: {e}"
            ),
        }
    }

    #[test]
    fn supported_sets_grow_monotonically_with_abi() {
        for abi in 1..6 {
            assert!(supported_fs(abi).contains(supported_fs(abi - 1)));
            assert!(supported_net(abi).contains(supported_net(abi - 1)));
        }
    }

    #[test]
    fn abi_gates_match_the_kernel_history() {
        assert!(!supported_fs(1).contains(AccessFs::REFER)); // REFER is ABI 2
        assert!(supported_fs(2).contains(AccessFs::REFER));
        assert!(!supported_fs(2).contains(AccessFs::TRUNCATE)); // TRUNCATE is ABI 3
        assert!(supported_fs(3).contains(AccessFs::TRUNCATE));
        assert!(!supported_fs(4).contains(AccessFs::IOCTL_DEV)); // IOCTL_DEV is ABI 5
        assert!(supported_fs(5).contains(AccessFs::IOCTL_DEV));
        assert_eq!(supported_net(3), AccessNet::empty()); // network is ABI 4
        assert_eq!(
            supported_net(4),
            AccessNet::BIND_TCP | AccessNet::CONNECT_TCP
        );
    }

    /// Build and install a ruleset (`create_ruleset` + `add_rule`) without sealing —
    /// exercises the syscall wrappers without sandboxing the test process.
    #[test]
    fn build_a_ruleset_without_restricting() {
        let Ok(mut rs) = Ruleset::new() else {
            return; // no Landlock on this host: skip
        };
        rs.allow_path(
            Path::new("/usr"),
            AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE,
        )
        .expect("allow /usr");
        rs.allow_port(443, AccessNet::CONNECT_TCP); // no-op below ABI 4
        let fd = rs.build_fd().expect("create ruleset + add rules");
        drop(fd); // not sealing; the syscalls succeeding is the assertion
    }

    /// Seal a ruleset in a child process and confirm it actually denies an
    /// un-allowed path while permitting an allowed one. Landlock is unprivileged,
    /// so this needs no root. The child does only async-signal-safe work after
    /// the fork (Landlock syscalls + libc open/close + _exit); all allocation
    /// happens before the fork.
    #[test]
    fn restrict_self_enforces_the_ruleset() {
        use std::ffi::CString;

        let Ok(mut rs) = Ruleset::new() else {
            return; // no Landlock: skip
        };
        rs.allow_path(
            Path::new("/usr"),
            AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE,
        )
        .expect("allow /usr");
        let allowed = CString::new("/usr").expect("cstring");
        let forbidden = CString::new("/etc/hostname").expect("cstring");

        // SAFETY: fork() in a multi-threaded test. The child branch performs only
        // async-signal-safe operations (the Landlock syscalls via restrict, libc
        // open/close, and _exit) and never returns to the test harness; every
        // allocation (the ruleset, the CStrings) happened before the fork.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = child_verdict(rs, &allowed, &forbidden);
                // SAFETY: _exit ends the child immediately without running Drop
                // glue or atexit handlers — correct after a fork.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                // Child exit codes: 0 = correct; 1 = forbidden path was allowed;
                // 2 = allowed path was denied; 3 = sealing failed.
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "sandboxed child reported failure: {status:?}"
                );
            }
        }
    }

    /// Child body: seal `rs`, then check the forbidden path is denied and the
    /// allowed path is permitted. Returns the process exit code (0 = correct).
    fn child_verdict(rs: Ruleset, allowed: &std::ffi::CStr, forbidden: &std::ffi::CStr) -> i32 {
        if rs.restrict_current_process().is_err() {
            return 3; // sealing itself failed
        }
        // SAFETY: open with a valid NUL-terminated path and no userspace buffers;
        // returns an fd or -1. Pure syscall, async-signal-safe.
        let f = unsafe { libc::open(forbidden.as_ptr(), libc::O_RDONLY) };
        if f >= 0 {
            // SAFETY: closing an fd we just opened.
            unsafe { libc::close(f) };
            return 1; // forbidden read was allowed — sandbox did not bite
        }
        // SAFETY: as above; O_DIRECTORY because /usr is a directory (needs READ_DIR).
        let a = unsafe { libc::open(allowed.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if a < 0 {
            return 2; // allowed read was denied — over-restricted
        }
        // SAFETY: closing an fd we just opened.
        unsafe { libc::close(a) };
        0
    }
}
