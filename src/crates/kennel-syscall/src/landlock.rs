//! Landlock filesystem/network sandboxing — hand-rolled bindings.
//!
//! # Purpose
//!
//! Apply a Landlock ruleset that confines the workload's filesystem and TCP
//! access (the design's primary filesystem-and-exec enforcement, `docs/design/08`).
//! Landlock is three syscalls and a few packed structs from the kernel UAPI
//! (`uapi/linux/landlock.h`); small enough that owning the `unsafe` is preferable
//! to the `landlock` crate's transitive cost (`syn` + the first proc-macros in
//! the privileged dependency tree). These definitions are taken from the kernel
//! ABI — facts about the kernel interface — not derived from the `landlock`
//! crate's source.
//!
//! # `unsafe`
//!
//! Each of the three Landlock syscalls has one raw FFI site, mirroring
//! `kennel-bpf`'s `bpf()`: `sys_create_ruleset` and `sys_add_rule` take typed
//! references (so they are sound to call from safe code, leaving `abi_version` /
//! `create_ruleset` / `add_path_rule` / `add_net_rule` `unsafe`-free), and
//! `restrict_self` holds the third. With the `OwnedFd` adoption in
//! `create_ruleset` that is four `unsafe` blocks, each carrying the §4 `SAFETY:` /
//! `INVARIANTS UPHELD:` / `FAILURE MODE:` comment (this module is the reason the
//! crate carries `#![allow(unsafe_code)]`). Opening rule paths goes through `std`
//! (`O_PATH`), and `no_new_privs` through nix — both safe. Landlock is
//! unprivileged: `restrict_self` needs no capabilities.
//!
//! # Kernel support
//!
//! The project floor is 6.10, which is Landlock ABI 5. [`abi_version`] queries
//! the running kernel so callers can refuse an unsupported one and mask the
//! requested access rights to what that ABI defines (requesting an unknown bit
//! is `EINVAL`). ABI history: 1 = filesystem (5.13), 2 = `REFER` (5.19),
//! 3 = `TRUNCATE` (6.2), 4 = TCP network (6.7), 5 = `IOCTL_DEV` (6.10),
//! 6 = scoping — abstract-AF_UNIX + signals (6.12), 7 (6.16). The crate handles
//! every right an ABI defines and degrades to the empty set below it, so a newer
//! kernel (e.g. 6.17 reports ABI 7) is used to its supported extent and an older
//! one is never asked for a bit it lacks. Scoping (ABI 6) is the kernel-native
//! enforcement of the `unix.abstract = "deny"` posture (`docs/design/07-4`) and a
//! complement to the PID-namespace signal isolation (`docs/design/07-7`), superseding
//! the seccomp `connect()` filter those sections describe as a fallback.

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

bitflags! {
    /// Landlock scoping (`LANDLOCK_SCOPE_*`, ABI 6). Unlike the access rights,
    /// scoping takes no per-resource exceptions: handling a scope confines the
    /// sandboxed process from reaching that resource class *outside* its own
    /// Landlock domain.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Scope: u64 {
        /// `connect(2)` to an abstract-namespace AF_UNIX socket bound outside the
        /// sandbox (the `docs/design/07-4` abstract-socket gap; closed natively from
        /// Landlock ABI 6).
        const ABSTRACT_UNIX_SOCKET = 0x1;
        /// Send a signal to a process outside the sandbox (`docs/design/07-7`).
        const SIGNAL = 0x2;
    }
}

/// `struct landlock_ruleset_attr`. `handled_access_net` exists from ABI 4 and
/// `scoped` from ABI 6; the kernel accepts the full struct on older ABIs as long
/// as the unknown trailing bytes are zero, which they are when `supported_net` /
/// `supported_scope` mask those fields empty (the kernel's extensible-struct
/// `copy_struct_from_user` contract).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
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

/// Raw `landlock_create_ruleset`. With `attr = Some`, creates a ruleset and
/// returns its fd as a non-negative integer; with `attr = None` it is the ABI
/// probe (pass `CREATE_RULESET_VERSION` as `flags`) and returns the version.
/// The raw syscall result is returned verbatim — the caller maps `< 0` to errno.
///
/// This is the single home for the `landlock_create_ruleset` FFI, mirroring
/// `kennel-bpf`'s `bpf()`; because its only inputs are an `Option<&RulesetAttr>`
/// (guaranteed live and correctly sized) and a `flags` word, it is sound to call
/// from safe code, so [`abi_version`] and [`create_ruleset`] carry no `unsafe`.
fn sys_create_ruleset(attr: Option<&RulesetAttr>, flags: libc::c_uint) -> i64 {
    let (ptr, size) = attr.map_or((std::ptr::null::<libc::c_void>(), 0_usize), |a| {
        (
            std::ptr::from_ref(a).cast::<libc::c_void>(),
            size_of::<RulesetAttr>(),
        )
    });
    // SAFETY: `landlock_create_ruleset` reads `size` bytes through `ptr` and does
    // not retain it. With `Some(attr)` the pair is (live RulesetAttr, its exact
    // byte length); with `None` it is (NULL, 0) — the kernel's version-probe form,
    // which dereferences nothing. Either way pointer and size describe the same
    // object (a struct, or nothing).
    //
    // INVARIANTS UPHELD: `flags` is 0 to create or CREATE_RULESET_VERSION to probe;
    // no memory we own is mutated (the kernel only reads).
    //
    // FAILURE MODE: an unsupported/invalid request returns -1 + errno (mapped by
    // the caller); no memory unsafety is reachable on any path.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr, size, flags) }
}

/// Raw `landlock_add_rule`. `attr` is a reference to the rule struct the kernel
/// selects from `rule_type` (`RULE_PATH_BENEATH` ↔ [`PathBeneathAttr`],
/// `RULE_NET_PORT` ↔ [`NetPortAttr`]). Sound to call from safe code: the kernel
/// reads only the fixed-size struct for `rule_type`, and a live `&T` is always
/// valid for that read, so [`add_path_rule`] / [`add_net_rule`] carry no `unsafe`.
fn sys_add_rule<T>(ruleset: BorrowedFd<'_>, rule_type: libc::c_uint, attr: &T) -> io::Result<()> {
    // SAFETY: `landlock_add_rule` reads the fixed-size rule struct selected by
    // `rule_type` through the pointer and does not retain it; `attr: &T` is a live
    // reference the caller pairs with the matching `rule_type`. `ruleset` is an
    // open ruleset fd (BorrowedFd guarantees it). The kernel only reads.
    //
    // INVARIANTS UPHELD: the two call sites pair the correct attr type with
    // `rule_type` (PATH_BENEATH↔PathBeneathAttr, NET_PORT↔NetPortAttr); flags 0.
    //
    // FAILURE MODE: a wrong fd or unsupported rule returns -1 + errno (Err); no
    // memory unsafety is reachable.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            rule_type,
            std::ptr::from_ref(attr),
            0_u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Query the Landlock ABI version supported by the running kernel.
///
/// # Errors
///
/// Returns the OS error if the kernel lacks Landlock (`ENOSYS`) or has it
/// disabled (`EOPNOTSUPP`), or [`io::ErrorKind::InvalidData`] in the
/// can't-happen case of an implausibly large version.
pub fn abi_version() -> io::Result<u32> {
    // The (NULL, 0, VERSION) probe form (uapi/linux/landlock.h): a kernel without
    // Landlock returns -1 + errno (ENOSYS / EOPNOTSUPP), surfaced below as Err.
    let ret = sys_create_ruleset(None, CREATE_RULESET_VERSION);
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

/// The scoping an `abi` kernel understands (none before ABI 6). Requesting a
/// scope bit an older kernel lacks is `EINVAL`, so callers mask to this.
#[must_use]
pub fn supported_scope(abi: u32) -> Scope {
    if abi >= 6 {
        Scope::ABSTRACT_UNIX_SOCKET | Scope::SIGNAL
    } else {
        Scope::empty()
    }
}

/// Create a ruleset fd governing the handled access rights in `attr`.
fn create_ruleset(attr: &RulesetAttr) -> io::Result<OwnedFd> {
    let ret = sys_create_ruleset(Some(attr), 0);
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
    sys_add_rule(ruleset, RULE_PATH_BENEATH, &attr)
}

/// Add a "allow `access` on TCP `port`" rule to `ruleset`.
fn add_net_rule(ruleset: BorrowedFd<'_>, access: AccessNet, port: u16) -> io::Result<()> {
    let attr = NetPortAttr {
        allowed_access: access.bits(),
        port: u64::from(port),
    };
    sys_add_rule(ruleset, RULE_NET_PORT, &attr)
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
    handled_scope: Scope,
    path_rules: Vec<(File, AccessFs)>,
    net_rules: Vec<(u16, AccessNet)>,
}

impl Ruleset {
    /// A ruleset that handles every access right the running kernel's Landlock
    /// ABI defines and enables every scope it supports — i.e. denies everything,
    /// and confines abstract-AF_UNIX/signal reach to the sandbox, until
    /// [`Ruleset::allow_path`] / [`Ruleset::allow_port`] grant exceptions.
    /// Scoping is all-or-nothing (no per-resource exception) and on by default,
    /// the native form of the `unix.abstract = "deny"` posture (`docs/design/07-4`).
    ///
    /// # Errors
    ///
    /// Propagates [`abi_version`]'s error if Landlock is unavailable.
    pub fn new() -> io::Result<Self> {
        let abi = abi_version()?;
        Ok(Self {
            handled_fs: supported_fs(abi),
            handled_net: supported_net(abi),
            handled_scope: supported_scope(abi),
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
        let mut access = access & self.handled_fs;
        // Landlock rejects directory-only rights (READ_DIR, MAKE_*, REMOVE_*, REFER) on
        // a regular file with EINVAL. Mask the access to the file-applicable subset when
        // the grant target is not a directory, so a read/write grant naming a file (e.g.
        // `/etc/ld.so.cache`) yields a valid rule rather than a fatal EINVAL. `fstat` is
        // permitted on the `O_PATH` fd.
        if !file.metadata()?.is_dir() {
            access &= AccessFs::EXECUTE
                | AccessFs::WRITE_FILE
                | AccessFs::READ_FILE
                | AccessFs::TRUNCATE
                | AccessFs::IOCTL_DEV;
        }
        self.path_rules.push((file, access));
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
            scoped: self.handled_scope.bits(),
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
    fn a_file_grant_drops_directory_only_rights() {
        // Landlock rejects a path rule on a regular file that requests directory-only
        // rights (READ_DIR, MAKE_*, REMOVE_*, REFER) with EINVAL — so `allow_path` must
        // mask them off for a non-directory. Regression for the `/etc/ld.so.cache`
        // spawn failure: a read grant carries READ_FILE|READ_DIR|EXECUTE.
        let Ok(mut rs) = Ruleset::new() else {
            return; // no Landlock on this host
        };
        // current_exe() is a regular file; granting it directory rights must mask them.
        let exe = std::env::current_exe().expect("current_exe");
        rs.allow_path(
            &exe,
            AccessFs::READ_FILE | AccessFs::READ_DIR | AccessFs::EXECUTE,
        )
        .expect("allow_path on a file");
        let (_, access) = rs.path_rules.last().expect("a path rule was recorded");
        assert!(
            !access.contains(AccessFs::READ_DIR),
            "READ_DIR (a directory-only right) must be masked off a regular file, got {access:?}"
        );
        assert!(
            access.contains(AccessFs::READ_FILE) && access.contains(AccessFs::EXECUTE),
            "file-applicable rights must survive, got {access:?}"
        );

        // A directory grant keeps its directory rights.
        rs.allow_path(Path::new("/"), AccessFs::READ_FILE | AccessFs::READ_DIR)
            .expect("allow_path on a dir");
        let (_, access) = rs.path_rules.last().expect("a path rule");
        assert!(
            access.contains(AccessFs::READ_DIR),
            "READ_DIR must survive on a directory, got {access:?}"
        );
    }

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
        for abi in 1..8 {
            assert!(supported_fs(abi).contains(supported_fs(abi - 1)));
            assert!(supported_net(abi).contains(supported_net(abi - 1)));
            assert!(supported_scope(abi).contains(supported_scope(abi - 1)));
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
        assert_eq!(supported_scope(5), Scope::empty()); // scoping is ABI 6
        assert_eq!(
            supported_scope(6),
            Scope::ABSTRACT_UNIX_SOCKET | Scope::SIGNAL
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

    /// Build an abstract-namespace `AF_UNIX` address (NUL-prefixed `name`) and its
    /// length, with raw libc (the crate's socket style, cf. `netlink`). Kept lint-
    /// clean: no per-element indexing or `as` casts.
    fn abstract_addr(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
        // SAFETY: sockaddr_un is plain-old-data; an all-zero value is valid.
        let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sun.sun_family =
            libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits sa_family_t");
        // SAFETY: `sun_path` is `[c_char; N]`; c_char and u8 share a 1-byte POD
        // layout, so a u8 slice aliasing the same storage is sound for a byte copy.
        // The abstract namespace is NUL-prefixed, so the name starts at index 1.
        let path: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                sun.sun_path.as_mut_ptr().cast::<u8>(),
                sun.sun_path.len(),
            )
        };
        if let Some(dst) = path.get_mut(1..=name.len()) {
            dst.copy_from_slice(name);
        }
        let raw_len = size_of::<libc::sa_family_t>()
            .saturating_add(1)
            .saturating_add(name.len());
        let len = libc::socklen_t::try_from(raw_len).expect("addr len fits");
        (sun, len)
    }

    /// ABI-6 scoping must deny a sandboxed process `connect(2)` to an
    /// abstract-namespace `AF_UNIX` socket bound outside its domain (the native
    /// `unix.abstract = "deny"`), while the same socket is reachable un-sandboxed.
    /// Landlock is unprivileged, so this needs no root.
    #[test]
    fn scoping_denies_a_host_abstract_socket() {
        let Ok(abi) = abi_version() else {
            return; // no Landlock: skip
        };
        if abi < 6 {
            return; // scoping is ABI 6+: skip on older kernels
        }

        let name = format!("kennel-scope-{}", std::process::id());
        let (addr, addrlen) = abstract_addr(name.as_bytes());
        let addr_ptr = std::ptr::from_ref(&addr).cast::<libc::sockaddr>();

        // SAFETY: socket/bind/listen/connect/close with valid constants and a live
        // sockaddr (`addr` outlives the block); each result is checked. The control
        // connect proves the abstract name is reachable when un-sandboxed.
        let listener = unsafe {
            let l = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            assert!(l >= 0, "socket: {}", io::Error::last_os_error());
            assert_eq!(
                libc::bind(l, addr_ptr, addrlen),
                0,
                "bind abstract: {}",
                io::Error::last_os_error()
            );
            assert_eq!(
                libc::listen(l, 1),
                0,
                "listen: {}",
                io::Error::last_os_error()
            );
            let c = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            assert_eq!(
                libc::connect(c, addr_ptr, addrlen),
                0,
                "control connect should reach it"
            );
            libc::close(c);
            l
        };
        // SAFETY: a fresh AF_UNIX socket the sandboxed child will try to connect.
        let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(client >= 0, "client socket");
        let rs = Ruleset::new().expect("ruleset"); // scoping on by default

        // SAFETY: fork() in a multi-threaded test. The child performs only
        // async-signal-safe work (the Landlock restrict syscalls, one libc::connect
        // on a pre-created fd, _exit) and never returns to the harness; all
        // allocation (the addr, the ruleset) happened before the fork.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = scope_child_verdict(rs, client, addr_ptr, addrlen);
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                // SAFETY: closing fds the parent owns.
                unsafe {
                    libc::close(client);
                    libc::close(listener);
                }
                // 0 = connect denied by the scope (EPERM/EACCES); 1 = connect allowed
                // (scope did not bite); 2 = denied with an unrelated errno; 3 = seal failed.
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "scoped child must be denied the abstract socket: {status:?}"
                );
            }
        }
    }

    /// Child body for the scoping test: seal `rs`, then `connect` the pre-created
    /// `client_fd` to the abstract address. Returns the exit code (0 = EACCES).
    fn scope_child_verdict(
        rs: Ruleset,
        client_fd: RawFd,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> i32 {
        if rs.restrict_current_process().is_err() {
            return 3;
        }
        // SAFETY: connect on a valid pre-created AF_UNIX fd with a live sockaddr
        // (built before the fork); a pure syscall, async-signal-safe.
        let r = unsafe { libc::connect(client_fd, addr, addrlen) };
        if r == 0 {
            return 1; // connect succeeded — scoping did not deny it
        }
        // A Landlock scope denies abstract-socket connect with EPERM; accept EACCES
        // too (the errno other Landlock denials use) so the test is robust to it.
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => 0, // denied by the scope
            _ => 2,                                // denied, but by an unrelated errno
        }
    }

    /// `IOCTL_DEV` (ABI 5) must gate a device `ioctl`: with the ruleset handling
    /// it, a granted device node's `ioctl` clears Landlock only when the path rule
    /// also grants `IOCTL_DEV`; otherwise it is denied (EACCES). Landlock is
    /// unprivileged. Uses `/dev/null` + `TIOCGWINSZ` — a gated (non-exempt) ioctl
    /// that `/dev/null` answers with ENOTTY once it clears Landlock.
    #[test]
    fn ioctl_dev_gates_device_ioctls() {
        let Ok(abi) = abi_version() else {
            return; // no Landlock: skip
        };
        if abi < 5 {
            return; // IOCTL_DEV is ABI 5+: skip
        }
        assert!(
            ioctl_denied_under(false),
            "a device ioctl without an IOCTL_DEV grant must be denied"
        );
        assert!(
            !ioctl_denied_under(true),
            "a device ioctl with an IOCTL_DEV grant must clear Landlock"
        );
    }

    /// Seal a ruleset granting `/dev/null` read+write (+ `IOCTL_DEV` iff
    /// `grant_ioctl`) in a child, then `ioctl(TIOCGWINSZ)` it. Returns whether
    /// Landlock denied the ioctl — true only when the grant is absent.
    fn ioctl_denied_under(grant_ioctl: bool) -> bool {
        let Ok(mut rs) = Ruleset::new() else {
            return grant_ioctl; // no Landlock: make the caller's asserts vacuous
        };
        let mut access = AccessFs::READ_FILE | AccessFs::WRITE_FILE;
        if grant_ioctl {
            access |= AccessFs::IOCTL_DEV;
        }
        rs.allow_path(Path::new("/dev/null"), access)
            .expect("allow /dev/null");
        let devnull = std::ffi::CString::new("/dev/null").expect("cstring");

        // SAFETY: fork(); the child does only async-signal-safe work (Landlock
        // restrict, libc open/ioctl/close, _exit) and never returns to the harness;
        // all allocation happened before the fork.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = ioctl_child_verdict(rs, &devnull);
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                // 0 = ioctl denied (EACCES); 1 = ioctl cleared Landlock; 2 = setup failed.
                matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0))
            }
        }
    }

    /// Child body: seal `rs`, open `/dev/null`, `ioctl(TIOCGWINSZ)`. Returns 0 if
    /// Landlock denied it (EACCES), 1 if it cleared Landlock (ENOTTY from the
    /// device), 2 on a setup failure.
    fn ioctl_child_verdict(rs: Ruleset, devnull: &std::ffi::CStr) -> i32 {
        if rs.restrict_current_process().is_err() {
            return 2;
        }
        // SAFETY: open a valid NUL-terminated path; returns an fd or -1.
        let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return 2; // open should be permitted (READ_FILE granted)
        }
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl on a valid fd with a writable winsize out-param.
        let r = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, std::ptr::from_mut(&mut ws)) };
        let errno = io::Error::last_os_error().raw_os_error();
        // SAFETY: closing an fd we just opened.
        unsafe { libc::close(fd) };
        if r == 0 {
            return 1; // the ioctl succeeded outright — it cleared Landlock
        }
        match errno {
            Some(libc::EACCES) => 0, // Landlock denied the ioctl
            _ => 1,                  // ENOTTY etc. — reached the device, i.e. cleared Landlock
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
