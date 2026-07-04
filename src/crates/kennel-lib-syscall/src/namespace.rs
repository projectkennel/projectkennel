//! Linux namespace operations.
//!
//! Safe wrappers (over nix) for `unshare(2)`, the first step of the spawn
//! sequence (Kennel book Vol 2 ch.2 (Process and Privilege Model)). The flag set is our own [`Namespaces`] type
//! rather than a re-export, so the rest of the workspace depends on this curated
//! API and not on nix's `CloneFlags` directly. No `unsafe` of ours.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use bitflags::bitflags;
use nix::sched::CloneFlags;

bitflags! {
    /// The namespaces the spawn sequence may unshare. Each maps to a `CLONE_NEW*`
    /// flag; the numeric values here are our own (translated in [`to_clone_flags`]),
    /// not the kernel constants.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Namespaces: u32 {
        /// Mount namespace (`CLONE_NEWNS`).
        const MOUNT = 1 << 0;
        /// PID namespace (`CLONE_NEWPID`); only children enter the new namespace.
        const PID = 1 << 1;
        /// System V IPC namespace (`CLONE_NEWIPC`).
        const IPC = 1 << 2;
        /// Network namespace (`CLONE_NEWNET`).
        const NET = 1 << 3;
        /// User namespace (`CLONE_NEWUSER`).
        const USER = 1 << 4;
        /// UTS (hostname) namespace (`CLONE_NEWUTS`).
        const UTS = 1 << 5;
        /// Cgroup namespace (`CLONE_NEWCGROUP`).
        const CGROUP = 1 << 6;
    }
}

/// Translate our [`Namespaces`] set to nix's `CloneFlags`.
fn to_clone_flags(ns: Namespaces) -> CloneFlags {
    let mut f = CloneFlags::empty();
    f.set(CloneFlags::CLONE_NEWNS, ns.contains(Namespaces::MOUNT));
    f.set(CloneFlags::CLONE_NEWPID, ns.contains(Namespaces::PID));
    f.set(CloneFlags::CLONE_NEWIPC, ns.contains(Namespaces::IPC));
    f.set(CloneFlags::CLONE_NEWNET, ns.contains(Namespaces::NET));
    f.set(CloneFlags::CLONE_NEWUSER, ns.contains(Namespaces::USER));
    f.set(CloneFlags::CLONE_NEWUTS, ns.contains(Namespaces::UTS));
    f.set(CloneFlags::CLONE_NEWCGROUP, ns.contains(Namespaces::CGROUP));
    f
}

/// Disassociate parts of the calling process's execution context, creating new
/// namespaces (`unshare(2)`).
///
/// Note the kernel semantics: a new PID namespace takes effect only for
/// *children* forked afterwards, not the caller; the others affect the caller
/// immediately. Most namespaces require `CAP_SYS_ADMIN` (in the current user
/// namespace); `USER` does not, and unsharing it first is the usual way an
/// unprivileged caller gains the capability for the rest.
///
/// # Errors
///
/// Returns the OS error if the unshare is not permitted (`EPERM`) or a flag is
/// unsupported.
pub fn unshare(ns: Namespaces) -> io::Result<()> {
    nix::sched::unshare(to_clone_flags(ns)).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// `clone(2)` a child that is **PID 1** of a fresh PID namespace, entering all of
/// `ns` in a single syscall, and run `child` in it.
///
/// This is the privhelper-factory's construction primitive (Kennel book Vol 2 ch.2 (Process and Privilege Model)): it
/// `clone`s once with `NEWUSER|NEWNS|NEWPID|NEWIPC[|NEWNET]`, and the cloned child is
/// itself PID 1 of the new PID namespace (a `clone(CLONE_NEWPID)` child *is* the
/// namespace init, unlike an `unshare` caller, which is not), so no
/// second fork is needed. The parent gets the child's **host** pid back — the fact
/// kenneld needs to gate the binder lifecycle verbs and to open
/// `/proc/<pid>/root/dev/binderfs/binder`.
///
/// # The map-write handshake (caller's responsibility)
///
/// With `CLONE_NEWUSER`, the child starts with **no** uid/gid mapping and therefore
/// **no** capabilities in the new user namespace until the parent writes
/// `/proc/<pid>/uid_map` and `gid_map`. So `child` MUST block (e.g. read a pipe)
/// until the parent signals the maps are written before it attempts any privileged
/// operation. This primitive does not impose that handshake — it only creates the
/// process; the construction closure wires the synchronisation.
///
/// # The child closure
///
/// `child` runs in the cloned process and **must not return** — it either
/// `execve`s/`fexecve`s the next image or `_exit`s. It is the same constrained
/// post-`clone` environment as a `pre_exec` hook — single-threaded, address space
/// shared copy-on-write with the parent — so it must keep to async-signal-safe work
/// (and the syscalls the construction sequence needs) and not unwind into the
/// parent's `Drop`/atexit glue. The contract cannot be expressed in the type on
/// stable Rust (the never type is unstable in a trait bound), so a closure that
/// does return is treated as a construction bug: the child is terminated `_exit(127)`
/// fail-closed rather than ever continuing as a second copy of the parent.
///
/// # Errors
///
/// Returns the OS error if `clone` fails (e.g. `EPERM` where the host forbids the
/// requested namespaces). On success the parent returns `Ok(child_pid)`; the child
/// never returns to the caller.
pub fn clone_pid1<F>(ns: Namespaces, child: F) -> io::Result<libc::pid_t>
where
    F: FnOnce(),
{
    // The clone flags: the namespace set plus SIGCHLD as the termination signal, so
    // the parent can `waitpid` the child (fork() implies SIGCHLD; raw clone does not).
    // The flag bits and SIGCHLD are kernel constants known non-negative, so
    // `unsigned_abs` reproduces their exact bit value and `u64::from` widens totally —
    // no cast, no panic path.
    let flags: u64 = u64::from(to_clone_flags(ns).bits().unsigned_abs())
        | u64::from(libc::SIGCHLD.unsigned_abs());
    // SAFETY: a raw `clone` syscall with a NULL child stack and all-zero
    // parent_tid/child_tid/tls behaves like `fork()` — the child returns 0 on a
    // copy-on-write copy of the caller's stack, the parent gets the child pid. Passing
    // zero for every pointer argument makes the call robust to the per-arch ordering of
    // clone's stack/tid/tls operands (only their values, all zero, would differ). The
    // child branch runs the caller's closure under the same post-fork discipline as a
    // pre_exec hook (module docs / spawn.rs) and then `_exit`s — it never returns into
    // safe parent code.
    //
    // INVARIANTS UPHELD: exactly one child is created; the parent's only side effect is
    // obtaining the pid.
    //
    // FAILURE MODE: a clone failure surfaces as Err (no child exists); a child closure
    // that wrongly returns is terminated _exit(127) rather than continuing.
    let ret = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    match ret {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            child();
            // The closure must have execed or _exited; if it returned, fail closed.
            // SAFETY: _exit ends the child without unwinding the parent's shared state.
            unsafe { libc::_exit(127) }
        }
        // A clone-returned pid is a real, small process id and always fits in pid_t.
        pid => libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("clone returned an out-of-range pid")),
    }
}

/// `fork(2)` a child that runs `setup`, then **holds** — blocking forever to keep it alive.
///
/// Whatever `setup` established (a namespace, a mount) lives as long as the child. Returns the
/// child's host pid once `setup` reports success.
///
/// This is the unprivileged mesh-bus mount holder primitive (§7.13.4a): the caller's `setup` (in a
/// `#![forbid(unsafe_code)]` crate) creates a user namespace, self-maps, and mounts a binderfs — all
/// unprivileged inside the new userns — and this wrapper owns the `fork`/pipe/`close_range`/`pause`.
///
/// **`fork`, not `clone`:** glibc's `fork` runs the `pthread_atfork` handlers that quiesce the
/// `malloc` arenas, so `setup` may allocate even though the caller is multi-threaded; a raw `clone`
/// would not. **`setup` discipline:** it runs in the forked child, so it must keep to atfork-safe
/// `malloc` and plain syscalls and take **no** std lock (no `println!`/`eprintln!`).
///
/// On success the child writes a ready byte up a pipe, drops every inherited fd (`close_range` from
/// fd 3 — kenneld's sockets and loopers must not leak into the resident holder), and `pause`s; the
/// parent returns its pid. On `setup` failure (or fork/pipe error) the child exits and the parent's
/// ready read sees EOF — reported as an error, the child reaped.
///
/// # Errors
///
/// The OS error if `pipe`/`fork` fails, or [`io::ErrorKind::Other`] if `setup` failed in the child.
pub fn fork_hold<F>(setup: F) -> io::Result<libc::pid_t>
where
    F: FnOnce() -> io::Result<()>,
{
    const READY: u8 = 1;
    let mut fds = [0i32; 2];
    // SAFETY: `pipe2` writes exactly two fds into a 2-element array; `O_CLOEXEC` is harmless here.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let [ready_r, ready_w] = fds;

    // SAFETY: `fork`. The child runs only atfork-safe `malloc` + syscalls (the `setup` contract) and
    // never returns to the caller — it `pause`s on success or `_exit`s on failure.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY (whole child branch): post-fork, single-threaded, async-signal-disciplined.
        unsafe { libc::close(ready_r) };
        let ok = setup().is_ok();
        let byte = [u8::from(ok) * READY];
        // SAFETY: write the 1-byte verdict up the pipe.
        unsafe { libc::write(ready_w, byte.as_ptr().cast(), 1) };
        if ok {
            // SAFETY: drop every inherited fd (incl. the ready pipe), then block forever.
            unsafe {
                libc::close_range(3, libc::c_uint::MAX, 0);
                loop {
                    libc::pause();
                }
            }
        }
        // SAFETY: `setup` failed — exit without unwinding the (forked) caller's state.
        unsafe { libc::_exit(1) };
    }

    // PARENT.
    // SAFETY: close our write end so a child death is EOF on `ready_r`.
    unsafe { libc::close(ready_w) };
    if pid < 0 {
        // SAFETY: clean up the unused read end.
        unsafe { libc::close(ready_r) };
        return Err(io::Error::last_os_error());
    }
    let mut byte = [0u8; 1];
    // SAFETY: read up to one verdict byte; then close the read end.
    let n = unsafe { libc::read(ready_r, byte.as_mut_ptr().cast(), 1) };
    unsafe { libc::close(ready_r) };
    if n == 1 && byte[0] == READY {
        Ok(pid)
    } else {
        let _ = crate::process::kill_pid(pid);
        let _ = crate::process::wait_pid(pid);
        Err(io::Error::other("forked holder setup failed"))
    }
}

/// Set this UTS namespace's hostname (`sethostname(2)`).
///
/// The construction child calls this after its UTS unshare; it holds `CAP_SYS_ADMIN`
/// over the new namespace via the identity-mapped user namespace, so no host
/// privilege is involved (`[identity].hostname`, W12).
///
/// # Errors
///
/// The OS error (`EPERM` without `CAP_SYS_ADMIN` over the UTS namespace,
/// `EINVAL`/`ENAMETOOLONG` for a bad length).
pub fn set_hostname(name: &str) -> io::Result<()> {
    // SAFETY: the pointer/length pair describes the borrowed `name` bytes for the
    // duration of the call; sethostname reads them and holds no reference after.
    let rc = unsafe { libc::sethostname(name.as_ptr().cast::<libc::c_char>(), name.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `open_tree(path, OPEN_TREE_CLONE)` → a detached, movable mount (the §7.13.4a mesh handoff).
///
/// Clones the mount subtree at `path` into a new anonymous mount, returned as an fd that can be
/// SCM-passed to another process and later attached with [`move_mount_fd`]. `OPEN_TREE_CLONE`
/// requires `CAP_SYS_ADMIN` in the *caller's* user namespace, and the mount must live in the
/// caller's mount namespace — so only the holder that mounted the binderfs can clone it.
///
/// # Errors
///
/// The OS error if `open_tree` fails (`EPERM` without `CAP_SYS_ADMIN`, `ENOENT`, …).
pub fn open_tree_clone(path: &std::path::Path) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags =
        libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_RECURSIVE as libc::c_uint;
    // SAFETY: `open_tree` reads the NUL-terminated `path` and returns an fd or -1; no retained pointer.
    let fd = unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = std::os::fd::RawFd::try_from(fd)
        .map_err(|_| io::Error::other("open_tree returned an out-of-range fd"))?;
    // SAFETY: `fd` is a fresh, owned mount fd from a successful `open_tree`.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// `move_mount(detached_fd → target)` — attach a detached mount (from [`open_tree_clone`]).
///
/// The other half of the mesh handoff: a process holding `CAP_SYS_ADMIN` in its own user namespace
/// attaches a detached binderfs clone (passed to it via `SCM_RIGHTS`) onto `target` in its mount
/// namespace — even when the clone was created by a different (the holder's) user namespace.
///
/// # Errors
///
/// The OS error if `move_mount` fails (`EPERM` without `CAP_SYS_ADMIN` in the target's mount ns, …).
pub fn move_mount_fd(
    detached: std::os::fd::BorrowedFd<'_>,
    target: &std::path::Path,
) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let t = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: from_fd is the detached mount; to-path is `target`; flags name an empty from-path.
    let r = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            detached.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            t.as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fork a resident **mount holder** that mounts via `setup`, then serves `open_tree(CLONE)` requests.
///
/// Returns the holder's pid and the kenneld-side control socket. Each one-byte request `kenneld`
/// writes on that socket makes the holder clone its mount at `clone_dir` (a fresh movable binderfs
/// clone) and SCM-send back the detached mount fd — one per mesh participant. EOF on the socket ends
/// the holder, dropping its mount namespace.
///
/// `setup` runs once in the forked child under the same atfork-safe contract as [`fork_hold`]
/// (atfork-safe `malloc` + syscalls, no std lock): it creates the userns, self-maps, and mounts the
/// binderfs the serve loop clones. The child drops every other inherited fd before serving, so
/// `kenneld`'s sockets and loopers never leak into the long-lived holder.
///
/// # Errors
///
/// The OS error if the socketpair or `fork` fails, or [`io::ErrorKind::Other`] if `setup` failed.
pub fn fork_mount_holder<F>(
    setup: F,
    clone_dir: &std::path::Path,
) -> io::Result<(libc::pid_t, std::os::fd::OwnedFd)>
where
    F: FnOnce() -> io::Result<()>,
{
    const READY: u8 = 1;
    let (kenneld_end, holder_end) = crate::scm::seqpacket_pair()?;
    let kenneld_raw = kenneld_end.as_raw_fd();
    let holder_raw = holder_end.as_raw_fd();
    let dir = clone_dir.to_owned();

    // SAFETY: `fork`. The child runs only atfork-safe `malloc` + syscalls (the `setup` contract) and
    // never returns to the caller — it serves on its socket or `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY (whole child branch): post-fork, single-threaded, async-signal-disciplined.
        unsafe { libc::close(kenneld_raw) };
        let ok = setup().is_ok();
        let byte = [u8::from(ok) * READY];
        // SAFETY: report the mount verdict up the socket.
        unsafe { libc::write(holder_raw, byte.as_ptr().cast(), 1) };
        if !ok {
            // SAFETY: setup failed — exit without unwinding the forked caller's state.
            unsafe { libc::_exit(1) };
        }
        // Re-home the serve socket at fd 3, then drop every other inherited fd.
        // SAFETY: dup the serve socket low, then close everything above it.
        unsafe {
            if holder_raw != 3 {
                libc::dup2(holder_raw, 3);
            }
            libc::close_range(4, libc::c_uint::MAX, 0);
        }
        serve_mount_clones(3, &dir); // never returns
    }

    // PARENT.
    drop(holder_end); // close our copy of the holder end
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut byte = [0u8; 1];
    // SAFETY: read the one-byte mount verdict.
    let n = unsafe { libc::read(kenneld_raw, byte.as_mut_ptr().cast(), 1) };
    if n == 1 && byte[0] == READY {
        Ok((pid, kenneld_end))
    } else {
        let _ = crate::process::kill_pid(pid);
        let _ = crate::process::wait_pid(pid);
        Err(io::Error::other("mount holder setup failed"))
    }
}

/// The resident holder's serve loop: clone `dir` on each request byte, SCM-send the detached fd.
///
/// Never returns: a clone failure replies with a zero-fd datagram (the requester sees the miss
/// without the holder dying); EOF on `sock` (`kenneld` gone) `_exit`s and drops the mount.
fn serve_mount_clones(sock: libc::c_int, dir: &std::path::Path) -> ! {
    use std::os::fd::AsFd as _;
    // SAFETY: `sock` is the holder's serve socket; borrow it for each call.
    let bsock = unsafe { BorrowedFd::borrow_raw(sock) };
    let mut req = [0u8; 1];
    loop {
        // SAFETY: block for the next one-byte clone request.
        let n = unsafe { libc::read(sock, req.as_mut_ptr().cast(), 1) };
        if n <= 0 {
            // SAFETY: `kenneld` closed the socket (or error) — the bus is gone; exit, dropping the mount.
            unsafe { libc::_exit(0) };
        }
        match open_tree_clone(dir) {
            Ok(fd) => {
                let _ = crate::scm::send_with_fds(bsock, &[1u8], &[fd.as_fd()]);
            }
            Err(_) => {
                let _ = crate::scm::send_with_fds(bsock, &[0u8], &[]);
            }
        }
    }
}

/// `struct clone_args` — the `clone3(2)` argument (the `CLONE_ARGS_SIZE_VER2` layout, so the
/// `cgroup` field is present). All fields are `__aligned_u64`; the kernel reads exactly
/// `size_of` bytes and retains no pointer.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Like [`clone_pid1`], but the child is created **directly inside** the cgroup-v2 directory
/// `cgroup_fd` (`clone3(2)` with `CLONE_INTO_CGROUP`, Linux 5.7+) rather than migrated in afterwards.
///
/// Migrating a task into a cgroup — a write to `cgroup.procs` — takes the global
/// `cgroup_threadgroup_rwsem`, whose write side waits a full RCU grace period; measured at ~10–14 ms
/// and the dominant kennel bring-up cost. Being *born* in the target cgroup skips the migration
/// entirely. `cgroup_fd` is an `O_RDONLY` fd of the target cgroup directory; the caller must have
/// write access to it (kenneld's delegated subtree is operator-owned, and the factory opens it
/// before dropping to the operator).
///
/// All of [`clone_pid1`]'s contract — PID 1 of a fresh namespace set, the map-write handshake, the
/// must-not-return child closure — applies unchanged.
///
/// # Errors
///
/// The OS error if `clone3` fails (`ENOSYS` on a pre-5.7 kernel, `EPERM`/`EBUSY` if the cgroup
/// cannot be joined, or a refused namespace). The child never returns to the caller.
pub fn clone_pid1_in_cgroup<F>(
    ns: Namespaces,
    cgroup_fd: BorrowedFd<'_>,
    child: F,
) -> io::Result<libc::pid_t>
where
    F: FnOnce(),
{
    // `CLONE_INTO_CGROUP` (`1 << 33`) — defined here as `u64` because libc's binding mis-types it as
    // `i32`, which would truncate the bit to 0. clone3 carries the exit signal in its own field (not
    // OR'd into the flags as raw clone does); the namespace bits and this flag go in `flags`.
    const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    let flags = u64::from(to_clone_flags(ns).bits().unsigned_abs()) | CLONE_INTO_CGROUP;
    let mut args = CloneArgs {
        flags,
        exit_signal: u64::from(libc::SIGCHLD.unsigned_abs()),
        cgroup: u64::from(cgroup_fd.as_raw_fd().unsigned_abs()),
        ..CloneArgs::default()
    };
    // SAFETY: `clone3` with a NULL stack (stack = stack_size = 0) and all-zero tid/tls/set_tid
    // fields is fork-like — the child returns 0 on a copy-on-write copy of the parent's stack, the
    // parent gets the child pid. `args` is a live, correctly sized `clone_args` (VER2, the `cgroup`
    // field present) and `size` matches; the kernel reads exactly those bytes and retains no
    // pointer. The child branch runs `child` under the same post-clone discipline as `clone_pid1`
    // (async-signal-safe, must not return) and `_exit`s.
    //
    // INVARIANTS UPHELD: exactly one child is created, inside the cgroup behind `cgroup_fd`.
    //
    // FAILURE MODE: -1 + errno (no child exists); a child closure that wrongly returns is
    // terminated `_exit(127)` rather than continuing as a second copy of the parent.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_mut(&mut args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    match ret {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            child();
            // SAFETY: _exit ends the child without unwinding the parent's shared state.
            unsafe { libc::_exit(127) }
        }
        pid => libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other("clone3 returned an out-of-range pid")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_map_to_the_right_clone_bits() {
        assert_eq!(to_clone_flags(Namespaces::empty()), CloneFlags::empty());
        assert_eq!(to_clone_flags(Namespaces::MOUNT), CloneFlags::CLONE_NEWNS);
        assert_eq!(to_clone_flags(Namespaces::PID), CloneFlags::CLONE_NEWPID);
        assert_eq!(to_clone_flags(Namespaces::IPC), CloneFlags::CLONE_NEWIPC);
        assert_eq!(to_clone_flags(Namespaces::NET), CloneFlags::CLONE_NEWNET);
        assert_eq!(to_clone_flags(Namespaces::USER), CloneFlags::CLONE_NEWUSER);
        assert_eq!(to_clone_flags(Namespaces::UTS), CloneFlags::CLONE_NEWUTS);
        assert_eq!(
            to_clone_flags(Namespaces::CGROUP),
            CloneFlags::CLONE_NEWCGROUP
        );
        // a combination
        assert_eq!(
            to_clone_flags(Namespaces::MOUNT | Namespaces::IPC),
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC
        );
    }

    #[test]
    fn unshare_of_nothing_succeeds() {
        // unshare(0) is a no-op the kernel accepts unprivileged: validates the
        // call path without needing any capability.
        unshare(Namespaces::empty()).expect("no-op unshare");
    }

    /// **The foundational premise:** a normal user builds a mount namespace by first
    /// establishing an identity-mapped user namespace — without the userns,
    /// `unshare(MOUNT)` is `EPERM` for an unprivileged caller; with it, it succeeds,
    /// which is how an unprivileged `kenneld` constructs the sandbox.
    ///
    /// The host must **permit** unprivileged user namespaces *with capabilities*. Two
    /// host policies break this, and the test reports each precisely instead of a
    /// blanket pass:
    /// * `kernel.unprivileged_userns_clone=0` / `user.max_user_namespaces=0` — the
    ///   `unshare(CLONE_NEWUSER)` itself is refused.
    /// * `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10+/24.04
    ///   default) — the unshare *succeeds* but the process holds **no capabilities**
    ///   in the new userns, so the first `/proc/self/setgroups`/map write is `EACCES`.
    ///   Production needs an `AppArmor` profile granting `userns` to the kenneld binary
    ///   (an install step), or the admin relaxes the sysctl.
    ///
    /// Where the mechanism is unavailable the test **skips with the precise cause**;
    /// it asserts success only where the host actually permits it. A skip is not a
    /// proof — `cargo test` cannot demonstrate the unprivileged spawn on a host that
    /// forbids it.
    #[test]
    fn identity_userns_grants_an_unprivileged_mount_namespace() {
        let uid = crate::unistd::real_uid();
        let gid = crate::unistd::real_gid();
        // SAFETY: fork(); the child only unshares, writes its own /proc maps, and
        // _exit()s — it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                // Distinguish "userns refused outright" (4) from "userns created but
                // capability-stripped — the AppArmor case" (5) from success/mount-fail.
                let code = if unshare(Namespaces::USER).is_err() {
                    4
                } else if std::fs::write("/proc/self/setgroups", "deny").is_err() {
                    5
                } else {
                    let _ = std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"));
                    let _ = std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"));
                    i32::from(unshare(Namespaces::MOUNT | Namespaces::IPC).is_err()) * 2
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                let aa = std::fs::read_to_string(
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                )
                .unwrap_or_default();
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 4) => {
                        eprintln!("SKIP: unprivileged user namespaces are disabled on this host");
                    }
                    nix::sys::wait::WaitStatus::Exited(_, 5) => {
                        eprintln!(
                            "SKIP: userns created but capability-stripped — \
                             kernel.apparmor_restrict_unprivileged_userns={} (needs an \
                             AppArmor profile granting `userns`, or the sysctl relaxed)",
                            aa.trim()
                        );
                    }
                    other => assert!(
                        matches!(other, nix::sys::wait::WaitStatus::Exited(_, 0)),
                        "unprivileged userns→mount-namespace failed (2 = mount EPERM): {other:?}"
                    ),
                }
            }
        }
    }

    /// The deferred-gid variant leaves the `gid_map` empty while still granting the
    /// in-namespace capability: an unprivileged caller establishes the userns
    /// without a `gid_map`, observes `/proc/self/gid_map` empty, and can still
    /// `unshare(MOUNT)` — exactly the window in which the privileged helper writes
    /// the multi-gid map (§7.4.8). Skips with the precise cause where the host
    /// forbids the userns or strips its capabilities (the same two conditions as
    /// [`identity_userns_grants_an_unprivileged_mount_namespace`]).
    #[test]
    fn defer_gid_userns_leaves_the_gid_map_empty_but_grants_the_capability() {
        let uid = crate::unistd::real_uid();
        // SAFETY: fork(); the child only unshares, writes its own /proc maps, reads
        // its own gid_map, and _exit()s — it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if unshare(Namespaces::USER).is_err() {
                    4
                } else if std::fs::write("/proc/self/setgroups", "deny").is_err()
                    || std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")).is_err()
                {
                    5
                } else {
                    // gid_map must be empty (deferred), AND the capability present
                    // (mount unshare succeeds). 0 = both hold; 6 = gid_map not empty;
                    // 2 = mount unshare failed despite the userns.
                    let gid_map = std::fs::read_to_string("/proc/self/gid_map").unwrap_or_default();
                    if gid_map.trim().is_empty() {
                        i32::from(unshare(Namespaces::MOUNT | Namespaces::IPC).is_err()) * 2
                    } else {
                        6
                    }
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                let aa = std::fs::read_to_string(
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                )
                .unwrap_or_default();
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 4) => {
                        eprintln!("SKIP: unprivileged user namespaces are disabled on this host");
                    }
                    nix::sys::wait::WaitStatus::Exited(_, 5) => {
                        eprintln!(
                            "SKIP: userns created but capability-stripped — \
                             kernel.apparmor_restrict_unprivileged_userns={} (needs an \
                             AppArmor profile granting `userns`, or the sysctl relaxed)",
                            aa.trim()
                        );
                    }
                    other => assert!(
                        matches!(other, nix::sys::wait::WaitStatus::Exited(_, 0)),
                        "deferred-gid userns failed (6 = gid_map not empty, 2 = mount EPERM): {other:?}"
                    ),
                }
            }
        }
    }

    /// `clone_pid1` with an empty namespace set behaves like `fork()` and needs no
    /// privilege: the child runs the closure and `_exit`s with a code, the parent
    /// receives the child pid and reaps it, observing that exact code. Proves the
    /// fork-like raw-clone path and the pid return without touching any namespace.
    #[test]
    fn clone_pid1_empty_flags_relays_the_child_exit_code() {
        let child = || {
            // SAFETY: _exit ends the child without running Drop/atexit glue (shared
            // copy-on-write with the test harness).
            unsafe { libc::_exit(42) }
        };
        let pid = clone_pid1(Namespaces::empty(), child).expect("clone_pid1");
        let status =
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 42)),
            "child should _exit(42): {status:?}"
        );
    }

    /// With privilege, `clone_pid1(PID|USER)` produces a child that is **PID 1** of a
    /// fresh PID namespace in a single syscall — the property the factory relies on to
    /// skip the double fork. The child reports its in-namespace pid via its exit code
    /// (0 ⇒ `getpid()==1`); `getpid` needs no uid mapping, so the still-empty userns
    /// map does not matter here. Gated behind `e2e`.
    #[cfg(feature = "e2e")]
    #[test]
    fn clone_pid1_makes_the_child_pid_namespace_init() {
        if crate::unistd::skip_if_unprivileged("clone_pid1_makes_the_child_pid_namespace_init") {
            return;
        }
        let child = || {
            // SAFETY: getpid()/_exit are async-signal-safe; the child does nothing
            // that needs the (still unwritten) userns maps.
            let me = unsafe { libc::getpid() };
            unsafe { libc::_exit(i32::from(me != 1)) }
        };
        let pid = clone_pid1(Namespaces::PID | Namespaces::USER, child).expect("clone_pid1");
        let status =
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).expect("waitpid");
        assert!(
            matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
            "cloned child must be PID 1 of its new PID namespace: {status:?}"
        );
    }

    /// With privilege, unsharing the mount namespace gives the caller a private
    /// mount namespace — observable as a changed `/proc/self/ns/mnt` link.
    /// Gated behind `e2e`; run via `sudo -E cargo test --features e2e`.
    #[cfg(feature = "e2e")]
    #[test]
    fn unshare_mount_namespace_changes_the_mount_ns() {
        if crate::unistd::skip_if_unprivileged("unshare_mount_namespace_changes_the_mount_ns") {
            return;
        }
        let before = std::fs::read_link("/proc/self/ns/mnt").expect("read ns link");
        // SAFETY: fork(); the child only unshares, reads a proc link, and _exit()s.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                let code = if unshare(Namespaces::MOUNT | Namespaces::IPC).is_err() {
                    1
                } else {
                    match std::fs::read_link("/proc/self/ns/mnt") {
                        Ok(after) if after != before => 0,
                        _ => 2,
                    }
                };
                // SAFETY: _exit ends the child without Drop/atexit glue.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                assert!(
                    matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                    "child failed (1=unshare err, 2=ns unchanged): {status:?}"
                );
            }
        }
    }
}
