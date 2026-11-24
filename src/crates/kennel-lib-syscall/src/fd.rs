//! File-descriptor helpers: flag manipulation and `openat2` path resolution.
//!
//! The `openat2` wrapper (`open_no_symlinks`) is an `unsafe` site — the fourth in
//! this crate — documented per §4 (SAFETY / INVARIANTS UPHELD / FAILURE MODE).
//! It uses the raw `openat2(2)` syscall (Linux 5.6+, `__NR_openat2 = 437`) because
//! neither `libc` nor `nix` wrap it. The pattern matches the existing `clone3`
//! wrapper in `namespace.rs`: a `#[repr(C)]` kernel struct and a raw
//! `libc::syscall`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};

// ─── openat2(2) — RESOLVE_NO_SYMLINKS / RESOLVE_NO_MAGICLINKS ────────────────

/// The kernel's `struct open_how` (v0, `OPEN_HOW_SIZE_VER0 = 24`).
///
/// All fields are `__u64`; the kernel reads exactly `size_of::<OpenHow>()` bytes
/// and retains no pointer. Defined in `<linux/openat2.h>`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `RESOLVE_NO_MAGICLINKS` (`<linux/openat2.h>`, kernel 5.6+).
///
/// If any path component is a procfs/sysfs "magic link" (`/proc/<pid>/fd/…`,
/// `/proc/<pid>/root`, …), the `openat2` call fails with `ELOOP`. Ordinary
/// symbolic links still resolve.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

/// `RESOLVE_NO_SYMLINKS` (`<linux/openat2.h>`, kernel 5.6+).
///
/// If any path component (including the final one) is a symbolic link, the
/// `openat2` call fails with `ELOOP`. Per `openat2(2)` this implies
/// [`RESOLVE_NO_MAGICLINKS`].
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// `__NR_openat2` — syscall 437 on x86-64 / aarch64 / riscv64.
const SYS_OPENAT2: libc::c_long = 437;

/// `AT_FDCWD`: resolve a relative path against the current directory.
///
/// Ignored for an absolute path. Re-exported so a `#![forbid(unsafe_code)]` caller without a
/// `libc` dependency need not spell the magic number.
pub const AT_FDCWD: RawFd = libc::AT_FDCWD;

/// Open `path` relative to `dir_fd` with `RESOLVE_NO_SYMLINKS`, returning an
/// `O_PATH` fd.
///
/// If any component of `path` is a symbolic link the call fails with `ELOOP`,
/// closing the writable-bind-source symlink-aliasing class (0.4.0 F1
/// residual). The returned fd is safe to use as `/proc/self/fd/N` — its target
/// is the inode the path resolved to without following any symlink.
///
/// `dir_fd` follows the kernel's `int dfd` semantics: pass `libc::AT_FDCWD` to
/// resolve relative to the current directory, or an open directory fd for
/// anchored resolution. For absolute paths the kernel ignores it.
///
/// # Errors
///
/// - `ELOOP`: a path component is a symlink.
/// - `ENOSYS`: kernel < 5.6 (does not support `openat2`).
/// - Any other `openat2` error (`ENOENT`, `EACCES`, …).
pub fn open_no_symlinks(dir_fd: RawFd, path: &Path) -> io::Result<OwnedFd> {
    openat2_o_path(dir_fd, path, RESOLVE_NO_SYMLINKS)
}

/// Open `path` relative to `dir_fd` with `RESOLVE_NO_MAGICLINKS`, returning an
/// `O_PATH` fd.
///
/// Ordinary symlinks resolve (an operator-owned source tree is commonly a
/// symlink farm — stow/chezmoi/home-manager), but a procfs/sysfs magic link in
/// any component fails with `ELOOP` — the redirected-bind-source escape class
/// (a `source` aliased through `/proc/<pid>/root/…` out of the intended tree).
/// The returned fd is safe to bind via `/proc/self/fd/N`.
///
/// `dir_fd` follows the kernel's `int dfd` semantics (see [`open_no_symlinks`]).
///
/// # Errors
///
/// - `ELOOP`: a path component is a magic link.
/// - `ENOSYS`: kernel < 5.6 (does not support `openat2`).
/// - Any other `openat2` error (`ENOENT`, `EACCES`, …).
pub fn open_no_magiclinks(dir_fd: RawFd, path: &Path) -> io::Result<OwnedFd> {
    openat2_o_path(dir_fd, path, RESOLVE_NO_MAGICLINKS)
}

/// Make sure the directory `path` exists and lies entirely on **kennel scaffolding**, creating
/// missing components, and return an `O_PATH` handle to it.
///
/// For `kennel-bin-init`, which is the kennel's uid 0 — host root — inside a view that also holds
/// binds of host directories. It is told by its bus peer where to attach the mesh mounts; creating
/// that directory by name would be a root `mkdir` wherever the name leads, including onto a bound
/// host inode. So the path is walked from `/` by descriptor, no symlink is followed in any
/// component, and every directory on the way — existing or created — must be on the same
/// filesystem as one of `anchors`: mounts the factory itself created (`/`, `/dev`, `/tmp`). A step
/// onto anything else (every bind is something else) is refused.
///
/// # Errors
///
/// `InvalidInput` if `path` is not absolute plain names; `PermissionDenied` if a component is
/// not on scaffolding; `ELOOP` for a symlink; any other `openat2`/`mkdirat`/`fstat` error.
pub fn scaffold_dir(path: &Path, anchors: &[&Path]) -> io::Result<OwnedFd> {
    use nix::errno::Errno;
    use nix::fcntl::{open, openat2, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::{fstat, mkdirat, stat, Mode};

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", path.display()),
        ));
    }
    let names = plain_names(path)?;
    let mut devices = Vec::new();
    for anchor in anchors {
        if let Ok(st) = stat(*anchor) {
            devices.push(st.st_dev);
        }
    }
    let on_scaffold = |fd: &OwnedFd| -> io::Result<()> {
        let st = fstat(fd).map_err(io::Error::from)?;
        if devices.contains(&st.st_dev) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} does not lie on kennel scaffolding (it crosses onto a bound filesystem)",
                    path.display()
                ),
            ))
        }
    };
    let mut current = open(
        Path::new("/"),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    on_scaffold(&current)?;
    for name in &names {
        let how = || {
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_SYMLINKS
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS,
                )
        };
        let next = match openat2(&current, name.as_os_str(), how()) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                // `current` was just checked to be scaffolding, so this creates there.
                mkdirat(&current, name.as_os_str(), Mode::from_bits_truncate(0o755))
                    .map_err(io::Error::from)?;
                openat2(&current, name.as_os_str(), how()).map_err(io::Error::from)?
            }
            Err(e) => return Err(io::Error::from(e)),
        };
        on_scaffold(&next)?;
        current = next;
    }
    Ok(current)
}

/// Make sure the directory at the absolute path `path` exists, creating missing components, with
/// **no symlink followed in any component**, and return an `O_PATH` handle to it.
///
/// For a privileged helper that must act on a directory under a caller-owned tree (the per-user
/// runtime directory): the handle pins the inode the walk reached, so a later mount lands on that
/// directory and nowhere a link could point.
///
/// # Errors
///
/// `InvalidInput` if `path` is not absolute plain names; `ELOOP`/`ENOTDIR` if a component is a
/// symlink or not a directory; any other `openat2`/`mkdirat` error.
pub fn dir_no_symlinks(path: &Path) -> io::Result<OwnedFd> {
    use nix::errno::Errno;
    use nix::fcntl::{open, openat2, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::{mkdirat, Mode};

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", path.display()),
        ));
    }
    let mut current = open(
        Path::new("/"),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    for name in &plain_names(path)? {
        let how = || {
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_SYMLINKS
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS,
                )
        };
        current = match openat2(&current, name.as_os_str(), how()) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                mkdirat(&current, name.as_os_str(), Mode::from_bits_truncate(0o755))
                    .map_err(io::Error::from)?;
                openat2(&current, name.as_os_str(), how()).map_err(io::Error::from)?
            }
            Err(e) => return Err(io::Error::from(e)),
        };
    }
    Ok(current)
}

/// The owner uid and file-type of an open descriptor's inode: `(uid, is_directory)`.
///
/// # Errors
///
/// The OS error if `fstat` fails.
pub fn owner_and_kind(fd: &OwnedFd) -> io::Result<(u32, bool)> {
    use nix::sys::stat::{fstat, SFlag};
    let st = fstat(fd).map_err(io::Error::from)?;
    let is_dir = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR;
    Ok((st.st_uid, is_dir))
}

/// An `O_PATH` handle to the **socket** named `leaf` directly inside the directory `dir`.
///
/// For connecting to a socket in a directory someone else can write: `dir` is reached with no
/// symlink followed, `leaf` must be a single name, it is opened without being followed, and it
/// must be a socket. Connecting to the handle (through [`proc_path`]) then reaches that socket and
/// nothing a link in the directory could point at.
///
/// # Errors
///
/// `InvalidInput` if `leaf` is not one plain name or the entry is not a socket; `ELOOP` if it is
/// a symlink; any other `openat2`/`fstat` error (`ENOENT` when it is not bound yet).
pub fn socket_in_dir(dir: &Path, leaf: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::SFlag;
    if plain_names(Path::new(leaf))?.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket name must be one plain name",
        ));
    }
    let dir_fd = open_no_symlinks(AT_FDCWD, dir)?;
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
        .resolve(
            ResolveFlag::RESOLVE_BENEATH
                | ResolveFlag::RESOLVE_NO_SYMLINKS
                | ResolveFlag::RESOLVE_NO_XDEV,
        );
    let sock = openat2(&dir_fd, leaf, how).map_err(io::Error::from)?;
    if file_type(&sock)? != SFlag::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the rendezvous entry is not a socket",
        ));
    }
    Ok(sock)
}

/// What a path inside a [`RootDir`] is required to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory.
    Directory,
    /// Anything that is neither a directory nor a symlink (a regular file, a device node, …).
    File,
}

/// A directory that paths are resolved **inside**, as the view being built will see them.
///
/// The privhelper factory builds a kennel's view under a staging root while the host filesystem is
/// still mounted, and parts of that tree are not its own: writable grants are host directories an
/// earlier workload could fill, and an OCI root is image content. A path resolved by name there
/// can be steered by a symlink — out of the root altogether (an absolute target resolves against
/// the HOST root before the pivot), or onto a different path than the one a mount is meant to
/// cover. `RootDir` resolves by descriptor instead:
///
/// - a path must be plain names — no `..`;
/// - a symlink in a **parent** component is followed only within the root (`RESOLVE_IN_ROOT`),
///   exactly as it will resolve once the root is `/`;
/// - the **final** component is never followed. [`ensure`](Self::ensure) refuses a symlink there,
///   so a mount point is always the path itself and the build fails closed on a planted link.
///
/// Callers act on the returned handle (through [`proc_path`]) rather than re-resolving the name.
pub struct RootDir {
    fd: OwnedFd,
}

impl RootDir {
    /// Open `path` as a resolution root.
    ///
    /// # Errors
    ///
    /// The OS error if `path` is not an openable directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;
        let fd = open(
            path,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        Ok(Self { fd })
    }

    /// An `O_PATH` handle to `path` if it exists, without following a final symlink (the
    /// `lstat` question). `None` if it is absent, or a parent is missing or not a directory.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a path that is not plain names; any unexpected `openat2` error.
    pub fn lookup(&self, path: &Path) -> io::Result<Option<OwnedFd>> {
        self.walk(path, None)
    }

    /// An `O_PATH` handle to wherever `path` leads inside the root, following symlinks —
    /// including a final one — but never out of the root. `None` if it leads nowhere.
    ///
    /// For a path the operator declared about content they do not author (an OCI image's
    /// `/bin`, which may be a link to `usr/bin`): the thing to act on is the link's target, as the
    /// view will resolve it. Not for a mount point that must cover the path itself — use
    /// [`ensure`](Self::ensure) for that.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a path that is not plain names; any unexpected `openat2` error.
    pub fn resolve(&self, path: &Path) -> io::Result<Option<OwnedFd>> {
        use nix::errno::Errno;
        use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
        let names = plain_names(path)?;
        if names.is_empty() {
            return Ok(Some(self.fd.try_clone()?));
        }
        let rel: std::path::PathBuf = names.iter().collect();
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        match openat2(&self.fd, rel.as_path(), how) {
            Ok(fd) => Ok(Some(fd)),
            Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => Ok(None),
            Err(e) => Err(io::Error::from(e)),
        }
    }

    /// Whether `path` exists and is a directory (a final symlink is not followed).
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn is_dir(&self, path: &Path) -> io::Result<bool> {
        match self.lookup(path)? {
            Some(fd) => Ok(file_type(&fd)? == nix::sys::stat::SFlag::S_IFDIR),
            None => Ok(false),
        }
    }

    /// Make sure `path` exists as `kind`, creating it and any missing parent directories, and
    /// return an `O_PATH` handle to it. An existing node is left untouched.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if the path is not plain names, if the final component is a symlink, or
    /// if it exists as the other kind; the OS error if a component cannot be created or opened.
    pub fn ensure(&self, path: &Path, kind: NodeKind) -> io::Result<OwnedFd> {
        use nix::sys::stat::SFlag;
        let fd = self.walk(path, Some(kind))?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} could not be resolved inside the root", path.display()),
            )
        })?;
        let found = file_type(&fd)?;
        let fits = match kind {
            NodeKind::Directory => found == SFlag::S_IFDIR,
            NodeKind::File => found != SFlag::S_IFDIR && found != SFlag::S_IFLNK,
        };
        if fits {
            Ok(fd)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} exists but is not the {} the view needs there (a symlink is never accepted)",
                    path.display(),
                    if kind == NodeKind::Directory { "directory" } else { "file" },
                ),
            ))
        }
    }

    /// Copy the file `source` (a host path, opened with the caller's current identity) to `path`
    /// inside the root, creating parent directories. The destination's final component is not
    /// followed; set-id and sticky bits are not carried over.
    ///
    /// # Errors
    ///
    /// As [`ensure`](Self::ensure) for the parent; `ELOOP` if the destination is a symlink; any
    /// open, copy or chmod error.
    pub fn copy_into(&self, source: &Path, path: &Path) -> io::Result<()> {
        use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
        use nix::sys::stat::Mode;
        use std::os::unix::fs::PermissionsExt as _;
        let (parent, name) = self.parent_of(path)?;
        let mut src = std::fs::File::open(source)?;
        // The copy is scaffolding the kennel's root owns and the workload only reads: carry the
        // source's read and execute bits, never group or other write (a source staged under a
        // 002 umask would otherwise arrive group-writable).
        let mode = src.metadata()?.permissions().mode() & 0o755;
        let how = OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_TRUNC
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::from_bits_truncate(mode))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
        let mut dst =
            std::fs::File::from(openat2(&parent, name.as_os_str(), how).map_err(io::Error::from)?);
        std::io::copy(&mut src, &mut dst)?;
        dst.set_permissions(std::fs::Permissions::from_mode(mode))
    }

    /// Remove the non-directory entry at `path` (a file or a symlink — the link itself, never
    /// its target). An absent path, or one whose parent is missing, is not an error.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a path that is not plain names; `EISDIR` for a directory; any other
    /// `unlinkat` error.
    pub fn remove(&self, path: &Path) -> io::Result<()> {
        use nix::errno::Errno;
        use nix::unistd::{unlinkat, UnlinkatFlags};
        let mut names = plain_names(path)?;
        let Some(name) = names.pop() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path names the root itself",
            ));
        };
        let parent: std::path::PathBuf = names.iter().collect();
        let Some(parent) = self.walk(&parent, None)? else {
            return Ok(());
        };
        match unlinkat(&parent, name.as_os_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(io::Error::from(e)),
        }
    }

    /// Create the file `path` with `bytes` and permission bits `mode & 0o777`, creating parent
    /// directories. The file must not exist: nothing is overwritten and nothing is followed.
    ///
    /// # Errors
    ///
    /// As [`ensure`](Self::ensure) for the parent; `EEXIST` if `path` exists (a symlink counts);
    /// any write or chmod error.
    pub fn write_new(&self, path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
        use nix::sys::stat::Mode;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let (parent, name) = self.parent_of(path)?;
        let mode = mode & 0o777;
        let how = OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::from_bits_truncate(mode))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
        let mut file =
            std::fs::File::from(openat2(&parent, name.as_os_str(), how).map_err(io::Error::from)?);
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
    }

    /// Create the symlink `path` → `text` inside the root (parents created as directories).
    ///
    /// # Errors
    ///
    /// As [`ensure`](Self::ensure) for the parent; `EEXIST` if `path` already exists.
    pub fn symlink(&self, text: &Path, path: &Path) -> io::Result<()> {
        let (parent, name) = self.parent_of(path)?;
        nix::unistd::symlinkat(text, &parent, name.as_os_str()).map_err(io::Error::from)
    }

    /// The (ensured) parent directory of `path`, and its final name.
    fn parent_of(&self, path: &Path) -> io::Result<(OwnedFd, std::ffi::OsString)> {
        let mut names = plain_names(path)?;
        let name = names.pop().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path names the root itself")
        })?;
        let parent: std::path::PathBuf = names.iter().collect();
        Ok((self.ensure(&parent, NodeKind::Directory)?, name))
    }

    /// Resolve `path` one name at a time. `create` makes missing components (directories, and
    /// for the last one whatever `create` says); with `None` a missing component yields `None`.
    fn walk(&self, path: &Path, create: Option<NodeKind>) -> io::Result<Option<OwnedFd>> {
        use nix::errno::Errno;
        use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
        use nix::sys::stat::{mkdirat, Mode, SFlag};

        let names = plain_names(path)?;
        let step = |dir: &OwnedFd, name: &std::ffi::OsStr| -> io::Result<Option<OwnedFd>> {
            let how = OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);
            match openat2(dir, name, how) {
                Ok(fd) => Ok(Some(fd)),
                Err(Errno::ENOENT) => Ok(None),
                Err(e) => Err(io::Error::from(e)),
            }
        };

        let mut current = self.fd.try_clone()?;
        let mut walked = std::path::PathBuf::new();
        for (index, name) in names.iter().enumerate() {
            let last = index.saturating_add(1) == names.len();
            walked.push(name);
            let mut next = step(&current, name)?;
            if next.is_none() {
                let Some(kind) = create else { return Ok(None) };
                if last && kind == NodeKind::File {
                    let how = OpenHow::new()
                        .flags(
                            OFlag::O_WRONLY
                                | OFlag::O_CREAT
                                | OFlag::O_EXCL
                                | OFlag::O_NOFOLLOW
                                | OFlag::O_CLOEXEC,
                        )
                        .mode(Mode::from_bits_truncate(0o644))
                        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
                    openat2(&current, name.as_os_str(), how).map_err(io::Error::from)?;
                } else {
                    mkdirat(&current, name.as_os_str(), Mode::from_bits_truncate(0o755))
                        .map_err(io::Error::from)?;
                }
                next = step(&current, name)?;
            }
            let Some(mut node) = next else {
                return Ok(None);
            };
            let kind = file_type(&node)?;
            if kind == SFlag::S_IFLNK && !last {
                // A symlink in a parent component: follow it as the view will — inside the root.
                let how = OpenHow::new()
                    .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                    .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
                node = match openat2(&self.fd, walked.as_path(), how) {
                    Ok(fd) => fd,
                    Err(Errno::ENOENT | Errno::ENOTDIR) if create.is_none() => return Ok(None),
                    Err(e) => return Err(io::Error::from(e)),
                };
            } else if kind != SFlag::S_IFDIR && !last {
                if create.is_none() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} is not a directory", walked.display()),
                ));
            }
            current = node;
        }
        Ok(Some(current))
    }
}

/// The `/proc/self/fd/N` path that names an open descriptor's inode, for a syscall wrapper that
/// takes a path. The descriptor must stay open for as long as the path is used.
#[must_use]
pub fn proc_path(fd: &impl AsRawFd) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// The file-type bits of an open descriptor.
fn file_type(fd: &OwnedFd) -> io::Result<nix::sys::stat::SFlag> {
    use nix::sys::stat::{fstat, SFlag};
    let mode = fstat(fd).map_err(io::Error::from)?.st_mode;
    Ok(SFlag::from_bits_truncate(mode) & SFlag::S_IFMT)
}

/// Split a view path into its plain names (a leading `/` and `.` are dropped; anything else that
/// is not a plain name — notably `..` — is refused).
fn plain_names(path: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    use std::path::Component;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name.to_owned()),
            Component::RootDir | Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not made of plain names", path.display()),
                ))
            }
        }
    }
    Ok(names)
}

/// Create the mount point `rel` beneath `root` — a directory, or an empty file — together with any
/// missing parent directories, **without leaving `root`'s mount**.
///
/// For the one place the privhelper factory must create a path with root's identity before the
/// pivot: a bind's mount point inside an OCI overlay root, whose directories belong to the kennel's
/// uid 0. The tree is image content, so a component may be a symlink pointing anywhere; and binds
/// of host directories are already mounted inside it. Every step is therefore resolved against
/// `root` with `RESOLVE_IN_ROOT | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS`: a symlink is followed
/// only within `root`, and stepping onto another mount fails `EXDEV`, so nothing is ever created
/// on a bound host inode or outside the overlay. `rel` must be made of plain names only.
///
/// An existing path is left as it is.
///
/// # Errors
///
/// `InvalidInput` if `rel` has a component that is not a plain name (`..`, a root, a prefix);
/// `EXDEV` if the path crosses a mount point; any other `openat2`/`mkdirat` error.
pub fn create_in_root_same_mount(root: &Path, rel: &Path, directory: bool) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::fcntl::{open, openat2, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::{mkdirat, Mode};
    use std::path::Component;

    let mut names: Vec<&std::ffi::OsStr> = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mount point path must be plain names beneath the root",
                ))
            }
        }
    }
    let root_fd = open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let resolve = ResolveFlag::RESOLVE_IN_ROOT
        | ResolveFlag::RESOLVE_NO_XDEV
        | ResolveFlag::RESOLVE_NO_MAGICLINKS;
    let handle = || {
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(resolve)
    };

    let mut walked = std::path::PathBuf::new();
    for (index, name) in names.iter().enumerate() {
        let parent = walked.clone();
        walked.push(name);
        match openat2(&root_fd, walked.as_path(), handle()) {
            Ok(_) => continue, // already there
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        let parent_fd = if parent.as_os_str().is_empty() {
            root_fd.try_clone()?
        } else {
            openat2(&root_fd, parent.as_path(), handle()).map_err(io::Error::from)?
        };
        let last = index.saturating_add(1) == names.len();
        if last && !directory {
            // One plain name under a parent we just resolved: create it there, exclusively.
            let create = OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                )
                .mode(Mode::from_bits_truncate(0o644))
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_XDEV
                        | ResolveFlag::RESOLVE_NO_SYMLINKS,
                );
            openat2(&parent_fd, *name, create).map_err(io::Error::from)?;
        } else {
            mkdirat(&parent_fd, *name, Mode::from_bits_truncate(0o755)).map_err(io::Error::from)?;
        }
    }
    Ok(())
}

/// Give `dir`, and everything beneath it **on the same mount**, to `uid`:`gid`.
///
/// The privhelper factory builds a kennel's view with the operator's filesystem identity (so the
/// kernel refuses anything the caller could not do itself), then uses this to hand the scaffolding
/// it created back to the kennel's uid 0. It must never touch an inode the factory did not create,
/// so the walk is descriptor-based and resolves every step with `RESOLVE_NO_XDEV |
/// RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`:
///
/// - a name that is a **mount point** (every bind of a host path is one) fails `EXDEV` and is
///   skipped, so no bound host inode is reached;
/// - a **symlink** is never followed — the link itself is re-owned (`AT_EMPTY_PATH` on an `O_PATH`
///   handle), never its target.
///
/// `skip`, when given, is a path **relative to `dir`** whose subtree is left alone (the workload's
/// constructed home, which is the operator's by design).
///
/// # Errors
///
/// Any `open`/`openat2`/`fchownat`/`readdir` error other than the `EXDEV` that marks a mount point.
pub fn chown_tree_same_mount(
    dir: &Path,
    uid: u32,
    gid: u32,
    skip: Option<&Path>,
) -> io::Result<()> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let root = open(
        dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    chown_tree_at(&root, Path::new(""), uid, gid, skip)
}

/// The recursive body of [`chown_tree_same_mount`]: `dir` is an open directory, `rel` its path
/// relative to the walk's root (only compared against `skip`, never resolved).
fn chown_tree_at(
    dir: &OwnedFd,
    rel: &Path,
    uid: u32,
    gid: u32,
    skip: Option<&Path>,
) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::fcntl::{openat2, AtFlags, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::{fstat, SFlag};
    use nix::unistd::{fchown, fchownat, Gid, Uid};
    use std::os::unix::ffi::OsStringExt as _;

    let owner = Some(Uid::from_raw(uid));
    let group = Some(Gid::from_raw(gid));
    fchown(dir, owner, group).map_err(io::Error::from)?;

    // Collect the names first: the directory stream shares its offset with `dir`'s duplicate, and
    // re-owning entries while iterating must not disturb it.
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    {
        let mut stream = nix::dir::Dir::from_fd(dir.try_clone()?).map_err(io::Error::from)?;
        for entry in stream.iter() {
            let entry = entry.map_err(io::Error::from)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(std::ffi::OsString::from_vec(name.to_vec()));
            }
        }
    }

    let resolve = ResolveFlag::RESOLVE_NO_XDEV
        | ResolveFlag::RESOLVE_NO_SYMLINKS
        | ResolveFlag::RESOLVE_BENEATH;
    for name in names {
        let child_rel = rel.join(&name);
        if skip == Some(child_rel.as_path()) {
            continue;
        }
        let handle = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(resolve);
        let node = match openat2(dir, name.as_os_str(), handle) {
            Ok(fd) => fd,
            // A mount point: not something we created. Leave it and everything under it alone.
            Err(Errno::EXDEV) => continue,
            Err(e) => return Err(io::Error::from(e)),
        };
        fchownat(&node, "", owner, group, AtFlags::AT_EMPTY_PATH).map_err(io::Error::from)?;
        let kind = SFlag::from_bits_truncate(fstat(&node).map_err(io::Error::from)?.st_mode);
        if kind & SFlag::S_IFMT == SFlag::S_IFDIR {
            let listing = OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(resolve);
            let sub = openat2(dir, name.as_os_str(), listing).map_err(io::Error::from)?;
            chown_tree_at(&sub, &child_rel, uid, gid, skip)?;
        }
    }
    Ok(())
}

/// The shared `openat2(2)` body: open `path` as `O_PATH` under `resolve` restrictions.
fn openat2_o_path(dir_fd: RawFd, path: &Path, resolve: u64) -> io::Result<OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let how = OpenHow {
        flags: libc::O_PATH as u64, // fd-only, no read/write capability
        mode: 0,
        resolve,
    };
    // SAFETY: `openat2` with a valid `dir_fd` (or `AT_FDCWD`), a NUL-terminated
    // `path`, and a correctly sized, stack-local `open_how` is a pure open-path
    // call — no pointer is retained, no aliasing concern. `O_PATH` means no I/O
    // capability is granted, only an fd for `/proc/self/fd/N` resolution. The
    // returned descriptor is fresh and owned by us.
    //
    // INVARIANTS UPHELD: `how` is stack-local, correctly sized (24 bytes,
    // `OPEN_HOW_SIZE_VER0`), zeroed in unused fields. `c_path` lives until
    // the syscall returns. `SYS_OPENAT2` is the correct syscall number for
    // all supported architectures (verified against `<asm/unistd.h>`).
    //
    // FAILURE MODE: -1 + errno → `Err`. The caller must not proceed with
    // the bind mount — a symlink in the path is a potential escape.
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dir_fd,
            c_path.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat2` returned a non-negative descriptor that we are the
    // sole owner of; wrapping it transfers that ownership for RAII close.
    let fd = RawFd::try_from(fd).map_err(|_| io::Error::other("openat2 fd out of range"))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ─── FD flag helpers ─────────────────────────────────────────────────────────

/// Set the close-on-exec flag (`FD_CLOEXEC`) on `fd`.
///
/// The privhelper factory uses this on the privileged kenneld↔helper control socket (the
/// helper's stdin): `clone` copies the fd table into the construction child, and `dup2`
/// onto stdin clears `O_CLOEXEC`, so without this the channel would survive the child's
/// `fexecve` into `kennel-bin-init` and leak a handle to the privileged factory transport into
/// the kennel (`07-2`; sec review: fd hygiene). Re-getting the existing flags first keeps
/// any other descriptor flags intact.
///
/// # Errors
/// An OS error if `fcntl(F_GETFD/F_SETFD)` fails.
pub fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    let current =
        fcntl(fd, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    let flags = FdFlag::from_bits_truncate(current) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Duplicate `src` onto descriptor number `dst` (`dup2(2)`).
///
/// `dup2` installs `src`'s open file at the exact number `dst` (closing any prior `dst`) and
/// the new descriptor is **not** close-on-exec — so it survives a subsequent `fexecve`. The
/// privhelper factory uses this to place the interactive pty return socket at the fixed
/// [`crate::pty::PTY_RETURN_FD`] the argv-less `kennel-bin-init` reads.
///
/// # Errors
/// The OS error if `dup2(2)` fails (e.g. `dst` is out of range).
pub fn dup_onto(src: BorrowedFd<'_>, dst: RawFd) -> io::Result<()> {
    // `dup2(fd, fd)` is a no-op that does NOT clear close-on-exec, so when `src` already sits
    // at `dst` we must clear it explicitly — otherwise the descriptor would not survive the
    // intended `fexecve`.
    if src.as_raw_fd() == dst {
        let flags =
            fcntl(src, FcntlArg::F_GETFD).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let cleared = FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC;
        fcntl(src, FcntlArg::F_SETFD(cleared))
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        return Ok(());
    }
    // SAFETY: a plain dup2 of a valid borrowed descriptor onto a raw target number. We work
    // in descriptor numbers, not `OwnedFd`, so there is no Rust ownership/aliasing concern;
    // the kernel closes any file previously at `dst` and the new `dst` is not close-on-exec.
    let rc = unsafe { libc::dup2(src.as_raw_fd(), dst) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mark descriptor number `fd` close-on-exec, if it is open (`fcntl(F_SETFD, FD_CLOEXEC)`).
///
/// `kennel-bin-init` receives several descriptors at fixed numbers for its own use (the
/// boot-sync socket, the pty return socket, the injected stdio). It marks them so that the
/// programs it later execs — the workload and the facades — do not inherit a descriptor that was
/// only ever meant for init. A number with nothing open at it is not an error.
///
/// # Errors
/// The OS error if `fcntl(2)` fails for a reason other than the descriptor not being open.
pub fn set_cloexec_at(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fcntl(F_SETFD)` on a descriptor number takes no pointer and changes only that
    // descriptor's close-on-exec flag in this process's own table.
    //
    // INVARIANTS UPHELD: no memory is read or written; a number that is not open yields EBADF.
    //
    // FAILURE MODE: -1 + errno; EBADF is treated as "nothing to mark".
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBADF) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Close descriptor number `fd` (`close(2)`).
///
/// For the privhelper construction child to drop its **inherited** copy of a handshake pipe's
/// write end right after `clone`: `clone` copies the fd table, so without this the child also
/// holds the parent's `ready_w`, and its `recv_ack` read on the matching read end can never see
/// EOF. A parent that dies before `send_ack` (e.g. a `uid_map`-write `EPERM`) would then hang the
/// child to the service-stop SIGKILL instead of failing fast. The child does not own the matching
/// `OwnedFd` (the parent does), so this operates in descriptor numbers with no Rust-ownership concern.
///
/// # Errors
/// The OS error if `close(2)` fails (e.g. `fd` is not open).
pub fn close_inherited(fd: RawFd) -> io::Result<()> {
    // SAFETY: a plain close of a raw descriptor the caller knows is open in this process (the
    // post-clone child's inherited copy). We operate in descriptor numbers, not `OwnedFd`, so
    // there is no double-close of a Rust-owned handle in this process.
    let rc = unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Duplicate `src` to the lowest free descriptor `>= base`, close-on-exec (`F_DUPFD_CLOEXEC`),
/// returned as an [`OwnedFd`].
///
/// Used to move the descriptors a process will place at fixed low numbers (via [`dup_onto`]) up
/// out of that range first, so the placements cannot clobber one another or another descriptor
/// the process still needs (e.g. the factory relocates the init-binary fd, the pty socket, and
/// the boot-sync socket above `PTY_RETURN_FD`/`BOOT_SYNC_FD` before `dup2`-ing them down).
///
/// # Errors
/// The OS error if `fcntl(F_DUPFD_CLOEXEC)` fails (e.g. the fd table is full).
pub fn dup_above(src: BorrowedFd<'_>, base: RawFd) -> io::Result<OwnedFd> {
    let raw = fcntl(src, FcntlArg::F_DUPFD_CLOEXEC(base))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    // SAFETY: `F_DUPFD_CLOEXEC` returned a fresh, owned descriptor we are the sole holder of;
    // wrapping it transfers that ownership for RAII close.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Adopt an **inherited** descriptor at a fixed number (a [`crate::boot`] slot) as an [`OwnedFd`].
///
/// A process that inherits descriptors at agreed fixed numbers across `execve` (e.g. `facade-tun`
/// receiving the tun and broker fds) holds only the numbers, not any `OwnedFd`. This takes
/// ownership of one so it can drive safe typed wrappers (`File`, `UnixDatagram`) inside a
/// `#![forbid(unsafe_code)]` binary — the same reason `boot::borrow` wraps `borrow_raw`.
///
/// The caller must guarantee `fd` is a valid, open descriptor this process owns and that nothing
/// else already wraps: exactly one `adopt` per inherited slot (a second wrap risks a double close).
#[must_use]
pub fn adopt(fd: RawFd) -> OwnedFd {
    // SAFETY: per the documented caller contract, `fd` is an owned, singly-wrapped inherited
    // descriptor; wrapping it transfers ownership for RAII close.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn set_cloexec_marks_the_descriptor_close_on_exec() {
        // A pipe read end starts without FD_CLOEXEC (nix `pipe` is plain); setting it must
        // make F_GETFD report the flag.
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        let before = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            !FdFlag::from_bits_truncate(before).contains(FdFlag::FD_CLOEXEC),
            "plain pipe is not close-on-exec to begin with"
        );
        set_cloexec(r.as_fd()).expect("set_cloexec");
        let after = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            FdFlag::from_bits_truncate(after).contains(FdFlag::FD_CLOEXEC),
            "the flag is set after set_cloexec"
        );
    }

    #[test]
    fn dup_onto_self_clears_cloexec() {
        // The subtle case: `dup_onto(fd, fd)` must NOT be a no-op — `dup2(fd, fd)` leaves
        // close-on-exec set, so the descriptor would not survive the factory's fexecve. Mark a
        // pipe end close-on-exec, dup it onto itself, and confirm the flag is now clear.
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        set_cloexec(r.as_fd()).expect("set_cloexec");
        dup_onto(r.as_fd(), r.as_raw_fd()).expect("dup_onto self");
        let flags = fcntl(r.as_fd(), FcntlArg::F_GETFD).expect("getfd");
        assert!(
            !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC),
            "dup_onto(fd, fd) clears close-on-exec so it survives fexecve"
        );
    }

    // ─── open_no_symlinks (openat2 RESOLVE_NO_SYMLINKS) ──────────────────

    #[test]
    fn open_no_symlinks_succeeds_on_a_real_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("kennel-test-openat2-real");
        std::fs::write(&path, b"ok").expect("create");
        let fd = open_no_symlinks(libc::AT_FDCWD, &path);
        let _ = std::fs::remove_file(&path);
        let fd = fd.expect("open_no_symlinks on a real file should succeed");
        // The fd is O_PATH — we can stat through /proc/self/fd/N.
        let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        assert!(
            std::fs::symlink_metadata(&proc_path).is_ok(),
            "/proc/self/fd/N must be resolvable"
        );
    }

    #[test]
    fn open_no_symlinks_rejects_a_symlink_target() {
        let dir = std::env::temp_dir();
        let real = dir.join("kennel-test-openat2-target");
        let link = dir.join("kennel-test-openat2-link");
        std::fs::write(&real, b"ok").expect("create");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let result = open_no_symlinks(libc::AT_FDCWD, &link);
        let _ = std::fs::remove_file(&real);
        let _ = std::fs::remove_file(&link);
        let err = result.expect_err("open_no_symlinks on a symlink target must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP, got: {err}"
        );
    }

    #[test]
    fn open_no_symlinks_rejects_a_symlink_component() {
        let dir = std::env::temp_dir();
        let real_dir = dir.join("kennel-test-openat2-realdir");
        let link_dir = dir.join("kennel-test-openat2-linkdir");
        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&link_dir);
        std::fs::create_dir_all(&real_dir).expect("mkdir");
        let target = real_dir.join("file");
        std::fs::write(&target, b"ok").expect("create");
        std::os::unix::fs::symlink(&real_dir, &link_dir).expect("symlink");
        // Try to open link_dir/file — the link_dir component is a symlink.
        let via_link = link_dir.join("file");
        let result = open_no_symlinks(libc::AT_FDCWD, &via_link);
        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&link_dir);
        let err = result.expect_err("open_no_symlinks with a symlink component must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP for symlink component, got: {err}"
        );
    }

    // ─── the descriptor walkers ──────────────────────────────────────────

    /// A fresh directory under the system temp dir (canonical, so no symlink is in its own
    /// path), removed on drop.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir()).expect("temp dir");
            let dir = base.join(format!("kennel-fd-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("scratch dir");
            Self(dir)
        }
        fn path(&self, rel: &str) -> std::path::PathBuf {
            self.0.join(rel)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(path).expect("stat").ino()
    }

    fn inode_of(fd: &OwnedFd) -> u64 {
        nix::sys::stat::fstat(fd).expect("fstat").st_ino
    }

    #[test]
    fn dir_no_symlinks_creates_missing_components_and_pins_the_directory() {
        let s = Scratch::new("dns");
        let target = s.path("a/b/c");
        let fd = dir_no_symlinks(&target).expect("create");
        assert_eq!(inode_of(&fd), inode(&target));
        // A second call finds the same directory.
        assert_eq!(
            inode_of(&dir_no_symlinks(&target).expect("again")),
            inode(&target)
        );
    }

    #[test]
    fn dir_no_symlinks_refuses_a_symlink_component_and_a_relative_path() {
        let s = Scratch::new("dns-link");
        std::fs::create_dir(s.path("real")).expect("mkdir");
        std::os::unix::fs::symlink(s.path("real"), s.path("link")).expect("symlink");
        assert!(
            dir_no_symlinks(&s.path("link/sub")).is_err(),
            "through a link"
        );
        assert!(
            !s.path("real/sub").exists(),
            "nothing was created behind the link"
        );
        assert!(dir_no_symlinks(&s.path("link")).is_err(), "a final link");
        std::fs::write(s.path("file"), b"x").expect("write");
        assert!(
            dir_no_symlinks(&s.path("file/sub")).is_err(),
            "through a file"
        );
        let err = dir_no_symlinks(Path::new("relative/dir")).expect_err("relative");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = dir_no_symlinks(&s.path("a/../b")).expect_err("dot-dot");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn scaffold_dir_creates_on_an_anchor_filesystem() {
        let s = Scratch::new("scaf");
        let target = s.path("mesh/a");
        // `/` and the scratch directory's filesystem are the scaffolding here.
        let fd = scaffold_dir(&target, &[Path::new("/"), s.0.as_path()]).expect("create");
        assert_eq!(inode_of(&fd), inode(&target));
    }

    #[test]
    fn scaffold_dir_refuses_a_path_off_the_anchors_and_a_symlink() {
        let s = Scratch::new("scaf-off");
        // Only procfs is an anchor: `/` itself is then not scaffolding.
        let err = scaffold_dir(&s.path("x"), &[Path::new("/proc")]).expect_err("off anchor");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            !s.path("x").exists(),
            "nothing is created off the scaffolding"
        );
        // A path that crosses onto another filesystem part-way is refused there.
        let err = scaffold_dir(Path::new("/proc/kennel-x"), &[Path::new("/")])
            .expect_err("crosses onto procfs");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        std::fs::create_dir(s.path("real")).expect("mkdir");
        std::os::unix::fs::symlink(s.path("real"), s.path("link")).expect("symlink");
        assert!(scaffold_dir(&s.path("link/sub"), &[Path::new("/"), s.0.as_path()]).is_err());
        assert!(!s.path("real/sub").exists());
    }

    #[test]
    fn socket_in_dir_opens_a_socket_and_nothing_else() {
        use std::ffi::OsStr;
        let s = Scratch::new("sock");
        let _listener = std::os::unix::net::UnixListener::bind(s.path("s.sock")).expect("bind");
        let fd = socket_in_dir(&s.0, OsStr::new("s.sock")).expect("socket");
        assert_eq!(inode_of(&fd), inode(&s.path("s.sock")));

        std::fs::write(s.path("plain"), b"x").expect("write");
        let err = socket_in_dir(&s.0, OsStr::new("plain")).expect_err("not a socket");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        std::os::unix::fs::symlink(s.path("s.sock"), s.path("link.sock")).expect("symlink");
        assert!(
            socket_in_dir(&s.0, OsStr::new("link.sock")).is_err(),
            "a link to a socket"
        );
        assert!(
            socket_in_dir(&s.0, OsStr::new("../x")).is_err(),
            "not one name"
        );
        assert!(socket_in_dir(&s.0, OsStr::new("a/b")).is_err(), "two names");
        assert!(socket_in_dir(&s.0, OsStr::new("absent")).is_err());
    }

    #[test]
    fn root_dir_ensure_creates_and_checks_kinds() {
        let s = Scratch::new("root-ensure");
        let root = RootDir::open(&s.0).expect("root");
        let dir = root
            .ensure(Path::new("/a/b"), NodeKind::Directory)
            .expect("dir");
        assert_eq!(inode_of(&dir), inode(&s.path("a/b")));
        let file = root.ensure(Path::new("a/f"), NodeKind::File).expect("file");
        assert_eq!(inode_of(&file), inode(&s.path("a/f")));
        // Existing nodes are accepted as they are, and the wrong kind is refused.
        root.ensure(Path::new("a/b"), NodeKind::Directory)
            .expect("again");
        assert!(root.ensure(Path::new("a/b"), NodeKind::File).is_err());
        assert!(root.ensure(Path::new("a/f"), NodeKind::Directory).is_err());
        assert!(root
            .ensure(Path::new("a/f/under"), NodeKind::Directory)
            .is_err());
        assert!(root
            .ensure(Path::new("a/../b"), NodeKind::Directory)
            .is_err());
    }

    #[test]
    fn root_dir_never_accepts_a_final_symlink_and_keeps_parent_links_inside() {
        let s = Scratch::new("root-link");
        let outside = Scratch::new("root-link-out");
        std::fs::create_dir(s.path("usr")).expect("mkdir");
        let root = RootDir::open(&s.0).expect("root");

        // A final symlink is refused as a mount point, whatever it points at.
        std::os::unix::fs::symlink("usr", s.path("bin")).expect("symlink");
        assert!(root.ensure(Path::new("bin"), NodeKind::Directory).is_err());
        // `lookup` sees the link itself; `resolve` sees where it leads.
        let seen = root
            .lookup(Path::new("bin"))
            .expect("lookup")
            .expect("present");
        assert_eq!(inode_of(&seen), inode(&s.path("bin")));
        let led = root
            .resolve(Path::new("bin"))
            .expect("resolve")
            .expect("present");
        assert_eq!(inode_of(&led), inode(&s.path("usr")));
        assert!(
            !root.is_dir(Path::new("bin")).expect("is_dir"),
            "a link is not a directory"
        );

        // A parent that is a relative link is followed inside the root.
        root.ensure(Path::new("bin/tool"), NodeKind::File)
            .expect("through the link");
        assert!(s.path("usr/tool").exists());

        // A parent that is an ABSOLUTE link resolves against the root, not the host: the
        // directory outside the root is never written.
        std::os::unix::fs::symlink(&outside.0, s.path("abs")).expect("symlink");
        let made = root.ensure(Path::new("abs/planted"), NodeKind::File);
        assert!(
            !outside.path("planted").exists(),
            "nothing lands outside the root"
        );
        assert!(made.is_err(), "the link leads nowhere inside the root");
        assert!(root.resolve(Path::new("abs")).expect("resolve").is_none());
    }

    #[test]
    fn root_dir_lookup_reports_absence_without_creating() {
        let s = Scratch::new("root-lookup");
        let root = RootDir::open(&s.0).expect("root");
        assert!(root.lookup(Path::new("no/such")).expect("lookup").is_none());
        assert!(!s.path("no").exists());
        assert!(!root.is_dir(Path::new("no")).expect("is_dir"));
        std::fs::write(s.path("f"), b"x").expect("write");
        assert!(root.lookup(Path::new("f/under")).expect("lookup").is_none());
        assert!(root.lookup(Path::new("../x")).is_err());
    }

    #[test]
    fn root_dir_writes_copies_links_and_removes_without_following() {
        use std::os::unix::fs::PermissionsExt as _;
        let s = Scratch::new("root-io");
        let outside = Scratch::new("root-io-out");
        let root = RootDir::open(&s.0).expect("root");

        root.write_new(Path::new("etc/passwd"), b"root:x:0:0\n", 0o4644)
            .expect("write");
        assert_eq!(
            std::fs::read(s.path("etc/passwd")).expect("read"),
            b"root:x:0:0\n"
        );
        let mode = std::fs::metadata(s.path("etc/passwd"))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o644, "set-id bits are not carried");
        assert!(
            root.write_new(Path::new("etc/passwd"), b"x", 0o644)
                .is_err(),
            "no overwrite"
        );

        // A destination that is a symlink is never written through.
        std::fs::write(outside.path("victim"), b"keep").expect("write");
        std::os::unix::fs::symlink(outside.path("victim"), s.path("etc/link")).expect("symlink");
        assert!(root.write_new(Path::new("etc/link"), b"x", 0o644).is_err());
        std::fs::write(outside.path("src"), b"payload").expect("write");
        std::fs::set_permissions(outside.path("src"), std::fs::Permissions::from_mode(0o6777))
            .expect("chmod");
        assert!(root
            .copy_into(&outside.path("src"), Path::new("etc/link"))
            .is_err());
        assert_eq!(
            std::fs::read(outside.path("victim")).expect("read"),
            b"keep"
        );

        root.copy_into(&outside.path("src"), Path::new("bin/tool"))
            .expect("copy");
        assert_eq!(std::fs::read(s.path("bin/tool")).expect("read"), b"payload");
        let mode = std::fs::metadata(s.path("bin/tool"))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755, "no set-id, no group or other write");

        root.symlink(Path::new("tool"), Path::new("bin/alias"))
            .expect("symlink");
        assert_eq!(
            std::fs::read_link(s.path("bin/alias")).expect("readlink"),
            Path::new("tool")
        );
        assert!(
            root.symlink(Path::new("x"), Path::new("bin/alias"))
                .is_err(),
            "exists"
        );

        // Removing a link removes the link, not what it points at.
        root.remove(Path::new("etc/link")).expect("remove");
        assert!(std::fs::symlink_metadata(s.path("etc/link")).is_err());
        assert!(outside.path("victim").exists());
        root.remove(Path::new("etc/link")).expect("absent is fine");
        root.remove(Path::new("no/parent/x"))
            .expect("missing parent is fine");
        assert!(
            root.remove(Path::new("etc")).is_err(),
            "a directory is not removed"
        );
        assert!(root.remove(Path::new("/")).is_err(), "nor the root");
    }

    #[test]
    fn create_in_root_same_mount_makes_mount_points_inside_the_root_only() {
        let s = Scratch::new("cirsm");
        let outside = Scratch::new("cirsm-out");
        create_in_root_same_mount(&s.0, Path::new("a/b/dir"), true).expect("dir");
        assert!(s.path("a/b/dir").is_dir());
        create_in_root_same_mount(&s.0, Path::new("a/b/file"), false).expect("file");
        assert!(s.path("a/b/file").is_file());
        // Existing paths are left alone.
        std::fs::write(s.path("a/b/file"), b"kept").expect("write");
        create_in_root_same_mount(&s.0, Path::new("a/b/file"), false).expect("again");
        assert_eq!(std::fs::read(s.path("a/b/file")).expect("read"), b"kept");

        let err = create_in_root_same_mount(&s.0, Path::new("../x"), true).expect_err("dot-dot");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = create_in_root_same_mount(&s.0, Path::new("/abs"), true).expect_err("absolute");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // An absolute symlink resolves inside the root: nothing is created at its host target.
        std::os::unix::fs::symlink(&outside.0, s.path("abs")).expect("symlink");
        let _ = create_in_root_same_mount(&s.0, Path::new("abs/planted"), true);
        assert!(!outside.path("planted").exists());
    }

    #[test]
    fn chown_tree_same_mount_walks_the_tree_without_following_links() {
        // Unprivileged, the only owner we can give is ourselves, so this checks the walk: it
        // reaches every entry, tolerates a dangling link and a link out of the tree (it re-owns
        // the link, never the target), and honours `skip`.
        let s = Scratch::new("chown");
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        std::fs::create_dir_all(s.path("t/a/b")).expect("mkdir");
        std::fs::write(s.path("t/a/f"), b"x").expect("write");
        std::os::unix::fs::symlink("/nonexistent/kennel", s.path("t/dangling")).expect("symlink");
        std::os::unix::fs::symlink("/etc", s.path("t/out")).expect("symlink");
        chown_tree_same_mount(&s.path("t"), uid, gid, Some(Path::new("a/b"))).expect("walk");
        chown_tree_same_mount(&s.path("t"), uid, gid, None).expect("walk");
        // The root of the walk must itself not be a symlink.
        std::os::unix::fs::symlink(s.path("t"), s.path("tl")).expect("symlink");
        assert!(chown_tree_same_mount(&s.path("tl"), uid, gid, None).is_err());
        // A mount point inside the tree is skipped, not entered: procfs under a scratch root
        // cannot be arranged unprivileged, so that half is covered by the root-only suite.
    }
}
