// SPDX-License-Identifier: Apache-2.0

//! Which directory an OCI overlay may take as its read-only image lower.
//!
//! The overlay is mounted with root's identity (see `mount_image_overlay`), and overlayfs keeps
//! the mounter's credentials for every later access to the real lower inodes. Two things follow:
//!
//! - the image's own mode stops mattering — the merged root takes its attributes from the upper
//!   layer, so a directory closed to the caller would be served to the workload open;
//! - the same happens to any directory **inside** the image that a layer above also has: a merged
//!   directory takes its attributes from the topmost layer, and the lower's contents are then
//!   read with root's credentials.
//!
//! So the caller's own access is established here, with the caller's filesystem identity, before
//! the mount is made: the image must be a directory the caller can read and search, it must be
//! the caller's own or a root-owned directory in a system location, and no directory in a layer
//! stacked above it may cover an image directory the caller cannot read and search.

use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use kennel_lib_syscall::fd::RootDir;

use super::{fd_path, overlay_dir};

/// Where a root-owned image may live: a directory **beneath** one of these.
///
/// The system's own trees. Not `/` itself and not `/root`, `/home`, `/tmp`, `/run` or anything
/// else — a root-owned directory elsewhere is somebody's private data, not a shared image.
const SYSTEM_IMAGE_ROOTS: [&str; 6] = ["/usr", "/var", "/etc", "/lib", "/lib64", "/opt"];

/// Whether `real` (a resolved, absolute path) lies beneath a system image root.
fn in_system_location(real: &Path) -> bool {
    SYSTEM_IMAGE_ROOTS.iter().any(|root| {
        real.strip_prefix(root)
            .is_ok_and(|rest| rest.components().next().is_some())
    })
}

fn refused(what: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("image {}: {why}", what.display()),
    )
}

/// Require that the CURRENT filesystem identity can list and search the directory `dir` names.
///
/// The kernel answers, not the mode bits: the directory is opened for reading, and a name is
/// looked up in it. `dir` is typically an `O_PATH` handle, which the kernel hands out for a
/// directory the caller has no access to at all — holding one proves nothing.
fn require_access(dir: &std::fs::File, what: &Path) -> io::Result<()> {
    let at = fd_path(dir);
    std::fs::read_dir(&at)
        .map(drop)
        .map_err(|e| refused(what, &format!("the caller cannot read it ({e})")))?;
    std::fs::symlink_metadata(at.join("."))
        .map(drop)
        .map_err(|e| refused(what, &format!("the caller cannot search it ({e})")))
}

/// Open the image directory for the overlay's lower, as an `O_PATH` handle pinning its inode.
///
/// `caller` is the uid whose filesystem identity is in force (`None`: the caller is root, and
/// there is nothing to establish). `persist` says the overlay gets a caller-owned upper that
/// outlives the kennel.
///
/// The image must be a directory the caller can read and search, and either
///
/// - the caller's own, or
/// - root's, not writable by group or other, beneath a [system location](SYSTEM_IMAGE_ROOTS),
///   and used without a persistent upper. The caller can add a directory to their own upper at
///   any time, and it would cover the image directory of the same name (module docs); no check
///   made before the mount can rule that out, so the combination is refused.
///
/// The location is judged on the path the handle resolved to, so neither a symlink nor `..` in
/// the given path changes the answer.
///
/// # Errors
///
/// `PermissionDenied` naming the rule the image breaks; the OS error if it cannot be opened.
pub fn image_dir(path: &Path, caller: Option<u32>, persist: bool) -> io::Result<std::fs::File> {
    let dir = overlay_dir(path, None)?;
    let Some(caller) = caller else {
        return Ok(dir);
    };
    require_access(&dir, path)?;
    let meta = dir.metadata()?;
    if meta.uid() == caller {
        return Ok(dir);
    }
    if meta.uid() != 0 {
        return Err(refused(
            path,
            &format!(
                "owned by uid {}, neither the caller ({caller}) nor root",
                meta.uid()
            ),
        ));
    }
    if persist {
        return Err(refused(
            path,
            "a root-owned image cannot be combined with a persistent rootfs",
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refused(path, "root-owned but writable by group or other"));
    }
    let real: PathBuf = std::fs::read_link(fd_path(&dir))?;
    if !in_system_location(&real) {
        return Err(refused(
            path,
            "a root-owned image must sit beneath /usr, /var, /etc, /lib, /lib64 or /opt",
        ));
    }
    Ok(dir)
}

/// Refuse a `layer` stacked above `image` that would open up an image directory.
///
/// Every directory in `layer` that the image also has as a directory will be merged with it, and
/// shown with the layer's attributes. Each such image directory must therefore be one the
/// current filesystem identity can read and search. Where the image has no directory of that
/// name (nothing, a file, a symlink) the layer's directory simply replaces it, and nothing
/// beneath it merges either.
///
/// # Errors
///
/// `PermissionDenied` naming the first image directory the caller has no access to; the OS error
/// if either tree cannot be walked.
pub fn guard_merges(image: &std::fs::File, layer: &Path) -> io::Result<()> {
    let root = RootDir::open(&fd_path(image))?;
    guard_merges_under(&root, layer, Path::new("/"))
}

fn guard_merges_under(image: &RootDir, layer_dir: &Path, at: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(layer_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let at = at.join(entry.file_name());
        // Every parent of `at` was found to be a real directory on the way down, so this lookup
        // follows no symlink: the final component is never followed, and no parent is one.
        let under = image
            .lookup(&at)
            .map_err(|e| refused(&at, &format!("inside the image, cannot be examined ({e})")))?;
        let Some(under) = under.map(std::fs::File::from) else {
            continue;
        };
        if !under.metadata()?.is_dir() {
            continue;
        }
        require_access(&under, &at)?;
        guard_merges_under(image, &entry.path(), &at)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory owned by the test's user, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("kennel-image-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            Self(dir)
        }

        fn dir(&self, rel: &str, mode: u32) -> PathBuf {
            let p = self.0.join(rel);
            std::fs::create_dir_all(&p).expect("mkdir");
            chmod(&p, mode);
            p
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            reopen(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Make a tree removable again (the tests close directories to their own owner).
    fn reopen(p: &Path) {
        if p.symlink_metadata().is_ok_and(|m| m.is_dir()) {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
                reopen(&e.path());
            }
        }
    }

    /// The test user's uid, or `None` when the tests run as root — root passes every access
    /// check, so the refusals below cannot be observed.
    fn me() -> Option<u32> {
        let uid = kennel_lib_syscall::unistd::real_uid();
        (uid != 0).then_some(uid)
    }

    #[test]
    fn system_locations_are_beneath_the_roots_never_the_roots_themselves() {
        for ok in [
            "/usr/share/img",
            "/var/lib/kennel/images/a",
            "/opt/x",
            "/lib/x",
        ] {
            assert!(in_system_location(Path::new(ok)), "{ok}");
        }
        for no in [
            "/",
            "/usr",
            "/var",
            "/usrx/y",
            "/root",
            "/root/img",
            "/home/a",
            "/tmp/x",
        ] {
            assert!(!in_system_location(Path::new(no)), "{no}");
        }
    }

    #[test]
    fn a_path_handle_alone_does_not_prove_access() {
        // The reason `image_dir` asks the kernel twice more: the handle is granted regardless.
        let Some(_) = me() else { return };
        let s = Scratch::new("handle");
        let closed = s.dir("closed", 0o000);
        assert!(overlay_dir(&closed, None).is_ok());
    }

    #[test]
    fn the_callers_own_readable_image_is_accepted() {
        let Some(uid) = me() else { return };
        let s = Scratch::new("own");
        let img = s.dir("img", 0o755);
        assert!(image_dir(&img, Some(uid), false).is_ok());
        assert!(image_dir(&img, Some(uid), true).is_ok());
    }

    #[test]
    fn an_image_the_caller_cannot_read_or_search_is_refused() {
        let Some(uid) = me() else { return };
        let s = Scratch::new("closed");
        for mode in [0o000, 0o400, 0o100] {
            let img = s.dir(&format!("m{mode:o}"), mode);
            let err = image_dir(&img, Some(uid), false).expect_err("must refuse");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
    }

    #[test]
    fn an_image_behind_a_closed_parent_is_refused() {
        let Some(uid) = me() else { return };
        let s = Scratch::new("parent");
        let img = s.dir("gate/img", 0o755);
        chmod(&s.0.join("gate"), 0o000);
        assert!(image_dir(&img, Some(uid), false).is_err());
    }

    #[test]
    fn a_root_owned_image_needs_a_system_location() {
        let Some(uid) = me() else { return };
        // Root-owned, closed to group and other for writing, beneath a system root. Which
        // directory qualifies depends on the host (a CI image may open `/usr/share` to all), so
        // take the first that does rather than assume one.
        let system = ["/usr/share", "/usr/lib", "/usr/bin", "/etc/ssl"]
            .into_iter()
            .map(Path::new)
            .find(|p| {
                p.metadata()
                    .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
            });
        if let Some(system) = system {
            image_dir(system, Some(uid), false).expect("a system image is accepted");
            // ...but never under a persistent, caller-owned upper.
            assert!(image_dir(system, Some(uid), true).is_err());
        }
        // Root-owned and readable, but not a system location (or the root of one).
        for no in ["/", "/usr", "/tmp", "/root"] {
            assert!(image_dir(Path::new(no), Some(uid), false).is_err(), "{no}");
        }
    }

    #[test]
    fn a_symlink_does_not_move_an_image_into_a_system_location() {
        let Some(uid) = me() else { return };
        let s = Scratch::new("link");
        let link = s.0.join("usr");
        std::os::unix::fs::symlink("/", &link).expect("symlink");
        assert!(image_dir(&link, Some(uid), false).is_err());
        assert!(image_dir(Path::new("/usr/share/../.."), Some(uid), false).is_err());
    }

    #[test]
    fn root_as_the_caller_is_not_second_guessed() {
        let s = Scratch::new("root");
        let img = s.dir("img", 0o755);
        assert!(image_dir(&img, None, true).is_ok());
    }

    #[test]
    fn a_layer_may_not_cover_an_image_directory_the_caller_cannot_enter() {
        let Some(_) = me() else { return };
        let s = Scratch::new("merge");
        let img = s.dir("img", 0o755);
        s.dir("img/open/deeper", 0o755);
        s.dir("img/closed", 0o755);
        s.dir("img/gate/inner", 0o755);
        std::os::unix::fs::symlink("closed", img.join("alias")).expect("symlink");
        chmod(&img.join("closed"), 0o000);
        chmod(&img.join("gate/inner"), 0o000);
        let image = overlay_dir(&img, None).expect("image handle");

        // Covers only directories the caller can enter, or names the image does not have.
        let fine = s.dir("fine", 0o755);
        s.dir("fine/open/deeper", 0o755);
        s.dir("fine/absent/x", 0o755);
        // The image has a symlink here, not a directory: nothing merges, nothing to refuse.
        s.dir("fine/alias", 0o755);
        guard_merges(&image, &fine).expect("no closed directory is covered");

        let top = s.dir("top", 0o755);
        s.dir("top/closed", 0o755);
        let err = guard_merges(&image, &top).expect_err("covers a closed directory");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let nested = s.dir("nested", 0o755);
        s.dir("nested/gate/inner", 0o755);
        assert!(guard_merges(&image, &nested).is_err());
    }
}
