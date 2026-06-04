//! Locating kenneld's own cgroup and placing kennel cgroups under it.
//!
//! kenneld runs as a systemd *user* service, so its own cgroup lives inside the
//! user's delegated `user@<uid>.service` subtree (`08-enforcement-architecture.md`
//! §8.5). Kennel cgroups are created as children of it: a child shares kenneld's
//! cgroup as the migration common ancestor, so the workload — born in kenneld's
//! cgroup — can be moved into its kennel cgroup unprivileged (the constraint that
//! made top-level delegation impossible; see the cgroup-join note on
//! `kennel_spawn`). Reading the *own* cgroup keeps this distro-agnostic: no
//! parsing for systemd-specific slice names.

use std::io;
use std::path::{Path, PathBuf};

/// The cgroup v2 unified mount point.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// The prefix for a per-kennel cgroup directory name (`kennel-<ctx>`).
const KENNEL_PREFIX: &str = "kennel-";

/// kenneld's own cgroup, as an absolute path under `CGROUP_MOUNT`.
///
/// # Errors
/// Returns an OS error if `/proc/self/cgroup` cannot be read, or `InvalidData`
/// if it has no cgroup v2 (`0::…`) line (the host is not cgroup-v2-unified).
pub fn self_cgroup() -> io::Result<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup")?;
    parse_self_cgroup(&content).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no cgroup v2 line in /proc/self/cgroup",
        )
    })
}

/// Parse the unified-hierarchy (`0::<path>`) line out of `/proc/self/cgroup`
/// content and resolve it to an absolute path under the cgroup mount.
fn parse_self_cgroup(content: &str) -> Option<PathBuf> {
    for line in content.lines() {
        // cgroup v2 unified hierarchy: "0::<path>", path relative to the mount.
        if let Some(rest) = line.strip_prefix("0::") {
            let relative = rest.trim_start_matches('/');
            return Some(Path::new(CGROUP_MOUNT).join(relative));
        }
    }
    None
}

/// The cgroup path for kennel `ctx`, as a child of `base` (kenneld's own cgroup
/// from [`self_cgroup`]).
#[must_use]
pub fn kennel_cgroup(base: &Path, ctx: u16) -> PathBuf {
    base.join(format!("{KENNEL_PREFIX}{ctx}"))
}

/// Forcibly kill **every** process in `cgroup` (`SIGKILL`) by writing `1` to its
/// `cgroup.kill` (cgroup v2, kernel 5.14+).
///
/// This is the correct way to stop a kennel's workload: with the unprivileged
/// spawn the workload is PID 1 of a nested PID namespace reached via a double-fork
/// (`kennel_spawn::spawn`), so the process kenneld holds a handle to is the
/// intermediate init, *not* the workload — signalling that pid by hand would leave
/// the workload running. `cgroup.kill` reaches every member regardless of PID-
/// namespace nesting (the intermediate, the workload, and any descendants), and
/// the kennel cgroup is in kenneld's own delegated subtree, so the write needs no
/// privilege.
///
/// # Errors
/// An OS error if the cgroup has no `cgroup.kill` (pre-5.14) or the write fails
/// (e.g. the cgroup was already removed). Callers treat it as best-effort and may
/// fall back to signalling the handle directly.
pub fn kill_cgroup(cgroup: &Path) -> io::Result<()> {
    std::fs::write(cgroup.join("cgroup.kill"), "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_unified_line() {
        let content = "0::/user.slice/user-1000.slice/user@1000.service/kenneld.service\n";
        assert_eq!(
            parse_self_cgroup(content),
            Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/kenneld.service"
            ))
        );
    }

    #[test]
    fn root_cgroup_resolves_to_the_mount() {
        assert_eq!(
            parse_self_cgroup("0::/\n"),
            Some(PathBuf::from(CGROUP_MOUNT))
        );
    }

    #[test]
    fn picks_the_v2_line_among_v1_lines() {
        // A hybrid /proc/self/cgroup: v1 controller lines, then the unified line.
        let content = "2:cpu,cpuacct:/foo\n1:name=systemd:/bar\n0::/baz\n";
        assert_eq!(
            parse_self_cgroup(content),
            Some(PathBuf::from("/sys/fs/cgroup/baz"))
        );
    }

    #[test]
    fn no_unified_line_is_none() {
        assert!(parse_self_cgroup("1:name=systemd:/foo\n").is_none());
    }

    #[test]
    fn kennel_cgroup_is_a_child_named_by_ctx() {
        let base = PathBuf::from("/sys/fs/cgroup/user.slice/user@1000.service/kenneld.service");
        assert_eq!(kennel_cgroup(&base, 7), base.join("kennel-7"));
    }

    #[test]
    fn kill_cgroup_writes_one_to_cgroup_kill() {
        // Against a stand-in directory (a real cgroupfs write needs a delegated
        // cgroup, exercised by the e2e): the helper must target `<cgroup>/cgroup.kill`
        // and write exactly `1` (the kernel's "kill every member" trigger).
        let dir = std::env::temp_dir().join(format!("kennel-cgkill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        kill_cgroup(&dir).expect("write cgroup.kill");
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.kill")).expect("read"),
            "1"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
