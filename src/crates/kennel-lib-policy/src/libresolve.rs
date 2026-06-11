//! Compile-time resolution of the dynamic **loaders** the allowlisted binaries need
//! (`07-3-exec`).
//!
//! Execution is deny-by-default, gated by Landlock `FS_EXECUTE`. The kernel checks that
//! right at `execve(2)` — **including** the open of a dynamic binary's `PT_INTERP` (its
//! loader, `ld.so`), which is opened `FMODE_EXEC`. So an allowlisted *dynamic* binary needs
//! `FS_EXECUTE` on its loader as well as on itself.
//!
//! Its shared libraries (`DT_NEEDED`, and anything `dlopen`ed at runtime) do **not** need
//! `FS_EXECUTE`: the loader `mmap`s them, and Landlock has no `mmap`/`mprotect` hook, so they
//! load with `READ` alone. The kennel therefore makes **no execute claim over libraries** —
//! granting it would be unenforceable theatre, and filtering it would be a blind policy
//! target that grants execute. This module resolves only each binary's loader; the libraries
//! are reachable purely through the `fs.read` grants that already cover the system lib dirs.
//!
//! The binaries are read from disk (the compile host must hold them) but never executed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSection};

/// The outcome of resolving the loaders for a set of binaries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoaderResolution {
    /// Absolute loader paths to `EXECUTE`-grant (sorted, deduped). One per distinct
    /// `PT_INTERP`; a statically-linked binary contributes none.
    pub loaders: Vec<String>,
    /// Non-fatal advisories: a binary that could not be read to resolve its loader.
    pub warnings: Vec<String>,
}

/// Resolve the `EXECUTE`-grant **loader** set for `binaries` — the `PT_INTERP` of each
/// concrete dynamic binary in the exec allowlist.
///
/// Wildcard (`**`) and glob entries are skipped: they are not single binaries to inspect
/// (and `**` is the permissive-exec opt-in, where everything is executable anyway). A
/// statically-linked binary has no `PT_INTERP` and needs no loader grant.
#[must_use]
pub fn resolve_loaders(binaries: &[String]) -> LoaderResolution {
    let mut loaders: BTreeSet<String> = BTreeSet::new();
    let mut warnings: Vec<String> = Vec::new();
    for binary in binaries {
        if binary.contains('*') || !binary.starts_with('/') {
            continue;
        }
        match interp_of(Path::new(binary)) {
            Ok(Some(loader)) => {
                loaders.insert(loader.to_string_lossy().into_owned());
            }
            Ok(None) => {} // statically linked: no loader to grant
            Err(()) => warnings.push(format!(
                "could not read `{binary}` to resolve its loader; a dynamic binary may fail to \
                 execve without an EXECUTE grant on its PT_INTERP"
            )),
        }
    }
    LoaderResolution {
        loaders: loaders.into_iter().collect(),
        warnings,
    }
}

/// Read a binary's `PT_INTERP` (the `.interp` section) — the dynamic loader path.
/// `Ok(Some(path))` for a dynamic binary, `Ok(None)` for a statically-linked one, and
/// `Err(())` if the file is unreadable or not an object file. Never executes the binary.
fn interp_of(path: &Path) -> Result<Option<PathBuf>, ()> {
    let data = std::fs::read(path).map_err(|_| ())?;
    let file = object::File::parse(&*data).map_err(|_| ())?;
    let interp = file
        .section_by_name(".interp")
        .and_then(|section| section.data().ok())
        .map(|bytes| {
            let nul_terminated = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
            PathBuf::from(String::from_utf8_lossy(nul_terminated).into_owned())
        })
        .filter(|p| !p.as_os_str().is_empty());
    Ok(interp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_loader_of_a_real_dynamic_binary() {
        // /bin/sh is dynamic on the test host; its PT_INTERP is an absolute ld.so path.
        let Ok(sh) = std::fs::canonicalize("/bin/sh") else {
            return; // no /bin/sh — skip
        };
        let res = resolve_loaders(&[sh.to_string_lossy().into_owned()]);
        assert!(
            res.warnings.is_empty(),
            "a readable binary yields no warning"
        );
        assert_eq!(
            res.loaders.len(),
            1,
            "exactly one loader: {:?}",
            res.loaders
        );
        let loader = res.loaders.first().expect("exactly one loader");
        assert!(
            loader.contains("ld-") || loader.contains("ld."),
            "the loader looks like ld.so: {loader}"
        );
        assert!(Path::new(loader).is_absolute(), "loader path is absolute");
    }

    #[test]
    fn wildcards_globs_and_missing_binaries_are_handled() {
        // `**` (permissive) and non-absolute entries are skipped, not inspected.
        let res = resolve_loaders(&["**".to_owned(), "sh".to_owned()]);
        assert!(res.loaders.is_empty() && res.warnings.is_empty());
        // An absolute path that does not exist warns (a real binary that we could not read).
        let res = resolve_loaders(&["/nonexistent/binary".to_owned()]);
        assert!(res.loaders.is_empty());
        assert_eq!(res.warnings.len(), 1, "unreadable binary warns");
    }
}
