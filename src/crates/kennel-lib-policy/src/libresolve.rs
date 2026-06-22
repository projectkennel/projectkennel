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
    /// Non-fatal advisories. The single actionable case: an allowlisted `#!` script whose
    /// **interpreter** (the path after `#!`) is itself absent from the allowlist, so the
    /// kernel would deny the `execve` of that interpreter.
    pub warnings: Vec<String>,
}

/// Resolve the `EXECUTE`-grant **loader** set for `binaries` — the `PT_INTERP` of each
/// concrete dynamic binary in the exec allowlist.
///
/// Wildcard (`**`) and glob entries are skipped: they are not single binaries to inspect
/// (and `**` is the permissive-exec opt-in, where everything is executable anyway). A
/// statically-linked binary has no `PT_INTERP` and needs no loader grant.
///
/// A `#!` **script** has no `PT_INTERP`; what it needs to `execve` is its *interpreter* (the
/// path after `#!`), which the kernel opens `FMODE_EXEC` and Landlock therefore gates. The
/// interpreter's own loader is resolved when the interpreter appears as its own allowlist
/// entry, so the only thing worth a warning is an interpreter the allowlist omits. A file
/// that cannot be read on the compile host (a binary present only on the deploy host) or that
/// is neither ELF nor a script is passed over silently — the deploy host is authoritative for
/// what is present.
#[must_use]
pub fn resolve_loaders(binaries: &[String]) -> LoaderResolution {
    let allow: BTreeSet<&str> = binaries.iter().map(String::as_str).collect();
    let mut loaders: BTreeSet<String> = BTreeSet::new();
    let mut warnings: Vec<String> = Vec::new();
    for binary in binaries {
        if binary.contains('*') || !binary.starts_with('/') {
            continue;
        }
        match classify(Path::new(binary)) {
            Kind::Elf(Some(loader)) => {
                loaders.insert(loader.to_string_lossy().into_owned());
            }
            Kind::Script(interp) => {
                let interp = interp.to_string_lossy();
                if !allow.contains(interp.as_ref()) {
                    warnings.push(format!(
                        "`{binary}` is a `#!` script whose interpreter `{interp}` is not on \
                         exec.allow; the kernel denies its execve — add `{interp}` to the allowlist"
                    ));
                }
            }
            // Statically linked (no loader), unreadable on this host, or not an executable
            // object: nothing to grant or warn about.
            Kind::Elf(None) | Kind::Opaque => {}
        }
    }
    LoaderResolution {
        loaders: loaders.into_iter().collect(),
        warnings,
    }
}

/// What an allowlisted path is, for loader resolution.
enum Kind {
    /// An ELF binary, with its `PT_INTERP` loader (or `None` when statically linked).
    Elf(Option<PathBuf>),
    /// A `#!` script, carrying the absolute interpreter path after `#!`.
    Script(PathBuf),
    /// Unreadable on this host, or readable but neither ELF nor a `#!` script — nothing to resolve.
    Opaque,
}

/// Classify a binary path without executing it: a `#!` script (by its leading shebang), an
/// ELF object (by parse), or opaque (unreadable / other).
fn classify(path: &Path) -> Kind {
    std::fs::read(path).map_or(Kind::Opaque, |data| classify_bytes(&data))
}

/// The pure classifier over a file's bytes (so the shebang parse is unit-testable without disk).
fn classify_bytes(data: &[u8]) -> Kind {
    if let Some(rest) = data.strip_prefix(b"#!") {
        // The interpreter is the first whitespace-delimited token of the shebang line.
        let line = rest.split(|&b| b == b'\n').next().unwrap_or(rest);
        let text = String::from_utf8_lossy(line);
        let token = text.split_whitespace().next().unwrap_or("");
        if token.starts_with('/') {
            return Kind::Script(PathBuf::from(token));
        }
        return Kind::Opaque; // a relative/empty shebang is not actionable here
    }
    object::File::parse(data).map_or(Kind::Opaque, |file| Kind::Elf(interp_of_elf(&file)))
}

/// Extract an ELF's `PT_INTERP` (the `.interp` section) — its dynamic loader path, or `None`
/// when statically linked.
fn interp_of_elf(file: &object::File<'_>) -> Option<PathBuf> {
    file.section_by_name(".interp")
        .and_then(|section| section.data().ok())
        .map(|bytes| {
            let nul_terminated = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
            PathBuf::from(String::from_utf8_lossy(nul_terminated).into_owned())
        })
        .filter(|p| !p.as_os_str().is_empty())
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
    fn wildcards_globs_and_missing_binaries_are_silent() {
        // `**` (permissive) and non-absolute entries are skipped, not inspected.
        let res = resolve_loaders(&["**".to_owned(), "sh".to_owned()]);
        assert!(res.loaders.is_empty() && res.warnings.is_empty());
        // An absolute path absent on the compile host is passed over silently — the deploy host is
        // authoritative for what is present, and an unreadable file is not the actionable case.
        let res = resolve_loaders(&["/nonexistent/binary".to_owned()]);
        assert!(res.loaders.is_empty() && res.warnings.is_empty());
    }

    #[test]
    fn shebang_is_parsed_to_its_interpreter() {
        assert!(matches!(
            classify_bytes(b"#!/bin/sh\nexec grep -E \"$@\"\n"),
            Kind::Script(p) if p == Path::new("/bin/sh")
        ));
        // `#!/usr/bin/env python3` → the interpreter is /usr/bin/env (the kernel's execve target).
        assert!(matches!(
            classify_bytes(b"#!/usr/bin/env python3\n"),
            Kind::Script(p) if p == Path::new("/usr/bin/env")
        ));
        // A relative or empty shebang is not actionable.
        assert!(matches!(classify_bytes(b"#!sh\n"), Kind::Opaque));
        // Arbitrary non-ELF, non-script data is opaque.
        assert!(matches!(classify_bytes(b"plain text\n"), Kind::Opaque));
    }

    #[test]
    fn a_script_warns_only_when_its_interpreter_is_not_allowlisted() {
        // Write a real `#!` script and resolve it against two allowlists.
        let dir = std::env::temp_dir();
        let script = dir.join(format!("kennel-libresolve-test-{}", std::process::id()));
        std::fs::write(&script, b"#!/bin/sh\nexec echo hi\n").expect("write script");
        let path = script.to_string_lossy().into_owned();

        // Interpreter present → silent (its own loader is resolved via its own allowlist entry).
        let res = resolve_loaders(&[path.clone(), "/bin/sh".to_owned()]);
        assert!(
            res.warnings.is_empty(),
            "interpreter allowlisted → no warning"
        );

        // Interpreter absent → exactly one actionable warning naming the interpreter.
        let res = resolve_loaders(&[path]);
        assert_eq!(res.warnings.len(), 1);
        let warning = res.warnings.first().expect("one warning");
        assert!(warning.contains("/bin/sh") && warning.contains("exec.allow"));

        let _ = std::fs::remove_file(&script);
    }
}
