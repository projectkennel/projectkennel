//! Compile-time shared-library closure resolution (`07-1-execution`).
//!
//! Execution is deny-by-default: a library is made `EXECUTE`-able (so the loader may
//! `mmap` it `PROT_EXEC`) only when an **allowlisted binary actually links it**. This
//! module computes that closure: for each `exec.allow` binary it reads the ELF
//! (`object`, never executing it), takes the `PT_INTERP` loader and the transitive
//! `DT_NEEDED` graph, resolves each soname against the standard search dirs, then
//! keeps only the paths that match a `[lib].allow` glob and no `[lib].deny` glob.
//!
//! The `[lib].allow`/`deny` globs are a **filter over the closure**, not a grant: a
//! binary planted under `/usr/lib` is never granted — nothing in the allowlist links
//! it. The result is settled at compile time and consumed by `kennel-spawn`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSection};

/// The outcome of resolving the library closure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibResolution {
    /// Absolute library paths to `EXECUTE`-grant (sorted, deduped).
    pub libraries: Vec<String>,
    /// Non-fatal advisories: a needed library that was denied or unresolvable.
    pub warnings: Vec<String>,
}

/// Sonames the C library `dlopen`s rather than linking via `DT_NEEDED` — chiefly the
/// NSS backends behind `getpwuid`/`getaddrinfo`. They never appear in the closure, so
/// without seeding them name resolution inside the kennel breaks. Seeded only when at
/// least one binary is allowlisted, and still filtered by `[lib].allow`/`deny`.
const DLOPEN_SEED: &[&str] = &[
    "libnss_files.so.2",
    "libnss_dns.so.2",
    "libnss_compat.so.2",
    "libresolv.so.2",
];

/// Resolve the `EXECUTE`-grant library set for `binaries`.
///
/// The result is the binaries' shared-library closure, filtered by the `[lib]`
/// `allow`/`deny` globs. Reads the binaries from disk (the compile host must hold the
/// allowlisted binaries) but never executes them.
#[must_use]
pub fn resolve_libraries(binaries: &[String], allow: &[String], deny: &[String]) -> LibResolution {
    let dirs = search_dirs();
    let mut closure: BTreeSet<PathBuf> = BTreeSet::new();
    let mut seen_soname: BTreeSet<String> = BTreeSet::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut queue: Vec<PathBuf> = Vec::new();

    // Seed: the concrete allowlisted binaries (skip the `**` wildcard, globs, and any
    // non-absolute entry — those are not single binaries to inspect).
    for binary in binaries {
        if binary.contains('*') || !binary.starts_with('/') {
            continue;
        }
        queue.push(PathBuf::from(binary));
    }
    // Seed the libc-dlopen'd modules, but only if anything actually runs.
    if !queue.is_empty() {
        for soname in DLOPEN_SEED {
            if let Some(path) = resolve_soname(soname, &dirs) {
                if closure.insert(path.clone()) {
                    queue.push(path);
                }
            }
        }
    }

    while let Some(path) = queue.pop() {
        let Some((interp, needed)) = inspect(&path) else {
            continue;
        };
        if let Some(interp) = interp {
            closure.insert(interp);
        }
        for soname in needed {
            if !seen_soname.insert(soname.clone()) {
                continue;
            }
            match resolve_soname(&soname, &dirs) {
                Some(lib) => {
                    if closure.insert(lib.clone()) {
                        queue.push(lib); // recurse into this library's own DT_NEEDED
                    }
                }
                None => warnings.push(format!(
                    "library `{soname}` (linked by an allowlisted binary) was not found in the \
                     standard search dirs; a binary that needs it may fail to load"
                )),
            }
        }
    }

    // Filter the closure by the allow/deny globs.
    let mut libraries: Vec<String> = Vec::new();
    for path in closure {
        let shown = path.to_string_lossy();
        if deny.iter().any(|g| glob_match(g, &shown)) {
            warnings.push(format!(
                "library `{shown}` is linked by an allowlisted binary but matches a `[lib].deny` \
                 pattern — NOT granted; a binary that needs it will fail to load"
            ));
            continue;
        }
        if allow.iter().any(|g| glob_match(g, &shown)) {
            libraries.push(shown.into_owned());
        } else {
            warnings.push(format!(
                "library `{shown}` is linked by an allowlisted binary but falls outside every \
                 `[lib].allow` pattern — NOT granted; widen `[lib].allow` if a binary needs it"
            ));
        }
    }
    libraries.sort();
    libraries.dedup();
    LibResolution {
        libraries,
        warnings,
    }
}

/// The standard `ld.so` search directories: the classic dirs plus every multiarch /
/// musl tuple dir found under `/lib` and `/usr/lib`. Resolution searches here; the
/// `[lib].allow` globs then decide what is granted.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/lib"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib64"),
    ];
    for base in ["/lib", "/usr/lib"] {
        let Ok(entries) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_tuple = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.ends_with("-linux-gnu")
                    || n.ends_with("-linux-gnueabihf")
                    || n.ends_with("-linux-musl")
            });
            if is_tuple && path.is_dir() {
                dirs.push(path);
            }
        }
    }
    dirs
}

/// Resolve a soname (or an absolute lib path) to an existing file in `dirs`.
fn resolve_soname(soname: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if soname.contains('/') {
        let path = PathBuf::from(soname);
        return path.exists().then_some(path);
    }
    dirs.iter()
        .map(|dir| dir.join(soname))
        .find(|candidate| candidate.exists())
}

/// Read a binary's `PT_INTERP` (via the `.interp` section) and its `DT_NEEDED`
/// sonames (parsed from the `.dynamic` table against `.dynstr`). Returns `None` if
/// the file is unreadable or not an object file. The binary is never executed.
///
/// Note: `Object::imports()` is deliberately **not** used — it returns versioned
/// *symbol* imports, which both miss transitive-only libraries (a lib a binary links
/// but imports no symbol from, e.g. `id` → libselinux → libpcre2) and yield empty
/// library names for unversioned symbols. `DT_NEEDED` is the actual link list.
fn inspect(path: &Path) -> Option<(Option<PathBuf>, Vec<String>)> {
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let interp = file
        .section_by_name(".interp")
        .and_then(|section| section.data().ok())
        .map(|bytes| {
            let nul_terminated = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
            PathBuf::from(String::from_utf8_lossy(nul_terminated).into_owned())
        })
        .filter(|p| !p.as_os_str().is_empty());
    let needed = needed_sonames(&file).unwrap_or_default();
    Some((interp, needed))
}

/// Parse `DT_NEEDED` sonames from the `.dynamic` table, resolving each entry's
/// `d_val` string-table offset against `.dynstr`. Handles 32/64-bit and endianness
/// from the ELF header. `DT_NEEDED` has tag value `1`.
fn needed_sonames(file: &object::File<'_>) -> Option<Vec<String>> {
    const DT_NEEDED: u64 = 1;
    let dynamic = file.section_by_name(".dynamic")?.data().ok()?;
    let dynstr = file.section_by_name(".dynstr")?.data().ok()?;
    let little = file.endianness() == object::Endianness::Little;
    let entry = if file.is_64() { 16 } else { 8 };
    let mut out = Vec::new();
    for chunk in dynamic.chunks_exact(entry) {
        let half = entry / 2;
        let (Some(tag), Some(val)) = (
            read_uint(chunk.get(..half), little),
            read_uint(chunk.get(half..), little),
        ) else {
            continue;
        };
        if tag != DT_NEEDED {
            continue;
        }
        if let Some(name) = cstr_at(dynstr, usize::try_from(val).unwrap_or(usize::MAX)) {
            if !name.is_empty() {
                out.push(name);
            }
        }
    }
    Some(out)
}

/// Read a little/big-endian unsigned integer from 4 or 8 bytes (the `.dynamic`
/// entry half-width). Returns `None` on a short slice.
fn read_uint(bytes: Option<&[u8]>, little: bool) -> Option<u64> {
    match bytes {
        Some(b) if b.len() == 8 => {
            let a = <[u8; 8]>::try_from(b).ok()?;
            Some(if little {
                u64::from_le_bytes(a)
            } else {
                u64::from_be_bytes(a)
            })
        }
        Some(b) if b.len() == 4 => {
            let a = <[u8; 4]>::try_from(b).ok()?;
            Some(u64::from(if little {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }))
        }
        _ => None,
    }
}

/// The NUL-terminated string at byte `offset` in a string table.
fn cstr_at(table: &[u8], offset: usize) -> Option<String> {
    let rest = table.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    rest.get(..end)
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

/// Match an absolute path against a `[lib]` glob.
///
/// `*` matches within one path component; `**` matches any number of components.
/// Supports a single `*` per component (prefix`*`suffix), which covers the patterns
/// templates use (`/lib/*-linux-gnu/**`, `/usr/lib/pam*/**`).
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let text: Vec<&str> = path.split('/').collect();
    seg_match(&pat, &text)
}

/// Segment-wise glob match; `**` consumes zero or more whole segments.
fn seg_match(pat: &[&str], text: &[&str]) -> bool {
    match pat.split_first() {
        None => text.is_empty(),
        Some((&"**", rest)) => {
            // `**` matches the rest here, or consumes one more segment and retries.
            if seg_match(rest, text) {
                return true;
            }
            match text.split_first() {
                Some((_, tail)) => seg_match(pat, tail),
                None => false,
            }
        }
        Some((seg, rest)) => match text.split_first() {
            Some((head, tail)) => comp_match(seg, head) && seg_match(rest, tail),
            None => false,
        },
    }
}

/// Match one path component against a single-`*` glob (`prefix*suffix`).
fn comp_match(pat: &str, text: &str) -> bool {
    match pat.split_once('*') {
        None => pat == text,
        Some((prefix, suffix)) => {
            text.len() >= prefix.len().saturating_add(suffix.len())
                && text.starts_with(prefix)
                && text.ends_with(suffix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_components_and_double_star() {
        assert!(glob_match(
            "/lib/*-linux-gnu/**",
            "/lib/x86_64-linux-gnu/libc.so.6"
        ));
        assert!(glob_match("/usr/lib/pam*/**", "/usr/lib/pam.d/foo"));
        assert!(glob_match("/lib64/**", "/lib64/ld-linux-x86-64.so.2"));
        assert!(!glob_match("/lib/*-linux-gnu/**", "/usr/lib/evil.so"));
        assert!(!glob_match("/usr/lib/pam*/**", "/usr/lib/libc.so.6"));
        // `**` matches zero segments too.
        assert!(glob_match("/usr/lib/**", "/usr/lib"));
    }

    #[test]
    fn a_planted_library_is_not_in_an_empty_closure() {
        // No binaries ⇒ empty closure ⇒ nothing granted, whatever allow says.
        let r = resolve_libraries(&[], &["/usr/lib/**".to_owned()], &[]);
        assert!(r.libraries.is_empty());
    }

    #[test]
    fn wildcard_and_relative_binaries_are_skipped_as_seeds() {
        // `**` (permissive-exec) and bare names are not single binaries to inspect.
        let r = resolve_libraries(
            &["**".to_owned(), "bash".to_owned()],
            &[
                "/lib/**".to_owned(),
                "/usr/lib/**".to_owned(),
                "/lib64/**".to_owned(),
            ],
            &[],
        );
        // Nothing concrete to seed ⇒ no closure (the DLOPEN seed only fires with a
        // concrete binary present).
        assert!(r.libraries.is_empty());
    }
}
