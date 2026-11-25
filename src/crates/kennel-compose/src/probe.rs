// SPDX-License-Identifier: Apache-2.0

// Workload probe — classify a binary or script and seed exec.allow + fs.read.
//
// The common case is a SCRIPT (`#!/bin/sh`, `#!/usr/bin/python3`,
// `#!/usr/bin/env python3`), not a raw ELF. The probe handles both.
//
// Resolution contexts (the key design distinction):
//   CLI `<binary>` argument  → resolved against CWD + PATH (operator intent)
//   #!/usr/bin/env <prog>    → resolved against PATH (same host, same PATH)
//
// The probe does NOT walk DT_NEEDED: Landlock FS_EXECUTE gates only execve(),
// not mmap(), so shared libraries need only fs.read — which base-confined already
// grants on /usr/**, /lib/**, /lib64/**. We reuse resolve_loaders() from
// kennel-lib-policy::libresolve for the PT_INTERP extraction.
//
// The probe does NOT hardcode the template's fs.read floor. Whether a path is
// covered by the base template is the compiler's problem — build_settled() will
// tell us. The probe just reports what it found.

use std::path::{Path, PathBuf};

use kennel_lib_policy::libresolve;

/// The result of probing a binary/script.
#[derive(Debug)]
pub struct ProbeResult {
    /// Absolute path to the probed workload (after CLI argument resolution).
    pub workload: String,
    /// `exec.allow` entries: the workload + interpreter chain + loaders.
    pub exec_allow: Vec<String>,
    /// Additional `fs.read` grants needed (paths the probe discovered are
    /// outside the usual system dirs).
    pub extra_fs_read: Vec<FsGrant>,
    /// Whether the workload is a script (changes comment style in output).
    pub is_script: bool,
    /// Warnings/advisories for the operator.
    pub warnings: Vec<String>,
}

/// An extra `[[fs.read.add]]` grant the probe determined is needed.
#[derive(Debug)]
pub struct FsGrant {
    pub path: String,
    pub reason: String,
}

/// Standard system directories — paths under these are typically already
/// covered by any confined template. We only emit extra fs.read grants for
/// paths OUTSIDE these prefixes. This is an advisory heuristic; the real
/// authority is the compiled template.
const SYSTEM_PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/"];

/// Why a workload could not be probed.
#[derive(Debug)]
pub enum ProbeError {
    /// The workload could not be resolved or read.
    Path(PathBuf, std::io::Error),
    /// A script whose `#!` line names no interpreter, or a relative one.
    Shebang,
    /// A `#!/usr/bin/env` line with no program after it.
    EnvWithoutProgram,
    /// Neither an ELF binary nor a `#!` script.
    NotExecutable(PathBuf),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Shebang => f.write_str("script has an empty or relative shebang — cannot probe"),
            Self::EnvWithoutProgram => f.write_str("#!/usr/bin/env with no program name"),
            Self::NotExecutable(path) => write!(
                f,
                "{}: not an ELF binary or a #! script — is it chmod +x?",
                path.display()
            ),
        }
    }
}

/// Probe a workload (binary or script) and produce the `exec.allow` seed.
///
/// # Errors
/// The [`ProbeError`] if the workload cannot be read or is not something that can be executed.
pub fn probe(workload: &Path) -> Result<ProbeResult, ProbeError> {
    let abs =
        std::fs::canonicalize(workload).map_err(|e| ProbeError::Path(workload.to_path_buf(), e))?;
    let abs_str = abs.to_string_lossy().into_owned();

    let data = std::fs::read(&abs).map_err(|e| ProbeError::Path(abs.clone(), e))?;

    let mut exec_allow: Vec<String> = Vec::new();
    let mut extra_fs_read: Vec<FsGrant> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut is_script = false;

    if let Some(rest) = data.strip_prefix(b"#!") {
        // --- Script ---
        is_script = true;
        let line = rest.split(|&b| b == b'\n').next().unwrap_or(rest);
        let text = String::from_utf8_lossy(line);
        let tokens: Vec<&str> = text.split_whitespace().collect();

        if tokens.is_empty() || !tokens[0].starts_with('/') {
            return Err(ProbeError::Shebang);
        }

        let shebang_binary = tokens[0];

        if shebang_binary == "/usr/bin/env" {
            // #!/usr/bin/env <prog> [flags...]
            // Strip -S and other flags to find the program name.
            let prog = tokens
                .iter()
                .skip(1)
                .find(|t| !t.starts_with('-'))
                .ok_or(ProbeError::EnvWithoutProgram)?;

            exec_allow.push("/usr/bin/env".to_owned());

            // Resolve <prog> via PATH.
            match resolve_via_path(prog) {
                Some(resolved) => {
                    let resolved_str = resolved.to_string_lossy().into_owned();
                    note_if_non_system(
                        &resolved_str,
                        &mut extra_fs_read,
                        &format!("{prog} interpreter (resolved from #!/usr/bin/env {prog})"),
                    );
                    exec_allow.push(resolved_str);
                }
                None => {
                    warnings.push(format!(
                        "#!/usr/bin/env {prog}: could not resolve `{prog}` on $PATH; \
                         add the absolute path to exec.allow manually"
                    ));
                }
            }
        } else {
            // #!/usr/bin/python3, #!/bin/sh, etc.
            exec_allow.push(shebang_binary.to_owned());
            // The shebang is text from the script being probed, not a path the operator chose.
            // An interpreter outside the system directories gets a read grant on that one file
            // only: granting its parent directory would let a script's first line decide that
            // `/home/<user>/**` (or any other directory) is readable in the generated policy.
            if !SYSTEM_PREFIXES
                .iter()
                .any(|pfx| shebang_binary.starts_with(pfx))
            {
                extra_fs_read.push(FsGrant {
                    path: shebang_binary.to_owned(),
                    reason: format!(
                        "shebang interpreter {shebang_binary} (named by the script itself) — \
                         review it; its libraries are not granted"
                    ),
                });
                warnings.push(format!(
                    "the script's shebang names `{shebang_binary}`, outside the system \
                     directories; only that file is granted — add what it needs by hand"
                ));
            }
        }
    } else if data.starts_with(b"\x7fELF") {
        // --- ELF binary ---
        // Use resolve_loaders to extract the PT_INTERP (dynamic loader).
        let resolution = libresolve::resolve_loaders(std::slice::from_ref(&abs_str));
        for loader in &resolution.loaders {
            exec_allow.push(loader.clone());
        }
        warnings.extend(resolution.warnings);
    } else {
        return Err(ProbeError::NotExecutable(abs));
    }

    // The workload itself goes on exec.allow.
    exec_allow.push(abs_str.clone());
    note_if_non_system(&abs_str, &mut extra_fs_read, "probed workload");

    // Deduplicate exec_allow preserving order.
    let mut seen = std::collections::HashSet::new();
    exec_allow.retain(|e| seen.insert(e.clone()));

    Ok(ProbeResult {
        workload: abs_str,
        exec_allow,
        extra_fs_read,
        is_script,
        warnings,
    })
}

/// Resolve a bare program name via `$PATH`.
fn resolve_via_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate).ok();
        }
    }
    None
}

/// If a path is outside the standard system directories, note it as an extra
/// fs.read that the operator should review. This is advisory — the real
/// authority is the compiled effective policy from the template chain.
fn note_if_non_system(path: &str, extra_fs_read: &mut Vec<FsGrant>, reason_context: &str) {
    if SYSTEM_PREFIXES.iter().any(|pfx| path.starts_with(pfx)) {
        return;
    }

    if let Some(parent) = Path::new(path).parent() {
        let glob = format!("{}/**", parent.to_string_lossy());
        if !extra_fs_read.iter().any(|g| g.path == glob) {
            extra_fs_read.push(FsGrant {
                path: glob,
                reason: format!(
                    "{reason_context} — review whether this path is correct for the kennel"
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn probes_a_real_elf_binary() {
        let Ok(sh) = std::fs::canonicalize("/bin/sh") else {
            return;
        };
        let result = probe(&sh).expect("probe /bin/sh");
        assert!(!result.is_script, "/bin/sh is an ELF, not a script");
        assert!(
            result
                .exec_allow
                .contains(&sh.to_string_lossy().into_owned()),
            "exec_allow includes the binary"
        );
        assert!(
            result.exec_allow.iter().any(|e| e.contains("ld-")),
            "exec_allow includes the dynamic loader: {:?}",
            result.exec_allow
        );
    }

    #[test]
    fn probes_a_direct_interpreter_script() {
        let dir = std::env::temp_dir();
        let script = dir.join(format!("kennel-compose-test-direct-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&script).expect("create script");
            f.write_all(b"#!/bin/sh\necho hello\n").expect("write");
        }
        let result = probe(&script).expect("probe script");
        assert!(result.is_script);
        assert!(
            result
                .exec_allow
                .iter()
                .any(|e| e == "/bin/sh" || e.ends_with("/dash") || e.ends_with("/bash")),
            "exec_allow includes the interpreter: {:?}",
            result.exec_allow
        );
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn probes_an_env_shebang_script() {
        let dir = std::env::temp_dir();
        let script = dir.join(format!("kennel-compose-test-env-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&script).expect("create script");
            f.write_all(b"#!/usr/bin/env sh\necho hello\n")
                .expect("write");
        }
        let result = probe(&script).expect("probe env script");
        assert!(result.is_script);
        assert!(
            result.exec_allow.contains(&"/usr/bin/env".to_owned()),
            "exec_allow includes /usr/bin/env: {:?}",
            result.exec_allow
        );
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn a_shebang_outside_the_system_dirs_grants_one_file_not_its_directory() {
        let dir = std::env::temp_dir().join(format!("kennel-probe-shebang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let script = dir.join("run");
        std::fs::write(&script, b"#!/home/someone/tool --flag\necho hi\n").expect("write");
        let probed = probe(&script).expect("probe");
        assert!(probed
            .extra_fs_read
            .iter()
            .any(|g| g.path == "/home/someone/tool"));
        assert!(
            !probed
                .extra_fs_read
                .iter()
                .any(|g| g.path == "/home/someone/**"),
            "the script's first line must not grant a directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_system_path_notes_extra_fs_read() {
        let mut extra = Vec::new();
        note_if_non_system("/usr/bin/python3", &mut extra, "test");
        assert!(
            extra.is_empty(),
            "system path should not produce extra grants"
        );

        note_if_non_system("/home/user/.venv/bin/python3", &mut extra, "test");
        assert!(
            extra.iter().any(|g| g.path == "/home/user/.venv/bin/**"),
            "non-system path should produce extra grants: {:?}",
            extra.iter().map(|g| &g.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn not_executable_gives_a_friendly_error() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("kennel-compose-test-plain-{}", std::process::id()));
        std::fs::write(&file, b"just some text\n").expect("write");
        let err = probe(&file).unwrap_err();
        assert!(matches!(&err, ProbeError::NotExecutable(_)), "error: {err}");
        assert!(err.to_string().contains("not an ELF binary or a #! script"));
        let _ = std::fs::remove_file(&file);
    }
}
