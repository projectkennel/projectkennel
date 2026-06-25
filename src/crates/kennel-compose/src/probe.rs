// Workload probe — classify a binary or script and seed exec.allow + fs.read.
//
// The common case is a SCRIPT (`#!/bin/sh`, `#!/usr/bin/python3`,
// `#!/usr/bin/env python3`), not a raw ELF. The probe handles both.
//
// Resolution contexts (the key design distinction):
//   CLI `<binary>` argument  → resolved against CWD + PATH (operator intent)
//   #!/usr/bin/env <prog>    → resolved against PATH (same host, same PATH)
//   BUT: non-standard paths  → emit fs.read.add + exec.path (carry consequences)
//
// The probe does NOT walk DT_NEEDED: Landlock FS_EXECUTE gates only execve(),
// not mmap(), so shared libraries need only fs.read — which base-confined already
// grants on /usr/**, /lib/**, /lib64/**. We reuse resolve_loaders() from
// kennel-lib-policy::libresolve for the PT_INTERP extraction.

use std::path::{Path, PathBuf};

use kennel_lib_policy::libresolve;

/// The result of probing a binary/script.
#[derive(Debug)]
pub struct ProbeResult {
    /// Absolute path to the probed workload (after CLI argument resolution).
    pub workload: String,
    /// `exec.allow` entries: the workload + interpreter chain + loaders.
    pub exec_allow: Vec<String>,
    /// Additional `exec.path` directories beyond base-confined's default.
    pub extra_exec_path: Vec<String>,
    /// Additional `fs.read` grants needed (paths outside the base floor).
    pub extra_fs_read: Vec<FsGrant>,
    /// Whether the workload is a script (changes comment style in output).
    pub is_script: bool,
    /// The interpreter for the comment header (e.g. "python3 script").
    pub interpreter_name: Option<String>,
    /// Warnings/advisories for the operator.
    pub warnings: Vec<String>,
}

/// An extra `[[fs.read.add]]` grant the probe determined is needed.
#[derive(Debug)]
pub struct FsGrant {
    pub path: String,
    pub reason: String,
}

/// The base-confined template's `fs.read` floor — paths covered by default.
/// If a resolved binary/interpreter falls outside these, we need an extra grant.
const BASE_FS_READ_PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64/", "/bin/", "/etc/", "/proc/", "/sys/"];

/// The base-confined template's `exec.path`.
const BASE_EXEC_PATH: &[&str] = &["/usr/bin", "/usr/local/bin", "/bin"];

/// Probe a workload (binary or script) and produce the `exec.allow` seed.
pub fn probe(workload: &Path) -> Result<ProbeResult, String> {
    let abs = std::fs::canonicalize(workload)
        .map_err(|e| format!("{}: {e}", workload.display()))?;
    let abs_str = abs.to_string_lossy().into_owned();

    let data = std::fs::read(&abs)
        .map_err(|e| format!("{}: {e}", abs.display()))?;

    let mut exec_allow: Vec<String> = Vec::new();
    let mut extra_exec_path: Vec<String> = Vec::new();
    let mut extra_fs_read: Vec<FsGrant> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut is_script = false;
    let mut interpreter_name: Option<String> = None;

    if let Some(rest) = data.strip_prefix(b"#!") {
        // --- Script ---
        is_script = true;
        let line = rest.split(|&b| b == b'\n').next().unwrap_or(rest);
        let text = String::from_utf8_lossy(line);
        let tokens: Vec<&str> = text.split_whitespace().collect();

        if tokens.is_empty() || !tokens[0].starts_with('/') {
            return Err("script has an empty or relative shebang — cannot probe".to_owned());
        }

        let shebang_binary = tokens[0];

        if shebang_binary == "/usr/bin/env" {
            // #!/usr/bin/env <prog> [flags...]
            // Strip -S and other flags to find the program name.
            let prog = tokens.iter().skip(1)
                .find(|t| !t.starts_with('-'))
                .ok_or("#!/usr/bin/env with no program name")?;

            interpreter_name = Some((*prog).to_owned());
            exec_allow.push("/usr/bin/env".to_owned());

            // Resolve <prog> via PATH.
            match resolve_via_path(prog) {
                Some(resolved) => {
                    let resolved_str = resolved.to_string_lossy().into_owned();
                    check_floor(&resolved_str, &mut extra_exec_path, &mut extra_fs_read,
                                &format!("{prog} interpreter (resolved from #!/usr/bin/env {prog})"));
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
            let basename = Path::new(shebang_binary)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned());
            interpreter_name = basename;
            exec_allow.push(shebang_binary.to_owned());
            check_floor(shebang_binary, &mut extra_exec_path, &mut extra_fs_read,
                        &format!("shebang interpreter {shebang_binary}"));
        }
    } else if data.starts_with(b"\x7fELF") {
        // --- ELF binary ---
        // Use resolve_loaders to extract the PT_INTERP (dynamic loader).
        let resolution = libresolve::resolve_loaders(&[abs_str.clone()]);
        for loader in &resolution.loaders {
            exec_allow.push(loader.clone());
        }
        warnings.extend(resolution.warnings);
    } else {
        return Err(format!(
            "{}: not an ELF binary or a #! script — is it chmod +x?",
            abs.display()
        ));
    }

    // The workload itself goes on exec.allow (scripts need execute on themselves
    // for the kernel's execve of the shebang path).
    exec_allow.push(abs_str.clone());
    check_floor(&abs_str, &mut extra_exec_path, &mut extra_fs_read,
                "probed workload");

    // Deduplicate exec_allow preserving order.
    let mut seen = std::collections::HashSet::new();
    exec_allow.retain(|e| seen.insert(e.clone()));

    Ok(ProbeResult {
        workload: abs_str,
        exec_allow,
        extra_exec_path,
        extra_fs_read,
        is_script,
        interpreter_name,
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

/// Check whether a resolved path falls outside base-confined's `fs.read` floor.
/// If so, add the containing directory to `extra_exec_path` and an `[[fs.read.add]]`
/// grant for the parent tree.
fn check_floor(
    path: &str,
    extra_exec_path: &mut Vec<String>,
    extra_fs_read: &mut Vec<FsGrant>,
    reason_context: &str,
) {
    if BASE_FS_READ_PREFIXES.iter().any(|pfx| path.starts_with(pfx)) {
        return; // covered by the base template
    }

    // Path is outside the base floor — the kennel needs explicit grants.
    if let Some(parent) = Path::new(path).parent() {
        let parent_str = parent.to_string_lossy().into_owned();

        // Add exec.path entry if not already covered.
        if !BASE_EXEC_PATH.iter().any(|p| *p == parent_str) {
            if !extra_exec_path.contains(&parent_str) {
                extra_exec_path.push(parent_str.clone());
            }
        }

        // Add fs.read grant for the parent tree.
        let glob = format!("{parent_str}/**");
        if !extra_fs_read.iter().any(|g| g.path == glob) {
            extra_fs_read.push(FsGrant {
                path: glob,
                reason: format!("{reason_context} (resolved from compose host — review whether this is correct for the kennel)"),
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
        // /bin/sh is present on every test host.
        let Ok(sh) = std::fs::canonicalize("/bin/sh") else {
            return; // skip if /bin/sh missing
        };
        let result = probe(&sh).expect("probe /bin/sh");
        assert!(!result.is_script, "/bin/sh is an ELF, not a script");
        assert!(result.interpreter_name.is_none());
        assert!(
            result.exec_allow.contains(&sh.to_string_lossy().into_owned()),
            "exec_allow includes the binary"
        );
        // Dynamic binary should have a loader.
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
        assert_eq!(result.interpreter_name.as_deref(), Some("sh"));
        assert!(
            result.exec_allow.iter().any(|e| e == "/bin/sh" || e.ends_with("/dash") || e.ends_with("/bash")),
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
            f.write_all(b"#!/usr/bin/env sh\necho hello\n").expect("write");
        }
        let result = probe(&script).expect("probe env script");
        assert!(result.is_script);
        assert_eq!(result.interpreter_name.as_deref(), Some("sh"));
        assert!(
            result.exec_allow.contains(&"/usr/bin/env".to_owned()),
            "exec_allow includes /usr/bin/env: {:?}",
            result.exec_allow
        );
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn floor_check_emits_grants_for_non_standard_paths() {
        let mut extra_exec_path = Vec::new();
        let mut extra_fs_read = Vec::new();

        // A path under /usr — covered, no extra grants.
        check_floor("/usr/bin/python3", &mut extra_exec_path, &mut extra_fs_read, "test");
        assert!(extra_exec_path.is_empty());
        assert!(extra_fs_read.is_empty());

        // A path under /home — NOT covered.
        check_floor("/home/user/.venv/bin/python3", &mut extra_exec_path, &mut extra_fs_read, "test");
        assert!(
            extra_exec_path.contains(&"/home/user/.venv/bin".to_owned()),
            "extra_exec_path: {:?}",
            extra_exec_path
        );
        assert!(
            extra_fs_read.iter().any(|g| g.path == "/home/user/.venv/bin/**"),
            "extra_fs_read: {:?}",
            extra_fs_read.iter().map(|g| &g.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn not_executable_gives_a_friendly_error() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("kennel-compose-test-plain-{}", std::process::id()));
        std::fs::write(&file, b"just some text\n").expect("write");
        let err = probe(&file).unwrap_err();
        assert!(err.contains("not an ELF") || err.contains("script"), "error: {err}");
        let _ = std::fs::remove_file(&file);
    }
}

