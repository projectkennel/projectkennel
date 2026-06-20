//! `AT_SECURE`-equivalent environment filtering for the OCI launcher (§7.11.6).
//!
//! `execve` of the image entrypoint does not cross a privilege boundary: the workload already
//! runs as the persona uid, with no setuid bit, no file caps, and no subuid range, so the dynamic
//! loader does not set `AT_SECURE` and does not apply its own `unsecvars` strip. Loader- and
//! interpreter-control variables in the image's `config.json` `Env` would therefore be honored
//! verbatim, letting a waived substrate redirect its own (waived) closure into attacker-chosen
//! code — including into an additive `[fs.read/write]` bind.
//!
//! The launcher applies the strip itself, to the image `Env` only. Kennel's synthesized
//! environment (policy `[env]`, persona, the `PATH` floor) is layered on top afterwards and is
//! never filtered here: an operator who deliberately wants any stripped name re-adds it via
//! `[env].set`, which wins on merge. Aggressive but recoverable.
//!
//! This is orthogonal to policy `[env].deny`, which filters the caller→kennel pass-through. The
//! image `Env` is a separate, later input that no policy field reaches; this strip is its only gate.

// Deliberately NOT stripped: `PATH` is the image's floor that policy `[env]` overrides on merge
// (so it is shadowed when policy sets it, useful when it does not); `IFS` is reset by every modern
// shell at startup. Both are one-line additions to STRIP_EXACT if that judgement ever changes.

/// Drop any image variable whose name begins with one of these.
const STRIP_PREFIXES: &[&str] = &[
    "LD_",    // glibc + musl loader: PRELOAD, LIBRARY_PATH, AUDIT, PROFILE, ...
    "GLIBC_", // GLIBC_TUNABLES (malloc.*, cpu.*, elision tuning, ...)
];

/// Drop any image variable whose name matches exactly (case-sensitive — Linux environment names
/// are case-sensitive).
const STRIP_EXACT: &[&str] = &[
    // glibc unsecvars.h, the non-LD_ remainder
    "GCONV_PATH",
    "GETCONF_DIR",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_TRACE",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TMPDIR",
    "TZDIR",
    // language runtimes — the same injection class one layer up. OCI app images are
    // overwhelmingly interpreted runtimes, so these are not optional.
    "NODE_OPTIONS", // --require / --import an arbitrary module
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "RUBYLIB",
    "RUBYOPT",
    "CLASSPATH",         // JVM library search
    "JAVA_TOOL_OPTIONS", // honored on every JVM start
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS", // JDK 9+ `java` launcher, same -javaagent/-Xbootclasspath reach
    // shell entrypoints — a sourced startup file is code execution
    "BASH_ENV",  // bash, non-interactive: sources $BASH_ENV before the script
    "ENV",       // POSIX sh: sources $ENV at startup
    "SHELLOPTS", // bash imports + enables these opts at startup (xtrace, allexport, ...)
    "BASHOPTS",  // ditto for shopt-managed options
];

/// True if `name` is loader/interpreter-control and must not come from the image.
fn is_stripped(name: &str) -> bool {
    STRIP_PREFIXES.iter().any(|p| name.starts_with(p)) || STRIP_EXACT.contains(&name)
}

/// The name half of an OCI `Env` entry (`KEY=VALUE`). An entry without `=` is malformed per the
/// OCI image-config spec; treat the whole token as the name so a bare stripped name is still dropped.
fn env_name(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(k, _)| k)
}

/// Filter the image's `Env`, dropping the loader/interpreter-injection family. Order preserved;
/// this is the floor that [`merge_env`] layers policy over.
#[must_use]
pub fn strip_image_env(image_env: &[String]) -> Vec<String> {
    image_env
        .iter()
        .filter(|e| !is_stripped(env_name(e)))
        .cloned()
        .collect()
}

/// Build the final environment. Image `Env` (stripped) is the floor; Kennel's synthesized env is
/// policy-authoritative and wins on every name collision. Result is name-sorted, so the workload's
/// environment is deterministic for a given (policy, image) pair.
#[must_use]
pub fn merge_env(
    kennel_env: &[(String, String)], // policy [env], persona, PATH floor — authoritative
    image_env: &[String],            // config.json Env — waived substrate
) -> Vec<(String, String)> {
    use std::collections::BTreeMap;

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for entry in strip_image_env(image_env) {
        if let Some((k, v)) = entry.split_once('=') {
            out.insert(k.to_owned(), v.to_owned());
        }
    }
    for (k, v) in kennel_env {
        out.insert(k.clone(), v.clone());
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{merge_env, strip_image_env};

    #[test]
    fn image_loader_and_interpreter_vars_are_stripped() {
        let img = vec![
            "LD_PRELOAD=/evil.so".to_owned(),
            "LD_LIBRARY_PATH=/img/lib".to_owned(),
            "GLIBC_TUNABLES=glibc.malloc.check=0".to_owned(),
            "NODE_OPTIONS=--require /evil.js".to_owned(),
            "BASH_ENV=/evil.sh".to_owned(),
            "PATH=/img/bin".to_owned(), // floor, NOT stripped
            "APP_MODE=prod".to_owned(), // ordinary app var, kept
        ];
        let kept = strip_image_env(&img);
        assert!(kept.iter().all(|e| !e.starts_with("LD_")));
        assert!(kept.iter().all(|e| !e.starts_with("GLIBC_")));
        assert!(!kept.iter().any(|e| e.starts_with("NODE_OPTIONS=")));
        assert!(!kept.iter().any(|e| e.starts_with("BASH_ENV=")));
        assert!(kept.iter().any(|e| e == "PATH=/img/bin"));
        assert!(kept.iter().any(|e| e == "APP_MODE=prod"));
    }

    #[test]
    fn ld_prefix_does_not_overmatch_ldflags() {
        // `LDFLAGS` starts with `LD` but not the `LD_` prefix — must be kept.
        let kept = strip_image_env(&["LDFLAGS=-O2".to_owned()]);
        assert_eq!(kept, vec!["LDFLAGS=-O2".to_owned()]);
    }

    #[test]
    fn policy_env_overrides_floor_and_can_readd_loader_vars() {
        let img = vec!["PATH=/img/bin".to_owned(), "LD_PRELOAD=/evil.so".to_owned()];
        let policy = vec![
            ("PATH".to_owned(), "/usr/local/bin:/usr/bin".to_owned()),
            // operator's deliberate choice — survives, because the strip is image-only and policy
            // is layered on top unfiltered.
            ("LD_LIBRARY_PATH".to_owned(), "/opt/app/lib".to_owned()),
        ];
        let merged = merge_env(&policy, &img);
        let get = |k: &str| merged.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("PATH"), Some("/usr/local/bin:/usr/bin")); // policy wins
        assert_eq!(get("LD_LIBRARY_PATH"), Some("/opt/app/lib")); // re-add survives
        assert_eq!(get("LD_PRELOAD"), None); // image's injection is gone
    }

    #[test]
    fn malformed_bare_name_is_still_stripped() {
        let kept = strip_image_env(&["LD_PRELOAD".to_owned(), "FOO".to_owned()]);
        assert_eq!(kept, vec!["FOO".to_owned()]);
    }
}
