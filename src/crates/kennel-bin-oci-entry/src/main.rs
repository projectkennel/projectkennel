// SPDX-License-Identifier: Apache-2.0

//! `kennel-bin-oci-entry` — the OCI launcher (§7.11.5, arch `02-9-oci.md`).
//!
//! Workload-side `argv[0]` for an image-root kennel. It runs post-`pivot_root` at the workload's
//! authority (no capability, no `mount`, no `unshare`), so it is **not** in the daemon TCB. It
//! reads the image's runtime config, sanitises and merges its `Env` ([`env_strip`]), applies
//! `WorkingDir`, and `execve`s the image entrypoint — which, post-pivot, resolves within the image
//! root the daemon already established, with the old root detached.
//!
//! `User` from the image config is intentionally **not** applied: the userns maps the precise
//! operator identity with no subuid range, so there is no uid to `setuid` into (T3.8 residual C).

#![forbid(unsafe_code)]

mod env_strip;

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

/// Where kenneld binds the image's runtime config read-only. Overridable by `argv[1]` (tests, and
/// a daemon that prefers to pass it explicitly).
const DEFAULT_CONFIG_PATH: &str = "/run/kennel/oci-config.json";

/// The OCI image-config blob (`config.json`): only the runtime `config` object is read.
#[derive(Debug, Deserialize, Default)]
struct ImageConfigBlob {
    #[serde(default)]
    config: ImageConfig,
}

/// The runtime config fields the launcher applies (OCI image-spec `Config`). `User` is omitted on
/// purpose — it is not honored (see the module docs).
#[derive(Debug, Deserialize, Default)]
struct ImageConfig {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default)]
    cmd: Vec<String>,
    #[serde(rename = "WorkingDir", default)]
    working_dir: String,
}

fn main() -> ExitCode {
    match run() {
        // A successful `exec` never returns, so `run` only returns on error.
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kennel-bin-oci-entry: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Why the image's command was not run.
#[derive(Debug)]
enum EntryError {
    /// The image config could not be read.
    Read(PathBuf, std::io::Error),
    /// The image config is not the JSON this launcher expects.
    Parse(PathBuf, serde_json::Error),
    /// The image config names no command and none was given.
    NoCommand,
    /// The command could not be executed.
    Exec(String, std::io::Error),
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(path, e) => write!(f, "reading {}: {e}", path.display()),
            Self::Parse(path, e) => write!(f, "parsing {}: {e}", path.display()),
            Self::NoCommand => f.write_str("image config has neither Entrypoint nor Cmd"),
            Self::Exec(prog, e) => write!(f, "execve {prog}: {e}"),
        }
    }
}

fn run() -> Result<(), EntryError> {
    // argv: [config-path] [-- override Cmd tokens...]. kenneld passes the config path as the
    // launcher's argv[1]; any `kennel oci run … -- <cmd>` tokens follow as a Cmd override.
    let mut cli = std::env::args().skip(1);
    let config_path = cli.next().unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_owned());
    let override_cmd: Vec<String> = cli.collect();
    let cfg = read_config(Path::new(&config_path))?.config;

    let argv = resolve_argv(&cfg.entrypoint, &cfg.cmd, &override_cmd);
    let Some((prog, rest)) = argv.split_first() else {
        return Err(EntryError::NoCommand);
    };

    // Env: image env (sanitised) is the floor; the launcher's own environ (Kennel-synthesised) is
    // layered on top, unfiltered, and wins — so policy `[env]` keeps the final say.
    let kennel_env: Vec<(String, String)> = std::env::vars().collect();
    let mut merged = env_strip::merge_env(&kennel_env, &cfg.env);

    // PATH is the exception to "policy wins": honor the IMAGE's PATH first (the substrate knows
    // where its binaries live — many images put them in /usr/local/bin, /usr/sbin, or /opt/.../bin
    // that the policy's `[exec].path` does not list), then the kennel-synthesised PATH as fallback.
    // A plain overwrite would drop the image's dirs, so a bare-name entrypoint outside the policy
    // path would fail to resolve. (The exec is still Landlock-gated; PATH only picks the dir.)
    let kennel_path = kennel_env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str());
    let image_path = cfg
        .env
        .iter()
        .filter_map(|e| e.split_once('='))
        .find(|(k, _)| *k == "PATH")
        .map(|(_, v)| v);
    if let Some(path) = env_strip::compose_path(image_path, kennel_path) {
        match merged.iter_mut().find(|(k, _)| k == "PATH") {
            Some(slot) => slot.1 = path,
            None => merged.push(("PATH".to_owned(), path)),
        }
    }

    let mut command = Command::new(prog);
    command.args(rest).env_clear().envs(merged);
    if !cfg.working_dir.is_empty() {
        command.current_dir(&cfg.working_dir);
    }
    // `exec` replaces this process image; it returns only on failure.
    Err(EntryError::Exec(prog.clone(), command.exec()))
}

fn read_config(path: &Path) -> Result<ImageConfigBlob, EntryError> {
    let bytes = std::fs::read(path).map_err(|e| EntryError::Read(path.to_path_buf(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| EntryError::Parse(path.to_path_buf(), e))
}

/// Resolve the final argv: `Entrypoint ++ Cmd` per OCI image-spec semantics, with a non-empty
/// CLI `override_cmd` replacing the image `Cmd` while keeping `Entrypoint` (the
/// `docker run <image> <cmd>` shape). An absent `Entrypoint` leaves `Cmd`/override as the whole argv.
fn resolve_argv(entrypoint: &[String], cmd: &[String], override_cmd: &[String]) -> Vec<String> {
    let effective_cmd = if override_cmd.is_empty() {
        cmd
    } else {
        override_cmd
    };
    entrypoint
        .iter()
        .chain(effective_cmd.iter())
        .cloned()
        .collect()
}

#[cfg(test)]
mod argv_tests {
    use super::resolve_argv;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn override_replaces_cmd_keeps_entrypoint() {
        // Entrypoint kept, image Cmd replaced by the override (docker run <img> <cmd>).
        let got = resolve_argv(
            &v(&["/entry"]),
            &v(&["default-arg"]),
            &v(&["custom", "--flag"]),
        );
        assert_eq!(got, v(&["/entry", "custom", "--flag"]));
    }

    #[test]
    fn no_override_uses_image_cmd() {
        let got = resolve_argv(&v(&["/entry"]), &v(&["default-arg"]), &[]);
        assert_eq!(got, v(&["/entry", "default-arg"]));
    }

    #[test]
    fn no_entrypoint_uses_cmd_or_override_alone() {
        assert_eq!(resolve_argv(&[], &v(&["sh"]), &[]), v(&["sh"]));
        assert_eq!(resolve_argv(&[], &v(&["sh"]), &v(&["bash"])), v(&["bash"]));
    }
}
