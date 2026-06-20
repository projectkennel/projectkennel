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
use std::path::Path;
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

fn run() -> Result<(), String> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_owned());
    let cfg = read_config(Path::new(&config_path))?.config;

    // argv = Entrypoint ++ Cmd (OCI semantics); Entrypoint-absent ⇒ Cmd alone.
    let argv: Vec<String> = cfg
        .entrypoint
        .iter()
        .chain(cfg.cmd.iter())
        .cloned()
        .collect();
    let Some((prog, rest)) = argv.split_first() else {
        return Err("image config has neither Entrypoint nor Cmd".to_owned());
    };

    // Env: image env (sanitised) is the floor; the launcher's own environ (Kennel-synthesised) is
    // layered on top, unfiltered, and wins — so policy `[env]` keeps the final say.
    let kennel_env: Vec<(String, String)> = std::env::vars().collect();
    let merged = env_strip::merge_env(&kennel_env, &cfg.env);

    let mut command = Command::new(prog);
    command.args(rest).env_clear().envs(merged);
    if !cfg.working_dir.is_empty() {
        command.current_dir(&cfg.working_dir);
    }
    // `exec` replaces this process image; it returns only on failure.
    Err(format!("execve {prog}: {}", command.exec()))
}

fn read_config(path: &Path) -> Result<ImageConfigBlob, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parsing {}: {e}", path.display()))
}
