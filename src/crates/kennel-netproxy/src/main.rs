//! `kennel-netproxy`: a per-kennel SOCKS5 / HTTP egress proxy.
//!
//! Reads a TOML config (the path is the sole argument), binds the listen socket,
//! and serves the egress proxy. `kenneld` writes the config from the resolved
//! policy and launches this binary as a per-kennel child; it also runs as a
//! standalone egress filter given a hand-written config.
//!
//! The binary is deliberately thin: all logic is in the library
//! (`kennel_netproxy::{config, server, ...}`), which is unit- and
//! integration-tested. `main` only wires the config to the server and maps
//! errors to an exit code.

use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use kennel_audit::build::{writer as build_writer, SinkConfig};
use kennel_audit::{Levels, SinkKind, Writer, WriterContext};
use kennel_netproxy::config::{self, ProxyConfig};
use kennel_netproxy::dns::SystemResolver;
use kennel_netproxy::server::Proxy;

/// How often the reloader thread re-stats the config file for a live reload.
const RELOAD_POLL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: kennel-netproxy <config.toml>");
        return ExitCode::from(2);
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kennel-netproxy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Load the config, open the audit sink, bind, and serve. Returns only on a
/// fatal error (a successful `serve` runs until the listener fails).
fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::load(path)?;
    let writer = Arc::new(build_audit_writer(&cfg));
    // One listener per configured address (a dual-stack kennel has a v4 and a v6
    // loopback address; one TcpListener binds a single family).
    let listeners = cfg
        .listen
        .iter()
        .map(TcpListener::bind)
        .collect::<io::Result<Vec<_>>>()?;
    let proxy = Arc::new(
        Proxy::new(
            cfg.ruleset,
            SystemResolver,
            cfg.accept_private_resolved,
            writer,
        )
        .with_host_services(cfg.host_services),
    );
    // Live-reload (§02-4): watch the config file and swap the ruleset/host-services
    // in place when `kenneld` rewrites it, without restarting or dropping connections.
    spawn_reloader(Arc::clone(&proxy), path.to_path_buf());
    proxy.serve_all(listeners)?;
    Ok(())
}

/// The config file's last-modified time, or `None` if it cannot be stated.
fn config_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Spawn a background thread that re-reads `path` whenever its mtime changes and
/// live-reloads the proxy's ruleset/host-services/resolved-address opinion (§02-4).
///
/// A reload that fails to parse is logged and ignored — the running policy is kept,
/// never silently widened. Listen addresses and audit sinks are *not* hot-reloaded
/// (those still require a respawn), so this only swaps the egress decision inputs.
fn spawn_reloader(proxy: Arc<Proxy<SystemResolver>>, path: PathBuf) {
    std::thread::spawn(move || {
        let mut seen = config_mtime(&path);
        loop {
            std::thread::sleep(RELOAD_POLL);
            let now = config_mtime(&path);
            if now == seen {
                continue;
            }
            seen = now;
            match config::load(&path) {
                Ok(cfg) => {
                    proxy.reload(cfg.ruleset, cfg.accept_private_resolved, cfg.host_services);
                    eprintln!(
                        "kennel-netproxy: reloaded egress policy from {}",
                        path.display()
                    );
                }
                Err(e) => {
                    eprintln!("kennel-netproxy: config reload failed, keeping current policy: {e}");
                }
            }
        }
    });
}

/// Build the unified audit writer. With an `[audit]` block (the `kenneld`-written
/// config), it uses the policy's sinks, levels, and shared `kennel_uuid`. Without
/// one (a standalone proxy), it falls back to a file sink at `audit_log`'s parent
/// directory, or stdout — emitting `network.jsonl` either way.
fn build_audit_writer(cfg: &ProxyConfig) -> Writer {
    if let Some(a) = &cfg.audit {
        let ctx = WriterContext {
            kennel: a.kennel.clone(),
            kennel_uuid: a.kennel_uuid.clone(),
            host: kennel_audit::hostname(),
        };
        let mut levels = Levels::default();
        if let Some(level) = a.network_level {
            levels.net = level;
        }
        let sinks = SinkConfig {
            kinds: a.sinks.clone(),
            dir: a.dir.clone(),
            rotate_at_bytes: a.rotate_at_bytes,
            compress_after_seconds: a.compress_after_seconds,
            retain_count: a.retain_count,
            syslog_facility: a.syslog_facility.clone(),
        };
        return build_writer(ctx, levels, &sinks);
    }
    // Standalone: a deterministic placeholder identity, a file sink in the
    // audit_log's parent dir (or stdout when unset).
    let ctx = WriterContext {
        kennel: "netproxy".to_owned(),
        kennel_uuid: kennel_audit::format_uuid_v7(0, [0; 10]),
        host: kennel_audit::hostname(),
    };
    let (kinds, dir) = cfg.audit_log.as_ref().map_or_else(
        || (vec![SinkKind::Stdout], PathBuf::from(".")),
        |path| {
            (
                vec![SinkKind::File],
                path.parent()
                    .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
            )
        },
    );
    let sinks = SinkConfig {
        kinds,
        dir,
        rotate_at_bytes: None,
        compress_after_seconds: None,
        retain_count: None,
        syslog_facility: None,
    };
    build_writer(ctx, Levels::default(), &sinks)
}
