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

use kennel_audit::build::{writer as build_writer, SinkConfig};
use kennel_audit::{Levels, SinkKind, Writer, WriterContext};
use kennel_netproxy::config::{self, ProxyConfig};
use kennel_netproxy::dns::SystemResolver;
use kennel_netproxy::server::Proxy;

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
    proxy.serve_all(listeners)?;
    Ok(())
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
        retain_count: None,
        syslog_facility: None,
    };
    build_writer(ctx, Levels::default(), &sinks)
}
