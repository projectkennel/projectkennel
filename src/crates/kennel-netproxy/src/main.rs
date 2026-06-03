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

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use kennel_netproxy::config;
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
    // The audit sink: the configured JSON Lines file (append), else stderr.
    let audit: Box<dyn Write + Send> = match &cfg.audit_log {
        Some(p) => Box::new(OpenOptions::new().create(true).append(true).open(p)?),
        None => Box::new(io::stderr()),
    };
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
            audit,
        )
        .with_host_services(cfg.host_services),
    );
    proxy.serve_all(listeners)?;
    Ok(())
}
