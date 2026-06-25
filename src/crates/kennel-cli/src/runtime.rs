//! Runtime verbs that talk to the daemon: `stop`, `list`, `daemon-reload`.
//!
//! These are the verbs that belong to `kennel-run` alongside `run`, `attach`,
//! `review`, and `release`.

use std::process::ExitCode;

use kennel_lib_control::control::{self, Request, Response};

use crate::{connect, send};

/// `kennel stop <name>`
pub fn stop(args: &[String]) -> Result<ExitCode, String> {
    let [name] = args else {
        return Err("usage: kennel stop <name>".to_owned());
    };
    let mut conn = connect()?;
    send(
        &conn,
        &Request::Stop {
            kennel: name.clone(),
        },
        &[],
    )?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Stopped => {
            eprintln!("kennel `{name}` stopped");
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `kennel list`
pub fn list() -> Result<ExitCode, String> {
    let mut conn = connect()?;
    send(&conn, &Request::List, &[])?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Listing(kennels) => {
            if kennels.is_empty() {
                println!("no running kennels");
            } else {
                print_topology(&kennels);
            }
        }
        Response::Error(message) => return Err(message),
        other => return Err(format!("unexpected response: {other:?}")),
    }
    let mut conn = connect()?;
    send(&conn, &Request::Mesh, &[])?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Mesh(providers) => {
            if !providers.is_empty() {
                println!();
                print_mesh(&providers);
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `kennel daemon-reload`
pub fn daemon_reload() -> Result<ExitCode, String> {
    let mut conn = connect()?;
    send(&conn, &Request::DaemonReload, &[])?;
    match control::recv_response(&mut conn).map_err(|e| format!("daemon: {e}"))? {
        Response::Reloaded { catalogued } => {
            let plural = if catalogued == 1 { "y" } else { "ies" };
            println!("reloaded: {catalogued} catalogued capabilit{plural}");
            Ok(ExitCode::SUCCESS)
        }
        Response::Error(message) => Err(message),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

// ─── Topology rendering ─────────────────────────────────────────────────────

fn print_mesh(providers: &[control::MeshProvider]) {
    let mut rows: Vec<&control::MeshProvider> = providers.iter().collect();
    rows.sort_by(|a, b| {
        a.capability
            .cmp(&b.capability)
            .then_with(|| a.provider.cmp(&b.provider))
    });
    println!(
        "{:<32} {:<16} {:<9} {:<11} {:<9} {:<5}",
        "CAPABILITY", "PROVIDER", "READINESS", "SHAPE", "ENABLE", "TIER"
    );
    for r in rows {
        println!(
            "{:<32} {:<16} {:<9} {:<11} {:<9} {:<5}",
            r.capability, r.provider, r.readiness, r.shape, r.enablement, r.tier
        );
    }
}

/// Parse a spawn topology name.
pub fn spawn_parent_ctx(name: &str) -> Option<u16> {
    name.strip_prefix("spawn-")?.split_once('-')?.0.parse().ok()
}

type Row<'a> = (&'a control::KennelInfo, &'static str, bool);

/// Order the running kennels as a what-spawned-what tree.
pub fn topology_rows(kennels: &[control::KennelInfo]) -> Vec<Row<'_>> {
    use std::collections::{BTreeMap, HashSet};
    let present: HashSet<u16> = kennels.iter().map(|k| k.ctx).collect();
    let mut children: BTreeMap<u16, Vec<&control::KennelInfo>> = BTreeMap::new();
    let mut roots: Vec<&control::KennelInfo> = Vec::new();
    for k in kennels {
        match spawn_parent_ctx(&k.kennel).filter(|p| present.contains(p)) {
            Some(parent) => children.entry(parent).or_default().push(k),
            None => roots.push(k),
        }
    }
    roots.sort_by_key(|k| k.ctx);
    for kids in children.values_mut() {
        kids.sort_by_key(|k| k.ctx);
    }
    let mut rows: Vec<Row<'_>> = Vec::with_capacity(kennels.len());
    for root in roots {
        let orphan = spawn_parent_ctx(&root.kennel).is_some();
        rows.push((root, "", orphan));
        if let Some(kids) = children.get(&root.ctx) {
            let last = kids.len().saturating_sub(1);
            for (i, kid) in kids.iter().enumerate() {
                rows.push((kid, if i == last { "└─ " } else { "├─ " }, false));
            }
        }
    }
    rows
}

fn print_topology(kennels: &[control::KennelInfo]) {
    println!(
        "{:<32} {:>5} {:>8}  {:<8} CLIENT",
        "NAME", "CTX", "PID", "STATE"
    );
    for (k, prefix, orphan) in topology_rows(kennels) {
        print_row(k, prefix, orphan);
    }
}

fn print_row(k: &control::KennelInfo, prefix: &str, orphan: bool) {
    let state = if k.running { "running" } else { "starting" };
    let client = if k.attached { "attached" } else { "detached" };
    let name = format!("{prefix}{}", k.kennel);
    let tail = if orphan { "  (orphan spawn)" } else { "" };
    println!(
        "{name:<32} {:>5} {:>8}  {state:<8} {client}{tail}",
        k.ctx, k.pid
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_parent_ctx_parses_the_topology_name() {
        assert_eq!(spawn_parent_ctx("spawn-5-0000000abcde"), Some(5));
        assert_eq!(spawn_parent_ctx("spawn-42-deadbeef0000"), Some(42));
        for top in [
            "my-agent",
            "echo-tool",
            "spawn",
            "spawnish",
            "spawn-",
            "spawn-x-1",
        ] {
            assert_eq!(
                spawn_parent_ctx(top),
                None,
                "`{top}` should have no parent ctx"
            );
        }
    }

    #[test]
    fn topology_nests_spawns_under_their_requester() {
        let ki = |name: &str, ctx: u16| control::KennelInfo {
            kennel: name.to_owned(),
            ctx,
            pid: 100 + u32::from(ctx),
            running: true,
            attached: false,
        };
        let kennels = vec![
            ki("spawn-7-00000000aaaa", 11),
            ki("agent", 7),
            ki("spawn-99-00000000bbbb", 20),
            ki("builder", 3),
        ];
        let shape: Vec<(&str, &str, bool)> = topology_rows(&kennels)
            .iter()
            .map(|(k, p, o)| (k.kennel.as_str(), *p, *o))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("builder", "", false),
                ("agent", "", false),
                ("spawn-7-00000000aaaa", "└─ ", false),
                ("spawn-99-00000000bbbb", "", true),
            ],
            "roots sorted by ctx, spawn nested under its parent, orphan flagged at root"
        );
    }
}
