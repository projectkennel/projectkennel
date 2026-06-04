//! The per-kennel egress proxy: deriving its config and launching it.
//!
//! Every outbound connection from a kennel terminates at a kennel-local
//! `kennel-netproxy` process (`docs/design/07-3-network.md` §7.3.2). The cgroup BPF
//! permits `connect()` to the proxy and nothing else; the proxy then enforces
//! the per-destination allowlist. **These are two different rule sets from the
//! one signed policy** — the BPF funnels, the proxy decides. This module owns the
//! proxy half: it writes the proxy's TOML config from the policy's [`NetPolicy`]
//! and launches the proxy as a per-kennel child.
//!
//! kenneld is the only writer of this config; the netproxy only ever reads it.
//! The config is a *derived* artefact inside kenneld's trust boundary (unsigned,
//! like the privhelper IPC) — only the settled policy it derives from is signed.
//!
//! To keep the writer from drifting from the netproxy's reader, the TOML is
//! produced with `serde`/`basic-toml` (not hand-assembled) and a unit test
//! round-trips it back through `kennel_netproxy::config`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use kennel_policy::{NameRule, NetMode, NetPolicy, NetRule, Protocol};
use serde::Serialize;

/// The unified-audit context kenneld hands the proxy (the config's `[audit]` block).
///
/// It lets the proxy's `net.egress` events reach the same sinks — and carry the
/// same `kennel_uuid` — as kenneld's own lifecycle events (`02-3`).
#[derive(Clone, Debug)]
pub struct ProxyAudit {
    /// The kennel name (envelope `kennel`).
    pub kennel: String,
    /// The shared per-instance `kennel_uuid`.
    pub kennel_uuid: String,
    /// The per-kennel state dir the file sink writes `network.jsonl` to.
    pub dir: PathBuf,
    /// The active sink tokens (`file`/`stdout`/`syslog`/`journald`).
    pub sinks: Vec<String>,
    /// The `net` audit level, if the policy set one.
    pub network_level: Option<String>,
    /// The syslog facility, if the policy set one.
    pub syslog_facility: Option<String>,
    /// The file-sink rotation threshold, if set.
    pub rotate_at_bytes: Option<u64>,
    /// The file-sink gzip-after-seconds delay, if set.
    pub compress_after_seconds: Option<u64>,
    /// The file-sink retained-rotation count, if set.
    pub retain_count: Option<u64>,
}

/// The proxy's TOML config shape — the on-disk schema the netproxy parses
/// (`kennel_netproxy::config`). Mirrored here, on the writer side, because the
/// netproxy is read-only by design. Field order matches TOML's requirement that
/// scalars precede sub-tables/arrays-of-tables.
#[derive(Serialize)]
struct ProxyToml {
    listen: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_log: Option<String>,
    accept_private_resolved: bool,
    net: NetToml,
    // A table, so declared after the scalars and `net`.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit: Option<AuditToml>,
}

/// The `[audit]` block (mirrors `kennel_netproxy::config`'s reader).
#[derive(Serialize)]
struct AuditToml {
    kennel: String,
    kennel_uuid: String,
    dir: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sinks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    syslog_facility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotate_at_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compress_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retain_count: Option<u64>,
}

#[derive(Serialize)]
struct NetToml {
    mode: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allow: Vec<AllowToml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<DenyToml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    host_services: Vec<HostServiceToml>,
}

/// A sanctioned host-loopback service (the SSH bastion, §7.8.4) the proxy may reach
/// despite the host-loopback invariant deny (`[[net.host_services]]`).
#[derive(Serialize)]
struct HostServiceToml {
    addr: String,
}

/// An allow entry carries exactly one of `name`/`cidr` (the netproxy enforces
/// that on read); we only ever set one.
#[derive(Serialize)]
struct AllowToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cidr: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
    protocol: &'static str,
}

#[derive(Serialize)]
struct DenyToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    cidr: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
}

/// The proxy's enforcement mode string for the netproxy config. The settled
/// schema has no `none` (a no-network kennel is expressed structurally, not as a
/// proxy mode), so only the two modes map.
const fn mode_str(mode: NetMode) -> &'static str {
    match mode {
        NetMode::Constrained => "constrained",
        NetMode::Open => "open",
    }
}

const fn proto_str(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Any => "any",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Translate a settled-policy port *range* into the netproxy's discrete `ports`
/// list: the full range is "any port" (empty); a single port is `[p]`; a genuine
/// sub-range is enumerated (the netproxy matches a port set, not a range).
fn ports_for(port_min: u16, port_max: u16) -> Vec<u16> {
    if port_min == 0 && port_max == u16::MAX {
        Vec::new()
    } else {
        (port_min..=port_max).collect()
    }
}

/// A CIDR rule's address as the netproxy's `addr/prefix` string.
fn cidr_str(rule: &NetRule) -> String {
    format!("{}/{}", rule.cidr, rule.prefix_len)
}

fn allow_from_cidr(rule: &NetRule) -> AllowToml {
    AllowToml {
        name: None,
        cidr: Some(cidr_str(rule)),
        ports: ports_for(rule.port_min, rule.port_max),
        protocol: proto_str(rule.protocol),
    }
}

fn allow_from_name(rule: &NameRule) -> AllowToml {
    AllowToml {
        name: Some(rule.name.clone()),
        cidr: None,
        ports: rule.ports.clone(),
        protocol: proto_str(rule.protocol),
    }
}

/// Build the proxy's TOML config from the policy's network section.
///
/// `listen` is the address(es) the proxy should bind — a dual-stack kennel passes
/// both its v4 and v6 loopback addresses; `audit` is the optional `[audit]`
/// block (the unified-audit context; `None` ⇒ the proxy logs egress to stdout).
///
/// The allowlist is the union of the policy's by-address (`net.allow`) and
/// by-name (`net.allow_names`) rules; the denylist is the invariant deny CIDRs,
/// which the proxy re-checks against every resolved address (the rebinding
/// defence). `accept_private_resolved` is left `false`.
///
/// # Errors
///
/// Returns the serialiser error string if the TOML cannot be produced (a shape
/// `basic-toml` rejects — caught by the round-trip test).
pub fn config_toml(
    net: &NetPolicy,
    listen: &[SocketAddr],
    audit: Option<&ProxyAudit>,
    host_services: &[SocketAddr],
) -> Result<String, String> {
    let mut allow: Vec<AllowToml> = net.allow.iter().map(allow_from_cidr).collect();
    allow.extend(net.allow_names.iter().map(allow_from_name));

    let deny: Vec<DenyToml> = net
        .deny_invariant
        .iter()
        .map(|r| DenyToml {
            cidr: Some(cidr_str(r)),
            ports: ports_for(r.port_min, r.port_max),
        })
        .collect();
    let host_services: Vec<HostServiceToml> = host_services
        .iter()
        .map(|a| HostServiceToml {
            addr: a.to_string(),
        })
        .collect();

    let doc = ProxyToml {
        listen: listen.iter().map(ToString::to_string).collect(),
        // kenneld supplies the `[audit]` block, not the legacy single-file path.
        audit_log: None,
        accept_private_resolved: false,
        net: NetToml {
            mode: mode_str(net.mode),
            allow,
            deny,
            host_services,
        },
        audit: audit.map(|a| AuditToml {
            kennel: a.kennel.clone(),
            kennel_uuid: a.kennel_uuid.clone(),
            dir: a.dir.display().to_string(),
            sinks: a.sinks.clone(),
            network_level: a.network_level.clone(),
            syslog_facility: a.syslog_facility.clone(),
            rotate_at_bytes: a.rotate_at_bytes,
            compress_after_seconds: a.compress_after_seconds,
            retain_count: a.retain_count,
        }),
    };
    basic_toml::to_string(&doc).map_err(|e| e.to_string())
}

/// Launch the netproxy `binary` with `config_path` as its sole argument.
///
/// Spawns it as a per-kennel child. The proxy inherits no stdio from the workload
/// (its stderr goes to the daemon's, for diagnostics until the audit log is
/// wired); the caller owns the returned [`Child`] and must reap/kill it on
/// teardown.
///
/// # Errors
///
/// An OS error if the proxy process cannot be spawned.
pub fn spawn(binary: &Path, config_path: &Path) -> std::io::Result<Child> {
    Command::new(binary)
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_policy::{NameRule, NetMode, NetPolicy, NetRule, Protocol};

    fn net() -> NetPolicy {
        NetPolicy {
            mode: NetMode::Constrained,
            proxy: kennel_policy::ProxyListen::default(),
            allow: vec![NetRule {
                cidr: "10.0.0.0".to_owned(),
                prefix_len: 24,
                port_min: 443,
                port_max: 443,
                protocol: Protocol::Tcp,
            }],
            allow_names: vec![NameRule {
                name: "api.example.com".to_owned(),
                ports: vec![443],
                protocol: Protocol::Tcp,
            }],
            deny_invariant: vec![NetRule {
                cidr: "169.254.169.254".to_owned(),
                prefix_len: 32,
                port_min: 0,
                port_max: 65535,
                protocol: Protocol::Any,
            }],
        }
    }

    #[test]
    fn config_round_trips_through_the_netproxy_parser() {
        // Both a v4 and a v6 listen address (the dual-stack case).
        let listen: Vec<SocketAddr> = vec![
            "127.0.144.81:1080".parse().expect("v4"),
            "[fd00:0:1:1::1]:1080".parse().expect("v6"),
        ];
        let toml = config_toml(&net(), &listen, None, &[]).expect("toml");

        // The netproxy's own reader must accept what we wrote, and reconstruct
        // the same ruleset — the anti-drift guarantee.
        let cfg =
            kennel_netproxy::config::from_toml_str(&toml).expect("netproxy parses our config");
        assert_eq!(cfg.listen, listen, "both listen addresses round-trip");
        assert!(cfg.audit_log.is_none());
        assert_eq!(cfg.ruleset.allow.len(), 2, "one cidr + one name allow");
        assert_eq!(cfg.ruleset.deny.len(), 1, "the invariant deny");
    }

    #[test]
    fn full_port_range_becomes_any_port() {
        // deny_invariant uses 0..=65535 → the netproxy "any port" (empty list).
        assert!(ports_for(0, u16::MAX).is_empty());
        assert_eq!(ports_for(443, 443), vec![443]);
        assert_eq!(ports_for(80, 82), vec![80, 81, 82]);
    }

    #[test]
    fn audit_block_round_trips_through_the_netproxy_parser() {
        let listen = ["127.0.144.81:1080".parse::<SocketAddr>().expect("addr")];
        let audit = ProxyAudit {
            kennel: "ai-coding".to_owned(),
            kennel_uuid: "01HZX".to_owned(),
            dir: PathBuf::from("/run/kennel/ai-coding"),
            sinks: vec!["file".to_owned(), "journald".to_owned()],
            network_level: Some("full".to_owned()),
            syslog_facility: None,
            rotate_at_bytes: Some(64 * 1024 * 1024),
            compress_after_seconds: Some(3600),
            retain_count: Some(8),
        };
        let toml = config_toml(&net(), &listen, Some(&audit), &[]).expect("toml");
        let cfg = kennel_netproxy::config::from_toml_str(&toml).expect("parse");
        let parsed = cfg.audit.expect("audit block present");
        assert_eq!(parsed.kennel, "ai-coding");
        assert_eq!(parsed.kennel_uuid, "01HZX");
        assert_eq!(parsed.dir, PathBuf::from("/run/kennel/ai-coding"));
        assert_eq!(parsed.sinks.len(), 2, "file + journald");
        assert_eq!(parsed.rotate_at_bytes, Some(64 * 1024 * 1024));
        assert_eq!(parsed.compress_after_seconds, Some(3600));
        assert_eq!(parsed.retain_count, Some(8));
        // No [audit] ⇒ the writer falls back (legacy/standalone).
        let none = config_toml(&net(), &listen, None, &[]).expect("toml");
        assert!(kennel_netproxy::config::from_toml_str(&none)
            .expect("parse")
            .audit
            .is_none());
    }
}
