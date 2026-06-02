//! The per-kennel egress proxy: deriving its config and launching it.
//!
//! Every outbound connection from a kennel terminates at a kennel-local
//! [`kennel-netproxy`] process (`docs/design/07-3-network.md` §7.3.2). The cgroup BPF
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
use std::path::Path;
use std::process::{Child, Command, Stdio};

use kennel_policy::{NameRule, NetMode, NetPolicy, NetRule, Protocol};
use serde::Serialize;

/// The installed `kennel-netproxy` binary (companion to kenneld under
/// `/opt/kennel/bin`, per the packaging plan).
pub const DEFAULT_NETPROXY_BIN: &str = "/opt/kennel/bin/kennel-netproxy";

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
}

#[derive(Serialize)]
struct NetToml {
    mode: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allow: Vec<AllowToml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<DenyToml>,
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
/// both its v4 and v6 loopback addresses; `audit` is an optional audit-log path
/// (`None` ⇒ the proxy logs to stderr).
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
pub fn config_toml(net: &NetPolicy, listen: &[SocketAddr], audit: Option<&Path>) -> Result<String, String> {
    let mut allow: Vec<AllowToml> = net.allow.iter().map(allow_from_cidr).collect();
    allow.extend(net.allow_names.iter().map(allow_from_name));

    let deny: Vec<DenyToml> = net
        .deny_invariant
        .iter()
        .map(|r| DenyToml { cidr: Some(cidr_str(r)), ports: ports_for(r.port_min, r.port_max) })
        .collect();

    let doc = ProxyToml {
        listen: listen.iter().map(ToString::to_string).collect(),
        audit_log: audit.map(|p| p.display().to_string()),
        accept_private_resolved: false,
        net: NetToml { mode: mode_str(net.mode), allow, deny },
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
        let listen: Vec<SocketAddr> =
            vec!["127.0.144.81:1080".parse().expect("v4"), "[fd00:0:1:1::1]:1080".parse().expect("v6")];
        let toml = config_toml(&net(), &listen, None).expect("toml");

        // The netproxy's own reader must accept what we wrote, and reconstruct
        // the same ruleset — the anti-drift guarantee.
        let cfg = kennel_netproxy::config::from_toml_str(&toml).expect("netproxy parses our config");
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
    fn audit_path_is_written_when_present() {
        let listen = ["127.0.144.81:1080".parse::<SocketAddr>().expect("addr")];
        let toml = config_toml(&net(), &listen, Some(Path::new("/run/kennel/p.jsonl"))).expect("toml");
        let cfg = kennel_netproxy::config::from_toml_str(&toml).expect("parse");
        assert_eq!(cfg.audit_log.as_deref(), Some(Path::new("/run/kennel/p.jsonl")));
    }
}
