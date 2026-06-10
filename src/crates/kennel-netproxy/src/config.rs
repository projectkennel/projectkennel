//! The proxy's TOML configuration (`[net]` policy + listen + audit).
//!
//! The proxy is launched with the path to a TOML config file. `kenneld` writes
//! that file from the resolved policy and passes the path; standalone operators
//! write it by hand (the proxy is a useful SOCKS5/HTTP egress filter on its own,
//! which is why the config is a documented file format rather than an in-process
//! struct hand-off). Either way the producer is the operator or `kenneld`, not
//! the confined workload.
//!
//! # Input handling
//!
//! The file is still parsed defensively (§10): the read is size-bounded
//! ([`MAX_CONFIG`]), every table rejects unknown fields
//! (`#[serde(deny_unknown_fields)]`), and each rule is validated as it is
//! converted to the typed [`Ruleset`] — a CIDR must parse, an allow/deny entry
//! must carry exactly one of `name` or `cidr`, and the listen string must parse
//! as a socket address. Parsing produces typed values or a specific error; there
//! is no half-validated intermediate.
//!
//! # Schema
//!
//! ```toml
//! listen = ["127.42.7.1:1080"]        # listen socket address(es); 1+ (v4 and/or v6)
//! audit_log = "/path/audit.jsonl"     # optional; default: stderr
//! accept_private_resolved = false     # optional; default: false
//!
//! [net]
//! mode = "constrained"                # "none" | "constrained" | "open"
//!
//! [[net.allow]]
//! name = "api.example.com"            # exactly one of name / cidr
//! ports = [443]                       # optional; empty = any port
//! protocol = "tcp"                    # optional; "tcp" (default) | "udp" | "any"
//!
//! [[net.allow]]
//! cidr = "10.0.0.0/24"                # bare address is treated as a host route
//! ports = [443]
//!
//! [[net.deny]]
//! name = ".tracker.example"           # leading dot = apex + subdomains
//! ```
//!
//! # Owed
//!
//! A `fuzz/config_parse` target (§10.6) once the fuzzing harness crosses the §5.5
//! gate; the unit tests hold the contract until then.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::allow::{Cidr, DenyMatcher, DenyRule, Matcher, NetMode, Rule, RuleProtocol, Ruleset};
use kennel_audit::{Level, SinkKind};

/// Largest config file the proxy will read. A policy config is small; this bounds
/// the read against a runaway or hostile file (§10.2).
pub const MAX_CONFIG: u64 = 1024 * 1024;

/// The proxy's fully-validated runtime configuration.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// The socket addresses the proxy listens on (at least one). A dual-stack
    /// kennel lists both its v4 and v6 loopback addresses, since one listener
    /// binds a single family; the proxy serves all of them ([`crate::server::Proxy::serve_all`]).
    pub listen: Vec<SocketAddr>,
    /// The resolved egress ruleset.
    pub ruleset: Ruleset,
    /// Whether a name may connect to a resolved special-use address.
    pub accept_private_resolved: bool,
    /// The per-kennel `kenneld`↔delegate conduit command socket to bind and serve (§7.5.2), or
    /// `None` for a standalone proxy with no `INet` conduit.
    pub command_socket: Option<PathBuf>,
    /// Sanctioned host-loopback services (`[[net.host_services]]`, §7.5): exact
    /// `addr:port` literals reachable despite the host-loopback invariant deny.
    pub host_services: Vec<SocketAddr>,
    /// Where to write the JSON Lines audit stream when no `[audit]` block is
    /// given; `None` means stdout. The legacy/standalone single-file sink.
    pub audit_log: Option<PathBuf>,
    /// The unified-audit context `kenneld` supplies (`[audit]`): the kennel name
    /// and shared `kennel_uuid`, the sinks, and the per-kennel state dir. `None`
    /// for a standalone proxy, which falls back to [`audit_log`](Self::audit_log).
    pub audit: Option<AuditConfig>,
}

/// The `[audit]` block: the unified-audit context for the proxy's writer.
///
/// It lets the proxy's `net.egress` events reach the same sinks (and carry the
/// same `kennel_uuid`) as `kenneld`'s lifecycle events. Fully validated at parse.
#[derive(Clone, Debug)]
pub struct AuditConfig {
    /// The kennel name (envelope `kennel`).
    pub kennel: String,
    /// The shared per-instance `kennel_uuid` (so egress events correlate with
    /// `kenneld`'s lifecycle events for the same run).
    pub kennel_uuid: String,
    /// The per-kennel state dir the file sink writes `network.jsonl` to.
    pub dir: PathBuf,
    /// The active sinks (validated tokens).
    pub sinks: Vec<SinkKind>,
    /// The `net` audit level (the only class the proxy emits).
    pub network_level: Option<Level>,
    /// The syslog facility name (default `user`).
    pub syslog_facility: Option<String>,
    /// File-sink rotation threshold in bytes.
    pub rotate_at_bytes: Option<u64>,
    /// File-sink gzip-after-seconds delay.
    pub compress_after_seconds: Option<u64>,
    /// File-sink retained-rotation count.
    pub retain_count: Option<usize>,
}

/// A configuration error.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Read(std::io::Error),
    /// The file was larger than [`MAX_CONFIG`].
    TooLarge,
    /// The TOML did not parse.
    Parse(String),
    /// The TOML parsed but was not a valid configuration.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "cannot read config: {e}"),
            Self::TooLarge => write!(f, "config file exceeds {MAX_CONFIG} bytes"),
            Self::Parse(m) => write!(f, "config is not valid TOML: {m}"),
            Self::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Read and validate the config at `path`.
///
/// # Errors
///
/// [`ConfigError::Read`] / [`ConfigError::TooLarge`] for I/O problems,
/// [`ConfigError::Parse`] for malformed TOML, [`ConfigError::Invalid`] for a
/// well-formed file that is not a valid configuration.
pub fn load(path: &Path) -> Result<ProxyConfig, ConfigError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(ConfigError::Read)?;
    let mut text = String::new();
    // Bounded read: take one byte past the cap so an over-cap file is detected.
    let limit = MAX_CONFIG.checked_add(1).unwrap_or(MAX_CONFIG);
    let read = file
        .take(limit)
        .read_to_string(&mut text)
        .map_err(ConfigError::Read)?;
    if u64::try_from(read).is_ok_and(|n| n > MAX_CONFIG) {
        return Err(ConfigError::TooLarge);
    }
    from_toml_str(&text)
}

/// Parse and validate a config from a TOML string (the I/O-free core of
/// [`load`], so it is unit-testable without a file).
///
/// # Errors
///
/// [`ConfigError::Parse`] for malformed TOML; [`ConfigError::Invalid`] for a
/// well-formed document that fails validation.
pub fn from_toml_str(text: &str) -> Result<ProxyConfig, ConfigError> {
    let raw: RawConfig =
        basic_toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    raw.validate()
}

// ---- the on-disk shape (untrusted; converted to the typed form by validate) ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: Vec<String>,
    #[serde(default)]
    audit_log: Option<PathBuf>,
    #[serde(default)]
    accept_private_resolved: bool,
    #[serde(default)]
    command_socket: Option<PathBuf>,
    net: RawNet,
    #[serde(default)]
    audit: Option<RawAudit>,
}

/// `[audit]` — the unified-audit context (kenneld writes it; standalone configs
/// may omit it and use `audit_log`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAudit {
    kennel: String,
    kennel_uuid: String,
    dir: PathBuf,
    #[serde(default)]
    sinks: Vec<String>,
    #[serde(default)]
    network_level: Option<String>,
    #[serde(default)]
    syslog_facility: Option<String>,
    #[serde(default)]
    rotate_at_bytes: Option<u64>,
    #[serde(default)]
    compress_after_seconds: Option<u64>,
    #[serde(default)]
    retain_count: Option<u64>,
}

impl RawAudit {
    fn validate(self) -> Result<AuditConfig, ConfigError> {
        let sinks = self
            .sinks
            .iter()
            .map(|s| {
                SinkKind::parse(s).ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "audit sink `{s}` is not file/stdout/syslog/journald"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let network_level = match &self.network_level {
            None => None,
            Some(l) => Some(Level::parse(l).ok_or_else(|| {
                ConfigError::Invalid(format!("audit network_level `{l}` is not a valid level"))
            })?),
        };
        let retain_count = self
            .retain_count
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX));
        Ok(AuditConfig {
            kennel: self.kennel,
            kennel_uuid: self.kennel_uuid,
            dir: self.dir,
            sinks,
            network_level,
            syslog_facility: self.syslog_facility,
            rotate_at_bytes: self.rotate_at_bytes,
            compress_after_seconds: self.compress_after_seconds,
            retain_count,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNet {
    mode: Mode,
    #[serde(default)]
    allow: Vec<RawAllow>,
    #[serde(default)]
    deny: Vec<RawDeny>,
    #[serde(default)]
    host_services: Vec<RawHostService>,
}

/// `[[net.host_services]]` — a sanctioned host-loopback service (§7.5).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHostService {
    /// The exact `addr:port` literal (e.g. `127.0.0.1:7022`) reachable despite the
    /// host-loopback invariant deny.
    addr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    None,
    Constrained,
    Open,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Proto {
    Tcp,
    Udp,
    Any,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllow {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    protocol: Option<Proto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeny {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
}

impl RawConfig {
    fn validate(self) -> Result<ProxyConfig, ConfigError> {
        // In the net-ns model netproxy has no TCP listener — it serves only the conduit command
        // socket (§7.5.3). A config must give at least one of the two; empty `listen` is valid
        // when a `command_socket` is set (conduit-only), but a config with neither serves nothing.
        if self.listen.is_empty() && self.command_socket.is_none() {
            return Err(ConfigError::Invalid(
                "config must give a listen address or a command_socket".to_owned(),
            ));
        }
        let listen = self
            .listen
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>().map_err(|_| {
                    ConfigError::Invalid(format!("listen is not a socket address: `{s}`"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mode = match self.net.mode {
            Mode::None => NetMode::None,
            Mode::Constrained => NetMode::Constrained,
            Mode::Open => NetMode::Open,
        };
        let allow = self
            .net
            .allow
            .into_iter()
            .map(RawAllow::into_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let deny = self
            .net
            .deny
            .into_iter()
            .map(RawDeny::into_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let host_services = self
            .net
            .host_services
            .iter()
            .map(|hs| {
                hs.addr.parse::<SocketAddr>().map_err(|_| {
                    ConfigError::Invalid(format!(
                        "host_services addr is not `ip:port`: `{}`",
                        hs.addr
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let audit = match self.audit {
            Some(raw) => Some(raw.validate()?),
            None => None,
        };
        Ok(ProxyConfig {
            listen,
            ruleset: Ruleset { mode, allow, deny },
            accept_private_resolved: self.accept_private_resolved,
            command_socket: self.command_socket,
            host_services,
            audit_log: self.audit_log,
            audit,
        })
    }
}

impl RawAllow {
    fn into_rule(self) -> Result<Rule, ConfigError> {
        let matcher = pick_matcher(self.name, self.cidr, "allow")?;
        let protocol = match self.protocol {
            None | Some(Proto::Tcp) => RuleProtocol::Tcp,
            Some(Proto::Udp) => RuleProtocol::Udp,
            Some(Proto::Any) => RuleProtocol::Any,
        };
        Ok(Rule {
            matcher,
            ports: self.ports,
            protocol,
        })
    }
}

impl RawDeny {
    fn into_rule(self) -> Result<DenyRule, ConfigError> {
        let matcher = match pick_matcher(self.name, self.cidr, "deny")? {
            Matcher::Name(n) => DenyMatcher::Name(n),
            Matcher::Cidr(c) => DenyMatcher::Cidr(c),
        };
        Ok(DenyRule {
            matcher,
            ports: self.ports,
        })
    }
}

/// Resolve an entry's `name`/`cidr` pair into a [`Matcher`], requiring exactly
/// one of the two and a non-empty name.
fn pick_matcher(
    name: Option<String>,
    cidr: Option<String>,
    kind: &str,
) -> Result<Matcher, ConfigError> {
    match (name, cidr) {
        (Some(_), Some(_)) => Err(ConfigError::Invalid(format!(
            "{kind} entry has both `name` and `cidr`"
        ))),
        (None, None) => Err(ConfigError::Invalid(format!(
            "{kind} entry has neither `name` nor `cidr`"
        ))),
        (Some(name), None) => {
            if name.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "{kind} entry has an empty `name`"
                )));
            }
            Ok(Matcher::Name(name))
        }
        (None, Some(cidr)) => Ok(Matcher::Cidr(parse_cidr(&cidr)?)),
    }
}

/// Parse a CIDR string `addr/prefix`, or a bare address (treated as a host route:
/// `/32` for IPv4, `/128` for IPv6).
fn parse_cidr(s: &str) -> Result<Cidr, ConfigError> {
    let (addr_str, prefix) = match s.split_once('/') {
        Some((addr, prefix_str)) => {
            let prefix = prefix_str
                .parse::<u8>()
                .map_err(|_| ConfigError::Invalid(format!("bad CIDR prefix in `{s}`")))?;
            (addr, Some(prefix))
        }
        None => (s, None),
    };
    let addr = addr_str
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::Invalid(format!("bad CIDR address in `{s}`")))?;
    let prefix = prefix.unwrap_or_else(|| if addr.is_ipv4() { 32 } else { 128 });
    Cidr::new(addr, prefix).map_err(|e| ConfigError::Invalid(format!("bad CIDR `{s}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
listen = ["127.42.7.1:1080"]
accept_private_resolved = false

[net]
mode = "constrained"

[[net.allow]]
name = "api.example.com"
ports = [443]

[[net.allow]]
cidr = "10.0.0.0/24"
ports = [443, 80]
protocol = "tcp"

[[net.deny]]
name = ".tracker.example"
"#;

    #[test]
    fn parses_a_valid_config() {
        let cfg = from_toml_str(VALID).expect("valid config");
        assert_eq!(
            cfg.listen,
            vec!["127.42.7.1:1080".parse::<SocketAddr>().expect("addr")]
        );
        assert!(!cfg.accept_private_resolved);
        assert_eq!(cfg.ruleset.mode, NetMode::Constrained);
        assert_eq!(cfg.ruleset.allow.len(), 2);
        assert_eq!(cfg.ruleset.deny.len(), 1);
        assert_eq!(
            cfg.ruleset.allow.first().map(|r| &r.matcher),
            Some(&Matcher::Name("api.example.com".to_owned()))
        );
        assert_eq!(
            cfg.ruleset.deny.first().map(|r| &r.matcher),
            Some(&DenyMatcher::Name(".tracker.example".to_owned()))
        );
    }

    #[test]
    fn parses_host_services_into_socket_addrs() {
        let cfg = from_toml_str(
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"constrained\"\n[[net.host_services]]\naddr=\"127.0.0.1:7022\"\n",
        )
        .expect("valid host_services config");
        assert_eq!(
            cfg.host_services,
            vec!["127.0.0.1:7022".parse::<SocketAddr>().expect("addr")]
        );
        // No [[net.host_services]] ⇒ empty (the common case).
        assert!(from_toml_str(VALID)
            .expect("valid")
            .host_services
            .is_empty());
        // A malformed addr is rejected.
        assert!(from_toml_str(
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"open\"\n[[net.host_services]]\naddr=\"not-an-addr\"\n"
        )
        .is_err());
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let cfg = from_toml_str("listen = [\"127.0.0.1:1\"]\n[net]\nmode=\"open\"\n[[net.deny]]\ncidr=\"169.254.169.254\"\n")
            .expect("config");
        let denied = cfg.ruleset.decide_request(
            &crate::allow::Destination::Addr("169.254.169.254".parse().expect("ip")),
            80,
            crate::allow::Transport::Tcp,
        );
        assert!(
            matches!(denied, crate::allow::RequestDecision::Deny(_)),
            "host-route deny applies"
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = "listen = [\"127.0.0.1:1\"]\nbogus = true\n[net]\nmode = \"open\"\n";
        assert!(
            matches!(from_toml_str(toml), Err(ConfigError::Parse(_))),
            "deny_unknown_fields"
        );
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let toml =
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"open\"\n[[net.allow]]\nname=\"x\"\nbogus=1\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn entry_with_both_name_and_cidr_is_invalid() {
        let toml = "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"constrained\"\n[[net.allow]]\nname=\"x\"\ncidr=\"10.0.0.0/8\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn entry_with_neither_name_nor_cidr_is_invalid() {
        let toml =
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"constrained\"\n[[net.allow]]\nports=[443]\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bad_cidr_is_invalid() {
        let toml =
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"open\"\n[[net.deny]]\ncidr=\"10.0.0.0/99\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bad_listen_is_invalid() {
        let toml = "listen=[\"not-an-address\"]\n[net]\nmode=\"open\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn empty_listen_is_invalid() {
        let toml = "listen=[]\n[net]\nmode=\"open\"\n";
        assert!(
            matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))),
            "at least one listen address required"
        );
    }

    #[test]
    fn two_listen_addresses_parse() {
        // The dual-stack case: a v4 and a v6 loopback address.
        let toml = "listen=[\"127.0.0.1:1080\", \"[::1]:1080\"]\n[net]\nmode=\"open\"\n";
        let cfg = from_toml_str(toml).expect("two-address config");
        assert_eq!(cfg.listen.len(), 2);
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let toml = "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"yolo\"\n";
        assert!(
            matches!(from_toml_str(toml), Err(ConfigError::Parse(_))),
            "unknown enum variant"
        );
    }

    #[test]
    fn protocol_defaults_to_tcp() {
        let toml =
            "listen=[\"127.0.0.1:1\"]\n[net]\nmode=\"constrained\"\n[[net.allow]]\nname=\"x\"\n";
        let cfg = from_toml_str(toml).expect("config");
        assert_eq!(
            cfg.ruleset.allow.first().map(|r| r.protocol),
            Some(RuleProtocol::Tcp)
        );
    }
}
