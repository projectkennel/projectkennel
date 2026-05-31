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
//! listen = "127.42.7.1:1080"          # the proxy's listen socket address
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

/// Largest config file the proxy will read. A policy config is small; this bounds
/// the read against a runaway or hostile file (§10.2).
pub const MAX_CONFIG: u64 = 1024 * 1024;

/// The proxy's fully-validated runtime configuration.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// The socket address the proxy listens on.
    pub listen: SocketAddr,
    /// The resolved egress ruleset.
    pub ruleset: Ruleset,
    /// Whether a name may connect to a resolved special-use address.
    pub accept_private_resolved: bool,
    /// Where to write the JSON Lines audit stream; `None` means stderr.
    pub audit_log: Option<PathBuf>,
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
    listen: String,
    #[serde(default)]
    audit_log: Option<PathBuf>,
    #[serde(default)]
    accept_private_resolved: bool,
    net: RawNet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNet {
    mode: Mode,
    #[serde(default)]
    allow: Vec<RawAllow>,
    #[serde(default)]
    deny: Vec<RawDeny>,
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
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid(format!("listen is not a socket address: `{}`", self.listen))
        })?;
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
        Ok(ProxyConfig {
            listen,
            ruleset: Ruleset { mode, allow, deny },
            accept_private_resolved: self.accept_private_resolved,
            audit_log: self.audit_log,
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
listen = "127.42.7.1:1080"
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
        assert_eq!(cfg.listen, "127.42.7.1:1080".parse().expect("addr"));
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
    fn bare_address_is_a_host_route() {
        let cfg = from_toml_str("listen = \"127.0.0.1:1\"\n[net]\nmode=\"open\"\n[[net.deny]]\ncidr=\"169.254.169.254\"\n")
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
        let toml = "listen = \"127.0.0.1:1\"\nbogus = true\n[net]\nmode = \"open\"\n";
        assert!(
            matches!(from_toml_str(toml), Err(ConfigError::Parse(_))),
            "deny_unknown_fields"
        );
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let toml =
            "listen=\"127.0.0.1:1\"\n[net]\nmode=\"open\"\n[[net.allow]]\nname=\"x\"\nbogus=1\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn entry_with_both_name_and_cidr_is_invalid() {
        let toml = "listen=\"127.0.0.1:1\"\n[net]\nmode=\"constrained\"\n[[net.allow]]\nname=\"x\"\ncidr=\"10.0.0.0/8\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn entry_with_neither_name_nor_cidr_is_invalid() {
        let toml =
            "listen=\"127.0.0.1:1\"\n[net]\nmode=\"constrained\"\n[[net.allow]]\nports=[443]\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bad_cidr_is_invalid() {
        let toml =
            "listen=\"127.0.0.1:1\"\n[net]\nmode=\"open\"\n[[net.deny]]\ncidr=\"10.0.0.0/99\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn bad_listen_is_invalid() {
        let toml = "listen=\"not-an-address\"\n[net]\nmode=\"open\"\n";
        assert!(matches!(from_toml_str(toml), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let toml = "listen=\"127.0.0.1:1\"\n[net]\nmode=\"yolo\"\n";
        assert!(
            matches!(from_toml_str(toml), Err(ConfigError::Parse(_))),
            "unknown enum variant"
        );
    }

    #[test]
    fn protocol_defaults_to_tcp() {
        let toml =
            "listen=\"127.0.0.1:1\"\n[net]\nmode=\"constrained\"\n[[net.allow]]\nname=\"x\"\n";
        let cfg = from_toml_str(toml).expect("config");
        assert_eq!(
            cfg.ruleset.allow.first().map(|r| r.protocol),
            Some(RuleProtocol::Tcp)
        );
    }
}
