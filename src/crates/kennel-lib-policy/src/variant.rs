// SPDX-License-Identifier: Apache-2.0

//! The mutable-field manifest and its **constraint family** (Kennel book Vol 2 ch.13 (Dynamic Spawning)
//! §7.12.3).
//!
//! A spawn-target template is signed *with* a manifest: a set of **variants** bounded by
//! **constraints**.
//!
//! A variant is a point where an in-memory instance may diverge from the signed template; its
//! constraint bounds the divergence. The instantiated policy is never re-signed (§7.12.3); its
//! integrity is the verified template signature plus these signed constraints plus the in-TCB validator
//! that applies them. This module owns that family: the signed wire form, the resolved logic form, and
//! the admission check.
//!
//! # The constraint family (extensible by design)
//!
//! The constraint is one of an open family — a loudness gradient from closed to open:
//! - [`Constraint::OneOf`] — pick one member of an enumerated set (closed, zero free text).
//! - [`Constraint::Pool`] — append up to `max` values, each drawn from a fixed set (closed).
//! - [`Constraint::Pattern`] — an *open* value admitted only if it matches a pre-baked shape (a net
//!   destination: `*.suffix:port` subdomain wildcard, `prefix.*:port` final-label wildcard).
//! - [`Constraint::Relpath`] — a typed, traversal-free path resolved under a root (`RESOLVE_IN_ROOT`).
//! - [`Constraint::Freeform`] — *no* shape; any value, the loud last-resort footgun. A `reason` is
//!   mandatory and every use is warned (warn, never forbid — the footgun rule).
//!
//! **To add a member:** add a [`Constraint`] arm, the field(s) that carry it on [`Variant`], a branch
//! in [`Variant::resolve`], and an arm in [`Constraint::admits`]. Nothing outside this file changes.

use serde::{Deserialize, Serialize};

/// The mutable-field manifest: the signed set of variants a spawn-target template carries. Empty on a
/// policy that is not a spawn target (then it is omitted from the canonical form and signs unchanged).
pub type Manifest = Vec<Variant>;

/// One variant — a leaf field that may diverge from the template, plus the constraint bounding it.
///
/// Flat by construction: a data-carrying enum would not round-trip through the `kennel-lib-toml` canonical
/// form the signature covers, so the constraint *kind* is identified by which fields are populated.
/// [`resolve`](Self::resolve) lifts it to the logic-form [`Constraint`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    /// The dotted path of the **existing** policy-schema leaf this variant opens (`net.proxy.allow`,
    /// `fs.read`, `fs.write`). A variant never coins a field — it names one the schema already has,
    /// and the applicator's registry (the authority on which leaves are mutable) validates it.
    pub field: String,
    /// `oneof` constraint: the enumerated member set the value must belong to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<String>,
    /// `pool` constraint: the fixed set a value may be drawn from (with [`pool_max`](Self::pool_max)).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool: Vec<String>,
    /// `pool` constraint: the maximum number of appended entries across the patch.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pool_max: u32,
    /// `pattern` constraint: the pre-baked net-destination shapes a value must match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pattern: Vec<String>,
    /// `predicate` (relpath) constraint: the root a traversal-free relpath resolves under.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relpath_under: String,
    /// `freeform` constraint: no shape — any value accepted. The loud footgun.
    #[serde(default, skip_serializing_if = "is_false")]
    pub freeform: bool,
    /// The operator's justification — mandatory for a `freeform` variant (the loud rule).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// The resolved constraint — the logic form of a [`Variant`]'s bound, and the family's home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// Pick one member of an enumerated set.
    OneOf(Vec<String>),
    /// Append at most `max` values, each a member of `from`.
    Pool {
        /// The fixed set a value may be drawn from.
        from: Vec<String>,
        /// The maximum number of appended entries across the patch.
        max: u32,
    },
    /// An open value admitted only if it matches one of the pre-baked net-destination shapes.
    Pattern(Vec<DestPattern>),
    /// A typed, traversal-free relpath resolved under `under` (`RESOLVE_IN_ROOT` at instantiation).
    Relpath {
        /// The root the relpath resolves under.
        under: String,
    },
    /// No shape — any value accepted. The loud footgun; `reason` is the operator's justification.
    Freeform {
        /// The operator's justification (mandatory).
        reason: String,
    },
}

/// Why a value was refused admission to its variant's constraint. The caller maps this to a
/// [`PolicyError`](crate::error::PolicyError) (the wire-facing error at the SPAWN verb).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied(pub String);

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A malformed variant in a (supposedly signed, well-formed) manifest. Should not arise after
/// signature verification — defence in depth at the verify layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedVariant(pub String);

impl std::fmt::Display for MalformedVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Variant {
    /// Resolve the flat wire form into the logic-form [`Constraint`], asserting exactly one kind is
    /// populated. Defensive: a signature-verified manifest is well-formed by construction, but the
    /// verify half re-checks rather than trust the bytes.
    ///
    /// # Errors
    ///
    /// [`MalformedVariant`] if zero or more than one constraint kind is populated, or a kind is
    /// incompletely specified (a `pool` without `pool_max`, a `freeform` without `reason`).
    pub fn resolve(&self) -> Result<Constraint, MalformedVariant> {
        let is_oneof = !self.one_of.is_empty();
        let is_pool = !self.pool.is_empty() || self.pool_max != 0;
        let is_pattern = !self.pattern.is_empty();
        let is_relpath = !self.relpath_under.is_empty();
        let is_freeform = self.freeform;
        let kinds = [is_oneof, is_pool, is_pattern, is_relpath, is_freeform]
            .into_iter()
            .filter(|b| *b)
            .count();
        let bad = |m: &str| MalformedVariant(format!("variant `{}`: {m}", self.field));
        if kinds != 1 {
            return Err(bad(&format!(
                "must carry exactly one constraint (oneof/pool/pattern/relpath/freeform); found {kinds}"
            )));
        }
        if is_oneof {
            return Ok(Constraint::OneOf(self.one_of.clone()));
        }
        if is_pool {
            if self.pool.is_empty() {
                return Err(bad("pool constraint has an empty `pool` set"));
            }
            if self.pool_max == 0 {
                return Err(bad("pool constraint has no `pool_max`"));
            }
            return Ok(Constraint::Pool {
                from: self.pool.clone(),
                max: self.pool_max,
            });
        }
        if is_pattern {
            let mut pats = Vec::with_capacity(self.pattern.len());
            for p in &self.pattern {
                pats.push(DestPattern::parse(p).map_err(|m| bad(&m.to_string()))?);
            }
            return Ok(Constraint::Pattern(pats));
        }
        if is_relpath {
            return Ok(Constraint::Relpath {
                under: self.relpath_under.clone(),
            });
        }
        // freeform
        if self.reason.trim().is_empty() {
            return Err(bad(
                "freeform constraint requires a non-empty `reason` (the loud rule)",
            ));
        }
        Ok(Constraint::Freeform {
            reason: self.reason.clone(),
        })
    }
}

impl Constraint {
    /// Whether a single agent-supplied `value` is admitted by this constraint. For [`Pool`], this is
    /// the per-value membership check; the `max` count across the whole patch is enforced by the
    /// applicator, not here.
    ///
    /// [`Pool`]: Constraint::Pool
    ///
    /// # Errors
    ///
    /// [`Denied`] with a human reason if the value is outside the constraint.
    pub fn admits(&self, value: &str) -> Result<(), Denied> {
        match self {
            Self::OneOf(set) => member(value, set, "oneof"),
            Self::Pool { from, .. } => member(value, from, "pool"),
            Self::Pattern(pats) => {
                let dest = Destination::parse(value)
                    .map_err(|m| Denied(format!("`{value}` is not a valid `host:port`: {m}")))?;
                if pats.iter().any(|p| p.matches(&dest)) {
                    Ok(())
                } else {
                    Err(Denied(format!(
                        "`{value}` matches no signed pattern (allowed: {})",
                        pats.iter()
                            .map(DestPattern::render)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )))
                }
            }
            Self::Relpath { .. } => admit_relpath(value),
            // Freeform admits anything by definition — its loudness is the warning, not a refusal.
            Self::Freeform { .. } => Ok(()),
        }
    }

    /// Whether this constraint is an *open* one (its value is not drawn from a sign-time set), so the
    /// open-value residual (T3.9 R1) attaches and — for [`Freeform`](Self::Freeform) — a loud warning
    /// is owed.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Pattern(_) | Self::Relpath { .. } | Self::Freeform { .. }
        )
    }

    /// The maximum number of patch entries this constraint admits for its field, or `None` for no
    /// per-constraint cap. `pool` allows up to its `max`; `oneof`/`relpath`/`freeform` are
    /// single-value picks (one entry); `pattern` is uncapped here — the agent may add several admitted
    /// destinations, bounded by the overall `SPAWN_PATCH_MAX_BYTES` transaction cap the wire enforces.
    #[must_use]
    pub const fn max_entries(&self) -> Option<u32> {
        match self {
            Self::Pool { max, .. } => Some(*max),
            Self::OneOf(_) | Self::Relpath { .. } | Self::Freeform { .. } => Some(1),
            Self::Pattern(_) => None,
        }
    }
}

fn member(value: &str, set: &[String], kind: &str) -> Result<(), Denied> {
    if set.iter().any(|m| m == value) {
        Ok(())
    } else {
        Err(Denied(format!(
            "`{value}` is not a member of the {kind} set (allowed: {})",
            join(set.iter().map(String::as_str))
        )))
    }
}

/// A traversal-free relpath: non-empty, not absolute, no `.`/`..` components, no `//`. The actual
/// `RESOLVE_IN_ROOT` open happens at instantiation; this is the static admission gate.
fn admit_relpath(value: &str) -> Result<(), Denied> {
    let deny = |m: &str| Err(Denied(format!("relpath `{value}`: {m}")));
    if value.is_empty() {
        return deny("is empty");
    }
    if value.starts_with('/') {
        return deny("is absolute");
    }
    for comp in value.split('/') {
        match comp {
            "" => return deny("has an empty component (`//` or a trailing slash)"),
            "." | ".." => return deny("contains a `.`/`..` traversal component"),
            _ => {}
        }
    }
    Ok(())
}

/// A net-destination value the agent supplied — a host plus an exact port.
///
/// Shared by the pattern matcher (which checks it) and the applicator (which builds a proxy rule from
/// it), so both agree on the `host:port` grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The destination host (a name or an IPv4 literal).
    pub host: String,
    /// The exact destination port.
    pub port: Port,
}

/// Why a string is not a `host:port` destination, or not a destination pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestFault {
    /// There is no `:port`.
    MissingPort,
    /// The host is empty.
    EmptyHost,
    /// The host contains `:` (an IPv6 literal).
    Ipv6Host,
    /// The port is not a number that fits a `u16`.
    NotAPort(String),
    /// The port is 0.
    PortZero,
    /// A `*.suffix` wildcard with an empty or wildcarded suffix.
    MalformedSuffix,
    /// A `prefix.*` wildcard with an empty or wildcarded prefix.
    MalformedPrefix,
    /// A wildcard that is neither a leading `*.` nor a trailing `.*`.
    InteriorWildcard,
    /// More than one wildcard.
    TooManyWildcards,
}

impl std::fmt::Display for DestFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPort => f.write_str("missing `:port`"),
            Self::EmptyHost => f.write_str("empty host"),
            Self::Ipv6Host => {
                f.write_str("host contains `:` (IPv6 is not supported by pattern constraints)")
            }
            Self::NotAPort(port) => write!(f, "`{port}` is not a port"),
            Self::PortZero => f.write_str("port 0"),
            Self::MalformedSuffix => f.write_str("malformed `*.suffix`"),
            Self::MalformedPrefix => f.write_str("malformed `prefix.*`"),
            Self::InteriorWildcard => {
                f.write_str("wildcard must be a leading `*.` or trailing `.*`, not interior")
            }
            Self::TooManyWildcards => f.write_str("at most one wildcard"),
        }
    }
}

/// A destination pattern that does not parse: the pattern as written, and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    /// The pattern as written.
    pub pattern: String,
    /// What is wrong with it.
    pub fault: DestFault,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pattern `{}`: {}", self.pattern, self.fault)
    }
}

impl std::error::Error for DestFault {}
impl std::error::Error for PatternError {}

/// A TCP or UDP port a destination names: never 0.
///
/// It can only be built by [`Port::parse`], so a destination or a pattern cannot carry the
/// wildcard port (CODING-STANDARDS.md §11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(std::num::NonZeroU16);

impl Port {
    /// Parse a decimal port number.
    ///
    /// # Errors
    /// [`DestFault::NotAPort`] if `text` is not a number that fits a `u16`, or
    /// [`DestFault::PortZero`] if it is 0.
    pub fn parse(text: &str) -> Result<Self, DestFault> {
        let port: u16 = text
            .parse()
            .map_err(|_| DestFault::NotAPort(text.to_owned()))?;
        std::num::NonZeroU16::new(port)
            .map(Self)
            .ok_or(DestFault::PortZero)
    }

    /// A port from its number; `None` for 0.
    #[must_use]
    pub fn new(port: u16) -> Option<Self> {
        std::num::NonZeroU16::new(port).map(Self)
    }

    /// The port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Destination {
    /// Parse `host:port`. The host is everything before the final `:`; the port is an exact `u16`.
    /// (IPv6 bracket syntax is out of scope for the pattern constraint — net patterns are names and
    /// IPv4.)
    ///
    /// # Errors
    ///
    /// The [`DestFault`] if there is no `:port`, the host is empty or contains `:` (IPv6), or the
    /// port is not a non-zero `u16`.
    pub fn parse(value: &str) -> Result<Self, DestFault> {
        let (host, port) = value.rsplit_once(':').ok_or(DestFault::MissingPort)?;
        if host.is_empty() {
            return Err(DestFault::EmptyHost);
        }
        if host.contains(':') {
            return Err(DestFault::Ipv6Host);
        }
        Ok(Self {
            host: host.to_owned(),
            port: Port::parse(port)?,
        })
    }
}

/// A pre-baked net-destination pattern: a host shape plus an exact port.
///
/// The single wildcard, when present, sits at one end only — a leading `*.` (subdomain) or a trailing
/// `.*` (final label / IPv4 last octet). No nested or interior wildcards; the shape is deliberately
/// narrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestPattern {
    host: HostPattern,
    port: Port,
}

/// The host half of a [`DestPattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// Exact host match (`ghcr.io`).
    Exact(String),
    /// `*.suffix`: the apex `suffix` itself, or any subdomain on a label boundary (`api.x.com`
    /// matches `*.x.com`, as does `x.com`).
    Suffix(String),
    /// `prefix.*`: `prefix` followed by exactly one more non-empty, dot-free label (the IPv4 `/24`
    /// form `10.0.0.*`).
    Prefix(String),
}

impl DestPattern {
    /// Parse a `HOSTPAT:PORT` pattern with at most one end-anchored wildcard.
    ///
    /// # Errors
    ///
    /// The [`PatternError`] if the port is not an exact `u16`, or the host carries a malformed,
    /// interior or second wildcard.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        Self::parse_parts(pattern).map_err(|fault| PatternError {
            pattern: pattern.to_owned(),
            fault,
        })
    }

    fn parse_parts(pattern: &str) -> Result<Self, DestFault> {
        let (host, port) = pattern.rsplit_once(':').ok_or(DestFault::MissingPort)?;
        let port = Port::parse(port)?;
        if host.is_empty() {
            return Err(DestFault::EmptyHost);
        }
        let stars = host.matches('*').count();
        let host = if stars == 0 {
            HostPattern::Exact(host.to_owned())
        } else if stars == 1 {
            if let Some(suffix) = host.strip_prefix("*.") {
                if suffix.is_empty() || suffix.contains('*') {
                    return Err(DestFault::MalformedSuffix);
                }
                HostPattern::Suffix(suffix.to_owned())
            } else if let Some(prefix) = host.strip_suffix(".*") {
                if prefix.is_empty() || prefix.contains('*') {
                    return Err(DestFault::MalformedPrefix);
                }
                HostPattern::Prefix(prefix.to_owned())
            } else {
                return Err(DestFault::InteriorWildcard);
            }
        } else {
            return Err(DestFault::TooManyWildcards);
        };
        Ok(Self { host, port })
    }

    fn matches(&self, dest: &Destination) -> bool {
        self.port == dest.port && self.host.matches_host(&dest.host)
    }

    /// Render back to `HOSTPAT:PORT` for an error message.
    fn render(&self) -> String {
        let host = match &self.host {
            HostPattern::Exact(h) => h.clone(),
            HostPattern::Suffix(s) => format!("*.{s}"),
            HostPattern::Prefix(p) => format!("{p}.*"),
        };
        format!("{host}:{}", self.port)
    }
}

impl HostPattern {
    fn matches_host(&self, host: &str) -> bool {
        match self {
            Self::Exact(h) => h == host,
            Self::Suffix(suffix) => {
                host == suffix
                    || host
                        .strip_suffix(suffix)
                        .is_some_and(|head| head.ends_with('.') && head.len() > 1)
            }
            Self::Prefix(prefix) => host
                .strip_prefix(prefix)
                .and_then(|tail| tail.strip_prefix('.'))
                .is_some_and(|last| !last.is_empty() && !last.contains('.')),
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // `skip_serializing_if` requires a `&T` predicate.
const fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)] // `skip_serializing_if` requires a `&T` predicate.
const fn is_false(b: &bool) -> bool {
    !*b
}

fn join<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items.collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant_toml(toml: &str) -> Variant {
        kennel_lib_toml::from_str(toml).expect("variant parses")
    }

    #[test]
    fn each_constraint_kind_resolves_and_round_trips_the_canonical_form() {
        for toml in [
            "field = \"rootfs.writable\"\none_of = [\"/a\", \"/b\"]\n",
            "field = \"fs.read\"\npool = [\"/a\"]\npool_max = 4\n",
            "field = \"net.proxy.allow\"\npattern = [\"*.x.com:443\"]\n",
            "field = \"fs.write\"\nrelpath_under = \"workspace\"\n",
            "field = \"env.X\"\nfreeform = true\nreason = \"varies per run\"\n",
        ] {
            let v = variant_toml(toml);
            v.resolve().expect("resolves");
            // The signed bytes must survive a kennel-lib-toml round-trip unchanged.
            let reser = kennel_lib_toml::to_string(&v).expect("serialises");
            let back: Variant = kennel_lib_toml::from_str(&reser).expect("re-parses");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn zero_or_multiple_constraint_kinds_are_malformed() {
        assert!(variant_toml("field = \"x\"\n").resolve().is_err());
        assert!(
            variant_toml("field = \"x\"\none_of = [\"a\"]\npattern = [\"y:1\"]\n")
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn oneof_and_pool_admit_only_members() {
        let oneof = Constraint::OneOf(vec!["/usr".to_owned(), "/opt".to_owned()]);
        assert!(oneof.admits("/usr").is_ok());
        assert!(oneof.admits("/etc").is_err());

        let pool = Constraint::Pool {
            from: vec!["pypi.org".to_owned()],
            max: 4,
        };
        assert!(pool.admits("pypi.org").is_ok());
        assert!(pool.admits("evil.com").is_err());
    }

    #[test]
    fn freeform_admits_anything_but_is_open() {
        let f = Constraint::Freeform {
            reason: "r".to_owned(),
        };
        assert!(f.admits("literally anything://x").is_ok());
        assert!(f.is_open());
    }

    #[test]
    fn freeform_without_reason_is_malformed() {
        assert!(variant_toml("field = \"x\"\nfreeform = true\n")
            .resolve()
            .is_err());
    }

    #[test]
    fn relpath_rejects_traversal_and_absolute() {
        let r = Constraint::Relpath {
            under: "workspace".to_owned(),
        };
        assert!(r.admits("sub/dir/file").is_ok());
        assert!(r.admits("../escape").is_err());
        assert!(r.admits("a/../b").is_err());
        assert!(r.admits("/abs").is_err());
        assert!(r.admits("a//b").is_err());
        assert!(r.admits("").is_err());
    }

    #[test]
    fn pattern_subdomain_wildcard_matches_apex_and_subdomains_only() {
        let c = Constraint::Pattern(vec![
            DestPattern::parse("*.pypi.org:443").expect("valid pattern")
        ]);
        assert!(c.admits("pypi.org:443").is_ok()); // apex
        assert!(c.admits("files.pypi.org:443").is_ok()); // subdomain
        assert!(c.admits("a.b.pypi.org:443").is_ok()); // deeper subdomain
        assert!(c.admits("evilpypi.org:443").is_err()); // not on a label boundary
        assert!(c.admits("pypi.org.evil.com:443").is_err()); // suffix not at the end
        assert!(c.admits("pypi.org:8443").is_err()); // wrong port
    }

    #[test]
    fn pattern_final_label_wildcard_is_one_label_only() {
        let c = Constraint::Pattern(vec![
            DestPattern::parse("10.0.0.*:443").expect("valid pattern")
        ]);
        assert!(c.admits("10.0.0.5:443").is_ok());
        assert!(c.admits("10.0.0.255:443").is_ok());
        assert!(c.admits("10.0.0.5.6:443").is_err()); // two labels in the wildcard slot
        assert!(c.admits("10.0.1.5:443").is_err()); // prefix differs
        assert!(c.admits("10.0.0.:443").is_err()); // empty final label
    }

    #[test]
    fn exact_pattern_and_malformed_patterns() {
        let c = Constraint::Pattern(vec![
            DestPattern::parse("ghcr.io:443").expect("valid pattern")
        ]);
        assert!(c.admits("ghcr.io:443").is_ok());
        assert!(c.admits("ghcr.io:80").is_err());
        // Interior / multiple / portless wildcards are refused at parse.
        let fault = |p: &str| DestPattern::parse(p).map_err(|e| e.fault);
        assert_eq!(fault("a.*.b:443"), Err(DestFault::InteriorWildcard));
        assert_eq!(fault("*.*.com:443"), Err(DestFault::TooManyWildcards));
        assert_eq!(fault("ghcr.io"), Err(DestFault::MissingPort));
        assert_eq!(fault("ghcr.io:0"), Err(DestFault::PortZero));
        assert_eq!(
            fault("ghcr.io:http"),
            Err(DestFault::NotAPort("http".to_owned()))
        );
        assert_eq!(fault(":443"), Err(DestFault::EmptyHost));
        assert_eq!(fault("*.:443"), Err(DestFault::MalformedSuffix));
        // The text names the pattern and the fault, as it did when this was a string.
        assert_eq!(
            DestPattern::parse("ghcr.io:0").map_err(|e| e.to_string()),
            Err("pattern `ghcr.io:0`: port 0".to_owned())
        );
        assert_eq!(Destination::parse("[::1]:443"), Err(DestFault::Ipv6Host));
        assert_eq!(Destination::parse("h"), Err(DestFault::MissingPort));
        // A port is never 0, and prints as its number.
        assert_eq!(Port::parse("0"), Err(DestFault::PortZero));
        assert_eq!(
            Port::parse("65536"),
            Err(DestFault::NotAPort("65536".to_owned()))
        );
        let port = Port::parse("443").expect("443");
        assert_eq!(port.get(), 443);
        assert_eq!(port.to_string(), "443");
        assert_eq!(Destination::parse("h:443").map(|d| d.port), Ok(port));
    }
}
