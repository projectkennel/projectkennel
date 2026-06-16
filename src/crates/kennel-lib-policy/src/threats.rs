//! The machine-readable threat catalogue (`dist/threats/catalogue.toml`).
//!
//! The canonical catalogue is `docs/design/THREATS.md` (prose). This module loads
//! the machine form that `kennel policy risks` maps a policy's `threats` tags
//! against: each entry is an id, family, scope, title, and a one-line distilled
//! residual (the full prose stays in THREATS.md). A CI check keeps the two in sync.
//!
//! The catalogue ships under the deployment data dir and is also **embedded** at
//! build time ([`EMBEDDED`]) so the tooling works from a source checkout with no
//! install — [`Catalogue::load`] reads a path if given, else falls back to the
//! embedded copy.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::PolicyError;

/// The catalogue committed in-tree, compiled into the binary as the fallback when
/// no on-disk catalogue is found. Path is relative to this source file.
pub const EMBEDDED: &str = include_str!("../../../../dist/threats/catalogue.toml");

/// One catalogued threat.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatEntry {
    /// The threat id (`T1.6`, `X9`).
    pub id: String,
    /// The family number (1/2/3/5 in-scope; 4 is the out-of-scope X-series).
    pub family: u8,
    /// `"in"` (addressed) or `"out"` (deliberately out of scope).
    pub scope: String,
    /// The one-line title (matches the THREATS.md heading).
    pub title: String,
    /// A one-line distilled residual; the full prose is in THREATS.md.
    pub residual: String,
}

impl ThreatEntry {
    /// Whether this threat is in scope (a Family 1/2/3/5 threat the framework addresses).
    #[must_use]
    pub fn in_scope(&self) -> bool {
        self.scope == "in"
    }
}

/// The parsed catalogue: a version plus the threats, indexed by id for lookup.
#[derive(Debug, Clone)]
pub struct Catalogue {
    /// The catalogue version (must match the THREATS.md version header).
    pub version: String,
    /// Threats keyed by id, in id order.
    entries: BTreeMap<String, ThreatEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalogue {
    catalogue_version: String,
    #[serde(default, rename = "threat")]
    threats: Vec<ThreatEntry>,
}

impl Catalogue {
    /// Parse catalogue TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Parse`] if the bytes are not a valid catalogue, or if
    /// two entries share an id.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let raw: RawCatalogue =
            basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))?;
        let mut entries = BTreeMap::new();
        for entry in raw.threats {
            if entries.insert(entry.id.clone(), entry.clone()).is_some() {
                return Err(PolicyError::Parse(format!(
                    "duplicate threat id `{}` in the catalogue",
                    entry.id
                )));
            }
        }
        Ok(Self {
            version: raw.catalogue_version,
            entries,
        })
    }

    /// Load the catalogue from `path` if given and readable, else the embedded copy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Parse`] if the chosen source does not parse. A missing
    /// `path` is not an error — it falls back to [`EMBEDDED`].
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, PolicyError> {
        if let Some(p) = path {
            if let Ok(bytes) = std::fs::read(p) {
                return Self::parse(&bytes);
            }
        }
        Self::parse(EMBEDDED.as_bytes())
    }

    /// The embedded catalogue (no disk access). Infallible at runtime: a malformed
    /// embedded catalogue would fail the crate's own tests.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Parse`] only if the compiled-in catalogue is malformed
    /// (caught by `embedded_catalogue_parses`).
    pub fn embedded() -> Result<Self, PolicyError> {
        Self::parse(EMBEDDED.as_bytes())
    }

    /// Look up a threat by id.
    #[must_use]
    pub fn lookup(&self, id: &str) -> Option<&ThreatEntry> {
        self.entries.get(id)
    }

    /// All entries, in id order.
    pub fn entries(&self) -> impl Iterator<Item = &ThreatEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalogue_parses_and_is_nonempty() {
        let cat = Catalogue::embedded().expect("embedded catalogue must parse");
        assert_eq!(cat.version, "0.3");
        assert!(
            cat.entries().count() >= 29,
            "expected the in-scope families"
        );
    }

    #[test]
    fn lookup_finds_a_known_threat_with_residual() {
        let cat = Catalogue::embedded().expect("parse");
        let t = cat.lookup("T1.6").expect("T1.6 present");
        assert!(t.in_scope());
        assert_eq!(t.family, 1);
        assert!(t.title.contains("Lateral movement"));
        assert!(!t.residual.is_empty());
    }

    #[test]
    fn out_of_scope_entries_are_marked() {
        let cat = Catalogue::embedded().expect("parse");
        let x = cat.lookup("X9").expect("X9 present");
        assert!(!x.in_scope());
        assert_eq!(x.family, 4);
    }

    #[test]
    fn unknown_id_is_none() {
        let cat = Catalogue::embedded().expect("parse");
        assert!(cat.lookup("T99.99").is_none());
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let dup = b"catalogue_version = \"x\"\n\
            [[threat]]\nid=\"T1.1\"\nfamily=1\nscope=\"in\"\ntitle=\"a\"\nresidual=\"r\"\n\
            [[threat]]\nid=\"T1.1\"\nfamily=1\nscope=\"in\"\ntitle=\"b\"\nresidual=\"r\"\n";
        assert!(Catalogue::parse(dup).is_err());
    }
}
