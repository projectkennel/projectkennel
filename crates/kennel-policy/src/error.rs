//! The crate's top-level error type.

use crate::invariant::InvariantViolation;
use crate::signature::SignatureError;

/// Everything that can go wrong loading or verifying a settled policy.
#[derive(Debug)]
pub enum PolicyError {
    /// The document could not be parsed.
    Parse(String),
    /// The body could not be serialised to its canonical form.
    Canonical(String),
    /// Signature verification failed.
    Signature(SignatureError),
    /// The settled-policy schema version is newer than this build accepts.
    UnsupportedSchemaVersion {
        /// The version found in the document.
        found: u32,
        /// The newest version this build accepts.
        max: u32,
    },
    /// One or more framework invariants were violated.
    InvariantViolations(Vec<InvariantViolation>),
    /// A source policy failed schema validation (identity, reference grammar, or
    /// a missing `reason`). Carries one human-readable message per problem found.
    SourceValidation(Vec<String>),
    /// Template-chain resolution failed: a reference was malformed, not found in
    /// the search path, formed a cycle, or exceeded the depth bound.
    Resolution(String),
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "parse error: {m}"),
            Self::Canonical(m) => write!(f, "canonical-form error: {m}"),
            Self::Signature(e) => write!(f, "signature: {e}"),
            Self::UnsupportedSchemaVersion { found, max } => {
                write!(f, "settled_schema_version {found} is newer than supported maximum {max}")
            }
            Self::InvariantViolations(vs) => {
                write!(f, "framework invariant violations:")?;
                for v in vs {
                    write!(f, " [{}: {}]", v.id, v.detail)?;
                }
                Ok(())
            }
            Self::SourceValidation(ms) => {
                write!(f, "source-policy validation failed:")?;
                for m in ms {
                    write!(f, " [{m}]")?;
                }
                Ok(())
            }
            Self::Resolution(m) => write!(f, "template resolution failed: {m}"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signature(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SignatureError> for PolicyError {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}
