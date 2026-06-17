//! The `[audit]` schema and its translation into the settled [`AuditRuntime`].
//!
//! This is the **single source of truth** for audit configuration: the source
//! `[audit]` section shape, the validation (sink names, per-class levels, sizes,
//! the syslog facility), and the defaults. Both the policy compiler (a policy's
//! `[audit]` section, via [`crate::translate`]) and the runtime (a standalone
//! `audit.toml` defaults file, which `kenneld` reads to resolve sinks) flow
//! through [`translate_audit_section`] here — they differ only in how a file
//! `dir` placeholder is substituted, which the caller supplies as a closure.
//!
//! It lives in the runtime crate (not the compiler) because `kenneld` needs
//! [`parse_audit_defaults`] at spawn time, and the daemon must not link the
//! policy compiler (CODING-STANDARDS.md §3/§5: keep the TCB minimal).

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;
use crate::settled::{AuditFileConfig, AuditRuntime, AuditSinkKind};

/// Accepted per-class audit levels.
const AUDIT_LEVELS: [&str; 4] = ["off", "denies-only", "summary", "full"];
/// Accepted syslog facilities.
const SYSLOG_FACILITIES: [&str; 20] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

/// `[audit]`: sink selection, per-class levels, and per-sink tuning
/// (`docs/architecture/02-3-audit-schema.md` §Sink configuration). Levels and
/// sink names are validated at translate time.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Active sinks (`file`, `journald`, `syslog`, `stdout`). Default `["file"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<String>,
    /// `[audit.file]` tuning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<AuditFileSection>,
    /// `[audit.syslog]` tuning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog: Option<AuditSyslogSection>,
    /// `[audit.journald]` — no fields; present to allow the empty table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journald: Option<AuditEmptySection>,
    /// `[audit.stdout]` — no fields; present to allow the empty table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<AuditEmptySection>,
    /// `[audit.network]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<AuditClassSection>,
    /// `[audit.filesystem]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<AuditClassSection>,
    /// `[audit.exec]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<AuditClassSection>,
    /// `[audit.unix]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<AuditClassSection>,
    /// `[audit.dbus]` level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbus: Option<AuditClassSection>,
}

/// `[audit.file]`: file-sink tuning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileSection {
    /// Override the per-kennel directory (placeholders allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Rotate at this size (e.g. `"64M"`, `"1G"`; bare = bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_at_bytes: Option<String>,
    /// Gzip a rotated file this many seconds after rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress_after_seconds: Option<u64>,
    /// Keep at most this many rotated files per class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_count: Option<u64>,
}

/// `[audit.syslog]`: syslog-sink tuning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSyslogSection {
    /// Syslog facility (`user`, `daemon`, `auth`, …). Default `user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<String>,
}

/// A `[audit.<class>]` level sub-table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditClassSection {
    /// One of `off`, `denies-only`, `summary`, `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// An empty `[audit.*]` table (journald, stdout: no fields).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEmptySection {}

/// Build a translation [`PolicyError`].
const fn translation(msg: String) -> PolicyError {
    PolicyError::Translation(msg)
}

/// Translate one `[audit]` section — a policy's, or a standalone `audit.toml`
/// defaults file — into the settled [`AuditRuntime`].
///
/// `dir_subst` substitutes a file-sink `dir` placeholder: the compiler passes its
/// deferred-placeholder substitution; [`parse_audit_defaults`] passes identity
/// (a standalone `audit.toml` keeps `dir` literal — `kenneld` roots the file sink
/// at the per-kennel state dir regardless). This is the one implementation both
/// callers share, so the defaults cannot diverge.
///
/// # Errors
///
/// [`PolicyError::Translation`] for an unknown sink, level, or syslog facility, or
/// a malformed `rotate_at_bytes` size.
pub fn translate_audit_section(
    audit: &AuditSection,
    mut dir_subst: impl FnMut(&str) -> String,
) -> Result<AuditRuntime, PolicyError> {
    let mut sinks = Vec::new();
    for name in &audit.sinks {
        let kind = match name.as_str() {
            "file" => AuditSinkKind::File,
            "journald" => AuditSinkKind::Journald,
            "syslog" => AuditSinkKind::Syslog,
            "stdout" => AuditSinkKind::Stdout,
            other => {
                return Err(translation(format!(
                    "unknown audit sink `{other}` (expected file/journald/syslog/stdout)"
                )))
            }
        };
        if !sinks.contains(&kind) {
            sinks.push(kind);
        }
    }

    let level = |class: &Option<AuditClassSection>| -> Result<Option<String>, PolicyError> {
        match class.as_ref().and_then(|c| c.level.as_ref()) {
            None => Ok(None),
            Some(l) if AUDIT_LEVELS.contains(&l.as_str()) => Ok(Some(l.clone())),
            Some(l) => Err(translation(format!(
                "unknown audit level `{l}` (expected off/denies-only/summary/full)"
            ))),
        }
    };

    let syslog_facility = match audit.syslog.as_ref().and_then(|s| s.facility.as_ref()) {
        None => None,
        Some(f) if SYSLOG_FACILITIES.contains(&f.as_str()) => Some(f.clone()),
        Some(f) => {
            return Err(translation(format!(
                "unknown syslog facility `{f}` (expected user/daemon/auth/local0-7/…)"
            )))
        }
    };

    let file = match &audit.file {
        None => AuditFileConfig::default(),
        Some(f) => AuditFileConfig {
            dir: f.dir.as_ref().map(|d| dir_subst(d)),
            rotate_at_bytes: match &f.rotate_at_bytes {
                None => None,
                Some(s) => Some(parse_size_bytes(s)?),
            },
            compress_after_seconds: f.compress_after_seconds,
            retain_count: f.retain_count,
        },
    };

    Ok(AuditRuntime {
        sinks,
        network_level: level(&audit.network)?,
        filesystem_level: level(&audit.filesystem)?,
        exec_level: level(&audit.exec)?,
        unix_level: level(&audit.unix)?,
        dbus_level: level(&audit.dbus)?,
        syslog_facility,
        file,
    })
}

/// Parse a standalone `audit.toml` defaults file into an [`AuditRuntime`].
///
/// The file body is the `[audit]` section content at top level (`sinks`,
/// `[file]`, `[network]`/`[filesystem]`/…), validated exactly as a policy's
/// `[audit]` section is. For the installation-wide `/etc/kennel/audit.toml` and
/// the per-user override (`08` §8.1). `dir` placeholders are left literal —
/// `kenneld` roots the file sink at the per-kennel state dir regardless.
///
/// # Errors
///
/// [`PolicyError::Parse`] if the TOML is malformed, or a translation error for an
/// unknown sink/level/facility or a malformed size.
pub fn parse_audit_defaults(toml: &str) -> Result<AuditRuntime, PolicyError> {
    let section: AuditSection =
        basic_toml::from_str(toml).map_err(|e| PolicyError::Parse(e.to_string()))?;
    translate_audit_section(&section, str::to_owned)
}

/// Parse a human byte size (`"64M"`, `"1G"`, `"512K"`, bare = bytes) into bytes.
fn parse_size_bytes(s: &str) -> Result<u64, PolicyError> {
    let bad = || {
        translation(format!(
            "size `{s}` is not a number with an optional K/M/G suffix"
        ))
    };
    let trimmed = s.trim();
    // (suffix-pair, multiplier), largest first; bare number is bytes.
    let units: [([char; 2], u64); 3] = [
        (['G', 'g'], 1024 * 1024 * 1024),
        (['M', 'm'], 1024 * 1024),
        (['K', 'k'], 1024),
    ];
    let mut num = trimmed;
    let mut mult = 1_u64;
    for (suffix, factor) in units {
        if let Some(stripped) = trimmed.strip_suffix(suffix) {
            num = stripped;
            mult = factor;
            break;
        }
    }
    let value = num.trim().parse::<u64>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    // `AuditSection`/`parse_audit_defaults` from this module, plus the settled
    // `AuditFileConfig`/`AuditSinkKind`/`AuditRuntime` it imports, all via the glob.
    use super::*;

    #[test]
    fn audit_defaults_file_parses_the_section_body_at_top_level() {
        // A standalone audit.toml: the [audit] body without the [audit] wrapper.
        let rt = parse_audit_defaults(
            r#"
            sinks = ["journald"]
            [network]
            level = "full"
            [file]
            rotate_at_bytes = "128M"
            compress_after_seconds = 3600
            "#,
        )
        .expect("parse defaults");
        assert_eq!(rt.sinks, vec![AuditSinkKind::Journald]);
        assert_eq!(rt.network_level.as_deref(), Some("full"));
        assert_eq!(rt.file.rotate_at_bytes, Some(128 * 1024 * 1024));
        assert_eq!(rt.file.compress_after_seconds, Some(3600));
    }

    #[test]
    fn audit_defaults_file_rejects_bad_values() {
        assert!(parse_audit_defaults("sinks = [\"smtp\"]").is_err());
        assert!(parse_audit_defaults("[file]\nrotate_at_bytes = \"big\"").is_err());
        assert!(parse_audit_defaults("not = valid = toml").is_err());
    }

    #[test]
    fn overlay_lets_the_higher_layer_win_per_field() {
        // The defaults file uses the source `[audit]`-section shape: the facility
        // is `[syslog] facility`, not the settled flat `syslog_facility`.
        let base = parse_audit_defaults(
            "sinks = [\"journald\"]\n[syslog]\nfacility = \"local0\"\n[file]\nretain_count = 8",
        )
        .expect("base");
        let over = AuditRuntime {
            network_level: Some("full".to_owned()),
            file: AuditFileConfig {
                retain_count: Some(2),
                ..AuditFileConfig::default()
            },
            ..AuditRuntime::default()
        };
        let merged = base.overlay(&over);
        // over wins where set:
        assert_eq!(merged.network_level.as_deref(), Some("full"));
        assert_eq!(merged.file.retain_count, Some(2));
        // base survives where over is unset:
        assert_eq!(merged.sinks, vec![AuditSinkKind::Journald]);
        assert_eq!(merged.syslog_facility.as_deref(), Some("local0"));
        // an empty `over.sinks` does not clobber the base sinks:
        assert!(!merged.sinks.is_empty());
    }
}
