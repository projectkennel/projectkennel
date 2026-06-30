//! Compile-time **local** validation of the `[[provides]]` / `[[consumes]]` mesh surface.
//!
//! Only what is checkable from the one policy in hand plus its signature provenance:
//! well-formedness, the reserved-namespace gate, and a duplicate `name` within *this* policy.
//! Cross-kennel resolution — does a consume's `name` resolve to a provider of the matching shape
//! — is a **runtime** act (the broker against the live catalogue) and is never attempted here:
//! the compiler only ever holds one policy.
//!
//! The reserved-namespace gate is **tier-aware and authoritative here**: a reserved name
//! may be claimed only through a template chain that verified at the tier the name requires —
//! `org.projectkennel.*` at vendor (maintainer) tier, a host `[[reserved]]` prefix at host tier — and
//! *any key at that tier is equivalent*. The [`ReservedAuthority`] the caller computes from the
//! signature provenance ([`crate::resolve::ProvidesOrigin`]) carries the declaring tier; this is the
//! sole authorizer. The daemon does **not** re-check provenance at runtime — it trusts the settled
//! signature it verifies (a trusted-key signature is the whole boundary); a holder of a
//! trusted key could re-sign a forged settled regardless, so a runtime tier-check would only be
//! theatre against the trust root.
//!
//! Validation runs on the *resolved* policy. Errors fail the compile; there are no footgun
//! warnings for this surface, so success returns an empty warning list, kept `Vec<String>`
//! for a uniform caller signature with the other source-section validators.

use std::collections::BTreeSet;

use crate::source::{Shape, SourcePolicy};
use crate::source_sig::Tier;
use kennel_lib_config::ReservedNamespace;
use kennel_lib_policy::settled::RESERVED_PREFIX;
use kennel_lib_policy::PolicyError;

/// The tier-aware reserved-namespace authority, resolved at compile.
///
/// A reserved capability `name` may be provided only through a template chain that verified at the
/// tier the name requires — `org.projectkennel.*` at [`Tier::Vendor`], a host `[[reserved]]` prefix
/// at [`Tier::Host`] — and **any key at that tier is equivalent**: the authority is the tier, never
/// an identity. `declaring_tier` is the tier conferring this policy's `[[provides]]` (the ancestor
/// template's verified tier, or the output `--key`'s tier for an entry-authored provide), or `None`
/// (User-equivalent → claims nothing reserved). `enforce` is false in development (no trust store),
/// where every name is permitted.
pub struct ReservedAuthority<'a> {
    /// Whether to enforce the gate; `false` in development (no trust store) permits everything.
    pub enforce: bool,
    /// The tier conferring this policy's provides, or `None` if unverified / no output signer.
    pub declaring_tier: Option<Tier>,
    /// The host-declared reserved namespaces; a name under one is gated at [`Tier::Host`].
    pub reserved: &'a [ReservedNamespace],
}

impl ReservedAuthority<'_> {
    /// The tier a reserved `name` requires, or `None` when it is unreserved (free to any signer).
    fn required_tier(&self, name: &str) -> Option<Tier> {
        if name.starts_with(RESERVED_PREFIX) {
            Some(Tier::Vendor)
        } else if self.reserved.iter().any(|ns| name.starts_with(&ns.prefix)) {
            Some(Tier::Host)
        } else {
            None
        }
    }

    /// Whether the declaring tier may claim `name` (an unreserved name is always permitted).
    fn permits(&self, name: &str) -> bool {
        if !self.enforce {
            return true;
        }
        self.required_tier(name)
            .is_none_or(|req| self.declaring_tier.is_some_and(|t| t >= req))
    }
}

/// The per-capability directory component for a provide rendezvous: `<name>`, or `<name>.<key>` when
/// a private key is set.
fn provide_dir_component(name: &str, key: Option<&str>) -> String {
    key.map_or_else(|| name.to_owned(), |k| format!("{name}.{k}"))
}

/// The default in-view `endpoint` for an `af-unix` provide that omits one: a `sock` socket
/// in a per-capability `/run` subdirectory `kenneld` binds its rendezvous directory at.
#[must_use]
pub fn default_af_unix_endpoint(name: &str, key: Option<&str>) -> String {
    format!("/run/{}/sock", provide_dir_component(name, key))
}

/// Whether an author-supplied `af-unix` `endpoint` is a safe rendezvous bind target: absolute, under
/// `/run`, with a subdirectory (so `dirname(endpoint)` is a `/run` subdir, never bare `/run`), and no
/// `..` traversal.
fn af_unix_endpoint_under_run(endpoint: &str) -> bool {
    let path = std::path::Path::new(endpoint);
    path.is_absolute()
        && path.starts_with("/run")
        && path.components().count() >= 4
        && !path
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new(".."))
}

/// Validate the `[[provides]]` / `[[consumes]]` entries of a resolved source policy.
///
/// `authority` is the tier-aware reserved-namespace gate: a reserved name may be claimed
/// only through a template chain that verified at the tier the name requires. Returns every problem
/// found, not just the first. On success returns an empty warning list.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] carrying one message per problem: a missing
/// `name`/`shape`/`endpoint`/`reason`, a reserved name claimed by a policy not permitted to, or a
/// duplicate provide `name`.
pub fn validate(
    policy: &SourcePolicy,
    authority: &ReservedAuthority<'_>,
) -> Result<Vec<String>, PolicyError> {
    let mut errs: Vec<String> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for p in &policy.provides {
        match p.name.as_deref() {
            None | Some("") => errs.push("[[provides]] entry is missing `name`".to_owned()),
            Some(name) => {
                if !authority.permits(name) {
                    errs.push(format!(
                        "[[provides]] `{name}` is a reserved capability name: it may be claimed only \
                         through a template signed at the tier the name requires — \
                         `{RESERVED_PREFIX}*` needs a vendor (maintainer) template, a host \
                         `[[reserved]]` name a host template; an unreserved name is free to any \
                         signed template"
                    ));
                }
                if !seen.insert(name) {
                    errs.push(format!(
                        "[[provides]] `{name}` is declared more than once in this policy \
                         (duplicate provide)"
                    ));
                }
            }
        }
        if p.shape.is_none() {
            errs.push(format!(
                "[[provides]] `{}` is missing `shape`",
                who(p.name.as_deref())
            ));
        }
        // An `af-unix` endpoint is optional — `kenneld` defaults it to `/run/<name>[.key]/sock`. When supplied, it must be a safe rendezvous bind target: absolute, under `/run`,
        // with a subdirectory, since construction binds `dirname(endpoint)` into the view. Other
        // shapes author a required `endpoint` (a bus name, a node).
        match p.shape {
            Some(Shape::AfUnix) => {
                if let Some(e) = p
                    .endpoint
                    .as_deref()
                    .filter(|e| !af_unix_endpoint_under_run(e))
                {
                    errs.push(format!(
                        "[[provides]] `{}` endpoint `{e}` must be an absolute path under `/run` with \
                         a subdirectory (e.g. `/run/<dir>/<sock>`) — `kenneld` binds \
                         `dirname(endpoint)` at construction; omit it for the \
                         `/run/<name>[.key]/sock` default",
                        who(p.name.as_deref())
                    ));
                }
            }
            // Other (deferred) shapes author a required `endpoint` (a bus name, a node).
            Some(_) if p.endpoint.as_deref().unwrap_or("").is_empty() => errs.push(format!(
                "[[provides]] `{}` is missing `endpoint`",
                who(p.name.as_deref())
            )),
            _ => {} // valid af-unix endpoint, a present other-shape endpoint, or a missing shape
        }
        if p.reason.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[provides]] `{}` is missing a `reason`",
                who(p.name.as_deref())
            ));
        }
    }

    for c in &policy.consumes {
        if c.name.as_deref().unwrap_or("").is_empty() {
            errs.push("[[consumes]] entry is missing `name`".to_owned());
        }
        if c.shape.is_none() {
            errs.push(format!(
                "[[consumes]] `{}` is missing `shape`",
                who(c.name.as_deref())
            ));
        }
        if c.reason.as_deref().unwrap_or("").is_empty() {
            errs.push(format!(
                "[[consumes]] `{}` is missing a `reason`",
                who(c.name.as_deref())
            ));
        }
    }

    if errs.is_empty() {
        Ok(Vec::new())
    } else {
        Err(PolicyError::SourceValidation(errs))
    }
}

/// A display handle for an entry whose `name` may be absent or empty.
fn who(name: Option<&str>) -> &str {
    name.filter(|s| !s.is_empty()).unwrap_or("(unnamed)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{ConsumesEntry, ProvidesEntry, Shape};

    fn policy_with(provides: Vec<ProvidesEntry>, consumes: Vec<ConsumesEntry>) -> SourcePolicy {
        SourcePolicy {
            provides,
            consumes,
            ..SourcePolicy::default()
        }
    }

    fn provide(name: &str) -> ProvidesEntry {
        // A well-formed af-unix provide omits `endpoint`: kenneld defaults it.
        ProvidesEntry {
            name: Some(name.to_owned()),
            shape: Some(Shape::AfUnix),
            reason: Some("a reason".to_owned()),
            ..ProvidesEntry::default()
        }
    }

    fn consume(name: &str) -> ConsumesEntry {
        ConsumesEntry {
            name: Some(name.to_owned()),
            shape: Some(Shape::AfUnix),
            reason: Some("a reason".to_owned()),
            ..ConsumesEntry::default()
        }
    }

    /// An authority that permits a vendor-reserved name: declaring tier is vendor.
    fn permitted() -> ReservedAuthority<'static> {
        ReservedAuthority {
            enforce: true,
            declaring_tier: Some(Tier::Vendor),
            reserved: &[],
        }
    }

    /// An authority that refuses any reserved name: a user-equivalent (unverified) declaring tier.
    fn refused() -> ReservedAuthority<'static> {
        ReservedAuthority {
            enforce: true,
            declaring_tier: None,
            reserved: &[],
        }
    }

    fn err_has(policy: &SourcePolicy, authority: &ReservedAuthority<'_>, needle: &str) -> bool {
        matches!(
            validate(policy, authority),
            Err(PolicyError::SourceValidation(ref m)) if m.iter().any(|s| s.contains(needle))
        )
    }

    #[test]
    fn empty_is_vacuously_valid() {
        validate(&SourcePolicy::default(), &refused()).expect("vacuously valid");
    }

    #[test]
    fn well_formed_provide_and_consume_validate() {
        let p = policy_with(vec![provide("build-cache")], vec![consume("metrics")]);
        assert!(validate(&p, &refused()).expect("valid").is_empty());
    }

    #[test]
    fn an_unreserved_provide_accepts_even_when_reserved_is_not_permitted() {
        // Anyone may author and sign a template for an unreserved name (e.g. `doe.john.cache`):
        // the reserved gate never touches it, regardless of `reserved_permitted`.
        let p = policy_with(vec![provide("doe.john.cache")], vec![]);
        assert!(validate(&p, &refused()).expect("valid").is_empty());
    }

    #[test]
    fn a_reserved_name_rejects_when_not_permitted() {
        // A reserved name from a non-maintainer-signed origin (the caller computes
        // `reserved_permitted = false`) is refused.
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(err_has(&p, &refused(), "reserved"));
        assert!(err_has(&p, &refused(), "vendor (maintainer) template"));
    }

    #[test]
    fn a_reserved_name_accepts_when_permitted() {
        // Permitted (the caller traced it to a maintainer-signed template, or development).
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        assert!(validate(&p, &permitted())
            .expect("valid when reserved is permitted")
            .is_empty());
    }

    #[test]
    fn org_projectkennel_needs_vendor_tier_a_host_template_cannot_claim_it() {
        // The built-in `org.projectkennel.*` namespace is vendor-only: a host-tier template is refused.
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        let host = ReservedAuthority {
            enforce: true,
            declaring_tier: Some(Tier::Host),
            reserved: &[],
        };
        assert!(err_has(&p, &host, "vendor (maintainer) template"));
        // A vendor-tier template may; any vendor key is equivalent (the tier is the authority).
        assert!(validate(&p, &permitted()).expect("vendor ok").is_empty());
    }

    #[test]
    fn a_host_reserved_name_is_gated_at_host_tier() {
        let reserved = vec![ReservedNamespace {
            prefix: "com.acme.".to_owned(),
            keys: vec![],
        }];
        let p = policy_with(vec![provide("com.acme.bus")], vec![]);
        let at = |tier| ReservedAuthority {
            enforce: true,
            declaring_tier: Some(tier),
            reserved: &reserved,
        };
        // User-tier cannot claim a host-reserved name; host- and vendor-tier can (Vendor >= Host).
        assert!(err_has(&p, &at(Tier::User), "reserved"));
        assert!(validate(&p, &at(Tier::Host)).expect("host ok").is_empty());
        assert!(validate(&p, &at(Tier::Vendor))
            .expect("vendor ok")
            .is_empty());
        // The same name is unreserved when no `[[reserved]]` table declares its prefix.
        let bare = ReservedAuthority {
            enforce: true,
            declaring_tier: Some(Tier::User),
            reserved: &[],
        };
        assert!(validate(&p, &bare)
            .expect("unreserved without a table")
            .is_empty());
    }

    #[test]
    fn dev_mode_permits_any_reserved_name() {
        // No trust store (authoring) ⇒ the gate does not enforce.
        let p = policy_with(vec![provide("org.projectkennel.wayland")], vec![]);
        let dev = ReservedAuthority {
            enforce: false,
            declaring_tier: None,
            reserved: &[],
        };
        assert!(validate(&p, &dev).expect("dev permits").is_empty());
    }

    #[test]
    fn a_duplicate_provide_name_rejects() {
        let p = policy_with(vec![provide("build-cache"), provide("build-cache")], vec![]);
        assert!(err_has(&p, &refused(), "duplicate"));
    }

    #[test]
    fn a_missing_provide_name_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                name: None,
                ..provide("x")
            }],
            vec![],
        );
        assert!(err_has(&p, &refused(), "missing `name`"));
    }

    #[test]
    fn a_missing_provide_shape_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                shape: None,
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(err_has(&p, &refused(), "missing `shape`"));
    }

    #[test]
    fn an_omitted_af_unix_endpoint_is_valid_and_defaults() {
        // af-unix may omit `endpoint`; kenneld defaults it to /run/<name>[.key]/sock.
        let p = policy_with(vec![provide("build-cache")], vec![]);
        assert!(validate(&p, &refused()).expect("valid").is_empty());
        assert_eq!(
            default_af_unix_endpoint("build-cache", None),
            "/run/build-cache/sock"
        );
        assert_eq!(
            default_af_unix_endpoint("org.x.wl", Some("K1")),
            "/run/org.x.wl.K1/sock"
        );
    }

    #[test]
    fn an_af_unix_endpoint_outside_run_rejects() {
        for bad in [
            "/tmp/x.sock",
            "$XDG_RUNTIME_DIR/x",
            "/run/x.sock",
            "/run/../etc/x/y",
        ] {
            let p = policy_with(
                vec![ProvidesEntry {
                    endpoint: Some((*bad).to_owned()),
                    ..provide("build-cache")
                }],
                vec![],
            );
            assert!(
                err_has(&p, &refused(), "under `/run`"),
                "endpoint {bad} should be rejected"
            );
        }
    }

    #[test]
    fn an_af_unix_endpoint_under_run_with_a_subdir_is_accepted() {
        let p = policy_with(
            vec![ProvidesEntry {
                endpoint: Some("/run/mesh/echo.sock".to_owned()),
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(validate(&p, &refused()).expect("valid").is_empty());
    }

    #[test]
    fn a_missing_provide_reason_rejects() {
        let p = policy_with(
            vec![ProvidesEntry {
                reason: None,
                ..provide("build-cache")
            }],
            vec![],
        );
        assert!(err_has(&p, &refused(), "missing a `reason`"));
    }

    #[test]
    fn a_missing_consume_shape_rejects() {
        let p = policy_with(
            vec![],
            vec![ConsumesEntry {
                shape: None,
                ..consume("metrics")
            }],
        );
        assert!(err_has(&p, &refused(), "missing `shape`"));
    }
}
