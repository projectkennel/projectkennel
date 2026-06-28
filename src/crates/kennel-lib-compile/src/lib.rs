//! Project Kennel policy compiler (the authoring front end).
//!
//! # Purpose
//!
//! Turn a **source** policy — a template, or a leaf with `+=`/`-=` deltas — into
//! the signed **settled** artefact the runtime enforces. The stages: parse and
//! validate the [`source`](mod@source) schema, walk and fold the template chain
//! ([`resolve`](mod@resolve)), apply [`leaf`] deltas, then
//! [`translate`](mod@translate)-and-substitute to the settled form and sign.
//! [`compile`](mod@compile) and [`compile_leaf`] orchestrate them; [`lint`] and
//! [`risks`] are the inspection tools; [`lock`] pins each resolved reference;
//! [`source_sig`] signs/verifies templates and fragments.
//!
//! # Relationship to `kennel-lib-policy`
//!
//! This crate depends on the runtime [`kennel_lib_policy`] crate for the settled
//! artefact types it produces, the signature/canonical/keys crypto it signs
//! through, the invariant validator, and the shared `audit` schema. The split is
//! deliberate: only the `kennel` CLI links this compiler, so its parsing and
//! resolution machinery stays out of the daemon's TCB (the daemon links only the
//! runtime crate, which verifies-and-loads). The dependency is one-directional:
//! authoring depends on runtime, never the reverse.
//!
//! # Threat bearing
//!
//! Resolution is the supply-chain choke point: every template/fragment is parsed,
//! validated, and signature-checked against the trust store before its bytes are
//! folded in. Cycles, over-deep chains, and missing references are hard errors.
//!
//! # Non-goals
//!
//! I/O-free by construction: callers supply a [`resolve::TemplateSource`] that maps
//! a reference to bytes. This crate does not verify a *settled* policy at spawn
//! time (that is [`kennel_lib_policy::verify_settled`]) and does not enforce policy.

#![forbid(unsafe_code)]

pub mod binder;
pub mod compile;
pub mod dev;
pub mod diff;
pub mod identity;
pub mod leaf;
pub mod lint;
pub mod lock;
pub mod mesh;
pub mod resolve;
pub mod risks;
pub mod source;
pub mod source_sig;
pub mod spawn;
pub mod ssh;
pub mod threats;
pub mod translate;
pub mod unix;
pub mod version;

pub use compile::{compile, compile_leaf, effective_source, seal_unsigned, Compiled};
pub use leaf::{parse as parse_leaf, LeafPolicy};
pub use lint::lint_settled;
pub use lock::{LockEntry, Lockfile};
pub use resolve::{resolve, resolve_verified, ChainLink, ResolvedChain, TemplateSource};
pub use source::{
    parse as parse_source, BpfRule, NetAllow, NetBpf, NetBpfAcl, NetDenyRule, NetProxy,
    NetProxyDeny, NetSection, SourcePolicy,
};
pub use source_sig::{
    canonical_leaf, canonical_source, sign_leaf, sign_source, verify_self, verify_source, Signable,
    SignatureMode, Trust,
};
pub use translate::{translate, Translated};
pub use version::{is_newer as version_is_newer, parse_reference};

/// Shared test fixtures: the shipped fragments the reference templates `include`. Test
/// `TemplateSource`s serve these (in addition to `base-confined`) so a retrofitted template's
/// includes resolve under `Trust::dev`. Kept in one place so adding a fragment a template uses
/// updates every test source at once.
#[cfg(test)]
pub(crate) const TEST_FRAGMENTS: &[(&str, &str)] = &[
    (
        "core-shell",
        include_str!("../../../../fragments/core-shell/policy.toml"),
    ),
    (
        "core-coreutils",
        include_str!("../../../../fragments/core-coreutils/policy.toml"),
    ),
    (
        "core-file-mutation",
        include_str!("../../../../fragments/core-file-mutation/policy.toml"),
    ),
    (
        "core-archive",
        include_str!("../../../../fragments/core-archive/policy.toml"),
    ),
    (
        "net-clients",
        include_str!("../../../../fragments/net-clients/policy.toml"),
    ),
    (
        "toolchain-c",
        include_str!("../../../../fragments/toolchain-c/policy.toml"),
    ),
    (
        "vcs-git",
        include_str!("../../../../fragments/vcs-git/policy.toml"),
    ),
];
