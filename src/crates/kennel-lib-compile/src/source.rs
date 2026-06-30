//! The source-policy schema — what an operator (or a template author) writes.
//!
//! # Purpose
//!
//! This is the **input** to `kennel compile`: a template or leaf policy as authored
//! in TOML. It is the
//! rich, human-facing surface — every resource section (`exec`, `fs`, `net`, `unix`,
//! `ssh`, `env`, `cap`, `seccomp`, `proc`, `ptrace`, `signal`,
//! `lifecycle`), identity and inheritance (`template_base`, `template_name`, `name`,
//! `include`), and signing metadata. The compiler resolves a chain of these into the
//! flat [`kennel_lib_policy::settled::SettledPolicy`] the runtime enforces.
//!
//! # Invariants
//!
//! - Every struct is `#[serde(deny_unknown_fields)]`: an unrecognised key is a hard
//!   parse error. The schema is the allowlist.
//! - All section fields are optional. A section absent from a file contributes
//!   nothing; presence is what a delta/merge step (the resolver) acts on. Faithful
//!   *parsing* is this module's job; *composition* is the resolver's (`source.rs`
//!   stays I/O-free and merge-free).
//! - Paths are carried verbatim as strings. Tilde/`<…>` expansion happens later, and
//!   only after signature verification — never at parse time.
//!
//! # Threat bearing
//!
//! `deny_unknown_fields` is a supply-chain control: a template that smuggles an
//! unknown key (a typo'd `deny` that silently does nothing, or a future field an old
//! binary would ignore) is rejected rather than under-enforced. [`SourcePolicy::validate`]
//! additionally requires a `reason` on every capability-granting entry, so a grant
//! cannot enter a policy without recorded intent.
//!
//! # Non-goals
//!
//! A template and a leaf are the one [`SourcePolicy`] type. Each list field parses as either the
//! bare-sequence **replace** form (`fs.read = ["…"]`, the template direct form) or the `{ add, remove }`
//! **increment** form (`[[fs.read.add]]`, the `+=` / `-=` leaf/fragment delta) at the same key —
//! [`PathField`] / [`ListField`] choose by TOML shape. Applying the increments (folding a delta onto
//! the inherited list) is the resolver's job ([the resolver](mod@crate::resolve)); this module only *parses* them.

use kennel_lib_policy::audit::AuditSection;
use kennel_lib_policy::signature::SignatureEnvelope;
use kennel_lib_policy::PolicyError;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A parsed source policy: a template or a leaf, before resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
#[cfg_attr(feature = "schema", schema(rename = "policy"))]
pub struct SourcePolicy {
    /// Reference to the parent template by name. Absent only for the root template
    /// (`base-confined`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_base: Option<String>,
    /// The template's own name. Present on templates, absent on leaf policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    /// The kennel name. Present on leaf policies, absent on templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Additional signed fragments composed additively, referenced by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// The `THREATS.md` catalogue version this artefact was authored against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_catalogue_version: Option<String>,
    /// The signature envelope over the artefact's canonical content. Required for
    /// templates and fragments; optional for leaf policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,

    /// Capability section (`[cap]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<CapSection>,
    /// Execution section (`[exec]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSection>,
    /// Filesystem section (`[fs]` and `[fs.*]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FsSection>,
    /// Network section (`[net]` and `[net.*]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetSection>,
    /// `AF_UNIX` section (`[unix]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixSection>,
    /// SSH egress section (`[ssh]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshSection>,
    /// Identity section (`[identity]`): the supplementary groups carried in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentitySection>,
    /// `[[provides]]`: capabilities this kennel offers to other kennels over the mesh.
    /// Top-level; each entry names a capability and its typed shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<ProvidesEntry>,
    /// `[[consumes]]`: capabilities this kennel reaches over the mesh.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumes: Vec<ConsumesEntry>,
    /// `[service]`: the supervision discipline for a service kennel: the restart policy
    /// `kenneld` applies once the operator enables this provider. Meaningful on a kennel with
    /// `[[provides]]`; folds scalar-wins up the chain like `[lifecycle]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceSection>,
    /// `[unsafe]`: advisory footgun sub-sections whose scoping is real but enforced
    /// elsewhere (the PID namespace + seccomp), not by the section. Grouped under one
    /// `[unsafe]` umbrella so an author sees they are in footgun territory; each
    /// present sub-section is warned at compile (`footgun-warn-dont-forbid`).
    #[serde(default, rename = "unsafe", skip_serializing_if = "Option::is_none")]
    pub unsafe_section: Option<UnsafeSection>,
    /// Environment section (`[env]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvSection>,
    /// Seccomp section (`[seccomp]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<SeccompSection>,
    /// Lifecycle section (`[lifecycle]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleSection>,
    /// Audit section (`[audit]` and `[audit.*]`): sinks and per-class levels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSection>,
    /// Resource limits (`[ulimits]`): a table of `name = "value"` pairs applied via
    /// `setrlimit(2)` in the seal. Nothing is set by default. The name is a short
    /// `setrlimit` resource (`nofile`, `nproc`, `as`, `cpu`, …); the value is `soft`,
    /// or `"soft:hard"`, each a number (with optional `K`/`M`/`G`) or `"unlimited"`.
    /// Validated at translate time; folds per-key like `[env].set`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<BTreeMap<String, String>>,
    /// The workload to run (`[workload]`). Optional: when absent, the command is given
    /// at `kennel run … -- <cmd>`. Folds scalar-wins up the chain like `[lifecycle]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadSection>,
    /// Terminal hardening (`[tty]`): the escape-sequence filter on the
    /// workload→operator PTY stream. Folds scalar-wins up the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<TtySection>,
    /// Workspace trust marker (`[trust]`): the masked `.trust-manifest.json` at
    /// each writable root. Folds scalar-wins up the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustSection>,
    /// D-Bus mediation (`[dbus]`): the per-method allowlist the `IDBus` facade
    /// enforces. Absent ⇒ no bus access (no facade node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbus: Option<DbusSection>,
    /// OCI substrate (`[rootfs]`): an unpacked image used as the kennel root. Its
    /// presence marks the policy OCI-model: `kennel run` rejects it, `kennel oci run` requires
    /// it. A loud substrate-trust grant (T3.8); the `reason` is mandatory (validated at compile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<RootfsSection>,
    /// Dynamic-spawn grant (`[spawn]`): the templates this workload may instantiate as
    /// ephemeral sibling kennels. A loud delegated-instantiation capability (T3.9); the `reason` is
    /// mandatory, and eligibility of each named template is checked at *this* policy's compile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn: Option<SpawnSection>,
    /// Mutable-field manifest (`[[mutable]]`): present on a *spawn-target template*, it
    /// names which leaf fields a spawn of this template may write and the bound each write must
    /// satisfy. Everything outside the manifest is frozen and inherited verbatim; absent on a
    /// non-target policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mutable: Vec<MutableField>,
}

/// `[rootfs]`: an OCI image unpacked as the kennel's root filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct RootfsSection {
    /// The unpacked image rootfs (the store entry's `rootfs/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The `image@sha256:…` the build pulled from; the runner refuses unless it equals the
    /// store entry's recorded `digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Why this substrate is trusted (required; the substrate-trust waiver is loud).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Rootfs persistence: `"discard"` (default) | `"persist"`. `"persist"` is a
    /// loud value the risk engine derives an exposure from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::Persistence")
    )]
    pub persistence: Option<String>,
    /// Closure-lock: rootfs paths Landlock denies writes to, the executable-closure
    /// boundary the DAC-flatten erased, build-derived for a non-root image. `["/"]` is
    /// whole-tree-immutable. Longest-prefix wins with `writable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<Vec<String>>,
    /// Closure-lock holes: rootfs paths kept writable, carved back out of `readonly`
    /// (longest-prefix wins). Each carve-out derives its own risk line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable: Option<Vec<String>>,
}

/// `[spawn]`: the delegated-instantiation grant.
///
/// A workload carrying this may ask `kenneld` to instantiate ephemeral sibling kennels from the
/// operator-signed templates it names in `[[spawn.allow]]`. A loud capability (T3.9), derived the way
/// `mode = host` derives T1.6. It names *which* templates, never capabilities; those live in the
/// (frozen, signed) templates; the agent only writes manifest fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SpawnSection {
    /// Concurrent-instance ceiling across this grant's spawns, the fork-bomb bound.
    /// Mandatory: an unbounded grant is a fork bomb (validated at compile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u32>,
    /// Why this delegation is extended (required; the spawn waiver is loud, validated at compile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The templates this grant may instantiate (`[[spawn.allow]]`), each optionally narrowed to a
    /// subset of its manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<SpawnAllow>,
}

/// One `[[spawn.allow]]` entry, a single signed template this grant may instantiate.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SpawnAllow {
    /// The trust-store template name (`net-fetch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Optional per-requester narrowing: the subset of the template's `[[mutable]]` manifest fields
    /// this requester may write (default: the template's full manifest). Narrows, never widens:
    /// every entry must name a field the template's manifest declares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutable: Option<Vec<String>>,
}

/// One `[[mutable]]` manifest entry: a leaf field a spawn of this template may write.
///
/// Each entry carries the **bound** that write must satisfy, exactly one bound kind: `pool`
/// (`from` + `max`: append from a fixed set), `oneof` (pick from an enumerated list), or
/// `predicate` (`type` + `under`: the loud traversal-free runtime-relative escape hatch).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
#[cfg_attr(feature = "schema", schema(rename = "mutable"))]
pub struct MutableField {
    /// The dotted leaf-field path this entry opens (`net.proxy.allow`, `rootfs.writable`, `fs.write`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Pool bound: the fixed set a spawn may append values from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
    /// Pool bound: the maximum number of appended entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    /// Oneof bound: the enumerated member list a spawn selects from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oneof: Option<Vec<String>>,
    /// Pattern bound: the pre-baked net-destination shapes an open value must match
    /// (`*.suffix:port`, `prefix.*:port`, exact). The agent supplies a destination not enumerated at
    /// sign time; it is admitted only if it fits one signed shape.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_: Option<Vec<String>>,
    /// Predicate bound: the value type (currently `relpath`).
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Predicate bound: the root the value resolves under (`RESOLVE_IN_ROOT`, traversal-free).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub under: Option<String>,
    /// Freeform bound: no shape at all, the loud last-resort footgun. Any value is accepted; a
    /// `reason` is mandatory and the variant is warned at compile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeform: Option<bool>,
    /// The justification a `freeform` variant requires (the loud rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Threat-tag metadata attached to a grant (`threats.exposed` / `threats.mitigated`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct Threats {
    /// Threat IDs this entry weakens defence against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposed: Vec<String>,
    /// Threat IDs this entry actively mitigates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitigated: Vec<String>,
}

/// One entry in the `{ add, remove }` increment of a path-list field.
///
/// A `path` plus the required `reason` (and optional threat tags): the `+=` / `-=` unit for
/// `fs.read`, `fs.write`, `fs.deny`, and `exec.allow`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct PathEntry {
    /// The path to add or remove.
    pub path: String,
    /// Why (required on every delta entry; validated at compile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// The `{ add, remove }` increment over a path list (`[[fs.read.add]]` / `[[fs.read.remove]]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct PathDelta {
    /// Entries to add (`+=`), appended if not already present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<PathEntry>,
    /// Entries to remove (`-=`), dropped by matching `path`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<PathEntry>,
}

/// A path-list field: replace or increment at the same key (-5.3).
///
/// A bare sequence of paths (`fs.read = ["…"]`, the SSH `Ciphers = …` set form) *replaces* the
/// inherited list; an `{ add, remove }` table of `{ path, reason }` entries (`[[fs.read.add]]`)
/// *increments* it. The deserializer picks by TOML shape (a sequence is a `Set`, a table is a
/// `Delta`), so one key carries both forms. After chain resolution every field is a `Set` (the
/// deltas have been folded in).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PathField {
    /// The bare-sequence replace form.
    Set(Vec<String>),
    /// The `{ add, remove }` increment form.
    Delta(PathDelta),
}

impl PathField {
    /// The resolved path list when this is the `Set` (replace) form: what every field is once the
    /// chain is folded. `None` for an unfolded `Delta`.
    #[must_use]
    pub fn set(&self) -> Option<&[String]> {
        match self {
            Self::Set(v) => Some(v),
            Self::Delta(_) => None,
        }
    }
    /// The resolved path list, treating a (post-fold-impossible) `Delta` as empty.
    #[must_use]
    pub fn resolved(&self) -> &[String] {
        self.set().unwrap_or(&[])
    }
    /// Whether this is the bare-sequence `Set` (replace) form.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        matches!(self, Self::Set(_))
    }
    /// The `{ add, remove }` increment's entries (`add` ∪ `remove`), each of which carries a
    /// required `reason`. Empty for the `Set` form (whose bare-string entries carry no reason).
    pub fn delta_entries(&self) -> impl Iterator<Item = &PathEntry> {
        let (add, remove): (&[PathEntry], &[PathEntry]) = match self {
            Self::Set(_) => (&[], &[]),
            Self::Delta(d) => (&d.add, &d.remove),
        };
        add.iter().chain(remove)
    }
    /// Whether this increment carries any `remove` (a non-additive delta, refused in a fragment).
    #[must_use]
    pub const fn has_remove(&self) -> bool {
        matches!(self, Self::Delta(d) if !d.remove.is_empty())
    }
    /// Whether this field is *additive-only*: an add-only increment. A bare-sequence `Set`
    /// *replaces* the inherited list, so it is never additive; a `Delta` is additive iff it carries
    /// no `remove`. The additive-only gate a fragment must satisfy.
    #[must_use]
    pub const fn is_additive(&self) -> bool {
        matches!(self, Self::Delta(d) if d.remove.is_empty())
    }
    /// Iterate the resolved path list (the `Set` slice; empty for an unfolded `Delta`).
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.resolved().iter()
    }
}

impl<'a> IntoIterator for &'a PathField {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.resolved().iter()
    }
}

/// The `{ add, remove }` increment over a typed list (`[[unix.allow.add]]`, `[[net.proxy.allow.add]]`, …).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delta<T> {
    /// Entries to add (`+=`), appended if not already present.
    #[serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<T>,
    /// Entries to remove (`-=`), dropped by matching unique key.
    #[serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<T>,
}

/// A typed-list field: replace or increment at the same key (-5.3).
///
/// A bare array-of-tables (`[[unix.allow]]`, the set form) *replaces* the inherited list; an
/// `{ add, remove }` table (`[[unix.allow.add]]`) *increments* it. The deserializer picks by TOML
/// shape (an array is a `Set`, a table is a `Delta`). After chain resolution every field is a `Set`.
/// An empty `Set` means *absent* (inherits the parent's list), preserving the original bare-list fold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListField<T> {
    /// The array-of-tables replace form.
    Set(Vec<T>),
    /// The `{ add, remove }` increment form.
    Delta(Delta<T>),
}

impl<T> Default for ListField<T> {
    fn default() -> Self {
        Self::Set(Vec::new())
    }
}

// The two untagged compose enums describe their `Set | Delta` shape by hand — a derive
// can't see an untagged union's arms — so the schema covers both the bare-list replace form
// and the `[[fs.read.add]]` / `[[net.proxy.allow.add]]` increment forms.
#[cfg(feature = "schema")]
impl kennel_schema::SchemaType for PathField {
    fn schema_node(defs: &mut kennel_schema::Defs) -> kennel_schema::Node {
        kennel_schema::Node::OneOf(vec![
            kennel_schema::Node::Array(Box::new(kennel_schema::Node::Str)),
            <PathDelta as kennel_schema::SchemaType>::schema_node(defs),
        ])
    }
}

#[cfg(feature = "schema")]
impl<T: kennel_schema::SchemaType> kennel_schema::SchemaType for ListField<T> {
    fn schema_node(defs: &mut kennel_schema::Defs) -> kennel_schema::Node {
        let mut item = || {
            kennel_schema::Node::Array(Box::new(<T as kennel_schema::SchemaType>::schema_node(
                defs,
            )))
        };
        let set = item();
        let delta = kennel_schema::Node::Object(kennel_schema::Obj {
            title: "Increment ({ add, remove }) over the inherited typed list.".to_owned(),
            props: vec![
                kennel_schema::Prop {
                    key: "add".to_owned(),
                    required: false,
                    desc: "Entries to append.".to_owned(),
                    node: item(),
                },
                kennel_schema::Prop {
                    key: "remove".to_owned(),
                    required: false,
                    desc: "Entries to drop by key.".to_owned(),
                    node: item(),
                },
            ],
        });
        kennel_schema::Node::OneOf(vec![set, delta])
    }
}

impl<T> ListField<T> {
    /// The resolved list when this is the `Set` (replace) form: what every field is once the chain
    /// is folded. An unfolded `Delta` resolves to an empty slice.
    #[must_use]
    pub fn resolved(&self) -> &[T] {
        match self {
            Self::Set(v) => v,
            Self::Delta(_) => &[],
        }
    }
    /// Whether this field is the *absent* sentinel: an empty `Set` (the bare-list "inherit" signal).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Set(v) if v.is_empty())
    }
    /// Whether this is the bare-array `Set` (replace) form.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        matches!(self, Self::Set(_))
    }
    /// Every entry this field carries (the `Set` list, or a `Delta`'s `add` ∪ `remove`), for
    /// the per-entry `reason` check (each grant records intent whether set or incremented).
    pub fn entries(&self) -> impl Iterator<Item = &T> {
        let (set, add, remove): (&[T], &[T], &[T]) = match self {
            Self::Set(v) => (v, &[], &[]),
            Self::Delta(d) => (&[], &d.add, &d.remove),
        };
        set.iter().chain(add).chain(remove)
    }
    /// Whether this increment carries any `remove` (a non-additive delta, refused in a fragment).
    #[must_use]
    pub const fn has_remove(&self) -> bool {
        matches!(self, Self::Delta(d) if !d.remove.is_empty())
    }
    /// Whether this field is *additive-only*: absent (the empty `Set` sentinel) or an add-only
    /// increment. A non-empty `Set` *replaces* and is never additive.
    #[must_use]
    pub const fn is_additive(&self) -> bool {
        match self {
            Self::Set(v) => v.is_empty(),
            Self::Delta(d) => d.remove.is_empty(),
        }
    }
    /// Iterate the resolved list (the `Set` slice; empty for an unfolded `Delta`), what every field
    /// is once the chain is folded, so a reader iterates the effective grants directly.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.resolved().iter()
    }
}

impl<'a, T> IntoIterator for &'a ListField<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.resolved().iter()
    }
}

impl<T> From<Vec<T>> for ListField<T> {
    /// A bare list is the `Set` (replace) form: the common case, and what a callsite that builds a
    /// concrete list means.
    fn from(v: Vec<T>) -> Self {
        Self::Set(v)
    }
}

impl From<Vec<String>> for PathField {
    fn from(v: Vec<String>) -> Self {
        Self::Set(v)
    }
}

/// `[cap]`: capabilities and `no_new_privs`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct CapSection {
    /// `PR_SET_NO_NEW_PRIVS`. A framework invariant once resolved (must be true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_new_privs: Option<bool>,
    /// The capability bounding set to retain (empty drops them all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounding_set: Option<Vec<String>>,
}

/// `[exec]`: what may be `execve`'d.
///
/// `Serialize` is hand-written (not derived) so the `allow` field can serialise as a value (its
/// `Set` form, a bare array) or a sub-table (its `Delta` form) while still emitting all values
/// before all tables: the `basic-toml` canonical-form requirement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct ExecSection {
    /// Allowlisted binary paths (the execve allowlist). Execution is deny-by-default:
    /// an empty/absent allow denies ALL execve; a bare `**`/`/**` is the explicit
    /// `permissive-exec` opt-out (the one case the compiler warns on).
    /// Replace (`allow = ["…"]`) or increment (`[[exec.allow.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<PathField>,
    /// Denylisted absolute paths or globs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Refuse setuid binaries at execve (framework invariant once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setuid: Option<bool>,
    /// Refuse setgid binaries (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setgid: Option<bool>,
    /// Refuse file-capability binaries (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_setcap: Option<bool>,
    /// Refuse execution of files in writable paths (framework invariant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_writable: Option<bool>,
    /// `PATH` search roots the resolver records for the workload's environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    /// The kennel's login shell: the synthetic-`passwd` `pw_shell` and
    /// `$SHELL`. Default `/bin/sh`; must be in [`allow`](Self::allow) when an
    /// allowlist is enforced (compile error otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
}

impl Serialize for ExecSection {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(None)?;
        // Value-class first: `allow` only when it is the bare-array `Set` form, then the scalar
        // arrays and flags. A `Delta` `allow` is a sub-table and must come after every value.
        if let Some(a) = self.allow.as_ref().filter(|a| a.is_set()) {
            m.serialize_entry("allow", a)?;
        }
        if let Some(v) = &self.deny {
            m.serialize_entry("deny", v)?;
        }
        for (k, v) in [
            ("deny_setuid", self.deny_setuid),
            ("deny_setgid", self.deny_setgid),
            ("deny_setcap", self.deny_setcap),
            ("deny_writable", self.deny_writable),
        ] {
            if let Some(b) = v {
                m.serialize_entry(k, &b)?;
            }
        }
        if let Some(v) = &self.path {
            m.serialize_entry("path", v)?;
        }
        if let Some(v) = &self.shell {
            m.serialize_entry("shell", v)?;
        }
        // Table-class last: a `Delta` `allow` (the `{ add, remove }` sub-table).
        if let Some(a) = self.allow.as_ref().filter(|a| !a.is_set()) {
            m.serialize_entry("allow", a)?;
        }
        m.end()
    }
}

/// `[fs]` and its sub-tables.
///
/// `Serialize` is hand-written (not derived) so the `read`/`write`/`deny` fields can each serialise
/// as a value (their `Set` form) or a sub-table (their `Delta` form) while still emitting all values
/// before all tables: the `basic-toml` canonical-form requirement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct FsSection {
    /// Paths granted read (and directory traversal / execute). Replace (`read = ["…"]`) or
    /// increment (`[[fs.read.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<PathField>,
    /// Paths granted write. Replace or increment at the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<PathField>,
    /// Writable paths bound **exclusively** (T2.8): while the kennel runs, `kenneld`
    /// over-mounts an opaque sentinel on the host path (a transient privhelper op) so the
    /// operator and the workload cannot use it concurrently, severing the live confused-deputy
    /// channel. Opt-in, per path; each must also appear in `write`. Default: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive: Option<Vec<String>>,
    /// Categorical denies (belt-and-braces over the constructed view). Replace or increment
    /// at the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<PathField>,
    /// `[fs.home]`: the constructed `$HOME` view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<FsHome>,
    /// `[fs.tmp]`: the private `/tmp` tmpfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmp: Option<FsTmp>,
    /// `[fs.proc]`: procfs hidepid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proc: Option<FsProc>,
    /// `[fs.dev]`: the minimal `/dev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<FsDev>,
}

impl Serialize for FsSection {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(None)?;
        // Value-class first: the `read`/`write`/`deny` path lists only when they are the bare-array
        // `Set` form, then `exclusive`. A `Delta` path list is a sub-table and follows every value.
        for (k, f) in [
            ("read", &self.read),
            ("write", &self.write),
            ("deny", &self.deny),
        ] {
            if let Some(pf) = f.as_ref().filter(|p| p.is_set()) {
                m.serialize_entry(k, pf)?;
            }
        }
        if let Some(v) = &self.exclusive {
            m.serialize_entry("exclusive", v)?;
        }
        // Table-class: first the `Delta` path lists, then the genuine sub-tables.
        for (k, f) in [
            ("read", &self.read),
            ("write", &self.write),
            ("deny", &self.deny),
        ] {
            if let Some(pf) = f.as_ref().filter(|p| !p.is_set()) {
                m.serialize_entry(k, pf)?;
            }
        }
        if let Some(v) = &self.home {
            m.serialize_entry("home", v)?;
        }
        if let Some(v) = &self.tmp {
            m.serialize_entry("tmp", v)?;
        }
        if let Some(v) = &self.proc {
            m.serialize_entry("proc", v)?;
        }
        if let Some(v) = &self.dev {
            m.serialize_entry("dev", v)?;
        }
        m.end()
    }
}

/// `[fs.home]`: the mandatory constructed-`$HOME` shim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct FsHome {
    /// Whether `$HOME` is shadowed by a constructed view (must be true once resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<bool>,
    /// Home-relative paths that **persist** across runs. By default the
    /// synthesised dotfiles are reconstructed read-only each spawn (no
    /// self-poisoning); a path named here is *not* reconstructed, so a writable
    /// home grant for it survives. Opt-in, per path; this list is where the
    /// persistent-`~/.bashrc` re-execution trade-off is taken, visible in the diff.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persist: Vec<String>,
    /// Make the constructed `$HOME` **read-only** (default: writable). The home root
    /// is writable by default (a non-system user owns their home) but it is a fresh
    /// tmpfs, so writes are ephemeral. Setting this suppresses the home write grant:
    /// only explicitly `write`-granted `~/` paths are then writable, the rest of the
    /// home read-only. The escape hatch for a workload that must not write its home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
}

/// `[fs.tmp]`: the workload's own `/tmp` tmpfs.
///
/// `/tmp` is always a fresh per-kennel tmpfs in the constructed view; `writable` is the Landlock
/// write grant that lets the workload use it (without it `/tmp` is a read-only tmpfs). `size` is the
/// human form (`"512M"`); the resolver converts it to mebibytes for the settled policy. The tmpfs is
/// owned by the workload user inside its own mount namespace, so it carries no DAC-mode knob.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct FsTmp {
    /// Whether the workload may **write** to its `/tmp` tmpfs (the Landlock write grant). Absent ⇒
    /// `/tmp` is a read-only fresh tmpfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
    /// Size cap in human form (`"512M"`, `"1G"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

/// `[fs.proc]`: procfs hidepid. Visibility is always self-only (structural).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct FsProc {
    /// Mount `/proc` with `hidepid=2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidepid: Option<bool>,
}

/// `[fs.dev]`: the constructed `/dev` allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct FsDev {
    /// The trivial pseudo-device baseline bound into the kennel's `/dev` (`/dev/null`,
    /// `/dev/urandom`, `/dev/tty`, …): bare paths, no documentation needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// `[[fs.dev.passthrough]]`: specific *real host devices* exposed to the kennel
    /// (a serial console, `/dev/ppp`, `/dev/net/tun`). Each is loud: a documented `reason` and a
    /// threat tag are required,
    /// because passing a hardware device through widens the kernel attack surface and
    /// its DAC group right reaches into the kennel. Replace (`[[fs.dev.passthrough]]`) or
    /// increment (`[[fs.dev.passthrough.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub passthrough: ListField<DevPassthrough>,
}

/// One `[[fs.dev.passthrough]]` entry: a specific host device made available in the
/// kennel's constructed `/dev`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct DevPassthrough {
    /// The device node, an absolute path under `/dev` (e.g. `/dev/ttyUSB0`,
    /// `/dev/net/tun`). Bound from the host, preserving its owner/group/mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The owning group that gates access (e.g. `dialout`, `modem`, `dip`). Access is
    /// DAC: the kennel reaches the device only if this group is in its group set, and
    /// the user must already be a member. Documentary today (the kennel inherits the
    /// user's groups); the hook for the future hardening that drops non-granted groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Why this device is exposed (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags, required to carry an `exposed` tag (passthrough widens the
    /// kernel attack surface and carries a group right into the kennel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[net]` and its sub-tables.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetSection {
    /// Egress mode: `"none"` (own empty net-ns, no interfaces), `"constrained"` (own net-ns,
    /// SOCKS proxy, default-deny, the default), `"unconstrained"` (own net-ns, SOCKS proxy,
    /// default-allow minus invariant + `net.deny` carve-outs), or `"host"` (host net-ns,
    /// direct egress, `net.allow` enforced by BPF/Landlock, no proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::NetMode")
    )]
    pub mode: Option<String>,
    /// Required (non-empty) only when `mode = "host"`: the documented justification for
    /// sharing the host network stack, which reinstates the host-recon residual (T1.6).
    /// The compiler refuses `mode = host` without it; the T1.6 exposure is *derived*
    /// from the mode (surfaced by `kennel policy risks` / the `risks` engine), not
    /// stored on a `threats.reinstated` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// IPv4 proxy listen address as `"offset:port"` within the kennel's subnet. A
    /// family is enabled iff its address is set (there is no separate on/off flag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v4_address: Option<String>,
    /// IPv6 proxy listen address as `"offset:port"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_listen_v6_address: Option<String>,
    /// `[net.proxy]`: the user-space egress policy the per-kennel proxy enforces
    /// (`constrained`/`unconstrained`): by-name (+CIDR) allow/deny, resolve-and-pin, plus
    /// the non-removable `[[net.proxy.deny.invariant]]` floor. Not enforced in `mode=host`
    /// (no proxy runs there): a `[net.proxy]` rule under `host` is a compile error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<NetProxy>,
    /// `[net.bpf]`: the kernel/syscall ACL (the cgroup `connect4/6` + `bind4/6` BPF and the
    /// matching Landlock grants): CIDR + port allow/deny, deny-first, **no names**. Present in
    /// every mode: in `host` it is the egress gate; in the proxied modes it is defence-in-depth
    /// (intersected with the framework's proxy-endpoint lock, an author rule can only narrow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf: Option<NetBpf>,
    /// `[net.bind]`: bind-address rewriting policy (the wildcard-rewrite knobs; the bind
    /// *allow/deny gate* is `[net.bpf.bind]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBind>,
    /// `[net.ipv6]`: IPv6-specific options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<NetIpv6>,
    /// `[net.audit]`: per-kennel egress audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<NetAudit>,
}

/// `[net.proxy]`: the user-space egress policy kenneld's proxy enforces.
///
/// Meaningful only in the proxied modes (`constrained`/`unconstrained`): kenneld resolves a
/// name, vets the answer against `allow`, re-checks the resolved address against `deny` +
/// `deny_invariant`, and pins it. In `mode=host` there is no proxy, so any rule here is a
/// compile error (names cannot be enforced by the kernel ACL; use `[net.bpf]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetProxy {
    /// `[[net.proxy.allow]]`: by-name (or by-CIDR) egress allow entries. Replace
    /// (`[[net.proxy.allow]]`) or increment (`[[net.proxy.allow.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub allow: ListField<NetAllow>,
    /// `[net.proxy.deny]`: the deny table: the non-removable `invariant` floor and the
    /// optional author `policy` denylist, both CIDR, both evaluated deny-first before `allow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<NetProxyDeny>,
}

/// `[net.proxy.deny]`: the proxy denies: the framework floor + the optional author list.
///
/// Two arrays in one table (TOML cannot nest `[[net.proxy.deny]]` under
/// `[[net.proxy.deny.invariant]]`): `invariant` is the non-removable floor (cloud-metadata /
/// link-local), `policy` is the author's optional subtraction (RFC1918, a known-bad range).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetProxyDeny {
    /// `[[net.proxy.deny.invariant]]`: cloud-metadata / link-local, non-removable (T1.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant: Vec<NetDenyRule>,
    /// `[[net.proxy.deny.policy]]`: the author's optional denylist (NOT mandatory). Replace
    /// or increment (`[[net.proxy.deny.policy.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub policy: ListField<NetDenyRule>,
}

/// `[net.bpf]`: the kernel/syscall ACL: socket-family shaping + the
/// directional connect/bind allow-deny gates the cgroup BPF and Landlock enforce.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetBpf {
    /// Permitted socket families (defence in depth; e.g. `["AF_INET", "AF_INET6", "AF_UNIX"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    /// Denied socket families (`inet_sock_create` returns EPERM): `AF_NETLINK`, `AF_PACKET`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_families: Option<Vec<String>>,
    /// `[net.bpf.connect]`: the outbound CONNECT ACL (cidr + ports, deny-first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<NetBpfAcl>,
    /// `[net.bpf.bind]`: the inbound BIND ACL (cidr + ports, deny-first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<NetBpfAcl>,
}

/// One direction of the `[net.bpf]` kernel ACL: CIDR+port allow/deny, deny-first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetBpfAcl {
    /// `[[net.bpf.connect.allow]]` / `[[net.bpf.bind.allow]]`: CIDR+port allow rules. Replace
    /// or increment (`[[net.bpf.connect.allow.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub allow: ListField<BpfRule>,
    /// `[[net.bpf.connect.deny]]` / `[[net.bpf.bind.deny]]`: CIDR+port deny rules (deny-first).
    /// Replace or increment at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub deny: ListField<BpfRule>,
}

/// One `[net.bpf]` rule: a CIDR (or `"*"` = any host) + ports + protocol. **No name field**:
/// the kernel ACL cannot resolve names, so a by-name rule is structurally inexpressible here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct BpfRule {
    /// The CIDR (`"10.0.0.0/8"`, a bare address, or `"*"` = `0.0.0.0/0` + `::/0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Permitted ports (empty = any port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Transport protocol (`"tcp"`, `"udp"`, `"any"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::Protocol")
    )]
    pub protocol: Option<String>,
    /// Why this rule exists (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// One `[[net.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetAllow {
    /// The destination host (or dot-prefixed suffix). Mutually informative with `cidr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A CIDR destination, when the rule is by-address rather than by-name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Permitted ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Transport protocol (`"tcp"`, `"udp"`, `"any"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::Protocol")
    )]
    pub protocol: Option<String>,
    /// Why this destination is permitted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    // `tls` and `threats` are TOML tables: declared after the scalar fields so they
    // serialise last (`basic-toml` emits values before tables).
    /// `tls.required` and friends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<NetTls>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `tls.*` on a `[[net.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetTls {
    /// Whether TLS is required to the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// One `[[net.proxy.deny.invariant]]` / `[[net.proxy.deny.policy]]` entry: a CIDR plus its
/// required `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetDenyRule {
    /// The denied CIDR (e.g. `"169.254.169.254/32"`).
    pub cidr: String,
    /// Why the deny exists (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[net.bind]`: bind-address handling.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetBind {
    /// What to do with a wildcard IPv4 bind (`"rewrite"` / `"deny"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::WildcardBindPolicy")
    )]
    pub inaddr_any_policy: Option<String>,
    /// What to do with a wildcard IPv6 bind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::WildcardBindPolicy")
    )]
    pub in6addr_any_policy: Option<String>,
    /// Whether binding the host IPv4 loopback is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_host_loopback_v4: Option<bool>,
    /// Whether binding the host IPv6 loopback is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_host_loopback_v6: Option<bool>,
    /// Lowest bindable port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_port: Option<u16>,
    /// Explicit allowlist of bindable ports. When non-empty, the workload may
    /// `bind` only these ports (in addition to passing [`min_port`](Self::min_port));
    /// empty/absent means any port at or above `min_port`. At most
    /// [`MAX_BIND_PORTS`](kennel_lib_policy::settled::MAX_BIND_PORTS) entries survive translation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ports: Option<Vec<u16>>,
}

/// `[net.ipv6]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetIpv6 {
    /// Force `IPV6_V6ONLY=1` so a dual-stack socket cannot escape the v4 rewrite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_v6only: Option<bool>,
}

/// `[net.audit]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct NetAudit {
    /// Where the per-kennel egress JSONL log is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// Audit verbosity (`"summary"`, `"full"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::NetAuditLevel")
    )]
    pub level: Option<String>,
}

/// `[unix]`: `AF_UNIX` policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct UnixSection {
    /// Abstract-namespace socket disposition (`"deny"` / `"allow"`).
    #[serde(rename = "abstract", default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::AbstractSocketPolicy")
    )]
    pub abstract_ns: Option<String>,
    /// `[[unix.allow]]`: granted sockets, including per-kennel service instances. Replace
    /// (`[[unix.allow]]`) or increment (`[[unix.allow.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub allow: ListField<UnixAllow>,
}

/// One `[[unix.allow]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct UnixAllow {
    /// A logical name (e.g. `"ssh-agent"`) for a per-kennel service instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The real host socket path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real: Option<String>,
    /// The shim path the socket is bound at inside the kennel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// An environment variable to set to the shim path (e.g. `SSH_AUTH_SOCK`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Why this socket is granted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// The typed shape of a mesh capability: defined in the settled crate so the
/// source parser and the signed runtime share one type.
pub use kennel_lib_policy::settled::Shape;

/// One `[[provides]]` entry, a capability this kennel offers over the mesh.
///
/// `name`/`shape`/`reason` are validated present at compile, not required at parse,
/// so a malformed entry yields one problem per missing field rather than a parse abort.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct ProvidesEntry {
    /// The capability's public identifier, what the catalogue advertises. A reserved
    /// `org.projectkennel.*` name may be claimed only by a maintainer-signed template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The typed transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Shape>,
    /// Where the capability is exposed, in the provider's own view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// An optional private match token, never advertised in the catalogue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Why this capability is offered (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// One `[[consumes]]` entry, a capability this kennel reaches over the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct ConsumesEntry {
    /// The capability's public identifier, resolved against the catalogue at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The transport it expects; the broker refuses a mismatched shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Shape>,
    /// Where the brokered connector is delivered, in this kennel's own view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// Environment variable(s) synthesised into this kennel to name the connector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// An optional private match token; must match the provider's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Whether the capability's absence fails kennel construction. Hard dependency by
    /// default; `false` starts the kennel without it.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Why this capability is consumed (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

impl Default for ConsumesEntry {
    fn default() -> Self {
        Self {
            name: None,
            shape: None,
            at: None,
            env: Vec::new(),
            key: None,
            required: true,
            reason: None,
            threats: None,
        }
    }
}

/// The `required` default: a consume is a hard dependency unless stated otherwise.
const fn default_required() -> bool {
    true
}

/// `[identity]`: the workload's identity inside the kennel.
///
/// Source-only and realised by `kenneld`: the supplementary Unix groups the confined
/// workload retains. By default a kennel carries **none** (the inherited host groups
/// are dropped by the privileged seal); each name listed here is kept, but only
/// if the operator is a member (a group the user lacks is refused, never
/// granted, since the privileged `setgroups` could otherwise over-grant). Groups named
/// by `[[fs.dev.passthrough]]` are added automatically. The resolved set drives the
/// seal's `setgroups` and is named in the synthetic `/etc/group` so `id` shows names.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct IdentitySection {
    /// The workload's masked user name, `$USER`/`$LOGNAME` and the synthetic
    /// `/etc/passwd` account, and the base of `$HOME` (`/home/<user>`). Defaults to
    /// `kennel` (a non-system, non-privileged account) when unset; an operator may
    /// override it. Validated as a portable username at translation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The workload's masked **primary** group name (synthetic `/etc/passwd` `pw_gid`
    /// name and the `/etc/group` entry for the primary gid). Defaults to `kennel`;
    /// validated as a portable name at translation. Distinct from `groups` below (the
    /// *supplementary* groups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Supplementary group names to retain (e.g. `["dialout", "plugdev"]`). The user
    /// must be a member of each; resolved to GIDs at spawn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// `[ssh]`: per-kennel SSH egress (source-only).
///
/// Resolved and folded like [`UnixSection`] and dropped from the settled
/// `EffectivePolicy` (`translate.rs`): its effect is realised by `kenneld`'s SSH
/// re-origination bastion (`kennel-sshd`), the synthetic `~/.ssh`, and the egress
/// allowlist, never by the runtime artefact. A kennel never holds a real key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SshSection {
    /// Whether a granted key may be driven by a non-interactive (CI) kennel with no
    /// per-use touch/confirmation. Loud and threat-tagged; default `false`. When
    /// `true`, [`threats`](Self::threats) must carry an `exposed` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_headless: Option<bool>,
    /// Threat tags for the section, required to carry an `exposed` tag whenever
    /// `allow_headless = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
    /// `[[ssh.destinations]]`: the SSH egress allowlist. Each entry is one destination
    /// the kennel may reach; `kenneld` mints a per-destination synthetic key (the
    /// capability the kennel authenticates to the bastion with) bound to a forced
    /// command that runs `ssh <options> -- <dest>` **as the operator on the host**.
    /// The destination (and which real key/port/config the host-side `ssh`
    /// uses) is fixed by *which synthetic key authenticated*, never by the workload. Replace
    /// (`[[ssh.destinations]]`) or increment (`[[ssh.destinations.add]]`) at the same key.
    #[serde(default, skip_serializing_if = "ListField::is_empty")]
    pub destinations: ListField<SshDestination>,
}

/// One `[[ssh.destinations]]` entry: a destination the kennel may reach over the bastion.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SshDestination {
    /// The SSH destination, in the form the host-side `ssh` is invoked with
    /// (`git@github.com`, `root@localhost`, a `~/.ssh/config` host alias). It is the
    /// capability the minted synthetic key stands for, never parsed from the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    /// Host-side `ssh` invocation options for this destination, passed verbatim as argv
    /// tokens before `<dest>` in the bastion's forced command (`-i ~/.ssh/id_x`,
    /// `-o IdentitiesOnly=yes`, `-p 2222`, …). They run **as the operator** and name
    /// which real key/port/config the outbound hop uses, host-side, never the kennel's
    /// choice. Trusted because the policy is operator-signed; passed as separate argv
    /// tokens (no shell), so a metacharacter cannot break out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// Why this destination is granted (required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Threat tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threats: Option<Threats>,
}

/// `[workload]`: the command the kennel runs, optionally pinned.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct WorkloadSection {
    /// The command + args (`argv[0]` is the program). Absent ⇒ supplied at `kennel run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Working directory inside the view (may carry a `~`/`<home>` placeholder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Refuse a CLI `--` override of `argv` unless `--force` (pin exactly what runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    /// Accepted lowercase-hex SHA-256 digests of the workload binary; the spawn verifies
    /// the binary against this set before exec. A list so multiple accepted versions of
    /// one binary validate under a single policy. Absent/empty ⇒ no pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Vec<String>>,
}

/// `[unsafe]`: the advisory footgun umbrella.
///
/// Its sub-sections describe controls whose *scoping is real* but is enforced by the
/// PID namespace + seccomp, not by the section itself. Grouping them under `[unsafe]`
/// makes the footgun visible; each present sub-section is warned at compile
/// (`footgun-warn-dont-forbid`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct UnsafeSection {
    /// `[unsafe.ptrace]`: ptrace across the kennel boundary (scoping from PID-ns + seccomp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptrace: Option<BoundaryAcl>,
    /// `[unsafe.signal]`: signalling across the kennel boundary (scoping from PID-ns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<BoundaryAcl>,
}

/// A cross-boundary allowlist (`allow_targets`/`allow_from`), shared by the
/// `[unsafe.ptrace]` and `[unsafe.signal]` sub-sections.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct BoundaryAcl {
    /// Permitted targets (`"self"`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_targets: Option<Vec<String>>,
    /// Permitted sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_from: Option<Vec<String>>,
}

/// `[env]`: environment curation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct EnvSection {
    /// Variables passed through from the caller's environment (globs allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<Vec<String>>,
    /// Variables denied even if passed (globs allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Variables forced to a specific value. Declared last: as a TOML table it must
    /// serialise after the array-valued fields (`basic-toml` emits values first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<BTreeMap<String, String>>,
}

/// `[seccomp]`: the seccomp filter (source carries a deny list; the resolver
/// produces the settled allow list + default action).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct SeccompSection {
    /// The baseline profile name (`"default"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Syscalls denied on top of the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    /// Syscalls explicitly allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
}

/// `[lifecycle]`: TTL and TTL action. `ttl` is the human form (`"8h"`); the
/// resolver converts it to seconds for the settled policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct LifecycleSection {
    /// Time-to-live in human form (`"8h"`, `"1h"`, `"30m"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// What to do at TTL expiry: `"exit"` (alias `"stop"`, the default) ends the
    /// kennel; `"warn"` emits an audit event and leaves it running; `"renew"` is an
    /// audited `warn` today (the interactive renewal prompt is still owed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::TtlAction")
    )]
    pub ttl_action: Option<String>,
}

/// `[service]`: the supervision discipline for a service kennel.
///
/// Present on a kennel that `[[provides]]` a capability; governs how `kenneld` restarts it once the
/// operator enables it. The fields default (restart `on-failure`, 500ms backoff, 5 attempts), so a
/// service may declare an empty `[service]` and accept the defaults; an absent `[service]` carries
/// no supervision runtime at all (`kenneld` applies its own default at enable time).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct ServiceSection {
    /// Restart discipline: `always` / `on-failure` (default) / `never`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<kennel_lib_policy::RestartPolicy>,
    /// Initial delay before a restart in human form (`"500ms"`, `"2s"`, default `"500ms"`); doubles
    /// each successive attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<String>,
    /// Restarts within the crash-loop window before declared-but-failed (default `5`; must be ≥ 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
}

/// `[tty]`: terminal hardening for an interactive (PTY) workload.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct TtySection {
    /// Filter the dangerous escape sequences a workload could write toward the
    /// operator's real terminal: OSC 52 (clipboard), OSC 9/777 (notifications),
    /// and the DCS/APC/PM/SOS opaque bands (`kennel-lib-term`, T2.6). Benign
    /// sequences (titles, hyperlinks, colour) pass through. Default `true`; set
    /// `false` only in an interactive template that needs raw terminal control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_terminal_escapes: Option<bool>,
}

/// `[trust]`: the masked workspace manifest (T2.8).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct TrustSection {
    /// Maintain a `.trust-manifest.json` at the root of every writable/persistent
    /// workspace (the CLI generates it pre-flight; the view masks it invisible to the
    /// workload, so the agent cannot forge the integrity pins host tooling trusts).
    /// Default `true`; set `false` for a workload where host-side trigger trust is
    /// irrelevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<bool>,
    /// What `kenneld` does when a watched trigger is mutated during the run:
    /// `warn` (audit, default), `freeze` (suspend the workload), or `kill` (terminate it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_change: Option<kennel_lib_policy::OnChangeAction>,
}

/// `[dbus]`: D-Bus mediation.
///
/// The per-method allowlist the `IDBus` facade enforces; the operator writes structured
/// policy, never proxy flags. A kennel with no `[dbus]` gets no facade node, the secure
/// default by construction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct DbusSection {
    /// `[dbus.session]`: the user session bus (the common case: notifications, portals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<DbusBus>,
    /// `[dbus.system]`: the system bus (rarely needed; mostly refuse-listed services).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<DbusBus>,
    /// `[dbus.audit]`: per-kennel D-Bus call audit verbosity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<DbusAudit>,
}

/// `[dbus.session]` / `[dbus.system]`: one bus's enable flag and rule set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct DbusBus {
    /// Whether this bus is reachable at all. Absent/`false` ⇒ no connection to this bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// `[dbus.<bus>.allow]`: what the kennel may reach (an allowlist; default-deny).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<DbusRules>,
    /// `[dbus.<bus>.deny]`: belt-and-braces explicit denies over the allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<DbusRules>,
}

/// `[dbus.<bus>.allow]` / `[dbus.<bus>.deny]`: the four rule classes at
/// destination / interface / member granularity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct DbusRules {
    /// Destinations the kennel may call methods on and receive replies/signals from
    /// (`org.freedesktop.Notifications`, `org.freedesktop.portal.*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub talk: Vec<String>,
    /// Finer than `talk`: specific `destination=interface.member` calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call: Vec<String>,
    /// Signals the kennel may receive (a subset of senders it may `talk` to).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcast: Vec<String>,
    /// Names the kennel may own (be addressable as). Almost always empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub own: Vec<String>,
}

/// `[dbus.audit]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(kennel_schema_derive::SchemaType))]
pub struct DbusAudit {
    /// Verbosity (`"off"`, `"summary"`, `"full"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schema(values_from = "kennel_lib_policy::settled::DbusAuditLevel")
    )]
    pub level: Option<String>,
}

/// Destinations that cannot be brokered to a kennel at all.
///
/// A credential oracle or a session/process-control escape. Naming one (or a pattern that
/// admits one) in an `allow` list is a compile error, not a warning; the same axiom
/// carve-out as the signing oracle, not a footgun the operator may choose.
pub const DBUS_REFUSE_TO_BROKER: &[&str] = &[
    "org.freedesktop.secrets", // Secret Service: a read-stored-credentials oracle
    "org.freedesktop.systemd1", // StartTransientUnit: spawn an unconfined process
    "org.freedesktop.login1",  // logout / reboot / lock / power
    "org.gnome.SessionManager", // GNOME session control
    "org.kde.ksmserver",       // KDE session control
];

/// Whether a D-Bus `allow` pattern admits `name`: exact, a trailing `.*` prefix
/// wildcard (`org.freedesktop.*`), or the catch-all `*`.
#[must_use]
pub fn dbus_pattern_admits(pattern: &str, name: &str) -> bool {
    if pattern == "*" || pattern == name {
        return true;
    }
    pattern
        .strip_suffix('*')
        .and_then(|p| p.strip_suffix('.'))
        .is_some_and(|prefix| {
            name == prefix
                || name
                    .strip_prefix(prefix)
                    .is_some_and(|r| r.starts_with('.'))
        })
}

/// The destination part of an `allow` entry: the substring before the first `=`
/// (a `call` entry is `destination=interface.member`; `talk`/`broadcast`/`own` are bare).
fn dbus_destination(entry: &str) -> &str {
    entry.split('=').next().unwrap_or(entry).trim()
}

/// Parse source-policy TOML bytes into a [`SourcePolicy`].
///
/// This is parse-only: it enforces the schema shape (`deny_unknown_fields`, types,
/// no duplicate keys) but not the semantic rules. Call [`SourcePolicy::validate`]
/// for identity coherence, reference grammar, and required `reason`s.
///
/// # Errors
///
/// Returns [`PolicyError::Parse`] if the bytes are not valid TOML matching the schema.
pub fn parse(bytes: &[u8]) -> Result<SourcePolicy, PolicyError> {
    basic_toml::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))
}

impl SourcePolicy {
    /// Validate the semantic rules this build enforces on a single source artefact.
    ///
    /// Checks: identity coherence (template vs leaf), `template_base`/`include`
    /// reference grammar, no duplicate includes, and a non-empty `reason` on every
    /// capability-granting entry (`[[net.proxy.allow]]`, `[[net.proxy.deny.*]]`,
    /// `[[net.bpf.*]]`, `[[unix.allow]]`).
    ///
    /// Chain resolution, signature verification, lockfile byte-pinning, and
    /// framework-invariant assertion are *cross-artefact* or *post-resolution*
    /// concerns handled by later compiler stages, not here.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::SourceValidation`] carrying one message per problem.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errs: Vec<String> = Vec::new();
        self.check_identity(&mut errs);
        self.check_references(&mut errs);
        self.check_reasons(&mut errs);
        self.check_leaf_invariants(&mut errs);
        self.check_dbus(&mut errs);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::SourceValidation(errs))
        }
    }

    /// Whether this artefact is a leaf policy (has `name`, no `template_name`).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.name.is_some() && self.template_name.is_none()
    }

    fn check_identity(&self, errs: &mut Vec<String>) {
        match (self.template_name.is_some(), self.name.is_some()) {
            (true, true) => {
                errs.push("artefact sets both `template_name` and `name`; a file is either a template or a leaf, not both".to_owned());
            }
            (false, false) => {
                errs.push(
                    "artefact sets neither `template_name` (templates) nor `name` (leaf policies)"
                        .to_owned(),
                );
            }
            _ => {}
        }
        // A leaf policy must name a parent template; only the root template may omit it.
        if self.is_leaf() && self.template_base.is_none() {
            errs.push(
                "leaf policy has no `template_base`; every leaf derives from a template".to_owned(),
            );
        }
    }

    fn check_references(&self, errs: &mut Vec<String>) {
        if let Some(base) = &self.template_base {
            // A `template_base` is a bare template name; the lockfile pins the exact parent by
            // its resolved signature.
            if let Err(msg) = validate_reference(base) {
                errs.push(format!("`template_base` = \"{base}\": {msg}"));
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for inc in &self.include {
            if let Err(msg) = validate_reference(inc) {
                errs.push(format!("`include` entry \"{inc}\": {msg}"));
            }
            if seen.contains(&inc.as_str()) {
                errs.push(format!("`include` entry \"{inc}\" is duplicated"));
            }
            seen.push(inc.as_str());
        }
    }

    fn check_reasons(&self, errs: &mut Vec<String>) {
        if let Some(net) = &self.net {
            if let Some(proxy) = &net.proxy {
                for a in proxy.allow.entries() {
                    let who = a
                        .name
                        .as_deref()
                        .or(a.cidr.as_deref())
                        .unwrap_or("<unnamed>");
                    if is_blank(a.reason.as_deref()) {
                        errs.push(format!(
                            "[[net.proxy.allow]] \"{who}\" is missing a `reason`"
                        ));
                    }
                }
                if let Some(deny) = &proxy.deny {
                    for d in deny.invariant.iter().chain(deny.policy.entries()) {
                        if is_blank(d.reason.as_deref()) {
                            errs.push(format!(
                                "[[net.proxy.deny]] \"{}\" is missing a `reason`",
                                d.cidr
                            ));
                        }
                    }
                }
            }
            if let Some(bpf) = &net.bpf {
                let acls = bpf.connect.iter().chain(&bpf.bind);
                for acl in acls {
                    for r in acl.allow.entries().chain(acl.deny.entries()) {
                        let who = r.cidr.as_deref().unwrap_or("<no-cidr>");
                        if is_blank(r.reason.as_deref()) {
                            errs.push(format!("[[net.bpf]] \"{who}\" is missing a `reason`"));
                        }
                    }
                }
            }
        }
        if let Some(unix) = &self.unix {
            for a in unix.allow.entries() {
                let who = a
                    .name
                    .as_deref()
                    .or(a.real.as_deref())
                    .unwrap_or("<unnamed>");
                if is_blank(a.reason.as_deref()) {
                    errs.push(format!("[[unix.allow]] \"{who}\" is missing a `reason`"));
                }
            }
        }
        if let Some(fs) = &self.fs {
            // A path-list *increment* requires a `reason` on every add/remove; the bare-set form
            // carries plain paths with no reason.
            for (label, field) in [
                ("fs.read", &fs.read),
                ("fs.write", &fs.write),
                ("fs.deny", &fs.deny),
            ] {
                for e in field.iter().flat_map(PathField::delta_entries) {
                    if is_blank(e.reason.as_deref()) {
                        errs.push(format!(
                            "[[{label}.*]] \"{}\" is missing a `reason`",
                            e.path
                        ));
                    }
                }
            }
            if let Some(dev) = &fs.dev {
                for d in dev.passthrough.entries() {
                    let who = d.path.as_deref().unwrap_or("<no-path>");
                    if is_blank(d.reason.as_deref()) {
                        errs.push(format!(
                            "[[fs.dev.passthrough]] \"{who}\" is missing a `reason`"
                        ));
                    }
                }
            }
        }
        if let Some(exec) = &self.exec {
            for e in exec.allow.iter().flat_map(PathField::delta_entries) {
                if is_blank(e.reason.as_deref()) {
                    errs.push(format!(
                        "[[exec.allow.*]] \"{}\" is missing a `reason`",
                        e.path
                    ));
                }
            }
        }
        if let Some(ssh) = &self.ssh {
            for d in ssh.destinations.entries() {
                let who = d.dest.as_deref().unwrap_or("<no-dest>");
                if is_blank(d.reason.as_deref()) {
                    errs.push(format!(
                        "[[ssh.destinations]] \"{who}\" is missing a `reason`"
                    ));
                }
            }
        }
    }

    /// A runnable **leaf** (a `name` + `template_base`) may not declare
    /// `[[net.proxy.deny.invariant]]` floors; invariants are template- and fragment-author tools.
    /// A template (`template_name`) or a fragment (`name`, no
    /// `template_base`) may; only the most-derived runnable leaf is barred.
    fn check_leaf_invariants(&self, errs: &mut Vec<String>) {
        if self.is_leaf() && self.template_base.is_some() && !self.invariant_denies().is_empty() {
            errs.push(
                "a leaf policy may not declare `[[net.proxy.deny.invariant]]`; invariants are \
                 template- and fragment-author tools"
                    .to_owned(),
            );
        }
    }

    /// Refuse-to-broker check: a `[dbus.*.allow]` entry that names (or whose
    /// wildcard admits) a categorically un-brokerable destination (Secret Service,
    /// session/process control) is a compile error, not a footgun. The same axiom
    /// carve-out as the signing oracle.
    fn check_dbus(&self, errs: &mut Vec<String>) {
        let Some(dbus) = &self.dbus else { return };
        for (bus_name, bus) in [("session", &dbus.session), ("system", &dbus.system)] {
            let Some(allow) = bus.as_ref().and_then(|b| b.allow.as_ref()) else {
                continue;
            };
            let entries = allow
                .talk
                .iter()
                .chain(&allow.call)
                .chain(&allow.broadcast)
                .chain(&allow.own);
            for entry in entries {
                let dest = dbus_destination(entry);
                if let Some(refused) = DBUS_REFUSE_TO_BROKER
                    .iter()
                    .find(|r| dbus_pattern_admits(dest, r))
                {
                    errs.push(format!(
                        "[dbus.{bus_name}.allow] `{entry}` reaches `{refused}`, which cannot be \
                         brokered to a kennel (a credential oracle or session-control \
                         escape — refused by axiom, not a footgun)"
                    ));
                }
            }
        }
    }

    /// Whether this artefact is *additive-only*: the gate an included **fragment** must pass. It
    /// may **add** rules but never remove or override.
    ///
    /// In the unified model a fragment is an ordinary [`SourcePolicy`] whose list fields are all
    /// add-only increments ([`PathField::is_additive`] / [`ListField::is_additive`]) and which sets
    /// none of the override-prone scalar/replace sections (a fragment carries only `name`, `include`,
    /// additive deltas, and `[[net.proxy.deny.invariant]]` floors). A `Set`-replace or a `*.remove`
    /// on any list, or any scalar section that would override an inherited value, makes it non-additive.
    #[must_use]
    pub fn is_additive_only(&self) -> bool {
        let path_ok = |f: &Option<PathField>| f.as_ref().is_none_or(PathField::is_additive);
        let fs_ok = self.fs.as_ref().is_none_or(|fs| {
            path_ok(&fs.read)
                && path_ok(&fs.write)
                && path_ok(&fs.deny)
                && fs.exclusive.is_none()
                && fs.home.is_none()
                && fs.tmp.is_none()
                && fs.proc.is_none()
                && fs.dev.as_ref().is_none_or(|d| d.passthrough.is_additive())
        });
        let exec_ok = self.exec.as_ref().is_none_or(|e| {
            path_ok(&e.allow)
                && e.deny.is_none()
                && e.path.is_none()
                && e.shell.is_none()
                && e.deny_setuid.is_none()
                && e.deny_setgid.is_none()
                && e.deny_setcap.is_none()
                && e.deny_writable.is_none()
        });
        let net_ok = self.net.as_ref().is_none_or(|n| {
            // mode/listen/bind/ipv6/audit are overrides; the proxy allow + deny.policy and the bpf
            // ACLs must be add-only. The `[[net.proxy.deny.invariant]]` floor is additive (unioned).
            n.mode.is_none()
                && n.proxy_listen_v4_address.is_none()
                && n.proxy_listen_v6_address.is_none()
                && n.bind.is_none()
                && n.ipv6.is_none()
                && n.audit.is_none()
                && n.proxy.as_ref().is_none_or(|p| {
                    p.allow.is_additive() && p.deny.as_ref().is_none_or(|d| d.policy.is_additive())
                })
                && n.bpf.as_ref().is_none_or(|b| {
                    b.families.is_none()
                        && b.deny_families.is_none()
                        && b.connect
                            .as_ref()
                            .is_none_or(|a| a.allow.is_additive() && a.deny.is_additive())
                        && b.bind
                            .as_ref()
                            .is_none_or(|a| a.allow.is_additive() && a.deny.is_additive())
                })
        });
        let unix_ok = self
            .unix
            .as_ref()
            .is_none_or(|u| u.abstract_ns.is_none() && u.allow.is_additive());
        let ssh_ok = self
            .ssh
            .as_ref()
            .is_none_or(|s| s.destinations.is_additive());
        // No override-prone top-level section: a fragment adds capability, never reshapes the cage.
        let top_ok = self.cap.is_none()
            && self.identity.is_none()
            && self.provides.is_empty()
            && self.consumes.is_empty()
            && self.service.is_none()
            && self.unsafe_section.is_none()
            && self.env.is_none()
            && self.seccomp.is_none()
            && self.lifecycle.is_none()
            && self.audit.is_none()
            && self.ulimits.is_none()
            && self.workload.is_none()
            && self.tty.is_none()
            && self.trust.is_none()
            && self.dbus.is_none()
            && self.rootfs.is_none()
            && self.spawn.is_none()
            && self.mutable.is_empty();
        fs_ok && exec_ok && net_ok && unix_ok && ssh_ok && top_ok
    }

    /// A fragment's `[[net.proxy.allow.add]]` entries: the increment a conflicting-include check
    /// compares across fragments. Empty when the proxy allow is absent or a (non-fragment) `Set`.
    #[must_use]
    pub fn net_allow_adds(&self) -> &[NetAllow] {
        match self
            .net
            .as_ref()
            .and_then(|n| n.proxy.as_ref())
            .map(|p| &p.allow)
        {
            Some(ListField::Delta(d)) => &d.add,
            _ => &[],
        }
    }

    /// A fragment's `[[net.proxy.deny.invariant]]` floors: the non-removable denies it contributes.
    #[must_use]
    pub fn invariant_denies(&self) -> &[NetDenyRule] {
        self.net
            .as_ref()
            .and_then(|n| n.proxy.as_ref())
            .and_then(|p| p.deny.as_ref())
            .map_or(&[], |d| d.invariant.as_slice())
    }
}

/// Whether an optional string is absent or whitespace-only.
fn is_blank(s: Option<&str>) -> bool {
    s.is_none_or(|v| v.trim().is_empty())
}

/// Unique key for a `[[net.proxy.allow]]` entry (name, else cidr): the dedup/match key the fold
/// and the include-conflict check use.
#[must_use]
pub(crate) fn net_key(a: &NetAllow) -> &str {
    a.name.as_deref().or(a.cidr.as_deref()).unwrap_or("")
}

/// Unique key for a `[[unix.allow]]` entry (name, else real).
#[must_use]
pub(crate) fn unix_key(a: &UnixAllow) -> &str {
    a.name.as_deref().or(a.real.as_deref()).unwrap_or("")
}

/// Unique key for a `[[ssh.destinations]]` entry (the destination string).
#[must_use]
pub(crate) fn ssh_key(a: &SshDestination) -> &str {
    a.dest.as_deref().unwrap_or("")
}

/// Unique key for a `[[fs.dev.passthrough]]` entry (the device path).
#[must_use]
pub(crate) fn dev_key(a: &DevPassthrough) -> &str {
    a.path.as_deref().unwrap_or("")
}

/// Unique key for a `[[net.bpf.*]]` rule (its cidr).
#[must_use]
pub(crate) fn bpf_key(a: &BpfRule) -> &str {
    a.cidr.as_deref().unwrap_or("")
}

/// Unique key for a `[[net.proxy.deny.policy]]` rule (its cidr).
#[must_use]
pub(crate) const fn deny_key(a: &NetDenyRule) -> &str {
    a.cidr.as_str()
}

/// Validate a template/fragment reference: a bare `<name>`.
pub(crate) fn validate_reference(reference: &str) -> Result<(), String> {
    validate_ref_name(reference)
}

/// Validate the `<name>` part of a reference: `[a-z0-9][a-z0-9-]{0,63}`.
pub(crate) fn validate_ref_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("name must be 1..=64 characters".to_owned());
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return Err("name must start with a lowercase letter or digit".to_owned()),
    }
    if chars.any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
        return Err("name may contain only lowercase letters, digits, and `-`".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod dbus_tests {
    use super::*;

    fn parse_ok(toml: &str) -> SourcePolicy {
        let p = parse(toml.as_bytes()).expect("parse");
        p.validate().expect("validate");
        p
    }

    #[test]
    fn benign_dbus_grants_parse_and_validate() {
        let p = parse_ok(
            "name = \"k\"\ntemplate_base = \"base-confined\"\n\
             [dbus.session]\nenabled = true\n\
             [dbus.session.allow]\ntalk = [\"org.freedesktop.Notifications\", \"org.freedesktop.portal.*\"]\n\
             [dbus.audit]\nlevel = \"summary\"\n",
        );
        let dbus = p.dbus.expect("dbus");
        assert_eq!(dbus.session.expect("session").enabled, Some(true));
    }

    #[test]
    fn refuse_to_broker_destinations_are_a_compile_error() {
        // Exact name, and a wildcard that admits a refused name, both rejected; system bus too.
        for entry in [
            "org.freedesktop.secrets",
            "org.freedesktop.systemd1",
            "org.gnome.SessionManager",
            "org.freedesktop.*", // admits secrets/systemd1/login1
            "*",
        ] {
            let toml = format!(
                "name = \"k\"\ntemplate_base = \"base-confined\"\n\
                 [dbus.session]\nenabled = true\n[dbus.session.allow]\ntalk = [\"{entry}\"]\n"
            );
            let err = parse(toml.as_bytes())
                .expect("parses")
                .validate()
                .expect_err(&format!("`{entry}` must be refused"));
            assert!(
                matches!(err, PolicyError::SourceValidation(_)),
                "got {err} for {entry}"
            );
        }
    }

    #[test]
    fn refuse_check_covers_call_own_and_the_system_bus() {
        let toml = "name = \"k\"\ntemplate_base = \"base-confined\"\n\
             [dbus.system]\nenabled = true\n\
             [dbus.system.allow]\ncall = [\"org.freedesktop.login1=org.freedesktop.login1.Manager.Reboot\"]\n";
        assert!(parse(toml.as_bytes()).expect("parse").validate().is_err());
    }

    #[test]
    fn pattern_admits_matches_exact_prefix_and_catchall() {
        assert!(dbus_pattern_admits(
            "org.freedesktop.secrets",
            "org.freedesktop.secrets"
        ));
        assert!(dbus_pattern_admits(
            "org.freedesktop.*",
            "org.freedesktop.secrets"
        ));
        assert!(dbus_pattern_admits("*", "anything.at.all"));
        // A sibling prefix must NOT admit: `org.freedesktop.portal.*` does not reach secrets.
        assert!(!dbus_pattern_admits(
            "org.freedesktop.portal.*",
            "org.freedesktop.secrets"
        ));
        assert!(!dbus_pattern_admits(
            "org.freedesktop.Notifications",
            "org.freedesktop.secrets"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CONFINED: &str =
        include_str!("../../../../toml/templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../toml/templates/ai-coding-strict/policy.toml");
    const PACKAGE_INSTALL: &str =
        include_str!("../../../../toml/templates/package-install/policy.toml");
    const UNTRUSTED_BUILD: &str =
        include_str!("../../../../toml/templates/untrusted-build/policy.toml");
    const INSPECT_ONLY: &str = include_str!("../../../../toml/templates/inspect-only/policy.toml");
    const CONTAINERISED_SERVICE: &str =
        include_str!("../../../../toml/templates/containerised-service/policy.toml");

    const ALL_TEMPLATES: &[(&str, &str)] = &[
        ("base-confined", BASE_CONFINED),
        ("ai-coding-strict", AI_CODING_STRICT),
        ("package-install", PACKAGE_INSTALL),
        ("untrusted-build", UNTRUSTED_BUILD),
        ("inspect-only", INSPECT_ONLY),
        ("containerised-service", CONTAINERISED_SERVICE),
    ];

    #[test]
    fn every_in_tree_template_parses_and_validates() {
        for (name, src) in ALL_TEMPLATES {
            let parsed = parse(src.as_bytes());
            assert!(
                parsed.is_ok(),
                "template {name} failed to parse: {parsed:?}"
            );
            let pol = parsed.expect("checked ok above");
            let validated = pol.validate();
            assert!(
                validated.is_ok(),
                "template {name} failed to validate: {validated:?}"
            );
            assert_eq!(
                pol.template_name.as_deref(),
                Some(*name),
                "template {name} name"
            );
            assert!(!pol.is_leaf(), "template {name} must not be a leaf");
        }
    }

    #[test]
    fn base_confined_is_the_root_with_no_parent() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        assert!(pol.template_base.is_none(), "base-confined is the root");
        let cap = pol.cap.expect("cap section");
        assert_eq!(cap.no_new_privs, Some(true));
        assert_eq!(cap.bounding_set.as_deref(), Some(&[][..]));
    }

    #[test]
    fn base_confined_carries_the_invariant_denies_with_reasons() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let net = pol.net.expect("net section");
        let deny = net.proxy.expect("net.proxy").deny.expect("net.proxy.deny");
        assert!(
            deny.invariant
                .iter()
                .any(|d| d.cidr == "169.254.169.254/32"),
            "cloud-metadata deny present"
        );
        assert!(
            deny.invariant
                .iter()
                .all(|d| !is_blank(d.reason.as_deref())),
            "every invariant deny has a reason"
        );
    }

    #[test]
    fn derived_templates_name_their_parent_by_versioned_reference() {
        for (name, src) in ALL_TEMPLATES.iter().filter(|(n, _)| *n != "base-confined") {
            let pol = parse(src.as_bytes()).expect("parse");
            assert_eq!(
                pol.template_base.as_deref(),
                Some("base-confined"),
                "template {name} extends base-confined"
            );
        }
    }

    #[test]
    fn ai_coding_strict_grants_net_allow_and_no_agent_sockets() {
        let pol = parse(AI_CODING_STRICT.as_bytes()).expect("parse");
        let net = pol.net.expect("net");
        let proxy = net.proxy.expect("net.proxy");
        assert!(proxy
            .allow
            .iter()
            .any(|a| a.name.as_deref() == Some("github.com")));
        assert!(
            proxy.allow.iter().all(|a| !is_blank(a.reason.as_deref())),
            "every allow has a reason"
        );
        // No agent sockets at all. GPG/commit signing cannot be made safe in a kennel
        // (a signing oracle) — there is no gpg-agent shim; and an exposed ssh-agent
        // is a destination-blind oracle, so SSH is routed via the bastion, not a shim.
        let has_agent = pol.unix.as_ref().is_some_and(|u| {
            u.allow.iter().any(|a| {
                a.name.as_deref() == Some("gpg-agent")
                    || a.name.as_deref() == Some("ssh-agent")
                    || a.env.as_deref() == Some("SSH_AUTH_SOCK")
            })
        });
        assert!(
            !has_agent,
            "ai-coding-strict ships no gpg-agent or ssh-agent shim"
        );
    }

    #[test]
    fn env_set_is_an_inline_table() {
        let pol = parse(BASE_CONFINED.as_bytes()).expect("parse");
        let env = pol.env.expect("env");
        let set = env.set.expect("env.set");
        assert_eq!(set.get("TMPDIR").map(String::as_str), Some("/tmp"));
    }

    #[test]
    fn container_block_is_now_rejected_at_parse() {
        // [container] was design-level language (parse + compile-warn, no runtime). It is now
        // removed from the schema entirely — assumptions on unbuilt code are off — so a policy
        // declaring it fails `deny_unknown_fields` at parse, rather than compiling with a warning.
        let src = "\
template_name = \"x\"
[container]
image = \"docker.io/library/postgres:17\"
";
        assert!(
            parse(src.as_bytes()).is_err(),
            "[container] is no longer a known section"
        );
    }

    #[test]
    fn containerised_service_is_an_honest_direct_service() {
        // The rewritten template carries NO [container] block — the kennel is the
        // container. It derives base-confined, persists one data dir, and stays
        // deny-by-default on exec (the leaf adds the server binary).
        let pol = parse(CONTAINERISED_SERVICE.as_bytes()).expect("parse");
        let fs = pol.fs.expect("fs");
        assert!(
            fs.write
                .as_ref()
                .is_some_and(|w| w.resolved().iter().any(|p| p.contains("data/<kennel>"))),
            "persists one data dir"
        );
    }

    #[test]
    fn ulimits_section_parses_into_a_name_value_map() {
        let src = "template_name = \"x\"\n\n[ulimits]\nnofile = \"8192\"\nas = \"4G\"\ncpu = \"unlimited\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let ulimits = pol.ulimits.expect("ulimits");
        assert_eq!(ulimits.get("nofile").map(String::as_str), Some("8192"));
        assert_eq!(ulimits.get("as").map(String::as_str), Some("4G"));
        assert_eq!(ulimits.get("cpu").map(String::as_str), Some("unlimited"));
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let src = "template_name = \"x\"\nbogus_key = 1\n";
        assert!(
            parse(src.as_bytes()).is_err(),
            "deny_unknown_fields rejects bogus_key"
        );
    }

    #[test]
    fn unknown_key_in_known_section_is_rejected() {
        let src = "template_name = \"x\"\n[cap]\nno_new_privs = true\nnope = 1\n";
        assert!(
            parse(src.as_bytes()).is_err(),
            "deny_unknown_fields rejects nested unknown"
        );
    }

    #[test]
    fn leaf_without_template_base_is_rejected() {
        let src = "name = \"myproj\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(pol.is_leaf());
        let err = pol
            .validate()
            .expect_err("leaf with no template_base must fail");
        assert!(matches!(err, PolicyError::SourceValidation(_)));
    }

    #[test]
    fn artefact_with_both_identities_is_rejected() {
        let src = "template_name = \"t\"\nname = \"n\"\ntemplate_base = \"base-confined\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(
            pol.validate().is_err(),
            "template_name + name is incoherent"
        );
    }

    #[test]
    fn net_allow_without_reason_is_rejected() {
        let src = "name = \"n\"\ntemplate_base = \"base-confined\"\n\
                   [[net.proxy.allow]]\nname = \"evil.example\"\nports = [443]\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let err = pol.validate().expect_err("missing reason must fail");
        assert!(
            matches!(err, PolicyError::SourceValidation(_)),
            "expected SourceValidation, got {err}"
        );
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms
                .iter()
                .any(|m| m.contains("evil.example") && m.contains("reason")));
        }
    }

    #[test]
    fn malformed_template_reference_is_rejected() {
        // A reference is a bare name; disallowed characters (@, space, uppercase) are rejected.
        let cases = ["base-confined@4", "Bad", "base confined", "base-confined@v"];
        for case in cases {
            let src = format!("name = \"n\"\ntemplate_base = \"{case}\"\n");
            let pol = parse(src.as_bytes()).expect("parse");
            assert!(pol.validate().is_err(), "reference {case} must be rejected");
        }
        // A well-formed bare-name reference validates.
        let src = "name = \"n\"\ntemplate_base = \"base-confined\"\n";
        let pol = parse(src.as_bytes()).expect("parse");
        assert!(pol.validate().is_ok(), "well-formed reference accepted");
    }

    #[test]
    fn duplicate_include_is_rejected() {
        let src = "name = \"n\"\ntemplate_base = \"base-confined\"\n\
                   include = [\"corp-egress\", \"corp-egress\"]\n";
        let pol = parse(src.as_bytes()).expect("parse");
        let err = pol.validate().expect_err("duplicate include must fail");
        assert!(
            matches!(err, PolicyError::SourceValidation(_)),
            "expected SourceValidation, got {err}"
        );
        if let PolicyError::SourceValidation(ms) = err {
            assert!(ms.iter().any(|m| m.contains("duplicated")));
        }
    }
}
