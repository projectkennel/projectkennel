# API surfaces — config schema

## Stability commitment

**Stable** per `02-0-overview.md`. The policy TOML schema is backwards-compatible across minor versions:

- New fields are additive. Older binaries reading newer policies ignore fields they do not recognise unless the field is marked `required-since` (in which case the older binary refuses to load the policy, with a clear error naming the required field).
- Existing fields do not change name or type within a major version.
- Existing fields' *semantics* do not narrow within a major version. A field's accepted value set may widen; it may not shrink.
- Removals follow the deprecation discipline in `02-0-overview.md`: announced, warned at load time, kept for at least one minor version before removal.

The schema does not carry a top-level version field. The project's CHANGELOG records when the schema changed and what migration (if any) is needed. Templates carry their own `template_version`; that field is independent of the schema's version.

This chapter describes the *schema*. The canonical worked example is [TEMPLATE-ai-coding-strict.md](../design/TEMPLATE-ai-coding-strict.md), which exhibits every section type in a real policy. Read that file first if the structure is unfamiliar.

---

## File layout

A policy file is TOML. The parser rejects on:

- Unknown top-level keys or unknown keys in known sections (`#[serde(deny_unknown_fields)]`).
- Duplicate keys at any level.
- Type mismatches at any field.
- Tilde (`~`) prefixed paths in fields the schema declares as absolute.
- `..` components in fields the schema declares as relative.
- Strings exceeding the per-field length limits documented in this chapter.

Validation happens after parsing, before signature verification, before any field is acted upon. A malformed file is rejected categorically; signatures are not checked against unparseable content.

---

## Top-level fields

Every policy file has the following top-level fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `template_base` | versioned reference | Yes for templates and leaf policies; No for the root template (`base-confined`) | Names the parent template as `<name>@<version>`. Resolution walks the chain to the root. See §Versioned references. |
| `template_version` | string | Legacy; optional | The two-field form. Accepted for backward compatibility when `template_base` carries no `@version`; the combined form is canonical. |
| `template_name` | string | Yes for templates; No for leaf policies | The template's own name. Leaf policies use the kennel name from `name`. |
| `name` | string | Yes for leaf policies; No for templates | The kennel name. Matches the leaf policy's filename without `.toml`. |
| `include` | array of versioned references | No | Additional signed fragments composed additively. See §Includes. |
| `threat_catalogue_version` | string | Yes | The version of `THREATS.md` the template was authored against. Used to detect catalogue drift. |
| `signature` | object | Yes for templates and fragments; optional for leaf policies | Signature envelope over the artefact's content; see §Signatures. |

The parser produces a structurally typed value before any field is read; raw `toml::Value` is not retained past parse (`10.5` in CODING-STANDARDS.md).

---

## Section catalogue

A policy is the union of an `[exec]` section, an `[fs]` section, and so on. Each section is independently typed and independently validated. Sections present in the template chain are inherited; sections in a leaf policy delta the inheritance.

The full section list:

| Section | Purpose | Detailed in (design doc) |
|---|---|---|
| `[exec]` | What binaries the workload may execve() | §7.1 |
| `[fs]` and `[fs.*]` | Filesystem read/write access, shim construction, scrub patterns | §7.2 |
| `[net]` and `[net.*]` | Network egress allowlist, proxy listen, loopback rules, bind rules, audit | §7.3 |
| `[unix]` | AF_UNIX socket allowlist, abstract-namespace handling | §7.4 |
| `[dbus]` | D-Bus session/system bus enablement and method filtering | §7.5 |
| `[x11]` | X11/Wayland display server isolation | §7.6 |
| `[env]` | Environment variable pass-through, deny patterns, forced values | §7.7 |
| `[cap]` | Capabilities and `no_new_privs` | §7.7 |
| `[seccomp]` | Seccomp filter | §7.7 |
| `[proc]` | Procfs visibility and hidepid | §7.7 |
| `[ptrace]` | Ptrace allow/deny across kennel boundary | §7.7 |
| `[signal]` | Signal allow/deny across kennel boundary | §7.7 |
| `[lifecycle]` | TTL and TTL-action | §9 |
| `[audit]` and `[audit.*]` | Audit sinks (file, journald, syslog, stdout), per-class levels, file rotation parameters | §8.6 |

Each section's specific fields are documented in the corresponding design-document chapter. This chapter describes *how the sections compose and inherit*, not what each field means.

---

## Path syntax

Fields that name filesystem paths use the following syntax:

- `~/foo/bar` — relative to the workload's `$HOME` after the shim is constructed. Tilde expansion is performed by Project Kennel, not by the workload's shell.
- `/abs/path` — absolute, against the host filesystem as seen *before* shim construction. Most absolute paths are reserved for system files (`/etc/*`, `/usr/*`); user data lives under `~/`.
- `<kennel>/foo` — Project Kennel placeholder, expanded to the kennel's runtime ID at load time.
- `**` and `*` — glob suffixes. `**` matches across path separators; `*` does not.

Tilde expansion does not happen until signature verification of the file containing the tilde-path completes. An attacker-controlled template cannot use `~/.ssh/...` to refer to the operator's keys at parse time.

Paths in `fs.read`, `fs.write`, `fs.deny`, `unix.allow[].real`, and `unix.allow[].shim` follow this syntax. Paths in `exec.allow` and `exec.deny` are absolute only — no `~` expansion, no glob `**` (specific paths or `glob` patterns within a directory only, to avoid inadvertent broad grants).

---

## Versioned references

A *versioned reference* names a template or fragment together with the exact version to resolve: `<name>@<version>`. It appears in `template_base` and in each element of `include`.

Grammar:

- `<name>` matches `[a-z0-9][a-z0-9-]{0,63}`.
- The separator is a literal `@`.
- `<version>` is `v` followed by a semver core: `v4`, `v4.2`, `v2.33.2`. The leading `v` is required.

Examples: `ai-coding-strict@v4`, `corp-egress-allowlist@v2.33.2`.

The parser rejects a `template_base` or `include` element that:

- omits the `@version` (production mode); development mode resolves to the highest installed version and warns.
- carries a malformed name or version.
- appears more than once in `include` (duplicate references are an error).

The legacy two-field form (`template_base = "ai-coding-strict"` with a separate `template_version = "4"`) is accepted when `template_base` carries no `@`. The two forms are mutually exclusive on a single reference; a `template_base` that carries `@v4` *and* a `template_version` field is a conflict error.

### Resolution and verification of a reference

Resolving one versioned reference:

1. Locate the artefact for the exact `(name, version)` in the search path (§File location).
2. Parse it (the same parse/validate discipline as any policy file).
3. Verify its `[signature]` envelope against the trust store (§Signatures). A reference whose artefact fails signature verification is refused; the content is not composed.
4. Compute the SHA-256 of the artefact's canonical-form content.
5. Check the hash against the lockfile (§The lockfile). On first resolution, record it; on subsequent resolution, a mismatch is a hard error.

Steps 3–5 are what make a reference a supply-chain control rather than a name lookup. Version pinning alone constrains *which* artefact is named; the signature and the lockfile constrain *what bytes* are composed. This is the same reasoning the dependency policy applies to Rust crates (CODING-STANDARDS.md §5.5).

### The lockfile

`kennel.lock` sits beside the leaf policy. It records, for every reference resolved while loading that policy (the inheritance chain and every include, transitively), one entry:

```toml
[[locked]]
name = "ai-coding-strict"
version = "v4"
content_sha256 = "e8d3...<full hex>"
signing_key_id = "kennel-maint-2026-01"

[[locked]]
name = "corp-egress-allowlist"
version = "v2.33.2"
content_sha256 = "91af...<full hex>"
signing_key_id = "corp-policy-2026"
```

On load, the resolver recomputes each artefact's `content_sha256` and compares against the lockfile. A mismatch — same `(name, version)`, different bytes — is `PolicyError::LockMismatch`, naming the reference. The only sanctioned way to change a locked entry is `kennel upgrade`, which surfaces the content change for review before rewriting the lockfile.

A policy committed to source control alongside its `kennel.lock` is a reproducible specification: resolving it against the same trust store yields byte-identical effective policy or a hard failure. A missing lockfile triggers first-resolution recording (trust-on-first-use); production deployments may require a present, matching lockfile via system configuration.

---

## Includes

`include` is an array of versioned references to *fragments* — signed, version-pinned policy pieces composed additively into the effective policy. Fragments let cross-cutting policy (a corporate egress allowlist, a mandated audit baseline) be reused across templates that do not share an inheritance line.

```toml
template_base = "ai-coding-strict@v4"
include = [
    "corp-egress-allowlist@v2.33.2",
    "corp-audit-baseline@v1.4.0",
]
```

A fragment is structurally a template: same schema, same `[signature]` requirement, same parse/validate/verify/lock discipline. The difference is in what it may contain and how it composes:

- **Additive-only.** A fragment may use `[[<section>.add]]` and `[[<section>.*.invariant]]`. It may *not* use `.remove`, `.replace`, or scalar `.override`. The validator rejects a fragment that does. Additive-only composition is order-independent and free of diamond-resolution ambiguity.
- **No inheritance of its own resolution into the parent's chain.** A fragment may itself declare `template_base` only as `base-confined` (or none); it does not splice a competing inheritance line into the including policy. A fragment that names a non-base `template_base` is rejected.
- **Conflict is an error, not last-wins.** If two includes contribute entries with the same unique key (e.g., two `[[net.allow]]` for the same host with different ports), resolution fails with `PolicyError::IncludeConflict` naming both fragments. The author reconciles deliberately.

---

## Template inheritance

A leaf policy, its inheritance chain, and its includes compose into an *effective* policy by the following rules.

### Resolution order

1. Start from the leaf policy. Parse, validate, verify signature (if present), lock-check.
2. Read `template_base` (a versioned reference). Resolve and verify it (§Resolution and verification of a reference).
3. Recurse on that template's `template_base`. Resolve up to the root template (`base-confined`), which has no `template_base`. This yields the linear inheritance chain, root-first.
4. Fold the inheritance chain into a base effective policy (root first, each child's deltas applied in turn).
5. Resolve every `include` reference (of the leaf policy and of each template in the chain), verify and lock-check each, and apply them additively in listed order.
6. Apply the leaf policy's own deltas last.

The inheritance chain depth is bounded at 16 (see `INVARIANTS` below). The total number of resolved references (chain plus includes, transitively) is bounded at 64. A circular reference — in inheritance or in includes — is rejected at parse time, before any signature is verified.

### Composition

For each section, the effective value is the union/override of the chain, with leaf-policy operators determining how:

- `[exec.allow]` and similar list-valued fields use *delta operators* in the leaf policy:
  - `[fs.read.add]` — appends entries.
  - `[fs.read.remove]` — removes entries from the inherited set, with a `reason` required for each removal.
  - `[fs.read.replace]` — replaces the inherited list entirely; requires a `reason`.
- Scalar fields (e.g., `[lifecycle].ttl`) are overridden by the most-leaf value that sets them.
- Object fields (e.g., `[fs.home]`) are merged shallowly: leaf fields override template fields key-by-key.

### Delta requirements

Every delta operation requires a `reason` field. The reason is free text, but the schema enforces that it is present and non-empty. The `kennel diff --threat-impact` view surfaces deltas with their reasons and any threat IDs the delta references.

A delta cannot weaken a *framework invariant* (see below). Attempting to do so causes the validator to reject the policy with `PolicyError::InvariantViolated`, naming the field.

### Threat tagging

Each delta and each `[[net.allow]]` entry may carry a `threats.exposed` array listing threat IDs (`["T8", "T9"]`) that this entry exposes. The list is informational; tooling reads it but does not enforce.

The threat IDs must be present in the version of `THREATS.md` named by `threat_catalogue_version`. The validator does not require the IDs to be there at parse time (the catalogue may not be available), but `kennel validate --strict-invariants` does check.

---

## Framework invariants

Certain properties cannot be weakened by any user delta, regardless of `reason`. These are framework invariants. The schema validator rejects policies that violate them.

The current invariants (mechanism details in design doc §12):

- `cap.no_new_privs = true`. Cannot be set false.
- `exec.deny_setuid = true`, `exec.deny_setgid = true`, `exec.deny_setcap = true`, `exec.deny_writable = true`. Cannot be set false.
- `fs.home.shadow = true`. The shim is mandatory.
- `[fs.home.shim_root]` must be under `/run/kennel/<kennel>/`.
- `[net.mode]` may be `"constrained"` or `"open"` (the latter only for `ai-coding-permissive`-style templates); it may not be `"unrestricted"` or absent.
- `[net.deny.invariant]` entries (cloud metadata, link-local, RFC1918) are present and cannot be removed by any delta.
- `[proc.visibility] = "self"`.
- `[fs.dev.allow]` is the default-deny list documented in design §7.7; user deltas may not add device files outside the framework-known safe set without an explicit `framework_override` flag (which is itself an invariant override and requires a separate signed envelope; see `04-trust-boundaries.md`).

Framework invariants are declared in `schema/invariants.toml` and surfaced in `kennel templates inspect`. Adding an invariant is a major-version event; removing one is also a major-version event.

---

## Signatures

Templates and fragments are signed. The signature covers the artefact's *content* — the substantive policy, not merely a filename or a version label — so that resolving a versioned reference (§Versioned references) yields exactly the bytes a trusted key signed for that version. The signature envelope:

```toml
[signature]
algorithm = "ed25519"
key_id = "kennel-maint-2026-01"
signature = "BASE64..."
signed_fields = ["template_base", "include", ..., "lifecycle"]
```

The signature is over the canonical-form serialisation of `signed_fields`, computed by the procedure documented in `02-6-internal-api.md` under `kennel-policy::canonical`. The canonical form pins field order, normalises whitespace, and excludes the `[signature]` block itself. The `content_sha256` recorded in the lockfile (§The lockfile) is the SHA-256 of this same canonical-form content, so the lockfile pins precisely the bytes the signature covered.

Signature verification rules:

- The signing key must be in the configured key set (the project's maintainer keys, or the customer's organisation keys for self-signed templates and fragments). The key store is under `~/.config/kennel/keys/` and `/etc/kennel/keys/` (`07-paths.md`).
- The `algorithm` must be in the supported algorithm set (currently: `ed25519`). Cryptographic minimums are enforced at validation; negotiation below the current floor is a categorical error.
- The `signed_fields` list must cover every top-level field of the artefact *except* `[signature]` itself — including `template_base` and `include`, so the reference's own dependency declarations are signed. An artefact that signs only a subset of its fields is rejected.
- An artefact whose signature does not verify is rejected even if the unverified fields are not consulted.

Leaf policies may be unsigned. The user wrote them; they are loaded under the user's authority. An organisation may require leaf-policy signing via a configured policy enforcer, but the schema does not mandate it. A leaf policy's `kennel.lock` still pins the signed artefacts it references, so an unsigned leaf composing signed templates and fragments is still byte-reproducible.

---

## Variable substitution

The following placeholders are substituted at load time:

| Placeholder | Meaning |
|---|---|
| `<kennel>` | The kennel's runtime ID (e.g., the kennel name for named kennels, or the generated ID for `--template` ad-hoc kennels). |
| `<tag>` | The Project Kennel installation's tag byte (per-installation, fixed at install time). |
| `<ctx>` | The kennel's allocated context byte (per-kennel, assigned at start by kenneld). |
| `<gid>` | The IPv6 ULA `<gid>` byte for this installation (random at install time). |
| `<uid>` | The user's UID as a decimal string. |

Substitution happens once at policy resolution; the substituted values are then immutable for the lifetime of the kennel. A template that uses `<ctx>` resolves to a different concrete value for each kennel that derives from it.

Substitution does not perform shell expansion: `$HOME` in a policy field is not expanded to the user's home. The shim's `$HOME` is referenced as `~/` (which is the workload's view, post-shim) or as `<kennel>/home` (which is the host path before shim construction).

---

## File location

Policies live under `~/.config/kennel/`:

- `~/.config/kennel/kennels/<name>.toml` — leaf policies.
- `~/.config/kennel/kennels/<name>.lock` — the lockfile beside each leaf policy.
- `~/.config/kennel/templates/<name>@<version>.toml` — local templates and fragments (cached or hand-installed). The filename encodes the versioned reference, so multiple versions of one name coexist.
- `~/.config/kennel/keys/` — installed signing keys (public only).

System-installed templates and fragments live under `/etc/kennel/templates/`. The search order for resolving a `<name>@<version>` reference is: user templates → system templates → built-in templates. The exact version must be found; the resolver does not fall back to a different version of the same name (that would defeat the pin). A template at a higher-priority location shadows the *same `name@version`* at lower priority, and the shadowing is logged at load time.

`07-paths.md` is authoritative for path locations.

---

## Schema evolution

When the schema changes, the change lands as one of three categories:

**Additive** — new optional field, new section, new permitted enum value. Old binaries reading newer policies see the new field as unknown and either ignore it (if marked `additive`) or refuse to load (if marked `required-since`).

**Deprecation** — an existing field is announced as deprecated, kept functional, surfaced with a warning at load time. Removal occurs no earlier than one minor version later.

**Breaking** — major-version event only. The old field is removed; binaries refuse to load policies that still use it.

The CHANGELOG entry for a schema change goes under `### Policy schema changes` and includes:

- Field name(s) affected.
- Category (additive / deprecation / breaking).
- Migration instructions for operator-authored policies.

---

## The settled policy (compilation)

> **As-built status (see `08-as-built-notes.md` §8.1/§8.2).** The implemented
> settled schema is authoritative in `src/crates/kennel-policy/src/settled.rs`. Two
> things to know when reading below. (1) The settled `effective_policy` carries
> only the **runtime-relevant** sections — `net`, `fs`, `exec`, `proc`, `cap`,
> `seccomp`, `lifecycle`; the source-only sections (`unix`, `dbus`, `x11`, `env`,
> `ptrace`, `signal`, `audit`) are compile-time concerns and are **not** present
> in the settled form, so "every section" below means that resolved subset.
> (2) Fields added since this chapter was written: `fs.tmp` (`private`,
> `size_mib`, `mode`), `fs.dev.allow`, `proc.hidepid`, `net.allow_names`
> (by-name proxy allowlist), and `net.proxy` (`offset`, `port`). Settled
> `FsPolicy` uses flat field names (`home_shadow`, `shim_root`), not nested
> `fs.home.*`.

The TOML schema above describes *source* policies — what an operator authors. The runtime does not enforce source policies directly. `kennel compile` resolves a source policy once and emits a **settled policy**: a flat, fully-resolved, signed artefact that the runtime consumes. The design rationale is in design doc §9.10; this section is the artefact's format and stability.

The split: all resolution (chain-walking, include merging, delta application, source-signature verification, lockfile byte-checks, invariant and threat-tag validation, installation-constant substitution) happens at compile time. The spawn path verifies one signature, re-asserts framework invariants, fills per-instance substitution slots, and builds kernel objects. It links none of the template machinery.

### Stability

The settled policy is an **internal-stable** surface per `02-0-overview.md`, with one external consumer: fleet/attestation tooling that distributes and verifies settled policies. It carries an explicit `settled_schema_version` integer. The compiler and the runtime within one release agree; across releases, the runtime accepts settled-policy schema versions back to the start of the current major version. Fleet tooling reads `settled_schema_version` and the `provenance` block; those two are treated as stable for the major version.

### Format

The settled policy is a TOML document, like every other Project Kennel config artefact — there is no second config format. It is machine-produced and machine-consumed (never hand-edited), but TOML serves a machine artefact just as well as a hand-authored one, and keeping one format avoids a second parser/serialiser dependency.

Reproducible hashing and signing do **not** require JSON's canonical form (sorted keys, normalised numbers): the canonical bytes are produced and verified by the *same* implementation, so a deterministic serialisation in fixed field order is sufficient and reproducible. (The schema carries no floating-point values, so "number normalisation" — the hard part of any canonicalisation — does not arise.) The procedure is documented under `kennel-policy::canonical`; the `[signature]` table is excluded from it. If independent third-party verification ever becomes a hard requirement, the signature would cover the literal stored payload bytes (still TOML), which is format-agnostic and needs no canonicaliser at all.

Top-level structure (the `[signature]` table is a sibling, excluded from the canonical form):

```toml
settled_schema_version = 1
name = "ai-coding"
deferred_substitutions = ["<ctx>", "<uid>", "<kennel>", "<home>"]
framework_invariants_asserted = [ "cap.no_new_privs", "..." ]  # ids the compiler checked

[effective_policy]
# ...flat resolved policy, every section, final values...

[provenance]
leaf_policy_sha256 = "..."
schema_version = 1
invariant_set_sha256 = "..."
threat_catalogue_version = "0.1"
compiler_version = "0.4.2"

[provenance.install_constants]
tag = 42
ula_gid = "..."

[[provenance.resolved_artifacts]]
name = "base-confined"
version = "v3"
content_sha256 = "..."
signing_key_id = "kennel-maint-2026-01"

[[provenance.resolved_artifacts]]
name = "corp-egress-allowlist"
version = "v2.33.2"
content_sha256 = "..."
signing_key_id = "corp-policy-2026"

[signature]
algorithm = "ed25519"
key_id = "corp-policy-2026"
signature = "BASE64..."
```

- `effective_policy` is the resolved policy: no `template_base`, no `include`, no delta operators (`.add`/`.remove`/`.override`/`.invariant`), only final rule sets. Installation-constant variables (`<tag>`, `<gid>`) are already substituted.
- `deferred_substitutions` lists the per-instance placeholders the runtime must fill. The runtime substitutes exactly these and refuses to spawn if any *other* unsubstituted placeholder is found in `effective_policy`.
- `framework_invariants_asserted` records which framework invariants the compiler validated. The runtime re-asserts them regardless (defence in depth, §below); the list is for audit, not for the runtime to trust.
- `provenance` makes the artefact self-describing: every input that produced it, by hash. `resolved_artifacts` embeds the relevant lockfile entries, so the settled policy records exactly which signed source bytes were composed, without those sources needing to be present at runtime.
- `signature` is over the canonical-form serialisation of every field except `signature` itself, by the compiling authority's key (`kennel-policy::canonical`, the same procedure as source signatures).

### Runtime consumption

`kennel run` against a settled policy:

1. Verify `signature` against the trust store. One verification; failure refuses the spawn.
2. Check `settled_schema_version` is in the supported range.
3. Re-assert framework invariants against `effective_policy` (see below). Failure refuses the spawn.
4. Substitute the `deferred_substitutions` with per-instance values; refuse if any other placeholder remains.
5. Build the Landlock ruleset, BPF maps, and mount plan from `effective_policy`; spawn.

### Framework invariants re-asserted at runtime

A valid signature means a trusted key vouched for the artefact; it does not mean the artefact upholds Project Kennel's structural guarantees, which are Project Kennel's and not the signer's. The runtime re-asserts the framework invariants (the same set in §Framework invariants above) on `effective_policy` as step 3, regardless of the signature. The checks are a handful of structural assertions and are cheap. A validly-signed settled policy that violates a framework invariant is refused.

This is the one place the runtime deliberately repeats compile-time work, and it is the property that lets the project state: no policy, however produced and whatever key signed it, can disable the protections that define a kennel.

### Two modes

- **Local development.** `kennel run` of a source policy auto-compiles in memory when no fresh settled artefact exists, seals the result by content hash plus lockfile, marks it a dev build, and runs it. Staleness is detected by comparing the settled policy's `provenance` hashes against the current source inputs; a mismatch triggers recompilation. `kennel compile` may also be run explicitly.
- **Fleet / attested.** The organisation compiles centrally and pushes only signed settled policies. The workstation need not hold the templates, fragments, lockfile, or exercise the resolver. The runtime trust surface is one signature verification plus the framework-invariant re-assertion.

### On-disk

Settled policies live beside their source under `~/.config/kennel/kennels/<name>.settled.toml` in development mode, or are pushed to `/etc/kennel/settled/<name>.settled.toml` (or a fleet-tool-chosen path) in attested deployments. `07-paths.md` is authoritative.

---

## What this chapter does not cover

- The field-by-field semantics of each section: see the corresponding design-document chapter (§7.x) or the worked example in [TEMPLATE-ai-coding-strict.md](../design/TEMPLATE-ai-coding-strict.md).
- The design-level treatment of signing, versioned references, and includes: design doc §5.10.
- The canonical-form serialisation procedure: `02-6-internal-api.md` (`kennel-policy::canonical`).
- The signing-key store and lockfile locations on disk: `07-paths.md`.
- The mechanism by which template and fragment signatures are verified at runtime, and how the lockfile is checked: `04-trust-boundaries.md`.
- How `kennel diff` and `kennel upgrade` compute and present deltas, and how `upgrade` rewrites the lockfile: `02-1-cli.md`.
- The `[audit]` schema in detail — sink selection, per-class levels, sink-specific parameters: `02-3-audit-schema.md`.
- The design-level rationale for compilation and the settled policy: design doc §9.10.
- How `kennel compile` is invoked and its flags: `02-1-cli.md`.
- How the runtime trust surface differs between source and settled policies: `04-trust-boundaries.md`.
