# API surfaces — config schema

## Stability commitment

**Stable** per `02-0-overview.md`. The policy TOML schema is backwards-compatible across minor versions:

- New fields are additive. Older binaries reading newer policies ignore fields they do not recognise unless the field is marked `required-since` (in which case the older binary refuses to load the policy, with a clear error naming the required field).
- Existing fields do not change name or type within a major version.
- Existing fields' *semantics* do not narrow within a major version. A field's accepted value set may widen; it may not shrink.
- Removals follow the deprecation discipline in `02-0-overview.md`: announced, warned at load time, kept for at least one minor version before removal.

The schema does not carry a top-level version field. The project's CHANGELOG records when the schema changed and what migration (if any) is needed. Templates carry their own `template_version`; that field is independent of the schema's version.

This chapter describes the *schema*. The canonical worked example is [TEMPLATE-ai-coding-strict.md](../TEMPLATE-ai-coding-strict.md), which exhibits every section type in a real policy. Read that file first if the structure is unfamiliar.

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
| `template_base` | string | Yes for templates and leaf policies; No for the root template (`base-confined`) | Names the parent template. Resolution walks the chain to the root. |
| `template_version` | string | Yes | The specific version of `template_base` being inherited from. Semver-shaped. |
| `template_name` | string | Yes for templates; No for leaf policies | The template's own name. Leaf policies use the kennel name from `name`. |
| `name` | string | Yes for leaf policies; No for templates | The kennel name. Matches the leaf policy's filename without `.toml`. |
| `threat_catalogue_version` | string | Yes | The version of `THREATS.md` the template was authored against. Used to detect catalogue drift. |
| `signature` | object | Yes for templates; optional for leaf policies | Signature envelope; see §Signatures. |

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

## Template inheritance

A leaf policy and the template chain compose into an *effective* policy by the following rules.

### Resolution order

1. Start from the leaf policy.
2. Read `template_base` and `template_version`. Locate that template; verify its signature.
3. Recurse: that template may itself have a `template_base`. Resolve up to the root template (`base-confined`), which has no `template_base`.
4. The chain is a linear list, root-first.

The chain depth is bounded at 16 (see `INVARIANTS` below). A circular chain is rejected at parse time.

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

Templates are signed. The signature envelope:

```toml
[signature]
algorithm = "ed25519"
key_id = "kennel-maint-2026-01"
signature = "BASE64..."
signed_fields = ["template_base", "template_version", ..., "lifecycle"]
```

The signature is over the canonical-form serialisation of `signed_fields`, computed by the procedure documented in `02-6-internal-api.md` under `kennel-policy::canonical`. The canonical form pins field order, normalises whitespace, and excludes the `[signature]` block itself.

Signature verification rules:

- The signing key must be in the configured key set (the project's maintainer keys, or the customer's organisation keys for self-signed templates).
- The `algorithm` must be in the supported algorithm set (currently: `ed25519`). Cryptographic minimums are enforced at validation; negotiation below the current floor is a categorical error.
- The `signed_fields` list must cover every top-level field of the policy *except* `[signature]` itself; a template that signs only a subset of its fields is rejected.
- A template whose signature does not verify is rejected even if the unverified fields are not consulted.

Leaf policies may be unsigned. The user wrote them; they are loaded under the user's authority. An organisation may require leaf-policy signing via a configured policy enforcer, but the schema does not mandate it.

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
- `~/.config/kennel/templates/<name>-v<version>.toml` — local templates (cached or hand-installed).
- `~/.config/kennel/keys/` — installed signing keys.

System-installed templates live under `/etc/kennel/templates/`. The search order is leaf policy → user templates → system templates → built-in templates. A template at a higher-priority location shadows the same name at lower priority.

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

## What this chapter does not cover

- The field-by-field semantics of each section: see the corresponding design-document chapter (§7.x) or the worked example in [TEMPLATE-ai-coding-strict.md](../TEMPLATE-ai-coding-strict.md).
- The canonical-form serialisation procedure: `02-6-internal-api.md` (`kennel-policy::canonical`).
- The signing-key store on disk: `07-paths.md`.
- The mechanism by which template signatures are verified at runtime: `04-trust-boundaries.md`.
- How `kennel diff` and `kennel upgrade` compute and present deltas: `02-1-cli.md`.
- The `[audit]` schema in detail — sink selection, per-class levels, sink-specific parameters: `02-3-audit-schema.md`.
