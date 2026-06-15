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
| `template_version` | string | Templates only | The template's own version. A leaf has none — the parent's version is inline in `template_base`. |
| `template_name` | string | Yes for templates; No for leaf policies | The template's own name. Leaf policies use the kennel name from `name`. |
| `name` | string | Yes for leaf policies; No for templates | The kennel name. Matches the leaf policy's filename without `.toml`. |
| `include` | array of versioned references | No | Additional signed fragments composed additively. See §Includes. |
| `threat_catalogue_version` | string | No | The version of `THREATS.md` the template was authored against. Used to detect catalogue drift. `Option<String>` in the schema; the validator does not require it, and the in-tree templates omit it. Authors are encouraged to set it. |
| `signature` | object | Yes for templates and fragments; optional for leaf policies | Signature envelope over the artefact's content; see §Signatures. |

The parser produces a structurally typed value before any field is read; raw `toml::Value` is not retained past parse (`10.5` in CODING-STANDARDS.md).

---

## Section catalogue

A policy is the union of an `[exec]` section, an `[fs]` section, and so on. Each section is independently typed and independently validated. Sections present in the template chain are inherited; sections in a leaf policy delta the inheritance.

The full section list:

| Section | Purpose | Detailed in (design doc) |
|---|---|---|
| `[exec]` | What binaries the workload may execve() | §7.3 |
| `[fs]` and `[fs.*]` | Filesystem read/write access, shim construction | §7.4 |
| `[net]` and `[net.*]` | Egress mode (`none`/`constrained`/`unconstrained`/`host`), split by enforcer: `[net.proxy]` (the user-space by-name allow/deny the per-kennel SOCKS proxy enforces, proxied modes only) and `[net.bpf]` (the kernel/syscall CIDR+port connect/bind ACL, present in every mode), plus `[net.bind]` rewrite knobs, `[net.ipv6]`, and `[net.audit]`. Each mode gets its own net-ns except `host`, which shares the host net-ns; the net-ns is the egress boundary (§7.5). See §The `[net]` section. | §7.5 |
| `[unix]` | AF_UNIX socket allowlist, abstract-namespace handling (built — the `UnixRuntime` shim; the brokered `org.projectkennel.IAfUnix/default` facade that supersedes it is `02-4`) | §7.6 |
| `[binder]`, `[[binder.provide]]`, `[[binder.consume]]` | Binder service registry: which `org.projectkennel.*`-free services this kennel provides to / consumes from named peer kennels (`02-4`). **Roadmap** (cross-instance relay is not built). | §7.1 |
| `[ipc.spawn]` | Grants this kennel the `SpawnKennel` control-socket capability (`02-4` §Kennel spawning). **Roadmap.** | §7.1 |
| `[ssh]` | per-kennel SSH via the re-origination bastion (`[[ssh.destinations]]` = `dest` + host-side `ssh` `options`; no real-key fingerprint, no agent); carried in the settled policy (`SshRuntime`, with the compile-time-minted synthetic public key pinned per grant), realised by kenneld | §7.10 |
| `[identity]` | Masked account (`user`/`group`, default `kennel`) + supplementary-group isolation (`groups`); carried in the settled policy (`IdentityRuntime`), realised by the spawn seal | §7.4 |
| `[env]` | Environment variable pass-through, deny patterns, forced values | §7.9 |
| `[ulimits]` | `setrlimit(2)` resource limits (`nofile`, `nproc`, `as`, `cpu`, …); nothing set by default, folded per-key, applied in the spawn seal | §7.4 |
| `[cap]` | Capabilities and `no_new_privs` | §7.9 |
| `[seccomp]` | Seccomp filter | §7.9 |
| `[proc]` | Procfs visibility and hidepid | §7.9 |
| `[ptrace]` | Ptrace allow/deny across kennel boundary | §7.9 |
| `[signal]` | Signal allow/deny across kennel boundary | §7.9 |
| `[lifecycle]` | TTL and TTL-action | §9 |
| `[audit]` and `[audit.*]` | Audit sinks (file, journald, syslog, stdout), per-class levels, file rotation parameters | §8.6 |

This chapter describes *how the sections compose and inherit*, and gives the full field-level schema for `[net]` and `[net.*]` (the §The `[net]` section below, kept exact against the parser). Each other section's specific fields are documented in the corresponding design-document chapter; the worked, validated policies in [`docs/design/06-worked-examples.md`](../design/06-worked-examples.md) — and the annotated [`TEMPLATE-openclaw.md`](../design/TEMPLATE-openclaw.md) — show every common section in real use.

---

## Path syntax

Fields that name filesystem paths use the following syntax:

- `~/foo/bar` — the home. **`~` is the only way to name the home, and it always means the kennel's persona home (`/home/<user>`, default `/home/kennel`)** — never a host path. See §The home and the persona below.
- `/abs/path` — absolute, against the host filesystem. Most absolute paths are reserved for system files (`/etc/*`, `/usr/*`).
- `<kennel>/foo` — Project Kennel placeholder, expanded to the kennel's runtime ID at load time.
- `**` and `*` — glob suffixes. `**` matches across path separators; `*` does not.

Tilde expansion does not happen until signature verification of the file containing the tilde-path completes. An attacker-controlled template cannot use `~/.ssh/...` to refer to the operator's keys at parse time.

Paths in `fs.read`, `fs.write`, `fs.deny`, `exec.allow`, `exec.deny`, `unix.allow[].real`, and `unix.allow[].shim` follow this syntax — all accept `~` and globs (e.g. `/usr/lib/git-core/**`). A bare `**`/`/**` in `exec.allow` is the explicit `permissive-exec` opt-out and is the one case the compiler warns about. Execution is deny-by-default (§7.3.4): `exec.allow` is the allowlist and `exec.deny` carves exceptions out of it (a path or glob that is refused even if an `allow` glob would otherwise admit it).

### The home and the persona

Inside the kennel the workload runs as a masked persona — user `kennel`, `$HOME = /home/kennel` (`[identity].user`, §7.4). A policy author never names the operator's host home. The home model:

- **`~` (and `$HOME`) are canonicalised to `~` at compile**, so the settled, signed policy carries exactly one home form and **zero host-context home/user references**. `$HOME/foo` in a source policy becomes `~/foo` in the settled artefact.
- **At spawn, a `~` path resolves to the persona home for everything the kennel sees** — the Landlock rule, the bind *target*, and the `exec.allow` match are all `/home/kennel/...`. So `exec.allow = ~/foo/bin/tool` grants execute on `/home/kennel/foo/bin/tool` (the path the workload actually execs), and `fs.read = ~/foo` is readable at `/home/kennel/foo`.
- **The bind *source*** — the only place a host path is needed — is the operator's real home (that is where the data lives), reverse-mapped at mount time. It never appears in the policy, the settled artefact, or the kennel's view; the workload cannot observe the operator's username or home.
- **`exec.path` (the `$PATH` search roots) and `exec.shell`** are persona *strings* the workload reads, not bind-backed paths: their `~`/`$HOME`/`<home>` resolves straight to the persona home. `exec.path = ["~/.local/bin"]` puts `/home/kennel/.local/bin` in `$PATH`, matching where a `~/.local/bin/...` `exec.allow` grant landed. (`<home>` here is the persona home too — it never expands to the operator's home in a string the workload can read.)

---

## Versioned references

A *versioned reference* names a template or fragment together with the exact version to resolve: `<name>@<version>`. It appears in `template_base` and in each element of `include`.

Grammar:

- `<name>` matches `[a-z0-9][a-z0-9-]{0,63}`.
- The separator is a literal `@`.
- `<version>` is `v` followed by a semver core: `v4`, `v4.2`, `v2.33.2`. The leading `v` is required.

Examples: `ai-coding-strict@v4`, `corp-egress-allowlist@v2.33.2`.

The parser rejects a `template_base` or `include` element that:

- omits the `@version` — every reference is `<name>@v<ver>`, so the lockfile pins an exact parent.
- carries a malformed name or version.
- appears more than once in `include` (duplicate references are an error).

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

- **Additive-only.** A fragment may use `[[<section>.add]]` and `[[<section>.*.invariant]]`. It may *not* use `.remove` or scalar `.override`. The validator rejects a fragment that does. Additive-only composition is order-independent and free of diamond-resolution ambiguity.
- **No inheritance of its own resolution into the parent's chain.** A fragment may itself declare `template_base` only as `base-confined` (or none); it does not splice a competing inheritance line into the including policy. A fragment that names a non-base `template_base` is rejected.
- **Conflict is an error, not last-wins.** If two includes contribute entries with the same unique key (e.g., two `[[net.proxy.allow]]` for the same host with different ports), resolution fails with `PolicyError::IncludeConflict` naming both fragments. The author reconciles deliberately.

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
- Scalar fields (e.g., `[lifecycle].ttl`) are overridden by the most-leaf value that sets them.
- Object fields (e.g., `[fs.home]`) are merged shallowly: leaf fields override template fields key-by-key.

### Delta requirements

Every delta operation requires a `reason` field. The reason is free text, but the schema enforces that it is present and non-empty. The `kennel diff --threat-impact` view surfaces deltas with their reasons and any threat IDs the delta references.

A delta cannot weaken a *framework invariant* (see below). Attempting to do so causes the validator to reject the policy with `PolicyError::InvariantViolated`, naming the field.

### Threat tagging

Each delta and each `[[net.proxy.allow]]` entry may carry a `threats.exposed` array listing threat IDs (`["T1.8", "T1.9"]`) that this entry exposes. The list is informational; tooling reads it but does not enforce.

The threat IDs must be present in the version of `THREATS.md` named by `threat_catalogue_version`. The validator does not require the IDs to be there at parse time (the catalogue may not be available), but `kennel validate --strict-invariants` does check.

---

## Implied rules

Translation (source → settled policy) derives a few grants the author would otherwise have to restate. The author writes the intent once; the **settled policy carries the derived grants explicitly**, so `kennel diff` and the audit show exactly what was added — nothing widens invisibly. An implied grant never overrides an explicit one: if the author already wrote the target grant, theirs (with whatever extra ports/scope) wins and the rule is a no-op.

- **`fs.write` implies `fs.read`.** Every path in the effective `fs.write` set is folded into `fs.read` if not already present. A writable tree is meant to be usable, which requires read; restating it as `fs.read` is noise.
- **`[[ssh.destinations]]` implies no kennel egress.** The SSH destination is reached host-side by the bastion's forced command (`ssh <options> -- <dest>`, run as the operator), not by the kennel — so a destination derives **no** `[net.bpf]`/`[net.proxy]` egress. The only egress the kennel needs is the bastion's own loopback endpoint, which `kenneld` grants as a host-service literal at spawn (see §7.10), never a policy egress rule.

The egress endpoint's own reachability — the workload connecting to `facade-socks5` on the kennel loopback — is granted at bring-up (the proxy's address+port get the cgroup-BPF allow and the Landlock `CONNECT_TCP`), not written in policy: a kennel with egress can always reach its own egress endpoint by construction.

---

## Framework invariants

Certain properties cannot be weakened by any user delta, regardless of `reason`. These are framework invariants. The schema validator rejects policies that violate them.

The current invariants (mechanism details in design doc §12):

- `cap.no_new_privs = true`. Cannot be set false.
- `exec.deny_setuid = true`, `exec.deny_setgid = true`, `exec.deny_setcap = true`, `exec.deny_writable = true`. Cannot be set false.
- `fs.home.shadow = true`. The shim is mandatory. `$HOME` is `/home/<user>` — the masked `[identity].user`, default `kennel`.
- `[net.mode]` is the enforcement-mode enum, the four-mode taxonomy `"none"` / `"constrained"` / `"unconstrained"` / `"host"`; it may not be any other value (an absent `[net.mode]` translates to `Constrained`). `"none"` is an own empty net-ns (no interfaces); `"constrained"` and `"unconstrained"` each get an own net-ns plus the per-kennel SOCKS proxy (default-deny vs. default-allow-minus-invariant); `"host"` shares the host net-ns for direct egress with no proxy. `"host"` requires a non-empty `reason` and auto-instates `threats.reinstated = ["T1.6"]` (it reinstates the host-recon residual). The invariant statement — `[net.mode]` is enum-bounded and the proxy/invariant-deny floor cannot be removed — holds in every mode.
- The proxy invariant denylist (cloud metadata, link-local) — `[[net.proxy.deny.invariant]]` — is present and cannot be removed by any delta. (RFC1918 is *not* invariant — design §7.5 — so it is not asserted here; an author may add it via `[[net.proxy.deny.policy]]`.)
- `[proc.visibility] = "self"`.
- `[fs.dev.allow]` is the default-deny list documented in design §7.9; user deltas may not add device files outside the framework-known safe set without an explicit `framework_override` flag (which is itself an invariant override and requires a separate signed envelope; see `04-trust-boundaries.md`).

Framework invariants are declared in `schema/invariants.toml` and surfaced in `kennel templates inspect`. Adding an invariant is a major-version event; removing one is also a major-version event.

---

## Signatures

Templates and fragments are signed. The signature covers the artefact's *content* — the substantive policy, not merely a filename or a version label — so that resolving a versioned reference (§Versioned references) yields exactly the bytes a trusted key signed for that version. The signature envelope:

```toml
[signature]
algorithm = "ed25519"
key_id = "kennel-maint-2026-01"
signature = "BASE64..."
# signed_fields is optional advisory metadata; the in-tree templates omit it.
```

The signature is over the canonical-form serialisation of the whole artefact minus the `[signature]` block, computed by the procedure documented in `02-8-internal-api.md` under `kennel-lib-policy::canonical`. The canonical form pins field order, normalises whitespace, and excludes the `[signature]` block itself. The `content_sha256` recorded in the lockfile (§The lockfile) is the SHA-256 of this same canonical-form content, so the lockfile pins precisely the bytes the signature covered.

Signature verification rules:

- The signing key must be in the configured key set (the project's maintainer keys, or the customer's organisation keys for self-signed templates and fragments). The key store is under `~/.config/kennel/keys/` and `/etc/kennel/keys/` (`07-paths.md`).
- The `algorithm` must be in the supported algorithm set (currently: `ed25519`). Cryptographic minimums are enforced at validation; negotiation below the current floor is a categorical error.
- Coverage is whole-body, not field-selectable. The signature is over the canonical form of every top-level field *except* `[signature]` itself — including `template_base` and `include`, so the reference's own dependency declarations are always signed. The `signed_fields` list in the envelope is advisory metadata (`#[serde(default)]`, empty when absent); the verifier does not read it to decide coverage, so there is no way to sign "only a subset" — the canonical form fixes the covered bytes as the whole artefact-minus-`[signature]`.
- An artefact whose signature does not verify is rejected even if the unverified fields are not consulted.

Leaf policies may be unsigned. The user wrote them; they are loaded under the user's authority. An organisation may require leaf-policy signing via a configured policy enforcer, but the schema does not mandate it. A leaf policy's `kennel.lock` still pins the signed artefacts it references, so an unsigned leaf composing signed templates and fragments is still byte-reproducible.

---

## Variable substitution

The following placeholders are substituted at load time:

| Placeholder | Meaning |
|---|---|
| `<kennel>` | The kennel's runtime ID (e.g., the kennel name for named kennels, or the generated ID for `--template` ad-hoc kennels). |
| `<tag>` | The caller's 12-bit IPv4 loopback tag, from their `/etc/kennel/subkennel` allocation (per-user, fixed for that user). |
| `<ctx>` | The kennel's allocated context byte (per-kennel, assigned at start by kenneld). |
| `<gid>` | The caller's 40-bit IPv6 ULA global ID, from their `/etc/kennel/subkennel` allocation (per-user). |
| `<uid>` | The user's UID as a decimal string. |
| `<home>` | The user's home directory (the host path before shim construction). |
| `<user>` | The workload's **masked** account name — `[identity].user`, default `kennel`. This is the base of the in-view `$HOME` (`/home/<user>`), not the caller's host login. |
| `<group>` | The workload's **masked** primary group — `[identity].group`, default `kennel`. |

Substitution happens once at policy resolution; the substituted values are then immutable for the lifetime of the kennel. A template that uses `<ctx>` resolves to a different concrete value for each kennel that derives from it.

Substitution does not perform shell expansion: `$HOME` in a policy field is not expanded to the user's home. The shim's `$HOME` is referenced as `~/` (which is the workload's view, post-shim) or as `<kennel>/home` (which is the host path before shim construction).

---

## File location

Policies live under `~/.config/kennel/`:

- `~/.config/kennel/policies/<name>/policy.toml` — the source leaf policy (folder per policy).
- `~/.config/kennel/policies/<name>/<name>.settled.toml` — the compiled, signed settled policy (what runs).
- `~/.config/kennel/policies/<name>/<name>.lock` — the lockfile beside the policy.
- `~/.config/kennel/templates/<name>@<version>.toml` — local templates and fragments (cached or hand-installed). The filename encodes the versioned reference, so multiple versions of one name coexist.
- `~/.config/kennel/keys/` — installed signing keys (public only).

`kennel run <name>` resolves a run policy **by name** across the `policies/` cascade (`~/.config/kennel` → `/etc/kennel` → `/usr/lib/kennel`); a literal path still works. See `07-paths.md` §Run-policy resolution.

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

The settled schema is defined in `src/crates/kennel-lib-policy/src/settled.rs`. The
settled body (`SettledPolicy`) has two layers. Its `effective_policy`
(`EffectivePolicy`) is the **kernel-enforcement core** — `net`, `fs`, `exec`,
`proc`, `cap`, `seccomp`, `lifecycle` — the sections the spawn seal and the BPF
realise directly. Alongside it the body carries the **service-input sections**
the daemon and spawn *services* realise (not the kernel), each signed but omitted
from the canonical form when empty (so a policy that does not use one signs
unchanged): `ssh` (`SshRuntime`), `unix` (`UnixRuntime`), `identity`
(`IdentityRuntime` — the masked `user`/`group` and supplementary `groups`),
`audit` (`AuditRuntime`), `env` (`EnvRuntime` — the synthesised environment), and
`ulimits` (`UlimitsRuntime` — the `setrlimit` caps). The informational sections
`ptrace`/`signal` (their scoping comes from the PID namespace + seccomp, not the
section) are dropped at translate and absent from the settled form; they compile
with a warning. (`[container]`, `[dbus]`, `[x11]`, `[fs.scrub]`, and
`[[fs.home.sanitise]]` are not in the schema — an unknown-section error at parse.)
The settled net section (`NetPolicy`) carries `mode`; the proxy egress policy
as `allow` (by-CIDR), `allow_names` (by-name), `deny_invariant` (the
non-removable floor) and `deny_author` (the `[net.proxy.deny.policy]`
denylist); the kernel ACL as `bpf_connect_allow` / `bpf_connect_deny` /
`bpf_bind_allow` / `bpf_bind_deny` (all CIDR+port, no names); `proxy`
(`ProxyListen` — `offset`, `port`); and the bind-port policy (`bind_port_min` +
`bind_allowed_ports`, §7.5.7). The settled fs section adds
`fs.tmp` (`private`, `size_mib`, `mode`) and `fs.dev.allow`, and the proc section
adds `proc.hidepid`. Settled `FsPolicy` uses flat field names (`home_shadow`,
`home_persist`, `home_readonly`), not nested `fs.home.*`. The settled exec section
carries `exec.loaders` — each `exec.allow` dynamic binary's ELF `PT_INTERP` (its
`ld.so`), resolved at compile time. The spawn grants `FS_EXECUTE` on the allowlisted
binaries **and** these loaders, because the kernel opens both `FMODE_EXEC` during
`execve`. It grants nothing for the binaries' shared libraries: Landlock does not gate
`mmap`, so libraries load via the ordinary `fs.read` grants and cannot be execute-gated
(§7.3.7). There is no `[lib]` source section.

The TOML schema above describes *source* policies — what an operator authors. The runtime does not enforce source policies directly. `kennel compile` resolves a source policy once and emits a **settled policy**: a flat, fully-resolved, signed artefact that the runtime consumes. The design rationale is in design doc §9.10; this section is the artefact's format and stability.

The split: all resolution (chain-walking, include merging, delta application, source-signature verification, lockfile byte-checks, invariant and threat-tag validation, installation-constant substitution) happens at compile time. The spawn path verifies one signature, re-asserts framework invariants, fills per-instance substitution slots, and builds kernel objects. It links none of the template machinery.

### Stability

The settled policy is an **internal-stable** surface per `02-0-overview.md`, with one external consumer: fleet/attestation tooling that distributes and verifies settled policies. It carries an explicit `settled_schema_version` integer. The compiler and the runtime within one release agree; across releases, the runtime accepts settled-policy schema versions back to the start of the current major version. Fleet tooling reads `settled_schema_version` and the `provenance` block; those two are treated as stable for the major version.

### Format

The settled policy is a TOML document, like every other Project Kennel config artefact — there is no second config format and no JSON serialiser anywhere in the tree (`basic-toml` is the only serde format dependency). It is machine-produced and machine-consumed (never hand-edited), but TOML serves a machine artefact just as well as a hand-authored one, and keeping one format avoids a second parser/serialiser dependency.

The canonical form for hashing and signing is **deterministic TOML emitted in struct-field order**. This is reproducible because the signer and the verifier are the *same* implementation: a fixed field order yields byte-identical canonical output on both sides. (The schema carries no floating-point values, so "number normalisation" — the hard part of any canonicalisation — does not arise.) The procedure is documented under `kennel-lib-policy::canonical`; the `[signature]` table is excluded from it. If independent third-party verification ever becomes a hard requirement, the signature would cover the literal stored payload bytes (still TOML), which is format-agnostic and needs no canonicaliser at all.

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
threat_catalogue_version = "0.3"
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
- `signature` is over the canonical-form serialisation of every field except `signature` itself, by the compiling authority's key (`kennel-lib-policy::canonical`, the same procedure as source signatures).

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

Settled policies live beside their source inside the policy folder: `<config>/policies/<name>/<name>.settled.toml`, across the cascade `~/.config/kennel` → `/etc/kennel` → `/usr/lib/kennel`. A fleet tool stages a `policies/<name>/` under `/etc/kennel` for an attested deployment. `07-paths.md` is authoritative.

### Trust split

The signature trust differs by artefact (`07-paths.md` §Policy-signing trust split, `04-trust-boundaries.md`): **templates** verify only against **system keys** (`/etc/kennel/keys`, `/usr/lib/kennel/keys`) — a user key cannot sign a template; **settled run policies** verify against **system keys *or* the user's own `~/.config/kennel/keys`**, so a user may run a policy signed with their own `kennel keygen` key while the template chain it derives from still verifies against system keys.

---

## The `[net]` section — egress mode, proxy policy, kernel ACL, bind, audit

This documents the **as-built** `[net]` schema — the form `kennel_lib_policy::source::NetSection`
parses (`deny_unknown_fields`, so an undocumented key is a hard error). The policy is **split by
enforcer**: `[net.proxy]` is the user-space egress policy the per-kennel SOCKS proxy enforces (by
name, proxied modes only), and `[net.bpf]` is the kernel/syscall CIDR+port ACL (cgroup
`connect4`/`6` + `bind4`/`6` BPF plus the matching Landlock grants), present in every mode. The two
layers **intersect** and both evaluate **deny-first**. Field *semantics* are design §7.5; this is the
structure a policy author writes.

### `[net]` scalars

| Field | Type | Notes |
|---|---|---|
| `mode` | string | `"none"` (own empty net-ns, no interfaces), `"constrained"` (own net-ns + proxy, default-deny — the default), `"unconstrained"` (own net-ns + proxy, default-allow minus the invariant + `[net.proxy.deny.policy]` carve-outs), or `"host"` (shares the host net-ns, direct egress, **no proxy** — `[net.bpf]` is the gate). |
| `reason` | string | **required** (non-empty) only when `mode = "host"`: the documented justification for sharing the host network stack. The compiler refuses `mode = host` without it and records `threats.reinstated = ["T1.6"]`. |
| `proxy_listen_v4` / `proxy_listen_v6` | bool | whether the per-kennel egress endpoint listens on that family (proxied modes). |
| `proxy_listen_v4_address` / `proxy_listen_v6_address` | string `"offset:port"` | the listen offset+port within the kennel's `/28` (v4) / `/64` (v6); absent → `1:1080`. |

In the proxied modes the workload-facing endpoint is `facade-socks5` on the kennel loopback;
`proxy_listen_*` set where it binds. The kennel has no other route off its loopback (§7.5), so egress
crosses the binder gateway to kenneld, which dials through the host-side `host-netproxy` delegate. In
`host` mode there is no proxy and no `proxy_listen_*` endpoint — egress is direct and gated solely by
`[net.bpf]`.

### `[net.proxy]` — the user-space egress policy (proxied modes only)

The policy the per-kennel SOCKS proxy enforces in `constrained`/`unconstrained`: kenneld resolves a
name, vets the answer against `allow`, re-checks the resolved address against the deny lists, and
pins it (the kennel never resolves DNS itself, so rebinding is structurally impossible). A
`[net.proxy]` rule under `mode = "host"` is a **compile error** — there is no proxy to resolve names;
use `[net.bpf]` CIDR rules instead.

`[[net.proxy.allow]]` — by-name (or by-CIDR) egress allow entries (array of tables):

| Field | Type | Notes |
|---|---|---|
| `name` | string | the destination host (or dot-prefixed suffix). Mutually informative with `cidr`. |
| `cidr` | string | a CIDR destination, when the rule is by-address. |
| `ports` | array of int | permitted ports; empty = any port. |
| `protocol` | string | `"tcp"`, `"udp"`, or `"any"`. |
| `reason` | string | why this destination is permitted (**required** on a leaf delta). |
| `tls.required` | bool | whether TLS is required to the destination (a `tls` sub-table). |
| `threats` | table | `threats.exposed` / `threats.mitigated` — threat IDs this grant bears. |

`[net.proxy.deny]` — the proxy denies, two CIDR arrays in one table, both evaluated **deny-first**
before `allow`:

| Table | Fields | Notes |
|---|---|---|
| `[[net.proxy.deny.invariant]]` | `cidr`, `reason`, `threats` | the **non-removable** floor (cloud-metadata IMDS, link-local), re-checked against every *resolved* address — an allowed name that resolves into a denied range is still refused. A **leaf may not declare** it (`LeafPolicy::validate` rejects it); invariants are template/fragment-author tools. |
| `[[net.proxy.deny.policy]]` | `cidr`, `reason`, `threats` | the author's **optional** denylist (e.g. RFC1918, a known-bad range) — removable, evaluated deny-first alongside the invariant floor. |

### `[net.bpf]` — the kernel/syscall ACL (every mode)

The cgroup `connect4`/`6` + `bind4`/`6` BPF and the matching Landlock `CONNECT_TCP`/`BIND_TCP`
grants. **CIDR + ports only — no names** (the kernel cannot resolve names, so a by-name rule is
structurally inexpressible here). Present in **every** mode: in `host` it is the egress gate; in the
proxied modes it is defence-in-depth. It is author-writable in every mode but **intersected with the
framework lock** — an author rule can only **narrow**. In the proxied modes the only reachable
destination is the proxy endpoint (added by the framework); an author connect-allow cannot widen
past it, and the author narrows via deny. Deny is checked before allow (deny-first), and Landlock is
allow-only (it can only narrow further).

`families` / `deny_families` — socket-family shaping (e.g. permit `AF_INET`/`AF_INET6`/`AF_UNIX`,
deny `AF_NETLINK`/`AF_PACKET`), arrays of strings.

`[net.bpf.connect]` (outbound) and `[net.bpf.bind]` (inbound) each carry `allow` and `deny` arrays of
rules:

| Field | Type | Notes |
|---|---|---|
| `cidr` | string | the destination CIDR, a bare address, or `"*"` (= `0.0.0.0/0` + `::/0`, any host). |
| `ports` | array of int | permitted ports; empty = any port. |
| `protocol` | string | `"tcp"`, `"udp"`, or `"any"`. |
| `reason` | string | why this rule exists (**required**). |
| `threats` | table | `threats.exposed` / `threats.mitigated`. |

`[[net.bpf.connect.allow]]` / `[[net.bpf.connect.deny]]` are the outbound CONNECT ACL and **are
enforced** (BPF + Landlock, deny-first). `[[net.bpf.bind.allow]]` / `[[net.bpf.bind.deny]]` are the
inbound BIND ACL: the language **parses and settles** them, but the CIDR bind gate (and the host-side
inbound mirror that would expose a bound port host-side) is **roadmap** — not yet enforced on this
branch. The bind-port floor (`[net.bind].min_port` / `allowed_ports`, below) is the bind protection
that *is* enforced today.

### `[net.bind]` — the bind-address rewrite knobs (§7.5.7)

Governs what the workload may `bind(2)`. All fields optional.

| Field | Type | Notes |
|---|---|---|
| `inaddr_any_policy` | string | wildcard IPv4 bind handling: `"rewrite"` (to the kennel loopback) or `"deny"`. |
| `in6addr_any_policy` | string | wildcard IPv6 bind handling. |
| `allow_host_loopback_v4` / `allow_host_loopback_v6` | bool | whether binding the host loopback is permitted. |
| `min_port` | int | lowest bindable port (the privileged-port floor, T6). |
| `allowed_ports` | array of int | explicit bindable-port allowlist; empty/absent = any port at or above `min_port`. Capped at `MAX_BIND_PORTS` at translation. |

### `[net.ipv6]`

| Field | Type | Notes |
|---|---|---|
| `force_v6only` | bool | set `IPV6_V6ONLY=1` so a dual-stack socket cannot escape the v4 bind rewrite. |

### `[net.audit]` — per-kennel egress audit (distinct from the global `[audit]`)

| Field | Type | Notes |
|---|---|---|
| `log_path` | string | where the per-kennel egress JSONL log is written. |
| `level` | string | egress audit verbosity: `"summary"` or `"full"`. |

> **Roadmap residual.** The four-mode taxonomy, the `[net.proxy]`/`[net.bpf]` split, and BOTH the
> `[net.bpf].connect` AND `[net.bpf].bind` ACLs (BPF + Landlock, deny-first) are **built and
> enforced** — the bind ACL gates every `bind()` at the cgroup `bind4`/`6` hook against dedicated
> `bind_{allow,deny}_v{4,6}` tries. What remains roadmap is only the host-side inbound *mirror* (the
> INet `BIND` verb that would expose a bound port host-side at the kennel's own loopback address) —
> a planned follow-up in design §7.5 / [`02-5-binder-net.md`](02-5-binder-net.md). Until it lands, a
> permitted bind is reachable only inside the kennel's net-ns.

---

## The `[binder]`, `[[binder.provide]]`, `[[binder.consume]]`, and `[ipc.spawn]` sections

> **Roadmap.** The cross-instance binder relay these sections drive is not built (the binder
> *gateway core* — node 0, the `IAfUnix` facade, `kennel-bin-init` lifecycle — is built and proven;
> the cross-kennel relay is the forward contract in [`02-4-binder.md`](02-4-binder.md)). This is
> the forward schema for `BinderRuntime`; field semantics are design §7.1.

These sections configure the binder service registry (`02-4`). The kennel-local registry and the
reserved `org.projectkennel.*` services need no policy — they are always available when their
backing section is non-empty. What these sections grant is **cross-kennel** service exchange and
kennel spawning.

`[[binder.provide]]` — services this kennel offers to named peer kennels:

| Field | Type | Notes |
|---|---|---|
| `name` | string | the service name (may **not** begin with `org.projectkennel.` — reserved) |
| `accept_from` | array of strings | peer-kennel names permitted to consume it |
| `reason` | string | why this service is offered (the audited justification) |
| `threats` | table | `threats.exposed` / `threats.mitigated` — threat IDs this grant bears |

`[[binder.consume]]` — services this kennel may look up from named providers:

| Field | Type | Notes |
|---|---|---|
| `name` | string | the service name (may **not** begin with `org.projectkennel.`) |
| `from` | string | the providing kennel's name |
| `reason` | string | why this lookup is needed |
| `threats` | table | `threats.exposed` / `threats.mitigated` |

A cross-instance lookup succeeds only when **both** sides declare it: the consumer's
`[[binder.consume]]` names the service and provider, and the provider's `[[binder.provide]]` names
the service and lists the consumer in `accept_from`. A unilateral declaration denies (`02-4`
§Cross-instance registry). Peer-kennel names live only in policy, never in the binder protocol the
workload sees.

`[ipc.spawn]` — grants the `SpawnKennel` control-socket capability (`02-4` §Kennel spawning): when
present, the kennel may ask kenneld to spawn a child kennel whose policy is the requested template
intersected with this kennel's own grants and any narrowings (never a superset). A spawned kennel
has no spawn capability of its own unless its template independently declares `[ipc.spawn]`.

### Reserved-namespace compile validation

The `org.projectkennel.*` prefix is reserved (`02-4` §The reserved namespace). It is a **categorical
policy-compile error** — not a runtime check (design §7.1.4) — for any `[[binder.provide]]` or
`[[binder.consume]]` `name` to begin with `org.projectkennel.`; only kenneld registers under that
prefix. The compiler rejects such a policy by name, the same way it rejects an out-of-range
`[net.mode]`.

---

## What this chapter does not cover

- The field-by-field semantics of each section: see the corresponding design-document chapter (§7.x) or the worked example in [TEMPLATE-ai-coding-strict.md](../design/TEMPLATE-ai-coding-strict.md).
- The binder IPC contract the `[binder]`/`[ipc.spawn]` sections feed, and the `org.projectkennel.*` service set: [`02-4-binder.md`](02-4-binder.md); the network-over-binder layer the `[net.proxy]`/`[net.bpf]` sections feed: [`02-5-binder-net.md`](02-5-binder-net.md). The standalone `net-policy.toml` schema reference is retired; its content is the §The `[net]` section above.
- The design-level treatment of signing, versioned references, and includes: design doc §5.10.
- The canonical-form serialisation procedure: `02-8-internal-api.md` (`kennel-lib-policy::canonical`).
- The signing-key store and lockfile locations on disk: `07-paths.md`.
- The mechanism by which template and fragment signatures are verified at runtime, and how the lockfile is checked: `04-trust-boundaries.md`.
- How `kennel diff` and `kennel upgrade` compute and present deltas, and how `upgrade` rewrites the lockfile: `02-1-cli.md`.
- The `[audit]` schema in detail — sink selection, per-class levels, sink-specific parameters: `02-3-audit-schema.md`.
- The design-level rationale for compilation and the settled policy: design doc §9.10.
- How `kennel compile` is invoked and its flags: `02-1-cli.md`.
- How the runtime trust surface differs between source and settled policies: `04-trust-boundaries.md`.
