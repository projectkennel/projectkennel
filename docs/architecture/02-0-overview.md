# API surfaces — overview

Project Kennel exposes several distinct APIs, each with its own stability commitment, its own versioning mechanism, and its own audience. This chapter is the *principle* layer: what we mean by an API, how the surfaces relate, and what discipline applies to changing them. Concrete syntax, schemas, wire formats, and field-by-field details are in the sub-chapters (`02-1` through `02-6`).

---

## What counts as an API

An API is any surface a third party may write code against. In Project Kennel that includes:

- **The CLI.** Subcommands, flags, output formats, exit codes. Scripts, deployment automation, ops runbooks, and shell-based workflow tooling rely on these.
- **The policy schema.** The policy TOML format and the template inheritance rules. Operators write to this; CI tooling validates against it; templates published by the project and by customers are bound by it.
- **The audit JSONL schema.** SIEM integrations, log-shipping tooling, ad-hoc analysis scripts read from this.
- **The privhelper IPC.** Between kenneld and the privhelper binary on the local machine.
- **The kenneld control protocol.** Between the CLI and kenneld on the local machine.
- **The BPF map ABI.** Between the loader (userspace) and the BPF programs (kernel-side), and between in-kernel state and ringbuf consumers.
- **The crate-to-crate Rust APIs.** Internal but documented; review boundaries and refactoring contracts.

Anything else — commit hashes, internal struct layouts, log file paths inside `~/.local/state/kennel/<id>/`, tempdir naming under `/tmp` — is *implementation detail* and may change without notice. The small set of paths that *are* stable is in `07-paths.md`.

---

## Stability tiers

Surfaces fall into three stability tiers. Each sub-chapter opens by declaring its tier and the version-bump discipline that applies.

### Stable

Backwards-compatible across the project's lifetime within a major version. Breaking changes only at a major version bump (X+1.0.0), with a deprecation cycle of at least one minor version before removal. Third parties may pin to a version and expect their code to keep working through patch and minor updates.

| Surface | Sub-chapter |
|---|---|
| CLI subcommands, flags, exit codes, output | `02-1-cli.md` |
| Policy TOML schema and template inheritance | `02-2-config-schema.md` |
| Audit JSONL schema (per `schema_version`) | `02-3-audit-schema.md` |

### Internal-stable

May change between minor versions, but the project ensures internal consistency *within a release*: the loader and the BPF programs are built from the same source, kenneld and privhelper are coordinated, the CLI knows what version of kenneld it can speak to. External consumers do not see breakage in a release; cross-release upgrade procedures are documented.

| Surface | Sub-chapter |
|---|---|
| Privhelper IPC wire format | `02-4-ipc.md` |
| kenneld control protocol | `02-4-ipc.md` |
| BPF map ABI and ringbuf event format | `02-5-bpf-abi.md` |

### Unstable

No commitment. Documented for review and audit (these are the review boundaries within the workspace) but external parties may not pin against them.

| Surface | Sub-chapter |
|---|---|
| Crate-to-crate Rust public APIs | `02-6-internal-api.md` |

---

## Versioning mechanisms

Different surfaces declare their version in different ways. The choice depends on what the consumer can do with the version information.

**SemVer string, exposed by `kennel --version`.** The CLI's version is the project's version. Operators script against `kennel --version` to gate behaviour on the installed version.

**Field in the artefact itself.** The policy TOML and the audit JSONL both carry version markers (`template_version` in templates, `schema_version` in audit events). A consumer reads the version, decides whether to proceed. The project commits to one minor version of overlap when bumping these.

**Handshake at connection setup.** The privhelper IPC and the kenneld control protocol both begin with a version exchange. Both sides reject and disconnect if the other is out of supported range. There is no inter-version translation layer; mismatch is a clean error, not a degraded mode.

**Magic number and version in a sentinel map.** The BPF map ABI is verified by the loader at attach time. Mismatch fails the attach with a structured error; the BPF programs do not load against a wrong-version loader.

**Crate version in `Cargo.toml`.** Internal Rust APIs are tracked by the workspace's crate versions. No external commitment; the version is for the loader/builder, not for downstream consumers.

---

## Deprecation policy

Stable-tier surfaces deprecate before they break. The discipline is:

- **Announcement.** Deprecation is announced in the CHANGELOG at the release that introduces it. The deprecated surface continues to function.
- **Runtime warning.** The relevant tool surfaces the deprecation at runtime when the deprecated feature is used. CLI prints to stderr; the policy loader prints when a deprecated field is read; audit events being phased out are tagged with a deprecation field readers may pick up.
- **Minimum duration.** A deprecated surface remains functional for at least one full minor version. A surface deprecated in `2.3` may not be removed before `3.0`; it continues to work through `2.4`, `2.5`, ... until the next major release.
- **Replacement.** The deprecation message names the replacement, with a concrete example. Vague "use the new API" is not enough; the operator should be able to do the migration with the warning text alone.
- **Removal announcement.** The removal is itself announced in the CHANGELOG of the release before the one in which it lands.

Internal-stable surfaces may break between minor versions without deprecation, but only across Project Kennel's own internal boundary; consumers of the kennel binary do not see breakage. Coordinated upgrades (kenneld and privhelper landing the new protocol in the same release) are routine and require no deprecation cycle.

Unstable surfaces are governed by the normal review rules; no deprecation discipline applies.

---

## Internal vs external

The internal/external boundary is not "what is in our source tree" — everything in this repository is in our source tree. It is "who else writes code against this surface":

- If an operator's deployment automation, a SIEM rule, a customer's policy CI, or a third-party tool depends on the surface — **external**.
- If only Project Kennel's own binaries depend on the surface — **internal**.

A surface starts internal by default. It becomes external when we make a stability commitment. The transition is itself a release event, announced in the CHANGELOG, and is one-way: a stable surface does not silently become internal again.

This is why the BPF map ABI is internal even though it crosses a kernel/userspace boundary: nothing outside Project Kennel writes BPF programs that read our maps, nor consumes our ringbuf events directly. If a third party ever asks for that surface to be stable, we evaluate and either commit or refuse explicitly — we do not slide into stability by accident.

---

## How API changes land

Changes that affect a stable surface follow [CODING-STANDARDS.md](../governance/CODING-STANDARDS.md) §13 generally, with two additions:

1. The PR template's "What changes" section must explicitly state which API surface is affected and how (additive, deprecation, removal).
2. A CHANGELOG entry is mandatory, in a section named for the surface affected: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, etc. One section per surface affected by the PR.

Changes that affect an internal-stable surface need the CHANGELOG entry but no deprecation cycle. The CHANGELOG section is named the same way (`### IPC protocol changes`, `### BPF ABI changes`).

Changes to unstable surfaces (the crate-to-crate Rust API) are governed by the normal review rules and need no special handling beyond accuracy in the PR description. They do not appear in the CHANGELOG unless they are observable through a stable or internal-stable surface.

---

## What this overview does not contain

- The concrete CLI subcommand list and flag semantics: `02-1-cli.md`.
- The policy TOML schema definitions and template inheritance rules: `02-2-config-schema.md`.
- The audit event types, fields, and `schema_version` evolution rules: `02-3-audit-schema.md`.
- The privhelper request/response wire format and the kenneld control protocol: `02-4-ipc.md`.
- The BPF map type declarations, attach points, and ringbuf event format: `02-5-bpf-abi.md`.
- The crate public-API surfaces: `02-6-internal-api.md`.
