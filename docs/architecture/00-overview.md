# Architecture overview

This tree describes Project Kennel's reference implementation. Where `docs/` is the *design* — what the system does and why — `architecture/` is the *implementation contract*: what binaries exist, what they expose, how the code is organised, where state lives, what the wire formats are.

The split is deliberate. A reader who only wants to understand the design and adopt the threat catalogue does not need to read this tree. A reader who wants to build, modify, or audit our specific implementation does.

---

## What is here

```
architecture/
├── 00-overview.md               this file
├── 01-process-model.md          binaries, privilege, process tree, IPC topology
├── 02-0-overview.md             API surfaces: what counts, stability policy
├── 02-1-cli.md                  CLI subcommands, flags, exit codes, output
├── 02-2-config-schema.md        policy TOML schema, templates, signature envelope
├── 02-3-audit-schema.md         JSONL event schema and evolution
├── 02-4-ipc.md                  privhelper and kenneld wire protocols
├── 02-5-bpf-abi.md              BPF map types, attach points, kernel features
├── 02-6-internal-api.md         Rust crate-to-crate public surfaces
├── 03-crate-decomposition.md    Cargo workspace layout
├── 04-trust-boundaries.md       privilege transitions, sanitisation points
├── 05-state-and-supervision.md  daemon lifecycles, state ownership, recovery
├── 06-build-and-test.md         dep graph, CI matrix, root vs userspace tests
└── 07-paths.md                  on-disk and runtime path layout
```

Read in order if new. Pick chapters by topic if not.

---

## Relationship to `docs/`

The two trees are independent products.

`docs/` describes a system any implementation could build to. It contains the threat model, the policy template format, the enforcement primitives, the design rationale. A different team could read `docs/`, ignore `architecture/`, and write a fresh reference runtime that interoperates with our threat catalogue and our template system.

`architecture/` describes *our* implementation. It commits to specific Rust crates, IPC formats, on-disk paths, and lifetime semantics. A different implementation would have a different `architecture/` tree; both could be valid reference runtimes for the same design.

Cross-references from `architecture/` to `docs/` are common and use the `docs/` chapter numbers (§8 of the design document, §7.4 of the mechanism reference, etc.). Cross-references the other way are rare; `docs/` should not depend on implementation specifics.

When `docs/` and `architecture/` disagree, `docs/` wins for what the system *should* do, and `architecture/` is amended to match. When an implementation choice diverges from the design intentionally (a deliberate simplification, a forced compromise on a specific platform), the divergence is recorded in the relevant `architecture/` chapter with a pointer to the design section it deviates from.

---

## Stability commitments

Different chapters describe contracts with different stability commitments. Each §02 sub-chapter opens with its own commitment statement. Summary:

| Surface | Stability |
|---|---|
| CLI (subcommands, flags, output) | Stable across minor versions; breaking changes only at major version, with a deprecation cycle |
| Config schema (policy TOML) | Stable; new fields are backward-compatible additions, removals only at major version |
| Audit JSONL schema | Versioned by an explicit `schema_version` field; readers may pin and the project guarantees one version of overlap on a major bump |
| Privhelper IPC | Internal; may change between minor versions, with `kenneld` and `privhelper` coordinated to upgrade together |
| BPF map ABI | Internal; the loader and the BPF programs are built from the same source within a release, so skew is impossible inside a release. Across releases, the loader's compatibility surface is documented |
| Internal Rust API (crate-to-crate) | No stability; this is a workspace boundary, not a public surface |

The "stable" surfaces are what a third party may rely on. The "internal" surfaces exist because they are useful to document for review and audit, not because they are commitments to consumers.

---

## How to amend

Changes to this tree follow the review discipline in [CODING-STANDARDS.md](../governance/CODING-STANDARDS.md) §13. The three-phase commit cadence (§7.3) does not apply directly — architecture documents are not test-driven — but:

- Significant changes warrant an issue first, tagged with the relevant `[T<id>]` or `[T-NONE]` (§13.5).
- The PR template's "Why, in project-local terms" applies: motivation cites specific design-document sections or threat IDs, not generic justification.
- A change to a stability commitment is itself a stability event. The relevant chapter's commitment statement is updated, and a CHANGELOG line lands describing what changed and why.

Architecture changes that affect the design get a paired PR in `docs/`. The design moves first; the implementation follows. Architecture-only changes (a refactoring, a paths rearrangement, a build-system update) land here without touching `docs/`.

---

## Out of scope

This tree does not contain:

- The threat catalogue (see [THREATS.md](../design/THREATS.md)).
- The design rationale (see [docs/](../)).
- Policy template examples (see [TEMPLATE-ai-coding-strict.md](../design/TEMPLATE-ai-coding-strict.md) for the canonical worked example).
- Contributor-facing guidance (see [CONTRIBUTING.md](../../.github/CONTRIBUTING.md)).
- Project-wide engineering rules (see [CODING-STANDARDS.md](../governance/CODING-STANDARDS.md)).

If a topic appears in two places, the more specific document wins. `docs/` references `THREATS.md` for threat IDs; `architecture/` references both; neither restates the catalogue.
