# Contributing to Project Kennel

Thanks for reading this. Kennel is a security-critical project — kernel-enforced confinement for unsigned code on developer workstations — and the bar for getting code merged is deliberately high. This document is the friendly entry point. The exhaustive, normative rules live in [CODING-STANDARDS.md](CODING-STANDARDS.md).

If you read this document and follow it, your contribution has a good chance of being merged. If you ignore it, the contribution is closed without review. We are direct about that on purpose; see *Why we are strict* at the bottom.

---

## What this project is

Project Kennel composes existing Linux kernel primitives (Landlock, cgroup BPF, namespaces, seccomp) into a policy-driven confinement layer for AI coding agents and other unsigned user-level workloads.

- [EXEC-SUMMARY.md](EXEC-SUMMARY.md) — why the project exists.
- [THREATS.md](THREATS.md) — the threat catalogue.
- [TEMPLATE-ai-coding-strict.md](TEMPLATE-ai-coding-strict.md) — a worked policy example.

---

## Reporting security vulnerabilities

**Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.** Email the maintainers at **security@projectkennel.org** (also listed in `SECURITY.md`, which is authoritative if the two ever differ). We acknowledge reports within 72 hours and coordinate disclosure on a timeline appropriate to the severity.

The threat catalogue describes *classes* of risk and is public. A *specific* vulnerability in our implementation is reported privately first; once a fix lands, the report and any associated catalogue updates become public.

Note the boundary with issue filing (below): a **suspected, non-exploit-specific** threat class that the catalogue does not cover is a public `[T-NEW]` issue. A **specific, working exploit** is a private report. When in doubt, treat it as private — a maintainer will tell you to open a `[T-NEW]` issue if that is the right venue.

---

## Before you contribute

Read, in this order:

1. [EXEC-SUMMARY.md](EXEC-SUMMARY.md).
2. [THREATS.md](THREATS.md). You will be expected to reference threat IDs by number.
3. [TEMPLATE-ai-coding-strict.md](TEMPLATE-ai-coding-strict.md).
4. [CODING-STANDARDS.md](CODING-STANDARDS.md). Skim it; refer back as needed. Appendix B is a one-page quick reference for the tags, the close-on-arrival categories, and the commit cadence.

If you skip these, every other step below will feel arbitrary.

---

## Development setup

```sh
# Install rustup via your preferred method (https://rustup.rs/).
# rust-toolchain.toml pins the version; rustup picks it up automatically.

# Clone.
git clone https://github.com/<org>/kennel.git
cd kennel

# Read the install script before running it. It is short.
less tools/install-hooks.sh
tools/install-hooks.sh

# Configure commit signing (CODING-STANDARDS.md §13.1).
git config commit.gpgsign true
# (or use SSH signing: git config gpg.format ssh)

# Verify your environment builds the project.
cargo build --offline --frozen --locked
cargo test
```

The git hooks (CODING-STANDARDS.md §15) run a **fast subset** of CI before each commit and push — `cargo fmt`, clippy, the offline build, and the two checksum verifiers. They do **not** run `cargo deny`, `cargo audit`, `cargo vet`, `cargo doc -D warnings`, the fuzz smoke test, the reproducible-build double-run, the BPF kernel-matrix, or the full workspace `cargo test`. Those are CI-only.

So: if the hooks pass, the *arrival-blocking* CI checks are expected to pass. But a dependency change can still fail `cargo deny`/`audit`/`vet` on arrival even with green hooks — those checks simply do not run locally. **Before any dependency PR, run them yourself** (`cargo deny check`, `cargo audit`, `cargo vet --locked`) and perform the §5.5 verification. A first-arrival failure on a CI-only check is not an auto-close (see *What gets closed* below); a first-arrival failure on a hook-covered check is.

---

## Filing an issue

Every issue title must start with exactly one of three tags, as the first thing in the title. A GitHub Action enforces this on every newly-opened issue.

- **`[T<id>]`** — an existing threat in [THREATS.md](THREATS.md), ID verbatim.
- **`[T-NONE]`** — a positive claim that you read the catalogue and this is **not** security-bearing (build break, typo, packaging, feature request).
- **`[T-NEW]`** — a positive claim that you believe this **is** security-bearing but is **not** in the catalogue yet (a novel threat class, or a hardening gap THREATS.md does not cover).

**Pass:**

```
[T12] Panic in template-chain depth-limit check
[T1]  fs.scrub does not catch .envrc.local pattern
[T-NEW] Resolver trusts template mtime for cache invalidation; not catalogued, looks attackable
[T-NONE] Build fails on aarch64-musl
[T-NONE] Typo in EXEC-SUMMARY.md §3
```

**Auto-closed:**

```
Bug: panic in parser                       (no tag)
[BUG] Panic in parser                      (not a recognised tag)
[CRITICAL] Issue with template parsing     (not a recognised tag)
[T99] Issue with template parsing          (T99 is not in THREATS.md)
[Security] Hardening idea                  (not a recognised tag — use [T-NEW])
```

**Do not reach for `[T-NONE]` when you are unsure.** `[T-NONE]` is a claim that the issue is *not* a security concern — using it for an uncatalogued security concern routes that concern into the explicitly-ignored bucket. If you think something is security-relevant but cannot find a matching ID, use `[T-NEW]`. A `[T-NEW]` issue is **not** auto-closed; a maintainer triages it and either catalogues it with a real ID or explains why it is out of scope. Guessing a wrong `[T<id>]` fails the Action; an honest `[T-NEW]` does not.

**Do not file a specific exploitable vulnerability as any kind of issue** — not `[T-NEW]`, not anything. See *Reporting security vulnerabilities* above. `[T-NEW]` is for suspected threat *classes*; the private channel is for working exploits.

Full rules in CODING-STANDARDS.md §13.5.

---

## Submitting a PR

Every PR follows the three-phase commit cadence from CODING-STANDARDS.md §7.1:

1. **`test:` commit.** Full tests for the new behaviour, plus the minimum stubs needed for the workspace to compile (function signatures with `todo!()` bodies, empty error variants). Tests fail at runtime, not at compile time. Every commit on the branch must compile so that `git bisect` works.
2. **`scaffold:` commit.** Flesh out the structure: input validation, error variants populated, plumbing through public APIs, doc comments. Structure-level tests pass; algorithm tests still fail.
3. **`feat:` commit** (or `fix:`). Fill in the implementation. All tests pass; no `todo!()` remains.

Folding is permitted in two cases:

- `test:` + `scaffold:` together when the structure is small.
- `scaffold:` + `feat:` together when the implementation is small.

**Skipping the `test:` commit is never permitted, and no fold ever removes it.** Note what this means in practice: a compliant PR always has **at least two commits, one of which is `test:`**. A PR that arrives as a single squashed commit — even a single `feat:` — has no `test:` history and is closed without review. The check is on your *branch history*, not on how you intend the PR to be merged; if you squashed locally, re-push the unsquashed branch. The cadence itself is the test that you understand the project.

### The PR description

Every PR fills out [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md). Required fields:

- **What changes.** The behaviour added, removed, or fixed, stated so a reader can verify against the diff.
- **Why, in project-local terms.** Threat IDs from `THREATS.md`, design-document invariants, open-issue references. "Best practice", "improves security", "follows convention" — none of these pass the template.
- **Phase boundaries.** Which commits are `test:`, `scaffold:`, `feat:`. If folded, why.
- **Dependency changes.** For any change to `Cargo.toml`, `Cargo.lock`, `crates-archive/`, or `CHECKSUMS.toml`: an explicit account of how you performed the §5.5 verification. Which independent sources you consulted, what their results were. "I ran `cargo update`" is not the answer.
- **Tests.** Names and what they cover. New behaviour without new tests fails review.
- **Threat-surface impact.** For changes touching workload-reachable surface: does this expand, contract, or leave unchanged what a confined workload can do? With reasoning.

Specificity is the test. References to specific threat IDs or invariants demonstrate engagement; generic boilerplate is closed.

---

## What gets closed without review

A PR from a non-maintainer is closed without review if any of the following are true. These are not negotiated; the macro close message points back to this document.

1. **Unsolicited refactor / "optimisation" / cleanup** without a maintainer-approved issue attached. Cleaning up working code is the most common form of low-effort contribution and we will not subsidise it.
2. **Missing the §7.1 cadence.** No `test:` commit in the branch history → closed. (A compliant PR is always ≥ 2 commits including a `test:`; a single squashed commit is never compliant.)
3. **Boilerplate PR description.** Generic justifications, no project-local references → closed.
4. **Arrival-blocking CI failure.** The checks the hooks can run locally — `cargo fmt`, the clippy gate, the offline build, both checksum verifiers — failing on the first CI run is grounds for close. Run the hooks before pushing.

   The CI-only checks the hooks **cannot** run locally — `cargo deny`, `cargo audit`, `cargo vet`, `cargo doc -D warnings`, the fuzz smoke test, the reproducible-build double-run, the BPF kernel-matrix, and the full workspace `cargo test` — are **not** auto-close on first arrival. You get a maintainer comment naming the failing check and a chance to fix, because you could not reasonably have run those checks yourself. A repeated failure on the same check after the comment is closed. (Dependency PRs land here most often: run `cargo deny`/`audit`/`vet` yourself per §5.5 to avoid the round-trip.)

An issue from a non-maintainer is auto-closed if the title does not begin with `[T<id>]`, `[T-NONE]`, or `[T-NEW]`. A `[T-NEW]` issue is never auto-closed — it is routed to maintainer triage.

If your PR or issue is closed and you believe it was in error, refile with the corrected form. We do not gatekeep on identity; we filter on whether the contribution meets the bar.

---

## Using AI to contribute

You can use AI assistance to write code, draft commit messages, or fill in the PR template. The standards do not change. An AI-assisted PR that satisfies the cadence, the template, the CI gate, and the specificity requirements is reviewed on its merits.

What the standards filter is *low-effort* contribution. AI tools amplify both careful work and lazy work; the project's checks are designed so that lazy work fails before it reaches a maintainer. If you are using AI to produce code, your responsibilities are:

- Read the code it produced before submitting.
- Verify every reference it generates — threat IDs, invariants, function names, file paths — against the actual documents and source. AI tools hallucinate identifiers convincingly. A wrong `[T<id>]` fails the issue Action; a wrong invariant name fails review.
- Run the hooks locally. Do not rely on CI to catch what your machine would have caught — and remember the hooks are only a subset, so for dependency changes run `cargo deny`/`audit`/`vet` yourself too.
- Write a PR description that is specific to *this* project, not generic. If you cannot do that, you have not engaged with the codebase enough to submit a PR.

In practice, the easiest way for AI-generated code to clear the bar is to treat the model's output as a draft and harden it manually. The hooks and CI are the same for everyone.

---

## Becoming a trusted contributor

After three PRs merged in compliance with the cadence and the template, you are added to `CONTRIBUTORS.md`. Trusted contributors get:

- A CI-failing PR receives a comment, not an immediate close.
- An issue with a missing tag receives a comment, not an immediate close.
- Refactor proposals may be filed as PRs directly, without first opening an issue, provided the PR still meets §7.1 and the template.

The list is small by design. Trust is a working assumption maintainers extend after seeing demonstrated understanding of the project; it can be revoked by maintainer majority with reasoning recorded.

---

## Where to ask questions

- **Design or threat-model questions** — GitHub Discussions, tagged appropriately.
- **"How do I satisfy rule X?"** — an issue tagged `[T-NONE]`.
- **"Is this contribution in scope before I write code?"** — an issue tagged with the relevant threat ID, or `[T-NEW]` if you think it concerns an uncatalogued threat. Strongly encouraged; saves both of us time.
- **A specific exploitable vulnerability in Kennel itself** — see *Reporting security vulnerabilities* above. Not a public issue.

---

## Conduct and licensing

Respectful conduct in all project spaces. Maintainers act on harassment, doxxing, or sustained disruption regardless of the technical quality of the contributor's work. See `CODE_OF_CONDUCT.md` (*[TBD]* until published).

**Licensing is split by component:**

- The **userspace — every Rust crate — is `Apache-2.0`.**
- The **BPF programs in `bpf/` are `GPL-2.0-only`** — by necessity, not preference. The kernel marks several helpers Kennel relies on as GPL-only (notably the `bpf_probe_read_kernel*` family on the §4.1 whitelist), and the verifier rejects a BPF program that does not declare a GPL-compatible license. This is the standard arrangement for any BPF that touches GPL-only helpers; see CODING-STANDARDS.md §4.1.

The two are *separate works* that communicate only across the `bpf(2)`/map ABI (CODING-STANDARDS.md §2.2) and are never linked into one binary, so the `Apache-2.0` / `GPL-2.0-only` combination raises no compatibility problem — the incompatibility only arises for a *single combined* work, which we never produce (CODING-STANDARDS.md §3, *Licensing*). The repository carries `LICENSE` (Apache-2.0) at the root, every crate's `Cargo.toml` sets `license = "Apache-2.0"`, and the `bpf/` sources carry `GPL-2.0` SPDX headers. (The companion `bpf/LICENSE` file and `SPDX-License-Identifier` headers on the Rust sources are still to come — see the checklist below.)

**By submitting a contribution you agree it is licensed under the licence of the file you touch:** Rust under `Apache-2.0`, `bpf/` C under `GPL-2.0-only`. We do not require a CLA.

> **Pre-publication checklist (mechanical, no decisions left).** Before the repository is opened to outside contribution: commit `bpf/LICENSE` (GPL-2.0-only) and add the `SPDX-License-Identifier` header to the Rust sources. (The root `LICENSE`, the per-crate `license` fields, and the `bpf/` SPDX headers are already in place, as is the security contact `security@projectkennel.org` and `SECURITY.md`.) No publish-blockers remain.

---

## Why we are strict

A security-critical project can absorb either thoroughness or volume of contribution, not both. We have chosen thoroughness. The rules above raise the cost of submission to the level where:

- A serious contributor pays the cost once, learns the process, and submits work that gets reviewed on its merits.
- A low-effort submission fails an automated check and never reaches a maintainer.

This is the contract: if you do the work, your contribution is read. If you do not, it is closed. We do not apologise for this and we will not relax it; the alternative is that the project's maintainers stop reading PRs at all, and the project loses the ability to evaluate any contribution.

One thing we *do* hold ourselves to: we will not close you for something you could not have caught. The auto-close categories are scoped to checks you can run locally and rules you can read in advance. The slow, infrastructure-dependent checks get a comment, not a close. If you did the work, you will not be blindsided.

Thanks for reading.
