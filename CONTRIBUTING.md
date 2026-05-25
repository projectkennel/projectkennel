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

**Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.** Email the maintainers at the address listed in `SECURITY.md` (*[TBD]* until the project publishes a contact). We acknowledge reports within 72 hours and coordinate disclosure on a timeline appropriate to the severity.

The threat catalogue describes *classes* of risk and is public. A *specific* vulnerability in our implementation is reported privately first; once a fix lands, the report and any associated catalogue updates become public.

---

## Before you contribute

Read, in this order:

1. [EXEC-SUMMARY.md](EXEC-SUMMARY.md).
2. [THREATS.md](THREATS.md). You will be expected to reference threat IDs by number.
3. [TEMPLATE-ai-coding-strict.md](TEMPLATE-ai-coding-strict.md).
4. [CODING-STANDARDS.md](CODING-STANDARDS.md). Skim it; refer back as needed.

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

The git hooks (CODING-STANDARDS.md §15) run the same checks as CI before each commit and push. If they pass locally, CI is expected to pass. Skipping them does not avoid the checks; it only delays finding out you missed something.

---

## Filing an issue

Every issue title must start with a tag identifying the relevant entry in [THREATS.md](THREATS.md), or `[T-NONE]` if the issue is not security-bearing. A GitHub Action enforces this on every newly-opened issue.

**Pass:**

```
[T12] Panic in template-chain depth-limit check
[T1]  fs.scrub does not catch .envrc.local pattern
[T-NONE] Build fails on aarch64-musl
[T-NONE] Typo in EXEC-SUMMARY.md §3
```

**Auto-closed:**

```
Bug: panic in parser                       (no tag)
[BUG] Panic in parser                      (not a threat ID)
[CRITICAL] Issue with template parsing     (not a threat ID)
[T99] Issue with template parsing          (T99 is not in THREATS.md)
```

If you are not sure which threat ID applies, use `[T-NONE]` — a maintainer will retag if it turns out to be security-bearing. Better to use `[T-NONE]` truthfully than to guess at a threat ID. Full rules in CODING-STANDARDS.md §13.5.

---

## Submitting a PR

Every PR follows the three-phase commit cadence from CODING-STANDARDS.md §7.1:

1. **`test:` commit.** Full tests for the new behaviour, plus the minimum stubs needed for the workspace to compile (function signatures with `todo!()` bodies, empty error variants). Tests fail at runtime, not at compile time. Every commit on the branch must compile so that `git bisect` works.
2. **`scaffold:` commit.** Flesh out the structure: input validation, error variants populated, plumbing through public APIs, doc comments. Structure-level tests pass; algorithm tests still fail.
3. **`feat:` commit** (or `fix:`). Fill in the implementation. All tests pass; no `todo!()` remains.

A PR that arrives as a single squashed commit with no `test:` / `scaffold:` history is closed without review. The cadence itself is the test that you understand the project.

Folding is permitted in two cases:

- `test:` + `scaffold:` together when the structure is small.
- `scaffold:` + `feat:` together when the implementation is small.

Skipping the test commit is never permitted.

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
2. **Missing the §7.1 cadence.** No `test:` / `scaffold:` / `feat:` history → closed.
3. **Boilerplate PR description.** Generic justifications, no project-local references → closed.
4. **CI failures on arrival.** Format, clippy, offline build, checksum verification, BPF verifier matrix — any fail and the PR is closed, not iterated. Run the hooks locally before pushing.

An issue from a non-maintainer is auto-closed if the title does not begin with `[T<id>]` or `[T-NONE]`.

If your PR or issue is closed and you believe it was in error, refile with the corrected form. We do not gatekeep on identity; we filter on whether the contribution meets the bar.

---

## Using AI to contribute

You can use AI assistance to write code, draft commit messages, or fill in the PR template. The standards do not change. An AI-assisted PR that satisfies the cadence, the template, the CI gate, and the specificity requirements is reviewed on its merits.

What the standards filter is *low-effort* contribution. AI tools amplify both careful work and lazy work; the project's checks are designed so that lazy work fails before it reaches a maintainer. If you are using AI to produce code, your responsibilities are:

- Read the code it produced before submitting.
- Verify every reference it generates — threat IDs, invariants, function names, file paths — against the actual documents and source. AI tools hallucinate identifiers convincingly.
- Run the hooks locally. Do not rely on CI to catch what your machine would have caught.
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
- **"Is this contribution in scope before I write code?"** — an issue tagged with the relevant threat ID. Strongly encouraged; saves both of us time.
- **A specific exploitable vulnerability in Kennel itself** — see *Reporting security vulnerabilities* above. Not a public issue.

---

## Conduct and licensing

Respectful conduct in all project spaces. Maintainers act on harassment, doxxing, or sustained disruption regardless of the technical quality of the contributor's work. See `CODE_OF_CONDUCT.md` (*[TBD]* until published).

By submitting a contribution you agree it is licensed under the project's licence ([LICENSE](LICENSE) — *[TBD]* until published). We do not require a CLA.

---

## Why we are strict

A security-critical project can absorb either thoroughness or volume of contribution, not both. We have chosen thoroughness. The rules above raise the cost of submission to the level where:

- A serious contributor pays the cost once, learns the process, and submits work that gets reviewed on its merits.
- A low-effort submission fails an automated check and never reaches a maintainer.

This is the contract: if you do the work, your contribution is read. If you do not, it is closed. We do not apologise for this and we will not relax it; the alternative is that the project's maintainers stop reading PRs at all, and the project loses the ability to evaluate any contribution.

Thanks for reading.
