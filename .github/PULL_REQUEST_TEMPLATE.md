<!--
Project Kennel PR template.

CONTRIBUTING.md and CODING-STANDARDS.md §13.4 describe what is expected here.
PRs that submit this template unedited, or with generic boilerplate
("improves security", "follows best practices", "fixes a bug" without
naming the bug), are closed without review.

Replace the italic prompt text and `<placeholder>` markers with your
content. Sections marked OPTIONAL may be deleted entirely when they
do not apply; do not leave a section with only its prompt text.
-->

## What changes

_One or two sentences naming the behaviour added, removed, or fixed, in terms a reader can verify against the diff. Not "improves X"; **names** the change._

## Why

**Threat ID(s) addressed:** `<e.g. T18; or "none — not security-bearing">`

**Design-document invariant(s) implemented or affected:** `<reference; or "none">`

**Issue(s) closed:** `<#NN; or "none">`

_One paragraph of project-local reasoning. "T18 (template-chain DoS) is currently unbounded in the resolver; this caps it at the documented limit" is the expected form. "Best practice" or "improves security and efficiency" fails the template and the PR is closed._

_If the change is not security-bearing, state explicitly what user-visible behaviour it changes and why that is desirable._

## Phase boundaries (CODING-STANDARDS.md §7.1)

- `test:` commit: `<sha>` — or folded into `scaffold:` (state reason below)
- `scaffold:` commit: `<sha>` — or folded into `feat:` (state reason below)
- `feat:` (or `fix:`) commit: `<sha>`

_Skipping the `test:` phase is never acceptable. If only Phase 1 and 2 are present (no implementation), name the tracked follow-up issue and state what currently passes vs. fails in CI._

_If you folded any phases, state which pair and why. Folding `test:` + `scaffold:` is acceptable when the structure is small enough that pulling them apart adds no review value. Folding `scaffold:` + `feat:` is acceptable when the implementation is small._

## Dependency changes — OPTIONAL

_Delete this entire section if the PR does not touch `Cargo.toml`, `Cargo.lock`, `crates-archive/`, or `CHECKSUMS.toml`._

**Crate(s) added / updated / removed:** `<name>`, `<old version>` → `<new version>`

**§5.5 verification performed:**

- Independent sources consulted: `<list, e.g. crates.io independent download; github.com/<org>/<repo> tag <v> signed by <fingerprint>; docs.rs source archive>`
- Result of each source: _what each returned and whether it agreed with the others._
- `tools/audit-helper` output: _summarise here, or attach as a PR comment._
- `audited-by` in `CHECKSUMS.toml`: `<name>`

_"I ran `cargo update`" is not §5.5 verification. The substance is the independent cross-checking; the helper does the mechanical work, the human does the reading._

## Tests

**New tests added:**

- `<crate>::<module>::<test_name>` — _one-line description of what it covers_
- _add lines as needed_

_Per CODING-STANDARDS.md §7.2, coverage must include: the success case, every documented error variant, every documented panic condition, boundary conditions, and adversarial input. State which of these the listed tests cover. If any required category is absent, state explicitly why._

_If the change is a docs-only or refactor-of-tests PR with no new behaviour, state that here._

## Threat-surface impact

_For changes that touch behaviour exposed to a confined workload (filesystem, network, AF\_UNIX, D-Bus, capabilities, syscalls, BPF programs, signal/ptrace), state which of the following applies:_

- _**Expand** the workload-reachable surface — the workload can now do something it could not before._
- _**Contract** the surface — the workload can no longer do something it previously could._
- _**Unchanged** — behaviour change without effect on the workload-reachable surface._

_State which and give reasoning. "Unchanged" is a legitimate answer but must be reasoned from the code, not asserted._

_For purely internal changes (refactors of code that does not touch the workload-facing surface): "Internal change; no workload-reachable surface affected."_

## Pre-submission checklist

- [ ] I have read CONTRIBUTING.md and CODING-STANDARDS.md.
- [ ] Every commit in this PR is signed (GPG or SSH).
- [ ] Local git hooks (`tools/install-hooks.sh`) are installed and have run on every commit.
- [ ] `cargo build --offline --frozen --locked` succeeds locally.
- [ ] `cargo test --all-features` passes locally.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes locally.
- [ ] `cargo fmt --check` passes locally.
- [ ] If dependencies changed: `tools/verify-checksums` (Rust) and `tools/verify-checksums.sh` (shell) both pass and agree.
- [ ] No italic prompt text or `<placeholder>` markers remain in this description.

_A PR with unticked boxes, unedited placeholders, or generic boilerplate in the prose sections is closed without further review (CODING-STANDARDS.md §13.4)._
