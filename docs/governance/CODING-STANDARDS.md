# Project Kennel — Coding Standards

**The bar is OpenSSH and libpam.** Code in this repository is read by people who do not trust us. It is auditable line by line. It compiles, tests, and runs the same way on the next LTS distro five years from now. The language is Rust; the BPF programs (only) are C.

This document is normative. Deviations require a written justification in the PR description, accepted by a maintainer, and a comment in the code pointing back to the PR.

---

## 1. Scope and authority

These standards govern all source code in this repository, including:

- Rust crates in the workspace (`crates/`).
- C source for BPF programs (`bpf/`).
- Build scripts, CI configuration, release tooling.

Vendored third-party code under `vendor/` is governed by §5 (Dependencies), not by this document — we do not rewrite upstream code to match our style. We do, however, audit it.

When this document and an external style guide disagree, this document wins. When this document and the Rust API Guidelines disagree, this document wins. When this document and a maintainer disagree, the maintainer either updates this document or the standard stands.

**Enforcement legend.** Throughout this document, each rule is enforced either by *tooling* (clippy/rustc lints, CI checks — mechanical, non-waivable, catches every instance) or by *review* (a human reading the diff — catches intent and content that tooling cannot express). Where it is not obvious, rules are marked `[tool]` or `[review]`. A `[review]`-only rule is exactly as binding as a `[tool]` rule; the difference is *who* catches a violation, not whether it is permitted. The §13.4 close-on-arrival filter and the §14 CI gate test only the `[tool]` subset; the `[review]` subset is what maintainer reading is for. A quick reference of the tool-vs-review split, the close-on-arrival categories, and the issue tags is in Appendix B.

---

## 2. Toolchain and versions

The project has two toolchains: Rust for the userspace, and clang/LLVM for the BPF programs in `bpf/`. Both are pinned.

### 2.1 Rust toolchain

**Development toolchain:** the version of Rust everyone uses to build the workspace, pinned in `rust-toolchain.toml`. Stable channel; no nightly. No `#![feature(...)]` in any crate. Contributors install via `rustup`, which honours `rust-toolchain.toml` automatically. We do not build against the distro's Rust package; Debian/Fedora packagers may target a different version (see MSRV below), but contributor workflow is `rustup`-driven and reproducible across hosts.

Pinning to recent stable is intentional. The OpenSSH analogy is about *auditability*, not about supporting ancient compilers — Rust moves faster than C and "Debian stable's rustc" is typically 18–24 months behind upstream. Tying the development toolchain to that floor would forgo `let...else`, modern async-fn-in-trait, recent stdlib additions, and clippy improvements that materially help the project. We accept the cost of contributors running `rustup` over the cost of writing 2022-era Rust in 2026.

Note the interaction with §12.2: because the development toolchain moves with `rustup`, lints whose set changes between clippy releases (notably `clippy::pedantic`) are denied only in the pinned-toolchain CI job, not on the moving toolchain. See §12.2 for the rationale; the short version is that a `rustup update` must never turn the tree red with no code change.

**Minimum supported Rust version (MSRV):** the floor declared in each crate's `Cargo.toml` `rust-version` field. This is what *packagers* may use, not what contributors use. MSRV is set conservatively but not tied to one distro's choices; it lags the development toolchain by no more than two stable releases (roughly twelve weeks). CI builds the workspace against both the development toolchain and the MSRV on every PR; either failing blocks merge.

Bumping MSRV requires:

1. A CHANGELOG line noting the new floor.
2. A justification in the PR (which feature, which crate).
3. Confirmation that the new MSRV is reachable for major packagers (Debian backports, Fedora current, Ubuntu LTS current, Arch, Homebrew). "Reachable" includes backports and PPAs; it does not require the version to be in main archives. If all major packagers would need a non-default toolchain, the bump is reconsidered.

### 2.2 C / BPF toolchain

The BPF programs in `bpf/` are compiled by clang against the kernel UAPI (no CO-RE). The Rust loader (`kennel-bpf`, a hand-rolled `bpf(2)` loader using `object` for ELF parsing — **not** libbpf-rs/libbpf-sys or aya) consumes the resulting `.o` files.

- **Compiler:** clang, version pinned by the build environment. CI uses a container image with a specific clang version recorded in `BUILD-ENV.md`. Release builds use the same image; reproducibility requires the same compiler.
- **No libbpf, no aya.** We do not vendor or link libbpf, and we do not use libbpf-rs/libbpf-sys or aya (their cost — ~1435 vendored C files / a 19-crate tree — outweighed what they save; see `DEPENDENCIES.md`). The loader is a small, reviewed `bpf(2)` FFI over `libc` with `object` for ELF parsing.
- **Kernel headers:** the programs compile against the kernel UAPI (`<linux/bpf.h>` from `linux-libc-dev`, plus the multiarch `<asm/types.h>` path), pinned in `BUILD-ENV.md`. There is **no** committed `vmlinux.h` and no BTF/CO-RE step — the programs touch only stable hook-context structs and our own maps.
- **bpftool:** optional, for inspection and the verifier-load matrix only; never on the build/load path. When invoked, its version is pinned in the same container as clang.
- **Map definitions** are declared in `bpf/maps.h`; the Rust loader mirrors them **by hand** in `kennel-bpf`'s `KENNEL_MAPS` (there is no skeleton-derived type generation), and the loader resolves map references by symbol name. The two sides share a layout via the committed `bpf/maps.h`, which is the single source of truth. Hand-mirroring is deliberate; drift between the C source of truth and the Rust mirror is caught by a test, not prevented by codegen (see §4.1, *Testing*).

### 2.3 Build properties

**Offline:** `cargo build --offline --frozen --locked` must succeed against `src/vendor/` for every crate (§5.4). Clang invocations must not fetch anything. CI fails if any network traffic is observed during build.

**Reproducibility:** release builds are reproducible. `SOURCE_DATE_EPOCH` is honoured, no build timestamps are embedded, no host paths leak into binaries, no kernel version leaks into BPF object files (they compile against the pinned UAPI headers, not a kernel-specific BTF dump). CI builds every release twice on two different runners and compares both the Rust binaries and the BPF `.o` files hash-for-hash.

---

## 3. Workspace structure

The repository is one Cargo workspace with one crate per architectural module. Crates have narrow, named purposes; no crate is a grab-bag.

Crate names are prefixed `kennel-`. Module boundaries match architectural boundaries; if a module wants to depend on internals of another crate, that is a design smell — make the API public or merge the crates.

A crate that requires `unsafe` is annotated as such in its top-level `lib.rs` documentation and listed in `UNSAFE-CRATES.md` at the workspace root. By default, every crate carries `#![forbid(unsafe_code)]`. Removing this attribute requires §4.

Each crate carries, at minimum:

- `Cargo.toml` with `rust-version`, `license` (`Apache-2.0` for every Rust crate — see *Licensing* below), `description`, and explicit dependency versions (§5).
- `src/lib.rs` (or `src/main.rs`) with a module-level doc comment describing the crate's purpose, its invariants, and which threats (from `THREATS.md`) bear on its design.
- `README.md` if any external party will read the crate.
- `tests/` for integration tests; unit tests live in `#[cfg(test)] mod tests` blocks beside the code.

### Licensing

The userspace is **`Apache-2.0`**; every Rust crate declares `license = "Apache-2.0"` and carries an `SPDX-License-Identifier: Apache-2.0` header. The BPF programs in `bpf/` are **`GPL-2.0-only`** — not by preference but by necessity: the kernel marks several of the helpers we rely on as GPL-only (notably the `bpf_probe_read_kernel*` family on the §4.1 whitelist), and the verifier rejects a program that calls them unless it declares a GPL-compatible license. The per-program declaration is specified in §4.1.

The `Apache-2.0` / `GPL-2.0-only` combination is legitimate here precisely because the two are *separate works*, not a combined derivative. The BPF `.o` files and the Rust binaries are distinct compilation units that communicate only across the stable `bpf(2)`/map ABI (§2.2), with no shared linkage and no GPL code linked into the userspace. `Apache-2.0` and `GPLv2` are mutually incompatible as a *single combined* work; we never create one, and the architectural separation that makes that true is the same separation §2.2 already requires for other reasons. The repository carries `LICENSE` (Apache-2.0) at the root and `bpf/LICENSE` (GPL-2.0-only), and every source file carries the matching SPDX header. A contributor's inbound license follows the file they touch: Rust under `Apache-2.0`, `bpf/` C under `GPL-2.0-only`.

---

## 4. `unsafe` code

`unsafe` is the only language feature whose review burden is fundamentally different from safe Rust. We treat it accordingly.

**Default:** every crate has `#![forbid(unsafe_code)]` at the top of `lib.rs` or `main.rs`. This is not negotiable for the policy crate, the CLI, the netproxy, or any test code.

**Where allowed:** the `kennel-syscall` crate (or equivalent, name TBD) is the *only* crate permitted to contain `unsafe` blocks. All raw syscalls, Landlock/seccomp/BPF library calls that require `unsafe`, and FFI live there. The crate is sized to be reviewable in one sitting.

**Required for every `unsafe` block:**

```rust
// SAFETY: <preconditions that make this call sound, stated in terms the
// reader can verify from the surrounding code, not from documentation
// elsewhere>.
//
// INVARIANTS UPHELD: <what this block preserves for the caller>.
//
// FAILURE MODE: <what happens if the preconditions do not hold — does
// the kernel reject the call, does memory get corrupted, does the
// process panic>.
unsafe {
    ...
}
```

**Review requirement:** any PR touching `unsafe` requires two maintainer approvals, one of whom must not have written the change. A PR adding a *new* `unsafe` block in a crate that did not previously contain any is reviewed by all current maintainers.

**Forbidden patterns inside `unsafe`:**

- `transmute` between types that are not documented as having the same layout in the Rust reference.
- Pointer arithmetic on `*mut u8` without a `// LAYOUT:` comment citing the type's declared layout.
- `unwrap_unchecked` and friends; if it can be checked, check it.
- Calling into a dependency's `unsafe` function without a `SAFETY:` comment for our call, even if the dependency claims safety.

### 4.1 BPF C code

C is `unsafe` by construction. The BPF programs in `bpf/` are the only C in this repository, and they are reviewed under stricter rules than the equivalent Rust would be.

**Where allowed:** `bpf/` only. No C anywhere else. C headers are pinned and vendored per §2.2; no inclusion of arbitrary system headers.

**Style:**

- POSIX C11 with the standard BPF map/helper macro idioms, compiled against the kernel UAPI (`<linux/bpf.h>`) — **no** CO-RE/`vmlinux.h`. No GCC-isms beyond what clang accepts. `-Wall -Wextra -Werror` in the build.
- `static` everything that isn't a BPF section symbol. No global mutable state beyond BPF maps.
- **License declaration.** Every program declares a GPL-compatible license at runtime — `char _license[] SEC("license") = "GPL";` — and carries an `SPDX-License-Identifier: GPL-2.0-only` header. This is mandatory, not stylistic: the GPL-only kernel helpers on the `bpf/HELPERS.md` whitelist (including the `bpf_probe_read_kernel*` family required below) cause the verifier to **reject** any program that declares a non-GPL-compatible license, so a wrong or missing declaration is a load failure, not a paperwork slip. The SPDX header and the `SEC("license")` string must agree; CI checks both are present on every program, and the §3 *Licensing* rationale explains why `bpf/` is `GPL-2.0-only` while the userspace is `Apache-2.0`.
- Map definitions are declared in `bpf/maps.h`; the Rust loader mirrors them by hand in `kennel-bpf`'s `KENNEL_MAPS` (there is no skeleton-derived type generation), and the loader resolves map references by symbol name. The two sides share a layout via the committed `bpf/maps.h`.

**Bounds and safety idioms required:**

- Every pointer dereference is preceded by an explicit verifier-visible bounds check against the bearing structure's declared end (`if (ptr + 1 > data_end) return …`). Drive-by `*ptr` without the preceding check is rejected at review, regardless of what the verifier happens to accept.
- Loops are bounded with a compile-time `#pragma unroll` and an explicit `i < N` constant, or use `bpf_loop` where available. No unbounded loops.
- String operations use `bpf_probe_read_kernel_str`/`bpf_probe_read_user_str` with explicit length limits; never `strcpy`, `strlen`, or pointer-walking from a kernel-side pointer.
- Helper-function usage is restricted to a whitelist maintained in `bpf/HELPERS.md`. Each helper has a documented rationale (why we need it, what verifier classes it engages). Adding a helper requires the same two-maintainer review as adding an `unsafe` block.
- `bpf_printk` is forbidden in shipped programs. It is a debug aid only and is stripped by the build before release.

**Required comment block on every program:**

```c
/*
 * Program: <attach point, e.g., cgroup/connect4>
 * Purpose: <one paragraph>.
 * Verifier complexity budget: <expected instructions / map accesses>.
 * Maps used: <list, each with a one-line purpose>.
 * Failure mode: <what happens if the program rejects an action — does
 *               the syscall fail with what errno, does the action proceed
 *               silently, does userspace get notified via ringbuf>.
 * Threat bearing: <T-IDs from THREATS.md>.
 */
```

**Review requirement:** identical to `unsafe` review (two maintainer approvals, one not the author). Adding a new BPF program is reviewed by all current maintainers, the same as introducing a new `unsafe`-bearing crate.

**Verifier failures are not warnings.** A BPF program that loads under one kernel and is rejected by another is a regression, and is treated the same as a compilation failure. CI runs the BPF programs through `bpftool prog load` (and/or `kennel-bpf`'s own loader) on a matrix of supported kernel versions; any rejection blocks merge. The matrix is declared in `BUILD-ENV.md`.

**Testing:**

- BPF programs are tested via two paths. First, unit tests against the loader crate use the kernel's `BPF_PROG_TEST_RUN` interface to invoke the program with constructed inputs and assert outputs. Second, integration tests run a real kennel and assert kernel-observable behaviour (cgroup BPF connect denials, etc.). Both run in CI on the kernel-version matrix.
- **BPF map types are hand-mirrored on the Rust side per §2.2**, with `bpf/maps.h` as the single source of truth. Drift between the C source of truth and the Rust mirror is caught by a **test, not by codegen**: a build-time check compiles a small C shim that emits `sizeof`/`offsetof` for each map-bearing struct against the committed `bpf/maps.h`, and compares those values against the Rust mirror's `size_of`/`offset_of!`. Any mismatch fails `cargo test`. We do **not** generate the Rust types from C (or C from Rust): generation would place unreviewed, machine-emitted code on the build path, which §5.3 (`build.rs`/codegen) constrains, and it would obscure exactly the layout a reviewer must check by eye. Hand-mirroring keeps both sides reviewable in plain source; the drift test keeps them honest. Manual `repr(C)` mirroring is therefore *required*, and the drift test — not codegen — is what makes it safe.

---

## 5. Dependencies (supply chain)

We are paranoid about supply-chain attacks. This is not rhetorical; it shapes the rules below.

### 5.1 Default

The default answer to "should we add a dependency?" is **no**. The standard library and what we have already written are tried first. The question "could I write this in a day" gets asked seriously before a dependency is added.

Examples of things we write rather than depend on (subject to revision with justification):

- Configuration parsing for our own formats once we know what we need.
- Small numerical or string utilities.
- Anything we would not be embarrassed to maintain ourselves.

Examples of things we use a dependency for (this is the short list; expanding it is a maintainer decision):

- Cryptography (`ring`, `ed25519-dalek`, `rustls`).
- TOML parsing (`toml`, `serde`).
- Landlock, seccomp, eBPF bindings where the kernel ABI is non-trivial.
- Async runtime (one only, in the proxy crate; never in the privhelper).

### 5.2 Adding a dependency

Adding a direct dependency requires, in the PR:

1. An entry in `DEPENDENCIES.md` with:
   - Crate name and exact version (no `^`, no `>=`, no `*` — see §5.4).
   - One-paragraph justification: what does it do, why are we using it instead of writing it.
   - License (must be MIT, BSD-2, BSD-3, Apache-2.0, ISC, or compatible; GPL/AGPL requires maintainer ratification). The permissive-only rule protects the **`Apache-2.0` userspace**: a GPL Rust crate linked into it would create exactly the `Apache`/`GPL` combined-work incompatibility §3 (*Licensing*) avoids. The `GPL-2.0-only` `bpf/` side pulls in no third-party code at all (no libbpf, no aya — §2.2), so its license raises no dependency question.
   - Maintainer-reviewer assignment: who on our side has read enough of this crate to vouch for it.
   - List of transitive dependencies added by this change.
2. A `cargo vet` audit entry for the crate and every newly transitively pulled crate. We use `cargo vet` (Mozilla) as the audit-of-record tool; entries cite version, audit type (full / delta), and reviewer.
3. Updated `src/vendor/` and `CHECKSUMS.toml` per §5.5.
4. CI passes including `cargo deny check`, `cargo audit`, `cargo vet --locked`, and `tools/verify-checksums`.

Updating an existing dependency version requires:

1. A line in CHANGELOG describing why (security advisory, required feature, upstream EOL).
2. A new `cargo vet` delta-audit entry.
3. Re-vendoring.
4. Two maintainer approvals.

Removing a dependency requires: the PR description and a CHANGELOG line. (Removing is encouraged.)

### 5.3 Forbidden by default

The following patterns require explicit per-instance maintainer approval, documented in `DEPENDENCIES.md`:

- **Procedural macros.** Proc-macros execute arbitrary code at compile time. We allow `serde_derive` and its near relatives; everything else needs a reason. We do not allow proc-macros in the privhelper or its dependency chain.
- **`build.rs` that does anything other than `println!("cargo:rustc-cfg=...")`-style metadata.** Build scripts that invoke external tools, fetch resources, or generate non-trivial code are an attack surface and require review of the script source.
- **Crates whose public API forces the *caller* to write `unsafe`** — an exported `unsafe fn`, or a documented safety contract the caller must uphold to use even the "safe" API soundly. This is about the *call site*, not the crate's internals. `ring`, `rustls`, and most of our allow-list use `unsafe` internally and expose a safe API; that is fine and is not what this rule covers. Where a dependency's API genuinely forces `unsafe` on us, the wrapping happens in `kennel-syscall` and nowhere else.
- **Crates that themselves depend on more than ten transitive crates.** We will sometimes accept this for foundational deps (the async runtime is the obvious case); we do not accept it for utility crates.
- **Crates whose latest release is more than two years old AND whose repository shows no maintenance activity.** Stagnation is not automatically disqualifying, but it requires us to commit to maintaining the dep ourselves if needed.

### 5.4 Pinning and vendoring

- Direct dependencies are pinned to exact versions: `serde = "=1.0.219"`, never `serde = "1"` or `serde = "1.0"`.
- `Cargo.lock` is committed for every crate (binary and library). We optimise for reviewer reproducibility, not for downstream library consumers.
- The unmodified `.crate` artifacts are committed to `src/vendor/`. Cargo is configured with a local-registry source pointing at this directory; builds run `--offline --frozen --locked`. CI fails if any build reaches the network or if `src/vendor/` and `Cargo.lock` disagree.
- Pinning a version constrains *which* crate Cargo resolves to. It does not constrain *what bytes* live under that name. The integrity ground truth is the checksum manifest in §5.5; pinning alone is insufficient.
- Dependency *merges* are never automated. Bots may *open* PRs (Dependabot, Renovate) as a notifier mechanism, since human attention to upstream releases is the alternative and humans miss things. A bot-opened PR is a starting point, not a candidate for merge: it triggers the manual procedure of §5.5 (independent download, cross-verification, checksum entry, two maintainer approvals). Auto-merge is off; PRs from bots have the same review burden as PRs from contributors and the bot account has no special trust. If a bot's PR sits open beyond the daily `cargo audit` cron's tolerance, the maintainer on duty either escalates or closes it explicitly.

### 5.5 Checksum manifest

`Cargo.lock` records SHA-256 hashes lifted from the registry at the moment `cargo update` runs. If the registry is compromised at that moment, the lockfile records the compromised hash as authoritative; `--locked` then faithfully reproduces the attack. Trust-on-first-use against a registry we do not control is not a supply-chain defence.

We maintain `CHECKSUMS.toml` at the workspace root as an independent, human-verified checksum manifest. Every direct and transitive dependency appears as an entry. The hash recorded is the hash *we* computed, against the `.crate` we audited, after cross-verification against at least one independent source. `CHECKSUMS.toml` is the audit artefact and the integrity ground truth; `Cargo.lock` is a working file Cargo maintains.

#### Format

```toml
[crate."serde"]
version = "=1.0.219"
crate-sha256 = "e8d3...<full hex>"
audited-by = "alice"
audited-on = "2026-05-25"
verified-against = [
    "crates.io published .crate (independent download)",
    "github.com/serde-rs/serde tag v1.0.219 (signed by serde-rs release key, fingerprint XXXX)",
    "docs.rs source archive",
]
notes = "Optional. Anything the next reviewer should know."
```

The reviewer's identity attaches their reputation to the entry. Entries without a named reviewer are rejected. The `verified-against` list cites the specific sources consulted; "I checked it" is not an acceptable entry.

#### Storage of artefacts

Crate artefacts are stored as the unmodified `.crate` tarballs in `src/vendor/<name>-<version>.crate`. Cargo is configured to consume them via a local-registry source. We do not commit the unpacked `vendor/<name>-<version>/` directory tree: the `.crate` is the authoritative artefact whose hash we control, and unpacked sources drift in subtle ways (line endings, permissions, extended attributes) that make a stable hash hard to reproduce across hosts.

#### Verification

`tools/verify-checksums` is a small, dependency-free Rust binary (sourced from `kennel-checksum-verify` in the workspace, itself with no external dependencies beyond `sha2` — which is itself listed in `CHECKSUMS.toml` and bootstrapped per §5.5.1). It:

1. Reads `CHECKSUMS.toml`.
2. Computes SHA-256 of every `.crate` in `src/vendor/`.
3. Fails if any `.crate` is missing from the manifest.
4. Fails if any manifest entry is missing from `src/vendor/`.
5. Fails if any computed hash does not match the manifest.
6. Fails if `Cargo.lock` references a crate version not pinned in the manifest.
7. Fails if `Cargo.lock`'s registry checksum for any crate differs from `CHECKSUMS.toml`. (Cargo's hash and ours must agree; if they do not, either the registry is lying to Cargo or our manifest is stale, and both are blocking conditions.)

This runs in CI on every PR and locally before any release tag.

#### Bootstrap (§5.5.1)

The verifier itself depends on a hashing implementation. To avoid an infinite-regress trust problem:

- The verifier uses only `sha2` (and its dependency chain) from the dependency set. `sha2` is audited under the same procedure as every other dep.
- A second, independent verifier path uses the system `sha256sum` binary (from coreutils), invoked via a shell script in `tools/verify-checksums.sh`. The two implementations must agree. CI runs both.
- The maintainer release checklist requires verifying on a freshly-installed system, against a distro-provided `sha256sum`, that the Rust verifier and the shell verifier produce identical results.

This is belt-and-braces against a compromise of the `sha2` crate itself.

#### Adding or updating an entry

The mechanical work (fetching, unpacking, hash computation, tarball comparison) is automated by `tools/audit-helper`. The reviewer's responsibility is *reading*, not tarball juggling. The helper:

- Fetches the `.crate` from `https://static.crates.io/crates/<name>/<name>-<version>.crate` independently of Cargo.
- Confirms byte-equality with what Cargo placed in `src/vendor/`.
- Clones the upstream repository at the corresponding tag into a scratch directory.
- Where the upstream signs tags, verifies the signature against keys recorded in `KEYS.md` (the project's pinned set of upstream maintainer keys, audited like any other dependency artefact).
- Runs `cargo package` in the upstream checkout and diffs the resulting file set against the `.crate`, surfacing differences for the reviewer.
- Computes the SHA-256 of the `.crate`.
- Prepares a draft entry for `CHECKSUMS.toml` that the reviewer edits and signs.

The helper does not commit anything. Its output is presented to the human; the human reads the source, fills in `verified-against`, fills in `notes` (if any), and commits.

The procedure for the reviewer:

1. On a clean checkout, run `cargo update -p <crate>` (or the equivalent for a new dep) and inspect the changes to `Cargo.lock`.
2. Run `tools/audit-helper fetch <crate> <version>` to fetch the new `.crate` files into `src/vendor/`. The helper refuses to overwrite existing files; updates are explicit removals and re-fetches.
3. Run `tools/audit-helper verify <crate> <version>` and read its output. The helper presents the diffs and the candidate hash; the reviewer reads the source code itself and decides whether the audit is accepted.
4. Fill in the `CHECKSUMS.toml` entry with reviewer name, ISO date, and `verified-against` sources.
5. Commit `CHECKSUMS.toml`, `src/vendor/<name>-<version>.crate`, and the updated `Cargo.lock` together. No splits.
6. Two maintainer approvals are required for any checksum addition or change. The approving maintainers should not be the same person as the auditor where avoidable.

The helper is treated as security-critical code: it is in the workspace, it is reviewed under §4 rules, and a compromise of the helper is treated as severe (it influences what reviewers see and could deceive them). The helper has no external dependencies beyond Rust stdlib and `sha2` (already in the manifest).

#### What this defends against

- **Registry compromise.** If crates.io is compromised after a crate was audited, the registry's serving of different bytes under the same version does not change `src/vendor/`. CI fails against the on-disk artefact. This is the most important property.
- **Typosquat in the dependency graph.** A new transitive dep that appears under a name we did not audit fails the "missing from manifest" check.
- **Silent version bump in `Cargo.lock`.** A lockfile change that promotes a dep to an unaudited version fails the cross-check between `Cargo.lock` and `CHECKSUMS.toml`.
- **Cargo's own registry-checksum lookup being misled.** Our hash is independent of Cargo's; if they disagree, that is a signal of a problem somewhere in the chain.
- **Single-point auditor-host compromise at audit time.** Degraded but not eliminated. The multi-source verification means an attacker would have to compromise the auditor's path to crates.io, the auditor's path to upstream git, and the auditor's signature-verification chain simultaneously. The rule that audits cite their specific sources is what makes shortcuts visible during review.

#### What this does not defend against

- A pre-compromised upstream where the malicious code is published as the canonical release across all sources (the Nx/Cline scenario, where the original author's account was compromised and the malicious code is *what was published*). No checksum scheme defends against this; only human reading of the source code does. `cargo vet` (§5.2) and the explicit auditor sign-off in `DEPENDENCIES.md` are the partial mitigations.
- An auditor who reads the source superficially and misses a backdoor. The checksum proves "what we audited is what we use"; it does not prove "what we audited is safe."

### 5.6 Audit cadence

- `tools/verify-checksums` runs in CI on every PR. Failing checksum verification blocks merge unconditionally.
- `cargo audit` runs in CI on every PR and on a daily cron against `main`. The daily cron exists because new advisories are filed against versions that were clean when we pinned them.
- `cargo vet` runs in CI on every PR; failing vet blocks merge.
- Quarterly, a maintainer reviews the dep graph and proposes removals. Removing a dep is always preferable to updating one.
- Quarterly, a maintainer re-verifies a random sample of `CHECKSUMS.toml` entries from scratch (re-downloads, re-cross-references) to catch silent drift in our procedures.

### 5.7 Upstream monitoring (non-CVE)

Bot-opened PRs (§5.4) surface new releases of pinned crates. `cargo audit` and the RustSec advisory feed surface security advisories. Together these cover known-bad. There remains a class the project must monitor explicitly: legitimate upstream bug fixes and maintenance changes that do not trigger a CVE or advisory but might still be material to Kennel's stability or correctness — a fix to a panic on an edge case we exercise, a parser hardening, a performance regression resolution, a deprecation we should adopt before it becomes a hard break.

The mechanism is `RELEASE-WATCH.toml` at the workspace root, listing each *direct* dependency with:

- Upstream repository URL.
- Release feed (GitHub Releases Atom URL, or equivalent).
- Last-reviewed version.
- Maintainer who reviewed it.
- Brief note if a release was deliberately skipped (so the next reviewer is not confused by the gap).

A weekly CI job parses `RELEASE-WATCH.toml`, polls each upstream feed, and opens a single tracking issue summarising any deps where upstream has a release we have not reviewed. The issue lists release titles, tags, and dates; the maintainer on rotation reads the release notes and decides whether to act. Acting means following §5.5 to update the checksum manifest. Not acting means updating `last-reviewed` in `RELEASE-WATCH.toml` to mark the release as seen and consciously skipped, with a one-line note.

The principle: *seeing* an upstream release is automated; *deciding* about it is not. Weekly cadence keeps the burden small; the issue thread carries the rationale for skipped releases.

Two additional discipline rules:

- **RustSec advisory subscription.** Maintainers watch `rustsec/advisory-db` on GitHub. New advisories surface in maintainer inboxes immediately; the daily `cargo audit` cron is a backstop, not the primary channel.
- **Maintenance signal review.** Monthly, the maintainer on rotation walks the dep graph and notes upstreams where activity has stalled (no commits in six months, unresponsive issues, ownership change in the published crate's `authors` field). Maintenance changes are themselves a supply-chain signal — the `xz-utils` precedent is that a new maintainer arrives, ships friendly contributions, then ships a backdoor. A change of upstream maintainer is recorded in `RELEASE-WATCH.toml` and triggers a fresh `cargo vet` audit at the next release.

---

## 6. Documentation

Code is read more often than it is written. In a security-critical project, it is read by people who do not have the option of asking the author what something meant.

Enforcement split for this section: doc-comment *presence* on `pub` items is `[tool]` (`missing_docs`, §12.2); the *structure* of `# Errors` and `# Panics` sections is `[tool]` (`clippy::missing_errors_doc` / `clippy::missing_panics_doc`, kept from pedantic specifically for this — §12.2); the *content quality* of every section, and the presence/accuracy of `# Security` and `# Safety`, is `[review]`.

### 6.1 Module-level documentation

Every `lib.rs`, `main.rs`, and `mod.rs` carries a module-level doc comment with:

- **Purpose:** one paragraph on what this module is for.
- **Invariants:** what this module guarantees to its callers, in plain language.
- **Threat bearing:** which threat IDs from `THREATS.md` this module participates in defending against, and how.
- **Non-goals:** what this module is *not* for, to head off scope creep.

Example skeleton:

```rust
//! Resolves and validates Kennel policy documents.
//!
//! # Purpose
//!
//! Given a leaf policy and a chain of templates, produce a fully-resolved
//! policy ready for the spawn wrapper to consume. Resolution is purely
//! functional: same inputs, same output, no I/O after the initial reads.
//!
//! # Invariants
//!
//! - A resolved policy never weakens a framework invariant (§12 of the
//!   design document). Attempts to do so are rejected at resolution time
//!   with [`PolicyError::InvariantViolated`].
//! - Template signatures are verified before any field is read. A policy
//!   whose template chain contains an unverified signature is rejected
//!   regardless of whether the unverified portion is referenced.
//! - Cryptographic minimums are enforced at validation; negotiation below
//!   the current floor is a categorical error.
//!
//! # Threat bearing
//!
//! Defends against T2.5 (template tampering) by signature verification,
//! T2.6 (invariant weakening by user delta) by the validator, and T2.7
//! (template-version drift) by the version-pinning checks.
//!
//! # Non-goals
//!
//! This module does not load policies from disk (see `kennel-policy-io`),
//! does not enforce policies at runtime (see `kennel-spawn`), and does not
//! own the threat catalogue (see `THREATS.md`).
```

### 6.2 Function-level documentation

Every `pub` function carries a doc comment. Every non-`pub` function whose behaviour is not obvious from the name carries one.

The standard form is:

```rust
/// One-line summary in imperative mood ("Resolves the template chain..." not
/// "This function resolves...").
///
/// Longer description if the one-liner is not enough. Cover what the
/// function does, not how — implementation is in the body, intent is
/// in the doc.
///
/// # Arguments
///
/// Only if the names are not self-documenting. Don't restate the obvious.
///
/// # Returns
///
/// What the success case carries. What the error variants mean.
///
/// # Errors
///
/// Each `Err` variant this function can produce, and what triggers it.
/// "Returns `Err(PolicyError::CycleDetected)` if the template chain
/// contains a cycle, before any signature is verified."
/// (Presence of this section on a fallible fn is enforced by
/// clippy::missing_errors_doc — see §12.2.)
///
/// # Panics
///
/// Every condition under which this function panics. If it never panics,
/// say so. If it panics on invariant violation, name the invariant.
/// (Presence of this section on a panicking fn is enforced by
/// clippy::missing_panics_doc — see §12.2.)
///
/// # Security
///
/// Anything a reviewer should think about. Examples: "Caller must not
/// pass attacker-controlled paths without canonicalising first." "This
/// function does not constant-time-compare; do not use for secret material."
/// (This section is [review]; no lint checks it.)
///
/// # Example
///
/// A doc-test if the function is non-trivial to call. Doc-tests run in CI.
```

`# Arguments` and `# Example` are optional; the others are required for any function whose failure modes are not trivially obvious. The `# Errors`/`# Panics` *sections* are `[tool]`-enforced; their *accuracy* (do they actually list every variant / every panic) is `[review]`.

### 6.3 Non-trivial code patterns

A non-trivial pattern is one where the *why* would not be obvious from re-reading the code in six months. Examples that require an inline comment:

- Order-dependent operations where the order is not arbitrary. ("We set `PR_SET_NO_NEW_PRIVS` before installing the seccomp filter because the filter relies on no-new-privs being already set.")
- Workarounds for a specific kernel version, library bug, or distro behaviour. Cite the bug.
- A comparison or check whose absence would be a subtle vulnerability. ("Constant-time compare: timing leak otherwise.")
- A loop bound or recursion limit. ("Bounded at 64 to prevent DoS from adversarial template chains; see T2.7.")

The standard is: if a reviewer would have to ask "why?", write it down. This rule is `[review]`.

### 6.4 What not to document

We do not write comments that restate the code. We do not write `// increment i` next to `i += 1`. We do not write "Returns a Result" in a doc comment when the signature already says so. Comments that rot are worse than no comments.

---

## 7. Tests come first

Unit tests are written before the function they test. This is a hard rule.

### 7.1 The cadence

Each behaviour landed in this repository goes through three phases. The phases correspond to three commits on the feature branch. They are written in order, not retrofitted. **Every commit must compile and `cargo test` must run**, so that `git bisect` works across the history and unrelated tests are not blocked by an in-flight change.

**Phase 1 — Tests and bare skeleton.** Write the full test suite for the new behaviour: success cases, every documented error variant, every documented panic condition, boundary cases, adversarial input. Alongside the tests, introduce the *bare minimum* declarations required for the workspace to compile: function signatures with `todo!()` bodies, empty error enum variants, type declarations. These are not the structure (that comes in Phase 2); they are the smallest possible stub set that makes the test file compilable.

At the end of this phase: the workspace compiles, `cargo test` runs, every new test fails — most via `todo!()` panics at runtime, none via compile errors. Existing tests in unrelated crates continue to pass. `git bisect` works.

Commit message: `test: <behaviour>`. The body explains what behaviour is being specified.

**Phase 2 — Structure.** Flesh out the stubs into a reviewable shape: input validation, error variants populated with their data, plumbing through public APIs, doc comments per §6, `From` impls for error conversion, builder code if needed. Algorithm bodies remain stubs (`todo!()`, or returning a sentinel error). At the end of this phase, the tests that exercise the structure — signature acceptance, input validation, error variants returned for invalid input, type-level invariants — pass. The tests that exercise the algorithm itself still fail (now via the sentinel error path rather than `todo!()`, where feasible).

The point of this phase is that *structure is a separable artefact that deserves its own review*. A reviewer can satisfy themselves that the function has the right shape, accepts the right inputs, refuses the wrong ones, returns the right error types, and is documented to the standard of §6 — before reading any algorithm. Splitting structure from algorithm matches the project's broader principle: separate things that can be reviewed independently.

Commit message: `scaffold: <behaviour>`. The body is brief; the diff is the substance.

**Phase 3 — Implementation.** Fill in the stub bodies. At the end of this phase, every test passes; no `todo!()` or sentinel remains.

Commit message: `feat: <behaviour>` or `fix: <behaviour>`.

#### Notes on the cadence

- The three commits live on the feature branch in order. Each one compiles; each one runs `cargo test`; each one is a valid `git bisect` candidate. Reviewers may ask to see the un-squashed history.
- PRs preserve the three commits on merge by default. Squashing is permitted when the change is small enough that the separation no longer aids review; the PR author decides, the reviewer can object. **Note the interaction with §13.4:** the folding rules below never collapse a PR below *two* commits, so a compliant PR — even a fully folded one — always carries a `test:` commit plus at least one other. A single squashed `feat:` commit is never compliant. This is what the §13.4 cadence check keys on.
- `todo!()`, `unimplemented!()` and similar stub macros are permitted in intermediate commits on feature branches. They are not permitted on `main`; CI's clippy lints catch this on every PR (§8.4). A PR that lands only Phase 1 (no Phase 2 or 3) must replace `todo!()` with either a tracked `Err(...)` variant or `#[ignore = "tracking issue #NN"]` on the happy-path tests, so that `main` never carries a `todo!()`.
- Folding phases 2 and 3 into one commit is acceptable when the implementation is genuinely small (a handful of lines, no algorithmic substance). Folding phases 1 and 2 is acceptable when the structure is small enough that pulling them apart adds no review value. **Skipping Phase 1 (the `test:` commit) is never acceptable, and no fold ever removes it.**
- The three-phase pattern is *generative*, not just procedural: writing the structure with stubs and seeing the structure-level tests pass forces clean boundaries between validation and computation. If you find Phase 2 hard to test because validation and computation are tangled, that is a design signal — separate them.

### 7.2 What tests cover

Every public function has tests covering, at minimum:

- The success case.
- Each documented `Err` variant.
- Each documented panic condition (using `should_panic` or `catch_unwind` where appropriate).
- Boundary conditions: empty input, maximum-sized input, off-by-one cases.
- Adversarial input where the function accepts untrusted data.

### 7.3 Test types

- **Unit tests.** Live in `#[cfg(test)] mod tests` blocks beside the code. Test one function or one tight cluster of functions. Fast: every unit test in the workspace should run in well under a second total.
- **Integration tests.** Live in `tests/` directories. Test the public API of a crate end-to-end. May take seconds. Required for any crate with a non-trivial public API.
- **Property tests.** Use `proptest` (one of our sanctioned deps) for any function whose input space is large enough that examples cannot cover it. The policy resolver and the parser are the obvious cases.
- **Fuzz tests.** `cargo-fuzz` corpora live in `fuzz/`. The TOML parser, the policy validator, and any code consuming untrusted bytes carry fuzz targets. CI runs each fuzz target for one minute on every PR; long-running fuzz runs happen out-of-band.
- **Doc tests.** Doc examples are tests. They run in CI. If a doc test does not actually exercise the behaviour, it is decorative and should be removed.

### 7.4 Test discipline

- Tests do not depend on each other or on execution order. `cargo test` parallelises; tests that fail under parallelism are broken tests.
- Tests do not read or write outside their own `tempdir` (or `tempfile`'s temporary directories). A test that touches the developer's `$HOME` is a bug.
- Tests do not reach the network. A test that does is a bug; if integration with an external service is needed, that goes in an explicitly-named, explicitly-gated integration suite that does not run by default.
- Test names describe the behaviour: `resolves_chain_with_two_templates`, not `test1`.
- Each test asserts one thing (or one tight cluster). A test that asserts five unrelated invariants is five tests pretending to be one.

### 7.5 Coverage

We do not chase a coverage number; we cover the behaviour. Coverage tools (`cargo-llvm-cov`) run in CI to surface untested code paths, not to gate PRs on a percentage.

---

## 8. Errors and panics

### 8.1 Error types

Every crate that returns errors defines its own error type, typically with `thiserror`. Error variants are specific enough that the caller can pattern-match on them; generic `Other(String)` variants are discouraged.

Errors carry enough context for a human reading the audit log to act. "File not found" is bad; "policy template '<name>' not found in templates directory '<path>'" is good. We do not sacrifice clarity for brevity in error messages.

### 8.2 No `unwrap`

`.unwrap()` is forbidden outside `#[cfg(test)]` code. The lint `clippy::unwrap_used` is `deny` in every crate. `[tool]`.

### 8.3 `expect` with documented invariant

`.expect("...")` is permitted *only* when the message documents the invariant that makes the call infallible:

```rust
let parsed = u32::from_str(value)
    .expect("INVARIANT: schema validator rejects non-numeric values before reaching here");
```

The privhelper crate is stricter: `.expect()` is also forbidden. The privhelper handles every case explicitly. (Presence of `.expect()` is `[tool]` via `clippy::expect_used` in the privhelper; the *quality* of the invariant message elsewhere is `[review]`.)

### 8.4 No `panic!`, `todo!`, `unimplemented!` in shipped code

Lints `clippy::panic`, `clippy::todo`, `clippy::unimplemented` are `deny`. `[tool]`. These are fine in tests; they do not ship. They are also fine in the structure-phase commit on a feature branch (§7.1); CI runs against the PR head, so the lints catch any state where structure has been merged without implementation.

### 8.5 Privhelper-specific

The privhelper is compiled with `panic = "abort"` in `[profile.release]`. A panic in the privhelper is a programming error and the process must terminate immediately rather than unwind through resource cleanup that may leave the system in an inconsistent state.

**`panic = "abort"` is incompatible with `catch_unwind` and with `#[should_panic]` test attributes** — both rely on the unwind machinery that `abort` removes. The privhelper's `[profile.test]` therefore overrides to `panic = "unwind"` so that documented-panic tests (§7.2) and any `catch_unwind`-based test scaffolding work. The release binary still aborts; only test binaries unwind.

This split is recorded in the privhelper's `Cargo.toml` and is enforced by CI: a release build of the privhelper that links unwind-table support is a regression.

### 8.6 Errors at trust boundaries

When data crosses a trust boundary (untrusted file content → parser, network bytes → handler, IPC message → privhelper), errors are *expected* outcomes, not exceptional. They get specific variants, structured logging, and audit-log entries where appropriate.

---

## 9. Logging and audit boundaries

There are two distinct log streams. Confusing them is a security bug.

### 9.1 Developer logging

`tracing` (sanctioned dep, async-runtime crates only) or simple `eprintln!` (everywhere else) for diagnostics that help developers and operators understand what the binary is doing. This stream:

- Goes to stderr or to a developer-chosen log file.
- Is for humans reading the output now.
- Has log levels (error, warn, info, debug, trace).
- Is *not* a security artefact.

### 9.2 Audit logging

Audit events are structured records of security-relevant decisions: a policy load, a denied connect(), a template signature failure, a kennel start/stop, a privhelper request. This stream:

- Goes to the audit log path declared by the policy (typically JSONL under `~/.local/state/kennel/<kennel>/`).
- Has a stable schema documented in `docs/architecture/02-3-audit-schema.md`.
- Is append-only from the writer's perspective; rotation is the supervisor's responsibility.
- Is the SIEM-integration artefact.

### 9.3 What never goes in either log

- Secrets, credentials, tokens, key material, passwords. Period.
- The contents of files the kennel exists to protect.
- The contents of network payloads (lengths and destinations are fine; payload bytes are not).
- Environment variable *values* (variable *names* may be fine in debug logging; values, no).

A log line that prints a value the writer has not personally verified to be non-sensitive is a bug. `[review]`.

### 9.4 Redaction

Where logging a structure that *might* contain sensitive fields, the structure implements a `Display` that redacts and a separate `fmt_debug_for_audit` (or similar) for the audit log, which is reviewed for what it actually emits. `Debug` derivation is not used on types that may carry secrets.

---

## 10. Input handling

**Always sanitise input. Always.** Every byte that enters the program from outside has been written by someone, and that someone is untrusted until parsing has produced a typed value. Configuration files are not exempt — they are emphatically *included*.

A configuration file looks like an internal artefact, so the reader tends to apply less scrutiny than to network bytes. This is exactly inverted from the threat picture. In Project Kennel, configuration files arrive from templates fetched over the network and unsigned at the time of parse, from user deltas hand-written or otherwise, from policy files cached on disk that may have been tampered with, from AI agents that the project exists to confine, and from sync tools (Dropbox, `git pull`, removable media) that may interleave content. Every parser of configuration treats its input as adversarial.

### 10.1 Trust boundaries

A trust boundary is any point where data crosses from outside our control to inside our process, or vice versa. The boundaries in Project Kennel:

- Reading a configuration file (TOML policy, template, user delta).
- Reading file contents the project did not write (project source files, agent-produced output).
- Reading environment variables.
- Receiving an IPC message (privhelper requests, audit-log writers, supervisor signals).
- Reading network bytes (the SOCKS5 proxy, DNS responses, signature material from a registry).
- Reading kernel-returned data (syscall error messages, structures from `/proc` and `/sys`, kernel audit records).
- Writing into a context that interprets formatting (terminal, JSON, markdown, HTML, audit log, generated reports).

Every boundary has an explicit handler. Types from one side do not silently flow to the other. The act of crossing the boundary is visible in the code: a parser call, a sanitiser call, a typed conversion. Implicit `From`/`Into` impls that cross a trust boundary are forbidden.

### 10.2 Parsing is the validation

A typed value is evidence that validation has occurred. We never produce a typed value from untrusted bytes without performing the checks the type's invariants require (see §11.1 for the newtype pattern).

Practically:

- **Unknown fields are rejected.** `#[serde(deny_unknown_fields)]` is the default for every config deserialisation type. Unknown means malicious until proven otherwise. Removing the attribute requires a written reason in the type's doc comment.
- **Malformed values are rejected before construction.** A `KennelId` is constructed only by a function that validates the format. A raw `String` cannot be cast to one.
- **Reads are bounded.** `read_to_string` on untrusted sources is forbidden. The pattern is `reader.take(N).read_to_string(...)`. The cap `N` is documented at the call site and reviewed for "would 100× this DoS us".
- **Recursion is bounded.** Parsing structures with potential nesting (template chains, included files, glob expansion, policy inheritance) carries an explicit depth limit checked *before* descent. The limit is documented in the threat-bearing block of the module that owns the parser.
- **Charsets and encodings are checked, not assumed.** UTF-8 is verified. Paths use `OsStr`/`PathBuf`, not `String`, where they may legitimately not be UTF-8.
- **Duplicate keys are rejected.** Some TOML parsers tolerate duplicate keys; ours does not. Duplicates are a sign of either confusion or tampering and either deserves an error.
- **Path traversal is rejected at parse.** Fields the schema declares as relative paths reject `..` components and absolute paths. Fields the schema declares as absolute reject relative paths. Mismatch is a categorical error, not a normalised acceptance.
- **Tilde and variable expansion are post-verification.** `~/foo` expansion based on `$HOME` is a privilege transition; it does not happen on a configuration file's contents until signature verification of that file completes.
- **Numeric ranges are enforced.** Integer fields with a declared range fail to parse outside it. `u32` is not a substitute for "a port number from 1024 to 65535".

### 10.3 Output sanitisation

Where data crosses into a context that interprets formatting, the data is sanitised on the way out. The sanitiser is chosen by the destination format, not by the producer.

- **Terminals (stdout, stderr, terminal-attached logs).** ANSI escape sequences, control characters, and non-printable bytes are stripped or escaped from any string of untrusted origin before writing, via `display_untrusted` (§10.4). Terminal injection — write attacker-controlled bytes, get cursor movement, screen clearing, paste-buffer abuse in some emulators — is a real attack class. "It is only an error message" is not a defence; error messages are exactly where attacker-controlled strings end up.
- **JSON (audit log, IPC).** Use a serialiser. JSON is never constructed by string concatenation. The serialiser handles escaping; ad-hoc code does not.
- **Markdown.** Markdown is a code path; attacker-controlled markdown is attacker-controlled output. We do **not** attempt to neutralise untrusted substrings by ad-hoc metacharacter escaping or by backtick-fencing — fencing does not contain a value that itself contains backticks, and CommonMark has no single stable escaping rule across reference-link definitions, autolinks, and raw-HTML passthrough. Two sound options, in order of preference:
  1. **Do not emit untrusted content as markdown markup at all.** Render it as inert text through `display_untrusted` (§10.4) — the same primitive used for terminals. This is the default. A policy diff quoting a `reason` field, an error report citing a config value, etc., all take this path.
  2. **If structured markdown rendering of untrusted content is genuinely required**, route it through a real CommonMark renderer in *safe mode* with raw HTML disabled and dangerous URL schemes filtered. Ad-hoc escaping is not an acceptable substitute for a renderer.
  - We never produce markdown for downstream HTML rendering without a downstream HTML sanitiser in the chain. We never interpolate untrusted strings into markdown headers, link targets, or image syntax under any option.
- **HTML.** HTML is an injection hazard. We do not produce HTML by string templating with interpolation. If we generate HTML at all, it is via a library that escapes by default, and untrusted strings pass through that library's escape function explicitly. Type-level distinction between "raw HTML" (a small whitelist of internally-produced content) and "untrusted text" (everything else) is the goal; bypassing the escaper "because we know the value is safe" defeats the type and is rejected at review.
- **Shell.** Never. External commands are invoked via `Command::new(...).arg(...)`-style APIs that take argv arrays. We do not construct a shell command string and pass it to `sh -c`, even for prototyping. The privhelper has no shell path at all.
- **File paths.** Untrusted strings do not flow into `Path::join` directly. Path construction from untrusted input goes through the canonicalising helper of §11.3, which verifies the result is within an explicit allowed prefix.
- **Regex.** Untrusted input is never used as a regex pattern (ReDoS class).
- **Format strings.** Untrusted input is never used as a `format!` template. Input is data, not code.

### 10.4 Error messages that quote input

Error messages frequently quote the input that caused the error: `invalid policy at line 42: '<bad-value>'`. The quoted portion is sanitised before it appears in the output. Otherwise the error path is a covert channel: an attacker controls a configuration field containing terminal escape sequences, our error message writes those escapes to the user's terminal, and the terminal does whatever the escapes tell it to.

`display_untrusted` (in `kennel-text`) is the single sound primitive for rendering an untrusted string into a *human-facing plain-text or markdown* context (terminal, error message, log line a human reads, or markdown-as-inert-text per §10.3 option 1). It:

- Replaces control characters with explicit escapes (`\x1b`, `\b`, `\r`, …) rather than emitting them raw.
- Wraps the value in visible delimiters so its boundaries are unambiguous in the rendered output.
- Truncates absurdly long values with an explicit marker, so the error message itself does not become a DoS vector.
- Marks the value as untrusted in the rendered output (e.g., a prefix indicating provenance).

`display_untrusted` is the default for *both* terminal and markdown contexts. It does not produce markdown markup — it produces inert, escaped text safe to drop into either. Where genuine markdown *structure* around untrusted content is required, see §10.3 option 2 (a real CommonMark renderer); `display_untrusted` handles the untrusted *leaf* values inside that structure.

Audit log entries achieve the same property structurally by going through JSON encoding (§10.3); they do not need a separate helper.

### 10.5 Banned patterns

The following patterns are forbidden by convention. Some are caught by clippy (`[tool]`); the rest are caught by review (`[review]`) because no lint expresses them. They are listed here so that the rule is concrete and citable in code review.

- String concatenation to build paths, URLs, SQL, shell, JSON, markdown, or HTML. Use the format-appropriate API. `[review]`.
- `format!` (or `write!`, `writeln!`) with an untrusted format string. (Note: `rustc` already requires the format spec to be a string literal, so the direct form is `[tool]` at compile time. The indirect path via `fmt::Arguments`-style constructions is `[review]`.)
- `Path::new(untrusted).join(...)` without going through the canonicalising helper. `[review]`.
- `Command::new("sh").arg("-c").arg(untrusted)` or any equivalent indirect-execution path. `[review]`.
- Reading untrusted sources with `read_to_string`, `read_to_end`, or any unbounded read. Use `take(N)` first. `[review]`.
- Logging or displaying untrusted strings without `display_untrusted` (or the JSON sanitiser for audit-log entries). `[review]`.
- `Regex::new(untrusted)`. `[review]`.
- `serde` derives without `deny_unknown_fields` on any type that deserialises external input. `[review]`.
- `serde_json::Value` or `toml::Value` as a long-lived type for data we introspect. Parse to a typed struct. `[review]` (see the carve-out below).
- Implicit `From`/`Into` impls that produce a typed value from a string or byte slice of untrusted origin. `[review]`.

#### Carve-out: opaque payload envelopes

There is one legitimate use of dynamically-typed JSON: forwarding an opaque payload that we *do not introspect*. The audit log forwarding to a SIEM is the canonical case — we receive a structured event from a sibling subsystem, we wrap it in our own envelope (timestamp, kennel ID, source), and we emit it without reading the wrapped portion. Parsing it into a typed struct would require us to track every possible schema downstream, which is exactly what an opaque envelope avoids.

When this case arises:

- Use `serde_json::value::RawValue` (or `&serde_json::value::RawValue`), not `Value`. `RawValue` preserves the original bytes byte-for-byte; `Value` is a parsed tree we would then have to validate. Bytes-through is the property we want.
- The wrapping struct is typed; only the payload field is `RawValue`. The structural fields (timestamp, source ID, schema URI) are typed, validated, and authoritative.
- The wrapped bytes are still untrusted. They are not displayed to a terminal without §10.4 sanitisation; they are not interpolated into markdown or HTML; they are not logged anywhere that interprets formatting.
- The use site carries a comment naming the contract: what the payload is, who produces it, why we do not parse it.

This carve-out is rare. The default is still: parse to a typed struct.

### 10.6 Fuzzing

Every parser of untrusted input carries a fuzz target under `fuzz/`. The TOML parser, the policy resolver, the signature-bearing file reader, the SOCKS5 message decoder, and the IPC frame parser are the obvious cases. The fuzz cadence and corpora discipline are governed by §7.3.

A new untrusted-input parser landing without a fuzz target is a missing piece, not a stylistic preference. Reviewers refuse the PR.

### 10.7 Markdown and HTML in this repository

We carry markdown documents in the repo (this one, THREATS.md, EXEC-SUMMARY.md, README files). These are human-authored and human-reviewed; they are inputs to *the reader of the repo*, not to the binary. They are out of scope for runtime sanitisation.

What is in scope: any future feature that *produces* markdown or HTML for display — a web UI, a generated policy-diff report, a rendered audit log view, a docs site that incorporates user-provided strings, a CLI subcommand that prints templates with embedded user content. Such features land with §10.3 enforcement from the first commit. We do not retrofit sanitisation later; the cost of doing so after a feature has shipped is several times higher and the gap between ship and retrofit is exactly when the bug bites.

---

## 11. API design patterns

### 11.1 Newtypes for security-relevant values

`String` is for free-form text. Anything with security meaning gets a newtype:

```rust
pub struct KennelId(String);          // not String
pub struct GrantedPath(PathBuf);      // not PathBuf
pub struct ProxyListenAddr(SocketAddr); // not SocketAddr
pub struct TemplateVersion(u32);      // not u32
```

The constructors do validation; the type's existence is evidence the validation happened. This is *parse, don't validate* applied as a default rather than an option.

### 11.2 Make invalid states unrepresentable

If `no_new_privs = false` is forbidden by framework invariant (§12 of the design), do not represent it as a `bool` field that has to be checked at runtime. Use a unit type or a `const`:

```rust
pub struct NoNewPrivs;  // can only construct one value; field is implicitly true
```

Where the schema requires a bool because users may set true/false at parse time, the *resolved policy* type after invariant validation has the unconditional shape.

### 11.3 Paths

We do not compare paths as strings. Path validation goes through `kennel-syscall`'s canonicalisation helper, which is the only place that performs `realpath`-equivalent resolution. Comparisons happen on canonicalised values.

Path inputs from untrusted sources are *never* used in `Path::join` directly. Joining is preceded by validation that the resulting path stays within an explicit allowed prefix.

### 11.4 No public mutable global state

No `static mut`. No `lazy_static!` of a mutable. No singleton patterns. State is passed explicitly through arguments or held in struct fields. The audit log is the closest thing to a global, and it is passed as a handle, not reached for.

### 11.5 Builders for non-trivial construction

If a struct has more than four fields, it gets a builder. The builder enforces required-vs-optional at the type level (`PolicyBuilder::without_path()` rather than `policy.path = None`).

### 11.6 Avoid `Default` for security-bearing types

`Default::default()` is fine for `String::new()` and friends. It is not fine for a policy, a kennel configuration, or anything that ships invariants. We do not provide a `Default` impl for types whose default would be a security regression to use.

---

## 12. Style, lints, formatting

### 12.1 Formatting

`cargo fmt` with default configuration. We do not customise rustfmt; reviewer attention is finite and "is this consistent with the rest of the codebase" should be answerable by running the formatter. `[tool]`.

### 12.2 Lints

The following lints are `deny` (compilation fails) in **every** crate, on **every** toolchain (development and MSRV). `[tool]`:

- `clippy::all`
- `clippy::unwrap_used`
- `clippy::expect_used` (in `kennel-privhelper` only)
- `clippy::panic`, `clippy::todo`, `clippy::unimplemented`
- `clippy::dbg_macro`
- `clippy::print_stdout`, `clippy::print_stderr` (in libraries; binaries handle stdout/stderr explicitly)
- `clippy::indexing_slicing` (force explicit `.get()` with handled `None`)
- `clippy::arithmetic_side_effects` (formerly `clippy::integer_arithmetic`, now deprecated under that name; force explicit `checked_*` / `wrapping_*` / `saturating_*`)
- `rust_2018_idioms`
- `missing_docs` (on all `pub` items in libraries)

**`clippy::pedantic` is `deny` only in the pinned-toolchain CI job** — the job that builds with the exact `rust-toolchain.toml` version. Everywhere else (the MSRV CI job, contributor local builds, the git hooks) it is `warn`.

Rationale: pedantic gains and changes lints across clippy releases. Because the development toolchain moves with `rustup` (§2.1), denying pedantic on that moving toolchain would let a `rustup update` with **no code change** turn the tree red — directly against the reproducibility goal of §2.1/§2.3. Pinning the deny to one known clippy version makes pedantic deterministic: new pedantic lints arrive only when we deliberately bump `rust-toolchain.toml`, and resolving them is part of that bump's PR (and CHANGELOG line). Contributors are never blocked by a lint their pinned toolchain does not yet have.

We keep pedantic specifically for two lints that nothing else enforces:

- `clippy::missing_errors_doc` — requires a `# Errors` section on every fallible `pub` function (§6.2).
- `clippy::missing_panics_doc` — requires a `# Panics` section on every panicking `pub` function (§6.2).

Plain `missing_docs` only checks that a doc comment *exists*; it does not check that a fallible function documents its errors or that a panicking function documents its panics. These two lints are the `[tool]` half of §6.2; everything else in §6.2 (content accuracy, `# Security`, `# Safety`) is `[review]`. Because both lints live under pedantic, they too are `deny` only in the pinned-toolchain job — which is sufficient: the pinned job runs on every PR.

The following are `warn` on all toolchains:

- `clippy::nursery`

`allow`s require an inline `// allow: <reason>` comment. Per-crate `allow`s for genuinely-wrong pedantic lints live in `lib.rs` with the same comment form.

### 12.3 Naming

- Types: `UpperCamelCase`.
- Functions, variables: `snake_case`.
- Constants, statics: `SCREAMING_SNAKE_CASE`.
- Modules: short, lowercase, no underscores where avoidable.
- Acronyms in type names follow Rust's convention (`HttpClient`, not `HTTPClient`).

Names describe purpose, not type. `path` not `path_str`. `kennel` not `k`. `policy` not `cfg`.

### 12.4 No emoji, no decorative ASCII art

In code, comments, doc strings, commit messages, error messages, or any user-facing output. Plain text only.

---

## 13. Commits, reviews, releases

### 13.1 Commits

- Conventional Commits format: `<type>(<scope>): <summary>`. Types: `feat`, `fix`, `test`, `scaffold`, `docs`, `refactor`, `chore`, `build`, `ci`. Scope is the crate name or a top-level area. `scaffold` is our addition, for the structure phase of §7.1.
- One logical change per commit. The three-phase cadence of §7.1 (`test:` → `scaffold:` → `feat:`) means up to three commits per behaviour change, and — after any permitted folding — never fewer than two.
- Commit messages explain *why*. The diff explains *what*.
- All commits are signed (GPG or SSH signature). CI verifies signatures.
- No `WIP` commits on `main`. PR branches may carry them; squash or rebase before merge.

### 13.2 Reviews

- Every PR has at least one maintainer review. PRs touching `unsafe` need two (§4).
- Reviewers verify: tests exist and were written first; documentation is present per §6; no new dependencies without §5 paperwork; no panics or `unwrap`s outside tests; clippy clean; CI green.
- Self-merge is permitted for maintainers on docs-only PRs and on changes confined to a single test file. Everything else needs another set of eyes.

### 13.3 Releases

- Releases are tagged. Tags are signed. Signatures are by maintainer keys listed in `MAINTAINERS.md`.
- Each release has a CHANGELOG entry listing every user-visible change, every dependency update, every MSRV change, every pinned-toolchain bump (§12.2), and every threat-catalogue addition that landed.
- Release artefacts are built reproducibly. The release process publishes the build command, the toolchain version, and the expected output hashes; any third party can rebuild and verify.

### 13.4 Contributions from outside the maintainer set

Project Kennel is a security-critical codebase with a finite maintainer attention budget. The standards in this document deliberately raise the cost of producing a compliant contribution. That cost is the filter: a contribution that satisfies the standards is worth reading; a contribution that does not is closed without review. Maintainers do not act as a remote compiler, a remote linter, or a remedial teacher for tooling that the contributor chose to use.

This subsection states the rules for incoming PRs from anyone outside the current maintainer set. They are aggressive on purpose. The alternative is that signal-to-noise collapses as soon as the project has visibility, and maintainers stop reading PRs.

#### Close-on-arrival categories

A PR from a non-maintainer that meets any of the following conditions is closed without review. No iteration, no negotiation.

**Unsolicited refactors, stylistic changes, or "optimisations."** A PR that rewrites working code without an underlying behaviour change is closed unless it is directly attached to an issue that a maintainer has triaged and approved. "Modernising" a loop, "cleaning up" a function, swapping a `for` for an `iter()`, switching a `match` to an `if let`, or any AI-suggested cleanup of code that was not broken does not qualify as a contribution. The pattern is the most common form of LLM-generated open-source spam because it requires no understanding of the system, and we will not subsidise the production of it.

**PRs missing the §7.1 commit cadence.** The check is on the PR's **branch history**, not on the merge shape: a PR whose commits do not include a `test:` commit preceding the structure/implementation is closed. Because the §7.1 folding rules never collapse a PR below two commits — folding `test:`+`scaffold:` still leaves a `feat:`; folding `scaffold:`+`feat:` still leaves a `test:`; and Phase 1 is never folded away — a compliant PR always carries **at least two commits, one of which is `test:`**. A single squashed `feat:` commit is therefore never compliant, regardless of how the contributor intends it to be merged. (A maintainer may still ask to see the un-squashed history per §7.1; a contributor who squashed locally can re-push the unsquashed branch.) Standard close message:

> This PR does not follow the §7.1 commit cadence required for review (`test:` → `scaffold:` → `feat:`, minimum two commits including a `test:` commit). Closing. Please resubmit with the required commit history.

No further explanation is owed. The §7.1 cadence is in the standards document; the contributor is expected to have read it.

**PRs whose description fails the template.** The PR template requires the contributor to map the change to specific items: a threat ID from `THREATS.md`, a design-document invariant, a citable rationale. Generic text — "improves security and efficiency", "follows best practices", "fixes a bug" without naming the bug — fails the template. Standard close message:

> This PR's description does not satisfy the PR template's specificity requirements. Closing. See `.github/PULL_REQUEST_TEMPLATE.md` for required content.

**PRs that fail an arrival-blocking CI check.** Auto-close applies to the checks a contributor can run locally via the §15 git hooks — and *only* those:

- `cargo fmt --check`
- the clippy gate (`-D warnings`)
- the offline `--frozen --locked` build
- both checksum verifiers (`tools/verify-checksums` and `tools/verify-checksums.sh`)

A first CI run failing any of these is closed; the hooks would have caught it locally. Standard close message:

> This PR fails an arrival-blocking §14 check that the §15 hooks run locally (`tools/install-hooks.sh` installs them). Closing. Please resolve locally and resubmit.

The CI-only checks that the hooks **cannot** run locally are **not** grounds for auto-close on first arrival:

- `cargo deny check`
- `cargo audit`
- `cargo vet --locked`
- `cargo doc --no-deps -D warnings`
- the fuzz smoke test
- the reproducible-build double-run
- the BPF verifier kernel-matrix

These require a multi-kernel host, two runners, network-isolated infrastructure, or wall-clock time that a contributor cannot reasonably reproduce before pushing. A first-arrival failure on one of these gets a maintainer (or bot) comment naming the failing check and a chance to fix — *not* a close. A **repeated** failure on the same check after the comment is closed like any other. (Dependency PRs are the common case here: a missing `cargo vet` entry or a `cargo deny` licence hit is invisible to the hooks; contributors are nonetheless expected to run `cargo deny`/`audit`/`vet` themselves per §5.2/§5.5, and a maintainer comment will say so.)

Exactly one further exception, as before: a CI failure caused by *our* infrastructure (CI-image bug, transient network in our own registry, a flaky test we own) is re-run by a maintainer. The exception covers our bugs, not the contributor's.

#### The PR template

Every PR carries a description following `.github/PULL_REQUEST_TEMPLATE.md`. The template requires, at minimum:

- **What changes.** One or two sentences naming the behaviour added, removed, or fixed, in terms a reader can verify against the diff. Not "improves X"; *names* the change.
- **Why, in project-local terms.** Which threat ID from `THREATS.md` this addresses, which design-document invariant it implements, which open issue it closes, which user-visible behaviour it changes. Generic justifications fail the template. "T2.7 (template chain DoS) is currently unbounded in the resolver; this caps it at the documented limit" is an answer. "Best practice" is not.
- **Phase boundaries.** Explicit identification of the `test:`, `scaffold:`, and `feat:` commits in the PR. If folded (per §7.1 notes), the reason. If only some phases are present, the reason and the tracked follow-up issue.
- **Dependency changes.** If the PR touches `Cargo.toml`, `Cargo.lock`, `src/vendor/`, or `CHECKSUMS.toml`: an explicit account of how §5.5 verification was performed. Which independent sources were consulted, what their results were, who is named as `audited-by` in the checksum entry. "I ran `cargo update`" fails the template; the §5.5 procedure is the substance.
- **Tests.** What was tested, including test names. New behaviour without new tests fails §7.
- **Threat-surface impact.** For any change that adds or removes a behaviour exposed to a confined workload: explicit statement of whether this expands, contracts, or leaves unchanged the workload-reachable surface, with reasoning.

The template's specificity is the test. AI agents fill plausible-sounding generic text easily; specific references to `T2.7`, to a named invariant, to the §5.5 procedure they actually performed, are hard to fabricate without engaging with the codebase. Maintainers can verify a threat-ID claim against the catalogue in seconds; an invented one is obvious.

#### What this is not

These rules deter low-effort contribution. They do not gatekeep on identity. A contributor — human, human-with-AI, or otherwise — who reads the standards, runs the hooks locally, follows the cadence, files an issue first when one is needed, and writes a PR description that engages with the project's actual concerns will see their work reviewed on its merits. We do not detect AI; we filter on whether the contribution meets the bar. If an AI-assisted PR clears all the close-on-arrival categories, satisfies the template, passes CI, and references the codebase concretely, it is reviewed like any other PR.

The point is: the cost of compliance is the test. The PR template tests that the standards have been read. The CI gate tests that the standards have been followed. If all of them pass, the maintainer reads the code.

#### Trusted contributors

A contributor who has had three PRs merged in compliance with the cadence and the template is added to `CONTRIBUTORS.md`. Their PRs are not auto-closed on first CI failure (we extend the courtesy of a comment instead). Their issues are not auto-closed on a missing tag (§13.5); they receive a comment requesting the tag. They may propose refactors without first filing an issue, provided the proposal still meets §7.1 and the template. Trust is a working assumption, not a property right; maintainers may delist by majority decision with reasoning recorded.

The list is small by intent. It exists to reduce friction for repeat contributors who have demonstrated they understand the project, not to create a tiered review experience.

### 13.5 Issues from outside the maintainer set

Issues are upstream of PRs. The same filtering principle applies: the cost of filing a serious issue is low enough that anyone who has read the project's threat catalogue can pay it, and high enough that an LLM hallucinating a generic bug into the queue will fail.

#### The title tag

Every issue title must start with exactly one of three bracketed tags, as the first non-whitespace content of the title:

- **`[T<id>]`** — an existing entry in `THREATS.md`, with the ID verbatim as it appears there. The issue concerns a catalogued threat.
- **`[T-NONE]`** — a positive assertion that you read the catalogue and this issue is **not** security-bearing: a build failure on an unusual platform, a documentation typo, a feature request, a packaging request.
- **`[T-NEW]`** — a positive assertion that you believe this issue **is** security-bearing but is **not yet** in the catalogue: a novel threat class, or a hardening observation `THREATS.md` does not cover.

`[T-NEW]` exists so the filter does not close the single highest-value external report — a genuine threat we have not catalogued — for the crime of not matching an ID that, by definition, cannot exist yet. A `[T-NEW]` issue is **routed to maintainer triage, not auto-closed.** A maintainer either catalogues the threat (assigning a real `T<id>` and updating `THREATS.md`) and retags, or explains why it is out of scope.

Do **not** reach for `[T-NONE]` when you are merely unsure. `[T-NONE]` is a claim that the issue is *not* a security concern; using it for an uncatalogued security concern routes that concern straight into the explicitly-ignored bucket. If you think something might be security-relevant and you cannot find a matching ID, that is exactly what `[T-NEW]` is for.

Examples that pass:

```
[T2.1] Panic in template-chain depth-limit check
[T1.1] fs.scrub does not catch .envrc.local pattern
[T1.9] static.crates.io reachable via DNS rebinding when proxy not started
[T-NEW] Resolver trusts template mtime for cache invalidation; not in catalogue, looks attackable
[T-NONE] Build fails on aarch64-musl
[T-NONE] Typo in EXEC-SUMMARY.md §3
```

Examples that fail:

```
Bug: panic in parser                       (no tag)
[BUG] Panic in parser                      (not a recognised tag)
[CRITICAL] Issue with template parsing     (not a recognised tag)
[T99] Issue with template parsing          (T99 does not exist in THREATS.md)
[Security] Hardening suggestion            (not a recognised tag — use [T-NEW])
```

The three recognised tags are `[T<id>]` (valid ID), `[T-NONE]`, and `[T-NEW]`; nothing else is accepted.

#### Specific exploitable vulnerabilities are never filed as issues

A working, exploitable vulnerability in Kennel itself is **not** filed as any kind of public issue — not `[T-NEW]`, not anything. It goes to the private channel described in `SECURITY.md` (summarised in CONTRIBUTING.md, *Reporting security vulnerabilities*). The distinction:

- **Private channel:** a *specific, exploitable* bug in our implementation. Disclosed privately; made public once a fix lands.
- **`[T-NEW]`:** a *suspected, non-exploit-specific* threat class or hardening gap. Public issue; triaged by a maintainer.

This boundary is load-bearing: the auto-close Action runs on public issues, and a live exploit posted as a public issue is a disclosure incident regardless of its tag. The private channel (`security@projectkennel.org`, see `SECURITY.md`) is the only correct destination for exploit specifics.

#### Auto-close on missing or invalid tag

A GitHub Action runs on every newly-opened issue. It parses the title against the threat-ID list generated from `THREATS.md` at build time, plus the two literals `T-NONE` and `T-NEW`. If the title does not start with a valid `[T<id>]`, `[T-NONE]`, or `[T-NEW]`, the action closes the issue with a standard comment:

> This issue's title does not begin with a recognised `[T<id>]`, `[T-NONE]`, or `[T-NEW]` tag. Closing. See §13.5 of CODING-STANDARDS.md and the threat catalogue in THREATS.md. Please refile with a corrected title; this is not a judgement on the underlying content, only a precondition for entering the queue.

A `[T-NEW]` issue is **not** closed; the action labels it `triage:new-threat` and leaves it open for a maintainer.

The action runs server-side without maintainer attention. Invalid issues do not appear in maintainer queues; the cognitive load of triaging hallucinated bug reports is eliminated structurally. The action's source lives in `.github/workflows/issue-tag-check.yml` and `tools/check-issue-tag` (a small Rust binary, reviewed under §4 rules, depending only on the existing checksum-manifest tooling chain). The threat-ID list it validates against is generated from `THREATS.md` at build time; updates to the catalogue propagate to the check on the next release.

#### Why this works as a filter

The threat IDs are project-local and stable. An LLM that has not consulted `THREATS.md` cannot produce a plausible mapping — the IDs are not derivable from the project name or the README, and there are not so many of them that random guesses are likely to hit. Producing a correct tag requires retrieval, which requires the submitter (human or otherwise) to have engaged with the catalogue.

Neither `[T-NONE]` nor `[T-NEW]` weakens this. Both are *positive assertions* about the issue's security character; a submitter who has not read the catalogue typically defaults to no tag at all (LLMs writing GitHub issues do not invent bracketed tags absent training data telling them to), and the action closes the issue. `[T-NEW]` opens a path for the rare high-value uncatalogued report without opening a path for spam: it still requires the submitter to assert, in a structured field, that they looked and did not find — and a maintainer reads every one.

#### What this is not

Auto-close on missing tag is not a judgement on the issue's underlying content. It is a precondition for entering the queue. A serious issue filed with the right tag gets the attention it deserves. A serious issue filed without a tag gets a polite invitation to refile; the project loses no information, and the contributor demonstrates engagement with the catalogue.

For contributors on the trusted list (§13.4), the action posts a comment requesting the tag rather than closing — the same courtesy extended to their PR submissions.

---

## 14. CI gate

The following must pass on every PR before merge is permitted. CI failures are not waivable; a failing check means the work is not done.

Checks the §15 hooks also run locally (arrival-blocking per §13.4):

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --offline --frozen --locked` (verifies `src/vendor/` completeness and no network access)
- `tools/verify-checksums` (Rust verifier; matches `CHECKSUMS.toml` against `src/vendor/` and `Cargo.lock`)
- `tools/verify-checksums.sh` (independent shell-based verifier; must agree with the Rust verifier)

CI-only checks the hooks cannot run locally (commented-not-closed on first arrival per §13.4):

- `cargo test --all-features` (workspace-wide) and `cargo test --no-default-features` (where applicable)
- `cargo clippy` in the pinned-toolchain job with `clippy::pedantic` denied (§12.2)
- `cargo deny check` (licences, advisories, banned crates, multiple-version policy)
- `cargo audit` (RustSec advisories)
- `cargo vet --locked` (audit chain)
- `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"`
- Fuzz smoke test: each fuzz target runs for one minute, no crashes.
- Reproducible build: the release profile builds twice on separate runners; hashes match.
- BPF verifier kernel-matrix: every BPF program loads on every supported kernel (§4.1).
- MSRV build: the workspace builds against the `rust-version` floor (§2.1).

(Note: `cargo test` is listed CI-only because the full workspace test run exceeds the hook time budget; the hooks run a scoped subset per §15. The arrival-blocking/commented split in §13.4 is what governs auto-close, not this list's ordering.)

The CI configuration itself is in this repository, reviewable, and changes to it go through the same review process as code.

---

## 15. Git hooks

Git hooks accelerate the developer loop by running a **fast subset** of CI checks locally before commits and pushes leave the machine. They are *convenience*, not a security gate; the gate is CI on the PR (§14). The hooks run a subset chosen to be fast enough that developers will not bypass them — which means they do **not** run every §14 check (see §15.5).

### 15.1 Location and installation

Hooks live in `tools/git-hooks/` as plain shell scripts, committed to the repository and reviewed like any other code.

Installation is opt-in. A developer runs:

```sh
tools/install-hooks.sh
```

which symlinks `.git/hooks/<name>` to `tools/git-hooks/<name>`. Symlinks mean updates to the committed scripts take effect on the next commit without re-running install.

Cloning the repository does not install hooks. A developer who has fetched an untrusted PR branch does not execute anything from the hooks directory until they have explicitly run the install script — which they should read first. This is intentional: hooks are arbitrary code, and a checkout should never be live-fire.

We do not use the `pre-commit.com` framework or equivalent. It pulls in a Python runtime, a configuration layer, and an out-of-band version manager for hook implementations. Plain in-tree shell scripts are auditable in one read, depend on nothing extra, and are governed by the same review process as the rest of the codebase.

### 15.2 What runs at each stage

The split is by speed. The commit hook must be fast enough that no one is tempted to bypass it.

**`pre-commit`** — target under five seconds on a clean workspace:

- `cargo fmt -- --check`.
- A clippy pass scoped to crates with staged changes (not the full workspace; speed). Pedantic is `warn` here, not `deny` (§12.2).
- A secret-pattern scan over staged content: RSA/Ed25519/SSH private key headers, AWS access key ID prefixes, GitHub fine-grained token prefixes, generic high-entropy hex of plausible secret length. Patterns live in `tools/git-hooks/secret-patterns`. False positives are bypassed with a one-line waiver in the commit message footer: `kennel-secret-waiver: <reason>`.
- File-size sanity: any single staged file over 10 MB is rejected. The `src/vendor/` path is exempt by prefix (audited tarballs land there).
- Consistency: if anything under `src/vendor/` is staged, `CHECKSUMS.toml` must also be staged (and vice versa). Catches the easy mistake of vendoring without updating the manifest.

**`commit-msg`:**

- Validates Conventional Commits format with the type set from §13.1: `feat`, `fix`, `test`, `scaffold`, `docs`, `refactor`, `chore`, `build`, `ci`.
- Summary line ≤ 72 characters; body lines ≤ 100 (wrap them).
- Rejects empty bodies on `feat:` and `fix:` commits (these change behaviour; the *why* belongs in the message).

**`pre-push`** — the arrival-blocking subset of §14. Slower; runs once per push, not per commit:

- `cargo fmt --check` (workspace).
- `cargo clippy --all-targets --all-features -- -D warnings` (pedantic `warn`, not `deny` — the pinned-toolchain pedantic-deny job is CI-only).
- `cargo build --offline --frozen --locked`.
- `tools/verify-checksums` (Rust verifier).
- `tools/verify-checksums.sh` (independent shell verifier; must agree).

If `pre-push` passes, the **arrival-blocking** CI checks (§13.4) are expected to pass. The hooks do **not** establish that the CI-only checks (`cargo deny`/`audit`/`vet`, `cargo doc`, fuzz, reproducible build, BPF matrix, full workspace `cargo test`) will pass — those are not run locally. A persistent divergence between hook and CI on the *arrival-blocking* checks is a project bug to be fixed in one or the other; it is not worked around with `--no-verify` as routine practice.

### 15.3 Bypass and authority

`git commit --no-verify` and `git push --no-verify` are permitted. The hooks are not the authoritative check. Appropriate uses of `--no-verify`:

- Intermediate commits on a feature branch (e.g., the structure commit of §7.1, where `todo!()` legitimately fails clippy).
- Rebasing or reordering history, where running checks on every replayed commit is wasted cycles.

Inappropriate use: bypassing the hook on a commit that will go to PR. CI will catch what the hook would have; the only thing bypassing changes is whether the developer finds out before or after pushing.

The authoritative controls live server-side on the canonical repository:

- Branch protection on `main`: required status checks per §14, required PR review counts per §13.2, required signed commits per §13.1.
- Direct push to `main` denied; merges only via PR.
- Force-push to `main` denied.
- Tag protection on release tags: only maintainer signing keys may push.

These cannot be bypassed by `--no-verify` or by any other developer-side action. The local hooks exist so that someone who follows them encounters very few surprises at the *arrival-blocking* server-side checks; the CI-only checks may still surface issues the hooks could not have caught, which is why §13.4 treats those failures with a comment rather than a close.

### 15.4 Hook scripts as code

The hook scripts themselves are subject to the same standards as the rest of the codebase:

- POSIX shell where possible (`#!/bin/sh`); bash where features genuinely require it (`#!/usr/bin/env bash`), with the bashism justified in a comment.
- `set -euo pipefail` (or POSIX equivalent) at the top of every script. Unset variables and pipeline failures are not silently ignored.
- No dependencies beyond what the project's build environment already requires (Rust toolchain, `git`, system `sha256sum`, POSIX coreutils).
- Tested. `tools/git-hooks/tests/` contains integration tests that run each hook against staged-state fixtures (a `git` workspace prepared with known-good and known-bad content). CI runs these tests on every PR; broken hooks fail CI like any other broken code.
- Reviewed. Changes to hooks go through the same PR/review process as production code. A hook change is not a "trivial" change for review purposes — hook scripts run on contributor machines and need the same scrutiny as anything else.

### 15.5 What the hooks do not do

The hooks are a *fast subset* of CI. They are not a place to add checks that exist nowhere else.

- **No check exists only in a hook.** Every hook check is also a CI check, so that bypass with `--no-verify` cannot route around it.
- **Conversely, the hooks do not run every CI check.** The CI-only checks of §14 (`cargo deny`/`audit`/`vet`, `cargo doc -D warnings`, fuzz smoke, reproducible-build double-run, BPF kernel-matrix, full workspace `cargo test`, pinned-toolchain pedantic-deny) are deliberately absent from the hooks: they are too slow, need infrastructure a developer machine lacks, or both. This is why §13.4 does **not** auto-close a first-arrival failure on those checks — the contributor could not have run them. Documentation that claims "the hooks run the same checks as CI" is wrong and must be corrected.
- **No hook makes network calls.** The pre-commit and pre-push hooks operate entirely on local content. A hook that needed to phone home would be both a privacy concern and an availability problem.
- **No hook modifies the working tree or staged content.** Hooks check; they do not fix. Auto-formatters that rewrite staged content silently are a footgun (developer commits one diff, hook commits another) and we do not use them. If `cargo fmt --check` fails, the developer runs `cargo fmt` explicitly and re-stages.
- **No hook installs other hooks or pulls additional scripts.** The hook content is what is in `tools/git-hooks/` at the time of the commit, no more.

---

## Appendix A: Justified deviations

Where this document is overridden in a specific PR, the PR description records:

- The rule being deviated from (section number).
- The reason.
- The maintainer who approved.
- Whether the deviation is permanent (and if so, a follow-up PR updating this document) or scoped to the change.

Permanent deviations that are not folded back into this document are bugs in the document.

---

## Appendix B: Quick reference

This appendix is a memory aid, not an authority. Where it abbreviates, the numbered section governs.

**Issue title tags (§13.5).** Exactly one, first thing in the title:

| Tag | Meaning | Action behaviour |
| --- | --- | --- |
| `[T<id>]` | Catalogued threat, ID verbatim from THREATS.md | Accepted |
| `[T-NONE]` | "I read the catalogue; this is NOT security-bearing" | Accepted |
| `[T-NEW]` | "I read the catalogue; this IS security-bearing but NOT catalogued" | Accepted; labelled `triage:new-threat`, never auto-closed |
| anything else / none | — | Auto-closed with refile invitation |

Exploitable specifics never go in a public issue → private channel in `SECURITY.md`.

**PR close-on-arrival (§13.4), non-maintainers:**

1. Unsolicited refactor/cleanup with no maintainer-approved issue.
2. No `test:` commit in branch history (compliant PR = ≥2 commits incl. `test:`).
3. PR description fails the template's specificity bar.
4. First CI failure on an **arrival-blocking** check: `cargo fmt`, clippy gate, offline build, both checksum verifiers. (CI-only checks — `deny`/`audit`/`vet`/`doc`/fuzz/repro/BPF-matrix/full-`test` — get a comment, not a close.)

**Commit cadence (§7.1):** `test:` → `scaffold:` → `feat:`. Folding never removes `test:`; minimum two commits.

**Tool-enforced vs review-enforced (the legend, §1):**

- `[tool]` examples: `cargo fmt`; `clippy::unwrap_used`, `panic`, `todo`, `unimplemented`, `indexing_slicing`, `arithmetic_side_effects`, `dbg_macro`; `missing_docs` (presence); `missing_errors_doc`/`missing_panics_doc` (the `# Errors`/`# Panics` *sections*); checksum verifiers; offline build.
- `[review]` examples: doc *content* and `# Security`/`# Safety`; the §10.5 banned patterns that no lint expresses (path joins, unbounded reads, `display_untrusted` usage, untrusted regex, `deny_unknown_fields` presence); §6.3 non-trivial-pattern comments; §9.3 "no secrets in logs"; cadence-was-written-first.

**Lints that move with the toolchain (§12.2):** `clippy::pedantic` is `deny` only in the pinned-toolchain CI job (`warn` everywhere else), so a `rustup update` cannot redden the tree. It is kept solely for `missing_errors_doc` and `missing_panics_doc`.

---

*This document is versioned with the repository. Significant revisions are noted in CHANGELOG.md. The maintainer set is in MAINTAINERS.md.*
