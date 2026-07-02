# Release ceremony

The repeatable steps to cut a Project Kennel release. Written from the 0.4.0 and 0.5.0 cuts;
update it when a step changes. The **prep** (everything below up to "Tag & publish") lands as one
reviewable PR; the **tag & publish** is the operator's act on a green `main`.

## The three version axes (they are independent — do not conflate)

A release bumps the **package** version. The other two move on their **own** triggers and are
usually already correct by release time — *verify*, do not blindly bump.

| Axis | Where | Bumps when | At release |
|---|---|---|---|
| **Package** | `Cargo.toml` `[workspace.package].version` (all crates inherit `version.workspace = true`) | every release | **bump** to the new `x.y.z` |
| **Settled-schema** | `SETTLED_SCHEMA_VERSION` (+ `MIN_…`) in `kennel-lib-policy/src/lib.rs`; pinned in `schema/schema-version.lock` | the **policy schema shape** changes (field/type/required/enum) — CI's `schema-version-pin.sh` forces it per-change | **verify only.** Run the pin test; it must say "no bump owed". Bumping without a shape change *fails CI* (no pin line for the new version). |
| **Threat-catalogue** | `catalogue_version` in `dist/threats/catalogue.toml` **and** the `Version` line in `docs/reference/THREATS.md` (they must match) | a `THREATS.md` entry is added/changed | **verify only.** Confirm the two match; it was bumped when the entry landed. |

> 0.5.0 example: package `0.4.0`→`0.5.0`; schema stayed `2` (no shape change — `abstract = "allow"`
> was a value gate, not a new field); threats stayed `0.5` (W13 bumped it when its entry landed).

## Prep (one PR)

1. **Bump the package version** — one line in `Cargo.toml` `[workspace.package].version`.

2. **Regenerate BOTH lockfiles.** The fuzz workspace path-deps the kennel crates, so it has its own
   lock that also carries the version.
   ```
   cargo update --workspace --offline                       # main Cargo.lock
   (cd src/fuzz && cargo update --workspace --offline)       # src/fuzz/Cargo.lock
   ```
   Verify both are `--frozen --locked` clean:
   ```
   cargo build --offline --frozen --locked -p kenneld
   (cd src/fuzz && cargo metadata --offline --frozen --format-version 1 >/dev/null)
   ```
   The diff should be **only** the workspace crates' `0.x.y` strings (symmetric ins/del), no
   dependency-graph change.

3. **Verify the schema axis** (do not bump unless a shape change is owed):
   ```
   cargo run --offline --locked -p gen-schema -- --out /tmp/s.json && diff -q schema/policy.toml.schema /tmp/s.json   # no drift
   bash src/tools/tests/schema-version-pin.sh                                                                          # "no bump owed"
   ```

4. **Verify the threat axis:** `catalogue_version` in `dist/threats/catalogue.toml` matches the
   `Version` line in `docs/reference/THREATS.md`. (Both are *frozen-tree-exempt* only if a new entry is
   genuinely owed; under the freeze, new entries are queued via `DOC-PATCH-LOG.md` and the catalogue
   version moves with the entry, not the release.)

5. **Regenerate the machine artifacts** that embed counts/shape (the inventory carries SLOC; man and
   schema are version-agnostic but regen to be safe):
   ```
   cargo run --offline --locked -p gen-inventory -- --json docs/reference/crate-inventory.json --doc docs/reference/03-crate-decomposition.md
   cargo run --offline --locked -p gen-man -- ...            # if any CLI surface changed this cycle
   ```

6. **Write the CHANGELOG.** Move `## [Unreleased]` content into `## [x.y.z] — <date>` in the
   house surface-section style (a bold-theme narrative lead, then `### Policy schema changes` /
   `### CLI changes` / `### IPC protocol changes` / `### Runtime & enforcement` / `### Privilege
   model` / `### Threat catalogue` / `### Fixed` …). Source it from the **merged PRs since the last
   release tag** (`gh pr list --state merged`), not from memory. Date = the planned tag day; note it
   may slip.

7. **Version-string sweep + accuracy pass.** `grep -rn "<old version>"` repo-wide (exclude
   `target/`, `Cargo.lock`). **Advance forward-looking fences** (`post-<old>` → `post-<new>` for
   items still deferred) and any **README / `docs/website/index.html` claim the release changes**
   (the 0.4.0 cut corrected a privhelper op-list and a "no setuid" line; 0.5.0 advanced the
   interactive-file-broker fence). **Leave historical references** (e.g. `0.4.0 F1 residual` in code
   comments, frozen `docs/design`/`docs/architecture`, and `audits/` reports) — they name the
   release they belong to.

8. **Local CI gate dry-run** before pushing (these are the jobs that bite):
   ```
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
   git diff --exit-code docs/reference/crate-inventory.json docs/reference/03-crate-decomposition.md   # inventory regen committed
   git diff --exit-code schema/policy.toml.schema                                                            # schema regen committed
   ```
   Open the PR against `main` and **watch every CI job** — especially `inventory`, `schema`,
   `schema-version-pin`, the **fuzz lock** (the second lockfile is the one most often forgotten),
   `supply-chain`, and `man`. A regen-diff job failing means a generated artifact was not committed.

## Tag & publish (operator, on green `main`)

9. **Build the cross-arch release tarballs.** `src/tools/build-release.sh` builds the in-kennel
   static-pie set + host binaries per target. Building *both* arches from one host is the norm and
   needs the cross toolchain + multiarch headers, or the privhelper BPF clang step dies on
   `asm/types.h not found`:
   - cross linker via `CARGO_TARGET_<TRIPLE>_LINKER` (e.g. `gcc-x86-64-linux-gnu`);
   - `dpkg --add-architecture <other>` + `linux-libc-dev:<arch>` + `libc6-dev:<arch>`.

10. **Acceptance-test the payload on a real host before publishing.** Unpack a tarball, verify it
    against `SHA256SUMS`, then run `sudo ./install.sh` and WATCH the effects land — the binaries in the
    three-dir layout; the reference policies actually *compiling* host-signed into `/etc/kennel/policies`;
    `/etc/kennel/templates` staying empty (maintainer content is vendor-tier, `/usr/lib/kennel`); the
    host key minted or reused — then a `kennel run <settled> -- …` that exits cleanly. Green CI does not
    exercise a real install: the 0.5.0 cut shipped an installer that put templates in the admin tier,
    never staged the reference policies, and (after those fixes) had `install_reference_policies`
    silently compile **zero** policies because it looked for the `kennel` shim at `$libexec` instead of
    `/usr/bin` — all three passed CI and surfaced only here. Fix and re-cut before tagging.

11. **Tag and publish.** First **re-verify the CHANGELOG against `gh pr list --state merged` since the
    readiness PR** — the prep (step 6) is written at readiness and DRIFTS if work merges after it; the
    0.5.0 notes still claimed the settled schema "stayed 2" when the merged tree was 3, and omitted a
    whole corpus/schema wave. Correct the section, then `git tag v<x.y.z>` on the merged release commit
    and `gh release create v<x.y.z>` with the tarballs + a `SHA256SUMS.txt` and the corrected CHANGELOG
    section as the body.

## Why these gotchas exist

- **Two lockfiles.** `src/fuzz` is a separate cargo workspace that path-deps the kennel crates, so
  its lock carries the same version and must be regenerated too — a `--frozen --locked` CI job
  checks it.
- **Schema version ≠ release version.** It is a settled-policy *compatibility* integer the W17
  control-plane handshake reads. CI pins its shape; a bump without a shape change has no pin line
  and fails. Never move it to "match" the release.
- **Inventory is a regen-diff gate.** It carries SLOC, so *any* code change drifts it; regen and
  commit (`--json` **and** `--doc`) or the `inventory` job goes red.
- **Cross-build headers.** The BPF privhelper compiles cgroup programs with clang at build time;
  cross-compiling the other arch needs that arch's libc headers present, or clang cannot find
  `asm/types.h`.
- **The real install-test is the only gate that exercises `install.sh`.** CI builds and unit/e2e-tests
  the binaries, but nothing drives an unpacked payload through `sudo ./install.sh` on a real host — so
  install-only logic (placement tiers, payload staging, the host-key compile) is unverified until
  step 10. The 0.5.0 cut proved the cost: three install bugs rode green CI to the edge of publish.
- **The CHANGELOG is written at readiness, tagged later.** Anything that merges between the prep PR and
  the tag is in the release but not yet in the notes — so the notes are re-verified against the merged
  PR list at tag time (step 11), not trusted from readiness.
