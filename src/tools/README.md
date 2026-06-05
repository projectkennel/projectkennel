# tools/

Developer and supply-chain tooling. Everything here is dependency-free (POSIX
shell / bash, `git`, `cargo`, coreutils incl. `sha256sum`) so it runs on a clean
checkout without bootstrapping anything.

## Supply-chain (CODING-STANDARDS.md §5.5)

| Tool | What it does |
|---|---|
| `verify-checksums.sh` | The independent **shell witness** (§5.5.1): checks `CHECKSUMS.toml` against `src/vendor/*.crate` (every artefact recorded, every entry present, every SHA-256 matches) and cross-checks `Cargo.lock` (every registry crate pinned, every checksum agrees). Uses only system `sha256sum`. Runs in CI (§14) and `pre-push` (§15). Passes vacuously while there are no dependencies. |
| `audit-helper.sh` | The mechanical half of *adding* a dependency: `fetch` a `.crate` from `static.crates.io` (refuses overwrite), `confirm` byte-equality on an independent re-download, and `draft` the `CHECKSUMS.toml` + `DEPENDENCIES.md` entries with the computed hash. It does **not** perform the human cross-source verification, fill `verified-against`, or commit — that is the reviewer's job (§5.5). |
| `audit-source.sh` | The **independent-of-crates.io** provenance check. A `.crate`'s sha256 only proves "this is what crates.io served"; this proves the `.crate`'s *code* matches the public upstream **GitHub source at the release tag**. It reads the commit cargo embedded at publish (`.cargo_vcs_info.json`), downloads GitHub's tree for that commit, confirms every source file is byte-identical and `Cargo.toml.orig` matches upstream, and resolves the version's git tag (via the GitHub API, dereferencing annotated tags) to confirm it equals the published commit. PASS ⇒ the bytes you compile are the public source at `github.com/<repo>@<tag>`. Network; auto-detects the repo from the crate's `repository` field (override with a 3rd arg). |

The Rust counterparts — `tools/verify-checksums` (from `kennel-checksum-verify`)
and the Rust `tools/audit-helper` — land once their `sha2` dependency is itself
vendored under §5.5.1. Until then these shell tools are the implementation, and
the shell witness is the enforcing check. The two verifier paths are required to
agree once both exist.

### Adding a dependency (operator flow)

1. `cargo update -p <crate>`; inspect the `Cargo.lock` diff.
2. `tools/audit-helper.sh fetch <crate> <version>` — vendors the `.crate`.
3. `tools/audit-helper.sh confirm <crate> <version>` — byte-check vs the registry.
4. `tools/audit-source.sh <crate> <version>` — confirm the `.crate` matches the
   public GitHub source at the release tag (provenance independent of crates.io).
   It prints a ready-made `verified-against` line on PASS.
5. **Read the source.** Step 4 proves the code is the public upstream source; a
   human still reads it for backdoors (a pre-compromised upstream publishes the
   same bytes everywhere — §5.5 "what this does not defend against"). Confirm the
   tag signature against `KEYS.md` where the upstream signs.
6. `tools/audit-helper.sh draft <crate> <version>` — paste the drafts into
   `CHECKSUMS.toml` and `DEPENDENCIES.md`; fill `audited-by` / `audited-on`, and
   the `verified-against` line from step 4.
7. `tools/verify-checksums.sh` — must pass.
8. Commit `CHECKSUMS.toml`, `src/vendor/<crate>-<version>.crate`, and
   `Cargo.lock` together; two maintainer approvals (§5.5).

### CI tool binaries (`ci-tools.toml`, `install-ci-tools.sh`)

The supply-chain gate's own tools — `cargo-deny`, `cargo-audit`, `cargo-vet` —
are not workspace crates and **cannot** be `cargo install`ed: the offline
`.cargo/config.toml` replaces crates.io with the local registry, so their
dependency trees have no source to resolve from. They are installed instead the
same way we treat a vendored `.crate` — pin the exact prebuilt release binary,
record the SHA-256 we verified, and refuse anything that does not match.

| Tool | What it does |
|---|---|
| `ci-tools.toml` | The integrity ground truth for the tool binaries (what `CHECKSUMS.toml` is for `.crate`s): per-tool version, download `url`, `archive-sha256`, in-archive `bin-path`, and the §5.5 audit fields. Entries start `audited-by = "PENDING"`. |
| `install-ci-tools.sh` | Downloads each pinned `url`, verifies its SHA-256 against `ci-tools.toml` **before** extracting the binary, and refuses on any mismatch or on an empty/`PENDING` `archive-sha256`. Prints the bindir on stdout (`PATH="$(tools/install-ci-tools.sh):$PATH"`). Runs in the CI `supply-chain` job. |

Pinning or bumping a CI tool (same shape as adding a dependency):

1. Pick the exact upstream release tag; note the linux x86_64 asset and its
   in-archive binary path.
2. Download the asset **and** its upstream-published `.sha256` (where one
   exists); confirm the computed hash equals the published one. For tools that
   publish no per-asset checksum (cargo-audit today), this is a single source —
   the cross-check in step 3 is then mandatory, not optional.
3. **Cross-verify** independently of the download: confirm the release tag and,
   where the project signs releases, the tag signature against `KEYS.md`. This
   is the §5.5 "one source is not enough" rule applied to a binary.
4. Record `url` / `archive-sha256` / `bin-path` in `ci-tools.toml`; fill
   `audited-by` / `audited-on` and the `verified-against` lines.
5. `tools/install-ci-tools.sh` must succeed (it re-verifies the hash).
6. Two maintainer approvals. Until the second approval lands, the entry stays
   `PENDING` and the CI `supply-chain` job is `continue-on-error` (advisory, not
   a required check). A maintainer flips it to required once ratified.

### The `cargo vet` store (`supply-chain/`)

`cargo vet --locked` runs in CI against the audit chain in `supply-chain/`.
cargo-vet rewrites these files into a canonical form (`cargo vet fmt`) and strips
free-floating header comments, so the project's posture is documented here rather
than in the files:

- **No third-party imports.** `config.toml` has no `[imports]` table. §5.5 is
  built on the project verifying crates *itself* (provenance against upstream
  GitHub at the release tag, source read, two approvals); importing another
  org's audit verdicts (Mozilla, Google, …) would substitute their trust for
  ours. Every crate is therefore covered by our own audit or an explicit
  exemption — nothing is trusted on an outside say-so.
- **Audits vs exemptions.** `audits.toml` holds our own `safe-to-deploy` audits
  for the crates with a full §5.5 review in `DEPENDENCIES.md` (currently the six
  direct deps: libc, nix, bitflags, object, seccompiler, ed25519-compact); each
  `notes` field cites the provenance check and review date. The remaining
  third-party crates (the serde / proc-macro build stack) are provenance-verified
  but not yet read to the `safe-to-deploy` bar, so they sit in `config.toml` as
  `[[exemptions]]`. **Burning the exemptions down** — reading each to the bar and
  moving it to `audits.toml` — is the standing owed work.
- **Editing the store.** Add an audit with `cargo vet certify`, or edit by hand
  then run `cargo vet fmt` (CI's `--locked` rejects a non-canonical store). A new
  dependency that is neither audited nor exempt fails the check until one or the
  other is added — which is the point.

## Install (`07-paths.md`, `08-as-built-notes.md` §8.4)

| Tool | What it does |
|---|---|
| `install.sh` | System installer (run with `sudo`): builds the release binaries (the privhelper with `--features bpf-egress`), installs them under `--prefix` (default `/opt/kennel`; binaries in `bin/`, the **setuid-root** privhelper in `sbin/`), installs the systemd *user* units to `/usr/lib/systemd/user/`, and creates the `/etc/kennel` skeleton. Supports `--no-build` and `--dry-run`. It does **not** fabricate the admin-provisioned security inputs (`/etc/kennel/subkennel` allocations, `/etc/kennel/scope` constants, trust-store keys) — it prints what the admin must populate, then each user runs `systemctl --user enable --now kenneld.socket`. |

## Reproducible release builds (`BUILD-ENV.md` §Reproducibility, CODING-STANDARDS.md §8)

| Tool | What it does |
|---|---|
| `reproducible-build.sh` | Builds release binaries whose bytes are a pure function of the committed tree, so two machines hash-for-hash agree. It pins `SOURCE_DATE_EPOCH` to the HEAD commit time (rustc embeds no other timestamp) and sets `--remap-path-prefix` for the three host-specific roots — the workspace → `/kennel`, the cargo home → `/cargo`, the rustup sysroot → `/rustup` — so no absolute path leaks into panic strings or debug info. (`--remap-path-prefix` is the stable stand-in for `trim-paths`, which is not yet stable on the pinned toolchain.) Builds `--locked --offline` from the vendored registry. Profile defaults to `release-with-debuginfo` (override with `KENNEL_PROFILE`). |

Two cargo profiles back this (root `Cargo.toml`): `release` (stripped, `codegen-units = 1` for determinism) and **`release-with-debuginfo`** (`inherits = "release"`, `strip = "none"`, `debug = "full"`) — an optimised, reproducible build that keeps symbols for production crash symbolication. Verified: a `release-with-debuginfo` artefact built through the script carries `/kennel/src/...`, `/cargo/registry/...`, and `/rustup/...` paths and **zero** occurrences of the builder's home directory.

## Git hooks (CODING-STANDARDS.md §15)

| Tool | What it does |
|---|---|
| `install-hooks.sh` | Opt-in installer; symlinks `.git/hooks/{pre-commit,commit-msg,pre-push}` to the in-tree scripts. A fresh clone runs nothing until you run this. |
| `git-hooks/pre-commit` | fmt check, clippy on staged crates, file-size cap, `src/vendor/`↔`CHECKSUMS.toml` consistency. |
| `git-hooks/commit-msg` | Conventional Commits + line caps + body-required on feat/fix; staged-content secret scan with the `kennel-secret-waiver:` footer. |
| `git-hooks/pre-push` | Mirrors the CI gate: fmt, clippy `-D warnings`, test, `build --offline --frozen --locked`, and the checksum verifiers. |

## Tests

`tools/tests/` and `tools/git-hooks/tests/` hold shell integration tests for the
above. Run them directly:

```sh
tools/git-hooks/tests/commit-msg.sh
tools/tests/verify-checksums.sh
tools/tests/audit-helper.sh
tools/tests/audit-source.sh
tools/tests/install-ci-tools.sh
```
