# tools/

Developer and supply-chain tooling. Everything here is dependency-free (POSIX
shell / bash, `git`, `cargo`, coreutils incl. `sha256sum`) so it runs on a clean
checkout without bootstrapping anything.

## Supply-chain (CODING-STANDARDS.md §5.5)

| Tool | What it does |
|---|---|
| `verify-checksums.sh` | The independent **shell witness** (§5.5.1): checks `CHECKSUMS.toml` against `crates-archive/*.crate` (every artefact recorded, every entry present, every SHA-256 matches) and cross-checks `Cargo.lock` (every registry crate pinned, every checksum agrees). Uses only system `sha256sum`. Runs in CI (§14) and `pre-push` (§15). Passes vacuously while there are no dependencies. |
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
8. Commit `CHECKSUMS.toml`, `crates-archive/<crate>-<version>.crate`, and
   `Cargo.lock` together; two maintainer approvals (§5.5).

## Install (`07-paths.md`, `08-as-built-notes.md` §8.4)

| Tool | What it does |
|---|---|
| `install.sh` | System installer (run with `sudo`): builds the release binaries (the privhelper with `--features bpf-egress`), installs them under `--prefix` (default `/opt/kennel`; binaries in `bin/`, the **setuid-root** privhelper in `sbin/`), installs the systemd *user* units to `/usr/lib/systemd/user/`, and creates the `/etc/kennel` skeleton. Supports `--no-build` and `--dry-run`. It does **not** fabricate the admin-provisioned security inputs (`/etc/kennel/subkennel` allocations, `/etc/kennel/scope` constants, trust-store keys) — it prints what the admin must populate, then each user runs `systemctl --user enable --now kenneld.socket`. |

## Git hooks (CODING-STANDARDS.md §15)

| Tool | What it does |
|---|---|
| `install-hooks.sh` | Opt-in installer; symlinks `.git/hooks/{pre-commit,commit-msg,pre-push}` to the in-tree scripts. A fresh clone runs nothing until you run this. |
| `git-hooks/pre-commit` | fmt check, clippy on staged crates, file-size cap, `crates-archive/`↔`CHECKSUMS.toml` consistency. |
| `git-hooks/commit-msg` | Conventional Commits + line caps + body-required on feat/fix; staged-content secret scan with the `kennel-secret-waiver:` footer. |
| `git-hooks/pre-push` | Mirrors the CI gate: fmt, clippy `-D warnings`, test, `build --offline --frozen --locked`, and the checksum verifiers. |

## Tests

`tools/tests/` and `tools/git-hooks/tests/` hold shell integration tests for the
above. Run them directly:

```sh
tools/git-hooks/tests/commit-msg.sh
tools/tests/verify-checksums.sh
tools/tests/audit-helper.sh
```
