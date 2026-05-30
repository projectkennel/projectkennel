# tools/

Developer and supply-chain tooling. Everything here is dependency-free (POSIX
shell / bash, `git`, `cargo`, coreutils incl. `sha256sum`) so it runs on a clean
checkout without bootstrapping anything.

## Supply-chain (CODING-STANDARDS.md §5.5)

| Tool | What it does |
|---|---|
| `verify-checksums.sh` | The independent **shell witness** (§5.5.1): checks `CHECKSUMS.toml` against `crates-archive/*.crate` (every artefact recorded, every entry present, every SHA-256 matches) and cross-checks `Cargo.lock` (every registry crate pinned, every checksum agrees). Uses only system `sha256sum`. Runs in CI (§14) and `pre-push` (§15). Passes vacuously while there are no dependencies. |
| `audit-helper.sh` | The mechanical half of *adding* a dependency: `fetch` a `.crate` from `static.crates.io` (refuses overwrite), `confirm` byte-equality on an independent re-download, and `draft` the `CHECKSUMS.toml` + `DEPENDENCIES.md` entries with the computed hash. It does **not** perform the human cross-source verification, fill `verified-against`, or commit — that is the reviewer's job (§5.5). |

The Rust counterparts — `tools/verify-checksums` (from `kennel-checksum-verify`)
and the Rust `tools/audit-helper` — land once their `sha2` dependency is itself
vendored under §5.5.1. Until then these shell tools are the implementation, and
the shell witness is the enforcing check. The two verifier paths are required to
agree once both exist.

### Adding a dependency (operator flow)

1. `cargo update -p <crate>`; inspect the `Cargo.lock` diff.
2. `tools/audit-helper.sh fetch <crate> <version>` — vendors the `.crate`.
3. `tools/audit-helper.sh confirm <crate> <version>` — byte-check vs the registry.
4. **Read the source.** Independently cross-check the upstream git tag (and its
   signature against `KEYS.md`) and docs.rs.
5. `tools/audit-helper.sh draft <crate> <version>` — paste the drafts into
   `CHECKSUMS.toml` and `DEPENDENCIES.md`, fill `audited-by` / `audited-on` /
   `verified-against`.
6. `tools/verify-checksums.sh` — must pass.
7. Commit `CHECKSUMS.toml`, `crates-archive/<crate>-<version>.crate`, and
   `Cargo.lock` together; two maintainer approvals (§5.5).

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
