# Build and test architecture

This chapter describes how the workspace is built, what the dependency graph looks like at build time, and how the test suite is structured. It is paired with CODING-STANDARDS.md §2 (toolchain pinning), §5 (dependency policy), §7 (test discipline), and §14 (CI gate); this chapter is the project-specific *application* of those rules.

---

## Build inputs

A build needs:

- Rust toolchain pinned by `rust-toolchain.toml` (installed via `rustup`).
- Clang at the version pinned in `BUILD-ENV.md` (for BPF compilation against the kernel UAPI, no CO-RE).
- The kernel UAPI headers (`linux-libc-dev`: `<linux/bpf.h>` plus the multiarch `<asm/types.h>` path) at the version pinned in `BUILD-ENV.md`.
- `bpftool` is **optional** (inspection and the verifier-load matrix only); the loader does not depend on it.
- Vendored Rust crates in `src/vendor/`, each in `CHECKSUMS.toml`.
- The system `sha256sum` binary (coreutils) for the shell-script checksum verifier.

A build does not need:

- Network access. `cargo build --offline --frozen --locked` is the only build command. CI fails if any network traffic is observed during build.
- `libbpf`, `vmlinux.h`, or any CO-RE machinery (the programs compile against the UAPI and are loaded by `kennel-bpf`'s own `bpf(2)` loader; ELF parsing uses the `object` crate).
- Any system Rust (we use rustup-managed Rust).

The release-build environment is a container image whose exact contents are pinned by digest in `BUILD-ENV.md`. The image's recipe lives in the repository; rebuilding the image from scratch is reproducible.

---

## Build sequence

For a full workspace build:

1. **Vendor verification.** `tools/verify-checksums` (and its shell twin) confirm `src/vendor/` matches `CHECKSUMS.toml` and `Cargo.lock`.
2. **BPF compilation.** `kennel-bpf`'s `build.rs` invokes clang against `bpf/*.bpf.c`, producing `*.bpf.o` files in `OUT_DIR`. Each `.bpf.c` includes `<linux/bpf.h>` (kernel UAPI) and `bpf/maps.h`; **no** `vmlinux.h`, no CO-RE relocations. The `.o` is embedded into the crate; map references are left as ELF relocations the loader resolves at load time.
3. **Rust compilation.** `cargo build --workspace` builds every crate. The workspace is twelve crates: `kennel-syscall`, `kennel-text`, `kennel-policy`, `kennel-bpf`, `kennel-audit`, `kennel-config`, `kennel-netproxy`, `kennel-privhelper`, `kennel-spawn`, `kennel-ssh-reorigin`, `kennel-socks-connect`, and `kenneld` (which also produces the `kennel` CLI binary alongside the `kenneld` daemon, in its `src/bin/`). Order is computed by Cargo from `[workspace.dependencies]`; the lower-layer crates (`kennel-syscall`, `kennel-text`) are built before higher layers (`kennel-spawn`, `kenneld`).
4. **Binary stripping** (release only). `strip = "symbols"` in the release profile; separately, debug-info binaries are produced under `target/release-with-debuginfo/` for distributions that want a parallel `.debug` package.
5. **Reproducibility check** (release-build CI only). The release builds twice on two different runners; output hashes must match.

A typical incremental dev build (no BPF source changes) takes 5-10 seconds on a modern workstation. A full release build (clean target, BPF compilation, all features) takes 2-4 minutes.

---

## Feature-flag matrix

Per `03-crate-decomposition.md`, several crates expose build-time feature flags. CI tests these combinations:

| Combination | What | Why |
|---|---|---|
| Default | The workspace with default features | Standard install. A plain `cargo build` needs no clang: BPF objects are not embedded unless `embed-programs` is set. |
| `--no-default-features` | Every crate with no features | Catches feature-gated code that was accidentally required. |
| `embed-programs` (`kennel-bpf`) | Compile `bpf/*.bpf.c` with clang at build time and embed the objects | Needed wherever the loader must actually attach programs. |
| `bpf-egress` (`kennel-privhelper`) | Privhelper built with the BPF egress path (pulls in `kennel-bpf` with `embed-programs`) | Root e2e and the privileged egress install. |
| `root-tests` | Tests that need root (transitively enables `embed-programs`/`bpf-egress`) | Run under a privileged CI runner. |

Every combination must compile, pass clippy, pass non-root tests. The `root-tests` combination additionally runs the privileged tests in a CI runner with elevated capabilities.

The full feature matrix is in `.github/workflows/ci.yml`; this section is the human-readable summary.

---

## Test taxonomy

Tests in the project come in five categories. Each has its own placement, runtime, and CI job.

### Unit tests

`#[cfg(test)] mod tests` blocks beside the code, in every crate. Per CODING-STANDARDS.md §7.3:

- Fast: every unit test in the workspace should run in well under a second total.
- Isolated: no network, no `$HOME`, no shared state.
- Comprehensive: success, every error variant, every panic condition, boundaries, adversarial input (§7.2).

Run by `cargo test --workspace --lib`. Required by every CI job.

### Integration tests

`tests/` directories per crate. Test the public API of one crate end-to-end.

Most integration tests run as the user with no special capabilities. A subset (in `kennel-spawn`, `kennel-bpf`, and `kennel-privhelper`) require root for namespace operations, cgroup creation, Landlock sealing on a real kernel, and BPF attach. These are gated behind the `root-tests` feature and run in a dedicated CI job.

### Property and round-trip tests

The deterministic-input properties — resolver/validator invariants (`kennel-policy`), sanitiser totality (`kennel-text`), and the wire-format encode/decode round-trip (`kenneld::control`) — are asserted as unit tests beside the code, run by the standard `cargo test` invocation. The adversarial-input side is covered by the `kennel-fuzz` harness below, which carves a seed into many boundary lengths via `arbitrary`.

Roadmap: a coverage-guided `proptest`/`cargo-fuzz` layer can be added on top once the corresponding crates are vendored; the harness entry points are already shaped for it.

### Fuzz tests

The fuzz harness (`kennel-fuzz`) lives in `src/fuzz/`, a **separate workspace** so it stays out of the shipped crates' `Cargo.lock`, member list, and `CHECKSUMS.toml` — the offline `cargo build --frozen --locked` gate is unaffected by anything here. Every parser of untrusted input is exercised (CODING-STANDARDS.md §10.6).

The approach is hand-rolled ("Path C"): the `arbitrary` crate carves a fuzzer seed into byte chunks, and a plain runner feeds each chunk to every parser. It is **not** `cargo-fuzz` / `libfuzzer-sys` — those would pull a C++-compiling `build.rs` and a bundled LLVM runtime. With `default-features = false`, `arbitrary` is the single dependency with zero transitive deps; only its `Unstructured` byte-carving is used. The `run`/`fuzz_parsers` entry points are shaped so a coverage-guided `fuzz_target!` can call them if that is ever adopted; until then `cargo test -p kennel-fuzz` drives them over a deterministic pseudo-random corpus.

A single pass feeds each seed to every parser in `fuzz_parsers`:

- `kennel-netproxy::protocol::detect`, `socks5::parse_greeting`, `socks5::parse_request`, `http::parse_request` — the network front-door parsers.
- `kennel-netproxy::config::from_toml_str` — the proxy config reader (over `String::from_utf8_lossy` of the bytes).
- `kenneld::control::Request::decode` / `Response::decode` — the kenneld control wire format.
- `kennel-privhelper::wire::Request::decode` — the privhelper packed-struct request.
- `kennel-policy::verify_settled` — the signed settled-policy reader (the TOML parse and schema-version gate run on the untrusted bytes before the signature check).

The property under test is robustness: for any input, every parser returns `Ok`/`Err` and never panics, hangs, or reads out of bounds. A returned `Err` on junk is a correct outcome. Round-trip and differential properties live in each crate's own unit tests, not here.

### BPF verifier tests

`cargo test` cannot verify a BPF program against a real kernel; that needs `bpftool prog load` on the matrix of supported kernel versions.

CI runs a dedicated job that, for each kernel version in the matrix (see `02-5-bpf-abi.md`), boots a VM (or uses a multi-kernel CI service), copies the built `.bpf.o` files in, and attempts `bpftool prog load` for each program. Failure on any matrix entry blocks merge — this is the BPF equivalent of a compile error.

Kernel matrix (subject to change in `BUILD-ENV.md`):

- 6.10 (project floor).
- Latest LTS.
- Current stable.
- Latest mainline.

---

## CI jobs

`.github/workflows/ci.yml` defines **five jobs**, each a sequence of steps on a hosted `ubuntu-latest` runner. The jobs and their steps:

| Job | Steps |
|---|---|
| `rust` | `cargo fmt --all -- --check`; `cargo clippy --all-targets --all-features -D warnings`; `cargo test --all-features`; `cargo test --no-default-features`; `cargo build --offline --frozen --locked`; `cargo doc --no-deps` (`RUSTDOCFLAGS=-D warnings`). |
| `bpf-compile` | Compile every `bpf/*.bpf.c` program against the kernel UAPI with `clang -Wall -Wextra -Werror -target bpf` (the compile-regression gate; the verifier-load matrix is owed, see below). |
| `fuzz` | Clippy and `cargo test` the separate `src/fuzz/` workspace, `--offline --locked` (the no-panic corpus across every untrusted-input parser). |
| `supply-chain` | Install the pinned, hash-verified `cargo-deny`/`-audit`/`-vet` binaries, then `cargo deny --all-features check`, `cargo audit --deny warnings`, `cargo vet --locked`. |
| `tooling` | The shell checksum witness (`tools/verify-checksums.sh`) and the hook/tool shell tests. |

The `rust` job folds what would otherwise be separate fmt/clippy/test/build/doc jobs into one runner's step sequence; a step failure fails the job. All five jobs gate a PR.

Owed, and **not** yet in CI (tracked in the workflow header): the Rust checksum verifier twin (needs `sha2`, §5.5.1), the reproducible-build double-build (needs the release image), the BPF verifier-load matrix on custom-kernel runners (the `bpf-compile` job is the hosted-runner compile part), and a privileged `root-tests` runner. CI must not claim to run a check it does not.

CI is configured in `.github/workflows/`. The configuration is reviewed under the same discipline as code (CODING-STANDARDS.md §14).

---

## Local development loop

A developer pre-pushes locally via `tools/install-hooks.sh`, which sets up the pre-commit and pre-push hooks per CODING-STANDARDS.md §15.

The hooks run the *fast subset* of CI:

- pre-commit: `cargo fmt --check` (workspace), scoped clippy, secret-pattern scan, file-size sanity, `src/vendor`/`CHECKSUMS.toml` consistency.
- pre-push: full clippy, full test, offline build, both checksum verifiers.

The hooks do not run the BPF verifier matrix (no kernel-VM setup on the developer's machine) or the reproducible-build check (single-runner). Those run in CI.

---

## Test placement decisions

A few specific placement choices:

### Root-required tests

`kennel-spawn::tests::namespace_setup`, `kennel-spawn::tests::landlock_sealing`, `kennel-bpf::tests::attach_to_real_cgroup`, `kennel-privhelper::tests::addr_add_succeeds` — these need root.

Placement: in `tests/root/` within each crate, behind `#[cfg(feature = "root-tests")]`. The feature flag is workspace-level; `cargo test --workspace --features root-tests` runs them, `cargo test --workspace` does not.

The CI runner for `root-tests` is privileged but ephemeral: a container or VM that exists only for the duration of the test run, with a fresh kernel, and no persistent state.

### Mock vs real

Where possible, use the real thing. Per CODING-STANDARDS.md (the testing-philosophy callout in §7 is implicit but consistent): integration tests use real files in `tempfile::tempdir`, real Unix sockets, real BPF programs against real cgroups (in the root-tests subset). Mocks are reserved for cases where the real dependency is genuinely unavailable (e.g., a CI machine without a recent enough kernel — in which case the test is skipped, not mocked).

### The audit-writer test

Audit events are JSON Lines: one well-formed JSON object per line, every string value escaped through `kennel-text` so no raw control bytes reach the sink. `kennel-netproxy`'s audit module (and the daemons that write their own events) own the sink — a file under the kennel's state dir, or an fd kenneld passed. The test discipline is a render-and-reparse round trip: emit every record type, then parse each line back and compare against the canonical event, which catches escaping and field-mapping drift cheaply.

---

## Reproducible builds

Release builds run twice on two different CI runners. The build process:

1. Pin `SOURCE_DATE_EPOCH` to the commit timestamp.
2. Build with the pinned toolchain and pinned clang.
3. Hash every output artefact (`kennel`, `kenneld`, `kennel-privhelper`, `kennel-netproxy`, each `.bpf.o`, the strip'd binaries, the debug-info packages).
4. Compare hashes between the two runs.

A mismatch blocks the release. Causes typically traced to:

- A path embedded in the binary (rustc may embed `CARGO_MANIFEST_DIR`). Fixed via `--remap-path-prefix`.
- A non-deterministic dependency (a build script that uses the wall clock or process ID). Each such dependency is patched or replaced.
- A kernel-version leak in the BPF output. Avoided by compiling against the pinned UAPI headers (not a kernel-specific BTF dump) with the same clang on both runners.

The reproducible-build job is not in the per-PR CI gate (it would be too slow); it runs on release tags and on `main` nightly.

---

## What this chapter does not cover

- Per-crate dep graph and crate purposes: `03-crate-decomposition.md`.
- The CI workflow files in detail: `.github/workflows/`.
- The container image used for release builds: `BUILD-ENV.md` and `tools/release-image/`.
- The set of clippy lints denied: CODING-STANDARDS.md §12.2.
- The dep audit cadence: CODING-STANDARDS.md §5.6, §5.7.
