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
3. **Rust compilation.** `cargo build --workspace` builds every crate. Order is computed by Cargo from `[workspace.dependencies]`; the lower-layer crates (`kennel-syscall`, `kennel-text`, `kennel-audit`) are built before higher layers (`kennel-spawn`, `kenneld`, `kennel-cli`).
4. **Binary stripping** (release only). `strip = "symbols"` in the release profile; separately, debug-info binaries are produced under `target/release-with-debuginfo/` for distributions that want a parallel `.debug` package.
5. **Reproducibility check** (release-build CI only). The release builds twice on two different runners; output hashes must match.

A typical incremental dev build (no BPF source changes) takes 5-10 seconds on a modern workstation. A full release build (clean target, BPF compilation, all features) takes 2-4 minutes.

---

## Feature-flag matrix

Per `03-crate-decomposition.md`, several crates expose build-time feature flags. CI tests these combinations:

| Combination | What | Why |
|---|---|---|
| Default | The workspace with default features | Standard install. |
| `--no-default-features` | Every crate with no features | Catches feature-gated code that was accidentally required. |
| `bwrap-compose` on | Spawn via bubblewrap subprocess | Distributions that prefer bwrap. |
| `sink-journald` on | Audit writer with journald | systemd-using distributions. |
| `sink-journald` + `sink-syslog` + `sink-file` | All sinks | Edge case: parallel-emission deployments. |
| `root-tests` on | Tests that need root | Run under a privileged CI runner. |

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

### Property tests

Use `proptest`. Located in `tests/property/` per crate, or `proptest!` blocks within unit tests for tighter cases.

Required for `kennel-policy` (resolver, validator), `kennel-text` (sanitiser), `kennel-ipc-shared` (framing round-trip). Run as part of the standard `cargo test` invocation; bounded shrink time.

### Fuzz tests

Under `fuzz/` at the workspace root. `cargo-fuzz` corpora committed; each parser of untrusted input has a fuzz target (CODING-STANDARDS.md §10.6).

Current targets:

- `fuzz/policy_parse` — `kennel-policy::parse`.
- `fuzz/policy_resolve` — `kennel-policy::resolve` against a structured fake template tree.
- `fuzz/signature_envelope` — `kennel-policy::signature::verify`.
- `fuzz/ipc_frame` — `kennel-ipc-shared::framing` decode.
- `fuzz/socks5_request` — `kennel-netproxy::socks5::parse_request`.
- `fuzz/bpf_event_parse` — `kennel-bpf::ringbuf::parse`.
- `fuzz/text_sanitise` — `kennel-text::sanitise_for_audit`.
- `fuzz/privhelper_request` — `kennel-privhelper::request::parse`.

CI runs each target for one minute on every PR (smoke test). Out-of-band runs (developer machines, scheduled long-run jobs) extend coverage; new findings update the committed corpus.

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

The full set of CI jobs that gate a PR (CODING-STANDARDS.md §14):

| Job | Runtime budget | Required for merge |
|---|---|---|
| `fmt` | 30 s | yes |
| `clippy` (default features) | 5 min | yes |
| `clippy` (all features) | 5 min | yes |
| `test` (default features, unprivileged) | 5 min | yes |
| `test` (`--no-default-features`) | 5 min | yes |
| `test` (`root-tests`, privileged runner) | 10 min | yes |
| `build-offline-frozen-locked` | 5 min | yes |
| `verify-checksums-rust` | 30 s | yes |
| `verify-checksums-shell` | 30 s | yes (must agree with the Rust verifier) |
| `cargo-deny` | 1 min | yes |
| `cargo-audit` | 1 min | yes |
| `cargo-vet` | 1 min | yes |
| `docs` (cargo doc --no-deps, `-D warnings`) | 3 min | yes |
| `fuzz-smoke` (1 min per target) | 10 min | yes |
| `bpf-verifier-matrix` (per-kernel) | 15 min | yes |
| `reproducible-build` (release-track only) | 30 min | yes for release tags |

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

`kennel-audit` has a dedicated round-trip test: emit every event type to every sink, then read back from each sink, then compare against the canonical event. This catches sink-mapping drift cheaply.

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
