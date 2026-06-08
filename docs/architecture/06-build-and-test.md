# Build and test architecture

This chapter describes how the workspace is built, what the dependency graph looks like at build time, and how the test suite is structured. It is paired with CODING-STANDARDS.md §2 (toolchain pinning), §5 (dependency policy), §7 (test discipline), and §14 (CI gate); this chapter is the project-specific *application* of those rules.

---

## Build inputs

A build needs:

- Rust toolchain pinned by `rust-toolchain.toml` (installed via `rustup`).
- Clang at the version pinned in `BUILD-ENV.md` (for BPF compilation against the kernel UAPI, no CO-RE).
- The kernel UAPI headers (`linux-libc-dev`: `<linux/bpf.h>` plus the multiarch `<asm/types.h>` path) at the version pinned in `BUILD-ENV.md`.
- `bpftool` is **optional** (inspection and the verifier-load matrix only); the loader does not depend on it.
- The binder kernel feature for the binder test path: `CONFIG_ANDROID_BINDERFS` + `CONFIG_ANDROID_BINDER_IPC` (`=y` or a loaded/auto-loadable `binder_linux` module) and the binder UAPI headers (`linux/android/{binder,binderfs}.h`), pinned in `BUILD-ENV.md`. The plain `cargo build` does not need binder (the `kennel-binder` ABI crate compiles against vendored UAPI constants); the *test* path that mounts binderfs does (see the binder load/test matrix below).
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

1. **Vendor verification.** `src/tools/verify-checksums.sh` confirms `src/vendor/` matches `CHECKSUMS.toml` and `Cargo.lock`. The Rust verifier twin (`kennel-checksum-verify`, needing vendored `sha2`) is a contingent §5.5.1 call, not yet built; the shell script is the implementation.
2. **BPF compilation.** `kennel-bpf`'s `build.rs` invokes clang against `bpf/*.bpf.c`, producing `*.bpf.o` files in `OUT_DIR`. Each `.bpf.c` includes `<linux/bpf.h>` (kernel UAPI) and `bpf/maps.h`; **no** `vmlinux.h`, no CO-RE relocations. The `.o` is embedded into the crate; map references are left as ELF relocations the loader resolves at load time.
3. **Rust compilation.** `cargo build --workspace` builds every crate. The workspace is fifteen crates: `kennel-syscall`, `kennel-text`, `kennel-policy`, `kennel-bpf`, `kennel-audit`, `kennel-config`, `kennel-netproxy`, `kennel-privhelper`, `kennel-spawn`, `kennel-ssh-reorigin`, `kennel-socks-connect`, `kennel-afunix-shim`, `kennel-binder` (the unsafe binder ABI crate, parallel to `kennel-bpf`), `kennel-init` (the root-owned PID-1 supervisor binary, `07-2-kennel-init.md`), and `kenneld` (which also produces the `kennel` CLI binary alongside the `kenneld` daemon, in its `src/bin/`). The roadmap `kennel-netshim` crate (`02-8-binder-net.md`) is not yet present. Order is computed by Cargo from each member's `[dependencies]` (there is no `[workspace.dependencies]` table — members pin their own external versions); the lower-layer crates (`kennel-syscall`, `kennel-text`) are built before higher layers (`kennel-spawn`, `kennel-init`, `kenneld`). The full per-crate decomposition lives in `03-crate-decomposition.md`.
4. **Binary stripping** (release only). `strip = "symbols"` in the release profile. A separate `release-with-debuginfo` profile producing parallel debug-info binaries under `target/release-with-debuginfo/` for distributions that want a `.debug` package is **roadmap** — only `[profile.release]` is defined today.
5. **Reproducibility check** (release-build CI only). Designed so the release builds twice on two different runners and the output hashes must match. **Roadmap**: this double-build is not yet wired (it needs the pinned release image), and `cargo build --offline --frozen --locked` is the only build command in the per-PR gate.

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

`#[cfg(test)] mod tests` blocks beside the code, in every crate. Per CODING-STANDARDS.md §7.5:

- Fast: every unit test in the workspace should run in well under a second total.
- Isolated: no network, no `$HOME`, no shared state.
- Comprehensive: success, every error variant, every panic condition, boundaries, adversarial input (§7.4).

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
- `kennel-binder::proto::parse` / `TransactionData::from_bytes` / `flat_binder_object_fd_value` — the binder driver-return (`BC`/`BR`) command stream and the sender-controlled transaction payload the kernel fills into the read buffer (`02-7-binder.md`).
- `kennel-spawn::wire` — the `Plan` decoder. The same flat encoding crosses two privilege boundaries on input the operator built (the privhelper `ConstructKennel` op payload and the `kennel-init` `GET_SANDBOX_PLAN` `BC_REPLY` payload, `07-2-kennel-init.md`); the decoder is bounded by construction. **Owed:** adding it to `fuzz_parsers` (the codec exists and is bounds-checked; the harness entry is the remaining wiring).
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

### Binder load/test matrix

The binder transport (`kennel-binder`, `02-7-binder.md`) needs a kernel with `CONFIG_ANDROID_BINDERFS` + `CONFIG_ANDROID_BINDER_IPC` (built in, or a loaded/auto-loadable `binder_linux` module) and `FS_USERNS_MOUNT`, so its mount/open/transaction path is exercised on a real driver, not in isolation. The matrix mounts a per-instance binderfs inside a child user namespace, allocates the `binder` device, checks `BINDER_VERSION` (protocol version 8), and drives a node-0 transaction round trip. This is covered as part of the construction-path e2e and the `root-tests` runner below (it shares their privileged runner and the same kernel matrix as the BPF verifier job); a kernel missing the binder driver skips the binder tests rather than failing (the `kennel check` posture, `02-7-binder.md` §Kernel requirements).

---

## CI jobs

`.github/workflows/ci.yml` defines **five jobs**, each a sequence of steps on a hosted `ubuntu-latest` runner. The jobs and their steps:

| Job | Steps |
|---|---|
| `rust` | `cargo fmt --all -- --check`; `cargo clippy --all-targets --all-features -D warnings`; `cargo test --all-features`; `cargo test --no-default-features`; `cargo build --offline --frozen --locked`; `cargo doc --no-deps` (`RUSTDOCFLAGS=-D warnings`). |
| `bpf-compile` | Compile every `bpf/*.bpf.c` program against the kernel UAPI with `clang -Wall -Wextra -Werror -target bpf` (the compile-regression gate; the verifier-load matrix is owed, see below). |
| `fuzz` | Clippy and `cargo test` the separate `src/fuzz/` workspace, `--offline --locked` (the no-panic corpus across every untrusted-input parser). |
| `supply-chain` | Install the pinned, hash-verified `cargo-deny`/`-audit`/`-vet` binaries, then `cargo deny --all-features check`, `cargo audit --deny warnings`, `cargo vet --locked`. |
| `tooling` | The shell checksum witness (`src/tools/verify-checksums.sh`) and the hook/tool shell tests. |

The `rust` job folds what would otherwise be separate fmt/clippy/test/build/doc jobs into one runner's step sequence; a step failure fails the job. All five jobs gate a PR.

Owed, and **not** yet in CI (tracked in the workflow header): the Rust checksum verifier twin (needs `sha2`, §5.5.1), the reproducible-build double-build (needs the release image), the BPF verifier-load matrix on custom-kernel runners (the `bpf-compile` job is the hosted-runner compile part), a privileged `root-tests` runner (which is also where the binder load/test matrix and the unprivileged construction-path e2e run), and the construction-path e2e itself. CI must not claim to run a check it does not.

**Roadmap CI additions** (designed, not built — the network-namespace redesign of `02-8-binder-net.md` / `07-11-binder-netns.md` is not built; the kennel still shares the host network namespace): root tests for the per-kennel net-ns path (`CLONE_NEWNET`, the four network modes, the loopback mirror, the host-side leg, `AddLoopbackAlias`/`RemoveLoopbackAlias`); and a fuzz target for the `kennel-netshim` SOCKS5 front-end once that crate exists. The `kennel-binder` `BC`/`BR` decoder fuzz target is *already* wired into the `fuzz` job (it is built), not roadmap.

CI is configured in `.github/workflows/`. The configuration is reviewed under the same discipline as code (CODING-STANDARDS.md §14).

---

## Local development loop

A developer pre-pushes locally via `src/tools/install-hooks.sh`, which sets up the pre-commit and pre-push hooks per CODING-STANDARDS.md §15.

The hooks run the *fast subset* of CI:

- pre-commit: `cargo fmt --check` (workspace), scoped clippy, secret-pattern scan, file-size sanity, `src/vendor`/`CHECKSUMS.toml` consistency.
- pre-push: full clippy, full test, offline build, the shell checksum verifier (`src/tools/verify-checksums.sh`; the hook probes for a Rust `kennel-checksum-verify` twin and skips it while that remains owed).

The hooks do not run the BPF verifier matrix (no kernel-VM setup on the developer's machine) or the reproducible-build check (single-runner). Those run in CI.

---

## Test placement decisions

A few specific placement choices:

### Root-required tests

A subset of integration tests need root for namespace operations, cgroup creation, Landlock sealing on a real kernel, and BPF attach. As built these live in each crate's flat `tests/` directory — `kennel-privhelper/tests/ipc.rs`, `kenneld/tests/e2e.rs`, `kenneld/tests/akc_openssh.rs`, `kennel-syscall/tests/landlock_exec_semantics.rs` — guarded at runtime/`#[cfg(feature = "root-tests")]` rather than collected under a `tests/root/` subdirectory.

The `root-tests` feature is defined **per crate** (`kennel-spawn`, `kennel-bpf`, `kennel-syscall`, `kennel-privhelper`, `kenneld`), not at the workspace level; it transitively enables `embed-programs`/`bpf-egress`. The real invocation is per crate, e.g. `sudo -E env PATH=$PATH cargo test -p kennel-privhelper --features root-tests`. CI exercises the privileged paths via the all-features build (`cargo test --all-features`); a dedicated privileged `root-tests` runner is owed (see the CI-jobs section).

The CI runner for `root-tests` is privileged but ephemeral: a container or VM that exists only for the duration of the test run, with a fresh kernel, and no persistent state.

### The unprivileged construction-path e2e

`src/tools/unprivileged-e2e.sh` drives the full vertical of the privhelper *factory* construction model (`07-2-kennel-init.md`, `02-7-binder.md`): an unprivileged, identity-mapped user namespace constructs the kennel, the privhelper mounts the per-instance binderfs and chowns the device, kenneld claims node 0 and serves the registry, `kennel-init` pulls its `GET_SANDBOX_PLAN` over the bus, and the brokered `org.projectkennel.IAfUnix/default` facade returns a connected fd. The spawn itself runs unprivileged; the script's `sudo` steps are the deployment prerequisites (reversible and local):

- `sudo setcap cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid,cap_setfcap=ep` on the privhelper. `cap_setuid` is the factory writing the `0 0 1` host-root line of the kennel's identity uid_map; **`cap_setfcap` is *also* required since Linux 5.12 to map host uid 0 into a new user namespace** (otherwise the `0 0 1` write is `EPERM` even for a privileged process). These join the privhelper's existing `cap_setgid` / `cap_sys_admin` / `cap_net_admin` (`07-paths.md`). This is the deployed `setcap` line, not a test-only artefact.
- A temporary **AppArmor `userns` profile** over the spawning binary *and* over the privhelper, matching the production `dist/apparmor/kenneld`. On distributions that set `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu), an unprivileged `CLONE_NEWUSER` transitions the new userns to the restricted `unprivileged_userns` profile, which forbids mapping host uid 0 in; the `flags=(unconfined) { userns, }` profile (it only *grants* `userns`; an enforcing profile cannot work because the spawn sets `no_new_privs` before exec'ing the workload, under which AppArmor denies every profile transition) makes the created userns "privileged" so host root can be mapped. The profile is unloaded on exit.

The script builds the participants it needs (`kennel-init`, the facade/proxy binaries, the test binary) and is the as-built proof for the binder construction vertical. Its privileged variant shares the `root-tests` runner; the owed privileged CI runner (below) is where it runs in CI.

### Mock vs real

Where possible, use the real thing. Per CODING-STANDARDS.md (the testing-philosophy callout in §7 is implicit but consistent): integration tests use real files in `tempfile::tempdir`, real Unix sockets, real BPF programs against real cgroups (in the root-tests subset). Mocks are reserved for cases where the real dependency is genuinely unavailable (e.g., a CI machine without a recent enough kernel — in which case the test is skipped, not mocked).

### The audit-writer test

Audit events are JSON Lines: one well-formed JSON object per line, every string value escaped through `kennel-text` so no raw control bytes reach the sink. `kennel-netproxy`'s audit module (and the daemons that write their own events) own the sink — a file under the kennel's state dir, or an fd kenneld passed. The test discipline is a render-and-reparse round trip: emit every record type, then parse each line back and compare against the canonical event, which catches escaping and field-mapping drift cheaply.

---

## Reproducible builds

**Status: roadmap.** This section describes the designed release-build process; none of the machinery below (`SOURCE_DATE_EPOCH` pin, `--remap-path-prefix`, the `release-with-debuginfo` profile, the double-build hash compare) is wired today, and the reproducible-build job is not in CI pending the pinned release image. No `SOURCE_DATE_EPOCH` or `--remap-path-prefix` appears in any `Cargo.toml` or workflow yet.

Release builds are designed to run twice on two different CI runners. The build process:

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
- The container image used for release builds: `BUILD-ENV.md` (the `release-image/` recipe directory is owed alongside the release image itself).
- The set of clippy lints denied: CODING-STANDARDS.md §12.2.
- The dep audit cadence: CODING-STANDARDS.md §5.6, §5.7.
