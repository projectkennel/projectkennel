# Build environment

The pinned build environment, referenced by [CODING-STANDARDS.md](CODING-STANDARDS.md) §2.2 (C/BPF toolchain) and `architecture/06-build-and-test.md`. Reproducible builds require the same compilers on every runner; this file is where their versions are pinned.

## Status

The reference runtime is not yet implemented; exact version pins below are marked *[TBD]* until the workspace and CI exist. The structure and intent are fixed.

## Rust toolchain

- **Development toolchain:** pinned in `rust-toolchain.toml` (stable channel, recent stable; no nightly, no `#![feature(...)]`). Contributors install via `rustup`, which honours the pin automatically.
- **MSRV:** declared in each crate's `Cargo.toml` `rust-version`; lags the development toolchain by no more than two stable releases. CI builds against both.

*[TBD: concrete pinned versions, set when the workspace is created.]*

## C / BPF toolchain

- **clang:** pinned version, used to compile `bpf/*.bpf.c` with CO-RE relocations. *[TBD final pin]* — first verify pass (2026-05-30) used clang 18.1.3 (Ubuntu).
- **bpftool:** pinned version, used for skeleton generation and the verifier matrix. *[TBD final pin]* — first verify pass used bpftool v7.4.0 (libbpf 1.4).
- **libbpf:** vendored as `crates-archive/libbpf-<version>.tar.gz`, hash in `CHECKSUMS.toml`. Not linked from the system. *[TBD: version]* — first verify pass used the system libbpf 1.3.0 headers; vendoring is owed when `kennel-bpf` lands.
- **vmlinux.h:** committed at `bpf/vmlinux.h`, generated once from a specific kernel via `bpftool btf dump`. Regenerating it is a maintainer-only operation with a PR documenting the source kernel.
  - **Source kernel (current copy):** Linux 6.8.0-110-generic, x86_64, Ubuntu 24.04.4 LTS. Generated 2026-05-30 from `/sys/kernel/btf/vmlinux` (BTF 6094376 bytes). `sha256(bpf/vmlinux.h) = 9f1fafdf44f1da0bee79c6357c9eea4c3958f0e3a38e02e65703ead58a5104ea`.
  - Note: this kernel is *below* the 6.10 project floor (see Kernel matrix). CO-RE makes the dumped types portable, so it is an acceptable build-time type source, but the canonical committed copy should be regenerated from a ≥6.10 kernel when the CI matrix is stood up.

## Kernel matrix (BPF verifier tests)

The kernel versions CI loads the BPF programs against (`architecture/06-build-and-test.md`, `02-5-bpf-abi.md`). Verifier rejection on any entry blocks merge.

- Project floor: **6.10** (required for Landlock `FS_EXECUTE`; design doc §8.2).
- Latest LTS *[TBD: concrete version]*.
- Current stable *[TBD]*.
- Latest mainline *[TBD]*.

## Release-build container

Release builds run in a container image pinned by digest, whose recipe lives in `tools/release-image/` *(not yet created)*. The image holds the pinned Rust toolchain, clang, bpftool, and the coreutils `sha256sum` used by the shell checksum verifier. Release builds run twice on two runners and compare output hashes (`architecture/06-build-and-test.md`).

- **Image digest:** *[TBD]*
- **Recipe:** `tools/release-image/` *[TBD — created with the implementation]*

## Reproducibility inputs

- `SOURCE_DATE_EPOCH` honoured; no build timestamps embedded.
- No host paths in binaries (`--remap-path-prefix`).
- No kernel-version leak in BPF objects beyond what `vmlinux.h` declares.
- The same clang and the same `vmlinux.h` on both release runners.
