# Build environment

The pinned build environment, referenced by [CODING-STANDARDS.md](CODING-STANDARDS.md) §2.2 (C/BPF toolchain) and `architecture/06-build-and-test.md`. Reproducible builds require the same compilers on every runner; this file is where their versions are pinned.

## Status

The reference runtime is not yet implemented; exact version pins below are marked *[TBD]* until the workspace and CI exist. The structure and intent are fixed.

## Rust toolchain

- **Development toolchain:** pinned in `rust-toolchain.toml` (stable channel, recent stable; no nightly, no `#![feature(...)]`). Contributors install via `rustup`, which honours the pin automatically.
- **MSRV:** declared in each crate's `Cargo.toml` `rust-version`; lags the development toolchain by no more than two stable releases. CI builds against both.

*[TBD: concrete pinned versions, set when the workspace is created.]*

## C / BPF toolchain

- **clang:** pinned version, used to compile `bpf/*.bpf.c` against the kernel UAPI (`<linux/bpf.h>`), **no CO-RE**. *[TBD final pin]* — first verify pass (2026-05-30) used clang 18.1.3 (Ubuntu). Requires the multiarch include path (`/usr/include/x86_64-linux-gnu`, for `<asm/types.h>`); `<linux/bpf.h>` comes from `linux-libc-dev`.
- **bpftool:** optional, for inspection and the (owed) verifier-load matrix. *[TBD final pin]* — first verify pass used bpftool v7.4.0 (libbpf 1.4). The programs load via `kennel-bpf`'s own `bpf(2)` loader, not bpftool.
- **No `vmlinux.h`, no libbpf, no aya.** The programs need no CO-RE (they touch only stable hook-context structs and our own maps), so there is no committed `vmlinux.h`. `kennel-bpf` loads them with a hand-rolled `bpf(2)` loader over `libc`, using only `object` (one §5.5-approved crate) for ELF parsing — see `bpf/README.md` and `DEPENDENCIES.md`. This deliberately avoids libbpf-rs/libbpf-sys (which vendor zlib+libelf+libbpf C, ~1435 files) and aya (19 crates).

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
- No kernel-version leak in BPF objects: they compile against the UAPI headers, not a kernel-specific CO-RE dump.
- The same clang and the same UAPI headers on both release runners.
