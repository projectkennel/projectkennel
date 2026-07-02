# Build environment

The pinned build environment, referenced by [CODING-STANDARDS.md](../governance/CODING-STANDARDS.md) §2.2 (C/BPF toolchain) and `docs/archive/architecture/06-build-and-test.md`. Reproducible builds require the same compilers on every runner; this file is where their versions are pinned.

## Status

The workspace is built and the reference runtime is verified on kernel 6.17 (Landlock ABI 7). The toolchains that gate every commit — the Rust toolchain and the hosted-CI BPF compile — are pinned and running. The pins that belong to the release pipeline (the digest-locked release-build image, and the multi-kernel verifier-load matrix) land with that infrastructure; they are listed under [Roadmap](#roadmap) rather than scattered through the sections below.

## Rust toolchain

- **Development toolchain:** `1.95.0`, pinned in `rust-toolchain.toml` (stable channel; no nightly, no `#![feature(...)]`). Contributors install via `rustup`, which honours the pin automatically; CI runs `rustup show` so the same toolchain installs there. The supply-chain tools (`cargo-deny`/`-audit`/`-vet`) run under it too.
- **MSRV:** `1.95`, declared once in `[workspace.package]` (`rust-version`) and inherited by every crate. The MSRV and the development toolchain coincide today; the standing rule is that the MSRV lags the development toolchain by no more than two stable releases. An MSRV-floor CI job is owed once the two diverge.

## C / BPF toolchain

- **clang:** compiles `bpf/*.bpf.c` against the kernel UAPI (`<linux/bpf.h>`), **no CO-RE**. The hosted `bpf-compile` CI job uses the runner's distribution clang (`-Wall -Wextra -Werror`, no version pin); the reproducible release build pins clang by version inside the release image (see Roadmap). Compilation requires the multiarch include path (`/usr/include/x86_64-linux-gnu`, for `<asm/types.h>`); `<linux/bpf.h>` comes from `linux-libc-dev`. The first verify pass (2026-05-30) used clang 18.1.3 (Ubuntu).
- **bpftool:** optional, for inspection and the verifier-load matrix (Roadmap). The programs load via `kennel-lib-bpf`'s own `bpf(2)` loader, not bpftool. The first verify pass used bpftool v7.4.0 (libbpf 1.4).
- **No `vmlinux.h`, no libbpf, no aya.** The programs need no CO-RE (they touch only stable hook-context structs and our own maps), so there is no committed `vmlinux.h`. `kennel-lib-bpf` loads them with a hand-rolled `bpf(2)` loader over `libc`, using only `object` (pinned `=0.36.7`, one §5.5-approved crate) for ELF parsing — see `bpf/README.md` and `DEPENDENCIES.md`. This deliberately avoids libbpf-rs/libbpf-sys (which vendor zlib+libelf+libbpf C, ~1435 files) and aya (19 crates).

## Binder

- **Kernel config:** the binder driver must be present — `CONFIG_ANDROID_BINDERFS` and `CONFIG_ANDROID_BINDER_IPC`, either `=y` or `=m` (as a module, `binder_linux` must be loaded or auto-loadable on first `mount -t binder`). Every kennel runs a per-instance binderfs bus as its inter-namespace control plane, so this is a hard prerequisite, not an option; `kennel check` reports an unavailable driver as fatal (`02-4-binder.md` §Kernel requirements). These ship as modules (`=m`) on mainstream distributions — Ubuntu's 6.17 kernel carries `CONFIG_ANDROID_BINDERFS=m` and `CONFIG_ANDROID_BINDER_IPC=m`.
- **Binder UAPI headers:** `kennel-lib-binder` compiles against the stable kernel UAPI directly — `<linux/android/binder.h>` and `<linux/android/binderfs.h>` (from `linux-libc-dev`), no CO-RE, the same posture as `bpf/` against `<linux/bpf.h>`. The protocol floor is binder version 8 (`kennel-lib-binder` checks `BINDER_VERSION` at open).
- **Privhelper file caps:** the privhelper is the construction factory — it clones the namespaces, writes the identity uid/gid maps (`0 0 1` + operator), builds the root-owned surfaces, mounts binderfs, and `fexecve`s `kennel-bin-init`. Its file caps are `cap_setuid`, `cap_setgid`, `cap_setfcap`, and `cap_sys_admin` (`cap_setuid`/`cap_setfcap` are required for the `0 0 1` map write under `CAP_SETFCAP`; `02-4-binder.md`, `07-2-kennel-bin-init.md`). The rare host-context operations are not on the factory — `cap_net_admin`/`cap_bpf`/`cap_perfmon` live in the single-purpose sub-helpers (`kennel-privhelper-net`/`-bpf`/`-mounts`) the factory execs on demand. The release build sets these via `setcap` on the installed binaries.
- **`kennel-bin-init`:** a root-owned, non-writable binary installed in libexec (the kennel's trusted uid-0 PID 1). The privhelper opens it pre-clone and `fexecve`s it; its provenance — root ownership and non-writability — is verified before exec, so the build/install must preserve those permissions.

## Reproducibility inputs

- `SOURCE_DATE_EPOCH` honoured; no build timestamps embedded.
- No host paths in binaries (`--remap-path-prefix`).
- No kernel-version leak in BPF objects: they compile against the UAPI headers, not a kernel-specific CO-RE dump.
- The same clang and the same UAPI headers on both release runners.

## Roadmap

These pins are part of the release pipeline and land with it. Until then the hosted CI gate (above) is authoritative for what every commit is checked against.

- **Release-build container.** Release builds run in a container image pinned by digest, whose recipe lives in `tools/release-image/`. The image holds the pinned Rust toolchain, a pinned clang, bpftool, and the coreutils `sha256sum` the shell checksum verifier uses. Release builds run twice on two runners and compare output hashes (`docs/archive/architecture/06-build-and-test.md`). The recipe, the digest, and clang's in-image version pin are set when the image is created.
- **Verifier-load kernel matrix.** Beyond the hosted compile check, CI loads each BPF program through the verifier on a matrix of kernels (`docs/archive/architecture/06-build-and-test.md`, `02-7-bpf-abi.md`); verifier rejection on any entry blocks merge. The project floor is **6.10** (required for Landlock `FS_EXECUTE`; §8.2). The concrete latest-LTS / current-stable / latest-mainline entries are fixed when the custom-kernel runners that host the matrix exist.
