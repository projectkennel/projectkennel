# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project will adopt semantic versioning at its first release.

Per [CODING-STANDARDS.md](CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency updates (§5), MSRV changes (§2), and threat-catalogue additions are also recorded here.

## [Unreleased]

The project is in its documentation and design stage. No releases yet; no runtime code yet. This section accumulates notable changes until the first tagged release.

### Documentation and design

- Threat catalogue (`THREATS.md`) and design document (`docs/`) at v0.1.
- Implementation architecture (`architecture/`): process model, API surfaces (CLI, config schema, audit schema, IPC, BPF ABI, internal API), crate decomposition, trust boundaries, state and supervision, build and test, paths.
- Engineering standards (`CODING-STANDARDS.md`), contribution guide (`CONTRIBUTING.md`), and PR template.
- Versioned, signed template references (`name@version`) with content-covering signatures and a byte-pinning lockfile (design §5.10).
- Compilation model: a `kennel compile` step produces a signed *settled policy* the runtime enforces, replacing live per-spawn resolution (design §9.10).
- Governance scaffolding: this file, `README.md`, `SECURITY.md`, `MAINTAINERS.md`, `CONTRIBUTORS.md`, `CODE_OF_CONDUCT.md`, and the dependency ledgers (`DEPENDENCIES.md`, `CHECKSUMS.toml`, `RELEASE-WATCH.toml`, `KEYS.md`, `UNSAFE-CRATES.md`, `BUILD-ENV.md`).

### Dependencies

- **First dependency adopted: `libc` =0.2.186** (§5.5-approved; reviewer remco). Vendored to `crates-archive/` as a cargo local registry (`.cargo/config.toml` replaces crates.io); recorded in `CHECKSUMS.toml`, `DEPENDENCIES.md`, `RELEASE-WATCH.toml`. Provenance verified independent of crates.io against the GitHub source at tag 0.2.186 (`tools/audit-source.sh`). No transitive deps.
- `kennel-syscall` is now the workspace's active `unsafe` crate (`#![allow(unsafe_code)]`); its first `unsafe` is the `unistd` credential wrappers over libc (`UNSAFE-CRATES.md`).

### Licensing

- Adopted **Apache License 2.0** for the project (Rust crates, threat catalogue, design document, reference runtime). The BPF programs under `bpf/` remain GPL-2.0 (SPDX headers; required by the kernel for "GPL"-declaring programs). See `LICENSE` and `NOTICE`.

### Pending

- Reference runtime implementation (the Cargo workspace and crates described in `architecture/03-crate-decomposition.md`).
- The remaining §14 CI checks (Rust checksum verifier, `cargo deny`/`audit`/`vet`, fuzz, reproducible build, the BPF verifier-load matrix) that activate with their inputs.
