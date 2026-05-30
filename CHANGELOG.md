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
- **`nix` =0.31.3** adopted (§5.5-approved; reviewer remco), `default-features = false, features = ["user", "process"]`. Safe, typed syscall wrappers preferred over hand-rolled `unsafe` (§4, "don't roll your own `unsafe`"). Transitive: `bitflags` =2.11.1, `cfg-if` =1.0.4 (normal), `cfg_aliases` =0.2.1 (build). Each vendored and GitHub-provenance-checked (`tools/audit-source.sh`).
- **`bitflags` =2.11.1** promoted to a direct dependency of `kennel-syscall` (typed Landlock access-right sets); already approved as a nix transitive.

### Enforcement (kennel-syscall)

- **`unistd` credential wrappers** (`effective_uid`, `real_uid`) over `nix::unistd` — no `unsafe` of ours.
- **Hand-rolled Landlock** (`landlock` module): `AccessFs`/`AccessNet`, `abi_version`, ABI-support masking, and a `Ruleset` builder that seals the current process (`set_no_new_privs` via nix, then `restrict_self`). Chosen over the `landlock` crate to keep `syn`/proc-macros out of the privileged dependency tree; the ABI is taken from the kernel UAPI. `kennel-syscall` carries `#![allow(unsafe_code)]` with the `unsafe` confined to Landlock's six raw syscall wrappers (each §4-commented). A fork-based test confirms the seal denies an un-allowed path while permitting an allowed one.

### Licensing

- Adopted **Apache License 2.0** for the project (Rust crates, threat catalogue, design document, reference runtime). The BPF programs under `bpf/` remain GPL-2.0 (SPDX headers; required by the kernel for "GPL"-declaring programs). See `LICENSE` and `NOTICE`.

### Pending

- Reference runtime implementation (the Cargo workspace and crates described in `architecture/03-crate-decomposition.md`).
- The remaining §14 CI checks (Rust checksum verifier, `cargo deny`/`audit`/`vet`, fuzz, reproducible build, the BPF verifier-load matrix) that activate with their inputs.
