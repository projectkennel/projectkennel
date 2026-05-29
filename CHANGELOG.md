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

### Pending

- Reference runtime implementation (the Cargo workspace and crates described in `architecture/03-crate-decomposition.md`).
- CI pipeline (`CODING-STANDARDS.md` §14), git hooks (§15), and the supply-chain tooling (`tools/`).
- A chosen licence.
