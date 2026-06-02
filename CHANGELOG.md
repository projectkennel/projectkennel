# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency updates (§5), MSRV changes (§2), and threat-catalogue additions are also recorded here.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-06-03

First versioned cut: all workspace crates set to `0.1.0` (centralised in `[workspace.package]`). Not yet git-tagged — the tag is a separate, deliberate release step. The reference runtime and the policy compiler are implemented (kernel 6.17, Landlock ABI ≥ 6). Everything below is the content of this cut.

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
- **data/cli/caps dependency batch** (§5.5-approved; reviewer remco) vendored ahead of use, all provenance-proven against GitHub via `tools/audit-source.sh`: direct `caps`, `serde`, `basic-toml`, `time`, `lexopt`; transitive serde proc-macro stack (`serde_core`/`serde_derive`/`proc-macro2`/`quote`/`syn`/`unicode-ident`), `time` (`itoa`/`time-core`/`time-macros`/`deranged`/`powerfmt`/`num-conv`). Chose `lexopt` over clap and `basic-toml` over toml to avoid their large trees.
- **`serde_json` dropped** (was vendored ahead of use, never wired in). The settled policy is TOML like every other config artefact — JSON's canonical form (sorted keys, normalised numbers) buys nothing when the same implementation signs and verifies, and the schema has no floats; the audit log's JSON Lines will be written by a small hand-rolled emitter. Removed its `.crate`, index entry, and `CHECKSUMS.toml` record.
- **`ed25519-compact` =2.3.0** adopted (§5.5-approved; reviewer remco), `default-features = false, features = ["std"]` — zero transitive deps. The Ed25519 verifier for `kennel-policy`; chosen over `ed25519-dalek` (≈9× the code) and `ring` (BoringSSL C/asm). Provenance proven against `github.com/jedisct1/rust-ed25519-compact` at tag 2.3.0.
- **`seccompiler` =0.5.0** adopted (§5.5-approved; reviewer remco), default features (no `json`/serde). The vetted `rust-vmm` seccomp-BPF filter compiler — hand-rolling BPF bytecode is the dangerous case (§4). No new transitives (only `libc`). Provenance proven against `github.com/rust-vmm/seccompiler` at tag v0.5.0 (`tools/audit-source.sh`).

### BPF loader (kennel-bpf)

- **Hand-rolled `bpf(2)` loader** over `libc`, using `object` (one crate) for ELF parsing — chosen over `libbpf-rs`/`libbpf-sys` (which vendor zlib+libelf+libbpf C, ~1435 files) and `aya` (19 crates). `kennel-bpf` is the workspace's second `unsafe` crate; the `unsafe` is five blocks in `sys.rs` (the `bpf()` syscall + `OwnedFd` wrap), each §4-commented. ELF parsing and relocation patching are safe.
- **`object` =0.36.7** adopted (§5.5-approved; reviewer remco), `default-features = false, features = ["read_core", "elf"]`; no new transitive (memchr already vendored). Provenance proven against `github.com/gimli-rs/object` at tag 0.36.7.
- A root-test compiles `connect4` against UAPI headers (no CO-RE), loads it through the loader, attaches it to a cgroup, and confirms it enforces (fail-closed on empty maps). Proves the approach: the programs need no CO-RE/BTF, so the loader resolves only `R_BPF_64_64` map relocations by symbol name against the `bpf/maps.h` ABI.

### Enforcement (kennel-syscall)

- **`unistd` credential wrappers** (`effective_uid`, `real_uid`) over `nix::unistd` — no `unsafe` of ours.
- **Hand-rolled Landlock** (`landlock` module): `AccessFs`/`AccessNet`, `abi_version`, ABI-support masking, and a `Ruleset` builder that seals the current process (`set_no_new_privs` via nix, then `restrict_self`). Chosen over the `landlock` crate to keep `syn`/proc-macros out of the privileged dependency tree; the ABI is taken from the kernel UAPI. `kennel-syscall` carries `#![allow(unsafe_code)]` with the `unsafe` confined to Landlock's six raw syscall wrappers (each §4-commented). A fork-based test confirms the seal denies an un-allowed path while permitting an allowed one.

### Runtime (kennel-spawn, kenneld, kennel-netproxy, kennel-privhelper)

- **The confinement seal** (`kennel-spawn`): `verify_settled` → substitute the
  per-instance placeholders → translate into a `Plan` → `spawn`, which seals the
  forked child before `execve` — mount/PID/IPC namespaces, a fresh `/proc` + private
  `/tmp`, the synthetic `/etc` binds, the constructed-`$HOME` view via `pivot_root`,
  the Landlock filesystem + network ruleset (built post-pivot; abstract-unix + signal
  scoping on ABI ≥ 6), the seccomp denylist, and cgroup join. Root e2e drives the
  whole vertical.
- **Per-kennel egress proxy** (`kennel-netproxy`): a blocking SOCKS5/HTTP proxy on
  the kennel's own v4+v6 loopback; the cgroup BPF fail-closed allowlist denies direct
  `connect()` to anything but the proxy; the proxy resolves names via the OS resolver
  and re-checks the answer against the allowlist + invariant denies. One JSONL audit
  record per request.
- **Per-user daemon + CLI** (`kenneld`): control socket (request/response), bring-up
  and teardown, the synthetic-`/etc` generator, the per-kennel egress audit-log file
  sink, and the dual-stack proxy config writer. The `kennel` client speaks to it over
  `SCM_RIGHTS` (stdio passed to the workload).
- **Privileged helper** (`kennel-privhelper`): setuid helper for address setup and
  BPF attach, with a tight wire protocol and dependency list; `panic = "abort"`.

### Policy compiler and CLI changes (kennel-policy, `kennel`)

- **`kennel compile`** resolves a source policy fully — template-chain folding (the
  SSH `=`/`+=`/`-=` model), additive signed `include` fragments (with conflict
  detection and fragment-declared invariants), leaf `add`/`remove`/`override` deltas,
  install-constant substitution, translation to the settled `EffectivePolicy`, and
  ed25519 signing — and emits a signed, byte-pinned settled policy + `kennel.lock`.
- **Trust is end-to-end ed25519**: templates, fragments, and the settled artefact are
  signed and verified; the lockfile pins each resolved reference by its signature (no
  separate content hash). `--require-signed` enforces the trust store.
- **Seccomp** translates a denylist by name; the spawn layer resolves names to numbers
  via `libc::SYS_*`, keeping the signed policy architecture-independent.
- New CLI verbs: **`compile`**, **`validate`**, **`sign`** (exit codes per
  `02-1-cli.md`). The template set under `templates/` (base-confined + the five
  executive-summary templates) compiles cleanly.

### Licensing

- Adopted **Apache License 2.0** for the project (Rust crates, threat catalogue, design document, reference runtime). The BPF programs under `bpf/` remain GPL-2.0 (SPDX headers; required by the kernel for "GPL"-declaring programs). See `LICENSE` and `NOTICE`.

### Supply-chain tooling

- **CI tool-install path** for the supply-chain gate. `cargo-deny`/`cargo-audit`/`cargo-vet` cannot be `cargo install`ed under the offline `.cargo/config.toml` (crates.io is replaced by the local registry), so they are installed from pinned, SHA-256-verified prebuilt binaries: `tools/ci-tools.toml` (the integrity manifest, mirroring `CHECKSUMS.toml`) + `tools/install-ci-tools.sh` (verifies each archive before extracting; refuses on mismatch). Pins maintainer-ratified (§5.5; reviewer remco), each cross-checked by an independent second download.
- **`deny.toml`** added: licence allow-list pinned to the 27-crate graph (`Apache-2.0`/`MIT`/`Unicode-3.0`), sources locked to the crates.io index only (no git, no other registry — §5.5 mechanised), multiple-versions/wildcards denied, advisories v2 with `yanked = deny`.
- New **`supply-chain` CI job** runs `cargo deny` + `cargo audit` via the install path (advisory/`continue-on-error` until observed green, then promoted to a required check). The `fuzz/` smoke job also runs. `cargo vet --locked` remains owed: its audit corpus (`supply-chain/audits.toml`) is unwritten.

### Pending

- Documented-but-deferred (`architecture/08-as-built-notes.md` §8.2): the
  journald/syslog/stdout audit sinks + unified audit writer (a per-kennel file sink
  exists), the IPC version handshake, the Rust `kennel-checksum-verify` (a shell
  witness exists), and container-runtime integration.
- Signing the shipped templates with a maintainer key (a key-custody decision).
- `cargo vet --locked` (audit corpus owed), the reproducible-build double-run, and the
  BPF verifier-load matrix — the §14 checks still awaiting their inputs.
- The workspace `repository` URL (`Cargo.toml`) is still `TBD`.
