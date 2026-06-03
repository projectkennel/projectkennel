# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency changes (§5), MSRV changes (§2), and threat-catalogue changes are also recorded here.

## [Unreleased]

Nothing yet.

## [0.1.0]

The first versioned cut (not yet git-tagged). Verified on Linux 6.17 (Landlock ABI 7; ABI ≥ 6 is required for native abstract-socket and signal scoping).

- **Confinement runtime.** `kennel run` brings a kennel up and tears it down when the workload exits: mount/PID/IPC namespaces, a constructed `$HOME` view via `pivot_root` (synthetic `/etc` and `/dev`, `/proc` with `hidepid=2`, private `/tmp`, writable binds resolving to persistent host inodes), a hand-rolled Landlock filesystem + network ruleset with ABI-6 abstract-socket and signal scoping, and a seccomp denylist.
- **Per-kennel egress proxy.** A blocking SOCKS5/HTTP proxy on the kennel's v4+v6 loopback; a cgroup-BPF fail-closed allowlist denies any direct `connect()` except to the proxy, which resolves names through the OS resolver and re-checks each answer against the policy. One JSON Lines audit record per request.
- **Policy compiler.** `kennel compile` resolves a source policy — template-chain fold (the SSH `=`/`+=`/`-=` model), signed `include` fragments, leaf deltas, install-constant substitution — into a signed, byte-pinned settled policy plus `kennel.lock`. `kennel validate` and `kennel sign` round out the CLI alongside `run`/`stop`/`list`.
- **End-to-end Ed25519 trust.** Templates, fragments, and the settled artefact are signed and verified; the lockfile pins each reference by signature — the deterministic signature *is* the content commitment, so there is no separate hash. The six reference templates are signed under the project key `kennel-maint-2026` (`keys/kennel-maint-2026.pub`).
- **Supply-chain gate.** Dependencies are vendored and checksum-pinned (`supply-chain/CHECKSUMS.toml`); the CI `supply-chain` job runs `cargo deny` + `cargo audit` + `cargo vet` via pinned, hash-verified tool binaries.
- **Licensing.** Apache-2.0 for the project; the BPF programs under `src/bpf/` are GPL-2.0 (SPDX headers, a kernel requirement for GPL-declaring programs).

Roadmap (designed, not yet built): the unified audit writer with journald/syslog/stdout sinks, the Rust `kennel-checksum-verify` twin of the shell witness, container-runtime integration, and the reproducible-build and BPF verifier-load CI matrices. See [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md).
