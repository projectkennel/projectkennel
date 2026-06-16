# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency changes (§5), MSRV changes (§2), and threat-catalogue changes are also recorded here.

## [Unreleased]

### CLI changes

- `kennel attach <name>` — reconnect a terminal to a running interactive kennel. An interactive `kennel run` is now **detachable**: kenneld owns the controlling pty and brokers it, so `Ctrl-\ d` detaches without ending the workload and `attach` reconnects (the tmux/`docker attach` model; one PTY, take-over on reattach). `kennel list` gains a `CLIENT` (attached/detached) column.
- `kennel review <policy>` — operator sign-off that re-pins a workspace's `.trust-manifest.json` after legitimate edits (the confined workload cannot, as the manifest is masked).
- The installer (`install.sh`) runs the post-install checks itself and prints a copy-pastable per-user bring-up; `--provision-users [GROUP]` allocates `/etc/kennel/subkennel` lines for a group.

### Policy schema changes

- `[tty].filter_terminal_escapes` (default `true`) — filter dangerous terminal escapes (OSC 52 clipboard, OSC 9/777 notifications, DCS/APC/PM/SOS) from the workload's PTY output at the broker (T2.6).
- `[trust].manifest` (default `true`) — maintain a masked `.trust-manifest.json` at each writable root so host tooling can detect workspace-trigger tampering (T2.8).

### Other

- Egress now refuses literal special-use destinations (loopback/ULA/RFC1918/link-local), closing the per-kennel inbound-mirror lateral edge (design §7.5.2, T1.6).
- The privhelper loads `binder_linux` if the `binder` filesystem is absent, so binderfs mounts on hosts where the module is not auto-loaded.
- **Website.** `projectkennel.org` is published from `docs/website/` via GitHub Pages, serving the landing page and the trust-manifest JSON Schema at the `$id` path shipped code references.
- **Docs.** Corrected `supply-chain/UNSAFE-CRATES.md` (it listed two `unsafe`-bearing crates; there are five — `kennel-lib-syscall`/`-landlock`/`-bpf`/`-binder`/`-scm` — and described modules since moved out of `kennel-lib-syscall`). README refreshed to the current CLI/feature set.

## [0.1.0]

The first versioned cut (not yet git-tagged). Verified on Linux 6.17 (Landlock ABI 7; ABI ≥ 6 is required for native abstract-socket and signal scoping).

- **Confinement runtime.** `kennel run` brings a kennel up and tears it down when the workload exits: mount/PID/IPC namespaces, a constructed `$HOME` view via `pivot_root` (synthetic `/etc` and `/dev`, `/proc` with `hidepid=2`, private `/tmp`, writable binds resolving to persistent host inodes), a hand-rolled Landlock filesystem + network ruleset with ABI-6 abstract-socket and signal scoping, and a seccomp denylist.
- **Per-kennel egress proxy.** A blocking SOCKS5/HTTP proxy on the kennel's v4+v6 loopback; a cgroup-BPF fail-closed allowlist denies any direct `connect()` except to the proxy, which resolves names through the OS resolver and re-checks each answer against the policy. One JSON Lines audit record per request.
- **Policy compiler.** `kennel policy compile` resolves a source policy — template-chain fold (the SSH `=`/`+=`/`-=` model), signed `include` fragments, leaf deltas, install-constant substitution — into a signed, byte-pinned settled policy plus `kennel.lock`. The `kennel policy` group also provides `validate`, `sign`, `list`, `show`, `edit`, `generate`, and `lint`, alongside top-level `run`/`stop`/`list`. An optional `[workload]` stanza pins the command (argv/cwd, optional `pinned`, optional `sha256` allowlist) into the signed policy; `net.mode` is one of `none`/`constrained`/`unconstrained`/`host`.
- **End-to-end Ed25519 trust.** Templates, fragments, and the settled artefact are signed and verified; the lockfile pins each reference by signature — the deterministic signature *is* the content commitment, so there is no separate hash. The six reference templates are signed under the project key `kennel-maint-2026` (`keys/kennel-maint-2026.pub`).
- **Supply-chain gate.** Dependencies are vendored and checksum-pinned (`supply-chain/CHECKSUMS.toml`); the CI `supply-chain` job runs `cargo deny` + `cargo audit` + `cargo vet` via pinned, hash-verified tool binaries.
- **Licensing.** Apache-2.0 for the project; the BPF programs under `src/bpf/` are GPL-2.0 (SPDX headers, a kernel requirement for GPL-declaring programs).

Roadmap (designed, not yet built): the unified audit writer with journald/syslog/stdout sinks, the Rust `kennel-checksum-verify` twin of the shell witness, container-runtime integration, and the reproducible-build and BPF verifier-load CI matrices. See [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md).
