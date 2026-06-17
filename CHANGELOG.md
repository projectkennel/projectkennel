# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency changes (§5), MSRV changes (§2), and threat-catalogue changes are also recorded here.

## [Unreleased]

### CLI changes

- `kennel policy diff <policy> [<other>]` — the interpreted grant delta between two
  effective policies (the semantic counterpart of `policy upgrade`'s source line diff,
  `05-templates.md` §5.11/§5.13). One argument diffs a policy against its template
  baseline (what the leaf's deltas add over the template it inherits); two diff any
  pair. Each change is classified `+`/`~`/`-`, marked when it widens the workload's
  reach, and annotated with the threats it exposes/mitigates plus a net threat-posture
  delta. Terminal output is sanitised (`sanitise_for_log`); `--json` emits the delta via
  `serde_json`. Read-only; never contacts the daemon.
- `kennel policy risks` now evaluates a **delta-leaf** policy (`[[fs.read.add]]`, …), not
  only a template/source document — both verbs share the `effective_source` fold that
  folds either form to its threat-bearing effective source.

### Internal / supply chain

- **The `kennel` CLI is now its own crate (`kennel-cli`), split out of `kenneld`.** The
  control-socket wire protocol moves to a shared `kennel-lib-control` crate (re-exported
  as `kenneld::{control, socket}`, so the daemon side is unchanged). This removes the
  CLI's dependencies — `serde_json` (≈ 16.5k SLOC, via the trust-manifest reader) and
  `lexopt` — from the privileged daemon's dependency closure entirely: a hard crate
  boundary in place of the previous "the daemon binary happens not to reference them".
  No change to the `kennel` or `kenneld` binaries' behaviour or surface.
- **The policy compiler is split out of the runtime crate.** `kennel-lib-policy` keeps the
  runtime verify-and-load half (settled types, `verify_settled`/`sign_settled`,
  `parse_audit_defaults`, invariant re-assertion — ~1.7k SLOC); the new
  `kennel-lib-compile` crate holds the authoring front end (source schema, template
  resolution, leaf deltas, translation, source signing, lockfile, lint, risks) and is
  linked only by `kennel-cli`. `cargo tree -p kenneld` shows zero `kennel-lib-compile` —
  the ~3.5k-SLOC compiler is now a hard crate boundary out of the daemon's TCB. The
  `[audit]` schema + translation are centralised in one module (single source of truth,
  shared by the compiler and the runtime `audit.toml` reader).
- **Leaf-binary crates consolidated** (24 → 21 workspace crates, no behaviour change): the
  four in-kennel facades become one `kennel-facade` crate (four binaries), and the two
  host-side delegates become one `kennel-host-delegate` crate (two binaries + the shared
  conduit-wire library). Binary names are unchanged.

## [0.1.0] — 2026-06-16

The first versioned cut. Verified on Linux 6.17 (Landlock ABI 7; ABI ≥ 6 is required for native abstract-socket and signal scoping). Pre-release: interfaces and guarantees may change.

### CLI

- `run`/`attach`/`review`/`stop`/`list` plus the `policy` group. An interactive `kennel run` is **detachable**: kenneld owns the controlling pty and brokers it, so `Ctrl-\ d` detaches without ending the workload and `kennel attach <name>` reconnects (the tmux/`docker attach` model; one PTY, take-over on reattach). `kennel review <policy>` is the operator sign-off that re-pins a workspace's `.trust-manifest.json` after legitimate edits. `kennel list` shows a `CLIENT` (attached/detached) column.
- The installer (`install.sh`) runs the post-install checks itself and prints a copy-pastable per-user bring-up; `--provision-users [GROUP]` allocates `/etc/kennel/subkennel` lines for a group.

### Policy schema

- `[tty].filter_terminal_escapes` (default `true`) — filter dangerous terminal escapes (OSC 52 clipboard, OSC 9/777 notifications, DCS/APC/PM/SOS) from the workload's PTY output at the broker (T2.6).
- `[trust].manifest` (default `true`) — maintain a masked `.trust-manifest.json` at each writable root so host tooling can detect workspace-trigger tampering (T2.8).
- `[workload]` pins the command (argv/cwd, optional `pinned`, optional `sha256` allowlist) into the signed policy; `net.mode` is one of `none`/`constrained`/`unconstrained`/`host`.

### Runtime & enforcement

- **Confinement runtime.** `kennel run` brings a kennel up and tears it down when the workload exits: mount/PID/IPC namespaces, a constructed `$HOME` view via `pivot_root` (synthetic `/etc` and `/dev`, `/proc` with `hidepid=2`, private `/tmp`, writable binds resolving to persistent host inodes), a hand-rolled Landlock filesystem + network ruleset with ABI-6 abstract-socket and signal scoping, and a seccomp denylist. The whole spawn vertical runs **unprivileged** via an identity-mapped user namespace; the only privileged component is the file-capabilities privhelper (loopback addresses, egress BPF, `gid_map` write). It loads `binder_linux` if the `binder` filesystem is absent, so binderfs mounts on hosts where the module is not auto-loaded.
- **Per-kennel egress proxy.** A blocking SOCKS5/HTTP proxy on the kennel's v4+v6 loopback; a cgroup-BPF fail-closed allowlist denies any direct `connect()` except to the proxy, which resolves names through the OS resolver and re-checks each answer against the policy. The decision refuses literal special-use destinations (loopback/ULA/RFC1918/link-local), closing the per-kennel inbound-mirror lateral edge (T1.6). One JSON Lines audit record per request.
- **Masked workspace manifest (T2.8).** A `.trust-manifest.json` at each writable root pins the SHA-256 of host-side execution triggers; the spawn view masks it invisible to the workload (an empty over-mount inside the writable bind), so a confined agent can rewrite a trigger but cannot forge its pin. Host tooling reads the real manifest; `kennel review` re-pins after legitimate edits.
- **AF_UNIX shim and SSH re-origination bastion.** A socket shim brokers granted `AF_UNIX` connects; per-kennel SSH routes through a forced-command bastion so the workload holds no key or agent socket (the double-blind design, §7.10).
- **Audit.** A unified `kennel-lib-audit` writer (one canonical event schema, one sanitisation pass, per-class levels) fanning out to file/stdout/syslog/journald sinks; the signed `[audit]` policy section selects them over installation and per-user `audit.toml` defaults.
- **Policy compiler.** `kennel policy compile` resolves a source policy — template-chain fold (the SSH `=`/`+=`/`-=` model), signed `include` fragments, leaf deltas, install-constant substitution — into a signed, byte-pinned settled policy plus `kennel.lock`. The `kennel policy` group also provides `validate`, `sign`, `list`, `show`, `edit`, `generate`, and `lint`.
- **End-to-end Ed25519 trust.** Templates, fragments, and the settled artefact are signed and verified; the lockfile pins each reference by signature — the deterministic signature *is* the content commitment, so there is no separate hash. The reference templates are signed under the project key `kennel-maint-2026` (`keys/kennel-maint-2026.pub`).
- **Supply-chain gate.** Dependencies are vendored and checksum-pinned (`supply-chain/CHECKSUMS.toml`); the CI `supply-chain` job runs `cargo deny` + `cargo audit` + `cargo vet` via pinned, hash-verified tool binaries.
- **Licensing.** Apache-2.0 for the project; the BPF programs under `src/bpf/` are GPL-2.0 (SPDX headers, a kernel requirement for GPL-declaring programs).

### Project

- **Website.** `projectkennel.org` (GitHub Pages from `docs/website/`) — landing page, a Try-it quickstart, a documentation hub, and the trust-manifest JSON Schema at the `$id` path shipped code references.
- **Docs.** `supply-chain/UNSAFE-CRATES.md` corrected to the real five `unsafe`-bearing crates (`kennel-lib-syscall`/`-landlock`/`-bpf`/`-binder`/`-scm`); README/CHANGELOG brought to the current surface.

Roadmap (designed, not yet built): the D-Bus and X11 facades, `fs.scrub`/`fs.home.sanitise`, per-kennel `[unix]` service launching, binder cross-instance relay (the MCP topology) and `SpawnKennel`-over-binder, `kennel diff`, and the composable-fragment catalogue. See [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md) §8.1.
