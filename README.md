# Project Kennel

**Kernel-enforced confinement for unsigned code on developer workstations.**

The user level of a modern developer workstation has become a complete software runtime — package managers, container runtimes, AI coding agents, MCP servers, IDE extensions — all running as the user, none arriving through the operating system's validated install path. The host level has decades of enforcement vocabulary for code like this (AppArmor, SELinux, systemd hardening, capability sets, audit). None of it operates at user-level workload granularity. Project Kennel provides the enforcement vocabulary the user level should have acquired as it grew into a runtime.

Policy describes kernel-level constraints (which files, which network destinations, which sockets, which D-Bus methods), not workload behaviour. The same policy confines Claude Code, Codex, a Postgres container, an `npm install`, or an MCP server. Enforcement is via Landlock, cgroup BPF, user/mount/PID/IPC namespaces, seccomp, and `PR_SET_NO_NEW_PRIVS` — kernel mechanisms the workload's userspace cannot reach.

**The daemon runs unprivileged.** `kenneld` is an ordinary user process; the sandbox — mount namespace, `mount`, `pivot_root`, the constructed view — is built by first establishing an identity-mapped **user namespace** (the bubblewrap mechanism), so no step needs real privilege. The only privileged component is a small, narrowly-scoped **privhelper** (installed with file capabilities, never `sudo`) that performs exactly the host-global operations a user namespace cannot reach: add/remove the per-kennel loopback addresses, attach the egress BPF, and write a policy-granted supplementary group into the workload's `gid_map`. There is no `sudo` anywhere in the spawn.

## Status

Pre-release; the binaries are unversioned. The threat catalogue ([v0.3](docs/design/THREATS.md)) and the design document (v0.1) are publishable, and the **reference runtime and policy compiler are implemented** — not just designed.

Working today (kernel 6.17, Landlock ABI ≥ 6; see [BUILD-ENV.md](docs/design/BUILD-ENV.md)) — **the full vertical runs unprivileged**, proven end-to-end as the ordinary operator with no `sudo`:

- **The spawn:** an identity-mapped user namespace, a double-fork so the workload is PID 1 of its own PID namespace, the constructed-`$HOME` view via `pivot_root` (non-granted paths are *absent*, not merely denied), a synthetic `/etc`, an allowlisted `/dev` with host-device passthrough, a fresh `/proc` + private `/tmp`, Landlock filesystem + network rules with abstract-unix/signal scoping, a seccomp denylist, `PR_SET_NO_NEW_PRIVS`, and cgroup join.
- **Identity:** the workload's account and groups are masked to `kennel`; inherited supplementary groups drop to the overflow gid by default, and a policy-granted group is re-granted through the privhelper's `gid_map` write.
- **Egress & IPC:** a per-kennel SOCKS5/HTTP proxy with a cgroup-BPF fail-closed allowlist and a per-kennel JSONL audit log; an `AF_UNIX` socket shim; and a per-user SSH re-origination bastion (the workload holds no key or agent socket).
- **The privhelper** (file caps `cap_net_admin,cap_sys_admin,cap_setgid`, never `sudo`): the loopback addresses, the egress-BPF attach, and the `gid_map` write — and nothing else.
- **The `kennel` CLI:** `compile` (resolve a source policy + its templates into a signed, byte-pinned settled policy), `validate`, `sign`, `run`, `stop`, `list` — with end-to-end ed25519 trust (templates, fragments, and the settled artefact) and a `kennel.lock` byte-pin. The shipped [templates](templates/) are signed under the maintainer key `kennel-maint-2026` (verify with `kennel validate --require-signed` against [keys/](keys/)).

On distributions that restrict unprivileged user namespaces (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`), an AppArmor profile grants `userns` to the kenneld binary ([dist/apparmor/kenneld](dist/apparmor/kenneld)) — the AppArmor counterpart of the privhelper's file capabilities, a one-time install step.

Deferred (designed, not yet built — see [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md) §8.1): the unified audit writer plus the journald/syslog/stdout sinks and the `[audit]` policy section (a per-kennel file sink and the proxy's per-request JSONL records run today), per-kennel `[unix]` service launching (§7.4.7), and the Rust `kennel-checksum-verify` (a dependency-free shell verifier runs today).

## Size

A rough sense of scale — far more specification than code, and the code that exists is small and mostly safe. (SLOC = lines of code excluding comments and blanks, via `tokei`; prose via `wc -w`. A snapshot that drifts.)

| Artefact | Size |
|---|---|
| Design docs ([`docs/design/`](docs/design/), 27 files) | ≈ 65,600 words |
| Architecture docs ([`docs/architecture/`](docs/architecture/), 15 files) | ≈ 32,500 words |
| Implementation — Rust (10 crates, tests included) | ≈ 20,100 SLOC |
| Implementation — BPF (C: 8 programs + 3 shared headers) | ≈ 510 SLOC |
| `unsafe` Rust — confined to `kennel-syscall` + `kennel-bpf` | ≈ 3,020 SLOC, 97 `unsafe` blocks |

The other eight crates carry `#![forbid(unsafe_code)]`: the entire `unsafe` surface — raw syscalls, the Landlock/seccomp FFI, and the hand-rolled `bpf(2)` loader — is quarantined to two crates sized to be reviewable in one sitting ([supply-chain/UNSAFE-CRATES.md](supply-chain/UNSAFE-CRATES.md)).

## What is here

| Path | What |
|---|---|
| [EXEC-SUMMARY.md](docs/design/EXEC-SUMMARY.md) | Why the project exists; the one-page case. |
| [THREATS.md](docs/design/THREATS.md) | The threat catalogue: stable IDs, incident citations, MITRE/compliance mappings. The durable contribution. |
| [docs/](docs/) | The design document — threat model, policy surface, template system, enforcement architecture. Its own product; an implementation-independent specification. |
| [TEMPLATE-ai-coding-strict.md](docs/design/TEMPLATE-ai-coding-strict.md) | A complete, annotated worked policy template. |
| [architecture/](docs/architecture/) | The reference implementation's architecture — process model, API surfaces, crate decomposition, trust boundaries, state and supervision, build, paths. |
| [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md) | Normative engineering rules (the bar is OpenSSH / libpam). |
| [CONTRIBUTING.md](.github/CONTRIBUTING.md) | How to contribute, and what gets closed without review. |

## Reading order

New readers: [EXEC-SUMMARY.md](docs/design/EXEC-SUMMARY.md) → [THREATS.md](docs/design/THREATS.md) → [docs/](docs/) (start at §1) → [TEMPLATE-ai-coding-strict.md](docs/design/TEMPLATE-ai-coding-strict.md). Implementers and auditors then read [architecture/](docs/architecture/) and [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md).

## Reporting a vulnerability

See [SECURITY.md](.github/SECURITY.md). Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The threat catalogue, design document, and reference runtime are all Apache-2.0.

One exception: the BPF programs under [bpf/](src/bpf/) (the `*.bpf.c` sources and their shared headers) are GPL-2.0, declared by the SPDX headers in those files and required by the Linux kernel for programs that declare a "GPL" license section. That applies to the in-kernel BPF object code; the user-space loader and everything else are Apache-2.0.

## Contact and links

- **Repository:** <https://github.com/projectkennel/projectkennel>
- **Security contact:** security@projectkennel.org (see [SECURITY.md](.github/SECURITY.md))
- **Canonical THREATS.md:** <https://github.com/projectkennel/projectkennel/blob/main/docs/design/THREATS.md>
