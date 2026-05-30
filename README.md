# Project Kennel

**Kernel-enforced confinement for unsigned code on developer workstations.**

The user level of a modern developer workstation has become a complete software runtime — package managers, container runtimes, AI coding agents, MCP servers, IDE extensions — all running as the user, none arriving through the operating system's validated install path. The host level has decades of enforcement vocabulary for code like this (AppArmor, SELinux, systemd hardening, capability sets, audit). None of it operates at user-level workload granularity. Project Kennel provides the enforcement vocabulary the user level should have acquired as it grew into a runtime.

Policy describes kernel-level constraints (which files, which network destinations, which sockets, which D-Bus methods), not workload behaviour. The same policy confines Claude Code, Codex, a Postgres container, an `npm install`, or an MCP server. Enforcement is via Landlock, cgroup BPF, mount and PID namespaces, seccomp, and `PR_SET_NO_NEW_PRIVS` — kernel mechanisms the workload's userspace cannot reach.

## Status

Documentation and design stage. The threat catalogue is publishable; the design document is at v0.1; the reference runtime is in design, implementation pending. This repository currently contains the design, the threat catalogue, the implementation architecture, and the project's engineering standards — no runtime code yet.

## What is here

| Path | What |
|---|---|
| [EXEC-SUMMARY.md](EXEC-SUMMARY.md) | Why the project exists; the one-page case. |
| [THREATS.md](THREATS.md) | The threat catalogue: stable IDs, incident citations, MITRE/compliance mappings. The durable contribution. |
| [docs/](docs/) | The design document — threat model, policy surface, template system, enforcement architecture. Its own product; an implementation-independent specification. |
| [TEMPLATE-ai-coding-strict.md](TEMPLATE-ai-coding-strict.md) | A complete, annotated worked policy template. |
| [architecture/](architecture/) | The reference implementation's architecture — process model, API surfaces, crate decomposition, trust boundaries, state and supervision, build, paths. |
| [CODING-STANDARDS.md](CODING-STANDARDS.md) | Normative engineering rules (the bar is OpenSSH / libpam). |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute, and what gets closed without review. |

## Reading order

New readers: [EXEC-SUMMARY.md](EXEC-SUMMARY.md) → [THREATS.md](THREATS.md) → [docs/](docs/) (start at §1) → [TEMPLATE-ai-coding-strict.md](TEMPLATE-ai-coding-strict.md). Implementers and auditors then read [architecture/](architecture/) and [CODING-STANDARDS.md](CODING-STANDARDS.md).

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The threat catalogue, design document, and reference runtime are all Apache-2.0.

One exception: the BPF programs under [bpf/](bpf/) (the `*.bpf.c` sources and their shared headers) are GPL-2.0, declared by the SPDX headers in those files and required by the Linux kernel for programs that declare a "GPL" license section. That applies to the in-kernel BPF object code; the user-space loader and everything else are Apache-2.0.

## Contact and links

- **Contact:** *[TBD]*
- **Repository:** *[TBD]*
- **Canonical THREATS.md:** *[TBD]*
