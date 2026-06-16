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
- **Audit:** a unified `kennel-lib-audit` writer (one canonical event schema, one sanitisation pass, per-class levels) fanning out to file, stdout, syslog, and (opt-in) journald sinks, with rotated files gzipped via the system `gzip(1)`; the signed `[audit]` policy section selects them, over installation-wide and per-user `audit.toml` defaults (built-in < `/etc/kennel` < `~/.config` < policy). All three userspace sources route through it — `kenneld`'s lifecycle, the egress proxy's per-request `net.egress`, and the privhelper's `priv.invoke`/`priv.refuse` (recorded by `kenneld` at the IPC boundary, `source: privhelper`).
- **The privhelper** (file caps `cap_net_admin,cap_sys_admin,cap_setgid`, never `sudo`): the loopback addresses, the egress-BPF attach, and the `gid_map` write — and nothing else.
- **The `kennel` CLI:** `run`/`attach`/`review`/`stop`/`list` plus a `kennel policy` group — `policy compile` (resolve a source policy + its templates into a signed, byte-pinned settled policy), `policy validate`, `policy sign`, `policy list`/`show`/`edit`/`generate`, and `policy lint` (flag template incoherences). An interactive `run` is **detachable** — kenneld owns the controlling pty and brokers it, so `Ctrl-\ d` detaches without ending the workload and `kennel attach <name>` reconnects (the tmux/`docker attach` model, no `setns`). End-to-end ed25519 trust (templates, fragments, and the settled artefact) and a `kennel.lock` byte-pin. The shipped [templates](templates/) are signed under the maintainer key `kennel-maint-2026` (verify with `kennel policy validate --require-signed` against [keys/](keys/)).
- **Workspace trust (T2.8):** a masked `.trust-manifest.json` at each writable root pins the SHA-256 of host-side execution triggers (`Makefile`, `.git/hooks/*`, `.vscode/tasks.json`, …). The CLI maintains it host-side; the spawn view **masks it invisible** to the workload (an empty over-mount inside the writable bind), so the confined agent can rewrite a trigger but cannot forge the pin — host tooling reads the real manifest and refuses a trigger whose hash diverged. `kennel review` is the operator re-pin. Two more terminal-facing hardenings: the PTY escape filter (`[tty]`, drops OSC 52 clipboard / 9/777 notifications / DCS-APC-PM-SOS, T2.6) and an egress refusal of literal special-use destinations (closing the per-kennel inbound-mirror lateral edge).

On distributions that restrict unprivileged user namespaces (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`), an AppArmor profile grants `userns` to the kenneld binary ([dist/apparmor/kenneld](dist/apparmor/kenneld)) — the AppArmor counterpart of the privhelper's file capabilities, a one-time install step.

Deferred (designed, not yet built — see [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md) §8.1): the D-Bus and X11 facades (`[dbus]`/`[x11]`), `fs.scrub`/`fs.home.sanitise`, per-kennel `[unix]` service launching (§7.6.7), binder cross-instance relay (the MCP topology) and `SpawnKennel`-over-binder, `kennel diff`, and the composable-fragment catalogue. The audit subsystem is complete at the userspace level (kernel-side BPF and LSM events report via the kernel's own ring buffer / `dmesg` by design, not this writer). Checksum verification is enforced today by the shell witness `src/tools/verify-checksums.sh`; a Rust twin is an optional §5.5.1 call (contingent on vendoring `sha2`), not a gap.

## SSH egress: double-blind re-origination

The most distinctive mechanism, and the hardest part of confining a workload that does real work — an agent or a build needs to `git push`/`pull` or `ssh` to a few hosts, with selected keys.

The obvious grant is to forward an `ssh-agent` socket into the sandbox. It is a **destination-blind signing oracle**: the agent protocol signs an opaque blob, *not* a hostname, so a workload holding the socket can have an allowlisted key sign a challenge it crafted for an *attacker-chosen* host and authenticate as the user anywhere that key is accepted (cross-host key reuse). A curated `~/.ssh/config` constrains only the client the workload is free to bypass.

Project Kennel routes SSH through a per-user **re-origination bastion** (a stock OpenSSH `sshd` running forced commands only) so that **both ends of the dangerous (key × destination) pairing are blinded**:

- **The workload is blind to the credential.** Its constructed `~/.ssh` holds only a *disposable synthetic* ed25519 key — never a real key, never an agent socket. The real key never enters the kennel; it stays in the user's host-side store (agent, hardware token, or `~/.ssh`).
- **The credential cannot be aimed by the workload.** *Which synthetic key authenticates is the destination selector*: the bastion's forced command bakes in the `(host, real-key-fingerprint)` edge, so `kennel-bin-ssh-reorigin` re-originates a fresh `ssh` with the real key — `IdentitiesOnly`, host-key-verified — to **exactly that host and no other**. The workload cannot redirect it, cannot choose a destination, and a non-synthetic key is refused.

A synthetic key is thus a capability for exactly one `(host, key)` edge: `git push` to a granted host just works, with **zero key material in the sandbox and no signing oracle to abuse**. Validated end-to-end against stock OpenSSH 9.6 (design [§7.10](docs/design/07-10-ssh.md); [`kennel-bin-ssh-reorigin`](src/crates/kennel-bin-ssh-reorigin/)). We have not found this double-blind arrangement — workload blind to the key, key unaimable by the workload — in another sandbox or SSH-confinement design.

## Size

A rough sense of scale — far more specification than code, and the code that exists is small and mostly safe. (SLOC = lines of code excluding comments and blanks, via `tokei`; prose via `wc -w`. A snapshot that drifts.)

| Artefact | Size |
|---|---|
| Design docs ([`docs/design/`](docs/design/), 27 files) | ≈ 67,500 words |
| Architecture docs ([`docs/architecture/`](docs/architecture/), 15 files) | ≈ 36,700 words |
| Implementation — Rust (22 crates, tests included) | ≈ 26,600 SLOC |
| Implementation — BPF (C: 8 programs + 3 shared headers) | ≈ 545 SLOC |
| `unsafe` Rust — confined to `kennel-lib-syscall` + `kennel-lib-bpf` | ≈ 3,400 SLOC, ~80 `unsafe` blocks |

Almost every crate carries `#![forbid(unsafe_code)]`. The entire `unsafe` surface is quarantined to five small, single-purpose crates, each owning one concern: the syscall/spawn hooks (`kennel-lib-syscall`), the Landlock bindings (`kennel-lib-landlock`), the `bpf(2)` loader + ringbuf (`kennel-lib-bpf`), the binder ioctl ABI (`kennel-lib-binder`), and SCM_RIGHTS fd adoption (`kennel-lib-scm` — a single `unsafe` line). The split is deliberate, so a consumer pulls in only the surface it needs; every block is held to a `SAFETY:`/`INVARIANTS`/`FAILURE MODE:` template ([supply-chain/UNSAFE-CRATES.md](supply-chain/UNSAFE-CRATES.md) is authoritative).

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

Using it: [INSTALL.md](INSTALL.md) to deploy → [HOWTO.md](HOWTO.md) to run and author policies → [HOWTO-admin.md](HOWTO-admin.md) to operate a host. The installed man pages are the reference (`man kennel`, `man policy.toml`, `man kenneld`).

New readers (design): [EXEC-SUMMARY.md](docs/design/EXEC-SUMMARY.md) → [THREATS.md](docs/design/THREATS.md) → [docs/](docs/) (start at §1) → [TEMPLATE-ai-coding-strict.md](docs/design/TEMPLATE-ai-coding-strict.md). Implementers and auditors then read [architecture/](docs/architecture/) and [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md).

## Reporting a vulnerability

See [SECURITY.md](.github/SECURITY.md). Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The threat catalogue, design document, and reference runtime are all Apache-2.0.

One exception: the BPF programs under [bpf/](src/bpf/) (the `*.bpf.c` sources and their shared headers) are GPL-2.0, declared by the SPDX headers in those files and required by the Linux kernel for programs that declare a "GPL" license section. That applies to the in-kernel BPF object code; the user-space loader and everything else are Apache-2.0.

## Contact and links

- **Website:** <https://projectkennel.org>
- **Repository:** <https://github.com/projectkennel/projectkennel>
- **Security contact:** security@projectkennel.org (see [SECURITY.md](.github/SECURITY.md))
- **Canonical THREATS.md:** <https://github.com/projectkennel/projectkennel/blob/main/docs/design/THREATS.md>
