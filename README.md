# Project Kennel

**Kennel runs code you haven't vetted — an AI coding agent, an `npm install`, a freshly-cloned repo — under your own user account, confined to just the files, network, and programs a signed policy allows.** The agent that goes off-script, or the postinstall script hunting for credentials, reaches your project and nothing else: not `~/.ssh`, not your other repositories, not the open network.

```bash
apt install kennel        # Debian/Ubuntu   (dnf install kennel on Fedora/RHEL)
kennel run claude         # run an agent confined to a repo, a toolchain, a few registries
```

It's the enforcement the user level never grew. The host has confined untrusted code for decades (SELinux, AppArmor, seccomp, the LSM framework), but your *account* — where agents and unsigned code now run — never did. Kennel keeps your uid and splits the **authority** off it: the workload runs as you, with exactly what its policy grants, checked one access at a time. That is a **reference monitor**. Where a sandbox or container draws its line once at launch and steps back, the monitor stays in the path for as long as the workload runs — cheap enough (~3 ms to spawn) to do per task and throw away.

## Install

Signed package repositories the project hosts and signs itself: no `curl | sh` anywhere (that's threat T1.4). You import **one** key, cross-check its fingerprint against three independent channels (this repo, the GitHub release, the domain's DNS `TXT` record), and `apt`/`dnf` verify every package and metadata refresh against it thereafter.

**Debian / Ubuntu:**
```bash
curl -fsSL https://packages.projectkennel.org/kennel-archive-keyring.asc | gpg --dearmor | sudo tee /usr/share/keyrings/kennel.gpg >/dev/null
gpg --show-keys /usr/share/keyrings/kennel.gpg          # cross-check the fingerprint first
echo "deb [signed-by=/usr/share/keyrings/kennel.gpg] https://packages.projectkennel.org/deb stable main" | sudo tee /etc/apt/sources.list.d/kennel.list
sudo apt update && sudo apt install kennel
```
**Fedora / RHEL** (the `.rpm` loads the SELinux module for you):
```bash
sudo curl -fsSL https://packages.projectkennel.org/rpm/kennel.repo -o /etc/yum.repos.d/kennel.repo
sudo rpm --import https://packages.projectkennel.org/kennel-archive-keyring.asc
sudo dnf install kennel
```
Signing key **`663C 67B0 9FDD A9EE E57F A295 88D5 8446 1C4D 6EE9`** (also at `_kennel-key.projectkennel.org`). Installing from a tarball or source, and the full post-install setup, are in [INSTALL.md](INSTALL.md).

## What it does

- **Construction by absence.** The workload's world is built from nothing, granted paths only. What isn't granted is *absent*, not denied: nothing to enumerate, nothing to probe.
- **Deny-by-default network**, four modes (`none` / proxied `constrained` / `unconstrained` / `host`), egress brokered and audited.
- **SSH with no signing oracle.** A per-user re-origination bastion; the sandbox holds a disposable synthetic key bound to one `(host, key)` edge: never your real key, never an agent socket.
- **Dynamic spawn + a service mesh.** A confined agent spawns scoped, signed-template sub-kennels and consumes brokered capabilities by name: deny-by-default, depth-1, reaped with the agent.
- **Confined GUI** (a per-kennel nested Wayland compositor), **OCI images** (digest-pinned rootfs), and **workspace-trust pinning** (a masked manifest the agent can rewrite but cannot forge).
- **Unprivileged by construction.** `kenneld` runs as you with no standing privilege; a single small file-capped helper builds the namespaces, operator-owned (not root). There is no `sudo` in the spawn.
- **Confinement, not detection.** The boundary never judges intent, so being wrong about the code is not a breach. A unified, structured audit log records every decision, and the trusted base only shrinks — 30 crates, every line of `unsafe` quarantined to 5 small ones.

Policy is signed, versioned, and inheritable, and describes kernel-level constraints rather than behaviour: the same policy confines an AI agent, a Postgres container, or an `npm install`. The full treatment lives in the book (below).

## Status

**0.7.x**, versioned on a stable-surface cadence ([CHANGELOG](CHANGELOG.md)). It runs the full vertical **unprivileged** on stock Linux (kernel ≥ 6.10, Landlock ABI ≥ 6), proven end-to-end on **Debian/Ubuntu** (AppArmor is the userns substrate) and on **Fedora, enforcing SELinux** (a two-domain module keeps the monitor and the workload as distinct SELinux subjects). Pre-1.0: interfaces may still change.

## Read more

- **The book** ([`books/`](https://github.com/projectkennel/books), separate repo) — the corpus: Vol 1 the platform-neutral design, Vol 2 the Linux realisation. The authoritative "what it is and why."
- **[THREATS.md](docs/reference/THREATS.md)** — the threat catalogue (stable IDs, incident citations, MITRE/compliance mappings). The durable, portable contribution: cite it even if you never run the code.
- **Using it:** [INSTALL.md](INSTALL.md) → [HOWTO.md](HOWTO.md) → [HOWTO-admin.md](HOWTO-admin.md), and the installed man pages (`man kennel`, `man policy.toml`, `man kenneld`).
- **Contributing:** [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## Reporting a vulnerability

See [SECURITY.md](.github/SECURITY.md). Report privately to security@projectkennel.org; do not open a public issue for a specific exploitable flaw.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). One exception: the host-mode egress BPF under [src/bpf/](src/bpf/) is GPL-2.0, as the kernel requires; everything else is Apache-2.0.

- **Website** <https://projectkennel.org> · **Packages** <https://packages.projectkennel.org> · **Source** <https://github.com/projectkennel/projectkennel>
