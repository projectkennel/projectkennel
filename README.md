# Project Kennel

An AI coding agent needs your repository and a toolchain. A package install needs a registry. A development container needs access to your files. Each grant makes a sandbox useful, but a broad mount or open network can give unvetted code much more access than the job requires.

**Project Kennel is a reference monitor for code running under your account.** It uses namespaces, Landlock, seccomp, and other Linux controls to confine an agent, an `npm install`, or code from a new repository. A signed policy grants each task the resources it needs. A task working on one project need not see `~/.ssh`, your other repositories, or the open network.

```bash
apt install kennel        # Debian/Ubuntu   (dnf install kennel on Fedora/RHEL)
kennel run claude         # run an agent confined to a repo, a toolchain, a few registries
```

Kennel uses the same scaffolding as a sandbox, then applies a different discipline. **Remove what the task does not need:** ungranted files, processes, devices, and routes are absent from its view; Landlock and seccomp restrict unused operations and kernel entry points. **Mediate what it does need:** for a network connection or service request, a separate daemon checks the signed policy before a host-side component acts. The first path enforces by construction; the second mediates each crossing at runtime. Together they form a reference monitor the workload cannot alter. A fresh kennel takes about 3 ms to construct, so it can be used per task.

## Install

Kennel is available from project-signed package repositories. Import the signing key, check its fingerprint against this repository, the GitHub release, and the domain's DNS `TXT` record, then install with `apt` or `dnf`. The package manager verifies subsequent packages and repository metadata.

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

- **Restricted view.** The workload sees the paths, processes, devices, and network routes its policy permits. Landlock and seccomp further restrict what it can do with them.
- **Network policy.** Four modes (`none`, proxied `constrained`, `unconstrained`, and `host`) let a policy choose the required reach. Constrained egress is brokered and audited.
- **SSH without exposing your agent.** A bastion uses a disposable key tied to a permitted destination; the workload never receives your real key or SSH agent socket.
- **Scoped delegation.** An agent can start sub-kennels from signed templates and reach named services through the brokered mesh. The children are reaped with their parent.
- **Other workloads.** Kennel supports a nested Wayland GUI, digest-pinned OCI root filesystems, and pinned workspace trust manifests.
- **No root workload, even inside the kennel.** The user namespace maps UID 0 so trusted setup code can build the boundary. Before the workload starts, it drops to your UID and cannot regain UID 0 in that namespace. Kennel does not map a delegated range of subordinate UIDs into the workload.
- **No standing root daemon.** `kenneld` runs as your user. A narrow file-capability helper performs the privileged setup; starting a kennel does not invoke `sudo`.
- **Audit.** Structured events record policy decisions. Kennel enforces access rules; it does not decide whether the code's intent is benign.

Policies are signed, versioned, and inheritable. They describe access rather than the identity of a particular tool, so the same policy model applies to an agent, a container, or a package install.

## Status

**0.7.x** ([CHANGELOG](CHANGELOG.md)). Kennel runs on Linux with kernel ≥ 6.10 and Landlock ABI ≥ 6. End-to-end runs have been verified on Debian/Ubuntu with AppArmor and Fedora with enforcing SELinux. Interfaces may change before 1.0.

## Read more

- **The book** ([`books/`](https://github.com/projectkennel/books), separate repo) — the design and its Linux implementation.
- **[THREATS.md](docs/reference/THREATS.md)** — the threat catalogue, with stable IDs, incident citations, and MITRE/compliance mappings.
- **Using it:** [INSTALL.md](INSTALL.md) → [HOWTO.md](HOWTO.md) → [HOWTO-admin.md](HOWTO-admin.md), and the installed man pages (`man kennel`, `man policy.toml`, `man kenneld`).
- **Contributing:** [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## Reporting a vulnerability

See [SECURITY.md](.github/SECURITY.md). Report privately to security@projectkennel.org; do not open a public issue for a specific exploitable flaw.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). One exception: the host-mode egress BPF under [src/bpf/](src/bpf/) is GPL-2.0, as the kernel requires; everything else is Apache-2.0.

- **Website** <https://projectkennel.org> · **Packages** <https://packages.projectkennel.org> · **Source** <https://github.com/projectkennel/projectkennel>
