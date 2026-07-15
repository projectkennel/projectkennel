# Installing Project Kennel

The recommended install is the **signed package repository** ([below](#packages-signed-apt--dnf-repositories)) — `apt install kennel` / `dnf install kennel` from repositories Project Kennel hosts and signs itself. The rest of this document covers building and installing from a release tarball or from source.

Project Kennel is **never** installed by piping a URL into a shell (`curl … | sh`) — that is threat T1.4 in [THREATS.md](docs/reference/THREATS.md), and a confinement tool has no business asking you to run unverified code as your user to get it. Every supported path verifies a signature you can cross-check.

## Packages (signed APT / DNF repositories)

The packages live in repositories at `packages.projectkennel.org` that the project builds and GPG-signs itself — no third-party build service or community mirror in the trust path. You import **one** public key (whose fingerprint you cross-check against this page, the GitHub release, and the domain's DNS TXT record), and thereafter `apt`/`dnf` verify every package and every metadata refresh against it. The host (Cloudflare Pages) only ever serves already-signed bytes; it holds no key and cannot forge a package.

**Debian / Ubuntu:**

```bash
curl -fsSL https://packages.projectkennel.org/kennel-archive-keyring.asc | gpg --dearmor | sudo tee /usr/share/keyrings/kennel.gpg >/dev/null
# Cross-check the fingerprint BEFORE trusting it (compare against the GitHub release notes):
gpg --show-keys /usr/share/keyrings/kennel.gpg
echo "deb [signed-by=/usr/share/keyrings/kennel.gpg] https://packages.projectkennel.org/deb stable main" | sudo tee /etc/apt/sources.list.d/kennel.list
sudo apt update && sudo apt install kennel
```

**Fedora / RHEL:**

```bash
sudo curl -fsSL https://packages.projectkennel.org/rpm/kennel.repo -o /etc/yum.repos.d/kennel.repo
sudo rpm --import https://packages.projectkennel.org/kennel-archive-keyring.asc   # then: rpm -qi gpg-pubkey-… to check the fingerprint
sudo dnf install kennel
```

> [!NOTE]
> The `curl` above fetches a **public key**, not a script — nothing executes, and apt/dnf reject the key unless its fingerprint matches what they later verify against. That is the difference between importing a cross-checkable trust anchor and `curl | sh`. After install, continue with [Admin Configuration](#2-admin-configuration-root) and the per-distro confinement-substrate step (AppArmor §4 on Debian/Ubuntu, SELinux §5 on Fedora — the `.rpm` loads the SELinux module for you).

---

## Building from a tarball or source

Building is two steps: build a self-contained release tarball with `src/tools/build-release.sh`, then install it with the `install.sh` bundled inside. `install.sh` is a **pure installer** — it places a prebuilt payload (the binaries, the vendor config, the systemd units, the AppArmor profile, the trust-store key, and the signed templates) and file-caps the privhelper factory (setuid-root only where the filesystem cannot carry file caps). It does **not** build, and it runs only from an unpacked release tree, never from the source checkout.

---

## Prerequisites

Project Kennel requires the following system environment:

* **Operating System**: Linux kernel version **&ge; 6.10** (required for Landlock `FS_EXECUTE` and modern cgroup/namespace delegations).
* **Compilers**: 
  * Rust toolchain version **&ge; 1.95.0** (installed via `rustup`).
  * `clang` (version 18+ recommended) for BPF program compilation.
* **Header Files & Libraries**:
  * `linux-libc-dev` (for BPF UAPI headers).
  * `libbpf-dev` (for helper headers like `<bpf/bpf_helpers.h>`).

On Debian/Ubuntu systems, install the compiler dependencies using:
```bash
sudo apt-get update
sudo apt-get install -y clang libbpf-dev linux-libc-dev
```

---

## 1. Building and Installing

First build a self-contained, offline-installable tarball for the host architecture. This compiles every binary (the privhelper with the `bpf-egress` feature), stages the flat install payload, and writes a `SHA256SUMS` manifest covering every shipped file — including the trust-store public key:

```bash
src/tools/build-release.sh --arch "$(uname -m)-unknown-linux-gnu"
# → dist/release/kennel-<version>-<sha>-<arch>-linux-gnu.tar.xz
```

Then unpack it, verify the manifest, and run its bundled installer with `sudo`. It installs the binaries under `/usr/libexec/kennel` (the documented non-PATH helper location; see `docs/archive/architecture/07-paths.md`):

```bash
tar xf dist/release/kennel-*.tar.xz
cd kennel-*/
sha256sum -c SHA256SUMS          # every shipped file, incl. the trust key
sudo ./install.sh
```

### Installation Options

`./install.sh` accepts the following flags:

* `--prefix DIR`: Set a custom libexec directory for the binaries (default: `/usr/libexec/kennel`).
* `--mandir DIR`: Set the man-page root (default: `/usr/share/man`).
* `--dry-run`: Print the actions the installer would perform without modifying the system.
* `-h` or `--help`: Display the usage guidelines.

For example, to preview the installation:
```bash
sudo ./install.sh --dry-run
```

---

## 2. Admin Configuration (Root)

After the installation script finishes, the administrator configures the system inputs in `/etc/kennel/`:

1. **Public Signing Keys**:
   Add any organizational or customer public keys to `/etc/kennel/keys/<key_id>.pub`. The project's own template-signing keys are automatically copied there by the installer.

There is no per-user allocation step: everything a kennel needs is derived from the caller's kernel-trusted real uid (the per-user loopback subnet is an FNV-1a hash of the uid, recomputed identically by `kenneld` and by `kennel-privhelper`'s validator).

**Restricting who may run kennels (optional).** By default the privhelper is world-executable, so any user may start a kennel. Access is governed by execute permission on the privhelper binary. To limit it to a group, give the binary to that group and drop other-execute:

```bash
sudo chgrp kennel-users /usr/libexec/kennel/kennel-privhelper
sudo chmod 0750 /usr/libexec/kennel/kennel-privhelper
```

Only members of `kennel-users` can then invoke the privileged factory and start a kennel.

---

## 3. User Setup (Unprivileged)

Each user enables the user-level systemd service — no admin provisioning is required:

```bash
systemctl --user enable --now kenneld.socket
```

This starts `kenneld` on demand whenever the user runs the `kennel` CLI.

---

## 4. AppArmor Profile (Ubuntu 23.10+ / 24.04)

On distributions restricting unprivileged user namespaces, install and load the AppArmor profile to allow `kenneld` to build the namespace sandboxes:

```bash
sudo install -m 0644 dist/apparmor/kenneld /etc/apparmor.d/kenneld
sudo apparmor_parser -r -W /etc/apparmor.d/kenneld
```

> [!NOTE]
> If you used a custom `--prefix` during installation (for example, `/usr/libexec`), edit the profile path `/usr/libexec/kennel/kenneld` inside `/etc/apparmor.d/kenneld` to match the actual installed `kenneld` binary path.

## 5. SELinux Policy (Fedora / RHEL, enforcing)

SELinux is the confinement substrate on Fedora-family systems, the analogue of the AppArmor profile above. The base policy withholds the `binder` object class from *every* domain — including `unconfined_t` — so under enforcing SELinux `kenneld` cannot become the per-kennel binder context manager, and a kennel fails to start (`binder context manager not started: Permission denied`). The `.rpm` loads the policy module automatically in `%post`; installing from the tarball, load it by hand:

```bash
sudo semodule -i dist/selinux/kennel.cil
sudo restorecon -F /usr/libexec/kennel/kenneld
```

The module defines two domains: `kennel_t` for the trusted base (`kenneld` + the file-capped privhelper + `kennel-bin-init`), and `kennel_workload_t` for the untrusted workload — bounded by `kennel_t` via `typebounds`, so a workload can talk to `kenneld` over binder but cannot become a context manager, relabel, or touch SELinux. The confiner and the confined are never the same SELinux subject.

> [!IMPORTANT]
> **Fedora silently `dontaudit`s binder denials.** If a kennel fails on an SELinux system and you see *no* AVC in `ausearch`/`journalctl`, that is expected — the denials are suppressed. Reveal them with `sudo semodule -DB` (disable `dontaudit`), reproduce, inspect `ausearch -m AVC -ts recent`, then `sudo semodule -B` to restore. The most common cause is simply that the module above is not loaded.

> [!NOTE]
> The `kennel_t` entry transition is defined from the `unconfined_r`, `staff_r`, and `sysadm_r` login roles (Fedora Workstation defaults to `unconfined_r`). If your operators log in under a custom confined role, add that role to the transition (`roletype <role> kennel_t` / `roletype <role> kennel_workload_t` in a local module) or they will get no binder and kennels will not start.

---

## Next steps

- **Operating a host** (trust store, signing keys, systemd, restricting who runs kennels, the config cascade, upgrades): [HOWTO-admin.md](HOWTO-admin.md).
- **Running and authoring policies** (your first kennel, confining an agent, writing/signing a policy, reading the audit log): [HOWTO.md](HOWTO.md).
- **Reference**: the installed man pages — `man kennel`, `man kenneld`, `man policy.toml`, `man system.toml`.
