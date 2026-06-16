# Installing Project Kennel

This document describes how to build, install, and configure Project Kennel from source on a Linux system.

The recommended installation method is using the provided `install.sh` script, which automates building the release binaries (including the BPF-enabled privileged helper), configuring directory structures, setting up setuid-root permissions, and copying systemd units.

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

## 1. Running the Installer

Run the installer script with `sudo` to perform the system-wide installation. By default, it builds all release binaries (compiling `kennel-privhelper` with the `bpf-egress` feature) and installs them under `/usr/libexec/kennel` (the documented non-PATH helper location; see `docs/architecture/07-paths.md`):

```bash
sudo src/tools/install.sh
```

### Installation Options

The script accepts the following flags to customize the installation:

* `--prefix DIR`: Set a custom installation directory prefix (default: `/usr/libexec/kennel`).
* `--no-build`: Skip the `cargo build` step and install the binaries already compiled in `target/release/`.
* `--dry-run`: Print the actions the installer would perform without modifying the system.
* `-h` or `--help`: Display the usage guidelines.

For example, to preview the installation without compiling:
```bash
sudo src/tools/install.sh --dry-run
```

---

## 2. Admin Configuration (Root)

After the installation script finishes, the administrator must configure the system inputs in `/etc/kennel/`:

1. **User Allocations (`/etc/kennel/subkennel`)**:
   Add one line per operator user following the format `<uid>:<tag>:<gid-hex>:<namespace>`.
   Example for UID `1000` (tag `42`, GID `0000000001`, namespace `kennel-alice`):
   ```text
   1000:42:0000000001:kennel-alice
   ```
2. **Scope Constants (`/etc/kennel/scope`)**:
   Provision `/etc/kennel/scope` with the installation's global tag and ULA GID constants that `kennel-privhelper` validates against.
3. **Public Signing Keys**:
   Add any organizational or customer public keys to `/etc/kennel/keys/<key_id>.pub`. The project's own template-signing keys are automatically copied there by the installer.

---

## 3. User Setup (Unprivileged)

Once the administrator has provisioned `/etc/kennel/subkennel`, each user enables the user-level systemd service:

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

---

## Next steps

- **Operating a host** (trust store, signing keys, systemd, per-user provisioning, the config cascade, upgrades): [HOWTO-admin.md](HOWTO-admin.md).
- **Running and authoring policies** (your first kennel, confining an agent, writing/signing a policy, reading the audit log): [HOWTO.md](HOWTO.md).
- **Reference**: the installed man pages — `man kennel`, `man kenneld`, `man policy.toml`, `man system.toml`, `man subkennel`.
