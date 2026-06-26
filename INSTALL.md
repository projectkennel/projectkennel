# Installing Project Kennel

This document describes how to build, install, and configure Project Kennel from source on a Linux system.

Installing is two steps: build a self-contained release tarball with `src/tools/build-release.sh`, then install it with the `install.sh` bundled inside. `install.sh` is a **pure installer** — it places a prebuilt payload (the binaries, the vendor config, the systemd units, the AppArmor profile, the trust-store key, and the signed templates) and file-caps the privhelper factory (setuid-root only where the filesystem cannot carry file caps). It does **not** build, and it runs only from an unpacked release tree, never from the source checkout.

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

Then unpack it, verify the manifest, and run its bundled installer with `sudo`. It installs the binaries under `/usr/libexec/kennel` (the documented non-PATH helper location; see `docs/architecture/07-paths.md`):

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
