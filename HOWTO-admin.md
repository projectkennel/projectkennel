# Project Kennel — HOWTO (operator / administrator)

Deploying and operating Project Kennel on a host: install, the trust store and
signing keys, systemd, AppArmor, per-user provisioning, the config cascade, and
upgrades. For authoring and running policies as a user, see
[HOWTO.md](HOWTO.md). Reference detail is in the man pages
(`man kenneld`, `man system.toml`, `man subkennel`) and `docs/`.

The privilege model in one line: **one** privileged component
(`kennel-privhelper`, setuid-root, file-caps not sudo), bounded to address setup
and the kennel-construction operation; kenneld and everything else run as the
user. See [docs/architecture/01-process-model.md](docs/architecture/01-process-model.md).

---

## 1. Install and verify

From a prebuilt release tarball (no toolchain needed on the target):

```sh
tar xf kennel-*.tar.xz && cd kennel-* && sudo ./install.sh
```

From a source checkout, build a tarball first, then install it the same way:

```sh
src/tools/build-release.sh --arch "$(uname -m)-unknown-linux-gnu"
tar xf dist/release/kennel-*.tar.xz && cd kennel-*/ && sudo ./install.sh
```

By default this installs every binary under `/usr/libexec/kennel` (the
documented non-PATH helper location), the vendor config under `/usr/lib/kennel`,
the per-user systemd units, the AppArmor profile, the man pages, and the
root-owned `/etc/kennel` skeleton. Useful flags (`./install.sh --help`):

- `--prefix DIR` — relocate the binaries (the vendor `system.toml`, the systemd
  unit, and the AppArmor profile are rewritten to match).
- `--mandir DIR` — man-page root (default `/usr/share/man`).
- `--dry-run` — print every action without touching the system.

Verify the result:

```sh
ls -l /usr/libexec/kennel/kennel-privhelper      # expect -rwsr-xr-x root root
sha256sum -c SHA256SUMS                           # in a release tarball
```

The eleven installed binaries: `kenneld`, `kennel`, `kennel-akc`,
`host-netproxy`, `host-inetd`, `facade-socks5`, `facade-client`,
`facade-afunix`, `facade-ssh`, `kennel-bin-init`, `kennel-privhelper`. kenneld
resolves the helpers it forks by absolute path from the config cascade (§6), so
each must be present where `system.toml` says. Each has a man page (`man
host-inetd`, etc.).

> **No path is baked into a binary.** The installer writes the vendor
> `system.toml` to match where it actually installed; relocating with `--prefix`
> stays coherent without hand-editing. See `man system.toml`.

---

## 2. The trust store and signing keys

kenneld enforces only policies whose template/fragment chain verifies against its
**trust store** — `trust_dir` in `system.toml`, default `/etc/kennel/keys`, one
`<key_id>.pub` per trusted signer. This is **system-owned and not
user-overridable**: letting a user redirect it would defeat signing.

```sh
# Add an org/customer policy-signing public key:
sudo install -m 0644 corp-policy-2026.pub /etc/kennel/keys/corp-policy-2026.pub
```

The installer ships the project's own template-signing public key, so the signed
reference templates verify out of the box.

**The trust split** (deliberate; see `man config.toml`):

- **Templates and fragments** verify only against the *system* stores
  (`/etc/kennel/keys`, `/usr/lib/kennel/keys`) — never a user's
  `~/.config/kennel/keys`. A user cannot introduce a template signed by their own
  key.
- **Run policies** the daemon enforces may be signed by a system key *or* the
  user's own key — a user may author and run their own leaf policies, but only
  atop templates the system trusts.

Rotate a key by adding the new public key to the store, re-signing the affected
templates with it, and removing the old key once nothing references it.

---

## 3. systemd and socket activation

kenneld is a **per-user**, socket-activated daemon. The installer places the user
units in `/usr/lib/systemd/user`. Each user enables it once:

```sh
systemctl --user enable --now kenneld.socket
```

The socket starts kenneld on the first `kennel` CLI connection; it then persists
for the session. There is no system-wide kenneld and no long-lived privileged
daemon — see [docs/architecture/05-state-and-supervision.md](docs/architecture/05-state-and-supervision.md).

Diagnose a user's daemon:

```sh
journalctl --user -u kenneld.service          # the daemon's own log
sudo journalctl -t kenneld                     # the in-kennel processes (system journal)
```

A spawn spans both journals (the daemon in the user journal; the privhelper
factory, `kennel-bin-init`, and the facades in the system journal). Read both,
merged by time, to see a spawn end to end.

---

## 4. AppArmor (unprivileged user namespaces)

On hosts that restrict unprivileged user namespaces (Ubuntu 23.10+,
`kernel.apparmor_restrict_unprivileged_userns=1`), kenneld needs an AppArmor
profile to create the kennel's namespaces. The installer stages and loads
`/etc/apparmor.d/kenneld`:

```sh
sudo apparmor_parser -r -W /etc/apparmor.d/kenneld     # reload after an edit
```

The profile attaches to the kenneld binary **by absolute path**, so if you
installed with `--prefix`, the profile's path is rewritten to match. If you move
the binary afterwards, edit the profile path and reload (the installer notes this
in INSTALL.md). On hosts that do not restrict userns, the profile is harmless.

---

## 5. Per-user provisioning (`/etc/kennel/subkennel`)

Each user that runs kennels needs one allocation line in `/etc/kennel/subkennel`
(analogous to `/etc/subuid`); a user with no valid line cannot start kenneld. The
format is `uid:tag:gid:namespace` (`man subkennel`):

```
1000:42:0000000001:kennel-alice
```

- `uid` — the user.
- `tag` — a per-user 12-bit tag (0–4095), unique per uid.
- `gid` — the reserved gid base, exactly ten lowercase hex digits.
- `namespace` — the allocation namespace (non-empty).

Do not hand-compute these. Use the CLI to append a provably-valid, collision-free
line and to validate the whole file:

```sh
sudo kennel subkennel add --uid 1000
sudo kennel subkennel check
```

The installer deliberately does **not** fabricate these (a security-sensitive
admin input); it creates the directory and tells you to populate it.

---

## 6. The configuration cascade

Three layers, each with a distinct trust posture (`man system.toml`,
`man config.toml`):

| File | Audience | Trust | Cascade (low → high) |
|---|---|---|---|
| `system.toml` | admin | **integrity-sensitive** (binary paths, trust store); never read from `~` | `/usr/lib/kennel` → `/etc/kennel` |
| `config.toml` | user | convenience only (CLI search paths); cannot affect enforcement | `/usr/lib/kennel` → `/etc/kennel` → `~/.config/kennel` |
| `audit.toml` | admin/user | audit sink + per-class levels | per `docs/architecture/02-3-audit-schema.md` |

A higher layer overrides a lower one **per key**; compiled-in defaults apply
where a key is unset, so a host with no config file still runs. To relocate one
helper binary or the trust store, set the key in `/etc/kennel/system.toml` — it
wins over the vendor copy. Every override key is documented inline in the shipped
`system.toml` and in `man system.toml`.

---

## 7. Upgrades

1. Reinstall: unpack the new release tarball and `sudo ./install.sh` (from a
   source checkout, `src/tools/build-release.sh` builds the tarball first).
2. **Restart the daemon** — a running kenneld keeps serving the *old* binary
   until restarted:
   ```sh
   systemctl --user restart kenneld.socket kenneld.service
   ```
3. If you published a new template version, users move to it deliberately with
   `kennel policy upgrade <name>` (it shows the source diff, asks for consent, and re-pins
   the lock — the sanctioned way to change a locked entry). If you re-signed a
   template *in place* (same version, new bytes), existing locks will mismatch
   (exit code 6) — that is the supply-chain tripwire working; prefer a version bump
   over an in-place re-sign so users get a reviewable upgrade rather than a hard
   error.
4. Re-verify: `ls -l /usr/libexec/kennel/kennel-privhelper` (still setuid-root)
   and a smoke `kennel run interactive -- /bin/true` as a provisioned user.

---

## See also

- `man kenneld`, `man system.toml`, `man subkennel`, `man config.toml`.
- [HOWTO.md](HOWTO.md) — authoring and running policies (user-facing).
- [INSTALL.md](INSTALL.md) — the installer in detail.
- [docs/architecture/01-process-model.md](docs/architecture/01-process-model.md),
  [07-paths.md](docs/architecture/07-paths.md) — the privilege and path models.
