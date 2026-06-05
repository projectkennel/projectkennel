# Runbook: get an interactive bash prompt inside a kennel (production daemon path)

> ⚠️ SUPERSEDED (config-layer / D11): the gaps below are largely fixed now. The
> daemon resolves paths from `/etc/kennel/system.toml` + `/usr/lib/kennel/system.toml`
> (default `/usr/libexec/kennel`, trust dir `/etc/kennel/keys`), and `install.sh`
> now installs to `/usr/libexec/kennel`, ships the vendor config, installs the
> AppArmor profile (G1/G2), and installs all binaries (G5). The manual `/opt`
> workarounds and the profile `sed`-to-`/opt` step below are obsolete — a plain
> `sudo src/tools/install.sh` plus a dev signing key (G3) + a bash-allowing
> policy (G4) is the path now. Kept for the G3/G4 steps only.
>
> Scratch doc — untracked, delete when done. Verified against the tree at HEAD
> (`0302c35`) on this host (Ubuntu, uid 1000, kernel 6.17,
> `apparmor_restrict_unprivileged_userns=1`). Your `/etc/kennel/subkennel`
> already has `1000:42:0000000002:kennel-dev`, so allocation is done.

This drives the real architecture: `kennel` (client) → `kenneld` (per-user
daemon) → setuid `kennel-privhelper`, with a signed, compiled policy. It is
deliberately the long way round so you see exactly where it breaks.

---

## The gaps you WILL hit (read first)

These are real defects/mismatches in the current tree, not user error. Each step
below works around the relevant one.

- **G1 — trust-dir mismatch.** The daemon reads trusted keys from
  `/etc/kennel/trust` (`kenneld/src/policy.rs:21`, `DEFAULT_TRUST_DIR`), but
  `install.sh` populates `/etc/kennel/keys` (`install.sh:106,121`). Left alone,
  the daemon trusts **nothing** and every `kennel run` fails verification.
  → Step 3 copies the dev pubkey into `/etc/kennel/trust`.
- **G2 — AppArmor path mismatch, and the profile isn't installed at all.** On
  this host the userns is blocked unless the kennel AppArmor profile grants
  `userns` to the binary that creates it. `install.sh` never installs
  `dist/apparmor/kenneld`, **and** that profile attaches to
  `/usr/libexec/kennel/kenneld` (`dist/apparmor/kenneld:61`) while `install.sh`
  installs the daemon at `/opt/kennel/bin/kenneld` and points systemd there
  (`kenneld.service:14`). → Step 2 installs the profile **and** rewrites its path.
- **G3 — no keygen tooling.** There is no `kennel keygen`. A signing key is just a
  base64 32-byte seed in a file whose stem is the key_id
  (`kennel.rs:534-544`). → Step 3 makes one with `openssl rand`.
- **G4 — no template runs a shell.** Every shipped template has an `exec.allow`
  that excludes `bash`/`sh` on purpose. → Step 4 authors a leaf that allows bash.
- **G5 — install.sh omits three binaries.** It installs only
  `kenneld kennel kennel-netproxy` + the privhelper (`install.sh:84-93`), but the
  daemon's identity references `/opt/kennel/bin/kennel-{socks-connect,ssh-reorigin,akc}`
  (`kenneld.rs:77-83`). Harmless for a `net=none` / no-SSH bash (the bastion is
  configured but never launched), but install them anyway so nothing latent bites.
- **G6 — `/etc/kennel/scope` is vapour.** `install.sh`'s next-steps tell you to
  create it; no code reads it. Ignore it. (`InstallConstants` are hardcoded
  `tag=42, ula_gid="fd00::"` in `kennel.rs` compile.) Your subkennel tag is 42, so
  this lines up.

---

## Step 0 — build everything (release)

```bash
cd /home/remco/src/kennel
cargo build --release -p kenneld -p kennel-netproxy \
                       -p kennel-socks-connect -p kennel-ssh-reorigin
# privhelper MUST carry its BPF feature or live egress paths fail with ENOSYS:
cargo build --release -p kennel-privhelper --features bpf-egress
```

`-p kenneld` builds the `kenneld`, `kennel`, and `kennel-akc` bins.

## Step 1 — system install to /opt + the three missing bins

```bash
sudo src/tools/install.sh --no-build         # --no-build: reuse Step 0's target/release
# G5: hand-install the binaries install.sh forgot
sudo install -m0755 target/release/kennel-socks-connect \
                    target/release/kennel-ssh-reorigin \
                    target/release/kennel-akc \
                    /opt/kennel/bin/
# sanity: the privhelper must be setuid-root
ls -l /opt/kennel/sbin/kennel-privhelper       # expect -rwsr-xr-x root root
```

Put the installed CLI on PATH for the rest of this runbook:

```bash
export PATH=/opt/kennel/bin:$PATH
```

## Step 2 — unlock the user namespace via AppArmor (G2)

```bash
sudo install -m0644 dist/apparmor/kenneld /etc/apparmor.d/kenneld
# rewrite the attachment path to where install.sh actually put kenneld:
sudo sed -i 's#/usr/libexec/kennel/kenneld#/opt/kennel/bin/kenneld#' /etc/apparmor.d/kenneld
sudo apparmor_parser -r -W /etc/apparmor.d/kenneld
```

Quick smoke test that the restriction is the only thing in the way (this still
fails — `unshare` has no profile — but confirms the mechanism):

```bash
unshare --user --map-root-user true && echo "userns OK" || echo "userns blocked (expected for unshare)"
```

> Escape hatch if AppArmor fights you: `sudo sysctl -w
> kernel.apparmor_restrict_unprivileged_userns=0` disables the restriction
> host-wide (less clean; revert with `=1`).

## Step 3 — dev signing key + trust store (G1, G3)

```bash
mkdir -p ~/.config/kennel/keys
# G3: a signing key is just a base64 32-byte seed; the filename stem is the key_id
openssl rand 32 | base64 -w0 > ~/.config/kennel/keys/dev.key
printf '\n' >> ~/.config/kennel/keys/dev.key
chmod 600 ~/.config/kennel/keys/dev.key

# Derive the matching PUBLIC key. There's no "show pubkey" command, so sign any
# template and copy the base64 it prints:
kennel sign templates/inspect-only/policy.toml --key ~/.config/kennel/keys/dev.key
# → prints: install this public key in the trust store as `dev.pub`: <BASE64>
```

Take that `<BASE64>` and install it in **both** stores (G1):

```bash
PUB='<paste the BASE64 from kennel sign>'
# DAEMON reads here (the gap):
sudo install -d -m0755 /etc/kennel/trust
echo "$PUB" | sudo tee /etc/kennel/trust/dev.pub >/dev/null
# CLI validate/compile reads here (optional, for `kennel validate`):
echo "$PUB" > ~/.config/kennel/keys/dev.pub
```

The maintainer pubkey (`keys/kennel-maint-2026.pub`) is already installed to
`/etc/kennel/keys` by `install.sh` — `kennel compile` needs it to verify the
`base-confined@v1` parent in Step 5.

## Step 4 — author a leaf policy that allows bash (G4)

```bash
cat > /tmp/dev-bash.toml <<'TOML'
template_base = "base-confined@v1"
template_name = "dev-bash"
template_version = "1"

# No network: skips the egress proxy/BPF/addresses entirely — simplest first run.
[net]
mode = "none"

# bash itself, plus a few coreutils so the shell can actually exec things.
# (Builtins like cd/echo work regardless; external commands must be allowlisted.)
[exec]
allow = [
  "/usr/bin/bash",
  "/usr/bin/ls", "/usr/bin/cat", "/usr/bin/env", "/usr/bin/pwd",
  "/usr/bin/id", "/usr/bin/grep", "/usr/bin/find", "/usr/bin/ps",
]
TOML
```

`base-confined` already grants `[fs].read` over `/usr/**`, `/lib/**`, `/lib64/**`
(the loader + libc + bash) and sets `[exec].path` to `/usr/bin:/usr/local/bin:/bin`.

## Step 5 — compile + sign into a settled policy

```bash
kennel compile /tmp/dev-bash.toml \
  --key ~/.config/kennel/keys/dev.key \
  --template-dir templates \
  --trust-dir keys \
  --output-path /tmp/dev-bash.settled
```

`--template-dir templates` finds the `base-confined` parent (nested
`name/policy.toml` layout); `--trust-dir keys` verifies its maintainer signature.
If `compile` rejects a **framework invariant**, it names it — that tells you which
field of the leaf the invariant set forbids.

## Step 6 — start the daemon (socket-activated)

```bash
systemctl --user daemon-reload
systemctl --user enable --now kenneld.socket
```

The daemon comes up inside `user@<uid>.service`, which is where its cgroup
delegation lives. (It reads `/etc/kennel/subkennel` for your uid — already
present — and `/etc/kennel/trust` for keys — populated in Step 3.)

## Step 7 — run bash

```bash
kennel run /tmp/dev-bash.settled mybash -- /usr/bin/bash -i
```

You should land at a prompt **inside** the kennel: a fresh user namespace
(`id` shows your mapped identity), a pivoted root with only the granted read
paths, a synthetic `/etc`, a private `/tmp`, no network, Landlock + seccomp
active. Try `ls /`, `ls /home`, `cat /etc/hostname`, `ps aux`. `exit` tears it down.

---

## When it breaks — where to look

- **`cannot reach kenneld at … is the kenneld.socket user unit enabled?`**
  → Step 6 didn't take. `systemctl --user status kenneld.socket`.
- **Daemon log shows userns / `uid_map`/`gid_map` `EPERM` or `EACCES`**
  → G2: the AppArmor profile path doesn't match the running binary. Confirm
  `head -1 /proc/$(pgrep -x kenneld)/…` path vs the `profile … /opt/kennel/bin/kenneld`
  line, re-`apparmor_parser -r`. Or use the sysctl escape hatch.
- **`kennel run` → policy verification / signature error**
  → G1: `dev.pub` isn't in `/etc/kennel/trust`, or its base64 doesn't match the
  seed in `dev.key`. Re-derive with `kennel sign` and reinstall.
- **`kennel compile` → untrusted key / bad signature on the parent**
  → maintainer pubkey missing from `--trust-dir`. Pass `--trust-dir keys`
  (repo dir) explicitly, or confirm `/etc/kennel/keys/kennel-maint-2026.pub`.
- **bash starts but `ls`/`ps` say "permission denied" or "not found"**
  → that binary isn't in the leaf's `exec.allow`, or its real path differs from
  `/usr/bin/...`. Add it and recompile (Step 5).
- **Daemon log: cgroup create/join `EACCES`**
  → cgroup delegation isn't reaching the user service. Reproduce the e2e's
  fallback: stop the unit and run the daemon by hand under a delegated scope:
  `systemd-run --user --scope -p Delegate=yes /opt/kennel/bin/kenneld`.
- **Read daemon logs:** `journalctl --user -u kenneld.service -f` (or run it in
  the foreground via the `systemd-run` line above to watch it live).

---

## Teardown

```bash
systemctl --user disable --now kenneld.socket
sudo rm -f /etc/apparmor.d/kenneld && sudo apparmor_parser -R /etc/apparmor.d/kenneld 2>/dev/null
# /opt/kennel and /etc/kennel/{trust,keys} left in place; remove if you want a clean slate.
rm -f /tmp/dev-bash.toml /tmp/dev-bash.settled RUN-BASH-IN-A-KENNEL.md
```
