# On-disk and runtime paths

This chapter is the path-layout reference. Every directory and file Project Kennel creates or expects is listed here, with ownership, mode, lifetime, and the component responsible. The set described here is the *stable surface*: paths a third party may write tooling against. Anything not listed here is implementation detail and may move between minor versions.

---

## Stability commitment

The paths in this chapter are **stable** per `02-0-overview.md`. They do not change within a major version. Operators may configure shell aliases, log-shipping rules, monitoring queries, and backup procedures against these paths and expect them to work across patch and minor updates.

Paths *not* in this chapter — temporary directories created by tests, internal cache files used by `kennel-policy`, paths under `OUT_DIR` at build time — are implementation detail. They are not listed because they may be removed or restructured at any time.

---

## User-scoped paths

These paths live under the running user's home directory and runtime directory. Per-user; not shared between users on a multi-user system.

### `~/.config/kennel/`

User configuration. Created by the CLI on first use if absent.

```
~/.config/kennel/
├── policies/                        run policies, one folder per policy
│   ├── ai-coding/
│   │   ├── policy.toml              source leaf (optionally signed)
│   │   ├── ai-coding.settled.toml   compiled + signed settled policy (what runs)
│   │   └── ai-coding.lock           lockfile beside the policy
│   ├── web-dev/
│   │   ├── policy.toml
│   │   ├── web-dev.settled.toml
│   │   └── web-dev.lock
│   └── ...
├── templates/                       user-installed templates and fragments
│   ├── ai-coding-strict@v4.toml     filename encodes the versioned reference
│   ├── corp-egress-allowlist@v2.33.2.toml
│   └── ...
├── keys/                            installed signing keys (public only)
│   ├── kennel-maint-2026-01.pub
│   ├── customer-org-key.pub
│   └── ...
└── audit.toml                       per-user audit-sink defaults (optional override of system default)
```

Owner: user. Mode: directory `0700`, files `0600`.

A run policy is a **folder** `policies/<name>/`, where `<name>` matches the policy's `name = "<name>"` field. Inside it: `policy.toml` is the source leaf; `<name>.settled.toml` is the compiled, signed settled policy — what `kennel run` actually enforces (`02-2-config-schema.md` §The settled policy); and `<name>.lock` records the signed content hash of every template and fragment the policy resolves (`02-2-config-schema.md` §The lockfile). `kennel run <name>` resolves the policy **by name** across the cascade (§Run-policy resolution) without a path; `kennel compile` writes the settled artefact and lockfile back into the folder. Templates and fragments are stored one file per `<name>@<version>`, so multiple versions of one name coexist; the resolver requires the exact pinned version and does not fall back to another.

### `~/.local/state/kennel/<kennel>/`

Per-kennel persistent state. Created by kenneld at first kennel start.

```
~/.local/state/kennel/<kennel>/
├── network.jsonl                    audit: network events (file sink)
├── filesystem.jsonl                 audit: filesystem events
├── exec.jsonl                       audit: exec events
├── unix.jsonl                       audit: AF_UNIX events
├── dbus.jsonl                       audit: D-Bus events
├── priv.jsonl                       audit: privhelper events
├── lifecycle.jsonl                  audit: kennel lifecycle events
├── network.<unix-ts>.jsonl(.gz)?    rotated files
├── ...
└── kennel-uuid                      single line: current kennel-instance UUID
```

Owner: user. Mode: directory `0700`, files `0600`.

The audit files exist only when the file sink is enabled (`02-3-audit-schema.md`). The directory itself exists for every kennel that has ever started, regardless of sink configuration, so that lifecycle metadata (`kennel-uuid`, `last-start-timestamp` and similar) has a home.

### `/run/user/<uid>/kennel/`

Per-user runtime state. Created by kenneld at startup; cleaned at logout.

```
/run/user/<uid>/kennel/
├── control.sock                     CLI ↔ kenneld control socket
├── proxy/                           per-kennel netproxy config (proxy-<ctx>.toml)
├── etc/  root/  bastion/            staged synthetic /etc, view roots, SSH bastion
├── bpf/                             bpffs holding the per-kennel BPF map pins (below)
```

Owner: user. Mode: directory `0700`, files `0600` (the socket too). The `bpf/`
subdirectory is a bpffs the privhelper mounts (it needs `CAP_SYS_ADMIN`); see
[`/run/user/<uid>/kennel/bpf/<id>/`](#runuseruidkennelbpfid).

Single-instance-per-user is provided by systemd socket activation (it owns the one bound listener), not a lock file: there is no `kenneld.lock` and no `kenneld.pid` (`05-state-and-supervision.md`).

`/run/user/<uid>/` is provided by `pam_systemd` on systemd systems (tmpfs, cleaned on logout). On non-systemd systems, kenneld creates `/run/user/<uid>/kennel/` itself with the appropriate mode and removes it on graceful shutdown.

### Per-kennel runtime state (under `/run/user/<uid>/kennel/`)

Kennel is per-user: every kennel's runtime state lives in the owning user's
`$XDG_RUNTIME_DIR` (`/run/user/<uid>/kennel/`, §`/run/user/<uid>/kennel/` above) —
`0700`, owned by the user, so two users running a kennel of the same name neither
collide nor see each other's. Per-kennel files within that tree are keyed by the
numeric context `<ctx>` (not the kennel name):

```
/run/user/<uid>/kennel/
├── proxy/proxy-<ctx>.toml           the per-kennel netproxy's config (kenneld writes, netproxy reads)
├── etc/etc-<ctx>/                   the per-kennel synthetic /etc, staged then bind-mounted
├── root/root-<ctx>/                 the constructed-view new-root mountpoint (pivot_root target)
├── ctx-<ctx>/binderfs/             the per-kennel binderfs instance staging mountpoint
└── bpf/<id>/                        the per-kennel BPF map pins (above)
```

Owner: user. Mode: directory `0700`, files `0600`.

The per-kennel binderfs instance (`02-4-binder.md`) is staged under `ctx-<ctx>/binderfs/`. binderfs carries `FS_USERNS_MOUNT`, so the instance is mounted inside the kennel's child user namespace by the privhelper factory, then ends up at `/dev/binderfs/` in the constructed view (below); kenneld reaches it for node 0 via `/proc/<init-host-pid>/root/dev/binderfs/binder`. The staging directory disappears with the child's mount namespace on kennel exit.

Inside the constructed view, the device follows the binderfs/Android convention: the instance mounts at `/dev/binderfs/`, the standard device is `/dev/binderfs/binder`, and `/dev/binder` is a symlink to it so a stock libbinder-shaped client finds the driver at its default path (`02-4-binder.md` §Device naming). These are *in-view* paths — the workload's, not the host's — and are listed here only because the device name is a stable contract; the rest of the view is out of scope for this chapter (§What this chapter does not cover). The privhelper factory chowns `/dev/binderfs/binder` to the operator uid (mode `0600`); `binder-control` stays root-only and is never granted to the workload.

The per-kennel egress proxy does **not** listen on a Unix socket: it listens on a
**TCP loopback address** — the kennel's own bit-packed `/28` (IPv4) or `/64`
(IPv6) address at the policy-given offset and port (offset 1, port 1080 by
default), e.g. `127.<…>:1080`. The address is computed from the kennel's tag/ctx
(`07-5-network.md` §7.5.2) and carried in the signed policy (`net.proxy`); kenneld
writes it into `proxy-<ctx>.toml` as the proxy's `listen` address. Reconfiguration
is by respawn with a fresh config file, not an on-socket control protocol — there
is no `proxy.ctl`/`proxy.sock`. The per-kennel ssh-agent and D-Bus proxy are
*future work* (`08-as-built-notes.md`); when built, their sockets stage under this
same per-user tree, never a shared one.

**Roadmap — the host loopback alias.** The per-kennel network-namespace redesign
(`02-5-binder-net.md`, design `07-11-binder-netns.md`) adds a *host-side* alias:
the kennel's own `/28` (IPv4) and `/64` (IPv6) are added to the host's `lo`
interface (the privhelper's `AddLoopbackAlias`/`RemoveLoopbackAlias` ops), so an
allowed in-kennel bind can be mirrored to the same `ip:port` host-side for host
observability and ingress. This is **not built**: the kennel still shares the host
network namespace, and the kennel's `/28`+`/64` is used today only as the egress
proxy's loopback listen address (above), not as a host `lo` alias.

---

## System-scoped paths

These paths are managed at install time and survive across user sessions. They are read by every running kennel; some are writable only by root.

### `/etc/kennel/`

System configuration. Installed by the package; managed by the administrator.

```
/etc/kennel/
├── templates/                       system-installed templates and fragments
│   ├── base-confined@v3.toml
│   ├── ai-coding-strict@v4.toml
│   └── ...
├── policies/                        system-installed run policies (folder per policy)
│   ├── ai-coding/
│   │   ├── policy.toml
│   │   ├── ai-coding.settled.toml
│   │   └── ai-coding.lock
│   └── ...
├── keys/                            project + org signing keys (shipped or pushed)
│   ├── kennel-maint-2026-01.pub
│   ├── corp-policy-2026.pub
│   └── ...
├── audit.toml                       installation-wide audit-sink defaults
├── system.toml                      deployment paths: libexec_dir, trust_dir, sshd (admin layer)
└── config.toml                      CLI conveniences: template/key/policy search dirs (admin layer)
```

Owner: root. Mode: directory `0755`, files `0644`. The `keys/` directory holds public keys only; private keys are not in this tree.

The installer creates `keys/`, `templates/`, and `policies/` (and the matching vendor dirs under `/usr/lib/kennel/`). It ships no reference policies — policies are user/org content; the shipped baseline is `templates/`. A `policies/<name>/` here is a system-staged run policy, structurally identical to the user's (§`~/.config/kennel/`); `kennel run <name>` finds it when no higher-priority user policy of that name exists (§Run-policy resolution).

**No install path is baked into a binary.** Deployment paths — the helper-binary directory (`libexec_dir`, default `/usr/libexec/kennel`), the daemon's signing-key `trust_dir` (default `/etc/kennel/keys`), and the host `sshd` — are expressed in `system.toml`, resolved through a cascade by the `kennel-config` crate. The cascade reads lowest-priority first, a higher layer overriding a lower one **per key**, with compiled-in fallback defaults so a host with no config files still runs:

* **`system.toml`** (deployment, integrity-sensitive) resolves from **root-owned dirs only** — `/usr/lib/kennel` (vendor) then `/etc/kennel` (admin). It is deliberately **not** read from the user's `~/.config`, and honours no environment override: `kenneld` runs as the user, so letting the user redirect `trust_dir` would defeat policy signing. Each helper binary defaults to `<libexec_dir>/<name>`; an explicit per-binary key overrides one.
* **`config.toml`** (CLI conveniences — template, key, and policy *search* dirs) resolves from `~/.config/kennel` then `/etc/kennel` then `/usr/lib/kennel`. Safe to be user-writable: it only steers where the CLI looks while authoring; the daemon re-verifies against the locked `system.toml` `trust_dir` (plus the user's own `keys/` for run policies, §Policy-signing trust split) at run.

The per-*user* loopback allocation — the 12-bit IPv4 `tag` and the 40-bit IPv6 ULA `gid` — is **not** in either file; it lives in `/etc/kennel/subkennel` (`<uid>:<tag>:<gid>:<namespace>`), kernel-trusted, and the daemon loads it from there to fill `<tag>`/`<gid>` at spawn. `kennel subkennel add` generates a valid line (collision-free `tag`/`gid`); the `<namespace>` defaults to `kennel-<user>`.

### `/sys/fs/cgroup/<namespace>/`

Project Kennel's cgroup hierarchy. `<namespace>` is the caller's resource namespace from their `/etc/kennel/subkennel` allocation (default `kennel-<user>`), and the per-kennel leaf is keyed by the numeric context byte `<ctx>`, not the kennel name.

```
/sys/fs/cgroup/<namespace>/
├── <ctx>/                           per-kennel cgroup; workloads in cgroup.procs
│   ├── cgroup.procs
│   ├── cgroup.controllers
│   └── ... (standard cgroup v2 files)
└── ...
```

Owner: user (kenneld creates the cgroup itself, unprivileged, within its delegated subtree).

Mode and ownership follow the system's cgroup delegation policy. Modern systemd configurations delegate `/sys/fs/cgroup/user.slice/user-<uid>.slice/` to the user, and Project Kennel's `<namespace>/` subtree lives within that delegation. kenneld — not the privhelper — creates and removes the per-kennel cgroup; the privhelper only *attaches* the egress BPF to a cgroup whose ownership it re-validates against the caller's allocation.

### `/run/user/<uid>/kennel/bpf/<id>/`

Per-kennel BPF map pinning, for the audit ring-buffer drain and for owner
inspection. The pins live in the **owner's own `$XDG_RUNTIME_DIR`** — systemd's
per-user `/run/user/<uid>/` tree (`0700`, owned by the user) — so isolation is
*structural*, not a permissions game in a shared directory. The privhelper mounts
a bpffs at `/run/user/<uid>/kennel/bpf/` (alongside kenneld's other per-user
runtime state) and pins each kennel's shared map set under it:

```
/run/user/<uid>/                     systemd per-user runtime dir (0700, owned by the user)
└── kennel/bpf/                      bpffs the privhelper mounts (owner-only, 0700)
    └── <id>/                        per-kennel pin dir (owner-only, 0700)
        ├── audit_ringbuf            pinned ringbuf — kenneld obj_gets + drains it
        ├── kennel_meta_map          pinned BPF maps (owner inspects with bpftool)
        ├── allow_v4
        ├── allow_v6
        ├── deny_v4
        ├── deny_v6
        └── bind_subnet_map
```

A kennel's programs share one map set (`kennel_bpf::create_maps` +
`load_program_against`), so there is exactly one `audit_ringbuf` per kennel and one
coherent set to pin. Because the whole `/run/user/<uid>/` tree is already private to
the user, this design needs no shared `/run/kennel/bpf` directory, no `kennel-readers`
group, and no `0711` hide-and-seek: another user simply cannot reach into another's
`$XDG_RUNTIME_DIR`. It also falls out for free that:

- **No collisions** — each user has their own runtime dir, so two users can both run
  a kennel named `dev` without clashing (the uid is in the path).
- **No cross-user clobber** — the root privhelper resolves the path from its own
  *real* uid (it is setuid-root but runs for the calling user), never the wire, so it
  only ever writes — and clears stale pins — under the caller's own
  `/run/user/<uid>/`. It can never touch another user's pins even though privileged.

The bpffs, the per-kennel dir, and the pins are all owner-only (`0700`/`0700`/`0600`,
no OS group): the unprivileged kenneld `BPF_OBJ_GET`s the ring buffer to drain it and
the owner inspects the maps with `bpftool`. Multiple users run kennels side by side,
none the wiser of the others. kenneld removes the pin dir when its kennel exits; the
bpffs mount is cleaned up with the rest of `/run/user/<uid>/` at logout.

The uid is resolved from the running user (not `$XDG_RUNTIME_DIR` in the environment)
so the privileged helper and the unprivileged daemon agree on the path without one
trusting the other's environment; in the standard systemd case this *is*
`$XDG_RUNTIME_DIR/kennel/bpf`.

Not `/sys/fs/bpf/kennel/` (the obvious bpffs): systemd mounts `/sys/fs/bpf`
`mode=700`, so an unprivileged kenneld cannot traverse it to reopen the ring
buffer. The owning user's `$XDG_RUNTIME_DIR` is both reachable by that user and
private from every other, so the pins live on a bpffs there instead.

The workload never sees this tree — the shim does not bind-mount the runtime bpffs
into the kennel's view.


### Binary install paths

| Binary | Default install path | Notes |
|---|---|---|
| `kennel` | `/usr/bin/kennel` | The CLI; user binary, no special permissions. |
| `kenneld` | `/usr/libexec/kennel/kenneld` | Started by systemd-user or by the CLI in degraded mode; not on `PATH`. |
| `kennel-init` | `/usr/libexec/kennel/kennel-init` | The kennel's PID 1 / supervisor (§7.2, `../design/07-2-kennel-init.md`); root-owned and non-writable (`0755`, owner root, no setuid/setcap). The privhelper verifies its root ownership + non-writability, opens it on the host pre-`clone`, and `fexecve`s it after `pivot_root`. Its path comes from the deployment config (`Deployment::kennel_init()` → libexec), never the wire. Not on `PATH`; located by absolute path. |
| `kennel-privhelper` | `/usr/libexec/kennel/kennel-privhelper` | `install.sh` installs it setuid root (mode `4755`, owner root); file capabilities `cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin,cap_net_admin=ep` are a documented per-distribution alternative the installer does not itself apply. The privhelper is the kennel *constructor* (`../design/07-2-kennel-init.md`): it clones the namespaces as the operator (so the userns is operator-owned), writes the identity map (host root `0 0 1` + the operator line + one line per granted gid) in a single `write(2)`, builds the root-owned surfaces, mounts binderfs, `pivot_root`s, and `fexecve`s `kennel-init`. `cap_setuid` writes the `0 0 1` uid map (the kennel's real uid 0); `cap_setgid` writes the `gid_map` so a workload keeps a granted supplementary group (§7.4.8); `cap_setfcap` lets the single map `write(2)` land; `cap_sys_admin` mounts (view, `/dev`, binderfs) and `pivot_root`s; `cap_net_admin` is for loopback addresses and egress BPF. Not on `PATH`; located by absolute path from kenneld. |
| `kennel-netproxy` | `/usr/libexec/kennel/kennel-netproxy` | Spawned by kenneld; not on `PATH`. |
| `kennel-akc` | `/usr/libexec/kennel/kennel-akc` | The SSH bastion's root-owned `AuthorizedKeysCommand` (§7.10); installed root-owned (safe-path), queries kenneld; not on `PATH`. |
| `kennel-socks-connect` | `/usr/libexec/kennel/kennel-socks-connect` | The `ProxyCommand` bridging a kennel's `ssh` to its egress proxy (§7.10); bound into the view with a Landlock execute grant. |

Distributions relocate the libexec directory with `install.sh --prefix <dir>`, which installs the binaries there and rewrites `libexec_dir` in the deployment `system.toml` (and the `kenneld.service` `ExecStart` and the AppArmor profile path) to match — no path is baked into a binary. The default `/usr/libexec/kennel` matches the FHS recommendation.

---

## Templates and template search

A versioned reference (`<name>@<version>`, `02-2-config-schema.md`) resolves against this search order (highest priority first):

1. `~/.config/kennel/templates/<name>@<version>.toml` (user-installed).
2. `/etc/kennel/templates/<name>@<version>.toml` (system-installed).
3. Built-in templates compiled into the `kennel` binary (`base-confined` only, at present).

The resolver requires the *exact* `<name>@<version>`; it does not fall back to a different version of the same name, since that would defeat the pin. A given `<name>@<version>` at a higher-priority location shadows the identical reference at lower priority; the shadowing is logged at policy-load time so the operator can detect surprises. The resolved artefact's signature is verified and its content hash checked against the leaf policy's lockfile before composition (`04-trust-boundaries.md` boundary 3).

---

## Run-policy resolution

`kennel run <policy> [<name>] -- <cmd>` resolves `<policy>` to a settled artefact:

1. If `<policy>` is an **existing file path**, it is used verbatim (a settled artefact is enforced as-is; a source leaf is compiled-and-signed in memory for the run, needing `--key`).
2. Otherwise `<policy>` is a **name** searched in the `policies/` cascade (highest priority first):
   1. `~/.config/kennel/policies/<name>/` (user).
   2. `/etc/kennel/policies/<name>/` (system).
   3. `/usr/lib/kennel/policies/<name>/` (vendor).
   Within the first folder found, `<name>.settled.toml` is preferred (the production artefact); failing that, `policy.toml` is compiled-and-signed in memory (needs `--key`).

The kennel instance `<name>` (second positional) is **optional** and defaults to the resolved policy name, so `kennel run ai-coding -- bash` runs `policies/ai-coding/` as a kennel named `ai-coding`. A name is a single safe path component (no `/`, `..`, or whitespace).

### Policy-signing trust split

Two distinct trust scopes, by layer:

- **Templates** — the security baseline (framework invariants + confinement floor) — verify **only against system keys** (`/etc/kennel/keys`, `/usr/lib/kennel/keys`), never the user's `~/.config/kennel/keys`. A template signed by a user key is rejected at compile time. (`kennel-config::User::system_key_dirs`.)
- **Run policies** — the settled leaf the daemon enforces — verify against **system keys *or* the user's own `~/.config/kennel/keys`**. A user may run a policy signed with their own key: a leaf can only narrow *within* the template's re-asserted invariants and a kennel runs with the user's own authority, so trusting the user's own run-policy signature grants no escalation. The daemon loads system keys then the user's, system winning a key-id clash (a user key cannot shadow a system key id). (`kenneld` `TrustStoreLoader::from_dirs`.)

This is detailed in `04-trust-boundaries.md`.

---

## Lifetime summary

| Path | Created by | Destroyed by | Persists across |
|---|---|---|---|
| `~/.config/kennel/` | Operator | Operator | All restarts and reboots |
| `~/.local/state/kennel/<kennel>/` | kenneld (first kennel start) | Operator (audit retention) | All restarts and reboots |
| `/run/user/<uid>/kennel/` | kenneld (startup) | logout (systemd) or kenneld (graceful shutdown) | User session |
| `/run/user/<uid>/kennel/{proxy,etc,root}/…-<ctx>` | kenneld (kennel start) | kenneld (immediately on workload exit) | Kennel lifetime |
| `/run/user/<uid>/kennel/ctx-<ctx>/binderfs/` | privhelper factory (kennel start) | child mount-ns teardown (workload exit) | Kennel lifetime |
| `/sys/fs/cgroup/<namespace>/<ctx>/` | kenneld (unprivileged, in its delegated subtree) | kenneld (immediately on workload exit) | Kennel lifetime |
| `/run/user/<uid>/kennel/bpf/<id>/` | privhelper (egress setup; pins chowned to the caller) | kenneld (immediately on workload exit) | Kennel lifetime |
| `/etc/kennel/` | Package installation | Package removal | All restarts and reboots |

---

## Path variable substitution

Paths in policies may use placeholders that are resolved at policy-load time. These are documented in `02-2-config-schema.md`; reproduced here for path-context convenience:

| Placeholder | Meaning |
|---|---|
| `<kennel>` | The kennel's runtime ID (e.g., `ai-coding`). |
| `<uid>` | The user's UID as a decimal string. |
| `<tag>` | The caller's 12-bit IPv4 loopback tag, from `/etc/kennel/subkennel` (per-user). |
| `<ctx>` | The kennel's allocated context byte (per-kennel). |
| `<gid>` | The caller's 40-bit IPv6 ULA global ID, from `/etc/kennel/subkennel` (per-user). |

`<id>` in this chapter is equivalent to `<kennel>` after substitution; the variant is used in path templates because some paths use the runtime ID even for ad-hoc kennels that do not have a user-facing name.

---

## Permissions and security properties

Each path's mode and ownership are part of its security contract. The most-load-bearing:

- **`~/.local/state/kennel/<kennel>/`** mode `0700`: the workload (running as the same UID) is denied access because the shim does not bind-mount this directory into the workload's view. The mode is belt-and-braces.
- **`/run/user/<uid>/kennel/control.sock`** mode `0600`: only the owning user may connect. kenneld additionally validates via `SO_PEERCRED` (boundary 7 in `04-trust-boundaries.md`).
- **`/run/user/<uid>/kennel/bpf/<id>/`** in the owner's private `$XDG_RUNTIME_DIR`; bpffs, per-kennel dir, and pins all **owner-only** (`0700`/`0700`/`0600`, chowned to the caller, no shared group): the owning user's kenneld reopens the ring buffer to drain it and the owner inspects the maps with `bpftool`; no other user can reach into `/run/user/<uid>/` at all. Because the path is in the user's own runtime dir (resolved from the caller's real uid, never the wire), per-user kennel names cannot collide and the root privhelper can only ever touch the caller's own subtree (no cross-user clobber). Kennel is per-user — isolation is structural, by ownership; there is no OS-level "readers" group.
- **`/etc/kennel/keys/*.pub`** mode `0644`: public keys; world-readable is fine. Private keys are not in this tree.
- **`kennel-privhelper`** setuid root (as installed; file capabilities a per-distribution alternative): a compromise of the calling process (kenneld) does not automatically gain privilege; the privhelper validates every request per `04-trust-boundaries.md` boundary 1.

---

## What this chapter does not cover

- The set of paths the workload sees (the constructed shim view): TEMPLATE-ai-coding-strict.md and design doc §7.4.
- How paths flow through the policy parser (tilde expansion, canonicalisation, traversal-rejection): CODING-STANDARDS.md §10 and `kennel-policy::path`.
- File-rotation algorithm for audit logs: `05-state-and-supervision.md`.
- The install-time relocation of paths: `06-build-and-test.md` and `install.sh --prefix`, which rewrites `libexec_dir` in the deployment `system.toml`.
- Whether the workload has access to any of these paths: it does not, except via explicit policy grant; the shim is the mechanism (`04-trust-boundaries.md` boundary 12).
