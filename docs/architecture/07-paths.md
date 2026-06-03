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
├── kennels/                         leaf policy files (one per kennel)
│   ├── ai-coding.toml
│   ├── ai-coding.lock               lockfile beside each leaf policy
│   ├── ai-coding.settled.toml       compiled settled policy (dev mode)
│   ├── web-dev.toml
│   ├── web-dev.lock
│   ├── web-dev.settled.toml
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

The `kennels/<name>.toml` filename and the policy's `name = "<name>"` field must match; the loader rejects on mismatch. The `kennels/<name>.lock` lockfile sits beside its policy and records the signed content hash of every template and fragment the policy resolves (`02-2-config-schema.md` §The lockfile). The `kennels/<name>.settled.toml` is the compiled settled policy in development mode — what `kennel run` actually enforces (`02-2-config-schema.md` §The settled policy); it is regenerated when the source or lockfile changes. Templates and fragments are stored one file per `<name>@<version>`, so multiple versions of one name coexist; the resolver requires the exact pinned version and does not fall back to another.

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
├── kenneld.sock                     CLI ↔ kenneld control socket
├── kenneld.lock                     flock target: one kenneld per user
└── kenneld.pid                      kenneld's own PID (single line)
```

Owner: user. Mode: directory `0700`, files `0600` (the socket too).

`/run/user/<uid>/` is provided by `pam_systemd` on systemd systems (tmpfs, cleaned on logout). On non-systemd systems, kenneld creates `/run/user/<uid>/kennel/` itself with the appropriate mode and removes it on graceful shutdown.

### `/run/kennel/<id>/`

Per-kennel runtime state. Created by kenneld; cleaned immediately when the workload exits.

```
/run/kennel/<id>/
├── proxy.sock                       netproxy listen socket (SOCKS5; user-facing)
├── proxy.ctl                        kenneld → netproxy control socket
├── proxy.pid                        netproxy's PID
├── ssh-agent.sock                   ssh-agent socket (shim-mounted into workload's $HOME)
├── ssh-agent.pid
├── dbus-proxy.sock                  dbus-proxy socket (shim-mounted)
├── dbus-proxy.ctl
├── dbus-proxy.pid
├── kennel.lock                      flock target: per-kennel exclusion (rare; guards concurrent bring-up of one kennel)
└── kennel.json                      current kennel metadata (uuid, ctx, policy_hash)
```

Owner: user. Mode: directory `0700`, files `0600`.

Note: `/run/kennel/` itself (without the `<id>` suffix) is owned by root, mode `0755`, so that kennels from different users can coexist (each user's kennel directory is under `/run/kennel/<id>` with `<id>` being globally unique, but the user's per-kennel directories are user-owned).

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
├── settled/                         fleet-pushed signed settled policies (attested mode)
│   ├── ai-coding.settled.toml
│   └── ...
├── keys/                            project + org signing keys (shipped or pushed)
│   ├── kennel-maint-2026-01.pub
│   ├── corp-policy-2026.pub
│   └── ...
├── audit.toml                       installation-wide audit-sink defaults
└── kennel.conf                      project-wide configuration (tag byte, ULA prefix, kernel-feature overrides)
```

Owner: root. Mode: directory `0755`, files `0644`. The `keys/` directory holds public keys only; private keys are not in this tree.

In an attested deployment, `settled/` holds the signed settled policies pushed by the organisation's central compile infrastructure. The workstation enforces these directly (`02-2-config-schema.md` §The settled policy); it need not hold the `templates/`, the lockfiles, or exercise the resolver. `kennel run` verifies the settled policy's signature against a key in `keys/` and spawns.

The `kennel.conf` file pins per-installation settings that are stable for the life of the installation: the `<tag>` byte for IPv4 loopback allocation, the IPv6 ULA `/48` prefix, the path to the privhelper binary, optional overrides for kernel-feature detection (used when an environment under-reports its capabilities).

### `/sys/fs/cgroup/kennel/`

Project Kennel's cgroup hierarchy.

```
/sys/fs/cgroup/kennel/
├── <id>/                            per-kennel cgroup; workloads in cgroup.procs
│   ├── cgroup.procs
│   ├── cgroup.controllers
│   └── ... (standard cgroup v2 files)
└── ...
```

Owner: user on systems with cgroup v2 delegation; root otherwise (privhelper creates).

Mode and ownership follow the system's cgroup delegation policy. Modern systemd configurations delegate `/sys/fs/cgroup/user.slice/user-<uid>.slice/` to the user, and Project Kennel's `kennel/` subtree lives within that delegation. On systems without delegation, the privhelper creates the cgroup with the user's ownership.

### `/sys/fs/bpf/kennel/`

BPF map and program pinning.

```
/sys/fs/bpf/kennel/
├── <id>/                            per-kennel BPF state
│   ├── kennel_meta                  pinned BPF map
│   ├── allow_v4
│   ├── allow_v6
│   ├── deny_v4
│   ├── deny_v6
│   ├── bind_subnet
│   └── progs/                       pinned program references (for debug inspection)
└── ...
```

Owner: root. Mode: directory `0750`, files `0640`. Group: `kennel-readers` (created at install time; operators in this group can `bpftool map dump` the pins).

The workload never sees this tree — the shim does not bind-mount `/sys/fs/bpf` into the kennel's view.

### `/run/kennel/privhelper.lock`

Machine-wide flock target for serialising privhelper invocations in degraded mode. Owner: root. Mode: `0600`. Created at first privhelper invocation; persists across reboots if the path is in `/run/` (which is tmpfs; recreated at boot).

### Binary install paths

| Binary | Default install path | Notes |
|---|---|---|
| `kennel` | `/usr/bin/kennel` | The CLI; user binary, no special permissions. |
| `kenneld` | `/usr/libexec/kennel/kenneld` | Started by systemd-user or by the CLI in degraded mode; not on `PATH`. |
| `kennel-privhelper` | `/usr/libexec/kennel/kennel-privhelper` | Installed setuid root OR with file capabilities `cap_net_admin,cap_sys_admin,cap_setgid=ep` (per-distribution choice). `cap_setgid` is for the `set-gid-map` op — writing a workload's user-namespace `gid_map` so it keeps a granted supplementary group (§7.2.8); the other two are for loopback addresses and egress BPF. Not on `PATH`; located by absolute path from kenneld. |
| `kennel-netproxy` | `/usr/libexec/kennel/kennel-netproxy` | Spawned by kenneld; not on `PATH`. |
| `kennel-ssh-agent` | `/usr/libexec/kennel/kennel-ssh-agent` | Spawned by kenneld (when the policy enables it); not on `PATH`. |

Distributions may relocate by setting `KENNEL_LIBEXEC_DIR` at build time. The default matches the FHS recommendation.

---

## Templates and template search

A versioned reference (`<name>@<version>`, `02-2-config-schema.md`) resolves against this search order (highest priority first):

1. `~/.config/kennel/templates/<name>@<version>.toml` (user-installed).
2. `/etc/kennel/templates/<name>@<version>.toml` (system-installed).
3. Built-in templates compiled into the `kennel` binary (`base-confined` only, at present).

The resolver requires the *exact* `<name>@<version>`; it does not fall back to a different version of the same name, since that would defeat the pin. A given `<name>@<version>` at a higher-priority location shadows the identical reference at lower priority; the shadowing is logged at policy-load time so the operator can detect surprises. The resolved artefact's signature is verified and its content hash checked against the leaf policy's lockfile before composition (`04-trust-boundaries.md` boundary 3).

---

## Lifetime summary

| Path | Created by | Destroyed by | Persists across |
|---|---|---|---|
| `~/.config/kennel/` | Operator | Operator | All restarts and reboots |
| `~/.local/state/kennel/<kennel>/` | kenneld (first kennel start) | Operator (audit retention) | All restarts and reboots |
| `/run/user/<uid>/kennel/` | kenneld (startup) | logout (systemd) or kenneld (graceful shutdown) | User session |
| `/run/kennel/<id>/` | kenneld (kennel start) | kenneld (immediately on workload exit) | Kennel lifetime |
| `/sys/fs/cgroup/kennel/<id>/` | privhelper or systemd delegation | kenneld (immediately on workload exit) | Kennel lifetime |
| `/sys/fs/bpf/kennel/<id>/` | kenneld (kennel start) | kenneld (immediately on workload exit) | Kennel lifetime |
| `/etc/kennel/` | Package installation | Package removal | All restarts and reboots |
| `/run/kennel/privhelper.lock` | First privhelper invocation | Reboot (tmpfs) | Reboot |

---

## Path variable substitution

Paths in policies may use placeholders that are resolved at policy-load time. These are documented in `02-2-config-schema.md`; reproduced here for path-context convenience:

| Placeholder | Meaning |
|---|---|
| `<kennel>` | The kennel's runtime ID (e.g., `ai-coding`). |
| `<uid>` | The user's UID as a decimal string. |
| `<tag>` | The installation's tag byte (fixed at install time). |
| `<ctx>` | The kennel's allocated context byte (per-kennel). |
| `<gid>` | The installation's IPv6 ULA `<gid>` byte. |

`<id>` in this chapter is equivalent to `<kennel>` after substitution; the variant is used in path templates because some paths use the runtime ID even for ad-hoc kennels that do not have a user-facing name.

---

## Permissions and security properties

Each path's mode and ownership are part of its security contract. The most-load-bearing:

- **`~/.local/state/kennel/<kennel>/`** mode `0700`: the workload (running as the same UID) is denied access because the shim does not bind-mount this directory into the workload's view. The mode is belt-and-braces.
- **`/run/user/<uid>/kennel/kenneld.sock`** mode `0600`: only the owning user may connect. kenneld additionally validates via `SO_PEERCRED` (boundary 7 in `04-trust-boundaries.md`).
- **`/sys/fs/bpf/kennel/<id>/`** mode `0750` group `kennel-readers`: operators in `kennel-readers` may inspect maps with `bpftool`; the workload (not in `kennel-readers`, and with no view onto `/sys/fs/bpf`) cannot modify them.
- **`/etc/kennel/keys/*.pub`** mode `0644`: public keys; world-readable is fine. Private keys are not in this tree.
- **`kennel-privhelper`** setuid root OR file capabilities: a compromise of the calling process (kenneld) does not automatically gain privilege; the privhelper validates every request per `04-trust-boundaries.md` boundary 1.

---

## What this chapter does not cover

- The set of paths the workload sees (the constructed shim view): TEMPLATE-ai-coding-strict.md and design doc §7.2.
- How paths flow through the policy parser (tilde expansion, canonicalisation, traversal-rejection): CODING-STANDARDS.md §10 and `kennel-policy::path`.
- File-rotation algorithm for audit logs: `05-state-and-supervision.md`.
- The build-time configuration that picks install paths: `06-build-and-test.md` and the `KENNEL_LIBEXEC_DIR` variable.
- Whether the workload has access to any of these paths: it does not, except via explicit policy grant; the shim is the mechanism (`04-trust-boundaries.md` boundary 12).
