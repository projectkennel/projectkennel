# Process model

This chapter describes the set of processes that exist at runtime, their privilege levels, parent-child relationships, and IPC topology. Detailed lifecycle and recovery rules are in `05-state-and-supervision.md`; wire formats are in `02-4-ipc.md`. This chapter is the *shape* of the system.

---

## Binaries

Project Kennel ships the following binaries.

### `kennel` (the CLI)

The user's entry point. Stateless. Reads a policy from disk, validates it, queries `kenneld` to ensure per-kennel daemons exist, performs the spawn sequence in its own process, and supervises the workload until it exits.

The CLI's process is the parent of the workload. This means `ctrl-C` in the user's terminal propagates naturally to the workload; closing the terminal closes the kennel. Operationally the CLI behaves like any other command the user runs.

Runs as the user. Subcommands and flags are documented in `02-1-cli.md`.

### `kenneld` (the per-user supervisor)

Long-running per-user daemon. One per logged-in user. Started by `systemd --user` on Linux (preferred), `launchd` on macOS, or manually for non-managed sessions.

Responsibilities:

- **Daemon lifecycle.** Owns the lifetime of per-kennel daemons (`kennel-netproxy`, `kennel-ssh-agent`, `xdg-dbus-proxy`). Spawns them on first use; reaps them after a grace period when the last kennel referencing them exits.
- **Audit log aggregation.** Per-kennel JSONL files live under `~/.local/state/kennel/<kennel>/`; kenneld writes to them, rotates them, and serves audit queries from the CLI's `kennel audit` subcommand.
- **Policy caches.** Template-chain resolution is pure but not free; kenneld amortises it across multiple `kennel run` invocations for the same kennel.
- **Privhelper mediation.** When a CLI needs a privhelper invocation (loopback address, cgroup creation), kenneld issues it on the CLI's behalf and returns the result. This means privhelper is invoked once per *kennel start* rather than once per *CLI invocation* for the same kennel.

Runs as the user. If kenneld is not running, the CLI degrades: it spawns daemons as its own children, they die with the kennel, and privhelper is invoked directly. Operationally this is fine for one-shot use; kenneld is the standard configuration for any workflow with multiple concurrent kennels or repeated re-entry.

### `kennel-privhelper` (the privileged component)

Small binary, target size approximately 500 lines of Rust plus the `kennel-syscall` dependency. Installed setuid root *or* with file capabilities `cap_net_admin,cap_sys_admin=ep`. File capabilities are preferred where supported; setuid is the fallback.

Operations:

- Add a per-kennel IPv4 address to loopback or a per-kennel dummy interface.
- Add a per-kennel IPv6 ULA address.
- Remove the addresses on kennel teardown.
- Create a cgroup under `/sys/fs/cgroup/kennel/<kennel>/` if cgroup v2 delegation is not pre-configured for the user (a fallback path; modern systemd configurations pre-delegate).

Refuses anything outside the per-kennel address allocations — each kennel's `127.<tag>.<ctx>.0/24` for IPv4 and `fd<gid>:<tag>:<ctx>::/64` for IPv6 — and outside the `kennel/` cgroup hierarchy. The validation is performed before any privileged syscall and rejects with a structured error if the request is out of scope. The `<tag>` byte is fixed per Project Kennel installation; `<ctx>` is allocated per kennel by kenneld and passed in the request.

**Invocation model:** short-lived per operation. The caller `exec()`s `kennel-privhelper`, the helper reads a structured request from stdin, validates it, performs the operation, writes a response to stdout, and exits. There is no long-running privileged daemon. This bounds the privileged process's exposure to the duration of a single operation.

A future revision may replace this with a long-running daemon owning the same capabilities, addressed over a privileged socket. The trade is fewer exec invocations against continuous privileged exposure. The current implementation is the conservative choice; see `04-trust-boundaries.md` for the rationale.

### `kennel-netproxy` (per-kennel SOCKS5 proxy)

SOCKS5 proxy enforcing the per-destination network allowlist. One instance per active kennel; concurrent kennels mean concurrent proxy processes, each listening on a different per-kennel loopback address (`127.<tag>.<ctx>.1:1080` and the corresponding IPv6 ULA).

Reads its configuration at startup from kenneld (resolved policy fragment relevant to networking) and accepts reconfiguration via SIGHUP-triggered reload of its control socket. Writes network audit events to the kennel's audit directory.

The proxy is the only network egress path for the workload. The cgroup BPF rules deny `connect()` to any address other than the proxy; the workload's `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` environment variables point at the proxy. Together this makes the proxy unbypassable from inside the kennel — kernel enforcement guarantees the workload cannot reach the network without going through the proxy, and the proxy enforces the destination allowlist.

Runs as the user.

### `kennel-ssh-agent` (per-kennel SSH agent)

Per-kennel ssh-agent, spawned by kenneld when a kennel's policy references one. The agent's socket is bound at `/run/kennel/<kennel>/ssh-agent.sock` and shim-mounted into the workload's `$HOME/.ssh/agent.sock`.

Two implementations are supported: stock `ssh-agent` (with a custom socket path), or a Project Kennel-supplied implementation that exposes the same wire protocol with additional auditing. The choice is a policy field; both are valid. The user's main `ssh-agent` is never bind-mounted into the kennel.

Runs as the user.

### Adopted external binaries

Project Kennel does not reimplement well-trodden tools where they exist. The following are invoked as subprocesses when policy enables them:

- **`xdg-dbus-proxy`** — D-Bus method-level filtering, one instance per kennel that enables D-Bus.
- **`Xwayland`** or **`Xephyr`** — X11 server isolation, per kennel (only for the `x11-isolated-dev` template family; not used by `ai-coding-strict`).
- **`bubblewrap`** — *optionally*, for the namespace/mount setup phase. Project Kennel can perform this work directly via `kennel-syscall`, but composing `bubblewrap` is a supported alternative; the choice is a build-time feature flag. See `03-crate-decomposition.md` and `06-build-and-test.md`.

These are dependencies, not source. Their versions are pinned in the build environment per `BUILD-ENV.md` and audited under §5 of the coding standards.

---

## Privilege levels

| Process | UID | Capabilities at exec | Notes |
|---|---|---|---|
| `kennel` (CLI) | user | inherited from shell | nothing special |
| `kenneld` | user | none | started by systemd --user or equivalent |
| `kennel-privhelper` | root (setuid) or user | `cap_net_admin,cap_sys_admin=ep` | preferred: file caps; fallback: setuid |
| `kennel-netproxy` | user | none | |
| `kennel-ssh-agent` | user | none | |
| `xdg-dbus-proxy` | user | none | external |
| Workload | user | bounding set cleared per policy | `PR_SET_NO_NEW_PRIVS` set unconditionally; Landlock sealed; cgroup BPF attached |

Only `kennel-privhelper` operates with elevated privilege, and only transiently per invocation. Project Kennel does not run any long-lived privileged daemon. The bounded duration of privilege is a deliberate constraint.

---

## Process tree at runtime

A representative process tree for a user running two concurrent kennels (`ai-coding` and `web-dev`):

```
systemd --user                                              (user, supervisor)
├── kenneld                                                 (user)
│   ├── kennel-netproxy [ai-coding]                         (user)
│   ├── kennel-ssh-agent [ai-coding]                        (user)
│   ├── xdg-dbus-proxy [web-dev]                            (user)
│   └── kennel-netproxy [web-dev]                           (user)
│
└── bash (the user's shell)                                 (user)
    ├── kennel run ai-coding bash                           (user, supervisor of ai-coding workload)
    │   └── bash [inside ai-coding kennel]                  (user, in cgroup, Landlock applied)
    │       └── ... workload subprocesses ...
    │
    └── kennel run web-dev npm test                         (user, supervisor of web-dev workload)
        └── npm [inside web-dev kennel]                     (user, in cgroup, Landlock applied)
            └── ... build subprocesses ...
```

`kennel-privhelper` does not appear: it is invoked on demand, performs one operation, and exits before any kennel workload starts.

Two structural points worth naming:

1. **The workload's immediate parent is the `kennel run` invocation**, not kenneld. Signal propagation (`ctrl-C`, `SIGHUP`, `SIGTERM` from the shell) reaches the workload naturally. Closing the terminal closes the kennel.
2. **Per-kennel daemons are children of kenneld**, not of any `kennel run` invocation. They survive across multiple `kennel run` invocations against the same kennel. Re-entering a running kennel does not respawn the proxy or the ssh-agent.

---

## IPC topology

Project Kennel processes communicate over Unix domain sockets and BPF maps. No process listens on TCP or UDP; the network APIs are reserved for the workload. The diagram shows the request direction at each edge.

```
   +----------------------------------------------------------------------+
   | User-side processes                                                  |
   |                                                                      |
   |   kennel (CLI)  ----->  /run/user/<uid>/kennel/kenneld.sock          |
   |                              ^                                       |
   |                              | (control protocol)                    |
   |                              |                                       |
   |   kennel run    ----->  kenneld                                      |
   |        |                     |                                       |
   |        |                     +-->  /run/kennel/<id>/proxy.ctl        |
   |        |                     +-->  /run/kennel/<id>/dbus.ctl         |
   |        |                     +-->  /run/kennel/<id>/ssh-agent.sock   |
   |        |                     +-->  writes ~/.local/state/            |
   |        |                                  kennel/<id>/*.jsonl        |
   |        |                                                             |
   |        v  (spawn sequence)                                           |
   |   Workload (in cgroup, Landlock sealed)                              |
   |        |                                                             |
   |        +-->  127.<tag>.<ctx>.1:1080  (SOCKS5 to netproxy)            |
   |        +-->  /run/kennel/<id>/ssh-agent.sock  (shim-mounted)         |
   |        +-->  /run/user/<uid>/bus  (D-Bus, via dbus-proxy)            |
   |                                                                      |
   |   BPF programs (attached to workload's cgroup)                       |
   |        |                                                             |
   |        +-->  ringbuf  -->  kenneld's audit reader                    |
   +----------------------------------------------------------------------+
                                  |
                                  | exec() on demand
                                  | request on stdin, response on stdout
                                  v
   +----------------------------------------------------------------------+
   | Privileged                                                           |
   |                                                                      |
   |   kennel-privhelper  (root or cap_net_admin,cap_sys_admin)           |
   |   (lives for the duration of one operation, then exits)              |
   +----------------------------------------------------------------------+
```

Notes on the diagram:

- The "control protocol" between CLI and kenneld handles kennel start, kennel stop, status query, audit query, and policy reload. Wire format in `02-4-ipc.md`.
- The proxy and dbus-proxy `.ctl` sockets are *control* sockets owned by kenneld, not the data sockets used by the workload. The workload's data path to the proxy is `127.<tag>.<ctx>.1:1080`, never the control socket.
- The ssh-agent socket is bind-mounted from `/run/kennel/<id>/ssh-agent.sock` into the workload's `$HOME/.ssh/agent.sock` via the shim. The workload sees only the shim path.
- BPF programs do not push events to userspace; they write into a ringbuf. A reader task in kenneld drains the ringbuf and writes JSONL events to the audit directory.
- The privhelper is invoked by kenneld in the standard configuration, not by the CLI directly. Without kenneld, the CLI invokes the privhelper itself.

---

## Lifecycle sketch

The full lifecycle is described in `05-state-and-supervision.md`. The summary:

- **kenneld** starts at login (via `systemd --user`) and runs until logout. It is the longest-lived Kennel process.
- **The first `kennel run <kennel>`** for a given kennel asks kenneld to ensure the per-kennel daemons exist. If they do not, kenneld spawns them, invokes the privhelper to allocate the loopback addresses and cgroup, and waits for the daemons to signal ready. Then the CLI proceeds with the spawn sequence.
- **The workload** runs as a child of the `kennel run` process. The CLI supervises it; the audit log captures lifecycle events (start, exit, abnormal termination).
- **Subsequent `kennel run <kennel>`** invocations for the same kennel reuse the existing daemons. Kenneld's reference counter for the per-kennel daemons increments.
- **When the last `kennel run` for a kennel exits**, kenneld's reference counter drops to zero. After a grace period (default: 60 seconds), kenneld reaps the daemons and invokes the privhelper to remove the loopback addresses. The grace period covers the user's "open another terminal and `kennel run` again" pattern without daemon churn.
- **`kennel-privhelper`** invocations are stateless and synchronous: exec'd, read request, perform, respond, exit. The privhelper does not retain any state between invocations.

---

## Concurrency

Multiple `kennel` CLI invocations connect to kenneld concurrently. This is the normal case — two terminals, parallel kennel starts, `kennel audit` running against one kennel while a workload runs in another. The transport supports it natively: kenneld uses a standard `accept()` loop over its Unix socket and handles each connection in its own worker.

Coordination across concurrent requests *inside* kenneld is internal:

- A mutex (or `RwLock` where reads dominate) guards the shared registry of kennels, the per-kennel reference counters, the `<ctx>` byte allocator, and the audit log file handles.
- Each kennel has a state machine: `absent` → `starting` → `running` → `draining` → `stopped`. Transitions are guarded by the registry mutex; long operations (privhelper invocation, daemon readiness wait) happen outside the lock.
- A CLI requesting a kennel in `starting` waits on a condvar until the in-flight setup completes. A CLI requesting a kennel in `draining` reclaims it — transitioning back to `running` rather than waiting through stop+restart. This handles "open another terminal during the grace window" cleanly.

Cross-process exclusion uses `flock`:

- `/run/user/<uid>/kennel/kenneld.lock` — exclusive, one kenneld per user.
- `/run/kennel/privhelper.lock` — exclusive across the machine, serialising privhelper invocations in degraded mode.

Stale-state recovery (kenneld crashed while daemons survive) is handled at kenneld startup: scan `/run/kennel/<id>/` pidfiles, verify each survivor against `/proc/<pid>/exe`, adopt the survivors, reconstruct reference counts from cgroup membership.

Full state-machine transitions, the lockfile inventory, and the recovery procedure are in `05-state-and-supervision.md`.

---

## What this chapter does not cover

- Sub-kennels (refinements within an existing kennel) and how they interact with the process tree: `05-state-and-supervision.md`.
- Failure modes (privhelper unavailable, kenneld crash, daemon crash, kernel feature missing): `05-state-and-supervision.md`.
- Kernel feature requirements per binary and per BPF program: `02-5-bpf-abi.md`.
- The wire format of the CLI↔kenneld and kenneld↔privhelper sockets: `02-4-ipc.md`.
- The detailed semantics of the BPF↔userspace ringbuf events: `02-5-bpf-abi.md` and `02-3-audit-schema.md`.
- The relationship between the workload's PID namespace and the host's: `04-trust-boundaries.md`.
