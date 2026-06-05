# Process model

This chapter describes the set of processes that exist at runtime, their privilege levels, parent-child relationships, and IPC topology. Detailed lifecycle and recovery rules are in `05-state-and-supervision.md`; wire formats are in `02-4-ipc.md`. This chapter is the *shape* of the system.

---

## Binaries

Project Kennel ships the following binaries.

### `kennel` (the CLI)

The user's entry point. Stateless. For `run`, it asks `kenneld` to start the kennel, passing the terminal's three stdio file descriptors over `SCM_RIGHTS`; kenneld performs the spawn sequence and attaches the workload to those descriptors. The CLI blocks until the workload exits and returns its exit code. For `compile`, `validate`, and `sign` it works purely on local policy files and never contacts kenneld.

The workload is a child of kenneld, not of the CLI. Signal handling is the CLI's job: `ctrl-C` reaches the CLI, which the user perceives as closing the kennel; the CLI blocks for the workload's lifetime and exits with its code. Operationally the CLI behaves like any other command the user runs.

Runs as the user. Subcommands and flags are documented in `02-1-cli.md`.

### `kenneld` (the per-user supervisor)

Per-user daemon, socket-activated by `systemd --user` on the first `kennel run` and persisting for the rest of the user session. One per logged-in user.

Responsibilities:

- **Kennel lifecycle.** Each `kennel run` is one kennel. kenneld brings it up — allocates a context byte, creates the per-kennel cgroup in its delegated subtree, invokes the privhelper for the loopback addresses and the egress-BPF attach, writes the proxy config, launches `kennel-netproxy`, performs the spawn sequence — and tears it down immediately when the workload exits. There is no grace period, no draining state, and no per-kennel reference counting; one workload is one kennel, with its own proxy, addresses, cgroup, and constructed view.
- **Spawning the workload.** kenneld runs the spawn sequence (`kennel-spawn`) on the CLI's behalf, attaching the workload to the stdio descriptors the CLI passed over `SCM_RIGHTS`.
- **Audit drain.** The BPF ringbuf reader drains kernel audit events; per-kennel JSONL files live under `~/.local/state/kennel/<kennel>/` (the egress proxy writes the network log, kenneld wires its path).
- **Privhelper mediation.** kenneld issues the privhelper invocations (loopback address add/del, egress-BPF setup, and the gid-map write when a group is granted) during a kennel's bring-up and teardown. kenneld creates and removes the cgroup itself.

Runs as the user.

### `kennel-privhelper` (the privileged component)

Small binary, target size approximately 500 lines of Rust plus the `kennel-syscall` dependency. The installer installs it setuid root (mode `4755`, owner root); file capabilities `cap_net_admin,cap_sys_admin,cap_setgid=ep` are a documented per-distribution alternative the installer does not itself apply (`cap_setgid` is for the `set-gid-map` op). `cap_net_admin`/`cap_sys_admin` cover the loopback addresses and egress BPF.

Operations — exactly four (the `Op` enum in `kennel-privhelper::wire`):

- **add-addr** — add a per-kennel loopback address (IPv4 in the kennel's `/28`, or IPv6 ULA in its `/64`).
- **del-addr** — remove a per-kennel address on kennel teardown.
- **setup-egress** — load, populate, and attach the egress BPF programs to the kennel's cgroup (the cgroup path is in the request; the helper validates the caller owns it).
- **set-gid-map** — write a workload's user-namespace `gid_map` so it retains a granted supplementary group the unprivileged caller cannot self-map (§7.2.8); gated on the caller being a member of every gid and owning the target pid.

The privhelper does **not** create or delete cgroups. kenneld creates and removes the per-kennel cgroup itself, unprivileged, within its systemd-delegated cgroup subtree; the privhelper only *attaches* the egress BPF to an already-created cgroup it confirms the caller owns.

Refuses anything outside the per-kennel address allocations — each kennel's IPv4 `/28` (laid out `127 | tag(12) | ctx(8) | host(4)`) and IPv6 `/64` (`0xfd | gid(40) | ctx(16) | host(64)`) — and any cgroup the caller does not own, any gid the caller is not in, and any pid the caller does not own. The validation is performed before any privileged syscall and rejects with a structured error if the request is out of scope. The `tag`/`gid` are the caller's per-user values (from `/etc/kennel/subkennel`); `ctx` is allocated per kennel by kenneld and passed in the request.

**Invocation model:** short-lived per operation. The caller `exec()`s `kennel-privhelper`, the helper reads a fixed-layout request from stdin, validates it, performs the one operation, writes a response to stdout, and exits. There is no long-running privileged daemon. This bounds the privileged process's exposure to the duration of a single operation.

A future revision may replace this with a long-running daemon owning the same capabilities, addressed over a privileged socket. The trade is fewer exec invocations against continuous privileged exposure. The current implementation is the conservative choice; see `04-trust-boundaries.md` for the rationale.

### `kennel-netproxy` (per-kennel SOCKS5 proxy)

SOCKS5 proxy enforcing the per-destination network allowlist. One instance per active kennel; concurrent kennels mean concurrent proxy processes, each listening on a different per-kennel loopback address — the kennel's primary (host offset 1 in its `/28`) at port 1080, exposed to the workload as `$KENNEL_SOCKS_PROXY`, plus the corresponding IPv6 ULA.

Reads its configuration at startup from a config file kenneld writes (the resolved networking policy) and **live-reloads** it: a watcher thread re-reads the file when its mtime changes and swaps the ruleset/host-services in place (`Proxy::reload`), so an egress-policy change needs only a config rewrite, not a respawn (§02-4). Listen-address and audit-sink changes still require a respawn. Writes network audit events to the kennel's audit directory.

The proxy is the only network egress path for the workload. The cgroup BPF rules deny `connect()` to any address other than the proxy; the workload's `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` environment variables point at the proxy. Together this makes the proxy unbypassable from inside the kennel — kernel enforcement guarantees the workload cannot reach the network without going through the proxy, and the proxy enforces the destination allowlist.

Runs as the user.

### `kennel-sshd` (per-kennel SSH egress bastion)

When a kennel's `[ssh]` policy grants SSH egress, kenneld re-originates it through a
**bastion** rather than handing the workload a key or an agent socket (design §7.8).
The bastion is a per-user managed instance of stock OpenSSH `sshd` (`kenneld::bastion`/`sshd`),
sibling to kenneld, lazily started on the first grant and stopped when the last kennel
deregisters. It re-originates a kennel's SSH to the policy-fixed destination with the
user's real key, held host-side; the workload reaches it through its egress proxy and
holds no key.

The supporting binaries:
- **`kennel-akc`** — the root-owned `AuthorizedKeysCommand`. OpenSSH's safe-path check
  accepts only a root-owned helper, so the forced-command bindings (the access policy)
  cannot be rewritten behind kenneld's back; `kennel-akc` answers each auth by querying
  the **running kenneld** over the control socket (`Request::AuthorizedKeys`) for the
  line bound to the offered key. No `authorized_keys` file is written. A prototype
  `AuthorizedKeysFile` on a `0700` safe-owned path remains as an e2e fallback.
- **`kennel-ssh-reorigin`** — the unprivileged forced-command router that maps an
  authenticated synthetic key to its fixed destination and execs outbound `ssh`.
- **`kennel-socks-connect`** — the `ProxyCommand` that bridges `ssh` to the kennel's
  SOCKS5 egress proxy (the workload may `connect()` only the proxy, §7.3).

The workload sees a synthetic read-only `~/.ssh` (one bastion-routed stanza per granted
host, the disposable synthetic key, the bastion-pinned `known_hosts`); the user's real
key and agent are never bound in. All run as the user except `kennel-akc` (root-owned,
runs as the bastion user to reach the per-user control socket).

### Adopted external binaries

Project Kennel does not reimplement well-trodden tools where they exist. The following are invoked as subprocesses when policy enables them:

- **`xdg-dbus-proxy`** — D-Bus method-level filtering, one instance per kennel that enables D-Bus.
- **`Xwayland`** or **`Xephyr`** — X11 server isolation, per kennel (only for the `x11-isolated-dev` template family; not used by `ai-coding-strict`).
Project Kennel performs the namespace/mount setup phase directly via `kennel-syscall` (bubblewrap-style, in an identity-mapped user namespace); it does not compose `bubblewrap` as a subprocess.

These are dependencies, not source. Their versions are pinned in the build environment per `BUILD-ENV.md` and audited under §5 of the coding standards.

---

## Privilege levels

| Process | UID | Capabilities at exec | Notes |
|---|---|---|---|
| `kennel` (CLI) | user | inherited from shell | nothing special |
| `kenneld` | user | none | started by systemd --user or equivalent |
| `kennel-privhelper` | root (setuid) or user | `cap_net_admin,cap_sys_admin,cap_setgid=ep` | installer uses setuid (mode `4755`); file caps a per-distribution alternative |
| `kennel-netproxy` | user | none | |
| `kennel-sshd` (bastion) | user | none | per-user, managed by kenneld; stock OpenSSH `sshd` |
| `kennel-akc` | root-owned, runs as bastion user | none | OpenSSH `AuthorizedKeysCommand`; queries kenneld, writes no file |
| `xdg-dbus-proxy` | user | none | external |
| Workload | user | bounding set cleared per policy | `PR_SET_NO_NEW_PRIVS` set unconditionally; Landlock sealed; cgroup BPF attached; `setrlimit` caps applied (`[ulimits]`, after Landlock) |

Only `kennel-privhelper` operates with elevated privilege, and only transiently per invocation. Project Kennel does not run any long-lived privileged daemon. The bounded duration of privilege is a deliberate constraint.

---

## Process tree at runtime

A representative process tree for a user running two concurrent kennels (`ai-coding` and `web-dev`):

```
systemd --user                                              (user, supervisor)
├── kenneld                                                 (user)
│   ├── kennel-netproxy [ai-coding]                         (user)
│   ├── bash [inside ai-coding kennel]                      (user, in cgroup, Landlock applied)
│   │   └── ... workload subprocesses ...
│   ├── kennel-netproxy [web-dev]                           (user)
│   └── npm [inside web-dev kennel]                         (user, in cgroup, Landlock applied)
│       └── ... build subprocesses ...
│
└── bash (the user's shell)                                 (user)
    ├── kennel run ai-coding.settled.toml ai-coding -- bash (user, client; blocks on the workload)
    └── kennel run web-dev.settled.toml web-dev -- npm test (user, client; blocks on the workload)
```

`kennel-privhelper` does not appear: it is invoked on demand, performs one operation, and exits before any kennel workload starts.

Two structural points worth naming:

1. **kenneld owns the workload's lifecycle**, not the `kennel run` invocation. kenneld performs the spawn; the CLI is a client that holds the connection open for the workload's lifetime and forwards its exit code. The workload is not literally kenneld's immediate child: the spawn forks an intermediate reaper (process A) which becomes PID 1 of the workload's new PID namespace, then forks the workload (process B) and `_exit()`s with B's status — so kenneld holds a `Child` handle for A, and A relays B's exit code up. The CLI and kenneld therefore see the workload's true exit status, but the workload's immediate parent is the in-namespace reaper A.
2. **Each `kennel run` is one kennel** with its own `kennel-netproxy` child of kenneld. Kennels are not shared by name and per-kennel resources are not reference-counted: a second `kennel run` is a separate kennel with its own proxy, addresses, cgroup, and view.

---

## IPC topology

Project Kennel processes communicate over Unix domain sockets and BPF maps. No process listens on TCP or UDP; the network APIs are reserved for the workload. The diagram shows the request direction at each edge.

```
   +----------------------------------------------------------------------+
   | User-side processes                                                  |
   |                                                                      |
   |   kennel (CLI)  ----->  /run/user/<uid>/kennel/control.sock          |
   |                              ^                                       |
   |                              | (control protocol)                    |
   |                              |                                       |
   |   kennel run    ----->  kenneld                                      |
   |        |                     |                                       |
   |        |                     +-->  /run/user/<uid>/kennel/proxy.ctl        |
   |        |                     +-->  /run/user/<uid>/kennel/dbus.ctl         |
   |        |                     +-->  kennel-sshd (SSH egress bastion, §7.8)  |
   |        |                     +-->  writes ~/.local/state/            |
   |        |                                  kennel/<id>/*.jsonl        |
   |        |                                                             |
   |        v  (spawn sequence)                                           |
   |   Workload (in cgroup, Landlock sealed)                              |
   |        |                                                             |
   |        +-->  $KENNEL_SOCKS_PROXY (kennel primary, :1080)            |
   |        +-->  ssh -> kennel-socks-connect -> proxy -> bastion (§7.8) |
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

- The "control protocol" between CLI and kenneld (`kenneld::control`) carries `Start` (with the workload's stdio fds over `SCM_RIGHTS`), `Stop`, and `List`. Wire format in `02-4-ipc.md`.
- The proxy and dbus-proxy `.ctl` sockets are *control* sockets owned by kenneld, not the data sockets used by the workload. The workload's data path to the proxy is the kennel's primary loopback (`$KENNEL_SOCKS_PROXY` — host offset 1 in its `/28`, port 1080), never the control socket.
- SSH egress is re-originated through the per-user `kennel-sshd` bastion (§7.8): the workload's `ssh` reaches it via `kennel-socks-connect` → the egress proxy, authenticating with a disposable synthetic key in its constructed `~/.ssh`. The workload holds no real key and no agent socket; the bastion uses the user's host-side key.
- BPF programs do not push events to userspace; they write into a ringbuf. A reader in kenneld drains the ringbuf and writes JSONL events to the audit directory.
- The privhelper is invoked by kenneld during a kennel's bring-up and teardown.

---

## Lifecycle sketch

The full lifecycle is in `05-state-and-supervision.md`. The summary:

- **kenneld** is socket-activated on the first `kennel run` and persists for the user session. It is the longest-lived Kennel process.
- **`kennel run`** asks kenneld to start a kennel. kenneld allocates a context byte, creates the cgroup in its delegated subtree, invokes the privhelper to add the loopback addresses and attach the egress BPF, writes the proxy config and launches `kennel-netproxy`, then performs the spawn sequence. The workload's PID lands in the kennel's cgroup.
- **The workload** runs under kenneld's ownership — PID 1 of a fresh PID namespace, reaped by the intermediate reaper kenneld forked, which relays the exit status. The CLI holds its connection open for the workload's lifetime; the audit log captures lifecycle events.
- **When the workload exits**, kenneld tears the kennel down immediately: reaps the proxy, invokes the privhelper to remove the loopback addresses, deletes the cgroup it created, and discards the constructed view. There is no grace window and no daemon sharing by name — a second `kennel run` is a separate kennel.
- **`kennel-privhelper`** invocations are stateless and synchronous: exec'd, read request, perform, respond, exit. The privhelper retains no state between invocations.

---

## Concurrency

Multiple `kennel` CLI invocations connect to kenneld concurrently. This is the normal case — two terminals, parallel kennel starts. The transport supports it natively: kenneld runs a standard `accept()` loop over its Unix socket and handles each connection in its own thread (`serve()` spawns one thread per accepted connection; blocking, no async runtime).

Coordination across concurrent requests *inside* kenneld is internal:

- A mutex guards the shared registry of kennels and the `<ctx>` byte allocator.
- Each kennel is `starting` until its workload is launched, then `running`; it is removed from the registry when the workload exits and teardown completes. There is no `draining` state and no reference counting — one workload is one kennel.
- The registry mutex is not held across the slow bring-up work (privhelper invocation, proxy launch, spawn); the registry records the kennel before that work begins and updates it after.

Cross-process exclusion:

- One kenneld per user is provided by systemd socket activation (it owns the single bound `control.sock` listener), not a lock file.
- The privhelper holds no inter-process lock: each invocation runs one validated operation and exits, and the kernel serialises the privileged syscalls.

Full state and the lockfile inventory are in `05-state-and-supervision.md`.

---

## What this chapter does not cover

- Sub-kennels (refinements within an existing kennel) and how they interact with the process tree: `05-state-and-supervision.md`.
- Failure modes (privhelper unavailable, kenneld crash, daemon crash, kernel feature missing): `05-state-and-supervision.md`.
- Kernel feature requirements per binary and per BPF program: `02-5-bpf-abi.md`.
- The wire format of the CLI↔kenneld and kenneld↔privhelper sockets: `02-4-ipc.md`.
- The detailed semantics of the BPF↔userspace ringbuf events: `02-5-bpf-abi.md` and `02-3-audit-schema.md`.
- The relationship between the workload's PID namespace and the host's: `04-trust-boundaries.md`.
