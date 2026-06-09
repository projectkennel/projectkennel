# Process model

This chapter describes the set of processes that exist at runtime, their privilege levels, parent-child relationships, and IPC topology. Detailed lifecycle and recovery rules are in `05-state-and-supervision.md`; wire formats are in `02-6-ipc.md`. This chapter is the *shape* of the system.

---

## Binaries

Project Kennel ships the following binaries.

### `kennel` (the CLI)

The user's entry point. Stateless. For `run`, it asks `kenneld` to start the kennel and passes fds over `SCM_RIGHTS`: three stdio descriptors for a non-interactive run, or a single socket for an interactive one (over which the spawn seal returns a controlling pty allocated in the kennel's own devpts, which the CLI proxies — §7.9.5a). kenneld drives the construction (via the privhelper factory) and supervision of the kennel. The CLI blocks until the workload exits and returns its exit code. For `compile`, `validate`, and `sign` it works purely on local policy files and never contacts kenneld.

The workload is a child of kenneld, not of the CLI. Signal handling is the CLI's job: `ctrl-C` reaches the CLI, which the user perceives as closing the kennel; the CLI blocks for the workload's lifetime and exits with its code. Operationally the CLI behaves like any other command the user runs.

Runs as the user. Subcommands and flags are documented in `02-1-cli.md`.

### `kenneld` (the per-user supervisor)

Per-user daemon, socket-activated by `systemd --user` on the first `kennel run` and persisting for the rest of the user session. One per logged-in user.

Responsibilities:

- **Kennel lifecycle.** Each `kennel run` is one kennel. kenneld brings it up — allocates a context byte, creates the per-kennel cgroup in its delegated subtree, invokes the privhelper for the loopback addresses and the egress-BPF attach, writes the proxy config, launches `kennel-netproxy`, builds the full Plan and drives the privhelper **construct-kennel** factory op — and tears it down immediately when the workload exits. There is no grace period, no draining state, and no per-kennel reference counting; one workload is one kennel, with its own proxy, addresses, cgroup, and constructed view.
- **Constructing the kennel.** kenneld no longer runs the namespace/mount construction itself. It compiles the Plan, splits it into a **construction half** (uid/gid maps, loopback, binderfs params, view binds, pivot target) and a **supervision half** (facades, workload argv/env, operator identity, Landlock/seccomp/ulimits, pty), and passes the construction half — with the stdio descriptors the CLI passed over `SCM_RIGHTS`, or the interactive pty-return socket (§7.9.5a) — to the privhelper construct-kennel op. The privhelper factory builds the namespaces and `fexecve`s `kennel-init`, which **pulls** the supervision half from kenneld over the binder bus (`GET_SANDBOX_PLAN` to node 0); kenneld serves it, gated by the init's host pid (learned from the privhelper at construction).
- **Binder context manager.** kenneld acquires **node 0** of the per-kennel binderfs instance by opening `/proc/<init-host-pid>/root/dev/binderfs/binder` (the open succeeds because the kennel userns is operator-owned). It runs the non-blocking looper, services the `org.projectkennel.*` service registry, the `IAfUnix` facade verb, and the `kennel-init` lifecycle/config verbs.
- **Audit drain.** The BPF ringbuf reader drains kernel audit events; per-kennel JSONL files live under `~/.local/state/kennel/<kennel>/` (the egress proxy writes the network log, kenneld wires its path).
- **Privhelper mediation.** kenneld issues the privhelper invocations (loopback address add/del, egress-BPF setup, and the construct-kennel factory op) during a kennel's bring-up and teardown. kenneld creates and removes the cgroup itself; the privhelper factory child *joins* it. The granted supplementary groups are written into the kennel's `gid_map` in one shot by the factory at construction, so there is no separate gid-map handshake.

Runs as the user.

### `kennel-privhelper` (the privileged component, and the kennel factory)

Small binary plus the `kennel-syscall` dependency. The installer installs it setuid root (mode `4755`, owner root); file capabilities `cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid,cap_setfcap=ep` are a documented per-distribution alternative the installer does not itself apply. `cap_net_admin`/`cap_sys_admin` cover the loopback addresses, the egress BPF, and the kennel's mount/pivot construction; `cap_setgid`/`cap_setuid`/`cap_setfcap` cover the identity map (the precise `0 0 1` + operator lines are written in one `write(2)`, which is why `cap_setfcap` is needed) and the operator drop.

The privhelper is the kennel **factory**: it does *all* privileged construction in a child it `clone`s, then hands off to a trusted root-owned `kennel-init`. Operations (the `Op` enum in `kennel-privhelper::wire`):

- **construct-kennel** — the long-lived construction op. Over a `SOCK_SEQPACKET` socketpair the caller sends the **construction half** of the Plan (the uid/gid maps, the loopback config, the binderfs params, the view bind list, the pivot target) plus any fds (`SCM_RIGHTS`). The privhelper parses it host-side (no namespace yet), provenance-checks and `open`s the `kennel-init` binary, then `clone(NEWUSER|NEWNS|NEWPID|NEWIPC[|NEWNET])` so the child is PID 1 of the new PID namespace. In that child it writes the maps, joins the kennel cgroup, brings up in-namespace `lo`, builds the view, mounts binderfs and chowns the device to the operator, `pivot_root`s and detaches the host root, then `fexecve`s `kennel-init` (empty argv/envp; by descriptor because the host path is gone post-pivot). The op stays alive as the child's parent: it returns the `init`/workload host pids and relays the final exit status. The user namespace is **operator-owned** (the child clones as the operator, self-escalates to construct), which is what lets the unprivileged `kenneld` reach the binderfs instance via `/proc/<init>/root`.
- **add-addr** — add a per-kennel loopback address (IPv4 in the kennel's `/28`, or IPv6 ULA in its `/64`).
- **del-addr** — remove a per-kennel address on kennel teardown.
- **setup-egress** — load, populate, and attach the egress BPF programs to the kennel's cgroup (the cgroup path is in the request; the helper validates the caller owns it).

The privhelper does **not** create or delete cgroups. kenneld creates and removes the per-kennel cgroup itself, unprivileged, within its systemd-delegated cgroup subtree; the privhelper only *joins* the construction child into, and *attaches* the egress BPF to, an already-created cgroup it confirms the caller owns.

Refuses anything outside the per-kennel address allocations — each kennel's IPv4 `/28` (laid out `127 | tag(12) | ctx(8) | host(4)`) and IPv6 `/64` (`0xfd | gid(40) | ctx(16) | host(64)`) — and any cgroup the caller does not own, any gid the caller is not in, and any uid other than the caller's real uid. The map's operator line is the caller's real uid (from `/proc` ownership), never wire-supplied; the construction-half decoder is bounded and fuzzed. Validation is performed before any privileged syscall and rejects with a structured error if the request is out of scope. The `tag`/`gid` are the caller's per-user values (from `/etc/kennel/subkennel`); `ctx` is allocated per kennel by kenneld and passed in the request.

**Invocation model:** the address and egress ops are short-lived per operation — the caller `exec()`s `kennel-privhelper`, the helper reads a fixed-layout request from stdin, validates it, performs the one operation, writes a response to stdout, and exits. The **construct-kennel** op is the exception: it persists for the kennel's lifetime as the construction child's parent, so it can reap the child and relay the workload's exit status up the process chain. There is no long-running privileged daemon shared across kennels; the privileged process is bounded to one operation, or to one kennel.

A future revision may replace the short-lived ops with a long-running daemon owning the same capabilities, addressed over a privileged socket. The trade is fewer exec invocations against continuous privileged exposure. The current implementation is the conservative choice; see `04-trust-boundaries.md` for the rationale.

### `kennel-init` (the kennel's PID 1)

The trusted root-owned binary the factory `fexecve`s as **PID 1** of the kennel's new PID namespace, after the privhelper child has built the view and `pivot_root`ed. It is `#![forbid(unsafe_code)]`, links `kennel-binder` (a lifecycle binder consumer) and reuses the `kennel-spawn` seal, and is deliberately tiny: it makes no policy decisions and runs no mount, netlink, device-provisioning, filesystem-lookup, or environment-scrubbing code. Its path comes from the root-owned deployment config (`Deployment::kennel_init()`, in libexec); the privhelper verifies it is root-owned and not group/other-writable, opens it pre-`clone`, and execs it by that descriptor — so the operator cannot substitute it and it never appears in the constructed view.

It is started with **empty argv and envp** and **pulls** its configuration over the binder bus: it opens `/dev/binderfs/binder`, sends `GET_SANDBOX_PLAN` to node 0 (retrying until kenneld has claimed node 0), and decodes the **supervision half** of the Plan (the facade list, the workload argv/env, the operator uid/gid, the Landlock ruleset, seccomp filter, ulimits, and the pty fd). It then forks the facades (each dropped to the operator) and the workload (dropped to the operator, then `no_new_privs` + seccomp + Landlock + ulimits + pty before `execve`), emitting `NOTIFY_BOOT_SYNC` / `NOTIFY_WORKLOAD_EXEC` / `NOTIFY_FACADE_CRASH` on node 0 as it goes. It then runs the `waitpid` supervision loop; on workload exit it `_exit`s the status — the reliable exit path is the process chain (`kennel-init` → privhelper → kenneld), not binder, which may already be torn down.

`kennel-init` runs as the kennel's **uid 0** (host root mapped `0 0 1`): it builds nothing privileged itself, but staying uid 0 keeps PID 1 a *different* uid from the operator-uid workload and facades, so they cannot signal or `ptrace` it. kenneld still reaches `/proc/<init>/root` to open the binderfs device because the kennel user namespace is operator-owned, so the operator `kenneld` holds `CAP_SYS_PTRACE` in it. Landlock and seccomp apply to the **workload child only**, never to `kennel-init` or the facades (which must stay free to fork, `waitpid`, and reach the bus).

### `kennel-netproxy` (per-kennel SOCKS5 proxy)

SOCKS5 proxy enforcing the per-destination network allowlist. One instance per active kennel; concurrent kennels mean concurrent proxy processes, each listening on a different per-kennel loopback address — the kennel's primary (host offset 1 in its `/28`) at port 1080, exposed to the workload as `$KENNEL_SOCKS_PROXY`, plus the corresponding IPv6 ULA.

Reads its configuration at startup from a config file kenneld writes (the resolved networking policy) and **live-reloads** it: a watcher thread re-reads the file when its mtime changes and swaps the ruleset/host-services in place (`Proxy::reload`), so an egress-policy change needs only a config rewrite, not a respawn (§02-6). Listen-address and audit-sink changes still require a respawn. Writes network audit events to the kennel's audit directory.

The proxy is the only network egress path for the workload. The cgroup BPF rules deny `connect()` to any address other than the proxy; the workload's `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` environment variables point at the proxy. Together this makes the proxy unbypassable from inside the kennel — kernel enforcement guarantees the workload cannot reach the network without going through the proxy, and the proxy enforces the destination allowlist.

Runs as the user.

> **Roadmap — the per-kennel network namespace ([`02-5-binder-net.md`](02-5-binder-net.md), design §7.11).** The kennel currently *shares the host network namespace*; the network redesign moves each kennel into its own `CLONE_NEWNET` namespace and re-shapes these processes. There, `kennel-netproxy` runs in the **host** net-ns as kenneld's **CONNECT delegate** (no binder access, reached over a per-kennel socketpair, no TCP loopback listener); a new **`kennel-netshim`** runs **inside** the kennel net-ns as the SOCKS5 front-end and the binder consumer of `org.projectkennel.INet/default`; and a **host-side spawn leg** runs in the host net-ns as the **BIND delegate**, holding the host-side mirror of the kennel's native inside listener. These processes are designed but **not built**; the shape above is the as-built (shared-net-ns) model.

### `kennel-sshd` (per-kennel SSH egress bastion)

When a kennel's `[ssh]` policy grants SSH egress, kenneld re-originates it through a
**bastion** rather than handing the workload a key or an agent socket (design §7.10).
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
  SOCKS5 egress proxy (the workload may `connect()` only the proxy, §7.5).

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
| `kennel-privhelper` | root (setuid) or user | `cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid,cap_setfcap=ep` | the kennel **factory**: clones the namespaces, writes the identity map, builds + pivots the view, then `fexecve`s `kennel-init`; installer uses setuid (mode `4755`), file caps a per-distribution alternative |
| `kennel-init` | operator (as built; design models uid 0) | none ambient (userns-scoped `CAP_SETUID`/`CAP_SETGID` only) | PID 1; root-owned binary, trapped post-pivot; forks + supervises the facades and the workload |
| `kennel-netproxy` | user | none | |
| `kennel-sshd` (bastion) | user | none | per-user, managed by kenneld; stock OpenSSH `sshd` |
| `kennel-akc` | root-owned, runs as bastion user | none | OpenSSH `AuthorizedKeysCommand`; queries kenneld, writes no file |
| `xdg-dbus-proxy` | user | none | external |
| Workload | user | bounding set cleared per policy | `PR_SET_NO_NEW_PRIVS` set unconditionally; Landlock sealed; cgroup BPF attached; `setrlimit` caps applied (`[ulimits]`, after Landlock) |

Only `kennel-privhelper` operates with host-elevated privilege; the address and egress ops are transient per invocation, and the construct-kennel op lasts only as long as the kennel it parents. `kennel-init` is uid 0 *in the userns only* (no ambient host caps, trapped post-pivot), and as built it runs as the operator regardless. Project Kennel does not run any long-lived privileged daemon shared across kennels. The bounded duration and scope of privilege is a deliberate constraint.

---

## Process tree at runtime

A representative process tree for a user running two concurrent kennels (`ai-coding` and `web-dev`):

```
systemd --user                                              (user, supervisor)
├── kenneld                                                 (user)
│   ├── kennel-netproxy [ai-coding]                         (user)
│   ├── kennel-privhelper construct-kennel [ai-coding]      (root; factory, parents the kennel)
│   │   └── kennel-init [ai-coding]                         (PID 1; operator as built / uid 0 by design)
│   │       ├── kennel-afunix-shim (facade)                 (operator)
│   │       └── bash [inside ai-coding kennel]              (operator, in cgroup, Landlock applied)
│   │           └── ... workload subprocesses ...
│   ├── kennel-netproxy [web-dev]                           (user)
│   └── kennel-privhelper construct-kennel [web-dev]        (root; factory, parents the kennel)
│       └── kennel-init [web-dev]                           (PID 1)
│           └── npm [inside web-dev kennel]                 (operator, in cgroup, Landlock applied)
│               └── ... build subprocesses ...
│
└── bash (the user's shell)                                 (user)
    ├── kennel run ai-coding.settled.toml ai-coding -- bash (user, client; blocks on the workload)
    └── kennel run web-dev.settled.toml web-dev -- npm test (user, client; blocks on the workload)
```

The short-lived `kennel-privhelper` ops (add-addr, del-addr, setup-egress) do not appear: each is invoked on demand, performs one operation, and exits before the workload runs. The **construct-kennel** privhelper invocation, by contrast, persists — it is the factory that `clone`d the kennel and stays alive as the parent of `kennel-init` (PID 1) to reap it and relay the exit status.

Two structural points worth naming:

1. **kenneld owns the workload's lifecycle**, not the `kennel run` invocation. kenneld drives the construction and is the connection endpoint; the CLI is a client that holds the connection open for the workload's lifetime and forwards its exit code. The workload is not literally kenneld's child: kenneld calls the privhelper's **construct-kennel** op, which `clone`s the namespace chain so the construction child is PID 1 of the new PID namespace directly (no double-fork — the single `clone(NEWPID|…)` makes it PID 1), then builds the view, pivots, and `fexecve`s **`kennel-init`** in place as that PID 1. `kennel-init` forks the facades and the workload (process B) and supervises them, `_exit`ing with B's status when the workload exits. That status rides the process chain `kennel-init` → privhelper → kenneld → CLI, so the CLI and kenneld see the workload's true exit status, while the workload's immediate parent is PID-1 `kennel-init`.
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
   |        |                     +-->  kennel-sshd (SSH egress bastion, §7.10)  |
   |        |                     +-->  writes ~/.local/state/            |
   |        |                                  kennel/<id>/*.jsonl        |
   |        |                                                             |
   |        |  (construct-kennel: SOCK_SEQPACKET socketpair)             |
   |        |   construction-half Plan + stdio/pty fds (SCM_RIGHTS) -->  |
   |        |   <-- init/workload host pids, then exit status            |
   |        v                                                             |
   |   kennel-init (PID 1)  <--->  kenneld node 0  (binder lifecycle)     |
   |        |   GET_SANDBOX_PLAN (supervision-half Plan + pty fd) /       |
   |        |   NOTIFY_BOOT_SYNC / NOTIFY_WORKLOAD_EXEC / _CRASH          |
   |        |  (forks, drops to operator, confines the workload)         |
   |        v                                                             |
   |   Workload (in cgroup, Landlock sealed)                              |
   |        |                                                             |
   |        +-->  $KENNEL_SOCKS_PROXY (kennel primary, :1080)            |
   |        +-->  ssh -> kennel-socks-connect -> proxy -> bastion (§7.10) |
   |        +-->  /run/user/<uid>/bus  (D-Bus, via dbus-proxy)            |
   |                                                                      |
   |   BPF programs (attached to workload's cgroup)                       |
   |        |                                                             |
   |        +-->  ringbuf  -->  kenneld's audit reader                    |
   +----------------------------------------------------------------------+
                                  |
                                  | addr/egress: exec() on demand,
                                  |   request on stdin, response on stdout
                                  | construct-kennel: SOCK_SEQPACKET socketpair
                                  |   (parents kennel-init for its lifetime)
                                  v
   +----------------------------------------------------------------------+
   | Privileged                                                           |
   |                                                                      |
   |   kennel-privhelper  (root / cap_net_admin,cap_sys_admin,            |
   |                       cap_setgid,cap_setuid,cap_setfcap)             |
   |   addr/egress ops: live for one operation, then exit                 |
   |   construct-kennel: the factory — clones the kennel, builds and      |
   |     pivots the view, fexecve's kennel-init, then stays its parent    |
   +----------------------------------------------------------------------+
```

Notes on the diagram:

- The "control protocol" between CLI and kenneld (`kenneld::control`) carries `Start` (with stdio fds, or the interactive pty-return socket, over `SCM_RIGHTS`), `Stop`, and `List`. Wire format in `02-6-ipc.md`.
- The proxy and dbus-proxy `.ctl` sockets are *control* sockets owned by kenneld, not the data sockets used by the workload. The workload's data path to the proxy is the kennel's primary loopback (`$KENNEL_SOCKS_PROXY` — host offset 1 in its `/28`, port 1080), never the control socket.
- SSH egress is re-originated through the per-user `kennel-sshd` bastion (§7.10): the workload's `ssh` reaches it via `kennel-socks-connect` → the egress proxy, authenticating with a disposable synthetic key in its constructed `~/.ssh`. The workload holds no real key and no agent socket; the bastion uses the user's host-side key.
- BPF programs do not push events to userspace; they write into a ringbuf. A reader in kenneld drains the ringbuf and writes JSONL events to the audit directory.
- The privhelper is invoked by kenneld during a kennel's bring-up and teardown. The addr/egress ops are one-shot; the **construct-kennel** op runs over a `SOCK_SEQPACKET` socketpair — kenneld sends the construction-half Plan and the stdio/pty fds (`SCM_RIGHTS`), and the op returns the init/workload host pids and, finally, the workload's exit status. The privhelper stays alive as `kennel-init`'s parent for the kennel's lifetime.
- The kennel's control plane is the **binder bus**, not an ad-hoc pipe: `kennel-init` (PID 1) is a binder consumer transacting to node 0 (kenneld) for both its config pull (`GET_SANDBOX_PLAN`, returning the supervision-half Plan and the pty fd as `BINDER_TYPE_FD`) and its lifecycle events (`NOTIFY_*`). kenneld gates these verbs on the init's host pid (a host context manager sees host pids, not the kennel-internal `1`), supplied by the privhelper at construction, never by the wire. The binder transaction surface is documented in `02-4-binder.md`.

---

## Lifecycle sketch

The full lifecycle is in `05-state-and-supervision.md`. The summary:

- **kenneld** is socket-activated on the first `kennel run` and persists for the user session. It is the longest-lived Kennel process.
- **`kennel run`** asks kenneld to start a kennel. kenneld allocates a context byte, creates the cgroup in its delegated subtree, invokes the privhelper to add the loopback addresses and attach the egress BPF, writes the proxy config and launches `kennel-netproxy`, then drives the privhelper construct-kennel factory op (passing the construction-half Plan and stdio/pty fds). The factory `clone`s the namespaces, builds and pivots the view, and `fexecve`s `kennel-init` (PID 1), which pulls its supervision half over binder and forks the facades and the workload. The workload's PID lands in the kennel's cgroup.
- **The workload** runs under kenneld's ownership but is a child of `kennel-init` (PID 1) — dropped to the operator and confined (`no_new_privs` + seccomp + Landlock + ulimits + pty). `kennel-init` supervises it and `_exit`s its status, which the privhelper relays to kenneld. The CLI holds its connection open for the workload's lifetime; the audit log captures lifecycle events.
- **When the workload exits**, kenneld tears the kennel down immediately: reaps the proxy and the construct-kennel privhelper parent, invokes the privhelper to remove the loopback addresses, deletes the cgroup it created, and discards the constructed view (binderfs unmounts with the namespace). There is no grace window and no daemon sharing by name — a second `kennel run` is a separate kennel.
- **`kennel-privhelper`** addr/egress invocations are stateless and synchronous: exec'd, read request, perform, respond, exit. The construct-kennel op is the stateful exception — it lives for the kennel's lifetime as `kennel-init`'s parent — but holds no state shared across kennels.

---

## Concurrency

Multiple `kennel` CLI invocations connect to kenneld concurrently. This is the normal case — two terminals, parallel kennel starts. The transport supports it natively: kenneld runs a standard `accept()` loop over its Unix socket and handles each connection in its own thread (`serve()` spawns one thread per accepted connection; blocking, no async runtime).

Coordination across concurrent requests *inside* kenneld is internal:

- A mutex guards the shared registry of kennels and the `<ctx>` byte allocator.
- Each kennel is `starting` until its workload is launched, then `running`; it is removed from the registry when the workload exits and teardown completes. There is no `draining` state and no reference counting — one workload is one kennel.
- The registry mutex is not held across the slow bring-up work (privhelper invocation, proxy launch, spawn); the registry records the kennel before that work begins and updates it after.

Cross-process exclusion:

- One kenneld per user is provided by systemd socket activation (it owns the single bound `control.sock` listener), not a lock file.
- The privhelper holds no inter-process lock: the addr/egress invocations run one validated operation and exit, and the construct-kennel ops are independent per kennel (one factory parent each); the kernel serialises the privileged syscalls.

Full state and the lockfile inventory are in `05-state-and-supervision.md`.

---

## What this chapter does not cover

- Sub-kennels (refinements within an existing kennel) and how they interact with the process tree: `05-state-and-supervision.md`.
- Failure modes (privhelper unavailable, kenneld crash, daemon crash, kernel feature missing): `05-state-and-supervision.md`.
- Kernel feature requirements per binary and per BPF program: `02-7-bpf-abi.md`.
- The wire format of the CLI↔kenneld and kenneld↔privhelper sockets: `02-6-ipc.md`.
- The detailed semantics of the BPF↔userspace ringbuf events: `02-7-bpf-abi.md` and `02-3-audit-schema.md`.
- The relationship between the workload's PID namespace and the host's: `04-trust-boundaries.md`.
