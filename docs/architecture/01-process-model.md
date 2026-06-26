# Process model

This chapter describes the set of processes that exist at runtime, their privilege levels, parent-child relationships, and IPC topology. Detailed lifecycle and recovery rules are in `05-state-and-supervision.md`; wire formats are in `02-6-ipc.md`. This chapter is the *shape* of the system.

---

## Binaries

Project Kennel ships the following binaries.

### `kennel` (the CLI)

The user's entry point. Stateless. For `run`, it asks `kenneld` to start the kennel and passes fds over `SCM_RIGHTS`: three stdio descriptors for a non-interactive run, or a single client-terminal socket for an interactive one. For an interactive run the spawn seal allocates a controlling pty in the kennel's own devpts and returns its master to **kenneld** (over the construction channel), which holds it in a per-kennel **PTY broker** and proxies the raw stream to the CLI's client socket (the escape filter runs client-side in the CLI, §4.8) — so the operator end is **detachable / reattachable** (`Ctrl-\ d`, `kennel attach`; §7.9.5a, `05-state-and-supervision`). kenneld drives the construction (via the privhelper factory) and supervision of the kennel. A non-interactive CLI blocks until the workload exits and returns its exit code; an interactive one blocks until exit *or* detach. For `compile`, `validate`, and `sign` it works purely on local policy files and never contacts kenneld.

The workload is a child of kenneld, not of the CLI. Signal handling is the CLI's job: `ctrl-C` reaches the CLI, which the user perceives as closing the kennel; the CLI blocks for the workload's lifetime and exits with its code. Operationally the CLI behaves like any other command the user runs.

Runs as the user. Subcommands and flags are documented in `02-1-cli.md`.

### `kenneld` (the per-user supervisor)

Per-user daemon, socket-activated by `systemd --user` on the first `kennel run` and persisting for the rest of the user session. One per logged-in user.

Responsibilities:

- **Kennel lifecycle.** Each `kennel run` is one kennel. kenneld brings it up — allocates a context byte, creates the per-kennel cgroup in its delegated subtree, invokes the privhelper for the loopback addresses and the egress-BPF attach, writes the proxy config, launches `host-netproxy`, builds the full Plan and drives the privhelper **construct-kennel** factory op — and tears it down immediately when the workload exits. There is no grace period, no draining state, and no per-kennel reference counting; one workload is one kennel, with its own proxy, addresses, cgroup, and constructed view.
- **Constructing the kennel.** kenneld compiles the Plan and hands the construction half to the privhelper factory, which builds the namespaces and `fexecve`s `kennel-bin-init`. It splits the Plan into a **construction half** (uid/gid maps, loopback, binderfs params, view binds, pivot target) and a **supervision half** (facades, workload argv/env, operator identity, Landlock/seccomp/ulimits, pty), and passes the construction half — with the stdio descriptors the CLI passed over `SCM_RIGHTS`, or the interactive pty-return socket (§7.9.5a) — to the privhelper construct-kennel op. The privhelper factory builds the namespaces and `fexecve`s `kennel-bin-init`, which **pulls** the supervision half from kenneld over the binder bus (`GET_SANDBOX_PLAN` to node 0); kenneld serves it, gated by the init's host pid (learned from the privhelper at construction). The factory then **exits** (it is not a reaper proxy); kenneld marks itself a **child subreaper** at startup, so the orphaned `kennel-bin-init` reparents to it and kenneld `waitpid`s it directly for the workload's exit status — one fewer resident host process per kennel.
- **Binder context manager.** kenneld acquires **node 0** of the per-kennel binderfs instance by opening `/proc/<init-host-pid>/root/dev/binderfs/binder` (the open succeeds because the kennel userns is operator-owned). It runs the non-blocking looper, services the `org.projectkennel.*` service registry, the `IAfUnix` facade verb, and the `kennel-bin-init` lifecycle/config verbs.
- **Audit drain.** The BPF ringbuf reader drains kernel audit events; per-kennel JSONL files live under `~/.local/state/kennel/<kennel>/` (the egress proxy writes the network log, kenneld wires its path).
- **Privhelper mediation.** kenneld issues the privhelper invocations (loopback address add/del, egress-BPF setup, and the construct-kennel factory op) during a kennel's bring-up and teardown. kenneld creates and removes the cgroup itself; the privhelper factory child is *born into* it (`clone3(CLONE_INTO_CGROUP)`), not migrated in afterwards — a post-`clone` `cgroup.procs` write blocks ~10–14 ms on the `cgroup_threadgroup_rwsem` RCU grace period, so the kennel is created directly inside its cgroup. The granted supplementary groups are written into the kennel's `gid_map` in one shot by the factory at construction, so there is no separate gid-map handshake.

Runs as the user.

### `kennel-privhelper` (the privileged component, and the kennel factory)

Small binary plus the `kennel-lib-syscall` dependency. The installer installs it with file capabilities `cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin=ep`, with setuid root (mode `4755`, owner root) only as the no-xattr fallback for filesystems that cannot carry file caps. `cap_setgid`/`cap_setuid`/`cap_setfcap` cover the identity map (the precise `0 0 1` + operator lines are written in one `write(2)`, which is why `cap_setfcap` is needed) and the operator drop; `cap_sys_admin` is the kernel's `uid_map`-write gate for mapping host uid 0 and covers the kennel's mount/pivot construction. The rare host-context operations are not on the factory: they are delegated to three single-purpose sub-helpers the factory execs only when a policy needs them — `kennel-privhelper-net` (`cap_net_admin`, the host-`lo` mirror loopback address), `kennel-privhelper-bpf` (`cap_bpf,cap_net_admin,cap_perfmon`, the host-mode egress BPF attach), and `kennel-privhelper-mounts` (`cap_sys_admin`, the exclusive-bind over-mount).

The privhelper is the kennel **factory**: it does *all* privileged construction in a child it `clone`s, then hands off to a trusted root-owned `kennel-bin-init`. Operations (the `Op` enum in `kennel-privhelper::wire`):

- **construct-kennel** — the one provisioning op. Over a `SOCK_SEQPACKET` socketpair the caller sends the **construction half** of the Plan (the uid/gid maps, the loopback config, the per-kennel **loopback addresses** to add, the binderfs params, the view bind list, the pivot target) plus the **egress BPF payload** as a framed tail, plus any fds (`SCM_RIGHTS`). The privhelper parses it host-side (no namespace yet), then — with its file caps, in the host net namespace — **adds the loopback addresses** on `lo` (re-validating each against the caller's subnet) and — **in `host` mode only** — **attaches the egress BPF** to the kennel cgroup (re-checking ownership); in every other mode the per-kennel net-ns is the egress boundary and no BPF is attached (§02-5, design §7.5). It provenance-checks and `open`s the `kennel-bin-init` binary, then `clone3(NEWUSER|NEWNS|NEWPID|NEWIPC[|NEWNET]|INTO_CGROUP)` so the child is PID 1 of the new PID namespace, **born directly in the kennel cgroup** (the cgroup dir fd is opened as root before the euid drop and passed to `clone3`, so no post-`clone` `cgroup.procs` migration is needed). In that child it writes the maps, brings up in-namespace `lo`, builds the view, mounts binderfs and chowns the device to the operator, `pivot_root`s and detaches the host root, then `fexecve`s `kennel-bin-init` (empty argv/envp; by descriptor because the host path is gone post-pivot). It then reports the init host pid and **exits** — it is not a reaper proxy. `kennel-bin-init` (PID 1 of its own namespace) outlives it; the orphaned init reparents to `kenneld`, which set itself a child subreaper at startup, and `kenneld` `waitpid`s it directly for the workload's exit status. So there is no resident factory process per kennel. The user namespace is **operator-owned** (the child clones as the operator, self-escalates to construct), which is what lets the unprivileged `kenneld` reach the binderfs instance via `/proc/<init>/root`.
- **del-addr** — remove a per-kennel address on kennel teardown. The **only** standalone one-shot op left: the address *add* and the egress-BPF *attach* are folded into `construct-kennel` above (one privileged spawn per kennel instead of four).

The privhelper does **not** create or delete cgroups. kenneld creates and removes the per-kennel cgroup itself, unprivileged, within its systemd-delegated cgroup subtree; the privhelper only *births* the construction child into (`clone3(CLONE_INTO_CGROUP)`), and — in `host` mode — *attaches* the egress BPF to, an already-created cgroup it confirms the caller owns.

Refuses anything outside the per-kennel address allocations — each kennel's IPv4 `/28` (laid out `127 | tag(12) | ctx(8) | host(4)`) and IPv6 `/64` (`0xfd | gid(40) | ctx(16) | host(64)`) — and any cgroup the caller does not own, any gid the caller is not in, and any uid other than the caller's real uid. The map's operator line is the caller's real uid (from `/proc` ownership), never wire-supplied; the construction-half decoder is bounded and fuzzed. Validation is performed before any privileged syscall and rejects with a structured error if the request is out of scope. The `tag`/`gid` are the caller's per-user values (from `/etc/kennel/subkennel`); `ctx` is allocated per kennel by kenneld and passed in the request.

**Invocation model:** the teardown `del-addr` op is short-lived — the caller `exec()`s `kennel-privhelper`, the helper reads a fixed-layout request from stdin, validates it, performs the one operation, writes a response to stdout, and exits. The **construct-kennel** op runs over a socketpair and does everything else (addresses, egress, namespaces, view), then **also exits** as soon as it has reported the init pid — it does not linger (the orphaned `kennel-bin-init` reparents to the subreaper `kenneld`). There is no long-running privileged daemon shared across kennels, and no resident privileged process per kennel; the privileged process is bounded to one short operation.

A future revision may replace the short-lived ops with a long-running daemon owning the same capabilities, addressed over a privileged socket. The trade is fewer exec invocations against continuous privileged exposure. The current implementation is the conservative choice; see `04-trust-boundaries.md` for the rationale.

### `kennel-bin-init` (the kennel's PID 1)

The trusted root-owned binary the factory `fexecve`s as **PID 1** of the kennel's new PID namespace, after the privhelper child has built the view and `pivot_root`ed. It is `#![forbid(unsafe_code)]`, links `kennel-lib-binder` (a lifecycle binder consumer) and reuses the `kennel-lib-spawn` seal, and is deliberately tiny: it makes no policy decisions and runs no mount, netlink, device-provisioning, filesystem-lookup, or environment-scrubbing code. Its path comes from the root-owned deployment config (`Deployment::kennel_bin_init()`, in libexec); the privhelper verifies it is root-owned and not group/other-writable, opens it pre-`clone`, and execs it by that descriptor — so the operator cannot substitute it and it never appears in the constructed view.

It is started with **empty argv and envp** and **pulls** its configuration over the binder bus: it opens `/dev/binderfs/binder`, sends `GET_SANDBOX_PLAN` to node 0 (retrying until kenneld has claimed node 0), and decodes the **supervision half** of the Plan (the facade list, the workload argv/env, the operator uid/gid, the Landlock ruleset, seccomp filter, ulimits, and an `interactive` flag). For an interactive run the controlling-pty return socket is not pulled here — the factory placed it at a fixed inherited descriptor (`PTY_RETURN_FD`) on the construction channel, and the flag tells the seal to use it. It then forks the facades (each dropped to the operator) and the workload (dropped to the operator, then `no_new_privs` + seccomp + Landlock + ulimits + pty before `execve`), emitting `NOTIFY_BOOT_SYNC` / `NOTIFY_WORKLOAD_EXEC` / `NOTIFY_FACADE_CRASH` on node 0 as it goes. It then runs the `waitpid` supervision loop; on workload exit it `_exit`s the status — the reliable exit path is the process chain (`kennel-bin-init` → kenneld, which reaps it as a subreaper), not binder, which may already be torn down. If the policy sets a TTL (§9.7), it also arms a one-shot timer; at expiry the timer interrupts the reap wait and `kennel-bin-init` makes a **blocking** `NOTIFY_TTL_EXPIRED` call to node 0 — kenneld freezes the whole kennel cgroup (suspending `kennel-bin-init` mid-call), decides per `ttl_action`, and either thaws so the call returns (the kennel resumes) or kills the frozen cgroup.

`kennel-bin-init` runs as the kennel's **uid 0** (host root mapped `0 0 1`): it builds nothing privileged itself, but staying uid 0 keeps PID 1 a *different* uid from the operator-uid workload and facades, so they cannot signal or `ptrace` it. kenneld still reaches `/proc/<init>/root` to open the binderfs device because the kennel user namespace is operator-owned, so the operator `kenneld` holds `CAP_SYS_PTRACE` in it. Landlock and seccomp apply to the **workload child only**, never to `kennel-bin-init` or the facades (which must stay free to fork, `waitpid`, and reach the bus).

### `host-netproxy` (per-kennel SOCKS5 proxy)

SOCKS5 proxy enforcing the per-destination network allowlist. One instance per active kennel; concurrent kennels mean concurrent proxy processes, each listening on a different per-kennel loopback address — the kennel's primary (host offset 1 in its `/28`) at port 1080, exposed to the workload as `$KENNEL_SOCKS_PROXY`, plus the corresponding IPv6 ULA.

Reads its configuration at startup from a config file kenneld writes (the resolved networking policy) and **live-reloads** it: a watcher thread re-reads the file when its mtime changes and swaps the ruleset/host-services in place (`Proxy::reload`), so an egress-policy change needs only a config rewrite, not a respawn (§02-6). Listen-address and audit-sink changes still require a respawn. Writes network audit events to the kennel's audit directory.

The proxy is the only network egress path for the workload. The cgroup BPF rules deny `connect()` to any address other than the proxy; the workload's `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` environment variables point at the proxy. Together this makes the proxy unbypassable from inside the kennel — kernel enforcement guarantees the workload cannot reach the network without going through the proxy, and the proxy enforces the destination allowlist.

Runs as the user.

> **The per-kennel network namespace ([`02-5-binder-net.md`](02-5-binder-net.md), design §7.5).** Every mode except `host` gives the kennel its own `CLONE_NEWNET` namespace (`kennel-lib-spawn::plan` unshares `Namespaces::NET`): `none` gets an empty net-ns, `constrained`/`unconstrained` get an in-ns `lo` carrying the proxy's loopback alias, and only `host` shares the host stack (BPF/Landlock-gated). The egress path crosses the boundary by binder, not a shared loopback. `host-netproxy` runs in the **host** net-ns as kenneld's **CONNECT delegate** (no binder access, reached over a per-kennel `AF_UNIX` command socket, no TCP loopback listener); **`facade-socks5`** runs **inside** the kennel net-ns as the SOCKS5/HTTP front-end and the binder consumer of `org.projectkennel.INet/default`; and **`host-inetd`** runs in the host net-ns as the **BIND delegate** of the §7.5.7 inbound mirror, with **`facade-client`** the in-kennel pull end. The `host` mode reinstates the host-network-recon residual (T1.6) in full — the only mode that shares the host net-ns.

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
- **forced command (no binary)** — `kennel-akc` bakes the bastion's forced command
  directly into the `authorized_keys` line it vends: `ssh <options> -- <dest>`, run as
  the operator. There is no separate re-origination binary, no agent, and no
  fingerprint selection — the destination and options are fixed in the signed grant.
- **`facade-ssh`** — the in-kennel `ProxyCommand` that bridges the workload's `ssh` to
  the bastion: it issues a binder `CONNECT_INET` to kenneld (node 0), which has
  `host-netproxy` dial the bastion on the kennel's behalf (the workload may reach the
  network only across the binder gateway, §7.10).

The workload sees a synthetic read-only `~/.ssh` (one bastion-routed stanza per granted
host, the disposable synthetic key, the bastion-pinned `known_hosts`); the user's real
key and agent are never bound in. All run as the user except `kennel-akc` (root-owned,
runs as the bastion user to reach the per-user control socket).

### Adopted external binaries

Project Kennel does not reimplement well-trodden tools where they exist. The following are invoked as subprocesses when policy enables them:

Project Kennel performs the namespace/mount setup phase directly via `kennel-lib-syscall` (bubblewrap-style, in an identity-mapped user namespace); it does not compose `bubblewrap` as a subprocess.

These are dependencies, not source. Their versions are pinned in the build environment per `BUILD-ENV.md` and audited under §5 of the coding standards.

---

## Privilege levels

| Process | UID | Capabilities at exec | Notes |
|---|---|---|---|
| `kennel` (CLI) | user | inherited from shell | nothing special |
| `kenneld` | user | none | started by systemd --user or equivalent |
| `kennel-privhelper` | user (file caps) or root (setuid fallback) | `cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin=ep` | the kennel **factory**: clones the namespaces, writes the identity map, builds + pivots the view, then `fexecve`s `kennel-bin-init`; installer uses file caps, setuid-root (mode `4755`) the no-xattr fallback |
| `kennel-privhelper-net` | user (file caps) | `cap_net_admin=ep` | sub-helper the factory execs on demand: adds/deletes the host-`lo` mirror loopback address (netlink) |
| `kennel-privhelper-bpf` | user (file caps) | `cap_bpf,cap_net_admin,cap_perfmon=ep` | sub-helper the factory execs on demand (`host` mode only): attaches the host-mode egress BPF to the kennel cgroup |
| `kennel-privhelper-mounts` | user (file caps) | `cap_sys_admin=ep` | sub-helper the factory execs on demand: over-mounts the exclusive-bind sentinel |
| `kennel-bin-init` | operator (as built; design models uid 0) | none ambient (userns-scoped `CAP_SETUID`/`CAP_SETGID` only) | PID 1; root-owned binary, trapped post-pivot; forks + supervises the facades and the workload |
| `host-netproxy` | user | none | |
| `kennel-sshd` (bastion) | user | none | per-user, managed by kenneld; stock OpenSSH `sshd` |
| `kennel-akc` | root-owned, runs as bastion user | none | OpenSSH `AuthorizedKeysCommand`; queries kenneld, writes no file |
| `IDBus` facade (§7.7) | user | none | first-party D-Bus method filter, per kennel that enables D-Bus |
| Workload | user | bounding set cleared per policy | `PR_SET_NO_NEW_PRIVS` set unconditionally; Landlock sealed; cgroup BPF attached; `setrlimit` caps applied (`[ulimits]`, after Landlock) |

Only `kennel-privhelper` operates with host-elevated privilege; the teardown `del-addr` op is transient per invocation, and the construct-kennel op (which provisions addresses + egress + namespaces in one go) is host-root only for the single map-writing step and then exits (it does not linger for the kennel's lifetime — kenneld, a child subreaper, owns the running kennel). `kennel-bin-init` is uid 0 *in the userns only* (no ambient host caps, trapped post-pivot), and as built it runs as the operator regardless. Project Kennel does not run any long-lived privileged daemon shared across kennels. The bounded duration and scope of privilege is a deliberate constraint.

---

## Process tree at runtime

A representative process tree for a user running two concurrent kennels (`ai-coding` and `web-dev`):

```
systemd --user                                              (user, subreaper of last resort)
├── kenneld                                                 (user; child subreaper — adopts each kennel-bin-init)
│   ├── host-netproxy [ai-coding]                         (user)
│   ├── kennel-bin-init [ai-coding]                             (PID 1; reparented to kenneld once the factory exited)
│   │   ├── facade-afunix (facade)                     (operator)
│   │   └── bash [inside ai-coding kennel]                  (operator, in cgroup, Landlock applied)
│   │       └── ... workload subprocesses ...
│   ├── host-netproxy [web-dev]                           (user)
│   └── kennel-bin-init [web-dev]                               (PID 1; reparented to kenneld)
│       └── npm [inside web-dev kennel]                     (operator, in cgroup, Landlock applied)
│           └── ... build subprocesses ...
│
└── bash (the user's shell)                                 (user)
    ├── kennel run ai-coding.settled.toml ai-coding -- bash (user, client; blocks on the workload)
    └── kennel run web-dev.settled.toml web-dev -- npm test (user, client; blocks on the workload)
```

**Every** `kennel-privhelper` op is short-lived and absent from the steady-state tree — the teardown `del-addr` op performs one operation and exits, and **construct-kennel** (which adds the addresses, attaches the egress BPF, and builds the namespaces) likewise exits as soon as it has reported the init pid. It is not a reaper proxy: `kennel-bin-init` (PID 1 of its own namespace) outlives it and reparents to `kenneld` (which marked itself a child subreaper at startup), so each running kennel shows as a direct child of kenneld with no resident factory process behind it.

Two structural points worth naming:

1. **kenneld owns the workload's lifecycle**, not the `kennel run` invocation. kenneld drives the construction and is the connection endpoint; the CLI is a client that holds the connection open for the workload's lifetime and forwards its exit code. The workload is not literally kenneld's child: kenneld calls the privhelper's **construct-kennel** op, which `clone`s the namespace chain so the construction child is PID 1 of the new PID namespace directly (no double-fork — the single `clone(NEWPID|…)` makes it PID 1), then builds the view, pivots, and `fexecve`s **`kennel-bin-init`** in place as that PID 1. `kennel-bin-init` forks the facades and the workload (process B) and supervises them, `_exit`ing with B's status when the workload exits. The factory that `clone`d `kennel-bin-init` has already exited, so `kennel-bin-init` reparents to `kenneld` (a child subreaper); `kenneld` `waitpid`s it and forwards its status to the CLI. The status path is thus `kennel-bin-init` → kenneld → CLI (no privhelper middleman), and the workload's immediate parent is PID-1 `kennel-bin-init`.
2. **Each `kennel run` is one kennel** with its own `host-netproxy` child of kenneld. Kennels are not shared by name and per-kennel resources are not reference-counted: a second `kennel run` is a separate kennel with its own proxy, addresses, cgroup, and view.

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
   |   kennel-bin-init (PID 1)  <--->  kenneld node 0  (binder lifecycle)     |
   |        |   GET_SANDBOX_PLAN (supervision-half Plan + pty fd) /       |
   |        |   NOTIFY_BOOT_SYNC / NOTIFY_WORKLOAD_EXEC / _CRASH          |
   |        |  (forks, drops to operator, confines the workload)         |
   |        v                                                             |
   |   Workload (in cgroup, Landlock sealed)                              |
   |        |                                                             |
   |        +-->  $KENNEL_SOCKS_PROXY (kennel primary, :1080)            |
   |        +-->  ssh -> facade-ssh -> kenneld -> netproxy -> bastion (§7.10) |
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
                                  |   (parents kennel-bin-init for its lifetime)
                                  v
   +----------------------------------------------------------------------+
   | Privileged                                                           |
   |                                                                      |
   |   kennel-privhelper  (file caps: cap_setuid,cap_setgid,             |
   |                       cap_setfcap,cap_sys_admin)                     |
   |   addr/egress ops: live for one operation, then exit                 |
   |   construct-kennel: the factory — clones the kennel, builds and      |
   |     pivots the view, fexecve's kennel-bin-init, then stays its parent    |
   +----------------------------------------------------------------------+
```

Notes on the diagram:

- The "control protocol" between CLI and kenneld (`kenneld::control`) carries `Start` (with stdio fds, or the interactive client-terminal socket, over `SCM_RIGHTS`), `Attach` (a client-terminal socket for `kennel attach`), `Resize` (relay a `SIGWINCH` to the broker-held master), `Stop`, and `List`. Wire format in `02-6-ipc.md`. The interactive **pty master** is returned by the seal to kenneld over the *construction* channel, not this control socket — the control socket only ever carries the client-terminal byte stream's endpoint.
- The proxy and dbus-proxy `.ctl` sockets are *control* sockets owned by kenneld, not the data sockets used by the workload. The workload's data path to the proxy is the kennel's primary loopback (`$KENNEL_SOCKS_PROXY` — host offset 1 in its `/28`, port 1080), never the control socket.
- SSH egress is routed through the per-user `kennel-sshd` bastion (§7.10): the workload's `ssh` reaches it via `facade-ssh` (a binder `CONNECT_INET` to kenneld, which has `host-netproxy` dial the bastion), authenticating with a compile-minted synthetic key in its constructed `~/.ssh`. The bastion's `kennel-akc` vends the forced command `ssh <options> -- <dest>`, run as the operator. The workload holds no real key and no agent socket; the bastion uses the user's host-side key.
- BPF programs do not push events to userspace; they write into a ringbuf. A reader in kenneld drains the ringbuf and writes JSONL events to the audit directory.
- The privhelper is invoked by kenneld during a kennel's bring-up and teardown. The addr/egress ops are one-shot; the **construct-kennel** op runs over a `SOCK_SEQPACKET` socketpair — kenneld sends the construction-half Plan and the stdio/pty fds (`SCM_RIGHTS`), and the op returns the init/workload host pids and, finally, the workload's exit status. The privhelper stays alive as `kennel-bin-init`'s parent for the kennel's lifetime.
- The kennel's control plane is the **binder bus**, not an ad-hoc pipe: `kennel-bin-init` (PID 1) is a binder consumer transacting to node 0 (kenneld) for both its config pull (`GET_SANDBOX_PLAN`, returning the supervision-half Plan; the interactive pty rides the construction channel, not binder) and its lifecycle events (`NOTIFY_*`). kenneld gates these verbs on the init's host pid (a host context manager sees host pids, not the kennel-internal `1`), supplied by the privhelper at construction, never by the wire. The binder transaction surface is documented in `02-4-binder.md`.

---

## Lifecycle sketch

The full lifecycle is in `05-state-and-supervision.md`. The summary:

- **kenneld** is socket-activated on the first `kennel run` and persists for the user session. It is the longest-lived Kennel process.
- **`kennel run`** asks kenneld to start a kennel. kenneld allocates a context byte, creates the cgroup in its delegated subtree, invokes the privhelper to add the loopback addresses and (in `host` mode) attach the egress BPF, writes the proxy config and launches `host-netproxy`, then drives the privhelper construct-kennel factory op (passing the construction-half Plan and stdio/pty fds). The factory `clone`s the namespaces, builds and pivots the view, and `fexecve`s `kennel-bin-init` (PID 1), which pulls its supervision half over binder and forks the facades and the workload. The workload's PID lands in the kennel's cgroup.
- **The workload** runs under kenneld's ownership but is a child of `kennel-bin-init` (PID 1) — dropped to the operator and confined (`no_new_privs` + seccomp + Landlock + ulimits + pty). `kennel-bin-init` supervises it and `_exit`s its status, which the privhelper relays to kenneld. The CLI holds its connection open for the workload's lifetime; the audit log captures lifecycle events.
- **When the workload exits**, kenneld tears the kennel down immediately: reaps the proxy and the construct-kennel privhelper parent, invokes the privhelper to remove the loopback addresses, deletes the cgroup it created, and discards the constructed view (binderfs unmounts with the namespace). There is no grace window and no daemon sharing by name — a second `kennel run` is a separate kennel.
- **`kennel-privhelper`** addr/egress invocations are stateless and synchronous: exec'd, read request, perform, respond, exit. The construct-kennel op is the stateful exception — it lives for the kennel's lifetime as `kennel-bin-init`'s parent — but holds no state shared across kennels.

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
