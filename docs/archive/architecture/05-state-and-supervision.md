# State and supervision

This chapter is the authoritative treatment of runtime state: the per-kennel lifecycle, how kenneld brings a kennel up and tears it down, the locking matrix that keeps concurrent access correct, and the failure modes. The process-topology view is in `01-process-model.md`; this chapter is what happens at the edges where those processes meet.

The model is deliberately small. kenneld persists for the user session (socket-activated). Each `kennel run` is one kennel with its own context byte, cgroup, egress proxy, loopback addresses, binderfs bus, and constructed view; those resources tear down immediately when the workload exits (`kenneld::Kennel::stop`). There is no grace period, no draining state, no reclaim, and no per-kennel reference counting — one workload is one kennel.

A kennel is constructed by the privhelper *factory*, not by kenneld directly: the privhelper clones the namespaces, builds the root-owned view, mounts the per-kennel binderfs instance, and `fexecve`s the trusted `kennel-bin-init` as PID 1, which supervises the facades and the workload (`01-process-model.md`, design §7.2). Supervision of a live kennel is therefore split across two long-lived processes — the kenneld thread that serves the `Start` and holds the registry entry, and `kennel-bin-init` inside the kennel that reaps the facades and the workload — joined by the binderfs bus (in-life control plane) and the construction process chain (exit-status path).

---

## Where state lives

Project Kennel keeps as little persistent state as it can. State is recoverable from the running system wherever possible, rather than written to disk and trusted.

| State | Owner | Lives in |
|---|---|---|
| Kennel registry (which kennels exist, their state) | kenneld | in-memory |
| `<ctx>` byte allocation | kenneld | in-memory |
| Proxy PID and kennel handle | kenneld | in-memory (the thread serving the `Start` owns the `Kennel`) |
| Loopback address allocation | kernel (the `lo`/dummy interface) | the interface itself |
| binderfs instance + `binder` device | kernel (the child mount namespace) | the per-kennel binderfs mount; node 0 held by kenneld |
| cgroup membership | kernel | `/sys/fs/cgroup/kennel/<id>/cgroup.procs` |
| Audit log | filesystem | `~/.local/state/kennel/<kennel>/` (append-only) |
| Settled policy | filesystem | the path the CLI passed to `kennel run` |

The runtime state of a kennel is owned by the kenneld thread that serves its `Start` request: that thread holds the `Kennel` value, blocks on the workload, and runs teardown when the workload exits. The kernel and the filesystem hold the durable side (cgroup membership, bound addresses, written audit events); kenneld's registry is the in-memory index of live kennels.

---

## The per-kennel lifecycle

A kennel is `starting` while it is being brought up and `running` once its workload is launched; it leaves the registry when the workload exits and teardown completes.

```
   (Start) ──► starting ──workload launched──► running ──workload exits──► (teardown, removed)
                  │
                  │ bring-up fails
                  ▼
            (unwound; error to caller)
```

| State | Meaning |
|---|---|
| `starting` | Bring-up in progress: `<ctx>` allocated, privhelper adding addresses and creating the cgroup, proxy config written and `host-netproxy` launched, the privhelper factory constructing the kennel (clone, maps, view, binderfs mount + device chown, `pivot_root`, `fexecve` of `kennel-bin-init`), kenneld acquiring binder node 0, `kennel-bin-init` pulling its `GET_SANDBOX_PLAN` and forking the facades. |
| `running` | Workload launched (forked by `kennel-bin-init`, dropped to the operator) and in the cgroup; proxy up; BPF attached; binderfs bus serving (node 0 = kenneld). |

### Transitions

**Start → `starting`.** A `Start` request arrives over the control socket. A non-interactive run passes the workload's three stdio fds via `SCM_RIGHTS`; an interactive run passes **one** socket — the client's proxied-terminal end — and kenneld keeps the workload's pty master itself (the PTY broker, below). kenneld allocates a `<ctx>` byte, records the kennel in the registry, and begins bring-up: verify the settled policy (`02-2`), invoke the privhelper to add the loopback addresses and create the cgroup, write the proxy config and launch `host-netproxy`, then drive construction. kenneld splits the settled `Plan` into a construction half and a supervision half and invokes the privhelper *factory* (`ConstructKennel`, `02-6-ipc.md`): the factory clones the namespaces, writes the identity maps, builds the view, mounts the per-kennel binderfs instance and chowns the `binder` device to the operator, `pivot_root`s, and `fexecve`s `kennel-bin-init`. kenneld then acquires binder node 0 by opening `/proc/<init-host-pid>/root/dev/binderfs/binder` (the init host pid arrives from the factory over the construction socketpair) and serves `kennel-bin-init`'s `GET_SANDBOX_PLAN` pull (the supervision-half bytes plus the pty fd).

**`starting` → `running`.** `kennel-bin-init` (PID 1) forks the facades, drops each to the operator, then forks the workload, drops it to the operator, and seals it (`no_new_privs` + seccomp + Landlock + ulimits + pty) before `execve`. kenneld replies `Started { ctx, pid }` to the CLI. The serving thread blocks on the construction process chain — it learns the workload exit status from the privhelper, which is `kennel-bin-init`'s parent.

**TTL expiry (optional, `[lifecycle]` §9.7).** When the settled policy sets `ttl_seconds`, `kennel-bin-init` arms a one-shot alarm; at expiry it makes a **blocking** `NOTIFY_TTL_EXPIRED` binder call to kenneld and parks in it. kenneld freezes the kennel's cgroup (`cgroup.freeze` ← `1`), so the whole kennel is atomically suspended mid-call and cannot act past its deadline, then dispatches on `ttl_action`. `exit` kills the still-frozen cgroup (`cgroup.kill`) — the workload never resumes — and audits `binder.ttl-terminate`. `warn` thaws and resumes once with no re-arm, audit `binder.ttl-warn`. `renew` thaws after asking the **attached operator** over the control connection (`prompt::PromptPort`) whether to extend: on yes it replies `RENEW` (audit `binder.ttl-renew`) and `kennel-bin-init` re-arms the alarm for a further period; on an explicit no it kills the frozen cgroup (audit `binder.ttl-decline`); when no operator can be asked (non-interactive, detached, or timed out) it falls back to a warn (`binder.ttl-warn-no-operator`), never destroying a kennel on a missed prompt. With no `ttl` the serving thread's wait is a single blocking `wait()`. kenneld's own threads are not in the kennel's cgroup, so freezing to decide never suspends the daemon, and the kill acts on the live handle's own cgroup, never racing teardown.

**Bring-up failure.** Any step fails (signature verification, privhelper refusal, proxy launch, spawn). kenneld unwinds whatever it allocated in reverse (`teardown`: reap the proxy if launched, remove any added addresses, delete the cgroup), removes the registry entry, and returns a structured error to the caller.

**`running` → removed.** The workload exits. `kennel-bin-init` `_exit`s the workload's status, the privhelper reaps `kennel-bin-init` and relays that status to kenneld over the construction socketpair — the exit status rides the **process chain** (`kennel-bin-init` → privhelper → kenneld), never binder, which may already be torn down. kenneld replies `Exited { code }`, runs teardown immediately — reap the proxy, invoke the privhelper to remove the loopback addresses, delete the cgroup, discard the constructed view — and removes the registry entry. The per-kennel binderfs instance needs no explicit teardown: it is a mount in the kennel's child mount namespace, so it disappears with that namespace when the last process exits (pending transactions get death notifications, all nodes are destroyed). A `Stop` request for the kennel reaches the same teardown by terminating the workload first. There is no grace window: a later `kennel run` is a separate kennel with its own resources.

---

## The interactive PTY broker (detach / reattach)

An interactive kennel's controlling terminal is owned by **kenneld**, not the client. The spawn seal allocates the workload's controlling pty inside the kennel's own devpts (so `ttyname(3)`/`tty` resolve it) and hands the **master** back to kenneld over a kenneld-minted socketpair — not to the CLI. kenneld holds that master in a per-kennel **PTY broker** that is a **raw-byte router**: a pump thread copies `master → a bounded ring buffer → the attached client` verbatim, with the client's input copied back to the master. The terminal-escape filter (07-9 §7.9.5) does **not** run here — it runs client-side in the `kennel` CLI (§4.8), so the daemon never parses workload-controlled output; the broker conveys the `[tty]` filter decision to each client in its `Started`/`Attached` response. The pump always drains the master even with no client attached, so the workload never blocks on a full pty; the ring (64 KiB) retains the recent raw tail for reattach (the client's single filter, fed the full replayed-plus-live stream, stays in sync).

This decouples the **client** from the **kennel**. The kennel's lifetime is still owned by the serving thread and the process chain — it ends only when the *workload* exits (or on `Stop`), exactly as above. What changes is that the *client* is now a detachable subscriber:

- **Detach** is purely client-side: the CLI watches its input for `Ctrl-\ d`, restores the terminal, and closes its socket. The broker sees the close, drops the client, and keeps pumping. The workload runs on. No control verb is involved.
- **`kennel attach <name>`** reconnects a terminal to a still-running kennel. The broker replays the ring tail, then **takes over** from any current client (a single PTY — the prior client gets a clean `Detached { reason: "another client attached" }` and exits 0). This is the "my SSH dropped, reconnect from a new terminal" case; both clients are the same operator (`SO_PEERCRED`).
- **Resize** rides a fire-and-forget `Resize { rows, cols }` request: because the broker holds the master, the CLI relays each `SIGWINCH` rather than `ioctl`-ing the fd itself.

The filter runs **client-side** in the `kennel` CLI, fed the broker's raw stream (replay + live), and the daemon conveys the `[tty]` decision in its `Started`/`Attached` response; the **workload** cannot opt out (it does not choose its client), and a raw consumer of the attach socket only footguns its own terminal — keeping the `vte` parser of workload bytes out of the daemon TCB (`07-9 §7.9.5`, §4.8, threat `T2.6`). This is **console-style** attach (one PTY, take-over), explicitly *not* `exec`-style: there is no `setns`, no second process injected into the live confinement (no `T3.2` surface) — the only objects that cross are the master fd (already in kenneld's TCB) and a benign client socket. `kennel list` shows each running kennel's client presence as `attached`/`detached`.

When the workload exits while a client is detached, teardown runs immediately as above; a later `attach` gets "kennel … has exited". A kenneld restart still ends the serving thread and thus the kennel — detach survives a *client* leaving, not kenneld leaving.

---

## The locking matrix

Every lock in the system, what it protects, and what acquisition failure means.

| Lock | Type | Scope | Held for | On failure |
|---|---|---|---|---|
| systemd socket activation on `/run/user/<uid>/kennel/control.sock` | the unit owns the listener | one kenneld per user | kenneld's whole lifetime | systemd hands the single bound listener to one daemon; it is the single-instance guarantee. When started without socket activation (dev), kenneld binds the path itself, replacing a stale socket first. |
| kenneld registry mutex | in-process `Mutex` | kenneld's registry and `<ctx>` allocator | brief; never across slow operations | N/A (in-process); the slow bring-up runs outside the lock. |

The privhelper holds no inter-process lock: each invocation runs one validated operation and exits, and the kernel serialises the privileged syscalls themselves.

Single-instance-per-user is enforced by **systemd socket activation**: the `kenneld.socket` user unit owns the one bound listener and hands it to a single daemon (`kennel-lib-config`/`socket.rs`). There is no `kenneld.lock` flock and no `kenneld.pid` file. In the development/socket-less path kenneld binds `control.sock` itself, removing any stale socket first.

### The discipline around the registry mutex

The registry mutex is never held across a slow or fallible operation (privhelper invocation, proxy launch, the spawn sequence). The pattern is: take the lock, record or remove the registry entry and allocate the `<ctx>`, release the lock, then do the slow work. Each kennel is independent — one kennel's bring-up never blocks another's, and the per-kennel resources (proxy, addresses, cgroup) are owned by the thread serving that kennel's `Start`.

---

## Concurrency

Multiple `kennel` CLI invocations talk to kenneld at once; this is the normal case (`01-process-model.md` §Concurrency). The accept loop spawns one thread per connection (blocking, no async runtime). Each thread that serves a `Start` owns its kennel's `Kennel` value for the workload's lifetime; coordination across threads is only over the registry mutex:

- Two `Start` requests for *different* kennels: fully parallel. The registry mutex is held only for the brief registry mutation and `<ctx>` allocation; each bring-up runs concurrently in its own thread.
- A `Stop` for a kennel signals the workload owned by that kennel's serving thread, which then runs teardown. There is no name-sharing and no `starting`-state wait — a second `kennel run` of the same name is a distinct kennel with its own `<ctx>`.

---

## Egress proxy lifecycle

A kennel's `host-netproxy` is a child of kenneld, launched during the kennel's bring-up and reaped during teardown. It is not shared across kennels: each kennel has its own proxy, listening on that kennel's loopback address.

**Launch.** kenneld writes the per-kennel proxy config (`proxy-<ctx>.toml`, derived from the settled policy's network fragment) and launches `host-netproxy` against it before the workload starts. The proxy is the workload's only egress path; the cgroup BPF rules deny direct `connect()` to anything but the proxy.

**Teardown.** When the workload exits (or `Stop` arrives), kenneld reaps the proxy as part of the kennel's teardown.

**Proxy exits while the kennel is running.** The cgroup BPF rules continue to deny all direct egress while the proxy is down, so no traffic escapes during the gap. The workload sees connection failures until the kennel is torn down or restarted; egress is fail-closed by construction.

**Proxy as a binder-coupled CONNECT delegate.** Under the per-kennel network namespace (`02-5-binder-net.md`), `host-netproxy` is reached not by a loopback TCP listener but as kenneld's host-net-ns **CONNECT delegate**, attached to a per-kennel `kenneld`↔delegate `AF_UNIX` command socket. Its lifetime is coupled to the kennel (one proxy per kennel, launched after binderfs is up, killed and reaped at teardown). The in-kennel `facade-socks5` (binder consumer of `org.projectkennel.INet/default`, SOCKS5/HTTP front-end) is forked into the kennel's namespaces and torn down with them. The §7.5.7 inbound mirror's host-side delegate `host-inetd` (kenneld's **BIND delegate**, holding the host-side mirror sockets) is likewise one-per-kennel and reaped at teardown; its accept loops and per-port reader threads end with it, and `facade-client` (the in-kennel pull end) goes with the namespaces. Teardown removes the kennel's `/28`+`/64` from the host `lo` via the privhelper `DelAddr` op (the construction-time add was folded into the one-shot `construct_kennel` op); the in-kennel listeners and facades go with the net/mount namespaces, and the delegate command sockets close when kenneld and the delegates exit.

---

## The binderfs bus and `kennel-bin-init` lifecycle

Each kennel runs its own binderfs instance — the auditable inter-namespace gateway, with kenneld as node 0 (`02-4-binder.md`). Its lifecycle is bound to the kennel's mount namespace and to `kennel-bin-init`, not to a separate resource kenneld must reclaim.

**Mount.** The privhelper factory mounts the binderfs instance inside the kennel's child mount namespace during construction, allocates the standard `binder` device, and chowns it to the operator — before `pivot_root` and the `fexecve` of `kennel-bin-init` (the mount work runs while the process is uid 0 in the kennel's userns, so `binder-control` stays root-only; the device is operator-readable). kenneld then takes node 0 via `/proc/<init-host-pid>/root/dev/binderfs/binder`.

**In life.** The bus carries the in-life control plane: `kennel-bin-init`'s `GET_SANDBOX_PLAN` config pull and its `NOTIFY_*` lifecycle events (`NOTIFY_BOOT_SYNC`, `NOTIFY_FACADE_CRASH`, `NOTIFY_WORKLOAD_EXEC`), plus the protocol facades (the built `org.projectkennel.IAfUnix/default` brokered connect). kenneld accepts a lifecycle verb only when the kernel-stamped `sender_pid` equals the init's host pid and `sender_euid == 0`.

**Teardown.** No explicit unmount and no kenneld reclaim step: the instance is a mount in the child mount namespace and disappears with it when the kennel's last process exits. Pending transactions receive death notifications and all nodes are destroyed. This rides the immediate, no-grace teardown described above. Because the bus may already be gone when the workload exits, the reliable exit-status path is the process chain (`kennel-bin-init` → privhelper → kenneld), not the bus — the bus carries in-life telemetry only.

**`kennel-bin-init` supervision.** `kennel-bin-init` is PID 1 in the kennel's PID namespace: it forks the facades (operator uid) and the workload (operator uid, sealed), then runs a `waitpid` loop. A facade death emits `NOTIFY_FACADE_CRASH` to node 0; on workload exit it `_exit`s the workload's status, ending the kennel. `kennel-bin-init` runs as the kennel's uid 0 — a different uid from the operator-uid children it supervises, so they cannot signal or `ptrace` PID 1.

## kenneld restart

kenneld is socket-activated and persists for the user session; a `systemctl --user restart kenneld` (upgrade, crash) interrupts the threads serving live kennels. Because each kennel's runtime state lives in its serving thread, a kenneld restart ends those threads: the workloads' confinement (Landlock, cgroup BPF, the sealed mount namespace) is kernel-enforced and survives, but kenneld's supervision of them does not. There is no registry to reconstruct across the restart — a fresh kenneld starts with an empty registry and serves new `Start` requests.

A kenneld restart also drops node 0 of every live kennel's binderfs bus (kenneld held the context-manager fd), so the in-life binder control plane and the facades go dark; `kennel-bin-init` keeps supervising and reaping the workload in-kennel (it does not depend on kenneld), but `BINDER_SET_CONTEXT_MGR` is one-per-instance and a fresh kenneld does not re-adopt an existing instance's node 0. The kennel runs out its confinement to workload exit without a bus.

---

## Sub-kennels (refinements)

A *refinement* is a kennel started inside another kennel — `kennel run ai-coding/npm -- npm install` from inside the `ai-coding` kennel. It does not get its own daemons or its own cgroup; it inherits the parent's confinement and adds a stricter Landlock ruleset on top (design doc §8.4).

- **No separate process tree role.** The refinement's workload is a descendant of the parent's workload, in the same cgroup and the same PID namespace. The cgroup BPF rules and the parent's Landlock ruleset already apply; the refinement adds a second, narrower Landlock ruleset that the kernel intersects with the parent's.
- **Lifetime.** A refinement cannot outlive its parent: it is in the parent's cgroup and namespace, which the kernel tears down when the parent's last process exits. The kernel enforces this; kenneld does not need to.
- **Policy.** A refinement may only *narrow*. Its policy is a stricter delta applied as an additional Landlock ruleset; it cannot widen the parent's grants (the kernel does not permit widening a sealed Landlock ruleset). A refinement that names a non-stricter policy is rejected at refinement-start.

---

## Failure modes

The catalogue, each with documented behaviour:

| Failure | Behaviour |
|---|---|
| kenneld unreachable at CLI start | The CLI cannot start a kennel: it reports that kenneld is not reachable (is the `kenneld.socket` user unit enabled?) and exits non-zero. No kennel is started. |
| privhelper missing | Kennel bring-up fails, naming the missing privhelper. kenneld unwinds and returns a structured error; no kennel is started. |
| privhelper refuses a request | Out-of-scope request (address outside the reserved range, cgroup outside `kennel/`). The privhelper returns `refused`; kenneld unwinds the bring-up and returns a structured error. |
| required kernel feature missing | Detected at bring-up. Bring-up fails naming the feature. The check is before the workload runs, so a feature does not vanish under a running kennel. |
| settled-policy signature invalid | The spawn path refuses before any setup; exit code 6. No kennel is started. |
| settled policy violates a framework invariant | Refused by the spawn path's invariant re-assertion (boundary 13, `04-trust-boundaries.md`); exit code 3. |
| egress proxy exits while the kennel is running | Egress stays denied by the cgroup BPF rules while the proxy is down; the workload sees connection failures until the kennel is torn down. |
| workload killed by the kernel (OOM, seccomp) | The workload exits; kenneld observes the exit and tears the kennel down immediately, exactly as for a clean exit. |
| kenneld crashes | A fresh kenneld starts with an empty registry. Running workloads keep their confinement (Landlock, cgroup BPF, sealed mount namespace) — kernel-enforced and independent of kenneld — but lose kenneld's supervision. |
| mount-namespace / factory construction fails mid-build | The privhelper factory aborts before `fexecve`ing `kennel-bin-init` (or `kennel-bin-init` aborts before the workload `execve`); the partially-constructed namespace — including the binderfs mount — is discarded with the failed child. Bring-up returns an error; no workload runs. The kennel never runs partially confined. |
| `kennel-bin-init` exits / crashes before the workload exits | The privhelper, as `kennel-bin-init`'s parent, reaps it and relays the status; kenneld observes it over the construction chain and tears the kennel down, exactly as for a workload exit. The bus is irrelevant to this path. |

A theme: the workload's *confinement* never depends on kenneld being alive. Landlock rulesets are sealed into the workload's process, cgroup BPF programs are attached to the cgroup, the mount namespace is the workload's own. kenneld dying removes supervision but does not weaken the kernel-enforced boundary around a running workload.

---

## Operational signals

kenneld installs no signal handlers: `run()` builds the shared state and calls `serve()`, a blocking accept loop, with no `sigaction`/`SIGTERM`/`ctrlc` handling. Signals therefore take their default disposition.

- **`SIGTERM`** — default-terminates the process (used by `systemctl --user stop kenneld`). This ends the accept loop and the per-kennel serving threads without an orderly drain; each thread's owned workload is left to the kernel-enforced confinement that survives kenneld (Landlock, cgroup BPF, the sealed mount namespace) and to whatever supervisor reaps the process tree. There is no "stop accepting new starts, let workloads drain" sequence — kenneld holds no draining state.

---

## What this chapter does not cover

- The process topology and IPC sockets: `01-process-model.md`.
- The control-protocol wire format that drives bring-up (`Start`, `Stop`, `List`): `02-6-ipc.md`.
- The settled-policy verification performed during bring-up: `02-2-config-schema.md` and `04-trust-boundaries.md` (boundary 13).
- The privhelper protocol invoked for address and cgroup operations: `02-6-ipc.md`.
- The on-disk layout of the per-kennel runtime tree (`/run/user/<uid>/kennel/`): `07-paths.md`.
- The binder bus contract, node 0, and the binderfs mount sequencing: `02-4-binder.md`; the network-over-binder contract: `02-5-binder-net.md`.
- The privhelper factory, `kennel-bin-init` PID 1, and the construction split: design §7.2 and `01-process-model.md`.
- The kernel mechanisms whose enforcement is independent of kenneld: design doc §7 and §8.
