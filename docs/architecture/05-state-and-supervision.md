# State and supervision

This chapter is the authoritative treatment of runtime state: the per-kennel lifecycle, how kenneld brings a kennel up and tears it down, the locking matrix that keeps concurrent access correct, and the failure modes. The process-topology view is in `01-process-model.md`; this chapter is what happens at the edges where those processes meet.

The model is deliberately small. kenneld persists for the user session (socket-activated). Each `kennel run` is one kennel with its own context byte, cgroup, egress proxy, loopback addresses, and constructed view; those resources tear down immediately when the workload exits (`kenneld::Kennel::stop`). There is no grace period, no draining state, no reclaim, and no per-kennel reference counting — one workload is one kennel.

---

## Where state lives

Project Kennel keeps as little persistent state as it can. State is recoverable from the running system wherever possible, rather than written to disk and trusted.

| State | Owner | Lives in |
|---|---|---|
| Kennel registry (which kennels exist, their state) | kenneld | in-memory |
| `<ctx>` byte allocation | kenneld | in-memory |
| Proxy PID and kennel handle | kenneld | in-memory (the thread serving the `Start` owns the `Kennel`) |
| Loopback address allocation | kernel (the `lo`/dummy interface) | the interface itself |
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
| `starting` | Bring-up in progress: `<ctx>` allocated, privhelper adding addresses and creating the cgroup, proxy config written and `kennel-netproxy` launched, spawn sequence running. |
| `running` | Workload launched and in the cgroup; proxy up; BPF attached. |

### Transitions

**Start → `starting`.** A `Start` request arrives over the control socket (the CLI passes the workload's stdio fds via `SCM_RIGHTS`). kenneld allocates a `<ctx>` byte, records the kennel in the registry, and begins bring-up: verify the settled policy (`02-2`), invoke the privhelper to add the loopback addresses and create the cgroup, write the proxy config and launch `kennel-netproxy`, then run the spawn sequence (`kennel-spawn`).

**`starting` → `running`.** The workload is launched into the cgroup. kenneld replies `Started { ctx, pid }` to the CLI and blocks on the workload.

**Bring-up failure.** Any step fails (signature verification, privhelper refusal, proxy launch, spawn). kenneld unwinds whatever it allocated in reverse (`teardown`: reap the proxy if launched, remove any added addresses, delete the cgroup), removes the registry entry, and returns a structured error to the caller.

**`running` → removed.** The workload exits. kenneld replies `Exited { code }`, runs teardown immediately — reap the proxy, invoke the privhelper to remove the loopback addresses, delete the cgroup, discard the constructed view — and removes the registry entry. A `Stop` request for the kennel reaches the same teardown by terminating the workload first. There is no grace window: a later `kennel run` is a separate kennel with its own resources.

---

## The locking matrix

Every lock in the system, what it protects, and what acquisition failure means.

| Lock | Type | Scope | Held for | On failure |
|---|---|---|---|---|
| systemd socket activation on `/run/user/<uid>/kennel/control.sock` | the unit owns the listener | one kenneld per user | kenneld's whole lifetime | systemd hands the single bound listener to one daemon; it is the single-instance guarantee. When started without socket activation (dev), kenneld binds the path itself, replacing a stale socket first. |
| kenneld registry mutex | in-process `Mutex` | kenneld's registry and `<ctx>` allocator | brief; never across slow operations | N/A (in-process); the slow bring-up runs outside the lock. |

The privhelper holds no inter-process lock: each invocation runs one validated operation and exits, and the kernel serialises the privileged syscalls themselves.

Single-instance-per-user is enforced by **systemd socket activation**: the `kenneld.socket` user unit owns the one bound listener and hands it to a single daemon (`kennel-config`/`socket.rs`). There is no `kenneld.lock` flock and no `kenneld.pid` file. In the development/socket-less path kenneld binds `control.sock` itself, removing any stale socket first.

### The discipline around the registry mutex

The registry mutex is never held across a slow or fallible operation (privhelper invocation, proxy launch, the spawn sequence). The pattern is: take the lock, record or remove the registry entry and allocate the `<ctx>`, release the lock, then do the slow work. Each kennel is independent — one kennel's bring-up never blocks another's, and the per-kennel resources (proxy, addresses, cgroup) are owned by the thread serving that kennel's `Start`.

---

## Concurrency

Multiple `kennel` CLI invocations talk to kenneld at once; this is the normal case (`01-process-model.md` §Concurrency). The accept loop spawns one thread per connection (blocking, no async runtime). Each thread that serves a `Start` owns its kennel's `Kennel` value for the workload's lifetime; coordination across threads is only over the registry mutex:

- Two `Start` requests for *different* kennels: fully parallel. The registry mutex is held only for the brief registry mutation and `<ctx>` allocation; each bring-up runs concurrently in its own thread.
- A `Stop` for a kennel signals the workload owned by that kennel's serving thread, which then runs teardown. There is no name-sharing and no `starting`-state wait — a second `kennel run` of the same name is a distinct kennel with its own `<ctx>`.

---

## Egress proxy lifecycle

A kennel's `kennel-netproxy` is a child of kenneld, launched during the kennel's bring-up and reaped during teardown. It is not shared across kennels: each kennel has its own proxy, listening on that kennel's loopback address.

**Launch.** kenneld writes the per-kennel proxy config (`proxy-<ctx>.toml`, derived from the settled policy's network fragment) and launches `kennel-netproxy` against it before the workload starts. The proxy is the workload's only egress path; the cgroup BPF rules deny direct `connect()` to anything but the proxy.

**Teardown.** When the workload exits (or `Stop` arrives), kenneld reaps the proxy as part of the kennel's teardown.

**Proxy exits while the kennel is running.** The cgroup BPF rules continue to deny all direct egress while the proxy is down, so no traffic escapes during the gap. The workload sees connection failures until the kennel is torn down or restarted; egress is fail-closed by construction.

---

## kenneld restart

kenneld is socket-activated and persists for the user session; a `systemctl --user restart kenneld` (upgrade, crash) interrupts the threads serving live kennels. Because each kennel's runtime state lives in its serving thread, a kenneld restart ends those threads: the workloads' confinement (Landlock, cgroup BPF, the sealed mount namespace) is kernel-enforced and survives, but kenneld's supervision of them does not. There is no registry to reconstruct across the restart — a fresh kenneld starts with an empty registry and serves new `Start` requests.

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
| mount-namespace setup fails mid-spawn | The spawn sequence aborts before `execve`; the partially-constructed namespace is discarded with the failed child. Bring-up returns an error; no workload runs. |

A theme: the workload's *confinement* never depends on kenneld being alive. Landlock rulesets are sealed into the workload's process, cgroup BPF programs are attached to the cgroup, the mount namespace is the workload's own. kenneld dying removes supervision but does not weaken the kernel-enforced boundary around a running workload.

---

## Operational signals

kenneld installs no signal handlers: `run()` builds the shared state and calls `serve()`, a blocking accept loop, with no `sigaction`/`SIGTERM`/`ctrlc` handling. Signals therefore take their default disposition.

- **`SIGTERM`** — default-terminates the process (used by `systemctl --user stop kenneld`). This ends the accept loop and the per-kennel serving threads without an orderly drain; each thread's owned workload is left to the kernel-enforced confinement that survives kenneld (Landlock, cgroup BPF, the sealed mount namespace) and to whatever supervisor reaps the process tree. There is no "stop accepting new starts, let workloads drain" sequence — kenneld holds no draining state.

---

## What this chapter does not cover

- The process topology and IPC sockets: `01-process-model.md`.
- The control-protocol wire format that drives bring-up (`Start`, `Stop`, `List`): `02-4-ipc.md`.
- The settled-policy verification performed during bring-up: `02-2-config-schema.md` and `04-trust-boundaries.md` (boundary 13).
- The privhelper protocol invoked for address and cgroup operations: `02-4-ipc.md`.
- The on-disk layout of the per-kennel runtime tree (`/run/user/<uid>/kennel/`): `07-paths.md`.
- The kernel mechanisms whose enforcement is independent of kenneld: design doc §7 and §8.
