# State and supervision

This chapter is the authoritative treatment of runtime state: the per-kennel state machine, how kenneld counts and reaps, the locking matrix that keeps concurrent access correct, how recovery works when kenneld restarts with daemons still alive, and the failure modes. The process-topology view is in `01-process-model.md`; this chapter is what happens at the edges where those processes meet.

---

## Where state lives

Project Kennel keeps as little persistent state as it can. State is recoverable from the running system wherever possible, rather than written to disk and trusted.

| State | Owner | Lives in | Survives kenneld restart? |
|---|---|---|---|
| Kennel registry (which kennels exist, their state-machine position) | kenneld | in-memory | Reconstructed from the running system (§Recovery) |
| Per-kennel reference counter | kenneld | in-memory | Reconstructed from cgroup membership |
| `<ctx>` byte allocation | kenneld | in-memory, mirrored in `/run/kennel/<id>/kennel.json` | Reconstructed from `/run/kennel/<id>/` scan |
| Drain timers | kenneld | in-memory | Reconstructed (a kennel found with zero live workloads re-enters draining) |
| Daemon PIDs | kenneld | in-memory, mirrored in `/run/kennel/<id>/<daemon>.pid` | Reconstructed from pidfiles + `/proc` |
| Loopback address allocation | kernel (the `lo`/dummy interface) | the interface itself | Yes — the addresses persist; kenneld re-reads them |
| cgroup membership | kernel | `/sys/fs/cgroup/kennel/<id>/cgroup.procs` | Yes — the source of truth for "who is running" |
| Audit log | filesystem | `~/.local/state/kennel/<kennel>/` | Yes — append-only files |
| Settled policy | filesystem | `~/.config/kennel/kennels/<name>.settled.toml` or `/etc/kennel/settled/` | Yes |

The design principle: the kernel and the filesystem hold the durable truth (who is in which cgroup, which addresses are bound, which audit events were written). kenneld's in-memory registry is a *cache* of that truth, rebuilt on restart. kenneld crashing and restarting does not lose kennels or orphan workloads; it re-derives its view from the system.

---

## The per-kennel state machine

Every kennel kenneld knows about is in exactly one of five states.

```
   absent ──start──► starting ──ready──► running ──last workload exits──► draining
                        │                   ▲                                │
                        │ failure           │ reclaim (new workload          │ grace
                        ▼                    │  arrives during grace)        │ elapses
                     (error to              └────────────────────────────────┤
                      caller; back                                           ▼
                      to absent)                                          stopped
                                                                              │
                                                                         (daemons reaped,
                                                                          addresses removed,
                                                                          back to absent)
```

| State | Meaning | Valid CLI operations |
|---|---|---|
| `absent` | Not running. May be defined on disk (a policy exists) or not. | `run` (→ starting), `status`, `list`, `validate`, `compile` |
| `starting` | Setup in progress: settled policy verified, privhelper allocating addresses and cgroup, daemons spawning. | `status`; a concurrent `run` waits (§Concurrency) |
| `running` | At least one workload alive; daemons up; BPF attached. | `run` (joins), `stop`, `kill`, `status`, `audit` |
| `draining` | Last workload exited; daemons still up; grace timer counting. | `run` (reclaims → running), `stop --reap` (→ stopped now), `status` |
| `stopped` | Teardown in progress: daemons reaped, addresses removed, cgroup deleted. Transient; ends at `absent`. | `status` |

### Transitions

**`absent` → `starting`.** Triggered by the first `kennel.start` for the kennel. kenneld takes the registry lock, confirms the kennel is `absent`, inserts a `starting` entry, and releases the lock before doing the slow work. The slow work: load and verify the settled policy (§The settled policy, `02-2`), allocate a `<ctx>` byte, invoke the privhelper to add loopback addresses and create the cgroup, spawn the per-kennel daemons, wait for each to signal ready.

**`starting` → `running`.** All daemons reported ready and the cgroup is prepared. kenneld takes the registry lock, transitions to `running`, wakes any threads waiting on this kennel (§Concurrency), releases the lock. The CLI that triggered the start proceeds to the spawn sequence; its workload's PID lands in the cgroup.

**`starting` → `absent` (failure).** Any setup step fails (signature verification, privhelper refusal, daemon failed to start, kernel feature missing). kenneld unwinds whatever it allocated (removes any added addresses, reaps any spawned daemons, deletes the cgroup), transitions to `absent`, and returns a structured error to the waiting caller(s).

**`running` → `running` (join).** A subsequent `kennel.start` for an already-`running` kennel does not re-run setup. It increments the reference counter (via `kennel.workload-attaching`) and returns the existing kennel's parameters. The new workload joins the same cgroup, same daemons, same allowlist.

**`running` → `draining`.** The reference counter reaches zero (last workload exited; §Reference counting). kenneld starts the drain timer (default 60s) and transitions to `draining`. Daemons stay up; addresses stay bound; the cgroup persists.

**`draining` → `running` (reclaim).** A `kennel.start` arrives while the kennel is `draining`. kenneld cancels the drain timer, increments the reference counter, transitions back to `running`, and returns the existing parameters. No setup re-runs; the daemons were never torn down. This is the path that makes "open a second terminal moments after the first exits" free of daemon churn.

**`draining` → `stopped`.** The drain timer elapses with the reference counter still zero, or `kennel.stop --reap` / `kennel.kill` forces it. kenneld transitions to `stopped` and begins teardown.

**`stopped` → `absent`.** Teardown completes: daemons reaped (SIGTERM, then SIGKILL after a short grace), privhelper invoked to remove the loopback addresses and delete the cgroup, `/run/kennel/<id>/` cleaned. The registry entry is removed.

---

## Reference counting

kenneld counts the live workloads in each kennel. The counter drives the `running` ↔ `draining` boundary.

- **Increment.** The CLI sends `kennel.workload-attaching` (with its own PID) immediately before forking the workload. kenneld increments and records the CLI's PID against the kennel.
- **Decrement.** The CLI sends `kennel.workload-exited` after the workload exits. kenneld decrements and forgets the CLI's PID.
- **Crash safety.** If a CLI process dies without sending `workload-exited` (killed, crashed), kenneld would otherwise leak a count. kenneld holds the CLI's connection for the workload's lifetime; the connection closing is an implicit `workload-exited` for any PIDs that CLI had attached. The connection close is the authoritative signal; the explicit message is an optimisation.
- **Ground truth.** The counter is a cache. `/sys/fs/cgroup/kennel/<id>/cgroup.procs` is the truth: it lists every PID in the cgroup. kenneld reconciles the counter against `cgroup.procs` on reconnect, on `SIGUSR1` state dump, and during recovery.

The drain timer (default 60s, configurable via the kennel's `[lifecycle]` policy) starts when the counter hits zero and is cancelled if it returns above zero before elapsing. The grace window absorbs the common "re-enter the kennel almost immediately" pattern without reaping and respawning daemons.

---

## The locking matrix

Every lock in the system, what it protects, and what acquisition failure means.

| Lock | Type | Scope | Held for | On failure |
|---|---|---|---|---|
| `/run/user/<uid>/kennel/kenneld.lock` | `flock` (exclusive) | one kenneld per user | kenneld's whole lifetime | Another kenneld is running; the second instance exits with a clear error naming the holding PID. |
| bind on `/run/user/<uid>/kennel/kenneld.sock` | kernel socket bind | one listener per path | kenneld's whole lifetime | `EADDRINUSE`; second instance exits. Belt-and-braces with the lockfile. |
| `/run/kennel/privhelper.lock` | `flock` (exclusive) | machine-wide | duration of one privhelper operation | Concurrent privhelper invocations serialise; the second waits. |
| `/run/kennel/<id>/kennel.lock` | `flock` (exclusive) | one mutator per kennel | brief, around start/reclaim/teardown transitions | A degraded-mode CLI and kenneld cannot both mutate the same kennel's runtime state; the loser waits or errors. |
| kenneld registry mutex | in-process `Mutex`/`RwLock` | kenneld's registry, counters, allocator | brief; never across slow operations | N/A (in-process); long operations happen outside the lock with state transitions guarding mid-operation visibility. |

### The discipline around the registry mutex

The registry mutex is never held across a slow or fallible operation (privhelper invocation, daemon-readiness wait, BPF attach). The pattern is: take the lock, read or transition state, release the lock, do the slow work, take the lock again, record the result. The `starting` state is what makes this safe — a second request that finds the kennel in `starting` waits on a condition variable rather than re-running setup, and is woken when the first request transitions to `running` or `absent`.

This means a CLI requesting a kennel never holds a lock while a privhelper call or a daemon spawn is in flight, and a slow setup never blocks an unrelated kennel's operations.

---

## Concurrency

Multiple `kennel` CLI invocations talk to kenneld at once; this is the normal case (`01-process-model.md` §Concurrency). The accept loop hands each connection to its own worker. Coordination is entirely through the registry mutex and the state machine:

- Two `kennel.start` for the *same* `absent` kennel: the first wins the race to insert `starting`; the second finds `starting` and waits on the condvar. When the first reaches `running`, both proceed (the second as a join — increment, no setup).
- Two `kennel.start` for *different* kennels: fully parallel. The registry mutex is held only for the brief registry mutations; the slow setup of each runs concurrently.
- `kennel.start` racing `kennel.stop` on the same kennel: serialised by the registry mutex at the transition points. A `stop` that arrives during `starting` is queued behind the start's completion; a `start` that arrives during `draining` reclaims (above).

---

## Daemon lifecycle and reuse

Per-kennel daemons (`kennel-netproxy`, `kennel-ssh-agent`, `xdg-dbus-proxy`) are children of kenneld, spawned during a kennel's `starting` phase and reaped during `stopped`.

**Spawn.** kenneld spawns each daemon the kennel's settled policy requires, places its socket at the framework path (`/run/kennel/<id>/<daemon>.sock`), writes the pidfile, and waits for the daemon to signal ready (the daemon connects back to its control socket and reports, or writes a readiness byte — see `02-4`).

**Reuse.** When a kennel transitions `draining` → `running` (reclaim), the daemons were never stopped; they are reused as-is. When a kennel is started fresh but a daemon for the same kennel name somehow still exists (recovery, §below), kenneld compares the daemon's configuration hash against the current settled policy: matching → adopt; differing → stop and respawn.

**Crash.** If a daemon exits while its kennel is `running`, kenneld receives `SIGCHLD`, reaps it, and audit-logs `lifecycle.daemon-exit`. The response is policy-driven:

- `kennel-netproxy` crash: the cgroup BPF rules continue to deny all direct egress while the proxy is down, so no traffic escapes during the gap. kenneld respawns the proxy and audit-logs the restart. In-flight connections are lost; the workload sees connection resets.
- `kennel-ssh-agent` crash: git-over-SSH fails for the kennel until kenneld respawns it; in-memory keys are lost (the workload or its init re-adds them).
- `xdg-dbus-proxy` crash: D-Bus calls fail until respawn.

Respawn is bounded: more than N restarts (default 5) within a window (default 60s) is treated as a crash loop; kenneld stops respawning, audit-logs `lifecycle.daemon-giveup`, and the kennel continues with that capability unavailable rather than churning.

---

## Recovery from kenneld restart

kenneld may be restarted (upgrade, crash, `systemctl --user restart kenneld`) while kennels are running and daemons are alive. Because the kernel and filesystem hold the durable truth, kenneld rebuilds its registry rather than losing state.

On startup:

1. **Acquire the lockfile.** `flock` on `kenneld.lock`. The kernel released the previous holder's `flock` when it exited, so a crashed predecessor's lock is gone. If the lock is held, another kenneld is live — exit.
2. **Claim the socket.** `connect()` to `kenneld.sock`. If something answers, another kenneld won the race — exit. If nothing answers, `unlink()` the stale socket and `bind()` fresh.
3. **Scan `/run/kennel/`.** For each `<id>/` directory, read `kennel.json` (the mirrored `<ctx>`, UUID, policy hash) and each `<daemon>.pid`. For each pidfile, verify the PID is alive *and* `/proc/<pid>/exe` resolves to the expected daemon binary path. A PID that is dead, or alive but a different binary (PID reuse), is treated as a dead daemon.
4. **Adopt or clean.** Daemons that pass the check are adopted into the registry. Directories whose daemons are all dead are cleaned: addresses removed via privhelper, cgroup deleted, directory removed.
5. **Reconstruct reference counts.** For each adopted kennel, read `/sys/fs/cgroup/kennel/<id>/cgroup.procs`. The count of live workload PIDs is the reference counter. A kennel with live workloads → `running`. A kennel with adopted daemons but zero workloads → `draining` with a fresh grace timer (the workloads exited during the kenneld outage; the grace window now applies).
6. **Resume.** kenneld begins accepting connections. Reconnecting CLIs re-register their attached PIDs; the connection-close crash-safety (§Reference counting) resumes.

The recovery is idempotent and bounded: it scans a directory tree and a handful of `/proc` entries. On a busy machine it adds a second or two to kenneld startup.

---

## Sub-kennels (refinements)

A *refinement* is a kennel started inside another kennel — `kennel run ai-coding/npm -- npm install` from inside the `ai-coding` kennel. It does not get its own daemons or its own cgroup; it inherits the parent's confinement and adds a stricter Landlock ruleset on top (design doc §8.4).

- **No separate process tree role.** The refinement's workload is a descendant of the parent's workload, in the same cgroup and the same PID namespace. The cgroup BPF rules and the parent's Landlock ruleset already apply; the refinement adds a second, narrower Landlock ruleset that the kernel intersects with the parent's.
- **Reference counting.** A refinement does not increment kenneld's per-kennel counter independently — its workload is already in the parent's cgroup and is already counted there. The parent kennel cannot drain while a refinement is live, because the refinement's PID is in `cgroup.procs`.
- **Lifetime.** A refinement cannot outlive its parent: it is in the parent's cgroup and namespace, which the kernel tears down when the parent's last process exits. The kernel enforces this; kenneld does not need to.
- **Policy.** A refinement may only *narrow*. Its policy is a stricter delta applied as an additional Landlock ruleset; it cannot widen the parent's grants (the kernel does not permit widening a sealed Landlock ruleset). A refinement that names a non-stricter policy is rejected at refinement-start.

---

## Failure modes

The catalogue, each with documented behaviour:

| Failure | Behaviour |
|---|---|
| kenneld unreachable at CLI start | The CLI falls into degraded mode: invokes the privhelper directly, spawns daemons as its own children (they die with the kennel), and serialises privhelper calls via `/run/kennel/privhelper.lock`. One-shot use works; no daemon sharing across invocations. |
| privhelper missing | Kennel start fails with exit code 5 (`permission denied`), naming the missing privhelper. No kennel is started. |
| privhelper refuses a request | Out-of-scope request (address outside the reserved range, cgroup outside `kennel/`). The privhelper returns `refused`; kenneld unwinds the `starting` kennel and returns a structured error. Audit: `priv.refuse`. |
| required kernel feature missing | Detected at kennel start (settled policy declares the features it needs; kenneld checks availability). Start fails with exit code 5 naming the feature. The check is at start, not mid-run, so a feature does not vanish under a running kennel. |
| settled-policy signature invalid | `kennel run` refuses before any setup; exit code 6. No kennel is started. |
| settled policy violates a framework invariant | Refused at runtime by the spawn path's invariant re-assertion (boundary 13, `04-trust-boundaries.md`); exit code 3. |
| per-kennel daemon crashes (kennel running) | kenneld reaps via SIGCHLD, audit-logs, respawns (bounded by the crash-loop limit). Egress stays denied by BPF while the proxy is down. |
| workload killed by the kernel (OOM, seccomp) | The cgroup loses the PID; kenneld observes the count drop (via the CLI's `workload-exited` or connection close, and reconciliation against `cgroup.procs`). Normal `running` → `draining` if it was the last workload. |
| kenneld crashes | The next kenneld start runs Recovery (§above) and rebuilds the registry from the running system. Workloads keep running throughout; their confinement (Landlock, cgroup BPF) is kernel-enforced and independent of kenneld being alive. |
| mount-namespace setup fails mid-spawn | The spawn sequence aborts before `execve`; the partially-constructed namespace is discarded with the failed child. The kennel start returns an error; no workload runs. |

A theme: the workload's *confinement* never depends on kenneld being alive. Landlock rulesets are sealed into the workload's process, cgroup BPF programs are attached to the cgroup, the mount namespace is the workload's own. kenneld dying removes supervision (audit aggregation, daemon respawn, lifecycle management) but does not weaken the kernel-enforced boundary around a running workload.

---

## Operational signals

kenneld responds to:

- **`SIGTERM`** — graceful drain. Stop accepting new kennel starts; let existing workloads run to completion (or up to a shutdown timeout); reap daemons; remove addresses; exit. Used by `systemctl --user stop kenneld`.
- **`SIGHUP`** — reload. Re-read installation configuration (`/etc/kennel/`, `~/.config/kennel/audit.toml`), invalidate the policy cache, re-open audit log files (for log rotation by an external tool). Running kennels are not disturbed.
- **`SIGUSR1`** — state dump. Write the current registry (kennels, states, reference counters, drain timers, daemon PIDs) to the audit log as `lifecycle.kenneld-state-dump` events. A debugging aid; reconciles the in-memory view against `cgroup.procs` as a side effect.

---

## What this chapter does not cover

- The process topology and IPC sockets: `01-process-model.md`.
- The control-protocol wire format that drives the transitions (`kennel.start`, `kennel.workload-attaching`, etc.): `02-4-ipc.md`.
- The settled-policy verification performed during `starting`: `02-2-config-schema.md` and `04-trust-boundaries.md` (boundary 13).
- The privhelper protocol invoked for address and cgroup operations: `02-4-ipc.md`.
- The on-disk layout of `/run/kennel/<id>/` and the pidfiles: `07-paths.md`.
- The kernel mechanisms whose enforcement is independent of kenneld: design doc §7 and §8.
