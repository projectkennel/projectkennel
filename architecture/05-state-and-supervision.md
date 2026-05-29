# State and supervision

**Status: stub.** This chapter is reserved for the detailed treatment of state management, daemon lifecycles, supervision across process boundaries, and recovery semantics. It is forward-referenced from `01-process-model.md` (concurrency note), `02-4-ipc.md` (control protocol that drives state transitions), and `04-trust-boundaries.md` (where the privhelper lifecycle bears on trust).

The high-level sketch in `01-process-model.md` is sufficient for understanding the system at the process-topology level. This chapter is the authoritative treatment of what actually happens when those processes meet at the edges.

---

## Planned scope

### Daemon lifecycles

When each daemon starts, when it terminates, what triggers each transition:

- **kenneld** — login → logout, with explicit start/stop semantics and what happens if it is killed mid-operation.
- **netproxy, ssh-agent, dbus-proxy** — per kennel, reference-counted by kenneld, with a documented grace-period for teardown.
- **privhelper** — per operation, never long-lived. The conditions under which a long-running privhelper daemon might replace this (see `04-trust-boundaries.md`).

### The per-kennel state machine

Transitions: `absent` → `starting` → `running` → `draining` → `stopped`.

For each state:

- What CLI operations are valid against a kennel in this state.
- What internal state kenneld maintains.
- The transition guards and the events that trigger them.
- The behaviour of concurrent CLI requests.

Particular attention to `draining` → `running` reclamation: the case where a CLI re-enters a kennel during its grace period.

### Reference counting

How kenneld counts kennel users, what increments and decrements the counter, the 60-second grace period before reaping daemons, the reclamation path.

Reconstruction after a kenneld restart: the counter is rebuilt from cgroup membership, not persisted.

### The locking matrix

Every `flock`/mutex/socket-bind in the system, what state it protects, and what happens if it cannot be acquired:

- `/run/user/<uid>/kennel/kenneld.lock` — exclusive, one kenneld per user. Held for the lifetime of the kenneld process. Acquisition failure is a clear error pointing to the holding PID.
- `/run/kennel/privhelper.lock` — exclusive across the machine, serialises privhelper invocations. Held for the duration of one privhelper operation only.
- kenneld's internal registry mutex — guards the kennel registry, reference counters, allocator state. Held briefly; long operations occur outside the lock with state transitions guarding mid-operation visibility.
- The bind on `/run/user/<uid>/kennel/kenneld.sock` — kernel-level exclusion; second kenneld instance fails with `EADDRINUSE`.

### Recovery from kenneld crash

The procedure on kenneld restart when daemons may have survived:

1. Acquire the lockfile.
2. Test the socket: connect attempt; unlink and rebind on no listener.
3. Scan `/run/kennel/<id>/` pidfiles; verify each PID via `/proc/<pid>/exe` matches the expected binary path.
4. Adopt survivors; clean up orphaned state for daemons that died with no pidfile cleanup.
5. Read `/sys/fs/cgroup/kennel/<id>/cgroup.procs` to count live workloads; reconstruct reference counters.
6. Cancel pending drain timers for any kennel with live workloads.

### Sub-kennels (refinements)

A kennel started inside another kennel (a refinement) inherits the parent's confinement and adds a stricter Landlock ruleset on top. The lifecycle questions:

- What is the parent–child relationship for reference counting?
- What happens when the parent kennel exits while a child is still running? (It cannot, by kernel design — the child inherits the parent's cgroup and is in the parent's PID namespace; but the user-visible semantics need to be spelled out.)
- Can a sub-kennel use a different policy template, or only a stricter delta?

### Failure modes

The failure-mode catalogue, with documented behaviour and recovery for each:

- kenneld unreachable at CLI start → CLI falls into degraded mode (direct privhelper invocation, daemons as CLI children).
- privhelper missing or refuses → kennel start fails with a structured error naming the rejected request.
- A per-kennel daemon crashes while a workload is running → kenneld notices via SIGCHLD, audit-logs the event, decides whether to respawn (policy-driven) or to terminate the workload.
- The kernel kills a confined workload (OOM, seccomp violation, etc.) → cgroup BPF observes the exit, audit log captures it, kenneld decrements the reference counter.
- A required kernel feature becomes unavailable at runtime → not currently expected since features are validated at kennel start, but mount namespace failure mid-operation is the realistic case.

### Operational signals

- `SIGTERM` to kenneld → graceful drain: stop accepting new kennel starts, wait for existing workloads to exit (or up to a timeout), reap daemons, exit.
- `SIGHUP` to kenneld → reload configuration (policy cache invalidation, audit log rotation re-open).
- `SIGUSR1` to kenneld → dump current state to the audit log for debugging (kennels registered, reference counts, drain timers).

---

## Not yet written

The sections above will be filled in as the implementation settles. The sketch in `01-process-model.md` is the working approximation; this chapter is its formalisation. Significant changes to the state machine or the locking matrix here trigger paired updates in `01` and in `02-4-ipc.md` (where the control protocol's wire format reflects state transitions).
