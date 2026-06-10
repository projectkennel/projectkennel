# §7.2 `kennel-bin-init` — the kennel's PID 1

## 7.2.1 Role and the construction split

A kennel is assembled by two trusted parties across one irreversible boundary:

- **The privhelper is the factory.** Already the host-side root utility, it does *all* the
  privileged construction in its own post-`clone` child, **including `pivot_root`**, and only
  then hands control on.
- **`kennel-bin-init` is the supervisor.** It is `execve`'d **after the host root is gone**, so it
  is trapped inside the sealed view from its first instruction. It holds **no ambient host
  capabilities** — being uid 0 *in the userns* (host root mapped `0 0 1`) gives it only
  userns-scoped `CAP_SETUID`/`CAP_SETGID`, enough to drop the workload and powerless against
  host-owned resources. It needs no `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` anywhere in its lifespan.

This placement is the security crux. If `kennel-bin-init` (or a facade) is exploited, the host
filesystem is **physically absent from its mount namespace** — `pivot_root` already detached
it — so host DAC on host-root-owned files is impossible even though the process is kuid 0.
The dangerous window of "uid-0-mapped binary while the host fs is still visible" never exists.

`kennel-bin-init` does **no policy decisions** and is deliberately tiny: open the binder driver,
pull its Plan over the bus, fork the facades and the workload, drop them to the operator,
confine the workload, supervise, report. No mount, netlink, device-provisioning, filesystem
lookup, or environment-scrubbing code.

### The factory sequence

```
privhelper (real host root)
  1. parse the construction half of the Plan (host-side, before any namespace exists)
  2. open() the trusted kennel-bin-init binary on the host  → hold the fd
  3. clone(CLONE_NEWUSER|NEWNS|NEWPID|NEWIPC[|NEWNET])  → child C is PID 1 of the new pidns
  └─ in C (still privhelper code, full caps in the new userns):
       4. write uid_map "0 0 1\n<op> <op> 1", gid_map "0 0 1\n<op> <op> 1" + granted groups
       5. join the kennel cgroup; bring up loopback; mount the view; mount binderfs,
          allocate the `binder` device, chown /dev/binderfs/binder to the operator uid
       6. pivot_root into the view and detach the old host root   ← the structural sever
       7. place inherited fds (boot-sync, pty); fexecve(initfd)  ← exec by the fd from step 2
       (privhelper then reports the init host pid + the boot-sync socket to kenneld and exits)
─────────────────────────────────────────────────────────────── trust boundary
kennel-bin-init (PID 1, uid 0, trapped in the pivoted view, zero argv/envp)
  8. boot-sync: send READY, block until kenneld signals GO (§7.2.1a) — kenneld claims node 0
  8b. open /dev/binderfs/binder; GET_SANDBOX_PLAN from node 0 (single transaction, no retry)
  9. fork facades (PIDs 2,3,…), each dropped to the operator; NOTIFY_BOOT_SYNC
 10. NOTIFY_WORKLOAD_EXEC; fork the workload, drop to operator, no_new_privs + seccomp +
     Landlock + ulimits + pty, execve
 11. waitpid loop: NOTIFY_FACADE_CRASH on a facade death; on workload exit, _exit its status
```

Single `clone(CLONE_NEWPID|…)` — the child is PID 1 directly; no double-fork (that was only
needed when `unshare` left the unsharer in the old pidns). The privhelper does **not** stay C's
parent: it reports C's host pid to kenneld over the construction socketpair and exits (its job
is done — it is not a reaper proxy). C (PID 1 of its own namespace) outlives it and reparents to
kenneld, which set itself a child subreaper and `waitpid`s C directly for the exit status. The
reliable exit path is thus the parent/`waitpid` relationship (kenneld → C), not binder, which
may already be torn down.

**`fexecve`, not a path exec, is load-bearing:** after `pivot_root` the host path
`<libexec>/kennel-bin-init` is absent from the mount namespace, so the privhelper opens the
trusted init on the host *before* the clone and execs it by descriptor afterward. As a bonus
the init binary never appears in the view; the workload cannot even see it.

## 7.2.1a Boot-sync: deterministic node-0 startup, no retry loop

`kennel-bin-init` pulls its Plan from node 0, which kenneld claims by opening the kennel's binderfs
via `/proc/<init>/root/dev/binderfs/binder`. Two facts make the ordering subtle: that open only
resolves **after** `kennel-bin-init` has `fexecve`'d (a blocked, pre-exec construction child is not
reachable that way), so the claim cannot precede the exec — yet the pull must not precede the
claim. The factory therefore cannot gate the *exec*; it gates the *pull*, from inside
`kennel-bin-init`, over a `SOCK_SEQPACKET` the factory hands it at a fixed inherited descriptor
(`kennel_lib_syscall::boot::BOOT_SYNC_FD`, the sibling of the interactive `PTY_RETURN_FD`):

1. The factory builds the kennel, `fexecve`s `kennel-bin-init`, and reports the init host pid to
   kenneld **with the kenneld end of the boot-sync socket** as an `SCM_RIGHTS` fd; then it exits.
2. `kennel-bin-init` (post-exec) sends `READY` on its end and **blocks**.
3. kenneld sees `READY`, opens the now-reachable binderfs, claims node 0, and sends `GO`.
4. `kennel-bin-init` wakes and pulls — node 0 is already serving, so it is a single first-try
   transaction.

This replaces the previous double retry (kenneld polling for the device to appear, `kennel-bin-init`
re-sending `GET_SANDBOX_PLAN` until it stopped getting `BR_DEAD_REPLY`) with one deterministic
handshake. The fixed descriptors `kennel-bin-init` inherits are placed collision-safe: the factory
lifts the init-binary, boot-sync, and pty fds above the target range before `dup2`-ing them down,
so an interactive run's extra pty fd cannot make a placement clobber one still needed.

## 7.2.2 The binder bus is the control plane

`kennel-bin-init` is a **binder client on the same per-kennel binderfs instance** the privhelper
mounted, transacting to **node 0 (kenneld)** for both its configuration pull and every
lifecycle event. This is the one IPC mechanism the kennel already runs; no ad-hoc pipes,
`stderr` scraping, or early UNIX socket.

The decisive property is **kernel-stamped, unforgeable caller identity**: the binder driver
injects `sender_pid`/`sender_euid` into every transaction; a process cannot lie about them.

### The identity gate

The gate cannot key on the kennel-internal PID 1. kenneld is the context manager from the
**host** PID namespace, and the binder driver reports a transaction's sender pid relative to
the *receiver's* namespace — so kenneld sees `kennel-bin-init`'s **host pid**, not the
kennel-internal `1`. That host pid is exactly the fact the privhelper already holds: having
created the namespace chain, it tells kenneld `kennel-bin-init`'s host pid at construction time
(out of band, never over the bus). kenneld therefore admits a lifecycle or config transaction
only when its kernel-stamped sender pid equals that host pid; anything else is denied and
audited.

The sender's effective uid being 0 is defense in depth: `kennel-bin-init` is the only uid-0
process in the kennel (the facades and workload run as the operator's non-zero uid), so it
cannot be impersonated. The host-pid match is the primary, exact gate.

### Lifecycle/config verbs ride node 0, in their own code range

Lifecycle is **reserved verb codes on node 0**, consistent with the `AF_UNIX` facade
(`CONNECT_AFUNIX`). Node 0's registry verbs occupy 1–5 and `CONNECT_AFUNIX` is 5, so the
lifecycle verbs sit in a **distinct high range** (`0x100+`) to avoid collision. A workload can
address node 0 but the sender-identity gate makes these verbs inert for anyone but
`kennel-bin-init`, which is thus a binder participant in its own right alongside kenneld and the
network facade.

## 7.2.3 The pull model: zero-argument `execve`, config over the bus

The privhelper mounts binderfs and `execve`s `kennel-bin-init` with **empty `argv` and `envp`** —
no serialized Plan shoved through arguments or the environment, and nothing for host-side
`ps`/`/proc/<pid>/cmdline`/`environ` to leak.

`kennel-bin-init` **pulls** its configuration:

1. Open the standard `/dev/binderfs/binder` (a compile-time constant path).
2. `GET_SANDBOX_PLAN` to node 0 — a single transaction, **no retry**. The boot-sync handshake
   (§7.2.1a) guarantees kenneld has already claimed node 0 by the time this runs.
3. kenneld looks up the **supervision half** of the pre-compiled Plan **by the binderfs
   instance the transaction arrived on** — each kennel has its own node-0 fd and looper, so a
   transaction on that queue is unambiguously that kennel; no token, cookie, or handshake is
   needed to identify the requester.
4. kenneld replies with the supervision half as a **flat serialized buffer**. Binder
   **copies** it into the target's mapped region — a binder transaction carries no shared
   pointers — so the Plan arrives as a localized flat buffer with no host↔sandbox
   shared-memory hazard. The interactive pty-return socket does **not** ride this reply: the
   factory passes it on the construction channel and `kennel-bin-init` inherits it at a fixed
   descriptor (decoupled from the bus, §7.9.5a), so the supervision half carries only an
   `interactive` flag telling the seal to use it.
5. `kennel-bin-init` decodes the flat buffer and knows exactly which facades to fork and which
   workload to launch.

### The `Plan` splits three ways

kenneld holds the full Plan and never serialises all of it to one place:

- **Construction half → privhelper** (the construction request): the uid/gid maps, the
  loopback config, the binderfs parameters, the view bind list, and the pivot target. Parsed
  host-side, where there is no sandbox to manipulate it.
- **Supervision half → `kennel-bin-init`** (the `GET_SANDBOX_PLAN` reply): the facade list
  (paths+args), the workload argv/env, the operator uid/gid to drop to, the Landlock ruleset,
  the seccomp filter, the ulimits, and an `interactive` flag (the pty return socket itself
  rides the construction channel, inherited at `PTY_RETURN_FD`). Parsed **post-pivot**, so even
  a decoder bug is contained to the sealed view.

Landlock and seccomp stay in `kennel-bin-init` (applied to the **workload child** it forks) — not
in the privhelper or before `fexecve` — because applying them earlier would also confine
`kennel-bin-init` and the facades, which must remain free to fork, `waitpid`, and reach the bus.

## 7.2.4 The `ILifecycle` verbs

Node-0 verb codes (distinct high range), `kennel-bin-init` ⇄ kenneld:

| Verb | Dir | Payload | Reply |
|---|---|---|---|
| `GET_SANDBOX_PLAN` | init → kenneld | none (identity is the instance) | the supervision-half Plan (flat serialized buffer) + optional pty file descriptor |
| `NOTIFY_BOOT_SYNC` | init → kenneld | facade name → in-namespace pid map | status |
| `NOTIFY_FACADE_CRASH` | init → kenneld | facade id + exit status + telemetry | status |
| `NOTIFY_WORKLOAD_EXEC` | init → kenneld | none | status |

`GET_SANDBOX_PLAN` is request/reply; the `NOTIFY_*` are fire-and-forget. All are audited as
binder **lifecycle** events (not `binder.cross`, which is cross-*kennel* relay). Payloads are
bounded and parsed with the same fixed-discipline codec as the rest of the binder surface.

## 7.2.5 Security invariants

- **Trapped from birth.** `kennel-bin-init` is `execve`'d after `pivot_root`; the host root is not
  in its mount namespace, so host DAC on host files is impossible despite kuid 0.
- **No ambient host caps.** All `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` work is done by the privhelper
  pre-`execve`; `kennel-bin-init` holds only userns-scoped `CAP_SETUID`/`CAP_SETGID` for the drop.
- **Only `kennel-bin-init` is uid 0.** Facades and the workload drop to the operator before
  `execve` (`set_gid` → groups → `set_uid`), then `no_new_privs` + seccomp make it
  irreversible; nothing regains uid 0.
- **The init binary is trusted by provenance.** Its path comes from the root-owned deployment
  configuration; the privhelper verifies it is root-owned and not group/other-writable, opens
  it pre-clone, and `fexecve`s it. The operator cannot substitute a uid-0 init.
- **Lifecycle/config authority is the pid gate.** kenneld serves `GET_SANDBOX_PLAN` and acts on
  a `NOTIFY_*` only from `sender_pid == init_host_pid && sender_euid == 0`; anything else is a
  logged `Deny`.
- **Root parses operator data only in safe places.** The construction half is parsed host-side
  (no sandbox yet); the supervision half is parsed by `kennel-bin-init` post-pivot (contained).
  Both decoders are bounded.
- **Fail-closed.** Any factory step or any pre-`execve` confinement step that fails aborts
  before the workload runs; the kennel never runs partially confined.

## 7.2.6 Non-goals

No policy evaluation, no network or mount syscalls, no trust-store handling, no service
registry (that is node 0 / kenneld), no config parsing beyond the flat supervision-half blob.
`kennel-bin-init` is a small, auditable supervisor — the same binary for every kennel.
