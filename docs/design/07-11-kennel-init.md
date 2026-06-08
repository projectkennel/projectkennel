# §7.11 `kennel-init` — the kennel's PID 1

## 7.11.1 Role

`kennel-init` is the trusted, root-owned process the privhelper `execve`s as **PID 1**
of a kennel's namespaces. It is the kennel's *only* uid-0 process and its construction
and supervision authority. Everything else in the kennel — the protocol facades and the
workload — is a child of `kennel-init` running as the non-root operator identity.

It exists because the kennel has a real uid 0 (host root mapped `0 0 1`, no subuid), and
that uid-0 authority must be held by trusted code that the operator cannot substitute or
reach (see `kennel-init-and-uid0`). The privhelper creates the user namespace, writes the
maps, and `execve`s the deployment's root-owned `kennel-init`; no operator-controlled code
ever runs as userns-0.

`kennel-init` does **no policy decisions**. It realises a `Plan` that kenneld already
compiled and the privhelper already authorised. It is deliberately minimal: construct the
view, hand the binder bus to the workload, supervise, report.

## 7.11.2 The binder bus is the control plane

`kennel-init` is a **binder client on the same per-kennel binderfs instance** it mounts,
transacting to **node 0 (kenneld)** for every lifecycle event. This replaces ad-hoc
control channels (anonymous pipes, `stderr` scraping, an early UNIX socket) with the one
IPC mechanism the kennel already runs.

The decisive property is **kernel-stamped, unforgeable caller identity**. The binder
driver injects the sender's pid and euid into every transaction (`binder_transaction_data`
`sender_pid`/`sender_euid`); a process cannot lie about them. kenneld validates each
lifecycle transaction against the init it is expecting and drops anything else.

### Correcting the identity check

The naive gate `sender_pid == 1` is **wrong** for this topology, and shipping it would
reject every legitimate lifecycle event. kenneld is the context manager **from the host
(init) PID namespace** — it acquires node 0 via `/proc/<pid>/root`. The binder driver
reports `sender_pid` relative to the *target's* PID namespace
(`task_tgid_nr_ns(sender, target_pidns)`), so kenneld sees `kennel-init`'s **host PID**,
not `1`. The kennel-internal PID-1-ness is invisible to a host-side receiver.

The correct gate uses facts kenneld already holds. The privhelper, having forked the
userns/PID-1 chain, reports `kennel-init`'s **host pid** to kenneld over the construction
socketpair (the bootstrap channel, §7.11.4). kenneld then enforces, on every lifecycle
transaction:

```rust
// init_host_pid: learned from the privhelper at construction (not from the wire).
if tr.sender_pid != init_host_pid || tr.sender_euid != 0 {
    audit("binder.lifecycle-forged", Outcome::Deny, tr.sender_pid);
    return Br::FAILED_REPLY;
}
```

`sender_euid == 0` is defense-in-depth: `kennel-init` is the only uid-0 process (host
kuid 0 via the `0 0 1` map → kenneld, in the host userns, sees euid `0`); the facades and
workload run as the operator's non-zero uid and so can never present euid 0. The pid match
is the primary, exact gate.

### Lifecycle verbs ride node 0

Lifecycle is **reserved verb codes on node 0**, not a separate node — consistent with the
`AF_UNIX` facade (`CONNECT_AFUNIX`, §7.9.5) and avoiding node-handle distribution. The
workload can address node 0 too, but the sender-identity gate makes the lifecycle verbs
inert for anyone but `kennel-init`; a workload attempt is a logged `Deny`, never an action.
(A distinct `org.projectkennel.ILifecycle/default` node is the alternative — cleaner
separation at the cost of vending its handle only to init and refusing it to the workload;
the sender-identity gate already provides the security boundary, so the reserved-verb form
is preferred.)

## 7.11.3 File-descriptor and uid mechanics (open-then-chown)

`kennel-init` is a binder *consumer* and the binderfs *owner*, which it reconciles by
acquiring its own client descriptor **before** it relinquishes path ownership:

1. **Open while uid 0.** In the privileged phase, still mapped to host root, `kennel-init`
   mounts binderfs, allocates the `binder` device, and `open(2)`s `/dev/binderfs/binder`,
   keeping the fd in its execution context. `binder-control` stays root-owned (only uid 0
   allocates devices — the Android model).
2. **Chown the path, keep the fd.** Only then does it `chown` `/dev/binderfs/binder` to the
   operator (workload) uid, so the facades and the workload can later `open` their own
   independent client descriptors. `kennel-init`'s already-open fd is unaffected by the
   ownership change.

A single binderfs instance, one `binder` device, many openers (each `open` is a distinct
`binder_proc`): `kennel-init`'s privileged early client, plus the workload's and each
facade's after the chown.

## 7.11.4 Lifecycle phases

`kennel-init` runs a fixed sequence. The privhelper→init **construction socketpair** is the
bootstrap channel (it carries the serialised `Plan` in and the init/workload host pids
back to kenneld); the **binder bus** carries the in-life events once node 0 is reachable.

- **P0 — Entry.** `execve`d as PID 1, userns uid 0, with the `Plan` blob on a fixed
  inherited fd and the privhelper control socket on another. Decode (`kennel-spawn::wire`)
  and re-validate the `Plan` (it is operator-authored; the privhelper validated what it
  acts on, init re-validates the whole — §7.11.6).
- **P1 — Privileged construction (uid 0).** Join the cgroup; `make_root_private`; build the
  view + `pivot_root` (root dir, `/dev`, RO library binds, synthetic `/etc`, fresh `/proc`,
  private `/tmp`) — all owned by **uid 0**, the headline outcome. Mount binderfs, allocate
  the device, **open it (§7.11.3)**, chown it to the operator.
- **P2 — Boot sync.** Using its early fd, transact `NOTIFY_BOOT_SYNC` to node 0, **retrying**
  until kenneld has acquired node 0 (kenneld polls `/proc/<init>/root/dev/binderfs/binder`
  on the pid the privhelper gave it; the retry closes the race with no extra channel).
- **P3 — Launch facades.** Fork each infrastructure facade (the `AF_UNIX` proxy today;
  `netshim`, dbus/gpg facades as they land), **each dropping to the operator identity**
  before `execve` — only `kennel-init` stays uid 0. Report the facades' internal pids in the
  `NOTIFY_BOOT_SYNC` payload so kenneld attributes host telemetry to true in-namespace pids.
- **P4 — Launch the workload.** Transact `NOTIFY_WORKLOAD_EXEC`, then fork the workload
  child: drop gid → supplementary groups → uid to the operator (`set_gid`/`set_uid`), then
  `no_new_privs`, seccomp, Landlock, ulimits, the interactive pty, and `execve`. After the
  drop + `no_new_privs` + seccomp the workload can never regain uid 0.
- **P5 — Supervise.** A `waitpid` reaper loop. A facade exit dispatches `NOTIFY_FACADE_CRASH`
  (kenneld emits a `service.crash` audit event off the workload's hot path). The workload's
  exit ends the kennel: `kennel-init` `_exit`s with the workload's status, which propagates
  through the privhelper chain to kenneld (the **reliable exit-status path is the process
  chain, not binder** — binder may already be torn down).

## 7.11.5 The `ILifecycle` verbs

Node-0 verb codes, init→kenneld, reply is a status byte unless noted:

| Verb | Payload | Meaning |
|---|---|---|
| `NOTIFY_BOOT_SYNC` | facade name→in-namespace pid map | construction complete; the kennel reached its target state (closes the loop with no host-side polling) |
| `NOTIFY_FACADE_CRASH` | facade id (enum) + exit status + telemetry | a supervised facade died; kenneld logs `service.crash` |
| `NOTIFY_WORKLOAD_EXEC` | none | crossing the pre-`execve` boundary into unprivileged execution |

Payloads are bounded and parsed with the same fixed-discipline codec as the rest of the
binder surface (`02-7` threat model; untrusted-shaped even though the sender is trusted).

## 7.11.6 Security invariants

- **Only `kennel-init` is uid 0.** Facades and the workload drop to the operator before
  `execve`; no path lets them regain it (`no_new_privs` + seccomp).
- **The init binary is trusted by provenance, never by the wire.** Its path comes from the
  root-owned deployment config (`Deployment::kennel_init()`); the privhelper verifies it is
  root-owned and not group/other-writable before `execve`. The operator cannot substitute a
  uid-0 init.
- **Lifecycle authority is the pid gate.** kenneld acts on a lifecycle verb only from
  `sender_pid == init_host_pid && sender_euid == 0`; everything else is a logged `Deny`.
- **`Plan` is operator data parsed by root** (init decodes it as uid 0): every length
  bounded, every path validated absolute/`..`-free, fail-closed; a fuzz target covers the
  decoder (§10.6).
- **Fail-closed construction.** Any P0–P4 step that fails aborts before the workload
  `execve`; the kennel never runs partially confined.

## 7.11.7 Non-goals

No policy evaluation, no network, no trust-store handling beyond what construction needs,
no service registry (that is node 0 / kenneld). `kennel-init` is scaffolding and a
supervisor — small, auditable, and the same binary for every kennel.
