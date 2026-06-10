# API surfaces — Binder IPC and the kenneld context manager

This chapter is the implementation contract for the binder-based IPC mechanism
designed in [`07-1-binder.md`](../design/07-1-binder.md) (§7.1). Where the design chapter
says *what and why*, this one commits to the concrete shape: which crate owns the
kernel ABI, how the binderfs instance slots into the spawn pipeline, kenneld's role
and threading as context manager, the transaction wire conventions, the
cross-instance relay, and the new control-socket operation for kennel spawning.

> **Status: gateway core BUILT; cross-instance relay + network still roadmap.** The
> inter-namespace gateway (§7.1) is built and proven end to end by the unprivileged
> vertical (`src/tools/unprivileged-e2e.sh`): the privhelper factory mounts the per-kennel
> binderfs instance and allocates the device; kenneld acquires node 0 via `/proc/<init>/root`
> and serves the registry; `kennel-bin-init` pulls its `GET_SANDBOX_PLAN` over the bus; and the
> `org.projectkennel.IAfUnix/default` facade brokers an AF_UNIX connect, returning the
> connected fd. What remains **roadmap** is the cross-instance/inter-kennel relay
> (§Inter-kennel IPC), the `org.projectkennel.INet` network crossing (→
> [`02-5-binder-net.md`](02-5-binder-net.md)), and the deferred facades (`IDBus`). Sections
> below mark "built" vs "designed, not yet built" inline; the as-built construction actor and
> node-0 acquisition are reconciled here, the relay/network sections remain forward contracts.

## Stability commitment

**Internal-stable** per [`02-0-overview.md`](02-0-overview.md). The binder transaction
conventions (service-name codes, payload layouts, the `org.projectkennel.*` namespace) and
the `kennel-lib-binder` ABI are internal: the workload never writes code against them as a
stable contract — it links a libbinder-shaped client, and the *services* it reaches are
the policy surface, not the byte layout. kenneld, the service processes, and the
`kennel-lib-binder` crate are built from one source within a release, so skew is impossible
inside a release. This chapter documents the surface for review and audit; it is not a
contract to consumers.

The relationship to [`02-6-ipc.md`](02-6-ipc.md) (the CLI/privhelper/daemon wire
formats) is deliberately left untouched for now. The one place the two overlap — the
new `spawn-kennel` control-socket request (§Kennel spawning below) — is documented here
and will be folded into the `02-6` control-protocol table when the surfaces are remapped.

---

## Why binder, in one paragraph

The AF_UNIX shim (§7.6, [`02-6`](02-6-ipc.md) for its IPC, built) gates at *connect
time*: a granted socket is bind-mounted into the constructed view and audited when the
workload connects. That cannot express authority that lives *inside* the protocol — a
gpg-agent socket signs anything, a Wayland socket reads the clipboard. The double-blind
SSH bastion (§7.10, built) was the first subsystem to reject the connection-level grant
outright and move enforcement to the *operation*: the credential stays host-side and is
unaimable by the workload. Binder generalises that move. kenneld becomes the policy
decision point for every protocol *call*, the workload holds only unforgeable binder
node references (no path to enumerate, no abstract name to probe), and the same primitive
carries inter-kennel IPC for the MCP topology. Rationale in full: design §7.1.1–7.1.2.

---

## The `kennel-lib-binder` crate

The binder ioctl ABI is hand-rolled in a **new, thirteenth workspace crate**,
`kennel-lib-binder`, parallel in every structural respect to `kennel-lib-bpf`
([`03-crate-decomposition.md`](03-crate-decomposition.md)):

- **`#![allow(unsafe_code)]`**, the third crate to carry it (after `kennel-lib-syscall` and
  `kennel-lib-bpf`). `unsafe` is confined to a single `sys.rs` holding the `ioctl(2)` FFI
  (`BINDER_WRITE_READ`, `BINDER_SET_CONTEXT_MGR`, `BINDER_SET_MAX_THREADS`,
  `BINDER_VERSION`, the binderfs control `BINDER_CTL_ADD`), the same discipline as
  `kennel-lib-bpf`'s `sys.rs`. Listed in `UNSAFE-CRATES.md`. Adding it is a new
  unsafe-bearing crate and triggers all-maintainer review per CODING-STANDARDS §4.
- **No libbinder, no libbinder-ndk.** Both carry Android-specific dependencies. We bind
  the stable UAPI directly (`include/uapi/linux/android/binder.h`,
  `.../binderfs.h`), the same way `bpf/` compiles against `<linux/bpf.h>` with no CO-RE.
  If the build ends up vendoring the binder UAPI headers, they live alongside the crate
  under the same pinning discipline as `bpf/` headers (`BUILD-ENV.md`), which is the
  second reason this is its own crate rather than a `kennel-lib-syscall` addition:
  `kennel-lib-syscall` has a 1500-line reviewable-in-one-sitting ceiling
  ([`03-crate-decomposition.md`](03-crate-decomposition.md)) and no kernel-header surface.
- **Near-leaf in the dependency graph.** Like `kennel-lib-bpf`, it depends on no other
  Project Kennel crate except (optionally) `kennel-lib-syscall` for shared raw-fd helpers.
  It links `libc`/`nix` for the syscalls; ELF/`object` is not needed (binder is an ioctl
  ABI, not an object format).

**What `kennel-lib-binder` owns** (mechanism, no policy): the `binder_write_read` command
loop, encode/decode of the `BC_*`/`BR_*` command stream and `binder_transaction_data`,
the context-manager looper primitive (looper registration, transaction receive, reply
dispatch), binderfs device allocation, and death-notification plumbing. The `BC_*`/`BR_*`
decoder consumes bytes the workload controls — it is an untrusted-input parser and
carries a fuzz target under `fuzz/` per CODING-STANDARDS §10.6.

**What `kenneld` owns** (policy/state, `#![forbid(unsafe_code)]`): which `addService`
and `getService` transactions are permitted, the per-kennel and cross-instance service
registries, the `org.projectkennel.*` services, and the relay. This mirrors the
`kennel-lib-bpf`↔`kenneld` split — the loader crate provides `create_maps`/`load_program`/the
ringbuf reader; kenneld decides what to load and drives the drain. Here `kennel-lib-binder`
provides the context-manager primitive; kenneld decides what to register and resolve and
drives the looper. The binder logic in kenneld lives in a new `kenneld::binder` module.

---

## binderfs instance lifecycle

### Mount sequencing within the spawn pipeline

> **BUILT — as-built via the privhelper factory ([`../design/07-2-kennel-bin-init.md`](../design/07-2-kennel-bin-init.md)).**
> binderfs assigns its control/device nodes to **uid 0 of the mounting user namespace**.
> The old pure-identity map (`{uid} {uid} 1`) had no uid 0, so the nodes landed on the
> overflow uid (`nobody`, mode `0600`) and nothing in the kennel could open them — proven
> by the full-vertical e2e (`add_binder_device` EACCES). The kennel now has a real uid 0,
> mapped by the precise two-line map `0 0 1` + `<operator> <operator> 1` (no subuid; written
> in one `write(2)` with `CAP_SETFCAP`). The **privhelper factory**, in its post-`clone`
> child, escalates to the kennel's uid 0, mounts binderfs, allocates the device, **chowns
> `/dev/binderfs/binder` to the operator** (mode 0600, so operator clients can open it),
> `pivot_root`s, drops to the operator, and `fexecve`s the trusted root-owned **`kennel-bin-init`
> (PID 1)** — so the uid-0 mount work never runs while the host fs is visible (`binder-control`
> stays root-only). Crucially the **user namespace is owned by the operator** (the child clones
> as the operator, then self-escalates), which is what lets the operator `kenneld` reach the
> instance via `/proc/<init>/root` (step 3). `kennel-bin-init` then `open`s its own lifecycle
> client on the device and **pulls** its config from node 0 (`GET_SANDBOX_PLAN`).
>
> `kennel-bin-init` is `fexecve`'d **as the kennel's uid 0** (the construction child does not drop
> before the hand-off): PID 1 stays a different uid from the operator-uid workload/facades, so
> they cannot signal or `ptrace` it. The operator `kenneld` still opens the device via
> `/proc/<init>/root` because the kennel userns is operator-owned (it holds `CAP_SYS_PTRACE`
> there); `kennel-bin-init` itself drops the workload and facades to the operator.

Each kennel gets its own binderfs instance — a fully independent mount, like devpts and
tmpfs, sharing no nodes with any other kennel's instance. **binderfs carries
`FS_USERNS_MOUNT`, so it mounts inside the kennel's child user namespace**, exactly where
the spawn already mounts tmpfs, devpts, and proc. No host-side mount and no privileged
step is involved; the mount happens in the same full-caps-within-the-child-userns context
the bubblewrap-style spawn already establishes.

The sequence relies on four binder properties: binderfs is `FS_USERNS_MOUNT` (mounts
inside the child userns); `BINDER_CTL_ADD` allocates the device; `BINDER_SET_CONTEXT_MGR`
is one-per-instance (a second call returns `EBUSY`); and a process in the initial userns
can become context manager of a child-userns instance opened via `/proc/<pid>/root`.
Binder protocol version is 8.

The step slots into the existing spawn sequence (`kennel-lib-spawn`, design §8.7):

1. During spawn setup, *inside* the kennel's new mount + user namespace, the spawn code
   creates the view's `/dev/binderfs/` and mounts a fresh binderfs there:
   `mount("binder", "/dev/binderfs", "binder", 0, "max=256")`. `max=256` caps
   binder-device allocation per kennel; the kernel default is unbounded, so the cap is a
   DoS bound, not a tuning knob. Mounting at the view path directly avoids a separate
   bind-mount-into-the-view step.
2. The spawn code opens `binder-control` and allocates the **standard binder device** via
   `BINDER_CTL_ADD` (name `binder`), which appears at `/dev/binderfs/binder`. The spawn
   also creates the conventional `/dev/binder` symlink to `binderfs/binder`, so a stock
   binder client finds the driver at libbinder's default path with no per-workload
   configuration (§Device naming below).
3. kenneld (the daemon, in the initial userns) acquires a fd on `/dev/binderfs/binder`
   for the new instance by opening `/proc/<init-host-pid>/root/dev/binderfs/binder`
   (the init host pid comes from the privhelper over the construction socketpair). **This is
   the as-built choice, and `SCM_RIGHTS` fd-passing was rejected:** a binder fd is bound to the
   process that opened it (its `binder_proc`), so a passed fd cannot be `mmap`'d or made
   context manager by a different process (`EINVAL`) — kenneld *must* open the device itself.
   The open succeeds because the kennel userns is operator-owned, so the operator `kenneld` is
   privileged over the instance; it retries until the factory's `pivot_root` has populated the
   path.
4. kenneld calls `BINDER_SET_CONTEXT_MGR` on that fd, taking ownership of node 0 for this
   instance, and starts the instance's looper thread (§Context manager). This runs in the
   daemon so one entity holds every instance's context-manager fd — the precondition for
   cross-instance routing.
5. The Landlock ruleset (built post-`pivot_root`, in the child — `08-as-built-notes.md`
   §8.2) grants the workload read/write on `/dev/binderfs/binder` (reached via the
   `/dev/binder` symlink) and read on `/dev/binderfs/features/`. **`binder-control` is
   never granted to the workload** — only the spawn setup allocates devices, before the seal.
6. The remaining spawn sequence (`pivot_root`, seal, execve) proceeds unchanged.

On kennel exit, the instance's mount disappears with the child's mount namespace (no
explicit host-side unmount needed); pending transactions receive death notifications and
all nodes are destroyed. This rides the immediate, no-grace teardown kenneld already
performs (`01-process-model.md`).

### Device naming follows binderfs/Android convention

The per-kennel device is the standard binderfs device named `binder`, mounted at
`/dev/binderfs/` with `/dev/binder` symlinked to `/dev/binderfs/binder` — exactly the
layout Android's init establishes, and the path libbinder (and any libbinder-shaped
client) opens by default. We deliberately do **not** invent a Kennel-specific device name:
each kennel already has its own isolated binderfs instance (no cross-kennel collision to
disambiguate), so a non-standard name would buy nothing and would force every binder
client in the workload to be specially pointed at it — defeating the same "the application
finds its driver at the default path" principle the §7.6 socket shim rests on. Kennel does
not use the Android `hwbinder`/`vndbinder` contexts (HAL/vendor splits with no analogue
here); the single `binder` context per instance is all a kennel needs.

This is purely about the **device** name. The `org.projectkennel.*` strings (§Context manager) are
binder *service-registry* names, not devices — and reverse-DNS service naming is itself the
Android convention (cf. `android.os.*`, `vendor.*`), so those are kept as-is.

### Privilege: no binder-specific op, but construction is now privhelper-driven

> **Updated by the uid-0 construction model ([`../design/07-2-kennel-bin-init.md`](../design/07-2-kennel-bin-init.md)).**
> The original claim here — that the entire mount → allocate → become-context-manager chain
> runs *without real privilege* — no longer holds. It rested on the spawn running uid-mapped
> 1:1 as the operator, but binderfs nodes are owned by the mounting userns's uid 0, which a
> pure-identity map does not provide. The kennel now maps host root `0 0 1`, which requires
> `CAP_SETUID` and so is written by the **privhelper**, which also `execve`s the root-owned
> `kennel-bin-init`. The privhelper is therefore now the kennel *constructor*, not a minimal
> add-addr/egress/gid-map helper (supersedes that framing in `01-process-model.md`).

There is still **no binder-*specific* privhelper op**: binderfs is `FS_USERNS_MOUNT`, so the
mount itself is namespace-local, done by the privhelper factory in its post-`clone` child
(which holds full caps in the new userns), along with the device allocation and the chown to
the operator — all before `pivot_root` and the `fexecve` of `kennel-bin-init`. What changed is the
*construction* privilege (the `0 0 1` map needs `CAP_SETUID`; the factory does the mounts and
the pivot) — see [`01-process-model.md`](01-process-model.md) — not a per-binder privileged surface.

---

## kenneld as context manager

### Threading model

kenneld is blocking, thread-per-connection, no async runtime
([`03-crate-decomposition.md`](03-crate-decomposition.md)).

Each kennel's node 0 is served by a **looper thread pool** (`kenneld::binder` over
`kennel-lib-binder::ctxmgr`). Binder replies are thread-bound — `BC_REPLY` completes the transaction
on the receiving thread's transaction stack, so a reply cannot be handed to a different thread —
which rules out a "looper dispatches to a worker, a reply-reader replies by cookie" split. The
pool is instead the AOSP looper model: every looper **receives, handles, and replies to its own
transactions on its own thread**, and there are enough loopers that one blocked on a facade dial
does not stall the rest.

Per kennel instance:

- **The looper pool.** It starts as one thread (`BC_ENTER_LOOPER`) and grows toward a bounded
  ceiling (`set_max_threads`, `POOL_MAX_THREADS`) as the driver requests more via `BR_SPAWN_LOOPER`
  (each new thread `BC_REGISTER_LOOPER`s). Each looper polls the context-manager fd (non-blocking,
  so a thundering-herd wake never blocks a loser of the race and shutdown stays prompt) and
  classifies each `BR_TRANSACTION`:
  - **Registry verbs** (`addService`/`getService`/`listServices`/`isDeclared`/
    `getDeclaredInstances`) and the reserved-namespace checks are O(1) in-memory operations against
    the settled policy and the per-kennel registry. The registry is behind a `Mutex` the looper
    takes only for these verbs — never across a blocking call — and replies on the same thread.
  - **Facade verbs** (`IAfUnix` `CONNECT`, and `INet` `CONNECT`/`BIND` once built) perform host
    I/O — a `connect()`, and for `INet` a DNS resolve + dial via the `host-netproxy` delegate
    over the per-kennel `socketpair`. The handling looper does that I/O inline and replies (with
    the connected fd as a `BINDER_TYPE_FD`) on its own thread; while it is blocked, the other
    loopers keep serving the registry and lifecycle/TTL verbs.
  - **Lifecycle/config verbs** (`GET_SANDBOX_PLAN`, the `NOTIFY_*`) are served as in §Threading
    above, gated on the kernel-stamped init pid.
- **(existing) the BPF-drain thread** (`kenneld::bpf_audit`).

**Bounding.** The pool size is the per-kennel head-of-line bound: a facade dial occupies one
looper, so `POOL_MAX_THREADS` is sized so the control plane always finds a free thread; when every
looper is busy, the driver queues further transactions until one frees. A facade dial carries a
connect deadline, so a wedged or unresponsive target reclaims its looper (degrading to a refusal
on that one transaction) rather than tying it up. A slow or hostile target therefore degrades to
delay then refusal on that one kennel, never a stall of other kennels (the relay-TCB concern
below). External delegates (`host-netproxy`; the host-side `BIND` leg — see
[`02-5-binder-net.md`](02-5-binder-net.md)) run their own blocking I/O in their own processes and
are not binder participants.

> **Roadmap — per-kennel caps.** A `[resources]` policy section bounds how many loopers and
> connections a single kennel may tie up (`POOL_MAX_THREADS` is a fixed default until then), and
> the kennel cgroup's `pids.max`/`memory.max` cap the aggregate.

### Node 0: the service registry protocol

Node 0 is the Android servicemanager analogue: clients reach the registry through the
well-known node (handle 0), never by name. Its verbs mirror Android's `IServiceManager`
semantics (the transaction codes are kenneld's own — we are not wire-compatible with
Android — but the verb set and names are deliberately the same so the model is familiar):

| Code | Verb | Direction | Payload | Reply |
|---|---|---|---|---|
| 1 | `addService` | service process → kenneld | service name (length-prefixed UTF-8, bounded) | status |
| 2 | `getService` | workload/service → kenneld | service name | a binder node reference, or `BR_FAILED_REPLY` |
| 3 | `listServices` | workload/service → kenneld | — | the names this caller is granted to look up |
| 4 | `isDeclared` | workload/service → kenneld | service name | bool: does policy declare this service for this caller |
| 5 | `getDeclaredInstances` | workload/service → kenneld | interface name | the granted instances of an interface |

Two further verb groups ride node 0. The **`kennel-bin-init` lifecycle** verbs are gated by the
unforgeable binder caller identity (`sender_pid == init_host_pid`, `sender_euid == 0`) so a
workload can address node 0 but cannot exercise them. The **`AF_UNIX` facade** verb
(`CONNECT_AFUNIX`, §7.1.5) is gated by the `[[unix.allow]]` policy name match; any in-kennel
caller may pull a granted facade fd. (Roadmap: a `sender_pid` gate restricting facade verbs to
the shim, the same shape as the lifecycle gate.) The two verb groups: the **`AF_UNIX` facade**
verb (`CONNECT_AFUNIX`, §7.1.5) and the **`kennel-bin-init` lifecycle** verbs
(`NOTIFY_BOOT_SYNC`/`NOTIFY_FACADE_CRASH`/`NOTIFY_WORKLOAD_EXEC`/`NOTIFY_FACADE_RESTART`, and
the blocking `NOTIFY_TTL_EXPIRED` by which the in-kennel TTL custodian asks kenneld to freeze
+ decide — §9.7; [`../design/07-2-kennel-bin-init.md`](../design/07-2-kennel-bin-init.md)). The lifecycle verbs
make `kennel-bin-init` (PID 1) a binder *consumer* on the same instance kenneld manages as
node 0, so the kennel's control plane is the binder bus itself. kenneld accepts a lifecycle
verb only when `sender_pid` equals the init's **host** pid (learned from the privhelper at
construction — a host-side context manager sees host pids, *not* the kennel-internal `1`)
and `sender_euid == 0`; any other sender is a logged `Deny`. (This means binder is no
longer confined to kenneld + `facade-netshim` — `kennel-bin-init` is a third participant.)
All other transactions on node 0 are rejected with `BR_FAILED_REPLY`. The
`listServices`/`isDeclared`/`getDeclaredInstances` verbs are the binder-surface
introspection a workload may run on itself; there is no separate policy-introspection
service node — node 0 answers it, exactly as Android's servicemanager does.

The service name is bounded (cap documented at the decode site, ≤ 255 bytes; binderfs's
own service-name charset is alphanumerics plus `_ - . /`), validated UTF-8, and
`..`/control-character-free per CODING-STANDARDS §10. kenneld validates the name against
the kennel's settled policy before recording or resolving it, and emits an audit event for
every verb (service name, outcome, requesting pid; §Audit below).

**The policy-declares-the-service check is the VINTF-declared analogue.** Android's
servicemanager refuses to register, and `isDeclared()` reports, a service that is not
declared in a VINTF manifest; Kennel's settled policy (`[[binder.provide]]` and the
reserved-section enablement below) is that manifest. A service the policy does not declare
cannot be registered and reports `isDeclared = false`.

Binder's general capability-passing (transferring arbitrary node references between
processes) is **not used**. References are issued only by kenneld as context manager and
are not transferable between kennels. This drops the reference-graph complexity that makes
Android's Binder subtle while keeping the four properties that matter: unforgeable
references, synchronous transactions, death notifications, per-instance isolation
(design §7.1.2).

### The `org.projectkennel.*` reserved namespace

kenneld is both context manager *and* the service provider for a built-in set occupying
the reserved prefix `org.projectkennel.*`. Two rules are checked **before any policy lookup**:

1. `addService` for an `org.projectkennel.*` name from any caller other than kenneld is rejected
   with `BR_FAILED_REPLY` and audited. There is no policy override.
2. `getService` for an `org.projectkennel.*` name always resolves to kenneld's own node on the
   *local* instance — never routed to the cross-instance registry (§Inter-kennel below),
   regardless of what any peer kennel declares.

An `org.projectkennel.*` node is present only if the corresponding policy section is non-empty;
absence of the node is proof the capability was not granted. The reserved set:

| Service | In scope for this chapter | Notes |
|---|---|---|
| `org.projectkennel.IAfUnix/default` | **Yes** | Brokered AF_UNIX connect; kenneld connects host-side and returns the fd. |
| `org.projectkennel.IDBus/default` | Deferred | D-Bus facade service process; own chapter. |
| `org.projectkennel.IGpgAgent/default` | Deferred | gpg-agent facade; key grip + purpose; closes T1.6. |
| `org.projectkennel.IWayland/default` | Deferred | Wayland facade; clipboard/screencopy gate; closes T2.6. |

Two things that were sketched as reserved services are **not** binder services: kennel
spawning is a control-socket operation (§Kennel spawning), not a node; and policy/service
introspection is answered by node 0's `listServices`/`isDeclared`/`getDeclaredInstances`
verbs, not a dedicated node.

**Naming convention.** Reserved services use the Android `INTERFACE/INSTANCE` grammar:
`INTERFACE` is a reverse-DNS interface name under a domain the project owns
(`org.projectkennel.*`, mirroring how `android.*` and `vendor.*` are owned in AOSP), and
`INSTANCE` is `default` until a service legitimately needs multiple instances. The
`org.projectkennel.*` prefix is reserved exactly as `android.*` is — only kenneld registers
under it. User-defined services (§Policy surface) take their own names and may not begin
with `org.projectkennel.`.

The three protocol-facade services (`dbus`, `gpg`, `wayland`) are kenneld-owned nodes
backed by spawned service processes that parse foreign, untrusted wire protocols and
translate to binder. Each is a new binary crate, each an untrusted-input parser requiring
its own fuzz target, and the D-Bus one displaces an external dependency
(`xdg-dbus-proxy`) with first-party code. They are **out of scope for this chapter** and
get their own architecture chapter(s); §7.1.5 is the design.

---

## The af-unix facade transaction

`org.projectkennel.IAfUnix/default` is the structurally significant in-scope facade. It replaces the
raw shim's "path in the view" with a brokered connect:

1. The workload sends a transaction to the `org.projectkennel.IAfUnix/default` node, code `CONNECT` (1),
   payload = the requested socket path as a length-prefixed flat string (bounded, no
   embedded NUL, validated UTF-8 or `OsStr` bytes per CODING-STANDARDS §10).
2. kenneld validates the path against the kennel's `[[unix.allow]]` list (the same settled
   `UnixRuntime` the shim consumes today — [`02-2-config-schema.md`](02-2-config-schema.md)).
3. On allow, kenneld performs the actual `connect()` **host-side** and returns the
   connected fd in the reply via `BINDER_TYPE_FD`. On deny, `BR_FAILED_REPLY` (and audit).

The workload receives an already-connected socket fd; it never holds a path into the host
AF_UNIX namespace, and the path **does not appear in the constructed view at all** — which
closes the residual where a workload could enumerate granted (or even un-granted) socket
paths from its view. Every connection attempt is audited at call granularity rather than
inferred from a connect on a bind-mounted node.

**Relationship to the built shim.** The `[unix]` AF_UNIX shim is built and proven
(`08-as-built-notes.md`). The af-unix facade is a *behaviour change* to a shipped
subsystem (broker-and-fd-pass vs bind-mount), not an additive one. Migration — whether
the facade supersedes the shim, coexists behind a policy/kernel-capability gate, or the
shim becomes the sub-ABI-6 fallback — is an open decision recorded in §Open questions; it
is not settled by this chapter.

---

## Intra-instance vs cross-instance object types

`BINDER_TYPE_FD` (fd passing) and `BINDER_TYPE_PTR` (shared-memory buffers) are permitted
**only within a single instance** — between the workload and a local service process, or
between the workload and a kenneld-owned node like `org.projectkennel.IAfUnix/default`. Both parties are
inside the same trust boundary, so fd-passing the connected af-unix socket is sound.

Across instances they are **rejected**. kenneld inspects the transaction object-type field
before relaying and returns `BR_FAILED_REPLY` for any fd or pointer object on a
cross-instance path. Only flat scalar / `BINDER_TYPE_ARRAY` payloads cross the boundary.
Extending shared memory cross-instance would be a separate design decision (design §7.1.10).

---

## Inter-kennel IPC

### Cross-instance registry and bilateral policy

Inter-kennel IPC uses the same mechanism: kenneld maintains a cross-instance registry
mapping service names to instances. When a `getService` for a name is not registered
locally, kenneld consults the cross-instance registry and, if a peer provides it and
policy on *both* sides permits, returns a node reference that tunnels through kenneld to
the peer instance. The workload cannot determine whether the node is local or remote — the
transport is opaque; the policy enforcement is in kenneld.

A cross-instance lookup succeeds only if **both** hold (design §7.1.6,
[`02-2-config-schema.md`](02-2-config-schema.md) for the schema):

1. The consuming kennel declares `[[binder.consume]]` naming the service and the providing
   kennel.
2. The providing kennel declares `[[binder.provide]]` naming the service and the consuming
   kennel in `accept_from`.

A unilateral declaration denies. kenneld validates both sides **at lookup time, not spawn
time** — the peer need not be running when the consumer starts; kenneld blocks the lookup
until the service registers or the consumer exits. Peer-kennel names appear only in policy
files, never in the binder protocol the workload sees (the workload sees a service name and
an opaque reference), so the naming is an authoring concern, not a runtime leak.

### The relay state machine — and the TCB decision it forces

This is the chapter's central architectural decision and the one reviewers will press
hardest, because it grows kenneld's role from control-plane supervisor to **synchronous
data-path relay**. For the MCP topology (§7.1.9), *every tool call's payload passes through
kenneld.* That is a real TCB and hot-path change away from the "small supervisor + tiny
privhelper" shape the rest of the system holds to, and it is called out here rather than
buried so the trade is explicit.

The relay, when kenneld routes a transaction cross-instance:

1. kenneld receives `BR_TRANSACTION` on the tunnel node (consuming instance's looper),
   carrying the transaction data and the binder transaction cookie.
2. kenneld copies the payload — a flat byte buffer; no shared memory crosses the boundary
   — into a pending-transaction record in a synchronised table keyed by the cookie.
3. kenneld delivers a fresh `BR_TRANSACTION` to the service process in the providing
   instance (provider's looper), carrying the payload.
4. On the provider's `BR_REPLY`, kenneld matches the pending record and issues `BR_REPLY`
   to the original caller using the saved cookie.

Because the caller's transaction is synchronous (the workload blocks on the reply), kenneld
holds the pending record open across the round-trip. A slow provider therefore consumes a
relay slot; this is what sizes the per-instance looper pool (§Threading model) and bounds
the pending table (capacity documented at the decode site; overflow → `BR_FAILED_REPLY`,
never silent queueing). Whether the relay stays in-kenneld or moves to a dedicated broker
process if the per-call cost proves material is the open question that most affects this
chapter's eventual as-built shape (§Open questions).

Death and teardown: a provider crash fires the binder death notification automatically, so
in-flight callers get `BR_DEAD_REPLY` rather than a hang (§7.1.5); kenneld restarts the
service process and re-registers the node. A consuming kennel's exit destroys its nodes;
pending cross-instance transactions it owned receive `BR_DEAD_REPLY`.

---

## Kennel spawning (new control-socket operation)

Spawning a kennel on behalf of a running kennel is a **privileged kenneld operation, not a
binder service transaction** (design §7.1.7): it goes over the existing CLI↔kenneld control
socket (`$XDG_RUNTIME_DIR/kennel/control.sock`, [`02-6-ipc.md`](02-6-ipc.md)), reached from
inside the kennel only when policy grants it (`[ipc.spawn]`). This adds one request and one
response to the control protocol. They are documented here and will be merged into the
`02-6` request/response tables on the remap:

**Request — op 5 `SpawnKennel`** (op bytes 1–4 are the existing `Start`/`Stop`/`List`/
`AuthorizedKeys`):

| Field | Type | Notes |
|---|---|---|
| `template` | length-prefixed UTF-8 string | template name to instantiate |
| `name` | length-prefixed UTF-8 string | kennel name scoped to the requesting kennel; unique within that scope |
| `narrowings` | length-prefixed list | grant *removals* only; widening is refused |

**Response — tag 6 `Spawned`** (tags 0–5 are the existing responses): `ctx` (u16),
`scoped_name` (length-prefixed UTF-8). Errors use the existing `Error` (tag 4) string
response.

kenneld validates, compiles the effective policy (template ∩ requesting kennel's own grants
∩ narrowings — never a superset of the requester), spawns the kennel, registers it in the
cross-instance registry, and returns the scoped name. The spawned kennel then registers its
services on its own binderfs instance normally; the requester reaches them via `getService`
as a cross-instance resolution. A spawned kennel has **no** `spawn-kennel` capability unless
its own template declares `[ipc.spawn]` — no ambient transitive spawning.

The frame carries no fds (unlike `Start`'s `SCM_RIGHTS` stdio), and the same
`SO_PEERCRED` UID check and field bounds as every other control request apply
([`02-6-ipc.md`](02-6-ipc.md) §Protocol invariants).

---

## Kernel requirements

| Requirement | Floor | Notes |
|---|---|---|
| binderfs | 5.0 | per-mount-namespace Binder filesystem; `FS_USERNS_MOUNT` (mounts in a child userns) |
| `CONFIG_ANDROID_BINDERFS` + `CONFIG_ANDROID_BINDER_IPC` | `=y` **or** `=m` | as a module, `binder_linux` must be loaded (or auto-loadable on first `mount -t binder`) |
| binder protocol | version 8 | `kennel-lib-binder` checks `BINDER_VERSION` at open |
| Project Kennel overall floor | 6.10 | already required for Landlock ABI 6 (`fs.execute`); binder is comfortably below it |

`kennel check` detects an unavailable binder driver — neither built in nor a loaded/loadable
`binder_linux` module — and reports it as a **fatal** prerequisite failure with a structured,
named-feature error, the same posture the BPF loader is designed to take for missing BPF
features (`02-7-bpf-abi.md`). These ship as **modules** (`=m`) on mainstream distributions
— Ubuntu's 6.17 kernel carries `CONFIG_ANDROID_BINDERFS=m` and `CONFIG_ANDROID_BINDER_IPC=m`
— so the check tests for a usable driver (built in, or a loaded/auto-loadable `binder_linux`),
not specifically for `=y`. Deployments on stock distribution kernels verify the module is
present rather than rebuild.

---

## Audit events

Every binder decision is audited through the unified writer (`kennel-lib-audit`,
[`02-3-audit-schema.md`](02-3-audit-schema.md)) with `source: kenneld`. This chapter
introduces the following event kinds; their JSONL field schemas are added to `02-3` when
the events land:

| Event | Emitted on |
|---|---|
| `binder.register` | `addService` (service name, outcome, pid) |
| `binder.lookup` | `getService` (service name, local/cross, outcome, pid) |
| `binder.cross` | a cross-instance transaction (`from_ctx`, `to_ctx`, service, transaction code, payload byte count, outcome) |
| `binder.service-crash` | a service process crash + restart (service name) |
| `kennel.spawn` | a `SpawnKennel` request (template, scoped name, effective policy hash) |

The `binder.cross` and `kennel.spawn` records, correlated by transaction code and calling
kennel ctx, are what let a security team reconstruct *which agent request caused which file
access in which kennel* from the JSONL log alone, with no application-layer instrumentation
(design §7.1.9). Payload *content* is never logged — byte counts and outcomes only, per
CODING-STANDARDS §9.3.

---

## Policy surface

The `[binder]` section, `[[binder.provide]]`/`[[binder.consume]]`, and `[ipc.spawn]`, plus
the rule that `org.projectkennel.*` names are rejected in `[[binder.provide]]`/`[[binder.consume]]`
at compile time, are schema additions owned by
[`02-2-config-schema.md`](02-2-config-schema.md). This chapter consumes the settled
`BinderRuntime` they produce; it does not define the schema. The reserved-namespace
validation is a categorical policy-compile error, not a runtime check (design §7.1.4).

---

## What this chapter does not cover

- The design rationale, MCP worked example, and residuals: design
  [`07-1-binder.md`](../design/07-1-binder.md).
- The `[binder]` / `[[binder.provide]]` / `[[binder.consume]]` / `[ipc.spawn]` schema:
  [`02-2-config-schema.md`](02-2-config-schema.md).
- The JSONL field layouts for the new audit events: [`02-3-audit-schema.md`](02-3-audit-schema.md).
- The dbus/gpg/wayland protocol-facade service processes (deferred to their own chapter).
- The CLI/privhelper/daemon non-binder wire formats: [`02-6-ipc.md`](02-6-ipc.md).
- The spawn pipeline this mounts into: design §8.7 and [`01-process-model.md`](01-process-model.md).
- Per-crate public APIs (`kennel-lib-binder`, `kenneld::binder`): [`02-8-internal-api.md`](02-8-internal-api.md).
- On-disk and runtime paths (`…/kennel/ctx-<n>/binderfs/`): [`07-paths.md`](07-paths.md).

---

## Open questions (to resolve as the build lands)

1. **Context-manager fd acquisition.** `/proc/<spawn-child-pid>/root/dev/binderfs/binder`
   vs `SCM_RIGHTS` fd-passing over the existing spawn socketpair. The `/proc` path is
   simplest; the `SCM_RIGHTS` path avoids a `/proc` open against the child but reuses a
   channel that must exist anyway. Low risk either way (§Mount sequencing).
2. **Relay placement.** In-kenneld relay vs a dedicated broker process, decided by the
   measured per-call cost of the MCP hot path and the TCB-growth concern (§The relay state
   machine).
3. **af-unix migration.** Whether the facade supersedes the built `[unix]` shim, coexists
   behind a gate, or the shim becomes the sub-feature fallback (§The af-unix facade).
4. **Looper-pool sizing.** Single looper per instance vs a pool, driven by head-of-line
   blocking on slow cross-instance round-trips (§Threading model).
5. **`kennel-lib-binder` UAPI vendoring.** Whether to vendor the binder UAPI headers (as `bpf/`
   does) or bind the structs by hand in Rust; affects the crate's build surface and the
   §2.2 header-pinning discipline. The UAPI headers ship in `linux-libc-dev` at
   `/usr/include/linux/android/{binder,binderfs}.h`.
