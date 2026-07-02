# §7.1 Binder: the inter-namespace gateway

> **Binder is load-bearing, not an opt-in feature.** Every kennel runs a per-instance
> binderfs bus with kenneld as its context manager (node 0), and that bus is the kennel's
> **auditable, unprivileged inter-namespace gateway**: the single kernel-mediated chokepoint
> through which anything crosses the kennel boundary. It carries the construction/lifecycle
> control plane (`kennel-bin-init` ⇄ kenneld, §7.2), the protocol facades that replace raw socket
> grants (`IAfUnix`, future `IDBus`, §7.1.5), the service registry and inter-kennel calls
> (§7.1.6–7.1.9), and — on the network path — the `INet` crossing (§7.5). Each crossing is a
> synchronous, kernel-stamped transaction kenneld can authorize and audit per call, with no
> ambient authority and no host-side privilege (binderfs is `FS_USERNS_MOUNT`, mounted inside
> the kennel's own user namespace). New boundary-crossing link types attach here rather than
> growing new ad-hoc shims — e.g. a future point-to-point **PPP** link would terminate in a
> facade on this bus, inheriting the same unprivileged, per-call-audited model.
>
> The rest of this chapter develops the primitive (§7.1.2), the registry and facades it
> enables, and the inter-kennel topology; §7.2 (`kennel-bin-init`) and §7.5 (network) are its two
> principal consumers.

## 7.1.1 Motivation

Several resource classes Kennel must police share an architectural problem: the
underlying protocol grants too much ambient authority to be safely forwarded raw,
but the application expects to find a conforming socket or device at a well-known
path. Each is mediated at the protocol level rather than by forwarding a raw socket:

- **D-Bus** is mediated at method-call granularity by the `IDBus` facade (§7.7).
- **Wayland** is not a binder facade at all: a graphical workload's display server is a
  nested inner compositor constructed in a GUI-service kennel (§7.14), reached as a `provide`/
  `consume` mesh service, so clipboard and screencopy are isolated by construction rather than
  by filtering a forwarded socket.
- **X11** is categorically denied (§7.8) because the protocol has no confinement
  vocabulary.

Each of these is the same underlying problem: Kennel needs a chokepoint at the
*protocol call* level, not just the *connection* level. The current model makes
raw socket grants auditable at connect time. What is needed is enforcement and
audit at call time, with kenneld as the policy decision point for every operation.

A second problem is inter-kennel communication. §8.8 documents inter-kennel
isolation as an invariant with no designed escape. Some topologies require two
kennels to communicate — a client kennel calling a standing service kennel
(§7.1.6) — without either holding ambient access to the other.

Both problems have the same solution: a kernel-enforced IPC primitive where
kenneld is the context manager, policy enforcement is per-call, and no kennel
can reach a service it has not been explicitly granted access to.

## 7.1.2 Architecture: binderfs as the IPC primitive

### Choice of primitive

The IPC primitive is binderfs — the Linux kernel's per-mount-namespace Binder
filesystem, mainline since 5.0, fully stable at the 6.10 kernel floor Kennel
already requires for Landlock ABI 6 (`fs.execute`).

Binder provides:
- **Synchronous datagram transactions** — call/return with kernel-managed
  transaction IDs. No async complexity; no application-level framing required.
- **Service name registry via a context manager** — a well-known node (node 0)
  that brokers service name → binder node resolution. kenneld registers as
  context manager for each kennel's binderfs instance.
- **Kernel-enforced capability references** — a binder node reference is an
  opaque kernel object. You hold it or you have nothing. There is no socket path
  to enumerate, no abstract namespace to probe.
- **Death notifications** — `BC_REQUEST_DEATH_NOTIFICATION` delivers an
  immediate kernel-driven notification when a service node dies. No polling,
  no timeout; the failure model is exact.
- **Per-instance isolation** — each binderfs mount is a fully independent
  instance, same as devpts and tmpfs. Two kennels' binderfs instances share no
  state.

Binder's capability-passing model (passing binder node references between
processes) is not used. References are issued by kenneld as context manager and
are not transferable between kennels. This eliminates the reference graph
complexity that makes Android's Binder implementation subtle, while retaining
the properties that matter: unforgeable references, synchronous transactions,
death notifications, and kernel-enforced isolation between instances.

### Why not a homebrew bus

The alternative — a kenneld-implemented message bus over socketpairs — would
require reimplementing transaction routing, reference management, death
notification, and instance isolation that binderfs already provides and that
Android has exercised at scale. Given that Kennel already operates at the ioctl
layer for Landlock and BPF, the binderfs ioctl ABI is consistent with the
existing codebase discipline.

### Kernel version and configuration

Kernel floor: 6.10 (already required for Landlock ABI 6).  
Kernel config: `CONFIG_ANDROID_BINDERFS=y`, `CONFIG_ANDROID_BINDER_IPC=y`.  
These are not enabled by default on all distributions; the reference runtime's
kernel configuration includes them explicitly.

## 7.1.3 binderfs instance lifecycle

> **The construction model is [§7.2](07-2-kennel-bin-init.md).** binderfs assigns its nodes to
> **uid 0 of the mounting user namespace**, so the kennel needs a real uid 0 (host root mapped
> `0 0 1`) for the nodes to be owned by a proper root rather than the overflow uid. The
> privhelper factory therefore mounts binderfs, allocates the device, and **chowns
> `/dev/binderfs/binder` to the operator** in its post-`clone` child — before `pivot_root` and
> before it `fexecve`s the trusted root-owned **`kennel-bin-init` (PID 1)**, so no uid-0 binary
> runs while the host filesystem is still visible. The map needs `CAP_SETUID`, so this work is
> the privhelper's; `kennel-bin-init` is a binder *consumer* that **pulls** its config over the bus
> (§7.2). The lifecycle mechanics below describe the steady-state bus.

### Mount sequencing

binderfs carries `FS_USERNS_MOUNT`, so each kennel's instance is mounted *inside*
the kennel's own user + mount namespace, alongside the tmpfs, devpts, and proc the
spawn already constructs there — no host-side mount and no privileged step. The
sequence within the existing spawn pipeline (§8.7) is:

1. Inside the kennel's new namespaces, the spawn mounts a fresh binderfs at the
   view's `/dev/binderfs/`: `mount("binder", "/dev/binderfs", "binder", 0, "max=256")`.
   `max=256` caps binder device allocation per kennel; the default is unbounded.
2. The spawn opens `binder-control` and allocates the **standard binder device** via
   `BINDER_CTL_ADD` with name `binder` → it appears at `/dev/binderfs/binder`, with
   `/dev/binder` symlinked to it (the Android/libbinder convention; see below).
3. kenneld becomes context manager: it acquires a descriptor on `/dev/binderfs/binder`
   (via `/proc/<spawn-child-pid>/root` or an `SCM_RIGHTS` hand-back over the spawn
   socketpair) and calls `BINDER_SET_CONTEXT_MGR`, taking node 0 for this instance.
   The context manager runs in the daemon so one entity owns every instance's node 0
   — the precondition for cross-instance routing (§7.1.6).
4. Landlock rules permit the workload read/write access to `/dev/binderfs/binder`
   (reached via the `/dev/binder` symlink) and read access to `/dev/binderfs/features/`.
   The `binder-control` device is not accessible to the workload — only the spawn
   allocates devices, before the seal.
5. The remaining spawn sequence (pivot_root, workload exec) proceeds as before.

On kennel exit, the binderfs instance disappears with the kennel's mount namespace.
All pending transactions on the instance receive death notifications; all binder
nodes are destroyed.

The device is the **standard binderfs device named `binder`**, not a Kennel-specific
name: each kennel has its own isolated instance, so there is no collision a custom
name would resolve, and a non-standard name would force every binder client in the
workload to be specially configured — defeating the "application finds its driver at
the default path" principle the §7.6 socket shim rests on. Kennel does not use the
Android `hwbinder`/`vndbinder` contexts; one `binder` context per instance suffices.
(The `org.projectkennel.*` strings below are service-*registry* names, not device names —
reverse-DNS service naming is itself the Android convention.)

### Context manager role

Node 0 is the Android servicemanager analogue — clients reach the registry through
the well-known node (handle 0), never by name. Its verbs mirror Android's
`IServiceManager` semantics:

- `addService` — a service process registers a named service. kenneld records the
  service name → binder node mapping in its per-kennel registry and validates that
  the kennel's policy declares the service.
- `getService` — a workload or service process resolves a service name to a binder
  node reference. kenneld checks policy and, if permitted, returns a reference the
  caller can use for subsequent transactions.
- `listServices` / `isDeclared` / `getDeclaredInstances` — service-surface
  introspection: the names a caller is granted to look up, whether a given service
  is declared for it, and the granted instances of an interface. A workload queries
  its own binder surface here; there is no separate introspection service node.

All other transactions on node 0 are rejected with `BR_FAILED_REPLY`. kenneld emits
an audit event for every verb, recording service name, outcome, and the requesting pid.

The "policy declares the service" check is the **VINTF-declared** analogue: as Android's
servicemanager refuses to register, and `isDeclared()` reports, a service absent from the
VINTF manifest, Kennel's signed policy is that manifest — a service the policy does not
declare cannot register and reports `isDeclared = false`.

### The `org.projectkennel.*` reserved namespace

kenneld is both context manager *and* service provider for a set of built-in
services. These are registered by kenneld itself — not by spawned service
processes — and are served directly from kenneld's context manager thread. They
occupy the reserved namespace `org.projectkennel.*`.

Two enforcement rules apply to this namespace, checked before any policy lookup:

1. `addService` with a name matching `org.projectkennel.*` is rejected for all callers
   other than kenneld itself. A workload or service process attempting to register
   under this prefix receives `BR_FAILED_REPLY`. There is no policy override.
2. `getService` for an `org.projectkennel.*` name is always resolved to kenneld's own
   node on the local instance. It is never routed to the cross-instance registry
   (§7.1.6), regardless of what any peer kennel declares.

The reserved services use the Android `INTERFACE/INSTANCE` naming grammar: a reverse-DNS
interface under a domain the project owns (`org.projectkennel.*`, owned exactly as `android.*`
and `vendor.*` are in AOSP) and an instance, `default` until a service needs more than one.
The reserved services and their roles:

| Service name | Role |
|---|---|
| `org.projectkennel.IAfUnix/default` | Brokered AF_UNIX connections — kenneld connects on the workload's behalf and returns the fd (§7.1.5) |
| `org.projectkennel.IDBus/default` | Mediated D-Bus access; method allowlist enforced per-call |

Kennel spawning is **not** a reserved service — it is a control-socket operation (§7.1.7),
not a binder node. Policy/service introspection is **not** a reserved service either — node 0
answers it through `listServices`/`isDeclared`/`getDeclaredInstances`, as Android's
servicemanager does.

An `org.projectkennel.*` service is only present in a kennel's instance if the
corresponding policy section is non-empty. A kennel with no `[dbus]` section
gets no `org.projectkennel.IDBus/default` node — `getService` for it returns `BR_FAILED_REPLY`.
Absence of the node is proof the capability was not granted.

### Rust implementation note

The binder ioctl ABI (`BINDER_WRITE_READ`, `binder_write_read`,
`binder_transaction_data`, the `BC_`/`BR_` command stream) is stable and
documented in `include/uapi/linux/android/binder.h`. The implementation in
kenneld is a minimal Rust wrapper around this ABI — not libbinder, not
libbinder-ndk, both of which carry Android-specific dependencies. The wrapper
covers the context manager state machine (looper registration, transaction
dispatch, reply handling) and is scoped to kenneld's needs as context manager.
Service processes (§7.1.5) use the same wrapper.

## 7.1.4 Policy surface

The `[binder]` policy section gates what services a kennel may register and
what services it may look up. Service names fall into two categories:

**Reserved (`org.projectkennel.*`)** — provided by kenneld itself. These are enabled by
their corresponding policy sections (`[dbus]`, `[wayland]`, `[unix]`), not by
`[[binder.provide]]`. A workload does not declare that it provides
`org.projectkennel.IDBus/default`; it declares `[dbus]` capabilities and kenneld registers the
service on the workload's binderfs instance automatically.

**User-defined** — provided by service processes the policy author declares.
These use arbitrary names that must not begin with `org.projectkennel.`.

```toml
# kenneld-provided services — enabled by their own policy sections
[dbus]
[[dbus.allow]]
destination = "org.freedesktop.Notifications"
interface   = "org.freedesktop.Notifications"
member      = "Notify"
reason      = "desktop notifications"
# → kenneld registers org.projectkennel.IDBus/default

[unix]
[[unix.allow]]
path   = "/run/user/<uid>/pipewire-0"
access = "rw"
reason = "audio via PipeWire"
# → kenneld registers org.projectkennel.IAfUnix/default

# User-defined service — registered by a service process the policy author provides
[[binder.provide]]
name   = "build-cache"
accept_from = ["builder"]
reason = "serve cached build artefacts to builder kennels"

# Services this kennel may look up and call
[[binder.consume]]
name   = "build-cache"
from   = "cache-server"
reason = "query the shared build cache"
```

`binder.provide` and `binder.consume` cover user-defined services only. The
`org.projectkennel.*` namespace is never declared in `[[binder.provide]]` or
`[[binder.consume]]` — attempting to do so is a policy validation error.

## 7.1.5 Service processes

### Two categories of service

**kenneld-provided services** are served directly from kenneld's context manager
thread. They do not involve a spawned service process; kenneld owns the binder
node and handles transactions itself. These are the `org.projectkennel.*` services.
The workload cannot distinguish a kenneld-provided node from a service process
node — both are opaque binder references.

**User-defined service processes** are small daemons spawned by kenneld into the
kennel's constructed view at kennel start. Each:

1. Opens `/dev/binder` (the standard device; `/dev/binderfs/binder`).
2. Sends `addService` to kenneld (node 0) with its service name.
3. Enters its binder looper, dispatching incoming transactions.
4. For each transaction, applies service-level logic and returns a reply.

Service processes are kenneld's agents inside the kennel. Their Landlock ruleset
is narrower than the workload's — access to `/dev/binder` and whatever
paths the service specifically requires, nothing else. They have no ambient
access to host services.

### kenneld-provided service detail

**`org.projectkennel.IAfUnix/default`** is the most structurally significant. The current raw
AF_UNIX shim model (§7.6.6) grants the workload a socket path in its constructed
view and audits at connect time only. `org.projectkennel.IAfUnix/default` replaces this: the
workload issues a binder transaction to the `org.projectkennel.IAfUnix/default` node carrying
the requested socket path as a flat string payload. kenneld validates the path
against the `[[unix.allow]]` list, makes the actual `connect()` on the host
side, and returns the connected fd to the workload via `BINDER_TYPE_FD` in the
reply. The workload receives a connected socket fd; it never holds a path into
the host AF_UNIX namespace, and every connection attempt is audited at the
call level rather than inferred from the constructed view.

This closes the gap where a workload could detect socket paths that appeared in
its constructed view even when it was not supposed to use them — with
`org.projectkennel.IAfUnix/default`, paths do not appear in the view at all.

**`org.projectkennel.IDBus/default`** is kenneld-provided but implemented via protocol-specific
processes that kenneld spawns and supervises (an in-kennel facade that parses the adversarial wire and
an operator-context delegate that holds the host connection — §7.7.2). The binder node is owned by
kenneld; the facade/delegate pair handles the foreign protocol on kenneld's behalf. From the
workload's perspective, the node is kenneld.

The protocol facades are:

| Service | Replaces | Translation |
|---|---|---|
| `org.projectkennel.IDBus/default` | a raw bus-socket grant + §7.7 | `facade-dbus` parses the D-Bus wire into typed messages; the `host-dbus` delegate filters them through the compiled `[dbus]` table and reconstructs the call to the real bus; kenneld builds the facade/delegate pair + conduit at construction only (§7.7.2 — the per-message check runs in the delegate, not the daemon) |

### Service process lifetime

Service process lifetime mirrors the kennel: kenneld spawns them before the
workload starts and destroys them after the workload exits. If a service process
crashes, kenneld restarts it and emits a `service.crash` audit event with the
service name. The binder death notification for the node triggers automatically
on crash, so callers receive `BR_DEAD_REPLY` for the in-flight transaction rather
than a hung call. Kenneld re-registers the node once the service process restarts.

## 7.1.6 Inter-kennel IPC

### Model

Inter-kennel IPC uses the same binderfs mechanism. Each kennel has its own
binderfs instance; kenneld maintains a cross-instance service registry mapping
service names to instances. When a workload issues `getService` for a service
name that is not registered locally, kenneld checks its cross-instance registry
and, if a peer kennel provides the service and policy on both sides permits it,
returns a binder node reference that tunnels through kenneld to the peer
instance.

The workload holds a binder node reference and issues transactions against it.
It does not know — and cannot determine — whether the node is local or in a peer
kennel. The transport is opaque; the policy enforcement is in kenneld.

### Cross-instance policy

For a cross-instance lookup to succeed, two conditions must both hold:

1. The consuming kennel's policy declares `[[binder.consume]]` with the service
   name and the providing kennel's ctx as `from`.
2. The providing kennel's policy declares `[[binder.provide]]` with the service
   name and the consuming kennel's ctx in `accept_from`.

```toml
# Consuming kennel (e.g. builder)
[[binder.consume]]
name = "build-cache"
from = "cache-server"
reason = "query the shared build cache"

# Providing kennel (e.g. cache-server)
[[binder.provide]]
name = "build-cache"
accept_from = ["builder"]
reason = "serve cached build artefacts to builder kennels"
```

A unilateral declaration on either side produces a `getService` denial. kenneld
validates both sides at lookup time, not at spawn time — the peer kennel need
not be running yet when the consuming kennel starts. kenneld blocks the lookup
until the service is registered or the consuming kennel exits.

### Kennel name leakage

Cross-instance policy requires naming the peer kennel in the `from` /
`accept_from` fields. These names appear in policy files, not in the binder
protocol seen by the workload. The workload sees a service name (`build-cache`)
and a binder node reference; it does not see the peer's ctx or any other kennel
identity. The naming is a policy-authoring concern, not a runtime information
leak.

### Tunnelling

When kenneld routes a transaction cross-instance, it acts as a relay:

1. Receiving instance: kenneld receives the `BC_TRANSACTION` on the tunnel node.
2. kenneld copies the transaction payload (a flat byte buffer; no shared memory
   across instances) into a pending transaction record.
3. Providing instance: kenneld delivers a `BR_TRANSACTION` to the service process
   in the peer kennel, carrying the payload.
4. The service process replies; kenneld delivers `BR_REPLY` back to the original
   caller.

Shared memory (`BINDER_TYPE_FD`, `BINDER_TYPE_PTR`) is not permitted across
instance boundaries — the flat `BINDER_TYPE_ARRAY` / scalar payload types only.
This is enforced by kenneld when it inspects the transaction object type field
before relaying. Attempts to pass file descriptors or pointer objects across
instances return `BR_FAILED_REPLY`.

The audit record for a cross-instance transaction:

```jsonl
{
  "ts": "...", "event": "binder.cross",
  "from_ctx": "builder", "to_ctx": "cache-server",
  "service": "build-cache", "transaction_code": 1,
  "payload_bytes": 312, "outcome": "allow"
}
```

## 7.1.7 Kennel spawning

Spawning a new kennel on behalf of a running kennel uses the kenneld control
socket (the existing Unix domain socket at `$XDG_RUNTIME_DIR/kennel/control.sock`,
not binderfs — spawning is a privileged kenneld operation, not a service
transaction). The workload sends a `spawn-kennel` request on the control socket:

- Template name (length-prefixed string).
- Kennel name scoped to the requesting kennel (length-prefixed string; must be
  unique within the requesting kennel's scope).
- Optional grant narrowings (may only remove from the requesting kennel's own
  grants; widening refused).

kenneld validates, compiles the effective policy (template + requesting kennel
grant intersection + narrowings), spawns the kennel, registers it in the
cross-instance registry, and returns the scoped kennel name. The spawned kennel
then registers its services on its own binderfs instance in the normal way;
the requesting kennel looks them up via `getService` as a cross-instance
resolution.

The spawned kennel has no `spawn-kennel` capability by default. Further spawning
requires an explicit `[ipc.spawn]` declaration in the spawned kennel's template.

## 7.1.8 Relationship to existing sections

| Section | Status after §7.1 |
|---|---|
| §7.7 D-Bus | Mediated by the `facade-dbus`/`host-dbus` pair on the kennel's binderfs instance (§7.7.2). |
| §8.8 Inter-kennel isolation | Default unchanged. Cross-instance IPC requires explicit `[[binder.consume]]` + `[[binder.provide]]` declarations on both sides. Kennels without `[binder]` sections have no IPC surface at all. |

## 7.1.9 Cross-instance worked example

A worked example, end to end. A `builder` kennel consumes a `build-cache` service
that a `cache-server` kennel provides; neither holds ambient access to the other.

```
builder
  [[binder.consume]] name = "build-cache", from = "cache-server"

cache-server
  [[binder.provide]] name = "build-cache", accept_from = ["builder"]
```

`builder` issues `getService("build-cache")`; kenneld resolves it cross-instance
(§7.1.6), validates both sides' declarations, and returns a tunnel node reference.
`builder` issues transactions against it; kenneld relays each as a flat payload to
the `cache-server` service process and relays the reply back, framing and parsing
none of the payload itself.

The audit trail correlates the two kennels without application-layer
instrumentation: a `binder.cross` event records each transaction — service name,
payload size, outcome, and the calling and providing ctx — so a security team can
reconstruct which client request reached which service from the JSONL log.

## 7.1.10 Residuals

**Cross-instance payload opacity.** kenneld validates transaction object types
(rejecting fd and pointer objects cross-instance) but does not inspect payload
content. Application-layer protocol correctness between kennels is the
application's responsibility.

**Shared memory.** `BINDER_TYPE_FD` and `BINDER_TYPE_PTR` are rejected cross-
instance. Within a single kennel (between the workload and a local service
process) shared memory transactions are permitted, since both parties are within
the same trust boundary. Extending shared memory cross-instance would require
a separate design decision.

**binderfs kernel config.** `CONFIG_ANDROID_BINDERFS` is not enabled by default
on all distributions. The reference runtime's kernel configuration includes it;
deployments on stock distribution kernels must verify or rebuild. `kennel check`
detects the missing config and reports it as a fatal prerequisite failure.

## 7.1.11 Test plan additions

Tests in `tests/binder/` and `tests/facades/`:

1. binderfs mounts as a separate instance per kennel; two kennels' instances
   share no nodes.
2. kenneld registers as context manager; workload `getService` for unknown
   service returns `BR_FAILED_REPLY`.
3. `addService` with name matching `org.projectkennel.*` from a non-kenneld caller:
   rejected with `BR_FAILED_REPLY`; audit event emitted; no policy override.
4. `getService` for `org.projectkennel.*` name: always resolved locally; never routed
   to cross-instance registry regardless of peer kennel declarations.
5. `addService` without matching `[[binder.provide]]` in policy: denied,
   audit event emitted.
4. `getService` without matching `[[binder.consume]]` in policy: denied,
   audit event emitted.
5. Local transaction (workload → service process, same kennel): allowed,
   payload delivered, reply returned.
6. Cross-instance transaction with bilateral declarations: allowed, payload
   tunnelled, reply returned, audit event emitted.
7. Cross-instance transaction with unilateral declaration: denied on lookup.
8. Cross-instance transaction carrying `BINDER_TYPE_FD`: rejected by kenneld,
   `BR_FAILED_REPLY` returned to caller.
9. Service process crash: `BR_DEAD_REPLY` delivered to in-flight callers;
   kenneld restarts service; `service.crash` audit event emitted.
10. Kennel exit: all binder nodes destroyed; cross-instance callers receive
    death notifications; pending cross-instance transactions receive
    `BR_DEAD_REPLY`.
11. `dbus` service: allowed method call returns real bus response; denied method
    call returns `org.freedesktop.DBus.Error.AccessDenied`.
15. Policy validation: `[[binder.provide]]` or `[[binder.consume]]` with a
    `org.projectkennel.*` name is rejected at policy compile time with a clear error.
16. `kennel check`: missing `CONFIG_ANDROID_BINDERFS` reported as fatal.