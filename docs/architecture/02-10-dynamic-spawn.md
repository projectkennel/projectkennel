# Dynamic spawn — the `SPAWN` transaction and the confined-stdio handoff

> **Status: designed, not yet built.** This chapter is the implementation contract for the
> dynamic-spawn feature designed in [`../design/07-12-dynamic-spawn.md`](../design/07-12-dynamic-spawn.md)
> (§7.12). It is the as-built target for roadmap workstreams W3–W8
> ([`../governance/ROADMAP-0.3.0.md`](../governance/ROADMAP-0.3.0.md)); it is written as a forward
> contract and reconciled to as-built truth as those workstreams land. Where this contract and the
> code diverge once built, the divergence is owed to the code.

A confined workload asks `kenneld` to instantiate a constrained, ephemeral **sibling** kennel from
an operator-signed template and wires a stdio channel to it. `kenneld` validates an ACL, brokers
file descriptors, and steps out of the byte path. MCP rides the channel as opaque JSON-RPC;
`kenneld` neither frames nor parses it. This is the binder Node 0 verb (`SPAWN`), the descriptor
handoff into the spawned kennel's supervision plan, and the fate-sharing reaper that bounds the
spawned kennel's life to the requester's.

## Stability commitment

**Internal-stable** (per [`02-0-overview.md`](02-0-overview.md)). The `SPAWN` wire format and the
injected-stdio fields added to the supervision plan are coordinated within a release across
`kenneld`, the privhelper, and `kennel-bin-init`; they carry no external commitment and may change
between minor versions. The **workload-facing** surface — the `[spawn]` grant and the template
`[[mutable]]` manifest grammar — is the *policy schema*, which is **stable** and specified in
[`02-2-config-schema.md`](02-2-config-schema.md). A third party writes policy against `[spawn]`;
nothing outside Project Kennel writes the `SPAWN` binder wire.

## Why this shape

The design rests on one rule: **a workload cannot author policy at runtime** (§7.12.1). It *names*
an operator-signed template and writes only the fields that template's manifest declares mutable;
the signature was checked when the operator installed the template, so no new signature is needed
and no new capability can be invented. Everything in this contract follows from that:

- `kenneld` is the spawner; the requester and the spawned kennel are **siblings** joined by an FD
  channel and a `kenneld`-brokered lifecycle coupling — not a parent owning a child. The requester
  holds no `ptrace` or signal reach into the spawned process (it runs in its own user/PID namespace
  with a distinct uid), or the isolation the spawn exists to create would be defeated at creation.
- `kenneld` stays **control-plane**: it evaluates the grant, diffs the candidate against the
  manifest, resolves the template in memory, and brokers descriptors. It mounts nothing beyond the
  template's own view, parses no JSON, and routes no traffic — the same discipline as the net-proxy
  data path ([`02-5-binder-net.md`](02-5-binder-net.md)), and the same TCB argument
  ([[tcb-only-shrinks]]): a protocol parser that co-evolves with the MCP specification never sits
  next to the daemon.

## Participants

| Process | Namespace | Binder role | Responsibility |
|---|---|---|---|
| **Requester workload** | its own kennel | Node 0 client (`SPAWN`) | Mints the channel fds, names the template + its mutable-field writes, keeps the local ends |
| **`kenneld`** | host (operator) | Node 0 context manager | Validates grant + manifest diff, resolves the template in memory, accepts the channel fds, drives construction |
| **`kennel-privhelper`** | transient, per-spawn | — | Factory: clones the spawned kennel's namespaces, injects the channel fds, `fexecve`s `kennel-bin-init` ([[no-standing-host-privilege]]) |
| **Spawned sibling** | fresh kennel | Node 0 client (own instance) | Runs the template's entrypoint (for MCP, a stdio JSON-RPC server) with the injected fds as stdio |

The spawned kennel is a full kennel: its own binderfs instance, its own `kennel-bin-init` at uid 0,
its own view. It is constructed by the same privhelper factory as an operator-launched kennel
([[kennel-init-and-uid0]], [[spawn-userns-owner-yama]]); dynamic spawn adds the descriptor injection
and the lifecycle coupling, not a new construction path.

## The `[spawn]` grant and manifest-diff validation

The agent controls exactly one thing: the writes it makes to the template's **mutable fields**. A
template is a *complete, signed, runnable policy* plus a declared `[[mutable]]` manifest naming which
leaf fields a spawn may write; everything outside the manifest is frozen and inherited verbatim
(§7.12.3). `kenneld` performs two checks at `SPAWN` time, both **policy validation in the existing
compiler**, not a new parser in the TCB:

1. **Grant.** The requesting kennel's compiled policy carries its `[spawn]` ACL — the
   `[[spawn.allow]]` template set, `max_instances`, and an optional per-requester `mutable` list
   that *narrows* (never widens) the template's manifest for this requester. It is held in the
   kennel's `kenneld`-side runtime record from construction. A template not in the ACL is **denied**
   (`kennel.spawn` / `outcome: Deny`).
2. **Manifest diff.** `kenneld` accepts the candidate **iff `candidate ∖ manifest == template ∖
   manifest`** — the candidate may differ from the signed template *only* within the declared
   (and per-requester-narrowed) mutable fields, and each such write must satisfy that field's
   **bound**. Any write outside the manifest is a **hard reject, fail-closed**. This inverts the
   surface from *synthesis* to *selection*: the agent fills labelled, fenced blanks in a sealed
   document and the compiler proves it filled only the blanks — a membership check, not satisfaction
   of a predicate over an open value space.

Each mutable field carries one of three **bound kinds** — one mechanism, not three:

| Bound | Declaration | The write must be |
|---|---|---|
| **pool** | `from = [...]`, `max = N` | a subset of the fixed pool, at most `N` entries (the agent *appends*, drawn from the pool) |
| **oneof** | `oneof = [...]` | one member of the enumerated list |
| **predicate** | `type`/`under` | a single value passing the typed, traversal-free, `RESOLVE_IN_ROOT` check |

The **predicate** kind is the old free-value case, demoted to the loud minority escape hatch for a
value that genuinely cannot be enumerated or pooled at sign time (the agent's actual working
subpath). Most templates are pure pool/oneof selection and carry **zero** agent-authored free text;
the open-value residual (T3.9 R1) attaches only to templates that declare a predicate field.

**The frozen set carries the invariants.** Single-leg (§7.12.2), the resource ceilings, and the TTL
live in *frozen* fields — `net.mode`, the absence of an `[fs]` root grant, the cgroup limits — so no
manifest write can add a trifecta leg, lift a ceiling, or escape the TTL, because those fields are
not in the agent's write set. Single-leg is enforced once, at the floor; the manifest flexes
underneath it. The unit of mutation is the leaf field (or an explicitly scoped subtree), so a
manifest opening `net.allow` cannot be used to rewrite `net.mode` beside it.

**Depth-1** (§7.12.8) is **not** re-checked here: it is enforced transitively at template *install*
time (a template named in any `[[spawn.allow]]` is refused if it carries `[spawn]`), so by the time
a `SPAWN` arrives the target is already known not to be a spawner. The reaper accounting below relies
on it (the hard-reaper coupling is a single hop because no spawned kennel can itself spawn).

## The `SPAWN` transaction

`SPAWN` is a Node 0 verb issued by the **requester workload** (operator uid, not `kennel-bin-init`),
so it is a facade-class verb dispatched without the registry lock — alongside `CONNECT_INET` /
`CONNECT_AFUNIX` ([`02-4-binder.md`](02-4-binder.md)) — **not** a lifecycle verb (the `0x100+`
range is gated `sender_pid == init_host_pid && sender_euid == 0`, which is `kennel-bin-init` only).

| Field | Direction | Encoding |
|---|---|---|
| `code` | req | `SPAWN` (facade range, next free verb code) |
| template | req | length-prefixed `name@version` (`<= MAX_NAME`) |
| mutable writes | req | count-prefixed `(field-path, value)` length-prefixed pairs — the candidate's manifest-field writes |
| **fd[0]** | req | `BINDER_TYPE_FD` — the socketpair remote end (spawned kennel's stdin + stdout) |
| **fd[1]** | req | `BINDER_TYPE_FD` — the pipe write end (spawned kennel's stderr) |
| reply | rep | status byte + transient `spawn-<uuid>` (audit/tracking handle) |

The requester mints a `socketpair()` (bidirectional JSON-RPC: it keeps the local end) and a
`pipe()` (the spawned kennel's `stderr`, kept on a separate descriptor so unstructured error text
never corrupts the framed channel — §7.12.5), and attaches the *remote* ends to the `SPAWN`
transaction as exactly **two** `BINDER_TYPE_FD` objects. The reply carries no fd — the requester
already holds its local ends.

### Inbound descriptor acceptance — the safety argument

`SPAWN` is the **one** Node 0 verb that accepts descriptors *into* `kenneld`. Every other Node 0
verb issues descriptors *outward* (the connected socket from `CONNECT_*`, the pushed conduit from
`DELIVER_INET`), and Node 0 is created `accept_fds = 0` so the kernel rejects any inbound fd before
a handler sees it ([[binder-fd-passing-safety-verdict]]). Accepting inbound fds for `SPAWN` is a
deliberate, **scoped** relaxation, and it holds because:

- **Bounded arity.** Node 0's `accept_fds` is raised to exactly **2** — the `SPAWN` maximum. A
  transaction presenting any other count is rejected. No fd-table-exhaustion vector opens.
- **Injection stays blocked for every other verb.** Each non-`SPAWN` handler asserts its `Incoming`
  carries no descriptors and returns `BAD_REQUEST` otherwise. The "injection-blocked" property is
  preserved by *handler-level rejection*, not by the driver-level `accept_fds = 0` it replaces — the
  registry/facade verbs gain no inbound-fd path.
- **The descriptors are opaque conduits, never operated on.** `kenneld` does not `read`, `write`,
  `seek`, `stat`, or otherwise act on the received fds. It translates them once (the kernel's
  `BINDER_TYPE_FD` translation is atomic and unforgeable) and relays them straight into the spawned
  kennel's construction. No content is trusted because no content is read.
- **Self-contained blast radius.** A malicious requester can pass an arbitrary descriptor (a file,
  not a socket; a pipe to nowhere). The only consequence is that *its own* spawned tool's stdio is
  that descriptor — the requester degrades a channel it owns. The fd cannot reach another kennel,
  another spawn, or any `kenneld` state; it is `CLOEXEC` on receipt and flows only to the one
  sibling the requester is authorised to spawn.

This is the residual the `requester-mints` model carries; it is acceptable precisely because the
descriptors are conduits the daemon never dereferences and the damage is confined to the requester's
own delegation.

## The capability handoff (construction)

On a validated `SPAWN`, `kenneld`:

1. **Resolves the template in memory** from the trust store and applies the validated mutable-field
   writes — no child policy is ever written to disk, because no child policy is ever authored
   (§7.12.1, §7.12.6). The instantiation is the signed template with the manifest blanks filled.
2. **Builds the supervision plan** with the two injected descriptors recorded as **presence flags**.
   The plan codec (`kennel-lib-spawn`) carries fds out-of-band via `SCM_RIGHTS` in a fixed order and
   records only a `bool` per fd in the wire bytes — the established pattern for the pty and
   sha256-pinned-workload descriptors. Three new presence flags are added (`stdin`/`stdout`/`stderr`
   injected), and three new fixed descriptor slots follow the existing `pty=3` / `boot-sync=4` /
   `workload=5` assignment. The privhelper pops the flagged fds in order and `dup_onto`s them to
   their slots before `fexecve`. *(W7. Adding required fields to the settled `Supervision` /
   `ConstructionHalf` structs touches every plan fixture across crates — a single coordinated
   commit, per the §8.3 settled-schema gotcha.)*
3. **`kennel-bin-init` `dup2`s** the injected slots onto the workload's stdin/stdout/stderr **before**
   the pty/controlling-tty setup and before the Landlock/seccomp seal. A dynamically-spawned tool is
   non-interactive (it speaks JSON-RPC over stdio), so it takes the injected-fd path, not the
   pty-allocation path. Init makes no policy judgment here ([[init-is-dumb-executor]]); the
   descriptors and their disposition were decided by `kenneld` pre-handoff.

### Construction is asynchronous to the reply

The `SPAWN` reply returns **after validation and fd acceptance, not after the spawned kennel boots.**
`kenneld` validates the grant + manifest diff, takes the two descriptors, enqueues the construction,
and replies immediately with the `spawn-<uuid>`; the heavy construction (privhelper factory,
namespace clone, `pivot_root`, init exec) proceeds off the binder looper. Rationale:

- The Node 0 looper pool is bounded (`POOL_MAX_THREADS`); holding a looper for a full kennel
  construction would let concurrent spawns exhaust it. Returning early keeps `kenneld`
  control-plane and decouples looper occupancy from construction latency (a W10 concern).
- The requester does not need to block on boot: it writes into its local socketpair end, which
  buffers until the spawned tool reads. A construction *failure* surfaces to the requester as
  **EOF on the channel** (the soft-reaper path below) plus a `kennel.spawn` / `outcome: Deny` audit
  event — the same way a tool that exits surfaces.

## Spawn sequencing

1. Requester mints `socketpair()` + `pipe()`; keeps the local socketpair end and the pipe read end.
2. Requester sends `SPAWN(template@version, mutable-writes, [socketpair-remote, pipe-write])` to Node 0.
3. `kenneld` validates the `[spawn]` grant and the manifest diff (deny → reply + audit, fds dropped).
4. `kenneld` accepts the two descriptors, resolves the template in memory, replies `spawn-<uuid>`.
5. `kenneld` enqueues construction; the privhelper factory clones namespaces and injects the fds
   into the supervision plan at the new fixed slots.
6. `kennel-bin-init` boots the sibling, `dup2`s the injected fds onto stdin/stdout/stderr, seals, and
   `execve`s the template entrypoint.
7. Data flows kernel-to-kernel over the socketpair; `kenneld` and binder are out of the byte path.

## Fate-sharing: the double reaper

A spawned kennel must not outlive its purpose; the coupling is `kenneld`-brokered, not parental
(§7.12.7).

- **Soft reaper (data plane).** The requester `close()`s its local ends; the spawned tool receives
  `EOF` on stdin / `SIGPIPE` on stdout and exits; `kennel-bin-init` tears the kennel down. The
  graceful path, and the path a construction failure also takes.
- **Hard reaper (control plane).** `kenneld` tracks the **binder session** that issued the `SPAWN`
  (the requester's Node 0 connection). If that session drops — requester crash, OOM, TTL expiry —
  `kenneld` issues a `cgroup.kill` to the spawned kennel, reusing the TTL freeze/kill plumbing
  ([`05-state-and-supervision.md`](05-state-and-supervision.md)). The backstop for a tool that
  ignores `EOF`.
- **Accounting.** The reaper that kills **decrements `max_instances`**, so a flapping requester
  cannot leak slots across teardown races. `max_instances` is the concurrent-spawn ceiling (the
  fork-bomb bound); depth-1 keeps it a global ceiling rather than a per-node one.

## Ephemerality and identity

- **In-memory instantiation, no host trace** — no child policy on disk (§7.12.6).
- **Transient identity** — spawned kennels take `spawn-<uuid>` names; they consume no operator
  registry namespace and cannot collide with an operator-named kennel.
- **No persistence** — the root is an ephemeral `tmpfs`, or an OCI image at `persistence = "discard"`
  ([`02-9-oci.md`](02-9-oci.md), §7.11.4a). A spawn-target template **must declare a memory
  ceiling**: artifacts pass in memory as `memfd`s charged to the spawned kennel's memory cgroup, and
  without a ceiling an oversized artifact is an unbounded-memory DoS rather than a bounded transfer.

> **`memfd` artifact transfer is roadmap, not first-build.** The stdio channel + control handoff
> above is the W6–W8 core. The in-memory `memfd` artifact path (§7.12.6) is net-new plumbing with no
> existing analogue in the spawn path; it is specified and built after the stdio core proves out.

## Audit events

| Event | Emitted when |
|---|---|
| `kennel.spawn` (`outcome: Allow`) | a validated `SPAWN` is accepted and construction enqueued |
| `kennel.spawn` (`outcome: Deny`) | grant/manifest-diff validation fails, or construction fails |
| `kennel.spawn.reaped` | soft or hard reaper tears the spawned kennel down (with which path) |

## Threat bearing

Defends the dynamic-spawn delegation as **T3.9 — Delegated spawning** (workload-class, derived from
the `[spawn]` grant the way `mode = host` derives T1.6; W2). What holds: the capability floor of
every spawn is the signed template's; the requester holds no `ptrace`/signal reach; `kenneld` brokers
fds and parses no JSON, so the TCB does not grow. The waived residuals: **R1** — the mutable-field
surface is agent-controlled, and the boundary is exactly the strength of the template's per-field
bounds (pure pool/oneof manifests reduce this to closed-set selection with no agent free text; a
predicate field is the loud exception that reintroduces an open value, held by its typed,
traversal-free, `RESOLVE_IN_ROOT` bound); **R2** — an agent that may spawn a network-capable tool and
a filesystem-capable tool can bridge their channels and reconstitute the lethal trifecta across two
kennels, not mechanically closed (it would put cross-kennel information-flow reasoning in the
daemon), mitigated by scoping `[[spawn.allow]]` to the templates an agent actually needs.

## What this chapter does not cover

- **MCP semantics** — tool allow-listing and call audit live in the opt-in in-kennel **interposer**
  (W21, §7.12.5), a confined disposable kennel the operator wires between requester and tool;
  `kenneld` does not understand MCP.
- **Fleet observability** — `kennel ps` over ephemeral spawns and what-spawned-what is the
  live-topology surface (W20).
- **The `[spawn]` / `[[mutable]]` policy schema** — [`02-2-config-schema.md`](02-2-config-schema.md).
- **Node 0 mechanics** — binderfs lifecycle, the verb dispatch, fd translation:
  [`02-4-binder.md`](02-4-binder.md).
- **Cross-instance `provide`/`consume` service mesh** — a *separate* capability (kennel reaching
  another kennel's already-running service), outside the dynamic-spawn model (§7.12.10). Dynamic
  spawn hands over a direct fd, so it needs no standing inter-kennel service registry.

## Open questions

- **`max_instances` default** — the concurrent-spawn ceiling when a `[spawn]` grant omits it.
- **The spawn-target memory ceiling** — a fixed framework floor, or always author-declared per
  template (the §7.12.6 requirement makes it mandatory; the question is the default).
- **Manifest-diff canonicalisation** — the diff `candidate ∖ manifest == template ∖ manifest` is
  computed over the resolved policy's leaf fields; the open detail is the canonical form the leaf
  comparison runs on (list-ordering for pool appends, subtree scoping) so that a semantically-empty
  write outside the manifest cannot read as equal.
- **Async-construction confirmation** — whether the early `spawn-<uuid>` reply is sufficient or a
  later `kennel.spawn.ready` signal on the channel is worth the added surface (default: no — boot
  success is observable as the tool responding; failure is observable as EOF).
