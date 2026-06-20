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
| **Requester workload** | its own kennel | Node 0 client (`SPAWN`) | Names the template + its mutable-field writes (carries no fds); receives its channel ends in the reply |
| **`kenneld`** | host (operator) | Node 0 context manager | Validates grant, pin/eligibility, and manifest patch; resolves the template, **mints the channel**, injects the spawned-kennel ends, returns the requester's ends, drives construction |
| **`kennel-privhelper`** | transient, per-spawn | — | Factory: clones the spawned kennel's namespaces, injects the channel fds, `fexecve`s `kennel-bin-init` ([[no-standing-host-privilege]]) |
| **Spawned sibling** | fresh kennel | Node 0 client (own instance) | Runs the template's entrypoint (for MCP, a stdio JSON-RPC server) with the injected fds as stdio |

The spawned kennel is a full kennel: its own binderfs instance, its own `kennel-bin-init` at uid 0,
its own view. It is constructed by the same privhelper factory as an operator-launched kennel
([[kennel-init-and-uid0]], [[spawn-userns-owner-yama]]); dynamic spawn adds the descriptor injection
and the lifecycle coupling, not a new construction path.

## The `[spawn]` grant and `SPAWN`-time validation

The agent controls exactly one thing: the writes it makes to the template's **mutable fields**. A
template is a *complete, signed, runnable policy* plus a declared `[[mutable]]` manifest naming which
leaf fields a spawn may write; everything outside the manifest is frozen and inherited verbatim
(§7.12.3). `kenneld` performs three checks at `SPAWN` time, all in the **verify half (`kennel-lib-policy`)
the daemon already links — never `kennel-lib-compile`**. The spawn-target template is signed *pre-resolved*
(its template chain folded at sign time), so instantiation is load-verify + patch-apply, not a compile, and
no policy compiler enters `cargo tree -p kenneld` ([[tcb-only-shrinks]]):

1. **Grant.** The requesting kennel's compiled policy carries its `[spawn]` ACL — the
   `[[spawn.allow]]` template set, `max_instances`, and an optional per-requester `mutable` list
   that *narrows* (never widens) the template's manifest for this requester. It is held in the
   kennel's `kenneld`-side runtime record from construction. A template not in the ACL is **denied**
   (`kennel.spawn` / `outcome: Deny`).
2. **Template pin + eligibility.** `kenneld` resolves the named template from the (mutable) trust
   store and verifies it against the **content-pin** the spawner's compiled policy recorded for it
   (fail-closed on mismatch), then **re-runs spawn-eligibility** (§7.12.8) on the resolved template.
   The install-time eligibility pass is fail-fast authoring feedback; *this* is the authoritative gate,
   because the trust store is mutable and a re-signed entry must not slip an ineligible target past a
   stale install-time result (a TOCTOU).
3. **Manifest patch.** The request carries the agent's writes as a **patch** — `(field-path, value)`
   pairs, never a full candidate policy. `kenneld` rejects any field-path not in the
   (per-requester-narrowed) manifest, validates each value against that field's **bound**, and applies
   the surviving writes onto the resolved template. The invariant established is `candidate ∖ manifest
   == template ∖ manifest`, but the enforcement is **key-membership on the patch**, not a whole-tree
   set-difference: a write whose value equals a frozen field's is still rejected for naming an
   out-of-manifest field, and no adversarial policy parser or deep tree-diff enters the daemon. Any
   out-of-manifest key is a hard reject, fail-closed. This inverts the surface from *synthesis* to
   *selection* — the agent fills fenced blanks in a sealed document, never authors a policy the daemon
   must parse.

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

**Spawn-eligibility is verified at `SPAWN`, not assumed from install** (check 2 above). The install-time
gate validates each named template at the *spawner's* compile — it carries no `[spawn]` (depth-1), and
declares its `max_lifetime`, resource ceilings (memory/pids/CPU), and `[[mutable]]` manifest; that gate
runs at the spawner's install, not the target's (a template cannot know which future policy will name
it, and depth-1 means no chain to walk). But that pass is **fail-fast authoring feedback**: because
`kenneld` resolves the template from the *mutable* trust store at `SPAWN`, the authoritative gate is the
content-pin verification plus the eligibility re-run on the resolved bytes (§7.12.8). So by the time
construction begins the target is *verified* eligible on the actual instantiated bytes — a non-spawner,
single-hop, bounded in lifetime and resources, with a fenced write surface.

## The `SPAWN` transaction

`SPAWN` is a Node 0 verb issued by the **requester workload** (operator uid, not `kennel-bin-init`),
so it is a facade-class verb dispatched without the registry lock — alongside `CONNECT_INET` /
`CONNECT_AFUNIX` ([`02-4-binder.md`](02-4-binder.md)) — **not** a lifecycle verb (the `0x100+`
range is gated `sender_pid == init_host_pid && sender_euid == 0`, which is `kennel-bin-init` only).

| Field | Direction | Encoding |
|---|---|---|
| `code` | req | `SPAWN` (facade range, next free verb code) |
| template | req | length-prefixed `name@version` (`<= MAX_NAME`) |
| mutable writes | req | count-prefixed `(field-path, value)` length-prefixed pairs — the manifest-field patch |
| flags | req | `TF_ACCEPT_FDS` set so the reply may carry fds; the request itself carries **none** |
| reply | rep | status + transient `spawn-<uuid>` + **two `BINDER_TYPE_FD`**: the socketpair local end (workload stdin+stdout) and the pipe read end (workload stderr) |

The requester carries no descriptors; it sets `TF_ACCEPT_FDS` so the reply may return them. `kenneld`
mints the `socketpair()` (bidirectional JSON-RPC) and the `pipe()` (the spawned kennel's `stderr`, on a
separate descriptor so unstructured error text never corrupts the framed channel — §7.12.5), injects the
spawned-kennel ends into construction, and returns the requester's two ends in the reply. This extends the
node-0 reply codec, which today returns a single fd (`Reply::Fd` / `DataAndFd`), to carry two — a small
`Reply::DataAndFds` addition, the same multi-offset shape the transaction encoder already has.

### Outbound descriptors only — the safety argument

Because `kenneld` mints the channel, **no descriptor ever flows into node 0.** Node 0 keeps the plain
`BINDER_SET_CONTEXT_MGR` registration with the accepts-fds flag *unset*, so the kernel refuses any inbound
fd on any verb before a handler sees it — the [[binder-fd-passing-safety-verdict]] invariant (fds flow
*out* of the TCB only) holds unbroken, and there is no daemon-wide fd-translation surface to bound. The
only fd movement is outbound:

- **Into construction.** The spawned-kennel ends are injected through the existing supervision-plan path
  ([[kennel-init-and-uid0]]) — the same outbound mechanism that already places the pty and workload fds.
- **Into the reply.** The requester's two ends ride the `SPAWN` reply, which the requester opted into with
  `TF_ACCEPT_FDS`; the kernel translates them into the requester's table. A requester receiving the
  channel it asked for is the trusted direction.

The rejected requester-mints alternative would have published `FLAT_BINDER_FLAG_ACCEPTS_FDS` on node 0
(via `BINDER_SET_CONTEXT_MGR_EXT`) and paid an fd-translation DoS on *every* node-0 verb — the kernel dups
a sender's fd objects into `kenneld`'s table before any handler runs, bounded only by the transaction
buffer (`MAP_SIZE`) and `RLIMIT_NOFILE`, not by the two `SPAWN` needs. Minting in `kenneld` removes that
surface outright. The cost paid instead is the bounded one §7.12.9 names — the channel mint and the
verify-half `SPAWN` validation — in the daemon, where it is reasoned about, not at an inbound-fd boundary.

## The capability handoff (construction)

On a validated `SPAWN`, `kenneld`:

1. **Resolves, mints, and replies.** `kenneld` resolves the template in memory, pin-verifies it, and
   applies the validated patch — no child policy is ever written to disk (§7.12.1, §7.12.6); the
   instantiation is the signed template with the manifest blanks filled. It then **mints the channel**
   (`socketpair()` + stderr `pipe()`) and returns the requester's two ends with the `spawn-<uuid>` in the
   reply, before construction proceeds (below).
2. **Builds the supervision plan** with the two injected descriptors recorded as **presence flags**.
   The plan codec (`kennel-lib-spawn`) carries fds out-of-band via `SCM_RIGHTS` in a fixed order and
   records only a `bool` per fd in the wire bytes — the established pattern for the pty and
   sha256-pinned-workload descriptors. Three new presence flags are added (`stdin`/`stdout`/`stderr`
   injected), and three new fixed descriptor slots follow the existing `pty=3` / `boot-sync=4` /
   `workload=5` assignment. The privhelper pops the flagged fds in order and `dup_onto`s them to
   their slots before `fexecve`. *(W7. Adding required fields to the settled `Supervision` /
   `ConstructionHalf` structs touches every plan fixture across crates — a single coordinated
   commit, per the §8.3 settled-schema gotcha.)*
3. **`kennel-bin-init` places the injected slots onto stdin/stdout/stderr as the final step before
   `execve`, after the seal** — not before it. A dynamically-spawned tool is non-interactive (it speaks
   JSON-RPC over stdio), so it takes the injected-fd path, not the pty-allocation path. The ordering is
   load-bearing: init keeps its *own* stderr on a host-side descriptor (the boot-sync channel) throughout
   construction and sealing, so a Landlock/seccomp failure — or a panic — during the seal writes to the
   host audit, never the agent's pipe; the injected fds reach 0/1/2 only as init hands control to the
   tool. (The spawn-template seccomp profile must therefore permit the `dup3`/`execve` that close out the
   placement.) Init makes no policy judgment here ([[init-is-dumb-executor]]); the descriptors and their
   disposition were decided by `kenneld` pre-handoff.

### Construction is asynchronous to the reply

The `SPAWN` reply returns **after validation and channel minting, not after the spawned kennel boots.**
`kenneld` validates the grant, pin/eligibility, and manifest patch, claims the slot, mints the channel,
returns the requester's two ends and the `spawn-<uuid>` in the reply, and enqueues the construction; the
heavy build (privhelper factory, namespace clone, `pivot_root`, init exec) proceeds off the binder looper.
Rationale:

- The Node 0 looper pool is bounded (`POOL_MAX_THREADS`); holding a looper for a full kennel
  construction would let concurrent spawns exhaust it. Returning early keeps `kenneld`
  control-plane and decouples looper occupancy from construction latency (a W10 concern).
- The requester does not need to block on boot: it writes into its local socketpair end, which
  buffers until the spawned tool reads. A construction *failure* surfaces to the requester as
  **EOF on the channel** (the soft-reaper path below) plus a `kennel.spawn` / `outcome: Deny` audit
  event — the same way a tool that exits surfaces.

## Spawn sequencing

1. Requester sends `SPAWN(template@version, mutable-patch)` to Node 0, carrying **no fds**, with
   `TF_ACCEPT_FDS` set.
2. `kenneld` validates the grant, pin/eligibility, and manifest patch, and **atomically claims a
   `max_instances` slot** under the Node 0 accounting lock (§7.12.7) — deny, or ceiling full → reply +
   audit.
3. `kenneld` **mints** the `socketpair()` + stderr `pipe()` and replies with `spawn-<uuid>` + the
   requester's two ends (socketpair local, pipe read).
4. `kenneld` enqueues construction; the privhelper factory clones namespaces and injects the
   spawned-kennel ends (socketpair remote, pipe write) into the supervision plan at the new fixed slots.
5. `kennel-bin-init` boots the sibling, **seals it, then** places the injected ends onto
   stdin/stdout/stderr as the final pre-`execve` step (its own diagnostics on the host channel
   throughout), and `execve`s the template entrypoint.
6. Data flows kernel-to-kernel over the socketpair; `kenneld` and binder are out of the byte path.

## Fate-sharing, self-reap, and slot accounting

A spawned kennel must not outlive its purpose; the coupling is `kenneld`-brokered, not parental
(§7.12.7).

- **Soft reaper (data plane).** The requester `close()`s its local ends; the spawned tool receives
  `EOF` on stdin / `SIGPIPE` on stdout and exits; `kennel-bin-init` tears the kennel down. The
  graceful path, and the path a construction failure also takes.
- **Hard reaper (control plane).** `kenneld` tracks the **binder session** that issued the `SPAWN`
  (the requester's Node 0 connection). If that session drops — requester crash, OOM, the *requester's*
  TTL expiry — `kenneld` issues a `cgroup.kill` to the spawned kennel, reusing the TTL freeze/kill
  plumbing ([`05-state-and-supervision.md`](05-state-and-supervision.md)). The backstop for a tool that
  ignores `EOF`.
- **Self-reap (the spawned kennel's own lifetime, §7.12.7).** Independent of the requester: the spawned
  kennel inherits the template's declared `max_lifetime` (a spawn-eligibility precondition, §7.12.8), and
  the standard TTL reaper applies it directly — so the tool cannot run past its declared life even if the
  requester holds its session open forever. Same `cgroup.freeze`/`cgroup.kill` plumbing.
- **Slot accounting — claim, not check (§7.12.7).** `max_instances` is enforced by an **atomic
  check-and-claim**: a single Node 0 accounting-lock operation validates the ceiling *and* increments the
  live count, taken at validation (step 2) **before** the reply and the asynchronous construction enqueue.
  Deferring the check to construction would let two concurrent `SPAWN`s on different loopers both pass a
  ceiling they jointly exceed; under the lock the second sees the first's claim. The slot is held from
  claim until **release on any terminal outcome**: a reaper release on teardown, *and* a release by the
  construction worker — which holds the claim as an RAII guard — if the build aborts before the spawned
  kennel reaches the reaper subsystem (a failed `clone`/`pivot_root`/init exec). A boot failure therefore
  cannot permanently leak a slot, and a flapping requester cannot leak slots across teardown races.
  `max_instances` is global (depth-1 keeps it so, not per-node).

## Ephemerality and identity

- **In-memory instantiation, no host trace** — no child policy on disk (§7.12.6).
- **Transient identity** — spawned kennels take `spawn-<uuid>` names; they consume no operator
  registry namespace and cannot collide with an operator-named kennel.
- **No persistence** — the root is an ephemeral `tmpfs`, or an OCI image at `persistence = "discard"`
  ([`02-9-oci.md`](02-9-oci.md), §7.11.4a). The spawned kennel's **resource ceilings** (memory/pids/CPU)
  are a spawn-eligibility precondition checked at the spawner's install (§7.12.8), independent of any
  artifact path; the `memfd` artifact transfer below is one consumer of the memory bound, not its reason
  for existing.

> **`memfd` artifact transfer is roadmap, not first-build.** The stdio channel + control handoff
> above is the W6–W8 core. The in-memory `memfd` artifact path (§7.12.6) is net-new plumbing with no
> existing analogue in the spawn path; it is specified and built after the stdio core proves out.

## Audit events

| Event | Emitted when |
|---|---|
| `kennel.spawn` (`outcome: Allow`) | a validated `SPAWN` is accepted and construction enqueued |
| `kennel.spawn` (`outcome: Deny`) | grant, pin/eligibility, or manifest-patch validation fails, or construction fails |
| `kennel.spawn.reaped` | soft or hard reaper tears the spawned kennel down (with which path) |

## Threat bearing

Defends the dynamic-spawn delegation as **T3.9 — Delegated spawning** (workload-class, derived from
the `[spawn]` grant the way `mode = host` derives T1.6; W2). What holds: the capability floor of
every spawn is the signed template's; the requester holds no `ptrace`/signal reach; `kenneld` brokers
fds outbound and parses no JSON; the TCB grows only by the bounded verify-half `SPAWN` validation and the
channel mint — never a compiler or MCP parser (§7.12.9). The waived residuals: **R1** — the mutable-field
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
- **Spawn-eligibility defaults** — the resource ceilings (memory/pids/CPU) and `max_lifetime` are
  mandatory spawn-eligibility declarations (§7.12.8); the open question is whether each carries a
  framework default when a template omits it, or eligibility hard-requires an explicit value.
- **Per-field value normalisation** — patch key-membership removes the whole-tree-diff canonicalisation
  concern; the residual is normalising each patched *value* before its bound check (CIDR/host canonical
  form for a `pool` membership test, path normalisation for a `predicate`), so an
  equivalent-but-differently-spelled value cannot dodge or spoof the bound.
- **Async-construction confirmation** — whether the early `spawn-<uuid>` reply is sufficient or a
  later `kennel.spawn.ready` signal on the channel is worth the added surface (default: no — boot
  success is observable as the tool responding; failure is observable as EOF).
