# Project Kennel — 0.3.0 plan

Status: **in flight** · Drafted: 2026-06-20 · Updated: 2026-06-21 · Targets: 0.3.0
Baseline: 0.2.0 (2026-06-20)

**Progress (2026-06-21).** Thrust 1 (W1–W2), Thrust 2 (W3–W5), and Thrust 4 · W9 are merged —
the whole spawn *policy/schema* surface (design + threat catalogue, the `[spawn]` grant +
eligibility, the `[[mutable]]` constraint family + patch validator, the signed single-leg template
set) plus address provisioning gated on inbound bind. Thrust 4 · W10 (spawn-latency
harness) is built and pulled ahead of Thrust 3 deliberately — the always-on boundary profile of the
*existing* construction path is the instrument that lands the spawn runtime, and re-measures it once
the SPAWN verb is in. Its payoffs so far — two real bring-up costs found and fixed: (1) a 170 ms
binder-teardown poll-out limiter, fixed with an eventfd waker (teardown 170 ms → 0.4 ms); and (2) the
dominant *construction* cost — the kennel's `cgroup.procs` task-migration write blocking ~13 ms on a
`cgroup_threadgroup_rwsem` RCU grace period (found by `strace -f`, not the trace spans, which the
journald sink perturbs) — fixed by birthing the kennel directly in its cgroup via
`clone3(CLONE_INTO_CGROUP)`. Net: spawn rate 3.2 → 7.3/sec, end-to-end `kennel run` 63 ms → 47 ms.
Next: **Thrust 3 · W6–W8** (the spawn runtime path). Per-workstream status is marked on each item below.

> This is a planning artefact, not a design or as-built document. The design corpus
> (`docs/design/`) and the as-built notes (`docs/architecture/08-as-built-notes.md`
> §8.1) remain the source of truth for *what each item is*; this file records *what
> 0.3.0 commits to, why, and in what order*. The dynamic-spawn design is
> [`docs/design/07-12-dynamic-spawn.md`](../design/07-12-dynamic-spawn.md) (§7.12); its
> architecture/implementation contract `02-10-dynamic-spawn.md` is written as-built across
> the spawn build (W1).

## Theme

**Dynamic spawn, reduced latency, less over-allocation.** Dynamic spawn is the driving
feature; the discipline it forces is *provision only what's consumed*, applied across three
surfaces:

- **Network:** provision per-kennel addresses only where an inbound bind consumes them
  (fixing over-allocation of the network surface).
- **Policy:** the mutable-field manifest replaces free-authored child policy with a few
  bounded blanks (fixing over-allocation of authority — selection, not synthesis).
- **Capability:** single-leg templates give each spawned kennel the minimum it needs (fixing
  over-allocation of capability per node).

It is one move at three layers — *"how can I do less"* — pointed directly at the spawn path.
Latency is the measurement that proves it: over-allocation has a runtime cost, and removing it
shows up on the profile. Dynamic spawn is what made the waste matter — it is the first workload
that exercises the spawn path hard enough for it to register.

One posture consequence, not the headline: because the spawned workload is an agent, the review
bar is higher than for any prior release. The red-team pass (Thrust 7) is budgeted as a
consequence of spawning adversarial workloads, not as a competing goal.

Standing constraints that shape the mix:

- **The TCB only shrinks** ([[tcb-only-shrinks]]). `kenneld` evaluates an ACL and brokers file
  descriptors for a spawn; it mounts nothing, parses no JSON, routes no bytes. MCP rides the
  channel as opaque JSON-RPC the daemon never frames or parses (§7.12.5). No spawn work may
  land a protocol parser in `cargo tree -p kenneld`.
- **No standing host privilege** ([[no-standing-host-privilege]]). Spawn instantiation reuses
  the existing privhelper *factory* (one validated op, then exit); it adds no lifetime-held
  capability.
- **Request, don't author** (§7.12.1, the load-bearing rule). A workload cannot introduce
  policy at runtime — it *names* an operator-signed template and writes only the fields the
  template's *mutable-field manifest* opens. No new policy is authored, so no new signature is
  needed; those manifest writes are the entire agent-controlled attack surface (§7.12.3).
- **Depth-1 is a hard rule** (§7.12.8). A spawn-target template may not carry `[spawn]`,
  refused at the spawner's install. This is a fork-bomb prohibition, not a deferred feature;
  there is no depth-N roadmap item.

## Workstreams

Sizes are rough: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week.
Tags: **[dep]** (0.3.0 is incomplete without it), **[debt]** (a tracked decision/doc that
rots if untracked), **[opt]** (real, cuttable to 0.4.0), **[non-goal]** (explicitly out).

### Thrust 1 — Design lock and threat catalogue (the foundation)

- **W1 · Promote the dynamic-spawn design + author the architecture contract.** **[dep] M.** · ✅ **done** (#56; `02-10` keeps growing as-built across W6–W8)
  The §7.12 design chapter is **promoted** into `docs/design/` (this plan's PR). The
  architecture/implementation contract **`02-10-dynamic-spawn.md`** — the `SPAWN` transaction,
  the FD-injection sequence, the manifest-diff validation point, the double reaper — is written
  *as-built* across W6–W8 ([[doc-layering-design-arch-code]]: architecture holds the as-built
  truth, so it grows with the code, not ahead of it). The thesis blockquote in §7.12 already
  points to it.

- **W2 · T3.9 lands in the catalogue, with the risk derivation.** **[dep] M.** · ✅ **done** (#57)
  Migrate the provisional §7.12.9 block into `THREATS.md` as **T3.9 — Delegated spawning**
  (workload-class, sibling to T3.8), add the machine entry to `dist/threats/catalogue.toml`
  (kept in sync by `src/tools/tests/threats-catalogue.sh`), and wire the **derivation**: the
  `[spawn]` grant derives T3.9 in `kennel-lib-policy::risks` the way `mode = host` derives T1.6
  — the grant is the tag, no stored `threats.reinstated` field. Carry both residuals (R1
  mutable-field surface, R2 delegated composition) and the compliance mapping (NIS2 21(2)(i)
  least-privilege + 21(2)(d) supply chain; DORA Art. 9/28). Once it lands, the §7.12.9
  blockquote becomes a cross-reference. Foundational: W3's risk derivation and W6's grant
  validation both reference the catalogued threat.

### Thrust 2 — Spawn policy surface (compiler, out of the TCB)

- **W3 · The `[spawn]` grant + spawn-eligibility rules.** **[dep] L.** · ✅ **done** (#58)
  `[spawn]` in `schema/policy.toml.schema` and `kennel-lib-compile`: the `max_instances`
  ceiling (fork-bomb bound), the `[[spawn.allow]]` template grant (+ optional per-requester
  `mutable` narrowing), and the T3.9 risk
  derivation. The compiler enforces **spawn-eligibility at the spawner's install**: when a policy
  carrying `[spawn]` is installed, each template it names in `[spawn.allow]` is refused if it (1)
  carries `[spawn]` itself (depth-1, §7.12.8 — fail-closed before any instantiation can reach it),
  or (2) fails to declare its own lifecycle bound (`max_lifetime`/reaper TTL), its resource ceilings
  (memory + pids + CPU), and its mutable-field manifest — whose worst-case patch (every `pool` at its
  `max`) must fit the binder transaction buffer, so an oversized manifest fails at install, not as a
  runtime transport error. (The gate runs at the spawner's install, not the target's — a template
  cannot know which future policy will name it.) *Instantiation is a manifest diff, not value synthesis.* All
  compiler-side — out of `cargo tree -p kenneld`.

- **W4 · Template `[[mutable]]` manifest grammar + instantiation-time patch validator.** **[dep] M.** · ✅ **done** (#59)
  The §7.12.3 attack surface — *selection, not synthesis*. The signed template is a complete
  runnable policy plus a `[[mutable]]` manifest naming which leaf fields may move, each with a
  **bound**: pool (`from` + `max` — append from a fixed set), `oneof` (pick from an enumerated
  list), or `predicate` (the loud free-value escape hatch — `type`/`under`, traversal-free,
  `RESOLVE_IN_ROOT`). The request is a **patch** (`(field-path, value)` pairs), not a full policy;
  `kenneld` rejects any field-path outside the (per-requester-narrowed) manifest, checks each value
  against its bound, and applies the survivors — establishing `candidate ∖ manifest == template ∖
  manifest` by key-membership, not a whole-tree diff (no adversarial policy parser in the daemon). Frozen
  fields (single-leg `net.mode`, ceilings, TTL) are not in the agent's write set, so no write can add a
  trifecta leg. Policy validation in the existing compiler — **not
  a new parser in the TCB**.

- **W5 · Signed single-leg template set + per-template tests.** **[dep] M.** · ✅ **done** (#60)
  A small Kennel-shipped set of spawn templates, each holding **at most one** trifecta leg, so
  composing them is a visible, signed operator act. Starting set:
  - `pure-compute` — code execution; `[net].mode = "none"` frozen; ephemeral tmpfs root; TTL +
    ceilings. Runs untrusted code, reaches nothing.
  - `net-fetch` — `[net].mode = "constrained"` frozen, fixed fetch entrypoint, no workspace fs.
    Reach without code.
  - `scratch-fs` — no net, no persistence; a predicate-bound workspace path. Data shuffling
    without reach.

  Each declares a **memory ceiling** (a spawn-target must, or an oversized `memfd` artifact is
  an unbounded-memory DoS — §7.12.6). Signed by the maintainer key, installed into the trust
  store, gated in CI per the W9-fragment-catalogue pattern (signature + compile-and-assert per
  template).

### Thrust 3 — Spawn runtime path (daemon, binder, init)

- **W6 · The `SPAWN` transaction verb on Node 0.** **[dep] L.** The keystone.
  In `kenneld/src/binder.rs`: grant + template pin/eligibility re-check + manifest-patch validation
  (W3/W4, all in the verify half — no `kennel-lib-compile` in the daemon), in-memory instantiation, and
  the channel handoff. **`kenneld` mints** the `socketpair()` (JSON-RPC) + `pipe()` (`stderr`), injects
  the spawned-kennel ends into the supervision plan, and **returns the requester's two ends in the
  reply** — so node 0 stays fd-free inbound and the [[binder-fd-passing-safety-verdict]] invariant (fds
  out of the TCB only) holds unbroken. Needs the small two-fd reply codec (`Reply::DataAndFds`); the
  daemon mounts nothing beyond the template's own view, parses no JSON, routes no traffic. (02-10 carries
  the outbound-only safety argument.)

- **W7 · Injected-stdio supervision + `kennel-bin-init` dup2.** **[dep] M.**
  `kennel-lib-spawn::Supervision` accepts injected stdin/stdout/stderr FDs; `kennel-bin-init`
  `dup2`s them onto the spawned kennel's stdio before `execve`ing the template's entrypoint
  (for MCP, a stdio JSON-RPC server). Init stays a dumb executor ([[init-is-dumb-executor]]) —
  every policy decision was made by `kenneld` pre-handoff.

- **W8 · Fate-sharing: the double reaper + `max_instances` accounting.** **[dep] M.**
  Soft reaper (data plane): requester `close()`s its channel ends → spawned tool gets `EOF`/
  `SIGPIPE` and exits → `kennel-bin-init` tears down. Hard reaper (control plane): `kenneld`
  tracks the binder session that issued the `SPAWN`; if it drops (requester crash/OOM/TTL),
  `kenneld` issues a `cgroup.kill` to the spawned kennel (reusing the TTL freeze/kill plumbing).
  The reaper that kills **decrements `max_instances`**, so a flapping requester cannot leak
  slots across teardown races.

### Thrust 4 — "Do less": over-allocation and latency (the discipline spawn forces)

- **W9 · Provision per-kennel addresses only where an inbound bind consumes them.** **[dep] M.** · ✅ **done** (#61)
  The trigger is **bind-list presence, not mode**: no bind list → an address-less net-ns. The
  empty-bind-list path is 100% of ephemeral tool spawns, so this eliminates address provisioning
  from the hot path entirely. Independent of the spawn build itself; lands in parallel.

- **W10 · Spawn-latency profiling harness.** **[dep] L.** · ✅ **done** (in flight: PR)
  Profile setup latency end-to-end across the five privilege-domain boundaries (kennel →
  kenneld → privhelper → bin-init → workload → teardown). *Built:* the spawn-path tracer
  (`kennel_lib_config::Tracer`) stamps every milestone with a wall-clock `[t=<nanos>]`
  (`CLOCK_REALTIME`, shared across the spawn-path processes), and `tools/spawn-latency.sh` drives N
  constructions of a policy-suite case against the **real installed** `kennel run`, parsing the
  milestone deltas into: a **per-boundary breakdown** (median + p90); **construction and teardown
  as separate first-class spans** (a slow reclaim makes spawn teardown-limited); **off-CPU hop
  attribution** via the `sched_switch` tracepoint (`--offcpu`, honestly split per-construction
  blocked-wait vs daemon idle-parking); **root-kind tagging** (tmpfs vs OCI); **spawn-rate-under-load**;
  and a **baseline/compare** (`--baseline`/`--compare`) that prints the **TCB latency delta as a
  runtime-behavioural signal** (a structural hot-path change shifts internal proportions even at flat
  absolute numbers) — the instrument that re-measures the SPAWN verb once Thrust 3 lands. The
  high-res function-level **XRay** deep-dive (`-Z instrument-xray`) is documented as a recipe
  (`--xray-recipe`): nightly + local-dev only, never the stable release path (CODING-STANDARDS §2.1).
  *First payoff:* the harness surfaced the teardown span at **170 ms** (≈10× construction) — the
  binder looper pool winding down only on its `POLL_MS=200` poll-out, `max` over 8 threads. An
  eventfd **`Waker`** added to the looper poll set (signalled on `stop`) cut teardown to **0.4 ms**
  and lifted the net-none spawn rate from **3.2 → 7.3 constructions/sec**; all 16 policy-suite cases
  stay green. *Follow-on increments (not gating):* off-CPU **stack** attribution (bpftrace
  `offcputime` flamegraphs) for the within-boundary waits, and per-boundary tagging by tmpfs-vs-OCI
  root in one run.

- **W11 · Skip the constrained-mode BPF egress attach.** **[opt] S.**
  In constrained mode the proxy already default-denies, so `[net.bpf]` egress is
  belt-and-suspenders; dropping it skips the privhelper BPF attach entirely. **Profile-gated:**
  surface only if W10 dictates; **do not bundle into W9** (address cleanup).

### Thrust 5 — OCI completion and the shared persistence store

- **W12 · First-party static in-kennel OCI unpacker.** **[dep] L.**
  Replace the `umoci` host dependency (the 0.2.0 interim) with a first-party static in-kennel
  unpacker over a vetted `tar` crate — no host prereq. In-kennel ⇒ static-linked
  ([[in-kennel-binaries-must-be-static]]); the unpack is adversarial-input parsing, so it runs
  at workload authority, never in the daemon closure. Completes the OCI fetch surface.

- **W13 · OCI carve-out preservation + the userns-map contract sentence.** **[debt] S.**
  `oci update` re-derives the base closure while preserving the operator's
  `[rootfs].readonly`/`writable` carve-out, surfacing the diff at re-sign. Plus the missing
  single-entry userns-map contract sentence in `02-9-oci.md`.

- **W14 · `.trust-manifest.d/<sha256>` content-addressed side store as a shared mechanism.** **[dep] M.**
  The 0.2.0 persistence store (the trust-manifest review/revert family) gets its **second
  consumer**: `oci revert` is defined as the
  *total* case of the store's selective revert (pin / diff-against-pin / restore-from-pin). One
  mechanism, two callers.

- **W15 · OCI integrity ladder + per-inode closure-derivation walk.** **[opt] M.**
  Rung 1 (content-addressed store entry, verified before pivot) and Rung 2 (fs-verity over
  `rootfs/` + `config.json`), opt-in behind the digest-pinned floor. Plus the per-inode
  closure-derivation walk that closes the two named gaps (gosu/su-exec reading as all-root; app
  code outside `/usr`|`/lib` staying writable). **May slip to 0.4** (the digest-pinned floor is
  the 0.3.0 minimum).

### Thrust 6 — Hygiene and descope

- **W16 · Remove X11.** **[dep] S–M.**
  Descope the `[x11]` design (already schema-rejected). **Grep architecture/design for anything
  that leans on display passthrough as a dependency before deleting**, so the descope doesn't
  strand a reference; reconcile the design index (07.8) and 08-as-built §8.1.

- **W17 · BPF-retained-over-Landlock-ABI4 decision record.** **[debt] S.**
  Record the *why*: Landlock ABI 4 network is TCP-port-only (no CIDR/address matching, no UDP);
  `[net.bpf]` is a CIDR+port ACL. Address-granular egress is inexpressible in a port-only
  mechanism, so BPF stays **by necessity**. Name the capability gap in the decision record.

- **W18 · Bastion sshd template → `/etc/kennel` cascade confirmation.** **[debt] S.**
  Confirm `/etc/kennel` fits the config cascade ([[no-hardcoded-paths-config-cascade]]):
  system-level root-owned config is legitimately `/etc`, but check it isn't an operator-config
  path that belongs under the XDG/per-operator cascade.

### Thrust 7 — Pre-ship

- **W19 · Spawn-surface threat-model / red-team pass.** **[dep, ship gate] M.**
  This is the riskiest release to date — delegated capability handed to prompt-injectable
  agents. The **R2 composition residual** (an agent that may spawn a network-capable tool and a
  filesystem-capable tool can bridge their channels and reconstitute the lethal trifecta across
  two kennels) is **accepted-and-tagged, not closed** — closing it would put cross-kennel
  information-flow reasoning in the daemon, a larger project. The ship gate is a deliberate
  review of the spawn surface, with R2 explicitly stated as the residual's load-bearing line.

- **W20 · Live topology surface.** **[dep] M.**
  A `kennel ps`-equivalent including ephemeral spawns and what-spawned-what — operating a fleet
  of agent-spawned workers is unmanageable without it, so it ships with the spawn set.

- **W21 · MCP interposer.** **[dep] M.**
  The in-kennel tool-filter/audit kennel from §7.12.5 — a small MCP-aware kennel the operator
  wires between requester and tool, parsing JSON-RPC *because it is confined and disposable, not
  because the daemon does*. The application-semantic mediation half of the spawn/MCP surface;
  operator-opt-in to *wire*, but shipped, not deferred.

## Sequencing

1. **Design lock first — W1 (promote design, this PR) + W2 (T3.9 catalogue).** W3's risk
   derivation and W6's grant validation both reference the catalogued threat and the settled
   transaction shape; settle the remaining open design questions (manifest-grammar defaults,
   reaper accounting, `max_instances` default) in `02-10` before W6 builds.
2. **Spawn policy surface — W3 → W4 → W5.** Compiler-only, out of the TCB, fully testable
   without the daemon; lands the schema both the templates and the runtime consume. W5 needs
   W3+W4.
3. **Spawn runtime — W6 → W7 → W8.** The daemon path. W6 is the keystone; W7/W8 hang off its
   FD-injection and session model. `02-10` (W1) is written as-built here.
4. **"Do less" — W9 in parallel** with the spawn build (independent net-ns change); **W10 ahead
   of Thrust 3** — the boundary harness lands against the existing construction path so it is the
   instrument that lands the spawn runtime, then re-measures the SPAWN verb once it exists; **W11
   only if W10's profile dictates.**
5. **OCI / persistence — W12–W15**, independent of spawn; slot against capacity. W14
   (`.trust-manifest.d`) pairs with W12 (`oci revert` is its total-revert case). W15 is opt and
   may slip.
6. **Hygiene — W16–W18 any time.** Do W16 (X11 removal) early to shrink the surface before the
   red-team pass reads it.
7. **Pre-ship — W19 last and gating**, after the whole spawn surface (W3–W9) exists. **W20
   (topology) and W21 (interposer) ship with the spawn/MCP set** — both are spawn-target/observer
   kennels that need the spawn runtime (W8), so they sequence after it; neither is optional.

## Exit criteria

0.3.0 ships when: dynamic spawn is built end-to-end (W3–W8) and proven by a policy-suite case
([[policy-test-suite-is-the-e2e]]) exercising request-don't-author, manifest-diff enforcement
(writes confined to the declared mutable fields, each within its bound), the depth-1 install-time
refusal, the double reaper, and the `max_instances`
ceiling; T3.9 is catalogued and risk-derived (W2); the single-leg template set is signed and
tested (W5); `02-10-dynamic-spawn.md` is written as-built (W1); per-kennel address provisioning
is gated on inbound bind (W9); the latency harness reports the five-boundary spawn profile and
the teardown span (W10); X11 is removed and the ABI4/BPF decision is recorded (W16/W17); and the
spawn-surface red-team pass is complete with the R2 composition residual explicitly
accepted-and-tagged (W19); and the **complete spawn/MCP agent-to-worker surface ships** — the
live-topology surface and the MCP interposer included (W20/W21), nothing in the set fenced or
deferred. CHANGELOG records every stable-surface change — the `[spawn]` / `[[mutable]]` policy
schema, any CLI surface, the `SPAWN` IPC verb, and the T3.9 threat-catalogue addition — per
CODING-STANDARDS §13/§14.

## Decisions taken (2026-06-20)

1. **Request, don't author.** A workload names a signed template and writes only the fields its
   `[[mutable]]` manifest opens; it cannot introduce policy at runtime (§7.12.1). The capability
   floor of every spawn is the signed template's, full stop.
2. **Depth-1 by hard rule, refused at the spawner's install** (§7.12.8). Not a deferred feature;
   there is no depth-N roadmap item.
3. **Kennel does not understand MCP** (§7.12.5). The `SPAWN`/FD primitive is a generic
   confined-stdio-service transport; MCP is an unparsed convention on top. Application-semantic
   mediation belongs in an opt-in in-kennel interposer (W21), never the daemon.
4. **A spawn-target template must declare a memory ceiling** (§7.12.6). Artifacts pass in memory
   as `memfd`s charged to the spawned kennel's cgroup; without a ceiling an oversized artifact
   is an unbounded-memory DoS.

## Open decisions for the maintainer

- **OCI first-party unpacker (W12): 0.3.0 `[dep]` or slip to 0.4 as `[opt]`?** 0.2.0 shipped
  `umoci` as the interim and flagged the first-party unpacker as a 0.3 follow-up. Listed here as
  `[dep]` (it completes the OCI surface), but it is the natural cut line if 0.3.0 gets tight —
  `umoci` works as the interim.
- **OCI integrity rungs (W15): in-scope or 0.4?** Marked `[opt]`/may-slip, as in 0.2.0 — the
  digest-pinned floor is the minimum.
- **W11 (skip constrained-mode BPF egress attach):** worth the defence-in-depth loss for the
  latency? Profile-gated — surface only if W10 dictates.
- **Defaults:** the `max_instances` default value; whether the spawn-target memory-ceiling floor
  is a fixed default or must always be author-declared.

## Non-goals (explicitly out of scope)

- **Depth-N spawning** — a hard prohibition (§7.12.8), not a deferred item.
- **Host-process-wants-a-kennel-on-a-pipe** — already served by `kennel run`; no host-side shim
  is built for it (§7.12.10).
- **MCP framing/parsing in the daemon** — a per-message mediation surface against the
  single-chokepoint invariant, and a spec dependency in the TCB (§7.12.5).
- **Closing R2 (delegated composition)** — cross-kennel information-flow reasoning in the daemon
  is a different and larger project; mitigated by `[spawn.allow]` scoping, not eliminated
  (T3.9 R2).
- **Continuous self-integrity / TOCTOU closure** — Kennel does not self-measure binaries or
  close the install-to-execve gap; confinement does not depend on them.

## Fenced to 0.4+

> The complete spawn/MCP agent-to-worker surface (§7.12) ships in 0.3.0 — the SPAWN verb, the
> template/var grant model, the reaper, the topology surface, and the MCP interposer (W3–W8,
> W20, W21). Nothing in that set is fenced; the dynamic-spawn model is bounded to single-hop
> kennel-to-kennel by design (§7.12.10), not by deferral.

- **Reproducible double-build + release image**; **multi-kernel BPF verifier matrix** —
  release-pipeline and kernel-matrix infra, deferred from prior releases.
- **§11.1 v2 design forks** — Wayland clipboard, GPU compute-only, TPM/FIDO per-key,
  comprehensive-seccomp template. Tracked, not scheduled.
