# §7.12 Policy surface: dynamic spawning and MCP transport

> **A confined workload can ask `kenneld` to spawn a constrained, ephemeral sibling kennel and
> hand it a stdio channel — without authoring policy, and without `kenneld` entering the byte
> path.** The workload names an operator-signed template and writes only its operator-declared
> mutable fields; `kenneld` instantiates it in memory, passes the file descriptors across the `SPAWN`
> transaction, and steps out. MCP rides the channel as opaque JSON-RPC; Kennel neither frames nor
> parses it. The spawned kennel's lifecycle is coupled to the requester's binder session and reaped
> on its death. Spawning is a loud, operator-declared capability (T3.9). The concrete shape — the
> `SPAWN` transaction, the FD-injection sequence, the reaper — is the implementation contract in
> [`02-10-dynamic-spawn.md`](../architecture/02-10-dynamic-spawn.md).

An AI agent is useful only with both code execution and network reach, and granting one workload
both is the breach the lethal trifecta describes: a prompt-injected agent with private-data access
and an exfiltration path. The industry's answers are a VM per task (Firecracker — heavy
orchestration) or Docker-in-Docker (root-equivalent, leaky). Kennel already has the cheaper
primitive: a workload that holds *neither* capability itself can instantiate a separate, tightly
scoped kennel that holds *one*, and wire a channel to it. The agent stays network-less and
code-execution-less; the tool kennel executes code with no network, or reaches the network with no
code-execution grant; the agent never holds both at once, and neither does any single spawned
kennel. This chapter is the model that makes that delegation safe (§7.12.2–§7.12.4), the data path
that keeps `kenneld` out of it (§7.12.5), and the trust the operator declares when they grant it
(§7.12.3, §7.12.9).

## 7.12.1 Request, don't author

The load-bearing rule, and the one the rest of the chapter rests on: **a workload cannot introduce
policy at runtime.** It can only *name* an operator-signed template and write the fields that template's
manifest declares mutable. The template was signed when the operator installed it into the trust store; the
agent's `SPAWN` is a reference to capability the operator already consented to, not a new grant.

This is why dynamic spawning does not weaken the signature model the way an in-RAM "build a child
policy on the fly" path would. No new policy is authored, so no new signature is needed — the
signature was checked at install time, on the template. Ephemerality (the instantiation never
touches host disk, §7.12.6) and consent (the template is signed) are *separate* properties: the
first is about leaving no trace, the second about authority, and neither is asked to do the other's
work. The agent controls exactly one thing — the writes it makes to the template's mutable
fields — and that surface is the entire attack surface of a spawn (§7.12.3).

Spawning is lateral, as everything in Kennel is. `kenneld` is the spawner; the requesting kennel and
the spawned kennel are siblings joined by an FD channel and a `kenneld`-brokered lifecycle coupling,
not a parent that owns a child. The requester cannot `ptrace`, signal, or otherwise reach into the
spawned process — if it could, the isolation the spawn exists to create would be defeated at the
moment of creation.

## 7.12.2 The `[spawn]` grant

A workload that may instantiate siblings declares it, and the grant is loud (T3.9): delegated
instantiation is a capability the operator extends deliberately, derived into `kennel policy risks`
the way `mode = host` derives T1.6.

```toml
[spawn]
max_instances = 8                 # concurrent ceiling; fork-bomb bound

[[spawn.allow]]
template = "net-fetch@v1"          # exact, versioned, trust-store template
# mutable = ["net.allow"]         # optional: sub-scope which of the template's
                                  # manifest fields this requester may write
                                  # (default: the template's full manifest)
```

The requester names *which* signed templates it may instantiate, and optionally
*which of each template's mutable fields* it may write (§7.12.3). It does not name
capabilities — those live in the template. If `net-fetch@v1` fixes `[net].mode`
frozen, no `[spawn]` grant and no mutable-field write can change it: the compiler
denies any capability the template does not grant, and the agent writes only the
fields the manifest opens. The capability floor of every spawn is the signed
template's, full stop.

## 7.12.3 The mutable-field surface

A template is not a constraint over values authored by the agent. It is a **complete, signed,
runnable policy, plus a declared manifest of which fields an autogen or child step may write.**
Everything outside the manifest is frozen and inherited verbatim. The spawn request carries the
agent's writes to the manifest fields and nothing else, and the compiler accepts the candidate
**iff it differs from the template only within the manifest** — `candidate ∖ manifest == template ∖
manifest`, any write outside the manifest a hard reject, fail-closed.

This inverts the surface from *synthesis* to *selection*, which is the single most useful thing for
making agent-generated policy tractable. The agent does not author a policy the validator then
checks; it fills a few labelled, fenced blanks in a sealed document, and the compiler proves it
filled only the blanks. Membership in a constrained surface is a far smaller and harder-to-fool
check than satisfaction of a predicate over an open value space, and an LLM cannot squeak a novel
grant through by finding a value that technically passes — the field it would need to write is
frozen, not in its write set.

Each manifest field carries its own **bound**; "mutable" means writable *within that bound*, never
free. A mutable `net.allow` that accepts `0.0.0.0/0` defeats the purpose, so the bound is part of
the signed declaration. Three bound kinds cover the cases, and they are one mechanism, not three:

```toml
# net-fetch@v1 (operator-signed): a full policy with [net].mode = "constrained" frozen
# and net.allow empty, plus the manifest naming what may move —

[[mutable]]
field = "net.allow"          # pool + max: the agent appends, drawn from a fixed pool
from  = ["10.0.0.0/8", "ghcr.io", "pypi.org"]
max   = 16

[[mutable]]
field = "rootfs.writable"    # oneof: the agent picks from an enumerated member list
oneof = ["/usr/lib/python3.12", "/opt/app/cache"]

[[mutable]]
field = "fs.workspace"       # predicate: the runtime-relative escape hatch (below)
type  = "relpath"            # traversal-free, RESOLVE_IN_ROOT at instantiation
under = "workspace"
```

The **predicate** kind is the old free-variable case, demoted to what it is — the minority escape
hatch for a value that genuinely cannot be enumerated or pooled at sign time, such as the agent's
actual working subpath. It is the loud one: most templates are pure pool/oneof selection and carry
*zero* agent-authored free text, so the open-value residual (R1, §7.12.9) attaches only to templates
that declare a predicate field, not to instantiation in general. The recommendation is variants and
allowlists by default, a predicate field by exception and with justification.

The frozen set is what carries the invariants. The single-leg property (§7.12.2), the resource
ceilings, and the TTL live in frozen fields — `net.mode`, the absence of an `[fs]` root grant, the
cgroup limits — so no manifest write can add a trifecta leg, lift a ceiling, or escape the TTL,
because those fields are not in the agent's write set. Mutability is scoped to the leg-safe degrees
of freedom by construction: filling `net.allow` extends reach *within* the one leg the template
already granted, never across to a second. Single-leg is enforced once, at the floor; the manifest
flexes underneath it.

The unit of mutation is the leaf field (or an explicitly scoped subtree), enforced by the diff, so a
manifest opening `net.allow` cannot be used to rewrite `net.mode` beside it. The signed artifact is
*template + manifest*; the requester's `[spawn.allow].mutable` may narrow the manifest further per
requester (§7.12.2), never widen it.

## 7.12.4 The capability handoff

The requester provisions the channel, then references it in a single `SPAWN` transaction; there is no
routing binary and no facade, because there is no host process that owns the pipe — the requester is
a kennel and the FD rides the transaction directly.

1. The requester creates a `socketpair()` (bidirectional JSON-RPC: a local end it keeps, a remote end
   it will hand over) and a `pipe()` (the spawned kennel's `stderr`, kept separate so unstructured
   error text never corrupts the framed channel — §7.12.5).
2. It sends a `SPAWN` transaction to `kenneld` naming the template and its mutable-field writes,
   attaching the socketpair-remote and pipe-write ends as `BINDER_TYPE_FD` objects.
3. `kenneld` validates the grant and diffs the candidate against the manifest (§7.12.3), resolves the
   template from the trust store, builds the instantiation in memory, and injects the translated FDs
   into the spawned kennel's supervision plan.
4. `kennel-bin-init` boots the spawned kennel, `dup2`s the injected FDs onto stdin/stdout/stderr, and
   `execve`s the template's entrypoint — for MCP, a stdio JSON-RPC server.

`kenneld` evaluates an ACL and brokers file descriptors. It mounts nothing for the spawned kennel
beyond the template's own view, parses no JSON, and routes no traffic.

## 7.12.5 The data plane: Kennel out of the byte path, MCP opaque

Once the spawned kennel is running, `kenneld` and binder are gone from the data path. The spawned tool
reads and writes JSON-RPC natively over stdio; the requester reads and writes its local socketpair end
directly; bytes flow kernel-to-kernel with no daemon in the middle. This is the same discipline as the
net proxy's data path — `kenneld` brokers the channel and stays control-plane only — and it carries the
same TCB argument: a protocol parser that co-evolves with the MCP specification never sits next to the
daemon.

**Kennel does not understand MCP, and that is deliberate.** The `SPAWN`/FD primitive is a generic
confined-stdio-service transport; MCP is a convention on top of it that Kennel cannot see, exactly as
an LSP server or any other JSON-RPC-over-stdio tool would ride the same channel. Teaching `kenneld`
`tools/call` would be the error the project refuses elsewhere — a per-message mediation surface against
the single-chokepoint invariant, and a spec dependency in the TCB. Application-semantic mediation
(tool allow-listing, audit) belongs in an *opt-in in-kennel interposer*: a small MCP-aware kennel the
operator wires between requester and tool, parsing JSON-RPC because it is confined and disposable, not
because the daemon does.

`stderr` on its own pipe is the one detail worth stating explicitly: a traceback, compiler warning, or
panic in the spawned tool flows out a separate descriptor, so the framed JSON-RPC channel is never
corrupted by unstructured text, and the requester can capture the exact error and feed it back to the
model.

## 7.12.6 Ephemerality

A spawned kennel leaves no host trace, and that property is independent of the trust argument (§7.12.1).

- **In-memory instantiation.** The template is resolved from the trust store and the instantiation
  built in RAM; no child policy is ever written to disk, because no child policy is ever authored.
- **Transient names.** Spawned kennels take transient identifiers (`spawn-<uuid>`); they consume no
  operator registry namespace and cannot collide with an operator-named kennel.
- **No persistence.** The root is an ephemeral `tmpfs`, or an OCI image at `persistence = "discard"`
  (§7.11.4a). The spawned kennel cannot write host disk. Artifacts pass in memory as `memfd`s over the
  channel, charged to the spawned kennel's memory cgroup. The **memory ceiling** that bounds them is not
  a `memfd` detail: it is one of the spawn-eligibility preconditions every spawn-target template declares
  (§7.12.8), so the cgroup is bounded whether or not any artifact is ever transferred. The `memfd` path
  is one consumer of that bound, not its reason for existing.

## 7.12.7 Fate-sharing, self-reap, and slot accounting

A spawned kennel must not outlive its purpose. Two triggers couple it to the requester
(`kenneld`-brokered, not parental — the double reaper); a third bounds it on its own; all three run on
the one `cgroup.freeze`/`cgroup.kill` plumbing.

- **Soft reaper (data plane).** When the requester is done it `close()`s its local channel ends; the
  spawned tool receives `EOF` on stdin / `SIGPIPE` on stdout and exits, and `kennel-bin-init` tears the
  kennel down. The graceful path.
- **Hard reaper (control plane).** `kenneld` tracks the binder session that issued the `SPAWN`. If that
  session drops — requester crash, OOM, the *requester's* TTL expiry — `kenneld` issues a `cgroup.kill`
  to the spawned kennel, terminating it regardless of whether the tool honoured `EOF`. The backstop for
  a hung tool.
- **Self-reap (the spawned kennel's own lifetime).** Independent of the requester: every spawn-target
  template declares a `max_lifetime` (a spawn-eligibility precondition, §7.12.8), and the standard TTL
  reaper applies it to the spawned kennel directly. An agent that spawns a tool and holds its session
  open forever still cannot run the tool past its declared life — the spawned kennel reaps itself at its
  own TTL, regardless of the requester's session.

**Slot accounting is a claim, not a check.** `max_instances` is enforced by an atomic *check-and-claim*:
validating the ceiling and incrementing the live count are a single indivisible operation under a Node 0
accounting lock, taken *before* the spawn is enqueued for construction. Because the `SPAWN` reply is
asynchronous to the build (§7.12.4), the check cannot be deferred to when construction completes — two
concurrent `SPAWN`s on different loopers would otherwise both pass a ceiling they jointly exceed. Under
the lock, the second to acquire it sees the first's claim. A slot is held from claim until a reaper
releases it on teardown; a kill-path release decrements the count, so a flapping requester cannot leak
slots across teardown races.

## 7.12.8 Depth-1 and spawn-eligibility

Spawning is **depth-1, by rule, not by default**: a template reachable as a spawn target may not
carry `[spawn]`. This is a fork-bomb prohibition, not a deferred feature. Recursion would turn
`max_instances` from a global ceiling into a per-node one — N levels deep the bound is
`max_instances`^N — so the rule keeps the ceiling global by construction and the hard-reaper coupling
a single hop (the requester's session, never a chain a cascade would have to walk). There is no
depth-N roadmap item; multi-level delegation is out of the model.

Depth-1 is one clause of **spawn-eligibility**, the preconditions a template must satisfy to be
nameable as a spawn target. A spawn-eligible template:

- carries no `[spawn]` of its own (depth-1, above);
- declares its own **lifetime bound** (`max_lifetime` — the §7.12.7 self-reap);
- declares its **resource ceilings** (memory, pids, CPU — the cgroup limits that keep a spawn bounded,
  independent of any artifact path); and
- declares its **`[[mutable]]` manifest** (§7.12.3), so the agent's write surface is the fenced one.

Eligibility is checked **at the spawner's install, not the target's**. When a policy carrying `[spawn]`
is installed or compiled, every template it names in `[[spawn.allow]]` is validated against the
preconditions above — fail-closed, before any instantiation can reach it. The direction matters: the
gate cannot run at the target's install, because a template cannot know, when it is installed, which
future policy will name it; and depth-1 means there is no chain, so there is nothing transitive to walk.
If A names B, the check runs when A is installed and rejects A if B is ineligible.

## 7.12.9 Security posture — what holds, what is waived

**What holds.** The spawned kennel receives no ambient authority *from the requester* beyond the file
descriptors handed across the `SPAWN` transaction; its base capability is the signed template's and
nothing more. The requester holds neither `ptrace` nor signal reach into it. `kenneld` mounts nothing,
parses no JSON, and routes no bytes for it — the daemon evaluates an ACL and brokers FDs, so the TCB is
the size it was. The whole multi-kennel topology is operator-consented: every template is signed, and
every `[spawn]` grant is a loud, declared, risk-derived capability.

**What is waived, T3.9.** Spawning is the delegation of instantiation to a workload, catalogued as a
T3-family residual (workload-class — a workload that instantiates workloads, the sibling of containers
at T3.8), derived from the `[spawn]` grant the way T1.6 derives from `mode = host`:

- **The mutable-field surface is agent-controlled.** The requester writes the fields the template's
  manifest opens (§7.12.3), and the strength of the boundary is exactly the strength of the per-field
  bounds. An under-bounded mutable field in a signed template is the residual's sharp edge — the
  operator signing a template with a manifest is signing its per-field bounds as load-bearing.
  Pure pool/oneof manifests carry no agent free text; a predicate field is the loud exception.
- **Delegated reach is the requester's to compose.** A requester that may spawn a network-capable tool
  and a filesystem-capable tool, and bridge their channels itself, can reconstitute the trifecta across
  two kennels even though no single kennel holds both legs. Kennel bounds each spawned kennel to its
  template; it does not bound what an agent composes from several. The operator's defence is the grant:
  scope `[spawn.allow]` to the templates a given agent actually needs, and the composition surface
  shrinks with it.

The posture claim is confinement and consented delegation, not control over what the agent does with
the tools it is permitted to spawn.

> **Provisional T3.9 catalogue entry** — drafted here pending the THREATS pass; migrates verbatim to
> `THREATS.md` when the catalogue entry lands, at which point this block is replaced by a cross-reference.
>
> **T3.9 — Delegated spawning.** A workload holding `[spawn]` instantiates ephemeral sibling kennels
> from operator-signed templates and hands them file descriptors (§7.12). The capability delegates
> *instantiation* to a workload that, for an AI agent, is itself untrusted and prompt-injectable. The
> exposure is **derived** from the `[spawn]` grant — `kennel policy risks` reports it with the grant as
> carrier and the operator's `reason`, the path `mode = host` uses for T1.6 — with no stored
> `threats.reinstated` field; the grant is the tag. Workload-class family, sibling to T3.8.
>
> *Adversary.* A compromised or prompt-injected spawning workload. It cannot author policy or invent
> capability — every spawn floors at the signed template (§7.12.1), and the compiler denies any
> capability the template does not grant. It controls two inputs only: the mutable-field writes it
> supplies, and the composition of the tools it is permitted to spawn.
>
> *Mitigations in place.* Request-don't-author (the capability floor is the signed template, not
> agent-supplied policy); a frozen template plus a mutable-field manifest, the candidate diffed against
> the template and accepted only if it differs within the manifest, each field within its bound (§7.12.3);
> depth-1 and spawn-eligibility (lifetime, ceilings, manifest) checked at the spawner's install (§7.12.8);
> the `max_instances` ceiling enforced by atomic check-and-claim, the fate-sharing double reaper, and the
> spawned kennel's own-lifetime self-reap (§7.12.7); ephemerality, no host persistence (§7.12.6).
>
> *Residuals.*
> - **R1 — mutable-field surface.** The boundary is exactly as strong as the template's per-field
>   bounds; an under-bounded mutable field (a `net.allow` whose pool is too wide, a predicate field that
>   admits traversal) is the residual's edge. Pure pool/oneof manifests reduce this to closed-set
>   selection — the agent writes no free text; a predicate field is the loud exception that reintroduces
>   an open value, and the bound (typed, traversal-free, `RESOLVE_IN_ROOT`) is what holds it.
>   Operator-owned: signing a manifest signs its per-field bounds as load-bearing.
> - **R2 — delegated composition.** Kennel bounds each spawned kennel to its template but does not
>   bound what an agent composes across several; an agent permitted to spawn a network-capable tool and
>   a filesystem-capable tool can bridge their channels and reconstitute the lethal trifecta across two
>   kennels though no single kennel holds both legs. **Not mechanically closed** — closing it would put
>   cross-kennel information-flow reasoning in the daemon, a different and larger project. Mitigated, not
>   eliminated, by scoping `[spawn.allow]` to the templates an agent actually needs. This is the line
>   that carries the residual's weight.
>
> *ATT&CK (tactic-level, best-effort).* The control contains Execution (TA0002) to the template's grant
> and resists Privilege Escalation via the depth-1/no-author rules; the unclosed R2 maps to Exfiltration
> (TA0010, T1041 — over an agent-bridged channel). Refine to technique level in the catalogue pass.
>
> *Compliance (to confirm in the mapping pass).* NIS2 21(2)(i) access control / least privilege (the
> `[spawn.allow]` scoping is the least-privilege control); NIS2 21(2)(d) supply chain where templates
> are third-party; DORA Art. 9 (prevention) and Art. 28 (third-party) by the same reading as T3.8.

## 7.12.10 Scope: kennel-to-kennel by definition

Dynamic spawn is a **kennel-to-kennel** function — one kennel opening another — and that is the whole
of it. The other MCP topology, a host process that wants a kennel on a pipe, is not a deferred item
here: the host already has `kennel run` and can pipe stdio to it directly if it insists. That is
neither a design objective of this chapter nor an encouraged pattern, and there is no host-side shim
to build for it. Stating the boundary this way keeps 0.3.0 from growing a second mechanism for a case
that is already served, badly enough to discourage, by an existing verb.

## 7.12.11 Roadmap implementation steps

1. `[spawn]` in `schema/policy.toml.schema` and `kennel-lib-compile`, with the `max_instances` ceiling,
   the `[[spawn.allow]]` template grant (+ optional per-requester `mutable` narrowing), and the T3.9 risk
   derivation; the compiler refuses, **at the spawner's install**, any template a `[[spawn.allow]]` names
   that is not spawn-eligible — carries `[spawn]` (depth-1), or fails to declare its `max_lifetime`,
   its resource ceilings, or its `[[mutable]]` manifest (§7.12.8).
2. Template `[[mutable]]` manifest grammar (the three bound kinds: pool+`max`, `oneof`, predicate) and
   the instantiation-time diff validator (`candidate ∖ manifest == template ∖ manifest`, each field within
   its bound, writes outside the manifest hard-rejected) — the §7.12.3 attack surface.
3. The `SPAWN` transaction verb on Node 0 (`kenneld/src/binder.rs`): grant + manifest-diff validation,
   in-memory template resolution, FD translation and injection.
4. `kennel-lib-spawn::Supervision` accepts injected stdin/stdout/stderr FDs; `kennel-bin-init` `dup2`s
   them before `execve`.
5. Binder-session tracking for the hard reaper, the spawned-kennel `max_lifetime` self-reap, and the
   atomic check-and-claim `max_instances` accounting (the Node 0 accounting lock).
6. The T3.9 THREATS entry (mutable-field surface + delegated-composition residuals) and the
   compliance-table mapping.