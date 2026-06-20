# §7.12 Policy surface: dynamic spawning and MCP transport

> **A confined workload can ask `kenneld` to spawn a constrained, ephemeral sibling kennel and
> hand it a stdio channel — without authoring policy, and without `kenneld` entering the byte
> path.** The workload names an operator-signed template and supplies operator-constrained
> variables; `kenneld` instantiates it in memory, passes the file descriptors across the `SPAWN`
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
policy at runtime.** It can only *name* an operator-signed template and supply a constrained set of
*variables*. The template was signed when the operator installed it into the trust store; the
agent's `SPAWN` is a reference to capability the operator already consented to, not a new grant.

This is why dynamic spawning does not weaken the signature model the way an in-RAM "build a child
policy on the fly" path would. No new policy is authored, so no new signature is needed — the
signature was checked at install time, on the template. Ephemerality (the instantiation never
touches host disk, §7.12.6) and consent (the template is signed) are *separate* properties: the
first is about leaving no trace, the second about authority, and neither is asked to do the other's
work. The agent controls exactly one thing — the variable values — and that surface is the entire
attack surface of a spawn (§7.12.3).

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
template = "pure-compute@v2"       # exact, versioned, trust-store template
vars     = ["workspace_subpath"]   # the variable names the requester may supply
```

The requester names *which* signed templates it may instantiate and *which* variable names it may
supply. It does not name capabilities — those live in the template. If `pure-compute@v2` fixes
`[net] mode = "none"`, no `[spawn]` grant and no variable can give the spawned kennel a network: the
compiler denies any capability the template does not grant, and the agent cannot supply policy to
add one. The capability floor of every spawn is the signed template's, full stop.

## 7.12.3 Variables are the attack surface

Once policy authoring is off the table, the *only* agent-controlled input is the variable values,
and they are therefore where the entire security argument concentrates. An unconstrained variable
that flows into a template's `[fs]` path is a path-traversal primitive: the agent supplies
`workspace_subpath = "../../../../etc"`, and the signed template faithfully binds it. The template is
signed; the *interpolation* is the agent's. "The agent cannot grant network access" can hold while
"the agent can redirect a filesystem grant" remains open — the same class of breach, one axis over.

So variables carry declared constraints, and the constraint lives in the **template**, which is
signed and whose author knows what the variable means:

```toml
# inside pure-compute@v2 (operator-signed)
[[vars]]
name  = "workspace_subpath"
type  = "relpath"                  # relative path; absolute is rejected
under = "workspace"                # resolved beneath the requester's own workspace root
                                   # no '..'; resolved with RESOLVE_IN_ROOT at instantiation
```

The split is clean: the requester's `[spawn.allow].vars` authorises *which* variable names it
controls; the template's `[[vars]]` constrains *what values* are legal. `kenneld` validates the
supplied value against the template's declared constraint at instantiation — typed, traversal-free,
resolved in-root — which is policy validation in the existing compiler, not a new parser in the TCB.
A variable with no declared constraint is refused, not passed through; the default is closed.

## 7.12.4 The capability handoff

The requester provisions the channel, then references it in a single `SPAWN` transaction; there is no
routing binary and no facade, because there is no host process that owns the pipe — the requester is
a kennel and the FD rides the transaction directly.

1. The requester creates a `socketpair()` (bidirectional JSON-RPC: a local end it keeps, a remote end
   it will hand over) and a `pipe()` (the spawned kennel's `stderr`, kept separate so unstructured
   error text never corrupts the framed channel — §7.12.5).
2. It sends a `SPAWN` transaction to `kenneld` naming `pure-compute@v2` and the variable values,
   attaching the socketpair-remote and pipe-write ends as `BINDER_TYPE_FD` objects.
3. `kenneld` validates the grant and the variables (§7.12.3), resolves the template from the trust
   store, builds the instantiation in memory, and injects the translated FDs into the spawned
   kennel's supervision plan.
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
  channel, and a `memfd` is charged to the spawned kennel's memory cgroup — so a template used as a
  spawn target **must declare a memory ceiling**, or an oversized artifact is an unbounded-memory DoS
  rather than a bounded transfer. The memory limit is part of what makes a template spawn-safe.

## 7.12.7 Fate-sharing: the double reaper

A spawned kennel must not outlive its purpose, and the coupling is `kenneld`-brokered, not parental.

- **Soft reaper (data plane).** When the requester is done it `close()`s its local channel ends; the
  spawned tool receives `EOF` on stdin / `SIGPIPE` on stdout and exits, and `kennel-bin-init` tears the
  kennel down. The graceful path.
- **Hard reaper (control plane).** `kenneld` tracks the binder session that issued the `SPAWN`. If that
  session drops — requester crash, OOM, TTL expiry — `kenneld` issues a `cgroup.kill` to the spawned
  kennel, terminating it regardless of whether the tool honoured `EOF`. The backstop for a hung tool.

## 7.12.8 Depth-1 is a hard rule

Spawning is **depth-1, by rule, not by default**: a template reachable as a spawn target may not
carry `[spawn]`. This is a fork-bomb prohibition, not a deferred feature. Recursion would turn
`max_instances` from a global ceiling into a per-node one — N levels deep the bound is
`max_instances`^N — so the rule keeps the ceiling global by construction and the hard-reaper coupling
a single hop (the requester's session, never a chain a cascade would have to walk). There is no
depth-N roadmap item; multi-level delegation is out of the model.

The check is **transitive and at install time**: a template named in any `[spawn.allow]` is refused
at install if it carries `[spawn]`, rather than discovered at instantiation. If A spawns B, B is a
spawn target and B with `[spawn]` is rejected when B is installed — fail-closed, before any
instantiation can reach it.

The reaper that kills decrements `max_instances`, so a flapping requester cannot leak slots across
teardown races.

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

- **The variable surface is agent-controlled.** The requester chooses variable *values*; the template
  constrains them (§7.12.3), and the strength of the boundary is exactly the strength of the template's
  declared constraints. An under-constrained variable in a signed template is the residual's sharp edge,
  and the catalogue says so — the operator signing a template that takes variables is signing its
  constraint declarations as load-bearing.
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
> capability the template does not grant. It controls two inputs only: the variable values it supplies,
> and the composition of the tools it is permitted to spawn.
>
> *Mitigations in place.* Request-don't-author (the capability floor is the signed template, not
> agent-supplied policy); template variable constraints validated at instantiation — typed,
> traversal-free, `RESOLVE_IN_ROOT` (§7.12.3); depth-1 by hard rule, refused transitively at install
> (§7.12.8); the `max_instances` ceiling and the double-reaper fate-sharing (§7.12.7); ephemerality,
> no host persistence (§7.12.6).
>
> *Residuals.*
> - **R1 — variable surface.** The boundary is exactly as strong as the template's declared variable
>   constraints; an under-constrained variable in a signed template that flows into an `[fs]` path or
>   other capability-shaping field is unguarded (a traversal value redirecting a workspace bind is the
>   canonical case). Operator-owned: signing a template that takes variables signs its constraint
>   declarations as load-bearing. Closes to the strength of those declarations, not below.
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
   the `[[spawn.allow]]` template+vars grant, and the T3.9 risk derivation; the compiler refuses, at
   install time and transitively, any spawn-target template that carries `[spawn]` (depth-1, §7.12.8).
2. Template `[[vars]]` constraint grammar (`type`, `under`, traversal-free, `RESOLVE_IN_ROOT`) and the
   instantiation-time validator in the compiler — the §7.12.3 attack surface.
3. The `SPAWN` transaction verb on Node 0 (`kenneld/src/binder.rs`): grant + variable validation,
   in-memory template resolution, FD translation and injection.
4. `kennel-lib-spawn::Supervision` accepts injected stdin/stdout/stderr FDs; `kennel-bin-init` `dup2`s
   them before `execve`.
5. Binder-session tracking for the hard reaper, and the kill-decrements-`max_instances` accounting.
6. The T3.9 THREATS entry (variable surface + delegated-composition residuals) and the compliance-table
   mapping.