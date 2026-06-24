# §7.12 Policy surface: dynamic spawning and MCP transport

> **A confined workload can ask `kenneld` to spawn a constrained, ephemeral sibling kennel and
> hand it a stdio channel — without authoring policy, and without `kenneld` entering the byte
> path.** The workload names an operator-signed template and writes only its operator-declared
> mutable fields; `kenneld` instantiates it in memory, mints the channel and returns its file descriptors
> across the `SPAWN` reply, and steps out. MCP rides the channel as opaque JSON-RPC; Kennel neither frames nor
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
frozen, no `[spawn]` grant and no mutable-field write can change it: the compiler, at install,
denies any capability the template does not grant, and the agent writes only the
fields the manifest opens. The capability floor of every spawn is the signed
template's, full stop.

A grant is only useful if its holder can *read* it. An agent need not — and should not — discover its
spawn surface by trial, firing speculative `SPAWN` calls to learn which template names and field writes
the daemon will accept. The grant is **interrogable**: a confined workload can ask `kenneld` for its own
`[spawn]` grant and receive back the allowed `name@version` templates, each template's mutable fields
*narrowed to that requester* with their bounds, and the `max_instances`/live ceiling. This is the
read-side of *request, don't author* (§7.12.1) — the agent learns the shape of the fenced blanks before
it fills them. The query returns only the caller's own grant — authority it already holds — so it crosses
no trust boundary and reveals no other kennel's grant, template body, or key.

## 7.12.3 The mutable-field surface

A template is not a constraint over values authored by the agent. It is a **complete, signed,
runnable policy, plus a declared manifest of which fields an autogen or child step may write.**
Everything outside the manifest is frozen and inherited verbatim. The spawn request carries the
agent's writes as a **patch** — a set of `(field-path, value)` pairs naming manifest fields, never a
full candidate policy. `kenneld` rejects any field-path not in the (per-requester-narrowed) manifest,
validates each value against that field's bound, and applies the surviving writes onto the resolved
template; it never ingests or whole-tree-diffs an agent-supplied document, so no adversarial policy
parser or deep tree comparison enters the daemon. The invariant this establishes is `candidate ∖
manifest == template ∖ manifest` — the instantiation differs from the signed template *only* within
the manifest — but the enforcement is **key-membership on the patch**, not a set-difference over two
trees: a write whose value happens to equal a frozen field's is still rejected for naming a field
outside the manifest, never waved through because the difference came out empty. Any out-of-manifest
key is a hard reject, fail-closed. And because a spawn target is signed *pre-resolved* — its template
chain folded at sign time — applying the patch is a bounded field-write over an already-parsed policy in
the daemon's **verify path**, not a compilation: `SPAWN` pulls in no policy *compiler*, only the
verify-and-load half the daemon already carries. The write is a **typed mutation on the already-parsed
policy, never a TOML re-serialise and re-parse** — that round-trip would smuggle the parser back into the
daemon, so it is the parser, not only the compiler, that `SPAWN` keeps out.

**The instantiated policy is never itself signed.** The signed artefact is the *template* plus its
manifest of variants; the instance an agent spawns — the template with its patch applied — exists only
in `kenneld`'s memory for the spawn's lifetime and is handed straight to construction. There is no
settled artefact on disk for the instance and nothing to re-sign. Its integrity rests not on a
signature of its own but on the chain that produced it: the verified template signature, the signed
per-field constraints, and the in-TCB validator that can only move a field the manifest opens, within
the bound it declares. The manifest *is* the signed statement of how far an instance may legally
diverge from the template.

This inverts the surface from *synthesis* to *selection*, which is the single most useful thing for
making agent-generated policy tractable. The agent does not author a policy the validator then
checks; it fills a few labelled, fenced blanks in a sealed document, and the patch validator proves it
filled only the blanks. Membership in a constrained surface is a far smaller and harder-to-fool
check than satisfaction of a predicate over an open value space, and an LLM cannot squeak a novel
grant through by finding a value that technically passes — the field it would need to write is
frozen, not in its write set.

Each variant carries its own **constraint** describing *how* its field may move; "mutable" means
writable *within that constraint*, never free. A mutable proxy allow that accepts `0.0.0.0/0` defeats
the purpose, so the constraint is part of the signed declaration. The constraint is one of an **open
family — not a fixed taxonomy**: each member describes a different *way* a variant may diverge, and a
new way to bound a divergence can be added as a new member without disturbing the others. The ones in
play:

```toml
# net-fetch@v1 (operator-signed): a full policy with [net].mode = "constrained" frozen
# and the proxy allowlist empty, plus the manifest naming what may move —

[[mutable]]
field = "net.proxy.allow"    # pattern: OPEN destinations, bounded by a pre-baked shape —
match = ["*.pypi.org:443", "ghcr.io:443", "10.0.0.*:443"]
# the agent supplies a concrete destination nobody enumerated at sign time; it is admitted
# only if it matches one signed pattern (subdomain `*.suffix`, final-label `prefix.*`), exact port.
# This governs the per-kennel egress PROXY filter only — an admitted destination joins the proxy
# allowlist. The cgroup BPF ACL is a separate mechanism (`[net.bpf]`), never touched here.

[[mutable]]
field = "rootfs.writable"    # oneof: the agent picks from an enumerated member list
oneof = ["/usr/lib/python3.12", "/opt/app/cache"]

[[mutable]]
field = "fs.read"            # pool + max: append up to `max`, each drawn from a fixed pool
from  = ["/opt/data", "/opt/models"]
max   = 8

[[mutable]]
field = "fs.write"           # predicate: a runtime-relative writable subpath (existing fs.write leaf)
type  = "relpath"            # traversal-free, RESOLVE_IN_ROOT at instantiation
under = "workspace"

# The fifth member, freeform, takes no shape at all and applies to any of these fields:
#   field = "fs.write"   freeform = true   reason = "…"   (loud, last-resort — see below)
```

Every `field` above is an **existing** policy-schema leaf (`net.proxy.allow`, `fs.read`, `fs.write`,
`rootfs.writable`) — a variant never coins a field, it constrains one the schema already has, and the
applicator's registry is the authority on which leaves are mutable (an unknown field is a compile
reject). The five constraint *members* are not the whole family — a new way to bound (or refuse to
bound) a divergence can join without disturbing the rest. They form a **loudness gradient from closed to open**. **pool** and
**oneof** are *closed* — the agent selects from a set fixed at sign time, zero free text. **pattern** is
the *shaped-open* case `net.allow` needs: the value is not pre-baked (no operator enumerates every
destination an agent may reach), but a wildcard is admitted only when it conforms to a signed shape — a
subdomain wildcard `*.suffix`, a final-label wildcard `prefix.*` (the IPv4 `/24` form), each with an
exact port — so the freedom is real but its shape is bounded by the signature. **predicate** is the
typed escape hatch (a traversal-free `RESOLVE_IN_ROOT` relpath) for a value that cannot be enumerated or
shaped, such as the agent's actual working subpath. **freeform** is the floor: *no* constraint, any
value accepted — so it is the loudest, governed by the footgun rule (warn, never forbid, §11.x): it
**requires a `reason`** and is flagged with big warnings at compile, at `validate`, and at every
instantiation, because a freeform variant is an operator handing an agent an open value by choice. The
open-value residual (R1, §7.12.9) attaches to the open constraints and grows along the gradient — bounded
under *pattern*, wider under *predicate*, maximal under *freeform*. The recommendation is closed
constraints by default, an open one by exception with justification, and *freeform* only when nothing
narrower can express the need.

The frozen set is what carries the invariants. The single-leg property (§7.12.2), the resource
ceilings, and the TTL live in frozen fields — `net.mode`, the absence of an `[fs]` root grant, the
cgroup limits — so no manifest write can add a trifecta leg, lift a ceiling, or escape the TTL,
because those fields are not in the agent's write set. Mutability is scoped to the leg-safe degrees
of freedom by construction: filling `net.allow` extends reach *within* the one leg the template
already granted, never across to a second. Single-leg is enforced once, at the floor; the manifest
flexes underneath it.

The unit of mutation is the leaf field (or an explicitly scoped subtree), enforced by patch
key-membership, so a manifest opening `net.allow` cannot be used to rewrite `net.mode` beside it. The signed artifact is
*template + manifest*; the requester's `[spawn.allow].mutable` may narrow the manifest further per
requester (§7.12.2), never widen it.

## 7.12.3a The facade interface contract — three authority regions

A `SPAWN` request, and the command line that carries it, partitions its authority into **three regions
that are syntactically distinct because they are semantically distinct**. Each is a different question with
a different answer, governed by a different mechanism, all floored in the **signed template**:

```
kennel run  net-fetch@v1   net.proxy.allow=ghcr.io:443   --  curl -sSL https://ghcr.io/…
            |__ template _| |___ mutable-field patch ___|     |________ argv ________|
              @-pinned         bounded, manifest-gated          unpinned, exec.allow-gated
```

- **The named template** (`net-fetch@v1`) is `@`-version-pinned and is the whole signed capability floor
  (§7.12.1): the requester *names* operator-consented capability, it does not author it. Everything the
  spawn may do floors at this template's grants.
- **The mutable-field patch** (`net.proxy.allow=ghcr.io:443`) writes only the leaf fields the template's
  `[[mutable]]` manifest *exposes*, each within its declared bound, validated by the manifest-patch
  validator (§7.12.3). Frozen fields cannot move and an unexposed field is not writable at all — a
  *bounded* authority, a value chosen inside a fence the operator signed.
- **The argv** (everything after `--`) is *unpinned* — the requester writes any command line — but gated by
  the template's `[exec].allow` floor: Landlock admits only a binary the allow-list permits, **matched on
  the resolved binary, not the literal `argv[0]` string**. argv is unpinned precisely because the allow-list
  does the gating; pinning the command line would be redundant with, and weaker than, gating the binary. A
  template that does not open the `workload.argv` mutable leaf runs its own fixed entrypoint and rejects a
  `--` command.

The three regions are **independent**, and the egress patch and the argv most sharply so: the per-kennel
proxy gates egress against `[net.proxy.allow]` **regardless of what the argv claims**. `curl` naming a
different host does not widen the patch, and the patch admitting `ghcr.io:443` does not compel any binary to
reach it — one governs *where the kennel may connect*, the other *what binary runs*, and neither constrains
the other. Reading them as coupled is the mistake to avoid; each region is floored separately by the signed
template, so widening one cannot widen another. This separability is what makes the surface safe to expose
to an untrusted requester.

**Scope.** This is the authority model for the single-host, kennel-to-kennel spawn that exists (§7.12.10):
the template runs *here*, under *this* `kenneld`. Placement and federation — *where* a spawn runs across
hosts — are non-goals; there is no scheduling engine. The contract answers the authority and envelope
questions, never a "where does it run" one.

## 7.12.4 The capability handoff

`kenneld` mints the channel and hands each side its ends; nothing flows *into* the daemon. Node 0 stays
free of inbound descriptors — the fd-passing invariant that it issues fds outward and never accepts them
inward holds unbroken — and the shape is the same as every other `kenneld` fd broker (`CONNECT_INET`
returns a connected socket; `SPAWN` returns a channel).

1. The requester sends a `SPAWN` transaction naming the template and its mutable-field writes (a patch,
   §7.12.3), carrying **no descriptors**, with its reply flagged to accept fds.
2. `kenneld` validates the grant, resolves the named template from the trust store and **verifies it
   against the content-pin the spawner's compiled policy recorded** (fail-closed on mismatch, §7.12.8),
   **re-checks spawn-eligibility on the resolved template**, and applies the manifest patch — all in the
   daemon's verify path, never its policy compiler (§7.12.3).
3. `kenneld` **mints the channel** — a `socketpair()` (bidirectional JSON-RPC) and a `pipe()` (the
   spawned kennel's `stderr`, kept separate so unstructured error text never corrupts the framed channel
   — §7.12.5). It injects the spawned-kennel ends (the socketpair remote, the pipe write) into the
   spawned kennel's supervision plan, and **returns the requester's ends** (the socketpair local, the
   pipe read) in the `SPAWN` reply, alongside the transient `spawn-<uuid>`.
4. `kennel-bin-init` boots the spawned kennel, seals it, and — as the **final step before `execve`** —
   places the injected ends onto stdin/stdout/stderr, then `execve`s the template's entrypoint (for MCP,
   a stdio JSON-RPC server). Init keeps its own diagnostics on a host-side descriptor throughout, so a
   failure during sealing reaches the host audit, never the channel (§7.12.5).

`kenneld` evaluates an ACL and brokers file descriptors, all **outbound**. It mounts nothing for the
spawned kennel beyond the template's own view, parses no JSON, and routes no traffic.

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
the single-chokepoint invariant, and a spec dependency in the TCB. Kennel writes no MCP interposer of its
own either: a first-party one re-imports the exact `tools/call` parsing this primitive keeps out. The
principled form of application-semantic mediation (tool allow-listing, audit), if an operator wants it, is
an *existing* MCP proxy confined like any other vendored tool — its code, dropped into a disposable kennel
between requester and tool, the way `oci-fetch` confines `skopeo`/`umoci` — not a Kennel-authored
interposer. Absent one, the cross-kennel composition residual is accepted-and-tagged (R2).

`stderr` on its own pipe is the one detail worth stating explicitly: a traceback, compiler warning, or
panic in the spawned tool flows out a separate descriptor, so the framed JSON-RPC channel is never
corrupted by unstructured text, and the requester can capture the exact error and feed it back to the
model. The injected `stderr` carries only the *tool's* output: `kennel-bin-init`'s own pre-`execve`
failures — a Landlock seal that will not apply, a seccomp filter that will not compile — route to the
host audit and the boot-sync channel, **never** to the injected pipe. The agent sees a clean `EOF` for
an infrastructure failure (no host-side init state leaks to it) and tracebacks only once its own tool is
the thing running.

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
  kennel down. The graceful path — but it depends on the tool *exiting*: a tool that dumps more than a
  pipe buffer to `stderr` while the requester drains only stdout blocks in `write(2)` and never exits,
  stalling this path. The self-reaper below is the backstop that breaks that deadlock.
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
the lock, the second to acquire it sees the first's claim. A slot is held from claim until release, and
release covers **every** terminal outcome, not only reaper teardown: a reaper kill releases it, and the
construction worker holds the slot as an RAII guard that releases it if the build aborts before the
spawned kennel reaches the reaper subsystem (a failed `clone`/`pivot_root`/init exec). A boot failure
therefore cannot permanently leak a slot, and a flapping requester cannot leak slots across teardown
races.

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

Install-time eligibility is **fail-fast, not the authoritative gate**: it validates the template as it
stood when the spawner was compiled, but `kenneld` resolves the template by name from the *mutable* trust
store at `SPAWN` time, so a re-signed or replaced entry would otherwise slip an ineligible target past a
stale install-time pass — a TOCTOU. Two things close it, both at `SPAWN`. The spawner's compiled policy
**content-pins** every template it names (the lockfile closure records each template's hash), and
`kenneld` verifies the resolved template against that pin, fail-closed on mismatch — so the bytes
instantiated are the bytes the install gate actually checked. And `kenneld` **re-runs the eligibility
check on the resolved template** regardless, cheap defense-in-depth that holds even if a pin is ever
mis-recorded. The install gate is authoring-time feedback; the pin-plus-recheck is what makes the runtime
instantiation safe against a mutable trust store. The pin carries the standard supply-chain cost: a
spawn-target template cannot be patched transparently — re-signing it in place changes its hash, so every
spawner that names it fails the pin closed at `SPAWN` until recompiled (no global hot-swap; the deliberate
trade of byte-exact integrity over convenience, recorded in 02-10's operational constraints).

## 7.12.9 Security posture — what holds, what is waived

**What holds.** The spawned kennel receives no ambient authority beyond its signed template and the
channel `kenneld` mints for it — nothing flows from the requester at all; its base capability is the
signed template's and nothing more. The requester
holds neither `ptrace` nor signal reach into it. `kenneld` mounts nothing, parses no JSON, and routes no
bytes for it — it evaluates an ACL, brokers FDs outbound, and mints the channel. The TCB grows by exactly
that and no more: the bounded `SPAWN` validation in the verify half (patch-apply, bound-check, pin and
eligibility) and the channel mint — never a policy compiler, never an MCP parser. The whole multi-kennel
topology is operator-consented: every template is signed, and every `[spawn]` grant is a loud, declared,
risk-derived capability.

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

> **Catalogued as T3.9 — Delegated spawning.** The full entry — adversary, mitigations, the R1
> mutable-field and R2 delegated-composition residuals, and the ATT&CK and compliance mappings — lives in
> `docs/design/THREATS.md` (T3.9), with the machine form in `dist/threats/catalogue.toml`. The exposure is
> **derived** from the `[spawn]` grant: `kennel policy risks` reports it with the grant as carrier and the
> operator's `reason`, the path `mode = host` uses for T1.6 — no stored `threats.reinstated` field, the
> grant is the tag. Workload-class family, sibling to T3.8.

## 7.12.10 Scope: kennel-to-kennel by definition

Dynamic spawn is a **kennel-to-kennel** function — one kennel opening another — and that is the whole
of it. The other MCP topology, a host process that wants a kennel on a pipe, is not a deferred item
here: the host already has `kennel run` and can pipe stdio to it directly if it insists. That is
neither a design objective of this chapter nor an encouraged pattern, and there is no host-side shim
to build for it. Stating the boundary this way keeps 0.3.0 from growing a second mechanism for a case
that is already served, badly enough to discourage, by an existing verb.