# Project Kennel — 0.4.0 plan

Status: **active** · Promoted: 2026-06-22 · Targets: 0.4.0
Baseline: 0.3.0 (released)

> This is a planning artefact, not a design or as-built document. The design corpus
> (`docs/design/`) and the as-built notes (`docs/architecture/`) remain the source of truth
> for *what each item is*; this file records *what 0.4.0 commits to, why, and in what order*.
> The two anchor designs are `docs/design/07-13-service-catalog.md` (sidecars + catalog) and
> `docs/design/07-14-confined-gui.md` (Wayland + portals); their architecture contracts are
> written as-built across the build. (Design chapter numbers provisional.)

## Theme

**Standing services and brokered composition.** 0.3.0 made it cheap and safe to spawn a single
isolated thing — an ephemeral tool kennel, kennel-to-kennel, over a one-shot FD channel,
deliberately with no standing registry (§7.12.10 left cross-kennel `provide`/`consume` out of
scope). 0.4.0 is the complement: a **fabric of cooperating confined kennels**, where a workload uses
capabilities *provided by other confined kennels* — GUI, D-Bus, and future brokered services — and every
cross-kennel capability is **operator-declared, `kenneld`-brokered, and deny-by-default.**

The discipline carried from 0.3.0 ("provision only what's consumed") becomes **compose only what's
declared**: the mesh is operator-signed, derived not authored, deny-by-default. A desktop app uses
the GUI service without holding GUI capability; an app reaches the session bus through the D-Bus
broker without a direct host socket; each capability comes from a confined provider, brokered by
`kenneld`.

Two continuities make this one move, not a new direction:

- **Provision once, consume many.** 0.3.0's spawn provisions per-use (a fresh kennel each time); a
  standing service amortises construction (the GUI kennel is up once, many apps use it). The mesh is
  the latency complement to spawn — repeated capability use stops paying per-use construction.
- **It completes the GUI story 0.3.0 opened.** W16 removed X11 from built artefacts; 0.4.0 ships the
  Wayland + portal path that makes that removal a replacement, not a capability regression.

The **forcing function and headline proof is confined GUI** — the first non-trivial service kennel,
and the thing that pressure-tests every mesh primitive.

Standing constraints that shape the mix (carried from 0.3.0):

- **The TCB grows here — and we state it plainly.** This is the first release since the post-spawn
  decomposition where `kenneld`'s own surface goes *up*, not down: the `SVC_CONNECT` broker, the
  catalogue resolver, the readiness state machine, and the lifted supervisor are new daemon logic and
  new daemon state-machine surface. The [[tcb-only-shrinks]] constraint as it actually binds is about
  the daemon's **dependency closure** and its **authored state**, and on *those* axes the line still
  holds: the broker parses no protocol bodies (fine-grained service mediation — which D-Bus method,
  which portal interface — lives in a confined interposer, never the daemon; no mesh work may land a
  protocol parser in `cargo tree -p kenneld`); the catalogue is a derived projection, not authored
  central state; the supervisor is *borrowed* `bin-init` code, not new code. So the discipline is
  **maximise reuse inside the TCB and add no new dependencies or authored state — while accepting that
  the daemon's behaviour, and therefore the audit surface, is larger after 0.4.0 than before.** Naming
  that openly is the cost of the mesh, paid honestly, rather than a constraint quietly bent.
- **No standing host privilege** ([[no-standing-host-privilege]]). Service kennels are constructed
  by the existing privhelper factory; the one trusted host-reach (the GUI AF_UNIX compositor leg) is
  a scoped, tagged residual held by a *confined* kennel, not a privileged host process.
- **Derived, not authored.** The catalogue is a projection of the `[provides]` blocks of known
  kennels, and supervision state is re-derived from signed declaration on daemon restart — neither is
  standing authored daemon state (the repo-is-truth discipline applied to service discovery).
- **The service-kennel trust class.** Operator-declared service kennels may hold multiple legs
  because they are trusted and non-composable, unlike agent-instantiated spawn targets (§7.12). The
  multi-leg exemption is a property of this trust class, defined once, not per-instance.
- **Authentication, never attestation.** The mesh provides capabilities a confined kennel may *use* —
  rendering, transport, session-bus access, holding a key to authenticate ("may I do this thing").
  It must never provide *attestation* — vouching, signing, secret-issuance ("trust that this is so").
  An attestation's value derives from the trust of its origin, and the mesh's origins are confined-and-
  untrusted by definition, so a peer kennel making a trust claim others rely on is incoherent. This is
  the ssh-vs-gpg call generalised: authentication-shaped capabilities can be services; attestation-
  shaped ones cannot, and a kennel whose job is to be trusted (a secrets broker, a signing service)
  is a trust root misplaced inside the boundary the project exists to confine. Trust material arrives
  as a signed construction parameter from the operator/host layer, never from a peer at runtime.

## Workstreams

Sizes: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week. Numbering is release-local (W1+);
carried-forward backlog items keep their 0.3.0 IDs where referenced.
Tags: **[dep]** · **[debt]** · **[opt]** · **[non-goal]**.

**Build order follows the coding standard — test, then scaffold, then logic — applied at the
*contract* altitude.** The schema and the API/wire surfaces are the cross-workstream contract;
every consumer (the broker, the catalogue, the GUI kennel, the topology surface) derives from them.
So the contracts land **first and test-first** — the schema's valid/invalid cases asserted, the
API's state transitions pinned as tests — *before* any runtime logic is written against them. This
is the same separation 0.3.0 used (the policy surface, W3–W5, compiler-only and fully testable,
landed ahead of the runtime W6–W11), and it is the anti-drift discipline applied to the build graph:
freeze and test the contract, then build consumers against the frozen thing, rather than building
consumers in parallel and reconciling their assumptions afterward.

### Thrust 0 — Substrate confirms (gating, run FIRST)

The assumptions about **external substrate the project does not control** that the GUI headline (W7)
rides on. They test whether the render mechanism (Wayland) and the host-services mechanism (the portal
over D-Bus) behave as the design needs *under a constructed view they were never built for*, and they run
**first** — ahead of committing the GUI scope, not merely ahead of scheduling W7 — because a dirty result
should inform whether confined GUI is a 0.4.0 ship item or the design forcing-function for a 0.4.0 mesh
foundation it later rides on. The first pass already earned its keep: it falsified the "vendor Flatpak's
Wayland proxy" premise and replaced it with the compositor-enforced `security-context-v1` model (below).
Both are detailed in `07-14-confined-gui.md`; both gate the headline.

- **W0 · GUI substrate confirms.** **[gating] S.** **Status: confirm A's mechanism settled; confirm B's
  premise corrected (the render mechanism is `security-context-v1`, not a proxy — the design is *better*
  for it); the new compositor-support confirm is OPEN and negative on the maintainer's own host; confirm
  A's interactive half remains open — the gate is not clear.** First pass run 2026-06-22.

  - **Confirm A — portal identity through the bwrap-mimicked view.** *Mechanism: SETTLED from substrate.*
    On a representative host (`xdg-desktop-portal` **1.18.4** — the version the roadmap's `gui-services@1.18.x`
    pin example names), the portal derives a caller's app-id by reading **`/.flatpak-info`** from the
    calling process's mount-namespace root (`instance-id` + the app-id; confirmed directly from the portal
    binary). Two consequences, both load-bearing:
    - The bwrap-mimicry delivers app-identity **for free** — the clean-win path. A constructed view that
      presents a well-formed `/.flatpak-info` is seen as that Flatpak app, so the permission store keys on
      it and persists; there is no per-call re-prompt *by construction*, provided the file is present and
      well-formed.
    - **Security (the W13 authentication/attestation seam — now substrate-confirmed, not hypothetical):**
      app-id is *asserted by the sandbox's own `/.flatpak-info`*, so the permission-store key is only as
      trustworthy as the view's integrity. The kennel must **own and seal `/.flatpak-info`** — synthesised
      at construction, never workload-writable — exactly as it masks the trust-manifest (§4.6). A workload
      able to author or rewrite it is a confused deputy against its own (or another app-id's) permission
      store. This converts confirm A's "identity seam" from a UX question into a *construction-integrity
      requirement* that W7 must carry.
    - *Interactive half: OPEN.* Whether the permission store persists across real sessions without
      re-prompting, and how a 1.18 backend behaves under the constructed view, needs a live graphical
      session plus a flatpak (or a faithful mimic) app — not runnable on the headless host this pass used,
      and the box's live GNOME session was deliberately **not** perturbed (exercising a real desktop's
      portal writes permission state and pops dialogs in the maintainer's session).

  - **Confirm B — the render-leg mechanism.** *Original premise FALSIFIED; corrected to a better one.*
    The premise "vendor **Flatpak's filtering Wayland proxy**" is wrong about Flatpak: with flatpak **1.14.6**
    installed, no `*wayland*proxy*` binary exists anywhere on the system, and flatpak filters only **D-Bus**
    (via `xdg-dbus-proxy`) while Wayland is *passed through* ("Allowing wayland access" — bind the socket
    in, no filtering). Flatpak relies on Wayland's built-in client isolation, not a proxy. The *correct*
    mechanism is the `wayland-protocols` staging protocol **`security-context-v1`** (≥ 1.32, mid-2023):
    the sandbox engine creates a **tagged** Wayland socket and **the compositor enforces** the
    privileged-protocol denial (screencopy / input / layer-shell). This is *better than the proxy the
    premise assumed* — no proxy binary, no filtering code in the byte path, no proxy kennel to compromise;
    enforcement lives in the compositor, already trusted to draw the screen — and it natively gives the
    control-plane-only property (engine touches the compositor at setup, the cage talks to the compositor
    direct over the tagged socket). Flatpak merged engine support Aug 2023; minimal engine example
    `~whynothugo/way-secure`; spec `wayland.app/protocols/security-context-v1`. **This is folded into W7's
    render leg; `07-14-confined-gui.md` must be rewritten off the proxy framing onto this.**
    - **New gating confirm (replaces "proxy deployment shape"): does the target compositor implement
      `security-context-v1`?** Verified on the substrate: **Mutter 46.2 — the maintainer's own GNOME host —
      does NOT** (no security-context globals in `libmutter-14`, while every other staging `wp_*_v1` global
      is present, so the probe is sound). sway implements it; Mutter 47+ and KWin status to confirm against
      current versions. **Consequence, stated not hidden:** where the compositor lacks the protocol there is
      **no render-leg enforcement**, so confined GUI carries a hard requirement — *a `security-context-v1`-
      capable compositor* — and on GNOME ≤ 46 it is unavailable today. This is now the open, host-gated half
      of confirm B; its e2e (a tagged socket under a constructed view, privileged globals denied) needs such
      a compositor, which this host's GNOME 46 is not.

  - **W0 exit:** both confirms fully clean. Confirm A's mechanism is green and already feeds the model
    (seal `/.flatpak-info`); **confirm B has corrected a load-bearing premise to a smaller, better
    mechanism (`security-context-v1`) and owes a `07-14` rewrite; the new compositor-support confirm is
    open and negative on the maintainer's own GNOME 46, and confirm A's interactive half remains to run on
    a `security-context-v1`-capable graphical host. W7 stays unscheduled until both come back clean.** The
    first pass has already paid for itself twice: it killed the proxy-premise error before any GUI code was
    written, and it surfaced the compositor-support requirement as a stated dependency rather than a silent
    runtime gap.

### Thrust 1 — Contracts first (schema + API, test-first, no daemon)

Self-contained and testable with no broker and no runtime — the contract every later thrust consumes.

- **W1 · `[provides]` / `[consumes]` schema + compile-time shape checking.** **[dep] M.**
  New policy blocks in `schema/policy.toml.schema` and `kennel-lib-compile`. A provider declares
  `[provides]` (name + typed *shape*: AF_UNIX / D-Bus name / binder connector); a consumer declares
  `[consumes]` (a name). The compiler checks the consumed name has a matching `[provides]` of the
  right shape across known kennels — compatibility verified before runtime, fail-at-compile not
  at-runtime (the version-pinning discipline). Compiler-side; out of `cargo tree -p kenneld`.
  **Test-first:** the valid/invalid provide-consume corpus (matching shapes accept; name-mismatch,
  shape-mismatch, dangling-consume, duplicate-provide all reject) is written and asserted before the
  compiler logic. The schema is frozen here — W2, W4, W5, W6 all compile against it.

  **Confine the provide-name namespace — `[provides]` is not sidecar-only.** Any kennel may declare a
  `[provides]`, not just the operator-declared service set, so the name a provider may *claim* is the
  load-bearing gate, not which kennels are allowed to provide. The reserved `dev.kennel.*` namespace
  (Wayland, portal, D-Bus, the system service names a consumer trusts by reputation) is claimable
  **only by the operator-declared, signed service-kennel trust class** (W11); an ordinary workload or
  spawn-target kennel that declares `[provides] dev.kennel.wayland` is refused at compile, because
  otherwise it could advertise a reserved name and have a consumer resolving `wayland` brokered to the
  impostor — provider-name spoofing, a capability-granting side channel through the catalogue. Other
  kennels may provide only in an unreserved namespace, and a consumer reaching one of those gets no
  more trust than the name carries. **Test-first:** a non-service-class kennel claiming a reserved
  name rejects; a duplicate claim on a reserved name rejects; an unreserved provide accepts. This makes
  deny-by-default cover *who may be resolved as what*, not only *who may consume*.

- **W2 · The sidecar + restart-policy declaration schema, and the supervision/readiness API.**
  **[dep] M.**
  The *declaration* half of sidecars (W6's logic is the other half): the autostart-set declaration,
  the per-sidecar restart policy (`always`/`on-failure`/`never` + backoff + max-attempts), and — the
  load-bearing API — the **readiness state machine** (declared-and-ready / declared-but-pending /
  declared-but-failed) and its transitions, which the catalogue (W4) and the topology surface (W11)
  both read. **Test-first:** the readiness transitions are asserted as a contract (pending→ready on
  construction success; pending→failed on crash-loop exhaustion; the legal/illegal transitions)
  *before* the supervisor implements them, because a wrong state or transition propagates into every
  reader. Scaffold the record types and the catalogue-readiness interface here; the supervision loop
  itself is W6.

- **W3 · The `SVC_CONNECT` wire contract on Node 0.** **[dep] M.**
  The reply/transaction shape for resolve-a-name → brokered-connector, specified and tested as a wire
  contract before W5 implements the broker behind it — the connector encoding, the deny-on-no-match
  reply, the consume-with-wait timeout semantics, the EOF-on-provider-restart behaviour. **The flat,
  no-boot-order model leans entirely on this timeout to stay safe under a dependency cycle:** if sidecar
  A consumes B and B consumes A (operator misconfig), async autostart + consume-with-wait does not
  settle itself — both block until timeout, then both land *declared-but-failed*, visible in the topology
  surface (W14). That is the correct fail-closed outcome, but it must be a *specified, tested* result
  rather than an assumed-DAG accident: the timeout is what turns a cycle from a silent hang into a loud,
  observable failure. **Test-first** at the codec/contract level (a resolve against a known catalogue
  returns the right connector shape; an unmatched name returns deny; the wire round-trips; a mutual
  consume cycle resolves to double-timeout-then-failed, not deadlock) so W5's broker logic is built to a
  frozen, asserted transaction surface, not one that emerges from the implementation.

### Thrust 2 — Runtime logic (built against the frozen contracts)

- **W4 · The service catalogue (the derived projection).** **[dep] M.**
  `kenneld` assembles the registry from the `[provides]` blocks (W1) of the kennels it knows — a
  projection of signed policy, not authored central state — carrying the W2 readiness states fed by
  construction status. The projection's *shape* is derived; its *membership* (which kennels exist, and
  thus which `[provides]` are in scope) is the operator's declared set — derived-shape over
  authored-membership, not magic. Reserved-namespace claims are already gated at compile (W1), so the
  catalogue can trust that a `dev.kennel.*` entry came from the service-kennel trust class.
  *Resolution-only, no runtime registration* (a workload registering a service at runtime is a
  capability-granting side channel — forbidden). Full design: `07-13-service-catalog.md`.

- **W5 · The service-connector broker (the logic behind `SVC_CONNECT`).** **[dep] L.** The keystone.
  Implements the W3 wire contract: resolve a name against the W4 catalogue, broker a connector to the
  providing kennel — the standing-service sibling of `SPAWN`'s FD-handoff (resolve-and-broker rather
  than mint-and-inject). Carries the three properties W3 specified and tested: deny-by-default
  resolution, consume-with-wait, and the restart-invalidates-connectors contract (consumers `EOF` and
  re-resolve, reusing the soft-reaper semantics). Lands §7.12.10's deferred cross-kennel
  `provide`/`consume`.

- **W6 · Sidecars: async boot-autostart + the borrowed supervisor (the logic behind W2).** **[dep] L.**
  The supervision half of W2's declaration schema. `kenneld` autostarts the declared set
  **asynchronously** at its own startup (lifecycle coupled to the daemon, not to any consumer),
  supervised by `kennel-bin-init`'s **already-multi-target facade supervisor** lifted to `kenneld`'s
  existing control level — the same control relationship `kenneld` already has with every kennel it
  owns, no new trust boundary (`kenneld` is not a kennel). Enforces the signed restart policy
  (executed not invented); crash-loop-exhaustion drives the W2 readiness machine into
  declared-but-failed (one mechanism, not two). Supervision state ephemeral, re-derived from signed
  declaration on daemon restart. Full design: `07-13-service-catalog.md`.

- **W7 · Confined GUI: `security-context-v1` Wayland + portals as a service kennel.** **[dep] L.**
  A sidecar that `[provides]` GUI capability against the W1 schema, in **two legs that use two different,
  correctly-named mechanisms** (W0 confirm B corrected the original "vendor Flatpak's Wayland proxy"
  premise — no such proxy exists):

  - **Render leg — `security-context-v1`, compositor-enforced (no proxy in the path).** There is no
    filtering Wayland proxy to vendor; the right mechanism is the `wayland-protocols` staging protocol
    **`security-context-v1`** (wayland-protocols ≥ 1.32). The GUI service kennel acts as a *security-context
    sandbox engine*: it creates a tagged Wayland listening socket via the compositor's
    `security_context_manager_v1`, stamps it with the sandbox-engine / app-id / instance-id metadata, and
    hands the socket into the cage; **the compositor itself** then denies the privileged globals
    (screencopy, input injection, layer-shell) to connections on that socket. This is *strictly less* than
    a proxy — no proxy binary, no filtering code in the byte path, no proxy kennel to compromise — and it
    is natively the property we want: the engine touches the host compositor only at setup (register the
    listener), the cage's Wayland traffic goes **direct to the compositor** over the tagged socket, and the
    protocol's close-FD lifecycle tears the context down when the app exits, so the engine need not stay in
    the data path (kenneld-brokers-doesn't-hold, delivered by the protocol). Reference engine: Flatpak's
    merged support (Aug 2023) and the minimal `~whynothugo/way-secure` CLI; spec at
    `wayland.app/protocols/security-context-v1`.
  - **Host-services leg — `xdg-dbus-proxy` + `xdg-desktop-portal` (this half stood as written).** The
    D-Bus filtering proxy `xdg-dbus-proxy` *is* real and Flatpak-shipped; the portal rides it, app-id via
    the `/.flatpak-info` mechanism W0 confirm A settled (the kennel owns and **seals** that file). This leg
    keeps the version-pinned, run-unpatched, bwrap-shaped-view framing; the render leg drops it (no binary
    to pin — the enforcement is the compositor's).

  **The tagged residual shrinks:** the host-compositor reach is now the engine's *setup-time* connection
  to register the tagged listener (control-plane), not a filtering proxy standing in the session-long data
  path. **The new gating substrate confirm (W0):** the target compositor must implement
  `security-context-v1` — sway does; **Mutter 46.2 (the maintainer's own host) does not** (verified: no
  security-context globals in `libmutter-14`), Mutter 47+/KWin to confirm. Where the compositor lacks it
  there is **no render enforcement**, and the honest answer is a stated requirement — *confined GUI needs a
  `security-context-v1`-capable compositor* — not a silent gap. The forcing function; completes the 0.3.0
  X11 removal. Full design: `07-14-confined-gui.md`.

### Thrust 3 — One `kennel` binary, context-aware (the spawn facade, harmonised)

W19a (a 0.3.0 red-team finding) surfaced that the spawn vertical rests on a facade interface that was
*built but never specified* — and specifying it uncovered that the authority model was implicit. The
resolution is small in mechanism but worth doing properly: document the contract, and unify the spawn
surface behind one `kennel` shim over a `/usr/libexec` host/spawn execution split (retiring the separate
`facade-spawn` binary). Sized out of
0.3.0 deliberately; it lands here.

- **W8 · The facade kennel-spawn interface contract (document the existing surface).** **[dep] M.**
  Write down what the spawn facade already does, deriving the authority model from the principles rather
  than from the code (then check the code against it — divergence is a code fix, not a spec
  accommodation). The settled model, all homed in the **signed template**: `exec.allow` gates every
  binary that may run in the spawned kennel (the existing every-exec mechanism, reused — argv is
  unpinned because the allow-list does the gating, matched on the resolved binary not argv[0]); mutable
  fields are only those the template *exposes*, each patched within its declared bound via the existing
  manifest-patch validator (0.3.0 W4); frozen fields cannot move. The CLI shape that falls out:
  `kennel run net-fetch@v1 net.proxy.allow=ghcr.io:443 -- curl …` — three authority regions (named
  template `@`-pinned · bounded mutable-field patch · unpinned argv gated by `exec.allow`),
  syntactically distinct because semantically distinct. **Bound the scope:** answer the authority and
  envelope questions for the single-host, kennel-to-kennel model that exists; fence placement/federation
  as non-goals (no "where does it run" engine — it runs here, under this `kenneld`). The egress-patch and
  the argv are *independent* (the proxy gates regardless of what argv claims) — state it, so the
  independence is not misread as coupling.

- **W9 · `kennel caps` — the spawn-envelope introspection verb.** **[dep] S.**
  A read-only projection of the caller's resolved `[spawn.allow]`: the templates it may spawn, each
  template's exposed mutable fields *with their bounds* (so an agent composes a valid request first
  try), and remaining `max_instances`. **Scoped to the caller's own grant** — deny-by-default applied to
  introspection: a requester sees exactly what it could successfully spawn, never the host's full
  template set (which would be a reconnaissance surface). Derived projection, like the service catalogue
  over `[provides]` — computed from the grant, cannot drift from it. The instance count is an advisory
  snapshot, not a reservation; the atomic slot-claim at spawn time remains authoritative.

- **W10 · Unify the spawn surface behind one `kennel` shim; split execution into `/usr/libexec`.** **[dep] L.**
  One command surface, three binaries — because linkage is a build-time property the cage constraint
  will not let a single ELF straddle (everything in-cage is static; `kennel` on the host is the one
  dynamically-linked thing). The split separates *dispatch* from *execution*:

  - **`kennel` — a static, authority-free shim on `$PATH`.** The only name a user or agent types, in
    either context. It holds no authority and does no work: it detects context and `exec`s the right
    execution unit. Static so the same artifact runs host-side and in-cage.
  - **`/usr/libexec/kennel/host` — the dynamically-linked host execution unit.** The operator-side
    implementation (spawn a first kennel, `policy`, `ps`, `oci`, the full host surface).
  - **`/usr/libexec/kennel/spawn` — the statically-linked in-cage execution unit.** The confined
    spawn-requester implementation (`run`, `caps` over Node 0). Retires the `facade-spawn` name into
    this unit.

  **The surface is defined once, in a shared crate** both units link — the verb grammar, help, and
  argv parsing live there, so "one surface, two contexts" is one definition plus two thin
  context-specific mains differing only in linkage and which authority path they wire (host-direct vs
  Node 0 `SPAWN`). Unification is interface-layer; the two authority paths stay distinct and
  separately validated, never shared enforcement.

  **The spawn unit is gated by `exec.allow` like every other in-cage binary — no exception.** From the
  cage's view `/usr/libexec/kennel/spawn` is just an executable, and the every-exec rule applies: a
  workload runs it only if it is in that cage's `exec.allow`. So spawning is **double-gated** by two
  independent mechanisms — the `[spawn]` grant (*may this kennel spawn at all*) and `exec.allow` (*may
  this binary execute here*) — and the second falls out of existing enforcement for free, with no
  special-casing. This removes what would otherwise be the one binary exempt from the exec gate, and it
  makes the capability **visible in the reviewable policy**: `kennel policy show` reveals both the
  `[spawn]` grant and the spawn unit in the executable surface, two places that must agree.

  **Granting `[spawn]` derives the shim + spawn unit into the view and the allow-list** (the way a
  grant derives its threat tags) — the spawn-capable template's base view includes both binaries and
  its `exec.allow` includes both, auto-derived rather than author-remembered, so a policy cannot grant
  spawn yet leave the agent with command-not-found.

  **Detection collapses into which binary is present, which construction controls.** Inside a cage the
  host unit is *absent from the constructed view* (construction-by-absence) and not in `exec.allow`, so
  the shim cannot `exec` it from inside regardless of any dispatch decision — the only reachable,
  allowed unit is the spawn one. Dispatch correctness is therefore an **ergonomic** property, not a
  security one: a wrong decision cannot reach host authority because the host unit is doubly
  unreachable (absent + unallowed). The shim presents host dispatch only when it can complete a real
  `kenneld` handshake; a context-inappropriate option is refused with a context-naming message (the
  failure being solved is confusion, so the fix is legibility).

  **Belt to the absence braces: the host `kenneld` control socket is explicitly ungrantable.** A
  confined workload cannot reach it today because construction-by-absence keeps it out of the
  constructed view — but absence is a property of *correct* construction, and a too-broad future `[fs]`
  grant, a path-cascade edge case, or an operator's debug mount could regress it. For the one endpoint
  whose reachability *is* the escalation, ungrantability is made a **rule**, not an emergent
  consequence: the compiler refuses at install any grant whose **resolved target** is the host control
  socket (endpoint, not path-string — robust against cascade relocation), and the spawn factory refuses
  to place it into any kennel view at construction. Install-time is the loud primary guard; construction
  is the backstop for anything that bypassed install. **Scoped to the *host* socket only** — the
  kennel's own Node 0 endpoint is established by `kenneld` at construction (not by a grant) and is *not*
  in scope; a workload legitimately reaches Node 0, so the blacklist must not catch it. This joins the
  small set of structurally-refused-regardless-of-policy items (alongside the T2.8 trust-manifest mask
  and the special-use-destination egress refusal) — things whose reachability defeats the model, denied
  by rule and not only by absence.

  **This rule is the one security-load-bearing mechanism in an otherwise ergonomic thrust, and it is
  built and reviewed as such — not as a sub-bullet.** Dispatch correctness is ergonomic (a wrong
  decision cannot reach host authority, because the host unit is absent + unallowed), but *this* refusal
  is an escalation gate: a bug here is a host-control-socket reach, not a confusing error. It gets its
  own valid/invalid test corpus at the same altitude as W1's schema — and pointedly the endpoint-vs-path
  cases the framing turns on: a grant whose path-string differs but whose **resolved endpoint** is the
  host socket must reject (the case a naive path-string check passes and an endpoint check catches), a
  cascade-relocated mount onto the socket must reject, and the kennel's own Node 0 must *accept* (the
  must-not-overcatch case). It is also named explicitly in W15's red-team scope below.

### Thrust 4 — Trust and threat (the new surface)

- **W11 · The service-kennel trust class + multi-leg exemption.** **[dep] S.**
  Define the operator-declared, signed, non-composable standing-service-kennel category in the
  architecture corpus and the threat model — distinct from both workload kennels and spawn-target
  templates. Home the multi-leg exemption here as a general principle, so it is cited consistently
  rather than restated per-instance (the GUI two-leg case references this, does not redefine it).

- **W12 · THREATS entries + compliance mapping.** **[dep] M.**
  New residuals into `THREATS.md` and `dist/threats/catalogue.toml`, derived-from-grant the way
  T3.8/T3.9 are: a **standing-service delegation residual** (longer-lived attack surface than
  ephemeral spawn; the cross-kennel brokering channel) and the **GUI host-compositor leg**
  (a T1.6-equivalent — the engine's setup-time connection to the host compositor to register a
  `security-context-v1` tagged socket; scoped, in a confined kennel, required `reason`, with
  privileged-protocol denial enforced compositor-side). Plus the compliance-table mapping.

- **W13 · Documentation sweep: "authentication, never attestation."** **[dep] S–M.**
  Land the principle solidly across the corpus, not as a buried backlog note. The mesh provides
  use-capabilities (ssh-side: authenticate, render, transport), never attestation (gpg-side: vouch,
  sign, issue secrets) — because attestation's worth derives from the trust of its origin and the mesh's
  origins are confined-and-untrusted. The canonical statement already exists — design §4.3 now carries
  the generalised paragraph that lifts the gpg refusal to the standing rule (it governs every brokered
  capability, present facade or future cross-kennel one), so this workstream *completes the sweep around
  that anchor* rather than starting it: cross-reference §4.3 from the service-kennel trust class (W11),
  the §7.12.10 service-mesh scope, and the existing ssh-vs-gpg decision record so the latter reads as an
  *instance* of the general rule rather than a one-off, and surface it in the public-facing material
  (the README already states it). The positive form is in §4.3 too: trust material (credentials, keys)
  arrives as a signed construction parameter from the operator/host layer, never provided to a kennel by
  a peer at runtime. This sweep is what stops a future "useful" signing or secrets service from being
  proposed as a service kennel — the principle is written down where a contributor will hit it. **The one
  seam to name, not gloss:** a portal-style permission store that persists a decision keyed on an app-id
  the confined app can influence (W7's substrate confirm #1) sits right on the authentication/attestation
  line — call it out as the thin spot, gated on the identity-spoofing confirm, rather than asserting the
  line is clean everywhere.

### Thrust 5 — Operability (extends a shipped surface)

- **W14 · Extend the live-topology surface to the mesh.** **[dep] M.**
  W20 shipped `kennel ps` over ephemeral spawns in 0.3.0; 0.4.0 extends it to the standing mesh —
  who-provides-what, who-consumes-what, the catalogue readiness states, and sidecar restart status.
  An extension of a shipped surface, not a new build. A standing mesh cannot be operated blind: a
  flaked secrets broker must be *visible*, not a silent resolve-deny.

### Thrust 6 — Pre-ship

- **W15 · Red-team the cross-kennel surface.** **[dep, ship gate] M.**
  Same logic as 0.3.0's W19, pointed at the new surface: the W5 connector broker (can a consumer
  reach a service it didn't declare; can resolution be raced; can a restart confuse a consumer); the
  **provide-name namespace gate** (can a non-service-class kennel claim a reserved `dev.kennel.*` name
  and have a consumer brokered to the impostor — provider-name spoofing, W1); the **ungrantable
  host-control-socket rule** (does the endpoint-not-path-string resolution actually hold under a
  cascade-relocated mount; does it over-catch the kennel's own Node 0, W10); and the GUI legs (the
  host-compositor setup leg; whether `security-context-v1` actually denies the privileged globals on the
  target compositor, and the `xdg-dbus-proxy`/portal filter coverage). Standing services
  are a longer-lived attack surface than ephemeral spawn, and two of these are new structural refusals
  whose bug-class is escalation — the review bar rises accordingly.

- **W16 · README + website reconciliation: accuracy, then positioning.** **[dep] M.**
  After 0.4.0 the codebase is a full confinement framework — dynamic spawn, sub-4ms per-task
  isolation, a standing service mesh, confined GUI — while the README and `projectkennel.org` still
  describe a much earlier, smaller thing. The public front door chronically under- and mis-sells what
  the code does. Two passes, in order, **split across the ship gate** — both get done, only one blocks:

  - **Accuracy first — and this pass *is* a ship gate.** Reconcile every public-facing claim against the
    as-built tree — the same discipline run on the architecture corpus, pointed at the README and
    site: delete what is now false (pre-spawn, pre-mesh descriptions), correct what is stale, add what
    shipped and is undocumented (the four network modes as-built, the spawn model, the service mesh,
    the measured construction floor). Largely mechanical; can run against the repo. A confinement
    framework must not ship public docs that overclaim — that is a first-class defect (below) — so the
    accuracy pass blocks the release the way the red-team does.
  - **Positioning second — a fast-follow, *not* a ship gate.** A deliberate rewrite of the lead framing,
    and it should be done — but a perfect, fully-red-teamed codebase must not sit unreleased because the
    site's lead paragraph isn't repositioned yet. Positioning copy cannot be "done" the way a passing
    corpus is, and gating a security release on prose is process theatre. So it lands as a fast-follow
    after the tag, not as an exit criterion. Where not stale, the material
    is accurate-but-flat — technically true and strategically mute, the merit present but illegible to
    a reader who feels the agent-isolation pain. Rewrite the lead so the thing it does and *why that
    is hard* is legible: the reference-monitor model, deny-by-default, construction-by-absence, and
    the result that full per-task isolation became cheap enough to be disposable. **Cover the drift
    from the original premises as a feature, not a confession** — design and implementation moved well
    past where they started (the as-built network/IPC/spawn model is stronger and the latency floor
    lower than the first design assumed); the public material should reflect the *current* ambition,
    not the founding one.

  **Governing invariant: never overclaim (a first-class defect, equal to a security bug).** This is
  what makes the positioning pass safe for *this* project — a confinement framework whose README
  oversells is self-refuting. No marketing speak. The merit is real enough that **precise description
  is the strong pitch**: state exactly what the system does, name the residuals (T1.6, the GUI
  AF_UNIX leg, R2 delegated composition, the host-mode caveats) rather than hiding them, and let the
  precision carry the credibility. The discipline that makes the threat catalogue trustworthy makes
  the README trustworthy; a claim that cannot be defended against the substrate ships in neither.

  Sequenced **after the 0.4.0 surface lands** — a front door written against in-flight work is stale
  on arrival, re-introducing the lag this fixes. A capture/legibility item, sibling to the red-team:
  W15 makes the system legible to an adversary, W16 to an adopter.

## Sequencing

0. **Substrate confirms first — W0.** The GUI confirms run ahead of everything, because W7's scope
   depends on their outcome. Confirm A's mechanism is settled (and already imposes the seal-`/.flatpak-info`
   requirement on W7); confirm B has corrected the render mechanism to `security-context-v1`. Confirm A's
   interactive half and the new compositor-support confirm must come back clean on a
   `security-context-v1`-capable graphical host before W7 is scheduled.
1. **Contracts first — W1 (schema) + W2 (sidecar/readiness API) + W3 (`SVC_CONNECT` wire).**
   Test-first, no daemon; these freeze the cross-workstream contract every later thrust derives from.
   W1's schema is consumed by W4/W6/W7; W2's readiness API by W4 and W14; W3's wire contract by W5.
   Settle the connector lifecycle (consume-with-wait timeout, restart-invalidates-connectors) in W3's
   contract before W5 implements it.
2. **Runtime logic — W4 → W5 → W6 → W7**, each built against a frozen contract. Catalogue (the
   derived projection over W1), then the connector broker (the logic behind W3, resolving against W4),
   then sidecars (the supervision logic behind W2), then GUI (the first real consumer). W7 gated on the
   W0 confirms coming back fully clean.
3. **Spawn facade — W8 → W9 → W10**, independent of the mesh (it documents and harmonises the
   *existing* spawn surface, not the new mesh one). W8 (the contract) first — it derives the authority
   model the other two implement against; W9 (`caps`) and W10 (the unified binary) follow. Can run in
   parallel with Thrusts 2/4; slot against capacity.
4. **Trust + threat — W11 → W12 → W13**, in parallel with Thrust 2; W11 (trust class) before the GUI
   multi-leg case references it, W12 after the residuals are concrete, W13 (the doc sweep) once the
   trust class and threat entries give it something canonical to point at.
5. **Operability — W14** after W4 (it reads the catalogue) and W6 (it reads readiness).
6. **Pre-ship — W15 (red-team) gating, then W16's accuracy pass (also gating); W16's positioning pass
   is a fast-follow after the tag**, all after the whole mesh surface (W1–W7) *and* the harmonised spawn
   facade (W8–W10) exist. The accuracy reconciliation is written against the shipped tree, not in-flight
   work, or it is stale on arrival; the positioning rewrite then lands without holding the release.

The release carries **no OCI tail and no natural-extensions thrust** by design — the OCI integrity
ladder and the secrets broker are both in Backlog for principled reasons (TCB growth, model fit), and
version-pinning generalisation is a one-line promote-if-needed, not a workstream. 0.4.0 is the
service-mesh release and nothing else.

## Exit criteria

0.4.0 ships when: the W0 GUI substrate confirms have come back clean on a `security-context-v1`-capable
graphical host (W0 — confirm A's mechanism is settled and feeding the model; its interactive half and the
new compositor-support confirm are the remaining gate, and confirm B has already rebased the render leg
onto `security-context-v1`); the `[provides]`/`[consumes]` schema compiles with shape-checking and its
valid/invalid corpus passes (W1); the sidecar/restart-policy declaration schema and the readiness
state machine are landed and their transitions asserted as tests (W2); the `SVC_CONNECT` wire
contract is specified and round-trip tested (W3); the derived catalogue resolves with readiness
states (W4); the service-connector broker is built and proven by a policy-suite case exercising
`provide`/`consume` against the W3 contract — deny-by-default resolution, consume-with-wait, the
restart-invalidates-connectors behaviour (W5); the sidecar set autostarts and is supervised with
crash-loop-bounded restart feeding declared-but-failed (W6); **confined GUI ships** — a Wayland +
portal service kennel an app kennel consumes, version-pinned, completing the 0.3.0 W16 X11 removal
(W7); the spawn facade interface is documented as-built with the authority model derived from
principles, `kennel caps` reports the caller's scoped envelope, and the spawn surface is unified behind
one `kennel` shim over a `/usr/libexec/kennel` host/spawn split — the spawn unit `exec.allow`-gated and
auto-derived from the `[spawn]` grant, the `facade-spawn` name retired (W8/W9/W10); the service-kennel
trust class is defined, the new residuals are catalogued and risk-derived, and the
authentication-never-attestation sweep has landed (W11/W12/W13); the topology surface covers the mesh
(W14); the cross-kennel red-team pass is complete (W15); and the README and website have passed the
**accuracy reconciliation** — every public claim true against the as-built tree, free of any claim that
cannot be defended against the substrate (W16 accuracy pass). The **positioning rewrite** (W16) is an
explicit fast-follow, not a ship gate — done after the tag, never blocking it. The W0 confirms must come
back clean before W7 is scheduled. CHANGELOG records every stable-surface change — the `[provides]`/`[consumes]` policy schema,
the sidecar/restart-policy schema, the `SVC_CONNECT` IPC verb, the unified `kennel` CLI surface
(retiring `facade-spawn`), and the new threat-catalogue entries.

## Parked work

Items with no timeline — declined-on-principle, promote-on-demand candidates, and work fenced to a
later release — live in [BACKLOG.md](BACKLOG.md), not here, so they are not carried from one roadmap to
the next. This roadmap lists only what 0.4.0 commits to; the parking lot holds what it deliberately does
not, with the reasoning that keeps each from being re-proposed every cycle.

## Non-goals (explicitly out of scope)

- **Runtime service registration / dynamic discovery** — the catalogue is operator-static and
  resolution-only; a workload registering a service at runtime is a capability-granting side channel.
- **Service mesh orchestration** — no health-check-as-load-balancing, no multi-provider selection, no
  failover policy. `kenneld` resolves and brokers; it is not an orchestrator.
- **Protocol-body mediation in the daemon** — which D-Bus method, which portal interface, which MCP
  tool: all live in confined interposers at workload authority, never in `kenneld`.
- **Boot-ordering logic** — async autostart + consume-with-wait makes dependencies settle themselves;
  no topological start-order computation in the daemon.
- **Patching upstream GUI binaries** — the constructed view is shaped to the bwrap contract so the
  Flatpak proxy/portal run unmodified; zero patches carried.

