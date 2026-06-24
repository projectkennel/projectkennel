# Project Kennel — 0.4.0 plan

Status: **active** · Promoted: 2026-06-22 · Targets: 0.4.0
Baseline: 0.3.0 (released)

> This is a planning artefact, not a design or as-built document. The design corpus
> (`docs/design/`) and the as-built notes (`docs/architecture/`) remain the source of truth
> for *what each item is*; this file records *what 0.4.0 commits to, why, and in what order*.
> The two anchor designs are `docs/design/07-13-service-catalog.md` (sidecars + catalog) and
> `docs/design/07-14-confined-gui.md` (nested-compositor Wayland); their architecture contracts are
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
  confined-Wayland path (a per-kennel nested compositor) that makes that removal a replacement, not a
  capability regression.

The **forcing function and headline proof is confined GUI** — the first non-trivial service kennel,
and the thing that pressure-tests every mesh primitive.

Standing constraints that shape the mix (carried from 0.3.0):

- **The TCB grows here — and we state it plainly.** This is the first release since the post-spawn
  decomposition where `kenneld`'s own surface goes *up*, not down: the `SVC_CONNECT` broker, the
  catalogue resolver, the readiness state machine, and the lifted supervisor are new daemon logic and
  new daemon state-machine surface. The [[tcb-only-shrinks]] constraint as it actually binds is about
  the daemon's **dependency closure** and its **authored state**, and on *those* axes the line still
  holds: the broker parses no protocol bodies (fine-grained service mediation — which D-Bus method,
  which portal interface — lives in a confined component at workload authority, never the daemon; no mesh
  work may land a protocol parser in `cargo tree -p kenneld`); the catalogue is a derived projection, not authored
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

### Build state (2026-06-24)

This is a planning artefact written ahead of the build; most of it has since **landed**. Snapshot so the
prose tense is not mistaken for open work:

- **Merged.** W0 (substrate confirm), W1 (schema) + W8 (spawn-facade contract) (#83), W2 (readiness
  scaffold) (#84), W3 (`SVC_CONNECT` wire) (#85), W4 (catalogue) (#86–#89), W5 (broker + af-unix handoff)
  (#90, #92), W6 (supervisor + ondemand activation) (#91, #95), W7 (confined GUI compositor-broker) (#99),
  W11 (trust class) + W13 (auth-not-attestation sweep) (#102), W14 (mesh topology view) (#100),
  **W21** (host-owned rendezvous point + `/run` endpoint gating — replaces the `/proc/<pid>/root` handoff,
  e2e-proven; #103 design, #105 code) and **W12** (THREATS T1.12 + T3.10, landed with #105; #101 closed);
  W17 (version handshake) partial (#94). The mesh runtime, the GUI path, the topology surface, and the
  brokered connector are **shipped**.
- **Open for 0.4.0.** **W15** (red-team the cross-kennel surface — ship-gate); **W16** (README accuracy
  pass — ship-gate; positioning pass a fast-follow). **W9** (`kennel caps`) verified-built; **W10** (unify
  the spawn surface — multi-week, deferrable) tracks independently of the mesh.

The per-thrust entries below keep their original planning prose; treat the snapshot above as the authority on
what is built. Status notes inline (`*Landed: …*`, `**Status:**`) are the per-item record.

### Thrust 0 — Substrate confirms (gating, run FIRST)

The assumptions about **external substrate the project does not control** that the GUI headline (W7)
rides on — the render mechanism (Wayland). They run **first** — ahead of committing the GUI scope, not
merely ahead of scheduling W7 — because a dirty result should inform whether confined GUI is a 0.4.0 ship
item or the design forcing-function for a 0.4.0 mesh foundation it later rides on. They earned their keep
many times over: they falsified the "Flatpak Wayland proxy" premise, then the "host `security-context-v1`"
premise (released GNOME doesn't ship it), retired the portal/identity leg as unnecessary, and landed
on the host-independent **nested inner compositor** — proven end-to-end on stock GNOME (below). Detailed in
`07-14-confined-gui.md`.

- **W0 · GUI substrate confirms.** **[gating] S.** **Status: RESOLVED (2026-06-22, firsthand on real
  hardware). Confirm A retired (the portal it investigated is cut from W7); confirm B went through two
  corrections and landed on a host-independent answer — the per-kennel *nested inner compositor*, proven
  end-to-end on stock GNOME. `security-context-v1` is real and enforces (verified on sway), but GNOME lacks
  it through Mutter 50.1, so the design no longer depends on it. The gate is clear; what remains is
  engineering, not substrate risk.**
  Confirms run against Ubuntu 25.10→26.04 LTS (GNOME 49→50, Mutter 50.1) and sway 1.11 / Weston 14 / cage.

  - **Confirm A — portal identity through the bwrap-mimicked view. *RETIRED — the portal is cut (W7).***
    The investigation stands as the trail that led to cutting it: `xdg-desktop-portal` 1.18.4 derives a
    caller's app-id by reading **`/.flatpak-info`** from the calling process's mount-ns root, so the
    permission-store key is only as trustworthy as the view (a confused-deputy seam that would have required
    the kennel to *seal* `/.flatpak-info`). But the portal turned out to be **unnecessary** — Kennel brokers
    host resources natively (`fs` grants, SOCKS egress, AF_UNIX, the `IDBus` facade), so W7 cuts it (see W7).
    With no portal there is no `/.flatpak-info`, no app-id mimicry, and no sealing requirement — the seam is
    designed out rather than defended. Interactive permission-store behaviour is now moot (no portal to
    persist anything).

  - **Confirm B — the render-leg mechanism.** *Premise corrected twice; landed host-independent.* Verified
    firsthand on real hardware (Ubuntu 25.10 → 26.04 LTS, plus sway 1.11 / Weston 14 / cage).
    - **First correction — there is no "Flatpak filtering Wayland proxy."** Flatpak (1.14.6) ships none; it
      passes the Wayland socket *through* and filters only D-Bus. The right mechanism is the staging protocol
      **`security-context-v1`**: a sandbox engine mints a *tagged* Wayland socket and the **compositor**
      enforces the privileged-protocol denial. It works and enforces hard — verified on **sway 1.11**: a
      tagged client saw 31 of 50 globals, with **19 privileged globals denied** (screencopy ×2, virtual
      keyboard/pointer, input-method, layer-shell, clipboard/data-control ×2, foreign-toplevel ×2,
      session-lock, output/gamma/power control, dmabuf-export) and the security-context manager itself
      withheld (nesting blocked).
    - **Second correction — released GNOME does not implement it.** `wayland.app` lists "Mutter 49.2," but
      the live registry **and** a full binary-string sweep show **Mutter 49.0 (Ubuntu 25.10) and Mutter 50.1
      (Ubuntu 26.04 LTS) both lack it entirely** — not advertised, not compiled in, not gated. Ubuntu's
      Weston 14 and cage builds lack it too; on Ubuntu only the **wlroots** family ships it. GNOME is the
      majority desktop, so a host-`security-context-v1` design won't run where most users are. Dead end.
    - **The resolution — a per-kennel *nested inner compositor* (bring-your-own compositor).** Rather than
      rely on the *host* compositor, the GUI-service kennel runs an upstream compositor (cage / Weston / sway)
      inside the confinement; the confined app connects to **that**, and the host sees one ordinary client.
      The isolation is **structural — construction-by-absence for the display server**: the app's
      `wl_registry` is the inner compositor's globals, not the host's; the host's screencopy / input / other
      clients live on a socket the app never touches. **Proven end-to-end on stock GNOME 50** (no
      security-context support): cage nested under GNOME, reaching the host **only via an inherited fd**
      (`WAYLAND_SOCKET`, host socket path *absent* from its view — the exact GUI-service-kennel handoff),
      rendered a real GUI app on the desktop. Host-independent; no Kennel-authored parser;
      `security-context-v1` demotes to **optional defense-in-depth** where the inner compositor has it
      (wlroots). The inner compositor's own permissive surface (cage exposes screencopy etc.) is **scoped to
      the kennel's own world by the nesting** — it cannot reach the host or sibling kennels, so it is a
      same-trust-domain non-issue. **Folded into W7; `07-14-confined-gui.md` is written on the
      nested-compositor model, not the host-protocol one.**

  - **W0 exit — CLEAR.** Confirm A retired (the portal is cut from W7, so `/.flatpak-info` and its sealing
    concern are designed out); confirm B resolved to the **host-independent nested-compositor architecture**,
    proven on real GNOME. The earlier "ship only on a security-context-capable compositor + `wl-proxy`
    fallback" framing is **withdrawn** — the nested compositor *is* the cross-host mechanism (and a better
    one: construction, not filtering), so it works on GNOME and the `wl-proxy` fallback is retired (BACKLOG).
    What remains for W7 is **engineering, not substrate risk**: the per-kennel compositor lifecycle, the
    fd-brokered host leg, toplevel→host-window mapping, and dmabuf-passthrough perf. The confirms paid for
    themselves many times over — they killed *two* reach-for-the-wrong-component errors, a "won't-run-on-
    GNOME" dead end, and a whole unneeded portal/identity leg before a line of GUI code was written.

### Thrust 1 — Contracts first (schema + API, test-first, no daemon)

Self-contained and testable with no broker and no runtime — the contract every later thrust consumes.

- **W1 · `[provides]` / `[consumes]` schema + local compile validation.** **[dep] M.**
  New policy blocks in `schema/policy.toml.schema` and `kennel-lib-compile`. A provider declares
  `[[provides]]` (a public `name`, a typed `shape` — AF_UNIX / D-Bus name / binder connector — an
  `endpoint`, an optional private `key`); a consumer declares `[[consumes]]` (a `name`, `shape`, `at`,
  an optional `env` and `key`, and a `required` flag — hard dependency by default, `false` to start degraded). **Neither
  side names the other**, and resolution is a **runtime** act (the broker, W5) against the live catalogue
  (W4): the compiler only ever holds one policy, so it does **not** — and cannot — resolve across kennels
  (policies compile and sign independently; the provider set is whatever is installed at connect time, not
  what existed when a consumer was signed; full reasoning in `07-13-service-catalog.md` §7.13.3). What W1
  freezes is the schema and the **local** checks: well-formedness, `shape` is a defined transport, the
  reserved-namespace gate (below), and duplicate `name` within one policy. Compiler-side; out of
  `cargo tree -p kenneld`.
  **Test-first:** the valid/invalid corpus (well-formed accept; missing field / undefined `shape` reject;
  reserved-name-from-an-unverified-origin reject; in-policy duplicate-provide reject) is written and asserted
  before the compiler logic. The schema is frozen here — W2, W4, W5, W6 all compile against it; the
  cross-kennel resolution / shape-mismatch / dangling-consume tests live with the runtime broker (W5) and
  catalogue (W4), where the live installed set exists.

  **Confine the provide-name namespace — `[provides]` is not sidecar-only.** Any kennel may declare a
  `[provides]`, not just the operator-declared service set, so the name a provider may *claim* is the
  load-bearing gate, not which kennels are allowed to provide. The reserved `org.projectkennel.*` namespace
  (GUI/Wayland, D-Bus, the system service names a consumer trusts by reputation) is the **project's own** and
  is claimable only through a template signed by the **project maintainer key** — the *same mechanism spawn
  targets use*: a signed template is the unit of trust, and the host varies only its named `[[mutable]]` fields
  (a different compositor). The gate is **name-scoped, not template-scoped:** a `[[provides]]` lives only on a
  template (the delta-leaf form carries none), and a template with an *unreserved* name (`doe.john.cache`) is
  freely authored and signed by any valid key — only a reserved name needs the authorized signature, so a user
  who self-signs a reserved provide is refused at verification, closing the provider-name-spoofing channel
  without a `service_class` flag. A host may **optionally** declare *additional* reserved namespaces of its own
  (e.g. `com.acme.*`) and their authorized keys in the root-owned `system.toml` `[[reserved]]` table (design
  §7.13.5a); `org.projectkennel.*` stays the project's and is not host-redefinable. **Test-first:** the
  built-in reserved-name permission is computed from signature provenance (`resolve::ProvidesOrigin` — a
  reserved name is permitted only when it traces to a signature-verified template, never an unverified layer);
  a reserved name from an unverified origin rejects, a duplicate reserved claim rejects, an unreserved provide
  accepts. The *authoritative* gate — a reserved provide's settled signature must be a key authorized for the
  namespace (project maintainer for the built-in, or a host's `[[reserved]]` keys) — is the catalogue's (W4);
  compile is the fail-fast on the built-in namespace. This makes deny-by-default cover *who may be resolved as
  what*, not only *who may consume*.

- **W2 · The sidecar + restart-policy declaration schema, and the supervision/readiness API.**
  **[dep] M.**
  The *declaration* half of sidecars (W6's logic is the other half), in three pieces:

  - **Enablement — the systemd `.wants` model, designed (§7.13.6).** Installing a provider (its signed
    policy in the `policies/` cascade) and *enabling* one are distinct: an installed provider is inert
    until the operator links it into a host-level enablement directory — `autorun/` (eager, started at
    daemon start) or `ondemand/` (lazy, socket-activated on first consume). Both live only at the
    operator layers (`/etc/kennel/{autorun,ondemand}/`, `~/.config/kennel/{autorun,ondemand}/`) and at
    **neither vendor layer** — a vendor ships a provider but cannot self-enable it. The autostart set is
    *the links on disk*, re-derived on `daemon-reload` and restart, never standing authored state. So
    eager-vs-lazy is the operator's symlink choice, not a signed-policy field.
  - **The `[service]` supervision discipline (§7.13.7).** The per-sidecar restart policy
    (`always`/`on-failure`/`never` + backoff + max-attempts), signed into the policy because *how a
    service tolerates its own crashes* is the author's to declare — unlike the deployment posture, which
    is the operator's symlink. Schema + local validation here.
  - **The readiness state machine (§7.13.7) — the load-bearing API.** declared-but-pending /
    declared-and-ready / declared-but-failed, the contract the catalogue (W4) and topology surface (W14)
    read. **Test-first:** the transitions are asserted as a contract (pending→ready on construction
    success; pending→failed on crash-loop exhaustion; ready→pending on restart; the sticky-failed and
    idle-reaped-to-pending rules; the illegal transitions) *before* the supervisor implements them,
    because a wrong state propagates into every reader.

  Scaffold the record types and the catalogue-readiness interface here; the supervision loop itself is W6.

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

- **W17 · Control-plane version handshake (the runtime anti-drift guard).** **[dep] S–M.**
  *(Added 2026-06-23, from a 0.3.1 field finding.)*
  W1–W3 freeze the contracts test-first — anti-drift at *compile* time. This is its **runtime
  complement:** when two *different builds* of `kennel` and `kenneld` nonetheless talk (a reinstall
  without a daemon restart, a half-upgraded host), the skew must fail **loudly and at the boundary**, not
  as a cryptic error five layers down. The 0.3.1 install surfaced exactly this — a newer CLI compiled a
  settled policy carrying a field (`on_change`) the still-running older daemon could not parse, and it
  surfaced as `unknown field on_change, expected manifest` deep in policy loading rather than "your daemon
  is older than your CLI; restart it." API drift happens *despite* the contract discipline; the handshake
  makes it legible.
  A **protocol version** (bumped on any control-wire *or* settled-policy-schema change) plus the **build
  identity** are exchanged on the control connection at connect; `kenneld` checks them and, on an
  incompatible version, returns a **typed refusal** naming both versions and the remedy (restart the
  daemon) — *before* any request body or policy file is parsed. The settled-policy schema the daemon loads
  is explicitly in scope: the protocol version is the proxy that catches a CLI-compiled policy a daemon of
  a different build cannot read (the precise drift that bit 0.3.1). **Test-first:** equal versions accept;
  an incompatible version returns the typed remediation (not a parse error); the preamble round-trips; and
  the check is the *first* thing on the connection, so it precedes policy load. **Honest limitation,
  stated:** a handshake only binds versions that *have* it — a pre-handshake daemon cannot speak it, so
  this ends the cryptic-skew class *going forward*, it does not retrofit onto already-shipped builds. An
  IPC-protocol surface change (CHANGELOG-tracked); homed in the control-plane contract (`02-6-ipc.md`).
  Independent of the mesh — it can land early, beside W1–W3.

### Thrust 2 — Runtime logic (built against the frozen contracts)

- **W4 · The service catalogue (the derived projection).** **[dep] M.**
  `kenneld` assembles the registry from the `[provides]` blocks (W1) of the kennels it knows — a
  projection of signed policy, not authored central state — carrying the W2 readiness states fed by
  construction status. The projection's *shape* is derived; its *membership* (which kennels exist, and
  thus which `[provides]` are in scope) is the operator's declared set — derived-shape over
  authored-membership, not magic. **The catalogue is the authoritative reserved-namespace gate:** before it
  admits a reserved-name entry, it verifies the provider's originating-template signature is a key **authorized
  for that namespace** — the project maintainer key for the built-in `org.projectkennel.*`, plus any **host-declared**
  additional namespaces and their keys from the root-owned `system.toml` `[[reserved]]` table (design §7.13.5a:
  `org.projectkennel.*` is the project's and not host-redefinable; a host may *add* its own, e.g. `com.acme.*`).
  An *unreserved* provide needs no such check — any valid signature. The compile-time check (W1) is the
  fail-fast on the built-in namespace; the catalogue is where a self-signed reserved provide is finally refused
  and where the host's `[[reserved]]` table is consulted, so a reserved entry in the catalogue is one an
  authorized key signed.
  *Resolution-only, no runtime registration* (a workload registering a service at runtime is a
  capability-granting side channel — forbidden). Re-derived from the installed set on `kennel daemon-reload`
  (the `systemctl daemon-reload` analogue — refresh the catalogue, bring newly-declared eager providers
  online) and on daemon restart; never standing authored state. Full design: `07-13-service-catalog.md`.

- **W5 · The service-connector broker (the logic behind `SVC_CONNECT`).** **[dep] L.** The keystone.
  Implements the W3 wire contract: resolve a name against the W4 catalogue, broker a connector to the
  providing kennel — the standing-service sibling of `SPAWN`'s FD-handoff (resolve-and-broker rather
  than mint-and-inject). Carries the three properties W3 specified and tested: deny-by-default
  resolution, consume-with-wait, and the restart-invalidates-connectors contract (consumers `EOF` and
  re-resolve, reusing the soft-reaper semantics). **Request-don't-author, like spawn:** the workload
  requests a capability through the broker facade and `kenneld` matches the request against the signed
  `[[consumes]]` grant — the floor it cannot widen — exactly as `SPAWN` is matched against `[[spawn.allow]]`
  (§7.12.1). The consumer's `at` is materialised at construction, but the backing provider is brokered (and
  socket-activated, W6) only when the workload first reaches for it — which is what makes a soft
  `required = false` ("wants") consume work, and what lets a hard `required = true` be a construction-time
  *resolvability* check with the connection still made on demand. Lands §7.12.10's deferred cross-kennel
  `provide`/`consume`.
  **Connector shapes — af-unix lands; dbus-name and binder-connector defer (BACKLOG).** The W1 schema
  types three transports, but 0.4.0 brokers the **af-unix** connector handoff only. It is the critical
  shape — confined GUI (W7) rides a Wayland af-unix socket, and an af-unix consume reuses the existing
  `CONNECT_AFUNIX` facade *byte-identically* (kenneld dispatches a name matching a signed `[[consumes]]`
  to the broker; the facade is unaware), so the consumer side cost nothing extra. The **dbus-name** and
  **binder-connector** handoffs are **deferred to a later release**: the schema accepts them (policies may
  be authored and validated against them), but a consume of either shape is refused at broker time until
  its handoff is built. af-unix is sufficient for the 0.4.0 headline; the other two are a later increment,
  not a 0.4.0 gap. *(Landed: the af-unix broker, the consumer-side facade dispatch, and the two-kennel
  provide/consume e2e — `mesh-roundtrip`. The provider-side connector handoff it shipped is the
  `/proc/<pid>/root` form **superseded by W21** — see there before building any further mesh consumer.)*

- **W21 · Host-owned rendezvous point for the `af-unix` handoff (supersedes the shipped `/proc/<pid>/root`).**
  **[debt, ship-gate] S. MERGED (#105; design #103).** Shipped: the rendezvous point
  (`<runtime>/mesh/<tier>/<name>[.key]/`, bound at the in-view `dirname(endpoint)`, broker connects
  host-side), the `pid`/`/proc` deletion, and the optional `af-unix` endpoint defaulted + gated under `/run`.
  Settled schema untouched; **+40 TCB** (measured — the rendezvous derivation + bind cost more than the
  `/proc` join they replace; the win is the primitive, not LOC). policy-suite e2e (`mesh-roundtrip`,
  `gui-mesh`) PASS. *(Original entry below, for the rationale.)*
  A **correction to merged code**, not a forward build item: W4/W5/W6/W7/W14 all
  **shipped** (PRs #86–#100), and the af-unix handoff among them (#92) reaches a provider's endpoint by
  traversing the provider's mount namespace — `connect` to `/proc/<pid>/root/<endpoint>`, keyed on the
  provider **pid**. That is a namespace-crossing connect in the most privileged process, over a path the
  provider's view controls, with a **pid-reuse race** between *Ready* and the connect. The merged mesh runs
  on it today; W21 reworks it underneath the built consumers (W6 readiness, W7 GUI rebase onto the
  rendezvous path) and **must land before 0.4.0 ships** so the release does not ship the weaker handoff — it
  also gates W12 (the threat prose describes this mechanism). Frozen design: `07-13-service-catalog.md`
  §7.13.4b.
  Replace it with a **host-owned rendezvous point** that names the *capability*, not the provider process —
  `<runtime>/mesh/<tier>/<name>[.<key>]/`, derived deterministically from `(tier, name, key)`, all
  signed-catalogue state (none of it the pid; the optional private `key` is appended iff set, the same token
  that disambiguates a shared public name across policies). `kenneld` **derives and injects** the af-unix
  endpoint into the provider — no author-chosen path — and binds only that **per-capability** directory into
  the provider's view (never a shared parent, so a provider cannot reach a sibling's endpoint behind the
  broker). The provider binds where it is told; the socket inode is the one `kenneld` holds host-side, so the
  handoff becomes a plain `connect` to that path — **byte-identical to the host-socket facade**
  (`af_unix_connect` over `socket.real`, §7.6), the same §4.3 fd-broker shape.
  **Reuse-only — invents no path and touches no privhelper verb.** Each capability's rendezvous bind is
  **one ordinary `BindMount`** in the provider's `ShimView.binds`, mounted by the existing `materialize_binds`
  loop that already binds every view path — the privhelper construct half runs it unchanged. The handoff
  collapses onto the existing `connect_unix_timeout(&real, …)` call the `[[unix.allow]]` facade already uses;
  the `/proc/<pid>/root` join and the `pid` field **delete** from `svc_connect_handoff` and from
  `broker::Selected`/the catalogue. Readiness (W6) `stat`s the same host path — the pid leaves the model
  entirely, the reuse race becoming **structurally absent** rather than mitigated.
  **Scope.** `svc_connect_handoff` (the connect), the provider-construction per-capability rendezvous bind,
  the `(tier, name, key)` path derivation (one pure function, shared by construction and broker), dropping
  `pid` from `Selected`/`CatalogueProvider`, and the **schema change** this entails (a revision of W1's
  frozen mesh schema, noted honestly): for `af-unix` the provider no longer authors `endpoint` — `kenneld`
  derives it and injects it via a provider-side `env`, the listen-direction mirror of the consumer's
  `at`+`env` — and `key` gains a filesystem-safe-charset validation (it now appears in a path; a UUID already
  complies). The `SVC_CONNECT` wire (§7.13.4a) does **not** move: this is broker-internal mechanism below a
  frozen surface. The shipped surface is still small — one `svc_connect_handoff` call site and two catalogue
  fields — so the rework is contained; land it before any further mesh shape or consumer accretes on the
  `pid`/`/proc/<pid>/root` form, and before the 0.4.0 tag.
  **Rendezvous ownership on a same-capability collision.** Two equally-enabled providers of one
  `(tier, name)` with no `key` to separate them contest one rendezvous point. The rule (§7.13.4b, the §7.13.4
  fail-open doctrine extended one inch): the point has **one owner — the provider the broker resolves the
  name to**, so construction binds the per-capability directory *only for that selected owner*; the non-owner
  runs normally and is **shadowed**, not denied (no collapse-to-none DoS, no `kenneld` blow-up, no bind race).
  RP ownership ≡ broker resolution — the **same** selection, so they cannot disagree. This rides W4's
  projection (the selection already exists) and W14's topology surface (mark the shadowed provide); default
  is the stable resolution order, with an optional **incumbency tiebreak** (a `Ready` owner keeps the slot
  over an equal newcomer across `daemon-reload`) as a fast-follow, not required for correctness.
  **Scrub the broker to decision-core-plus-shims.** W21 is also the moment to audit the whole `SVC_CONNECT`
  subsystem (`kenneld::broker` + the `binder::svc_connect*` handlers) against the TCB-reuse discipline, so
  what remains is *truly* separate logic and thin shims over primitives that already exist — not a parallel
  implementation of things the codebase already does. The target end-state: the only irreducibly-novel code
  is `broker::decide` (pure resolution — match a signed consume to a catalogue candidate, no I/O) and the
  consume-with-wait loop in `svc_connect_activate_wait` (the cycle-safety deadline, §7.13.4a); everything
  else reduces to a shim — `svc_connect_handoff` → `connect_unix_timeout(derive_rp(…))` (the same call the
  `[[unix.allow]]` facade uses), the rendezvous mount → one `BindMount` through `materialize_binds`,
  request/reply → the existing `kennel-lib-binder::service` codec, audit → `writer.emit`. **As built it
  adds ~40 TCB SLOC** (measured): the `/proc/<pid>/root` join and `pid` plumbing it deletes are small,
  and the rendezvous derivation plus the construction bind cost more than they save — the win is the
  primitive (no namespace-crossing connect, no pid-reuse race), not LOC. No new dependency and no new
  authored state (the catalogue stays a projection); no second connect/bind/route path beside an existing
  one.

- **W6 · Sidecars: async boot-autostart + the borrowed supervisor (the logic behind W2).** **[dep] L.**
  The supervision half of W2's declaration schema. `kenneld` autostarts the declared set
  **asynchronously** at its own startup (lifecycle coupled to the daemon, not to any consumer),
  supervised by `kennel-bin-init`'s **already-multi-target facade supervisor** lifted to `kenneld`'s
  existing control level — the same control relationship `kenneld` already has with every kennel it
  owns, no new trust boundary (`kenneld` is not a kennel). Enforces the signed restart policy
  (executed not invented); crash-loop-exhaustion drives the W2 readiness machine into
  declared-but-failed (one mechanism, not two). Supervision state ephemeral, re-derived from signed
  declaration on daemon restart.
  **Two start disciplines, one supervisor.** Beside the eager boot-autostart set, a provider may start
  **lazily, on demand**: its config is installed, so its `[[provides]]` is in the catalogue from install
  (W4) and resolves, but the kennel is **not spun up until a consumer first reaches its capability** (the
  §7.14 "no consumer, no compositor" rule). The name is in the catalogue while the kennel is not yet
  running; the broker (W5) starts it on first consume and it is **idle-reaped through the existing kennel
  TTL custodian** (§9.7), not a parallel reaper. A consumer *is* the keep-alive: while a provider has at
  least one live consumer its TTL auto-renews; when the **last** consumer disconnects the TTL counter
  (re)starts, and if none returns before it expires the custodian reaps the now-idle provider (a fresh
  consume re-activates it from cold). The **policy sets the max TTL** — the ceiling on how long an idle
  provider lingers — so reaping is the author's tunable and rides one mechanism with the workload-TTL
  path, never a second one. *(Owed W6 work: activation lands, this consumer-refcount TTL idle-reaping is
  the remaining piece.)* Only the **trigger**
  (daemon start vs first consume) and the **lifecycle** (daemon-coupled vs consumer-driven) differ — the
  signed restart policy, the readiness machine, and the borrowed supervisor are the same for both. Full
  design: `07-13-service-catalog.md`.

- **W7 · Confined GUI: a per-kennel nested compositor as a service kennel.** **[dep] L.**
  A sidecar that `[provides]` GUI capability against the W1 schema: a **rendering leg** (the nested
  compositor) plus a small **Kennel-native file-broker** for interactive file access (the portal is cut; the
  one capability worth keeping is kept in-model — both below). W0 proved the render leg on real hardware,
  **host-independent** — it works on stock GNOME, which ships no `security-context-v1`.

  **Status — render/display leg BUILT (2026-06-24), with two refinements to the plan below; durable truth
  in [`07-14-confined-gui.md`](../design/07-14-confined-gui.md) +
  [`02-11-confined-gui.md`](../architecture/02-11-confined-gui.md).** (1) The host leg landed as the
  **af-unix facade brokered connect** (the inner compositor opens a facade shim; `kenneld` brokers each
  connect to the host, the relay forwarding `SCM_RIGHTS` fds via `splice_with_fds`), **not
  `WAYLAND_SOCKET`** — simpler, reusing the §7.6 path, and the host socket *path* is still absent (the shim
  names the facade). (2) The compositor is spawned **per app connection** by the `compositor-broker`
  workload and **reaped on disconnect** — the window folds when the app disconnects — not
  per-consuming-kennel / reaped-on-kennel-exit. Also landed: the private `/dev/shm` tmpfs (wlroots
  `shm_open`) and a headless `gui-mesh` policy-suite case. **Still designed, not built:** the interactive
  file-broker and the other desktop-service brokers below.

  - **Render leg — a per-kennel nested inner compositor (bring-your-own compositor).** The GUI-service
    kennel does not rely on the host compositor; it runs an upstream compositor (**cage** — a lightweight
    single-app kiosk — by default; Weston / sway as alternatives) **inside the confinement, one instance per
    consuming kennel**. The confined app connects to *that* compositor; the host sees one ordinary client.
    Isolation is **construction-by-absence for the display server** (§4.2): the app's `wl_registry` is the
    inner compositor's globals, never the host's — the host's screencopy / input / other clients sit on a
    socket the app cannot reach, *absent* not denied. This **composes the 0.4.0 primitives** rather than
    adding GUI-specific daemon surface:
    - **mesh** — the app kennel `consume`s GUI; **spawn** — the service kennel's broker spawns a compositor
      on demand (lazy: no connection, no compositor; reaped when the connection closes — see Status).
    - **fd-brokering** — the GUI-service kennel holds the **one** host Wayland socket; the inner compositor
      reaches it through the **af-unix facade brokered connect** (as built — see Status; W0 also proved the
      `WAYLAND_SOCKET` inherited-fd variant), so the host socket **path is absent** from the compositor's
      view (proven: cage nested under GNOME 50 rendering a real app on the desktop).
    - **per-connection isolation (§4.5)** — one compositor per app connection ⇒ cross-kennel GUI
      invisibility, and *finer*: even apps within a kennel do not share a compositor unless they share a
      connection. The compositor runs in its **own** kennel, never the app's (tamperproofing §4.6 — the app
      must not be able to subvert what confines it).
    The inner compositor's own surface (cage exposes screencopy, virtual input, etc.) is **scoped to the
    kennel's world by the nesting** — it captures the kennel's own pixels and injects into the kennel's own
    apps; it cannot reach the host or sibling kennels, so it is a same-trust-domain non-issue.
    `security-context-v1` is **optional defense-in-depth** where the inner compositor implements it (verified
    enforcing on sway 1.11: 19 privileged globals denied to a tagged client), not a dependency — which is
    *why this works on GNOME*. No Kennel-authored Wayland parser anywhere; the `wl-proxy` filter idea is
    retired (the nested compositor is the cross-host mechanism, and a better one — construction, not filtering).
    **Design invariant — confined GUI depends on no host-compositor enforcement.** The host sees one ordinary
    client and is asked to enforce nothing; bring-your-own-compositor is the right shape *unconditionally*,
    regardless of what any host compositor supports now or later. This is **not** "revisit when GNOME ships
    `security-context-v1`" — depending on the host compositor at all is the weaker position even where the
    protocol exists. The enforcer is a compositor Kennel ships and controls, inside a kennel.
  - **No host-services leg — the portal is CUT (2026-06-22).** `xdg-desktop-portal` is Flatpak's *only*
    escape hatch to host resources; Kennel already brokers those natively and in-model (files via `fs`
    grants, network via SOCKS egress, sockets via AF_UNIX brokered-connect, D-Bus via the `IDBus` facade), so
    the portal would only re-add a foreign D-Bus protocol + an app-id permission store + the `/.flatpak-info`
    identity mimicry. Cutting it **retires W0 confirm A** and the `/.flatpak-info` sealing requirement (they
    existed only to satisfy the portal). The one portal capability worth keeping — interactive file access —
    is kept *Kennel-native*, next.
  - **Interactive file access — a Kennel-native file-broker (committed, the one portal residual kept).**
    The portal's genuinely-useful function was FileChooser: the user picks a file at runtime and the app
    receives an **fd to just that file**, having held no filesystem. That pattern is not portal-shaped — it
    is *Kennel*-shaped: the same fd-broker as AF_UNIX brokered-connect and the SPAWN channel
    (construction-by-absence + interposition-by-transaction, §4.3). So confined GUI carries a **small
    Kennel-native file-broker**: `kenneld` brokers a host file picker, the user consents, and the workload
    gets one fd into its view — no D-Bus portal protocol, no app-id permission store, no `/.flatpak-info`.
    Coarse first (open/save one user-chosen file → one fd); save-back and multi-select are extensions. This
    is a **committed deliverable of confined GUI**, not a deferred maybe — a GUI app that can only touch its
    pre-granted paths is half a capability. (Whether it lands in 0.4.0 with W7 or as a fast-follow is a
    sequencing call; the capability is on the roadmap either way.)
  - **Other desktop services, if ever needed, are Kennel-native brokers — never a portal.** Screenshot /
    screencast is the inner compositor's own (cage) capability, scoped to the kennel (the compositor is
    Kennel's here, not the host's); openURI / notifications are brokered host-request services (the broker
    pattern again); desktop-service D-Bus rides the `IDBus` facade. None reintroduce a foreign protocol or
    identity model. **There is no foreign desktop-sandbox substrate in confined GUI** — only kennels, a
    compositor-in-a-kennel, and Kennel brokers; the capabilities are preserved, the implementation is owned.

  **The host residual is one AF_UNIX leg, concentrated and bounded:** only the GUI-service kennel reaches
  the host compositor, and only to vend fds — and even there it is *one ordinary Wayland client* to the host,
  contained by the host's own client isolation (the GUI T1.6-equivalent, required `reason`).

  **What remains is engineering, not substrate risk** (W0 cleared the substrate): the per-connection
  compositor lifecycle and its fd-brokered host leg are **built** (Status above); what is left is the
  interactive **file-broker**, dmabuf passthrough so the composition hop is ~zero-copy, and toplevel→host
  surface polish; clipboard / DnD left **isolated by default** (§4.7), a deliberate mediated bridge only
  later. The forcing function; completes the 0.3.0 X11 removal. Full design: `07-14-confined-gui.md`;
  as-built contract: `02-11-confined-gui.md`.

  **Open thread — RESOLVED (`07-14-confined-gui.md` written).** Both halves are landed in the design
  corpus, so the conclusion survives this roadmap's retirement: §7.14 carries the durable conclusions
  present-tense, as-built — the *no host-compositor enforcement* invariant (§7.14.4), *no foreign
  desktop-sandbox substrate* (§7.14.8), and the capability-preservation mapping (render = nested compositor,
  file access = Kennel file-broker, other desktop services = Kennel brokers). The substrate verdict is the
  chapter's closing **decision record (§7.14.13)**, recorded *in the chapter* rather than a standalone
  governance audit — a positive rationale (why the display server is constructed, not borrowed; why the
  non-existent Wayland proxy, host `security-context-v1`, and a foreign desktop-sandbox substrate each fail
  their check) that passes the `no-never-built-mechanisms` guard and fits the no-tombstone standard. The
  superseded `IWayland` Node-0 wire-facade framing was struck from the binder corpus in the same pass.

### Thrust 3 — One `kennel` binary, context-aware (the spawn facade, harmonised)

W19a (a 0.3.0 red-team finding) surfaced that the spawn vertical rests on a facade interface that was
*built but never specified* — and specifying it uncovered that the authority model was implicit. The
resolution is small in mechanism but worth doing properly: document the contract, and unify the spawn
surface behind one `kennel` shim over a `/usr/libexec` host/spawn execution split (retiring the separate
`facade-spawn` binary). Sized out of
0.3.0 deliberately; it lands here.

- **W8 · The facade kennel-spawn interface contract (document the existing surface).** **[dep] M.**
  **Documented (2026-06-23): the contract is design §7.12.3a — the three authority regions (`@`-pinned
  template · bounded mutable-field patch · `exec.allow`-gated argv), their independence (the proxy gates
  egress regardless of argv), and the single-host kennel-to-kennel scope bound; the as-built mechanics are
  02-10 (`facade-spawn`). Code checked against the model — `exec.allow` gates the resolved binary via
  Landlock (not the `argv[0]` string), no divergence.**
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

- **W12 · THREATS entries + compliance mapping.** **[dep] M. MERGED (landed with #105).** T3.10
  (standing-service delegation) and T1.12 (GUI host-compositor leg) are in `THREATS.md` +
  `dist/threats/catalogue.toml`, the mitigation written against the rendezvous point (§7.13.4b); the
  first cut (#101, against the `/proc` handoff) is closed. *(Original entry below.)*
  New residuals into `THREATS.md` and `dist/threats/catalogue.toml`, derived-from-grant the way
  T3.8/T3.9 are: a **standing-service delegation residual** (longer-lived attack surface than
  ephemeral spawn; the cross-kennel brokering channel) and the **GUI host-compositor leg**
  (a T1.6-equivalent — the GUI-service kennel's connection to the host compositor, held only to vend
  per-kennel host fds; one ordinary Wayland client to the host, in a confined kennel, required `reason`).
  Plus the compliance-table mapping.
  **Sequenced after W21 — the threat prose describes the handoff, which W21 reshapes.** The
  standing-service residual's mitigation must describe the **host-owned rendezvous point** (§7.13.4b), not
  the `/proc/<pid>/root` namespace-crossing connect the broker does today: W21 *strengthens* this story —
  it removes the namespace-cross, the provider-controlled endpoint path, and the pid-reuse race — so the
  T3.10 mitigation and its residuals shift. (A first cut of these entries was written against the old
  handoff and must not merge ahead of W21; rewrite the mitigation/residual prose against §7.13.4b once it
  lands.)

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
  proposed as a service kennel — the principle is written down where a contributor will hit it. *(The
  portal-permission-store seam earlier flagged here is **designed out**: W7 cut the portal, so there is no
  app-id permission store to be a confused deputy — the thin spot was removed rather than defended.)*

### Thrust 5 — Operability (extends a shipped surface)

- **W14 · Extend the live-topology surface to the mesh.** **[dep] M.**
  W20 shipped `kennel ps` over ephemeral spawns in 0.3.0; 0.4.0 extends it to the standing mesh —
  who-provides-what, who-consumes-what, the catalogue readiness states, and sidecar restart status.
  An extension of a shipped surface, not a new build. A standing mesh cannot be operated blind: a
  flaked secrets broker must be *visible*, not a silent resolve-deny.

  **Status — provider side built (2026-06-24).** `kennel list` now carries the mesh view (the §7.13.7
  topology surface): a `Mesh` control verb projects the live catalogue, and the CLI prints a
  capability→provider table with each provider's **readiness** (pending/ready/failed — so a flaked
  broker is visible), shape, enablement, tier, and pid, below the running-kennel tree. This is
  *who-provides-what + the readiness states + sidecar restart status* (the supervisor drives readiness,
  so a crash-looped sidecar shows `failed`). **Follow-up: the consumer side** (*who-consumes-what*) —
  each running kennel's `[[consumes]]` is loaded into its `KennelData` but not held in the registry, so
  surfacing it needs a `KennelMeta` field set in `run_kennel`; deferred to keep this increment off the
  construction hot path.

### Thrust 6 — Pre-ship

- **W15 · Red-team the cross-kennel surface.** **[dep, ship gate] M.**
  Same logic as 0.3.0's W19, pointed at the new surface: the W5 connector broker (can a consumer
  reach a service it didn't declare; can resolution be raced; can a restart confuse a consumer); the
  **provide-name namespace gate** (can a self-signed or unverified-origin template claim a reserved
  `org.projectkennel.*` name and have a consumer brokered to the impostor — provider-name spoofing; does the
  catalogue's maintainer-signature gate hold against a user-signed reserved provide, W1/W4); the **ungrantable
  host-control-socket rule** (does the endpoint-not-path-string resolution actually hold under a
  cascade-relocated mount; does it over-catch the kennel's own Node 0, W10); and the GUI legs (does the
  nested inner compositor leak any host global to the confined app; can one kennel's compositor reach
  another's or the host beyond one-client; the fd-brokered host leg). Standing services
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

0. **Substrate confirms first — W0: DONE (2026-06-22).** The GUI confirms ran ahead of everything and
   cleared the substrate. Confirm A is retired (W7 cuts the portal it investigated); confirm B resolved to
   the host-independent **nested inner compositor**, proven end-to-end on stock GNOME 50. W7 is no longer
   substrate-gated; what remains is engineering, not substrate risk.
1. **Contracts first — W1 (schema) + W2 (sidecar/readiness API) + W3 (`SVC_CONNECT` wire) + W17
   (version handshake).** Test-first, no daemon; these freeze the cross-workstream contract every later
   thrust derives from. W1's schema is consumed by W4/W6/W7; W2's readiness API by W4 and W14; W3's wire
   contract by W5. W17 is the runtime anti-drift guard on the same control plane, independent of the mesh,
   so it lands whenever capacity allows. Settle the connector lifecycle (consume-with-wait timeout,
   restart-invalidates-connectors) in W3's contract before W5 implements it.
2. **Runtime logic — W4 → W5 → W6 → W7 → W21: MERGED** (#86–#100, #105), each built against a frozen
   contract. Catalogue (the derived projection over W1), the connector broker (the logic behind W3, resolving
   against W4), sidecars (the supervision logic behind W2), GUI (the first real consumer), then **W21** — the
   post-merge correction of the provider-side handoff (#92) to the host-owned rendezvous point, reworked
   *underneath* the built W6 readiness and W7 GUI and proven by the policy-suite e2e.
3. **Spawn facade — W8 → W9 → W10**, independent of the mesh (it documents and harmonises the
   *existing* spawn surface, not the new mesh one). W8 (the contract) first — it derives the authority
   model the other two implement against; W9 (`caps`) and W10 (the unified binary) follow. Can run in
   parallel with Thrusts 2/4; slot against capacity.
4. **Trust + threat — W11 → W12 → W13: MERGED** (#102, #105). W11 (trust class) before the GUI multi-leg
   case references it; W12 (T3.10/T1.12) landed with W21 (#105) so the mitigation describes the rendezvous
   point, not the superseded `/proc/<pid>/root` connect; W13 (the doc sweep) once the trust class and threat
   entries gave it something canonical to point at.
5. **Operability — W14** after W4 (it reads the catalogue) and W6 (it reads readiness).
6. **Pre-ship — W15 (red-team) gating, then W16's accuracy pass (also gating); W16's positioning pass
   is a fast-follow after the tag**, all after the whole mesh surface (W1–W7) *and* the harmonised spawn
   facade (W8–W10) exist. The accuracy reconciliation is written against the shipped tree, not in-flight
   work, or it is stale on arrival; the positioning rewrite then lands without holding the release.

The release carries **no OCI tail and no natural-extensions thrust** by design — the OCI integrity
ladder and the secrets broker are both in Backlog for principled reasons (TCB growth, model fit), and
version-pinning generalisation is a one-line promote-if-needed, not a workstream. 0.4.0 is the
service-mesh release — plus the one robustness item its expanded IPC surface earns (W17, the
control-plane version handshake) — and nothing else.

## Exit criteria

0.4.0 ships when: the W0 GUI substrate confirms are cleared (DONE — confirm B resolved to the
host-independent nested-compositor architecture, proven on stock GNOME 50; confirm A retired with the
portal); the `[provides]`/`[consumes]` schema compiles with shape-checking and its
valid/invalid corpus passes (W1); the sidecar/restart-policy declaration schema and the readiness
state machine are landed and their transitions asserted as tests (W2); the `SVC_CONNECT` wire
contract is specified and round-trip tested (W3); the control-plane version handshake rejects an
incompatible CLI/daemon pair with a typed remediation *before* any policy is parsed, round-trip tested
(W17); the derived catalogue resolves with readiness states (W4); the service-connector broker is built and proven by a policy-suite case exercising
`provide`/`consume` against the W3 contract — deny-by-default resolution, consume-with-wait, the
restart-invalidates-connectors behaviour (W5); the sidecar set autostarts and is supervised with
crash-loop-bounded restart feeding declared-but-failed (W6); **confined GUI ships** — a GUI-service
kennel that spawns a per-kennel nested inner compositor (host-independent, no portal) plus a Kennel-native
file-broker for interactive file access, an app kennel consumes it, completing the 0.3.0 X11 removal (W7); the spawn facade interface is documented as-built with the authority model derived from
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
the sidecar/restart-policy schema, the `SVC_CONNECT` IPC verb, the control-plane version handshake,
the unified `kennel` CLI surface (retiring `facade-spawn`), and the new threat-catalogue entries.

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
  tool: all live in confined components at workload authority (an existing tool, not a Kennel-built
  interposer), never in `kenneld`.
- **Boot-ordering logic** — async autostart + consume-with-wait makes dependencies settle themselves;
  no topological start-order computation in the daemon.
- **Patching upstream GUI binaries** — the nested inner compositor (cage / Weston / sway) runs
  **unmodified**; the confinement is the per-kennel nesting, not a patched compositor. Zero patches carried.

