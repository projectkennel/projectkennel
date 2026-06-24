# §7.13 Policy surface: the cross-kennel capability mesh (`provide` / `consume`)

> **A kennel offers a capability to other kennels by declaring `[[provides]]` (a name and a typed
> *shape*); a kennel reaches one by declaring `[[consumes]]` (the same name and shape). `kenneld`
> instantiates the connector between a declared provider and a declared consumer at construction,
> deny-by-default — neither side reaches the other unless both declared it and the operator signed
> both policies.** Resolution is a **runtime** act: the broker matches a consumer's declared capability to a
> provider in the catalogue, and a `consume` that resolves to nothing simply reaches nothing. There is
> no cross-kennel guarantee baked in at compile, because policies are compiled and signed *independently* and
> the providers a consumer can reach are whatever the operator has installed — discovered, and started on
> demand, at runtime — not whatever existed when the consumer was signed. Compile-time validates only what is
> *local* to the one policy in hand. This is the substrate of the
> standing-service fabric — the GUI display service (§7.14) is its first consumer.

The single isolated kennel is complete on its own: it holds the capabilities its policy grants and reaches
nothing else, and two kennels are mutually invisible by default (§4.5). A *mesh* is the deliberate
exception — a workload that uses a capability another confined kennel provides, without either kennel
holding the other's authority. A desktop application reaches a display server it does not run; an app
reaches the session bus through a D-Bus broker without holding a host socket. The mesh keeps the lateral
model intact: the provider and consumer
remain sibling kennels under `kenneld`, neither nested in the other (§4.5), and the only thing that crosses
between them is the one connector the operator declared and `kenneld` brokered.

The mesh is **operator-declared, derived, and deny-by-default**, the discipline carried from dynamic spawn
(§7.12): a workload cannot author a cross-kennel reach at runtime any more than it can author policy. Both
the provider's offer and the consumer's use are signed declarations; `kenneld` brokers only the pairs both
sides declared, and the set of reachable capabilities is a *projection* of those declarations, never
standing authored state.

## 7.13.1 The declaration — `[[provides]]` and `[[consumes]]`

A provider lists each capability it offers:

```toml
[[provides]]
name = "org.projectkennel.wayland"              # the public identifier — what the catalogue advertises
shape = "af-unix"                        # the transport (§7.13.2)
endpoint = "$XDG_RUNTIME_DIR/wayland-0"  # where the capability is exposed, in the provider's own view
reason = "the confined display service for desktop-application kennels"
# key = "…"  — optional private match token (below); omitted here, a reserved name on a maintainer-signed template
```

A consumer lists each capability it reaches:

```toml
[[consumes]]
name = "org.projectkennel.wayland"              # the public identifier, resolved against the catalogue
shape = "af-unix"                        # the broker presents a socket here; the workload connects to it (§7.13.2)
at = "$XDG_RUNTIME_DIR/wayland-0"        # the socket the workload connects to, in its own view
env = ["WAYLAND_DISPLAY"]                # names `at` to the workload
required = true                          # absence fails kennel construction (default); false → start without it
reason = "render the application's window through the confined display service"
```

**Name, not peer; and an optional private key.** A provider does not enumerate its consumers and a consumer
does not name a provider kennel. A consumer names the **capability** — by `name`, the way a client names a
service or an interface, never the process behind it. The `name` is the capability's *public identifier*:
it is what the service catalogue advertises and what a consumer resolves against at runtime (§7.13.4), and it is not a
secret. The optional **`key`** is its private complement — an opaque, non-advertised token (a UUID, say)
that a provider and a chosen consumer both set to the same value, which the broker additionally requires to
match at runtime (§7.13.4). The name lets a consumer *discover and resolve*; the key lets a provider and a
specific consumer *bind privately*, so a public name a different kennel could also advertise does not by
itself get a consumer brokered to the wrong provider. The key is **optional** — a reserved `org.projectkennel.*`
capability is trusted through its maintainer-signed service template (§7.13.5) and needs none — and it is
**never published in the catalogue**. Crucially, nothing in a declaration points at another kennel: a key is a
literal value both sides happen to share, not a reference to another policy. There is no cross-kennel
reference anywhere in the surface — resolution happens at runtime, by name, against the catalogue
(§7.13.4).

**The shape says the transport; each side says where.** `shape` names *how* the capability is carried
(§7.13.2) but not *where* it lives. A `[[provides]]` declares its **`endpoint`** — where, in the provider's
own view, the capability is exposed (a socket path it listens on for `af-unix`, a bus name for `dbus-name`,
a registered node for `binder-connector`). A `[[consumes]]` declares **`at`** — the standing endpoint the
broker presents in the consumer's own view for the workload to *act against*: an `af-unix` socket the
workload connects to, named to it by the optional **`env`** (a Wayland client reads `WAYLAND_DISPLAY`). The
two are independent and per-view: the provider's `endpoint` is absent from the consumer's view (§4.2) and the
consumer's `at` is its own, so the broker's whole job is to wire one to the other without either side
learning the other's address. (Delivery is a socket the workload *connects to*, **not** a pre-connected fd
handed in, precisely so the connect can be the on-demand trigger — §7.13.4; the inherited-fd form,
`WAYLAND_SOCKET`, is the *eager* parent-hands-child case of §7.14.3, not an on-demand mesh consume.)

`env` lives on the **consumer**, not the provider, for the same reason everything else does: a consumer's
environment is built at **its** construction (§7.9.2's policy-synthesised environment), when the provider's
policy is not in hand — the provider may not even be resolved yet (lazy, on-demand) — so the consumer must
carry its own env declaration rather than read it across a boundary that is not there at construction time.
The minor cost is that a consumer restates the variable its capability needs (a GUI consumer restates
`WAYLAND_DISPLAY`); that is carried by the consumer-side template, not hand-repeated per kennel.

Both sides also carry the **`shape`** deliberately: a consumer must know a capability's shape to use it at
all — a connected `AF_UNIX` fd, a reachable D-Bus name, and a binder connector are acquired through entirely
different mechanisms — so stating the expected shape lets the broker **refuse a mismatched transport** (a
consumer that expects an `af-unix` fd is never handed a `dbus-name`): caught at connect, deny-and-audit
(§7.13.4), not silently misdelivered. Each entry also carries a `reason` (every capability grant does) and
an optional threat-tag set.

**Required or optional.** A `[[consumes]]` carries a **`required`** flag for whether the capability's
absence breaks the kennel. `required = true` (the default) is a hard dependency: if the capability does not
**resolve** against the catalogue at construction — no installed provider offers the `name` — **kennel
construction fails**, loudly, rather than start a workload missing something it needs (and a mistyped `name`
is caught at setup, not at first use). The check is *resolvability*, not connection: even a required
capability is connected on demand (§7.13.4), so `required = true` aborts construction when nothing *provides*
the name, not when the provider is merely not yet running. `required = false` is a soft dependency: an
unavailable capability is skipped and the kennel starts without it, the workload responsible for tolerating
the absence. This is the systemd `Requires=`/`Wants=` distinction, evaluated at **construction against the
catalogue** — never at compile, which cannot know what a deployment has installed (§7.13.3). The default is
hard because declaring a consume is declaring a dependency; tolerating absence is the deliberate opt-out.

`[[provides]]` and `[[consumes]]` are the **single** cross-kennel surface. There is no separate
transport-specific provide/consume; the binder cross-instance reach that earlier drafts expressed as a
dedicated `[binder]` provide/consume list is the **binder-connector shape** of this surface (§7.13.2), and
the agent↔tool topology is expressed in those terms. Folding the transports into one
shape-typed surface is what lets a single broker and a single catalogue describe *every* cross-kennel reach
uniformly, rather than a separate mechanism per transport.

## 7.13.2 Typed shapes

A capability's shape is how its connector is delivered to the consumer once `kenneld` has authorised the
pair. Three shapes are defined:

- **`af-unix`** — the broker presents an **`AF_UNIX` socket** at the consumer's `at`; the workload connects
  to it, and `kenneld` bridges that connection to the provider's `endpoint` — socket-activating the provider
  on the first connect if it is not up (§7.13.4) — then steps out of the byte path (§4.3). The consumer
  connects only to its own `at`; the provider's socket *pathname* never enters its view. The display render
  leg is this shape: the app connects to the Wayland socket its inner compositor is reached at, and that
  first connect is what spins the compositor up (§7.14.3).
- **`dbus-name`** — the consumer may reach a specific **D-Bus name** on a bus, mediated by the `IDBus`
  facade (§7.7), which already filters D-Bus per message. The mesh declaration authorises *which* provider
  name is reachable; the facade governs the calls. No second D-Bus path is introduced.
- **`binder-connector`** — the provider offers a binder node, and the broker delivers a **connector** to
  it: the consumer's standing endpoint is node 0, its action is a **`getService`** (§7.1), and `kenneld`
  returns a reference to the provider's node. Whatever rides the connector afterwards is opaque to
  `kenneld`, which frames and parses none of it.

The shapes are not delivered identically, but they share the structure that makes **on-demand** possible:
each gives the consumer something *present from construction to act against*, and the consumer's action
against it is the trigger `kenneld` intercepts to resolve the provider, socket-activate it if it is cold, and
bridge. For `af-unix` that standing thing is the socket at `at` and the action is a **connect**; for
`dbus-name` it is the `IDBus` facade the consumer already has (§7.7) and the action is a **call** — the
broker's part is to widen the facade's allow-set for this consumer, authorising *which* destination it will
carry calls to, not to mint a new socket; for `binder-connector` it is node 0 and the action is a
**`getService`**. None hands a **pre-connected fd into** a workload, and that is deliberate, not incidental:
a workload that acts on demand has no fd to receive at its own construction (it has not acted yet, and the
provider may not be up). The standing endpoint plus the action-as-trigger is exactly what lets a provider
come up only when reached — see §7.13.4.

The shape set is closed and small on purpose: each shape is a *transport the system already mediates*, so
the mesh adds a declaration-and-brokering layer over existing facades rather than a new protocol surface.
Adding a shape means adding a transport `kenneld` already brokers, never teaching the broker a new wire
protocol.

## 7.13.3 What compile validates, and what only runtime can

A cross-kennel match cannot be settled at compile, and the design does not pretend otherwise. Policies are
compiled and signed **independently** — the compiler only ever holds the one policy in front of it, never
the others — and the providers that can answer are whatever the operator has **installed** at connection
time (started on demand if not already up), not whatever existed when a consumer was signed. A signed artefact cannot be made to depend on
the presence of another mutable, independently-authored one; "resolve this consume against the known
kennels, at compile" has no known kennels to resolve against. Matching is therefore a **runtime** property,
and putting it anywhere else would be a guarantee the system cannot keep.

So the two checks live in two places:

- **At compile — local validation only.** Everything checkable from the single policy in hand plus the
  signature provenance: each `[[provides]]`/`[[consumes]]` is well-formed (a `name`, a `shape`, an
  `endpoint`/`at`, a `reason`); `shape` is one of the defined transports (§7.13.2); a reserved
  `org.projectkennel.*` provide traces to a maintainer-signed template (§7.13.5); and no two
  `[[provides]]` in *this* policy claim the same `name`. None of these consults another kennel, so all of
  them hold on a signed artefact for its whole life.
- **At runtime — resolution and matching.** When a consumer reaches for a capability, the broker resolves
  its `name` against the **catalogue** — the projection of the installed configs that declare `[[provides]]`
  (§7.13.4) — requires the optional `key` to match, enforces the expected `shape`, and applies the
  deny-by-default identity check. The matched provider need not already be running: an enabled provider is
  **started on demand** if it is not up (the lazy enablement of §7.13.6), so a `name` is in the catalogue
  because a signed config provides it *and the operator enabled it* (§7.13.6), not because that kennel
  happens to be running. A consume
  that resolves to no installed provider, to a shape that disagrees, or to a key that does not match is
  **denied and audited** at connect — it reaches nothing, the correct and safe outcome, not a failure to have
  caught something earlier.

The honest version of "verify before you run" is an **operator diagnostic**, not a signature gate: tooling
*may* report, over the set a deployment has *currently installed*, which `[[consumes]]` resolve and which do
not — a useful snapshot for an operator wiring a mesh, explicitly advisory because that set changes the
moment a service kennel is added or removed. The authority remains the runtime broker; the diagnostic only
tells the operator what the broker would find *right now*.

## 7.13.4 Deny-by-default and the brokered connector

Authorisation is the **consumer's signed `[[consumes]]`** — nothing else. A kennel reaches a capability iff
its own operator-signed policy declares a `[[consumes]]` for it; a kennel with no such declaration reaches
nothing (deny-by-default). The provider is passive: it offered the capability, and the operator decides who
uses it by what it signs into each *consumer's* policy, never by an allowlist the provider maintains. This
keeps the provider decoupled from its consumer set — the display service need not know which applications
render through it — and it is the same shape as the rest of Kennel, where a capability is granted on the
kennel that uses it (egress on the consuming kennel, not an allowlist on the destination). Two kennels with
no consuming declaration between them remain mutually invisible (§4.5), exactly as before the mesh existed.

**What the broker does on a consume request**, stated once and canonically — when the workload first reaches
for `at` (or its facade), `kenneld`:

1. checks the request against the consumer's **kernel-stamped identity** (§4.3, the unforgeable principal)
   and confirms its signed policy declares this `[[consumes]]` — request-don't-author (§7.12.1): the workload
   can only request what its policy already grants, and cannot widen it;
2. resolves the `name` against the catalogue to a single provider;
3. requires the optional `key` to match, if both sides set one;
4. enforces the consumer's expected `shape`;
5. **socket-activates the provider if it is not already running** (below) and bridges the workload's
   connection — made to the socket at `at` — through to the provider's `endpoint`, then steps out of the
   byte path.

Every step is a lookup or an equality, not a fresh policy evaluation: *whether* this kennel may consume was
decided when the operator signed its `[[consumes]]`; the broker only enforces that signed grant against what
is present. A failure at any step — no installed provider, a shape that disagrees, a key that does not
match — is a **denial-and-audit**, never a silent fallback to another provider.

**A shared name keeps every provider; the key (then tier) selects.** Resolution is to a *single* provider,
but the catalogue is a projection of independently-signed policies and a public `name` may be offered by
more than one enabled provider — the design anticipates exactly this, which is why the optional `key` exists
(§7.13.1). The catalogue keeps **all** authorized providers of a name as candidates and never collapses
them: collapsing to "no winner, so none" would let one provider **revoke** a name another serves simply by
also claiming it — a denial-of-service by name-claim, honesty-shaped but a DoS all the same. So a second
provider claiming a name **adds a candidate**; it can never empty the name. The broker (§7.13.4a) selects
among candidates: a consumer that set a `key` is bound to the candidate whose `key` matches (the private
binding); for candidates that are **truly equivalent** — no `key` to tell them apart — the preference is the
cascade direction, **per-user over per-host** (a user's own enabled provider wins the name on that user's
kennels; there is no vendor tier, as a vendor cannot enable, §7.13.6). A reserved name cannot be contested
this way across trust boundaries — only an authorized key may claim it (§7.13.5) — so a shared *public* name
is the only case, and it is the operator's own arrangement, made legible (the topology surface shows the
several providers), never a silent denial. This is the cross-provider complement to the compile-time
in-policy duplicate check (§7.13.3): the compiler rejects two `[[provides]]` of one name in one policy; the
catalogue keeps one name offered across two policies, ordered, and fails **open**.

**Bringing the provider up (step 5).** The matched provider need not already be running. A provider enabled
for **lazy** start (linked into `ondemand/`, §7.13.6) is **socket-activated** on first consume — a capability
is reachable from the moment its provider is enabled, and the first request is what brings it up, `kenneld`
doing for a provider kennel what systemd's socket activation does for `kenneld` itself. A provider enabled
for **eager** start (linked into `autorun/`) is simply already up, started when `kenneld` (re-)reads the
enablement set (`kennel daemon-reload`, the `systemctl daemon-reload` analogue, which re-derives the
catalogue and brings newly-enabled eager providers online) or at daemon start. The two postures coexist,
chosen per provider by which enablement directory holds its link (§7.13.6); step 5 is the same for both —
bridge the workload's connection to a running provider, starting it first only when it is not.

This is why delivery is a **socket the workload connects to** and not a connected fd handed in: you cannot
hand an fd to a process that has not connected yet, and under lazy start there is nothing to connect it *to*
until the workload asks. An inherited connected fd would have to exist at the **workload's own
construction** — which forces the provider up eagerly, before any consumer reaches it, and defeats the lazy
model entirely. A socket the workload connects to inverts that: the listening end stands in the consumer's
view from construction, costs nothing while idle, and the **connect itself is the trigger** that resolves
and socket-activates the provider. That is precisely what systemd socket activation is, and it is the reason
a capability can be reachable before its provider runs.

**A consume is a runtime request, matched like a spawn.** The steps above are the same grant-matched,
`kenneld`-brokered request as a `SPAWN` (§7.12), pointed at a standing capability instead of a fresh kennel:
the signed declaration is the floor, the runtime request cannot exceed it, and `kenneld` mints the
connection. This is why the delivery point `at` is set up at construction — the socket (or fd placeholder) is
present in the consumer's view from the start — while the backing provider need not be: a soft
`required = false` ("wants") consume is simply requested if and when the workload reaches for `at`. A hard
`required = true` additionally has `kenneld` confirm at construction that the capability **resolves** — that
an installed provider offers it — failing construction if none does; the *connection* is still made on demand
even for a required consume (resolution is checked eagerly, bring-up and wiring stay lazy).

**Connector lifecycle — not durable across a provider restart.** A brokered connector is a live fd to a
running provider, not a standing guarantee for the kennel's life. When a provider is restarted or dies (under
the supervision machinery), its consumers' connectors go dead: each consumer observes **`EOF`** and may
**re-request** the capability, which re-resolves against the catalogue and socket-activates the provider
afresh — the restart-invalidates-connectors contract the broker wire specifies, reusing the soft-reaper
semantics. A consumer therefore treats its connector as reconnectable, not permanent: the mesh guarantees
*a* connection to the named capability on request, never the *same* connection for the kennel's life.
Materialising `at` as a re-requestable endpoint (rather than a one-shot fd) is what makes a restart
transparent to a workload that simply reconnects.

## 7.13.4a The `SVC_CONNECT` wire contract

The broker of §7.13.4 is realised by **one Node 0 transaction, `SVC_CONNECT`** — the standing-service
sibling of `SPAWN` (§7.12): where `SPAWN` *mints* a fresh kennel and injects its stdio fds,
`SVC_CONNECT` *resolves* a named capability against the catalogue and brokers a connector to a provider
that already exists. It is a **facade-class verb** the consumer's facade transacts on the workload's
behalf the moment the workload acts against its `at` endpoint (connects to the `af-unix` socket, calls
through `IDBus`, `getService`s the binder node) — never the workload directly. This is
request-don't-author at the wire (§7.12.1): the facade names a capability; it cannot widen what the
consumer's signed `[[consumes]]` already grants.

**The request carries only the name.** The wire payload is the capability `name` and nothing else. The
optional private **`key`** (§7.13.1) is *deliberately not on the wire*: `kenneld` matches it broker-side,
reading the consumer's key from its signed `[[consumes]]` (selected by the kernel-stamped caller identity
and this `name`) and the provider's from its signed `[[provides]]`, then comparing the two. So the private
token never transits the in-kennel facade boundary where a workload could observe or forge it — the name
*discovers*, the key *binds privately*, and only the broker, holding both signed policies, ever sees the
key. Everything the broker enforces — identity, key, expected `shape` — is read from the signed grant, not
asserted by the requester.

**The reply is a status byte, and the connector rides the object table.** The reply payload is a single
status byte; on success (`OK`) the connector itself is attached as a **binder object**, exactly as
`SPAWN`'s channel fds are — not in the status bytes. What that object is, is the `shape` (§7.13.2):

- **`af-unix`** → a **connected fd** to the provider, the byte path `kenneld` then steps out of (§4.3).
- **`binder-connector`** → a **node handle** referencing the provider's node; whatever rides it afterward
  is opaque to `kenneld`, which frames and parses none of it (the TCB discipline — no protocol body in the
  daemon).
- **`dbus-name`** → **no object**: success means the broker widened the consumer's `IDBus` allow-set to
  the resolved name (§7.13.2), and the consumer continues to call through the facade it already holds.

A non-`OK` status carries no object and names *why* the connect did not happen, distinguishably:

| Status | Meaning |
|---|---|
| `OK` | resolved and brokered; the connector is attached per shape. |
| `DENIED` | the caller's signed policy declares no `[[consumes]]` for this name (or the identity check failed) — the request-don't-author floor (§7.13.4 step 1). |
| `NOT_FOUND` | nothing in the catalogue offers the name — the clean resolve-miss (no enabled provider, §7.13.6). |
| `UNAVAILABLE` | the name *resolves*, but the provider is not serving: **declared-but-failed** (§7.13.7), or **pending past the consume-with-wait deadline** (below). |
| `BAD_REQUEST` | a malformed name (empty, oversized, non-UTF-8). |

The `NOT_FOUND`/`UNAVAILABLE` split is the wire half of the §7.13.7 readiness requirement: a failed
provider stays catalogued (the operator's link is unchanged), so its consume must be distinguishable from
"no such capability" — `UNAVAILABLE` is "the capability exists but is down," `NOT_FOUND` is "no such
capability," and a consumer (or operator) can tell them apart without guessing.

**Consume-with-wait, and why it is the cycle's safety valve.** Step 5 of §7.13.4 may socket-activate a
cold provider, so a `SVC_CONNECT` against a lazy provider does not return instantly: the broker **blocks
the transaction until the provider is declared-and-ready, or a deadline fires** (the *consume-with-wait*
deadline — a broker constant, default **5 s**, sized to the slowest legitimate provider start; it is not a
`[service]` field). A provider that is itself still **declared-but-pending does not satisfy a waiter** —
the connector is brokered only at `Ready` (§7.13.7). That single rule is what makes the flat, boot-order-free
model safe under a dependency cycle. Consider the operator misconfiguration where sidecar **A** consumes
**B** and **B** consumes **A**, both enabled eager: at daemon start `kenneld` autostarts both
asynchronously, A's readiness blocks on consuming B and B's on consuming A. Neither reaches `Ready` (each
waits on the other), so neither consume-with-wait is satisfied; both hit the deadline, both return
`UNAVAILABLE`, and both providers' pending construction is driven to **declared-but-failed** (the
`pending → failed` transition, §7.13.7). The cycle resolves to a **loud, observable double-timeout** —
visible in the topology surface (§7.13.7, the `kennel ps` mesh view) — not a silent deadlock. The timeout
is not an implementation detail; it is the contract that converts an un-orderable dependency graph into a
fail-closed, legible outcome, which is why it is specified here and asserted before the broker is built.

**Restart invalidates the connector.** A brokered connector is a live handle to a running provider, not a
standing guarantee (§7.13.4, *connector lifecycle*). When the provider restarts or dies, the consumer
observes **`EOF`** on the connector and re-transacts `SVC_CONNECT` for the same name, which re-resolves and
socket-activates afresh. The consumer treats the connector as reconnectable; the mesh guarantees *a*
connection to the named capability on request, never the *same* one for the kennel's life.

The wire itself is **internal-stable** and lives with the other Node 0 verbs in
`kennel-lib-binder::service` (`svc_connect`): both ends ship from one release, the request/reply codec is
hand-rolled and bounded (no `serde` in the daemon's binder path — the TCB discipline), and `kenneld`
frames the connector but parses nothing that rides it. The behaviour above — resolution, key/shape match,
socket-activation, the consume-with-wait timeout, the restart-`EOF` — is the **broker logic** built against
this frozen surface (§7.13.4); this section freezes the surface.

## 7.13.5 The reserved namespace and the service-kennel trust class

A capability name is the thing a consumer trusts: a kennel that resolves `org.projectkennel.wayland` is trusting
whatever the mesh brokers it under that name to *be* the display service. So **who may claim a name** is the
load-bearing gate, not merely who may consume one.

A **reserved namespace** is a name prefix whose claimants a consumer trusts by reputation. `org.projectkennel.*`
is the **project's own** reserved namespace — built in, not host-configurable, claimable only by the **project
maintainer key** (the display service, the D-Bus broker, the system services live here). A `[[provides]]`
claiming a name under it is legitimate **only when its originating template is signed by the project maintainer
key**. This is the **same mechanism spawn targets already use** (§7.12): a signed template is the unit of
trust, and the host varies only the template's named `[[mutable]]` fields (below). Were a reserved name
claimable by anyone, an impostor could advertise it and have a consumer resolving `wayland` brokered to it —
provider-name spoofing, a capability-granting side channel through the catalogue. (A host may declare *further*
reserved namespaces of its own, §7.13.5a — but `org.projectkennel.*` is the project's and a host cannot
redefine, release, or reassign it.)

The gate is **scoped to the reserved namespace, not to templates in general.** A `[[provides]]` with an
*unreserved* name (`doe.john.cache`, `com.example.build-cache`) is freely authored and signed by **any valid
key** — a user's own included — exactly like any run policy; nothing about declaring a provider requires a
maintainer. Only a reserved name carries the extra gate, because only a reserved name carries reputation a
consumer relies on by name alone. Two facts make this precise:

- **A `[[provides]]` can only be declared in a template, never in a user delta-leaf.** The leaf form (the
  `[[*.add]]`/`[[*.remove]]` delta a user authors under their own key) carries no `provides` surface at all,
  so a `[[provides]]` is always a template — and a template is trusted exactly as far as the key that signed
  it. (This is *not* the base-template trust split: a provider template is not a security-baseline template
  re-asserting invariants, so it is not confined to system keys — an unreserved provider is user-signable.)
- **A reserved name additionally requires an authorized signature.** Claiming a reserved name is the one extra
  bar: the originating template's signature must be a key authorized for that namespace — the **project
  maintainer key** for `org.projectkennel.*`, or the host-declared keys for a host's own namespace (§7.13.5a).
  So a user who authors a template with a reserved provide and signs it with their own key is **refused at
  verification** — their key is not authorized for the reserved namespace — while the *same template under an
  unreserved name* is accepted. The authority is the signature on the originating template, checked when the
  provider is catalogued (§7.13.4) against the authorized-key set — structural, not a self-asserted context.

## 7.13.5a Host-declared reserved namespaces (additive)

`org.projectkennel.*` is the project's and is built in; a host may **optionally** reserve **further** namespaces
of its own — an organisation that wants `com.acme.*` to carry the same name-is-trusted guarantee for its
internal services. This is a host-level trust-root decision, declared in the root-owned, integrity-sensitive
`system.toml` (the deployment config, `07-paths`; never user-writable, so a user cannot grant themselves a
reserved namespace):

```toml
# /etc/kennel/system.toml (admin) or /usr/lib/kennel/system.toml (vendor)
[[reserved]]
prefix = "com.acme."                   # an organisation reserves its own namespace
keys = ["acme-platform-2026"]          # key-ids whose signature may claim a name under it
```

A reserved provide under a declared `prefix` is legitimate iff its originating template is signed by one of
that entry's `keys`. These entries are **purely additive** — the built-in `org.projectkennel.*` reservation
(bound to the project maintainer key) is not expressed here and **cannot be redefined, released, or reassigned**
by a host; `system.toml` only *adds* a host's own reputation-bearing prefixes alongside it. A name under
neither the built-in namespace nor any declared one is unreserved and free to any valid key (above). Because
`system.toml` is resolved only from root-owned dirs (never `~/.config`, `07-paths`), the host's reserved set is
a property of the host, not of any policy author.

This is the trust-root analogue of the signing-key store: the store says *which keys the host trusts at all*;
the reserved table says *which of those keys may speak for a host-reputation-bearing name* — while the
project's own namespace stays the project's. Both are root-owned and out of any policy's reach.

**Named mutables are where the host diverges.** A maintainer-signed reserved-name template is not frozen
whole: it exposes the bits a host legitimately varies as `[[mutable]]` fields, patched within their declared
bounds by the existing manifest validator (§7.12.2, §7.12.3) — the **same** fenced-write surface a spawn
target uses. The display service is the worked case: `org.projectkennel.wayland` is maintainer-signed and its
reserved name is pinned, but the *compositor* (cage by default; sway or Weston as alternatives, §7.14) is a
named mutable, so a host runs a different inner compositor without re-authoring the reserved name or escaping
its trust. The reserved name carries the reputation; the mutable carries the host's choice — and the line
between them is exactly the maintainer-pinned / host-patchable line spawn already draws.

Within `org.projectkennel.*`, `kenneld` owns the **facade interface nodes** — the `I*`/instance forms such
as `org.projectkennel.IAfUnix/default` and `org.projectkennel.IDBus/default`, which only `kenneld` registers
(§7.1) — and **mesh capability names** such as `org.projectkennel.wayland`, which a maintainer-signed service
template claims. Both are reserved under the one namespace: the facade nodes are `kenneld`'s alone, and a mesh
name is claimable only by a maintainer-signed template, as above.

The service-kennel trust class also carries the **multi-leg exemption**, and this is its canonical
definition. The single-leg discipline (§7.12) is a review invariant on **composable spawn targets** — the
things an *untrusted agent* may instantiate and bridge, where holding two legs at once would let the agent
reconstitute, across one kennel, a capability the operator never granted as a whole. A service kennel is not
such a target: it is a **maintainer-signed template the operator deliberately enabled** (§7.13.6), so both
the maintainer (by the signature) and the operator (by the enablement) have vouched for the whole of it, legs
included. It may therefore **hold multiple legs** without violating the discipline, because the discipline
binds what an *agent composes*, not what a maintainer signs and an operator enables. The GUI-service kennel's
host-compositor connection together with its file broker (§7.14) is the worked instance. Chapters that hold
multi-leg service kennels cite this exemption (e.g. §7.14.10); the definition lives here.

The exemption widens *how many* legs a service kennel may hold; it does not widen *what kind*. A service
kennel is still bound by the §4.3 limit on every broker the monitor grows: it may vend
**authentication-shaped** capabilities (render, transport, reach a destination, authenticate), never
**attestation-shaped** ones (vouching, signing, secret-issuance). A standing service whose job is to *be
trusted* — a secrets broker, a signing service — is a trust root placed inside the boundary the project
exists to confine, incoherent regardless of how cleanly it fits the mesh grammar; trust material a kennel
needs arrives as a signed construction parameter from the operator (§4.3), never brokered from a peer at
runtime. The multi-leg exemption is permission to compose **use**-capabilities the operator vouched for, not
a route by which a trust-issuing service slips in as "just another provider."

## 7.13.6 Enablement — the operator links what the vendor provides

A `[[provides]]` block makes a capability *claimable*; it does not make the providing kennel run, nor put its
name in the catalogue. **Installing** a provider — placing its signed policy in the `policies/` cascade
(`07-paths`) — and **enabling** one are two distinct acts, and the gap between them is deliberate: a
freshly-installed service kennel is present-but-inert until an operator deliberately turns it on. This is the
deny-by-default discipline at the deployment layer, and it follows systemd exactly — a package ships a unit
under `/usr/lib/systemd/system/`, and the unit does nothing until an operator *enables* it.

**Enablement is a host-level symlink.** An operator enables a provider by linking its installed policy into
one of two enablement directories:

- **`autorun/`** — **eager**: `kenneld` starts the provider at daemon start (and on `daemon-reload` for a
  newly-linked one) and supervises it for the daemon's life. The `multi-user.target.wants` analogue.
- **`ondemand/`** — **lazy**: the provider's `name` is in the catalogue and resolvable from the moment it is
  linked, but the kennel is **not** started until a consumer first reaches its capability — socket-activated
  on first consume (§7.13.4), reaped when idle. The socket-activation analogue.

Both directories exist at the two **operator** layers — `/etc/kennel/{autorun,ondemand}/` (the system admin)
and `~/.config/kennel/{autorun,ondemand}/` (the user) — and at **neither vendor layer**: there is no
`/usr/lib/kennel/autorun`. A vendor ships a provider policy under `/usr/lib/kennel/policies/`, but it
**cannot enable its own provider** — enablement requires writing a symlink into an operator-owned directory,
which the vendor package does not own. A vendor offers a capability; only the operator turns it on, and only
by an act in a directory the operator controls. The two postures are the same provider differing in
**trigger** (daemon start vs first consume) and **lifetime** (daemon-coupled vs consumer-driven); the restart
policy, the readiness machine, and the supervisor are identical for both (the supervision work).

**The link spans the cascade, and does not bypass signing.** A link `/etc/kennel/autorun/wayland` →
`/usr/lib/kennel/policies/org.projectkennel.wayland/…settled.toml` enables a *vendor-shipped* capability from a
*system* enablement directory — the operator turns on what the vendor provides without copying it, and a
vendor policy update flows through the link. The link target is a settled, **signed** policy, verified at
construction like any other (`04-trust-boundaries`); enabling a provider does not weaken the signature gate,
it only adds the provider to the set `kenneld` will construct and supervise.

**What the signature covers, and what the symlink covers.** The signed provider policy carries the
*capability* (`[[provides]]`) and the *supervision discipline* (the `[service]` restart policy, §7.13.7). It
does **not** carry whether the provider autostarts, or whether eagerly or lazily: that is the operator's
deployment posture, expressed solely by which enablement directory holds the link, and deliberately kept out
of the signed artefact. This is the same split as the config trust levels (`07-paths`): the vendor signs
*what the service is and how it is supervised*; the operator decides *whether and how it participates* with a
writable symlink, with no signed artefact to re-mint when they change their mind. A vendor cannot bake
"autostart on every host that installs me" into a signed policy, and an operator cannot alter a service's
restart discipline without re-signing it — each side owns exactly its half.

**`daemon-reload` re-derives the enabled set from the filesystem.** `kennel daemon-reload` (the `systemctl
daemon-reload` analogue) re-scans the enablement directories, re-derives the catalogue (§7.13.4) from the
now-enabled providers, brings newly-linked `autorun/` providers online, and makes newly-linked `ondemand/`
providers resolvable without starting them. Removing a link and reloading drops the capability from the
catalogue and stops an eager provider. The enabled set is **the links on disk** — re-read on every reload and
on daemon restart, never standing authored daemon state. This is the repo-is-truth discipline applied to
service discovery: the filesystem *is* the registry, and `kenneld` holds no enabled-set state a restart could
lose or a bug could desynchronise.

## 7.13.7 The `[service]` block — supervision discipline and readiness

A provider that the operator enables (§7.13.6) is a kennel `kenneld` keeps running on the operator's behalf,
so it carries the one thing an ephemeral spawn does not: a **supervision discipline**, declared in a
`[service]` block and signed into the policy with everything else.

```toml
[service]
restart = "on-failure"   # always | on-failure | never  (default: on-failure)
backoff = "500ms"        # initial delay before a restart; doubles each attempt (capped)
max_attempts = 5         # restarts within the crash-loop window before declared-but-failed
```

- **`restart`** is the systemd `Restart=` analogue. `always` restarts on any exit (a long-running service
  expected to stay up); `on-failure` (the default) restarts only on a non-zero exit or signal; `never` runs
  the provider once and lets it stay down. A `never` provider that exits cleanly is *done*, not failed.
- **`backoff`** is the delay before the first restart; it doubles each successive attempt (to a cap), so a
  provider that crashes immediately on start does not spin the supervisor. The first start has no backoff.
- **`max_attempts`** bounds the restarts within the crash-loop window. Exhausting it is what drives the
  provider into **declared-but-failed** (below) rather than restarting forever — a flapping service becomes
  a *visible, terminal* failure, not an invisible hot loop.

The `[service]` block is **only meaningful for a provider** — a kennel with at least one `[[provides]]`. A
policy that declares `[service]` without any `[[provides]]` is supervising nothing it offers to the mesh; the
compiler accepts the block (a service kennel may be enabled before its first consumer exists) but the block
does nothing until the kennel is enabled (§7.13.6). The discipline lives in the **signed** policy, not the
enablement symlink, precisely because it is a property the *author* owns: how a service tolerates its own
crashes is part of what the operator vouches for when they sign it, unlike the deployment posture
(eager/lazy) which is the operator's alone.

**Readiness — the state every reader sees.** An enabled provider is in exactly one of three readiness states,
and this small machine is the contract the catalogue (§7.13.4) projects and the topology surface reads:

- **declared-but-pending** — enabled and known to the catalogue, construction not yet complete: an `autorun/`
  provider between daemon start and a successful seal, or an `ondemand/` provider that a consume has just
  triggered. Its `name` **resolves** (a `required = true` consumer's construction-time resolvability check
  passes, §7.13.4) but a connect waits on the transition to ready.
- **declared-and-ready** — construction succeeded and the capability is reachable; a consumer's connect
  bridges straight through (§7.13.4 step 5).
- **declared-but-failed** — construction or supervision gave up: `max_attempts` exhausted within the
  crash-loop window, or a `restart = never` provider that exited non-zero. The `name` stays in the catalogue
  (it is still *enabled* — the operator's link is unchanged) so the failure is **visible**, not a silent
  resolve-miss; a consume against it is denied-and-audited, distinguishable from "no such capability."

The legal transitions are exactly: **pending → ready** (construction succeeds), **pending → failed**
(construction fails, or crash-loop exhausts before a first ready), **ready → pending** (the provider died and
is being restarted under its `[service]` policy — the same restart that invalidates live connectors,
§7.13.4), and **ready → failed** (a restart-loop after a prior ready run exhausts `max_attempts`). There is
**no** failed → \* transition without an operator act: a failed provider is terminal until the operator
intervenes (fixes and `daemon-reload`s, or re-enables), so a failure is sticky and observable rather than
self-clearing. An `ondemand/` provider reaped while idle returns to **declared-but-pending** (enabled,
resolvable, not running) — idle reaping is not failure.

This is one machine for both enablement postures: only the *trigger* into pending differs (daemon start vs
first consume). Crash-loop exhaustion drives `failed` through the **same** path for an eager and a lazy
provider, so there is one readiness contract for every reader to depend on, not two.

## 7.13.8 What the mesh composes

The mesh is not a new subsystem so much as a composition of primitives the system already has: the
**`[[provides]]`/`[[consumes]]` declarations** (this section), each locally validated at compile (§7.13.3);
the **service-connector broker** on Node 0 that resolves a capability against the catalogue, hands the
consumer its connector, and steps out (the §4.3 fd-broker, built against the `SVC_CONNECT` wire of
§7.13.4a); the **service
catalogue**, a derived projection of the installed configs' `[[provides]]` blocks that the broker resolves
against and the topology surface reads (developed with the catalogue); **enablement and autostart** (§7.13.6)
— a provider the operator links into `autorun/` (eager, started at daemon start) or `ondemand/` (lazy,
socket-activated on first consume), the posture chosen by which enablement directory holds the link
(developed with the supervision work); and **per-kennel isolation** (§4.5), which keeps
every brokered reach pairwise and declared. The confined GUI display service
(§7.14) is the first non-trivial consumer and exercises every one of them.
