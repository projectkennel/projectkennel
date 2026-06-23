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
# key = "…"  — optional private match token (below); omitted here, a reserved service-class name
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
capability is trusted through its service-class provider (§7.13.5) and needs none — and it is **never
published in the catalogue**. Crucially, nothing in a declaration points at another kennel: a key is a
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
the canonical agent↔tool topology (§7.13.7) is written in those terms. Folding the transports into one
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
  operator's signing context: each `[[provides]]`/`[[consumes]]` is well-formed (a `name`, a `shape`, an
  `endpoint`/`at`, a `reason`); `shape` is one of the defined transports (§7.13.2); a `org.projectkennel.*`
  provide is refused unless the policy is compiled in the service-class context (§7.13.5); and no two
  `[[provides]]` in *this* policy claim the same `name`. None of these consults another kennel, so all of
  them hold on a signed artefact for its whole life.
- **At runtime — resolution and matching.** When a consumer reaches for a capability, the broker resolves
  its `name` against the **catalogue** — the projection of the installed configs that declare `[[provides]]`
  (§7.13.4) — requires the optional `key` to match, enforces the expected `shape`, and applies the
  deny-by-default identity check. The matched provider need not already be running: a declared provider is
  **started on demand** if it is not up (the lazy autostart of the supervision section), so a `name` is in
  the catalogue because a signed config provides it, not because that kennel happens to be running. A consume
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

**Bringing the provider up (step 5).** The matched provider need not already be running. A **lazily**
declared provider is **socket-activated** on first consume — a capability is reachable from the moment its
config is installed, and the first request is what brings it up, `kenneld` doing for a provider kennel what
systemd's socket activation does for `kenneld` itself. An **eagerly** declared provider is simply already up,
started when `kenneld` (re-)reads the installed configs (`kennel daemon-reload`, the `systemctl
daemon-reload` analogue, which re-derives the catalogue and brings newly-declared eager providers online) or
at daemon start. The two disciplines coexist, chosen per provider; step 5 is the same for both — bridge the
workload's connection to a running provider, starting it first only when it is not.

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

## 7.13.5 The reserved namespace and the service-kennel trust class

A capability name is the thing a consumer trusts: a kennel that resolves `org.projectkennel.wayland` is trusting
whatever the mesh brokers it under that name to *be* the display service. So **who may claim a name** is the
load-bearing gate, not merely who may consume one.

`org.projectkennel.*` is the **reserved capability namespace** — the well-known names a consumer trusts by
reputation (the display service, the D-Bus broker, the system services). A `[[provides]]` claiming a
`org.projectkennel.*` name is accepted **only from a kennel in the operator-declared, signed service-kennel trust
class**; an ordinary workload or spawn-target kennel that declares `[[provides]] name = "org.projectkennel.wayland"`
is **refused at compile**. Were it not, such a kennel could advertise a reserved name and have a consumer
resolving `wayland` brokered to the impostor — provider-name spoofing, a capability-granting side channel
through the catalogue. The gate keys on the **operator-supplied service-class context** under which a policy
is compiled and signed, not on a field the policy sets about itself: a workload cannot self-grant the trust
class by writing a flag, because the class is asserted by the operator at sign time and the workload's own
declarations are not consulted for it. Any kennel may `[[provides]]` freely in an **unreserved** namespace,
and a consumer reaching one of those gets exactly the trust the name carries and no reputation it has not
earned.

Within `org.projectkennel.*`, `kenneld` owns the **facade interface nodes** — the `I*`/instance forms such
as `org.projectkennel.IAfUnix/default` and `org.projectkennel.IDBus/default`, which only `kenneld` registers
(§7.1) — and **mesh capability names** such as `org.projectkennel.wayland`, which a service-class provider
claims. Both are reserved under the one namespace: the facade nodes are `kenneld`'s alone, and a mesh name
is claimable only in the service-class context above.

The service-kennel trust class also carries the **multi-leg exemption**, and this is its canonical
definition. The single-leg discipline (§7.12) is a review invariant on **composable spawn targets** — the
things an *untrusted agent* may instantiate and bridge, where holding two legs at once would let the agent
reconstitute, across one kennel, a capability the operator never granted as a whole. A service kennel is not
such a target: it is **operator-declared and signed**, so the operator has already vouched for the whole of
it, legs included. It may therefore **hold multiple legs** without violating the discipline, because the
discipline binds what an *agent composes*, not what an *operator signs*. The GUI-service kennel's
host-compositor connection together with its file broker (§7.14) is the worked instance. Chapters that hold
multi-leg service kennels cite this exemption (e.g. §7.14.10); the definition lives here.

## 7.13.6 What the mesh composes

The mesh is not a new subsystem so much as a composition of primitives the system already has: the
**`[[provides]]`/`[[consumes]]` declarations** (this section), each locally validated at compile (§7.13.3);
the **service-connector broker** on Node 0 that resolves a capability against the catalogue, hands the
consumer its connector, and steps out (the §4.3 fd-broker, developed with the broker wire); the **service
catalogue**, a derived projection of the installed configs' `[[provides]]` blocks that the broker resolves
against and the topology surface reads (developed with the catalogue); **autostart** — eager at daemon start
for a standing provider, or lazy on first consume for one worth running only when reached, the operator's
choice per provider (developed with the supervision work); and **per-kennel isolation** (§4.5), which keeps
every brokered reach pairwise and declared. The confined GUI display service
(§7.14) is the first non-trivial consumer and exercises every one of them.
