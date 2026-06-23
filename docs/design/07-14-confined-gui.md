# §7.14 Policy surface: confined GUI (the nested-compositor display service)

> **A confined workload reaches a graphical display not by being handed the host
> compositor's socket, but by talking to a display server constructed for it: an upstream
> compositor running inside a separate, operator-declared GUI-service kennel, one instance
> per consuming kennel.** The app's `wl_registry` is that inner compositor's globals; the
> host compositor is *absent* from its view, not denied. The GUI-service kennel holds the one
> connection to the host compositor and hands each inner compositor a connected host file
> descriptor, so even the host socket's pathname is absent from the workload's world. Confined
> GUI therefore depends on **no enforcement by the host compositor** — it is the same construction
> and brokering the rest of the system is built from, pointed at the display. The concrete
> lifecycle and fd-handoff are the implementation contract, written as-built in the architecture
> corpus.

A graphical workload needs a display server the way a networked workload needs a route: it is a
capability the workload cannot supply itself and the operator must mediate. X11 admits no mediation
that can confine a client and is out of scope (§7.8) — any X client can read every other client's windows, keystrokes,
and clipboard, and the protocol offers no mechanism to constrain a client once connected. Wayland is
different in kind: its per-client model *can* be confined. But the obvious way to grant it — bind the
host compositor's socket into the kennel's view — would make confinement depend on which compositor the
operator happens to run and which version, a property outside Kennel's control and not guaranteed on any
target. This chapter is the display capability granted the way every other reachable capability is:
construct the view (§4.2), broker the one host leg as a descriptor (§4.3), and depend on nothing foreign
in the trusted path.

It builds on the cross-kennel service mesh (§7.13): the GUI-service kennel `provide`s a capability that an
app kennel `consume`s, and `kenneld` brokers the connector at construction, deny-by-default. The mesh
primitives — the `[provides]`/`[consumes]` grammar, the broker, the reserved-name and service-kennel
trust classes — are defined there; this chapter is their first non-trivial consumer and the headline of
the standing-service model.

## 7.14.1 The display server is constructed, not granted

The host compositor is a shared resource. Handing a kennel a connection to it grants whatever that
compositor exposes to its clients — and what a compositor exposes varies: screen-capture globals, virtual
input, layer-shell, the set of other connected clients. Some compositors gate these from a tagged
sandboxed client (the `security-context-v1` staging protocol); most, including the mainstream desktop
default, do not. A design that rested on the host compositor denying privileged globals would be enforced
on one machine and unenforced on the next, with no way for Kennel to tell the difference from inside the
kennel. That is the X11 failure in a milder form: confinement that the protocol's *server* must opt into,
which Kennel does not own.

So the display server is not granted from the host; it is **constructed**. The workload is given a
display server that exists only for it, whose every global is one Kennel placed there. The host
compositor is reduced to a single, ordinary, downstream client relationship held by a *different* kennel
— never the workload's. This is §4.2's absence path applied to the display: rather than enumerate what a
graphical workload must be denied on the host compositor, present it with a positively constructed
compositor that contains only what a single confined app should see.

## 7.14.2 The nested inner compositor — absence for the display server

The GUI-service kennel runs an upstream Wayland compositor *inside* the confinement — **cage** (a
single-application kiosk compositor) by default, with Weston or sway as alternatives — and runs **one
instance per consuming kennel**. The confined app connects to *that* compositor. Its `wl_registry`
enumerates the inner compositor's globals and nothing else: the host's screen-copy, input-synthesis, and
layer-shell globals, and the host's other clients, sit on a socket the app's view does not contain. They
are not present, not deniable, not enumerable — absence, not denial (§4.2). There is no allow-list of host
globals to maintain and no Wayland protocol parser anywhere in the trusted path; the inner compositor is
unmodified upstream software, and the isolation is a property of *which compositor the app can reach*, not
of filtering the bytes it exchanges with one.

The choice of inner compositor is the operator's, declared in the GUI-service kennel's policy. cage is the
default because it is small and draws exactly one application full-window, which matches the per-kennel
topology; Weston and sway suit a kennel that should present multiple windows or a desktop-shaped surface.
None of them is patched: the GUI-service kennel is an ordinary confined kennel whose workload happens to
be a compositor.

## 7.14.3 Brokering the host leg — the socket path is absent

A nested compositor must itself reach *some* compositor to put pixels on the user's screen. The
GUI-service kennel holds that one connection to the host compositor, and hands each inner compositor an
**already-connected host file descriptor** rather than a path to open. A Wayland client offered
`WAYLAND_SOCKET` (an inherited connected fd) uses it directly and never consults `WAYLAND_DISPLAY`; the
host compositor's socket *pathname* is therefore absent from the inner compositor's constructed view, and
from the app's beneath it. The app cannot name the host socket, cannot reach the host's other display
clients, and cannot open a second connection of its own — it has a display server, and that display server
is the kennel's.

This is the §4.3 interposition fd-handoff, the same machinery as AF_UNIX brokered connect (§7.6) and the
dynamic-spawn channel (§7.12): a capability arrives as a descriptor the broker established, the workload
holding the one resource it was granted and no means to name or widen it. This **host** leg is a brokered fd
like the other §4.3 hand-offs; the app's own leg is brokered differently — on demand — as the next paragraph
sets out.

The two legs use two mechanisms, and the split is lazy-versus-eager. The **inner-compositor → host** leg is
the inherited connected fd above (`WAYLAND_SOCKET`): the GUI-service kennel spawns the inner compositor and
hands it the already-open host connection at spawn, which it can because the host compositor is always up —
eager, fd by inheritance, a parent handing its child a descriptor. The **app → inner-compositor** leg is the
**mesh consume**, and it is **socket-activated** (§7.13.4): the app connects to a Wayland socket presented at
its own `at` (`WAYLAND_DISPLAY`), and that first connect is what spins up its dedicated inner compositor —
lazy, because there is no inner compositor to hand a descriptor from until the app reaches for one, and no fd
to hand a workload that has not connected. What is absent from the app's view is the **host** socket; the
socket it connects to is its own inner compositor's, brought up on demand — so "the host socket path is
absent from the workload's world" holds without claiming the app has no display socket at all.

## 7.14.4 The invariant: no dependence on host-compositor enforcement

The load-bearing property, stated as a standing invariant:

> **Confined GUI depends on no enforcement by the host compositor.** The host compositor sees one
> ordinary Wayland client (the GUI-service kennel's leg) and is asked to enforce nothing. Every
> confinement property of the display is carried by a compositor Kennel ships and controls, inside a
> kennel.

Bring-your-own inner compositor is the right shape *unconditionally*, regardless of what any host
compositor supports now or later. Where the inner compositor itself implements `security-context-v1`, it
is **optional defense-in-depth** — a second, redundant denial of privileged globals to a tagged client —
never a dependency. This is deliberately *not* "revisit when the host compositor gains the feature":
depending on the host compositor at all is the weaker position even where the protocol exists, because it
ties the confinement guarantee to deployment-specific software outside the operator's policy. The enforcer
must be inside the boundary; the nested compositor puts it there.

## 7.14.5 Per-kennel isolation and tamperproofing

One inner compositor per consuming kennel makes cross-kennel GUI invisibility structural (§4.5): two
graphical kennels have two disjoint display servers, with no shared global, surface, or input path —
the same lateral isolation as their disjoint loopback subnets and AF_UNIX views. Applications *within* a
single kennel share that kennel's compositor, which is correct: they are one trust domain, and a window
manager that lets a kennel's own apps see each other is the kennel's own world.

The inner compositor runs in the **GUI-service kennel, never the app's** (§4.6): a workload must not be
able to reach or subvert the component that confines its display. This is why the model is two kennels and
not a compositor injected into the app's own view — placing the enforcer inside the thing it confines is
exactly the tamperproofing failure the reference monitor must avoid.

The inner compositor's own interface is permissive by design — cage and its alternatives expose
screen-copy and virtual-input globals, because a compositor's *clients* legitimately screenshot and drive
the surfaces it owns. That surface is **scoped to the kennel's own world by the nesting**: the inner
compositor captures the kennel's own pixels and injects into the kennel's own apps, and reaches neither
the host nor any sibling kennel. A capability confined to a single trust domain, exercised within it, is
not a leak — it is that domain's own software operating on its own surfaces.

The mechanism, not just the claim: the inner compositor's capture and input globals operate on **its own
scene graph**, which holds only the kennel's surfaces, and have no path to the host's scene because the
inner compositor is itself a mere *client* of the host compositor. It can screencopy what it composites
(the kennel's app) and inject into the windows it owns (the kennel's), and a client cannot reach across its
own connection to capture or drive the *server's* other clients — the host and its sessions. That is what
makes the permissive inner interface safe rather than merely asserted to be, and it is the keystone of the
T2.7 coverage (§7.14.11): the permissiveness is bounded by the same client-isolation the host compositor
enforces on every client, the inner compositor among them.

## 7.14.6 The host residual — one concentrated, bounded leg

Confined GUI does not eliminate trusted host-reach; it **concentrates and bounds** it. Exactly one party
reaches the host compositor — the GUI-service kennel — and it reaches it only to vend connected fds to the
inner compositors it spawns. Even there it is *one ordinary Wayland client* to the host, contained by the
host compositor's own client isolation the same way any application is. No workload kennel holds the host
leg; no unconfined host process holds standing display capability.

This is the GUI analogue of the host-reconnaissance residual (T1.6): a single, deliberate, reasoned
host-reach held by a confined kennel, catalogued and loud. The GUI-service kennel's policy declares it
with a required `reason`, and `kennel policy risks` surfaces the exposure derived from the grant — a
host-reach exception that reads as reasoned, not as a boundary quietly bending. (The one other host-side
component the user touches is the interactive file picker of §7.14.7 — but it is *transient and
user-invoked*, summoned per request and gone after the choice, holding no standing capability, so it is not
a counterexample to "no unconfined host process holds standing display capability.")

## 7.14.7 Interactive file access — the Kennel-native file broker

A graphical application that can touch only its pre-granted paths holds half a capability: the defining
desktop interaction is the user choosing a file at runtime — an open dialog, a save target — that the
application had no prior grant to. That pattern is **Kennel-shaped**, not foreign: the user picks a file,
and the application receives *an fd to exactly that file*, having held no filesystem and gained no path it
can enumerate. It is the §4.3 fd-broker again — the same move as AF_UNIX brokered connect and the spawn
channel — with the user's live consent as the authorising act.

So the display service carries a **Kennel-native file broker**: `kenneld` brokers a host file picker, the
user consents to a specific file, and the workload receives one fd placed into its view. No foreign
desktop-service protocol, no application-identity permission store, no out-of-band consent daemon — one
consented file, one descriptor, construction-by-absence plus interposition-by-transaction. The coarse form
is the floor (open or save one user-chosen file → one fd); save-back into a chosen file and multi-select
are extensions of the same broker. This is **part of the display capability**, not an optional adjunct: a
confined GUI without it is a window that cannot open a document.

**The picker runs host-side.** The chooser the user clicks through is the host's own file dialog — a
trusted process the user already relies on — not a UI drawn inside a confined component the user would have
to extend trust to. Consent therefore happens *outside* the confinement boundary, on the host the user
trusts, which is the right place for it: the workload requests a file, `kenneld` invokes the host picker,
the user chooses, and `kenneld` delivers the resulting fd into the workload's view. The picker is
**transient** — summoned per request, gone when the choice is made (the §7.14.6 carve-out) — so it holds no
standing capability; the workload never sees the picker, the filesystem it browsed, or any path but the one
fd it was handed.

## 7.14.8 Other desktop services — Kennel-native brokers, no foreign substrate

The remaining desktop-integration capabilities are each the broker pattern, owned:

- **Screenshot / screencast** is the inner compositor's own capability, scoped to the kennel (§7.14.5) —
  the compositor here is Kennel's, so a kennel screenshotting its own surfaces reaches nothing else.
- **Open-a-URL / post-a-notification** are brokered host-request services: the workload asks `kenneld` to
  perform a bounded host action and receives a result, never the underlying capability. Notifications ride
  the D-Bus facade (§7.7), which already mediates `org.freedesktop.Notifications` per message.
- **Desktop-service D-Bus traffic** rides that same `org.projectkennel.IDBus` facade (§7.7); confined GUI
  introduces no second D-Bus path.

The result is the project's own thesis applied to the desktop: **there is no foreign desktop-sandbox
substrate in confined GUI** — only kennels, a compositor-in-a-kennel, and Kennel brokers. The capabilities
a desktop application expects are preserved; the implementation is Kennel's, reusing the primitives the
rest of the system is built from rather than importing a foreign confinement model and shaping a view to
satisfy it.

## 7.14.9 Clipboard and drag-and-drop — isolated by default

Nothing crosses the kennel boundary that policy does not route (§4.7), and the clipboard and
drag-and-drop are no exception. Between the kennel's display world and the host session they are
**isolated by default**: a workload neither reads the user's clipboard nor writes one the user will paste
elsewhere (T2.6), and no drag bridges in or out. Because the kennel's compositor is its own, this
isolation is structural rather than dependent on a host compositor's clipboard policy — the kennel's
clipboard is the inner compositor's, disjoint from the host's. A mediated clipboard bridge — a consented,
direction-aware transfer — is a deliberate later grant, the same broker pattern under user consent, never
the default.

## 7.14.10 The grant model and the service-kennel trust class

An app kennel declares `[consumes] org.projectkennel.wayland`; the GUI-service kennel declares `[provides]
org.projectkennel.wayland`; `kenneld` instantiates the connector at construction, deny-by-default (§7.13).
`org.projectkennel.*` is the reserved capability namespace — only an operator-signed kennel in the reserved-name
trust class may `provide` such a name, so a workload cannot advertise `org.projectkennel.wayland` and have a
consumer's display brokered to an impostor (§7.13). The grant is **coarse**: the consumer's grant is "may
reach the GUI service," not a per-protocol or per-global predicate; finer policy must never drag a Wayland
protocol parser into the broker, the same line held against message-body inspection elsewhere.

The GUI-service kennel holds two distinct legs — the host-compositor connection (§7.14.6) and the file
broker (§7.14.7). Per the **multi-leg exemption** of the service-kennel trust class, defined in §7.13.5, an
operator-declared, signed service kennel may hold multiple legs: the single-leg discipline (§7.12) binds
only the composable spawn targets an untrusted agent instantiates, not a service the operator has signed.
The GUI-service kennel's two legs are that exemption's worked instance, not a fresh argument for it.

## 7.14.11 Threat coverage

- **Display-server lateral reach (the X11 categorical capability, §7.8).** Closed by construction: the
  workload's display server is the kennel's own inner compositor, so there is no host display to read
  windows, keystrokes, or the client list from. There is no `[x11]` analogue and no host-compositor socket
  in the view.
- **Screen capture and input synthesis (T2.7).** The inner compositor's capture and virtual-input globals
  operate on its own scene graph and, because the inner compositor is a mere *client* of the host, cannot
  reach the host's scene or its other clients (the §7.14.5 keystone); they reach neither the host screen nor
  a sibling kennel. There is no host portal mediating capture under consent fatigue, because there is no
  host portal in the path.
- **Clipboard (T2.6).** Isolated by default (§7.14.9); the kennel's clipboard is its own compositor's, not
  the host's, so the residual is not "depends on the host compositor's clipboard policy" but "until a
  bridge is deliberately granted, there is no path."
- **Host-reconnaissance-shaped residual (T1.6 analogue).** The one host-compositor leg (§7.14.6) is a
  deliberate, reasoned, `reason`-required host-reach held by a confined kennel, contained by the host's own
  client isolation — concentrated and bounded, not eliminated, and surfaced in `kennel policy risks`.

## 7.14.12 Substrate and scope

The host need only run *a* Wayland compositor for the GUI-service kennel to be one client of; which
compositor it is does not change any confinement property, because the enforcer is the inner compositor
inside the kennel. The primary command-line tenant has no display leg at all — confined GUI is the
desktop-application case, and a kennel that needs no graphical surface declares no `org.projectkennel.wayland`
consumption and constructs no compositor. Lazy construction is the rule: no consumer, no inner compositor;
the per-kennel compositor is spawned on demand and reaped when its consuming kennel exits.

This makes the GUI-service kennel's relationship to its inner compositors a **per-consumer lifecycle**, not
a fixed sidecar set: it supervises one inner compositor *per consuming kennel*, each spawned when that
consumer first reaches for the display and reaped when that consumer exits, so the supervised set tracks the
live consumer population rather than a static declaration. That is a design property — a compositor's life
is bound to its consumer's — closer to what `kenneld` does for a spawn than to a fixed facade-supervisor
set; the supervision mechanism for it lives in the architecture corpus, but a reader should model the set as
per-consumer-dynamic, not static.

## 7.14.13 Decision record — why the display server is constructed, not borrowed

This shape was reached by eliminating every alternative that borrows confinement from outside the
boundary, and each alternative was eliminated for a structural reason, not a preference. The record exists
so none is re-proposed on a stale premise: the appeal of reusing an existing desktop-sandbox mechanism is
real, and recurs, and the reasons it does not hold are not obvious until checked against deployment
reality. The settled conclusion is the invariant of §7.14.4 — **confined GUI must depend on no enforcement
by the host compositor or any foreign substrate** — and the alternatives below all violate it.

- **A filtering Wayland proxy — does not exist.** The intuition is that a graphical sandbox interposes a
  proxy that parses the Wayland wire and strips privileged requests, the way the egress facade interposes
  on SOCKS. No such proxy ships in the desktop-sandbox ecosystem to vendor: the established sandbox passes
  the Wayland socket *through* unfiltered and relies on Wayland's inherent per-client isolation, filtering
  only its D-Bus leg. There is no filtering Wayland proxy to adopt, and building one would put a
  Kennel-authored parser of an adversarial display protocol in the trusted path — the parse-nothing-foreign
  line the project holds everywhere else. The premise was simply wrong; the nested compositor needs no such
  parser because the app talks to a real compositor that is the kennel's own.

- **Host-compositor enforcement (`security-context-v1`) — real, but not a foundation.** A staging Wayland
  protocol does let a compositor deny privileged globals to a tagged sandboxed client, and some compositors
  enforce it. Two independent reasons rule it out as the mechanism Kennel depends on. First, deployment:
  the mainstream desktop compositor does not ship it (GNOME/Mutter lacks it through current releases; on the
  common distributions only the wlroots family carries it), so a design resting on it would be enforced on
  one machine and silently unenforced on the next. Second, and decisive even where the protocol is present:
  depending on the *host* compositor at all ties the confinement guarantee to software outside the
  operator's policy and Kennel's control. This is therefore **not** "adopt it once the mainstream desktop
  ships it" — the nested compositor is the right shape unconditionally, and `security-context-v1` is kept
  only as optional defense-in-depth inside the inner compositor (§7.14.4), never as the floor.

- **A foreign desktop-sandbox substrate — redundant, and rejected with its identity model.** The remaining
  alternative reuses a foreign desktop-services layer wholesale: a host-services portal over a foreign
  D-Bus filtering proxy, plus the sandbox-identity file and bubblewrap-shaped view those components expect
  before they will treat a kennel as a sandbox they recognise. Its headline capability — hand an
  application an fd to a user-chosen file without granting the filesystem — is the broker pattern Kennel
  already owns (§4.3), so adopting the foreign stack would re-implement a primitive Kennel has while
  importing a foreign protocol, a foreign application-identity permission store, and an identity-forgery
  layer that exists *only* to make foreign components accept the kennel. Each capability it offers is
  instead a Kennel-native broker: interactive file access (§7.14.7), screenshot/screencast (§7.14.5),
  open-URL and notifications (§7.14.8). There is no foreign desktop-sandbox substrate in the result, and no
  mimicry of one.

What remains, once every borrowed-enforcement option is removed, is the design with no external-substrate
dependency at all: a compositor Kennel ships and controls, run inside a kennel, with desktop services as
Kennel brokers. The confined-GUI leg reduces to the three things the rest of the system is built from —
kennels, a compositor-in-a-kennel, and brokers — which is the project's own thesis (own the trusted path,
depend on nothing foreign in it, prefer construction to filtering) arrived at not by preference but by each
external option failing its check.
