# Project Kennel — 0.6.0 plan

Status: **active** · Promoted: 2026-07-02 · Targets: 0.6.0
Baseline: 0.5.0 (released)

> This is a planning artefact, not a design or as-built document. The corpus remains the source
> of truth for *what each item is* — and 0.6.0 is the release in which the corpus itself moves:
> the frozen `docs/design/` and `docs/architecture/` trees retire in favour of the two-volume
> book (W9). Until W9 lands, the frozen trees and the patch log remain the record. This file
> records *what 0.6.0 commits to, why, and in what order*.

## Theme

**Two structural bets, and the mediation story finished.** 0.5.0 paid the debt the spawn and mesh
releases accrued; 0.6.0 spends the ground they cleared on the two largest gaps left in the
confinement story itself. First: the monitor is the one process that has never been inside a box —
kenneld constructs and seals its own confinement before it touches kennel input, converting "monitor
compromise is total" into "monitor compromise is bounded" (W1). Second: constrained mode has never
carried the transport class the web is moving to — UDP egress lands without giving up the property
that DNS exfiltration is unexpressible (W2). Around the bets, the release finishes what the
`dbus-broker` started: the interactive file broker the confined GUI has owed since §7.14.7 (W3), and
the retirement of the legacy per-kennel `host-dbus` delegate once the broker demonstrably subsumes
it (W4). Three small owed debts ride along (W5–W7). The release also carries the corpus
succession: the frozen design/architecture trees retire in favour of the two-volume book (W9),
sequenced early because both bets write their corpus halves into it. The release opens with a
validation stream (W0): every empirical unknown the bets rest on is measured before a manifest or
schema is drawn, not reasoned about. A pre-ship adversarial pass on the three new boundaries gates
the tag (W8).

Standing constraints carried from 0.5.0:

- **The TCB does not grow to add a capability.** W1 adds no privilege and reuses only mechanisms the
  daemon already wields for kennels; W2's adversarial parsing lands entirely outside the daemon
  (facade on the untrusted side, broker as a quarantined operator-context leaf). Where a workstream
  touches a TCB crate, the growth is measured (`gen-inventory`) and justified, never assumed — and
  W4 is measured because it *shrinks*.
- **Authentication, never attestation.** Load-bearing for W3: file-open consent is the operator's
  act, performed host-side; nothing confined can vouch for it.
- **Never overclaim.** W1's claim is *bounded* compromise, not containment — the docs ship that
  claim exactly as scoped or not at all. W2's accepted residuals (AF_INET-only legacy clients,
  exfil inside approved flows) are recorded, not papered over.

## What this release is *not*

- **Not kenneld restart-fork resolution and not global spawn-storm accounting.** Both are real and
  corpus-grounded — a kenneld restart still ends every running kennel
  (`docs/architecture/05-state-and-supervision.md`), and per-spawn cgroup ceilings (§7.12) have no
  aggregate — but neither is this release's bet. Both move to [BACKLOG.md](BACKLOG.md) with named
  promote conditions rather than riding roadmap non-goal prose from release to release.
- **Not multi-operator delegation.** The keys design deliberately leaves the delegation model open
  (who may add a key to a place, how holders are scoped against one another); there is nothing
  schedulable until the design track settles it. Fenced in the backlog as design-gated.
- **Not fine-grained `[consumes]` method policy.** Same class: fenced behind its design question
  (finer policy must not drag a protocol-body parser into a broker).
- **Not a first-party MASQUE/`connect-udp` endpoint.** If the ecosystem brings UDP to the existing
  CONNECT chokepoint, that is a later, cheaper workstream; W2 does not preempt it (backlog note).
- **Not the macOS port** — tracked in the backlog, not scheduled.

Items with no timeline remain in [BACKLOG.md](BACKLOG.md); this file lists only what 0.6.0 commits to.

## Workstreams

Sizes: **XS** ≈ hours, **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week.
Tags: **[dep]** · **[debt]** · **[security]** · **[quality]** · **[validation]** · **[ship-gate]**.

### W0 · Front-matter validation: measure the unknowns the bets rest on

**[validation] S. Runs first; a red result reshapes the dependent workstream before its manifest or
schema lands, which is the entire point of paying for it up front.**

The codebase measures rather than reasons about kernel behaviour, and both bets rest on specific,
cheaply-probeable claims. Each probe below names its dependent and what a red result means. Results
are recorded in a dated note under `audits/` so the manifests that follow cite measurements, not
assumptions.

- **P1 — Landlock across the magic symlink (gates the W1 fs manifest).** kenneld reaches
  `/proc/<init>/root/dev/binderfs/binder` for each kennel — a magic-symlink traversal into another
  mount namespace. Whether Landlock cleanly governs that traversal (resolves the symlink, applies
  the ruleset to the target across the mount-ns boundary) is kernel behaviour, not documented
  contract. Red: the fs surface is reshaped — the binder reaches are held as pre-seal fds or granted
  by a different rule shape — before the manifest is drawn.
- **P2 — Fork-point threading (gates the W1 fork split).** The parent relay must fork before any
  thread exists. Verify kenneld's startup is genuinely single-threaded at the intended fork point
  (no library — resolver, logging, runtime — has spawned earlier). Red: the fork point moves, or the
  offending initialisation is deferred.
- **P3 — Inet inventory of the future child (gates the W1 seccomp seal).** The seal assumes DNS
  (`inet::dns::SystemResolver`) is the *only* inet-socket user in what becomes the sealed child.
  Inventory every `socket(AF_INET*)` across the policy suite under strace — NSS and glibc have
  surprised before. Red: each additional user is either moved to the parent behind the same relay
  protocol or eliminated; none survives in the child.
- **P4 — `MSG_ERRQUEUE` port-unreachable recovery (shapes W2 Part D).** The broker translates a
  flow's `ECONNREFUSED` into an ICMPv6 port-unreachable reconstructed from the error-queue read.
  Verify the connected-UDP error-queue actually delivers what the reconstruction needs on the
  pinned kernel. Red: refused ports degrade to idle-expiry semantics and the W2 exit criterion is
  re-scoped honestly before the broker is built.
- **P5 — AppArmor `userns` grant across the fork split (accompanies W1).** The mesh fork-holder
  proved the grant crosses a `clone(CLONE_NEWUSER)` child; the W1 shape adds a sealed child and an
  unsealed parent under the same profile. Verify the profile semantics hold for both sides of the
  split — verify, do not assume, is the W14 lesson. Red: the profile edit lands with W1, not as a
  post-hoc fix.

**Exit:** every probe has a recorded result in a dated `audits/` note; each red result has a named
consequence applied to its dependent workstream before that workstream's manifest, schema, or wire
protocol is committed.

### W1 · kenneld self-confinement · the monitor inside its own kennel

**[security, foundational] L.**

The reference monitor is the floor of the TCB, and the tamperproof property says nothing below it can
reach up and alter it. That property is real until something gets in, and then it is empty: a compromised
kenneld holds total authority and the game is over. This is the one place the property was always vacuous,
and the work closes it. kenneld constructs and seals its own confinement before it touches any kennel input,
so a breakout from a kennel into kenneld lands inside a box kenneld no longer controls. The seal does not
reverse within a process, so even an owned monitor stays held. That converts "monitor compromise is total"
into "monitor compromise is bounded," and it does so by turning the framework on its own root: kenneld writes
the same `[fs]`/`[net]`/`[exec]` manifest it writes for every workload, for itself.

**Standing constraint.** The seal adds no privilege and no TCB. It reuses mechanisms the daemon already
wields for kennels: the AppArmor `userns` grant, Landlock, `no_new_privs`, seccomp. The privhelper stays the
only file-caps component, and where the work touches a TCB crate the growth is measured (`gen-inventory`) and
justified. Authentication, never attestation, carries through unchanged.

**The seal.**

- **Filesystem, Landlock fs.** kenneld's filesystem surface is enumerable and small: the trust store (read),
  the runtime dir under `$XDG_RUNTIME_DIR/kennel/` (read-write, the control socket and per-kennel state),
  templates, fragments, and keys (read), the privhelper (read and execute), and the procfs reaches into
  kennels. A Landlock ruleset grants exactly those and denies the operator's home and the rest of the host.
  This is kenneld's own `[fs]`, drawn the way a kennel's is.

- **Network, seccomp, not a netns and not Landlock.** kenneld stays in the host network namespace by
  necessity: its control plane rides AF_UNIX sockets, and abstract-namespace sockets are scoped to the netns,
  so a fresh `CLONE_NEWNET` would sever the broker and delegate connections. The seal is a seccomp
  `socket(AF_INET)`/`socket(AF_INET6)` deny, tighter than a Landlock TCP rule because it removes UDP and raw
  at the source rather than gating `connect`/`bind` on TCP alone. The runtime does not use this mechanism
  elsewhere; kennels gate egress at the BPF CIDR ACL, the monitor gates its own at the syscall. kenneld does
  open inet sockets today, for DNS resolution (`inet::dns::SystemResolver`), so the seal is not free: that one
  operation has to move, which the fork split below handles. Accepted trade: no netns means kenneld keeps
  host-netns visibility, so a compromised monitor can still enumerate interfaces. For the monitor, action
  denial outweighs recon denial, and the view cannot be flattened without cutting the AF_UNIX sockets the
  control plane needs.

- **Execution, the privhelper only.** Landlock execute on the privhelper and its narrow sub-helpers, nothing
  else, under `no_new_privs`.

- **Syscalls, seccomp floor.** A filter admitting the mount, clone, and binder operations the job requires
  and denying the rest.

**The fork split.** kenneld forks once at startup, before the seal. The parent stays host-side and unsealed;
the child installs the seal and becomes the monitor. The parent is the inet-capable relay: it launches the
`host-netproxy` and `host-inetd` delegates, so they descend from it and inherit no seal, and it relays their
fds to and from the child over a socketpair held across the fork. The child mints AF_UNIX socketpairs, vets,
pins, brokers, and passes fds, none of which needs an inet socket. DNS moves to the parent and nowhere else,
not into the dumb dialer, which stays dumb so the pin holds: the parent resolves, the child re-checks every
address against `[dns]` and the denylist and pins the vetted set, the dialer dials the pinned literal.
`inet::decide` already takes the resolver as a parameter, so the move is one resolver implementation swapped
behind an existing seam, with the decision and the pin unchanged in the child. The parent is not confined,
because its job is inet and exec of the delegates, and a sandbox that granted those back would protect
nothing. Its safety is that it is small, reachable only from the child, treats every message from the child as
hostile, and is mutually un-`ptrace`-able with it. The boundary the seal buys is the gap between what a
monolithic kenneld could do on compromise, arbitrary inet and arbitrary host, and what this parent will do on
request, a DNS lookup and a delegate spawn. That request channel is the one new artifact in the whole shape, and
because the parent is unconfined it is the entire boundary, so it takes the privhelper's wire discipline:
fixed-layout structs, length-prefixed frames, no TOML, a message set held to three, resolve a name and return
the addresses, spawn a delegate and return its fd, and the fd relay itself. The smaller that protocol, the
smaller the surface a compromised child can drive the parent across.

**What the seal keeps, and what it cannot.** The seal strips everything outside the job: the operator's home
and keys, arbitrary host writes, arbitrary exec, and direct inet, the raw sockets, backdoor listeners, and
scanning a monitor never needs. It cannot strip kenneld's reason for
existing. The monitor keeps its parent-userns authority over kennels, the privhelper exec, and the
trust-store read, because those are the job. A compromised-and-sealed kenneld can still mis-broker inside that
authority (a new threat-catalogue entry is minted for the sealed monitor mis-brokering within its retained
authority): it can drive the dumb dialer to an address it pins, because brokering egress is the job and the
pin is the monitor's own step. The win is precise and worth stating plainly: a kennel breakout into kenneld
can no longer open a raw socket, plant a host backdoor, exec a payload, or read the operator's keys, but it
stays inside kenneld's legitimate authority and could still mis-route. Bounded, not neutered, and
the docs ship that claim or none.

**The surface is operational classes, not a frozen fd set.** A kennel opens once and runs a fixed workload,
so its box freezes. kenneld is long-lived and keeps opening kennel resources as it spawns: new procfs
reaches, new binder devices, new control connections. Its box grants operational classes rather than a fixed
set, which makes the surface broader than a kennel's and harder to draw. Drawing it precisely is the bulk of
the work, and it is the test the `do-less` discipline sets itself, the claim that the surface is enumerable,
made to prove itself on the monitor.

**Dependency, and what the mesh already settled.** Gated on the 0.5.0 mesh, which has done more than provide
the ground to stand on. The mesh fork-holder measured the keystone the whole family rests on: kenneld's
`userns` grant crosses a `clone(CLONE_NEWUSER)` child and not an exec'd binary, and a single-uid
`0 <kenneld-uid> 1` self-map mounts binderfs and adds the device with no caps and no privhelper. The holder is
the proof of concept for the parent relay, the same fork-from-the-single-threaded-startup-parent move with a
different payload, so the parent and the mesh-inits inherit a primitive that is already built and de-risked
rather than one still to invent.

**Two halves, one de-risked.** The work divides cleanly, and the division is worth holding because the halves
carry different risk. The process shape is the near-known half: fork the parent before threads at startup,
seal the child, and define the small protocol across the three seams that already exist, DNS behind the
`inet::decide` resolver parameter and the netproxy and inetd spawns that are already separate delegates driven
over command sockets. None of that cuts a new seam; it traces lines the runtime already draws, on a fork
primitive the mesh holder proved. The filesystem surface is the unknown half: the manifest must enumerate
everything kenneld touches and prove nothing was missed, and a missed seam hides there, not in the process
shape. It is gated on the W0 P1 probe, and it is where the real remaining work and the real remaining risk
both sit.

**Sketch of the steps.**

The process half, mostly mechanical:

1. The parent-child protocol: fixed-layout length-prefixed frames, three messages (resolve, spawn-delegate,
   fd-relay), the privhelper's wire discipline. This is the new boundary, so it gets the care — and a fuzz
   target lands with the frame parser (§10.6).
2. Fork the parent at startup before threads (P2); seal the child (seccomp `socket(AF_INET)` deny,
   `no_new_privs`); hold the relay socketpair across the fork.
3. Relocate the delegate spawns to the parent, netproxy and inetd descending from it rather than the sealed
   child, and swap DNS to a parent-backed resolver behind the `inet::decide` seam, the dumb dialer and the
   pin unchanged.

The filesystem half, where the unknown is:

4. The W0 P1 Landlock traversal probe result applied. Gates the fs manifest.
5. kenneld's `[fs]` manifest: enumerate the surface against the as-built reach set, grant exactly it, with the
   exec and seccomp floors alongside.
6. The open-and-seal sequencing: acquire every handle the job needs, the relay socketpair among them, then
   seal, then serve, so the seal precedes the first kennel input.

**Exit:** kenneld forks the unsealed parent relay at startup and the child installs the full seal
(Landlock fs manifest, seccomp inet-deny + syscall floor, `no_new_privs`, privhelper-only exec)
before reading any kennel input; the parent-child protocol is the three-message fixed-layout set
with a fuzz target; the policy suite passes end-to-end under the sealed daemon; the sealed child
demonstrably cannot open an inet socket, exec outside the privhelper set, or read the operator's
home (asserted by test from inside the sealed process); the mis-brokering threat entry is minted
(catalogue version bump); the corpus ships the bounded-compromise claim exactly as scoped.

### W2 · UDP egress in constrained mode: the naming shim, the tun facade, and the flow broker

**[security, foundational] L.**

**Why now.** The brokered path is CONNECT-shaped; a workload that needs UDP today has exactly one
answer, `net.mode = "host"`, which reopens host reconnaissance (T1.6) *and* the in-kennel DNS exfil
axis for a transport class that is becoming default (QUIC/h3). Proxy-aware clients already degrade
correctly — with a proxy configured they never attempt QUIC — so this workstream serves the residual
population only: raw QUIC libraries, DNS tooling, VoIP/game stacks that never honour proxy
convention. The design fell out of the 0.5.0 mesh work and was settled in design review 2026-07-02;
this entry records the commitment, the design corpus records the *what* (§7.x, to be written as
Part E).

**The load-bearing invariant, stated first.** Constrained mode currently makes DNS exfiltration
*unexpressible*: no resolver, no reply, no query the workload can cause. This workstream must not
convert that absence into interposition. Every part below preserves it — denied names are answered
locally with **zero wire activity**, real addresses and real DNS replies never enter the kennel, and
the check-then-resolve ordering of §8.2 (policy check *before* any resolution) is promoted to a named,
tested invariant rather than an emergent property.

- **Part A — schema and compile: the synthetic table.** `[net.udp]` is opt-in within `constrained`;
  the destination grammar is the existing `[[net.proxy.allow]]` `name`/`ports`/`protocol` triple with
  `protocol = "udp"` — no second allowlist grammar (*do-less*). The compiler mints a **deterministic
  synthetic IPv6 table** into the settled artefact: exact names assigned at compile (the table *is*
  signed policy — auditable, diffable, restart-identical); spawn-patched match-set selections minted
  at instantiation; wildcard matches hash-minted at first resolution so the table stays a pure
  function of (policy, names seen). Synthetics are capability tokens shaped like addresses; nothing
  expires, because the real resolution happens host-side at each flow's dial. Pool is a ULA /64,
  interface address partitioned from the hashed suffix space so a mint can never collide with the
  tun's own address. `[net.udp]` is a settled-artefact shape change, so this bumps
  `SETTLED_SCHEMA_VERSION`; `kennel-compose` gains the corresponding capability question.

- **Part B — construction: the tun.** The factory child creates `tun0` **pre-pivot, inside the
  existing in-namespace `CAP_NET_ADMIN` window** (same moment as loopback bring-up): ULA /64, MTU
  1280, **no default route** — the only route is the connected prefix, so a literal-IP destination
  dies in the kennel's own kernel with `ENETUNREACH` before any facade sees it. The routing table is
  itself the allowlist. No v4 address on the tun (suppresses `getaddrinfo` A-queries via
  `AI_ADDRCONFIG`). The tun **fd** rides `fexecve` into `bin-init` and the supervision Plan into the
  facade, exactly as the SOCKS listener does; `/dev/net/tun` stays **absent from the view** —
  the fd is the capability, and absence of the node closes the `IFF_MULTI_QUEUE` second-writer path
  even against in-namespace root. Interface config is immutable to the workload by the uid line
  (§2.5), before any filter is consulted.

- **Part C — `facade-tun`: a stateless predicate, not a codec.** In-kennel, workload-uid, empty
  bounding set, holding the tun fd and one `SOCK_SEQPACKET` socketpair to the broker. It copies
  **whole L3 frames** in both directions behind a symmetric shape check, and originates nothing:
  - egress: `v6 ∧ nexthdr==UDP ∧ src == kennel-addr (exact) ∧ dst ∈ pool ∧ len sane` — all
    workload-originated ICMPv6 is dropped (MTU is pinned; there is no legitimate use, and passing it
    hands the workload an injection primitive into the broker's parser);
  - ingress: `(UDP ∨ ICMPv6 error, type 1, codes {1, 4}) ∧ src ∈ pool ∧ dst == kennel-addr` — a
    compromised broker cannot spoof arbitrary sources into the workload's stack;
  - any failure: drop + counter, never an ICMP (a predicate failure is an internal fault surfaced as
    a metric, not network weather).
  The facade holds no flow state — nothing to exhaust, nothing to desync. The egress path parses
  genuinely hostile workload input and is the **fuzz target**; the ingress path is trusted-but-verified.

- **Part D — the per-kennel flow broker.** kenneld is **absent from the per-flow path** — the
  ACCEPT_SESSION lesson applied (a flow-request verb on node 0 is a DoS aperture; all judgment was
  spent at compile). A per-kennel operator-context broker is spawned at construction when
  `[net.udp]` is enabled, handed the compiled synthetic table, wildcard patterns, and invariant
  denies **once**, and fate-shared with the kennel (cgroup kill / socketpair HUP). It owns:
  - **the naming shim**: DNS queries arrive over the tun path addressed to a reserved pool address
    and are answered from the table — AAAA from the synthetic table, A answered **NODATA**
    (`NOERROR`, empty answer — never `NXDOMAIN`, which would kill the AAAA), denied names NODATA,
    **zero wire activity in every case**. There is no `[net.dns]`; the shim is not a DNS client.
  - **the flow table**, keyed from the packet (the tuple is never predicted, only observed): first
    datagram to a synthetic → resolve-check-pin-dial host-side (resolution vetted against the
    invariant denies, which can never be compiled away), one **connected** UDP socket per flow
    (kernel-enforced return-path filtering for free), epoll loop, `recvmmsg`/`sendmmsg` if it ever
    matters. No per-flow processes — UDP is many cheap flows, not few long conduits.
  - **teardown**: idle expiry as the semantics (RFC 4787 posture), broker-owned; kennel death
    propagates as HUP on the socketpair. Re-establishment is a fresh policy re-check, which gives
    UDP a **bounded revocation latency** the TCP conduits lack — a deliberate narrowing of the
    T1.10 residual, recorded as such.
  - **ICMPv6, minimal**: admin-prohibited synthesized locally for policy denials (the triggering
    packet is in hand — no retained state), port-unreachable translated from `ECONNREFUSED` via
    `MSG_ERRQUEUE` (the quotation reconstructed from the error-queue read; the W0 P4 probe verifies
    the recovery on the pinned kernel). Rate-capped per flow-key — never a reflection amplifier at
    our own tun. No PTB, no PMTUD: MTU stays pinned.
  - **ceilings**: concurrent-flow cap, new-flow token bucket, resolution concurrency bound — all
    per-kennel by construction, so a spraying workload saturates only itself.
  - **audit**: the broker writes its own flow records (the dbus delegate precedent for trusted-side
    writers outside the daemon); `source` field distinguishes it.

- **Part E — threat catalogue, inventory, and corpus.** New entries: the broker as a
  **trusted-side adversarial parser** (hostile L3/L4 headers and DNS wire in operator context —
  quarantined per-kennel, fate-shared, fuzzed; the §4.3 empty-intersection claim is *scoped to the
  daemon*, and the inventory note says so explicitly rather than letting the daemon's cleanliness
  read as the system's); the accepted residual that **AF_INET-only legacy clients fail**
  (`gethostbyname` gets NODATA — recorded, not papered over); exfil inside approved UDP flows as
  the T1.8 shape unchanged. §8.2's check-then-resolve ordering gets an explicit test pinning it.
  Design corpus and Vol 2 chapter 8 gain the mechanism section; the `interactive`-line guidance
  ("UDP means host mode") is revised to "UDP means `[net.udp]`; host mode remains for raw sockets
  and packet capture."

**TCB accounting.** The daemon grows two things only: the compile-time table mint and the
construction-time broker spawn. The adversarial parsing (facade egress, broker L3/DNS) lands
entirely outside the daemon — facade on the untrusted side, broker as a quarantined
operator-context leaf. Measured by `gen-inventory` at landing, per the standing constraint.

**Sequencing.** A → B → C/D (parallel once the socketpair contract is fixed) → E. No dependency on
W1 or W3; independent of both.

**Exit criteria.**
- A `constrained` kennel with `[net.udp]` and one `protocol = "udp"` grant runs a stock QUIC client
  (quiche/msquic example) and `dig` against the granted name; both work with **zero DNS packets on
  the host wire for denied names** (packet-capture assertion in the test).
- A denied name resolves NODATA and a denied flow receives admin-prohibited within the rate cap;
  a refused port receives port-unreachable; a client in an infinite-retry loop against a dead
  destination fails fast (the reason this workstream exists).
- Literal-IP egress fails `ENETUNREACH` in-kernel; a crafted v4/ICMPv6/spoofed-src frame written to
  the tun is dropped and counted on the facade predicate (fuzz corpus covers all four classes).
- Broker ceilings hold under a flow-spray test; kenneld's transaction rate is **flat** during it.
- `gen-inventory` delta reviewed; threat entries and the §8.2 ordering test landed; the
  `SETTLED_SCHEMA_VERSION` bump and `kennel-compose` question landed with Part A.

**Non-goals.** PMTUD/PTB and any MTU above 1280. Workload-originated ICMPv6. Multicast/MLD. v4
synthetics (AAAA-only is the posture; the legacy-client residual is accepted). A first-party
MASQUE/`connect-udp` endpoint — if the ecosystem brings UDP to the existing CONNECT chokepoint,
that is a later, cheaper workstream and this one does not preempt it (backlog note).

### W3 · The interactive file broker

**[capability] M. Promoted from BACKLOG; the fence condition is met.**

The confined GUI's committed residual (§7.14.7): a confined app touches only its pre-granted paths —
there is no consented, per-file grant, so "open a file the policy did not anticipate" means editing
policy. The backlog fenced this behind one question — where the D-Bus broker itself lives — and
0.5.0 answered it: D-Bus mediation is a standing `dbus-broker@v1` service kennel on the mesh. The
app-facing surface now has a home.

The shape, within the settled model:

- **App-facing:** an unmodified GTK/Qt app reaches a chooser only through the
  `org.freedesktop.portal.FileChooser` D-Bus interface. The request rides the kennel's existing
  in-view D-Bus facade over the brokered path — no new socket, no new protocol parser in the daemon;
  the FileChooser method surface is handled where D-Bus is already handled.
- **Consent-facing:** the picker is a host-side transient component in operator context, under the
  delegate pattern (`host-netproxy`/`host-inetd` precedent). Consent is the operator's act;
  nothing confined can vouch for it (authentication, never attestation).
- **Delivery:** the result of consent is **one fd** delivered into the workload's view (the §4.3
  fd-broker shape) — the file, not its path, not its parent directory, no grant widening.
- **Floor first:** open-one-file and save-one-file. Per-method/fine-grained service policy stays
  fenced behind its own design question (see non-goals).

**Exit:** an unmodified GTK or Qt app in a confined GUI kennel opens a host file through the portal
FileChooser and receives exactly the picked file as an fd in its view; the save-one-file round trip
works; a policy-suite case covers the deny shape (no chooser surface granted → the portal call fails
cleanly, no picker appears); a test asserts the picked fd is the only new reach in the view.

### W4 · Retire the per-kennel `host-dbus` delegate

**[debt] M. Gated on demonstrated subsumption — the demonstration is the workstream.**

The 0.5.0 decision (2026-06-29) kept the legacy per-kennel `host-dbus` operator delegate as the
fallback for `[dbus.session]`-only consumers, "until the broker has demonstrably subsumed it." This
workstream is that demonstration, then the deletion, in that order:

- **Route the last consumer class over the broker.** `[dbus.session]` alone compiles to the brokered
  path (the section implies the `dbus-name` consume; one path, not two coexisting). The broker is
  `ondemand`-enabled, so a host with no D-Bus consumer still pays nothing.
- **Prove parity.** The policy suite, the 0.5.0 brokered-D-Bus e2e, and the confined-GUI session
  cases all pass with every consumer routed over `dbus-broker@v1` — the workload-visible bus
  behaviour is unchanged from the facade seat.
- **Then delete.** The `host-dbus` delegate pair, the two-declaration contract, and the routing
  split are removed from the tree. The deletion is the point: one auditable mediation home, minus a
  legacy path and its maintenance. The shrink is measured (`gen-inventory`), not asserted.

If parity fails on something real — a bus behaviour the broker cannot carry — the workstream stops
and records why: the delegate stays, this roadmap says so, and the gate did its job. Sequenced after
W3, which adds a real brokered consumer and is exactly the subsumption evidence the gate wants.

**Exit:** `[dbus.session]` alone routes over the standing broker; the policy suite and confined-GUI
cases pass with the `host-dbus` delegate deleted from the tree; the `gen-inventory` delta is
recorded; CHANGELOG carries the migration note.

### W5 · Remove the legacy raw-base64 key format

**[debt] XS.**

0.5.0's key-format workstream committed the schedule: both formats accepted during 0.5.0, raw-base64
removed in 0.6.0. The transition window was taken — the legacy acceptance is still live in both
loaders (`kennel-cli` `shared.rs`: the trust-store and signing-key legacy branches) — so this is
real code, not a doc line. The OpenSSH wire format becomes the only parse; the legacy branches and
their tests go; the diagnostic on a raw-base64 file names the migration (regenerate or import via
`ssh-keygen`) rather than failing as a generic parse error.

**Exit:** a raw-base64 key file is refused with a migration-pointing diagnostic; the loaders parse
OpenSSH format only; CHANGELOG records the removal.

### W6 · Runtime-validate the four schema-enum'd policy fields

**[quality] S. A behaviour change, deliberately its own workstream.**

Six policy fields carry closed value-sets; two validate through their enums' `Deserialize`, so an
invalid value errors at compile. The other four — `[net.bind].inaddr_any_policy` /
`in6addr_any_policy`, `[net.audit].level`, `[dbus.audit].level` — got schema *hints* from real types
(#142) but still pass through unchecked at compile, so an invalid value rides silently into the
settled artefact. That is a §10.2 violation (parsing is the validation) with the fix already shaped:
route the four through the same enum `Deserialize` as the two. It starts rejecting values that slip
through today — the reason it was fenced out of #142 rather than folded in, and the reason it lands
here as a named change with its own CHANGELOG line. No settled-artefact shape changes; compile-time
only.

**Exit:** an invalid value in any of the four fields is a typed compile error; a test covers each
field; CHANGELOG names the tightening.

### W7 · Derive the man pages from the CLI definition

**[debt, quality] S.**

`gen-man` emits the groff pages from a hand-kept data table that mirrors the CLI dispatch, kept
honest by a sync test — the same hand-mirror-plus-babysitter shape #142 removed from `gen-schema`,
and the drift class is live: 0.5.0 churned the CLI surface (`inspect` added, `policy upgrade`
removed) through that table by hand. Reflect the pages from the CLI definition itself so the table
cannot diverge, and delete the table and its sync test — derive, don't duplicate-then-sync.

**Exit:** the man pages are generated from the CLI definition with no hand-kept mirror; the sync
test is deleted (nothing left to desync); the man regen CI job passes unchanged.

### W8 · Pre-ship adversarial pass on the three new boundaries

**[security, ship-gate] S.**

0.6.0 creates three boundaries that did not exist: the parent-child relay protocol (the one
unconfined component reachable from the sealed monitor), the UDP facade predicate and flow broker
(hostile L3 and DNS wire parsed in operator context), and the file-broker consent path (a host-side
picker delivering fds across the boundary). The 0.5.0 precedent holds — no finding from a focused
pass is not proven safe — and none of these has been driven from the hostile seat. Drive each live:

- the **relay** from a compromised-child position: arbitrary bytes on the wire, message flooding,
  fd-relay abuse, anything that makes the parent do more than resolve, spawn, and relay;
- the **UDP facade and broker** with the four crafted-frame classes and DNS-wire fuzz — the §10.6
  fuzz targets land with their parsers in W1/W2; this pass drives them further and from composed
  positions (facade and broker together);
- the **picker path** for consent bypass, fd-scope widening, and confused-deputy shapes (a kennel
  inducing a picker it should not reach).

**Exit:** a dated `audits/` note covers all three boundaries; every confirmed finding is fixed
before the tag.

### W9 · Corpus cutover: retire `docs/design` + `docs/architecture` in favour of the book

**[debt, structural] M. The parallel track, recorded; sequenced early because W1 and W2 write
their corpus halves into the book.**

The clean-sheet rewrite has landed: the two-volume book — its own repo, `projectkennel/books`,
typically checked out in-tree at `books/` (gitignored) — carries the design (Vol 1,
platform-neutral) and the Linux realisation (Vol 2), with a Threats tree at T-ID parity with the
frozen catalogue (verified 2026-07-02: identical heading sets). The frozen trees retire in its
favour. Most of the work is mechanical; the discipline is in not losing anything load-bearing on
the way out.

Decisions settled up front (2026-07-02):

- **The threat catalogue stays canonical in this repo.** `THREATS.md` is machine-coupled —
  `dist/threats/catalogue.toml` (what `kennel policy risks` reads), the CI sync guard, compile
  diagnostics citing T-IDs, the issue-tag Action — and none of that can depend on a sibling
  checkout. The book's Threats material derives from this repo's catalogue; it never forks it
  (derive, don't duplicate-then-sync).
- **The book is referenced, not vendored.** The corpus is named by URL, with the in-tree `books/`
  checkout as the expected working convention; the standing orders and README say so. No submodule
  pin — the book has its own cadence.
- **The machine-coupled and as-built artefacts get one durable home in this repo** —
  `docs/reference/` (name final at landing): the canonical `THREATS.md`; the generated crate
  inventory and SLOC table (`crate-inventory.json` + the generated decomposition doc, today
  regenerated into `docs/architecture/` by CI); the pointer to the authoritative policy schema
  (the artefact itself stays `schema/policy.toml.schema`, derived from the parser structs); and
  the **as-built log**, the successor of `DOC-PATCH-LOG.md` — per-PR as-built deltas recorded
  against *book* chapter targets, ingested on the book's cadence. The freeze's one-way ingestion
  queue becomes the steady-state channel between the repos.

The mechanical body:

- **Drain the queue first.** The patch log holds 11 entries; each is verified present in the book
  (or ingested now) before anything is deleted, itemised in the PR that performs the drain.
- **Repoint the code to chapter and verse.** ~40 source files cite the old trees' chapter/§ scheme
  in rustdoc and comments. Build the mapping once — old chapter/§ → book volume/chapter/section —
  and rewrite every citation to the book's chapter and verse. Where the book dissolved a section,
  the citation follows the fact to its new home, never the old filename.
- **Repoint the governance and user-facing set.** The standing orders' corpus definition (the
  escalation order names the book: Vol 1 for design intent, Vol 2 for the as-built contract),
  CODING-STANDARDS' chapter pointers, RELEASE-CEREMONY, README/INSTALL/HOWTOs.
- **Repoint CI.** The inventory job regenerates into the new home instead of
  `docs/architecture/`; the threats guard follows `THREATS.md`; the schema job is untouched.
- **Then delete.** `docs/design/` and `docs/architecture/` leave the tree; the patch log closes
  with a final entry naming its successor. Git history keeps both trees.

**Exit:** the book is the named corpus in the standing orders and README (URL + in-tree
convention); the reference home carries the canonical threat catalogue, the regenerated
inventory/SLOC artefacts, and the as-built log; the 11 queued patch entries are verified ingested;
no source, governance, or CI reference to `docs/design/` or `docs/architecture/` remains; both
trees are deleted; CI is green with the inventory and threats jobs on their new targets.

## Sequencing

```
W0 (validation probes) ── S,  first: P1→W1-fs, P2/P3→W1-fork, P4→W2-D, P5→W1 ►
W9 (corpus cutover)    ── M,  early: before W1/W2 write their corpus halves ─►
W1 (self-confinement)  ── L,  process half after P2/P3; fs half after P1 ────►
W2 (UDP egress)        ── L,  A→B→C/D→E; independent of W1/W3 ───────────────►
W3 (file broker)       ── M,  independent; lands before W4 ──────────────────►
W4 (host-dbus retire)  ── M,  after W3 (its consumer is the evidence) ───────►
W5 (raw-base64 removal)── XS, independent ───────────────────────────────────►
W6 (enum validation)   ── S,  independent ───────────────────────────────────►
W7 (gen-man)           ── S,  independent ───────────────────────────────────►
W8 (adversarial pass)  ── S,  after W1 + W2 + W3, ship gate ─────────────────►
```

W0 opens the release and is cheap insurance on both bets. W9 runs alongside it — the cutover does
not touch the bets' code but must land before W1/W2 write their corpus halves, so those chapters
are written once, in the book. W1 and W2 are the two long poles and are independent of each other —
they proceed in parallel against capacity. W3 lands before W4 because the file broker is itself the
brokered-D-Bus consumer that W4's subsumption gate wants as evidence. W5–W7 slot against capacity.
W8 blocks the tag.

## Exit criteria

0.6.0 ships when:

- Every W0 probe has a recorded result and every red result has its named consequence applied (W0).
- kenneld runs sealed: the fork split is in place, the child installs the full seal before any
  kennel input, the three-message relay protocol carries a fuzz target, the policy suite passes
  under the sealed daemon, in-process assertions prove the child cannot open inet sockets, exec
  outside the privhelper set, or read the operator's home; the mis-brokering threat entry is minted
  and the corpus ships the bounded-compromise claim exactly as scoped (W1).
- A constrained kennel with `[net.udp]` runs a stock QUIC client and `dig` with zero wire activity
  for denied names (packet-capture asserted); literal-IP egress dies in-kernel; the facade fuzz
  corpus covers the four crafted-frame classes; broker ceilings hold under flow-spray with kenneld's
  transaction rate flat; the `SETTLED_SCHEMA_VERSION` bump, threat entries, §8.2 ordering test, and
  `kennel-compose` question land with it (W2).
- An unmodified GTK/Qt app opens and saves a host file through the portal FileChooser, receiving
  exactly the picked fd, with the deny shape covered in the policy suite (W3).
- `[dbus.session]` alone routes over `dbus-broker@v1`, the suite and GUI cases pass with the
  `host-dbus` delegate deleted, and the inventory shrink is recorded — or the parity failure is
  recorded and the delegate stays, explicitly (W4).
- Raw-base64 key files are refused with a migration-pointing diagnostic; OpenSSH is the only parse
  (W5).
- The four unchecked enum fields reject invalid values at compile with tests per field (W6).
- The man pages derive from the CLI definition; the hand-kept table and its sync test are gone (W7).
- The corpus cutover is complete: the book is the named corpus, the reference home carries the
  catalogue/inventory/as-built artefacts, the patch-log queue is drained, and the frozen trees are
  deleted with no dangling reference (W9).
- The adversarial pass covers the relay, the UDP facade/broker, and the picker path; every confirmed
  finding is fixed before the tag (W8, ship gate).

CHANGELOG records every stable-surface change — the sealed-daemon process shape, the `[net.udp]`
section and the settled-schema bump, the portal FileChooser surface, the `host-dbus` retirement (or
its recorded retention), the raw-base64 removal, the four-field validation tightening, the
threat-catalogue additions (+ version bump), the man-page derivation, and the corpus move to the
book (with the reference-home relocation of the catalogue and inventory artefacts).

## Parked work

Items with no timeline — declined-on-principle, promote-on-demand candidates, and work fenced to a
later release — live in [BACKLOG.md](BACKLOG.md), not here, so they are not carried from one roadmap
to the next.
