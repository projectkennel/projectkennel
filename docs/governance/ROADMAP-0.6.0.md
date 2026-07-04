# Project Kennel — 0.6.0 plan

Status: **active** · Promoted: 2026-07-02 · Targets: 0.6.0
Baseline: 0.5.0 (released)

> This is a planning artefact, not a design or as-built document. The corpus remains the source
> of truth for *what each item is* — and 0.6.0 is the release in which the corpus itself moves:
> the frozen `docs/archive/design/` and `docs/archive/architecture/` trees retire in favour of the two-volume
> book (W9). Until W9 lands, the frozen trees and the patch log remain the record. This file
> records *what 0.6.0 commits to, why, and in what order*.

## Theme

**One structural bet, and the mediation story finished.** 0.5.0 paid the debt the spawn and mesh
releases accrued; 0.6.0 spends the ground they cleared on the largest tractable gap left in the
confinement story: constrained mode has never carried the transport class the web is moving to — UDP
egress lands without giving up the property that DNS exfiltration is unexpressible (W2). Around the
bet, the release finishes what the `dbus-broker` started: the interactive file broker the confined
GUI has owed since §7.14.7 (W3), and the retirement of the legacy per-kennel `host-dbus` delegate
once the broker demonstrably subsumes it (W4). Three small owed debts ride along (W5–W7), and the
clunky admin-provisioned `/etc/kennel/subkennel` per-user allocation retires — derived from the
kernel-trusted uid instead, which also clears the ULA addressing scheme for W2 (W10). The adoption
story finally reaches its last mile: a maintainer-signed `claude` policy that runs in three commands
with no user-authored leaf, on two small additive policy fields that generalise to a catalogue of
agent policies (W11). The release also carries the corpus succession: the frozen design/architecture
trees retire in favour of the two-volume book (W9). The release opens with a validation stream (W0): every empirical unknown the
work rests on is measured before a manifest or schema is drawn, not reasoned about. A pre-ship
adversarial pass on the new boundaries gates the tag (W8).

**kenneld self-confinement was the release's second structural bet (W1); it is withdrawn.** Building
its relay half surfaced that the fork-split seam is drawn through code not factored for it — the
daemon's host-facing effects (exec, inet, cross-namespace opens) are interleaved through construction
and brokering, so the boundary keeps hitting them ad hoc and the relay protocol grows without
converging. The tidy prerequisite (factoring all host effects behind one seam) is larger than the
seal itself. The finding is written up in
[audits/2026-07-02-w1-self-confinement-seam.md](audits/2026-07-02-w1-self-confinement-seam.md); W1
moves to [BACKLOG.md](BACKLOG.md), gated on that factoring as its named first step.

Standing constraints carried from 0.5.0:

- **The TCB does not grow to add a capability.** W2's adversarial parsing lands entirely outside the
  daemon (facade on the untrusted side, broker as a quarantined operator-context leaf). Where a
  workstream touches a TCB crate, the growth is measured (`gen-inventory`) and justified, never
  assumed — and W4 is measured because it *shrinks*.
- **Authentication, never attestation.** Load-bearing for W3: file-open consent is the operator's
  act, performed host-side; nothing confined can vouch for it.
- **Never overclaim.** W2's accepted residuals (AF_INET-only legacy clients, exfil inside approved
  flows) are recorded, not papered over.

## What this release is *not*

- **Not kenneld restart-fork resolution and not global spawn-storm accounting.** Both are real and
  corpus-grounded — a kenneld restart still ends every running kennel
  (`docs/archive/architecture/05-state-and-supervision.md`), and per-spawn cgroup ceilings (§7.12) have no
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

The codebase measures rather than reasons about kernel behaviour, and the structural work rests on
specific, cheaply-probeable claims. Each probe below names its dependent and what a red result means.
Results are recorded in a dated note under `audits/` so the manifests that follow cite measurements,
not assumptions. (P1/P2/P3/P5 gated the now-withdrawn W1 — recorded for a future attempt; P4 feeds
W2. The probe descriptions below are kept as the historical record of what W0 measured.)

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

### W1 · kenneld self-confinement — WITHDRAWN

**[security, foundational] L. Withdrawn 2026-07-02; moved to [BACKLOG.md](BACKLOG.md).**

Sealing kenneld inside its own confinement (an unsealed relay + a sealed monitor, split at a startup
fork) was this release's second structural bet. Building the relay half surfaced that the seam is
drawn through code not factored for it: the daemon's host-facing effects — exec (`sha256sum`, the
netproxy/inetd/dbus delegates, the ssh bastion), inet resolution, and cross-mount-namespace binder
opens — are interleaved through construction and runtime brokering, not routed through one seam. So
the confinement boundary hits them one at a time and the relay protocol grows without converging; and
seccomp's inheritance across `execve` forces every inet-needing delegate onto the unsealed relay,
which a bounded-allowlist seal cannot accommodate. The tidy prerequisite — factoring **all** host
effects behind one narrow interface, after which the seal is mechanical — is larger than the seal
itself, so the split was premature.

The full analysis (including what W0's probes settled, which still holds) is in
[audits/2026-07-02-w1-self-confinement-seam.md](audits/2026-07-02-w1-self-confinement-seam.md). W1 is
backlogged, gated on the host-effects factoring as its named first step; PR #154 (the relay work) was
closed and the primitive removed (unused TCB weight if the seam moves).

### W2 · UDP egress in constrained mode: the naming shim, the tun facade, and the fenced flow broker

**[security, foundational] L.**

**Why now.** The brokered path is CONNECT-shaped; a workload that needs UDP today has exactly one
answer, `net.mode = "host"`, which reopens host reconnaissance (T1.6) *and* the in-kennel DNS exfil
axis for a transport class becoming default (QUIC/h3). Proxy-aware clients already degrade correctly
(with a proxy configured they never attempt QUIC), so this serves the residual population only: raw
QUIC libraries, DNS tooling, VoIP/game stacks that never honour proxy convention. The design was
settled in review (2026-07-02/03); the book records the *what* (Vol 2 ch.8).

**The load-bearing invariant, stated first.** Constrained mode currently makes DNS exfiltration
*unexpressible*: no resolver, no reply, no query the workload can cause. This workstream must not
convert that absence into interposition. Denied names are answered locally with **zero wire
activity**, real addresses and real DNS replies never enter the kennel, and the check-then-resolve
ordering of §8.2 (policy check *before* any resolution) becomes **structural** here — the broker
cannot complete a dial the kernel BPF fence will not clear.

- **Part A — schema + compile: the allowlist, and nothing more.** `[net.udp]` is opt-in within the
  proxied modes (`constrained` or `unconstrained` — the modes with an own net-ns and a broker to
  carry it; `host` and `none` are refused). Destinations declare under their **own endpoint**,
  `[[net.udp.allow]]`, which **adopts the shape** of `[[net.proxy.allow]]` (the `name`/`ports`
  grammar) — the same struct and the same parser, a distinct table; *not* a `protocol = "udp"`
  overload of the proxy list (*do-less* = reuse the shape, not the endpoint). **Hostnames only:** a
  UDP entry carries a `name`, never a `protocol` (the transport is implied) and never a bare IP/CIDR
  — the capture-by-synthetic mechanism has no address to match, and a literal-IP UDP datagram dies
  `ENETUNREACH` in-kernel anyway (Part B). `[[net.proxy.allow]]` and the `[[net.<transport>.allow]]`
  tun endpoints share **one** parser carrying a `cidr_allowed` flag: the `NetAllow` grammar allows a
  CIDR by **default** (the proxy passes `true`), and the tun endpoints pass `false`. The proxy's
  behaviour is unchanged — same grammar, same acceptance — it simply no longer carries its own copy
  of the loop. UDP destinations settle into their **own** `udp_allow_names` list, kept separate from
  the existing `allow_names` (which `kenneld` consumes protocol-blind, so a UDP name there would
  over-grant). The fenced broker (Part D) is that list's sole consumer; fragments compose
  `[[net.udp.allow.add]]` exactly like the proxy list.
  **There is no compile-time table:** the allowlist may hold wildcards
  (`*.example.com`) the compiler cannot enumerate, so nothing is baked — the settled artefact carries
  only the signed allowlist, and every synthetic address is minted **at runtime** by the broker
  (Part D). `[net.udp]` is an **additive-optional** settled field (a v3 artefact without it stays
  valid), so it **re-pins the v3 shape** in `schema/schema-version.lock` — no `SETTLED_SCHEMA_VERSION`
  bump; `kennel-compose` gains the capability question.

- **Part B — construction: the tun.** The factory child creates `tun0` **pre-pivot, inside the
  existing in-namespace `CAP_NET_ADMIN` window** (same moment as loopback bring-up): a `/64` in the
  **Kennel ULA space W10 established** (`fd6b:6e00:<uid-subnet>::/64`, uid-derived), MTU 1280, **no
  default route** — the only route is the connected prefix, so a literal-IP destination dies
  `ENETUNREACH` in the kennel's own kernel before any facade sees it. The routing table *is* the
  allowlist. No v4 address on the tun (suppresses `getaddrinfo` A-queries via `AI_ADDRCONFIG`). The
  tun **fd** rides `fexecve` into `bin-init` and the Plan into the facade, as the SOCKS listener does;
  `/dev/net/tun` stays **absent from the view** (the fd is the capability; absence closes the
  `IFF_MULTI_QUEUE` second-writer path even against in-namespace root). Interface config is immutable
  to the workload by the uid line (§2.5). Two addresses in the `/64` are reserved: the **broker's
  resolver** (the kennel's `resolv.conf` nameserver) and the tun's own interface address; the rest is
  the synthetic pool, partitioned so a mint can never collide with either.

- **Part C — `facade-tun`: a stateless L3 predicate, not a codec.** In-kennel, workload-uid, empty
  bounding set, holding the tun fd and one `SOCK_SEQPACKET` socketpair to the broker. It copies
  **whole L3 frames** both ways behind a symmetric shape check and originates nothing —
  egress: `v6 ∧ nexthdr==UDP ∧ src == kennel-addr ∧ dst ∈ pool-or-resolver ∧ len sane` (workload
  ICMPv6 dropped); ingress: `(UDP ∨ ICMPv6 error type 1, codes {1,4}) ∧ src ∈ pool ∧ dst ==
  kennel-addr`; any failure: drop + counter, never an ICMP. **It knows nothing about DNS** — a query
  to the resolver address is just another UDP packet it forwards. No flow state. The egress path
  parses genuinely hostile workload input and is the **fuzz target**.

- **Part D — the fenced flow broker (a host-mode leaf).** kenneld is **absent from the per-flow path**
  (the ACCEPT_SESSION lesson: no per-flow verb on node 0). The broker is a **per-kennel
  operator-context leaf run `net.mode = host`**, spawned at construction when `[net.udp]` is enabled,
  handed the allowlist + wildcard patterns **once**, fate-shared with the kennel (cgroup kill /
  socketpair HUP). Its cgroup carries a `net.bpf` egress program used **deny-first as a floor over a
  broad allow** — broad allow (the destinations are name-gated upstream, so their resolved IPs are
  not known at compile) **plus the invariant-deny CIDRs** (cloud-metadata, link-local). That is the
  **IP-layer fence**, kernel-enforced on the *actual dial* (`cgroup/connect6`/`sendmsg6` gate UDP).
  The broker owns:
  - **the naming shim (half 1):** the kennel's `resolv.conf` points at the broker's reserved ULA
    address. A query → check the name against the allowlist → if approved, mint a `name→synthetic-IPv6`
    mapping **if absent** (persistent for the kennel's life) and answer **AAAA** with the synthetic.
    A / CNAME / etc → blanket **NODATA** (`NOERROR` empty — never `NXDOMAIN`, which would kill the
    AAAA). Denied names → NODATA. **Zero wire activity in every case** — it mints, it does not
    resolve. There is no `[net.dns]`; the shim is not a DNS client.
  - **the flow forwarder (half 2):** an L3 packet from the facade → look up the dst synthetic in the
    mapping. Miss → ICMP-unreach. Hit → route to the flow's socket, creating it on the first datagram
    by handing the **name** (from the mapping) to **host-netproxy**, which gains a **UDP mode**: it
    `getaddrinfo`s the name and opens a **connected** UDP socket to the resolved address — reusing the
    existing dumb dialer, now for UDP (keeping a DNS client *out* of the broker: *dont-roll-your-own*).
    **DNS rebinding is closed structurally:** an allowed name that resolves to a special-use IP is
    refused by the broker cgroup's `net.bpf` at `connect()` — no name-based denylist, no
    "metadata-is-TCP" assumption to lean on.
  - **teardown:** idle expiry (RFC 4787 posture), broker-owned; kennel death → socketpair HUP.
    Re-establishment is a fresh policy re-check → UDP gets a **bounded revocation latency** the TCP
    conduits lack (a deliberate T1.10 narrowing, recorded).
  - **ICMPv6, minimal:** admin-prohibited synthesised locally for denials; port-unreachable
    translated from `ECONNREFUSED` via `MSG_ERRQUEUE` (W0 P4 verified the recovery). Rate-capped per
    flow-key. No PTB/PMTUD: MTU stays pinned.
  - **ceilings:** concurrent-flow cap, new-flow token bucket, resolution concurrency bound — all
    per-kennel, so a spraying workload saturates only itself.
  - **audit:** the broker writes its own flow records (the dbus-delegate precedent); `source`
    distinguishes it.

- **Part E — threat catalogue, inventory, corpus.** New entries: the broker as a **host-mode,
  `net.bpf`-fenced, trusted-side adversarial parser** (hostile L3/L4 + DNS wire in operator context —
  quarantined per-kennel, fate-shared, fuzzed; the §4.3 empty-intersection claim is *scoped to the
  daemon*, said explicitly). The **hostnames-only** posture, and the accepted residual that
  **AF_INET-only legacy clients fail** (`gethostbyname` → NODATA — recorded, not papered over). Exfil
  inside approved flows = the T1.8 shape unchanged. **The IP-rebinding case is closed** (by the
  `net.bpf` fence), recorded as *closed*, not accepted. §8.2's check-then-resolve gets an explicit
  test pinning that it is now structural. Book Vol 2 ch.8 gains the mechanism; the `interactive`
  guidance is revised ("UDP means `[net.udp]`; host mode remains for raw sockets / packet capture").

**TCB accounting.** The daemon grows one thing only — the construction-time broker spawn; kenneld
resolves nothing on the per-flow path, so the inet host-effect stays out of the daemon here by
construction. The adversarial parsing (facade egress, broker DNS/L3) lands entirely outside the
daemon — facade on the untrusted side, broker a host-mode `net.bpf`-fenced leaf; host-netproxy gains
a UDP resolve+dial mode (a host-side delegate, not the daemon). Measured by `gen-inventory` at
landing.

**Sequencing.** A → B → C/D (parallel once the socketpair + `resolv.conf` contracts are fixed) → E.
Independent of the other workstreams.

**Exit criteria.**
- A `constrained` kennel with `[net.udp]` and one `[[net.udp.allow]]` grant runs a stock QUIC client
  and `dig` against the granted name; both work with **zero DNS packets on the host wire for denied
  names** (packet-capture assertion).
- A denied name resolves NODATA; a denied flow receives admin-prohibited within the rate cap; a
  refused port receives port-unreachable; a client in an infinite-retry loop against a dead
  destination fails fast (the reason this exists).
- Literal-IP egress fails `ENETUNREACH` in-kernel; a crafted v4/ICMPv6/spoofed-src frame is dropped
  and counted on the facade predicate (fuzz corpus covers all four classes).
- **An allowed name that rebinds to `169.254.169.254` is refused by the broker's `net.bpf` at
  `connect()`** (rebinding closed, not accepted).
- Broker ceilings hold under a flow-spray test; kenneld's transaction rate is **flat** during it.
- `gen-inventory` delta reviewed; threat entries + the §8.2 ordering test landed; the **v3 shape
  re-pin (additive-optional — no version bump)** and the `kennel-compose` question landed with Part A.

**Non-goals.** PMTUD/PTB and any MTU above 1280. Workload-originated ICMPv6. Multicast/MLD. v4
synthetics (AAAA-only; the legacy-client residual is accepted). **Bare-IP/CIDR UDP destinations** —
`[net.udp]` is hostname-only (no name ⇒ no synthetic; a literal IP dies `ENETUNREACH`). A first-party
MASQUE/`connect-udp` endpoint (a later, cheaper workstream if the ecosystem brings UDP to the CONNECT
chokepoint; W2 does not preempt it).

**Future directions (adjacent, NOT W2 — recorded so the shape is on the map).** The broker +
`net.bpf`-fence pattern generalises two ways, each its own later workstream, **complementary, not a
fork**:
- **A transparent slow-lane for TCP, on this tun path.** Extending the capture to TCP gives
  non-proxy-aware **raw TCP** clients a transparent egress (the TCP sibling of the UDP residual) — at
  userspace-L3 (per-frame memcpy) cost. It coexists **permanently** with `net.proxy`, which stays the
  **fast lane**: the CONNECT conduit **splices** kernel-to-kernel (zero userspace copy) for
  proxy-aware bulk TCP. Two lanes in the same kennel — the proxy on loopback, the tun owning the
  synthetic pool — selected by whether the client honours the proxy or dials a resolved synthetic raw
  (the same DNS shim feeds both). Additive; touches `net.proxy` nothing.
- **Relocating `net.proxy`'s broker into a provider kennel.** Lifting the current binder/afunix
  conversation + the INet decision out of kenneld into a mesh provider kennel (the `dbus-broker@v1`
  pattern) moves the inet + cross-ns-binder host-effects off the daemon's per-flow path **while
  preserving the splice datapath and the proven resolve-check-pin enforcement** — the lower-risk,
  direct line at the W1 seam. Only a move of the *decision* (not just the plumbing) evicts inet;
  orthogonal to the TCP slow-lane.

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

### W10 · Retire `/etc/kennel/subkennel` — derive per-user disambiguation from the uid

**[debt, quality] S–M. Clears W2's path; capacity opened by W1's withdrawal.**

`/etc/kennel/subkennel` is an `/etc/subuid`-shaped, root-owned, admin-provisioned file — one line per
user — that kenneld **refuses to start without** ([bin/kenneld.rs](../../src/crates/kenneld/src/bin/kenneld.rs)).
Despite the framing, it does **not** allocate subuid ranges (the userns id-map is the privhelper's
self-map); it now carries only three per-user *disambiguation* values: a `tag` byte (the SSH bastion
port `8022+tag` and the v4 loopback alias), a 40-bit ULA `gid` (the kennel's v6 loopback address), and
a `namespace` name (cosmetic — a topology label). Their whole job is to keep two users' daemons from
colliding on shared host loopback for the inbound BIND mirror (§7.5.7) and the bastion. That is a
heavyweight ceremony — an admin must provision a line before a user can run kenneld at all — for what
is now a small, derivable quantity.

**Why now, and why it touches W2.** With W1 withdrawn there is room; and the per-user ULA `gid` is the
same addressing axis W2's synthetic-UDP ULA /64 pool lives on, so the two schemes would otherwise have
to be reconciled. Removing subkennel lets W2 own the ULA scheme cleanly and drops a provisioning step
from every install.

The change: derive `tag`/`ula_gid`/`namespace` deterministically from the **kernel-trusted real uid**
(no NSS in any privileged path, no `/etc` file), delete the `kennel-privhelper::alloc` module and the
file, and drop the refuse-to-start gate. One real design point: the `tag` byte's collision domain on a
shared host (uid mod 256) — decide the derivation and whether the 40-bit `ula_gid` simply *is* the uid
(or a hash of it). No security boundary moves: the values are collision-avoidance, not access control
(identity stays the kernel's real uid); the admin loses an allocation knob that gated nothing.

**Sequenced before or with W2's addressing** (Part B, the tun ULA /64), so the ULA derivation is
settled once. `install.sh` stops provisioning `subkennel`.

**Exit:** kenneld starts with no `/etc/kennel/subkennel`; per-user loopback/bastion addressing derives
from the uid; the file, the `alloc` module, and the refuse-to-start gate are gone; the installer no
longer provisions it; the policy suite (inbound mirror + bastion) passes on the derived addressing.

### W11 · `kennel run claude`: `allowed_args`, the invocation-cwd grant, and the vendor agent leaf

**[quality] S. The adoption story's last mile: a shipped, signed agent policy that runs in three
commands — invocation, binary, state, endpoints, and the project tree all resolved without the user
authoring any policy.**

The generic `ai-coding-strict` template deliberately omits the LLM API endpoint, the agent binary,
and the project path, so today the honest quickstart is "derive and sign a leaf" — which contradicts
the out-of-the-box pitch. Three deltas close it, each riding mechanism that already exists:

- **`[workload] allowed_args`.** The `-- <args>` tokens append to a pinned workload's argv instead of
  being refused. The append itself already exists — the OCI branch does it unconditionally
  ([server.rs](../../src/crates/kenneld/src/server.rs), the launcher-argv `extend`) — so this exposes
  it as a schema field and adds a third arm to `effective_workload`: policy argv present ∧ `pinned` ∧
  `allowed_args` ∧ request argv non-empty ⇒ `workload.argv ⧺ req.argv`. `pinned` still binds the
  program and base argv exactly (the fd-pin/digest binds the *program*, not the args); the
  pinned-refusal diagnostic names the field.

- **`[fs] cwd.grant` / `cwd.required`, with a required `reason`.** A signed policy may declare that
  the invocation cwd is materialised into the view: `cwd.grant = "read" | "write" | "none"` (default
  `none`) and `cwd.required = [".git", ".claude/"]` (dirent markers; trailing slash ⇒ directory). A
  non-`none` grant **requires a `reason`** — the same acknowledged-tradeoff forcing function as
  `mode = host` and `[[net.proxy.allow]]`, because this is a genuinely new authority shape (signed
  policy declares the slot; the invocation fills it with a writable directory). kenneld resolves
  `req.cwd` host-side pre-spawn, checks it against the floor and markers, and appends it to the run's
  effective grant set; the materialised grant is recorded in the run audit event. **Framework floor,
  non-overridable:** realpath-normalised, owned by the operator, never `$HOME`. Resolution rides the
  0.5.0 `RESOLVE_NO_SYMLINKS` writable-bind-source path. Floor or markers unmet ⇒ the run **refuses**
  with a diagnostic naming the missing marker — never a silent no-grant. A `write` grant lands the
  T2.8 trust manifest at the project root, which is where that workflow belongs.

- **The `claude` vendor leaf + in-view launcher.** `policies/claude` on `ai-coding-strict`: both
  install layouts granted (native `~/.local/{bin,share}/claude` and the npm-global module tree —
  absent layouts normalise away, verified: `materialize_binds` skips a bind whose source does not
  exist and the Landlock seal builds `skip_missing`, so a grant for an absent path is vacuous, not an
  error), `[fs.home] persist` for `.claude`/`.claude.json`, the Anthropic API + OAuth endpoints
  (T1.8-tagged), telemetry silenced via `[env] set` rather than audit-noisy denied connects,
  `cwd.grant = "write"` (with its `reason`) and `[".git", ".claude/"]` as per-project consent
  markers, and a pinned `[workload]` pointing at `kennel-facades/run-claude.sh` — an in-view discovery
  launcher (layout probing belongs inside the view, not in policy) with `allowed_args` for passthrough.
  Maintainer-signed at source, host-signed settled at install, like the existing reference leaves. The
  drafted leaf and launcher are in `scratch/claude.toml` / `scratch/run-claude.sh`. `codex`/`gemini`
  siblings follow the same shape when wanted; not this workstream (and MCP-server confinement is a
  distinct shape — an endpoint the agent dials, not an agent binary — deferred to the backlog).

**Schema.** `allowed_args` and the `[fs] cwd` fields are additive-optional on settled v3; they
**re-pin the v3 shape** (no `SETTLED_SCHEMA_VERSION` bump — shipped that way), independent of W2 (W11
is fully adjacent, no shared bump), and are recorded under Policy schema changes. The book's policy chapter and
`policy.toml(5)` gain both; `kennel(1)` documents the append semantics.

**Endpoints are measured, not drafted.** The `claude.toml` endpoint set (`api.anthropic.com`,
`claude.ai`, `console.anthropic.com`; statsig/sentry silenced) is a hypothesis until one live
`kennel run claude` pass with the egress audit open confirms it — the denied-connect set is the
authoritative list. An exec-glob check confirms the versioned-payload grant survives a claude
self-update.

**Sequencing.** Independent of the other feature work; its schema fields land with W2 Part A's version
bump. The `cwd`-write authority is a W8 adversarial target (below).

**Exit:** `kennel run claude -- <args>` works from a marked project root on a stock install with no
user-authored policy; an unmarked or floor-violating cwd refuses with a naming diagnostic; the
endpoint set is confirmed by a live audit pass; the two schema fields re-pin the v3 shape (no version bump); the README/website quickstart claim ships in the same release, not before.

### W12 · Persona hostname: `[identity].hostname` + a UTS namespace — **TENTATIVE**

**[quality] XS–S. Tentative; slots late or defers to 0.7.0.**

**Why (not anti-recon — coherence).** The persona masks the workload's user as `kennel`, but the
kennel shares the host **UTS** namespace (the spawn unshares USER/MOUNT/PID/IPC/NET, not UTS), so
`uname -n` returns the host's nodename and there is no way to give a kennel a meaningful name of its
own. The synthetic `/etc/hostname` + `/etc/hosts` already carry a hostname
([`kenneld::etc`](../../src/crates/kenneld/src/etc.rs)), but it is unwired to `[identity]` and does
not cover `uname`. This is **not** justified as anti-reconnaissance — masking the hostname while the
workload holds the operator's login token would be theatre (see the accepted persona-recon residual)
— but as **persona coherence + operator control**: one consistent, policy-set identity across
`uname`, `/etc/hostname`, `/etc/hosts`, and the shell prompt. Closing the recon leak is a *bonus*,
not the reason.

**Default: no masking (opt-in).** `[identity].hostname` is optional and **defaults to unset ⇒ no
masking**: no UTS namespace, and `uname -n` / `/etc/hostname` reflect the host — the current
behaviour, backward-compatible, and honest (no pretence of hiding a name the workload's token already
exposes). Setting it opts into a coherent masked identity. This is why the field, not a masked
default, is the design: masking-by-default would be the theatre the persona-recon residual warns
against.

**Schema (additive-optional → re-pin, do NOT bump).** Add `[identity].hostname` — source
`Option<String>` ([`IdentitySection`](../../src/crates/kennel-lib-compile/src/source.rs)), settled
**`Option<String>`** (`None` = no masking) ([`IdentityRuntime`](../../src/crates/kennel-lib-policy/src/settled.rs)),
`skip_serializing_if = "Option::is_none"` so a policy that omits it signs unchanged. Because it is
additive-optional, a v3 artefact stays valid: **re-pin the schema shape fingerprint in
`schema/schema-version.lock`, no `SETTLED_SCHEMA_VERSION` bump** (the established pattern; the CI
guard is unforgiving, so the re-pin lands in the same change).

**Wiring (all gated on `hostname.is_some()`).**
- **Namespace:** when `[identity].hostname` is set, add `Namespaces::UTS` to the unshare set in
  [`Plan::from_policy`](../../src/crates/kennel-lib-spawn/src/plan.rs); **unset ⇒ no UTS unshare**
  (the host UTS, unchanged). The `CLONE_NEWUTS` flag already exists in `kennel_lib_syscall::namespace`.
- **Set the name:** when set, the construction child `sethostname(hostname)` after the UTS unshare —
  it holds `CAP_SYS_ADMIN` over its **own** new UTS via the identity-mapped user namespace, so no
  host privilege is involved. Needs a small `sethostname` wrapper in `kennel-lib-syscall` (an
  `unsafe` syscall site, like the existing ones).
- **Reconcile the synthetic `/etc`:** when set, route the name into `EtcParams.hostname` so
  `uname -n`, `/etc/hostname`, and the `localhost <hostname>` line in `/etc/hosts` all agree; when
  unset, `/etc/hostname`/`/etc/hosts` keep the current (host-reflecting) default — no masking either
  way (verify the current `/etc` default at implementation so unset is genuinely no-masking).

**TCB.** Adds a conditional `Namespaces::UTS` to the plan and one `sethostname` syscall wrapper to
`kennel-lib-syscall` (a TCB crate) — measured with `gen-inventory`, tiny.

**Exit:** with `[identity].hostname` set, `uname -n` inside a kennel returns the policy name (not the
host's) and `/etc/hostname` / `/etc/hosts` agree; with it **unset, the host name shows through
unchanged** (no masking) and the policy signs byte-identically (schema shape re-pinned, version
unbumped); a test asserts the UTS isolation when set (a workload `sethostname` cannot reach the host
UTS). Gives the operator an opt-in knob to close the persona-recon hostname residual, without making
masking (theatre) the default.

### W13 · Ephemeral-bind exemption — SHIPPED (#175); the ingress leg declined on principle (→ BACKLOG)

**What shipped: `bind4`/`bind6` exempt a port-0 (ephemeral) bind in every mode (#175). What was
declined: the `[net.bind.ingress]` OAuth loopback-callback leg — the design is preserved in
[BACKLOG.md](BACKLOG.md), declined on principle.**

**Shipped (#175).** The bind ACL used to refuse an ephemeral `:0` bind even on the kennel's own
loopback. That deny was never load-bearing — the workload already has pipes and filesystem/abstract
unix sockets free in its own netns — and it broke legitimate software (test harnesses, debuggers)
and, load-bearingly, the tun-broker's own outbound dial:
[`connect_udp`](../../src/crates/kennel-host-delegate/src/netproxy/udp.rs) binds `::` / `0.0.0.0`
port 0 for an ephemeral **source** port before `connect()`, which the default-deny ACL
([`bind4`](../../src/bpf/bind4.bpf.c) / [`bind6`](../../src/bpf/bind6.bpf.c)) refused, so a
constrained `[net.udp]` flow was `connect`-allowed yet never got a source port. The fix exempts a
port-0 bind unconditionally — a kernel-allocated ephemeral source port is not a T6 *listening*
surface — ahead of the floor, the port allowlist, and the address ACL, and without the wildcard
rewrite (an outbound socket keeps `0.0.0.0` / `::` so the kernel picks the source per route). That
was the generic value in W13, and it unblocked **W2's live UDP round-trip end-to-end** (#174 resolver
+ `/etc` overlays, #175 this exemption, #176 the shipped ondemand tun-broker) — verified against the
installed service.

**Declined on principle: the `[net.bind.ingress]` inbound leg.** The remainder — a policy-declared
block of host-reachable ephemeral loopback ports (a host-inetd allocation inversion, `bind4`/`bind6`
steering, a binder inbound-accept forwarder), whose motivating receipt was making an interactive
OAuth login work inside a confined `kennel run claude` — is **not built and not scheduled**.
Completing the RFC 8252 native-app flow *inside* the boundary has the confined workload end up
holding a fresh **user-equivalent bearer token**: credential *creation* moved across the confinement
boundary, the inverse of the ssh-bastion shape (which re-originates a *host-held* credential with the
destination bound and never holds the key). The operator's browser approval is a single consent, but
the artifact is durable operator-equivalent authority in untrusted hands — the wrong side of
[[authentication-never-attestation]]. Host-seeded tokens (the operator does the OAuth on the host and
seeds the token in as a signed construction parameter) are the standing answer and keep creation
host-side. The full design, and the one condition that would re-open it, live in
[BACKLOG.md](BACKLOG.md). The port-0 exemption W13 *did* ship stands on its own — it needed no
ingress table.

### W14 · Seccomp hardening: uid-0-unreachable invariant, additive deny composition, denylist completeness — SHIPPED (#173)

**[debt] S. Shipped (`22350ce`, PR #173). No security hole — see
[`governance/audits/2026-07-seccomp-mediation.md`](audits/2026-07-seccomp-mediation.md).
The seccomp layer is defence-in-depth whose every gap is independently closed
(egress by the proto-layer cgroup hook, mount/bpf/kexec by the
uid-0-unreachable property, fs by Landlock LSM hooks). This item hardens the
layer and closes a composition defect; it does not fix a fail-open.**

The audit refuted the io_uring egress-bypass hypothesis: `cgroup/connect4` fires
from `->pre_connect` at the proto-op layer, which io_uring's `io_connect` also
traverses. The mount-API / bpf / kexec / module gaps are closed because the
workload is never uid-0-in-ns. Three pieces of debt remain.

**1. Assert uid-0-unreachable, don't proxy it with a syscall floor.** The
cap-gated set (mount API, bpf, kexec, module) is safe *because* bin-init drops
the workload to the masked non-zero operator uid before `execve` and
`deny_setuid`+`no_new_privs` (both already hard invariants in
`kennel-lib-policy::invariant`) prevent re-acquisition. The drop itself is
enforced by construction but not checked. Add a construction-time invariant:
the workload's effective uid in-ns is non-zero. This closes the entire cap-gated
set structurally and makes a seccomp floor over those syscalls redundant — which
is why W14 defines **no code-level seccomp invariant**.

**2. Additive-only seccomp deny composition.** `[seccomp] deny` is `or()`-folded
for the flag fields, but the deny *list* can be replaced by a leaf writing a
bare `deny = [...]`, silently dropping the base-confined hardening. Make the
list additive over the resolved base (a leaf may add, not remove), or warn on
narrowing — consistent with the `net.allow.add`/`exec.allow.add` increment
model. This is the one real defect; everything else here is hardening.

**3. Complete the base-confined denylist.** Not a floor — declared hardening in
`base-confined`, weakenable in principle but now protected by (2). Add the
families the audit found absent: `io_uring_{setup,enter,register}` (enforced
anyway; removes a complex unaudited surface), the new mount API (`fsopen`,
`fsconfig`, `fsmount`, `move_mount`, `open_tree`, `mount_setattr`), and
`open_by_handle_at`/`name_to_handle_at`. All cap-gated or otherwise closed
today; the deny makes intent match enforcement and defends against a future
uid-map or hook-placement regression. Keep the existing entries. See the audit's
disposition table.

**Out of scope:** io_uring egress *audit-record parity* (whether an
io_uring-issued connect emits the same egress event as the syscall path).
Enforcement is confirmed; audit parity is not investigated.

**Record the findings.** [`governance/audits/2026-07-seccomp-mediation.md`](audits/2026-07-seccomp-mediation.md)
landed with this workstream — the negative result (no bypass, and *why*) is the
durable artefact; a future kernel bump or uid-model change re-opens exactly the
questions it answers.

**Exit (met):** a settled policy whose workload would run uid-0-in-ns is rejected at
construction; `[seccomp] deny` cannot be narrowed by a leaf (added-to or warned);
`base-confined` denies the io_uring, new-mount-API, and handle-open families; the
audit record is committed; no code-level seccomp syscall invariant is introduced.

### W15 · Asymmetric `source` on fs grants: view path decoupled from host origin

**[quality] S. An optional `source` on `[[fs.read.add]]`/`[[fs.write.add]]` so a view path may be
backed by a different host path — per-workload credential/state redirection without reparenting the
whole home.**

Today the fs mapping is symmetric: the host inode at `path` appears at `path` in the view. `source`
breaks the symmetry deliberately for the case where an operator wants a view path served from an
operator-held per-workload store:

```
[[fs.read.add]]
path   = "~/.claude/.credentials.json"
source = "~/workloads/acme/claude-creds.json"
```

Granularity (single file vs whole dir) is the operator's choice; the mechanism is a bind with a
distinct source either way — a dir source reparents the subtree, a file source redirects one inode.

**Schema — two carriers, both additive.** In the source form, `source: Option<String>` on
[`PathEntry`](../../src/crates/kennel-lib-compile/src/source.rs) (`skip_serializing_if =
"Option::is_none"`), so entries without it keep their canonical form and every existing signature is
unchanged. `PathEntry.path` is `Vec<String>` (multi-path under one `reason`); `source` against N
paths has no coherent meaning, so **`source` present with `path.len() > 1` is a compile error** —
as is `source` on `remove` deltas or `fs.deny`. In the **settled** form there is no per-entry
struct to hang it on — `FsPolicy.read`/`write` are plain path lists
([`settled.rs`](../../src/crates/kennel-lib-policy/src/settled.rs)) — so the fold emits the
divergences into a new `redirect` list (`{ path, source }` pairs, omitted when empty). Both
additions are additive-optional: **re-pin the v3 shape, no `SETTLED_SCHEMA_VERSION` bump**, and
every existing settled artefact signs byte-identical.

**The floor — a cross-grant self-consistency check, not an ownership check.** Signing authenticates
the redirect's author, not its correctness: a maintainer-signed leaf whose `source` points at a
workload-writable path is a valid signature over a confused-deputy hole (workload writes the source,
reads it back at `path` as operator-provided content — the asserted-identity failure, one altitude
down). So:

- **At settle**, `source` must not be covered by any workload-writable surface in the resolved
  policy — the intersection runs against `fs.write` ∪ `fs.exclusive` ∪ `home_persist` (persist
  paths are host-side state the workload writes across runs). Intersecting is a compile error,
  decidable post-resolution, and lives in
  [`invariant::validate`](../../src/crates/kennel-lib-policy/src/invariant.rs) beside
  `deny_setuid`.
- **At spawn**, the one writable surface settle cannot see: the `[fs.cwd]` grant is a slot the
  invocation fills, so a host-side floor check refuses a run whose resolved cwd covers a redirect
  source — same altitude as the existing cwd floors (realpath-normalised, operator-owned,
  never-`$HOME`).
- `source` resolves host-side with `RESOLVE_NO_MAGICLINKS` (blocks procfs/sysfs magic-link escape;
  ordinary symlinks in an operator-owned path are permitted — credential stores are commonly
  symlink farms: stow/chezmoi/home-manager). The existing *writable-bind* guard
  ([`materialize_binds`](../../src/crates/kennel-lib-spawn/src/lib.rs) resolves writable sources
  with `RESOLVE_NO_SYMLINKS`) **keeps its stricter flag**: that asymmetry is the 0.4.0 F1
  writable-source symlink-swap residual, documented at the call site, and is not relaxed here. The
  inherited consequence: a redirected **RW** grant whose source path traverses a symlink is refused
  at materialisation.
- Normal home-relative (`~`) expansion applies; `source` is operator-authored like any grant.

**Materialisation is already built.** [`BindMount`](../../src/crates/kennel-lib-spawn/src/plan.rs)
carries separate `source`/`target`; today the planner sets them equal for fs grants, and a redirect
just sets them apart. Depth-sorted bind materialisation (grants sorted by path length) means a
redirected file grant inside an RO parent lands after the parent and overmounts it — the RO/RW
stack composes with no new mechanism. The write-set floor and an RO parent are orthogonal: a
redirected RO grant is fine; a redirected RW grant is fine iff its *source* is outside the write
set, which for a credential store the workload cannot write holds by construction.

**Audit — the provenance the symmetric case gave for free.** With symmetric mapping, a view path
*is* its origin; the audit account relies on that. A redirected grant must record `source → path`
wherever they diverge, or the account asserts a false origin. There is no per-bind runtime audit
event today; the divergence surfaces in the settled-policy account (`kennel policy audit` / the
diff surface) and in the spawn's error strings. Symmetric grants render exactly as before.

**Exit:** an fs grant may carry `source`; a divergent grant materialises the source inode at the
view path; `source` intersecting the resolved write set (`write` ∪ `exclusive` ∪ `home_persist`),
carrying `path.len() > 1`, resolving through a magic-link, or appearing on `remove`/`fs.deny` is a
compile error; a run whose resolved `[fs.cwd]` covers a redirect source is refused at spawn; the
policy account records `source → path` on divergence; the v3 shape is re-pinned (no bump); existing
symmetric policies and their signatures are byte-unchanged.

### W8 · Pre-ship adversarial pass on the new boundaries

**[security, ship-gate] S.**

0.6.0 creates boundaries and authorities that did not exist: the UDP facade predicate and flow broker
(hostile L3 and DNS wire parsed in operator context), the file-broker consent path (a host-side picker
delivering fds across the boundary), and the W11 invocation-cwd write grant (a signed slot the
invocation fills with a writable directory). The 0.5.0 precedent holds — no finding from a focused pass
is not proven safe — and none has been driven from the hostile seat. Drive each live:

- the **UDP facade and broker** with the four crafted-frame classes and DNS-wire fuzz — the §10.6
  fuzz targets land with their parsers in W2; this pass drives them further and from composed
  positions (facade and broker together);
- the **picker path** for consent bypass, fd-scope widening, and confused-deputy shapes (a kennel
  inducing a picker it should not reach);
- the **cwd-write grant** for floor escape — symlink/bind-mount races against the `RESOLVE_NO_SYMLINKS`
  resolution, marker spoofing, and any path to a `$HOME`-or-unowned target slipping past the floor;
- the **fs-redirect floor (W15, if landed by then)** for write-set escape — a redirect source
  reached through `[fs.cwd]`, `home_persist`, or a symlink/magic-link at resolution time; the
  confused-deputy shape (workload-authored content read back at `path` as operator-provided) driven
  live.

**Exit:** a dated `audits/` note covers each boundary above; every confirmed finding is fixed before
the tag.

(The parent-child relay boundary this pass was also to cover is gone with the withdrawn W1.)

### W9 · Corpus cutover: retire `docs/design` + `docs/architecture` in favour of the book

**[debt, structural] M. The parallel track, recorded; sequenced early because W2 writes its corpus
half into the book.**

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
  regenerated into `docs/archive/architecture/` by CI); the pointer to the authoritative policy schema
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
- **Repoint CI.** The inventory job regenerates into the new home (`docs/reference/`) instead of
  `docs/architecture/`; the threats guard follows `THREATS.md`; the schema job is untouched.
- **Then archive, don't delete.** `docs/design/` and `docs/architecture/` move to `docs/archive/` —
  a large body of work, preserved for reference rather than binned. The patch log becomes the
  as-built log (`docs/reference/AS-BUILT.md`); as-built is kept separate from the book, not ingested
  into it.

**Exit:** the book is the named corpus in the standing orders and README (URL + in-tree convention);
the reference home carries the canonical threat catalogue, the regenerated inventory/SLOC artefacts,
and the as-built log; the pre-book trees are moved to `docs/archive/` with nothing treating them as
the corpus; no source, governance, or CI reference is left dangling; CI is green with the inventory
and threats jobs on their new targets. (The website's deeper reconciliation is owed work, not part of
the cutover — a short pass repoints its corpus links to the book and the threat catalogue.)

## Sequencing

```
W0 (validation probes) ── S,  first: P4→W2-D (P1/P2/P3/P5 gated the withdrawn W1) ►
W9 (corpus cutover)    ── M,  early: before W2 writes its corpus half ────────────►
W1 (self-confinement)  ── WITHDRAWN → BACKLOG (seam not tidy; see the audit note) ►
W2 (UDP egress)        ── L,  A→B→C/D→E; the release's structural bet ────────────►
W3 (file broker)       ── M,  independent; lands before W4 ───────────────────────►
W4 (host-dbus retire)  ── M,  after W3 (its consumer is the evidence) ────────────►
W5 (raw-base64 removal)── XS, independent ────────────────────────────────────────►
W6 (enum validation)   ── S,  independent ────────────────────────────────────────►
W7 (gen-man)           ── S,  independent ────────────────────────────────────────►
W10 (retire subkennel) ── S–M, before/with W2's ULA addressing ───────────────────►
W11 (kennel run claude)── S,  additive fields re-pin v3 (no bump); adjacent to W2 ────►
W12 (persona hostname) ── XS–S, TENTATIVE — additive field, re-pin not bump; late/0.7 ►
W13 (bind exemption)   ── ephemeral :0 exemption SHIPPED (#175); ingress leg declined → BACKLOG ►
W14 (seccomp hardening)── S,  SHIPPED (#173); defence-in-depth hardening, no fail-open ►
W15 (fs source redirect)── S, independent; additive re-pin (no bump); before W8 ──────►
W8 (adversarial pass)  ── S,  after W2 + W3 + W11, ship gate ──────────────────────►
```

W0 opened the release and is cheap insurance on the work that remains; with W1 withdrawn, its live
consequence is P4 → W2 (the other probes are recorded for a future W1). W9 runs alongside it — the
cutover must land before W2 writes its corpus half, so that chapter is written once, in the book. W2
is the one long pole. W3 lands before W4 because the file broker is itself the brokered-D-Bus consumer
that W4's subsumption gate wants as evidence. W5–W7, W11, and W15 slot against capacity, with W15 landing before W8 so the pass can cover its
floor. 0.6.0 makes only **additive-optional** settled changes (W2
`[net.udp]`, W11 `allowed_args`/`[fs.cwd]`, W12 `hostname`, W15 `source`/`redirect`), so it
**re-pins the v3 shape** rather
than bumping `SETTLED_SCHEMA_VERSION`; W11/W12 are adjacent to W2, not coupled. W13 shipped as a pure
BPF change (the ephemeral-bind exemption, no schema); its `[net.bind.ingress]` grant was declined
(→ BACKLOG), so it adds no settled surface. W8 blocks the tag.

## Exit criteria

0.6.0 ships when:

- Every W0 probe has a recorded result and every red result has its named consequence applied (W0).
  (W1's probes are recorded for a future W1; P4 feeds W2.)
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
- kenneld starts with no `/etc/kennel/subkennel`; per-user loopback/bastion addressing derives from
  the uid; the file, the `alloc` module, and the refuse-to-start gate are gone; the installer no
  longer provisions it (W10).
- `kennel run claude -- <args>` runs from a marked project root on a stock install with no
  user-authored policy; an unmarked or floor-violating cwd refuses with a naming diagnostic; the
  `claude` endpoint set is confirmed by a live egress-audit pass; `allowed_args` and the `[fs] cwd`
  fields re-pin the v3 shape (no version bump); the quickstart claim ships with it (W11).
- The corpus cutover is complete: the book is the named corpus, the reference home carries the
  catalogue/inventory/as-built artefacts, the patch-log queue is drained, and the frozen trees are
  deleted with no dangling reference (W9).
- A port-0 (ephemeral) bind is exempt from the bind ACL in every mode, so W2's constrained
  `[net.udp]` round-trip completes on the unblocked source-port bind — **shipped (#175)**. The
  `[net.bind.ingress]` inbound leg (OAuth loopback callback) is **declined on principle** and moved
  to [BACKLOG.md](BACKLOG.md); W13's exit is the exemption alone (W13).
- The seccomp layer is hardened and its composition defect closed: a uid-0-in-ns workload is rejected
  at construction, `[seccomp] deny` cannot be narrowed by a leaf, `base-confined` denies the io_uring /
  new-mount-API / handle-open families, and the mediation audit record is committed — no code-level
  seccomp syscall invariant introduced (W14, shipped #173).
- An fs grant may carry `source`: the divergent grant materialises the source inode at the view
  path; a source inside the resolved write set (`write` ∪ `exclusive` ∪ `home_persist`), a
  multi-path entry, a magic-link resolution, or `source` on `remove`/`fs.deny` refuses at compile;
  a resolved `[fs.cwd]` covering a redirect source refuses at spawn; the policy account records
  `source → path` on divergence; the v3 shape is re-pinned (no bump) and existing signatures are
  byte-unchanged (W15).
- The adversarial pass covers the UDP facade/broker, the picker path, the W11 cwd-write grant, and
  the W15 redirect floor; every confirmed finding is fixed before the tag (W8, ship gate).

CHANGELOG records every stable-surface change — the `[net.udp]` section (v3 shape re-pinned, no version bump),
the portal FileChooser surface, the `host-dbus` retirement (or its recorded retention), the
raw-base64 removal, the four-field validation tightening, the threat-catalogue additions (+ version
bump), the man-page derivation, the retirement of `/etc/kennel/subkennel` (per-user disambiguation now
derived from the uid), the new `[workload] allowed_args` and `[fs] cwd` policy fields (v3 shape re-pinned) and the `claude` reference policy, the port-0 ephemeral-bind exemption (a QoL BPF change, no
schema surface — W13; the `[net.bind.ingress]` grant was declined, → BACKLOG), the seccomp hardening
(uid-0-in-ns construction refusal, additive-only `[seccomp] deny`, the completed base-confined
denylist — W14), the asymmetric `source` on fs grants and the settled `redirect` list (v3 shape
re-pinned — W15), and the corpus move to the book (with the reference-home
relocation of the catalogue and inventory artefacts).

## Parked work

Items with no timeline — declined-on-principle, promote-on-demand candidates, and work fenced to a
later release — live in [BACKLOG.md](BACKLOG.md), not here, so they are not carried from one roadmap
to the next.
