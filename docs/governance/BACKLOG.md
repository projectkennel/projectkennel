# Project Kennel — backlog / parking lot

Status: **standing** · Last touched: 2026-07-08

> The parking lot for work that is **not on any release roadmap** and should not be carried from one to
> the next. Three kinds live here: items **declined on principle** (mostly risk, little reward — re-open
> only if the named condition is met), **promote-on-demand candidates** (reuse that lands the moment a
> second consumer needs it), and work **fenced to a later release** (real, but not the next one). A
> roadmap names what a release commits to; this file holds what it deliberately does not, with the
> reasoning that stops each from being re-proposed every cycle. Moving an item onto a roadmap is the
> only thing that takes it out of here.

## Backlog — stays out, for a reason

These are not deferred-for-capacity; they are **declined on the do-less principle** — mostly risk,
little reward. They move onto a roadmap only if the specific condition named is met.

- **MCP interposer — declined as a first-party build.** A first-party interposer that inspects
  `tools/call` re-imports the exact JSON-RPC-parsing burden the spawn design deliberately kept out of
  the daemon (§7.12.5) — relocated into a kennel Kennel now writes and maintains, new adversarial-input
  parsing surface, to mediate a protocol the system chose not to understand. That violates *how can I
  do less*. **The only version that survives the principle is one Kennel does not write**: an *existing*
  MCP proxy/filter, dropped into a confined service kennel the way `oci-fetch` drops in `skopeo`/`umoci` —
  their code, their maintenance, Kennel only brokers it. Promote **only** if such a tool exists and is sound; until
  then the seam stays at the operator and R2 (delegated composition) remains accepted-and-tagged. No
  first-party interposer is built. Adjacent but distinct (deferred by 0.6.0 W11): **MCP-server
  confinement** — an MCP server is an *endpoint the agent dials*, not an agent binary, so its
  confinement shape is a standing service kennel offering the endpoint over the mesh (the existing
  provides/consumes model as-is, no new mechanism and no protocol parsing). Promote when a concrete
  MCP server wants confining; it needs a policy, not a workstream.

- **First-party OCI unpacker — stays backlogged, do not promote.** The security argument for
  first-party (unpacking is adversarial-input parsing) is **already met by confinement**: `skopeo`+`umoci`
  run inside the signed `oci-fetch@v1` view, at workload authority, never in the daemon. Writing a
  first-party static unpacker buys only dropping the `umoci` dependency and a host-prereq convenience —
  marginal, against the cost of maintaining a bespoke adversarial-input image parser. Mostly risk, little
  reward; violates do-less. The `umoci`-confined path is the shipped state, not interim. Do not let this
  drift up into a release body.

- **OCI integrity ladder (fs-verity) + per-inode closure walk — backlog, TCB cost.**
  **Declined as a release item because it grows the TCB** (fs-verity verification
  machinery, the per-inode walk) for marginal value over the digest-pinned floor — which already
  verifies image content at the trust boundary on a RO-mounted rootfs. The residual it closes (offline
  tampering of the *cached* unpacked rootfs by a separate local attacker) is narrow, and buying it with
  trusted-core growth is the exact trade the project refuses. The digest-pinned floor is the minimum and
  it holds; revisit only if that residual ever becomes load-bearing for a real deployment.

- **Secrets broker / any attestation service — declined on principle, not held.** This is the
  ssh-vs-gpg call one level up. A secrets broker does not provide a *capability a workload uses*; it
  provides *trust material it must vouch for* — "here is the credential, it is the right one" is an
  **attestation**, and an attestation's worth derives entirely from the trust of its origin. The mesh's
  origins are confined-and-untrusted by definition, so a peer kennel attesting anything is incoherent: a
  trust claim with no trust behind it. Delegating to a keyring/TPM/vault does not rescue it — it
  relocates the attestation to "I am authorised to retrieve this on behalf of that workload," which is
  the broker vouching for authority it cannot be trusted to vouch for. A secrets broker is a **trust
  root wearing a service kennel's clothes**, and a trust root inside the confinement boundary is the
  category error the project exists to refuse. Secrets belong **outside** the boundary: the operator
  constructs a kennel *with* the credential as a signed, declared construction parameter (authentication-
  shaped — the kennel *has* what it needs), never *provided to it by a peer at runtime* (attestation-
  shaped — a peer vouching). Not backlogged pending a better design; **declined**, and the general rule
  is now a standing constraint ([[authentication-never-attestation]], design §4.3) and the subject of a
documentation sweep.
- **`[net.bind.ingress]` — the OAuth loopback-callback ingress leg — declined on principle.** W13
  shipped its generic half (the port-0 ephemeral-bind exemption, #175, which unblocked W2's outbound
  dial); this is the inbound remainder it did **not** build. The motivating receipt is `kennel run
  claude` on a host with no seeded token: the RFC 8252 native-app flow binds an ephemeral loopback
  listener and advertises `localhost:<port>` to a host browser, and the design would make that
  reachable — a policy-declared `[net.bind.ingress]` block of ephemeral loopback ports, allocated by
  **inverting host-inetd's** bind-and-hold (`allocate { addr, count }` → it binds `127.0.0.1:0` × N,
  reads the real ports via `getsockname()`, keeps those very sockets as the serving listeners),
  steered into by a `bind4`/`bind6` rewrite of `:0` to the next block port (port identity preserved
  1:1 across the boundary, or the advertised redirect URI breaks), and forwarded inbound over a
  binder connector — the mirror of host-netproxy's egress leg. The full spec is recoverable from this
  paragraph and the ROADMAP-0.6.0 history. **Why declined, not deferred:** completing the OAuth flow
  *inside* the boundary has the confined workload end up holding a fresh **user-equivalent bearer
  token** — credential *creation* moved across the confinement boundary, the inverse of the
  ssh-bastion shape (which re-originates a *host-held* credential with the destination bound and never
  holds the key). The operator's browser approval is a single consent, but the artifact is durable
  operator-equivalent authority in untrusted hands — the wrong side of
  [[authentication-never-attestation]] (design §4.3): not *using* a bounded capability, but *minting*
  operator-equivalent authentication. **Standing answer:** host-seeded tokens — the operator does the
  OAuth on the host and seeds the token in as a signed, declared construction parameter
  (authentication-shaped: the kennel *has* what it needs), never mints it at runtime inside the
  boundary. **Re-open only if** the operator-consent step is shown to change the calculus — i.e. that
  a single human-approved login does not amount to creating the user-equivalent authentication the
  axiom forbids. The port-0 exemption W13 shipped stands on its own; it needed no ingress table.

- **The interactive file broker — the per-file portal FileChooser fd grant — declined as too much
  plumbing for too little, and subsumed.** The confined-GUI residual (§7.14.7, was 0.6.0 W3): a
  confined app touches only its pre-granted paths, so "open a file the policy did not anticipate"
  means editing policy. The proposed shape routed `org.freedesktop.portal.FileChooser` over the
  existing D-Bus facade to a host-side operator-context picker, delivering **one fd** into the view
  (the §4.3 fd-broker shape). The D-Bus refactor (W4) made the *request* path nearly free — the
  filter already understands `org.freedesktop.portal.*` and the broker holds the real bus — but the
  **result** path is where the cost lives, and it is not small. `xdg-desktop-portal` decides
  sandbox-ness from the *caller's* credentials, and on the real bus the caller is the unsandboxed
  broker, so FileChooser returns a `file://` **URI**, not an fd; an unmodified GTK/Qt client then
  `open()`s that path — outside the sealed view. Making an *unmodified* app consume the result
  therefore forces a materialisation layer (URI rewriting + a post-seal view-mutation verb on
  `kennel-bin-init` to bind the received fd under a pre-granted docs dir, plus per-request async
  Response-signal tracking) — the flatpak documents-FUSE nightmare in miniature, and it turns the
  D-Bus mediation from a pure filter into an active reply-body-rewriting participant. Dropping
  "unmodified app" collapses it to a small kennel-aware fd verb (`kennel grant <kennel> <file>`:
  operator-context `open()`, fd over the mesh, SCM_RIGHTS to the app) — real, but **niche** given
  `[fs.cwd]` (W11) and the W15 `source` redirects already cover the anticipated-file cases, and
  **subsumed** by the honest alternative: an `xdg-desktop-portal` *inside* the kennel's own private
  session (the `gui-session` bus), which consents within the kennel's world with no host reach-through
  and no fd-broker at all. **Why declined, not deferred:** the fd *transport* was never the hard part
  (binder carries `BINDER_TYPE_FD` today); the hard part is the unmodified-client contract mismatch,
  and the capability the mismatch buys is already covered from two directions. The GUI investment for
  0.6.0 goes into the display stack that exists (W3 recast — default configs + the session runtime),
  not a bespoke consent path. **Re-open only if** a concrete workload needs interactive per-file
  access that neither `[fs.cwd]`/`source` nor an in-session portal can serve — at which point the
  small kennel-aware fd verb is the shape, and the unmodified-app URI-materialisation face stays out.

## Candidate (promote-if-needed, not a workstream)

- **Cross-instance binder reach — a kennel offering a rich binder interface to other kennels.** The mesh's
  `binder-connector` shape (§7.13.2) is defined and the cross-instance mechanism is designed (§7.1.6,
  designed-not-built per 08-as-built §8.1), but no provider offers a binder node over the mesh today:
  agent↔tool composition is dynamic spawn with a minted stdio channel (§7.12), not a standing binder service.
  Promote when a standing service genuinely needs to publish a binder interface cross-kennel; until then
  `af-unix` and `dbus-name` are the shapes with consumers.

- **Generalise policy-pinned-to-bundled-binaries.** A reusable service-kennel build mechanism for the
  moment a binary-bundling service kennel needs it. *(It lost its first presumed consumer: confined GUI no
  longer bundles version-pinned Flatpak proxy/portal binaries — the nested compositor runs unmodified, with
  no version-pin-to-mimicry premise. So this reverts to a clean promote-if-needed candidate with no current
  consumer.)* Reuse, not new surface; promote on demand, no scheduled work.

- **`wl-proxy`-based render-leg filtering proxy — RETIRED, superseded (not promotable).** Briefly considered
  as the compositor-independent fallback for hosts without `security-context-v1` (notably GNOME, which W0
  verified lacks it through Mutter 50.1). Superseded outright by W7's **per-kennel nested inner compositor**,
  which is host-independent (proven on stock GNOME), construction-by-absence rather than data-path filtering,
  and carries **no Kennel-authored Wayland parser** — strictly better on every axis the proxy was meant to
  buy. Recorded here only so the idea is not re-proposed: the nested compositor *is* the cross-host render
  mechanism; there is no filtering-proxy fallback to build.

- **A transparent TCP slow-lane on the tun path (the raw-TCP sibling of `[net.udp]`).** Carried from
  the retired 0.6.0 roadmap (W2's named generalisation). Extending the tun capture to TCP gives
  non-proxy-aware **raw TCP** clients a transparent egress at userspace-L3 (per-frame memcpy) cost.
  It coexists **permanently** with `net.proxy`, which stays the fast lane — the CONNECT conduit
  splices kernel-to-kernel for proxy-aware bulk TCP. Two lanes in one kennel: the proxy on loopback,
  the tun owning the synthetic pool, selected by whether the client honours the proxy or dials a
  resolved synthetic raw (the same DNS shim feeds both). Additive; touches `net.proxy` nothing.
  Promote when a real workload needs raw-TCP egress that cannot honour a proxy.

- **Relocating `net.proxy`'s broker decision into a provider kennel.** Carried from the retired
  0.6.0 roadmap (W2's second named generalisation). Lifting the binder/afunix conversation + the
  INet decision out of kenneld into a mesh provider kennel (the `dbus-broker@v1` pattern) moves the
  inet + cross-ns-binder host-effects off the daemon's per-flow path **while preserving the splice
  datapath and the proven resolve-check-pin enforcement**. Only a move of the *decision* (not just
  the plumbing) evicts inet. Doubly motivated: it is also a concrete step toward the kenneld
  self-confinement prerequisite (the host-effects factoring named in the fenced self-confinement
  entry below) — the lower-risk, direct line at that seam. Orthogonal to the TCP slow-lane. Promote with the
  self-confinement factoring, or on its own when a hardening pass is scheduled.

## Fenced to a later release

- **kenneld self-confinement — the monitor inside its own box (was 0.6.0 W1; withdrawn 2026-07-02).**
  Seal kenneld inside its own `[fs]`/`[net]`/`[exec]` confinement so a kennel breakout into the daemon
  is *bounded*, not total. The 0.6.0 attempt (an unsealed relay + a sealed monitor split at a startup
  fork) was withdrawn: the seam is drawn through code not factored for it. kenneld's host-facing
  effects — exec (`sha256sum`, the netproxy/inetd/dbus delegates, the ssh bastion), inet resolution,
  and cross-mount-namespace binder opens — are interleaved through construction and runtime brokering,
  so the confinement boundary hits them one at a time and the relay protocol grows without converging;
  seccomp's inheritance across `execve` additionally forces every inet-needing delegate onto the
  unsealed side, which a bounded-allowlist seal cannot accommodate. **Promote only after the named
  prerequisite: factor *all* host-facing effects behind one narrow interface** (a `HostEffects` seam —
  resolve, exec-delegate + lifecycle, open-cross-ns, run-to-completion), after which the seal is
  mechanical (sealed side = logic + an effects-client; unsealed side = the one effects-impl). The full
  analysis, and what W0's probes settled (still valid), is in
  [`audits/2026-07-02-w1-self-confinement-seam.md`](audits/2026-07-02-w1-self-confinement-seam.md).
  Even complete, the sealed monitor retains authority to *drive* the effects side, so the
  "bounded compromise" claim is real but wide — weigh that against the factoring cost before promoting.
- **Kenneld restart-fork resolution — kennels that survive a daemon restart.** A kenneld restart
  today ends every running kennel: each kennel's serving thread lives in the daemon process, so
  detach survives a *client* leaving, not kenneld leaving
  (`docs/archive/architecture/05-state-and-supervision.md`). Every daemon upgrade or reinstall is therefore
  a fleet-wide workload restart. The fix is structural — the serving relationship must be
  re-adoptable across a daemon generation (state handoff or re-attach, never authored daemon state
  that contradicts repo-is-truth). Named as a 0.6.0-horizon item by the 0.5.0 roadmap; not taken for
  0.6.0 (the release's structural bet is kenneld self-confinement, and reshaping the process
  lifecycle *while* sealing it is two structural changes to one process in one release). Promote
  when an availability-focused release schedules it — after the sealed-daemon shape has settled,
  since adoption must be designed against the sealed topology, not the monolith.
- **Global spawn-storm accounting.** Per-spawn resource ceilings exist (each dynamic spawn carries
  its own cgroup limits, §7.12); there is no *aggregate* — N spawned kennels are N × ceiling, and
  nothing accounts for the sum. A spraying parent saturates the host by fan-out rather than by any
  single kennel. Bounded work: a per-operator (or per-parent-kennel) aggregate budget enforced at
  spawn admission. Promote when an availability/hardening pass is scheduled; pairs naturally with
  the restart-fork item above.
- **Multi-operator delegation — design-gated, do not schedule build work.** The keys model
  deliberately leaves the delegation question open: a trust tier can carry many signers, but who may
  add a key to a place and how holders are scoped against one another is unsettled (the keys
  chapter records it as open). There is nothing buildable until the design track answers that;
  promote only after the book settles the delegation model.
- **First-party MASQUE/`connect-udp` endpoint.** If the ecosystem brings UDP to the existing
  CONNECT chokepoint, proxy-aware clients get UDP through the already-brokered path and the 0.6.0
  tun/broker path serves only proxy-oblivious stacks. That would be a later, cheaper workstream —
  recorded so the 0.6.0 UDP workstream is not read as preempting it. Promote if/when MASQUE support
  in mainstream client stacks makes the chokepoint real.
- **Fine-grained service-method policy** — `[consumes]` at interface/method granularity (FileChooser
  yes, Camera no) rather than coarse service-name reachability. Ships coarse first; finer policy must
  not drag a protocol-body parser into a broker.
- **Sidecar dependency graphs** — if flat consume-with-wait proves insufficient and explicit
  inter-sidecar ordering is genuinely needed (it should not be).
- **macOS service mesh** — the port's Mach-port analogue of the connector broker; tracked, not scheduled.
- **README + website positioning rewrite — the lead-framing pass.** The accuracy reconciliation shipped
  (every public claim true against the as-built tree); what remains is the deliberate rewrite of the *lead
  framing* so the reference-monitor model, deny-by-default, construction-by-absence, and "full per-task
  isolation made cheap enough to be disposable" are legible to a reader who feels the agent-isolation pain.
  Where not stale the material is accurate-but-flat — technically true, strategically mute. The governing
  invariant carries: **never overclaim** (a first-class defect equal to a security bug) — precise
  description is the strong pitch, residuals named not hidden (T1.6, the GUI AF_UNIX leg, R2 delegated
  composition, the host-mode caveats). Deliberately **not a release gate**: positioning copy cannot be
  "done" the way a passing corpus is, and gating a release on prose is process theatre. Promote when a
  positioning pass is scheduled.
- **Small designed-but-unbuilt pieces (parked from the old `08-as-built-notes` roadmap).** Each is a
  convenience or a low-level hardening with a working path today — recorded so they are neither
  re-proposed nor lost, none blocking a release: the `[env].template` / `[fs.home].template` file-seed
  (design §7.9.2a — the inline `[env].set` + built-in dotfile defaults cover it); the `[unix]`
  `--dry-run` shim output (§7.6 — `kennel inspect --unix` shipped in 0.5.0; the dry-run half did not);
  the removed-from-schema `fs.scrub` / `fs.home.sanitise` design (§7.4.5 — revive only on a concrete need);
  and the **rendezvous-ownership incumbency tiebreak** (§7.13.4b — a `Ready` owner keeps the slot over an
  equal newcomer across `daemon-reload`; the default stable-resolution order is correct without it).
