# Project Kennel — backlog / parking lot

Status: **standing** · Last touched: 2026-06-25

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
  first-party interposer is built.

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

## Fenced to a later release

- **Minimal view floor — tighten the default host-rootfs visibility (`/usr`, `/var`).** The base templates
  grant `fs.read = ["/usr/**", "/bin/**", "/lib/**", "/lib64/**"]`, so every constructed view sees the
  *entire* `/usr` (incl. `/usr/share`, `/usr/src`, `/usr/local`) — more host rootfs than a confined workload
  needs. The principle is the one the W10 `/usr/libexec/kennel` blacklist is a single concrete instance of:
  **a view should see the minimum host rootfs it needs, not a blanket subtree** (the read-side of
  construction-by-absence, §4.2). The reason it is fenced rather than a quick edit: curating `/usr` is
  breakage-prone — `terminfo`, `ca-certificates`, locale/`gconv` data live under `/usr/share`, the loader and
  lib closure under `/usr/lib*` — so the floor must be **derived from what workloads actually resolve at
  runtime** (measure-then-narrow), or it ships a default that mysteriously breaks TLS or the terminal. Pin it
  as a design-corpus *principle* (the minimal-view floor, beside §4.2) + the *concrete floor* in the base
  templates' fs grants + a *threat* entry (host-rootfs info-leak into views). **Out of 0.4.0** — a deliberate
  later-release item, not a near-term follow-on: 0.4.0's down-payment on the principle is the W10
  `/usr/libexec/kennel` blacklist (built), and the full floor-tightening is a measure-then-narrow exercise
  that earns its own release slot rather than riding the service-mesh release. Promote onto a roadmap when
  that release schedules it.
- **Interactive file broker (confined GUI's §7.14.7 residual) — fenced post-0.4.0, behind a D-Bus-broker
  re-evaluation.** The confined-GUI render/display leg shipped (#99); the one committed residual is the
  Kennel-native file broker — a host-side transient picker the user consents through, delivering one fd into
  the workload's view (§4.3 fd-broker, no portal). It is fenced not for capacity but because its **app-facing
  interface is unsettled and couples to a deliberate re-evaluation now that service kennels exist**: an
  unmodified GTK/Qt app reaches a file chooser only through the `org.freedesktop.portal.FileChooser` D-Bus
  interface, which §7.14 cuts — so the broker's app-facing surface is entangled with **where the D-Bus broker
  itself (the `org.projectkennel.IDBus` facade, §7.7) should live now that the GUI service kennel exists**:
  whether the D-Bus mediation belongs in daemon/host-facade surface or in a signed service kennel of its own,
  and how a FileChooser-shaped request rides that home. Settle the D-Bus-broker home first; the file broker
  follows whatever that decides. Promote when that re-evaluation lands and the app-facing interface is chosen
  (the coarse open/save-one-file floor first; the fine-grained per-method policy below is a further increment
  on top). Until then a confined GUI app touches only its pre-granted paths — a real limit, recorded, not
  rushed into the tag.
- **Mesh connector handoff: dbus-name + binder-connector shapes** — the `[[provides]]`/`[[consumes]]`
  schema types three transports (`af-unix` / `dbus-name` / `binder-connector`), and 0.4.0 brokers only
  the **af-unix** handoff — the critical shape (confined GUI rides a Wayland af-unix socket) and the one
  that reuses the existing `CONNECT_AFUNIX` facade byte-identically. The other two are schema-accepted but
  broker-refused until built; promote when a real consumer needs a brokered D-Bus name or a binder
  connector node-handle. Not a 0.4.0 gap — a later increment on a frozen schema.
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
- **Live-topology surface — the consumer side (who-consumes-what).** The mesh topology view projects
  who-*provides*-what (readiness / shape / enablement / tier / pid); the consumer half — each running
  kennel's `[[consumes]]` — is loaded into its `KennelData` but not held in the registry, so surfacing it
  needs a `KennelMeta` field set in `run_kennel`. Deferred to keep the increment off the construction hot
  path. Promote when the demand side is wanted: a flaked dependency is already visible provider-side
  (`failed` readiness), this completes the picture with who-reaches-for-what.
- **Cross-kennel red-team — the two dynamic-pass residuals.** The static red-team closed safe-with-fixes;
  two residuals were recorded for a later *dynamic* (runtime) pass — the connector-broker resolution race
  and the GUI confidentiality legs — neither blocking the tag. They are written up in
  [`audits/2026-06-24-cross-kennel-redteam.md`](audits/2026-06-24-cross-kennel-redteam.md); promote when a
  dynamic red-team is scheduled.
- **Writable-bind SOURCE symlink guard (`persist`-gated).** A writable bind's *source* resolution follows
  symlinks; the fix is an **anchored** runtime guard — `openat2 RESOLVE_NO_SYMLINKS` past the shallowest
  writable ancestor, then bind `/proc/self/fd/N` (no new `unsafe`). It is narrow: gated behind
  `[fs.home].persist` (a writable home is ephemeral by default), so the exposure exists only for an opt-in
  persistent writable home. The BPF-DoS half of the original finding is already solid — do **not** add
  eviction. Maintainer-deferred; promote when the `persist` exposure is taken on.
- **Small designed-but-unbuilt pieces (parked from the old `08-as-built-notes` roadmap).** Each is a
  convenience or a low-level hardening with a working path today — recorded so they are neither
  re-proposed nor lost, none blocking a release: the `[env].template` / `[fs.home].template` file-seed
  (design §7.9.2a — the inline `[env].set` + built-in dotfile defaults cover it); the `[unix]`
  deferred bits (§7.6 — the ABI-gated `abstract = "allow"` escape hatch and the
  `--dry-run`/`inspect` shim output); `kennel_meta` BPF-map **read-only sealing + `magic`/`abi` readback**
  (`02-7-bpf-abi.md` — written once by loader convention, not yet frozen with `BPF_F_RDONLY_PROG`); and
  the removed-from-schema `fs.scrub` / `fs.home.sanitise` design (§7.4.5 — revive only on a concrete need);
  and the **rendezvous-ownership incumbency tiebreak** (§7.13.4b — a `Ready` owner keeps the slot over an
  equal newcomer across `daemon-reload`; the default stable-resolution order is correct without it).
