# Project Kennel — backlog / parking lot

Status: **standing** · Last touched: 2026-06-22

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

- **Fine-grained service-method policy** — `[consumes]` at interface/method granularity (FileChooser
  yes, Camera no) rather than coarse service-name reachability. Ships coarse first; finer policy must
  not drag a protocol-body parser into a broker.
- **Sidecar dependency graphs** — if flat consume-with-wait proves insufficient and explicit
  inter-sidecar ordering is genuinely needed (it should not be).
- **macOS service mesh** — the port's Mach-port analogue of the connector broker; tracked, not scheduled.
