# W9 — enforcement-point ship-gate pass (0.7.0)

Status: **complete** · Date: 2026-07-10 · Gates: the 0.7.0 tag

The 0.7.0 release adds operator-UX ceremonies — `run` narrowing, the `policy`/`template`/`key`
houses, `clone`/`install`, the v5 composition rule. W9 verifies the standing property that **none
of them is an enforcement point**: every new verb operates at the authority its invoker already
holds, and confinement integrity stays with the authoritative gates — kenneld's signature
verification, the compiler's `reserved_authority`, the framework-invariant re-assertion, and
filesystem permission on the tier directories. Each surface was bypassed by hand and the gate
behind it checked.

One load-bearing courtesy was found and fixed (finding W9-F1); everything else holds.

## Bypass results

### B1 — the run-verify gate (W1) · **HOLDS**

`run` narrows to a settled name in the three repos. Bypassing the CLI resolution by placing
artefacts directly in a repo:

- **Tampered signed artefact** (flip a grant after signing) → daemon refuses `signature: signature
  did not verify`, *after* the CLI's courtesy `running` line — the daemon gate is authoritative.
- **Unsigned artefact** (`algorithm = "none"`) placed directly → daemon refuses `unsupported
  signature algorithm none (only ed25519)`.
- **Source policy at the settled path** → caught by the CLI courtesy (`is a source policy`); the
  daemon behind it is the same verify path that killed the tampered/unsigned artefacts after they
  passed the courtesy `running` line, so the courtesy is not load-bearing.

### B2 — the reserved-namespace authority gate (W3) · **FINDING W9-F1 (fixed)**

The reserved gate (§7.13.5) is meant to be compile-time-sole: only a vendor (maintainer) key may
sign a `[[provides]] org.projectkennel.*`, a host key a host `[[reserved]]` family. Bypassing the
`install`/`clone` CLI courtesy by using `kennel policy compile` directly:

- A **user key** compiled and signed a leaf claiming `org.projectkennel.evil` — **no refusal**.
- Enabled at the user tier (`~/.config/kennel/ondemand`, user-writable) and `daemon-reload`ed, the
  daemon **catalogued** the forged reserved capability (`org.projectkennel.w9forge … user`).

The gate was enforced by **nothing** on the compile path. `install`/`clone` carry the only check
(a courtesy pre-flight), and W1 made `compile` the primary dev path that bypasses it. The daemon
does not re-check (compile-time-sole by design). A user could forge a vendor-reserved capability
and have their own confined workloads — e.g. the shipped `claude` policy consuming
`org.projectkennel.wayland` — connect to an impostor rather than the vendor broker.

**Root cause.** For a leaf's *own* (entry-origin) reserved provide, the gate's declaring tier comes
from `Trust::signing_tier()` — the tier of the key that will sign the output. The mechanism was
fully built (`Trust::with_signing_key`, `signing_tier`, the `signing_key` field documented for
exactly this case), but the compile CLI **never set it**, so `signing_tier()` was always `None`,
`enforce` was always `false` for entry-origin, and the gate was off.

**Severity.** Medium. The immediate blast radius is self-contained — the mesh is per-user, so a
forged name serves only the forger's own consumers, and the user is their own trust root. But it
breaks the reserved-namespace integrity guarantee (`org.projectkennel.*` = maintainer authority)
within the user's domain: a confined workload trusting a vendor-reserved service could be
transparently MITM'd. No cross-user or cross-tier escalation (host enablement needs root).

**Fix (enforcement moved down, per the W9 rule).** The compile CLI now resolves the `--key`'s
trust-store key-id before compiling (`resolve_signing_key_id`, deriving the public half via
`ssh-keygen -y` and matching the trust dirs) and wires it into the trust context
(`TrustContext::with_signing_key_id` → `Trust::with_signing_key`). The compiler's own
`reserved_authority` gate then enforces the entry-origin provide against the signing key's tier —
the `install`/`clone` courtesies become belt-and-braces over the real gate. `--unsigned` leaves it
`None` (the artefact will not verify at spawn, so an unenforced reserved claim on it is inert).

Verified after the fix: a user key claiming `org.projectkennel.*` is **refused at compile**
(`is a reserved capability name … needs a vendor (maintainer) template`); a vendor key is allowed;
a user key claiming an unreserved name is allowed; the shipped brokers (whose reserved provide is
*ancestor-origin*, inherited from a maintainer-signed template) compile unchanged. Guarded by the
new unit test `entry_origin_reserved_provide_is_gated_by_the_signing_key_tier`.

### B3 — tier filesystem permission (W3/W4) · **HOLDS**

`install --host` and `key trust`/`untrust` route to `/etc/kennel/*` and need root. Bypassing the
CLI by writing directly as a non-root user: `/etc/kennel/policies` and `/etc/kennel/keys` are
root-owned `0755`, so the writes fail `Permission denied`. The OS is the authoritative gate; the
CLI's root check is a courtesy over it.

### B4 — the v5 composition floors (W6) · **HOLDS**

- **Bare-set clobber of a deny floor**: a leaf setting `exec.deny = []` and `seccomp.deny = []` to
  drop base-confined's floor — the union-fold keeps the inherited denies; the settled artefact
  carries base-confined's 6 seccomp denies unchanged. The floor is not a leaf's to weaken.
- **Invariant re-assertion**: `verify_doc` runs `invariant::validate` *after* `verify_signature`,
  so even a validly-signed policy is re-checked (the mandatory cloud-metadata deny, the `deny_*`
  flags, `no_new_privs`). A hand-stripped mandatory deny fails the signature check first (B1); a
  re-signed strip is caught by the invariant re-assertion (unit-tested in `invariant.rs`).

### B5 — the delta-over-absent silent-drop (W10 finding) · **LATENT-ONLY**

The compiler footgun recorded in [BACKLOG.md](../BACKLOG.md) — a `.add` delta over a section the
whole chain lacks resolves to empty — relies on the delta form over an absent parent section. Every
`net.udp` grant in the shipped corpus and the suite uses the bare `[[net.udp.allow]]` **Set** form
(compose emits Set for exactly this reason), so **no shipped path relies on the shape**. It stays a
recorded backlog item for a focused compiler cycle, not a 0.7.0 blocker.

## Exit

Every new 0.7.0 surface has a recorded bypass check confirming the authoritative gate behind it.
The one load-bearing courtesy found (W9-F1, the reserved gate off at `kennel policy compile`) is
fixed by moving enforcement down to the compiler, with a regression test. The v5 composition rule
holds at the compiler, not at a CLI nicety. The tag is unblocked.
