# Design / Architecture patch log

`docs/design/**` and `docs/architecture/**` are **frozen** pending a clean-sheet rewrite
(the two-volume book). While the freeze is in effect, do not edit those trees. Any change
that would normally land as an as-built update to a design or architecture chapter is
recorded here instead, to be ingested into the rewrite.

Each entry: the **target** (chapter / §, best guess — the rewrite may restructure), the
**as-built fact** the docs should reflect (or the stale claim to drop), the **why**, and the
**source** (PR / commit). Newest first.

---

<!-- Template:
## YYYY-MM-DD — <short title>
- **Target:** docs/<design|architecture>/<chapter>.md §<x> (approx)
- **Change:** <what is now true as-built / what is stale and should be dropped>
- **Why:** <one line>
- **Source:** #<PR> / <commit>
-->

## 2026-06-28 — Signature format → SSHSIG (OpenSSH detached signatures)

- **Target:** book ch16.3 (Audits — the commitment); the settled-policy chapter (the
  user's §17.1, "signature over the canonical serialisation"); the keys chapter (the user's
  §18). In the frozen trees: docs/architecture/02-2-config-schema.md (§Signatures),
  docs/design/05-templates.md (§5.10 trust store), docs/architecture/04-trust-boundaries.md,
  docs/architecture/02-10-dynamic-spawn.md (the spawn content-pin).
- **Change (as-built to capture in the rewrite):**
  - **The on-disk signature is now an SSHSIG** (OpenSSH detached signature, `PROTOCOL.sshsig`),
    not a bare Ed25519 signature over the canonical bytes. The `[signature]` envelope's
    `algorithm` is `"sshsig"`; `signature` holds the armored `-----BEGIN SSH SIGNATURE-----`
    blob verbatim. Authoring signs via **`ssh-keygen -Y sign`** (so a key in a file, an
    ssh-agent, or a hardware token are all transparent — the framework writes no agent client).
  - **Verification is in-process** for Ed25519 keys (`kennel_lib_policy::sshsig`): de-armor →
    check the namespace → require the embedded key to equal the trust-store key → recompute
    `SHA-512(canonical)` → rebuild the SSHSIG preimage → one Ed25519 check. It never execs
    `ssh-keygen` (the trust root stays self-contained, `refuse-to-start`/`rule-of-1`). A real
    settled policy passes **both** `ssh-keygen -Y verify` and the in-process verifier — a
    cross-check test asserts it (`tests/sshsig_crosscheck.rs`).
  - **Domain separation:** the SSHSIG `namespace` is `policy.v1@projectkennel.org`. A signature
    minted for SSH authentication or git commits carries a different namespace and cannot be
    replayed as a kennel-policy signature, even with the same key — which matters now that an
    operator may sign with their ordinary SSH key.
  - **The commitment changed (ch16.3 — drop the "no sha2" line).** It was "the signature *is*
    the content commitment, no hashing." It is now "we pin the SSHSIG; it commits to
    `SHA-512(canonical)`." Still deterministic (Ed25519, RFC 8032) and collision-bound, one
    layer deeper. **SHA-512 is load-bearing in the commitment** (it was incidental inside
    Ed25519 before). The lockfile/spawn content-pin is unchanged in *role* — it still pins the
    `[signature]` string; that string is now the armor.
  - **Schema bump:** `settled_schema_version` is **2**. A v1 (pre-SSHSIG) settled policy is
    refused with `ObsoleteSchemaVersion` whose fix is "recompile" — single-format, no permanent
    dual verifier in the hot path. The shipped template/fragment corpus (28 files) was re-signed
    SSHSIG in the same change.
  - **Trust model UNCHANGED:** the three-tier store and precedence, the set of signed artefacts,
    compile-time ancestor verification against the system-only tiers, and the daemon's SPAWN
    re-verification of the content-pin all hold — only *what a "signature" is, byte-for-byte*,
    changed at each existing checkpoint. The key chapter (§18) gains one sentence: signatures are
    now SSH-verifiable, not merely SSH-shaped keys.
  - **New dependency:** `hmac-sha512` 1.1.12 (bare unkeyed SHA-512, `default-features = false`,
    zero transitive deps, same author as `ed25519-compact`). The SHA-512 inside `ed25519-compact`
    is private; exposing it would be a forbidden feature-add patch (`src/vendor/patches/README.md`)
    and would break that crate's byte-identical-to-upstream provenance, so a dedicated crate is the
    policy-conformant choice. Recorded in CHECKSUMS.toml / DEPENDENCIES.md / cargo-vet.
- **OWED (designed, not yet landed):**
  - **FIDO `sk-` signers** verify via an `ssh-keygen -Y verify` breakout (fixed argv, an
    allowed-signers file built from the **trust store** never the artefact, construction-path
    only, never a fallback after a failed in-process check). The verifier already detects `sk-`
    keys structurally and returns `HardwareKeyRequiresExternalVerify`; signing rejects `sk-` with a
    clear message. The breakout itself, the trust-store `sk-` entry shape (application string +
    authenticator flags alongside the 32 bytes), and `kennel policy risks` surfacing
    "signer is a hardware token" are owed.
- **THREATS (owed catalogue line):** the signature format is security-load-bearing; the SSHSIG
  namespace is the control that prevents cross-protocol signature reuse once an operator's SSH key
  doubles as their policy-signing key. A `T*` id for "cross-protocol signature reuse — mitigated by
  the SSHSIG namespace" should be minted by the catalogue owner (not invented here).
- **Why:** docs/design + docs/architecture are frozen; this lands the format change with no doc edits.
- **Source:** branch feat/w5-key-location (SSHSIG migration), PR #134.

---

## 2026-06-26 — W1: connector-shape mesh bus + dbus-broker@v1 standing service

- **Target:** docs/design §7.7 (D-Bus mediation), §7.13.4a (connector shapes / service catalogue),
  02-4-binder.md (node 0); docs/architecture 01-process-model / 02-8-internal-api / 03-crate-decomposition.
- **Change (as-built to capture in the rewrite):**
  - **binder-connector mesh bus** — `kenneld` runs a `MeshBus` controller as node 0 of a shared binder
    bus; providers acquire a node handle via `ADD_SERVICE` and consumers receive it via `SVC_CONNECT`.
    New binder primitive: `Reply::Handle(u32)` / `reply_with_handle()` (kennel-lib-binder).
  - **dbus-broker@v1** — a new standing **service kennel** (`templates/dbus-broker/`, new crate
    `kennel-dbus-broker`) is the intended replacement for the per-consumer `host-dbus` delegate:
    `kenneld` pushes per-consumer D-Bus filter sets over the mesh and relays frames for mediation.
    New node-0 verbs (kennel-lib-binder `service.rs`): `REGISTER_CONSUMER`, `UNREGISTER_CONSUMER`,
    `RELAY_FRAME`. `DbusRelay` routes to the broker if a transactor is configured, else falls back to
    the legacy `host-dbus` delegate.
  - **dbus-name / binder-connector handoff** (`svc_connect_handoff`): `Shape::DbusName` replies `OK`
    (filter set already registered at startup); `Shape::BinderConnector` replies `UNAVAILABLE`
    (connector transactions happen directly on the mesh bus).
  - **MeshBusGuard** — RAII guard that decrements participant refcounts and unmounts the per-mesh
    binderfs on the last participant's exit (both normal teardown and bring-up failure).
  - **⚠ NOT-yet-built:** the broker's **frame relay is a stub** — `handle_relay` registers the filter
    and the wire path but does NOT parse/filter/forward frames to the real D-Bus bus. D-Bus mediation
    currently flows through the legacy `host-dbus` delegate; the broker is dormant unless selected. The
    rewrite should describe the broker as the *designed* mediation path with the relay as a known gap.
- **Why:** docs/design + docs/architecture are frozen; W1 ships this architecture with no doc updates.
- **Source:** PR (W1 integration) — branch feat/w1-integration; agent branch feat/w1-connector-shapes.
