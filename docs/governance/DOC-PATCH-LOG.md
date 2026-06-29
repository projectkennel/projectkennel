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

## 2026-06-30 — reserved-namespace authority is compile-only and tier-based

- **Target:** the service-catalogue chapter, design §7.13.4 / §7.13.5 (the reserved-namespace gate)
  and §7.13.5a (host `[[reserved]]`). In the frozen trees: docs/design/07-13-service-catalog.md.
- **Change (as-built to capture in the rewrite):** the reserved-namespace authority is resolved
  **entirely at compile**, **tier-based**, and sealed into the settled policy's signature. There is
  **no runtime gate**. Drop the §7.13.4/§7.13.5 framing of a "runtime backstop / authoritative
  catalogue gate" where "a reserved provide's settled *signature* must be a maintainer key", and the
  per-entry `ReservedNamespace.keys` allowlist for host names. The as-built rule:
  - A reserved name has a *required tier*: `org.projectkennel.*` → **vendor** (the key dir
    `/usr/lib/kennel/keys`); a host `[[reserved]]` prefix (`system.toml`) → **host** (`/etc/kennel/keys`).
    Tiers order `User < Host < Vendor`; the gate checks the **declaring tier ≥ required**.
  - **The authority is the tier, not the identity — any key at a tier is equivalent.** The declaring
    tier is the verified tier of the ancestor *template* that supplied the `[[provides]]`
    (ancestor-origin), or the output `--key`'s tier when the leaf authored them itself (entry-origin).
    So a **host-signed** settled may provide `org.projectkennel.wayland` legitimately when it derives a
    **vendor-signed** template that declares it — which is what lets the installer host-compile the
    reference providers (no maintainer private key on the target host).
  - The daemon does **not** re-derive this. It loads only a settled policy whose signature verifies
    against the trust store (`verify_settled_signed`); that trusted signature is the whole boundary.
    The old runtime signer-tier check was **security theatre** against the trust root: a holder of any
    trusted key can re-sign a forged settled, and its only reach is that operator's own per-user daemon.
  - Mechanism: `kennel-lib-compile::mesh::ReservedAuthority` (the sole authorizer) + a tier-aware
    `source_sig::Trust` (`Tier`, `tier_of`); `resolve::ProvidesOrigin::Ancestor { tier }`. Removed:
    `kenneld::catalogue::{provide_authorized, first_unauthorized_provide}` and the daemon's
    `vendor_key_ids` / host-`reserved` plumbing.
- **Why:** the runtime gate forced reserved providers to be maintainer-signed *settled* artefacts —
  un-shippable across arches (settled pins arch loaders) and un-buildable on a target host (no
  maintainer key), while adding no real security. Moving the (already-existing) compile fail-fast to be
  the tier-aware sole authority unblocks host-compiled reference providers with zero shortcut.
- **Source:** branch fix/reserved-namespace-tier-gate.

## 2026-06-29 — D-Bus brokering is opt-in per consumer; host-dbus retained

- **Target:** the D-Bus mediation chapter (design §7.7) and the mesh chapter (§7.13.2,
  `dbus-name` shape). In the frozen trees: docs/design/07-7-dbus.md, docs/design/07-13-mesh.md.
- **Change (as-built to capture in the rewrite):** brokered D-Bus is **opt-in per consumer**, not
  a wholesale replacement of the `host-dbus` delegate. A kennel is routed over the standing
  `dbus-broker@v1` only when it declares **both** `[dbus.session]` **and** a `[[consumes]]` of a
  `dbus-name` capability (`org.projectkennel.dbus`); `[dbus.session]` alone keeps the legacy
  per-consumer `host-dbus` operator delegate. The two coexist (the two-declaration contract
  documented in `dbus-brokered/consumer.toml`). Drop any "host-dbus is retired / decommissioned"
  framing — that retirement is **deferred past 0.5.0** (decision 2026-06-29: keep the host facade
  for now). kenneld gates this on `loaded.consumes` carrying a `Shape::DbusName` entry.
- **Why:** the broker consolidates mediation onto the mesh; it does not yet subsume the
  non-consuming `[dbus.session]` case, which `host-dbus` still serves.
- **Source:** #136 (`brokered_dbus` gated on a dbus-name consume) + the 2026-06-29 decision;
  ROADMAP-0.5.0 W1 exit reconciled.

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
  - **dbus-broker@v1** — a standing **service kennel** (`templates/dbus-broker/`, new crate
    `kennel-dbus-broker`) replacing the per-consumer `host-dbus` delegate. It `ADD_SERVICE`s one
    **control node** on the D-Bus mesh bus (`org.projectkennel.dbus-broker`), which only kenneld
    holds. The single control verb (kennel-lib-binder `service.rs::broker`) is **`ACCEPT_SESSION`**
    `[bus | talk | call | broadcast | own | deny_talk]`: kenneld tells the broker to accept one
    session and apply that filter; the broker mints a **per-session node**, stores the filter
    against the node's cookie, and replies with the node. Consumer→broker is then direct
    (`DBUS_SEND`/`RECV`/`CLOSE` on the session node, mediated by the reused `host-dbus::mediate`
    engine); the session is reclaimed on the node's `Br::Release`. kenneld never relays frames.
  - **Mesh-bus caller identity** — the D-Bus mesh bus's node-0 handler resolves a connecting
    consumer **fresh, per `SVC_CONNECT`**: kernel-attested `sender_pid` → `/proc/<pid>/cgroup` →
    `kennel-<ctx>` → that ctx's one settled `[dbus]` filter (`kenneld` holds a ctx→filter map,
    populated when a brokered kennel is prepared, dropped when its ctx is released). No cookie, no
    session table, no facade-pid keying — the cgroup is the restart-invariant kennel name and the
    only standing state is the policy. The handler then issues `ACCEPT_SESSION` as a *nested*
    transaction on its own context-manager connection and returns the session node via
    `Reply::Handle`. Distinct per-bus capability names carry the bus selector
    (`org.projectkennel.dbus` = session, `org.projectkennel.dbus-system` = system).
  - **dbus-name handoff is a pure locator** (`svc_connect_handoff`, `Shape::DbusName`): on the
    *per-kennel* bus kenneld replies `[OK][mesh-device-path]` when D-Bus is brokered (the facade
    then opens the mesh bus and connects there) or `[OK]` when not (legacy `host-dbus` route). It
    resolves no identity and mints no session — that is the mesh handler's job.
    `Shape::BinderConnector` replies `UNAVAILABLE` (connector transactions happen on the mesh bus).
  - **MeshBusGuard** — RAII guard that decrements participant refcounts and unmounts the per-mesh
    binderfs on the last participant's exit (both normal teardown and bring-up failure).
- **Why:** docs/design + docs/architecture are frozen; W1 ships this architecture with no doc updates.
- **Source:** PR (W1 integration) — branch feat/w1-integration. Supersedes the earlier draft of this
  entry (the `REGISTER_CONSUMER`/`UNREGISTER_CONSUMER`/`RELAY_FRAME` relay model and the startup-time
  filter registration were replaced before merge by the per-session `ACCEPT_SESSION` + cgroup-identity
  shape above; those verbs and the stub frame-relay no longer exist).

---

## 2026-06-29 — W1: mesh binderfs mountable unprivileged + exposed into views; binder handle-ref fix

- **Target:** docs/design §7.13.4a (connector mesh bus), §7.7 (D-Bus mediation), 02-4-binder.md (node 0
  / handle refs), 07-2 (kennel-bin-init role); docs/architecture 01-process-model / 02-8-internal-api.
- **Change (as-built to capture in the rewrite):**
  - **Unprivileged mesh-bus mount holder (§7.13.4a)** — the shared connector binderfs is mounted by a
    **forked, not exec'd** child of `kenneld` (`kenneld::mesh_holder`) under kenneld's own AppArmor
    profile (which carries the `userns` grant across the fork but NOT an exec). The holder creates a
    user namespace with a single-uid **self-map `0 <kenneld-uid> 1`** (unprivileged — no `cap_setuid`,
    no subuids) and mounts the binderfs there; nodes are owned by kenneld's own uid, so kenneld serves
    node 0 by opening the device via `/proc/<holder>/root`. **No privhelper, no host privilege** —
    the privhelper construct protocol, the boot-sync handshake, and the view construction are all
    UNTOUCHED. (A privhelper that *holds* a namespace would be a long-lived privileged process — the
    drift this deliberately avoids.)
  - **Mount handoff is fd-based, not path-based.** A kennel cannot reach the holder's mount by path
    (its construction has its own PID namespace, so `/proc/<holder>/root` does not resolve there), and
    only the holder — the namespace that *has* the mount — may `open_tree(OPEN_TREE_CLONE)` it. So the
    holder **serves clone requests**: on demand it clones a detached, movable binderfs mount and hands
    the fd back over `SCM_RIGHTS`. `kenneld` relays each detached fd into the kennel over a
    **connectionless `AF_UNIX` datagram** the init binds at a fixed in-view path (`RENDEZVOUS_SOCK`,
    on the writable `/dev` tmpfs), reached via `/proc/<init>/root` after boot-sync READY.
    `kennel-bin-init` `move_mount`s each clone into the view (`/dev/binderfs-mesh`) and adds the device
    to the **workload's Landlock ruleset** — all *before* it forks the workload, so the broker/facade
    open the device by path unchanged. `open_tree(CLONE)` shares the binderfs superblock/inode (same
    binder context), so cross-userns object translation works (verified by root probe: the mount/clone/
    userns are not the constraint). New primitives: `kennel_lib_syscall::namespace::{fork_mount_holder,
    open_tree_clone, move_mount_fd}`, `kennel_lib_scm::{bind_dgram, send_to_with_fds}`,
    `kennel_lib_spawn::mesh_rendezvous` (frame + `RENDEZVOUS_SOCK`). `Spec.mesh_mounts` carries the
    detached fds + in-view targets from `kenneld`'s plan into `bring_up`.
  - **Binder handle ref-acquire (correctness fix, 02-4 / 07-7).** `Connection::transact_handle` now
    **acquires a strong ref on the returned handle before freeing the reply buffer** — binder drops a
    transaction's object refs on `BC_FREE_BUFFER`, so without this the returned handle was already
    dangling (the node's refcount hit zero, its owner got `BR_RELEASE`, and the first transaction on
    the handle failed `BR_FAILED_REPLY`). This is what made the brokered D-Bus `ACCEPT_SESSION` handoff
    work end to end (latent until W1 first exercised it). New `Reply::HandleOnce(u32)`: forward a
    handle then **release the endpoint's own ref** — for the per-session node `kenneld` only relays
    (so the broker reclaims the session when the consumer disconnects), distinct from `Reply::Handle`
    (a persistent provider node the node-0 endpoint keeps).
  - **Brokered-consumer mesh-bus tier** — the consumer's brokered-D-Bus path resolves the broker's
    tier **from the catalogue** (not a hardcoded `Host`), so consumer and broker key the *same* mesh
    binderfs instance (a user-enabled broker is `User`-tier). A tier mismatch put them on separate
    buses and `ACCEPT_SESSION` failed closed with the broker's control node "not registered".
  - **Mesh-bus audit is durable** — the `MeshBus` uses a real journal-backed daemon writer
    (`audit::daemon_writer`, `stdout` sink → kenneld's journal), not a noop drain: every
    `SVC_CONNECT` / `ACCEPT_SESSION` / provider-death verdict on the most-trusted cross-kennel
    mediation path is recorded.
- **Why:** docs/design + docs/architecture are frozen; this lands the W1 mountability + the binder
  ref-lifetime correctness with no doc edits. e2e `dbus-brokered` round-trips `GetId` end to end.
- **Source:** branch feat/w1-integration.
