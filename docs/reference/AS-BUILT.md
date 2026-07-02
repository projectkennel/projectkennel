# As-built log

The durable record of **as-built facts** — what the running code actually does — kept in this
repository, deliberately **separate from the design corpus**. The corpus (the two-volume book,
`github.com/projectkennel/books`, checked out in-tree at `books/`) states the design and the
intended mechanism; this log states where the built system elaborates or diverges from it. When the
two disagree, the book is the design of record and this log is the ground truth about the code — a
code↔design gap is code-owed, and this log is where it is written down.

It is the steady-state successor of the freeze-era patch log (the frozen `docs/design/` and
`docs/architecture/` trees retired with the corpus cutover). It is **not** an ingestion queue:
as-built facts live here; they are not drained into the book.

Each entry: the **bears-on** book chapter (Vol N ch.M, best-effort — the book may restructure), the
**as-built fact**, the **why**, and the **source** (PR / commit). Newest first. Entries dated before
the cutover cite the retired trees' chapter numbers in their target line, preserved as written.

---

<!-- Template:
## YYYY-MM-DD — <short title>
- **Bears-on:** Kennel book Vol <N> ch.<M> (<Title>) §<x> (best-effort)
- **Change:** <what is now true as-built / what the book's design would otherwise imply>
- **Why:** <one line>
- **Source:** #<PR> / <commit>
-->

## 2026-07-01 — the policy JSON Schema is *derived* from the parser structs, not a hand-kept table

- **Target:** docs/architecture/02-2-config-schema.md §intro (the "It is **generated**, not
  hand-maintained" paragraph), and any prose describing how `schema/policy.toml.schema` is produced.
- **Change (as-built; drop the stale claim):** the schema is **no longer emitted from an in-repo data
  table that mirrors the source structs**, and there is **no cross-check test that "pins that table to
  the real parser."** `gen-schema` now reflects the `kennel-lib-compile` source structs **directly**
  via `#[derive(SchemaType)]` (a tiny first-party derive on the already-vendored `syn`/`quote` stack,
  behind a `schema` feature that is off in the runtime/TCB build) and emits the JSON with `serde_json`.
  The schema is a **pure export of the parser**, so it cannot describe a field the parser lacks or omit
  one it has — drift is **structurally impossible, not test-guarded**. The hand table
  (`gen-schema/src/model.rs`), the hand JSON writer (`json.rs`), and the emitter (`emit.rs`) are
  **deleted**. The cross-check test collapses to two mechanical checks: regenerating is **idempotent**
  (committed file equals a fresh regen) and **every in-tree template parses with the real parser**
  (`kennel-lib-compile/tests/schema_parser_crosscheck.rs`).
- **Why:** the hand table was a second source of truth for the most load-bearing artifact in the
  system, kept honest only by a test — and that test's `templates ⊆ model` direction made a forgotten
  entry in a doc-generation mirror **fail a parser-valid template** (`[[fs.write.add]]`). Deriving from
  the one source removes the duplicate, the babysitter test, and the inverted authority. No new
  vendored crate, no TCB-closure change.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — drop template/fragment *versioning*: identity is the name, integrity is the signature (rides schema v3)

- **Target:** the templates chapter (design §5.10 "Signing, versioned references, and includes" and
  §5.11 the upgrade flow), the config-schema chapter (`template_base`/`template_version`/`include`
  reference grammar), and the lockfile/provenance model. In the frozen trees:
  docs/design/05-templates.md, docs/architecture/02-2-config-schema.md.
- **Change (as-built to capture in the rewrite) — this OVERRIDES §5.10:** there is **no version axis**
  on templates or fragments. A reference is a **bare name** (`template_base = "base-confined"`,
  `include = ["core-shell"]`, `[[spawn.allow]] template = "net-fetch"`); the `@vN` suffix, the
  `template_version` field, the `meta.toml` `version`, the reference-grammar version validator, the
  settled `ResolvedArtifact.version`, and the lockfile `version` key are all removed.
  - **Identity is the name; integrity is the signature.** §5.10 held that version-pinned references
    were a supply-chain control inseparable from signing. As-built, the **signature alone** is the
    content commitment: the lockfile pins each `name` → its ed25519 signature and hard-errors on
    drift (re-pointed/re-signed bytes change the signature and are caught); the dynamic-spawn
    content-pin (§7.12.8) likewise verifies the recorded *signature*, not a version label. The
    version string added no enforcement (resolution never cross-checked it, and the whole corpus was
    `@v1`), so it was theatre by the project's own no-theatre rule.
  - **Coexisting "versions" are coexisting names.** When a base template needs a breaking change,
    author a new **named** template (e.g. `base-confined-v2`) and point `template_base` at it
    deliberately — a reviewed edit, not an automatic bump. The `kennel policy upgrade` command (and
    its version-ordering module) is therefore **removed**; there is no "newest version" to detect.
  - Rides the existing **`SETTLED_SCHEMA_VERSION` 3** (the settled `ResolvedArtifact` loses `version`).
- **Why:** a control must move a real, named threat; an unenforced version string did not. Name +
  signature is the whole supply-chain control, and it is simpler and honestly enforced.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — remove the `[binder]` service section + two invariant-only schema keys (rides schema v3)

- **Target:** the binder chapter (design §7.1, the user-defined service registry), the config-schema
  chapter (the `[binder]`, `[fs.proc]`, and `[unix]` tables), and the procfs/AF_UNIX construction. In
  the frozen trees: docs/design/07-1-binder.md, docs/architecture/02-2-config-schema.md,
  docs/architecture/02-4-binder.md.
- **Change (as-built to capture in the rewrite):**
  - The **`[binder]` user-defined service section is removed** — `[[binder.provide]]` /
    `[[binder.consume]]`, the settled `BinderRuntime`, and `kenneld`'s node-0 service `Registry`
    (the `addService`/`getService` gate, plus the `GET_SERVICE`/`IS_DECLARED`/`LIST_SERVICES`
    verbs). It was a wired-but-unused mechanism with zero corpus/test usage, superseded by the
    cross-kennel capability **mesh** (`[[provides]]`/`[[consumes]]` → `MeshRuntime` → the
    `SVC_CONNECT` broker). Drop any framing of `[binder]` as the way to publish a service. The
    binder **transport** is untouched: `kenneld` still owns node 0 (the `Manager`/lifecycle), the
    per-kennel binder *device* is still the universal control plane, and `ADD_SERVICE` survives as
    the mesh-bus registration verb.
  - **`fs.proc.visibility` is removed.** Procfs is always self-only (`hidepid` such that the
    workload sees only its own tree); the field's only legal value was `self`, enforced as a
    framework invariant. The invariant-only key was theatre — procfs is now structurally self-only
    with no knob, and the `proc.visibility` framework-invariant marker is dropped. `[fs.proc]` keeps
    `hidepid`.
  - **`unix.default` is removed.** Default-deny is structural (the AF_UNIX shim contains only what is
    bound in); the field's only legal value was `deny` (`allow` was a hard compile error). `[unix]`
    keeps `abstract` (the real deny/allow escape hatch) and `[[unix.allow]]`.
  - These ride the existing **`SETTLED_SCHEMA_VERSION` 3** (no new bump — one v3 absorbs the whole
    schema cleanup); the settled `SettledPolicy` loses its `binder` field and `ProcPolicy.visibility`.
- **Why:** the schema should carry only fields that express a real choice against a real adversary.
  `[binder]` was unbuilt-in-practice dead weight (a TCB-shrinking removal of ~250 SLOC across the
  three TCB crates); `fs.proc.visibility` and `unix.default` were invariant-only keys whose single
  legal value made them cruft.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — `[fs.tmp]`: `private` → `writable`, drop the DAC-mode knob (settled schema v3)

- **Target:** the config-schema chapter (the `[fs.tmp]` section) and the filesystem chapter's
  `/tmp` construction. In the frozen trees: docs/architecture/02-2-config-schema.md and
  docs/design/07-4-filesystem.md.
- **Change (as-built to capture in the rewrite):**
  - `[fs.tmp].private` is renamed **`writable`** — that is what it always was: the Landlock write
    grant on `/tmp`. `/tmp` is *always* a fresh per-kennel tmpfs in the constructed view; `writable =
    true` lets the workload use it, absent/false leaves it read-only. Drop the stale claim that
    `private = false` "bind-mounts the host `/tmp`" — it never did; it only withholds the write grant.
  - `[fs.tmp].mode` is **removed**. The tmpfs lives in the workload's own mount namespace and is owned
    by the workload uid, so a per-policy DAC mode gated no real adversary (the host can't reach it
    across the namespace; the kennel is single-uid). The mount now fixes `0700` internally — owner =
    the workload, private-and-usable. The octal-mode validation (an option-injection guard for a knob
    that no longer exists) is gone with it.
  - The settled `TmpPolicy` loses `mode` and renames `private` → `writable`; this bumps
    **`SETTLED_SCHEMA_VERSION` 2 → 3** (and `MIN` → 3): a pre-v3 settled carries the old shape and must
    be recompiled. The spawn plan wire format drops `tmp_mode` accordingly.
- **Why:** `private`/`mode` were a misleading name and security theatre; the schema should say what
  the field does (grant write) and not offer a knob that isn't a real choice.
- **Source:** the schema-fs-tmp-writable PR.

## 2026-06-30 — one policy type: list fields replace *or* increment at the same key

- **Target:** the templates chapter, design §5.2-5.3 (the composition model) and the config-schema
  chapter, architecture §the policy schema / the leaf-policy delta form. In the frozen trees:
  docs/design/05-templates.md and docs/architecture/02-2-config-schema.md.
- **Change (as-built to capture in the rewrite):** there is **one** source-policy type. The
  separate `LeafPolicy` (the delta-only `[[*.add]]` / `[[*.remove]]` form) and `SourcePolicy` (the
  bare-list "set" form) are unified — drop any framing that a leaf is a distinct type, or that the
  delta operators are a leaf-only increment applied after the chain fold. The as-built rule:
  - **Every list field replaces *or* increments at the same key.** A bare sequence
    (`fs.read = ["…"]`, `[[unix.allow]]`) *replaces* the inherited list (the SSH `Ciphers = …` set
    form); an `{ add, remove }` table (`[[fs.read.add]]` / `[[unix.allow.remove]]`) *increments* it
    (the `+=` / `-=` form). The deserializer picks by TOML shape. This holds for every list a leaf
    could previously delta: `fs.read`/`write`/`deny`, `exec.allow`, `unix.allow`, `net.proxy.allow`,
    `net.proxy.deny.policy`, `net.bpf.*.allow`/`deny`, `ssh.destinations`, `fs.dev.passthrough`.
  - **A *template* can now increment**, not only replace — which is the point: the shipped corpus is
    the teachable shape, so the increment form must be available wherever a list lives, not only in a leaf.
  - The chain fold applies the increments (`resolve`), so the **effective** policy always carries
    concrete `Set` lists; there is no separate post-fold delta pass.
  - Identity, not type, tells the three roles apart: a **template** has `template_name`; a runnable
    **leaf** has `name` + `template_base`; a composable **fragment** has `name`, no `template_base`,
    and is additive-only. A leaf may not declare `[[net.proxy.deny.invariant]]` (template/fragment only).
  - Mechanism: `kennel-lib-compile::source::{PathField, ListField, Delta}` (untagged set-or-delta);
    `resolve::fold` applies set-then-increment; `apply_fragment` folds an additive include. Removed:
    the `leaf` module (`LeafPolicy`, `compile_leaf`, `parse_leaf`, `sign_leaf`, `canonical_leaf`).
- **Why:** the two-type split forced a template to *replace* a list it wanted to extend (it could not
  `.add`), so the shipped reference corpus could not demonstrate the increment shape it teaches.
- **Source:** the unify-source-leaf-policy PR.

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
