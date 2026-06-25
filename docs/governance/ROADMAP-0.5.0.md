# Project Kennel — 0.5.0 plan

Status: **active** · Promoted: 2026-06-25 · Targets: 0.5.0
Baseline: 0.4.0 (released)

> This is a planning artefact, not a design or as-built document. The design corpus
> (`docs/design/`) and the as-built notes (`docs/architecture/`) remain the source of truth
> for *what each item is*; this file records *what 0.5.0 commits to, why, and in what order*.

## Theme

**Owed work and quality of life.** 0.3.0 and 0.4.0 were intentionally large — the dynamic-spawn
model and the standing service mesh are both behind us. 0.5.0 pays the debt they accrued: it
**completes the connector-shape story** (the two mesh transports the schema accepts but the broker
still refuses, and the D-Bus service that needs them), **tightens the security posture in the two
places the cross-kennel red-team explicitly left open**, brings **key management into line with the
tools operators already use**, and makes the system **meaningfully easier to adopt** (a policy-authoring
tool and a CLI split). No gratuitous surface expansion — every workstream has a named reason to be
here *now*, most of them a residual a prior release recorded and deferred on purpose.

Standing constraints carried from 0.4.0:

- **The TCB does not grow to add a capability.** The D-Bus consolidation (W1) moves mediation *across*
  the mesh, not into the daemon; the broker still parses no protocol bodies. Where a workstream touches
  a TCB crate, the growth is measured (`gen-inventory`) and justified, never assumed.
- **Authentication, never attestation.** Unchanged and load-bearing for W1: a `dbus-broker` service
  kennel carries *use*-capabilities (route a call to an authorised destination), never attestation.
- **Never overclaim.** W4/W5 (keys, docs) and W10 (CLI) are public-facing surface; every claim ships
  true against the as-built tree or it does not ship.

## What this release is *not*

- **Not the interactive file broker** (§7.14.7). It depends on the D-Bus service kennel (W1) landing
  first; it is a 0.6.0 item, built correctly against the settled `dbus-broker` rather than rushed onto
  this tag. Stays fenced in [BACKLOG.md](BACKLOG.md).
- **Not multi-operator delegation, global spawn-storm accounting, or degraded-mode semantics** —
  0.6.0-horizon structural items.
- **Not the macOS port** — tracked in the backlog, not scheduled.

Items with no timeline remain in [BACKLOG.md](BACKLOG.md); this file lists only what 0.5.0 commits to.

## Workstreams

Sizes: **XS** ≈ hours, **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week.
Tags: **[dep]** · **[debt]** · **[security]** · **[quality]** · **[ship-gate]**.

### W1 · Complete the connector-shape story: `binder-connector` + `dbus-name` + the D-Bus service kennel

**[dep, foundational] L.**

Three parts in sequence — each is a prerequisite for the next. The mesh schema (§7.13.2) types three
transports; 0.4.0 brokers only `af-unix` and refuses the other two at broker time
(`kenneld::binder` `svc_connect`, status `UNAVAILABLE`). W1 implements both refused shapes and lands the
first real consumer of them.

- **Part A — the `binder-connector` handoff (promoted from BACKLOG).** The backlog promotion condition
  is "a real consumer needs a binder connector node-handle." That consumer is the D-Bus service kennel
  (Part C): `kenneld` must deliver per-consumer authorisation decisions to the broker workload at runtime
  — "this kennel may call this D-Bus name" — and the in-model channel for that control traffic is binder.
  The shape is schema-accepted but broker-refused today; here it is brokered.

- **Part B — the `dbus-name` handoff (promoted from BACKLOG).** Promotion condition: "a real consumer
  needs a brokered D-Bus name" — again the D-Bus service kennel (Part C). `kenneld` resolves a
  `dbus-name` consume against the catalogue and authorises which destination the consumer's existing
  in-view D-Bus facade endpoint may carry calls to — **no new socket, no new path**: the IDBus facade the
  consumer already holds is the standing endpoint, and the broker's job is the destination authorisation
  (§7.13.2). Part A lands before Part B is built.

- **Part C — a standing `dbus-broker@v1` service kennel (consolidation, not a TCB rescue).** D-Bus
  mediation is **already confined and out of the daemon**: each kennel that needs the session bus runs an
  in-view `facade-dbus` aux process that mediates to a `host-dbus` **operator-side delegate** over binder
  node 0 — the same delegate pattern as `host-netproxy` / `host-inetd`, never `kenneld` surface. What this
  part changes is the **topology, not the privilege home**: replace the per-kennel `host-dbus` delegate
  with one **standing `dbus-broker@v1` service kennel** that `[[provides]]` a `dbus-name`-shaped
  capability, consumed via the mesh — parallel to `gui-broker@v1`. The kennel receives per-consumer
  authorisation decisions from `kenneld` over the `binder-connector` channel (Part A) and brokers calls
  accordingly; it is **`ondemand`-enabled** (no D-Bus consumer ⇒ it never starts). The one trusted host
  reach — the session-bus leg — is held by the service kennel, exactly as the GUI service kennel holds the
  one host Wayland socket. The value is **one auditable, lazily-activated D-Bus mediation service** in
  place of a mediation pair instantiated per consuming kennel, and it makes D-Bus the second real consumer
  that proves Parts A/B on a frozen schema. This is **not** a TCB reduction (mediation is already
  confined) — it is a consolidation onto the mesh, and the roadmap states it as such.
  The exact retirement boundary (what stays the consumer's in-view facade endpoint vs what moves into the
  service kennel, and how `host-dbus` is decommissioned) is settled in design §7.7 / §7.13 during the
  build, not pinned here. Parts A and B land before Part C is built.

**Exit:** `binder-connector` and `dbus-name` are no longer broker-refused; the `dbus-broker@v1` service
kennel template is signed and ships; a policy-suite case exercises a `dbus-name` consume end-to-end; the
per-kennel `host-dbus` operator delegate is retired in favour of the brokered service kennel.

### W2 · Filesystem view floor: measure-then-narrow

**[security, quality] M.**

The base templates grant `fs.read = ["/usr/**", …]` wholesale (`base-confined`), so every constructed
view sees the entire host `/usr` — every binary, the whole library tree, locale data, certificates, the
loader closure — a host-rootfs information-leak surface into every kennel. `/var` is absent entirely.
Neither is a principled minimal view; both are legacy approximations. The backlog names this as "a
measure-then-narrow exercise that earns its own release slot." This is that slot, and the 0.4.0
`/usr/libexec/kennel` blacklist was its down-payment.

**Measure first** — the floor must be *derived* from what workloads actually resolve, or it ships a
default that mysteriously breaks TLS or the terminal:

- Instrument the runtime to record which paths under `/usr` workloads resolve (loader closure, `execve`
  targets, `open` of `/usr/share/**`). Run against the in-tree policy suite and representative workloads.
- Derive a principled floor: the loader + its lib closure, the specific `/usr/share` subtrees that break
  things without them (`terminfo`, `ca-certificates`, locale/`gconv` data), the facade binaries under
  `/usr/libexec/kennel`. The `**` glob becomes an explicit curated set.
- Evaluate `/var` the same way — add only the subtrees workloads legitimately need, explicitly.
- Pin the **minimal-view floor** as a design-corpus principle beside §4.2, the concrete floor in the base
  templates, and a **threat entry** (host-rootfs info-leak into views).

**Exit:** the base templates grant an explicit, measured minimal `/usr` floor (and a considered `/var`)
rather than `/usr/**`; the threat entry is written; the policy suite passes on the tightened floor; the
floor and its principle are documented in the design corpus.

### W3 · `RESOLVE_NO_SYMLINKS` on writable-bind sources

**[security] S.**

The 0.4.0 red-team's F1 fix (#120) closed the control-socket exposure at two layers — compile-time
refusal + a privhelper blind-mask backstop — and recorded one residual: a writable bind **source** that
symlink-resolves to a *different* in-view path sidesteps both the lexical compile guard and the canonical
mask. Verified open: `materialize_binds` mounts `b.source` directly via `mount::bind`, and there is no
`openat2` / `RESOLVE_NO_SYMLINKS` anywhere in the tree.

The fix is the **anchored** runtime guard the backlog names: resolve the bind source with
`openat2(RESOLVE_NO_SYMLINKS)` past the shallowest writable ancestor and bind `/proc/self/fd/N`, so a
source that symlink-escapes the granted tree is refused before the mount is applied (no new `unsafe`).
This closes the general writable-bind-source symlink-aliasing class, not just the control-socket instance.
It requires an operator-placed host symlink at a granted path to exploit — not reachable by a confined
workload — but "not reachable by the workload" is not "closed," and the audit explicitly did not close it.
Narrow by gating: the writable-home case is behind `[fs.home].persist` (ephemeral by default).

**Exit:** writable-bind sources are resolved with `RESOLVE_NO_SYMLINKS` in the privhelper; a test asserts
a source that symlink-escapes the granted tree is refused at construction.

### W4 · Signing-key format → OpenSSH wire format

**[quality] S.**

Keys are stored as raw base64 32-byte Ed25519 seeds (private) and raw base64 public keys — functional,
but alien to every operator who already manages SSH keys, and inconsistent with the SSH re-origination
bastion (§7.10), which uses `ssh-ed25519` format throughout already.

Migrate to the OpenSSH wire format: `ssh-ed25519 <base64-blob> [comment]` for public keys in the trust
store, `-----BEGIN OPENSSH PRIVATE KEY-----` for signing keys — so `ssh-keygen -t ed25519` is the standard
key-generation tool, no Kennel-specific tooling required. `load_trust_store` and `load_signing_key` parse
OpenSSH format. The three-tier key hierarchy (vendor / host / user) and rotation/revocation semantics are
**unchanged** — wire format only. Transition: both formats accepted during 0.5.0, raw-base64 deprecated and
removed in 0.6.0; given keys are unlikely to be in wide operator use yet, a one-shot migration tool is an
acceptable alternative to a transition window — decide at implementation time.

**Exit:** `ssh-keygen -t ed25519 -f mykey` produces a key pair that works without conversion with
`kennel policy compile --key mykey` and in the trust store.

### W5 · Key-management documentation

**[documentation] S.**

The three-tier key hierarchy, the key format (after W4), rotation (additive-and-lazy), revocation
(construction-time, no in-flight kill), and the local-trust-root honesty section (what the host trust root
actually guarantees, the tiered integrity paths) are designed and implemented but not written down in the
corpus. An operator managing signing keys for a fleet cannot operate without this. Sequenced **after W4** —
documentation written against the old format is stale on arrival.

**Exit:** the design corpus carries a key-management chapter covering all of the above, accurate to the
W4 format.

### W6 · The `who-consumes-what` topology leg

**[operability] S.**

The 0.4.0 topology surface shows who-*provides*-what; the consumer side is owed. Each running kennel's
`[[consumes]]` is held in `KennelMeta.consumed` but used only for the W6-era idle-reap census — it is
never carried in `Response::Mesh` / `KennelInfo`, so `kennel list` cannot show it. The data is already
present at construction; this is plumbing it through to the client.

Each running kennel's active `[[consumes]]` becomes visible: capability name, shape, required/optional, and
current resolution state (resolved / pending / unavailable). A standing mesh is operated blind without it —
a flaked dependency is visible provider-side; the demand side completes the picture.

**Exit:** `kennel list` shows both who-provides-what and who-consumes-what; a test asserts the consumer leg
is populated for a running consumer kennel.

### W7 · `kennel_meta` BPF-map read-only sealing

**[security] XS.**

The `kennel_meta` BPF map is written once by loader convention but created with `map_flags: 0` — not yet
frozen with `BPF_F_RDONLY_PROG` as `02-7-bpf-abi.md` specifies. Seal it: a workload cannot corrupt the meta
map even if it somehow reaches the BPF subsystem, and the `magic`/`abi` readback becomes verifiable.

**Exit:** `kennel_meta` is created with `BPF_F_RDONLY_PROG`; a test asserts a write from a BPF program
fails.

### W8 · `[unix]` deferred completions: the abstract-socket escape hatch + `kennel inspect --unix`

**[security, operability] S.**

Two designed-but-unbuilt §7.6 pieces.

1. **`abstract = "allow"` — an ABI-gated escape hatch, *relaxing a current hard denial*.** Today
   `abstract = "allow"` is a **compile rejection** (`kennel-lib-compile::unix`): abstract-namespace sockets
   are denied by the always-on Landlock scope (`Scope::ABSTRACT_UNIX_SOCKET`, enabled from Landlock ABI 6 —
   the ABI machinery and `supported_scope` are already in place). W8 introduces the opt-in escape hatch,
   ABI-gated, for the workloads that genuinely need an abstract peer.

   **Hard constraint — `abstract = "allow"` with `net.mode = "host"` is a compile error.** Abstract
   sockets are scoped to the **network** namespace, not the mount namespace. A `host`-mode kennel shares
   `CLONE_NEWNET` with the host — no net-ns boundary — so `abstract = "allow"` there is a direct hole into
   the host abstract namespace (X11, the D-Bus session bus, arbitrary daemon IPC), below Landlock, the
   proxy, and BPF, regardless of ABI version (on pre-ABI-6 kernels the scope silently does nothing). The
   net-ns boundary is the structural control; ABI-6 abstract scoping is defence-in-depth on top of it, never
   a substitute. So the combination is a **hard compile error** with a typed diagnostic (citing the W13
   threat ID), not a warning and not a runtime check. `abstract = "allow"` is valid only when the kennel
   owns its `CLONE_NEWNET` — `net.mode` is `none` / `constrained` / `unconstrained`.

2. **`kennel inspect <name> --unix`.** The §7.6.5 design exists in full; the CLI surface was never built
   (there is no `inspect` verb today). An operator cannot reason about a kennel's AF_UNIX grants without
   reading the policy. Lands as its own commits.

**Exit:** `abstract = "allow"` is accepted and ABI-gated; `abstract = "allow"` + `net.mode = "host"` is
refused at compile with a typed error citing the W13 threat ID; `kennel inspect <name> --unix` produces
output matching the §7.6.5 design.

### W9 · `kennel-compose` — a standalone policy-authoring tool

**[quality, ship-gate] M.**

The adoption barrier for Kennel is policy authorship. `kennel-compose` is a **fully standalone** binary —
separate optional install, no runtime dependency, no part of the `kennel` dispatch tree — that closes the
gap with two modes. Being disjunct from the runtime, it may carry heavier deps (a TUI library) without
those touching the runtime path. It is **not** an LLM and not a policy compiler; it emits a policy the
operator owns and is expected to review and tighten. `--no-prompts` produces a maximally-restrictive
skeleton for CI.

- **Mode A — binary probe (`kennel-compose <binary>`).** Probe the ELF (interpreter, linked-library
  closure) to seed the `fs` and `exec.allow` floor automatically — **informed by the W2 measured floor** so
  it does not emit `/usr/**`; ask a structured set of capability questions (net mode, home access,
  Wayland/audio/SSH, GUI via `gui-broker@v1` / D-Bus via `dbus-broker@v1`); emit a leaf `.toml` against the
  inferred base template with `reason` fields pre-populated from the probe; validate via
  `kennel policy validate` before writing.
- **Mode B — interactive composer (`kennel-compose --compose`).** Present the available templates and
  signed fragments (multi-select `[[include]]`) for selection; ask the same capability questions without
  probing; if more than one signing key is present, prompt for which to use; emit, validate, and optionally
  sign.

**Exit:** `kennel-compose /usr/bin/firefox` produces a compilable policy; `kennel-compose --compose` walks
template/fragment/key selection and produces a compilable signed policy; both pass `kennel policy validate`
before writing.

### W10 · Split the `kennel` host CLI by keyword

**[structural, ship-gate] M.**

`kennel-host` is the largest binary by far and growing — one monolith handling every host verb
(`run`, `attach`, `review`, `release`, `stop`, `list`, `daemon-reload`, the `policy` sub-tree,
`keygen`, `subkennel`, `audit`, `oci`). The static `kennel` front-shim (0.4.0 W10) makes a clean split
straightforward: the shim already detects context by the presence of the `kenneld` control socket
(present ⇒ host side; absent ⇒ in-kennel ⇒ `kennel-facades/spawn`, keywords irrelevant). On the host side
the keyword selects the sub-binary.

- `kennel-run` — runtime verbs that talk to the daemon (`run`, `attach`, `stop`, `list`, `review`,
  `release`, `daemon-reload`).
- `kennel-policy` — authoring verbs (`compile`, `validate`, `sign`, `lint`, `risks`, `diff`, `upgrade`,
  `show`, `generate`, and `inspect` once W8 adds it).
- `kennel-oci` — the OCI substrate verbs.
- `kennel-misc` — smaller verbs without their own binary yet (`keygen`, `subkennel`, `audit`); graduate
  out as they grow.

`kennel` retains only dispatch + in-kennel detection. `kennel-compose` is fully disjunct and not part of
this split. Ship gate ordering: `kennel-compose` (W9) calls `kennel policy validate`, so the
`kennel-policy` sub-binary must exist first — W10 lands after W9. The verb buckets above are reconciled to
the *actual* host verb set (there is no `ps`; mesh/topology is under `list`).

**Exit:** `kennel-run`, `kennel-policy`, `kennel-oci`, `kennel-misc` exist as separate installed binaries;
`kennel` dispatches correctly by context and keyword (and to `kennel-facades/spawn` in-kennel); the
installed binary layout is updated in `07-paths.md`.

### W11 · Pre-ship dynamic red-team pass

**[security, ship-gate] S.**

The 0.4.0 cross-kennel audit recorded two surfaces as assessed by code-read, not by a live racing/probe
harness, and explicitly did **not** close them:

- **Connector-broker resolution race** — TOCTOU between `SVC_CONNECT` and the live capability map.
- **GUI confidentiality legs** — host-global leak through the inner compositor; one kennel reaching
  another's compositor.

"No finding from a focused pass is not proven safe." Both surfaces are *more* exercised after W1 (new
`binder-connector` and `dbus-name` consumers; the `dbus-broker` standing service), so a **dynamic pass
against a running daemon and compositor** is owed before the tag. This is a ship gate and may produce
findings that require fixes before 0.5.0 ships — budget accordingly. Runs after W1.

**Exit:** a dynamic red-team pass covers the connector-broker race and the GUI confidentiality legs against
the 0.5.0 surface; findings are recorded in `audits/`; any confirmed finding is fixed before the tag.

### W12 · Stale-comment sweep

**[housekeeping] XS.**

Two stale comments in `kennel-lib-compile/src/resolve.rs`, both verified stale against the tree:

- it describes `[[*.add]]` / `[[*.remove]]` (`+=` / `-=`) delta operators as "a later increment" — they
  shipped in `leaf.rs`.
- it describes lockfile byte-pinning of resolved template references as "the remaining increment" — it
  shipped in `lock.rs`.

Update both to the as-built state (the CODING-STANDARDS comments-carry-the-contract-not-the-history rule).

**Exit:** both comments are accurate to as-built.

### W13 · Threat catalogue: abstract-socket namespace escape via host net mode

**[threat catalogue] S.**

The W8 analysis surfaces a threat class with no named entry in `THREATS.md` (verified absent): a workload
in `net.mode = "host"` with `abstract = "allow"` shares the host's abstract-socket namespace
unconditionally — direct access to host-side X11, the D-Bus session bus, and any daemon binding an abstract
socket, with no Landlock, proxy, or BPF gate in the path. This is **distinct from T1.6** (host-network
*egress* reachability): it is an IPC escape below the proxy layer, not an egress one.

One new `THREATS.md` entry (+ `dist/threats/catalogue.toml`) with a stable ID and ATT&CK mapping; the
structural mitigation (own net-ns is the boundary; Landlock ABI-6 scoping is defence-in-depth, not the
primary control) and a reference to the W8 compile-time refusal. Cross-reference from the `[unix]` and
`[net]` design sections. Sequenced **after W8** so the compile error can cite the threat ID.

**Exit:** `THREATS.md` carries the new entry with a stable ID; the `[unix]`/`[net]` design sections
reference it; the W8 compile error cites it. (Bumps the threat-catalogue version.)

## Sequencing

```
W7  (BPF seal)        ── XS, independent ─────────────────────────►
W12 (comment sweep)   ── XS, independent ─────────────────────────►
W6  (consumer topo)   ── S,  independent ─────────────────────────►
W3  (bind symlinks)   ── S,  independent ─────────────────────────►
W8  (unix)            ── S,  before W13 ──────────────────────────►
W13 (threat entry)    ── S,  after W8 (cited in the W8 diagnostic) ►
W4  (key format)      ── S,  before W5 ───────────────────────────►
W5  (key docs)        ── S,  after W4 ────────────────────────────►
W2  (fs floor)        ── M,  measure-first, informs W9 ───────────►
W1  (connectors+D-Bus)── L,  Part A → B → C ──────────────────────►
W9  (kennel-compose)  ── M,  after W2 + W1, ship gate ────────────►
W10 (CLI split)       ── M,  after W9, ship gate ─────────────────►
W11 (dynamic red-team)── S,  after W1, ship gate ─────────────────►
```

W1 is the only deep dependency chain (A→B→C). W8 lands before W13 so the threat ID can be cited in the
compile diagnostic. W2 completes before W9 so the composer does not seed the `/usr/**` floor it replaces.
The three ship gates — W9, W10, W11 — all block the tag.

## Exit criteria

0.5.0 ships when:

- `binder-connector` and `dbus-name` are implemented and no longer broker-refused; the `dbus-broker@v1`
  service kennel ships with a policy-suite e2e; the per-kennel `host-dbus` operator delegate is retired in
  favour of the brokered service kennel (W1).
- The base templates grant a measured minimal `/usr` floor (and a considered `/var`); the threat entry is
  written; the policy suite passes on the tightened floor (W2).
- Writable-bind sources are resolved with `RESOLVE_NO_SYMLINKS` in the privhelper (W3).
- `ssh-keygen -t ed25519` output is accepted in the trust store and by `kennel policy compile --key`
  without conversion (W4); the key-management chapter is written and accurate to that format (W5).
- `kennel list` shows the consumer leg of the mesh topology (W6).
- `kennel_meta` is sealed with `BPF_F_RDONLY_PROG` (W7).
- `abstract = "allow"` is ABI-gated and enforced, the `host`-mode combination refused at compile with a
  typed error citing the W13 threat ID, and `kennel inspect --unix` is implemented (W8).
- `kennel-compose <binary>` and `kennel-compose --compose` both produce a compilable (signed, for
  `--compose`) policy that passes `kennel policy validate` before writing (W9).
- `kennel-run` / `kennel-policy` / `kennel-oci` / `kennel-misc` exist as separate installed binaries and
  `kennel` dispatches correctly by context and keyword (W10).
- The dynamic red-team pass on the connector-broker race and the GUI confidentiality legs is complete and
  every confirmed finding fixed (W11, ship gate).
- The stale `resolve.rs` comments are accurate to as-built (W12); `THREATS.md` carries the abstract-socket
  namespace-escape entry with a stable ID cited by the W8 diagnostic (W13).

CHANGELOG records every stable-surface change — the two newly-brokered connector shapes, the
`dbus-broker@v1` template, the OpenSSH key format, the `kennel inspect` verb, the split CLI binaries, and
the new threat-catalogue entry (+ version bump).

## Parked work

Items with no timeline — declined-on-principle, promote-on-demand candidates, and work fenced to a later
release — live in [BACKLOG.md](BACKLOG.md), not here, so they are not carried from one roadmap to the next.

## Non-goals (explicitly out of scope)

- **Interactive file broker** (§7.14.7) — deferred to 0.6.0; depends on W1 landing first.
- **Fine-grained `[consumes]` method policy** — coarse service-name reachability ships first; finer policy
  must not drag a protocol-body parser into a broker.
- **Kenneld restart-fork resolution, global spawn-storm accounting, multi-operator delegation** —
  0.6.0-horizon structural items.
- **macOS port** — tracked in the backlog, not scheduled.
