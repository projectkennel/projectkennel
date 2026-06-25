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

### W2 · Filesystem view floor: narrow `/usr` to the flatpak base stance

**[security, quality] M.**

Today the whole host `/usr` is recursively bind-mounted read-only into every view (`base-confined`'s
`fs.read = ["/usr/**", …]` + the bind beneath it), so the complete host tree is *present* in the view —
`/usr/local`, `/usr/src`, every dev header, the full installed-package set — with Landlock gating reads
on top. That is semantically bubblewrap's plain `--ro-bind /usr /usr`: the **unnarrowed** end of the
ecosystem. `/var` is absent; the synthetic `/etc` (six vanilla files) and the curated `/dev` already
match the established stance and need no change.

The stance to mimic is the one shipped at scale and therefore **needing no novel defense — flatpak's**:
a confined app never sees the host `/usr`; it runs against a **curated base** (the loader + core lib
closure, `ca-certificates`, `terminfo`, locale/`gconv`, the base toolchain) with the host's sprawl simply
**not present**. W2 narrows Kennel's default view to that shape — applied to the host `/usr` (Kennel
confines host binaries linked against host libraries, so it curates the host tree down to the
base-equivalent subset rather than swapping in a runtime image; image-backed workloads remain the OCI
substrate's job).

- **Narrow at the mount, not just the grant.** Bind only the curated base subtrees into the view, so the
  sprawl is **absent** (construction-by-absence, §4.2), not merely read-denied — closing the
  `readdir`-still-enumerates gap a Landlock-only narrowing leaves (§7.4.3). The `/usr/**` glob collapses
  to that explicit set at both layers.
- **Anchor to precedent, validate by measurement.** The base set is anchored to the flatpak runtime /
  bwrap-ecosystem base (the precedent that needs no defense), and **measurement confirms** it against the
  policy suite and representative workloads — measurement is the safety net that the precedent-anchored
  floor does not break the loader, TLS, or the terminal, not a from-scratch derivation we would then have
  to defend.
- **`/var` the flatpak way** — stays absent; synthesize only the bits a workload needs (`/var/run` →
  `/run`, `/var/tmp` as tmpfs), explicitly, never a host `/var` bind.
- **Ship the two ecosystem baselines as reference templates.** Land `base-bwrap` and `base-flatpak`
  beside `base-confined`, each encoding the respective tool's *view stance* as a Kennel policy —
  `base-bwrap`: whole host `/usr` ro + usrmerge, all-namespaces (net `none`), `--dev`/`--proc`/`--tmpfs`,
  permissive-exec, no egress proxy (plain bubblewrap, the unnarrowed bracket); `base-flatpak`: the
  curated-runtime narrowing this workstream measures, plus flatpak's seccomp filter and the D-Bus/portal
  mediation the IDBus facade already provides. They make the baseline **concrete and runnable**, not just
  prose — the narrowed floor is anchored against `base-flatpak` and bracketed by `base-bwrap`. Loud
  headers mark them **reference baselines, not recommended starts**: they still run under Kennel's
  non-optional invariants (Landlock from the grants, the binder gateway, `no_new_privs`), so the
  comparison is in *posture*, not in defeating the reference monitor.

The 0.4.0 `/usr/libexec/kennel` blacklist was the down-payment on this. Lands the **host-rootfs
visibility threat entry** — and the residual it records is now precisely *flatpak's* (a curated base is
visible), the accepted, precedent-backed one, not "the whole host `/usr`". Concretises §4.2's
minimal-view floor with that precedent target.

**Exit:** the base templates bind **and** grant a curated `/usr` base anchored to the flatpak/bwrap base
stance, with host sprawl absent from the view; measurement confirms the policy suite and representative
workloads pass on the narrowed floor; `/var` is handled the flatpak way; the floor and its precedent
anchor are documented beside §4.2; the threat entry is written.

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
`[[consumes]]` is held in `KennelMeta.consumed` but used only for the idle-reap census (the ondemand
provider keep-alive) — it is never carried in `Response::Mesh` / `KennelInfo`, so `kennel list` cannot
show it. The data is already
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

### W14 · Privhelper: setuid-root → a split, capability-gated factory

**[security] L.**

The privhelper is installed **setuid-root (mode 4755)** — the one privileged component, so its whole
pre-drop codepath runs with **euid 0 and the full root capability set** (~40 caps) though it needs a
handful; the window is LPE surface (the privilege-origin survey's "minimized setuid helper" row; Firejail
is the cautionary tale for the shape). Move to **file capabilities**, and — having traced the construct
path — **split the rare, potent capabilities out of the common factory** so the everyday privileged window
carries none of `CAP_SYS_ADMIN`, `CAP_BPF`, or `CAP_NET_ADMIN` — only the identity-map caps.

**The structural finding (verified against `construct.rs`).** Almost all privileged construction —
namespace clone, `uid_map`/`gid_map`, every mount, `pivot_root`, binderfs, the in-ns netlink, `chown` —
runs **inside the operator-owned user namespace the factory clones into**, where the child holds full caps
*intrinsically* (a `CLONE_NEWUSER` child does; binderfs is `FS_USERNS_MOUNT`). **None of it needs a host
file cap.** The only privileged work in the *host* context is the id-map write
(`CAP_SETUID`/`CAP_SETGID`/`CAP_SETFCAP`) — always — plus **three feature-conditional** host-context
operations, each absent from the common path: the host-`lo` bind mirror (`CAP_NET_ADMIN`, only when a
policy binds mirrored ports — `lib.rs:778`), the egress BPF attach (`CAP_BPF`+`CAP_NET_ADMIN`, `host` mode
only — `lib.rs:812` `bpf_egress = net.mode == Host`), and the `[fs.write].exclusive` over-mount
(`CAP_SYS_ADMIN`).

**The split — four binaries, each with its own file caps, each gated to its own scope:**

- **`kennel-privhelper`** (the common factory) — **`cap_setuid,cap_setgid,cap_setfcap`** — *pure identity-map
  writing, "uid/gid magic."* Builds *every* kennel: the namespace clone (unprivileged under the AppArmor
  grant), the `0 0 1`+operator id-maps, and the entire userns-scoped view/binderfs/pivot/`chown`/in-ns-`lo`
  (the kernel hands `lo` its `127.0.0.1`/`::1` for free when the child brings it up inside the userns).
  **No `CAP_SYS_ADMIN`, no `CAP_BPF`, no `CAP_NET_ADMIN`.** Under setcap its euid is already the operator,
  so the clone is operator-owned for free and the maps are written with `CAP_SETUID` effective — the
  `seteuid(0)` dance disappears. This is the window almost every spawn opens, and it can now do essentially
  nothing but write the identity map.
- **`kennel-privhelper-net`** (inbound bind mirror only) — **`cap_net_admin`**. Adds/removes the per-kennel
  address on the **host** `lo` so `host-inetd` can mirror a bound listening port host-side (§7.5.7) — the
  current `add_loopback_addresses` + the `del-addr` teardown. Invoked **only** when a policy binds mirrored
  ports (`[net.bind]`); "100% of ephemeral tool spawns" bind nothing (`lib.rs:778`) and never touch it, so
  `CAP_NET_ADMIN` leaves the common path.
- **`kennel-privhelper-bpf`** (host-mode egress only) — **`cap_bpf,cap_net_admin`**. Loads + attaches the
  cgroup egress programs and pins their maps. Invoked **only** when `net.mode = host` (rare,
  `reason`-required, isolation-reducing by design), so `CAP_BPF` — a verifier-bug LPE surface — never sits
  on the common path. This is the recently-folded `SetupEgress` op un-folded into its own fcap binary.
- **`kennel-privhelper-mounts`** (exclusive binds only) — **`cap_sys_admin`**. The host-namespace
  `[fs.write].exclusive` over-mount and its `umount2` teardown — the one operation that *must* run in the
  operator's mount-ns (it shadows the operator-side source, §2.7) and so can't borrow a userns's
  `CAP_SYS_ADMIN`. Invoked **only** when a policy uses exclusive binds; absent that feature, the
  near-root cap is never installed/loaded.

**Gating — possession must not equal abuse.** Each helper validates its *narrow* operation against the
caller's reserved scope before any privileged syscall, exactly as the current factory does (the
`validate` module, the cgroup-ownership check, the addr-subnet check): `privhelper-net` adds only an
address inside the **caller's reserved subnet** (`validate_addr`); `privhelper-bpf` attaches only to a
cgroup the **caller owns** (`exec.rs` `REFUSAL_CGROUP_NOT_OWNED`); `privhelper-mounts` over-mounts only a
path the **caller owns** (`exclusive.rs` `check_owned_dir`). So holding `CAP_NET_ADMIN`, `CAP_BPF`, or
`CAP_SYS_ADMIN` in a split helper grants only that helper's one scoped job, not a general primitive — the
split narrows *what each cap can do*, not just *where it lives*.

The supporting moves:

- **Drop the runtime `modprobe`** (the `CAP_SYS_MODULE` + ambient-cap-across-`execve` problem): load
  `binder_linux` at install (`install.sh` + `/etc/modules-load.d/kennel.conf`), so it's present every boot
  and the factory never module-loads. *(Decided.)*
- **Pin BPF maps into the system `/sys/fs/bpf`** (already mounted at boot) instead of self-mounting a
  bpffs under `/run/user` — `BPF_OBJ_PIN` needs `CAP_BPF`, not `CAP_SYS_ADMIN`, so even the pin stays
  within `privhelper-bpf`'s set.
- **Drop the `seteuid(0)` dance in the common factory.** Setuid-root used euid 0 both to make the clone
  operator-owned (it dropped euid to the operator across the clone, then restored it) and to regain
  `CAP_SETUID` for the map write. Under setcap the euid is *already* the operator (the clone is
  operator-owned for free) and `CAP_SETUID`/`CAP_SETGID`/`CAP_SETFCAP` are effective from the file caps, so
  the map write needs no escalation — the transitions collapse rather than port. (The split helpers raise
  their one cap from the permitted set as needed.)
- **Install + portability.** `install.sh` `setcap`s each binary with its set, with **xattr-support
  detection** and a **setuid fallback** for filesystems that can't carry file caps (the universal default,
  why setuid exists). Confirm the AppArmor `userns` grant still inherits across `exec` onto an fcap binary
  (the profile attaches by path — verify, don't assume).
- **Doc + threat update.** Re-home the privilege model across the corpus to the split-setcap model (the
  AppArmor profile, `RELEASE.md`, the `bubblewrap-vs-kennel-mapping` privilege-origin row, T3.1). **Fold in
  the stale `cgroup-BPF-enforces-constrained-egress` comments** — host-only in fact — across
  `base-confined`/`containerised-service`/their READMEs, `templates/README`, `EXEC-SUMMARY`, and the
  `ai-coding-strict` worked example (the net-ns is the boundary in non-`host` modes; verify the bind/
  `INADDR_ANY` path before rewriting those claims).

**Honest benefit, not overclaimed.** The common factory drops from the full ~40-cap root set to **three
identity-map caps** — `CAP_SYS_ADMIN`, `CAP_BPF`, and `CAP_NET_ADMIN` all absent, each quarantined to a
rare, scope-gated helper rather than carried on every spawn. It is **not** zero-privilege: `CAP_SETUID`/
`CAP_SETGID` are potent (become any uid). But the everyday privileged window can do essentially nothing but
write the identity map — it can't mount, load BPF, configure the network, or override DAC. The helper is
still the TCB's privileged locus; the bet stays "small, single-purpose, signed-policy-gated" — the split
sharpens it hard. *(Setcap is the simpler stance's honest superior, not the only honest stance — setuid
remains the portability fallback.)*

**Exit:** the common `kennel-privhelper` installs with `{setuid,setgid,setfcap}` and **none** of
`CAP_SYS_ADMIN`/`CAP_BPF`/`CAP_NET_ADMIN`; `privhelper-net` (`{net_admin}`), `privhelper-bpf`
(`{bpf,net_admin}`), and `privhelper-mounts` (`{sys_admin}`) carry their caps and are reachable only for
the bind mirror, `host`-mode egress, and exclusive binds respectively, each scope-gated; binder loads at
install, BPF pins into `/sys/fs/bpf`; a setuid fallback covers no-file-cap filesystems; construction —
common path, bind mirror, host-mode egress, and exclusive binds — passes e2e on the hardened-kernel +
AppArmor path; the corpus privilege model (and the stale egress-BPF comments) read true.

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
W14 (privhelper setcap)── M, independent (security) ──────────────►
```

W1 is the only deep dependency chain (A→B→C). W8 lands before W13 so the threat ID can be cited in the
compile diagnostic. W2 completes before W9 so the composer does not seed the `/usr/**` floor it replaces.
W14 is independent of the mesh and slots against capacity. The three ship gates — W9, W10, W11 — all block
the tag.

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
- The installed privhelper carries a minimised file-cap set with no setuid bit (setuid fallback only where
  file caps are unsupported); construction passes e2e on the hardened-kernel + AppArmor path; the corpus
  privilege model reads setcap (W14).

CHANGELOG records every stable-surface change — the two newly-brokered connector shapes, the
`dbus-broker@v1` template, the OpenSSH key format, the `kennel inspect` verb, the split CLI binaries, the
new threat-catalogue entry (+ version bump), and the privhelper privilege model moving setuid → setcap.

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
