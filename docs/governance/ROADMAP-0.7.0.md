# Project Kennel — 0.7.0 plan

Status: **active** · Promoted: 2026-07-08 · Targets: 0.7.0
Baseline: 0.6.0 (released)

> This is a planning artefact, not a design or as-built document. The corpus (the book +
> `docs/reference/`) remains the source of truth for *what each item is*; this file records *what
> 0.7.0 commits to, why, and in what order*.

## Theme

**The operator-UX release: the CLI reads as the model.** 0.6.0 finished the confinement story's
largest gap and, in its last act, nailed the tier model to the filesystem (host config in `/etc`,
vendor invariants in `/usr/lib`, #186). 0.7.0 spends no capacity on new confinement surface;
it makes the surface that exists **legible and operable**. The system's load-bearing distinctions —
settled vs source, template vs leaf, user vs host vs vendor authority — are all real and all
enforced, but today they are enforced by *failure*: the CLI lets you hold the wrong object at the
wrong verb and tells you at the end, sometimes with a stale pointer. The release restructures the
verb set so each house owns its material — **run** touches only settled artefacts, **authoring**
owns source/templates/keys, and every boundary refusal names what the user is holding and the real
next step — and adds the missing ceremonies (`clone`, `install`, key management) so the paths an
operator actually walks are single verbs instead of folklore. The one schema slot goes to the
list-field consistency pass (v5) — the biggest policy-*authoring* footgun left. A pre-ship pass
proving the new ceremonies never became enforcement points gates the tag.

Standing constraints carried forward:

- **The TCB does not grow to add a capability.** Everything here is CLI, installer, and schema-shape
  work; where a workstream touches a TCB crate (the settled schema, the key/verify paths), the
  growth is measured (`gen-inventory`) and justified, never assumed.
- **Keys operate at one level.** A user key signs at user level, a host key at host level, the
  maintainer key is the project's affair and never appears in shipped tooling. No verb offers a
  cross-tier signing path.
- **Never overclaim.** Diagnostics say what is true ("that's a template — a base, not runnable"),
  not what is convenient.

## What this release is *not*

- **Not kenneld restart-fork resolution and not global spawn-storm accounting.** Both stay fenced in
  [BACKLOG.md](BACKLOG.md); restart-fork is the natural *structural bet of 0.8.0* — it wants a
  release's full attention the way self-confinement did, and mixing it into a UX cycle is how
  structural work gets half-done.
- **Not multi-operator delegation.** The key-management house (W4) is strictly *mechanical* — keys
  managed within the existing tier model, authorization from filesystem reality (host-tier verbs
  need root). Who may add a key to a place, and how holders scope against one another, stays
  design-gated in the backlog; no verb pre-empts it.
- **Not a policy-language change.** W6 regularises the *composition semantics* of existing
  list-shaped fields; it adds no new capability surface.
- **Not the README/website positioning rewrite.** Stays a backlog item promoted on its own schedule;
  prose does not gate a release.

Items with no timeline remain in [BACKLOG.md](BACKLOG.md); this file lists only what 0.7.0 commits to.

## Workstreams

Sizes: **XS** ≈ hours, **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week.
Tags: **[dep]** · **[debt]** · **[security]** · **[quality]** · **[validation]** · **[ship-gate]**.

### W0 · Front-matter verification: pin the contracts the reshape rests on

**[validation] S. Runs first; each item gates a dependent workstream's design, which is the point of
paying for it up front.**

The reshape rests on as-built contracts that must be *read, not assumed* before verbs are drawn:

- **V1 — Confirm the tier-inclusive verification contract as-built (gates W3, W4).** The contract
  is stated by ruling: **an artefact at a level verifies under a key from its own level or any
  level above it** — user-level artefacts under user, host, or vendor keys; host-level under host
  or vendor; vendor under the maintainer key alone. Downward copies just work (the higher tier's
  public key is present a level down); a lower-tier signature never carries upward. Read the
  actual verify path (`kenneld`'s settled-signature check, `system_key_dirs`, the trust-store
  resolution order) and confirm the code implements exactly this, recording which key dirs feed
  verification per placement tier. Red: any divergence is a 0.7.0 defect fixed toward the stated
  model *before* W3's verbs are built — the ceremonies' design (no user-tier trust list; re-sign
  only what lacks an at-or-above signature) rests on it.
- **V2 — The refusal inventory (feeds W1, W2).** Catalogue every CLI diagnostic that names a next
  step, and check each pointer against the real verb set (the `kennel compile` stale pointer is the
  known receipt; post-0.6.0 renames may have left more). The sweep in W1/W2 works from this list,
  not from grep-as-you-go.
- **V3 — The `run` acceptance inventory (feeds W1).** Record exactly what forms `run`/`oci run`
  accept today (settled name, source name, literal path, in-memory compile with which flags) and
  which the policy suite exercises — so the strip in W1 is a diff against receipts, and the e2e
  fallout is known before the cut.

**Exit:** each item has a recorded result in a dated `audits/` note; V1's answer is reflected in
W3/W4's design before their verbs land.

### W1 · The operating house: `run` reads settled artefacts, nothing else

**[quality, debt] S–M. The release's anchor invariant.**

`kennel run` today is a compile+run hybrid: it accepts a **source** policy (template or leaf) and
compiles+signs it in memory as a dev convenience, which is what drags `--key`, `--key-id`,
`--template-dir`, and `--trust-dir` onto the run verb and blurs the house boundary. The ruling:
**`run` only ever looks at a `*.settled.toml` inside one of the three policies repositories**
(`~/.config/kennel/policies`, `/etc/kennel/policies`, `/usr/lib/kennel/policies`). Templates,
includes, keys — the whole compile side of the house — never appear on `run`.

The change, for `run` and the shared launch core `oci run` uses:

- Resolution narrows to *name → settled artefact in the three repos*. The **literal-path form dies**
  with the rest: a settled artefact anywhere else must be placed into a repo to run. The contract
  becomes one sentence with no second form to explain.
- The `is_source_policy` branch and the in-memory compile/sign (`build_settled`, `TempSettled`,
  `FsTemplateSource`) leave the run path; `--key`/`--key-id`/`--template-dir`/`--trust-dir` are
  removed from the verb. The dev loop is `kennel policy compile … && kennel run <name>` — two
  commands, no hybrid (compile already writes the settled artefact beside its source in the repo,
  so run-by-name follows immediately).
- **Instructive refusals at the boundary** (from the V2/V3 inventories): handed a source leaf →
  "source policy — compile it first: `kennel policy compile <name> --key K`"; handed a template
  name → "that's a template — a base, not runnable: `kennel policy generate --from <t>`, then
  compile"; handed a path → the one-sentence contract and where to put the file. Every stale
  pointer found by V2 is fixed in the same pass.

**Exit:** `run`/`oci run` accept only a name resolving to a settled artefact in the three repos;
the compile-side flags and the in-memory compile are gone from the run path; each wrong-object
refusal names the object and the real next step; the policy suite passes with its cases invoked
through the narrowed form; CHANGELOG records the CLI surface change.

### W2 · The authoring split: `kennel template` beside `kennel policy`

**[quality] S.**

Templates and leaves are different objects — different layout (`meta.toml`), different signing
authority, different composition role — but one interleaved verb list serves both, which is how
`sign` vs `sign-template` confusion happened in the first place (0.6.0 fixed the worst by rename;
the house split removes the class). The surface becomes:

```
kennel policy    list/show/edit/generate/clone/install/compile/validate/diff/inspect/risks
kennel template  list/show/clone/install/sign/lint
```

- Under its own house, `template sign` is unambiguous — `sign-template` retires to a
  pointer-diagnostic (the same one-release courtesy `sign` got in 0.6.0).
- Each house refuses the other's material instructively: `policy install` handed a template points
  at `template install`, and vice versa.
- `policy inspect`/`risks` stay in the policy house deliberately — they read settled artefacts as
  the operator's pre-flight lens; the straddle is named in the help text rather than hidden.

**Exit:** both verb houses exist with the surface above; `sign-template` and any other retired
spelling answer with a pointer; the man pages (derived from the CLI definition since 0.6.0 W7)
reflect the split with no hand-edits; CHANGELOG records the surface change.

### W3 · The missing ceremonies: `clone` and `install`

**[quality] M. The distribution story: receive → install → run.**

Two multi-step rituals become verbs, sharing one ceremony implementation. Both consume the
compiler's own `reserved_authority` machinery as its third consumer — a parallel hand-list of
reserved families would drift.

**`clone <source> [<new-name>]` — fork an object into the user house.**

- Copies **source form only** — never a settled artefact, never a lock; those are derived objects
  carrying the old authority's signature. Anything the tier ships source for is clonable (all of
  vendor; host templates where present). A settled-only object refuses with the reason and where
  the source lives.
- The **authority gate runs at clone time, and renaming is no escape.** The pre-flight *is* the
  gate: "would this object, as content, compile and sign under a user key?" — asked of the
  compiler's own `reserved_authority` logic, never a hand-list. An object carrying reserved
  claims — a reserved name, or a `[provides]` resource in a reserved family — is **not clonable
  to user space at all**: the claim lives in the content, not the filename, and a user key cannot
  re-sign it under any name. The refusal says exactly that and points at the legitimate path —
  `generate --from` *derives* from the template where it stands, vendor-signed, floor intact.
  Fork is only for what you could have authored yourself.
- `clone` vs `generate --from`, stated in the help text: *derive vs fork*. `generate --from` makes a
  child that inherits the template's floor; `clone` makes a sibling — your copy, your name, your
  key, no inherited floor.
- **Shadowing is the default; the tier leads.** `clone <source>` with no second argument keeps
  the name — the user copy overloads the original under user-first resolution, which is the point:
  same workload, your tweak, your key. The optional second argument clones to a different name
  instead. What makes this safe to live with is **tier provenance made visible everywhere a policy
  is used**: `policy list` names each object's tier and marks a shadowed name
  (`claude · user · shadows vendor`), `policy show`/`inspect` carry the origin tier, and `run`
  reports which tier's artefact it resolved (`running claude [user]`) — "which claude am I
  actually running" is never answered by ls-ing three trees. Provenance is **two facts, both
  shown where they differ**: the placement tier and the signing tier — a vendor-signed artefact
  copied down to user space is `[user, vendor-signed]`, distinct from a user-signed clone,
  because acceptance is downward-inclusive (V1) and the two are different objects to reason
  about. (Objects carrying reserved claims
  never reach this question — they are not clonable at all, per the authority gate above.)

**`policy|template install <file.toml> [--host]` — place and sign at the invoking tier.**

- Classify from content (identity from the `name` field, filename irrelevant), reject the
  cross-house case, and run the normal resolve/validate — garbage is never placed.
- **Tier + authority**: user tier (default) requires the whole object — name *and* content, any
  `[provides]` resource included — clear of every reserved family, and signs with the user key;
  `--host` requires root, may claim a host `[[reserved]]` family, signs with the host key.
  `org.projectkennel.*` refuses at **every** install level — the vendor tier is package payload,
  never an install target.
- Places into the canonical layout at the tier; collision → refuse, `--force` to replace. **Source
  is kept beside the artefact at both tiers** — for an admin-authored host object `/etc` is its only
  home, and dropping source would make it uneditable.
- Signs at the tier's level: leaf → compile against the tier's trust context, settled lands beside
  source; template → tier-key signature. A host-template re-sign states its known consequence
  (leaf lockfiles re-pin) instead of leaving it folklore. **No unsigned mode** — an unsigned install
  is just `cp`; the verb's value is the ceremony (`compile --unsigned` remains for the dev loop).
- `clone` composes on `install`'s backend: copy source + authority-gate + install-at-user-tier.
- **The signature model behind both ceremonies, stated once:** an artefact at a level verifies
  under a key from its own level or any level above (V1). A vendor- or host-signed settled
  artefact copied down to a lower tier therefore *just works* — no ceremony, the public key is
  already present — while a lower-tier signature never carries upward. The ceremonies exist for
  objects that **lack** an at-or-above signature for their destination: authoring and receiving,
  not downward replication.

**Exit:** a bare `.toml` received from anywhere is runnable in two commands (`install`, `run`);
a same-name clone shadows user-first and every use surface names the tier (`list` marks the
shadow, `show`/`inspect` carry origin, `run` reports the resolved tier); clone and user-tier
install refuse any object carrying a reserved claim — name or `[provides]`, renaming no escape —
with the compiler's own diagnostic and the `generate --from` pointer; no ceremony copies a
settled artefact or lock; V1's verified trust contract is what the re-sign step relies on; e2e
covers user-tier install→run and (root) host-tier install→run.

### W4 · The `key` house: tier-bound key management

**[quality, security] M.**

Today: one verb (`keygen`), three tier dirs, and every other key operation is manual file
management — the install banner literally instructs a `cp` into `/etc/kennel/keys`. The model
ruling makes the house simple: **a key's tier is where it lives, and that is the only level it
signs at**. User keys sign user objects, the host key signs host objects, the maintainer key never
appears in shipped tooling.

```
kennel key generate <name>     # invoked as user → user key; as root → host key. Context is tier.
kennel key list                # all tiers: name, fingerprint, tier, mine-vs-trusted
kennel key show <name>         # fingerprint + signed-object inventory across the repos
kennel key trust <file.pub>    # HOST level only (root): org/customer pubs into the daemon store
kennel key untrust <name>      # host level, with the impact report before it proceeds
kennel key rotate <name>       # per-tier ceremony; see below
```

- `keygen` retires to a pointer-diagnostic.
- `trust`/`untrust` exist **only at host level**: the user tier needs no trust list, because the
  W3 install ceremony re-signs foreign objects under the user's own key — that re-signing *is*
  user-level trust, per object, explicit every time (contract verified by W0-V1).
- `untrust` names every settled artefact and template that stops verifying **before** asking to
  proceed — trust-store mutation is never silent. The scan spans the key's own level **and every
  level below it**: acceptance is downward-inclusive (V1), so untrusting a host-tier key also
  orphans the user-level artefacts riding its signature.
- `rotate <name>`: generate successor, re-sign everything the old key signs (templates re-signed,
  leaves recompiled, lockfile re-pins driven correctly), then untrust the old — the whole cascade
  that today requires knowing four gotchas by heart, as one supervised ceremony. **Rotate ships
  with the house.** It is the heavy half, but the house without it leaves the worst manual
  ceremony in place — and proving the machinery against the user and host tiers now means it is
  known-good before the maintainer key's own turnover (2027) needs the upstream analogue.

**Exit:** the key house exists with tier-bound semantics and no cross-tier signing path; `keygen`
answers with a pointer; `untrust` is impact-reporting; `key list` answers "which keys exist, whose,
at what tier, signing what" in one command; a rotation on a populated user tier leaves every owned
object verifying under the successor key, and a host-tier rotation drives the template re-sign and
lockfile re-pin cascade correctly (both e2e-asserted).

### W5 · `kennel version`: the whole-stack skew report

**[quality] XS–S.**

Nothing reports a version today — the tarball name is the only carrier. The interesting output is
not one number but the *skew set*: CLI version; **daemon version, queried live** (which instantly
surfaces the old-binary-still-serving-after-reinstall trap); `SETTLED_SCHEMA_VERSION` and the MIN
floor; privhelper presence and features (bpf-egress or not). One verb, whole stack, skew visible.
Also carried on `--version` for convention's sake.

**Exit:** `kennel version` reports CLI + daemon + schema/MIN + privhelper facts; a deliberately
skewed install (old daemon, new CLI) shows the skew in one invocation; the man page carries it.

### W6 · Schema v5: the list-field consistency pass

**[debt, quality] M. The release's one schema slot; both items ride the same bump.**

List-shaped policy fields do not compose uniformly (backlog, parked 2026-07-04): some are
`ListField` — bare-set *or* `.add`/`.remove` delta with a required `reason` — while others are
plain `Vec` with silent bare-set-replaces-parent fold semantics (`[identity].groups`,
`[[provides]]`/`[[consumes]]`). Nothing documents which is which or why; the live consequences are
the W14-class silent floor-drop and set-vs-`.add` surprises visible only in a compiled-artefact
diff. The pass:

- **Decide the rule** — default to `ListField` for any inheritable list where a base contributes a
  floor; keep plain `Vec` only where replace-is-the-contract, and document *why* per field.
- Apply it uniformly; document the set/delta/fold semantics in **one** place in the book.
- **`proxy_listen_v4_address`/`proxy_listen_v6_address` collapse** rides the same bump: addressing
  has been v6-only since 0.6.0 W10 (#156), the split is vestigial.
- `SETTLED_SCHEMA_VERSION` bumps to **5** — a real shape change, not a re-pin. The MIN floor
  follows the **variance rule**, now standing: the floor holds only while an artefact of the floor
  version runs against the new schema **without variance** — v4 kept a credible v3 floor because a
  v3 artefact runs identically under v4. This pass changes composition semantics, so the question
  is asked per covered field, concretely: does a v3/v4 artefact still validate and behave
  identically under v5? If any non-optional part cannot be validated against the previous floor,
  **the floor goes up** — no grandfathering an artefact whose meaning shifted. The determination
  and its receipts (the per-field variance check) are recorded with the bump.

**Exit:** every list-shaped field's composition semantics are deliberate, uniform where the rule
says uniform, and documented in one place; a leaf can no longer silently drop an inherited floor
via bare-set on any field the rule covers; the listen-key split is collapsed; schema v5 is pinned
in `schema/schema-version.lock`; the MIN floor is set by the variance rule with the per-field
receipts recorded; compile of the shipped template corpus is clean; CHANGELOG records the
policy-schema change and the ABI consequence.

### W7 · Install-surface hygiene: the payload manifest, and the `/etc`-binds trap

**[debt, quality] S–M.**

**The payload manifest.** #186 added targeted cleanup for the moved config files; the general
class remains: **nothing removes what the payload no longer ships.** Live receipt:
`/usr/libexec/kennel/host-dbus` (retired by 0.6.0 W4) still sits on upgraded hosts from the
pre-W4 install. The fix is manifest-driven: the staged tree *is* the manifest; on install,
anything in the managed vendor/libexec directories that the incoming payload does not ship (and
that the installer's own records placed) is removed, named in the output. `/etc` is never touched
by this — host config is the admin's.

**The `/etc`-binds trap (promoted from drafting).** Exposing an `/etc` subtree into a view
requires **both** an `fs.read` grant and an etc-binds catalogue entry (the
`essential_etc_subtrees()` floor plus the additive `etc-binds.catalog` cascade); miss either and
the subtree silently fails to appear — a policy author's dead end diagnosable only by knowing the
mechanism. Take the closer look first: read the view-construction path and decide whether the fix
is a **diagnostic** (compile- or spawn-time: "`/etc/foo` is granted but not bindable — no
catalogue entry") or a **unification** (one of the two derives from the other). Decided by
reading, not assumed; the trap dies either way — a granted-but-uncatalogued subtree is never
silent again.

**Exit:** an upgrade over a host carrying a retired binary removes it and says so; a fresh install
is byte-identical to an upgraded one in the managed directories; `install.sh --dry-run` shows the
would-remove set; the `/etc`-binds closer-look is recorded and its chosen fix ships — an
`fs.read`-granted `/etc` subtree with no catalogue entry produces a naming diagnostic (or the
distinction is unified away).

### W8 · UDP synthetic-pool per-grant rotation

**[quality] S–M. From the backlog (parked 2026-07-08, W8 hardening).**

The `MAX_PER_GRANT` (32) mint cap is tight on exfil but breaks a legitimate app that fans out to
more than 32 subdomains of one granted domain over its life. Promote the cap to a **rotating
window** — evict the oldest/least-recently-used mint past the cap, so the bound becomes 32
*concurrent* rather than 32 *ever*. The known catch is the whole workstream: `shim::Pool` does not
know which mints have live flows (`FlowTable`, in `serve.rs`, does), so eviction must coordinate —
evict only inactive mints, or tear the flow down on eviction, never silently break a live flow.

**Exit:** a >32-subdomain fan-out under one grant keeps working across the window; the concurrent
bound holds under the flow-spray case; no live flow is broken by eviction (e2e-asserted); the
threat note records the loosened-but-bounded exfil surface.

### W10 · `kennel-compose` gains the `[net.udp]` capability question

**[debt] XS. Owed from the 0.6.0 retirement sweep.**

0.6.0 W2's exit recorded the compose capability question as landed with Part A; the tree says
otherwise — `kennel-compose`'s network dialogue asks only the TCP leg (a proxy grant, port 443)
and `udp` appears nowhere in the crate. The dialogue gains the UDP leg: granted names + ports
minting `[[net.udp.allow]]` deltas with a `reason`, the same shape as the proxy leg beside it.

**Exit:** compose can author a `[net.udp]` grant; the emitted leaf compiles and runs the
`net-udp` suite case's shape; the compose walkthrough names it.

### W9 · Pre-ship pass: the ceremonies are not enforcement points

**[security, ship-gate] S. After W1–W4 and W6; blocks the tag.**

Done right, nothing in this release touches the trust base or the integrity of confinement:
every new verb operates at the authority its invoker already holds, and enforcement stays exactly
where it lives today — kenneld's signature verification against the trust store, the compiler's
`reserved_authority` gate, and filesystem permission on the tier directories. The clone authority
gate, install's tier routing, and every instructive refusal are **courtesies layered over that
enforcement, never the enforcement itself**. The pass verifies the property held through the
build, one surface at a time: bypass each CLI check by hand — place a reserved-name source
directly, hand-craft an install into the wrong tier, drive `--force` through every refusal — and
confirm the authoritative gate behind it still refuses: the artefact does not verify, the compile
does not sign, the write needs privilege the caller lacks. The v5 composition rule gets the same
treatment from the schema side: a crafted artefact attempting to compose a floor away fails at
the compiler, not at a CLI nicety. Any place a ceremony turns out to be load-bearing — where the
CLI check is the only thing standing — is a finding, and the fix is always moving the enforcement
down, never hardening the courtesy.

**Exit:** every new surface has a recorded bypass check confirming the authoritative gate behind
it; any load-bearing courtesy found is fixed by moving enforcement down before the tag; the audit
note is committed under `audits/`.

## Sequencing

```
W0 (contract verification) ── S,  first: V1→W3/W4, V2/V3→W1/W2 ───────────────────►
W1 (run strips to settled) ── S–M, the anchor; after V2/V3 ───────────────────────►
W2 (policy/template split) ── S,  with or right after W1 (one CLI-surface story) ─►
W3 (clone + install)       ── M,  after W2 (verbs land in their houses) + V1 ─────►
W4 (key house)             ── M,  after V1; ships whole, rotate included ─────────►
W5 (version verb)          ── XS, independent ────────────────────────────────────►
W6 (schema v5 pass)        ── M,  independent of the CLI train; owns the bump ────►
W7 (installer manifest)    ── S,  independent ────────────────────────────────────►
W8 (UDP pool rotation)     ── S–M, independent ───────────────────────────────────►
W10 (compose udp question) ── XS, independent ────────────────────────────────────►
W9 (enforcement-point pass)── S,  after W1–W4 + W6; ship gate ────────────────────►
```

W0 opens; V1 is the only result that can reshape a design (the install/clone re-sign ceremony and
the no-user-trust-list claim). The CLI train (W1→W2→W3) is sequential — the houses must exist
before the ceremonies land in them — and W4 joins after V1. W6 is the long pole outside the train
and can run in parallel throughout. W5/W7/W8 slot against capacity. W9 blocks the tag.

The release makes **one** settled-schema change (W6, v5); the CLI train touches no schema. All
retired spellings (`keygen`, `sign-template`, source-accepting `run`) answer with pointer
diagnostics for this release rather than vanishing silently.

## Exit criteria

0.7.0 ships when:

- Every W0 item has a recorded result and V1's answer is reflected in the shipped ceremony design (W0).
- `run`/`oci run` accept only a settled-artefact name from the three policy repos; compile-side
  flags are gone from the run path; wrong-object refusals name the object and next step; the policy
  suite passes through the narrowed form (W1).
- The `policy`/`template` houses exist as specified; retired spellings answer with pointers; the
  derived man pages reflect the split (W2).
- A received `.toml` is runnable in two commands at user tier and (as root) host tier; a
  same-name clone shadows user-first with the tier named at every use surface; clone and
  user-tier install refuse any object carrying a reserved claim — renaming is no escape — with
  the compiler's own diagnostic; no ceremony copies a settled artefact or lock (W3).
- The key house ships whole and tier-bound: no cross-tier signing path exists; `untrust` reports
  impact before acting; `key list` answers the inventory question in one command; rotation leaves
  every owned object verifying under the successor key, re-pin cascade included (W4).
- `kennel version` reports the whole-stack skew set in one invocation (W5).
- Schema v5: list-field composition is uniform-by-rule and documented in one place; the silent
  floor-drop class is closed for covered fields; the listen-key split is collapsed; the v5 pin,
  the variance-rule floor determination with its per-field receipts, and the CHANGELOG ABI note
  land together (W6).
- An upgrade removes payload the release no longer ships, and says so; an `fs.read`-granted `/etc`
  subtree with no catalogue entry is never silent (W7).
- A >32-fan-out under one UDP grant works within the rotating window with no live-flow breakage
  and the concurrent bound intact (W8).
- `kennel-compose` can author a `[net.udp]` grant and the emitted leaf compiles (W10).
- Every new ceremony has a recorded bypass check proving the authoritative gate behind it holds;
  any load-bearing courtesy is fixed by moving enforcement down before the tag (W9).

CHANGELOG records every stable-surface change: the run-verb narrowing, the house split and every
retired spelling with its pointer, the new `clone`/`install`/`key` verbs, `kennel version`, the
schema v5 composition rule + listen-key collapse (ABI note included), the installer manifest
behaviour, and the UDP rotating window.

## Parked work

Items with no timeline — declined-on-principle, promote-on-demand candidates, and work fenced to a
later release — live in [BACKLOG.md](BACKLOG.md), not here. Notable fences this cycle: kenneld
restart-fork resolution is the presumptive **0.8.0 structural bet**; multi-operator delegation
stays design-gated. (The `/etc`-binds trap, raised during drafting, was promoted into W7 rather
than parked.)
