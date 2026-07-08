# W0 · Front-matter verification — the contracts the 0.7.0 reshape rests on

Date: 2026-07-08 · Status: complete — V1 GREEN, V2 GREEN (fix list), V3 RED (consequence
applied to W1: the suite moves to the verbatim operator flow before the hybrid strip)
([ROADMAP-0.7.0.md](../ROADMAP-0.7.0.md) W0). Each item is read from the tree, not reasoned
about; each names its consequence for the dependent workstream.

## V1 — The tier-inclusive verification contract (gates W3, W4)

**Ruling under test:** an artefact at a level verifies under a key from its own level or any
level above it — user under {user, host, vendor}; host under {host, vendor}; vendor under the
maintainer key alone. Downward copies just work; a lower-tier signature never carries upward.

**Verdict: GREEN — the contract holds as-built.** With one nuance the W3/W4 designs must carry
(below).

**Receipts:**

- **Spawn-time trust set** (`kenneld/src/policy.rs`, `kenneld/src/bin/kenneld.rs:51-65`): the
  production loader is `TrustStoreLoader::from_trust_dirs(vendor, [admin, user], …)` — the vendor
  dir `/usr/lib/kennel/keys` loaded **first and unshadowable** (an id clash resolves to the
  earlier dir: `policy.rs::load_dir_into`, "an earlier dir already defined this id; do not
  shadow"), then the admin trust dir (`Deployment::trust_dir()`, `/etc/kennel/keys`), then the
  calling user's `~/.config/kennel/keys` (`user_key_dir()`). Dirs are re-read on **every** load —
  a `keygen`/trust edit takes effect with no daemon restart.
- **Verification is placement-blind** (`kennel-lib-policy/src/lib.rs::verify_settled_signed`):
  bytes + KeySet only; nothing consults where the artefact sits.
- **Compile-time template trust is system-only** (`kenneld/src/policy.rs` module doc, `07-paths`
  trust split): a settled *run* policy may be signed by a system key or the calling user's own;
  **templates** — the security baseline — verify against system keys alone, at compile, never at
  spawn.
- **The reserved gate is tier-aware and compile-time-sole**
  (`kennel-lib-compile/src/compile.rs:136-163`, `reserved_authority`): `org.projectkennel.*`
  claimable only through a vendor-tier template, a host `[[reserved]]` name only through a
  host-tier one, *any* key at the required tier equivalent; "this is the sole authorizer: there
  is no runtime re-check (the daemon trusts the settled signature it verifies)."

**How the ruling emerges** (the nuance): the daemon never consults placement. Tier-inclusive
acceptance is **emergent** from three mechanisms, each verified above:

1. *Downward works:* vendor and host public keys are in **every** user daemon's trust set, so a
   vendor-/host-signed artefact verifies wherever it is placed — a downward copy needs no
   ceremony.
2. *Upward is structurally void:* a user's key is loaded **only** by that user's own per-user
   daemon. A user-signed artefact placed at host tier verifies for its signer alone (harmless —
   a leaf runs at the user's own authority; its key grants no escalation) and is noise to every
   other principal. Meaningful host-tier placement therefore requires a host/vendor signature —
   not because the verifier checks, but because nothing else trusts it.
3. *The floors are compile-gated:* template trust is system-only and reserved-namespace claims
   are tier-checked at compile — a user key categorically cannot mint either, at any placement.

**Consequences applied:**

- **W3 (`install`/`clone`)**: the design's re-sign ceremony is confirmed — re-signing under the
  invoking tier's key is exactly what makes a received object verify, and no user-tier trust
  list exists or is needed. The ceremonies must NOT assume the daemon polices placement; the
  authoritative gates behind the courtesies are the three mechanisms above (this is also the
  W9 bypass-check list for these surfaces).
- **W4 (`key` house)**: `key list`/`show`'s "trusted" answer is the union the daemon loads
  (vendor ∪ admin ∪ own, first-dir-wins). Bonus receipt: first-dir-wins means a user key named
  `kennel-host.pub` (or `kennel-maint-2026.pub`) **cannot shadow** the real one — `key generate`
  refusing a tier-colliding id is a courtesy on top of standing enforcement, per the W9 rule.

## V2 — The refusal inventory (feeds W1, W2)

**Verdict: GREEN with a concrete fix list.** The verb dispatch was verified against every
diagnostic that names a next step. One drift class accounts for every stale pointer: the
top-level spelling of verbs that live under `policy` (`kennel compile` / `kennel validate` do
not exist).

**Stale, user-facing (the W1/W2 sweep list):**

1. `kennel-cli/src/shared.rs:158` — `resolve_policy`'s not-found error: "compile one with
   `kennel compile`" → `kennel policy compile`. (The known receipt.)
2. `kennel-cli/src/policy.rs:118` — `policy compile`'s own usage string says
   "usage: kennel compile …" — and also drifts from the canonical usage in
   `kennel-lib-cli` (missing `--key-id/--require-signed/--no-lock/--trust-dir`). Sibling verbs
   (risks/diff/sign-template) spell themselves correctly.
3. `kennel-cli/src/policy.rs:414` — `policy validate`'s usage says "usage: kennel validate …".
4. `kennel-cli/src/misc.rs:114` — the `keygen` success blurb points at "kennel compile <name>"
   (the `kennel run <name>` line beside it is correct).

**Stale, comments only (same drift, fix in the same sweep):** `policy.rs:23`, `policy.rs:66`,
`policy.rs:383`, `run.rs:30`.

**Missing next-step where one obviously exists:** `kennel-compose/src/main.rs:460` — after
writing a leaf source policy it prints only "wrote {path}", with no pointer at
`kennel policy compile` (every other leaf-producing path names it). One line; rides the sweep
(and W10's revisit re-reads the whole dialogue later regardless).

**Verified CORRECT (spot inventory, no action):** the `sign` → `compile`/`sign-template`
redirect; every `oci` pointer (`oci build`/`oci run`/`policy compile`); the `attach`/`review`/
`stop`/`list`/`daemon-reload` pointers; `keygen` usage + `--key` hints; the `keygen migrate`
mentions are deliberate removed-in-0.6.0 historical redirects, not stale next-steps.

**Consequence applied:** the W1/W2 instructive-refusal sweep works from this list — four
user-facing fixes, four comment fixes, one compose pointer — rather than grep-as-you-go; the
usage-string drift in item 2 is additional evidence for W2's derive-don't-hand-write posture
(the canonical usage already lives in `kennel-lib-cli`; hand-copies of it drifted).

## V3 — The `run` acceptance inventory (feeds W1)

**Verdict: RED (consequence named and applied to W1).** The acceptance surface is wider than the
target contract, and — the load-bearing finding — **the settled pass-through, the only path that
survives the W1 strip, has zero e2e coverage today.**

**The acceptance matrix as-built** (`kennel-cli/src/run.rs:64-99`, `shared.rs:128-160`):

- `<policy>` is a **literal path** if one exists at that string (`shared.rs:130`), else a **name**
  resolved through the three policy repos (`~/.config`, `/etc`, `/usr/lib` — nested layout only:
  `<dir>/<name>/<name>.settled.toml` then `<dir>/<name>/policy.toml`, settled preferred;
  `shared.rs:138-155`). There is no flat-layout probe on the run path.
- A resolved **source** policy triggers the in-memory compile+sign hybrid (`run.rs:147-200`):
  `is_source_policy` → `build_settled` → sign with `--key` or `default_signing_key()` →
  `TempSettled` temp artefact. This is what drags `--key`/`--key-id`/`--template-dir`/
  `--trust-dir` onto the verb. A resolved **settled** artefact passes straight through with no
  key (`run.rs:201-204`).
- `[rootfs]` under plain `run` is refused toward `oci run` (`run.rs:216-220`). `oci run` resolves
  its policy from the store path only (`oci.rs:1237`, `<store>/<name>/policy.toml` — source, so
  it takes the same hybrid path) and shares `run::launch`; it accepts `--key`/`--force` but not
  `--template-dir`/`--trust-dir`/`--key-id`.

**Coverage as-built** (`src/tools/policy-e2e.sh:253-255`): every non-hook suite case invokes
exactly one form — `kennel run <literal path to policy.toml> <name> --key <suite key>
--trust-dir <dir>` — i.e. **always** the literal-path + source-compile hybrid. Both `oci run`
hook cases likewise compile store source with `--key`. Zero coverage exists for: run-by-name
through the repos, the settled pass-through, `--force`, `--key-id`, `--template-dir`,
key auto-select, name defaulting, and the `[rootfs]`-refusal diagnostic.

**Consequence applied to W1 (ruling, 2026-07-08): the e2e eats the dogfood — no CLI shortcuts,
no special verbs, no test-only flags.** The suite is already self-hosting at the daemon level
(it drives the real `kenneld`, real spawns); this finding shows it is NOT self-hosting at the
CLI level — it types things no operator types (a literal path to source, `--key`/`--trust-dir`
on `run`). The strip therefore cannot be code-first. Sequenced inside W1:

1. Re-point `policy-e2e.sh` to the **operator's golden path, verbatim**: `kennel keygen` (the
   suite key into the user keydir — auto-trusted per V1), `kennel policy compile <case>` (the
   default cascade: installed templates verifying against installed vendor/host keys — no
   `--trust-dir`, no `--template-dir`), `kennel run <name>` (the settled artefact, by name, from
   the user repo). Every flag the quickstart wouldn't use is a smell. This gives the production
   path its first end-to-end coverage *before* the hybrid is removed.
2. Remove the hybrid and the compile-side flags from `run`.
3. The suite now exercises exactly — and only — the surface that ships, in the form it ships.

`oci run`'s store-source compile is part of the same strip: post-W1 the store entry must hold
(or gain at `build`) a compiled artefact rather than compiling source at run time — folded into
W1's design, decided against the store layout, not improvised.
