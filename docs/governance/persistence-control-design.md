# W1/W2 persistence control — design pass

Status: **BUILT + e2e-verified (2026-06-18)** · Graduated to THREATS T2.8 (mitigation rewritten to
the three-limb pin / live tripwire / restore form, plus the `[fs.write].exclusive` channel-sever).
W1 (manifest v2 + content store + catalogue + `review --revert` + `.d` mask), W2 (inotify tripwire +
`[trust].on_change` + `fs.mutation` audit + escaping-symlink pins), and the exclusive over-mount
(factory-folded, ownership-gated, `kennel release` recovery) are all shipped. This doc is retained
as the design rationale + the maintainer steers (§4) behind the corpus entry.

> The critical-path item. This pass did the design settled from the code + the review, ending with
> the steers (§4) that were the maintainer's call — all now resolved and built.

## 0. What already exists (the foundation — bigger than the roadmap implied)

W1/W2 is **not greenfield**; it extends the shipped trust-manifest mechanism.

- **`kennel-lib-manifest`** (CLI-side, host-only, `kenneld` never links it — out of TCB):
  `KNOWN_TRIGGERS` (`Makefile`, `package.json`, `.vscode/tasks.json`/`launch.json`, …) +
  `KNOWN_TRIGGER_DIRS` (`.git/hooks`); `enumerate_triggers(root)`; `hash_file` (via system
  `sha256sum`, no in-crate crypto); `generate(root)` → `Manifest`; `review(manifest, root)` →
  `Vec<TriggerChange>`; `apply_review` (re-pin).
- **The manifest schema** (`docs/schemas/trust-manifest-v2.json`, v2.0 — W1 bumped it from v1.0): `execution.triggers`
  (relative-path → `sha256:…`) + `execution.boundaries.untrusted_paths` (no-exec globs).
- **Masking is already per-writable-bind** (`kennel-lib-spawn` `lib.rs:492`, `plan.rs:922`): each
  `<writable-bind>/.trust-manifest.json` is over-mounted with an empty RO file from the tmpfs
  scaffold — the workload sees neither the pins nor (the key bit) can a workload write *reach the
  host inode*: its writes land in the ephemeral over-mount.
- **`kennel review <policy> [--yes]`** exists: review + re-pin after legitimate edits.
- **The persist model** distinguishes the surface: `fs.write` paths resolve to **persistent** host
  inodes; the constructed `$HOME` is **ephemeral tmpfs** unless `[fs.home].persist`. A `[trust]`
  policy section already gates this (`[trust].manifest = false`).

**What's detect-only today:** the manifest pins *hashes*; a host IDE (or `kennel review`) notices a
hash diverged from its pin and drops to Restricted Mode / asks the operator to re-pin. There is no
stored content, no restore, and `kenneld` does nothing at runtime.

## 1. The delta W1/W2 adds (detect-only → pin / diff / restore + live tripwire)

1. **A content store** `.trust-manifest.d/<sha256>` — the pinned *blobs*, content-addressed. The
   manifest is the index (path → hash); the `.d` store is the bytes. Needed for two things the hash
   alone can't do: **show** the diff (not just "hash changed") and **restore** (revert).
2. **`revert`** — a teardown disposition that copies the pinned blob back.
3. **The `on_change` live tripwire** — `kenneld` watches the trigger paths during the run and acts on
   the *workload* (warn / freeze / kill). New; today `kenneld` is uninvolved.
4. **Escaping-symlink pins (W2)** — a symlink inside a writable bind pointing outside the delegation
   boundary is a trigger class: pin its target, flag/revert a planted one.
5. **A versioned trigger catalogue** — promote the hardcoded `KNOWN_TRIGGERS`/`_DIRS` consts to
   `dist/vendor/triggers.catalog` (like `dist/threats/catalogue.toml`), versioned + CI-checked, and
   widen the set.
6. **Per-workload-class dispositions** — `on_change` + teardown disposition as policy enums.
7. **Scope to persistent writable binds** — the ephemeral tmpfs home can't carry a trigger to the
   next run, so it's out of scope by construction.
8. **Exclusive host bind** (opt-in, §2.7) — `[fs.write].exclusive` over-mounts a sentinel on the
   *host* path for the run, severing the **live confused-deputy channel** (T2.8 residuals 1 + 2) that
   the enumerated manifest leaves open. Mandatory crash-leak recovery path.

## 2. Mechanism

### 2.1 Store + schema (bump to manifest v2)
The v1 schema pins only hashes. v2 carries, per trigger, what diff/restore/symlink need:

```
execution.triggers["<rel-path>"] = {
  kind:    "content" | "symlink",
  sha256:  "sha256:…",        # content kind: hash of the blob in .d/
  target:  "<path>",          # symlink kind: the pinned link target (the escape)
  mode:    "0644",            # mode bits (setuid/setgid/sticky are security-relevant; never lost)
  pattern: "<catalogue-id>",  # which catalogue entry matched (provenance)
  pinned:  "<rfc3339>"        # when/by-what (compile pin vs review re-pin)
}
```
The blob bytes live at `<writable-bind>/.trust-manifest.d/<sha256>` (content-addressed ⇒ dedup;
mode `0700`, operator-owned). `review` diffs the live path against `.d/<pinned-sha>`; `revert`
copies it back (and for a `symlink` kind, restores the link target / removes a planted link).

### 2.2 Lifecycle (host-side; the workload is never in the loop; pins are explicit — no TOFU)
- **Pin — explicit operator step** (`kennel compile` / `kennel review`, host-side, outside any
  kennel): for each *persistent* writable bind, enumerate catalogue triggers and pin them (blob →
  `.d`, entry → index). Escaping symlinks pinned + **warned loudly**. This is the **only** path that
  writes the store. The manifest is settled config, like the signed policy.
- **Verify — `kennel run` prep, fail-closed** (before the kennel namespace exists): every
  catalogue-matching file in the persistent writable binds must be pinned **and** matching. An
  unpinned catalogue file, or a divergent pin, is a **failed settled config** → refuse, direct to
  `kennel review`. `kennel run` never pins (§4.5). A run thus starts from a verified-complete surface.
- **Run — `kenneld` live tripwire** (§2.4): writes to the (clean-at-start) trigger surface are the
  workload's.
- **Teardown — authoritative diff** (CLI, full catalogue): new catalogue-matching paths and divergent
  pins are the workload's changes this run (clean attribution, because the start was verified);
  disposition applied. `kennel review` inspects + re-pins (the explicit re-bless).

### 2.3 Masking (extend the existing over-mount)
Over-mount **both** `.trust-manifest.json` (already done) **and** `.trust-manifest.d/` (new) per
persistent writable bind — an empty RO dir over the `.d` path so it's invisible to `readdir` and a
workload `mkdir .trust-manifest.d` / colliding `<sha256>` write lands in the ephemeral over-mount,
never the host store. The host reads/writes the real store outside the view. **Trust by content
address, never by the workload-visible listing.**

### 2.4 The tripwire (`kenneld`, TCB-minimal — no manifest crate in the daemon)
The `Plan` carries three things, all computed CLI/prep-side: the **watch set** (pinned trigger paths
+ the catalogue *dir* globs like `.git/hooks` so newly-created triggers are caught), the
**`on_change` disposition**, and nothing else. `kenneld` inotify-watches those paths under the
persistent writable binds (host inodes, operator context — **unprivileged**, notify-only) and reuses
the existing TTL `cgroup.freeze`/`cgroup.kill` plumbing. It needs **no** catalogue logic and **not**
`kennel-lib-manifest` — just a path list + inotify + the cgroup it already controls. The live watch
is **best-effort** (overflow / new-dir races); the teardown review (full catalogue) is the
authoritative backstop, so a missed event is still caught at the door.

### 2.5 Dispositions (two enums, parallel to `ttl_action`)
Build **all** the primitives (the maintainer's priority — the per-class defaults are a convenience
on top of built primitives, not the deliverable).
- **`on_change`** (live, `kenneld`): `warn` (audit `fs.mutation`) / `freeze` (suspend cgroup,
  operator decides) / `kill` (terminate). Unprivileged.
- **teardown** (host-side, `review`): `warn` (report) / `interactive` (prompt) / `revert`
  (restore-from-pin). **`revert` is scoped to the trigger paths** — it restores a planted hook and
  *keeps the rest of the tree* — so it's clean for classes that don't legitimately edit triggers and
  unusable for those that do (see §3).
- **`interactive` is in 0.2.0** (steer 1): it rides the **operator-prompt channel** built for the
  TTL `renew` prompt, pulled into this release (ROADMAP W13) — the kenneld→attached-CLI prompt path
  the daemon lacks today. One channel serves both the TTL renew prompt and `interactive` teardown.

### 2.6 The catalogue — an **additive** layered config, no compiled default (steer 3, revised)
A **deployment config** on the project's standard config cascade ([[no-hardcoded-paths-config-cascade]]),
composed **additively** (union, not replace — like the SSH `+=`/`-=` model
[[compiler-list-composition-ssh-model]]):

> effective catalogue = `/usr/lib/kennel/triggers.catalog` (vendor, the package default)
> **∪** `/etc/kennel/triggers.catalog` (admin) **∪** `~/.config/kennel/triggers.catalog` (user)

**There is no compiled-in default.** A baked-in trigger list is a footgun: the operator cannot see
or fully control what is watched by reading the config, and can only *subtract* the invisible default
with `-pattern`. So the default trigger set ships as the **vendor** layer file (the lowest-priority,
package-shipped, read-only layer — the same place every other shipped default lives), and the effective
set is exactly what the cascade files say. Line-oriented: one trigger pattern per line (`#` comments);
each higher layer **adds** patterns, or **removes** one a lower layer set with a leading `-` (the only
subtractive op). A trailing `/` marks a directory trigger. Loaded by `kennel-lib-manifest` (the daemon
links none of this — it receives a resolved path list, §2.4).
- **The shipped vendor default is conservative**: `Makefile`/`makefile`/`GNUmakefile`, the `Just`/`Task`
  runners, `package.json`, the `.vscode` task/launch defs, and the `.git/hooks/` directory. `/etc/kennel`
  widens system-wide; `~/.config` widens or prunes per-user. Noisier patterns (`.envrc`, `.npmrc`,
  `.pth`/`sitecustomize`, `.desktop`) ship as commented lines in the vendor file, to add, not defaults.
- **Weakening is explicit, via `-pattern` only** (no "empty file = off"; additive means an empty user
  file changes nothing). The operator is the trust root (§11.2), so pruning is fine — and a *workload*
  cannot reach these host files. A **hard disable** is the existing `[trust].manifest = false` toggle.
- **An empty catalogue watches nothing** — and because there is no hidden default, a missing vendor
  file would silently disable T2.8. So the CLI **warns loudly** when `[trust].manifest = on` resolves an
  empty catalogue (a deployment fault), rather than failing closed or pretending coverage.
- Documented as **"detects this configured set, never *clean*"** — the boundary is stated, not implied.

### 2.7 Exclusive host bind (`[fs.write].exclusive`) — severing the live confused-deputy channel (opt-in)
An **opt-in** per-bind flag (`[fs.write].exclusive`, default **off**, persistent writable binds
only): for the duration of a run a writable host path is usable by **either** the operator **or** the
kennel, never both concurrently.

**Mechanism.** After the kennel view is constructed (the real host path already bound into the
kennel's rec-private mount NS), a **transient privhelper op** over-mounts an opaque sentinel dir on
the *host* path — not silently empty but a marker (`IN USE by kennel <id> since <ts> — released at
teardown`). Kennel views are `MS_PRIVATE`/rec-private, so the *later* host over-mount does not
propagate in: the workload keeps the real inode, the operator sees the sentinel. A second transient
privhelper op `umount`s it at teardown. No process holds a capability ([[no-standing-host-privilege]]
intact — both are discrete validated ops that exit); the *mount state* persists for the lifetime,
which is why recovery (below) is mandatory.

**What it closes — T2.8 residuals (1) and (2), for the run's duration.** The masked manifest (§0) is
precise but honest about two gaps (THREATS T2.8 *Residuals*): it defends only **enumerated** triggers,
and it **relies on host tooling / the human honouring** the pin (a user who runs `make` by hand, or
acts on a planted `install.sh`, is unprotected). Both are the **confused-deputy** shape: the operator
— full host authority, the trust root (§11.2) — is induced to wield that authority on content the
*workload* planted in the shared tree. `exclusive` severs the **channel** instead of enumerating its
contents: while the kennel holds the path the operator has no view of it, so there is nothing to be
socially induced to run and nothing concurrently-open to be tampered mid-edit. The operator only ever
sees the **post-teardown, post-review** state (manifest diff + disposition already applied).

**Not theatre** ([[no-security-theatre]]): the adversary is the **workload** (in-model, T2.8 family),
the asset is the **operator's unconfined host authority**, and the control denies the workload a
*channel to weaponize the trust root* — it does **not** defend owner-only state *against* the trust
root (which would be incoherent, the theatre shape). Distinct from the manifest, not redundant:
manifest = precise / enumerated / post-hoc detection + revert + host-IDE Restricted Mode; `exclusive`
= coarse / enumeration-free / cooperation-free / **live**. They compose — `exclusive` closes the
run-window the manifest leaves open; the manifest handles the post-run state `exclusive` then reveals.

**Caveats (the real cost, stated):**
- **Host mount-NS mutation, session-global.** The over-mount lives in the operator's host mount
  namespace — it hides the path from the IDE and every host process (the point), but it is a new
  privhelper op surface.
- **Crash-leak ⇒ operator lockout.** If kenneld / privhelper dies mid-run the sentinel persists and
  the operator is locked out of their own path until cleared. **Mandatory recovery path**, part of
  the same slice: a teardown-sweep on daemon restart **+** an explicit `kennel release <id>` unmount
  command. Ships *with* the feature or the feature does not ship.
- **Scope = persistent writable binds only.** The constructed `$HOME` is ephemeral tmpfs, already
  private to the kennel (no host inode), so `exclusive` is meaningless there — consistent with the
  rest of W1/W2's scope (§1.7, §3).

**Small decisions left:** sentinel content/format; whether to also offer a read-only "operator may
look but not write" middle mode (lean **no** — two states only, keep it legible).

## 3. Decisions taken in this pass (rationale; confirm if you disagree)

- **`revert` is scoped to trigger paths, not the whole tree.** It restores pinned triggers to
  baseline and leaves everything else. This is *why* `revert` is clean for `inspect-only` /
  `untrusted-build` (they shouldn't be editing triggers) and unusable for `ai-coding` (which
  legitimately edits `package.json`/`Makefile` — reverting clobbers the work). The review's "for
  ai-coding revert is unusable" is exactly this overlap; stated in the doc, not papered over.
- **Explicit pins only; no TOFU; `kennel run` verifies fail-closed** (steer 5). Pins are written only
  by `kennel compile`/`kennel review`; `kennel run` refuses to start if any catalogue-matching file in
  the persistent writable binds is unpinned or divergent ("failed settled config"). The manifest is a
  settled, complete precondition — which buys clean workload-attribution at teardown (§4.5).
- **Watch = catalogue *dirs* + pinned paths; review = full catalogue, authoritative.** Live is
  best-effort, teardown is the verdict — consistent with the snapshot-authoritative decision.
- **Scope = persistent writable binds only.** Ephemeral tmpfs home can't persist a trigger across
  runs, so it's out by construction (and stated as the boundary).
- **`.d` store is GC'd at manifest-write** (steer 6): whenever the index is (re)generated (run-prep
  pin or `review` re-pin), prune any `.d/<sha>` blob no longer referenced by the index. The store
  holds exactly the current trusted-baseline's blobs — bounded, no unreferenced accumulation, no
  prior-state history. Simpler and self-limiting.
- **On by default for persistent writable binds** (steer 4). The catalogue is **additive** (§2.6), so
  there's no "empty file = off"; weakening is explicit `-pattern` pruning, and a **hard disable** is
  the existing `[trust].manifest = false` toggle.
- **Manifest schema bumps to v2** (steer 7 — richer per-trigger metadata + symlink kind + blob refs).
  A stable-surface change ⇒ CHANGELOG `### Policy schema changes`; pre-1.0, so no compat shim.

## 4. Steers — resolved (2026-06-18)

1. **`interactive` is in 0.2.0**; build the TTL `renew` prompt's operator-prompt channel and reuse it
   (ROADMAP W13). `ai-coding` teardown default stays `warn`, but `interactive` is an available
   primitive. *(Priority: all disposition primitives built; defaults are convenience — steer 2.)*
2. **Per-class default matrix confirmed:** `inspect-only`/`untrusted-build`/`package-install` =
   `freeze` + `revert`; `ai-coding`/`containerised-service` = `warn` + `warn`.
3. **Catalogue is an *additive* layered config** (compiled default ∪ `/etc/kennel` ∪ `~/.config`),
   line-oriented, `-pattern` to prune; conservative default (§2.6).
4. **On by default**; weakening is `-pattern`, hard disable is the `[trust].manifest` toggle (no
   "empty file = off" under additive composition).
5. **Pin timing — explicit only, never `kennel run`. No TOFU** (§4.5).
6. **GC the `.d` store at manifest-write** (§3).
7. **Schema bumps to v2.**

### 4.5 Pin timing — explicit, fail-closed; the manifest is a settled precondition

**Pins are established *only* by an explicit operator step — `kennel compile` / `kennel review` —
never at `kennel run`.** There is **no TOFU**. The manifest is settled config, the same way the
signed policy is:

- **`kennel run` is a fail-closed verifier, not a pinner.** At prep, it scans the persistent writable
  binds; every catalogue-matching file must be **in the manifest and matching its pin**. A
  catalogue-matching file that is **not** in the manifest is a **failed settled config** — `kennel
  run` refuses and directs the operator to `kennel review`. A pinned file whose content diverged is
  the same: stale config → review. So a run only ever starts from a **verified-complete, matching**
  trigger surface.
- **The payoff — clean attribution.** Because the surface is verified complete-and-matching *at the
  start*, anything at teardown that is new (a catalogue-matching path absent from the manifest) or
  divergent (a pinned path whose content changed) was produced **by the workload during this run** —
  no conflation with operator between-run edits. The `on_change` tripwire and the teardown diff both
  attribute cleanly.
- **Re-pin is the same explicit step.** Operator edits a trigger → `kennel run` fails closed until
  they `kennel review` to re-bless (or revert). A workload can never launder its tampering into the
  baseline — only `compile`/`review`, host-side, outside any kennel, writes the store.
- **Cost, stated:** a new trigger surface (fresh repo with a `Makefile`) requires one `kennel review`
  before the first run. Deliberate, fail-closed, one-time-per-new-trigger — the project's
  explicit-over-implicit stance, not silent first-use trust.

## 5. Build shape (once steered — tests-first, §7.3)

- **kennel-lib-manifest** (out of TCB): catalogue loader (`dist/vendor/triggers.catalog`); schema v2
  types; `.d` store read/write; `generate` → pin blobs; `review` → diff-against-blob; `revert`.
- **kennel-lib-spawn**: extend the mask to the `.d` dir; the `Plan` gains the watch-set +
  `on_change` disposition fields.
- **kenneld**: the inotify tripwire (watch-set from the Plan, reuse cgroup freeze/kill); emit
  `fs.mutation` audit events.
- **policy schema**: `[trust]` gains the dispositions; per-template-class defaults.
- **CLI**: `kennel review` gains diff-show + `revert`.
- **policy-suite**: a case that plants a `.git/hooks/post-commit`, asserts `on_change` fires and
  `review`/`revert` restores.
