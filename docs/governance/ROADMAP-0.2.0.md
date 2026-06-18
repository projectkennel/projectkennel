# Project Kennel — 0.2.0 plan

Status: **proposal** (mix in revision) · Drafted: 2026-06-18 · Targets: 0.2.0
Baseline: 0.1.0 (first versioned cut, 2026-06-18)

> This is a planning artefact, not a design or as-built document. The design corpus
> (`docs/design/`) and the as-built notes (`docs/architecture/08-as-built-notes.md`
> §8.1) remain the source of truth for *what each item is*; this file records *what
> 0.2.0 commits to, why, and in what order*.

## Theme

**What the workload leaves behind, and how policy gets written.** 0.1.0 ships a working
reference runtime that confines a workload *while it runs*. 0.2.0 turns to the two
things 0.1 left open: what the workload can **leave behind** to fire later in the
unconfined shell (the T2.8 persistence family — the largest owed security control), and
the **authoring experience** that decides whether anyone writes good policy at all. One
new mediated surface (D-Bus) rides along, built to the TCB-contained facade pattern.

Standing constraints that shape the mix:

- **The TCB only shrinks** ([[tcb-only-shrinks]]). The binder cross-instance **MCP relay**
  grows `kenneld`'s trusted base; it is **deferred to 0.3**. D-Bus is included only
  because it is a *facade/host split* (below), not a parser in the daemon.
- **The workload never signs on the operator's behalf** (§11.2, settled axiom). The T2.8
  work is *inspection and revert*, never delegated trust.

## Workstreams

Sizes are rough: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week.

### Thrust 1 — Persistence safety (the flagship)

**What 0.1 already covers (the integrity floor).** The sha256 pin is a partial T2.8 mitigation
already shipped: `[workload].sha256` (an accepted-digest set, verified on the workload fd at
spawn — `server.rs`) and the lockfile-pinned template/fragment/include closure (`lock.rs`) both
**fail the next run closed** if their content was tampered with. So persistence that works by
mutating *pinned* content (the workload binary, the policy supply chain) is already caught. The
two gaps this thrust closes are exactly the ones pinning can't reach: **(1)** the classic trigger
is planted in the *writable* project tree (git hooks, `Makefile`, `.vscode` tasks) — writable by
design ⇒ unpinnable by design; and **(2)** it fires in the *unconfined shell*, not the next kennel
run, so the sha256 re-exec gate never sees it. Pinning is the integrity floor for read-only
content; W1/W2 is the layer for the writable-tree → unconfined-shell vector.

**Framing — look hard at how git does this.** Every compile and every teardown is
essentially a *commit* of the files inside the trust manifest. The design pass should
evaluate modelling the persistent writable tree as a git-like content-addressed snapshot:
**compile commits the baseline** (the known-good state + the manifested escaping symlinks),
**teardown commits/diffs against it** (what the workload added/changed), and **revert is
just `reset --hard` to the baseline**. If that model holds, the trust manifest, the
teardown diff (W1), the escaping-symlink removal (W2), and COW/revert all fall out of one
mechanism instead of three hand-rolled ones — and a reviewer reads the change as a diff
they already understand. The open question is whether to *use* git (a real repo/object
store per writable bind) or borrow the model (content-addressed snapshot, no git
dependency); the design pass decides.

**The watch layer — inotify/fanotify, complementary not authoritative.** A live filesystem
watch is tempting as *the* mechanism but cannot be: inotify is lossy where a security control
can't be — queue overflow (`IN_Q_OVERFLOW`) silently drops events, watches don't recurse (a
file created in a freshly-`mkdir`'d subtree before its watch is added is missed), and
mmap-write / rename-replace / hardlinks are seen unreliably. A snapshot diff has none of those
holes, so **the snapshot stays authoritative**; making a lossy watch the sole control is the
silent-coverage-gap [[no-security-theatre]] rejects. Where the watch *does* earn its place, as a
layer on top:
- **Live audit.** kenneld inotify-watches the host-side writable bind sources (**unprivileged** —
  notify-only needs no caps, and the sources are host inodes in the operator context) and emits
  `fs.mutation` events as the workload writes — real-time visibility into the audit stream.
- **Teardown-diff scoping.** The watch tells the snapshot diff *where* to look so teardown skips a
  full-tree rescan — with a **full-compare fallback on overflow** (dropped events ⇒ can't trust the
  scoping ⇒ fall back to the authoritative diff).
- **Live reaction — `on_change` = warn / freeze / kill (in 0.2.0, unprivileged).** A mutation to a
  *trigger-class* path during the run is a tripwire. inotify can't un-write the file, but kenneld
  can act on the **workload**: **warn** (audit only), **freeze** (suspend the kennel cgroup — reusing
  the TTL `cgroup.freeze` freeze-decide-thaw/kill plumbing: halt mid-sequence, preserve forensic
  state, let the operator decide), or **kill** (`cgroup.kill`, terminate the run). No new privilege —
  inotify needs no caps and kenneld already freezes/kills its delegated cgroup for TTL. This enforces
  against the *workload* (halt it), not the *file*; the teardown snapshot is the authoritative
  cleanup behind it, and **backs the watch when events are dropped** (overflow ⇒ a missed tripwire is
  still caught at teardown).
- **Write-*prevention* is OUT OF SCOPE (not deferred).** Stopping the write *itself* before it lands
  needs **fanotify permission events** (`FAN_*_PERM`), which require a process holding `CAP_SYS_ADMIN`
  and responding to perm events for the **whole kennel lifetime** — a *standing* privileged
  capability on the host. Project Kennel takes none: the only privileged surface is the privhelper,
  whose privilege is **transient** (one validated op, then exit), and the host delegates run
  unprivileged ([[no-standing-host-privilege]]). A lifetime-long privileged watcher is the very
  attack surface §4.6 set out not to add. So 0.2.0 (and beyond) **reacts-and-cleans** — inotify
  tripwire + teardown snapshot, both unprivileged — and never pre-blocks.

- **W1 · Post-run inspection of persistent writes (T2.8).** *(→ design §11.1)* **L.**
  At teardown, diff everything the workload wrote to persistent writable binds against the
  pre-run state and flag newly-introduced **execution triggers** — git hooks, `core.hooksPath`
  redirects, `Makefile`/`package.json` script entries, `.vscode`/`.idea` tasks — for operator
  review before the user next acts on the tree. Folded into one coherent `kennel review`
  surface with the commit-time review (T2.2), not a second tool.
  **Open questions to settle first (§11.1):** the canonical trigger-pattern set and how it
  stays current; cheap diff scoping over large trees; and — the decision that sizes the whole
  workstream — **block-at-teardown vs. acknowledge-able report** (see open decisions).

- **W2 · Boundary-escape symlinks — fold into W1's compile + teardown machinery.**
  *(→ [[vfs-bind-source-nofollow-owed]], reframed)* **M.** Not a standalone `openat2` runtime
  guard. A symlink inside a delegated writable subtree that points *outside* the delegation
  boundary is both a read-escape and a persistence vector, and it belongs to the same trust-
  manifest pipeline as W1:
  - **At compile:** enumerate the escaping symlinks that already exist in a delegated source,
    record them in the **trust manifest** (the known-good set), and **warn loudly** — an
    escaping symlink in a delegated tree is a footgun the operator should see.
  - **At teardown:** any escaping symlink *not* in the manifest was planted during the run —
    **remove it**.
  - **Revert falls out of the git model.** Under the snapshot framing above, reverting the whole
    writable tree at teardown (throwing away everything the workload did, planted symlinks
    included) is `reset --hard` to the compile-time baseline — a stronger control than per-trigger
    removal, and *free* if the git model is adopted rather than a separate COW overlay to build.

### Thrust 2 — A new mediated surface

- **W8 · D-Bus mediation — facade / host split.** *(→ design §7.7, `07-1-binder.md`, §8.1)* **L.**
  The binder successor to the never-built `xdg-dbus-proxy` design, built to the egress pattern:
  an **in-kennel facade** speaks the D-Bus protocol (untrusted parse, out of TCB) and brokers
  each method call across the binder gateway; **kenneld decides**; a **host-side delegate**
  performs the call. The host-side delegate **subscribes to D-Bus on the host and filters both
  inbound and outbound** with a small set of simple rules fed from kenneld — *much like the pty
  terminal-escape filter* (`kennel-lib-term`): a thin bidirectional content filter, not a complex
  per-method ACL engine. The configurable option space is small, so the policy is **fed from
  kenneld into the host side** rather than parsed in the daemon — TCB growth is a decision point,
  not a parser. Re-add the `[dbus]` config surface (removed from the schema in 0.1) as a *built*
  surface this time. Proven by a policy-suite case.

### Thrust 3 — Authoring experience

- **W9 · Composable fragment catalogue — with the framing that makes it usable.** *(→ design
  §5.10, §8.1)* **M.** The `include` mechanism is built; the gap is not content alone but the
  **framing** that makes fragments a shortcut people actually reach for — discoverability, how
  they compose without surprising the author, the convenience story in the docs and the CLI. Owed:
  that framing + the signed fragments (`lang-python`, `lang-node`, `toolchain-c`, `net-permissive`,
  `vcs-git`) + per-fragment tests.

- **W10 · IDE policy intellisense (VSCode extension).** *(new)* **M.** A VSCode/editor extension
  that gives policy-TOML authors completion, hover docs, and inline validation — derived from the
  **existing parser/enforcer schemas** (the `kennel-lib-compile` source structs / the
  `02-2-config-schema.md` reference), emitted as a machine schema the editor consumes. Lowers the
  authoring floor and pairs naturally with W9. Lives as a separate deliverable (an extension), not
  in the runtime crates.

### Thrust 4 — TCB hygiene

- **W11 · Move the terminal-escape filter out of the daemon TCB into the CLI.** *(→ §4.8,
  [[tcb-only-shrinks]])* **S–M.** Today `kenneld`'s PTY broker (`pty_broker.rs`) runs
  `kennel-lib-term` (the vendored `vte` ANSI parser) at the single master-read point — so an
  *untrusted-input parser* (it parses workload-controlled PTY bytes) runs inside the privileged
  daemon, the §4.8 anti-pattern, and its only consumer is the `kennel` CLI. Move the filter
  client-side: the broker becomes a **raw-byte router** (ring stores raw, reattach replays raw), and
  each terminal client filters on its way to the real terminal.
  **The real cut (vendored, not first-party):** `vte` (2,943 SLOC) + its sole dep `arrayvec` (1,314)
  leave the daemon — **~4,257 vendored SLOC** of in-process *parsing logic*, plus the 157 first-party
  of `kennel-lib-term`. (`arrayvec` is reached only via `vte`; `vte 0.15` folded `utf8parse` in.) It
  removes the daemon's **only parser of workload-controlled bytes** — `basic-toml` parses *signed*
  policy, the rest aren't parsers.
  **Cost (conscious):** the broker's documented *"no client can bypass the filter"* chokepoint
  becomes *"the official CLI filters; a raw consumer of the attach socket is a footgun"* — acceptable,
  since the workload can't choose the client, the core T2.6 threat (escapes → operator terminal) is
  fully handled CLI-side, and a raw client is the operator footgunning their own terminal
  ([[footgun-warn-dont-forbid]]). Rewrite the broker module doc's security claim to match. Stateful
  continuity holds client-side (filter the full received stream; a truncated escape at the ring head
  is incomplete ⇒ harmless). `kennel-lib-term`'s fuzz target is unaffected (the fuzz crate deps it
  directly).

- **W12 · Honest TCB accounting in the inventory.** *(→ `03-crate-decomposition.md`)* **S.** The
  crate inventory counts *first-party* SLOC only, which understates the real TCB ~13× — the trusted
  base is the vendored deps too (~215k vendored vs ~16k first-party). Upgrade the inventory's
  "Crate inventory and TCB" section to carry the **vendored dimension, split logic vs bindings**:
  - **logic** (runs in our process — the real attack surface): `object` ~36k, `serde`+`serde_core`
    ~19k, `ed25519-compact` ~3.7k, `seccompiler` ~2.8k, `basic-toml` ~2.7k, and `vte` ~2.9k *until
    W11 removes it* — ~65k vendored logic.
  - **bindings / glue** (declarations resolving to the platform `libc.so`/kernel, ≈0 per-line risk;
    cfg-gated): `libc`, most of `nix`, `bitflags`, `memoffset`, `cfg-if`.
  Why it matters: it makes the TCB-reduction argument legible — the serde_json/lexopt/compiler splits
  kept *subtrees* out, W11 keeps `vte`'s parser out, and it documents why `libc`/`nix`/`seccompiler`
  (~base) and `object` (vetted ELF+relocation parser, load-bearing via the BPF loader) are **not**
  reduction targets despite their size. Regenerated whenever a TCB edge changes (W11 included).

## Dropped / deferred (with reasons)

- **W3 · `kennel_meta` RO-seal + readback — DROPPED.** The meta map lives in the owner-only
  `0600` pin under `/run/user/<uid>/kennel/bpf/`. Sealing it / reading it back defends owner-only
  state against the owner — i.e. the trust root — which is outside the threat model. The
  `magic`/`abi_version` readback is a sanity assert, not a security control. Not worth a workstream.
- **W4 · `--strict` threat-tag lint — DROPPED.** Policy about policy; turtles all the way down.
- **W5 · Reproducible double-build + release image — DEFERRED to 0.3.** Release-pipeline infra,
  lands with the rest of it.
- **W6 · Multi-kernel BPF verifier matrix — DEFERRED / low priority.** We already build multi-OS /
  multi-arch and it works; the marginal value of a dedicated verifier-load matrix is low until the
  custom-kernel runners exist anyway.
- **W7 · `checksum-verify` Rust twin — DROPPED.** The `sha2` vendoring is a nightmare not worth
  touching; the shell witness (`src/tools/verify-checksums.sh`) is the settled, acceptable
  implementation ([[checksum-verify-is-settled]]).

## Fenced to 0.3+ (scope fence)

- **The binder cross-instance / MCP relay** (provide/consume, `SpawnKennel`-over-binder) — grows
  the TCB; wait until the facade foundations (incl. W8's D-Bus split) are proven. *(§8.1)*
- **X11 isolation**, **`[env].template`/`fs.scrub`**, **`[unix]` service-launch /
  `abstract="allow"` / `--dry-run`**, **accept-unsigned dev mode**, **TTL `renew` prompt**. *(§8.1)*
- **§11.1 v2 design forks** — Wayland clipboard, GPU compute-only, TPM/FIDO per-key,
  comprehensive-seccomp template. Tracked, not scheduled.

## Sequencing

1. **Design pass on W1 + W2 together** — they share the trust manifest and the teardown diff;
   settle the §11.1 open questions and the block-vs-report and COW/revert decisions as one design.
   This is the only unresolved *design* in the release.
2. **W1 + W2 build** — the flagship, after the design pass.
3. **W8 (D-Bus)** — in parallel; independent of the persistence work.
4. **W10 (IDE extension)** and **W9 (fragments)** — the authoring thrust; W10's schema emission
   pairs with W9's fragment surface, so sequence them together.
5. **W11 (filter → CLI)** any time — independent, small. **W12 (TCB accounting)** rides the docs
   pass every release touches, regenerated after W11 lands so the inventory reflects the cut.

## Exit criteria

0.2.0 ships when: T2.8 inspection + boundary-escape handling are built and folded into `kennel
review` (W1 + W2); D-Bus mediation is built to the facade/host split and proven by a policy-suite
case (W8); the fragment catalogue is authored, signed, framed, and tested (W9); the IDE extension
gives working completion + validation against a current schema (W10); the terminal filter runs
CLI-side with `vte` out of `cargo tree -p kenneld` (W11); and the crate inventory carries the
vendored logic-vs-bindings accounting, regenerated post-W11 (W12). CHANGELOG records every
stable-surface change (CLI / policy schema / IPC / BPF ABI) per CODING-STANDARDS §14.

## Decisions taken (2026-06-18)

1. **W1/W2 mechanism: the git model.** Persistence inspection is built as commit/diff against a
   compile-time baseline (see Thrust 1 framing). The trust manifest, the teardown diff, the
   escaping-symlink removal, and revert are one mechanism, not three. The design pass decides
   *use-git vs. borrow-the-model*; either way per-trigger removal is no longer the frame.
2. **Two configurable dispositions, both policy enums parallel to `ttl_action`.**
   - **`on_change` (live, during the run):** **`warn`** / **`freeze`** / **`kill`** — kenneld's
     reaction when inotify reports a trigger-class mutation. Unprivileged; reuses the TTL cgroup
     freeze/kill plumbing. Backed by teardown (a dropped event is still caught at the door).
   - **teardown disposition (at the end):** **`revert`** (hard reset to baseline) / **`interactive`**
     (prompt) / **`warn`** (audited report). Snapshot-authoritative.
   Defaults TBD in the design pass.
3. **W8 host delegate runs in the operator context** alongside `host-netproxy`/`host-inetd`,
   subscribing to the host bus and applying the simple bidirectional filter. *(confirmed)*

## Open decisions for the maintainer

- **W1: default teardown disposition** (`revert` / `interactive` / `warn`) — to settle in the
  design pass.
- **W1/W2: use git, or borrow the model?** A real per-bind object store vs. a content-addressed
  snapshot with no git dependency. Design pass decides.
- **W1: how far up the watch layer in 0.2.0?** Authoritative-snapshot-only, or snapshot +
  inotify live-audit/diff-scoping + the `on_change` tripwire (all unprivileged, additive). fanotify
  write-prevention is **out of scope entirely** — it needs a standing privileged watcher
  ([[no-standing-host-privilege]]).
