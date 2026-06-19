# Project Kennel — 0.2.0 plan

Status: **building — 14 of 15 original workstreams landed** (2026-06-19); **W15** (as-built prose pass) open; **W16** (facade-client poll-elimination) added post-plan from the delegate/facade audit · Drafted: 2026-06-18 · Targets: 0.2.0
Baseline: 0.1.0 (first versioned cut, 2026-06-18)

> **Progress (2026-06-19).** W1+W2 (persistence), W8 (D-Bus), W9 (fragments), W10 (IDE schema),
> W11 (terminal filter → CLI), W12 (TCB accounting), W13 (operator-prompt channel), and W14
> (`essential_etc` cascade) are **built + merged**; each is marked inline below. The one remaining
> workstream is **W15** (strip history/apology prose + purge never-built mechanisms). **W16**
> (`facade-client` poll-elimination) was added post-plan from the delegate/facade DoS audit — a
> follow-up to the shipped facade-only mitigation, gated on a kenneld-side design decision (see
> Thrust 4). The per-workstream prose is kept as the plan-of-record; the as-built truth lives in the
> design corpus and `CHANGELOG.md`.

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

**Scope the control to the trust-manifest surface, not the whole writable tree (decided in review).**
The control's domain is *exactly the manifest's declared trigger set* — not "we scanned the tree for
all triggers," which is unwinnable. This makes *complete* a property you can actually hold: complete
coverage **of the declared surface**. The arms race relocates to "is the manifest's pattern set
current," a versioned-catalogue problem (run it like THREATS), not a guarantee you can't keep. A
trigger at a path no manifest entry covers is invisible *by construction* — the correct trade, but
one `review` must **state plainly** ("checked the declared surface"), never imply a clean tree; an
unstated boundary is the theatre [[no-security-theatre]] rejects.

**Borrow git's diff/revert *model*, not git itself (decided in review).** Real git is lossy exactly
where this control can't be — it drops setuid/setgid/sticky bits, xattrs, ACLs, special files, and
sub-second mtime, applies ignore semantics, and treats `.git/hooks` as both the trigger class *and*
bulk objects. So no git dependency; borrow the mental model (a content-addressed baseline you diff
and restore against).

**Backend: a content-addressed masked side store.** `.trust-manifest.d/<sha256sum>` adjacent to
`.trust-manifest.json` at each writable root, masked the same way (empty over-mount, invisible to the
workload). The store *is* the baseline: `review` diffs the live trigger-path against its pinned blob;
revert is copy-the-blob-back. One mechanism — **pin, diff-against-pin, restore-from-pin** — replaces
snapshot + detect + COW-revert, and collapses W1/W2 into a smaller, more honest **L**. The host trusts
the store **by content address, never by the workload-visible listing**; store writes happen *only*
host-side (compile + `review`), never from anything reachable inside a kennel.

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
  **✅ Built + merged** (#36 design · #37 build) — graduated to THREATS T2.8 / §7.4 (manifest v2 +
  content store + catalogue + `review --revert` + `.d` mask).
  Pins are **explicit** (`kennel compile`/`review`, host-side) — enumerate the declared writable binds
  and pin every existing **trigger-class** path (git hooks, `core.hooksPath`, `Makefile`/`package.json`
  scripts, `.vscode`/`.idea` tasks) into the manifest + the `.d` store. **`kennel run` never pins; it
  verifies fail-closed** — an unpinned catalogue-matching file or a divergent pin is a *failed settled
  config* (refuse, direct to `review`), so a run starts from a verified-complete surface and teardown
  changes attribute cleanly to the workload. `kennel review` is the inspect-and-re-pin surface, one
  with the commit-time review. **No TOFU.** Key bounds (the design pass settled these; the as-built
  truth is now in THREATS T2.8 / design §7.4):
  - **Two-tier cost.** Always content-**hash** the trigger class (mtime-games-proof — never trust
    `stat` for the security path); reserve full snapshot/restore cost for when `revert` is actually
    selected.
  - **The trigger catalogue is versioned and necessarily incomplete.** Even scoped, the pattern set
    misses things (`.gitattributes` clean/smudge, git `alias = !sh`, `.pth`/`sitecustomize`, `.envrc`,
    `.npmrc` `NODE_OPTIONS`, `.desktop` autostart, user systemd units). Version it like THREATS;
    document W1 as *"detects this enumerated, versioned set,"* never *"clean."*
  - **Default disposition is per workload class, not global** (see Decisions). `revert` is complete
    and right for `inspect-only`/`untrusted-build`; for **ai-coding** (the flagship) you *keep* the
    agent's diff, so `revert` is unusable and the control is on the incomplete-detection story — state
    that plainly rather than letting "revert is stronger and free" imply it covers the case that
    matters most.

- **W2 · Boundary-escape symlinks — same pin/diff/restore pipeline as W1.**
  *(→ [[vfs-bind-source-nofollow-owed]], reframed)* **M.** **✅ Built + merged** (#36/#37) —
  escaping-symlink trigger detection + pins shipped with the W1 store.
  Not a standalone `openat2` runtime guard.
  A symlink inside a delegated writable subtree that points *outside* the delegation boundary is both
  a read-escape and a persistence vector — it's a trigger class, pinned and restored by the same
  content-addressed store:
  - **At compile:** enumerate the escaping symlinks that already exist in a delegated source, pin them
    into the manifest + `.d` store (the known-good set), and **warn loudly** — an escaping symlink in
    a delegated tree is a footgun the operator should see.
  - **At `review` / teardown:** an escaping symlink not in the pinned set was planted during the run —
    flag it (and, under `revert`, restore-from-pin removes it for free).
  - **`.d`-store masking is the design wrinkle.** Masking a *populated directory* is harder than one
    file: the `.d` store must be invisible to `readdir`, and a workload `mkdir .trust-manifest.d` or a
    colliding `<sha256sum>` write must not shadow or corrupt it. Mask the file *and* the `.d` dir under
    **every** writable bind (not just project root); the host trusts blobs by content address, never
    by the workload-visible listing.

- **W13 · Operator-prompt channel + TTL `renew` prompt.** *(→ §9.7, pulled from 0.3)* **M.**
  **✅ Built + merged** — `PromptPort` + control-wire variants + the TTL `renew` prompt + CLI surfacing. Today
  kenneld is a daemon with no session channel, so the TTL `renew` action degrades to an audited
  `warn`. Build the **kenneld → attached-CLI prompt path** (over the detachable PTY broker's control
  channel) so kenneld can ask the operator a question and get an answer. It lands the real TTL `renew`
  prompt *and* unlocks W1's **`interactive`** teardown disposition — one channel, both consumers.
  Small enough to be worth pulling in now (maintainer call). When detached (no attached client), both
  fall back to their audited-default behaviour.

### Thrust 2 — A new mediated surface

- **W8 · D-Bus mediation — facade / host split.** *(→ design §7.7, `07-1-binder.md`, §8.1)* **L.**
  **✅ Built + merged** (#43 design · #44 schema · #45 vendored crate · #46 facade/membrane/delegate
  + e2e). **As-built note:** the split evolved past "kenneld decides on the typed form / simple
  bidirectional filter" (Decision 3 below) to the **membrane** model — kenneld relays opaque frames
  and owner-checks the connection; the `host-dbus` delegate applies the allowlist. Proven by the
  `dbus-session-allowed` + `dbus-deny-wins` policy-suite cases. See `docs/design/07-7-dbus.md`.
  The binder successor to the never-built `xdg-dbus-proxy` design, built to the egress convert/decide/
  act line — and the review's correction is load-bearing: **drop the pty-filter analogy, it builds the
  wrong thing.** The pty filter pattern-strips bytes without understanding a protocol; D-Bus filtering
  is *message-level* (it must read destination / path / interface / member). "Thin bidirectional
  content filter" would smuggle an adversarial-wire parser into the host delegate. Hold the line:
  - the **in-kennel facade is the sole parser of adversarial D-Bus wire** (out of TCB), and emits a
    **typed** call to kenneld;
  - **kenneld decides on the typed form** (vetted fields, no wire);
  - the **host-side delegate constructs a well-formed call from those vetted fields** — it does *not*
    re-filter adversarial bytes. Only then is "TCB growth is a decision point, not a parser" true.
  - **Inbound ≠ outbound.** Host-origin signals are *trusted-origin* data, so the delegate parsing
    them is acceptable — but the bidirectional framing hid that asymmetry. Design the two directions
    separately.
  - **D-Bus is a credential vector.** It reaches `org.freedesktop.secrets` (gnome-keyring/KWallet
    Secret Service), notifications, portals. The Secret Service is a read-stored-credentials oracle and
    gets the **signing-oracle treatment — refuse to broker, named explicitly** (§11.2 axiom-adjacent;
    the same reason GPG signing is not brokered at all), not "default-deny in a small option space." The option space stops being small the moment keyring/
    portals/notifications are in scope.
  Re-add the `[dbus]` config surface (removed from the schema in 0.1) as a *built* surface this time.
  Proven by a policy-suite case.

### Thrust 3 — Authoring experience

- **W9 · Composable fragment catalogue — with the framing that makes it usable.** *(→ design
  §5.10, §8.1)* **M.** **✅ Built + merged** (#42) — the signed fragment catalogue + leaf syntax.
  The `include` mechanism is built; the gap is not content alone but the
  **framing** that makes fragments a shortcut people actually reach for — discoverability, how
  they compose without surprising the author, the convenience story in the docs and the CLI. Owed:
  that framing + the signed fragments (`lang-python`, `lang-node`, `toolchain-c`, `net-permissive`,
  `vcs-git`) + per-fragment tests.

- **W10 · IDE policy intellisense (VSCode extension).** *(new)* **M.** **✅ Built + merged** (#41) —
  the policy JSON Schema is emitted from the `kennel-lib-compile` source structs and CI-checked.
  A VSCode/editor extension
  giving policy-TOML authors completion, hover docs, and inline validation. **The real prerequisite is
  *generating* the schema, not consuming one** (review): the corpus cites `schema/policy.toml.schema`
  as canonical (00, 05, the worked template) but **the file isn't in the tree** (confirmed). W10 must
  **emit** the machine schema from the `kennel-lib-compile` source structs as the single source of
  truth, **CI-checked against the parser** — which also kills the dangling references and prevents
  doc/code drift. Generation, not hand-maintenance, or W10 becomes a new drift surface. The extension
  consumes the generated schema; it lives as a separate deliverable, not in the runtime crates.

### Thrust 4 — TCB hygiene

- **W11 · Move the terminal-escape filter out of the daemon TCB into the CLI.** *(→ §4.8,
  [[tcb-only-shrinks]])* **S–M.** **✅ Built + merged** (#39) — the broker is a raw-byte router and
  the filter runs CLI-side; `vte` is out of `cargo tree -p kenneld`.
  Today `kenneld`'s PTY broker (`pty_broker.rs`) runs
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
  **State the input/output asymmetry (review):** only the *output* path becomes a raw router — that's
  the win. Detach-key detection scans the *input* path, which is **operator-controlled** bytes, not
  workload-controlled, so keeping it daemon-side is fine. Say so explicitly, so the "no parser of
  workload-controlled bytes in the daemon" claim is airtight rather than apparently contradicted by
  detach handling.

- **W12 · Honest TCB accounting in the inventory.** *(→ `03-crate-decomposition.md`)* **S.**
  **✅ Built + merged** (with #39) — the inventory carries the vendored logic-vs-bindings accounting,
  regenerated after the W11 cut.
  The crate inventory counts *first-party* SLOC only, which understates the real TCB ~13× — the trusted
  base is the vendored deps too (~215k vendored vs ~16k first-party). Upgrade the inventory's
  "Crate inventory and TCB" section to carry the **vendored dimension, split logic vs bindings**:
  - **logic** (runs in our process — the real attack surface): `object` ~36k, `serde`+`serde_core`
    ~19k, `ed25519-compact` ~3.7k, `seccompiler` ~2.8k, `basic-toml` ~2.7k, and `vte` ~2.9k *until
    W11 removes it* — ~65k vendored logic.
  - **bindings / glue** (declarations resolving to the platform `libc.so`/kernel, ≈0 per-line risk;
    cfg-gated): `libc`, most of `nix`, `bitflags`, `memoffset`, `cfg-if`.
  Plus the axis that ranks *danger* (review): **adversarial-input vs trusted-input**, on top of
  logic-vs-bindings. Logic-vs-bindings says what runs in-process; it doesn't say what an attacker can
  reach. `vte` eats workload output (**adversarial** — which is why W11 is the highest-value cut);
  `basic-toml` eats *signed* policy (trusted); serde-over-binder eats our own *typed* wire
  (trusted-ish).
  **`object` re-checked and exempt — confirmed (2026-06-18).** In the daemon, `object` parses only
  *first-party* ELF: the SSH dialer + the facade binaries (`lib.rs` libresolve sites are `ssh_bin`/
  `shim_bin`/`socks5_bin`/`client_bin`) and the first-party BPF object (privhelper). The *workload's*
  (adversarial) ELF is resolved at **compile time in the CLI** (`resolve_settled_loaders` — "the
  runtime never re-resolves"), out of the TCB. So `object`'s daemon input is trusted — it sits with
  `basic-toml`, not `vte` — and the adversarial ELF parse being CLI-only is another point for
  compiler-out-of-TCB. `libc`/`nix`/`seccompiler` are base (bindings/glue). Regenerated whenever a TCB
  edge changes (W11 included).

- **W14 · Move `essential_etc_subtrees()` to a vendor+system config cascade.** *(→ §2.6,
  [[no-hardcoded-paths-config-cascade]], [[deploy-gotchas-etc-binds]])* **S–M.**
  **✅ Built + merged** (#38) — the list is an `etc-binds.catalog` vendor+system cascade.
  `kenneld` binds a
  **hardcoded** list of host `/etc` subtrees read-only into every view (`etc.rs`
  `essential_etc_subtrees()`: `/etc/ssl/certs`, `/etc/ca-certificates`, `/etc/pki`, `/etc/ld.so.*`,
  `/etc/alternatives`) — the **same opacity footgun** the trust-trigger catalogue had (W1): the
  operator can neither see nor tune it, and it interacts confusingly with `fs.read` (a subtree must be
  in *both* this hidden list *and* `fs.read` to appear, [[deploy-gotchas-etc-binds]]). It is also
  distro-variant (Debian `/etc/ssl` vs Red Hat `/etc/pki`), so a per-distro **vendor** file is *more*
  correct than a baked cross-distro union. Move it to an `etc-binds.catalog` cascade on the standard
  config path — **vendor (`/usr/lib/kennel`) + system (`/etc/kennel`) only, NOT user** (the
  integrity-sensitive tier): unlike triggers, where user-widening is *safe* (more watching), widening
  this *binds host paths into kennels* — a capability grant, where a stray entry exposes a secret.
  Ship the current set as the vendor default; keep the `.exists()` cross-distro filtering. Mirrors the
  W1 catalogue loader shape (additive, `-` to prune) minus the user layer. Sequenced after W12/W13.

- **W15 · As-built prose pass — strip history/apology and never-built mechanisms.** *(→
  [[docs-as-built-no-prerelease-history]], [[comments-no-history-no-apology]])* **S–M.**
  **⏳ OPEN — the one remaining 0.2.0 workstream.** (The grep gate still finds `xdg-dbus-proxy` /
  `IGpgAgent` / `per-kennel ssh-agent` residue across the corpus.) Two coupled
  cleanups across `docs/` and code comments: **(1)** the "this is *not* X" / "replaced by" / "the old
  X" / "no longer" apology-history prose — state the design in present-tense as-built, never narrate
  what was removed or what we don't do; and **(2)** purge the mechanisms that were *designed-on-paper
  but never built and never will be* — `xdg-dbus-proxy` (the D-Bus carrier is the `IDBus` facade,
  §7.7), the per-kennel `ssh-agent` socket shim (SSH egress is the §7.10 bastion), and any residual
  `gpg-agent`/`IGpgAgent` facade (GPG signing is not brokered; §11.2). These were never written and
  never used, so they are deleted outright — **no tombstone, no "we don't do X" marker**, which is
  itself the apology pattern. A grep gate (`xdg-dbus-proxy`, `IGpgAgent`, `per-kennel ssh-agent`) keeps
  them out once removed. Touches ~15 corpus files; do it as one pass, not per-edit drive-bys.

- **W16 · `facade-client` poll-elimination — parked/blocking `BIND_INET`.** *(→ §7.5.7,
  `07-1-binder.md`, [[ipc-inventory-binder-is-sole-in-kennel-core]])* **S–M.** **NEW — surfaced by
  the W8-era delegate/facade DoS audit; the facade-only mitigation already shipped, so this is a
  follow-up, not a 0.2.0 blocker (target: maintainer's call).** `facade-client` services each
  mirrored inbound port by *polling* `BIND_INET` and re-arming on `AGAIN`; the kennel-cleanup PR
  reduced the cost (one reused binder connection + geometric idle backoff 50 ms → 1 s) but the model
  is still a poll. The complete fix is to **park** the `BIND_INET` transaction in kenneld until a
  conduit actually arrives (the `DBUS_RECV` long-poll pattern — condvar demux off the
  `InboundRuntime` queue), eliminating idle wakeups and first-connection-after-idle latency
  together. **The design decision that gates it:** parking one looper per mirrored port interacts
  with the serving pool (`POOL_MAX_THREADS = 8`) — a kennel mirroring >8 ports would exhaust it. So
  W16 must first settle one of: parked recvs not counting against the serving pool, a per-port
  eventfd the facade waits on (no parked looper), or a pool bump tied to the mirror-port count. A
  kenneld change ([[tcb-only-shrinks]] — keep it transport-only, no new parser), so it needs
  maintainer sign-off before build.

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
  `abstract="allow"` / `--dry-run`**, **accept-unsigned dev mode**. *(§8.1)* *(TTL `renew` prompt
  pulled into 0.2.0 as W13.)*
- **§11.1 v2 design forks** — Wayland clipboard, GPU compute-only, TPM/FIDO per-key,
  comprehensive-seccomp template. Tracked, not scheduled.

## Sequencing

1. **Design pass on W1 + W2 together** — one mechanism (the content-addressed `.d` store) over both;
   settle the remaining design questions: the `ai-coding` default disposition, `.d`-store GC, the
   versioned trigger catalogue, and the `.d`-dir masking under every writable bind. This is the only
   unresolved *design* in the release — bound the claims (scope, boundary statement, catalogue
   versioning) before the mechanism, per the review.
2. **W13 (operator-prompt channel)** then **W1 + W2 build** — W13 first (W1's `interactive`
   disposition rides it; it's small and also lands the TTL `renew` prompt).
3. **W8 (D-Bus)** — in parallel; independent of the persistence work.
4. **W10 (IDE extension)** and **W9 (fragments)** — the authoring thrust; W10's schema emission
   pairs with W9's fragment surface, so sequence them together.
5. **W11 (filter → CLI)** any time — independent, small. **W12 (TCB accounting)** rides the docs
   pass every release touches, regenerated after W11 lands so the inventory reflects the cut.
6. **W14 (`essential_etc_subtrees` → vendor+system cascade)** after W12/W13 — independent config-hygiene
   fix, reuses the W1 catalogue-loader shape.

## Exit criteria

0.2.0 ships when: T2.8 inspection + boundary-escape handling are built and folded into `kennel
review` (W1 + W2), with all disposition primitives built and the operator-prompt channel + TTL
`renew` prompt landed (W13); D-Bus mediation is built to the facade/host split and proven by a
policy-suite case (W8); the fragment catalogue is authored, signed, framed, and tested (W9); the IDE extension
gives working completion + validation against a current schema (W10); the terminal filter runs
CLI-side with `vte` out of `cargo tree -p kenneld` (W11); and the crate inventory carries the
vendored logic-vs-bindings accounting, regenerated post-W11 (W12). CHANGELOG records every
stable-surface change (CLI / policy schema / IPC / BPF ABI) per CODING-STANDARDS §14.

## Decisions taken (2026-06-18)

1. **W1/W2 mechanism: content-addressed masked side store, scoped to the manifest surface.**
   Persistence inspection is pin / diff-against-pin / restore-from-pin over the declared trigger set
   (see Thrust 1 framing) — the manifest, the diff, the escaping-symlink handling, and revert are one
   mechanism. **git is out as the store** (lossy on setuid/xattrs/ACLs/special-files/sub-second
   mtime/ignore semantics); borrowed only as the diff/revert *model*. The control is scoped to the
   declared surface, and `review` states that boundary explicitly.
4. **Default disposition is per workload class, not global.** `revert` for `inspect-only`/
   `untrusted-build`; `ai-coding` keeps the agent's diff, so it runs on the incomplete-detection story,
   stated plainly — not the "revert is free and stronger" framing.
2. **Two configurable dispositions, both policy enums parallel to `ttl_action`.**
   - **`on_change` (live, during the run):** **`warn`** / **`freeze`** / **`kill`** — kenneld's
     reaction when inotify reports a trigger-class mutation. Unprivileged; reuses the TTL cgroup
     freeze/kill plumbing. Backed by teardown (a dropped event is still caught at the door).
   - **teardown disposition (at the end):** **`revert`** (hard reset to baseline) / **`interactive`**
     (prompt) / **`warn`** (audited report). Snapshot-authoritative.
   Defaults TBD in the design pass.
3. **W8 host delegate runs in the operator context** alongside `host-netproxy`/`host-inetd`,
   applying the compiled allow/deny table to each typed call. *(confirmed)* **As-built supersedes the
   "simple bidirectional filter" framing:** kenneld is the **membrane** (it relays opaque frames per
   message and owner-checks the connection — it does *not* decide on the typed form); the `host-dbus`
   delegate is the sole filter; per-connection ownership replaced any daemon-wide facade identity.
   See `docs/design/07-7-dbus.md`.

## Open decisions for the maintainer

- **W1: default disposition *per class*** — `revert` for `inspect-only`/`untrusted-build` is settled;
  the `ai-coding` default (`warn` vs `interactive`, since `revert` is unusable there) is for the design
  pass.
- **W1: `.d`-store lifecycle / GC** — GC unreferenced blobs, or keep them as tamper-evident trigger
  history (revert-to-any-prior-pinned-state, arguably a feature)? A decision, not a default to back
  into.
- **W1: how far up the watch layer in 0.2.0?** Authoritative-store-only, or store + inotify
  live-audit/diff-scoping + the `on_change` tripwire (all unprivileged, additive). fanotify
  write-prevention is **out of scope entirely** ([[no-standing-host-privilege]]).
- **W8: Secret Service / portals / notifications** — *(decided)* refuse-to-broker list = Secret
  Service + session/process control (systemd1/login1/session managers), named explicitly
  (signing-oracle treatment, §11.2); inbound = replies + match-rule'd signals; the per-method
  check runs in the `host-dbus` delegate, not kenneld. See `docs/design/07-7-dbus.md`.
