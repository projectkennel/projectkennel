# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Runtime changes

- **The UDP synthetic-pool per-grant cap is now a rotating window (0.7.0 W8).** The 32-mint
  per-grant ceiling on the tun broker's naming shim bounded distinct subdomains per wildcard
  grant *ever* — tight on exfil, but it broke a legitimate app fanning out to more than 32
  subdomains of one granted domain over its life. The bound becomes 32 **concurrent**: minting
  a new name past the window evicts the least-recently-used mint of the same grant that has
  **no live flow** (the pool consults the flow table — eviction never breaks a flow in flight;
  a window full of live flows still refuses with NODATA, so the concurrent bound holds under
  flow-spray). An evicted mint's synthetic address is never reused — the `/64` suffix pool is
  monotonic — so a client holding a stale cached AAAA can never reach another name's
  destination; it re-queries and re-mints. The threat note (T1.15) records the
  loosened-but-bounded exfil surface: per-moment 32 names, unlimited labels over time at
  query rate, all zero-wire and all inside the granted family.

### Installer changes

- **The payload manifest (0.7.0 W7): an upgrade removes what the release no longer ships,
  and says so.** The staged tree is the manifest: anything in a fully kennel-managed
  directory (`/usr/libexec/kennel`, `/usr/libexec/kennel-facades`, and the vendor tree's
  `keys/`, `templates/`, `policies/`) that the incoming payload does not ship is removed,
  named in the output (`install.sh: removing retired /usr/libexec/kennel/host-dbus`).
  `/etc` is never swept — host config is the admin's. The vendor `keys/` sweep is
  deliberate and security-relevant: a stray `.pub` there would hold vendor-tier
  (`org.projectkennel.*`) authority, so the trust-anchor dir is payload-exact; a payload
  that ships no `keys/` at all declares nothing and sweeps nothing. `--dry-run` prints
  the would-remove set. A fresh install and an upgraded one are now byte-identical in the
  managed directories. Live receipts on the dev host: the retired `host-dbus` delegate
  (0.6.0 W4) and the retired `gui-broker-sway` provider, both removed and named.
- **The `/etc`-binds trap is dead (0.7.0 W7): a granted-but-uncatalogued `/etc` subtree
  is never silent.** Exposing an `/etc` subtree needs both an `fs.read` grant and an
  `etc-binds.catalog` entry; missing the catalogue half used to fail as a bare ENOENT
  inside the kennel. The fix is a **diagnostic, not a unification** — deriving binds from
  a user-signed leaf's `fs.read` would let any policy widen `/etc` exposure, which is
  exactly what the vendor+system-only catalogue prevents. The compiler
  (`policy compile`/`validate`) and the daemon (at spawn) now both warn, naming the grant
  and the fix (`…granted but not bindable — no etc-binds.catalog entry covers it…`), off
  one shared implementation (the catalogue reader moved from `kenneld` into
  `kennel-lib-config` — code motion within the TCB). Synthetic `/etc` files and
  `source`-redirected view paths are recognised as servable and never flagged. The
  shipped catalogue gains `/etc/fonts` (the confined GUI's fontconfig — the gui fragments
  granted it, the catalogue never bound it: the trap's own live receipt, caught by the
  new diagnostic).

### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency changes (§5), MSRV changes (§2), and threat-catalogue changes are also recorded here.

## [Unreleased]

### CLI changes

- **`kennel run` runs settled artefacts, nothing else (0.7.0 W1).** The run house narrows to its
  contract: `kennel run <name>` resolves a **settled** artefact (`<name>.settled.toml`) from the
  three policy repos (`~/.config/kennel/policies`, `/etc/kennel/policies`,
  `/usr/lib/kennel/policies`) — never a path, never source. The in-memory compile+sign hybrid
  (the old dev loop) is **removed**, and with it the compile-house flags `run` carried:
  `--key`, `--key-id`, `--template-dir`, `--trust-dir` now refuse with a pointer at
  `kennel policy compile`. The dev loop is two commands with no hybrid:
  `kennel policy compile <name>` (writes the settled artefact beside the source in the repo;
  picks the sole user key with no `--key`) then `kennel run <name>`. Every wrong-object refusal
  names what the user is holding and the real next step — a source policy points at `compile`,
  a template name points at `policy generate --from`, a path states the one-sentence contract.
- **`kennel oci run` boots the store entry's compiled artefact.** The scaffold flow is now
  load-bearing: `oci build` scaffolds, the operator completes `reason` and compiles
  (`kennel policy compile <store>/<name>/policy.toml --key <key>` — the build banner prints the
  exact command), and `oci run <name>` boots `<entry>/<name>.settled.toml`, refusing an
  uncompiled entry with that pointer. `--key` is gone from `oci run` (`oci build` keeps it —
  the confined fetch compiles its generated leaf in the authoring house). The `[rootfs]`
  grammar partition and digest provenance check are unchanged.
- **Stale diagnostic pointers fixed** (the W0-V2 sweep): the resolve-miss hint, the
  `policy compile`/`validate` usage strings, and the `keygen` success blurb all said
  `kennel compile`/`kennel validate` — spellings that do not exist; all now say
  `kennel policy …`. `kennel-compose` gained the missing next-step pointer after writing a
  leaf. The installer's quickstart banner shows the real three-step flow
  (generate → compile → run).
- **The policy e2e suite eats the dogfood.** `policy-e2e.sh` and every `run.sh` hook now drive
  the verbatim operator flow — stage into the user repo, `policy compile`, `run <name>` — so
  the settled pass-through (the production path) is what the whole suite exercises; no
  compile-side flag appears on any `run` invocation anywhere in the tree.
- **The authoring house splits: `kennel template` beside `kennel policy` (0.7.0 W2).** Templates
  and fragments — signed shared bases, never runnable — get their own noun group:
  `kennel template list/show/sign/lint`. Under its own house `sign` is unambiguous, so the
  `sign-template` workaround name retires (a pointer diagnostic remains for one release, like
  `sign` before it); `policy lint` moves with the corpus it checks (pointer likewise);
  `policy list` and `template list` each list their own house. `template show <name>` resolves
  the template cascade and prints the floor a deriving leaf inherits — the same renderer as
  `policy show`, which now answers a template name with a cross-house pointer (and vice versa).
  `policy compile` deliberately still accepts template sources: compiling a template into a
  settled artefact is the spawn-target flow, not a house violation. New man page
  `kennel-template(1)`, derived from the CLI definition like the rest.
- **The missing ceremonies land: `clone` and `install`, plus tier provenance everywhere
  (0.7.0 W3).** `kennel policy|template install <file.toml> [--host]` places and signs a
  source object at the invoking tier in one verb — receive → install → run. The whole object
  must be signable at the destination: a `[[provides]]` claim in a reserved family refuses at
  user tier, and `org.projectkennel.*` refuses at **every** install level (the vendor tier is
  package payload) — pre-flighted by the compiler's own `reserved_authority` rule (now `pub`,
  one implementation), and re-enforced at compile regardless: the ceremony is a courtesy,
  never the gate. A settled artefact refuses with the copy note (acceptance is
  downward-inclusive, so a higher-tier-signed artefact just works when placed — `install`
  signs *source*); a failed sign rolls the placement back. `kennel policy|template clone
  <name> [<new-name>]` forks a higher-tier object's **source** into the user house — your
  copy, your key, versus `generate --from`, which *derives*. The gate is content-total and
  renaming is no escape: a reserved `[[provides]]` claim is not clonable under any name (the
  pointer says derive instead). By default the clone keeps its name and shadows the original,
  user-first. What makes shadowing livable: **tier provenance is visible everywhere a policy
  is used** — `list` labels each cascade dir with its tier and marks shadowing both directions
  (`shadows vendor` / `shadowed by user`) plus the signing tier where it differs from
  placement (`vendor-signed` on a downward copy); `show` names the origin tier; `kennel run`
  reports which tier's artefact won resolution (`running claude [user tier]`).
- **The `key` house lands, tier-bound, and `keygen` retires (0.7.0 W4).** Key management
  becomes a noun group with the model rule built in — **a key's tier is where it lives, and
  that is the only level it signs at**; no verb offers a cross-tier signing path.
  `kennel key generate <name>` derives the tier from context: as a user it mints into
  `~/.config/kennel/keys`, as root into the host trust store (`/etc/kennel/keys`) — which is
  what the installer now uses to mint `kennel-host`. `key list` answers the inventory question
  in one command (name, tier, mine-vs-trusted, SHA256 fingerprint via `ssh-keygen -lf` — no
  new hash dependency); `key show <name>` adds the signed-object inventory across the policy
  and template cascades (settled artefacts, source-signed templates, lockfile pins).
  `key trust <file.pub>` / `key untrust <name>` exist **only at host level** (root): the user
  tier needs no trust list, because `policy install` re-signs foreign objects under the user's
  own key — that re-signing *is* user-level trust, per object. `untrust` prints the impact
  report **before** acting — every artefact that stops verifying, spanning the host tier and
  the user tier below it (acceptance is downward-inclusive) — and proceeds only with `--yes`.
  `kennel key rotate <name> [--yes]` ships with the house: the supervised ceremony that
  retires the old pair (the public half leaves the `.pub` namespace so the trust store stops
  loading it), mints a successor under the same key id, re-signs every template the key
  signs, and recompiles every leaf it signs — a settled artefact whose source ships in the
  vendor tree (the reference-policy layout, `providers/` included) recompiles from that
  source with the output pinned back onto the artefact's own path, and a lockfile pinning a
  re-signed template is re-pinned in the same pass, so the four-gotcha manual ritual is one
  verb. Out-of-tier objects riding the old signature are named as owed work, never silently
  skipped. `keygen` answers with a pointer diagnostic for this release; the installer banner,
  the e2e suite, and the perf scripts all speak `key generate`. New man page `kennel-key(1)`,
  derived from the CLI definition; a self-driving `key-rotate` suite case e2e-asserts both
  the user-tier rotation and the host-tier re-sign + re-pin cascade through a real
  `kennel run` under the successor key.
- **`kennel version` — the whole-stack skew report (0.7.0 W5).** Nothing reported a version
  before; the tarball name was the only carrier. The interesting output is not one number but
  the *skew set*, in one invocation: the CLI's build and settled-schema range
  (`SETTLED_SCHEMA_VERSION` + the MIN floor), the **daemon's — queried live over the control
  socket**, which instantly surfaces the old-binary-still-serving-after-reinstall trap, and
  the privhelper facts (factory + capability-split sub-helpers present, and whether the
  bpf-egress sub-helper shipped — that feature is a separate binary, so presence is a
  filesystem fact, no privileged probe). Every degraded state is a report, not an error:
  an unreachable daemon, a daemon too old for this CLI's schema (the typed handshake skew),
  and a daemon that predates the version query each print their line plus the remedy, exit 0.
  Also carried on `--version`/`-V` for convention's sake; kennel(1) carries the verb.

### Policy schema changes

- **The list-field consistency pass (0.7.0 W6): composition is uniform-by-rule, and a floor
  never silently drops.** Every policy field now falls into exactly one of three composition
  classes, documented in one place (the book, Vol 2 §16.2):
  - **List-shaped grants compose**: bare-set replaces, `add`/`remove` increments — now uniformly.
    New this pass: `[[consumes.add]]` (demand-side mesh entries, keyed by name — and a fragment
    may now carry an add-only `[[consumes.add]]`, e.g. a GUI fragment consuming the compositor
    socket), `[[spawn.allow.add]]` (spawn targets, keyed by template), and
    `[[identity.groups.add]]`/`.remove` (supplementary groups, each add carrying a `reason` — a
    group is a privilege).
  - **Deny floors union and never drop**: `exec.deny`, `env.deny`, and `net.bpf.deny_families`
    join `[seccomp].deny` and the invariant denies as add-only floors — a child's bare-set can no
    longer silently erase an inherited denylist (the W14 class, closed for every deny-shaped list).
  - **Three fields stay set-replace deliberately, each with its stated why**: `[[provides]]` (the
    reserved-namespace gate attributes the whole set to ONE declaring layer's signing tier —
    per-entry composition would smear authority attribution), `[[mutable]]` (the spawn target's
    own contract; composed mutability would be a hole), and `audit.sinks` (deployment
    configuration, and its section lives in the policy crate — no compose machinery in the TCB).
  - **A bare-set clobber is never silent**: replacing a non-empty inherited list on ANY covered
    field now prints a compile warning naming the field and what was dropped ("use the `add`
    increment to extend"). Previously visible only in a compiled-artefact diff.
- **Source-key retirements**: `proxy_listen_v4_address` is renamed **`proxy_listen_address`**
  (the settled artefact has carried a single family-agnostic `ProxyListen` since 0.6.0 W10; the
  "v4" name was vestigial on the v6-only stack) and two dead keys are removed —
  `proxy_listen_v6_address` (parsed, ignored) and `[cap].bounding_set` (parsed, never translated;
  the bounding set is dropped structurally by the spawn). A source still using them gets the
  parser's unknown-field refusal naming the key.
- **ABI note: `SETTLED_SCHEMA_VERSION` bumps to 5; the MIN floor stays 3 (the variance rule).**
  The settled shape did NOT move — composition resolves at compile, so a v3/v4 artefact loads and
  enforces identically under a v5 build (the receipt: zero settled-shape delta). The bump covers
  the **authorable surface** (the schema-version lock's standing rule): an old CLI meeting a
  source that uses the new forms fails its parse legibly, and an old daemon refuses a v5-stamped
  artefact cleanly as too-new — recompile, or restart the daemon to the new build
  (`kennel version` names the skew).
- **The base templates were re-signed.** Removing the dead keys changed `base-confined`,
  `base-flatpak`, and `base-bwrap`'s canonical bytes, so all three carry fresh maintainer
  signatures. A leaf lockfile pinning the old signatures re-pins on its next
  `kennel policy compile` (remove the stale `<name>.lock` if the pin refuses).

### IPC protocol changes

- **`Request::Version` (tag 10) / `Response::Version` (tag 11)** — the additive control-plane
  pair behind `kennel version`: the daemon answers its build version and the settled-schema
  range it parses (`schema_version`, `min_schema_version`). Additive by design: a pre-0.7.0
  daemon drops the connection on the unknown request tag (after a successful W17 handshake),
  which the CLI reports as "the running daemon predates `kennel version`" — the skew report
  degrades, never breaks, against every older daemon.

## [0.6.0] — 2026-07-06

**UDP egress, the mediation story finished, and the corpus moves to the book.** 0.6.0 spends the
ground 0.5.0 cleared on the largest tractable gap in the confinement story: **UDP egress in
constrained mode** (W2) — a QUIC/DNS client reaches a name-gated destination over a per-kennel tun,
brokered by a fenced `net.mode = host` leaf, **without** making DNS exfiltration expressible (denied
names are answered locally with zero wire activity; DNS rebinding is closed by a kernel `net.bpf`
fence on the actual dial). Around the bet the release **finishes the mediation story** — the legacy
per-kennel `host-dbus` delegate is retired and the standing `dbus-broker@v1` is the one mediation
home (W4) — turns the **confined GUI** from "it renders" into a usable, host-independent windowed
desktop (W3), retires the admin-provisioned `/etc/kennel/subkennel` allocation file for
uid-derived addressing (W10), and ships a maintainer-signed **`claude`** policy that runs an agent in
three commands with no user-authored leaf (W11). Owed debts ride along: the legacy raw-base64 key
format is gone (W5), four enum'd policy fields validate at compile (W6), the man pages derive from
the CLI definition (W7), the persona hostname is an opt-in knob (W12), and the asymmetric fs `source`
redirect lands (W15). The frozen `docs/design` / `docs/architecture` trees retire in favour of the
two-volume book (W9). The **settled-schema ABI bumps to v4**: the additive stanzas this cycle moved
the shape, so an old daemon now refuses a 0.6.0 artefact cleanly instead of choking on an `unknown
field`. Verified on Linux 7.0 against the installed stack.

### CLI changes

- **`kennel policy` authoring is coherent end to end.** Signing the policy you run is
  `kennel policy compile <policy> --key <key>` — nothing else. The old `kennel policy sign`, which
  signed *templates* (a shared base other policies inherit) and never the leaf you run, is **renamed
  to `kennel policy sign-template`**; the bare `sign` verb now returns a diagnostic pointing at
  `compile` (for your own policy) or `sign-template` (for a base). `--key` takes a key **name**
  resolved from the key dir where `keygen` writes it — `--key remco-dev` — falling back to a path,
  and names the available keys on a miss (previously it demanded a filesystem path, so `--key <name>`
  failed and the fix was undiscoverable). `sign-template` resolves a template by **name** from the
  template cascade (`~/.config/kennel/templates/<name>` first), and refuses a leaf with a pointer to
  `compile` instead of a cryptic `unknown file`. `kennel policy generate --from <template>` no longer
  demands a phantom `@version` suffix (versioned references were removed in 0.5.0); it validates the
  base name with the compiler's own rule and fails fast on a bad one. `kennel oci build` / `oci
  update` scaffolds now tell you to `compile` (which signs) the leaf they produce, not `sign` it.
- **Removed `kennel subkennel`** (the `add` / `check` sub-verbs) and its `subkennel(5)`
  man page. The per-user `/etc/kennel/subkennel` allocation file is retired: a kennel's
  reserved loopback subnet is now derived from the caller's kernel-trusted real uid (an
  FNV-1a hash into the fixed Kennel ULA space `fd6b:6e00::/24`, `/64` per kennel), so there
  is nothing to provision. Per-kennel loopback and inbound-mirror addressing is **IPv6-only**
  — the IPv4 loopback alias was removed (a v4-only inbound service is an accepted non-goal).
  Who may run kennels is governed by execute permission on the privhelper under the libexec
  dir (`chgrp` / `chmod`), not an allocation file; `install.sh` drops its `--provision-users`
  flag accordingly. The unused `<tag>` / `<gid>` template substitution variables are removed.
- **Removed the legacy raw-base64 key format** (the schedule 0.5.0 committed: both formats
  accepted during 0.5.0, raw-base64 removed in 0.6.0). The OpenSSH wire format is now the only
  parse everywhere a key is loaded — the CLI trust-store loader and default-key discovery, and
  the daemon's per-request trust-store read (signing already went through `ssh-keygen -Y sign`,
  which never read the legacy seed). A `.pub` still in the legacy format (bare base64 of the 32
  public-key bytes) is refused with a diagnostic naming the migration: regenerate with
  `kennel keygen`, or convert the pair once with 0.5.x's `kennel keygen migrate` — which is
  itself removed; the dead pre-SSHSIG `load_signing_key` path is deleted outright. The shipped
  maintainer key `keys/kennel-maint-2026.pub` is re-encoded to the OpenSSH line (same key
  bytes; existing signatures verify unchanged). **Upgrade note:** `install.sh` refreshes the
  vendor store (`/usr/lib/kennel/keys`), but legacy-format keys linger in the admin and user
  tiers (`/etc/kennel/keys`, `~/.config/kennel/keys`) — the CLI refuses with the file named
  until each is converted or removed; the daemon skips them with a warning.

### Mediated sections imply their consume

- **The per-kennel `host-dbus` delegate is retired** (W4) — the 0.5.0 gate ("until the broker has
  demonstrably subsumed it") is met, and the standing `dbus-broker@v1` service kennel is now the
  ONE mediation home. `[dbus.session]` / `[dbus.system]` **alone** routes over the broker: the
  section implies the per-bus `dbus-name` consume (`org.projectkennel.dbus` / `.dbus-system`),
  synthesized by the daemon when the policy does not spell it out — pre-W4 v3 artefacts route
  identically, and an explicit `[[consumes]]` remains valid and equivalent. The two-declaration
  contract and the routing split are gone. With no enabled broker the bus is unserved,
  fail-closed (a loud daemon diagnostic; no fallback). The broker gains the **system-bus leg**
  and the `org.projectkennel.dbus-system` provide (the delegate served both buses, so subsumption
  had to too), and **`install.sh` enables the broker ondemand at the per-host layer**
  (`/etc/kennel/ondemand/dbus-broker`) — lazy, so a host with no D-Bus consumer pays nothing.
  Deleted: the `kennel-host-dbus` crate (its `mediate` engine moved into `kennel-dbus-broker`,
  its one consumer), kenneld's D-Bus relay membrane and delegate spawn path, and the `host_dbus`
  `system.toml` key (remove a stale override from an admin `system.toml` after upgrading). The
  daemon no longer knows any bus address. Measured shrink: TCB 22,851 → 22,300 SLOC.
- **A `[net.udp]` kennel's resolver now reaches the broker naming shim** (W2 tail). Part D
  specifies the kennel's `resolv.conf` points at the tun broker's `::2` resolver so `getaddrinfo`
  reaches the naming shim over the tun — but the wiring was never shipped: a `[net.udp]` kennel's
  `resolv.conf` pointed at the proxy (a TCP SOCKS/HTTP endpoint that answers no UDP DNS), so an
  allowed name never resolved to a synthetic and UDP name resolution did not work end to end. The
  daemon now points a `[net.udp]` kennel's stub resolver at the tun broker's resolver address (the
  single source the broker also derives, `kennel_privhelper::addr`); an allowed name mints a
  synthetic AAAA, a denied name is NODATA, zero wire either way. The tun-egress suite case is now
  a real naming verdict (allowed → synthetic in the tun ULA, denied → NODATA), not just a
  tun-existence check. Non-`[net.udp]` kennels are unchanged (the proxy fast-fail line).
- **The tun-broker reference provider gains its `[net.bpf.connect]` broad IP allow** (W2 Part D):
  its `net.mode = "host"` policy had no `[net.bpf]` allow, so the deny-first cgroup ACL denied
  every flow on fallthrough (an empty allow trie). The deny floor was never missing —
  base-confined's non-removable `[net.proxy.deny.invariant]` (cloud-metadata v4/v6, link-local)
  is merged into the BPF deny map in every mode — so only the broad `allow = "*"` was owed. With
  it, deny-first closes DNS rebinding structurally at `connect()`: an allowed name that rebinds to
  a special-use address dies `EPERM`, no name-based denylist. The W4 mechanism generalizes: a `[net.udp]` policy
  no longer needs to spell out `[[consumes]] org.projectkennel.tun-udp` — the section implies the
  af-unix consume to the standing tun-broker, synthesized the same way as the D-Bus capabilities
  (an explicit consume remains valid and equivalent; the tun-egress suite case now proves the
  bare form). A future `[net.tcp]` slow-lane rides the same table.
- **`fs.read` of a host `/etc` file or directory overlays the real path over the synthetic floor**
  (W2 Part D). The constructed `/etc` is a scrubbed floor (masked `passwd`/`group`, a `resolv.conf`
  pointed at the proxy), built not bound — so a `net.mode = "host"` service that must resolve real
  names could not see the host resolver, and a GUI app could not find fontconfig or the CA bundle. A
  policy that `fs.read`s a host `/etc` path now gets the REAL path mounted read-only over the
  synthetic one (an OCI image gets it copied into the top overlay lower). Both **files**
  (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`) and whole **directories** (`/etc/fonts`,
  `/etc/ssl/certs`, `/etc/sway`) work — the earlier version created a file-only mountpoint and failed
  `ENOTDIR` on a directory grant. Restricted to exact paths (no glob, no bare `/etc`, no `..`). The
  floor it refuses to clobber is **kennel's own constructed `/etc`, not the operator's secrets**: the
  persona mask (`passwd`/`group`/`hostname` — real ones re-leak the host identity, T1.1) and the
  dynamic-loader config (`ld.so.preload`/`ld.so.cache`/`ld.so.conf`/`ld.so.conf.d`, execution
  integrity) can never be overlaid; the resolver files stay overlayable (that is the feature). An
  operator exposing their own host subtree (`/etc/ssh`, `/etc/shadow`) into a kennel they run is a
  footgun, not a blocked action — the persona uid gates what it can actually read. The synthetic
  `/etc` stays the floor for every path not explicitly granted.
- **The standing UDP-egress broker ships as a maintainer-signed `tun-broker` template + provider,
  enabled ondemand** (W2 Part D) — the dbus-broker pattern applied to UDP egress. A `[net.udp]`
  kennel's egress is unserved without a running broker; `install.sh` now keys the reference
  provider into `/etc/kennel/policies/providers/tun-broker/` and links it into `ondemand/`, so the
  broker is socket-activated on the first `[net.udp]` consume and a host with no UDP consumer pays
  nothing. The template carries the reserved `org.projectkennel.tun-udp` provide, `net.mode = host`
  with the broad connect allow, and the resolver-config overlays; a host key compiles + signs the
  thin leaf at install (no maintainer private key on the target).
- **The generic af-unix ondemand activation now covers the tun capability.** The `CONNECT_AFUNIX`
  path that serves a `[net.udp]` consumer previously delivered only to an already-registered sink
  (assuming a standing broker); it now socket-activates a cold `ondemand` tun-broker through the
  same activator the mesh connector uses (`activate_for_capability`), then consume-with-waits until
  the broker's sink is deliverable. Only the delivery stays role-specific (a per-session sink mint,
  not a rendezvous connector); activation and readiness are the shared af-unix mechanism.

### IPC protocol changes

- **The node-0 `DBUS_OPEN` verb (code 8) and its `conn-id` request codec are removed** with the
  legacy relay; the code is not reused. `DBUS_SEND`/`DBUS_RECV`/`DBUS_CLOSE` remain as the
  facade↔broker wire on the per-session mesh node (bare TLV frame / empty payloads — the session
  node is the connection). The `binder.dbus-open`/`binder.dbus-close` audit events go with the
  verbs; broker-side session mediation is audited by the broker, as before.

### Policy schema changes

- **Settled-schema ABI bumped to v4** (`SETTLED_SCHEMA_VERSION = 4`; `MIN_SETTLED_SCHEMA_VERSION`
  stays 3). The additive-optional stanzas this release adds — `[net.udp]` + `udp_allow_names` (W2),
  `[identity].hostname` (W12), the fs `redirect` list backing a `source` redirect (W15), and
  `[workload] allowed_args` / `[fs.cwd]` (all detailed below) — were re-pinned onto v3 *in-cycle*
  because a policy using none of them is byte-identical to a v3 artefact. But an artefact that *uses*
  one carries a field a v3 reader's `deny_unknown_fields` structs reject, so stamping it v3 would let
  an old daemon accept the version and then choke on a cryptic `unknown field` (the 0.3.1 drift
  class). The release promotes the accumulated shape change to a real bump: 0.6.0 artefacts are v4,
  an old (v3-max) daemon refuses a v4 artefact cleanly as too-new, and a 0.6.0 daemon still reads v3
  artefacts (MIN 3). `schema/schema-version.lock` freezes v3 at its pre-additions shape and pins v4;
  `RELEASE-CEREMONY.md` records the rule — re-pin in-cycle, bump at release when the shape moved.
- **Two additive-optional settled fields (part of the v4 shape).** Both are backward-compatible — a
  policy not using them is byte-identical and old v3 artefacts stay valid under a 0.6.0 daemon — but
  an artefact that uses one is a v4 artefact (see the ABI bump above).
  - **`[workload] allowed_args`** — when a `[workload]` is `pinned`, CLI `-- <args>` tokens are
    *appended* to the pinned argv instead of refused. The program and base argv stay pinned
    exactly (the fd-pin/digest binds the program, not the args).
  - **`[fs.cwd]`** — a signed policy may materialise the invocation cwd into the view:
    `grant = "read" | "write" | "none"` (default `none`) with `required = [".git", ".claude/"]`
    dirent markers. A non-`none` grant requires a `reason`. The spawn resolves the cwd host-side
    under a non-overridable framework floor (realpath-normalised, operator-owned, never `$HOME`);
    an unmet floor or marker refuses the run with a naming diagnostic, and the materialised grant
    is recorded in the run audit event.
- **The four schema-enum'd fields now validate at compile** (W6): `[net.bind].inaddr_any_policy`
  / `in6addr_any_policy` (`rewrite` / `deny`), `[net.audit].level` (`summary` / `full`), and
  `[dbus.audit].level` (`off` / `summary` / `full`) deserialize through their enums, so an
  invalid value is a typed compile error naming the accepted set. Previously they passed
  through unchecked (a §10.2 violation — the values were only schema *hints* since the JSON
  Schema derivation), so a policy carrying a misspelled value that compiled before now fails —
  the reason this is a named change. Valid values are unaffected; the settled artefact shape is
  unchanged (no re-pin, no bump), and the published JSON Schema's value sets were already
  identical.
- **`[identity].hostname` — the opt-in persona hostname (W12; additive-optional, part of the v4
  shape).** Setting it gives the kennel its own **UTS namespace** with one coherent,
  policy-set identity: `uname -n`, the synthetic `/etc/hostname`, and `/etc/hosts` all agree (the
  factory `sethostname`s inside the new namespace — unprivileged, via the identity-mapped userns).
  **Unset means no masking**: no UTS namespace, `uname -n` shows the host name — the current
  behaviour, byte-identical signatures. The synthetic `/etc/hostname` is now part of the
  construction **floor** for every kennel (it carries the kennel's runtime name, the same name
  `/etc/hosts` maps to loopback; `[identity].hostname` overrides both). This is persona *coherence*, not anti-reconnaissance
  (masking the hostname while the workload holds the operator's login token would be theatre);
  it also gives the operator the knob to close the accepted hostname-leak residual.
- **`[[fs.read/write/deny.add]]` and `[[exec.allow.add]]` now accept an array `path`** (a list of
  paths under one `reason`), matching the bare-set form — QoL, source-only. A single-path entry
  still serialises as a bare string, so existing signed artefacts verify unchanged.
- **`source` on `[[fs.read.add]]` / `[[fs.write.add]]` — the asymmetric fs grant (W15;
  additive-optional, part of the v4 shape).** By default the fs mapping is symmetric —
  the host inode at `path` appears at `path` in the view. An entry carrying `source` serves the
  view path from a **different host path** instead: per-workload credential/state redirection
  (`path = "~/.claude/.credentials.json"`, `source = "~/workloads/acme/claude-creds.json"`)
  without reparenting the whole home. A dir source reparents the subtree; a file source redirects
  one inode, over-mounting a symmetric parent grant it sits inside. The settled artefact carries
  the divergences in a new `redirect` list (omitted when empty, so redirect-free policies sign
  byte-identically), and `policy show` / `policy diff` account every `source → path` divergence.
  The floor is a cross-grant self-consistency check, not signing: a `source` intersecting the
  workload-writable surface (`fs.write` ∪ `fs.exclusive` ∪ `home_persist`) is refused at compile
  and re-asserted at spawn (`fs.redirect.write-set` — a workload-writable source is a
  confused-deputy hole however validly signed), and a `[fs.cwd] write` invocation whose resolved
  cwd intersects a redirect source is refused at run time (the one writable surface settle cannot
  see). `source` is legal only on a single-`path` add — refused on `remove`, `fs.deny`,
  `exec.allow`, and multi-path entries — and a redirect under `/proc` (a fresh namespaced mount,
  not a host bind) is a compile error. A redirect onto an `/etc` path **does** compose: it drives
  the `/etc` overlay from the alternate `source`, which is how a kennel ships an app config
  (`/etc/sway` served from `/etc/kennel/config/sway`) over the synthetic floor without touching or
  exposing the host's version; the floor is preserved (a redirect onto a protected-floor entry is
  simply not overlayable, so the persona mask stands). At materialisation a redirected
  read-only source resolves with `RESOLVE_NO_MAGICLINKS` (procfs/sysfs aliasing refused; ordinary
  symlink farms — stow/chezmoi — still work); writable sources keep the stricter existing
  `RESOLVE_NO_SYMLINKS` guard.

### Runtime & enforcement

- **Confined-GUI QoL: a real windowed desktop session, kennel-authored and host-independent (W3).**
  `gui-session` is now a usable **stacking desktop** instead of a fullscreen tiling terminal. It runs
  **labwc** (a wlroots stacking WM — apps open as movable/resizable windows with title bars and a
  right-click application menu), with **yambar** (clock panel), **fuzzel** (`Alt+d` launcher),
  **mako** (notifications on the private `dbus-run-session` bus), and a solid `swaybg` background —
  all fcft/cairo, no GTK, so they start clean in the confined view (waybar was tried and dropped: it
  is GTK and fatally reaches for `xdg-desktop-portal`). GTK *applications* (gnome-text-editor, files,
  calculator, viewers) run fine as windows. All shell configs are kennel-authored under
  `/etc/kennel/config` and served into the view — labwc's `rc.xml`/`menu.xml`/`autostart` at
  `/etc/xdg/labwc` via a **W15 `source` redirect** — so a session is identical on any host and never
  inherits the host's compositor config. Closing the anchor terminal *or* `Alt+Shift+e`/the menu's
  "Log out" tears the session and the kennel down cleanly. `install.sh` installs the configs and
  enables the display broker ondemand (it shipped the provider but never enabled it).
- **The confined display is a decorated host window (weston broker) and splits by client type.** The
  display broker's per-connection compositor is now **weston** (windowed mode — its wayland backend
  draws a decorated, resizable, closable host window), the default the installer enables; **cage**
  (kiosk) ships as an alternative. The reserved capability splits into two: **`org.projectkennel.wayland`**
  (a single confined window — `gui-interactive`) and **`org.projectkennel.wayland-session`** (a full
  confined desktop whose consumer runs its own compositor — `gui-session`). One broker serves both:
  `compositor-broker` now **listens on multiple sockets** (comma-separated argv), and the two
  capabilities take **distinct endpoint directories** (`/run/mesh/wayland/` vs
  `/run/mesh/wayland-session/`) so their per-provide mesh rendezvous, bound at `dirname(endpoint)`,
  do not collide. `compositor-broker` also waits for the nested compositor to advertise
  `wl_compositor` before handing the client over — and holds that probe connection open across the
  hand-off — closing a cold-start race where a nested session hit `Connection reset` / `does not
  support wl_compositor`.
- **W15 `source` redirects compose with the `/etc` overlay.** A redirect whose view path is under
  `/etc` (e.g. `/etc/sway` ← `/etc/kennel/config/sway`) now drives the `/etc` overlay from the
  alternate source instead of being refused at compile — the mechanism the GUI configs above ride.
  The floor is preserved (a redirect onto a protected-floor entry is simply not overlayable). Only
  a `/proc` redirect stays a compile error (a fresh namespaced mount, never a host bind). The
  `/etc` overlay also honours a **directory** source now (fontconfig `/etc/fonts`, the CA bundle
  `/etc/ssl/certs`), where it previously created a file mountpoint and failed `ENOTDIR`.
- **The `/etc` overlay floor protects kennel's constructed `/etc`, not the operator's secrets.** The
  never-overlayable set is reframed to the persona mask (`passwd`/`group`/`hostname` — real files
  re-leak host identity, T1.1) and the dynamic-loader config (`ld.so.preload`/`cache`/`conf`/
  `conf.d` — execution integrity); `resolv.conf`/`hosts`/`nsswitch.conf` stay overlayable (that is
  the feature). An operator exposing their own `/etc/ssh` or `/etc/shadow` into a kennel they run is
  a footgun, not a blocked action (the non-root persona uid gates what it can read).
- **Ephemeral (`:0`) binds are always permitted by the cgroup bind ACL (W13).** A bind to port 0
  is a kernel-allocated ephemeral **source** port, not a reachable listening surface — so the
  `bind4`/`bind6` programs now allow it unconditionally, ahead of the port floor, the port
  allowlist, and the address ACL, and **without** the wildcard-address rewrite (an outbound socket
  needs `0.0.0.0` / `::` to stay unspecified so the kernel picks the source per route). Only port-0
  binds are affected; every explicit port is gated exactly as before, and egress from the resulting
  socket still passes the connect ACL. This is what lets a `net.mode = "host"` delegate's outbound
  UDP dial work (it binds `:0` before `connect()`); no policy needs a `[[net.bpf.bind.allow]]` for
  it. No BPF ABI or schema change; no catalogued threat is affected (T3.3 is about explicit
  *published* ports).
- **Seccomp hardening (W14).** Three pieces of defence-in-depth debt, no fail-open (the
  [seccomp mediation audit](docs/governance/audits/2026-07-seccomp-mediation.md) refuted the
  io_uring egress-bypass hypothesis — the cgroup connect fence sits at the proto-op layer io_uring
  also traverses — and confirmed the cap-gated set is closed by the workload's non-zero in-ns uid):
  - **`[seccomp] deny` composes additively.** A leaf's `deny` list now **unions** with the
    resolved base instead of replacing it, so a bare `deny = [...]` can only strengthen
    `base-confined`'s hardening, never silently drop it (the one real defect; consistent with the
    `net.*.add` / `exec.*.add` increment model). No remove form — the base deny is a floor.
  - **`base-confined` denies the io_uring, new-mount-API, and handle-open families**
    (`io_uring_{setup,enter,register}`, `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/
    `mount_setattr`, `open_by_handle_at`/`name_to_handle_at`). All cap-gated or otherwise closed
    today; the deny makes intent match enforcement. Content-only — the `base-confined` reference
    template is re-signed; no schema change.
  - **The confined workload's non-zero in-ns uid is now asserted, not just enforced.** The final
    drop before `execve` fails closed if the effective uid is 0 — a defensive check (no policy can
    request a uid-0 drop today) at the point the cap-gated set's structural closure is established.
    No code-level seccomp syscall invariant is introduced.

### Docs & tooling

- **The man pages derive from the CLI definition** (W7). The `kennel(1)` / `kennel-policy(1)`
  command synopses now come straight from the live `CommandSpec` tables (moved to
  `kennel-lib-cli`, where dispatch and `--help` read them); the hand-kept `SYNC_*` mirror in
  `gen-man` and its babysitting sync test are deleted — derive, don't duplicate-then-sync. The
  curated per-verb OPTIONS prose is keyed by verb name and checked against the live table at
  generation time, so stale curation fails the build instead of silently mis-attaching. Two
  real drifts surfaced and fixed on the way out: the `policy` usage line (CLI help and man) was
  missing the `inspect` sub-verb, and `kennel(1)` omitted `release` / `stop` / `list` /
  `daemon-reload` entirely — a new table row now appears in help and man by construction.
- **Host configuration lives in `/etc`; the vendor tree is invariants-only.** `/usr/lib/kennel` is
  package payload (FHS: static, package-owned) holding the vendor **invariants** — the
  reserved-namespace authority (maintainer key + signed templates/fragments), the threat catalogue,
  the trigger/etc-bind catalogues — while `/etc/kennel` is host configuration. The three config files
  (`system.toml`, `config.toml`, `kennel-sshd.conf`) are host config **with a vendor default**, like
  any `/etc` conffile: `install.sh` now **seeds** them into `/etc/kennel` install-if-absent (an
  existing admin copy is never clobbered) and ships **none** of them into the vendor tree; an upgrade
  removes any stale vendor copy so the tier ends up invariants-only. `kennel-lib-config` reads
  `system.toml` from `/etc` alone (the compiled defaults backstop any unset key), so the config source
  is unambiguous; the key/template/policy **search** cascades still span `/etc` + `/usr/lib`, since
  that pair *is* the host/vendor authority split the reserved-namespace gate keys on. The installer no
  longer `sed`s package-owned files per host either: a `--prefix` `libexec_dir` relocation is recorded
  where a host fact belongs — a merge-safe override in `/etc/kennel/system.toml` and a
  `/etc/systemd/user/kenneld.service.d/` drop-in — with **zero** `sed` of `/usr`. The completion
  banner names `/usr/lib/kennel` as immutable vendor payload and `/etc/kennel` as the host-config root.
- **`dev-install.sh` — a one-command dev rebuild + reinstall.** The release payload needs each binary
  built a specific way (host-side dynamic, in-view `+crt-static`, the privhelper with `bpf-egress`)
  and `stage-tree.sh` routes each from the right directory; hand-mirroring that split — and the
  `kennel-host`→`host` rename — for a one-crate change was a recurring puzzle. The new tool builds the
  workspace both ways, then hands off to the same `stage-tree.sh` + `install.sh` a release uses. It is
  the dev sibling of `build-release.sh` (native, not byte-reproducible); `stage-tree.sh` stays the
  single source of truth for the layout.

### Fixed

- **Confined-GUI readiness probe broke the headless `gui-mesh` suite case.** The `compositor-broker`
  cold-start readiness probe (which waits for the nested compositor to advertise `wl_compositor`
  before handing the client over) treated a peer that connects and then closes/errors without
  speaking Wayland as "not ready yet", looping to the 8 s display-wait timeout — so the suite's echo
  stand-in, which is not a compositor, made the consumer see `Connection reset` after 50 attempts.
  The probe now treats a peer-close or hard error *after a successful connect* as a hand-off (the
  peer is up but not talking Wayland), and only a failed *connect* keeps polling. The real
  compositor path is unchanged; the suite case passes.

### New reference content

- **The `claude` reference policy** (`kennel run claude [-- <args>]`): a maintainer-signed leaf on
  `ai-coding-strict` that resolves the Claude Code binary (both native and npm layouts), the
  Anthropic API endpoints, session state (with a read-only split over the instruction/config
  surface so agent edits cannot persist executable config into a later unconfined session), and
  the writable project root via `[fs.cwd]` — runnable with no user-authored policy. Ships with an
  in-view discovery launcher and the **`agent-tools`** fragment (the coding-agent toolset:
  `rg`/`fd`/`jq`/`patch`/own-tree process management/binary inspection/`sqlite3`).

### Threat catalogue

- **Catalogue version 0.5 → 0.6, two W2 entries added.** `T1.15` (UDP egress channel: DNS
  rebinding, exfiltration, and the naming shim) records the hostnames-only capture-by-synthetic
  posture, DNS rebinding **closed** by the broker's `net.bpf` floor at `connect()` (not accepted),
  and the two accepted residuals (in-band exfil in an approved flow = the T1.8 shape;
  AF_INET-only legacy clients fail). `T5.5` (UDP-egress broker: hostile L3 and DNS wire parsed in
  operator context) records `facade-tun` + the broker as trusted-side adversarial parsers kept
  **outside** the daemon — quarantined per-kennel, fate-shared, `net.bpf`-fenced, fuzzed — so the
  §4.3 empty-intersection claim stays scoped to the daemon. Mirrored into
  `dist/threats/catalogue.toml`; the sync guard passes.

## [0.5.0] — 2026-06-29

**Owed work and quality of life.** 0.5.0 pays the debt the two large prior releases accrued. It
**completes the connector-shape story**: the two mesh transports the schema typed but the broker
refused — `dbus-name` and `binder-connector` — are now brokered, and D-Bus mediation moves *onto*
the mesh as a standing, lazily-activated **`dbus-broker@v1`** service kennel (the daemon still
parses no protocol body). It **narrows the default view** from the whole host `/usr` to a curated
flatpak-style base, **brings keys into line with the tools operators already use** (OpenSSH wire
format, `ssh-keygen` signing), **moves the one privileged helper off `setuid-root` to file
capabilities**, and eases adoption with a standalone policy-authoring tool. Both ship gates cleared:
the `kennel-compose` authoring tool, and a **dynamic red-team** of the broker-resolution race and
the GUI confidentiality legs ([audit](docs/governance/audits/2026-06-29-dynamic-redteam-w11.md)) —
no finding. Verified on Linux 7.0 against the installed stack.

### Policy schema changes

- **Settled schema version 2 → 3** (`SETTLED_SCHEMA_VERSION` and `MIN_SETTLED_SCHEMA_VERSION` are
  both `3`). A 0.5.0 daemon loads only v3 settled policies, so any settled artefact compiled under
  0.4.0 (v2) must be recompiled. The bump is the sum of the shape changes below; a source
  `policy.toml` written for 0.4.0 recompiles unchanged except where it used a removed key.
- **`[fs.tmp]`: `private` renamed to `writable`, and `mode` removed.** `/tmp` is always a fresh
  per-kennel tmpfs in the constructed view; `writable = true` grants the workload write, absent
  leaves it read-only (the old `private = false` never bind-mounted the host `/tmp`). The per-policy
  DAC `mode` gated no real adversary — the tmpfs lives in the workload's own mount namespace, owned
  by the workload uid — so it is gone; the mount fixes `0700` internally.
- **`[binder]` user-defined service section removed.** `[[binder.provide]]`/`[[binder.consume]]`
  and kenneld's node-0 service registry were wired-but-unused, superseded by the capability mesh
  (`[[provides]]`/`[[consumes]]` → `SVC_CONNECT`). The binder transport is untouched — kenneld still
  owns node 0 and the per-kennel binder device stays the control plane. Shrinks the TCB ~250 SLOC.
- **`fs.proc.visibility` and `unix.default` removed** — each had exactly one legal value (`self`,
  `deny`) encoding a framework invariant, not an authorable choice. procfs is always self-only;
  `[unix]` is always default-deny. `[fs.proc]` keeps `hidepid`; `[unix]` keeps `abstract` and
  `[[unix.allow]]`.
- **`[[provides]]` / `[[consumes]]`: `name` and `shape` are now required** (they were already
  compile-validated as such; the schema now types them so). `endpoint`/`at` keep their documented
  defaults.
- **`[unix].abstract = "allow"`** — an ABI-gated escape hatch for a workload that needs an
  abstract-namespace peer, denied by default (the always-on Landlock `ABSTRACT_UNIX_SOCKET` scope,
  ABI ≥ 6). **`abstract = "allow"` with `net.mode = "host"` is a hard compile error** (a typed
  diagnostic citing the new threat ID): an abstract socket is scoped to the network namespace, so a
  host-mode kennel sharing the host netns would have a direct hole into the host abstract namespace
  below every other gate.
- **Templates drop the version axis.** The `@vN` suffix, `template_version`, and the `meta.toml`
  `version` key are gone — a reference is a bare name (`template_base = "base-confined"`), and the
  signature is the content commitment (the lockfile pins name → signature and hard-errors on drift).
  Coexisting "versions" become coexisting names: a breaking base change is authored as
  `base-confined-v2` and pointed at deliberately.
- **The published JSON Schema (`schema/policy.toml.schema`) is now derived from the parser structs**,
  so it cannot drift from what the compiler accepts (it previously came from a hand-kept mirror that
  omitted the `[[*.add]]` increment forms). Build-only; the runtime/TCB build is unaffected.

### Keys & signing

- **OpenSSH wire format.** Signing keys are `-----BEGIN OPENSSH PRIVATE KEY-----` and trust-store
  public keys are `ssh-ed25519 <blob> [comment]`, so **`ssh-keygen -t ed25519`** generates a key
  that works with `kennel policy compile --key` and in the trust store with no conversion. `kennel
  keygen` produces the same. The three-tier key hierarchy and rotation/revocation are unchanged.
- **SSHSIG signatures.** Settled policies are signed as detached **SSHSIG** blobs via `ssh-keygen
  -Y sign` (so a key in a file, an `ssh-agent`, or a hardware token are all transparent);
  verification is in-process against the trust-store key (never execs `ssh-keygen`). A key-management
  chapter is added to the corpus.

### CLI changes

- **`kennel-compose`** — a standalone, optional policy-authoring tool (separate install, no runtime
  dependency). *Binary-probe mode* reads an ELF's interpreter + linked-library closure to seed the
  `fs`/`exec.allow` floor and asks a structured set of capability questions; *interactive mode*
  walks the available templates and signed fragments. It emits a policy the operator owns and
  reviews; `--no-prompts` produces a maximally-restrictive CI skeleton. It is **not** an LLM and not
  a compiler.
- **`kennel inspect <name> --unix`** — surfaces a kennel's resolved `AF_UNIX` grants (§7.6.5).
- **`kennel list`** now shows the **consumer** leg of the mesh topology (who-consumes-what:
  capability, shape, required/optional, resolution state) beside who-provides-what.
- **`kennel policy upgrade` removed** — it existed only to bump template `@vN` references, which no
  longer exist (see *Policy schema changes*).
- The proposed keyword CLI split (`kennel-run`/`-policy`/`-oci`) was **prototyped, measured, and
  declined** — it tripled deployed size for no functional gain; the host CLI stays one `kennel-host`
  unit behind the context-detecting shim (the `kennel-cli` library extraction was kept).

### IPC protocol changes

- **`binder-connector` and `dbus-name` are brokered.** Both shapes were schema-typed but
  broker-refused (`UNAVAILABLE`) in 0.4.0; `SVC_CONNECT` now resolves and hands them off. The
  `binder-connector` channel delivers per-consumer authorisation decisions to a service workload at
  runtime; the `dbus-name` shape authorises which destination a consumer's existing in-view D-Bus
  facade endpoint may carry calls to (no new socket, no new path).
- **Brokered D-Bus is opt-in per consumer.** A kennel routes over the standing `dbus-broker@v1`
  only when it declares **both** `[dbus.session]` **and** a `[[consumes]]` of a `dbus-name`
  capability; `[dbus.session]` alone keeps the legacy per-consumer `host-dbus` operator delegate.
  The two coexist — wholesale `host-dbus` retirement is deferred past 0.5.0.

### Runtime & enforcement

- **View floor narrowed to the flatpak base stance.** The default view no longer binds the whole
  host `/usr`; it binds a curated base (the loader + core lib closure, CA certs, terminfo,
  locale/`gconv`, the base toolchain) so the host's sprawl is **absent**, not merely read-denied
  (construction-by-absence, closing the `readdir`-still-enumerates gap). `/var` is handled the
  flatpak way (synthesised bits, never a host bind). Two reference templates ship beside
  `base-confined`: **`base-bwrap`** (the unnarrowed bracket) and **`base-flatpak`** (the narrowed
  floor) — loudly marked reference baselines, not recommended starts.
- **`RESOLVE_NO_SYMLINKS` on writable-bind sources.** A writable bind source is resolved with
  `openat2(RESOLVE_NO_SYMLINKS)` past the shallowest writable ancestor and bound via
  `/proc/self/fd/N`, refusing a source that symlink-escapes the granted tree — closing the
  0.4.0 F1 writable-bind-source aliasing residual.
- **`kennel_meta` BPF map sealed read-only.** Created with `BPF_F_RDONLY_PROG` and frozen, so a
  workload cannot corrupt the meta map even if it reached the BPF subsystem.

### Corpus & references

- **Confined GUI desktop corpus.** A nested-compositor confined desktop on the connector mesh:
  **`gui-broker`** — a GUI-service kennel that holds the GPU (`/dev/dri/renderD128`) and the single
  host-Wayland leg, provides the reserved `org.projectkennel.wayland`, and spawns a fresh nested
  compositor per accepted mesh connection; **`gui-session`** — runs its own software-rendered `sway`
  under a private session bus, consuming the broker's display over the mesh; plus app fragments
  (`gui-desktop`, `gui-editor`, `gui-accessories`, `gui-viewers`, `gui-files`) that compose
  additively. The `compositor-broker` runs in-cage.
- **Reference policies ship and compile at install.** The payload carries the maintainer-signed
  reference policy *sources* (runnable leaves + service providers); `install.sh` mints a host signing
  key in `/etc/kennel/keys` and compiles each to a **host-signed settled artefact** under
  `/etc/kennel/policies` — a settled policy is host-specific (the loader pin embeds the host library
  closure), so it cannot be shipped pre-compiled. A thin leaf inherits reserved-namespace authority
  from the vendor-signed template it derives, so the host key signs it with no maintainer key on the
  target. Maintainer-signed templates and fragments ship to the vendor tier (`/usr/lib/kennel`),
  never to `/etc/kennel`; every shipped template carries a `meta.toml`.
- **`dbus-broker` restructured to the thin-leaf shape.** The whole D-Bus-broker shape (the host
  session-bus leg, the broker exec grant, the `org.projectkennel.dbus` provide) moves into the
  template; the provider policy is a thin leaf that derives it and pins the workload.

### Privilege model

- **Privhelper: `setuid-root` → file capabilities.** The one privileged component no longer runs
  the whole pre-drop codepath as euid 0 with the full root set. The common factory carries exactly
  `{cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin}` (no setuid bit) — a brief euid-0 window only
  for the `uid_map` write — and the **rare** host-context caps are shed onto separately-gated
  sub-helpers: `kennel-privhelper-net` `{cap_net_admin}`, `kennel-privhelper-bpf`
  `{cap_bpf,cap_net_admin,cap_perfmon}`, `kennel-privhelper-mounts` `{cap_sys_admin}`. `install.sh`
  `setcap`s on xattr-capable filesystems with a `setuid` fallback where file caps are unsupported.
  The corpus privilege model moves with the code.

### Threat catalogue

- **Abstract-socket namespace escape via host net mode** — a new entry (catalogue **v0.5**): a
  `net.mode = "host"` workload with `abstract = "allow"` would share the host abstract-socket
  namespace below the proxy/Landlock/BPF gates. Distinct from the host-network *egress* entry; the
  structural mitigation (own net-ns is the boundary) and the W8 compile-time refusal cite it.
- The **2026-06-29 dynamic red-team** (the 0.5.0 ship gate) is recorded: the connector-broker
  resolution race and the GUI confidentiality legs were driven live against the running daemon —
  no confirmed finding.

### Observability

- **Privhelper failure cause surfaced.** A factory or sub-helper construction failure now folds the
  helper's own stderr (a missing cap, a refused scope, a BPF-attach errno) into the
  operator-visible diagnostic and the journal, instead of the bare transport symptom — no `strace`
  needed. A parent-side failure between the clone and the maps-ack now fails fast instead of hanging
  to the service-stop timeout.

### Fixed

- **Host-mode BPF egress was entirely broken.** `BPF_MAP_FREEZE` was defined as command `27`
  (`BPF_MAP_DELETE_BATCH`); the real value is `22`. Sealing the egress meta map failed `EINVAL`, so
  the whole host-mode egress construction aborted. Corrected, plus a uninitialised-padding fix in
  the map-element attr.
- **Brokered-D-Bus routing regression.** `brokered_dbus` was set whenever the broker merely existed
  in the catalogue, stripping the `host-dbus` delegate from every `[dbus.session]` consumer; now
  gated on a `dbus-name` consume.
- **OCI substrate `SIGBUS`.** A base template's host `/usr/lib` read-binds were materialised over
  the image overlay, so the image's `ld.so` loaded the host glibc instead of the image's; the
  mismatch faulted. For an OCI view the image-owned FHS roots are no longer host-bound, the
  facades dir is bound directly, and the host-control-surface mask skips a read-only-parent path.

## [0.4.0] — 2026-06-25

**The service mesh.** Confined kennels now offer capabilities to one another and consume them
**by name**, every cross-kennel connection operator-declared, `kenneld`-brokered, and
deny-by-default. The catalogue is *derived* from the signed `[[provides]]` blocks of enabled
kennels — a projection of signed policy, never authored central state — so it cannot drift from
reality. On this substrate ships the **confined GUI**: a graphical app reaches a real desktop
through a per-kennel **nested Wayland compositor** run as a GUI-service kennel, completing 0.3.0's
X11 removal with no portal and no raw host-compositor socket. The cross-kennel surface was
red-teamed before ship ([audit](docs/governance/audits/2026-06-24-cross-kennel-redteam.md)): the
strong claim — *no kennel reaches another's services or the host control surface beyond its signed
grant* — held, with one fs-grant escape on the control socket found and closed. Verified on Linux
6.17 against the installed stack.

### Policy schema changes

- **`[[provides]]` / `[[consumes]]`** — the cross-kennel capability mesh. A provider offers a
  capability by `name` + typed `shape` (`af-unix` / `dbus-name` / `binder-connector`) + `endpoint`
  + optional private `key`; a consumer reaches one by `name` + `shape` + `at` + `env` + `key` +
  `required`. Resolution is a **runtime** act against the catalogue, deny-by-default; nothing in a
  declaration points at another kennel. The reserved **`org.projectkennel.*`** namespace is
  claimable only by a maintainer-signed template (a self-signed reserved provide is dropped *and*
  its policy refused); host admins may reserve further namespaces via root-owned **`[[reserved]]`**.
  Carried in the settled policy (`MeshRuntime`).
- **`[service]`** — supervision discipline for a service kennel: `restart` (`always`/`on-failure`/
  `never`) + `backoff` + `max_attempts` (≥ 1). Paired with the readiness state machine
  (`pending`/`ready`/`failed`).

### CLI changes

- **One `kennel` command, two contexts.** A static `kennel` shim installs to `/usr/bin`; the host
  execution unit and the in-cage spawn unit move under `/usr/libexec/kennel` and
  `/usr/libexec/kennel-facades`. Host-side `kennel` is the operator command; **inside a
  spawn-capable kennel the same `kennel` dispatches `run` / `caps` over the binder** — the
  `facade-spawn` binary name is **retired**. `/usr/libexec/kennel` is masked from every constructed
  view (the host control surface is ungrantable).
- **`kennel list`** carries the cross-kennel **mesh topology** — which kennels provide and consume
  which capabilities, with provider readiness.

### IPC protocol changes

- **`SVC_CONNECT`** (Node 0 facade verb) — resolves a consumer's signed `[[consumes]]` against the
  catalogue to a single provider (shape-checked, key-matched, deny-by-default, consume-with-wait for
  an on-demand provider), then brokers an `af-unix` connector through a **host-owned rendezvous
  point** and returns the connected fd. `kenneld` stays control-plane: it never parses the protocol
  that rides the connector.
- **Control-plane version handshake (W17).** The control socket now opens with a one-frame
  version preamble before any request: the client sends the settled-policy schema version it
  compiles to (and a diagnostic build identity), and a daemon that parses an older schema refuses
  a too-new client at the boundary with a typed *"restart the daemon"* remedy — instead of the
  cryptic parse error a schema skew surfaced as in 0.3.1 (a half-upgraded host: a newer CLI
  compiling a field the running older daemon could not read). The gate is the settled-policy
  *schema* version (what drifts), not a binary version. Within a release both ends are the same
  build, so it always accepts; it only bites the cross-build case, and only binds versions that
  have it (a pre-W17 daemon cannot speak it).

### Runtime & enforcement

- **The catalogue and broker.** `kenneld` derives the catalogue from the enabled kennels'
  `[[provides]]` (per-host `/etc/kennel` and per-user `~/.config/kennel`, per-user winning),
  keeping **every** provider of a shared name (a second claimant adds a candidate, never empties a
  name). The `key` is a strict discriminator: if either side sets one, both must hold the identical
  key. There is **no failover** past the preferred provider.
- **Sidecars & lifecycle.** An `autorun` sidecar set starts with the daemon under its signed
  restart policy (crash-loop-bounded → declared-but-failed); an `ondemand` provider is
  **socket-activated on first consume** and **idle-reaped** when no consumer kennel runs.
- **Confined GUI.** A GUI-service kennel runs `compositor-broker`, spawning a per-connection inner
  compositor (bring-your-own `cage`/Weston/sway, host-independent — proven on stock GNOME) reached
  as the `org.projectkennel.wayland` mesh capability; the single host-compositor leg is af-unix
  brokered, the host's other clients absent by construction. The broker is bounded (a concurrency
  cap and a connect rate limit).
- **The host control socket is ungrantable by rule.** The CLI→daemon control socket cannot be
  exposed into any view — refused on the `[[unix.allow]]` path at compile and construction, on the
  `fs.read`/`fs.write` path at compile, and over-mounted blind by the privhelper as a structural
  backstop (W15).

### Threat catalogue

- The **service-kennel trust class** is homed and its standing-service residuals catalogued and
  risk-derived (**T3.10**, **T1.12**), published at catalogue **v0.4**, with the **authentication-never-attestation** boundary made
  explicit (§4.3): the mesh confers capabilities to *use*, never attestation — there is no secrets
  broker and no signing service. The 2026-06-24 cross-kennel red-team audit is recorded.

### Fixed

- **Privhelper binder-module load.** The env-stripped privhelper invoked `modprobe` by bare name
  (no `PATH`) → `ENOENT` → the binder module never loaded → `boot-sync: kennel-bin-init did not
  report ready`. Now an absolute `/sbin/modprobe`.

### Docs & hygiene

- The README, the website, and the design/architecture corpus are reconciled to the as-built 0.4.0
  tree (accuracy pass — every public claim defensible against the substrate), and a corpus-wide
  sweep cleared built features still wearing "roadmap" labels. Single-version `W##` work-item tags
  stay out of the durable docs (roadmap only).

## [0.3.1] — 2026-06-23

**Installer fix.** The 0.3.0 release tarball was unusable: it mirrored the dev source tree and
its `install.sh` read the in-kennel binaries from a `target/<triple>/release` directory the
tarball never shipped, so the install failed on the first `kennel-bin-init`. 0.3.1 reships a
clean, flat tarball and a pure installer. Packaging only — no code, schema, CLI, IPC, or
BPF-ABI changes.

- The release tarball is now **flat** — `install.sh`, `bin/` (every binary), and
  `dist/ keys/ templates/ fragments/ man/ SHA256SUMS` — with no source-tree mirror and no
  wrapper. `install.sh` is a **pure installer**: it places the payload beside it, refuses to
  run without a `bin/` (so it never runs from a source checkout), and no longer builds (the
  `--no-build` flag is gone — `build-release.sh` builds, the new `stage-tree.sh` assembles the
  payload as the single source of truth both it and the dev/e2e install share).
- `SHA256SUMS` now covers **every** shipped file — and especially the trust-store public key —
  and `install.sh` verifies the payload against it before placing anything, aborting on any
  mismatch rather than installing a tampered key or binary.
- The `facade-spawn-probe` / `facade-spawn-bench` test drivers are no longer shipped in a
  release; they are staged only for the spawn end-to-end / benchmark harness.

## [0.3.0] — 2026-06-22

**Dynamic spawn.** A confined workload instantiates ephemeral **sibling** kennels from
operator-signed templates and talks to them over a kernel-to-kernel channel — choosing the
command within a frozen cage, never authoring policy at runtime. Plus the composable
exec-fragment catalogue, OCI substrate completion, the live topology surface, and the
"do less" latency discipline spawn forces. The spawn surface was red-teamed before ship
([audit](docs/governance/audits/2026-06-22-spawn-surface-redteam.md)): the cage held — no
escape — and the contract-vs-enforcement gaps it surfaced are fixed. Verified on Linux 6.17;
the policy test suite runs 19 self-checking cases against the installed stack.

### CLI changes

- **`facade-spawn`** — the in-kennel `SPAWN` client a workload drives: `caps` interrogates
  the kennel's `[spawn]` grant (which templates it may instantiate, the mutable fields it
  may write and their bounds, the `max_instances`/live ceiling); `run <template@version>
  [field=value]… [-- <argv>…]` instantiates the sibling and splices this process's stdio onto
  its channel. The command after `--` is the caller's choice, gated by the template's frozen
  `[exec].allow`.
- **`kennel ps` / topology** — a live view of running kennels and the spawn parent/child tree.
- **`kennel oci update`** preserves operator carve-outs across a re-pull; **`kennel oci
  revert`** selectively restores. `kennel policy sign` gained the leaf-syntax path so it signs
  a composable fragment as well as a template.

### Policy schema changes

- **`[spawn]` grant** — `max_instances` (the fork-bomb ceiling) + `[[spawn.allow]]` naming the
  signed `name@version` templates a workload may instantiate, each with an optional per-requester
  `mutable` narrowing. A loud delegated-instantiation capability (threat **T3.9**).
- **`[[mutable]]` manifest** on a spawn-target template — the leaf fields a spawn may write and
  the bound each must satisfy (`oneof` / `pool` / `pattern` / `relpath` / `freeform`). `workload.argv`
  is a mutable leaf: the caller supplies the command line, contained by the frozen `[exec].allow`
  (Landlock) and cage, not by the argument shape.
- **Composable fragments** (`include = […]`, §5.10) — signed, version-pinned, additive-only
  capability bundles under `fragments/`. Two kinds: capability (`lang-python`, `lang-node`,
  `toolchain-c`, `vcs-git`, `net-permissive`) and base userland (`core-shell` incl. `/usr/bin/env`,
  `core-coreutils`, `core-file-mutation`, `core-archive`, `net-clients`). The reference templates
  compose these instead of hand-listing.

### IPC protocol changes

- **`SPAWN`** (Node 0 facade verb) — request: a length-prefixed `name@version` then a
  count-prefixed `(field-path, value)` manifest patch, bounded to 64 KiB (enforced at decode);
  reply: a status byte, the transient `spawn-<uuid>`, and **two** `BINDER_TYPE_FD` (the socketpair
  + the stderr pipe) via `Reply::DataAndFds`. Node 0 stays accepts-fds-unset (fds flow *out* only).
- **`SPAWN_QUERY`** (Node 0 facade verb) — read-only grant interrogation; no request payload (the
  grant identifies the caller), a plain UTF-8 reply (no serializer in the daemon TCB). Exposes only
  the caller's own grant.

### Runtime &amp; enforcement

- **Spawn construction** — the privhelper factory mints the channel and constructs the sibling;
  fate-sharing is the claimed `max_instances` slot, the soft reaper (channel `EOF`), the
  template-TTL self-reap, and the hard cgroup-kill reaper. Depth-1 is enforced at the spawner's
  compile (no recursion).
- **Writable `$HOME`/`/tmp`/`/dev` tmpfs is mounted `noexec`** — extends the "writable is never
  executable" (`deny_writable`) rule from execve to mmap, closing the file-backed `PROT_EXEC`
  load path Landlock has no hook for.
- **"Do less"** — per-kennel loopback addresses are provisioned only where an inbound `bind`
  consumes them; the egress BPF attach is skipped outside `host` mode (~7–10 ms/spawn saved). A
  spawn-latency profiling harness backs the discipline.

### Threat catalogue

- **T3.9 — delegated instantiation** added with its risk derivation (`kennel policy risks`
  surfaces it). The open-value (R1) and cross-kennel-composition (R2) residuals are tagged, not
  closed; the in-kennel MCP interposer that would close R2 is explicit backlog.

### Hygiene

- X11 removed (`07-8-x11.md` is now an out-of-scope record). The bastion `sshd_config` template is
  surfaced to the `/etc/kennel` cascade. Single-version `W##` work-item tags purged from the
  durable docs (they belong only in a release roadmap). The spent 0.3.0 roadmap is retired; its
  deferred items (first-party OCI unpacker, the OCI `fs-verity` integrity ladder, the MCP
  interposer) live in `08-as-built-notes.md` §8.1.

### Internal / supply chain

- The runtime **TCB closure** stays 16 crates; dynamic spawn adds no daemon dependency (no JSON
  parser, no serializer in `kenneld`). The spawn policy compiler stays out of the daemon — `SPAWN`
  is load-verify + typed patch-apply in the verify half, never a compile.

## [0.2.0] — 2026-06-20

Persistence safety (the trust-manifest review/revert family), the authoring experience
(`policy diff`/`risks`/fragments/IDE schema), the D-Bus mediation membrane, the inbound-BIND
push, OCI substrate execution (boot a vendor image as a confined kennel root, with a confined
`oci build` fetch), and a TCB-shrinking CLI/compiler crate split. Verified on Linux 6.17
(Landlock ABI 7); the policy test suite runs 16 self-checking cases against the installed stack.

### CLI changes

- `kennel policy diff <policy> [<other>]` — the interpreted grant delta between two
  effective policies (the semantic counterpart of `policy upgrade`'s source line diff,
  `05-templates.md` §5.11/§5.13). One argument diffs a policy against its template
  baseline (what the leaf's deltas add over the template it inherits); two diff any
  pair. Each change is classified `+`/`~`/`-`, marked when it widens the workload's
  reach, and annotated with the threats it exposes/mitigates plus a net threat-posture
  delta. Terminal output is sanitised (`sanitise_for_log`); `--json` emits the delta via
  `serde_json`. Read-only; never contacts the daemon.
- `kennel policy risks` now evaluates a **delta-leaf** policy (`[[fs.read.add]]`, …), not
  only a template/source document — both verbs share the `effective_source` fold that
  folds either form to its threat-bearing effective source.
- **`kennel oci build` now performs the confined image fetch (§7.11.7).** It runs `skopeo`
  (pull) + `umoci unpack --rootless` **inside a kennel** under the maintainer-signed,
  vendor-shipped `oci-fetch@v1` policy (constrained egress to a registry allowlist;
  `fs.write` only to the store entry, added by a per-build leaf), populating `rootfs/` +
  `config.json` + a digest-pinned `digest`. The broad egress an image pull needs lives only
  there, so the operator never authors or signs it; `oci-fetch@v1` is overridable at the
  system/user layer (a private registry) via the template cascade. `--no-fetch` keeps the
  prior prepare-only behaviour (out-of-band population). Needs `skopeo` + `umoci` on the host.

### Runtime &amp; enforcement

- **Writable paths now permit symlink creation and cross-directory rename.** The Landlock
  access set a `fs.write` grant receives (`write_access`) adds `MAKE_SYM` and `REFER`: an
  ordinary writable-path workflow (an unpack, `npm`, a build, an editor's atomic save) can
  create symlinks and `rename`/`link` files between directories within the writable subtree.
  Previously both failed (`EACCES` on symlink, `EXDEV` on cross-directory rename). Landlock
  still re-checks a symlink's target on access and forbids a REFER move into a
  broader-rights directory, so neither escalates beyond the granted subtree.

### Internal / supply chain

- **The `kennel` CLI is now its own crate (`kennel-cli`), split out of `kenneld`.** The
  control-socket wire protocol moves to a shared `kennel-lib-control` crate (re-exported
  as `kenneld::{control, socket}`, so the daemon side is unchanged). This removes the
  CLI's dependencies — `serde_json` (≈ 16.5k SLOC, via the trust-manifest reader) and
  `lexopt` — from the privileged daemon's dependency closure entirely: a hard crate
  boundary in place of the previous "the daemon binary happens not to reference them".
  No change to the `kennel` or `kenneld` binaries' behaviour or surface.
- **The policy compiler is split out of the runtime crate.** `kennel-lib-policy` keeps the
  runtime verify-and-load half (settled types, `verify_settled`/`sign_settled`,
  `parse_audit_defaults`, invariant re-assertion — ~1.7k SLOC); the new
  `kennel-lib-compile` crate holds the authoring front end (source schema, template
  resolution, leaf deltas, translation, source signing, lockfile, lint, risks) and is
  linked only by `kennel-cli`. `cargo tree -p kenneld` shows zero `kennel-lib-compile` —
  the ~3.5k-SLOC compiler is now a hard crate boundary out of the daemon's TCB. The
  `[audit]` schema + translation are centralised in one module (single source of truth,
  shared by the compiler and the runtime `audit.toml` reader).
- **Leaf-binary crates consolidated** (24 → 21 workspace crates, no behaviour change): the
  four in-kennel facades become one `kennel-facade` crate (four binaries), and the two
  host-side delegates become one `kennel-host-delegate` crate (two binaries + the shared
  conduit-wire library). Binary names are unchanged.

### IPC protocol changes

- **Inbound BIND mirror (§7.5.7) is now push, not poll.** The in-kennel `facade-client`
  no longer polls node 0 with `BIND_INET` and re-arms on `AGAIN`; it registers a binder
  **callback node** per mirrored port (`REGISTER_MIRROR`) and sleeps in a server loop,
  and kenneld pushes each accepted conduit with a **one-way `DELIVER_INET`** carrying the
  fd. Removes the idle-poll CPU (a geometric 50 ms → 1 s wake per port) and the
  up-to-1 s first-connection latency. New node-0 verbs `REGISTER_MIRROR`/`DELIVER_INET`
  replace the `BIND_INET` poll; bounded by death-notify lifecycle, one-way delivery with
  a per-port bounce buffer, and port-gated registration. Internal-stable surface (kenneld
  and the facade ship from one release); no external client is affected.

## [0.1.0] — 2026-06-16

The first versioned cut. Verified on Linux 6.17 (Landlock ABI 7; ABI ≥ 6 is required for native abstract-socket and signal scoping). Pre-release: interfaces and guarantees may change.

### CLI

- `run`/`attach`/`review`/`stop`/`list` plus the `policy` group. An interactive `kennel run` is **detachable**: kenneld owns the controlling pty and brokers it, so `Ctrl-\ d` detaches without ending the workload and `kennel attach <name>` reconnects (the tmux/`docker attach` model; one PTY, take-over on reattach). `kennel review <policy>` is the operator sign-off that re-pins a workspace's `.trust-manifest.json` after legitimate edits. `kennel list` shows a `CLIENT` (attached/detached) column.
- The installer (`install.sh`) runs the post-install checks itself and prints a copy-pastable per-user bring-up; `--provision-users [GROUP]` allocates `/etc/kennel/subkennel` lines for a group.

### Policy schema

- `[tty].filter_terminal_escapes` (default `true`) — filter dangerous terminal escapes (OSC 52 clipboard, OSC 9/777 notifications, DCS/APC/PM/SOS) from the workload's PTY output at the broker (T2.6).
- `[trust].manifest` (default `true`) — maintain a masked `.trust-manifest.json` at each writable root so host tooling can detect workspace-trigger tampering (T2.8).
- `[workload]` pins the command (argv/cwd, optional `pinned`, optional `sha256` allowlist) into the signed policy; `net.mode` is one of `none`/`constrained`/`unconstrained`/`host`.

### Runtime & enforcement

- **Confinement runtime.** `kennel run` brings a kennel up and tears it down when the workload exits: mount/PID/IPC namespaces, a constructed `$HOME` view via `pivot_root` (synthetic `/etc` and `/dev`, `/proc` with `hidepid=2`, private `/tmp`, writable binds resolving to persistent host inodes), a hand-rolled Landlock filesystem + network ruleset with ABI-6 abstract-socket and signal scoping, and a seccomp denylist. The whole spawn vertical runs **unprivileged** via an identity-mapped user namespace; the only privileged component is the file-capabilities privhelper (loopback addresses, egress BPF, `gid_map` write). It loads `binder_linux` if the `binder` filesystem is absent, so binderfs mounts on hosts where the module is not auto-loaded.
- **Per-kennel egress proxy.** A blocking SOCKS5/HTTP proxy on the kennel's v4+v6 loopback; a cgroup-BPF fail-closed allowlist denies any direct `connect()` except to the proxy, which resolves names through the OS resolver and re-checks each answer against the policy. The decision refuses literal special-use destinations (loopback/ULA/RFC1918/link-local), closing the per-kennel inbound-mirror lateral edge (T1.6). One JSON Lines audit record per request.
- **Masked workspace manifest (T2.8).** A `.trust-manifest.json` at each writable root pins the SHA-256 of host-side execution triggers; the spawn view masks it invisible to the workload (an empty over-mount inside the writable bind), so a confined agent can rewrite a trigger but cannot forge its pin. Host tooling reads the real manifest; `kennel review` re-pins after legitimate edits.
- **AF_UNIX shim and SSH re-origination bastion.** A socket shim brokers granted `AF_UNIX` connects; per-kennel SSH routes through a forced-command bastion so the workload holds no key or agent socket (the double-blind design, §7.10).
- **Audit.** A unified `kennel-lib-audit` writer (one canonical event schema, one sanitisation pass, per-class levels) fanning out to file/stdout/syslog/journald sinks; the signed `[audit]` policy section selects them over installation and per-user `audit.toml` defaults.
- **Policy compiler.** `kennel policy compile` resolves a source policy — template-chain fold (the SSH `=`/`+=`/`-=` model), signed `include` fragments, leaf deltas, install-constant substitution — into a signed, byte-pinned settled policy plus `kennel.lock`. The `kennel policy` group also provides `validate`, `sign`, `list`, `show`, `edit`, `generate`, and `lint`.
- **End-to-end Ed25519 trust.** Templates, fragments, and the settled artefact are signed and verified; the lockfile pins each reference by signature — the deterministic signature *is* the content commitment, so there is no separate hash. The reference templates are signed under the project key `kennel-maint-2026` (`keys/kennel-maint-2026.pub`).
- **Supply-chain gate.** Dependencies are vendored and checksum-pinned (`supply-chain/CHECKSUMS.toml`); the CI `supply-chain` job runs `cargo deny` + `cargo audit` + `cargo vet` via pinned, hash-verified tool binaries.
- **Licensing.** Apache-2.0 for the project; the BPF programs under `src/bpf/` are GPL-2.0 (SPDX headers, a kernel requirement for GPL-declaring programs).

### Project

- **Website.** `projectkennel.org` (GitHub Pages from `docs/website/`) — landing page, a Try-it quickstart, a documentation hub, and the trust-manifest JSON Schema at the `$id` path shipped code references.
- **Docs.** `supply-chain/UNSAFE-CRATES.md` corrected to the real five `unsafe`-bearing crates (`kennel-lib-syscall`/`-landlock`/`-bpf`/`-binder`/`-scm`); README/CHANGELOG brought to the current surface.

Roadmap (designed, not yet built): the D-Bus and X11 facades, `fs.scrub`/`fs.home.sanitise`, per-kennel `[unix]` service launching, binder cross-instance relay (the MCP topology) and `SpawnKennel`-over-binder, `kennel diff`, and the composable-fragment catalogue. See [docs/archive/architecture/08-as-built-notes.md](docs/archive/architecture/08-as-built-notes.md) §8.1.
