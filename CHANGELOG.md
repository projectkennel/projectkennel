# Changelog

All notable changes to Project Kennel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the project follows semantic versioning from 0.1.0, its first versioned cut.

Per [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md), changes that touch a stable surface are recorded under a section named for that surface: `### CLI changes`, `### Policy schema changes`, `### Audit schema changes`, `### IPC protocol changes`, `### BPF ABI changes`. Dependency changes (§5), MSRV changes (§2), and threat-catalogue changes are also recorded here.

## [Unreleased]

## [0.4.0] — 2026-06-26

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
  risk-derived (**T3.10**, **T1.12**), with the **authentication-never-attestation** boundary made
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

Roadmap (designed, not yet built): the D-Bus and X11 facades, `fs.scrub`/`fs.home.sanitise`, per-kennel `[unix]` service launching, binder cross-instance relay (the MCP topology) and `SpawnKennel`-over-binder, `kennel diff`, and the composable-fragment catalogue. See [docs/architecture/08-as-built-notes.md](docs/architecture/08-as-built-notes.md) §8.1.
