# §8 Implementation notes: roadmap, lessons, and gotchas

The design and architecture chapters describe the system as built. This chapter
collects what does not belong in a surface description: the pieces that are
designed but not yet implemented (roadmap), the implementation lessons that
should shape the rest of the build, and the build/test gotchas that bite.

## 8.1 Roadmap — designed, not yet built

The as-built behaviour of every shipped feature lives in the design and architecture
chapters. This section is only (a) what is genuinely **not built yet**, and (b) a
pointer index for features that recently graduated from this roadmap — no build-log
narration is kept here; the chapter named is the source of truth.

### Not built yet

- **`fs.scrub` / `fs.home.sanitise`** (`07-4-filesystem.md` §7.4.5) — designed, not built. Both
  config surfaces have been **removed from the schema** (rejected at parse) rather than parsed +
  dropped at translate; the design stands as roadmap.
- **Run-environment `template` file-loading** (`07-9-other.md` §7.9.2a) — the one unbuilt
  piece of the otherwise-built run environment. `[env].template` / `[fs.home].template`
  would seed values/dotfiles from a policy-referenced file pinned at compile; it needs the
  same compiler file-input plumbing as the `audit.toml` defaults — a convenience over the
  inline `[env].set` / built-in dotfile defaults that work today.
- **TTL interactive `renew` prompt** (`09-policy-lifecycle.md` §9.7) — the reaper is built
  (`05-state-and-supervision.md`); the desktop/terminal renewal prompt is not (kenneld is a
  daemon with no session channel), so `renew` behaves as an audited `warn` today.
- **`[unix]` deferred bits** (`07-6-afunix.md` §7.6) — the core socket shim is built; still
  owed: per-kennel service launching (§7.6.7), the `abstract = "allow"` escape hatch
  (ABI-gated), and the `--dry-run`/`inspect` shim output (§7.6.5).
- **Daemon-side accept-unsigned dev mode** (`09-policy-lifecycle.md` §9.10, `algorithm =
  "none"`) — not built; `kennel run`'s in-memory compile-and-sign dev loop covers the
  local-dev need without a daemon change.
- **`kennel_meta` read-only sealing + readback verification** (`02-7-bpf-abi.md`) — the map
  is written once by loader convention but not frozen (`BPF_F_RDONLY_PROG`) nor read back to
  validate `magic`/`abi_version`.
- **Composable fragment catalogue** (`05-templates.md` §5.10) — **built.** The `include`
  mechanism and the curated set of signed à-la-carte fragments (`lang-python`, `lang-node`,
  `toolchain-c`, `vcs-git`, `net-permissive`) ship under `fragments/`, signed by the
  maintainer key, installed into the runtime template search dir, surfaced by `kennel policy
  list` as `(fragment)`, and gated in CI (`kennel-lib-compile/tests/fragments_catalogue.rs`:
  signature + additive-only + compile-and-assert per fragment). `kennel policy sign` gained
  the leaf-syntax (fragment) signing path. `net-permissive` is a curated broad-egress
  allowlist, not a `net.mode` flip (a mode override belongs in the inheritance chain, not an
  additive fragment).
- **Binder cross-instance / inter-kennel relay** (`07-1-binder.md`, `02-4-binder.md`
  §Inter-kennel IPC) — the per-instance binder bus and node 0 are built (see below), but the
  bilateral `provide`/`consume` cross-instance relay that lets one kennel reach another
  kennel's services through kenneld (the MCP topology) is designed, not built, as is
  `SpawnKennel`-over-binder. kenneld owns the reserved nodes; the relay grows kenneld's TCB and
  is tracked as a new threat surface.
- **`[container]` runtime** (`05-templates.md` §5.7) — there is no container-runtime integration,
  and the `[container]` config surface has been **removed from the schema** (rejected at parse)
  rather than kept as design-level language. No shipped template uses it: `containerised-service`
  runs the service directly under the kennel (the kennel *is* the container).

### Built — now described in the chapters

Each graduated from this roadmap; its as-built detail lives in the named architecture
chapter (and the design § for the mechanism). No build notes are kept here.

- **D-Bus mediation** (`07-7-dbus.md`, `02-4-binder.md` §Node 0) — the `org.projectkennel.IDBus/default`
  facade and the membrane: `facade-dbus` (in-kennel) speaks D-Bus to the workload and the `DBUS_*`
  verbs to node 0; kenneld is the membrane (per-connection state + rate cap) relaying opaque frames to
  the `host-dbus` delegate over the owner-only pipe; the `[dbus]` policy surface gates the session/system
  buses. Proven by the `dbus-session-allowed` / `dbus-deny-wins` policy-suite cases.
- **`kennel policy diff`** (`05-templates.md` §5.11/§5.13, `02-1-cli.md`) — the interpreted,
  threat-impact-annotated effective-policy delta (`+`/`~`/`-` per grant, each with the threats it
  exposes/mitigates, a widening marker, and a net threat-posture summary). One argument diffs a
  policy against its template baseline (the §5.13 *your-deltas* view); two diff any pair. Built on
  the shared `kennel-lib-compile::effective_source` fold (the same threat-bearing folded source the
  `risks` engine reads — which now folds delta-leaves too). The engine lives in `kennel-lib-compile`
  (out of the daemon TCB); the CLI renders the terminal view through `sanitise_for_log` and `--json`
  through `serde_json`. `02-1-cli.md` (`kennel policy diff`).
- **Per-kennel network namespace + INet egress** — egress kennels unshare `CLONE_NEWNET` in the
  construction child, bring up in-ns `lo` + the loopback mirror, and reach egress only across the
  binder gateway (`facade-socks5` → `CONNECT_INET` → kenneld → `host-netproxy` dumb dialer); the
  net-ns boundary *is* the egress gate and cgroup-BPF drops to defence-in-depth. Closes T1.6 for
  the net-ns modes (`/proc/net` + netlink now reflect the kennel's own stack): `07-5-network.md`,
  `02-5-binder-net.md`.
- **Four network modes + the `[net.proxy]`/`[net.bpf]` split** — the mode enum is the four-tier
  taxonomy `none`/`constrained`/`unconstrained`/`host`: `none` is an own empty net-ns,
  `constrained`/`unconstrained` an own net-ns + SOCKS proxy (default-deny vs. default-allow-minus-
  invariant), `host` shares the host net-ns for direct egress with no proxy (`reason`-gated; its
  T1.6 exposure is derived from the mode and surfaced by `kennel policy risks`, not stored on a
  field). Policy is split by enforcer: `[net.proxy]` (the user-space
  by-name allow + `deny.invariant`/`deny.policy` the proxy enforces, proxied modes only — a
  by-name rule under `host` is a compile error) and `[net.bpf]` (the kernel CIDR+port ACL, no
  names, present in every mode, author-narrows-only against the framework lock). The
  `[net.bpf].connect` AND `[net.bpf].bind` ACLs are enforced (cgroup `connect4`/`6` + `bind4`/`6`
  BPF + Landlock `CONNECT_TCP`/`BIND_TCP`, deny-first over dedicated allow/deny LPM tries); all
  layers intersect and evaluate deny-first: `07-5-network.md`, `02-5-binder-net.md`.
- **Inbound host-side BIND mirror (§7.5.7)** — a port the workload binds inside the kennel is
  exposed back on the host at the kennel's own loopback alias, the pull-based reverse of egress:
  `host-inetd` (the inbound delegate, reverse of `host-netproxy`) binds each policy-mirrored
  `ip:port` on host `lo`, accepts, splices locally, and pushes the conduit's kennel end to kenneld;
  `facade-client` (in-kennel, reverse of `facade-socks5`) pulls each conduit with the `BIND_INET`
  node-0 verb and connects the workload's native listener. kenneld is a stateless fd router with NO
  inbound policy decision (the `bind4`/`6` ACL already gated the bind) and the `BIND_INET` handler
  never parks a binder looper (`AGAIN` re-arm; the wait lives in a per-port reader thread).
  Hardware-proven by the `net-bind-mirror` e2e.
- **Run-environment synthesis** — `env_clear` + synthesised `envp`, `[exec].shell`, system
  rc, user dotfiles, `[fs.home].persist`: design `07-9-other.md` §7.9.2a.
- **Unified audit writer + four sinks** — file/stdout/syslog/journald, per-class filtering,
  `audit.toml` defaults merge, `gzip(1)`-at-rest, and privhelper operations recorded by
  kenneld on its behalf (`source: privhelper`, so no audit write is ever privileged):
  `02-3-audit-schema.md`.
- **BPF audit ring-buffer drain** — per-kennel `audit_ringbuf`, owner-only pin under
  `/run/user/<uid>/kennel/bpf/<id>/`, drained by the unprivileged kenneld via `BPF_OBJ_GET`:
  `02-3-audit-schema.md`, `02-7-bpf-abi.md`, `07-paths.md`.
- **`kennel-sshd` SSH egress bastion** + root-owned `kennel-akc` `AuthorizedKeysCommand`
  (bindings live only in the running kenneld; no `authorized_keys` file): `01-process-model.md`,
  `02-6-ipc.md`, design `07-10-ssh.md` §7.10.
- **`[unix]` AF_UNIX socket shim** — granted sockets bind-mounted into the view, abstract
  denied by the always-on Landlock scope: design `07-6-afunix.md` §7.6.
- **Binder gateway core — the per-kennel inter-namespace gateway** — every kennel runs a
  per-instance binderfs bus with kenneld as node 0, the kennel's auditable unprivileged
  boundary crossing, carrying the construction/lifecycle control plane and the protocol
  facades. Built and proven by the unprivileged vertical (`src/tools/unprivileged-e2e.sh`):
  the privhelper *factory* clones the namespaces as the operator (so the userns is
  operator-owned), its child self-escalates to the kennel's uid 0 to build the root-owned
  view/`/dev`/library binds and binderfs, mounts binderfs + chowns the device to the operator,
  `pivot_root`s and `fexecve`s the trusted root-owned `kennel-bin-init` (PID 1) with empty
  argv/envp; kenneld acquires node 0 by opening `/proc/<init-host-pid>/root/dev/binderfs/binder`
  (SCM_RIGHTS fd-passing is rejected — binder fds are per-opener — and the operator-owned userns
  is what makes the open succeed); `kennel-bin-init` *pulls* its supervision-half via
  `GET_SANDBOX_PLAN` to node 0 (kenneld identifies the kennel by the binderfs instance the txn
  arrived on), the `NOTIFY_*` lifecycle verbs ride node 0 in the `0x100+` range gated by
  `sender_pid == init_host_pid`, and the `org.projectkennel.IAfUnix/default` facade brokers an
  AF_UNIX connect (returning the connected fd) in place of the bind-mount grant. New crates
  `kennel-lib-binder` (unsafe ABI, parallel to `kennel-lib-bpf`) and `kennel-bin-init`, plus the
  `kennel-lib-spawn::wire` Plan codec and the privhelper `ConstructKennel` op (`SOCK_SEQPACKET` +
  `SCM_RIGHTS`): `02-4-binder.md`, design `07-1-binder.md` §7.1, `07-2-kennel-bin-init.md`.
  - **Identity map — subuid rejected, `0 0 1` chosen.** binderfs assigns its nodes to uid 0
    of the mounting userns, so the pure-identity map (`{uid} {uid} 1`) left them on the overflow
    `nobody`/`0600` and nothing in the kennel could open them. The kennel is given a real uid 0
    by mapping host root `0 0 1` (deliberately **no** subuid/subgid — "there be dragons"), plus
    the operator identity line (and one line per granted gid), written by the privhelper in a
    single `write(2)` with `CAP_SETFCAP`. There is no "0 0 N" range and no single-extent rule;
    the only constraint was always the single write. The privhelper gains `CAP_SETUID` for this;
    the gid map is part of this single write (§7.4.8) — the maps are written once, fully,
    by the constructor before `kennel-bin-init` starts. The escalation hazard of a userns-0 is
    bounded by the crux invariant: operator code never runs as userns-0 (only privhelper code
    runs between `clone` and `fexecve`; thereafter only the trusted `kennel-bin-init`; the workload
    is dropped to the operator with `no_new_privs` before any operator-named `execve`). Design
    `07-2-kennel-bin-init.md`; the no-subuid decision is in `../design/04-trust-boundaries.md`.
  - **`kennel-bin-init` runs as the kennel's uid 0** (as designed): PID 1 holds a different uid
    from the operator-uid workload and facades, so they cannot signal or `ptrace` it. kenneld
    still acquires node 0 via `/proc/<init>/root` because the kennel userns is operator-owned
    (kenneld holds `CAP_SYS_PTRACE` there); `kennel-bin-init` drops each child to the operator.
- **`[[fs.dev.passthrough]]`** — specific host devices, GID-gated (not capability), merged
  into `DevPolicy.allow`: `02-2-config-schema.md`, design `07-4-filesystem.md` §7.4.8.
- **`[identity]`** — masked `user`/`group` (default `kennel`) + supplementary `groups`
  (default drop-all; the privhelper `set-gid-map` op re-grants a specific group):
  `02-2-config-schema.md`, design `07-4-filesystem.md` §7.4 + spawn flow §8.3.
- **Writable-by-default `$HOME` + `[fs.home].readonly` + `[ulimits]`** —
  `02-2-config-schema.md`, `01-process-model.md`, design `07-4-filesystem.md` §7.4.5/§7.4.12.
- **TTL runtime reaper** (`exit`/`warn`/`renew`): `05-state-and-supervision.md`, design
  `09-policy-lifecycle.md` §9.7.
- **Deny-by-default `execve` + per-binary loader resolution** — an empty `exec.allow` denies
  all `execve`; `**` is the warned `permissive-exec` opt-out; there is no `exec.deny` (moot
  under deny-by-default). `FS_EXECUTE` gates `execve` only (the kernel opens a dynamic binary
  AND its `PT_INTERP` `FMODE_EXEC`), so the compiler resolves each allowlisted binary's loader
  (`PT_INTERP`, via the vendored `object` crate), settles it into `exec.loaders`, and the seal
  grants `FS_EXECUTE` on the binaries + their loaders. It does **not** execute-gate libraries:
  Landlock has no `mmap` hook, so they load via `READ` — there is no `[lib]` section and no
  closure (the earlier filter was unenforceable). Boundary verified by `kennel-lib-spawn`'s
  `exec_gating` test; design `07-3-exec.md` §7.3.4/§7.3.7.
- **Narrowed net invariant** — the non-removable deny set is cloud-metadata + link-local only;
  RFC1918/CGNAT/ULA are reachable (by `[[net.proxy.allow]]` in `constrained`, freely in
  `unconstrained`). A policy may still author its own RFC1918 deny via `[[net.proxy.deny.policy]]`:
  design `07-5-network.md` §7.5.
- **Interactive controlling terminal** — the seal allocates the workload's pty inside the
  kennel's own post-`pivot_root` devpts (so `ttyname`/`tty` resolve and the operator's tty is
  never exposed), `setsid` + `TIOCSCTTY` + `dup2`s it onto stdio, and hands the master back to
  the CLI over a socketpair for proxying; non-interactive runs pass stdio straight through:
  design `07-9-other.md` §7.9.5a.
- **Bind-port policy** — `min_port` floor + `allowed_ports`, enforced in `bind4`/`bind6`:
  `02-7-bpf-abi.md`, design `07-5-network.md` §7.5.7.
- **ssh-agent footgun** — warned (at validate/compile/runtime), not forbidden: design
  `05-templates.md` §5.9 / `07-10-ssh.md`.
- **`kennel run` auto-compile** — in-memory compile-and-sign of a source policy for the
  local-dev loop: design `09-policy-lifecycle.md` §9.10.
- **`kennel-checksum-verify`** — settled, not owed: the shell witness
  `src/tools/verify-checksums.sh` is the implementation (`06-build-and-test.md`); a Rust twin
  is a contingent §5.5.1 `sha2`-vendoring call.
- **Config-schema reference — complete** (the 2026-06-11 documentation-gaps audit is closed).
  `02-2-config-schema.md` now carries a field-level table for **every** section, kept exact
  against the parser structs in `kennel-lib-policy/src/source.rs` (`[net]`/`[net.*]` and
  `[binder]`/`[ipc.spawn]` inline as before; `[exec]`/`[fs.*]`/`[identity]`/`[env]`/`[cap]`/
  `[seccomp]`/`[proc]`/`[ptrace]`/`[signal]`/`[lifecycle]`/`[ssh]`/`[unix]`/`[workload]`/
  `[ulimits]`/`[audit.*]` in §The remaining sections). The earlier correctness bugs — the
  `[unix]` `path`/`access` phantom fields, the `[env]` "no `pass`" claim, the `[fs]`
  `create`/`exec_allowed_from` phantoms, and the `ttl_action` enum — are reconciled in the
  design chapters and the `source.rs` doc-comments too.
- **Threat catalogue + `kennel policy risks`** — the threat framework is now evaluated, not just
  parsed. `THREATS.md` (canonical prose) gains a machine form `dist/threats/catalogue.toml`
  (id/family/scope/title/one-line-residual), kept in sync by a CI check
  (`src/tools/tests/threats-catalogue.sh`) and loaded by `kennel-lib-policy::threats` (with an
  embedded fallback). `kennel-lib-policy::risks` evaluates a resolved source policy into an
  exposed/mitigated/residual report — authored `threats` tags plus the compiler-derived exposures
  (`mode=host`→T1.6, passthrough→T2.1, `allow_headless`→T1.6) — and `kennel policy risks <policy>`
  surfaces it (`02-1-cli.md`). The stale "compiler records `threats.reinstated`" claim is corrected
  everywhere to "derived" (no such field exists; the settled artefact carries no threat tags by
  design). `kennel policy diff` (above) builds the interpreted *delta* between two policies (the
  `+/~/-` threat-impact view) on this same `risks` + catalogue foundation. Tag-correctness as a hard
  lint (invalid/missing-required → non-zero) is a noted `--strict` follow-up.
- **Pre-release schema + CLI consistency sweep** — removed surface clutter (no compat shims, per
  the pre-release policy): the dead `[net].proxy_listen_v4`/`v6` booleans (only `proxy_listen_*_address`
  was ever consumed — a family is on iff its address resolves); the duplicate top-level `[proc]`
  (procfs settings now live only in `[fs.proc]`, beside the other constructed-view sub-tables); and
  the scattered advisory `[ptrace]`/`[signal]` sections folded under one `[unsafe]` umbrella
  (`[unsafe.ptrace]`/`[unsafe.signal]`) so the footgun is visible — their scoping is real but
  PID-ns/seccomp-enforced, so declaring one still warns. CLI: `upgrade` moved under `policy`
  (`kennel policy upgrade`, beside the other policy verbs); `compile --output-path` renamed to
  `--output` to match `sign`; the `policy` usage string + summary corrected. The `man`/help drift
  guards (the `kennel.rs` sync-test + the gen-man regen-check) kept these honest.

## 8.2 Implementation lessons (apply these to the rest)

- **A read-only bind remount must preserve the source's locked flags inside a userns.**
  `mount(MS_BIND|MS_REMOUNT|MS_RDONLY)` that *clears* a flag locked on the source
  superblock (`nosuid`/`nodev`/`noexec`) is `EPERM` in an unprivileged user namespace —
  the kernel permits clearing locked flags only with real privilege. So
  `mount::remount_readonly` `statvfs`es the target and carries the locked flags into the
  remount (this matters when binding a file from a `nosuid,nodev` mount — e.g. the
  `AF_UNIX` socket on the `$XDG_RUNTIME_DIR` tmpfs). It is also strictly more restrictive
  (a read-only grant never wants `suid`/`dev`), and a source without those flags (the root
  fs under `/usr`) is unaffected, so an executable bind stays executable. The lesson
  generalises: under a userns, a remount may only *add* restrictions.
- **The kenneld `AppArmor` profile is `flags=(unconfined)`; its only job is to grant
  `userns`.** An enforcing profile cannot confine kenneld here: the forked spawn child
  shares the profile and needs `userns`/`mount`/`pivot_root`/`sys_admin` to build the
  sandbox, then sets `PR_SET_NO_NEW_PRIVS` (seccomp requires it) and execs the arbitrary
  workload — and under no-new-privs the kernel denies *every* AppArmor exec transition
  (`Ux`→unconfined and even `Cx`/`Px`→stricter both give `apparmor="DENIED" …
  info="no new privs"`). That leaves only `ix` for the workload, which would inherit
  kenneld's `mount`/`userns`/`sys_admin` — worse than unconfined. The workload is confined
  by Landlock + seccomp + namespaces, not AppArmor; confining it via AppArmor would need
  runtime `aa_change_onexec` (a v2 question). See `dist/apparmor/kenneld`.
- **Userns-dependent proofs must report their precise skip cause, and be confirmed with
  `--nocapture`.** `cargo test` captures a passing test's output, so a test that skips
  (e.g. where the host lacks the `AppArmor` `userns` grant) still reads as a green `ok`
  unless its skip cause is surfaced. The spawn proofs `eprintln!` the exact reason; the
  production proof is the off-sudo runner `src/tools/unprivileged-e2e.sh`, which loads the
  `userns` profile. Relaxing the host sysctl is not the remedy (security-weakening).
- **The Landlock ruleset must be built *after* `pivot_root`, in the child.** A rule
  opens an `O_PATH` fd at build time and is keyed to that inode. Bind mounts preserve
  inodes (so system/home/dev rules match a parent-built ruleset), but the constructed
  `/etc` has fresh tmpfs inodes a host-opened fd would never match — libc would be
  denied `/etc`. So the seal builds the ruleset post-pivot with a *skip-missing* pass
  (a grant for a path the view doesn't contain is vacuous). See `kennel-lib-spawn::spawn`.
- **The process is ephemeral; the work is not.** The new root is a throwaway tmpfs,
  but every *writable* bind resolves to a persistent host inode (the agent's real
  project tree), so work survives teardown. Any new writable surface must keep this
  property — never let something the workload means to keep live only on the tmpfs.
- **Fail closed, and prove it adversarially.** Every BPF decision path defaults to
  `KENNEL_DENY`; every new scope/right ships with a test that shows the *denied*
  case actually denies on the running kernel (the IPv4-mapped-IPv6 connect, the
  abstract-socket scope, the device ioctl). A test that only shows the allow path
  is half a test.
- **Landlock denial errnos differ by class.** Filesystem/network rules deny with
  `EACCES`; scoping (`SCOPE_*`) denies with `EPERM`. Accept both when asserting "the
  scope bit fired".
- **The daemon's TCB is bounded by crate boundary, not vigilance — and it only
  shrinks.** The runtime trusted computing base is the dependency closure of the
  privileged binaries (`kenneld`, `kennel-privhelper`, `kennel-bin-init`); a compromise
  of anything in it breaks confinement. The structural rule is that anything the daemon
  does **not** need to *verify-and-load and supervise* lives in its own crate, outside
  that closure: the operator CLI is `kennel-cli` (its `serde_json`/`lexopt` deps stay
  there), the policy **compiler** is `kennel-lib-compile` (the daemon links only the
  verify-and-load `kennel-lib-policy` half), the control wire is `kennel-lib-control`,
  and the trust-manifest reader is `kennel-lib-manifest`. `cargo tree -p kenneld` must
  show **none** of those. The inventory and the TCB-closure total live in
  `03-crate-decomposition.md` § "Crate inventory and TCB". When adding a dependency or a
  feature, ask first whether it lands in the TCB closure; if the daemon does not strictly
  need it, put it behind a crate boundary the daemon does not cross. The TCB is a budget
  that goes down, not up — a heavyweight dep (a JSON/serialisation stack, an async
  runtime, a parser the daemon does not run) reaching `kenneld`'s closure is a regression
  to be refused, not absorbed.

## 8.3 Build and test gotchas

- **Rebuild the BPF privhelper before root tests.** A workspace `cargo test` /
  `cargo clippy --all-targets` rebuilds `kennel-privhelper` with default features,
  clobbering the `--features bpf-egress` binary; the `kenneld` e2e then fails with
  `ENOSYS`. Always `cargo build -p kennel-privhelper --features bpf-egress` (and
  `host-netproxy`) immediately before running the gated binaries.
- **Run the gated test *binaries* directly under sudo**, not `sudo cargo` (which
  leaves root-owned files in `target/`). Compile with `--features e2e
  --no-run`, then `sudo ./target/debug/deps/<name>-<hash>`. Use `pkill -x kenneld`,
  never `pkill -f` (which matches the harness wrapper and kills the shell).
- **Stage shim / `/etc` / new-root dirs outside `/tmp`.** The seal mounts a fresh
  tmpfs over `/tmp` before the shadow binds; a `/tmp`-staged source vanishes.
  Production stages under `$XDG_RUNTIME_DIR`; tests under `/run`.
- **`cargo fmt --all` is a gate — run it before committing.** Default rustfmt (no
  `rustfmt.toml`); `cargo fmt --all -- --check` runs in CI and the pre-commit/pre-push
  hooks, so the corpus is rustfmt-clean and new code must be too. (This reverses the
  earlier hand-formatting convention; the corpus was reflowed when the gate was added.)
- **A required new settled-schema field touches every fixture.** Adding a
  non-defaulted field to a policy struct forces every `FsPolicy`/`Plan` literal
  across crates into the same commit.
- **`src/fuzz` is a separate workspace with its own `Cargo.lock`; CI runs it
  `--offline --locked`.** Any change to the *transitive* dep graph of its path-deps
  (it links `kenneld`, so a change to kenneld's deps counts) staleness the fuzz lock,
  and the `fuzz` CI job fails to resolve even though the shipped build is fine — the
  main `--frozen --locked` gate never reaches it. After a crate restructuring,
  regenerate it: `cd src/fuzz && cargo update --offline` (it inherits the repo-root
  `.cargo` vendor config), then commit `src/fuzz/Cargo.lock`. It does not enter the
  main Cargo.lock or `CHECKSUMS.toml`, so its only failure mode is the stale lock.
