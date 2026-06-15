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

- **D-Bus proxy** (`07-7-dbus.md`) — designed, not built. The `[dbus]` config surface has been
  **removed from the schema** (a policy declaring it is now rejected at parse, not carried as a
  no-op toggle); the design stands as roadmap, and the binder successor is
  `org.projectkennel.IDBus/default` (below), not the old `xdg-dbus-proxy`.
- **X11 isolation** (`07-8-x11.md`) — designed, not built. The `[x11]` config surface
  (`xwayland_isolated`/`xephyr_isolated`) has been **removed from the schema** (rejected at
  parse); the design stands as roadmap.
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
- **Composable fragment catalogue** (`05-templates.md` §5.10) — the `include` mechanism is
  built; the curated set of à-la-carte fragments (`lang-python`, `lang-node`, `toolchain-c`,
  `net-permissive`, `vcs-git`) is not yet authored/signed. Work owed is content + per-fragment
  tests, not mechanism.
- **`[net.bpf].bind` CIDR gate + inbound host-side mirror** (`07-5-network.md` §7.5.6) — the four
  network modes, the `[net.proxy]`/`[net.bpf]` split, and the `[net.bpf].connect` ACL are all built
  (see below). What remains roadmap is the *inbound* path: the `[net.bpf].bind` ACL language parses
  and settles, but the CIDR bind gate is not yet wired into the cgroup `bind4`/`6` BPF, and the
  host-side mirror (the INet `BIND` verb exposing a bound port host-side) is not built. The
  bind-port floor (`[net.bind].min_port`/`allowed_ports`) is the bind protection enforced today.
- **Binder cross-instance / inter-kennel relay** (`07-1-binder.md`, `02-4-binder.md`
  §Inter-kennel IPC) — the per-instance binder bus and node 0 are built (see below), but the
  bilateral `provide`/`consume` cross-instance relay that lets one kennel reach another
  kennel's services through kenneld (the MCP topology) is designed, not built. So is the
  `org.projectkennel.IDBus/default` D-Bus facade (the binder successor to `xdg-dbus-proxy`,
  superseding the unbuilt `07-7-dbus.md` proxy) and `SpawnKennel`-over-binder. kenneld owns
  the reserved nodes; the relay grows kenneld's TCB and is tracked as a new threat surface.
- **`[container]` runtime** (`05-templates.md` §5.7) — there is no container-runtime integration,
  and the `[container]` config surface has been **removed from the schema** (rejected at parse)
  rather than kept as design-level language. No shipped template uses it: `containerised-service`
  runs the service directly under the kennel (the kennel *is* the container).

### Config-schema reference — documentation gaps owed (audit 2026-06-11)

The schema reference (`02-2-config-schema.md`) is built: it carries full field-level tables for
`[net]`/`[net.*]` and `[binder]`/`[ipc.spawn]`, and **delegates** every other section's
field-by-field detail to its design chapter (§7.x). An audit of those delegation targets — checked
against the parser structs in `src/crates/kennel-lib-policy/src/source.rs` as ground truth — found
most resolve, but these do not. The mechanism is done; what is owed is backfilling these specific
field tables (in the §7.x chapter, or pulled into `02-2`). Two are correctness bugs, not just
omissions, because the doc names fields the parser does not accept (or vice versa).

- **`[unix]` / `[[unix.allow]]`** (`07-6-afunix.md` §7.6.4) — **WRONG, not just thin.** The doc
  documents the superseded shim-model field names `path`/`access`; the parser's `UnixAllow`
  accepts `name`/`real`/`shim`/`env`/`reason`/`threats`. The doc also describes `[[unix.deny]]`
  and `[[unix.allow_abstract]]` tables that the parser rejects (`deny_unknown_fields`). A policy
  copied from the doc fails to parse. Owed: rewrite §7.6.4 to the real `UnixAllow` schema.
- **`[lifecycle]`** (`09-policy-lifecycle.md` §9.7) — **PROSE-ONLY, with a stale source comment.**
  No field table: `ttl` format/limits and the `ttl_action` enum are not specified. The accepted
  `ttl_action` set is `exit | stop(alias) | warn | renew` (see `translate.rs` ~L880), but the
  `LifecycleSection` doc-comment in `source.rs` claims only `"stop"/"warn"` — fix the comment too.
  Owed: a `ttl`/`ttl_action` field table; note `reconsent_interval` (§9.8) is designed-not-built
  and would be rejected at parse.
- **`[env]`** (`07-9-other.md` §7.9.2) — **PROSE-ONLY.** Parser `EnvSection` is `pass`/`deny`/`set`;
  the doc covers `set` by example and explicitly (and wrongly) says there is "no `pass` list".
  Owed: a field table for all three.
- **`[seccomp]`** (`07-9-other.md` §7.9.6) — **PARTIAL.** Parser is `profile`/`deny`/`allow`; the
  doc omits `allow`. Owed: add `allow`.
- **`[fs.*]` subtables** (`07-4-filesystem.md`) — **PARTIAL/PROSE-ONLY.** No field tables for
  `[fs.home].persist`/`.readonly`, `[fs.tmp].mode`, `[fs.proc]` (`visibility`/`hidepid`), or
  `[fs.dev]` (`allow`/`passthrough`) + `[[fs.dev.passthrough]].threats.mitigated`. The §7.4.4
  prose also names `create`/`exec_allowed_from`, which the parser does not accept (verify and
  strike). Owed: per-subtable field tables + reconcile the phantom fields.
- **`[identity]`** (`07-4-filesystem.md` §7.4.8) — **PARTIAL.** `groups` shown by example; `user`
  and `group` (both default `kennel`) appear only in prose. Owed: a three-field table.

Clean (delegation resolves, no action): `[exec]` (§7.3.4), `[ssh]`/`[[ssh.destinations]]`
(§7.10.8), `[ulimits]` (§7.4.12), `[cap]`/`[proc]`/`[ptrace]`/`[signal]` (§7.9.1/§7.9.3).

### Built — now described in the chapters

Each graduated from this roadmap; its as-built detail lives in the named architecture
chapter (and the design § for the mechanism). No build notes are kept here.

- **Per-kennel network namespace + INet egress** — egress kennels unshare `CLONE_NEWNET` in the
  construction child, bring up in-ns `lo` + the loopback mirror, and reach egress only across the
  binder gateway (`facade-socks5` → `CONNECT_INET` → kenneld → `host-netproxy` dumb dialer); the
  net-ns boundary *is* the egress gate and cgroup-BPF drops to defence-in-depth. Closes T1.6 for
  the net-ns modes (`/proc/net` + netlink now reflect the kennel's own stack): `07-5-network.md`,
  `02-5-binder-net.md`.
- **Four network modes + the `[net.proxy]`/`[net.bpf]` split** — the mode enum is the four-tier
  taxonomy `none`/`constrained`/`unconstrained`/`host`: `none` is an own empty net-ns,
  `constrained`/`unconstrained` an own net-ns + SOCKS proxy (default-deny vs. default-allow-minus-
  invariant), `host` shares the host net-ns for direct egress with no proxy (`reason`-gated, auto
  `threats.reinstated = ["T1.6"]`). Policy is split by enforcer: `[net.proxy]` (the user-space
  by-name allow + `deny.invariant`/`deny.policy` the proxy enforces, proxied modes only — a
  by-name rule under `host` is a compile error) and `[net.bpf]` (the kernel CIDR+port ACL, no
  names, present in every mode, author-narrows-only against the framework lock). The
  `[net.bpf].connect` ACL is enforced (cgroup `connect4`/`6` BPF + Landlock `CONNECT_TCP`,
  deny-first); all layers intersect and evaluate deny-first: `07-5-network.md`,
  `02-5-binder-net.md`.
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
    the old deferred-gid map handshake (§7.4.8) is subsumed — the maps are written once, fully,
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
