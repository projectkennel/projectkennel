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

- **D-Bus proxy** (`07-7-dbus.md`) — designed, not built. The schema exposes only a
  per-bus `enabled` toggle (`[dbus.session]`/`[dbus.system]`); no `xdg-dbus-proxy` is
  launched and no per-method allowlist is enforced.
- **X11 isolation** (`07-8-x11.md`) — designed, not built. The schema exposes only the
  `xwayland_isolated`/`xephyr_isolated` toggles; no isolated display is constructed.
- **`fs.scrub` / `fs.home.sanitise`** (`07-4-filesystem.md` §7.4.5) — designed, not built.
  Both parse and fold up the template chain but are dropped at translate (source-only): no
  shim step overlays scrubbed files or writes the sanitised copy.
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
- **Per-kennel network namespace** (`07-5-network.md` §7.5.6, `07-11-binder-netns.md`,
  THREATS T1.6) — a kennel currently shares the host network namespace (egress is gated by
  the cgroup BPF + proxy, not net-ns isolation), so the workload can *read* host network state
  (interfaces, routes, listening sockets, the LAN ARP table) via `/proc/net/*` and
  `AF_NETLINK`. Recon-only — egress stays blocked — but a genuine info-disclosure residual.
  The closure path is now designed (`07-11`): unshare `CLONE_NEWNET` in the construction
  child, configure an in-namespace `lo`, and reach the host-side proxy across the boundary via
  the `org.projectkennel.INet` binder facade (SOCKS5 → `kennel-netshim` → `INet` `CONNECT` →
  the `kennel-netproxy` delegate) rather than a direct loopback connect — re-architecting the
  §7.5 loopback/egress model onto the four network modes (`none`/`constrained`/`unconstrained`/
  `host`) + the loopback mirror. When that lands, T1.6 closes for `none`/`constrained`/
  `unconstrained` (`mode = host` re-shares the host net-ns and deliberately reinstates the
  recon, recorded as `threats.reinstated`); until then it remains a deferred, accepted residual.
  Would also make the network-inspection tools report the kennel's own stack.
- **Binder cross-instance / inter-kennel relay** (`07-1-binder.md`, `02-4-binder.md`
  §Inter-kennel IPC) — the per-instance binder bus and node 0 are built (see below), but the
  bilateral `provide`/`consume` cross-instance relay that lets one kennel reach another
  kennel's services through kenneld (the MCP topology) is designed, not built. So is the
  `org.projectkennel.IDBus/default` D-Bus facade (the binder successor to `xdg-dbus-proxy`,
  superseding the unbuilt `07-7-dbus.md` proxy) and `SpawnKennel`-over-binder. kenneld owns
  the reserved nodes; the relay grows kenneld's TCB and is tracked as a new threat surface.
- **`[container]` runtime** (`05-templates.md` §5.7) — `[container]` is design-level *language*
  only (parse + compile-warn, same family as `[dbus]`/`[x11]`); there is no container-runtime
  integration. No shipped template uses it: `containerised-service` runs the service directly
  under the kennel (the kennel *is* the container).

### Built — now described in the chapters

Each graduated from this roadmap; its as-built detail lives in the named architecture
chapter (and the design § for the mechanism). No build notes are kept here.

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
  `pivot_root`s and `fexecve`s the trusted root-owned `kennel-init` (PID 1) with empty
  argv/envp; kenneld acquires node 0 by opening `/proc/<init-host-pid>/root/dev/binderfs/binder`
  (SCM_RIGHTS fd-passing is rejected — binder fds are per-opener — and the operator-owned userns
  is what makes the open succeed); `kennel-init` *pulls* its supervision-half via
  `GET_SANDBOX_PLAN` to node 0 (kenneld identifies the kennel by the binderfs instance the txn
  arrived on), the `NOTIFY_*` lifecycle verbs ride node 0 in the `0x100+` range gated by
  `sender_pid == init_host_pid`, and the `org.projectkennel.IAfUnix/default` facade brokers an
  AF_UNIX connect (returning the connected fd) in place of the bind-mount grant. New crates
  `kennel-binder` (unsafe ABI, parallel to `kennel-bpf`) and `kennel-init`, plus the
  `kennel-spawn::wire` Plan codec and the privhelper `ConstructKennel` op (`SOCK_SEQPACKET` +
  `SCM_RIGHTS`): `02-4-binder.md`, design `07-1-binder.md` §7.1, `07-2-kennel-init.md`.
  - **Identity map — subuid rejected, `0 0 1` chosen.** binderfs assigns its nodes to uid 0
    of the mounting userns, so the pure-identity map (`{uid} {uid} 1`) left them on the overflow
    `nobody`/`0600` and nothing in the kennel could open them. The kennel is given a real uid 0
    by mapping host root `0 0 1` (deliberately **no** subuid/subgid — "there be dragons"), plus
    the operator identity line (and one line per granted gid), written by the privhelper in a
    single `write(2)` with `CAP_SETFCAP`. There is no "0 0 N" range and no single-extent rule;
    the only constraint was always the single write. The privhelper gains `CAP_SETUID` for this;
    the old deferred-gid map handshake (§7.4.8) is subsumed — the maps are written once, fully,
    by the constructor before `kennel-init` starts. The escalation hazard of a userns-0 is
    bounded by the crux invariant: operator code never runs as userns-0 (only privhelper code
    runs between `clone` and `fexecve`; thereafter only the trusted `kennel-init`; the workload
    is dropped to the operator with `no_new_privs` before any operator-named `execve`). Design
    `07-2-kennel-init.md`; rationale also `11-open-questions.md`.
  - **`kennel-init` runs as the kennel's uid 0** (as designed): PID 1 holds a different uid
    from the operator-uid workload and facades, so they cannot signal or `ptrace` it. kenneld
    still acquires node 0 via `/proc/<init>/root` because the kennel userns is operator-owned
    (kenneld holds `CAP_SYS_PTRACE` there); `kennel-init` drops each child to the operator.
- **`[[fs.dev.passthrough]]`** — specific host devices, GID-gated (not capability), merged
  into `DevPolicy.allow`: `02-2-config-schema.md`, design `07-4-filesystem.md` §7.4.8.
- **`[identity]`** — masked `user`/`group` (default `kennel`) + supplementary `groups`
  (default drop-all; the privhelper `set-gid-map` op re-grants a specific group):
  `02-2-config-schema.md`, design `07-4-filesystem.md` §7.4 + spawn flow §8.3.
- **Writable-by-default `$HOME` + `[fs.home].readonly` + `[ulimits]`** —
  `02-2-config-schema.md`, `01-process-model.md`, design `07-4-filesystem.md` §7.4.5/§7.4.12.
- **TTL runtime reaper** (`exit`/`warn`/`renew`): `05-state-and-supervision.md`, design
  `09-policy-lifecycle.md` §9.7.
- **Deny-by-default execution + the compile-time library closure** — an empty `exec.allow`
  denies all execution; `**` is the warned `permissive-exec` opt-out; there is no `exec.deny`
  (moot under deny-by-default). The compiler resolves each allowlisted binary's `PT_INTERP` +
  transitive `DT_NEEDED` closure (via the vendored `object` crate), filters it through `[lib]`
  allow/deny, settles it into `exec.libraries`, and the seal grants `FS_EXECUTE` on exactly
  those files: design `07-3-exec.md` §7.3.4/§7.3.7.
- **Narrowed net invariant** — the non-removable deny set is cloud-metadata + link-local only;
  RFC1918/CGNAT/ULA are reachable (by `[[net.allow]]` in `constrained`, freely in `open`). A
  policy may still author its own RFC1918 `[[net.deny]]`: design `07-5-network.md` §7.5.
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
  (a grant for a path the view doesn't contain is vacuous). See `kennel-spawn::spawn`.
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
  `kennel-netproxy`) immediately before running the gated binaries.
- **Run the gated test *binaries* directly under sudo**, not `sudo cargo` (which
  leaves root-owned files in `target/`). Compile with `--features root-tests
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
