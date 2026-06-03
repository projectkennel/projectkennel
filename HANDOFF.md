# Handoff — unprivileged spawn (user namespace) work stream

_Last updated: 2026-06-04. Branch: `main`. Pick up from here in a fresh session._

## The one thing not to get wrong

**kenneld is an UNPRIVILEGED user process. It calls a (suid/file-caps) privhelper.
No `sudo` is involved in the spawn, ever.** The workload sandbox (mount namespace,
`mount`, `pivot_root`, the constructed view) is built unprivileged by first
unsharing a **user namespace** (`CLONE_NEWUSER`, identity-mapped — the operator's
real uid/gid 1:1, no subuid), which grants `CAP_SYS_ADMIN` *inside that namespace*.
This is the bubblewrap mechanism. The privhelper (file-caps, never sudo) does only
the host-global ops a userns can't reach: `add-addr`/`del-addr`/`setup-egress` and
`set-gid-map`.

**A skip is not a proof, and `cargo test` hides skips.** The userns-dependent
proofs `eprintln!` their precise skip cause, but a *passing* libtest captures
stdout/stderr, so a silent skip reads as a green `ok`. Always confirm a real run
with `--nocapture` (or the runner). On Ubuntu (`apparmor_restrict_unprivileged_userns=1`)
the spawn binary needs an `AppArmor` `userns` profile or the userns is created but
capability-stripped; without the profile every userns proof skips.

## State: the two remaining action items are DONE this session (4 commits on `main`)

| Commit | What |
|---|---|
| `e00ca04` | `kennel_syscall::handshake` pipe primitive + `namespace::establish_userns_defer_gid_map` (userns with the `gid_map` deferred) |
| `f9d4fe9` | `kennel_spawn::spawn_with_gid_map` — the deferred-gid handshake, design (a): scoped servicer thread services A's pid pipe while `Command::spawn` blocks |
| `7298365` | `kenneld`: `Privileged::set_gid_map` + `HelperClient` impl + `bring_up`/`spawn_workload` wiring (userns + granted group → handshake); `FakePriv` made `Sync` |
| `1687fc9` | The **unprivileged off-sudo e2e** (`kenneld tests/e2e.rs` rewritten to the userns path) + `src/tools/unprivileged-e2e.sh`; **`mount::remount_readonly` locked-flags fix** |

All 413 workspace lib tests green; `cargo clippy --workspace --all-targets --all-features -D warnings` clean (incl. the `bpf-egress` privhelper).

### 1. Spawn-time gid_map handshake — DONE (design (a), kenneld-side)

Re-granting a supplementary group on the userns path (§7.2.8): child A establishes
the userns with the `gid_map` **deferred** (`establish_userns_defer_gid_map`: unshare
USER + `setgroups=deny` + `uid_map`, **not** `gid_map`), signals its pid down a pipe,
and blocks. Because `Command::spawn` blocks the calling thread until A execs, a scoped
**servicer thread** inside `kennel_spawn::spawn_with_gid_map` reads the pid, calls the
privhelper `set-gid-map` (it holds `CAP_SETGID` in the init userns), and acks — only
then does A fork the PID-1 grandchild and exec. The servicer polls the pipe with an
`AtomicBool` cancel flag, *not* EOF (the parent keeps a copy of the write end alive in
`Command`'s stored `pre_exec` closure). `kenneld::spawn_workload` builds the mapper from
`dedupe(real_gid + plan.supplementary_groups)`; a `set-gid-map` refusal fails the spawn
closed. Default drop-all (no granted group) still needs none of this — the single-line
`gid_map` collapses every other group to the overflow gid for free.

### 2. e2e off sudo — DONE

`kenneld tests/e2e.rs` is rewritten to the production userns path and runs as the
ordinary operator. It derives uid/home/namespace, the delegated cgroup
(`/proc/self/cgroup`), the reserved scope and the loopback addresses from the live
environment; keeps `USER|MOUNT|IPC|PID`; re-grants a real supplementary group via the
handshake; and asserts **userns-correct** group isolation (every supplementary gid is
the primary, the overflow gid, or the granted one — the legacy `id -G | wc -w == 2`
does not hold once unmapped groups fold to `nogroup`). Missing prerequisites skip with
the precise cause.

Run it: **`src/tools/unprivileged-e2e.sh`**. It does the one-time host setup
(build + `setcap cap_net_admin,cap_sys_admin,cap_setgid=ep` the privhelper, provision
an `/etc/kennel/subkennel` line for the uid, load an `AppArmor` `userns` profile over
the test binary) and runs the test under `systemd-run --user --scope -p Delegate=yes`
(for a writable delegated cgroup). Proven on 6.17: view + synthetic `/etc` + `~/.ssh` +
`AF_UNIX` shim + `/dev/net/tun` passthrough + the gid_map-handshake group grant, all
unprivileged.

## Load-bearing facts established (verified, not assumed)

- **The off-sudo proof needs four host prerequisites** (the runner sets all up): the
  privhelper with file-caps; an `/etc/kennel/subkennel` allocation for the operator's
  uid; an `AppArmor` `userns` profile over the spawn binary (Ubuntu restriction); and a
  **writable delegated cgroup** — a plain login `session-NNN.scope` is root-owned, so the
  test is re-executed under `systemd-run --user --scope -p Delegate=yes` (which delegates
  the scope subtree). Where any is missing the test skips with that precise cause.
- **A userns RO bind remount may only ADD restrictions.** `mount(MS_BIND|MS_REMOUNT|
  MS_RDONLY)` that clears a flag locked on the source superblock (`nosuid`/`nodev`/
  `noexec`) is `EPERM` inside an unprivileged userns. Binding the `AF_UNIX` socket (source
  on the `nosuid,nodev` `$XDG_RUNTIME_DIR` tmpfs) failed until `mount::remount_readonly`
  learned to `statvfs` the target and carry the locked flags into the remount. This only
  ever worked on the legacy root path, where clearing locked flags is allowed.
- **`apparmor_restrict_unprivileged_userns=1`**: the `flags=(unconfined) { userns, }`
  per-binary profile grants the new userns full caps (the map writes succeed). An
  *unconfined* process instead transitions to the stock cap-denying `unprivileged_userns`
  profile on `unshare`. Relaxing the sysctl is refused (security-weakening) and is not the
  remedy; the production analogue is `dist/apparmor/kenneld` over the real daemon.
- **An unprivileged `gid_map` maps only the caller's own primary gid** (`man 7
  user_namespaces`), so re-granting a *specific* supplementary group needs the
  privhelper's multi-gid write — hence the handshake.

## Remaining work (next session)

The two action items from the previous handoff are complete. Open follow-ons:

- **CI/runner for the off-sudo e2e.** `src/tools/unprivileged-e2e.sh` uses `sudo` for the
  one-time setcap/subkennel/AppArmor steps and `systemd-run --user`. Wiring this into CI
  needs a runner with a systemd user session, AppArmor, and the ability to setcap — decide
  the CI shape (privileged setup stage + unprivileged test stage).
- **kennel-sshd §7.8.9 regression tests** — the only minor item left on the SSH stream
  (separate from this work).

## Key files

- Handshake primitive: `src/crates/kennel-syscall/src/handshake.rs`;
  deferred userns: `src/crates/kennel-syscall/src/namespace.rs`
  (`establish_userns_defer_gid_map`).
- Spawn handshake: `src/crates/kennel-spawn/src/lib.rs`
  (`spawn_with_gid_map`, `run_with_gid_map_servicer`, `gid_map_servicer`).
- kenneld wiring: `src/crates/kenneld/src/lib.rs` (`Privileged::set_gid_map`,
  `spawn_workload`, `gid_map_set`).
- Privhelper op: `src/crates/kennel-privhelper/src/{wire,validate,exec,client}.rs`
  (`set-gid-map`).
- RO remount fix: `src/crates/kennel-syscall/src/mount.rs` (`remount_readonly`).
- Off-sudo e2e + runner: `src/crates/kenneld/tests/e2e.rs`,
  `src/tools/unprivileged-e2e.sh`.
- Deploy artifact: `dist/apparmor/kenneld`.
- Corpus: architecture `08-as-built-notes.md` (§8.1 identity groups, §8.2 lessons),
  `02-4-ipc.md` (set-gid-map), `07-paths.md` (`cap_setgid`); design
  `08-enforcement-architecture.md` §8.2/§8.3.
