# Handoff — unprivileged spawn (user namespace) work stream

_Last updated: 2026-06-03. Branch: `master`. Pick up from here in a fresh session._

## The one thing not to get wrong

**kenneld is an UNPRIVILEGED user process. It calls a (suid/file-caps) privhelper.
No `sudo` is involved in the spawn, ever.** The workload sandbox (mount namespace,
`mount`, `pivot_root`, the constructed view) is built unprivileged by first
unsharing a **user namespace** (`CLONE_NEWUSER`, identity-mapped — the operator's
real uid/gid 1:1, no subuid), which grants `CAP_SYS_ADMIN` *inside that namespace*.
This is the bubblewrap mechanism. The privhelper (file-caps, never sudo) does only
the host-global ops a userns can't reach: `add-addr`/`del-addr`/`setup-egress` and
now `set-gid-map`.

A prior session claimed this was "proven" when the proof was a **silent test skip** —
`establish_identity_userns` was actually failing the whole time. Do not repeat that:
a skip is not a proof; tests must report the precise reason they don't run.

## State: done this session (6 commits on `master`)

| Commit | What |
|---|---|
| `b2552e5` | `kennel_syscall::namespace::establish_identity_userns` (unshare USER, setgroups=deny, identity uid/gid maps) |
| `b99eb57` | Corrected the false-proof; userns-first seal (branch on `USER`); shipped `dist/apparmor/kenneld` |
| `b43e687` | `kennel_syscall::spawn::fork_into_pid1` (double-fork) — **full unprivileged spawn proven end-to-end, no sudo** |
| `2ea21e5` | Corpus aligned: userns-as-core mechanism + AppArmor prerequisite + as-built spawn flow (design §8.2/§8.3, arch §8) |
| `c06e988` | `Plan::from_policy` emits `USER \| MOUNT \| PID \| IPC` (production on the userns path); `cgroup.kill` lifecycle (`terminate`, server `stop`) |
| `97c1c33` | Privhelper `set-gid-map` op (wire + security gates + client + tests + docs) |

All workspace lib tests green (10 crates). The full-spawn proof is
`kennel-spawn` `tests::unprivileged_userns_spawn_builds_the_confined_view`.

## Load-bearing facts established (verified, not assumed)

- **Ubuntu 23.10+/24.04 ship `kernel.apparmor_restrict_unprivileged_userns=1`.**
  Under it `unshare(CLONE_NEWUSER)` *succeeds* but the process holds **no
  capabilities** in the new userns — the first `/proc/self/setgroups` write is
  `EACCES`. Remedy = an AppArmor profile granting `userns` to the kenneld binary
  (`dist/apparmor/kenneld`). Do **not** relax the host sysctl (security-weakening;
  the auto-classifier refuses it anyway).
- **`mount proc` is `EPERM` without a PID namespace.** So the workload must be PID 1
  of its own pidns — reached by a fork *after* `unshare(CLONE_NEWPID)` (the
  double-fork). This is why `fork_into_pid1` exists; PID-as-PID-1 is not deferrable.
- **An unprivileged `gid_map` maps only the caller's own primary gid** (`man 7
  user_namespaces` rule 5). So default group-drop is free (every unmapped group →
  overflow gid `nogroup`), but **re-granting** a specific supplementary group needs
  the privhelper (`cap_setgid`) to write a multi-gid map — hence the `set-gid-map` op.
- The double-fork makes kenneld's `Child` handle the **intermediate init**, not the
  workload, so kill-by-pid leaks the workload → both forced-kill paths use
  `cgroup.kill` (`kenneld::cgroup::kill_cgroup`). `stop()`/`try_finished()` stay
  correct because the init propagates the workload's exit status.

## How to re-run the end-to-end unprivileged proof (no sudo in the spawn)

```sh
cargo test -p kennel-spawn --lib --no-run
BIN=$(ls -t target/debug/deps/kennel_spawn-* | grep -v '\.d$' | head -1)
cat > /tmp/kst.aa <<EOF
abi <abi/4.0>,
include <tunables/global>
profile kennel_spawn_test $(pwd)/$BIN flags=(unconfined) { userns, }
EOF
sudo apparmor_parser -r -W /tmp/kst.aa     # one-time host setup, additive (not weakening)
"$BIN" unprivileged_userns_spawn_builds_the_confined_view --nocapture
sudo apparmor_parser -R /tmp/kst.aa; rm /tmp/kst.aa   # clean up
```
With the profile loaded it asserts (granted path readable, secret name absent,
`/proc` live); without it, it **skips with the precise cause** (never a false pass).

## Remaining work (next session)

### 1. Spawn-time gid_map handshake — the hard half of the gid_map op
The privhelper `set-gid-map` op is built and tested; what's missing is calling it at
the right moment in the spawn. An unprivileged process can map only its own primary
gid, so the privhelper must run in the **init userns** (where it has `cap_setgid`)
against the spawn child's pid, **after** the child created its userns and **before**
the workload uses the group. Two designs (pick one):

- **(a) kenneld-side**: child A creates the userns (writes `uid_map` + `setgroups=deny`,
  but NOT `gid_map`), sends "ready, pid=P" down a pipe and blocks; kenneld — on a
  thread, because `Command::spawn` blocks until A execs — calls
  `kennel_privhelper::client::set_gid_map(P, gids)`, then unblocks A.
- **(b) in-spawn helper**: A pre-forks H *before* `unshare(USER)` (so H stays in the
  init userns); A creates the userns and signals H; H execs the privhelper (which
  then has `cap_setgid` over A's userns) to write the map; H signals A to continue.
  Keeps it all in `kennel-spawn` (no kenneld threading) but is delicate post-fork
  pipe plumbing and needs the privhelper path threaded into the seal.

Only needed for **re-granting** a supplementary group (e.g. `dialout` device
passthrough). Default-drop-all needs none of it.

### 2. e2e off sudo
`src/crates/kenneld/tests/e2e.rs` is a ~400-line root scenario that overrides
`plan.namespaces = MOUNT` and uses the legacy `setgroups`. To run it as the ordinary
user it needs: uid = real user, home = real home, namespace from the user's
`/etc/kennel/subkennel`, a **writable delegated cgroup** (the dev box runs in a
`session-NNN.scope`, so this likely needs `systemd-run --user` to get into
`user@<uid>.service`), the privhelper installed with file-caps
(`sudo setcap cap_net_admin,cap_sys_admin,cap_setgid=ep …` — one-time), the AppArmor
`userns` profile loaded, and the group assertion changed to default-drop (or the
gid_map handshake from task 1 for the granted case).

## Key files

- Spawn primitive: `src/crates/kennel-syscall/src/spawn.rs` (`fork_into_pid1`),
  `src/crates/kennel-syscall/src/namespace.rs` (`establish_identity_userns`).
- Seal split (outer/inner, branch on `USER`): `src/crates/kennel-spawn/src/lib.rs`.
- Plan namespaces: `src/crates/kennel-spawn/src/plan.rs` (`from_policy`).
- Lifecycle: `src/crates/kenneld/src/cgroup.rs` (`kill_cgroup`),
  `src/crates/kenneld/src/lib.rs` (`Instance::terminate`),
  `src/crates/kenneld/src/server.rs` (`stop`).
- Privhelper op: `src/crates/kennel-privhelper/src/{wire,validate,exec,client}.rs`.
- Deploy artifact: `dist/apparmor/kenneld`.
- Corpus: design `08-enforcement-architecture.md` §8.2/§8.3; architecture
  `07-paths.md`, `02-4-ipc.md`, `08-as-built-notes.md`.
