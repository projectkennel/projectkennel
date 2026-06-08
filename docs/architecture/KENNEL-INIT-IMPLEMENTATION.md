# `kennel-init` / privhelper-factory — implementation plan

The build plan for the uid-0 construction inversion (design: [`../design/07-11-kennel-init.md`](../design/07-11-kennel-init.md);
owed corpus edits: [`BINDER-NET-INTEGRATION.md`](BINDER-NET-INTEGRATION.md)). A tracking doc:
delete a stage when it lands; delete the file when the cutover is done and the corpus is
reconciled. Not new design — design is settled in 07-11.

---

## 1. Privilege + responsibility split

| Actor | Identity / caps | Owns | Must NOT |
|---|---|---|---|
| **kenneld** | operator uid, no caps | Builds the full `Plan`; splits it construction-half / supervision-half; drives the `ConstructKennel` socketpair; receives `init_host_pid`/`workload_host_pid`; takes binder node 0 via `/proc/<init>/root`; **serves `GET_SANDBOX_PLAN`** (supervision-half bytes + pty fd) and the `NOTIFY_*` events, gated by `init_host_pid`; relays the workload exit status. | hold uid 0; `pivot_root`; parse operator input *as root* (it **is** the operator). |
| **privhelper** = **FACTORY** | host **real root**; caps `cap_sys_admin,cap_net_admin,cap_setgid` **+ new `cap_setuid`** | Parse the construction-half (host-side, no namespace yet); provenance-check + `open()` `kennel-init`; `clone(NEWUSER\|NEWNS\|NEWPID\|NEWIPC[\|NEWNET])` (child C = PID 1); in C: write `0 0 1`+operator maps, join cgroup, bring up in-ns `lo`, build the view, mount binderfs + allocate + **chown the device to operator**, `pivot_root` + detach host root, **`fexecve` `kennel-init`** (empty argv/envp); stay C's parent, report pids, relay exit status. | apply Landlock/seccomp (would confine init); make policy decisions; exec operator-named binaries. |
| **`kennel-init`** = **SUPERVISOR / spawn-owner** | uid 0 **in-userns only** (host kuid 0 via `0 0 1`); userns-scoped `CAP_SETUID`/`CAP_SETGID` only; **no ambient host caps**; trapped post-pivot; zero argv/envp | Pull config over binder; fork facades + workload; drop them to the operator; confine the **workload child**; supervise + report lifecycle; propagate exit status. | mount, netlink, device-provision, fs-lookup, env-scrub, policy-eval; confine itself or the facades; ever let operator code run as uid 0. |
| **facade children** | operator uid (dropped) | the af-unix shim today; netshim/dbus/gpg later | be Landlock/seccomp-confined (must reach the bus). |
| **workload child** | operator uid (dropped), fully confined | the user's program | regain uid 0 (`no_new_privs` makes the drop irreversible). |

**Crux invariant:** operator code never runs as userns-0. Between `clone` and `fexecve` only
privhelper code runs; after `fexecve` only the trusted root-owned `kennel-init` is uid 0; its
first operator-named `execve` (the workload) is preceded by the irreversible identity drop.

---

## 2. `kennel-init` duties

**Bring-up (pull).** `open("/dev/binderfs/binder")` → `GET_SANDBOX_PLAN` to node 0, retrying
on `BR_DEAD_REPLY` until kenneld has claimed node 0 → decode the supervision-half
(`kennel-spawn::wire::decode_plan`) → inject the pty fd (arrived as `BINDER_TYPE_FD`) into
`interactive_return_fd`.

**Spawn-owner.** For each facade: `fork`; child drops `set_gid` → `set_supplementary_groups`
→ `set_uid`, then `execve` (no Landlock/seccomp). Emit `NOTIFY_BOOT_SYNC` (facade→pid map).
Then `NOTIFY_WORKLOAD_EXEC`; `fork` the workload; child drops gid→groups→uid, then
`no_new_privs` + seccomp + Landlock (post-pivot, `skip_missing`) + ulimits + pty, then
`execve`. (This is today's `inner_seal` confinement half, minus mount/pivot/aux.)

**Supervise.** `waitpid(-1)` loop; `NOTIFY_FACADE_CRASH` on a facade death; on workload exit
`_exit(status)` — the reliable exit path is the process chain init→privhelper→kenneld, not
binder.

**Does NOT:** mount, pivot, provision binderfs, configure the network, join the cgroup, write
maps, evaluate policy, or read argv/env (there is none).

---

## 3. Current → target mapping (`kennel-spawn`/`kenneld`/`kennel-syscall`)

| Today (file:line) | Target |
|---|---|
| `spawn`/`spawn_inner` (`kennel-spawn/lib.rs:257,319`) | **deleted** as production (legacy-feature for old root tests until cutover); body split below |
| gid-map handshake: `spawn_with_gid_map`, `handshake_pipes`, `run_with_gid_map_servicer`, `gid_map_servicer`, `combine_spawn_and_servicer` (`:289,621,639,673,700`) | **deleted** — the privhelper writes the full `gid_map` once (`0 0 1`+operator+groups) with `CAP_SETGID` |
| outer seal: cgroup-join + `establish_*_userns` + `unshare` (`:525-593`) | **→ privhelper child**, rewritten as `clone` + direct map writes + `join_cgroup` |
| mount/pivot: `make_root_private`, `build_view_and_pivot`, `apply_file_binds`, `create_bind_target` (`:419,755,911,891`) | **→ privhelper child** |
| binderfs block (`:855-866`) | **→ privhelper child** + **new chown of the device to the operator** |
| confinement: tty adopt, `setup_view_pty`, group drop, `set_no_new_privs`, seccomp install, `build_ruleset`+`restrict_current_process`, ulimits (`:416-509,722`) | **→ kennel-init** (workload child only). `build_ruleset` reused as-is (shared/duplicated; it is `unsafe`-free) |
| `launch_aux_process` (`:930`) | **→ kennel-init**, generalised to fork-drop-exec per facade |
| `fork_into_pid1` (`kennel-syscall/spawn.rs:63`) | **deleted** from production (the privhelper's `clone(NEWPID)` makes C PID 1 directly) |
| `establish_identity_userns` / `establish_userns_defer_gid_map` (`namespace.rs:88,118`) | **deleted**; replaced by a new `namespace::clone_pid1` primitive |
| `attach_egress`/`populate_egress_maps`; `gid_map_set` | **reused** (egress op unchanged; `gid_map_set` feeds the construction-half map block) |
| kenneld `spawn_workload` (`lib.rs:986`) | **replaced** by `Privileged::construct_kennel(construction_half, fds) -> (init_pid, workload_pid, Supervisor)` |
| kenneld `acquire_binder_node0`/`workload_pid` (`:935,970`) | **reused, simplified** — open `/proc/<init_host_pid>/root/dev/binderfs/binder`; init pid from the privhelper, not the `/children` walk; keep the retry |
| privhelper `perform_set_gid_map` + `Op::SetGidMap` (`exec.rs:115`) | **deleted** (subsumed by construction) |

Already built this session (reused, not re-planned): `kennel-spawn::wire`
(`encode_plan`/`decode_plan`), `kennel-syscall::process::resource_name`,
`kennel-syscall::unistd::set_gid`/`set_uid`, the af-unix facade + `kennel-afunix-shim` +
`kennel_syscall::spawn::launch_aux`.

---

## 4. Resolved design questions (no ambiguity for the build)

- **cgroup join** → the privhelper child (root writes `cgroup.procs` of kenneld's delegated
  subtree; the pid it writes is C's, resolved in C's pidns — same logic as today's
  `join_cgroup`).
- **Construction-half representation** → a **typed `ConstructionHalf` struct** with its own
  bounded codec (style of `EgressPayload`), reusing `kennel-spawn::plan` types for `view` /
  `new_root` / `cgroup`. *Not* the full `Plan` — the privhelper must see only construction
  data, never the supervision-half (Landlock/seccomp/argv).
- **Loopback** → the **host-side alias** stays a separate `add_address` op kenneld calls
  *before* `construct_kennel`; bringing up the **in-namespace `lo`** moves into the
  construction child.
- **Binder reply shape** → extend `kenneld::binder::Reply` to `DataAndFd(Vec<u8>, OwnedFd)`
  so `GET_SANDBOX_PLAN` returns the supervision-half bytes and the pty fd in one reply
  (`reply_with_fd` already writes a data+offsets transaction, so it generalises).
- **privhelper lifetime** → the `ConstructKennel` op is a **distinct, long-lived** invocation
  (it persists as C's parent to relay exit status); the addr/egress ops stay one-shot.
- **Lifecycle verb codes** → distinct high range: `GET_SANDBOX_PLAN=0x100`,
  `NOTIFY_BOOT_SYNC=0x101`, `NOTIFY_FACADE_CRASH=0x102`, `NOTIFY_WORKLOAD_EXEC=0x103`
  (registry verbs 1–5 / `CONNECT_AFUNIX=5` untouched).

---

## 5. Stages (tree green between each; production path unchanged until Stage F)

- **Stage A — `clone`-based PID-1 primitive.** `kennel_syscall::namespace::clone_pid1(flags,
  child) -> pid` (the one new reviewed `unsafe`, mirroring `fork_into_pid1`). Unit: empty-flags
  works unprivileged; namespaced is a root test. *Breaks nothing.*
- **Stage B — operator-drop spawn primitives.** `kennel_syscall::spawn::fork_drop_exec(...)`
  and a confined variant that runs a seal closure before `execve`. Reuses
  `set_gid`/`set_supplementary_groups`/`set_uid`. *Additive.*
- **Stage C — the `kennel-init` crate.** New `src/crates/kennel-init` (`#![forbid(unsafe_code)]`,
  binary; deps `kennel-binder` + `kennel-spawn` + `kennel-syscall`). `main` = open device →
  pull loop → decode → spawn-owner → supervise. Add lifecycle verb consts to
  `kennel-binder::service`. Unit: feed it `encode_plan` bytes, assert the decode. *Not yet
  wired.*
- **Stage D — kenneld serves the lifecycle/config verbs.** `kenneld::binder::handle()` gains a
  lifecycle branch gated by `sender_pid == init_host_pid && sender_euid == 0` (kernel-stamped),
  before the registry/af-unix dispatch. `GET_SANDBOX_PLAN → Reply::DataAndFd`. `Manager`/`spawn`
  carry `init_host_pid` + the supervision-half bytes + optional pty fd. Root test: spoofed pid
  denied; real init pid served.
- **Stage E — privhelper `ConstructKennel` op + socketpair client.** wire: `Op::ConstructKennel`
  + the `ConstructionHalf` codec (round-trip test + fuzz target). client: `construct_kennel`
  over `socketpair(SOCK_SEQPACKET)` (sends op+payload+pty fd via `SCM_RIGHTS`, stays alive for
  pids-then-status). exec: provenance-check (`uid==0 && mode & 0o022 == 0` on the opened fd, no
  TOCTOU), `clone_pid1`, write maps (real `CAP_SETUID`/`SETGID`), join cgroup, in-ns `lo`,
  view, binderfs+chown, `pivot_root`, `fexecve`. New `kennel-syscall` `fexecve`/`clone`
  (privhelper stays `forbid(unsafe_code)`). Deployment `kennel_init()`; runner builds it +
  `cap_setuid`. Root test: fexecve a stub init, observe exit-status relay.
- **Stage F — cutover.** `bring_up` calls `construct_kennel` instead of `spawn_workload`; stash
  the supervision-half in `BinderPrep`; `acquire_binder_node0` takes `init_host_pid`; `Kennel`
  holds the `Supervisor`. Delete the gid-map handshake, `Op::SetGidMap`, `establish_*_userns`,
  `fork_into_pid1` from production. Update the full-vertical e2e + binder root-tests. *Proves:*
  a workload constructed by the factory with a real uid 0; the binderfs EACCES is gone;
  lifecycle gated by init pid.
- **Stage G — corpus reconciliation.** Work the [`BINDER-NET-INTEGRATION.md`](BINDER-NET-INTEGRATION.md)
  inversion-owed list (01-process-model, the higher-level design, trust boundaries, 02-4-ipc,
  03-crate, 07-paths, 06-build, 07-2 §7.2.8, 07-9/02-7 full text).

---

## 6. Security review points (root parses operator input; capability boundaries)

1. **privhelper parses the construction-half host-side** — root, but before any namespace
   exists; reuse the scope/cgroup/addr ownership gates (`validate.rs`, `exec.rs:184`); bounded
   codec, fuzzed.
2. **`kennel-init` parses the supervision-half post-pivot** — root-in-userns but trapped (host
   fs absent), so a decoder bug is contained; bounded (`wire.rs`), fuzzed.
3. **kennel-init provenance + `fexecve`** — path from root-owned config, never the wire; open
   once, `fstat` the fd (`uid==0`, not group/other-writable), `fexecve` the same fd (no
   TOCTOU).
4. **Escalation window** — assert only privhelper code runs between `clone` and `fexecve`, and
   the workload drop (`set_uid`+`no_new_privs`) precedes any operator-named `execve`.
5. **Lifecycle pid gate** — `init_host_pid` is the privhelper bootstrap fact, never wire-
   supplied; every forged attempt audited; `sender_euid==0` is defense-in-depth.
6. **Map authority** — the operator map line is the caller's *real* uid (from `/proc`
   ownership), never wire-supplied (same discipline as today's `perform_set_gid_map`).
7. **binderfs chown** — to the caller's real uid, inside C, before the pivot detaches.

---

## 7. De-risk order

1. **The privhelper socketpair + `clone` + `fexecve` skeleton** — the biggest departure from
   the one-shot `exchange` model and the only new `unsafe`. Prove with a stub init + exit relay
   before any real construction logic.
2. **`GET_SANDBOX_PLAN` serve vs. node-0 acquisition** — the init pull races kenneld's
   `acquire_binder_node0`; the existing retry models it; verify init tolerates `BR_DEAD_REPLY`.
3. **The kennel-init pull loop** — lowest risk (binder client reuse).
