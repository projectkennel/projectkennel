# 2026-11-19 — whole-tree review of the reference monitor: findings and fixes

**Status of this document (2026-11-25):** two parts, both closed.

- **The first review.** Its 69 rows are all fixed and shipped in 0.8.1 (tag `v0.8.1`,
  2026-11-20; PRs #239 and #240). What it left open is under
  [Where this landed](#where-this-landed).
- **The [follow-up review](#follow-up-review-2026-11-24).** It covers the code the first review
  skipped, plus a quality assessment of the TCB. Its rows (N-01 to N-23, and N-24 found while
  reviewing the fixes) are fixed in PR #244. The quality assessment's recommendations are
  worked through in PRs #245 to #274, listed under its "Suggested order". All of it is merged
  to `main` and none of it is in a release yet; 0.8.2 is the release that carries it.

What is still open after that work is not in this file: it is in CODING-STANDARDS.md
Appendix A.1 (the newtypes that touch the signed policy format and the plan wire layout).

## What was reviewed, and how

- **Scope:** all first-party Rust under `src/crates` (31 crates, about 95k lines), the BPF programs
  under `src/bpf`, the installers and packaging scripts, at `main` = `ef7f963` plus the
  `fix/cli-name-before-file` diff.
- **Method:** nine independent read-only reviews, one per trust boundary, each told to skip what
  THREATS.md, BACKLOG.md and earlier audits already record as accepted. Every critical and high
  finding was then re-read against the code by a second reviewer.
- **Dynamic checks:** ten findings were checked on a test VM (Ubuntu 26.04, kernel 7.0, aarch64,
  AppArmor) through the installed `kennel` CLI and daemon, with suite-style signed policies and
  controls alongside. These were control checks (does the control hold?), not exploit development.
- **Limits:** nothing was tested on SELinux, on x86_64, or on a kernel older than 7.0. Each
  reviewer listed files it did not read; the larger gaps are parts of `kennel-lib-compile`
  (`unix.rs`, `spawn.rs`, `identity.rs`), the facade SOCKS and TUN code, and `kenneld/src/inbound.rs`.

## Reading the table

- **Evidence:** `VM` = reproduced on the test VM. `read ×2` = confirmed by two independent readings
  of the code. `read` = one reviewer's reading only. `kernel?` = depends on kernel behaviour that
  has not been tested.
- **Status:** `fixed` (with the commit and the test that guards it), `partial`, `open`.
- **Reach:** who can trigger it. `workload` = code confined in a kennel. `local user` = any
  unconfined process on the host that can run the helper (it is world-executable by default).
  `author` = whoever writes a policy or repository the operator then uses. `operator error` = a
  mistake that silently weakens a control.

## Root causes

Most findings are instances of six patterns. Fixing a pattern closes several rows.

| | Pattern | Rows |
|---|---|---|
| A | The privileged helper trusts its caller, and host uid 0 exists in a user-reachable place | R-06 R-07 R-08 R-09 R-10 R-28 |
| B | A registration verb authorises by where the message arrived, not who sent it | R-01 R-15 L-01 |
| C | Addresses are not canonicalised before matching | R-03 R-23 R-24 |
| D | Host-side code follows paths a workload controls | R-14 R-19 R-33 R-34 R-11 |
| E | The D-Bus driver is filtered as an ordinary destination | R-02 |
| F | The threat catalogue claims a control the code does not deliver | R-07 (T5.4), R-23 (T1.6), R-25 (line 172), R-01 (line 616), R-32 (T2.8), L-05 (line 186). The first five became true when their rows were fixed; for L-05 the T1.8 text was corrected instead (#243, `77ab437`, merged 2026-11-24) |

## Critical and high

| ID | Finding | Reach | Where | Evidence | Status |
|---|---|---|---|---|---|
| R-07 | The kennel user namespace was owned by the operator and maps host uid 0, so any process at the operator's uid could join it and become host root, or enter the kennel | local user | `kennel-privhelper/src/construct.rs` (the euid drop before `clone`) | VM | **fixed** `ebce4c3`; suite case `ns-not-enterable` (`352450b`) |
| R-06 | The construction child, as host uid 0 before `pivot_root`, performs file operations on caller-supplied paths: root read and write on the host | local user | `kennel-lib-spawn/src/lib.rs` (`build_view_and_pivot`), `kennel-privhelper/src/construct.rs` | read ×2; kernel premise VM (via R-07) | **fixed** for the pre-pivot root operations (`85fee8c`); suite case `construction-as-operator`. Residual: R-42 |
| R-28 | The same pre-pivot root operations follow symlinks a previous workload run left in a writable grant | workload | `kennel-lib-spawn/src/lib.rs` (`create_bind_target`, the `file_binds` copy, mask targets) | read | **fixed** for root impact (`85fee8c`). Residual at the operator's own authority: R-43 |
| R-08 | bpffs is mounted, with `CAP_SYS_ADMIN` in the host mount namespace, on a path under the caller's runtime directory, resolved by name | local user | `kennel-privhelper/src/construct.rs` (`ensure_bpf_pin_bpffs`) | VM | **fixed** `2adffc7` |
| R-09 | Wire-supplied `granted_gids` go into `gid_map` with no membership check in the helper; gid 0 is always mapped and `kennel-bin-init` will drop a workload to it | local user | `kennel-privhelper/src/construct.rs` (`build_identity_maps`), `kennel-bin-init` | read | **fixed** `2adffc7` |
| R-10 | The mounts sub-helper checks ownership of a path, then mounts by name (race); its `unmount` verb is gated only on a sentinel file the caller can create | local user | `kennel-privhelper/src/bin/privhelper-mounts.rs` | VM (unmount, and the fix); read (race) | **fixed** `2adffc7` |
| R-01 | `ADD_SERVICE` on a mesh bus has no sender check and overwrites, so any participant can replace a provider — including the D-Bus broker for every other kennel | workload | `kenneld/src/mesh_bus.rs` (`mesh_add_service`) | VM (an ordinary consumer's `ADD_SERVICE` for the broker was answered OK) | **fixed** `6cebda7`; suite case `registration-denied` |
| R-15 | `REGISTER_TUN_SINK` is accepted on every kennel's bus and the sink is daemon-global, so any kennel can receive every other kennel's UDP egress | workload | `kenneld/src/binder.rs`, `kenneld/src/tun_sink.rs` | VM (an ordinary kennel's `REGISTER_TUN_SINK` was answered OK) | **fixed** `6cebda7`; suite case `registration-denied` |
| R-16 | A failed `BC_REPLY` leaves the following `BC_FREE_BUFFER` unconsumed and `write_only` ignores `write_consumed`: a peer can pin node 0's buffer for good | workload | `kennel-lib-binder/src/client.rs` | VM (8 × 8 KiB one-way sends accepted, then every send fails) | **fixed** `2791ff5`; suite case `binder-oneway-buffer` |
| R-03 | IPv4-mapped IPv6 literals and AAAA answers bypass the proxy's special-use gate and every v4 deny CIDR | workload | `kennel-lib-policy/src/netaddr.rs`, `kenneld/src/inet/allow.rs` | VM | **fixed** `6ce7b5f`; suite case `net-mapped-literal` |
| R-24 | The same bypass at the BPF layer: `connect6` consults only the v6 maps, and a `*` allow covers the mapped range; the `IPV6_V6ONLY` hook only acts if the workload calls that option | workload (host mode) | `src/bpf/connect6.bpf.c`, `src/bpf/setsockopt.bpf.c` | VM | **fixed** `6ce7b5f`; suite case `net-host-aliases` |
| R-23 | Host mode stamps the "own loopback" proxy allow although there is no private net namespace, opening the host's `127.0.0.1` and `::1` | workload (host mode) | `kenneld/src/lib.rs` (`stamp_proxy` call), `kennel-lib-spawn/src/plan.rs` | VM (UDP; TCP is stopped by Landlock) | **fixed** `6ce7b5f`; suite case `net-host-aliases` |
| R-19 | For an af-unix provide, kenneld path-connects from the host into a directory the provider can write; a symlink there redirects the connection to any socket the operator can reach, including the control socket | workload (provider + consumer) | `kenneld/src/binder.rs`, `kenneld/src/server.rs` | VM | **fixed** `5012eb6`; suite case `mesh-rendezvous-symlink` |
| R-33 | `[[provides]]` `name` and `key` have no grammar check, yet the daemon joins them into a host path it creates, chmods and binds writable | author (signed, enabled provider) | `kennel-lib-compile/src/mesh.rs`, `kenneld/src/mesh.rs` | VM (a `[[provides]]` name of `x/../../../../tmp/…` compiled) | **fixed** `5012eb6`; suite case `mesh-rendezvous-symlink`, unit tests in `meshname` |
| R-34 | `kennel review --revert` writes pinned blobs through symlinks, and a manifest shipped by a cloned repository is trusted (paths with `..`, unverified blob names) | workload; author | `kennel-lib-manifest/src/lib.rs` | read ×2 | **fixed** `fcf9ff0`; five unit tests in `kennel-lib-manifest` |
| R-11 | Signing stages the message in `/tmp/kennel-sign-<pid>` via `create_dir_all`; root signs through it with the host key at install | local user | `kennel-cli/src/shared.rs` (`sshsig_sign`) | read ×2 | **fixed** `3e01d19` |
| R-02 | Once `org.freedesktop.DBus` is in `talk` (every suite policy has it), all driver methods are forwarded; `own` is carried to the broker and never read | workload with a `[dbus]` grant | `kennel-lib-dbus/src/filter.rs`, `kennel-dbus-broker` | VM (with only the driver granted and an empty `own`, `RequestName` succeeded) | **fixed** `b50022b`; suite case `dbus-driver-mediated`, unit tests in `filter` |

## Medium

| ID | Finding | Reach | Where | Evidence | Status |
|---|---|---|---|---|---|
| R-04 | The bastion's host-side `ssh` keeps its escape character and forwardings (`~C` on OpenSSH < 9.2) | workload with an `[ssh]` grant | `kenneld/src/sshd.rs` | unit test; OpenSSH < 9.2 untested | fixed |
| R-05 | A malformed deny CIDR compiles and signs, then is dropped at runtime | operator error | `kennel-lib-compile/src/translate.rs` (`parse_cidr`), `kenneld/src/inet.rs` | unit tests (compile + load) | fixed |
| R-12 | A bare name that matches no installed policy silently falls back to a file in the working directory; `policy compile` then signs it | author | `kennel-cli/src/shared.rs` (`resolve_name_then_file`) | read ×2 | **fixed** in #239 (`54c83c0`, `e313b65`), narrowed by design: a name now resolves before a same-named file, with a note, but a word that names no policy still falls back to a file so `policy compile policy.toml` works |
| R-13 | `kennel review` re-pins what is on disk at confirm time, not what it displayed | workload | `kennel-lib-manifest/src/lib.rs` (`apply_review`) | read ×2 | **fixed** `fcf9ff0`; unit test `a_repin_refuses_a_trigger_that_changed_after_it_was_reviewed` |
| R-17 | Daemon-initiated binder transactions busy-spin on a non-blocking fd with no deadline | workload (as a peer) | `kennel-lib-binder/src/client.rs` (`cycle`) | suite `binder-peer-stalled` (1001 ticks before, 4 after) | fixed |
| R-18 | Handlers take a handle from payload bytes with no proof the driver translated it | workload | `kennel-lib-binder/src/service.rs`, `kenneld/src/binder.rs` | unit test; no forged-object e2e | fixed |
| R-20 | The workload sha256 pin is skipped whenever CLI arguments are appended under `allowed_args` | workload (persistence) | `kenneld/src/server.rs` | unit test | fixed |
| R-21 | Audit events over 4096 bytes are rejected by the sink and the timeout wrapper discards the error: no record, no drop event | workload with a `[spawn]` grant | `kennel-lib-audit/src/timeout.rs`, `sinks.rs` | unit test | fixed |
| R-22 | Any `accept()` error on the control socket ends the daemon; an unbounded inbound bounce queue can drive it to the fd limit | workload + a host-local peer | `kenneld/src/server.rs`, `kenneld/src/inbound.rs` | unit tests | fixed |
| R-25 | `sock_create` admits every type and protocol in the inet families; ICMP ping sockets carry data past the ACL with no audit | workload (host mode) | `src/bpf/sock_create.bpf.c` | suite `net-host-socket-types` (5 kinds created before, refused after) | fixed |
| R-26 | `listen()` on an unbound TCP socket, and a UDP bind to port 0, skip the bind policy and the wildcard rewrite; there is no ingress hook | workload (host mode) | `src/bpf/bind4.bpf.c`, `bind6.bpf.c` | suite `net-host-unbound-listen` | fixed |
| R-27 | Several ports or protocols on one CIDR collapse to the last map entry; deny rules ignore ports and protocol | operator error (fails closed) | `kennel-lib-compile/src/translate.rs`, `privhelper-bpf.rs` | suite `net-host-port-rules`; unit tests | fixed |
| R-29 | No Landlock ABI floor is enforced; on ABI 5 (kernel 6.10–6.11) scoping is silently absent. README says ABI 6, the kernel floor gives ABI 5 | workload (host mode, old kernel) | `kennel-lib-landlock/src/lib.rs`, `kennel-bin-init` | unit test; no ABI 5 kernel available | fixed |
| R-30 | The seccomp denylist matches exact numbers under one arch value, so x32 twins are unfiltered on x86_64 kernels built with x32 | workload | `kennel-lib-syscall/src/seccomp.rs` | unit test (filter shape); x86_64 untested | fixed |
| R-31 | Read-only binds are recursive but the read-only remount is not; in OCI mode Landlock relies on the mount being read-only | workload (OCI, nested mount) | `kennel-lib-spawn/src/lib.rs` | read; suite regression only, no nested-mount case | fixed |
| R-32 | The trust-manifest mask, tripwire and `review` do not cover the `[fs.cwd]` write grant | workload | `kennel-lib-spawn/src/plan.rs`, `kennel-cli` | unit test (mask); CLI side by reading | fixed |
| R-35 | The TOML parser has no depth limit and a quadratic header index, and runs before signature verification with no size cap | anyone who can place a file the daemon loads | `kennel-lib-toml/src/de.rs` | tests/limits.rs | fixed |
| R-36 | Key tier is decided by `key_id` string while `KeySet` accepts duplicate ids (first wins) and the compile loader lists the vendor directory last | author (with `--trust-dir`) | `kennel-lib-policy/src/keys.rs` | unit test | fixed |
| R-37 | The `fs.redirect` write-set floor compares unsubstituted strings, omits write-redirect sources, and is not re-run after substitution or a spawn patch | author | `kennel-lib-policy/src/invariant.rs` | unit test (invariant); plan check by reading | fixed |
| R-38 | The chain fold drops `deny` increments when the parent is also an increment, or the section is absent in the parent | author; operator error | `kennel-lib-compile/src/resolve.rs` (`fold_listfield`) | unit test | fixed |
| R-39 | `fs.dev.allow` bypasses passthrough loudness; `is_additive_only` misses `fs.cwd`, `fs.dev.allow`, `net.udp` and others; fragments are never `validate()`d | author | `kennel-lib-compile/src/dev.rs`, `source.rs`, `compile.rs` | unit tests; `reason` rule not applied to fragments | fixed |
| R-40 | `policy diff` and `risks` emit nothing for `[dbus]`, `[fs.cwd]`, `fs.home.persist`, `[env].set`, `[seccomp]` and more | author | `kennel-lib-compile/src/diff.rs`, `risks.rs` | unit test (diff); `risks` unchanged | fixed |
| R-41 | `[policy.workload]` without `argv`, `[rootfs]` without `path`, and `dbus.audit_level` without a bus are parsed and honoured but left out of the signed bytes | anyone who can edit a settled file | `kennel-lib-policy/src/settled.rs` | unit test | fixed |
| R-42 | Residual of R-06. `kennel-bin-init` is kuid 0 in a view that holds binds of host paths the caller chose; it created a mesh mount target by name at its bus peer's direction, a root `mkdir` that could land on a bound host inode | local user | `kennel-bin-init/src/main.rs` (`place_mesh_mounts`) | read | **fixed** `387d4dc`; init's remaining root path uses are a `chdir` and a `stat` |
| R-43 | Residual of R-28. Destinations beneath the new root were resolved by name before the pivot, so a symlink in a writable grant (or an OCI image) could redirect an operator-identity copy, or make a mask or bind land off the path it must cover | workload | `kennel-lib-spawn/src/lib.rs` | VM (on main a symlink at `.trust-manifest.d` let the kennel start with the mask misplaced) | **fixed** `387d4dc`; suite case `mount-point-symlink` |
| R-14 | `oci revert -- <path>` follows symlinks in the workload-written upper; its containment check is a lexical `starts_with` on a joined path | workload (OCI persist) | `kennel-cli/src/oci.rs` | unit test | fixed |

## Low

| ID | Finding | Where | Status |
|---|---|---|---|
| L-01 | `GET_SESSION_POLICY` answers any mesh participant for any ctx | `kenneld/src/mesh_bus.rs` | **fixed** `6cebda7` |
| L-02 | Unbounded D-Bus broker inbound queue; no per-kennel session cap; `thread::spawn` panic kills the broker | `kennel-dbus-broker/src/main.rs` | fixed |
| L-03 | PTY broker writes to the client while holding its mutex; a stalled client wedges `kennel list` | `kenneld/src/pty_broker.rs` | fixed |
| L-04 | A `protocol = "udp"` proxy allow yields a TCP connection | `kenneld/src/binder.rs`, `inet.rs` | fixed |
| L-05 | No cap on egress conduits or delegate threads; the documented rate limit and volume audit do not exist | `kennel-host-delegate/src/netproxy/conduit.rs` | fixed (conduit cap). The rate limit and volume audit are not built; THREATS T1.8 no longer claims them |
| L-06 | `authorized_keys_line` does not escape `"` or `\` | `kenneld/src/sshd.rs` | fixed |
| L-07 | `kennel-compose` turns a script's shebang into an `fs.read` grant on its parent directory | `kennel-compose/src/probe.rs` | fixed |
| L-08 | `recv_with_fds` leaks installed fds on `MSG_CTRUNC` (reachable in the compositor broker) | `kennel-lib-scm/src/lib.rs` | fixed |
| L-09 | Exclusive over-mount failure is logged and the kennel runs anyway (T2.8 fails open) | `kennel-privhelper/src/construct.rs` | fixed |
| L-10 | Unbounded host-`lo` address adds through the net sub-helper | `kennel-privhelper/src/bin/privhelper-net.rs` | fixed |
| L-11 | Every dynamic spawn leaves a permanent audit directory | `kenneld/src/server.rs` | fixed |
| L-12 | Audit files and the fallback control socket do not get the documented 0700/0600 modes | `kennel-lib-audit/src/sinks.rs`, `kennel-lib-control/src/socket.rs` | fixed |
| L-13 | `SPAWN` does its expensive work before the `max_instances` check | `kenneld/src/spawn.rs` | fixed |
| L-14 | `[rootfs].readonly` closure-lock is path-based and skipped if the path is absent | `kennel-lib-spawn/src/lib.rs` | fixed |
| L-15 | The workload and facades inherit init's hand-off descriptors | `kennel-privhelper/src/construct.rs`, `kennel-bin-init` | fixed |
| L-16 | Orphans reaped by init are reported as facade crashes | `kennel-bin-init/src/main.rs` | fixed |
| L-17 | BPF audit: ring overflow is silent; allowed-bind events are dropped by the reader | `src/bpf/kennel.bpf.h`, `kenneld/src/bpf_audit.rs` | fixed |
| L-18 | The `sock_create` deny branch cannot run for the non-inet families it names | `src/bpf/sock_create.bpf.c` | fixed |
| L-19 | The BPF ACL maps are pinned writable and unfrozen at the workload's own uid | `kennel-privhelper/src/bin/privhelper-bpf.rs` | fixed |
| L-20 | Untrusted strings reach the terminal unsanitised outside `policy diff` (review diff, `risks`, `show`, `oci revert --list`) | `kennel-cli` | fixed |
| L-21 | `install.sh` copies GUI config with `cp -a`, preserving the unpacking user's ownership under `/etc/kennel/config` | `src/tools/install.sh` | fixed |
| L-22 | `--prefix` plus the retired-file sweep deletes unrelated files in a shared directory | `src/tools/install.sh` | fixed |
| L-23 | Control-socket rule and the metadata-deny invariant are enforced only in the compiler | `kennel-lib-policy/src/invariant.rs` | fixed |
| L-24 | The lockfile does not pin unsigned artefacts and never compares the signer | `kennel-lib-compile/src/lock.rs` | fixed (signer); unsigned artefacts still unpinned |
| L-25 | Inside a constructed view `/` is mode 1777 and the synthetic `/etc` is 775 with 664 files (group root). Only Landlock stops the workload writing there; with R-09 (a workload at gid 0) the group bits matter. Seen on main and on the branch (VM) | `kennel-lib-spawn/src/lib.rs` (tmpfs mount with no mode; the inherited umask) | fixed |
| L-26 | The BPF loader requested a verifier log on every load into a fixed 64 KiB buffer; the kernel fails the load `ENOSPC` when the log outgrows it, even for a valid program (found when a small change to `bind6` stopped host-mode kennels starting) | `kennel-lib-bpf/src/loader.rs` | **fixed** `6ce7b5f` |

## Fix log

### R-07 — root-owned kennel user namespace (fixed)

- **Commits:** `352450b` (test), `ebce4c3` (fix), `9f66246` (inventory).
- **Change:** the factory raises its effective uid to 0 across the `clone`, so the namespace owner
  is root; its filesystem uid stays the operator's for that call so `CLONE_INTO_CGROUP` passes.
  kenneld no longer uses `/proc/<init>/root`: it receives an `O_PATH` handle to the binder device
  from the factory and re-opens it, and it sends the mesh mounts over the boot-sync socket.
  `kennel-bin-init` no longer sets `PR_SET_PTRACER_ANY`.
- **New invariant (THREATS T5.4):** no user-owned namespace ever contains host uid 0.
- **Verification on the VM:** policy suite 34 of 34 on main, 35 of 35 on the branch. The original
  check (`nsenter -U` at uid 1000 against a running kennel) went from "uid 0, file created in
  `/etc`" to "Operation not permitted".
- **Not covered:** the setuid-root install fallback (same code path, not exercised), SELinux.
- **Corpus:** the book's §2.8 analysis covers only code that goes through the pivot. Recorded in
  AS-BUILT.md; the book itself (separate repository) still needs the correction.

### R-06 / R-28 — view construction with the operator's filesystem identity (fixed, with residuals)

- **Commits:** `b3c4542` (test), `85fee8c` (fix), `d16e3cd` (inventory).
- **Change:** `build_view_and_pivot` takes an `FsIdentity` and sets the construction child's
  fsuid/fsgid to the operator's for the whole build. Leaving fsuid 0 clears the filesystem
  capabilities from the effective set, so the kernel enforces "nothing the caller could not do
  itself" on every lookup, read, create and copy. `CAP_SYS_ADMIN` is untouched, so mounts work.
- **Where root's identity is taken back, and why each is safe:**
  1. `add_binder_device` — opens the root-only `binder-control` on the binderfs just mounted.
  2. Re-owning the two OCI scaffold layers before the overlay mount — on the staging tmpfs the
     child mounted, nothing mounted inside, no symlink followed, no mount crossed.
  3. The OCI overlay mount — overlayfs needs a mounter with root's file capabilities (its work
     directory is mode 000). The image, upper and work directories are opened **as the operator**
     first; a persistent upper and work must be operator-owned; the mount uses those descriptors.
     *Corrected 2026-11-24 (N-24):* opening the image as the operator was an `O_PATH` open, which
     proves the path is reachable and nothing about the directory itself. See N-24.
  4. A bind mount point the image does not provide, inside the overlay root — created with
     `RESOLVE_IN_ROOT | RESOLVE_NO_XDEV`, so it stays in the overlay mount and cannot land on a
     bound host directory or outside the root.
  5. After the pivot: re-owning the scaffolding (`fd::chown_tree_same_mount`, which never follows
     a symlink or crosses a mount point).
- **Removed:** `chown_constructed_home`, a root chown walk guarded only by a device-and-uid
  heuristic that a bind at the home path could satisfy.
- **Verification on the VM:** policy suite 36 of 36. The two new cases fail against main's
  binaries: `ns-not-enterable`, and `construction-as-operator`, which found a root-owned
  `.trust-manifest.d` left by construction in a writable grant on the host. Ownership and modes
  inside a view are unchanged from main (scaffolding `0:0`, `$HOME` and `/tmp` the operator's).
  `fmt`, `clippy -D warnings` and the unit tests of the touched crates pass.
- **Not done:** no test drives the helper directly with a hostile construction request (that is
  exploit development). The guarantee for that case rests on the kernel's permission checks under
  the operator's fsuid, not on a test.
- **Residuals:** R-42 and R-43 above. A caller who runs the helper directly also still has R-08,
  R-09 and R-10.

### R-42 / R-43 — destinations resolved by descriptor inside the new root (fixed)

- **Commits:** `62aa713` (test), `387d4dc` (fix), `eccbdfb` (inventory).
- **Change (R-43):** `fd::RootDir` resolves a view path by descriptor: plain names only, a symlink
  in a parent component followed only inside the root, the final component never followed. Every
  destination in view construction goes through it, and mounts are made on the returned handle.
  A symlink at a mount point makes construction fail, so the kennel does not start.
- **Change (R-42):** `kennel-bin-init` creates a mesh mount target with `fd::scaffold_dir`: walked
  from `/` by descriptor, no symlink followed, every component on a filesystem the factory
  created (`/`, `/dev`, `/tmp`). The mount attaches to that descriptor.
- **Behaviour change to note:** a mesh `at` or `endpoint` whose directory lies inside a bound
  host path, or (in an OCI kennel) under `/home`, is now refused. A mount point that is a symlink
  — previously mounted through — now stops the kennel from starting.
- **Verification on the VM:** policy suite 37 of 37. `mount-point-symlink` fails against main's
  binaries ("the workload ran with the mask path a symlink"). `fmt`, `clippy -D warnings` and the
  unit tests of the touched crates pass.
- **Not tested:** the refusal path of `scaffold_dir` (a mesh target inside a bind) has no suite
  case; the suite exercises only the accepted path (`dbus-brokered`). OCI `persist` with a
  symlink planted in the upper is not exercised either.
- **Left by name, deliberately:** the `/proc` curation scratch directory and `pivot_root`'s
  `put_old`, both directly under a directory just checked to be real.

### R-08 / R-09 / R-10 — the helpers check what they are given (fixed)

- **Commit:** `2adffc7`
- **R-09:** the factory refuses a granted gid that is not the caller's real gid or one of its
  supplementary groups, and never gid 0; `kennel-bin-init` refuses a persona with gid 0. Unit test
  `a_granted_gid_must_be_one_of_the_callers_own`.
- **R-08:** the bpffs pin root is reached with no symlink followed, must be the caller's own
  directory, and the mount is made on that descriptor.
- **R-10:** the mounts sub-helper pins the directory before checking and mounting; `unmount`
  requires a caller-owned tmpfs mount root carrying the sentinel.
- **Verification on the VM:** policy suite 37 of 37, and host-side control checks as uid 1000:
  - mount of an owned directory: locked, sentinel present, read-only;
  - mount through a symlinked path, and of `/etc`: refused;
  - unmount of a root-created tmpfs with a planted sentinel (the original R-10 check): refused;
  - unmount of a plain directory with a sentinel: refused; of the helper's own lock: released;
  - pin root replaced by a symlink to a root-owned directory (the original R-08 check): no mount
    there; with a plain directory: bpffs mounted and host-mode egress still enforced.
- **Not tested:** the check-then-mount race itself (it is removed by construction, not measured);
  R-09 end to end with a hostile construction request.
- **Still open in the helpers:** L-09 (over-mount failure does not stop the kennel) and L-10
  (unbounded host-`lo` address adds).

### R-01 / R-15 / L-01 — registration verbs authorise their sender (fixed)

- **Commits:** `5f3cb44` (test), `6cebda7` (fix).
- **Change:** `ADD_SERVICE` and `GET_SESSION_POLICY` on a mesh bus are honoured only from the
  supervised provider of that name at the bus's tier (`server::provides_at`, from the daemon's
  registry and the kennel's signed `[[provides]]`). `REGISTER_TUN_SINK` requires that the
  kennel's signed policy provides the tun capability. The sender is the kernel-stamped pid.
- **A choice to review:** the tun gate is "signed policy provides the capability", not
  "supervisor-started", because the `tun-egress` suite case (and an operator) runs the broker by
  hand. Two such kennels can still replace each other's registration.
- **Verification on the VM:** policy suite 38 of 38. `registration-denied` fails against the
  previous build (both registrations answered OK) and passes with the fix (all three DENIED).
- **Not done:** the hijack itself (a rogue broker serving another kennel) was not built or run;
  the test stops at "the registration was accepted". R-16, R-17 and R-18 are untouched.

### R-03 / R-23 / R-24 — an address is judged as what the kernel dials (fixed)

- **Commits:** `8df38bb` (tests), `6ce7b5f` (fix).
- **Change:** `netaddr::canonical` maps an IPv4-mapped address to IPv4 before it is classified,
  CIDR-matched, pinned or dialled; IPv4-compatible is refused; NAT64 and 6to4 are classified by
  their embedded IPv4 address. In BPF, `kennel_decide_v6` hands a mapped address to the IPv4
  tries, both decide functions judge the unspecified address as loopback, and a mapped bind is
  refused. The proxy's any-port loopback allow is stamped only in the proxied modes.
- **Newly confirmed on the VM while writing the tests:** a connect to `::` reached a denied `::1`
  in host mode, and IPv4-compatible and NAT64 spellings of loopback opened a proxy tunnel.
- **Verification on the VM:** policy suite 40 of 40. Both new cases fail against the previous
  build and pass with the fix. Unit test `addresses_that_dial_ipv4_are_classified_as_ipv4`.
- **Not tested:** the `0.0.0.0` alias in host mode (only `::` is in the suite case; the code path
  is the IPv4 twin), a name whose AAAA record is a mapped address, and the tun broker's UDP path.
- **Still open nearby:** R-25 (ICMP and other non-TCP/UDP sockets), R-26 (listen without bind),
  R-27 (several ports on one CIDR collapse).

### R-19 / R-33 / R-11 — the rendezvous connect, mesh names, and signing (fixed)

- **Commits:** `ba15607` (test), `5012eb6` (R-19, R-33), `3e01d19` (R-11).
- **R-33:** `meshname` defines the capability `name`/`key` grammar; enforced at compile, at
  settled-policy load (`invariant::validate`) and in the daemon's path builder.
- **R-19:** kenneld's host-side connect to a provider's rendezvous socket goes through
  `fd::socket_in_dir` — no symlink followed, the entry must be a socket.
- **R-11:** the message to sign is piped to `ssh-keygen`; nothing is staged in `/tmp`.
- **Verification on the VM:** policy suite 41 of 41. `mesh-rendezvous-symlink` fails against the
  previous build at its first step (the path-shaped name compiled). No `kennel-sign-*` directory
  is left in `/tmp` after a full run.
- **Not tested:** the suite case's second half (the symlinked socket) was reproduced against the
  original build earlier by hand, but not re-run against a build with only R-33 fixed. R-11's
  race itself was never reproduced; it is removed by construction. The load-time re-assertion of
  the name grammar has no test with a directly signed settled artefact.
- **Still open nearby:** the other predictable `/tmp` paths in the CLI (clone staging,
  `TempSettled` fallback, pinned-baseline temp file).

### R-34 / R-13 — the trust manifest and `kennel review` (fixed)

- **Commit:** `fcf9ff0`.
- **Change:** `Manifest::validate` on load (trigger paths relative plain names; content hashes
  well-formed). Revert resolves inside the workspace by descriptor, replaces the entry without
  following it, and verifies the blob against its pin. A symlinked directory trigger is not
  listed through. Re-pin stores only what the review showed.
- **Verification on the VM:** unit tests — a manifest pointing outside the workspace is refused;
  a symlinked trigger is replaced and its target left untouched; a symlinked trigger directory is
  not enumerated; a swapped blob is refused; a trigger changed after review is not pinned. Policy
  suite 41 of 41.
- **Not tested:** end to end through the `kennel review` command; these are library tests.
- **Still open nearby:** review does not require the kennel to be stopped; `New` triggers are
  pinned without their content being shown; L-20 (the diff is printed unsanitised next to the
  prompt); reads through a symlinked parent of an already-pinned trigger.

### R-16 — node 0 frees the buffer before it replies (fixed)

- **Commits:** `9e36b3c` (test), `2791ff5` (fix).
- **Change:** replies are written `[BC_FREE_BUFFER][BC_REPLY]`; a one-way transaction is freed
  and not replied to.
- **Verification on the VM:** `binder-oneway-buffer` — 8 of 40 one-way sends accepted before the
  fix, 40 of 40 after. Policy suite 42 of 42.
- **Not tested:** the mesh-bus variant (one participant exhausting the shared bus), and the
  other ways a reply can fail (a peer that dies first, a peer that does not accept a returned fd).
- **Still open nearby:** R-17 (busy-spin, no deadline), R-18 (handles read from payload bytes),
  the skipped handle release after a failed `HandleOnce` reply, nested inbound transactions.

### R-02 — the bus driver is mediated by method (fixed)

- **Commits:** `2494ef7` (test), `b50022b` (fix).
- **Change:** a call to `org.freedesktop.DBus` that the policy admits is decided by method,
  default-deny; `RequestName`/`ReleaseName` are checked against `own`, `StartServiceByName`
  against what the kennel may call, `AddMatch` against eavesdropping.
- **Behaviour change:** an application that requests its own bus name needs it in `own`.
- **Verification on the VM:** `dbus-driver-mediated` fails against the previous build
  (`RequestName` outside `own` succeeded) and passes with the fix. Policy suite 43 of 43.
- **Not tested:** a real GUI client's start-up sequence against the method allowlist; the system
  bus leg; `UpdateActivationEnvironment` was only ever sent to the fixed broker.
- **Still open nearby:** signals are admitted by the sender-chosen interface string, not by
  sending service; replies are matched on `reply_serial` alone; L-02 (broker queue and sessions).

## Verification probes

The dynamic checks from the first pass live outside the repository (`~/rv-review` on the test
VM, still there on 2026-11-24). Each is a suite-style policy plus a host-side driver. Every row
they check now has a suite case in the repository, so they are kept only as a record:

| Probe | Rows it checks |
|---|---|
| `policy.toml.in` + `run.sh` (host mode) | R-23 R-24 R-25 R-26, and R-08 when the pin path is a symlink |
| `proxy.toml.in` + `run-proxy.sh` | R-03 |
| `binder.toml` + `run-binder.sh` | R-16 |
| `mesh-provider.toml`, `mesh-consumer.toml` + `run-mesh.sh` | R-19 |
| `f7b.sh` | R-07 (superseded by the `ns-not-enterable` suite case) |

### The decision-free mediums (fixed 2026-11-20)

- **R-41, R-38, R-05** (`51633eb`): the canonical form is read back and must equal the body; an
  inherited increment is resolved before a child's is applied; an address rule must be an IP
  literal with a fitting prefix, at compile and at load.
- **R-20, R-04, R-22, R-21, R-31** (`067aa85`): the digest pin covers `allowed_args`; the
  bastion's `ssh` runs with `EscapeChar=none` and `ClearAllForwardings=yes`; `accept` failures are
  retried and the bounce buffer is capped at 64 per port; an oversized audit event is truncated
  and marked; read-only binds are sealed recursively.
- **R-17** (`3f304d5` test, `23d084b` fix): the reply wait sleeps in `poll` and gives up after
  30 s with `BINDER_THREAD_EXIT`.
- **Residuals:** after an R-17 timeout the consumer whose connect was being served is not
  answered; nested inbound transactions during a wait are still ignored; `fold_redirects` was
  not revisited; R-31 and R-04 have no end-to-end case.

### R-25 / R-27 / R-29 — host mode (fixed 2026-11-20)

- **Decisions (user, 2026-11-20):** refuse non-TCP/UDP at socket creation; change the map value
  format; require Landlock ABI 6 only when the policy needs scoping.
- **R-25:** `sock_create` admits `SOCK_STREAM`/TCP and `SOCK_DGRAM`/UDP only.
- **R-27:** `struct allow_entry` holds up to eight rules; `acl::build_entries` merges rules per
  prefix and inherits from wider prefixes; denies match port and protocol. ABI version 2.
- **R-29:** `kenneld` refuses `net.mode = "host"` below Landlock ABI 6. "Needs scoping" was read
  as host mode, the only mode sharing the host's abstract-socket namespace.
- **Residuals:** R-26 (unbound `listen()`, UDP port-0 bind) is untouched; more than eight port
  rules on one prefix is a start-time refusal, not a compile error.

### The remaining mediums (fixed 2026-11-20)

- **R-26:** `cgroup_skb/ingress` program; also fixed a regression from R-27 (a deny with no
  protocol had become TCP-only).
- **R-14, R-18, R-30, R-32, R-37:** one commit ("handles, x32, OCI revert, the cwd workspace and
  the redirect floor").
- **R-35, R-36, R-39, R-40:** one commit ("parser limits, key precedence, fragment validation and
  a complete diff").
- **Residuals:** the `reason` rule is not applied to fragments (the signed `gui-desktop`
  fragment lacks one; needs a maintainer re-sign); `policy risks` derives nothing for the
  sections the diff now shows (needs a threat mapping); R-30 untested on x86_64.

### The lows (fixed 2026-11-20)

Two commits ("low-severity hardening, first group" and "second group"). Evidence is unit tests
plus the full suite (47 of 47) and a mode probe on the VM for L-25. Not exercised end to end:
the exclusive over-mount failure path (L-09), the lost-event counter (L-17), the session, queue,
conduit and address caps (L-02, L-05, L-10), the closure-lock on an absent path (L-14), the
installer changes under `--prefix` (L-22). Still open after this pass: L-24's unsigned
artefacts, L-05's rate limit and volume audit, R-12 (on `fix/cli-name-before-file`), the
`reason` rule for fragments, and a threat mapping for `policy risks`.

## Where this landed

Written 2026-11-24, after the 0.8.1 release.

### Shipped

- **Branch and PRs:** the fixes merged as #240 (`bc18e2b`); R-12 merged separately as #239.
  Two breaks surfaced only when the full CI ran on the merged tree (three tests built with
  `--all-features` and one doc link) and were fixed in `b6c0ee7`.
- **Release:** 0.8.1, tag `v0.8.1` on `204f76d`, published to GitHub and to the signed APT and
  DNF repositories on 2026-11-20. Settled schema stayed v6; threat catalogue stayed 0.6.
- **Verification at release:** policy suite 47 of 47 on merged `main` (aarch64, kernel 7.0);
  1299 unit and integration tests with all features; the install acceptance test from the
  aarch64 tarball; 43 of 47 suite cases against the installed release payload, the other four
  needing test-only binaries a release does not ship.

### How each severity is guarded

| Severity | Rows | Guard |
|---|---|---|
| Critical and high | 17 | 12 by a suite case that failed on the old build; R-08 and R-10 by manual control checks on the VM; R-09 and R-34 by unit tests; R-11 removed by construction |
| Medium | 26 | R-17, R-25, R-26, R-27 and R-43 by suite cases; the rest by unit tests or by reading |
| Low | 26 | unit tests and the suite staying green; L-25 probed on the VM |

### Still open

These were found or left by the review and are not fixed.

- **`policy risks`** derives nothing for the sections `policy diff` now reports (R-40). It needs
  a threat mapping.
- **Fragments** are not held to the `reason` rule (R-39): the signed `gui-desktop` fragment has
  an `fs.read` entry without one and needs a maintainer re-sign first.
- **The lockfile** pins the signer but cannot pin an unsigned artefact (L-24).
- **Egress volume** is neither limited nor audited (L-05). The catalogue no longer claims it is.
- **The tun sink gate** is "the signed policy provides the capability": two such kennels can
  replace each other's registration (R-15, accepted 2026-11-20).
- **R-12** keeps the file fallback for a word that names no policy.
- **Noted beside a fix, never numbered:**
  - other predictable `/tmp` paths in the CLI (clone staging, the `TempSettled` fallback, the
    pinned-baseline temp file);
  - `kennel review` does not require the kennel to be stopped, pins `New` triggers without
    showing their content, and reads through a symlinked parent of a pinned trigger;
  - D-Bus signals are admitted by the sender-chosen interface string, and replies are matched
    on `reply_serial` alone;
  - after a binder transaction times out (R-17) the waiting consumer is not answered, and
    nested inbound transactions during a wait are ignored;
  - the handle release skipped after a failed `HandleOnce` reply;
  - `fold_redirects` was not revisited with the other fold functions (R-38);
  - more than eight port rules on one prefix is refused at start, not at compile (R-27).

### Never tested

- **Platforms:** x86_64, SELinux, a kernel older than 7.0, and the setuid-root install
  fallback. R-30 (x32) and R-29 (the Landlock floor) rest on unit tests. The x86_64 tarball and
  packages for 0.8.1 were built but not installed anywhere.
- **Code the review did not read:** parts of `kennel-lib-compile` (`unix.rs`, `spawn.rs`,
  `identity.rs`), the facade SOCKS and TUN code, and most of `kenneld/src/inbound.rs`. These
  gaps were not closed by the fix work.
- **No end-to-end case:** R-31 (nested read-only mounts), R-04 on OpenSSH below 9.2, R-18 with
  a forged object, R-34 through the `kennel review` command, and most of the lows (L-02, L-05,
  L-09, L-10, L-14, L-17, L-22).
- **Not attempted, by scope:** no test drives the helper with a hostile construction request
  and no finding was developed past "the control did not hold". This was a defensive review.

### Outside this repository

- The book's §2.8 analysis covers only code that goes through the pivot (see R-07); the
  correction is recorded in AS-BUILT.md but the book itself is unchanged.

## Follow-up review (2026-11-24)

### What was reviewed, and how

- **Scope, part 1 (security):** the code the first review listed as unread, at `main` =
  `4b1707d` (0.8.1 plus #242 and #243): `kennel-lib-compile` `unix.rs`, `spawn.rs` and
  `identity.rs`; `kenneld/src/inbound.rs` and the inbound delegate; the SOCKS/HTTP facade and
  the daemon's `CONNECT_INET` path; the whole tun path (`kennel-facade` `tun.rs` and
  `facade-tun.rs`, all of `kennel-tun-broker`).
- **Scope, part 2 (quality):** the 17 TCB crates (about 28,200 non-test lines), judged against
  CODING-STANDARDS.md and against the design goal that `unsafe` is minimal and concentrated.
- **Method:** six independent read-only reviews (three per part). Every row in the table below
  was then re-read against the code by a second reader. Three had a control check on the test
  VM (marked `VM`). Per-crate metrics were computed mechanically.
- **Limits:** nothing was developed past "the control does not hold". `kennel-lib-audit` was
  about a third read; `kennel-lib-bpf` and `kennel-lib-os` were sampled; in `kenneld`,
  `catalogue.rs`, `etc.rs`, `policy.rs`, `bastion.rs`, `sshd.rs` and the `inet` modules got
  metrics only. The vendored `simple-dns` parser (fed workload bytes by the tun mediator) was
  not read. Non-TCB crates were not assessed for quality.

### Findings

Evidence and reach are as defined under [Reading the table](#reading-the-table).

| ID | Finding | Reach | Where | Evidence | Status |
|---|---|---|---|---|---|
| N-01 | `mount_overlay` joins layer paths into overlayfs's comma-separated option string. Its doc said callers never pass `,` or `:`; the OCI staging root comes from the factory's caller unchecked, and the mount runs with root's filesystem identity | local user | `kennel-lib-syscall/src/mount.rs`, `kennel-lib-spawn/src/lib.rs` (`mount_image_overlay`) | read ×2 that the bytes reach the string; the effect of an injected option was not tested | **fixed** `6c3ac4e` (test `e6f1982`), branch `fix/overlay-options-and-dotted-keys` |
| N-02 | Dotted keys are not covered by the R-35 limits: `a.a.a…` with 100,000 parts (200 KB) recurses once per part and overflows the stack, before signature verification | anyone who can place a file the daemon or CLI loads | `kennel-lib-toml/src/de.rs` (`dotted_key`, `add_dotted_key`) | VM (the installed 0.8.1 CLI aborts) | **fixed** `109c355` (test `1512df9`), same branch |
| N-03 | A `tun-flow` mediator never learns its consumer is gone: the session channel is a `SOCK_DGRAM` pair, which signals nothing on peer close, and every `send` result is discarded. Any process in a `[net.udp]` kennel can open sessions without limit; each spawns a process and a reaper thread in the shared broker kennel, and the per-session flow and rate ceilings multiply | workload | `kennel-tun-broker/src/main.rs` (`deliver`), `serve.rs`; `kenneld/src/binder.rs` (`tun_connect`) | read ×2; VM for the kernel behaviour (DGRAM: no event, no EOF; SEQPACKET: both). Not run end to end | **fixed** `ab7602d` (test `52212ed`) |
| N-04 | `[[unix.allow]]` can name kenneld's own delegate command sockets. Only `control.sock` is refused; `netproxy-cmd-<ctx>.sock` dials whatever address it is handed with no policy, so the proxy rules and the metadata invariant deny are skipped | author | `kennel-lib-compile/src/unix.rs`; `kenneld/src/binder.rs` (`af_unix_connect`); `kennel-lib-control/src/socket.rs` (`is_control_socket`) | read ×2 | **fixed** `0438b16` (test `32edfcb`) |
| N-05 | A unix grant's `real` path is never checked against the write set and is connected by name; the control-socket backstop is `canonicalize` then a separate connect. The R-19 pattern on a path that fix did not cover | operator error, then workload | `kenneld/src/binder.rs` (`af_unix_connect`), `kennel-lib-os/src/net.rs` | read ×2; race not measured | **fixed** `0438b16` (test `32edfcb`), with a residual |
| N-06 | The inbound mirror binds a ULA assigned to host `lo`. That is not loopback-scoped: a peer arriving on another interface reaches it unless a host firewall stops it, and any local uid can connect. THREATS T3.3 says "the LAN cannot". No audit event for an inbound connection | on-link peer; local user | `kenneld/src/lib.rs`, `kennel-host-delegate/src/inetd/listen.rs`, `kennel-privhelper/src/addr.rs` | read ×2; VM (an address on `lo` accepted a connection from a peer on a veth; no firewall rules, forwarding off). Not run with a real kennel | **fixed** `f1360d4` (test `3921a19`), narrowed: other local users can still connect |
| N-07 | The egress gate does not exclude the host's own non-loopback addresses. The proxy and the UDP path both dial them from the host stack, reaching host services bound to a wildcard address | workload (`unconstrained`, or an allow that covers the address) | `kenneld/src/inet.rs` (`decide`), `kennel-lib-policy/src/netaddr.rs`, `kennel-tun-broker/src/flow.rs` | read ×2 | **fixed** `dd8f9c3` |
| N-08 | Enforcement results are discarded and audited as done: the tripwire's freeze and kill, the TTL handler's kill, and `request_death` in three registrations | n/a (fails open on error) | `kenneld/src/tripwire.rs` (`apply`), `kenneld/src/binder.rs` (`ttl_expired`, `register_mirror`, `register_tun_sink`), `mesh_bus.rs` | read ×2 | **fixed** `766ab1b` (test `6f69f6d`) |
| N-09 | `mutable = []` on a `[[spawn.allow]]` entry means the template's full manifest: the settled form cannot tell an empty list from an absent one. A child's narrower entry for an inherited template is silently dropped | author; operator error | `kennel-lib-compile/src/spawn.rs`, `kenneld/src/spawn.rs` (`build_patch`) | read ×2 | **fixed** `407aab9`; `mutable = []` is refused, not given a meaning |

Lower severity, each confirmed by one reading:

| ID | Finding | Where | Status |
|---|---|---|---|
| N-10 | A unix `shim` has no grammar check and grants Landlock read/write/remove over its whole parent directory (`shim = "/x.sock"` covers `/`) | `kennel-lib-compile/src/unix.rs`, `kenneld/src/lib.rs` | fixed `0438b16` |
| N-11 | Rules enforced only in the compiler, not at load: identity user, group and hostname grammar (they reach `/etc/passwd`, `PS1` and a home path), proxy offset and port range, `MAX_BIND_PORTS`, BPF map capacity, sha256 form, ulimit tokens. `patch::instantiate` returns a policy that is not re-validated | `kennel-lib-compile/src/translate.rs`, `kennel-lib-policy/src/invariant.rs`, `patch.rs` | fixed `13b8f10`; map capacity and ulimit tokens left to fail at spawn |
| N-12 | `host-inetd` caps conduits per listener, not per process, costs 4 fds and 2 threads each, spins on `EMFILE`, and panics when a thread cannot be created; the L-05 treatment was not applied to it | `kennel-host-delegate/src/inetd/listen.rs` | fixed `f1360d4` |
| N-13 | `REGISTER_MIRROR` takes a binder reference and death registration per call and never releases a replaced one | `kenneld/src/binder.rs`, `inbound.rs` | fixed `f1360d4` |
| N-14 | Bounced inbound conduits are drained only on a new registration; a single receive error ends a port's mirror for the kennel's life with no log | `kenneld/src/inbound.rs` | fixed `f1360d4` |
| N-15 | `mesh_rendezvous::decode` returns the pairs that parse and drops the rest, so a truncated message starts the workload with a partial mesh | `kennel-lib-spawn/src/mesh_rendezvous.rs` | fixed `a191e6e` |
| N-16 | The loopback-address cap fails open when `/proc/net/if_inet6` is unreadable | `kennel-privhelper/src/bin/privhelper-net.rs` | fixed `a191e6e` |
| N-17 | A failure to become binder context manager is a warning; bring-up continues | `kenneld/src/lib.rs` (`bring_up`) | fixed `a191e6e` |
| N-18 | Start refusals (signature, digest pin, Landlock floor, cwd floor), a foreign-uid control connection, `Stop`, `Attach` and `DaemonReload` are not audited; `kennel_exit` always says "stopped" | `kenneld/src/server.rs` | fixed `49e5559` |
| N-19 | THREATS T1.15 says DNS rebinding is closed structurally; the UDP path deliberately dials RFC1918, CGNAT and ULA. A `[net.udp]` `name` has no grammar check, so an IP literal becomes an address grant | `kennel-tun-broker/src/flow.rs`, `kennel-lib-compile/src/translate.rs` | fixed `dd8f9c3`; rebinding into private space stays, now stated in T1.15 |
| N-20 | `facade-tun` neither exits nor recovers when its mediator goes away; `EINTR` from `epoll_wait` ends the mediator | `kennel-facade/src/bin/facade-tun.rs`, `kennel-tun-broker/src/serve.rs` | fixed `ab7602d` |
| N-21 | `openssh::parse_private_key` slices `pem[start..end]` and panics when the END marker precedes BEGIN (no caller found in the daemon or CLI) | `kennel-lib-policy/src/openssh.rs` | fixed `a191e6e` |
| N-22 | An operator-chosen kennel name of the form `spawn-<ctx>-…` is reaped with that ctx's children and shares its audit directory: parentage is parsed from the name (the L-11 fix added a second parser of it) | `kenneld/src/server.rs` (`reap_children`, `audit_dir_name`) | fixed `a191e6e` |
| N-23 | The supervisor's restart count never resets, so a provider that crashes `max_attempts` times over any span is failed for good | `kenneld/src/supervisor.rs` | fixed `a191e6e` |
| N-24 | The OCI image lower only had to be reachable by the caller. The overlay is mounted as root, overlayfs reads the lower with the mounter's credentials, and a merged directory takes the top layer's attributes — so a root-owned directory closed to the caller (the image root itself, or any image directory a layer above also has) could be served to the workload with its world-readable contents | `kennel-lib-spawn/src/lib.rs` (`mount_image_overlay`, `overlay_dir`) | fixed `e634531` |

Gaps this pass found in the first pass's own fixes: N-02 (R-35's limits missed dotted keys),
N-12 (L-05 fixed one delegate of two), N-22 (L-11), N-24 (R-06's third exception), and the
structural items below.

### Fix log

#### N-01 / N-02 (fixed 2026-11-24, PR #244)

- **Commits:** `1512df9` and `e6f1982` (tests), `109c355` (N-02), `6c3ac4e` (N-01), `c4bef2c`
  (inventory), on `fix/overlay-options-and-dotted-keys`.
- **N-01:** `mount_overlay` returns `InvalidInput` for a lower, upper or work path that is not
  UTF-8 or contains `,`, `:` or `\`, before the mount. Unit test, unprivileged: before the fix
  the mount was attempted (`NotFound`).
- **N-02:** each part of a dotted key after the first counts toward `MAX_NESTING`, shared with
  brackets, and the key is refused as soon as it would pass the limit. Two tests in
  `tests/limits.rs`: before the fix one aborted the test binary with a stack overflow and the
  other parsed 120 levels.
- **Verification on the VM:** policy suite 47 of 47 (it includes the OCI cases that take the
  overlay path); 1302 tests with all features; clippy `-D warnings` and `fmt` clean.
- **Not done:** no test drives the factory with a hostile staging root (out of scope, as for
  R-06). The two remaining `expect`s in the parser and the `remove(0)` in `add_dotted_key` are
  unchanged.

#### N-03 to N-23 (fixed 2026-11-24, PR #244)

All on `fix/overlay-options-and-dotted-keys`. "Failed first" means the test was committed and
run against the unfixed code and failed; where it does not say so, test and fix landed together
because the test needs an interface the fix introduces.

| Rows | Commits | What changed | Tests |
|---|---|---|---|
| N-03, N-20 | `52212ed`, `ab7602d` | Session channel is `SOCK_SEQPACKET`; mediator ends on hang-up or a peer-gone send, not on `EINTR`; broker caps live sessions (2 for one kennel, 256 overall) and reaps from one thread; kenneld does not retry a refused delivery; `facade-tun` exits when the channel closes | 2 failed first (hang-up, loop exit); 2 for the ledger |
| N-04, N-05, N-10 | `32edfcb`, `0438b16` | Compiler and daemon refuse a `real` anywhere in the daemon's runtime directory; daemon opens the socket once (`O_PATH`), checks that file's path and connects through the descriptor; loader refuses a `real` in the writable surface and a `shim` or af-unix `at` that is not a plain path | 4 failed first; 3 for the pinned connect (one swaps the name for a symlink between open and connect) |
| N-06, N-12, N-13, N-14 | `3921a19`, `f1360d4` | Mirror listener bound to the `lo` device before the address; conduit cap per process, accept backoff, no panic on a refused thread; `net.inbound-connect` audit record; replaced mirror handle released; held conduits drained on each arrival, in order; reader retries `EINTR` and logs why it ended; T3.3 corrected | 1 failed first (device bind); 2 for the bookkeeping. VM control check: a peer on a veth connects to an unbound listener on an `lo` address and is refused by a device-bound one |
| N-07, N-19 | `dd8f9c3` | INet decision and UDP mediator refuse a literal or resolved destination that is one of the host's interface addresses; a `[net.udp]` name must be a DNS name (compiler, loader, mediator); T1.15 corrected | 3 on the decision with a stub host-address predicate; 1 on the enumeration; 4 on the name grammar |
| N-08 | `6f69f6d`, `766ab1b` | Tripwire and TTL handler report the cgroup write's result (`error` record, stderr line); a registration whose death notification cannot be requested is released and refused | 1 failed first (TTL); 1 for the tripwire |
| N-09 | `407aab9` | `mutable = []` is a compile error; a child's `[[spawn.allow.add]]` for an inherited template replaces the inherited entry, with a warning | 2 |
| N-15, N-16, N-17, N-21, N-22, N-23 | `a191e6e` | Rendezvous decode is all or nothing; address cap refuses when it cannot count; a context manager that does not start fails the bring-up; PEM markers out of order are an error; `spawn-<number>-…` names reserved; restart count resets after a minute of readiness | 5 (none for N-16 and N-17) |
| N-18 | `49e5559` | Daemon-level audit writer: `lifecycle.kennel-start-refused`, `lifecycle.control-refused`, `lifecycle.control`; `lifecycle.kennel-exit` reason is `exited`, `stopped` or `reaped` | 1 (event shape only) |
| N-11 | `13b8f10` | Identity, hostname, bind-port and digest rules are predicates in `kennel-lib-policy`, called by the compiler and by `invariant::validate`; supplementary group names get a rule in both; `patch::instantiate` validates its result | 2 |

Decisions taken while fixing, for the maintainer to confirm or reverse:

- **N-04 widens the ungrantable set** from `control.sock` to the whole of
  `$XDG_RUNTIME_DIR/kennel/`. One existing unit test asserted that a socket inside that
  directory was grantable; its example path was moved outside the directory.
- **N-09 refuses `mutable = []`** instead of making it mean "no fields". Meaning it would need a
  new field in the signed settled form, which is a schema decision.
- **N-08 does not escalate** a failed `freeze` to a kill. It reports the failure and tries again
  on the next mutation.
- **N-07 is lifted by `accept_private_resolved`**, like the special-use gate. No policy can set
  that flag today; an existing test of the flag passes unchanged.
- **Session ceiling of 2 for one kennel** (N-03) and **stable-run window of one minute** (N-23)
  are chosen values, not derived ones.

Residuals:

- N-05: `[fs.cwd]` is writable and is not in the load-time check (it is known only at spawn);
  the comparison is on the paths as written, so `~/x` and an absolute spelling of the same
  directory do not match.
- N-06: any local user can connect to a mirrored port. The kennel's address is still assigned
  to host `lo`.
- N-11: BPF map capacity and ulimit tokens are not re-checked at load; a wrong value fails the
  spawn.
- N-13: the handle release is exercised by a unit test of the bookkeeping, not against the
  binder driver.
- N-18: the daemon-level records go to stdout only (the journal under systemd), not to a
  kennel's audit directory. `list`, `mesh`, `version` and `resize` are not recorded.
- N-19: rebinding an allowed UDP name into RFC1918, CGNAT or ULA space is by design and is now
  stated in T1.15.

Verification on the VM, at the branch head:

- `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo test`: all features, and without default features, no failures (1337 with all features at the
  head; 1292 without default features, run before the last correction).
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`: clean.
- The root end-to-end policy suite: 47 of 47.

The suite's first run was 42 of 47 and found two errors in these fixes, both corrected in
`6595bd4`:

- N-22 first reserved every name starting with `spawn-`, which refused the suite's own
  `spawn-argv`, `spawn-caps`, `spawn-compute` and `spawn-roundtrip` kennels. It now reserves
  `spawn-<number>-…`, exactly the prefix the hard reaper matches.
- The `net-bind-mirror` fixture located the listener by matching `ss -ltn` output; a
  device-bound listener is printed as `[addr]%lo:port`. The pattern was widened. The listener
  was up in the failing run.

It also showed the N-18 records carrying two `kennel` keys; the kennel acted on is now `target`.

#### N-24 — which directory may be an OCI image root (fixed 2026-11-24, PR #244)

Raised by the maintainer as a question: since the helper builds a root-owned process, does it
check that what it links in is accessible to the original user? It did, through the operator's
filesystem identity (R-06), everywhere but here.

- **Commit:** `e634531`. New module `kennel-lib-spawn/src/image.rs`.
- **Severity:** not rated with the others. Reach is limited: only inodes root owns (other
  users' uids are not mapped in the kennel, so the mounter has no access to their closed
  directories), and only files whose own mode already admits the workload — the exposure is
  content that relied on a parent directory's mode. It is a read, never a write.
- **How it was established:** from the code and from overlayfs's documented permission model.
  It was **not** demonstrated against the factory; doing so is exploit development.
- **Change:** before the mount, with the operator's filesystem identity:
  1. the operator must be able to list and search the image directory. The kernel is asked (an
     open for reading, and a lookup inside it), not the mode bits;
  2. the directory is the operator's own, or root's, not writable by group or other, and
     beneath `/usr`, `/var`, `/etc`, `/lib`, `/lib64` or `/opt`. The location is judged on the
     path the handle resolved to. `/` and the six roots themselves do not qualify;
  3. every directory in the `kennel-etc` layer that the image also has as a directory must be
     one the operator can list and search;
  4. a root-owned image is refused with `persistence = "persist"`.
  None of it applies when the operator is root.
- **Tests:** nine, unprivileged, against real directories: closed modes (000, 400, 100), a
  closed parent, a symlink and `..` aimed at a system location, system and non-system
  root-owned directories, a covered closed directory at one and two levels, and a symlink in
  the image where the layer has a directory. One test records the kernel fact behind the
  finding: an `O_PATH` handle to a mode-000 directory is granted. Test and fix landed together.
- **Verification on the VM:** 1346 tests with all features, 1301 without default features;
  `fmt`, clippy `-D warnings` and `cargo doc` clean; policy suite 47 of 47, including
  `oci-substrate` and `oci-confined-fetch`. A formatting-only change followed the suite run;
  the crate's lint and tests were re-run after it, the suite was not.
- **Decisions, for the maintainer to confirm or reverse:**
  - the maintainer's rule named `/usr`, `/var`, `/etc`, `/lib`; `/lib64` and `/opt` were added
    and `/srv` left out;
  - rule 4 is a reading of "fine if read only". A shared system image therefore cannot have a
    per-user persistent rootfs. The reason is that the operator can add a directory to their
    own upper at any time, and no check before the mount can stop it covering a closed image
    directory.
- **Residuals:**
  - an operator-owned image may contain directories the operator cannot enter (left there by
    root); with a persistent upper the operator could cover one. Root's credentials stay
    inside the operator's own tree, the same rule as for the upper;
  - rule 3 walks the `kennel-etc` layer once, before the mount. That layer is on the staging
    tmpfs in the child's private mount namespace, so nothing outside the child can add to it;
  - the helper does not restrict an `/etc` overlay's `view_path` to `/etc`; rule 3 is what
    makes a path elsewhere harmless;
  - ~~`THREATS.md` is not updated~~ — the factory paragraph of the userns threat now states
    the image rules (PR #246).
- **Checked and found sound in the same pass:** binds and `/etc` overlays (resolved as the
  operator; the bound inode keeps its own mode), copied files (read as the operator), the
  persistent upper and work directories (operator-owned), and `kennel-bin-init`, which drops
  to the operator before the workload's `chdir` and `exec`.

### TCB quality assessment

**Design goals.**

- *Unsafe is concentrated, with leaks at the edges.* Five crates carry
  `#![allow(unsafe_code)]` (`kennel-lib-syscall` 59 production sites, `kennel-lib-bpf` 28,
  `kennel-lib-binder` 25, `kennel-lib-landlock` 5, `kennel-lib-scm` 1) and they are the five in
  `supply-chain/UNSAFE-CRATES.md`; every other TCB crate root has `#![forbid(unsafe_code)]`
  (the two `kennel-host-delegate` binaries gained it in PR #246, with the four binary roots
  outside the TCB, the `kennel-schema-derive` proc macro and the three generator tools — every
  crate root outside the five now forbids it. The `kennel-lib-syscall` count predates PR #245,
  which removed one site.)
  The leaks:
  - `kennel-lib-syscall` exports safe functions whose soundness is the caller's: `fd::adopt`,
    `fd::close_inherited`, `fd::dup_onto`, `boot::borrow`, `boot::place_injected_stdio`,
    `pty::setup_view_pty`. `clone_pid1`'s doc requires an async-signal-safe child; its one
    caller builds the whole view there, and what makes that sound (the factory is
    single-threaded at the clone) is stated and checked nowhere.
  - `kennel-lib-binder` has 7 unsafe blocks in `client.rs`; three doc comments say `sys.rs` is
    the only place.
  - The three-part `SAFETY / INVARIANTS UPHELD / FAILURE MODE` form §4 requires is on about 16
    of 93 production sites in the privileged path.
  - Avoidable unsafe: a hand-rolled `openat2` beside `nix::fcntl::openat2` (used eight times in
    the same file), and `fork_hold`, which has no caller.
- *Errors are handled, not panicked, but not always acted on.* Non-test TCB code has three
  `expect`s and no `unwrap`, `panic!` or `unreachable!`; every decoder read fails closed. The
  gaps: N-08, N-15, N-16, N-17; the binder looper pool ends silently on any error; config reads
  map "unreadable" to "absent"; most errors are `io::Error` or `String` with formatted text.
  `clippy::expect_used` and `clippy::string_slice` are not enabled, so two rules hold by habit.

**Ratings.**

| Rating | Crates |
|---|---|
| Strong | `kennel-lib-landlock`, `kennel-lib-scm`, `kennel-lib-text`, `kennel-host-delegate`, `kennel-lib-bpf` (sampled) |
| Adequate | `kenneld` (low end), `kennel-lib-spawn`, `kennel-lib-policy`, `kennel-lib-binder`, `kennel-bin-init`, `kennel-lib-os`, `kennel-lib-audit` (a third read), `kennel-lib-control`, `kennel-lib-config` |
| Needs work | `kennel-privhelper`, `kennel-lib-syscall`, `kennel-lib-toml` |

**Structure.**

- Four functions carry the orchestration: `run_kennel` (`kenneld/src/server.rs`, 991 lines, 16
  hand-written failure exits), `bring_up` (`kenneld/src/lib.rs`, 623 lines, 20 positional
  parameters), `construct` (`kennel-privhelper`, 417 lines), `Plan::from_policy`
  (`kennel-lib-spawn`, 425 lines). The median function is 8 lines.
- Structs are built and then exploded into positional arguments (`Spec` into `bring_up`,
  `BinderPrep` into the 15-argument `binder::spawn`), with adjacent `bool`s a swap would not
  break.
- Duplication: seven copies of the binder transact loop (`kennel-lib-binder/src/client.rs`);
  four descriptor walkers in `kennel-lib-syscall/src/fd.rs`; seven copies of "bind a facade
  binary and grant its loaders" in `kenneld/src/lib.rs`; six hand-rolled byte cursors.
- Dead code: `attach_egress` / `populate_egress_maps`, `fork_hold`, `relay_winch`,
  `canonicalise_path`, three write-only struct fields in `kenneld`.
- Locks held across blocking work: the daemon-wide mesh-bus mutex across a fork, a mount and a
  socket round trip; the bastion mutex across key staging.

**Tests.**

- No binder node-0 handler has a unit test; `mesh_bus.rs` and `kenneld/src/lib.rs` have none.
  Refusals at handler level are tested only by the root-requiring shell suite, so `cargo test`
  cannot see a regression in one.
- Nothing the first pass added to `fd.rs` (`RootDir`, `scaffold_dir`, `dir_no_symlinks`,
  `socket_in_dir`, `chown_tree_same_mount`) has a unit test, though most is testable
  unprivileged in a temporary directory.
- The fuzz job feeds 20,000 random byte strings from a fixed seed; for text formats these
  rarely pass UTF-8 validation. The SSHSIG path, seven binder service decoders,
  `EgressPayload::decode` and `mesh_rendezvous::decode` are not reached. No property tests.
- The canonical form is derived mechanically and read back (good), but no test populates every
  field and there is no golden-bytes file.

**Policy validity is defined in several places.** Serde shape, the canonical round trip,
`invariant::validate`, `Variant::resolve` (lazily, at spawn), `spawn_eligible`, the schema gate,
and the compiler (N-11). No type distinguishes a validated `SettledPolicy` from a constructed
one. Security values are bare `String`, `u8` and `u16` with public fields.

**Comments and documents.**

- The privilege narrative in `kennel-privhelper` reads two ways in one file: `construct.rs`
  says both that the factory holds `cap_sys_admin` and that it does not, and that the drop to
  the operator happens later and then performs it.
- Module docs describe earlier designs in `kenneld/src/lib.rs`, `kennel-lib-syscall/src/lib.rs`
  ("two sites carry our own unsafe"), `namespace.rs` ("no unsafe of ours", 28 sites) and
  `kennel-lib-spawn/src/lib.rs` ("the pure half"). Four doc comments in `kenneld` sit on the
  wrong function. One comment in the TOML tokenizer says a working branch never matches.
- About 370 `§` citations, 18 "Kennel book" citations and the `W<n>` work-package ids resolve
  only under `docs/archive/` or not at all.
- CODING-STANDARDS.md and the code disagree: §4 (only `kennel-lib-syscall` may hold unsafe),
  §3 (SPDX headers: none present; the unsafe register's location), §8.1 (error types), §11.1
  (newtypes), §12.2 (the lint table), §7.3 (cargo-fuzz and property tests).

**Did the first pass leave the code worse?** Partly. Each fix has a test and none added a lint
suppression. Its costs: `fd.rs` tripled with overlapping walkers and no unit tests; `construct`
grew by 68 lines; `IS_LOOPER` and `REPLIES_ORPHANED` are thread-local state in the binder
client; the address-rule check now exists in both the compiler and the loader; and comments
describing the pre-fix privilege model were left behind.

### Suggested order

1. ~~N-03 to N-08~~ done, with the rest of the rows.
2. ~~Unit tests for the node-0 handlers and for `fd.rs`~~ done in PR #245 (eight and eleven
   tests), together with the duplication items: one host-root walker and no hand-rolled
   `openat2` in `fd.rs` (one `unsafe` site fewer than the count above), one transact loop in
   the binder client, one facade-install function, and one byte reader in the new TCB crate
   `kennel-lib-bytes` (the closure is 18 crates). `tun_connect`, `register_mirror` and
   `register_tun_sink` still have no handler-level tests. The long functions are not
   refactored.
3. ~~A fuzz corpus seeded from fixtures and valid frames~~ done in PR #247: valid inputs built with each decoder's own encoder, then every
   truncation and single-byte change decoded, for the seven binder service decoders,
   `EgressPayload::decode`, `mesh_rendezvous::decode`, the SSHSIG path, the control protocol
   and the plan wire; and a property test that a signed policy with one byte changed never
   verifies as a different policy. It found no defect. Not done: multi-byte or
   structure-aware mutation, coverage guidance, and a golden-bytes file for the canonical
   form. ~~One definition of load-time validity (N-11)~~ done in PR #244.
4. The privilege-narrative and stale-comment sweep, and CODING-STANDARDS.md against the code.
   - **PR #248:** corrected the `construct.rs` / `main.rs` capability narrative and the module
     docs of `kennel-lib-syscall`, `kennel-lib-binder` and `kennel-lib-spawn`; removed
     `fork_hold`, `relay_winch`, `attach_egress` / `populate_egress_maps`; corrected §3, §4,
     §7.3 and §10.6 of the standard; listed eleven unmet rules in a new Appendix A.1.
   - **PR #250** does the work for nine of the eleven: SPDX headers on all 257 Rust files;
     the three-part comment on all 68 `unsafe` blocks that lacked it; `missing_docs`,
     `print_stdout` and (for the helper) `expect_used` denied; two property tests and a
     one-minute fuzz run in CI; and the rule text corrected where the code was the stricter
     (§11.3 paths, §12.2 `pedantic` and `print_stderr`, §7.3 `proptest`).
   - **PR #251** starts the tenth (§8.1): the factory's
     `construct` returns a `ConstructError` that separates refusals from failed system calls
     and names the failed step. The rest of the privileged path (`kennel-lib-spawn`'s view
     build, `kenneld`'s `String` errors) is not converted.
   - **PR #255** continues it: the view build in `kennel-lib-spawn` returns a `ViewError`
     (an image refusal with its reason, or the phase that failed), the mounts helper an
     `OverMountError`, and the daemon's start refusals name a `StartStage`. **PR #259**
     (merged) adds `LoadError` for the daemon's policy loader, and **PR #260** (merged)
     converts the rest of the start path (`CwdError`, `LandlockFloorError`, `WorkloadError`,
     `SshEgressError`). **PR #261** (merged) gives the CLI a `CliError` that sorts failures by kind
     (usage, file, daemon, failed step, refusal). **PR #262** (merged) converts the last
     four `String` errors in `kenneld`, and **PR #263** (merged) the rest: `kennel-compose`,
     `kennel-bin-oci-entry`, the destination, pattern and OpenSSH key parsers in
     `kennel-lib-policy`, and the reference-name check in `kennel-lib-compile`. No shipped
     function returns `Result<_, String>`. Bare `io::Error` returns remain in parts of
     `kennel-lib-spawn` and the privhelper client. CodeQL
     flagged the mounts helper's not-owned message for logging the caller's uid; the message
     no longer carries it.
   - **PR #252** starts the eleventh (§11.1): `KennelName`, taken by the daemon's dispatch,
     registry and `run_kennel`. Granted paths, addresses and ports are still plain types.
   - **PR #258** keys the daemon's registry map by `KennelName`; every registry method
     takes one.
   - **PR #264** adds `ScopedAddr` (the helper's checked loopback address),
     `ViewPath` (a bind's in-view target, enforced at plan decode) and `Port` (a
     destination's port). Still plain: a bind's host source, the settled policy's port
     lists and address rules, the proxy endpoint and the kennel context.
   - **PR #257** (merged) adds `MeshName` and `MeshKey` for the daemon's mesh path builder
     and removes its `_invalid` fallback directory: a malformed name or key is now refused
     by the caller.
   - **Leftovers, done in PR #271:** the one field in `kenneld` a search now finds
     written and never read (`Provision::factory`; the assessment counted three and did not
     name them); `effective_workload`'s doc
     comment, which sat on `resolve_cwd_grant`, and a missing one on `af_unix_connect`; a
     section in CODING-STANDARDS.md (§6.5) saying where the code's `§`, file-number, threat and
     "Kennel book" citations resolve, in place of rewriting some 900 comments; multi-byte fuzz
     mutations; a golden-bytes test for the canonical form; the BPF SPDX identifier.
   - **Test gaps, closed in PR #272:** a golden file for a fully populated policy;
     suite cases `interactive-pty` and `mesh-bus-concurrent`. The fully populated fixture
     found a defect: a policy using `fs.redirect` and `fs.write_mmap_exec` together could not
     be serialised, so it could not be signed. Fixed by declaring the two fields the other
     way round; no existing signature is affected.
   - **The bare `io::Error` returns at public boundaries** are typed in PR #273:
     the privhelper client (`ClientError`), the Landlock ruleset builder (`RulesetError`,
     which names the failing path) and the mesh rendezvous decoder (`RendezvousError`). The
     daemon's `Privileged` trait and the private helpers of the view build still use
     `io::Error`.
   - **The last two comment items** are done in PR #274. The TOML tokenizer comment
     was wrong, not stale: the branch it called unreachable handles a CRLF inside a multi-line
     string, and a test now shows that. The module docs of `kenneld/src/lib.rs` are rewritten.
   - **Kept on purpose:** `canonicalise_path` (§11.3 names it).
5. The positional-argument call sites are done in PR #249: `bring_up` takes the `Spec` (it
   took twenty positional parameters) and `binder::spawn` takes a `NodeZero` struct (fifteen,
   with two adjacent `bool`s).
6. Splitting the four long functions: `construct` (PR #265), `Plan::from_policy`
   (PR #266) and `bring_up` (PR #267) are merged, split into their stages with no length
   exemption; `run_kennel` (1046 lines) is split into four phases in PR #268, which also adds a
   suite case for a digest-pinned workload. The locks held across blocking work (the mesh-bus
   table, the bastion) are fixed in PR #269, and the decisions of `register_mirror`,
   `register_tun_sink` and `tun_connect` are tested in PR #270. That closes the list in this
   item; what is still open is under the coding standard's Appendix A.1.
