# Binder + network-namespace integration debt

The binder IPC mechanism and the network-namespace redesign are written as four
forward-contract chapters:

- design [`07-9-ipc.md`](../design/07-9-ipc.md) — binder IPC, the `org.projectkennel.*`
  service registry, inter-kennel IPC, kennel spawning.
- design [`07-10-binder-netns.md`](../design/07-10-binder-netns.md) — per-kennel network
  namespace, the loopback mirror, `org.projectkennel.INet`.
- architecture [`02-7-binder.md`](02-7-binder.md) — the binder implementation contract.
- architecture [`02-8-binder-net.md`](02-8-binder-net.md) — the network-over-binder contract.
- design [`07-11-kennel-init.md`](../design/07-11-kennel-init.md) — the kennel's PID 1: the
  uid-0 construction model, privhelper-constructs-the-kennel, and the binder bus as the
  init↔kenneld lifecycle control plane.

The **rest of the corpus does not yet reflect them.** This doc is the catch-up backlog: the
owed edits to fold the four chapters into the existing design and architecture, so the corpus
is internally consistent. It is a tracking doc, not a specification — delete each entry as it
lands, and delete the doc when the list is empty. Nothing here is new design; it is the
integration of design already made.

---

## Settled decisions the integration must carry

So no entry re-opens a closed question:

- **Naming** is Android-convention: reserved namespace `org.projectkennel.*` (owned like
  AOSP `android.*`), services `INTERFACE/INSTANCE` (`org.projectkennel.IAfUnix/default`, …),
  node 0 is the servicemanager with `IServiceManager`-style verbs (addService / getService /
  listServices / isDeclared / getDeclaredInstances), the `isDeclared` check is the
  VINTF-declared analogue (the signed policy is the manifest). The device stays the standard
  binderfs `binder` at `/dev/binderfs/binder` with a `/dev/binder` symlink.
- **`kennel-binder`** is the unsafe ABI crate (parallel to `kennel-bpf`); binder participants
  are `kenneld` (node 0), `kennel-netshim` (consumer), **and `kennel-init`** (PID 1, the
  lifecycle consumer — added by the uid-0 inversion below). No other process links it.
- **binderfs is `FS_USERNS_MOUNT`:** the instance is mounted inside the kennel's child userns;
  no host-side mount, no binder-*specific* privhelper op; kenneld takes node 0 via
  `/proc/<pid>/root` (or `SCM_RIGHTS`). **Superseded actor/privilege (see the inversion
  section):** the mount is now done by the root-owned `kennel-init` the privhelper `execve`s,
  not the old unprivileged spawn fork, and construction *is* privileged now (the `0 0 1`
  uid map needs `CAP_SETUID`).
- **kenneld is the trust anchor and sole owner** of the reserved nodes (incl. `INet`).
  `kennel-netproxy` (CONNECT) and the host-side spawn leg (BIND mirror) are **delegates over
  a per-kennel socketpair**, not binder participants.
- **kenneld concurrency** is the non-blocking looper + bounded pending-cookie table + global
  reply-reader of [`02-7-binder.md`](02-7-binder.md) §Threading model. Blocking I/O lives in
  the delegates. A slow delegate degrades to a refusal on one instance, never a looper stall.
- **Four network modes** — `none` / `constrained` / `unconstrained` / `host` — replace the
  old `none` / `constrained` / `open`. `[net]` splits into `[net.proxy]` + `[net.bpf]`.
- **The loopback mirror:** the kennel's `/28` + `/64` exist on both sides. A workload binds
  **natively inside** the kennel net-ns (intra-kennel reach by loopback); `[[net.bpf.bind]]`
  at the cgroup `bind` hook is the allow/deny gate; every **allowed** bind is mirrored
  host-side automatically (the host-side leg binds the same `ip:port` on the host alias),
  giving host observability and (relayed through the shim) host ingress.
- **Privhelper gains two net ops** — `AddLoopbackAlias` / `RemoveLoopbackAlias` — and **no**
  binder op.

Cross-cutting open items still live in [`02-7-binder.md`](02-7-binder.md) §Open questions
(relay placement in-kenneld vs broker; af-unix shim migration; looper-pool sizing; UAPI
vendoring). They are not part of this integration; they are design still in flight.

---

## Owed edits — design tree

| Target | Owed change | Source |
|---|---|---|
| [`07-3-network.md`](../design/07-3-network.md) | Replace the three-mode model with the four-mode taxonomy; re-architect the §7.3 loopback/egress model onto per-kennel net-ns + mirror + binder crossing; egress is SOCKS5→shim→`INet` `CONNECT`→netproxy delegate, not a direct loopback connect; `[net]`→`[net.proxy]`+`[net.bpf]`. | 07-10 |
| [`07-4-afunix.md`](../design/07-4-afunix.md) | The AF_UNIX shim model is superseded by the `org.projectkennel.IAfUnix/default` brokered-connect facade (no path in the view; fd returned). Reconcile §7.4 with §7.9.5; settle shim-vs-facade migration. | 07-9 §7.9.5 |
| [`07-5-dbus.md`](../design/07-5-dbus.md) | `xdg-dbus-proxy` is superseded by the `org.projectkennel.IDBus/default` facade (deferred build). Note the direction. | 07-9 §7.9.5/7.9.8 |
| `08-enforcement-architecture.md` §8.7 | Spawn sequence gains `CLONE_NEWNET`, inside-`lo` config, binderfs mount (in child userns), node-0 acquisition, the host-side leg, the reaper-forked `kennel-netshim`, delegate socketpairs, and the privhelper `AddLoopbackAlias` host mirror. §8.8 inter-kennel isolation gains the binder cross-instance exception (bilateral `provide`/`consume`). | 07-9, 07-10, 02-7, 02-8 |
| [`THREATS.md`](../design/THREATS.md) | T1.6 (host-network recon) closed by net-ns for `none`/`constrained`/`unconstrained`; `mode = host` reinstates it (`threats.reinstated`). New owed: a root-context-kennel threat section (`CAP_NET_RAW` raw/packet sockets). Consider threats for the binder IPC surface, cross-kennel relay, and the kenneld-as-relay TCB growth. | 07-10 §7.10.10, 02-7, 02-8 |

---

## Owed edits — architecture tree

| Target | Owed change | Source |
|---|---|---|
| [`01-process-model.md`](01-process-model.md) | New processes: `kennel-netshim` (kennel ns), the host-side spawn leg (host ns, BIND delegate), `kennel-netproxy` now host-net-ns + CONNECT delegate. Refined fork tree. kenneld binder context-manager + relay/reply-reader threads. IPC topology: binder node 0 / `INet` + per-kennel delegate socketpairs. CLI stays thin (no binder, no listener fds). **Largely rewritten by the uid-0/kennel-init inversion below** — the fork tree, PID 1, the privilege table, and the construction owner all change. | 02-7, 02-8, 07-11 |
| [`02-1-cli.md`](02-1-cli.md) | `kennel check` gains binder/net-ns prerequisites (binderfs driver, `CLONE_NEWNET`). `validate`/`compile` surface the four net modes and the `mode = host` `reason` requirement. | 07-10, 02-8 |
| [`02-2-config-schema.md`](02-2-config-schema.md) | `[net]`→`[net.proxy]`+`[net.bpf]`; four modes; `[[net.bpf.bind/allow/deny]]`, families/types/protocols/limits; `threats.reinstated` (auto for host); `[binder]` + `[[binder.provide]]`/`[[binder.consume]]` + `[ipc.spawn]`; reserved-namespace (`org.projectkennel.*`) compile validation. Fold [`net-policy.toml`](net-policy.toml) in and retire it. | 02-7, 02-8, net-policy.toml |
| [`02-3-audit-schema.md`](02-3-audit-schema.md) | Field schemas: `binder.register`/`lookup`/`cross`/`service-crash`, `kennel.spawn`; `net.bind` (with `mirrored`), `net.bpf.deny`; `INet` `CONNECT`/`INBOUND` outcomes. `net.egress` unchanged. | 02-7 §Audit, 02-8 §Audit |
| [`02-4-ipc.md`](02-4-ipc.md) | `SpawnKennel` control op (op 5 / resp 6). Note binder is a separate surface (→ 02-7/02-8). Document the kenneld↔delegate socketpair wire (netproxy CONNECT, host-leg mirror/INBOUND). netproxy is no longer reached by a TCP loopback listener. | 02-7 §Kennel spawning, 02-8 |
| [`02-5-bpf-abi.md`](02-5-bpf-abi.md) | The cgroup `bind` hook both enforces `[[net.bpf.bind]]` and **reports allowed binds** to kenneld (ringbuf) to drive the mirror. New socket-shaping programs/maps for `[net.bpf]` families/types/protocols/limits. connect/sendmsg interplay with the per-kennel net-ns (egress still gated to the proxy path). | 02-8 §BPF |
| [`02-6-internal-api.md`](02-6-internal-api.md) | New crates `kennel-binder` (+ `kenneld::binder`) and `kennel-netshim`. The kenneld↔delegate socketpair protocol. `kennel-netproxy` API change (drop SOCKS5 server, add delegate reader). | 02-7, 02-8 |
| [`03-crate-decomposition.md`](03-crate-decomposition.md) | Add `kennel-binder` (13th, unsafe) and `kennel-netshim` (14th, fuzzed SOCKS5). netproxy changes. Dep graph: binder confined to kenneld + netshim. | 02-7, 02-8 |
| [`04-trust-boundaries.md`](04-trust-boundaries.md) | Binder transaction boundary (shim↔kenneld); kenneld-as-relay TCB; the kenneld↔delegate socketpairs; the net-ns boundary; the host-side mirror; `INBOUND` fd delivery; reserved-node rules. | 02-7, 02-8 |
| [`05-state-and-supervision.md`](05-state-and-supervision.md) | Lifecycles: binderfs instance, `kennel-netshim`, the host-side leg, netproxy (binder-instance-coupled), delegate channels, mirror sockets. Teardown ordering (`RemoveLoopbackAlias`; binderfs unmounts with the ns). | 02-7, 02-8 |
| [`06-build-and-test.md`](06-build-and-test.md) | `CONFIG_ANDROID_BINDERFS` in the build/test env; binder load/test matrix; net-ns + root tests for the new path; fuzz targets (netshim SOCKS5, `kennel-binder` `BC`/`BR` decoder). | 02-7, 02-8 |
| [`07-paths.md`](07-paths.md) | `$XDG_RUNTIME_DIR/kennel/ctx-<n>/binderfs/`; `/dev/binderfs` + `/dev/binder` symlink in the view; the host loopback alias (kennel `/28`+`/64` on host `lo`). | 02-7, 02-8 |
| `08-as-built-notes.md` §8.1 | Add the binder IPC and net-ns redesign as roadmap entries; record T1.6's net-ns closure path (graduating the §8.1 shared-net-ns residual). | this work |
| `BUILD-ENV.md` | Pin the binder kernel config and the binder UAPI headers (`linux/android/{binder,binderfs}.h`). | 02-7 |

---

## Owed edits — the uid-0 / `kennel-init` construction inversion (decided 2026-06-08)

A foundational change that surfaced while building binder: binderfs assigns its control and
device nodes to **uid 0 of the mounting user namespace**. The kennel's pure-identity uid map
(`{uid} {uid} 1`) provides no uid 0, so the nodes landed on the overflow uid (`nobody`, mode
`0600`) and **nothing in the kennel could open them** — proven by the full-vertical e2e
(`add_binder_device` EACCES). Beyond binder, the same gap made the view root, `/dev`, and the
RO library binds display as `nobody`/`kennel` rather than a proper root.

**Decision (see [`07-11-kennel-init.md`](../design/07-11-kennel-init.md)):** give the kennel a
real uid 0 by mapping **host root `0 0 1`** (no subuid — "there be dragons"), plus the
operator identity line. Because `0 0 1` needs `CAP_SETUID` and is a privilege-escalation
hazard if operator code can run as userns-0, the **privhelper constructs the kennel**: it
creates the userns, writes the maps, and `execve`s the **root-owned `kennel-init`** as the
trusted uid-0 **PID 1** — the only userns-0 process. `kennel-init` builds the view (system
surfaces owned by root), mounts + chowns binderfs, launches the operator-uid facades, then
forks the workload dropped to the operator and supervises it. Binder is now **integral**: the
init↔kenneld lifecycle control plane rides the binder bus (§7.11.2).

This **inverts** the prior "kenneld constructs unprivileged; the privhelper does only
add-addr / egress / gid-map" model. It supersedes that framing wherever it appears.

### Settled decisions this inversion carries

- **uid 0 = host root mapped `0 0 1`** + operator identity line; **no subuid/subgid**.
  Written by the privhelper (gains `CAP_SETUID`; already has `CAP_SETGID`). The old gid-map
  handshake (§7.2.8, deferred-gid) is subsumed: the maps are written once, fully, by the
  constructor before `kennel-init` starts.
- **The privhelper is the kennel constructor**: new op (e.g. `ConstructKennel`) over a
  `SOCK_SEQPACKET` socketpair (it must pass fds via `SCM_RIGHTS` and return the init/workload
  host pids and exit status). The `Plan` crosses kenneld→privhelper→`kennel-init` as bytes
  (`kennel-spawn::wire`, built); the privhelper forwards it, `kennel-init` (root) decodes +
  re-validates it — operator data parsed by root, fuzzed (§10.6).
- **`kennel-init` is root-owned and trusted by provenance**: its path comes from the
  deployment config (`Deployment::kennel_init()` → libexec), never the wire; the privhelper
  verifies root ownership + non-writability before `execve`. The operator cannot substitute a
  uid-0 init.
- **The workload is never uid 0**: `kennel-init` forks it and drops gid → groups → uid to the
  operator (`set_gid`/`set_uid`), then `no_new_privs` + seccomp + Landlock + ulimits + pty +
  `execve` — irreversible. Facades drop the same way; only `kennel-init` stays uid 0.
- **Lifecycle identity gate**: kenneld accepts a lifecycle verb only from
  `sender_pid == init_host_pid` (a host-side context manager sees host pids, **not** the
  kennel-internal `1`) `&& sender_euid == 0`. The init host pid is the privhelper bootstrap
  fact, not wire-supplied.
- **Exit status rides the process chain** (`kennel-init` `_exit` → privhelper → kenneld), not
  binder (which may be torn down). Binder carries in-life telemetry only.

### Owed edits

| Target | Owed change | Source |
|---|---|---|
| [`01-process-model.md`](01-process-model.md) | Rewrite the fork tree and PID-1 semantics: the **privhelper** forks the userns/PID-1 chain and `execve`s **`kennel-init`** (PID 1, uid 0); `kennel-init` forks the facades + the workload (operator uid). Privilege table: privhelper gains **`CAP_SETUID`** and becomes the **constructor** (drop the "minimal add-addr/egress/gid-map only" claim). New trusted binary `kennel-init`. IPC topology gains the construction socketpair (Plan in, pids/status back) and the binder lifecycle channel (init→node 0). | 07-11 |
| design [`01-thesis.md`](../design/01-thesis.md), [`02-adversary-model.md`](../design/02-adversary-model.md), [`03-problem-statement.md`](../design/03-problem-statement.md), [`04-trust-boundaries.md`](../design/04-trust-boundaries.md) | **Binder becomes integral**, not an opt-in IPC facade: every kennel runs a binder bus as its control plane (init↔kenneld), so the thesis/problem framing must present binder as load-bearing. The adversary model gains: host uid 0 mapped into the userns (safe only because no operator code reaches userns-0 — state the invariant + the escalation-window analysis), and the workload-vs-init uid-0 separation. Trust boundaries: the privhelper is now the constructor parsing an operator `Plan` (largest new root-parses-operator-input surface). | 07-11, 02-7 |
| architecture [`04-trust-boundaries.md`](04-trust-boundaries.md) | Boundary 1 (operator↔privhelper) is now a *construction* boundary: the privhelper holds `CAP_SETUID`, maps host root, parses the operator `Plan`, and `execve`s a trusted init. Add the escalation-window analysis (operator code never runs as userns-0) and the `kennel-init`-path provenance trust. | 07-11 |
| [`02-4-ipc.md`](02-4-ipc.md) | New privhelper `ConstructKennel` op (socketpair, `SCM_RIGHTS` fds, Plan blob in, init/workload pids + exit status out). Document the `kennel-spawn::wire` Plan encoding as the op payload. | 07-11 |
| [`03-crate-decomposition.md`](03-crate-decomposition.md) | Add the **`kennel-init`** crate (root-owned PID-1 binary); `kennel-init` links `kennel-binder` (lifecycle consumer) + reuses the `kennel-spawn` seal. Update the "binder confined to kenneld + netshim" dep-graph note to include `kennel-init`. | 07-11 |
| [`07-paths.md`](07-paths.md) | `kennel-init` in libexec (root-owned, non-writable); the privhelper gains `cap_setuid` (alongside `cap_sys_admin`/`cap_net_admin`/`cap_setgid`). | 07-11 |
| [`06-build-and-test.md`](06-build-and-test.md) | `cap_setuid` in the privhelper `setcap` line; build `kennel-init`; the construction-path root e2e; fuzz the Plan decoder (`kennel-spawn::wire`). | 07-11 |
| design [`07-9-ipc.md`](../design/07-9-ipc.md) §7.9.3, architecture [`02-7-binder.md`](02-7-binder.md) §Mount sequencing / §Privilege | Full reconciliation of the binderfs lifecycle text to the `kennel-init`/uid-0 actor + the open-then-chown device hand-off (callouts added; prose still describes the old unprivileged-spawn actor). | 07-11 |
| design [`07-2-filesystem.md`](../design/07-2-filesystem.md) §7.2.8 | The deferred-gid map handshake is replaced by the constructor writing both maps once (`0 0 1` + operator + granted groups). | 07-11 |
| `08-as-built-notes.md` §8.1 / design [`11-open-questions.md`](../design/11-open-questions.md) | Record the subuid rejection rationale and the `0 0 1` mapping decision; graduate the uid-0/`nobody`-ownership residual. | 07-11 |

