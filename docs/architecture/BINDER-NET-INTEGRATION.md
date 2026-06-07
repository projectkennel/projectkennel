# Binder + network-namespace integration debt

The binder IPC mechanism and the network-namespace redesign are written as four
forward-contract chapters:

- design [`07-9-ipc.md`](../design/07-9-ipc.md) — binder IPC, the `org.projectkennel.*`
  service registry, inter-kennel IPC, kennel spawning.
- design [`07-10-binder-netns.md`](../design/07-10-binder-netns.md) — per-kennel network
  namespace, the loopback mirror, `org.projectkennel.INet`.
- architecture [`02-7-binder.md`](02-7-binder.md) — the binder implementation contract.
- architecture [`02-8-binder-net.md`](02-8-binder-net.md) — the network-over-binder contract.

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
- **`kennel-binder`** is the unsafe ABI crate (parallel to `kennel-bpf`); binder is confined
  to `kenneld` (node 0) and `kennel-netshim` (consumer). No other process links it.
- **binderfs is `FS_USERNS_MOUNT`:** the instance is mounted inside the kennel's child userns
  during spawn; no host-side mount, no privhelper binder op. kenneld takes node 0 via
  `/proc/<pid>/root` (or `SCM_RIGHTS`).
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
| [`01-process-model.md`](01-process-model.md) | New processes: `kennel-netshim` (kennel ns), the host-side spawn leg (host ns, BIND delegate), `kennel-netproxy` now host-net-ns + CONNECT delegate. Refined fork tree (host-side leg → in-ns reaper A → workload + netshim). kenneld binder context-manager + relay/reply-reader threads. Privilege table: +2 privhelper ops, **no** binder op. IPC topology: binder node 0 / `INet` + per-kennel delegate socketpairs. CLI stays thin (no binder, no listener fds). | 02-7, 02-8 |
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
</content>
