# API surfaces — network over binder (`org.projectkennel.INet`)

This chapter is the implementation contract for the binder-based network service
introduced by the network namespace redesign in [`07-5-network.md`](../design/07-5-network.md).
Where `07-5` says *what and why*, this chapter commits to the concrete shape: which
processes participate on the kennel's binderfs instance, the transaction wire conventions
for `org.projectkennel.INet/default`, the spawn sequencing changes, the thread model, and
the relationship to the existing `host-netproxy` crate.

> **Status: largely built.** The core network subsystem is as-built: the four modes
> (`none`/`constrained`/`unconstrained`/`host`), the per-kennel net-ns + loopback alias, the
> socketpair conduit, the `CONNECT_INET` egress path (`facade-socks5` → node 0 → kenneld
> resolve/pin → `host-netproxy` dumb dialer), and the inbound host-side mirror
> (`host-inetd` + `facade-client`, **push-based**: the facade registers a callback node and kenneld
> pushes each accepted conduit — see §The host-side mirror and `BIND`). What remains
> roadmap is the **cross-instance / inter-kennel relay** (one kennel reaching another kennel's
> services through kenneld) and `SpawnKennel`; those legs still read "kenneld is designed to do X".

> The design — the four modes, the socketpair conduit, the `CONNECT`/`BIND` verbs, the
> kenneld-side policy/resolve/pin, and the dumb `host-netproxy` dialer — is
> [`07-5-network.md`](../design/07-5-network.md) (§7.5). This chapter is the wire-level contract
> for that design.

## Stability commitment

**Internal-stable** per [`02-0-overview.md`](02-0-overview.md). The `org.projectkennel.INet`
transaction wire format, the `facade-socks5` SOCKS5 interface, and the inter-process
fd-passing conventions documented here are internal: the workload never addresses them
directly. The stability surface the workload sees is the SOCKS5 endpoint at
`$KENNEL_SOCKS_PROXY` — that is unchanged from the pre-netns model.

---

## Participants on the kennel's binderfs instance

The network service involves four processes, each with a defined role on the kennel's
binderfs instance. This is an extension of the participant set defined in
[`02-4-binder.md`](02-4-binder.md):

| Process | Net-ns | Binder role | Network responsibility |
|---|---|---|---|
| `kenneld` | host | context manager (node 0); **sole owner** of `org.projectkennel.INet/default` | policy enforcement, transaction relay; never in the data path |
| `host-netproxy` | host | kenneld's **CONNECT delegate** (no binder access) | outbound dial, proxy allowlist enforcement, DNS vetting, audit |
| host-side spawn leg | host | kenneld's **BIND delegate** (no binder access) | holds the host-side mirror (same `ip:port` on the host alias) of the kennel's native inside listener |
| `facade-socks5` | kennel | binder **consumer** of `org.projectkennel.INet/default` | SOCKS5 inbound, binder transaction dispatch, accept loop, splice to workload |

Only kenneld registers `org.projectkennel.INet/default` — it is a reserved-namespace node
and the reserved rule (`02-4-binder.md` §The `org.projectkennel.*` reserved namespace)
admits no other registrant. `host-netproxy` and the host-side spawn leg are kenneld's
**delegates, not binder participants**: kenneld receives every `INet` transaction on node 0,
runs the policy check, and forwards `{cookie, payload, target}` to the right delegate over a
per-kennel `kenneld`↔delegate channel — a `socketpair` established at spawn. The delegate
does the blocking work (dial / bind) and returns the fd by `SCM_RIGHTS`; kenneld returns it
to the shim in the binder reply via `BINDER_TYPE_FD` (§Thread model). The only binder
endpoints are therefore kenneld (node 0) and the shim (consumer); neither delegate links
`kennel-lib-binder` or opens `/dev/binder`. The workload reaches none of these processes
directly — it speaks SOCKS5 to the shim.

### The host-side mirror and `BIND`

The listener itself lives **inside** the kennel net-ns: the workload `bind()`s natively on
its `lo` addresses (cgroup BPF gating against `[[net.bpf.bind]]`), and intra-kennel callers
reach it directly over loopback — no proxy, no binder in that path. The host-side spawn leg
does **not** own that listener; it holds the **host-side mirror** — the same `ip:port` on
the host alias — so the port is observable in host `ss`/`lsof` at the kennel's own IP and,
when policy exposes it, reachable from the host (host inbound is relayed into the kennel
through the shim, which connects to the native inside listener and splices).

The leg is the right owner of the mirror because it is the spawn's host-net-ns leg
([`01-process-model.md`](01-process-model.md) for the fork structure): per-kennel,
host-side, lifetime = kennel, so the mirror socket is attributable to the kennel and is
reclaimed when the kennel exits. The CLI is uninvolved — `kennel run` stays the thin,
stateless control-socket client of [`01-process-model.md`](01-process-model.md), with no
binder role and no listener fds.

**The mirror is BPF-`bind`-hook-driven, policy-gated.** A native `bind()` inside the kennel
is decided by `[[net.bpf.bind]]` at the cgroup `bind` hook — policy sits in between, not the
workload. A **denied** bind fails at the syscall (`EACCES`) and no listener exists; an
**allowed** bind succeeds and the hook reports it to kenneld, which raises the host-side
mirror for it. Every listener that exists is therefore both intra-kennel-reachable and
observable host-side at the kennel's IP, and the allow/deny decision is policy's alone.
There is no workload-initiated `BIND` transaction: the `INet` node carries egress `CONNECT`
and the kenneld→shim inbound delivery only (§Transaction codes).

### Why `host-netproxy` is per-kennel

`host-netproxy` remains one instance per active kennel, not a shared host-side service.
Per-kennel rulesets, per-kennel audit streams, no cross-kennel policy surface. The only
thing that changes is how the workload's connection request reaches it — a relayed delegate
request from kenneld instead of a direct TCP connect to a loopback listener. The
`Proxy::reload` live-ruleset mechanism is unaffected.

---

## The loopback mirror

The kennel's assigned address space — an IPv4 `/28` from `127.0.0.0/8` and an IPv6 `/64`
from the project ULA, allocated at spawn (design §7.5) — exists on **both** sides of the
net-ns boundary as the *same* addresses:

- **Inside the kennel net-ns:** the spawn configures `lo` with the kennel's `/28` + `/64`,
  unprivileged (`CAP_NET_ADMIN` holds in the kennel's own netns). The workload and the shim
  bind/connect/listen against these normally.
- **Host net-ns:** the privhelper adds the same `/28` + `/64` as an alias on the host `lo`
  (`AddLoopbackAlias`).

This symmetry is deliberate and serves **both** directions:

- **Inside (the load-bearing case):** the workload binds and listens **natively** on its
  `lo` addresses, so a listener it opens — say `127.43.16.1:8080` — is immediately reachable
  by any other process in the same kennel through ordinary loopback, with no proxy and no
  binder in that path. The bind is gated by cgroup BPF against `[[net.bpf.bind]]`; the
  listener lives in the kennel's own stack, which is exactly what makes it reachable from
  inside the kennel.
- **Host:** the same `127.43.16.1` exists on the host alias, so that listener can be
  observed and (when policy exposes it) reached from the host at the kennel's own IP — the
  host-side leg holds the mirror socket (§The host-side mirror and BIND). On the host
  `ss`/`lsof` it shows at `127.43.16.1`, owned by a process attributable to the kennel.

There is no routing and no NAT: the two stacks are independent — a `connect()` inside the
kennel to its loopback stays inside it — and the only controlled crossing is binder.
`mode = host` kennels share the host stack directly and use no mirror.

---

## `org.projectkennel.INet/default` transaction protocol

`org.projectkennel.INet/default` is a kenneld-owned node in the reserved
`org.projectkennel.*` namespace, subject to the same two hard rules as all reserved
services (`02-4-binder.md` §The `org.projectkennel.*` reserved namespace): only
kenneld may register it; `getService` for it always resolves locally. It is present only
when `net.mode` is `constrained`, `unconstrained`, or `host`. A `mode = none` kennel has
no net-ns crossing point and no `INet` node.

### Transaction codes

| Code | Name | Direction | Payload | Reply |
|---|---|---|---|---|
| 1 | `CONNECT` | shim → kenneld → netproxy delegate | hostname (length-prefixed UTF-8, ≤ 253 bytes) + port (u16 BE) | connected fd via `BINDER_TYPE_FD`, or `BR_FAILED_REPLY` |
| 2 | `INBOUND` | kenneld → shim | target port (u16 BE) + accepted host-inbound socket fd via `BINDER_TYPE_FD` | ack |

There is no `BIND` transaction: inbound listeners are native inside the kennel and the
host-side mirror is raised by kenneld off the cgroup `bind` hook (§The host-side mirror and
`BIND`), not by a workload request. `INBOUND` is the ingress half — kenneld calls into the
shim to hand off a connection the host-side mirror accepted, and the shim connects the native
inside listener and splices. kenneld can call the shim because the shim passes a callback
node when it registers as the `INet` consumer; the delivery is intra-instance, so
`BINDER_TYPE_FD` is permitted. All other transaction codes on this node are rejected with
`BR_FAILED_REPLY` and audited.

### Payload constraints

Hostname is validated UTF-8, ≤ 253 bytes, no embedded NUL, no control characters, per
CODING-STANDARDS §10. The hostname is passed to `host-netproxy` as-is; resolution
happens proxy-side, never shim-side (`socks5h://` semantics are preserved — the kennel
has no DNS path of its own). Port 0 on `CONNECT` is rejected (`BR_FAILED_REPLY`) — the
shim must supply a concrete port. `INBOUND` carries the target port (the mirrored
listener's, never ephemeral) plus the accepted fd.

### fd passing

Reply fds are passed via `BINDER_TYPE_FD`, which the kernel dups into the receiving
process's fd table — semantically equivalent to `SCM_RIGHTS`. The fd the shim receives
is a real socket in the host net-ns, usable for `read`/`write`/`shutdown`. The shim
never calls `connect()` or `bind()` on a received fd — it is already in the desired
state when returned. This is a design invariant; violating it constitutes a net-ns
crossing outside the controlled path.

`BINDER_TYPE_FD` is permitted on this node because the shim and kenneld are within the same
trust boundary for this transaction class (the delegates hand their fds to kenneld by
`SCM_RIGHTS`, off the binder path entirely). The general cross-instance fd prohibition
(`02-4-binder.md` §Intra-instance vs cross-instance object types) is not implicated — shim
to kenneld is intra-instance.

---

## Transaction flows

### CONNECT

```
workload
  │  SOCKS5 CONNECT (hostname, port)
  ▼
facade-socks5  (kennel net-ns, :1080)
  │  binder CONNECT(1): hostname + port
  ▼
kenneld  (host, context manager — node 0 looper)
  │  mode / policy check; forward to CONNECT delegate over socketpair
  ▼
host-netproxy  (host net-ns, delegate — no binder)
  │  [net.bpf] CIDR check (unconstrained/host)
  │  DNS resolution
  │  [net.proxy] invariant_deny + deny + allow vetting
  │  dial TCP to resolved address
  │  audit: net.egress event
  │  return connected fd by SCM_RIGHTS over socketpair
  ▼
kenneld  (reply-reader: BC_REPLY with fd via BINDER_TYPE_FD on saved cookie)
  ▼
facade-socks5
  │  receives connected fd
  │  splice loop: workload ↔ fd
  ▼
workload  (data flows directly; kenneld not in data path)
```

### BIND (listener inside; host-side mirror)

```
intra-kennel path (always — the load-bearing case):

  workload ── bind()/listen() 127.43.16.1:8080 on inside lo ──►  native listener
                  (cgroup BPF gates against [[net.bpf.bind]])
  other in-kennel process ── connect() 127.43.16.1:8080 ──►  reaches it directly
                  (normal loopback; no proxy, no binder)

host-side mirror (observe / expose at the same IP) — BUILT, push-based:

  bring-up ──► kenneld eagerly registers each policy-mirrored port with host-inetd
       ▼
  host-inetd  (host net-ns, delegate — no binder; reverse of host-netproxy)
       │  bind() the same 127.43.16.1:8080 on the host alias, listen, accept
       │  per accept: mint socketpair, splice accepted⇄host_end LOCALLY,
       │             push the kennel_end + port to kenneld (SCM_RIGHTS)
       ▼
  kenneld  pushes the kennel_end to the port's registered mirror node  (pure fd router)
       ▼
  facade-client (in-kennel; reverse of facade-socks5)
       │  REGISTER_MIRROR(port) + own node, at bring-up, then SLEEPS in a server loop
       │  on each push: one-way DELIVER_INET(port) carries the kennel_end fd
       │  connect() the native inside listener 127.43.16.1:8080 and splice
       ▼  bytes: external → accepted → host_end⇄kennel_end → facade-client → listener
```

> **As-built: push (§7.5.7).** `facade-client` registers a callback node per mirrored port
> ([`REGISTER_MIRROR`], `transact_node` sending a `BINDER_TYPE_BINDER`) and then sleeps in a binder
> server loop — zero CPU, no poll. kenneld acquires the translated handle, watches its death, maps
> `port → handle`, and on each `host-inetd` accept pushes a **one-way** [`DELIVER_INET`] carrying the
> conduit fd ([`transact_oneway_fd`]). kenneld makes no inbound policy decision (the `bind4`/`6` ACL
> already gated the bind). Three guards bound the new callback surface: **death-notify** lifecycle
> (`BR_DEAD_BINDER` → drop the stale handle), **one-way + per-port bounce buffer** (kenneld never
> blocks on the facade; the queue above is the bounce path for the register/full-buffer window), and
> **port-gated registration** (the facade and workload share the persona uid, so registration is
> gated on the policy mirror set, not `sender_euid`). It reverses the no-callback-node property
> knowingly — for inbound, kenneld→kennel is the data direction — while the conduit fd stays
> out-of-TCB (the [fd-passing verdict, `02-4`](02-4-binder.md) is intact). Why push beats the earlier
> pull (idle-poll CPU + delivery latency; the thread-bound-reply sidestep): [`07-5`](../design/07-5-network.md) §7.5.7.
>
> [`REGISTER_MIRROR`]: the inbound-mirror registration verb (node 0).
> [`DELIVER_INET`]: the one-way conduit-delivery push (to the mirror node).
> [`transact_oneway_fd`]: `kennel-lib-binder` one-way transaction carrying a `BINDER_TYPE_FD`.

---

## Thread model

All processes use the existing blocking thread-per-connection discipline — no async
runtime, consistent with the rest of the codebase.

**`kenneld`:** the canonical binder threading is in [`02-4-binder.md`](02-4-binder.md)
§Threading model — a non-blocking per-instance looper that hands relay verbs (`INet`
`CONNECT`/`BIND` among them) to a delegate over the per-kennel `socketpair` and returns to
`BINDER_WRITE_READ`, plus a global reply-reader that issues `BC_REPLY` with the returned fd
on the saved cookie. The `INet` relay adds **no** kenneld threads beyond that model: the
looper never blocks on a dial, and the bounded pending-cookie table is the head-of-line and
memory bound. A slow `host-netproxy` dial degrades to a refusal on that one instance, not
a looper stall.

**`facade-socks5`:** one listener thread on :1080; one thread per accepted SOCKS5
connection. Each thread issues one binder transaction (blocking on its reply), receives the
fd, then runs a splice loop. For host inbound to a mirrored port it connects the native
inside listener and splices each relayed connection. The shim is the only network process
besides kenneld that touches binder.

**`host-netproxy`:** no binder. One delegate-request reader thread on its
`kenneld`↔delegate `socketpair`; each `CONNECT` request dispatches a worker thread (DNS
resolution, dial) that returns the connected fd by `SCM_RIGHTS`. The existing `Proxy`,
`Ruleset`, and `Resolver` split is unchanged; only the inbound half (previously the SOCKS5
accept loop) becomes the delegate-socketpair reader. `Proxy::reload` is unaffected.

**host-side spawn leg:** no binder. One delegate-request reader thread on its `socketpair`;
for each mirror request it binds the same `ip:port` on the host alias, retains the mirror
socket (lifetime = kennel, host-side attribution), and forwards inbound host connections to
the shim for relay into the kennel. The native inside listener — the one intra-kennel
callers reach — is the workload's own, not the leg's.

---

## Spawn sequencing

The spawn sequence in `kennel-lib-spawn` (`01-process-model.md`, design §8.7) changes
as follows. New steps are marked **†**; existing steps are condensed.

1. Mount namespaces (including **† `CLONE_NEWNET`**), pivot_root, construct view —
   existing + net-ns addition. Inside the kennel net-ns the spawn configures `lo` with the
   kennel's assigned `/28` + `/64` (unprivileged — `CAP_NET_ADMIN` in the kennel's own
   netns).
2. **† Privhelper `AddLoopbackAlias`**: `ip addr add <kennel-cidr> dev lo` in the host
   net-ns, for both IPv4 `/28` and IPv6 `/64` — the host mirror of the same address space
   (§The loopback mirror). Must complete before any host-side `bind()` on the kennel's IP.
   Corresponding `RemoveLoopbackAlias` at kennel exit.
3. Mount binderfs, allocate `binder` device, create `/dev/binder` symlink — existing
4. kenneld acquires context-manager fd, calls `BINDER_SET_CONTEXT_MGR` — existing
5. **† Connect delegate channels**: kenneld opens a `socketpair` to each delegate. The
   host-side spawn leg (already in the host net-ns; BIND delegate) keeps its end; kenneld
   launches **`host-netproxy`** (host net-ns; CONNECT delegate) and passes it its end.
   Neither delegate opens `/dev/binder` or registers anything — they speak the delegate
   protocol over the socketpair only.
6. **† Reaper A forks `facade-socks5`** into the kennel's namespaces and view (sibling of
   the workload under the in-kennel reaper — `01-process-model.md`): it opens `/dev/binder`,
   `getService`s `org.projectkennel.INet/default`, and starts its SOCKS5 listener on the
   kennel's assigned loopback address at :1080.
7. Landlock seal, workload exec — existing

**`host-netproxy` launch timing** is the surgery. It previously launched early with a
config file and a SOCKS5 listen address; it now launches after binderfs is up and attaches
to the delegate socketpair instead of binding a SOCKS5 listener. The config file path
(`Proxy::reload`) is unchanged; only the startup ordering and the inbound half change.

`CLONE_NEWNET` at step 1 means the kennel's network namespace is empty from the moment of
creation — no host network state is ever visible inside it. The `AddLoopbackAlias`
privhelper call at step 2 must complete before any host-side `bind()` at step 5/6.

**`mode = none` spawn:** steps 2, 5, 6 are skipped entirely. `CLONE_NEWNET` still applies
(step 1, with an empty `lo`). No privhelper network operation, no delegates, no shim, no
`INet` node.

---

## Relationship to `host-netproxy` crate

The `host-netproxy` crate splits into two concerns that were previously unified:

| Concern | Pre-netns | Post-netns |
|---|---|---|
| Inbound SOCKS5 accept / handshake | `server.rs` in `host-netproxy` | `facade-socks5` (new crate, inside kennel net-ns) |
| Outbound dial, proxy allowlist, DNS vetting, audit | `server.rs` in `host-netproxy` | `host-netproxy` (unchanged logic, new delegate-socketpair inbound) |

`facade-socks5` is a **new crate** in the workspace. It is a thin process: binder consumer,
SOCKS5 state machine, splice loop. It carries no policy logic. It parses untrusted input
(SOCKS5 from the workload) and requires a fuzz target under `fuzz/` per CODING-STANDARDS
§10.6. It is the only new process that links `kennel-lib-binder`.

`host-netproxy` loses its SOCKS5 inbound half and gains a delegate-socketpair reader in
its place — **not** a binder endpoint. The `Proxy`, `Ruleset`, `Resolver`, and audit logic
are unchanged, and the crate stays `#![forbid(unsafe_code)]` with no `kennel-lib-binder`
dependency (binder stays confined to kenneld and the shim). The config schema changes:
`[net]` becomes `[net.proxy]` throughout; the crate's config reader is updated accordingly.

---

## BPF policy enforcement

For `unconstrained` and `host` mode kennels, cgroup BPF programs enforce the
`[net.bpf]` policy at the socket level. The BPF programs gate:

- `socket(family, type, protocol)` — against `[net.bpf.families]`,
  `[net.bpf.types]`, `[net.bpf.protocols]`
- `bind(addr, port)` — against `[[net.bpf.bind]]` and `[[net.bpf.deny]]`
- `connect(addr, port)` — against `[[net.bpf.allow]]` and `[[net.bpf.deny]]`
- Connection count and rate — against `[net.bpf.limits]`

For `constrained` kennels, `[net.bpf]` is optional. When present, the BPF programs
run as defence-in-depth; the net-ns boundary is the enforcement primitive.

For `host` mode kennels, BPF is the primary enforcement primitive — no net-ns
boundary exists. The proxy remains mandatory to preserve the audit trail.

For `mode = none` kennels, no BPF network programs are loaded. There is no network
surface to gate.

---

## Audit events

Network audit events are unchanged in schema. The `net.egress` event is still
emitted by `host-netproxy` per outbound connection, with the same fields (`kennel
ctx`, destination, outcome, byte counts, duration). The transport change — binder
instead of SOCKS5 inbound — is invisible to the audit layer.

New events:

| Event | Emitted by | Fields |
|---|---|---|
| `net.bind` | kenneld (BPF drain) | kennel ctx, addr, port, outcome (allowed binds carry `mirrored: true` once the host-side mirror is raised) |
| `net.bpf.deny` | kenneld (BPF drain) | kennel ctx, family, type, protocol, addr, port, rule (a policy-denied `bind()`/`connect()`/`socket()`) |