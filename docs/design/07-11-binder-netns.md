# §7.11 Network namespace isolation

## 7.11.1 Motivation

The network design in §7.5 documents an accepted residual in T1.6: a kennel shares the
host network namespace, so despite the cgroup BPF egress gate blocking outbound
connections, the workload can read the host's full network state — interface table,
routing table, listening socket table, ARP/neighbour cache — via both `/proc/net/*` and
`AF_NETLINK` (`RTM_GETLINK`, `RTM_GETROUTE`, `sock_diag`). This is reconnaissance
without consequence (egress is blocked) but it is information leakage the design should
not accept permanently.

Masking `/proc/net` alone does not close it — netlink is an independent vector.
Restricting `AF_NETLINK` via seccomp breaks `getaddrinfo`'s `AI_ADDRCONFIG` path used
by many runtimes. The complete fix is a per-kennel network namespace, which makes
`/proc/net` show only the kennel's own stack and netlink answer only about the kennel's
own interfaces. This is a re-architecture of the §7.5 egress/loopback model, set out here.

## 7.11.2 Design constraints

Non-negotiable, coming out of §7.5 and the fd-over-binder safety review (§7.11.7):

**The SOCKS5 contract is preserved.** The workload finds a SOCKS5 listener at
`$KENNEL_SOCKS_PROXY` and connects to it. Every tool — `curl`, `git`, `pip`, `npm`,
`cargo`, `ssh` via `ProxyCommand` — already speaks this. The net-ns boundary must not
require any workload-visible change.

**No host socket ever crosses the boundary into the kennel.** The thing the kernel hands
a process inside the kennel is only ever a **local socketpair end** that kenneld minted —
never a host-network socket. A host socket carries its origin net-ns and answers
`getpeername`/`getsockname`/`SIOCGIF*` against the *host* stack; a socketpair end is
anonymous (no peer name, network ioctls return `ENOTTY`, it cannot `connect()` anywhere).
This is what keeps the net-ns isolation the chapter exists to add from leaking back through
the very fd that crosses it (§7.11.7).

**kenneld is never in the data path.** kenneld is the highest-authority host userspace
process and `#![forbid(unsafe_code)]`; it must not run a per-connection byte-copy loop over
untrusted payload (T5.3). It brokers the *control* (decide, resolve, mint the conduit) and
steps out; bytes move by `splice` at the two ends, never through kenneld.

**The control plane never blocks on I/O.** The per-kennel binder looper carries the
lifecycle/TTL verbs and the service registry as well as `INet`; a `CONNECT` that blocks the
looper on DNS or a `dial()` head-of-line-stalls the *whole* kennel control plane. The looper
does only O(1) policy and returns; resolve/dial/accept run on a bounded worker, replied
asynchronously by transaction cookie (§7.11.8).

**Every kennel's network surface is resource-bounded.** The shim's per-connection splice
threads and the conduit fds are bounded structurally by the kennel cgroup
(`pids.max`/`memory.max`) and a per-kennel concurrent-connection cap, not by the operator's
shared session budget (§7.11.9).

**No veth.** A veth pair needs `CAP_NET_ADMIN` in the host net-ns, host routing/NAT, and a
kernel stack per kennel — the container-runtime architecture, correct but below the
userspace confinement layer Kennel operates at. The design avoids it; the only host-side
network object is a loopback alias.

## 7.11.3 Network modes

§7.5 defined three modes (`none`, `constrained`, `open`). This chapter introduces a
four-mode taxonomy that separates the isolation axis (net-ns or not) from the enforcement
axis (proxy allowlist, BPF, or both). The old `open` mode is retired and replaced by
`unconstrained` and `host`.

| Mode | Net-ns | Proxy | BPF role | Use case |
|---|---|---|---|---|
| `none` | `CLONE_NEWNET`, empty | absent | absent | Untrusted scripts, code inspection; zero network surface |
| `constrained` | `CLONE_NEWNET` + loopback alias | present, allowlist | optional defence-in-depth | AI agents, package installs from known registries |
| `unconstrained` | `CLONE_NEWNET` + loopback alias | present, invariant denylist only | socket-level capability shaping, DoS bounds | Build-from-source, open egress with audit retained |
| `host` | host net-ns | present, mandatory | **primary enforcement primitive** | Packet capture, raw socket tooling, root-context kennels |

`mode = none` is the zero-cost case. `CLONE_NEWNET` inside the user namespace is
unprivileged — no privhelper involvement, no loopback alias, no shim, no proxy. The kennel
gets a fully empty network stack; `/proc/net` is empty; netlink answers only about that
empty stack. The T1.6 host-network-reconnaissance residual is closed structurally.

`mode = host` reinstates the T1.6 residual in full — the workload shares the host network
stack and can read its full state. The compiler auto-sets
`threats.reinstated = ["T1.6:host-recon"]` and requires an explicit `reason`. BPF is the
primary enforcement primitive; the net-ns boundary does not exist. The proxy remains
mandatory for audit continuity.

## 7.11.4 The loopback alias model

The kennel's assigned address space (a `/28` from `127.0.0.0/8` for IPv4 and a `/64` from
the project's ULA `/48` for IPv6, allocated at spawn by §7.5) already exists on both sides:
kenneld knows it, the workload's `$KENNEL_SOCKS_PROXY` points into it.

For `constrained` and `unconstrained` modes, the same address space is brought up on both
sides of the boundary using `lo`:

- **Inside the kennel net-ns:** `lo` is configured with the kennel's assigned addresses.
  The workload (and `kennel-netshim`) bind, connect, and listen against these normally.
- **Host net-ns:** the privhelper adds the same addresses as an alias on the host `lo`
  (`AddLoopbackAlias`). The host-side **mirror** for an allowed inbound bind appears here at
  the kennel's own IP, so an operator's `ss`/`lsof` maps it straight back to the kennel.
  `kennel-netproxy` *dials outbound* from the host stack; it does not listen for the
  workload (the shim does, inside the net-ns).

The mirror is deliberate: the same address reality on both sides makes a kennel's bound
socket observable and attributable from the host without extra tooling. No routing, no NAT,
no kernel interfaces beyond loopback aliases. The kernel enforces the boundary — a
`connect()` inside the kennel net-ns to its own loopback goes nowhere outside it. The one
controlled crossing point is binder, not a network path.

The privhelper gains two operations: `AddLoopbackAlias` at spawn and `RemoveLoopbackAlias`
at exit, both scoped to address add/remove on the existing `lo`. `mode = host` kennels use
no alias.

## 7.11.5 The crossing point: `org.projectkennel.INet`

With the kennel in its own net-ns and no veth, the workload has no network path to
`kennel-netproxy`. The crossing point is the kennel's binderfs instance (§7.1), via the
reserved service `org.projectkennel.INet/default` — a kenneld-owned node under the standard
reserved-namespace rules (only kenneld registers it; `getService` resolves locally).

The facade is split into a **control node** and per-connection **data conduits**:

- **`INet/default` (control).** `CONNECT(target)` (and the inbound `BIND`, §7.11.6) are
  transacted here. This is the singleton entry point the shim always knows.
- **`INet/<n>` (data conduit), kenneld-minted.** On an *approved* `CONNECT`, kenneld
  allocates a per-connection conduit, returns its handle `<n>` in the reply, and passes the
  kennel end of a **socketpair** as the reply fd. `<n>`'s lifetime *is* the connection's:
  binder death-notification on it tears the connection down with no reaper logic, and `<n>`
  is the connection's identity for any later control. The workload/shim can only ever hold a
  conduit kenneld minted *after* the policy decision — it cannot fabricate an `<n>` for an
  unapproved target, so the data plane can never outrun the policy plane.

**Outbound (`CONNECT`).** The shim sends `CONNECT(target)` to `INet/default`. kenneld, on its
looper, does only the O(1) checks — mode, the `[net.proxy]` allow-by-name match — and hands
the rest to a bounded worker (§7.11.8). The worker **resolves** the name (OS resolver),
**re-checks the resolved IP** against the invariant denylist (`[net.bpf]` CIDRs, e.g.
cloud-metadata `169.254.169.254`) — closing the DNS-rebinding window by **pinning** the IP it
vetted — then drives the host-side `kennel-netproxy` delegate to `connect()` that exact
pinned address. kenneld mints the socketpair, hands the host end and the pinned target to the
delegate, replies on the saved cookie with `<n>` + the kennel end. The delegate `splice`s the
upstream socket ↔ the host socketpair end; the shim `splice`s the workload ↔ the kennel
socketpair end. **The upstream host socket never leaves the host** — it is held only by the
delegate; the workload holds a socketpair end. kenneld touches no payload byte.

**The whitelist lives in kenneld.** Because kenneld sees `CONNECT(target)` and holds the
settled `[net.allow]`/`[net.deny]`, it makes the egress decision itself and resolves+pins the
address. `kennel-netproxy` therefore needs **no per-kennel config and no policy** — it
becomes the *dumb outer half*: `connect(pinned-ip)` + `splice`, nothing else (§7.11.10). It
listens **only** on the per-kennel `kenneld`↔delegate `AF_UNIX` socket, never a host TCP
port (one less host-side surface).

**Inbound (`BIND`).** A workload listener is bound **natively inside the kennel net-ns** —
real, reachable from inside by ordinary loopback — and gated at the cgroup `bind` hook by
`[[net.bpf.bind]]`: a denied bind fails at the syscall, an allowed bind succeeds and the hook
reports it. For every *allowed* bind, kenneld raises the host **mirror** (its delegate binds
the same `ip:port` on the host alias) so the port is observable and reachable from the host
at the kennel's own IP. A host connection to the mirror is accepted host-side by the delegate,
which relays it inward over a fresh `INet/<n>` socketpair — exactly as outbound, in reverse.
**No listener fd and no accepted-connection host fd ever crosses the boundary.** (The SOCKS5
`BIND` command maps to the shim performing a native bind plus this mirror.) The decision to
allow is policy's, never the workload's.

## 7.11.6 `kennel-netshim`: the SOCKS5 facade inside the kennel

The workload must not know the network architecture changed. `kennel-netshim` is a small
process the in-kennel init forks into the kennel's namespaces and view, a sibling of the
workload (so it inherits the net-ns and the constructed view directly). It listens on the
kennel's assigned loopback at `:1080` — where `$KENNEL_SOCKS_PROXY` has always pointed — and
speaks SOCKS5 inbound. It **terminates** the SOCKS5 handshake in-kennel; only the target and
the post-handshake byte stream cross the boundary, never the SOCKS5 framing.

For each SOCKS5 session:

- `CONNECT` → parse the target, send `CONNECT(target)` to `INet/default`. The reply is the
  approval result (mapped straight back to the SOCKS5 reply byte) plus, on success, `<n>` and
  the conduit socketpair end. `splice` the SOCKS5 client ↔ the socketpair end. **TCP
  half-close and teardown are kernel-implicit:** the workload's `shutdown(WR)` propagates as
  EOF across the socketpair to the delegate, which shuts down the upstream, and vice versa —
  so no `SHUTDOWN` control verb is needed.
- `BIND` → native-bind a listener inside the net-ns and request the host mirror; inbound
  connections arrive over per-connection `INet/<n>` socketpairs and are spliced back to the
  SOCKS5 session.

The shim does no policy, no DNS, no audit — those stay in kenneld and the delegate. It is a
protocol-translation layer: SOCKS5 in, `CONNECT` out, a socketpair back, `splice`. Because it
parses untrusted workload SOCKS5, it is a security-sensitive parser kept correspondingly
small, with a fuzz target (CODING-STANDARDS §10.6).

## 7.11.7 The data plane is a socketpair, not the host socket — and why

The fd-over-binder safety review (recorded with the binder design state) confirmed the
**mechanism** of passing fds through binder is sound: fds flow *out* from the trusted TCB to
the less-trusted in-kennel party and never in (request-direction fd injection into node 0 is
structurally `-EPERM` — node 0 is created with no fd-accept right), reply fds are forced
`O_CLOEXEC`, the reply is gated on the requester's `TF_ACCEPT_FDS` (fails closed), and the
24-byte object decoder is bounds-checked, `fd>=0`-filtered, and fuzzed. The kernel's
`security_binder_transfer_file` LSM hook is a **no-op** on this host (no binder LSM in the
active set) — so the structural gate, not the LSM, is what protects the inbound direction;
the design must not rely on the hook.

Given that, the open choice was *which* fd crosses. Two candidates:

- **(A) the host-dialed socket.** Fastest (the shim `splice`s straight to the upstream
  socket), but the shim then holds a host-net-ns socket that answers
  `getpeername`/`getsockname`/`SIOCGIF*` against the *host* stack — re-opening the very
  interface/route/peer-path recon the net-ns exists to close — and kenneld must validate a
  delegate-supplied fd's type/state before relaying it (the LSM won't).
- **(C) a kenneld-minted socketpair end** (this design). One extra in-kernel `splice` hop
  (workload ↔ socketpair ↔ upstream), negligible for our traffic, in exchange for: the shim
  holds an anonymous socketpair — **no host introspection, nothing to seccomp-deny**; the
  host socket never crosses, so there is **no delegate-fd to validate**; and it is *still
  fd-passing*, so it keeps every property that makes the mechanism safe (kenneld out of the
  data path, the minimal fuzzed fd wire, the `TF_ACCEPT_FDS` fail-closed opt-in). It is
  strictly safer on every axis except raw throughput.

(C) is the design. The socketpair is the *data* plane only; it does not address control-plane
blocking, which §7.11.8 handles separately.

## 7.11.8 The control plane is non-blocking by construction

`INet` shares the per-kennel binder looper with the registry and the lifecycle/TTL verbs, so
a `CONNECT` that blocks the looper on DNS or `connect()` stalls everything — including the
trusted lifecycle plane. The model:

- The **looper** runs only the O(1) decision (mode + `[net.proxy]` name match), records a
  pending entry keyed by the binder transaction **cookie** in a **bounded** per-kennel table,
  dispatches `{cookie, target}` to a bounded **delegate worker pool**, and returns
  immediately to `BINDER_WRITE_READ`.
- A **reply-reader** issues the reply (`<n>` + socketpair, or a failure) on the saved cookie
  when the worker finishes. Reply-reader threads register as binder loopers
  (`BINDER_SET_MAX_THREADS` with a bounded ceiling).
- When the pending table is full or the worker pool is saturated, the looper replies
  `BR_FAILED_REPLY` on that one transaction — **backpressure as refusal**, never a stall.

This is a design *constraint*; the as-built threading lives in `02-5-binder-net.md` (and the
foundational build that realises it is owed — the current single-serial-looper-with-inline-
`connect` does **not** meet this constraint and `INet` must not be built on it).

## 7.11.9 Resource bounds

The shim runs as the operator uid and forks a splice thread per connection; without bounds a
runaway (malicious or merely wedged) workload exhausts threads/fds against the operator's
shared session budget. Bounds are structural and uid-independent:

- **Per-kennel cgroup caps.** The kennel cgroup carries `pids.max` (bounds the splice-thread
  explosion) and `memory.max` (bounds per-connection buffers), written at bring-up with
  conservative defaults, overridable via a new `[resources]` policy section (alongside
  `[ulimits]`, which is per-process and does not bound the aggregate).
- **Per-kennel concurrent-connection cap** in kenneld (the bounded pending-cookie table of
  §7.11.8 is the same bound) and a connect-rate limit; over-cap `CONNECT`s get
  `BR_FAILED_REPLY`.
- **Daemon backstop.** `kenneld.service` carries `TasksMax`/`LimitNOFILE`; facade forks apply
  `RLIMIT_NOFILE`/`NPROC`.

## 7.11.10 `kennel-netproxy` after this change

`kennel-netproxy` becomes the *dumb outer half* of the proxy and loses most of its surface:

- **No config, no policy, no DNS.** kenneld decides, resolves, and pins; the delegate is told
  a pinned IP and connects to it. The per-kennel `proxy-<ctx>.toml` generation, the
  allow/deny logic, and the resolver move out.
- **No TCP listener.** It listens only on the per-kennel `kenneld`↔delegate `AF_UNIX` socket
  (0600, owner-only) — removing the host loopback TCP port that anything host-side could
  reach.
- **What remains:** `connect(pinned-ip)`, `splice(upstream ↔ socketpair)`, audit emission for
  the egress event, and the inbound mirror's `accept`+`splice`. It is kept a separate process
  from kenneld (blast-radius isolation: the code that touches a possibly-hostile upstream is
  not the policy daemon), but it is now stateless and trivial.

## 7.11.11 Per-mode behaviour

| Mode | Net-ns | `INet` node | Shim | Proxy delegate | BPF |
|---|---|---|---|---|---|
| `none` | `CLONE_NEWNET`, empty | absent | not launched | not launched | not loaded |
| `constrained` | `CLONE_NEWNET` + alias | present | launched | launched (dumb dialer) | optional |
| `unconstrained` | `CLONE_NEWNET` + alias | present | launched | launched (dumb dialer) | socket shaping + limits |
| `host` | host net-ns | present | launched | launched (dumb dialer) | **primary enforcement** |

## 7.11.12 Spawn sequence

`CLONE_NEWNET` is in the namespace set at spawn — the kennel's network namespace is empty
from creation; no host network state is ever visible inside it. For `constrained`/
`unconstrained`, the privhelper's `AddLoopbackAlias` runs immediately after namespace
creation, before any host-side `bind()` on the kennel's addresses. `kennel-netproxy` launches
after binderfs is up and attaches to its `kenneld`↔delegate socketpair (it is a delegate, not
a binder participant). The in-kennel init forks `kennel-netshim` inside the view last, once
`INet/default` is registered.

## 7.11.13 Network flow (outbound, `constrained`/`unconstrained`)

```
┌──────────────────────── KENNEL NET-NS ───────────────────────┐
│  process ──connect()──► 127.42.7.1:1080  (kennel-netshim, SOCKS5)
│                              │  terminates SOCKS5, parses target
│              binder CONNECT(target) → INet/default
└──────────────────────────────┼───────────────────────────────┘
                               │  net-ns boundary (binder, control only)
                               ▼
                kenneld looper:  mode + [net.proxy] name allow  (O(1), non-blocking)
                               │  → bounded worker, by cookie
                               ▼
                worker:  resolve (OS) → re-check resolved IP vs invariant denylist
                         → PIN the IP  (closes DNS-rebind)
                         → mint socketpair(a,b); audit net.egress
                               │
                 ┌─────────────┴───────────────┐
                 ▼                              ▼
        reply on cookie:                kennel-netproxy delegate (host net-ns):
        <n> + socketpair end b           connect(pinned-ip) → upstream u
                 │                        splice(a ↔ u)        ← dumb dialer, no policy
                 ▼
        kennel-netshim: splice(workload ↔ b)
        (host socket u never crosses; kenneld not in data path;
         half-close/teardown implicit via the socketpair)
```

`mode = host` is identical except there is no net-ns boundary and BPF is the primary
enforcement; the SOCKS5→`CONNECT`→delegate path is unchanged for audit continuity.

## 7.11.14 Resolved decisions

- **`INet`/`CONNECT_AFUNIX` are caller-identity-gated to the shim.** Only the in-kennel
  facade shim (not the workload directly) may pull a facade conduit — kenneld checks the
  kernel-stamped `sender_pid` against the known shim pid before serving the verb, in addition
  to the policy-name match. This shrinks the (already small, with (C)) blast radius to the
  shim and is the same gate the lifecycle verbs already use. (This also corrects an as-built
  over-claim: `CONNECT_AFUNIX` is *not* currently caller-gated — see the architecture
  reconciliation note.)
- **A `[resources]` policy section carries the per-kennel floor** (`pids.max`, `memory.max`,
  max concurrent connections, connect rate) with conservative non-opt-in defaults, overridable
  per template.
- **Brokered conduits are not revocable mid-life (accepted T1.10 residual).** A delivered
  conduit outlives the policy decision and survives `warn`/`renew` TTL actions; only `exit`
  (cgroup freeze + kill) closes it. A mid-life kill switch would force kenneld back into the
  data path, which §7.11.2 rejects. The freezer (§9.7) still suspends the whole kennel
  atomically, so a TTL `exit` does close every conduit; what is not offered is selective
  per-connection revocation while the kennel runs.

## 7.11.15 Residuals

**Loopback alias visibility.** The kennel's assigned addresses appear on the host `lo` for
the kennel's life, visible via `ip addr` — equivalent to the pre-netns situation where the
proxy listened on them. No new information.

**`AI_ADDRCONFIG` inside `mode = none`.** An empty net-ns means only `127.0.0.1`/`::1`;
`getaddrinfo` with `AI_ADDRCONFIG` suppresses IPv6 if no global IPv6 exists — correct for a
kennel with no network. `constrained`/`unconstrained` carry a ULA address on `lo`, sufficient
to satisfy `AI_ADDRCONFIG`.

**`mode = host` reinstates T1.6 in full.** Explicit, acknowledged: the operator declares
`mode = host` with a `reason`; the compiler enforces the acknowledgement and the diff tool
surfaces it.

**`SOCK_RAW`/`AF_PACKET` in unprivileged kennels.** These need `CAP_NET_RAW`, unavailable to a
user-namespace kennel; `allow = [..., "raw"|"packet"]` warns and has no effect (valid for a
root-context kennel where the capability exists). Root-context kennels are a distinct
deployment model; a dedicated threat-catalogue section is owed.

**Conduit outlives the policy decision (T1.10).** See §7.11.14 — accepted; closed only by a
TTL `exit` / kennel teardown, not selectively mid-life.

**No host-net-ns fd in the shim.** Recorded as a *closed* residual relative to the (A)
alternative: with the socketpair data plane (§7.11.7) the shim never holds a host socket, so
the `getpeername`/`getsockname`/`SIOCGIF*` host-introspection leak that (A) would carry does
not arise and needs no per-shim seccomp ioctl-deny.
