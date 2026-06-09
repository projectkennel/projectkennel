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
own interfaces. §8.1 of `08-as-built-notes.md` defers this as a re-architecture of the
§7.5 egress/loopback model. This chapter is that re-architecture.

## 7.11.2 Design constraints

Three constraints are non-negotiable coming out of §7.5:

**The SOCKS5 contract is preserved.** The workload finds a SOCKS5 listener at
`$KENNEL_SOCKS_PROXY` and connects to it. This is the interface every tool — `curl`,
`git`, `pip`, `npm`, `cargo`, `ssh` via `ProxyCommand` — already speaks. The network
namespace boundary must not require any workload-visible change.

**`kennel-netproxy` is per-kennel and its policy model is unchanged.** Per-kennel
rulesets, per-kennel audit streams, `Proxy::reload` for live updates — none of this
changes. The transport layer between the workload and the proxy changes; the proxy
itself does not.

**No veth.** Creating a veth pair to give the kennel network connectivity requires
`CAP_NET_ADMIN` in the host network namespace, host-side routing or NAT configuration,
and a kernel network stack per kennel. This is the architecture every container runtime
uses and it is correct — but it belongs below the userspace confinement layer Kennel
operates at. The design avoids it.

## 7.11.3 Network modes

§7.5 defined three modes (`none`, `constrained`, `open`). This chapter introduces
a four-mode taxonomy that cleanly separates the isolation axis (net-ns or not) from
the enforcement axis (proxy allowlist, BPF, or both). The old `open` mode is retired
and replaced by `unconstrained` and `host`.

| Mode | Net-ns | Proxy | BPF role | Use case |
|---|---|---|---|---|
| `none` | `CLONE_NEWNET`, empty | absent | absent | Untrusted scripts, code inspection; zero network surface |
| `constrained` | `CLONE_NEWNET` + loopback alias | present, allowlist | optional defence-in-depth | AI agents, package installs from known registries |
| `unconstrained` | `CLONE_NEWNET` + loopback alias | present, invariant denylist only | socket-level capability shaping, DoS bounds | Build-from-source, open egress with audit retained |
| `host` | host net-ns | present, mandatory | **primary enforcement primitive** | Packet capture, raw socket tooling, root-context kennels |

`mode = none` is the zero-cost case. `CLONE_NEWNET` inside the user namespace is
unprivileged — no privhelper involvement, no loopback alias, no shim, no proxy. The
kennel gets a fully empty network stack. `/proc/net` is empty. netlink answers only
about that empty stack. The T1.6 host-network-reconnaissance residual is closed
structurally.

`mode = host` reinstates the T1.6 residual in full — the workload shares the host
network stack and can read its full state. The compiler auto-sets
`threats.reinstated = ["T1.6:host-recon"]` and requires an explicit `reason` field.
BPF is the primary enforcement primitive; the net-ns boundary does not exist. The proxy
remains mandatory for audit continuity.

## 7.11.4 The loopback alias model

The kennel's assigned address space (a `/28` from `127.0.0.0/8` for IPv4 and a `/64`
from the project's ULA `/48` for IPv6, allocated at spawn by §7.5) already exists on
both sides: kenneld knows it, `kennel-netproxy` listens on it, the workload's
`$KENNEL_SOCKS_PROXY` points into it.

For `constrained` and `unconstrained` modes, this same address space is brought up on
both sides of the network namespace boundary using the host's `lo` interface:

- **Inside the kennel net-ns:** `lo` is configured with the kennel's assigned addresses.
  The workload binds, connects, and listens against these addresses normally.
- **Host net-ns:** the privhelper adds the same addresses as an alias on the host `lo`
  (`ip addr add <kennel-cidr> dev lo`). The host-side BIND delegate binds inbound listeners
  here at the kennel's own IP, so a socket the workload binds inside the net-ns appears
  host-side at that **same** address — an operator's `ss`/`lsof` maps the listener straight
  back to the kennel. `kennel-netproxy` dials outbound from the host stack; it does not
  listen for the workload (the shim does, inside the net-ns).

The mirror is deliberate: the same address reality on both sides is what makes a kennel's
bound socket observable and attributable from the host without extra tooling. No routing.
No NAT. No kernel interfaces beyond loopback aliases. The kernel enforces the network
namespace boundary — a `connect()` inside the kennel net-ns to its own loopback address
goes nowhere outside it. The controlled crossing point is binder, not a network path.

The privhelper gains two new operations: `AddLoopbackAlias` at spawn and
`RemoveLoopbackAlias` at kennel exit, both scoped to address addition and removal on
the existing `lo` interface. This is the only new privileged step these modes add.

`mode = host` kennels use no loopback alias — they share the host network stack
directly and require no address-space mirroring.

## 7.11.5 The crossing point: `org.projectkennel.INet/default`

With the kennel in its own net-ns and no veth, the workload has no network path to
`kennel-netproxy`. The crossing point is the kennel's binderfs instance (§7.1), via
the reserved service `org.projectkennel.INet/default`.

`org.projectkennel.INet/default` is a kenneld-owned node subject to the standard
reserved-namespace rules: only kenneld may register it; `getService` always resolves
locally.

**Outbound** crosses via the node's `CONNECT` (1) transaction: the workload (via the shim —
§7.11.6) requests a connection to a named host and port; kenneld validates mode and policy
and relays to its host-side `kennel-netproxy` delegate, which applies the `[net.bpf]` CIDR
rules, resolves the name, vets against the `[net.proxy]` allowlist and denylist, dials, and
returns the connected fd. The shim splices between the workload and the fd.

**Inbound** does *not* go through the node to create a listener. A workload listener is
bound **natively inside the kennel net-ns**, which is what makes it reachable from inside the
kennel by ordinary loopback. Policy sits in between: the bind is decided by `[[net.bpf.bind]]`
at the cgroup `bind` hook — a denied bind fails at the syscall, an allowed bind succeeds and
the hook reports it to kenneld. For every *allowed* bind, kenneld raises the **mirror** — its
host-side delegate binds the same `ip:port` on the host alias — so the port is observable and
reachable from the host at the kennel's own IP, with host inbound relayed into the kennel
through the shim. The mirror is automatic for allowed binds; the decision to allow is
policy's, never the workload's. Implementation detail is in
[`02-5-binder-net.md`](../architecture/02-5-binder-net.md).

kenneld owns the `INet` node and is never in the data path. It relays each transaction to
the appropriate delegate, receives the fd in the reply, and forwards it to the shim via
`BINDER_TYPE_FD`. Once the shim has the fd, data flows directly between the workload and the
fd. The delegates are not binder participants — the fd-passing mechanics are in
[`02-5-binder-net.md`](../architecture/02-5-binder-net.md).

The full transaction wire protocol and fd-passing conventions are in
[`02-5-binder-net.md`](../architecture/02-5-binder-net.md).

## 7.11.6 `kennel-netshim`: the SOCKS5 facade inside the kennel

The workload must not know the network architecture changed. `kennel-netshim` is a
small process the in-kennel reaper forks into the kennel's namespaces and view, a sibling
of the workload (so it inherits the net-ns and the constructed view directly). It listens
on the kennel's assigned loopback address at :1080 — the same address `$KENNEL_SOCKS_PROXY`
has always pointed at — and speaks SOCKS5 inbound.

For each incoming SOCKS5 session:

- `CONNECT` request → issue `CONNECT` (1) binder transaction to
  `org.projectkennel.INet/default`, receive connected fd, splice bidirectionally
  between the SOCKS5 client and the fd.
- `BIND` request → issue `BIND` (2) binder transaction, receive listener fd, run
  accept loop with one thread per accepted connection, splice each back to the SOCKS5
  session.

The shim does no policy enforcement, no DNS resolution, no audit. These remain in
`kennel-netproxy` and kenneld as before. The shim is purely a protocol translation
layer: SOCKS5 wire format in, binder transactions out, fds back, splice. It is a new
crate (`kennel-netshim`) and, as an untrusted-input parser (SOCKS5 from the workload),
carries a fuzz target under `fuzz/` per CODING-STANDARDS §10.6.

## 7.11.7 Per-mode behaviour

| Mode | Net-ns | `INet` node | Shim | Proxy | BPF |
|---|---|---|---|---|---|
| `none` | `CLONE_NEWNET`, empty | absent | not launched | not launched | not loaded |
| `constrained` | `CLONE_NEWNET` + alias | present | launched | launched, `[net.proxy]` allowlist | optional |
| `unconstrained` | `CLONE_NEWNET` + alias | present | launched | launched, invariant denylist | socket shaping + limits |
| `host` | host net-ns | present | launched | launched, mandatory | **primary enforcement** |

## 7.11.8 Spawn sequence

The full implementation detail is in `02-5-binder-net.md` §Spawn sequencing; the
design-level summary:

`CLONE_NEWNET` is included in the namespace set at spawn — the kennel's network
namespace is empty from the moment of creation; no host network state is ever visible
inside it. For `constrained` and `unconstrained` modes, the privhelper's
`AddLoopbackAlias` call runs immediately after namespace creation, before any host-side
`bind()` on the kennel's addresses. `kennel-netproxy` launches after binderfs is up and
attaches to its `kenneld`↔delegate socketpair (it is a delegate, not a binder participant).
The in-kennel reaper forks `kennel-netshim` inside the view last, once `INet` is registered.

## 7.11.9 Network flow

```
┌──────────────────────────────────────────────────────────────┐
│                      KENNEL NET-NS                           │
│  (constrained / unconstrained)                               │
│                                                              │
│  process ──connect()──► 127.42.7.1:1080                      │
│                         (kennel-netshim, SOCKS5)             │
│                              │                               │
│              binder CONNECT(1) transaction                   │
└──────────────────────────────┼───────────────────────────────┘
                               │  net-ns boundary
                               ▼
                    kenneld (host, context manager)
                    mode + policy check
                               │
                               ▼
                  kennel-netproxy (host net-ns)
                  [net.bpf] CIDR check
                  DNS resolution
                  [net.proxy] denylist + allowlist vetting
                  audit: net.egress
                  dial TCP to destination
                  return connected fd via BINDER_TYPE_FD
                               │
                               ▼
                  kennel-netshim receives fd
                  splice: workload ↔ fd
                  (kenneld not in data path)

──────────────────────────────────────────────────────────────

  mode = host (no net-ns boundary):

  process ──connect()──► 127.42.7.1:1080
                         (kennel-netshim, SOCKS5)
                              │
              binder CONNECT(1) transaction
                              │
                    kenneld + kennel-netproxy
                    [net.bpf] enforcement (primary)
                    [net.proxy] invariant denylist + optional allowlist
                    audit: net.egress
```

## 7.11.10 Residuals

**Host-net-ns fd in the shim.** The fd the shim receives from a `CONNECT` or accepted
`BIND` connection is a socket in the host net-ns, held by a process in the kennel
net-ns. The shim only `read`/`write`/`shutdown`s on it — `connect()` and `bind()` on
an already-connected or already-bound socket are no-ops or errors. This is a design
invariant enforced by convention; documented here for reviewer verification.

**Loopback alias visibility.** The kennel's assigned addresses appear on the host `lo`
for the duration of the kennel's life, visible to other host processes via `ip addr`.
This is equivalent to the pre-netns situation where the proxy listened on those
addresses — no new information is exposed.

**`AI_ADDRCONFIG` inside `mode = none` kennels.** An empty net-ns means only
`127.0.0.1`/`::1` on `lo`. `getaddrinfo` with `AI_ADDRCONFIG` will suppress IPv6
results if no global IPv6 address exists. For `mode = none` this is correct — the
kennel has no network. For `constrained`/`unconstrained` kennels the ULA address on
`lo` is sufficient to satisfy `AI_ADDRCONFIG` for IPv6.

**`mode = host` reinstates T1.6 in full.** The workload shares the host network stack
and can read its complete state via `/proc/net` and netlink. This is an explicit,
acknowledged tradeoff — the operator accepts it by declaring `mode = host` with a
`reason`. The compiler enforces the acknowledgement; the diff tool surfaces it.

**`SOCK_RAW` / `AF_PACKET` in unprivileged kennels.** These require `CAP_NET_RAW`.
A kennel running as the user's uid in a user namespace cannot obtain this capability.
Declaring `allow = [..., "raw"]` or `allow = [..., "packet"]` in an unprivileged
context is not a policy error — the policy compiler warns and the rule has no effect.
The same policy file is then valid for a root-context kennel where the capability is
available. Root-context kennels are a distinct deployment model whose threat profile
differs materially from the standard user-level model; a dedicated threat catalogue
section is owed.