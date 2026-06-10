# §7.5 Policy surface: network

A kennel lives in its **own network namespace** (`CLONE_NEWNET`, unshared inside the kennel's user namespace) with its own piece of `127.0.0.0/8` *and* its own IPv6 ULA `/64`. Inbound and outbound, the kennel behaves as if it were on its own loopback interface — for both address families, symmetrically. The user reaches it from outside via either family; the kennel reaches the outside only across the binder gateway (§7.1) to its proxy; siblings cannot reach each other on either family, because each sits in a distinct network namespace. Cross-family ambiguities (dual-stack sockets, IPv4-mapped IPv6) are resolved by forcing `IPV6_V6ONLY=1` inside kennels, surfacing each family at the application layer where policy can reason about it.

The network namespace is the isolation axis; the proxy allowlist and the BPF socket-shaping are the enforcement axes. The four modes below combine them.

## 7.5.1 The four modes

A kennel's relationship to the network is one of:

| Mode | Net-ns | Outbound | Use case |
|---|---|---|---|
| `none` | `CLONE_NEWNET`, empty stack | No `connect()`, no `bind()` to inet families, no inet socket creation at all — zero network surface | Untrusted post-install scripts, untrusted-code inspection |
| `constrained` | `CLONE_NEWNET` + loopback alias | Specific allowlist of destinations, via the per-kennel proxy across the binder gateway | AI agents, package installs from known registries |
| `unconstrained` | `CLONE_NEWNET` + loopback alias | Public internet via the proxy; the invariant denylist only (cloud metadata + link-local); socket-level capability shaping retained | Build-from-source kennels that genuinely need open egress with audit retained |
| `host` | host net-ns (shared) | Public internet via the proxy, mandatory; BPF is the primary enforcement primitive | Packet capture, raw socket tooling, root-context kennels |

The default in defensible templates is `constrained`. `unconstrained` is documented as weaker and used only where the workflow truly requires open egress; it keeps the net-ns boundary and the audit stream but drops the allowlist down to the invariant denies. `none` is the strongest and appropriate for several common cases (npm post-install, repo inspection); it is the zero-cost case — the empty network namespace needs no loopback alias, no shim, no proxy.

`host` is the one mode that does **not** get its own network namespace: the kennel shares the host network stack directly. This reinstates the host-network-reconnaissance residual (T1.6) in full — the workload can read the host's interfaces, routes, listening sockets, and neighbour table — so it is an explicit, acknowledged tradeoff: the operator opts in with a `reason`, BPF becomes the primary enforcement primitive (the net-ns boundary does not exist), and the proxy stays mandatory for audit continuity.

## 7.5.2 The proxy-as-gateway model

Every outbound connection from a kennel terminates at a kennel-local proxy that Project Kennel controls. The kennel sits in its own network namespace with no route off the loopback alias, so it has no network path to the proxy at all: outbound crosses the **binder gateway** (§7.1). The workload speaks SOCKS5 to an in-kennel shim (`kennel-netshim`) on the kennel's loopback at `:1080`; the shim issues an `org.projectkennel.INet/default` `CONNECT` transaction to kenneld (node 0); kenneld makes the policy decision, resolves the name, pins the vetted address, and drives its host-side `kennel-netproxy` delegate to dial it. kenneld mints a socketpair for the connection and returns one end to the shim; the delegate splices the other end to the dialled socket. The shim splices the workload to its end.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       KENNEL NET-NS (constrained / unconstrained)         │
│                                                                          │
│  process ──connect()──► 127.42.7.1:1080                                  │
│                         (kennel-netshim, SOCKS5)                         │
│                              │                                           │
│              binder CONNECT → org.projectkennel.INet/default            │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │  net-ns boundary (binder, control only)
                               ▼
                    kenneld (host ns, node 0)
                    mode + [net.proxy] allow · resolve · re-vet IP · PIN
                    mint socketpair(a,b) · audit                          │
                ┌──────────────┴──────────────┐                          │
                ▼                              ▼                          │
        reply: conduit handle + end b   kennel-netproxy (host ns)        │
                │                        connect(pinned-ip) → upstream u  │
                ▼                        splice(a ↔ u)                    │
        kennel-netshim splices workload ↔ b  ──► internet
```

The fd that crosses into the kennel is the socketpair end `b` — a local conduit kenneld minted, not the dialled socket. The upstream socket `u` never leaves the host; kenneld touches no payload byte (it brokers the connection and steps out); half-close and teardown propagate through the socketpair and the conduit's binder death-notification.

There is no direct loopback `connect()` to the proxy and no cgroup-BPF "allow only the proxy address" rule: the network namespace boundary denies every other destination — a `connect()` inside the kennel net-ns to anything but the shim's loopback listener goes nowhere. The single controlled crossing point is binder, not a network path.

Why this is the right primitive:

- **Policy lives in user-space, in one place.** kenneld is the policy decision point for every `INet` transaction: it holds the settled policy, makes the allow/deny call on the name, resolves it, re-checks the resolved address against the denies, and pins it — so a poisoned or rebinding answer is caught before the dial. The kernel just enforces the namespace boundary; `kennel-netproxy` is a dumb dialer that connects to the pinned address and splices.
- **The kennel never holds an address, only a name** — DNS rebinding is structurally impossible because kenneld resolves and pins under policy on every request.
- **Audit is free.** kenneld logs every request with the requesting kennel, destination, byte counts, duration — it *is* the policy decision, so there is nothing to correlate.
- **Composes with loopback isolation** (§7.5.6). The kennel's `127.42.x.1` is where the shim listens. The kennel cannot reach the user's `127.0.0.1` services — they are in a different network namespace — except by naming them as host services kenneld dials on its behalf.

`org.projectkennel.INet/default` is a control node: `CONNECT` and `BIND` transact to it, and each approved connection gets a per-connection conduit kenneld mints, whose binder death-notification tears the connection down. The control plane is non-blocking — the node-0 looper makes the O(1) policy decision and hands resolution and the dial to a bounded worker, replying by transaction cookie, so a slow dial never stalls the kennel's lifecycle or registry traffic on the same node; over-capacity requests are refused, never queued. Each kennel's network surface is resource-bounded by the kennel cgroup (`pids.max`/`memory.max`) and a per-kennel concurrent-connection cap, configurable via `[resources]`.

What the kernel still enforces, via cgroup BPF inside the net-ns, is socket-level shaping rather than per-destination routing:

- `cgroup BPF inet_sock_create`: deny `AF_PACKET`, `AF_NETLINK`, raw socket families (the `[net.bpf]` family/type/protocol shaping).
- `cgroup BPF bind`: gate every `bind()` against `[[net.bpf.bind]]` and report each *allowed* bind to kenneld to drive the host-side mirror (§7.5.7).
- `cgroup BPF connect`: in `host` mode (no net-ns boundary), BPF is the primary egress gate; in `none`/`constrained`/`unconstrained` the empty/loopback-only stack already denies non-shim destinations, so BPF is optional defence-in-depth.

The proxy is where the interesting egress policy lives, and that policy is in user-space code Project Kennel controls.

## 7.5.3 The proxy implementation

A small, single-purpose daemon launched per kennel, running in the **host** network namespace as kenneld's dial delegate:

- Blocking, thread-per-connection Rust (`kennel-netproxy`). No async runtime — the same TCB bar as OpenSSH.
- Stateless: no config, no policy, no resolver. kenneld holds the policy and resolves+pins the address (§7.5.5); the delegate is told a pinned IP and connects to it.
- Listens only on the per-kennel `kenneld`↔delegate `AF_UNIX` socket (0600, owner-only) — no TCP listener, no host-reachable port. The SOCKS5 endpoint the workload sees is `kennel-netshim` inside the kennel net-ns.
- For each request from kenneld: `connect(pinned-ip)`, then `splice` the upstream socket against the conduit socketpair end kenneld supplied. For an inbound `BIND` (§7.5.7) it binds the host-side port, accepts, and splices each connection the same way.
- Emits the JSONL egress audit event.

The SOCKS5 wire format is preserved end-to-end so the workload sees no change — it terminates in `kennel-netshim` (§7.5.6), which carries only the target and the byte stream across the boundary. SOCKS5 specifically because:

- Transport-agnostic (TCP, optionally UDP via SOCKS5 UDP ASSOCIATE).
- Authenticates if needed (per-kennel proxy credentials enable further sub-kennel discrimination).
- Universally supported. `curl`, `wget`, `git`, `pip`, `npm`, `cargo`, `ssh` (via `ProxyCommand`), every browser.
- `socks5h://` (with the `h`) means "let the proxy resolve the name" — the kennel never resolves DNS itself; the name rides the `CONNECT` transaction and kenneld resolves it.

Per-destination policy beyond allow/deny (rate limits, byte caps, time windows) and structured audit live in kenneld, the decision point.

## 7.5.4 Policy primitives

`[net]` carries the mode and splits into two enforcement sections: `[net.proxy]` (the user-space egress policy kenneld enforces) and `[net.bpf]` (the kernel-level socket shaping and the bind gate).

```toml
[net]
mode = "constrained"        # "none" | "constrained" | "unconstrained" | "host"
reason = ""                 # required (non-empty) only when mode = "host";
                            #   the compiler auto-sets threats.reinstated = ["T1.6:host-recon"]

# ── [net.proxy]: the user-space egress policy (the CONNECT delegate enforces it) ──
[net.proxy]
# The proxy delegate dials from the host stack and the shim listens inside the
# net-ns at the kennel's loopback :1080 (the address $KENNEL_SOCKS_PROXY points at,
# computed from the kennel's tag and ctx — §7.5.2). There is no proxy_listen_*
# address: the workload-facing listener is the shim's, not the proxy's.

# Name resolution is not configured in policy: the proxy uses the OS resolver and
# vets the answers (the name must clear net.proxy.allow; the resolved address is
# re-checked against net.proxy.deny + special-use refusal). The answer-vetting is the
# security property — there is no hand-rolled DNS and no resolver dependency.

# Outbound allow rules. A settled rule carries only name/ports/protocol.
[[net.proxy.allow]]
name = "api.openai.com"
ports = [443]
protocol = "tcp"

[[net.proxy.allow]]
name = "github.com"
ports = [22, 443]
protocol = "tcp"

[[net.proxy.allow]]
cidr = "10.0.0.0/24"        # raw CIDR (rare; internal network exceptions)
ports = [443]

# Invariant denies. Mandatory and non-removable (a leaf cannot delete them),
# evaluated before allow and enforced even in `unconstrained` and `host` modes.
# Deliberately NARROW: cloud metadata (the SSRF crown jewel) and link-local only.
[[net.proxy.deny.invariant]]
cidr = "169.254.169.254/32"     # IPv4 cloud metadata
[[net.proxy.deny.invariant]]
cidr = "fd00:ec2::254/128"      # AWS IMDSv6
[[net.proxy.deny.invariant]]
cidr = "fe80::/10"              # IPv6 link-local

# Optional policy denies. A policy MAY subtract address space it knows it never
# needs; these are NOT mandatory. RFC1918 / CGNAT / ULA are intentionally NOT
# invariant denies — making private space permanently unreachable is self-defeating
# (a kennel routinely needs a local dev server, a LAN database, an internal
# registry). In `constrained` mode nothing private is reachable anyway unless a
# `[[net.proxy.allow]]` names it; in `unconstrained`/`host` mode the operator has
# opted into arbitrary egress. Either way it is the policy author's call, not an
# immovable floor.
[[net.proxy.deny]]
cidr = "10.0.0.0/8"             # example: this policy chooses to deny RFC1918
[[net.proxy.deny]]
cidr = "172.16.0.0/12"
[[net.proxy.deny]]
cidr = "192.168.0.0/16"

# ── [net.bpf]: the kernel-level socket shaping and the bind gate ──
[net.bpf]
# Socket-family / type / protocol shaping (defence in depth; the primary egress
# gate in mode = host). Denying a family at inet_sock_create returns EPERM.
families = ["AF_INET", "AF_INET6", "AF_UNIX"]
deny_families = ["AF_NETLINK", "AF_PACKET", "AF_BLUETOOTH", "AF_VSOCK"]

# The bind gate. Each [[net.bpf.bind]] is an allow rule evaluated at the cgroup
# bind hook; a bind not matched is denied at the syscall. Every ALLOWED bind is
# reported to kenneld to drive the host-side mirror (§7.5.7).
[[net.bpf.bind]]
families = ["v4", "v6"]
ports = []                       # empty = any ephemeral
min_port = 1024

# Loopback handling — see §7.5.6
[net.loopback]
private_subnet_v4 = "127.42.7.0/24"
private_subnet_v6 = "fd24:8a7c:91e3:4207::/64"

[[net.loopback.host_services]]
name = "host-postgres"
addr_v4 = "127.0.0.1:5432"
addr_v6 = "[::1]:5432"
proxy.required = true        # named host services are dialled by the proxy delegate on
                             #   the kennel's behalf — the host loopback lives in a
                             #   different network namespace, so there is no direct path

# Bind handling — see §7.5.7. The bind allow/deny gate lives in [[net.bpf.bind]] above;
# these are the address-rewrite knobs the bind hook applies inside the kennel net-ns.
[net.bind]
private_addr_v4 = "127.42.7.1"       # the kennel's primary loopback address (net-ns side)
private_addr_v6 = "fd24:8a7c:91e3:4207::1"
inaddr_any_policy = "rewrite"        # 0.0.0.0 -> private_addr_v4
in6addr_any_policy = "rewrite"       # :: -> private_addr_v6

# Rate limits and audit
[net.rate_limit]
bytes_per_second = "10MB"
bursts_allowed = 5

[net.audit]
log_path = "~/.local/state/kennel/<kennel>/network.jsonl"
level = "summary"           # "off" | "summary" | "full"
```

## 7.5.5 DNS handling

DNS is where naive proxy designs leak. The full story:

**The kennel cannot do its own DNS.** The kennel's empty (or loopback-only) network namespace has no route to any resolver: UDP/53 and TCP/53 to external resolvers go nowhere, and `127.0.0.53` (systemd-resolved) is in the host network namespace, unreachable from inside the kennel. There is nothing for the kennel to resolve against.

The kennel does not run DNS at all. Clients use `socks5h://` which defers resolution and doesn't require local DNS; the shim carries the name across the binder gateway in the `CONNECT` transaction, and kenneld resolves it via the OS resolver and vets the answer. The kennel's `/etc/resolv.conf` can be set to an invalid IP so that failing-to-go-through-the-proxy is immediately obvious.

**Name resolution happens in kenneld.** On a request to `github.com`, kenneld resolves the name via the OS resolver (in the host network namespace), vets and pins the result, and hands `kennel-netproxy` the pinned address to dial. There is no hand-rolled resolver and no configurable upstream: kenneld delegates resolution to the OS and makes its security decision on the *answer*.

**Answer-vetting is the security property.** The name must clear the allowlist (`net.proxy.allow`), and every address the OS resolver returns is re-checked against the policy's deny rules and the invariant refusals (cloud metadata, link-local) before kenneld pins it and the delegate dials. A poisoned or rebinding answer that resolves an allowlisted name to a denied address is refused — the kennel never holds an address, only a name, and kenneld resolves and pins under policy on every request, so the address the delegate dials is exactly the one kenneld vetted. (A policy that also denies RFC1918 — its choice, not a mandatory floor — gets the same rebinding protection for those ranges.)

**The allowlist is by name, not IP.** The user writes `github.com`; kenneld enforces against whatever the name resolves to, then vets each resolved address against the denies. This is the right level of abstraction — IPs change, names are stable — and the answer-vetting means a malicious resolver answer cannot smuggle the kennel onto a denied address.

**No DNS leakage.** kenneld is the only thing that resolves on the kennel's behalf, in the host namespace; the kennel has no resolver path of its own. tcpdump on the host's external interface during kennel operation shows zero DNS queries originating from the kennel — part of the test plan.

## 7.5.6 Loopback isolation

Project Kennel assigns each kennel a small IPv4 subnet in `127.0.0.0/8` and an IPv6 ULA `/64`. Linux routes the entire `127/8` to `lo`; IPv6 ULA requires explicit interface configuration. The allocation is **per user** (the `/etc/kennel/subkennel` file, the analogue of `/etc/subuid`): each user gets a 12-bit `tag` (IPv4) and a 40-bit random ULA global ID (IPv6); `ctx` is the per-kennel context.

**IPv4 allocation** — the 24 bits below `127/8` are bit-packed (a kennel needs a handful of addresses, not a /24), giving 4096 users × 256 v4-enabled kennels each:

```
127 | tag(12 bits) | ctx(8 bits) | host(4 bits)
127.<user's /20>                 ← the user's space (12-bit tag)
<the kennel's /28>               ← per-kennel (16 addresses)
host 1 within the /28            ← kennel's primary address; the shim listens here
                                   (net-ns side) and the host alias mirrors it
```

Because the fields straddle octet boundaries, the addresses are not octet-readable (e.g. tag 9 / ctx 5 / host 1 → `127.0.144.81`); they are computed, not written by hand.

**IPv6 allocation:**

Project Kennel picks a ULA `/48` per user at allocation time per RFC 4193 §3.2.2 (random 40-bit global ID). `ctx` is 16-bit in IPv6 (its low 8 bits coincide with the v4 `ctx`, so a dual-stack kennel shares one context number; v6-only kennels may use the full 16-bit range). No `tag` is needed in IPv6 — the random per-user `gid` already isolates users:

```
fd | gid(40 bits) | ctx(16 bits) | host(64 bits)
fd<gid>::/48                     ← the user's space
fd<gid>:<ctx high:ctx low>::/64  ← per-kennel
…::1                             ← kennel's primary IPv6 address
```

**The loopback mirror.** The kennel's assigned addresses exist on *both* sides of the network namespace boundary:

- **Inside the kennel net-ns:** `lo` carries the kennel's assigned addresses. The workload binds, connects, and listens against them normally; the shim listens at `…1:1080` for SOCKS5.
- **Host net-ns:** the same addresses are added as an alias on the host `lo` (`ip addr add <kennel-cidr> dev lo`). The `INet` `BIND` verb (§7.5.7) binds an exposed listener here at the kennel's own IP, so a port the workload exposes appears host-side at that **same** address — an operator's `ss`/`lsof` maps it straight back to the kennel. The workload-facing SOCKS5 listener is the shim's, inside the net-ns; the host-side delegate dials outbound (`CONNECT`) and listens for host inbound (`BIND`).

The mirror is deliberate: the same address reality on both sides is what makes a kennel's bound socket observable and attributable from the host without extra tooling. There is no routing, no NAT, no kernel interfaces beyond the loopback aliases. The kernel enforces the namespace boundary — a `connect()` inside the kennel net-ns to its own loopback address goes nowhere outside it — and the one controlled crossing point is binder (§7.1), not a network path.

**Configuration requires privilege.** Adding addresses to the host `lo` alias requires `CAP_NET_ADMIN`. The privhelper gains two operations — `AddLoopbackAlias` at spawn and `RemoveLoopbackAlias` at kennel exit — both scoped to address addition and removal on the existing `lo` interface, accepting requests only from Project Kennel's UID and operating only on Project Kennel's reserved address space. This is the only new privileged step the `constrained`/`unconstrained` modes add. `mode = none` needs no alias (its net-ns is empty); `mode = host` needs none (it has no net-ns and shares the host stack).

Inside the net-ns there is no `CAP_NET_ADMIN` requirement for IPv6: bringing up the kennel's own `lo` addresses is unprivileged within the kennel's user+network namespace. (The privileged step is the host-side alias only.)

**Isolation properties.** With a kennel bound to `127.42.7.1` and `fd...:4207::1`:

- Other kennels on the same host cannot reach it. Each kennel is in a distinct network namespace; one kennel's loopback is structurally invisible to another.
- The user's normal shell (default context) can reach it via the host `lo` alias — the mirror exposes the kennel's listeners at the kennel's own IP on the host. This is correct: the user is in control.
- Other users on the system can see the alias addresses on host `lo` but cannot reach the kennel's listeners except through a host-side mirror the `BIND` verb raises, which binds only the kennel's own addresses.
- Same-uid processes outside the kennel reach the kennel only through the host-side mirror, not by sharing its stack — the kennel's native listeners live in its own namespace. The honest residual is at the mirror: a host-side listener at the kennel's IP is reachable by anything that can route to host `lo`.

**Network-state visibility — closed by the net-ns (T1.6).** The kennel's own network namespace means `/proc/net/*` and `AF_NETLINK` answer only about the kennel's own stack: in `none` mode an empty stack, in `constrained`/`unconstrained` mode only the kennel's loopback aliases. The host's interfaces, routes, listening-socket table, and neighbour (ARP) table are not visible from inside — the host-network-reconnaissance surface that was T1.6 is structurally closed for these three modes. `mode = host` is the deliberate exception: it shares the host network stack and therefore reinstates T1.6 in full (the compiler records `threats.reinstated = ["T1.6:host-recon"]` and requires the `reason`).

## 7.5.7 Bind semantics

A kennel legitimately needs to `bind()`: AI agent runs `npm run dev` spinning up a webpack dev server, build tool starts a local service for testing, language server opens a socket for the editor.

The bind happens **natively inside the kennel net-ns** — which is what makes the listener reachable from within the kennel by ordinary loopback. Policy sits in between: every `bind()` is decided by `[[net.bpf.bind]]` at the cgroup `bind` hook (a non-matching bind fails at the syscall).

Exposing that listener to the host is the **`BIND` verb** on `org.projectkennel.INet/default`. Where `CONNECT` is pulled by the kennel — the shim transacts to node 0 and gets the conduit fd in the reply — `BIND` is pushed by the daemon, so the direction reverses on every leg:

- **The host-side listener is a delegate.** A per-kennel host-side leg (kenneld's `BIND` delegate, a control-socket delegate alongside the `CONNECT` dialer) binds the policy-allowed `ip:port` on the host `lo` alias at the kennel's own IP, listens, and accepts. The bind decision is kenneld's, gated by `[[net.bpf.bind]]`; the workload never decides what is exposed.
- **The kennel-side facade exposes a callback.** `kennel-netshim`'s `BIND` transaction registers a callback node (with the kennel-side `ip:port` to forward to) that kenneld holds a reference to. This is the reverse of `CONNECT`: kenneld pushes inbound connections *to* the netshim rather than the netshim pulling outbound *from* kenneld.
- **Per inbound connection, kenneld brokers a socketpair.** On an accepted connection the host-side delegate signals kenneld over the control socket; kenneld mints a socketpair, hands one end back to the delegate (control socket, `SCM_RIGHTS`) to splice against the accepted connection, and pushes the other end through binder to the netshim's callback node. The netshim connects to the kennel-side service (the workload's native listener at the same `ip:port`) and splices.

Bytes flow `external → accepted connection → socketpair → netshim → kennel-side service`; kenneld mints both ends, so it relays no delegate-supplied fd and stays out of the data path, and the only fd crossing into the kennel is a benign socketpair end — the same conduit shape as `CONNECT`, only minted on the daemon's initiative. No host listener fd and no accepted-connection fd ever crosses the boundary. The operator sees the port at the kennel's own IP on host `lo`, mapping straight back to the kennel. An allowed native bind reported by the cgroup hook (or a SOCKS5 `BIND` request) is what prompts the shim to register the callback.

What we don't want:

- Context binds to `0.0.0.0:8080` and its dev server is reachable from the LAN.
- Context binds to `127.0.0.1:5432` and conflicts with the user's real Postgres, or worse, makes itself silently substitutable.
- Context binds to a port and same-uid processes outside the kennel reach it inadvertently.
- Context binds to a privileged port.
- Context binds to a non-loopback address it shouldn't have access to (VPN interface, Tailscale, Docker bridge).

The net-ns already removes most of these: there is no LAN interface, no VPN interface, no host `127.0.0.1` Postgres inside the kennel's namespace to collide with — only the kennel's own loopback aliases exist. The bind gate and the rewrites below shape what remains and decide what gets mirrored host-side.

**INADDR_ANY rewriting.** Webpack, Vite, Flask, Django dev server, Jupyter, `http.server`, half the JavaScript ecosystem default to binding `0.0.0.0`. Denying this breaks every dev server. Project Kennel rewrites instead, via cgroup BPF on `bind4`:

```c
SEC("cgroup/bind4")
int bind_rewrite(struct bpf_sock_addr *ctx) {
    if (ctx->user_ip4 == 0) {  // INADDR_ANY
        ctx->user_ip4 = bpf_htonl(PRIVATE_ADDR_V4);
    }
    // additional allowed-range/denied-address checks
    return 1;
}
```

The userspace process believes it bound to `0.0.0.0`; the kernel actually bound to the kennel's private address. `getsockname()` reflects the rewritten address, which most tools handle correctly (they print "Listening on 127.42.7.1:3000" rather than "0.0.0.0:3000").

**IPv6 dual-stack.** A socket created `AF_INET6` and bound to `::` with `IPV6_V6ONLY` unset accepts both IPv4 and IPv6 connections. If we rewrite only the IPv6 side, the IPv4 fallback escapes our isolation. Project Kennel forces `IPV6_V6ONLY=1` for kennels: cgroup BPF intercepts `setsockopt(IPV6_V6ONLY, 0)` and either denies or rewrites to 1. The kennel's IPv6 socket only handles IPv6; if the kennel wants IPv4 it must explicitly create an `AF_INET` socket. This surfaces dual-stack ambiguity at the application layer.

**IPv4-mapped IPv6 (`::ffff:0.0.0.0`).** Treat as the IPv4 case: rewrite to `::ffff:<private_addr_v4>` and apply IPv4 policy.

**Port allocation.** Two kennels can both bind `:3000` without conflict — each binds inside its own network namespace, and the host-side mirrors land on distinct addresses (`127.42.7.1:3000` and `127.42.11.1:3000`) on the host `lo` alias. Tools that hardcode `localhost:3000` for status checks within the kennel work, because the kennel's `/etc/hosts` shadows `localhost` → `127.42.<ctx>.1`.

**The in-kennel facade.** The workload never sees any of the binder mechanics. `kennel-netshim` runs as a sibling of the workload inside the kennel net-ns and view, listens on the kennel's loopback at `:1080` (the address `$KENNEL_SOCKS_PROXY` points at), and speaks SOCKS5. A `CONNECT` request becomes an `org.projectkennel.INet/default` `CONNECT` transaction; the conduit fd comes back in the reply and the shim splices it against the SOCKS5 session. For inbound, the shim registers a `BIND` callback once; kenneld pushes each arriving connection's conduit fd to it, and the shim splices that against a connection it opens to the kennel-side service. The shim does no policy, no DNS, no audit — those are kenneld's; it is purely the SOCKS5↔binder translation layer, and as a parser of untrusted workload input it carries a fuzz target.

## 7.5.8 Threats addressed

Against the threats in `THREATS.md`:

- **T1.1 (credential reconnaissance):** kennel cannot exfiltrate code to `attacker.example.com` because the proxy refuses. Cannot reach the user's other dev services — they are in a different network namespace. Cannot bypass via raw socket. Audit log records every destination attempted.
- **T1.2 (malicious post-install script):** with `net.mode = "none"`, the script gets an empty network namespace and can't reach anything. With `constrained` to the registry only, can't exfiltrate stolen data.
- **T1.9 (supply chain in legitimately-allowed dependency):** the audit log surfaces unexpected destinations the dependency tries to reach.
- **T1.7 (DNS exfiltration):** structurally impossible — the kennel has no route to any resolver and cannot make raw DNS queries.
- **T1.6 (host-network reconnaissance):** closed by the per-kennel network namespace for `none`/`constrained`/`unconstrained` — `/proc/net` and netlink answer only about the kennel's own stack. `mode = host` is the explicit, `reason`-gated exception that reinstates it. Lateral movement to host local services is likewise structural: the host's dockerd socket, Postgres, etc. are not in the kennel's namespace and are reachable only if the policy names them as host services the proxy delegate dials on the kennel's behalf.

## 7.5.9 Residuals

- **TLS exfiltration via allowed destinations (T1.8).** A kennel that may reach `api.openai.com` can exfiltrate by putting data in API requests; the proxy cannot see inside TLS. This is an accepted residual of a destination-allowlist model — the mitigation is a tighter allowlist, not payload inspection.
- **Covert channels.** Timing, name-resolution patterns for allowed hosts, TLS SNI to allowed hosts can carry exfiltration bandwidth. Out of scope for a non-paranoid threat model.
- **Pre-existing trust.** If the user pasted `OPENAI_API_KEY` into the kennel's env, the kennel can use it. Limiting which env vars cross the boundary (§7.9) is the mitigation, not the proxy.
- **`mode = host` reinstates T1.6 in full.** A `host`-mode kennel shares the host network stack and reads its complete state via `/proc/net` and netlink. This is the explicit, `reason`-gated tradeoff for packet-capture and raw-socket tooling; the compiler records the reinstatement and the diff tool surfaces it.
- **Brokered conduit outlives the policy decision (T1.10).** A conduit kenneld minted for an approved connection stays open for the connection's life; it survives `warn`/`renew` TTL actions, and only `exit` (the cgroup freeze + kill, §9.7) closes it. There is no selective per-connection revocation while the kennel runs — a kill switch would put kenneld in the data path, which the gateway design excludes.
- **Loopback alias visibility.** The kennel's assigned addresses appear on the host `lo` for the kennel's lifetime, visible to other host processes via `ip addr`. This is the deliberate mirror — equivalent to the pre-netns situation where the proxy listened on those addresses — and exposes no new information.
- **`SOCK_RAW` / `AF_PACKET` in unprivileged kennels.** These require `CAP_NET_RAW`, which a kennel running as the user's uid in a user namespace cannot obtain. Declaring `families = [..., "raw"/"packet"]` in such a context is not a policy error — the compiler warns and the rule has no effect — but the same policy is valid for a root-context kennel where the capability exists. Root-context kennels are a distinct deployment model with a materially different threat profile.

## 7.5.10 Failure modes

| Situation | Behaviour |
|---|---|
| Proxy daemon crashes | All outbound traffic blocked (the net-ns has no other egress path; the `INet` `CONNECT` delegate is gone). kenneld detects, optionally restarts. |
| Proxy denies a connection | The refusal propagates through kenneld and the shim to a SOCKS5 reply (0x02) the client reads. Audit logs the deny. |
| `CLONE_NEWNET` unavailable | Refuse to start a `none`/`constrained`/`unconstrained` kennel (the isolation axis is missing). No silent degradation; `host` mode does not require it. |
| `AddLoopbackAlias` (privhelper) unavailable | The host-side mirror cannot be raised; refuse to start or warn per policy. The in-kennel stack and egress still work; only host observability/ingress is lost. |
| Context tries raw socket | `inet_sock_create` BPF (`[net.bpf]`) denies, returns EPERM. |
| Client doesn't honour `*_PROXY` env | Direct `connect()` reaches no destination — the net-ns has only the shim's loopback listener. Audit logs the absent egress. |
| OS resolver fails for an allowlisted name | Connection refused; the proxy never falls back to a direct dial. |

## 7.5.11 Test plan additions

For each invariant, a regression test in `tests/net/`:

1. Context with `mode=none` gets an empty net-ns; any `connect()` reaches nothing and `/proc/net` is empty.
2. Context with constrained mode and `api.openai.com` allowlisted connects there via the shim→`INet`→proxy path; expect success.
3. Context attempts direct `connect()` to `1.1.1.1:443`; expect no route off the net-ns loopback (the binder crossing is the only egress).
4. Context attempts UDP/53 to external resolver; expect no route (no resolver reachable from the net-ns).
5. Context binds `127.0.0.1:3000` (host loopback) inside the net-ns; expect it binds the kennel's own loopback, not the host's.
6. Context binds `0.0.0.0:3000` with `inaddr_any_policy=rewrite`; expect success, `getsockname` returns `127.42.<ctx>.1:3000`, and the allowed bind is mirrored host-side.
7. Two kennels both bind `:3000`; expect both succeed, each in its own net-ns, mirrored to distinct host-`lo` addresses.
8. From default context, connect to the kennel's `127.42.<ctx>.1:3000` host-side mirror; expect success.
9. From sibling kennel, connect to first kennel's address; expect no route (distinct network namespaces).
10. Context attempts `setsockopt(IPV6_V6ONLY, 0)`; expect denied or rewritten to 1.
11. Context binds `[::1]:3000` inside the net-ns; expect it binds the kennel's own loopback, not the host's.
12. Kennel connects to `[fc00::1]:80` (other ULA outside framework's prefix); expect no route / proxy refusal.
13. Kennel connects to `[fe80::1]:80` (link-local); expect proxy refusal (invariant deny).
14. tcpdump on host external interface during kennel operation; expect zero DNS queries originating from the kennel.
15. Context attempts `AF_NETLINK` socket creation; expect EACCES (`[net.bpf]` family deny).
16. Context exceeds `bytes_per_second` rate limit; expect proxy throttles.
17. Context attempts to bind privileged port (`80`); expect the `[[net.bpf.bind]]` gate denies (min_port).
18. DNS rebinding test: an allowlisted name resolves to a denied address (the cloud-metadata invariant, or an RFC1918 range the policy chose to deny); expect the proxy refuses at dial time (answer-vetting).
19. `mode=host` kennel reads host interfaces/routes via `/proc/net` and netlink; expect success and `threats.reinstated` recorded (the explicit T1.6 tradeoff).

The full network test corpus is approximately 50 cases. The list above is the core invariants.
