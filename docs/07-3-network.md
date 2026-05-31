# §7.3 Policy surface: network

A kennel has its own piece of `127.0.0.0/8` *and* its own IPv6 ULA `/64`. Inbound and outbound, the kennel behaves as if it were on its own loopback interface — for both address families, symmetrically. The user reaches it from outside via either family; the kennel reaches the outside only via its proxy; siblings cannot reach each other on either family. Cross-family ambiguities (dual-stack sockets, IPv4-mapped IPv6) are resolved by forcing `IPV6_V6ONLY=1` inside kennels, surfacing each family at the application layer where policy can reason about it.

## 7.3.1 The three modes

A kennel's relationship to the network is one of:

| Mode | Outbound | Use case |
|---|---|---|
| `none` | No `connect()`, no `bind()` to inet families, no inet socket creation at all | Untrusted post-install scripts, untrusted-code inspection |
| `constrained` | Specific allowlist of destinations, via per-kennel proxy | AI agents, package installs from known registries |
| `open` | Public internet via proxy; specific denylist (cloud metadata, RFC1918, host loopback) | Build-from-source kennels that genuinely need open egress |

The default in defensible templates is `constrained`. `open` is documented as weaker and used only where the workflow truly requires it. `none` is the strongest and appropriate for several common cases (npm post-install, repo inspection).

## 7.3.2 The proxy-as-gateway model

Every outbound connection from a kennel terminates at a kennel-local proxy that Project Kennel controls. Direct `connect()` to anything else is blocked at the kernel level via cgroup BPF.

```
┌────────────────────────────────────────────────────────────────────┐
│                       CONFINED CONTEXT                             │
│                                                                    │
│   process ──connect()──► 127.42.7.1:1080  ── SOCKS5 ─►  proxy ─────┼──► internet
│                          (kennel proxy)               (host ns)   │
│                                                                    │
│   cgroup BPF: deny all connect() except to 127.42.7.1:1080         │
└────────────────────────────────────────────────────────────────────┘
```

Why this is the right primitive:

- **Policy lives in user-space** where it can be expressive: per-destination TLS pinning, per-host rate limits, structured audit, name resolution control. The kernel just enforces "you may only talk to the proxy".
- **DNS is the proxy's problem.** The kennel cannot resolve names itself; the proxy resolves on its behalf or refuses unknown names. DNS rebinding is structurally impossible — the kennel never holds an address, only a name, and the proxy resolves under policy.
- **Audit is free.** The proxy logs every request with the requesting kennel, destination, byte counts, duration. No need to correlate kernel events with policy decisions; the proxy is the policy decision.
- **TLS inspection is optional but available.** If the proxy is MITM-capable (own CA installed in the kennel's trust store), certificate pinning and request logging become possible. Costs: complexity, breaks TLS-pinning apps, requires CA management. Optional layer, off by default.
- **Composes with loopback isolation** (§7.3.6). The kennel's `127.42.x.1` is where the proxy lives. The kennel cannot reach the user's `127.0.0.1` services except through the proxy.

The kernel-level rules become trivially expressible:

- `cgroup BPF inet4_connect`: allow `127.42.<ctx>.1:1080`, deny everything else.
- `cgroup BPF inet6_connect`: allow `[fd<gid>:<tag>:<ctx>::1]:1080`, deny everything else.
- `cgroup BPF inet_sock_create`: deny `AF_PACKET`, `AF_NETLINK`, raw socket families.
- `cgroup BPF bind`: allow loopback in the kennel's assigned range, deny elsewhere.

The proxy is where the interesting policy lives, and that policy is in user-space code Project Kennel controls.

## 7.3.3 The proxy implementation

A small, single-purpose daemon launched per kennel:

- Approximately 1000 lines of Go or Rust.
- Reads its policy from the same TOML file the rest of the kennel config lives in.
- Listens on the kennel's loopback address, port 1080 (or assigned).
- Speaks SOCKS5 (well-defined, every HTTP client and most others speak it via `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`).
- Optionally speaks HTTP CONNECT (some clients prefer it).
- Resolves DNS itself, against a configured resolver, with the policy's name allowlist applied.
- Logs JSONL audit events.
- Refuses gracefully on policy violation, with a useful error the requesting process can read.

SOCKS5 specifically because:

- Transport-agnostic (TCP, optionally UDP via SOCKS5 UDP ASSOCIATE).
- Authenticates if needed (per-kennel proxy credentials enable further sub-kennel discrimination).
- Universally supported. `curl`, `wget`, `git`, `pip`, `npm`, `cargo`, `ssh` (via `ProxyCommand`), every browser.
- Crucially: `socks5h://` (with the `h`) means "let the proxy resolve the name". The kennel never resolves DNS itself.

What SOCKS5 doesn't natively cover, the proxy adds: TLS inspection (optional), per-destination policy beyond allow/deny (rate limits, byte caps, time windows), structured audit.

## 7.3.4 Policy primitives

```toml
[net]
mode = "constrained"        # "none" | "constrained" | "open"

# Each proxy listener is enabled by a required boolean (default false) and
# configured by an optional address. The kennel's own subnet is computed from
# its tag and ctx (§7.3.2), so the address only carries the parts the kennel
# does not already own: a host offset within that subnet and a port.
proxy_listen_v4 = true              # enable the v4 SOCKS5 listener (default false)
proxy_listen_v4_address = "1:1080"  # optional "offset:port" within the kennel's /28
                                    #   offset 1..=14 (0 and 15 reserved), port 1025..=32767
                                    #   absent ⇒ "1:1080"
proxy_listen_v6 = true              # enable the v6 listener (default false)
proxy_listen_v6_address = "1:1080"  # optional "offset:port" within the kennel's /64

[net.dns]
resolver = "1.1.1.1:53"     # kennel's DNS resolver, used by the proxy
mode = "allowlist"          # "allowlist" | "passthrough" | "system"
                            # allowlist: only names in net.allow are resolvable
                            # passthrough: any name resolves, but connect still gated
                            # system: use system resolver
cache_ttl = "5m"            # how long resolved IPs are pinned
on_resolve_change = "deny"  # "deny" | "warn" | "allow" — see §7.3.5

# Outbound allow rules
[[net.allow]]
name = "api.openai.com"
ports = [443]
protocol = "tcp"
tls.required = true         # refuse plaintext
tls.pin_sha256 = ["abc123..."]   # optional cert pinning

[[net.allow]]
name = "github.com"
ports = [22, 443]
protocol = "tcp"

[[net.allow]]
cidr = "10.0.0.0/24"        # raw CIDR (rare; internal network exceptions)
ports = [443]

# Categorical denies. Evaluated before allow.
[[net.deny]]
cidr = "169.254.169.254/32"     # IPv4 cloud metadata
[[net.deny]]
cidr = "fd00:ec2::254/128"      # AWS IMDSv6
[[net.deny]]
cidr = "fe80::/10"              # IPv6 link-local
[[net.deny]]
cidr = "fc00::/7"               # other ULAs (kennel's own /64 is allowed by allow)
[[net.deny]]
cidr = "10.0.0.0/8"
[[net.deny]]
cidr = "172.16.0.0/12"
[[net.deny]]
cidr = "192.168.0.0/16"

# Loopback handling — see §7.3.6
[net.loopback]
private_subnet_v4 = "127.42.7.0/24"
private_subnet_v6 = "fd24:8a7c:91e3:4207::/64"

[[net.loopback.host_services]]
name = "host-postgres"
addr_v4 = "127.0.0.1:5432"
addr_v6 = "[::1]:5432"
proxy.required = false       # direct connect allowed (or set true to force-through-proxy)

# Bind handling — see §7.3.7
[net.bind]
private_addr_v4 = "127.42.7.1"
private_addr_v6 = "fd24:8a7c:91e3:4207::1"
inaddr_any_policy = "rewrite"        # 0.0.0.0 -> private_addr_v4
in6addr_any_policy = "rewrite"       # :: -> private_addr_v6
allow_host_loopback_v4 = false
allow_host_loopback_v6 = false
families = ["v4", "v6"]
allowed_ports = []                   # empty = any ephemeral
min_port = 1024

# Rate limits and audit
[net.rate_limit]
bytes_per_second = "10MB"
bursts_allowed = 5

[net.audit]
log_path = "~/.local/state/kennel/<kennel>/network.jsonl"
level = "summary"           # "off" | "summary" | "full"

# Socket family allowlist (defence in depth)
[net.families]
allow = ["AF_INET", "AF_INET6", "AF_UNIX"]
deny = ["AF_NETLINK", "AF_PACKET", "AF_BLUETOOTH", "AF_VSOCK"]
```

## 7.3.5 DNS handling

DNS is where naive proxy designs leak. The full story:

**The kennel cannot do its own DNS.** Cgroup BPF rules deny `connect()` to anything except the proxy. UDP/53 and TCP/53 to external resolvers are blocked. `/etc/resolv.conf` pointing at `127.0.0.53` (systemd-resolved) is broken inside the kennel unless that AF_UNIX socket is also denied.

Best practice: shadow `/etc/resolv.conf` in the kennel to point at the proxy's address, run a stub DNS resolver inside the proxy daemon that serves only the allowlisted names.

Alternative: don't run DNS in the kennel at all. Clients use `socks5h://` which doesn't require local DNS. Set the kennel's `/etc/resolv.conf` to an invalid IP so failing-to-go-through-the-proxy is immediately obvious.

**Name resolution happens in the proxy.** The proxy maintains a name → IP cache. On first request to `github.com`, the proxy resolves via its configured upstream resolver, caches the result, and dials the resulting IP. On subsequent requests, the cached IP is used until `cache_ttl` expires.

**Re-resolution policy is explicit.** When the TTL expires and the proxy re-resolves, what happens if the IP has changed?

- `on_resolve_change = "allow"`: accept the new IP, log a notice. Lowest friction. Vulnerable to TTL-driven DNS rebinding.
- `on_resolve_change = "warn"`: accept the new IP but log a warning. Default for most workflows.
- `on_resolve_change = "deny"`: refuse the new IP, require explicit policy reload. Highest friction, strongest. For high-value kennels.

**The allowlist is by name, not IP.** The user writes `github.com`; the proxy enforces against whatever IP resolves to. This is the right level of abstraction — IPs change, names are stable — but the resolver itself is a trust point. Pin the resolver: use a known DoH endpoint if the threat model demands it.

**No DNS leakage.** The proxy is the only thing in the kennel that does DNS. Verifying this is part of the test plan: tcpdump on the host's external interface during kennel operation should show zero DNS queries originating from the kennel.

## 7.3.6 Loopback isolation

Project Kennel assigns each kennel a small IPv4 subnet in `127.0.0.0/8` and an IPv6 ULA `/64`. Linux routes the entire `127/8` to `lo`; IPv6 ULA requires explicit interface configuration. The allocation is **per user** (the `/etc/kennel/subkennel` file, the analogue of `/etc/subuid`): each user gets a 12-bit `tag` (IPv4) and a 40-bit random ULA global ID (IPv6); `ctx` is the per-kennel context.

**IPv4 allocation** — the 24 bits below `127/8` are bit-packed (a kennel needs a handful of addresses, not a /24), giving 4096 users × 256 v4-enabled kennels each:

```
127 | tag(12 bits) | ctx(8 bits) | host(4 bits)
127.<user's /20>                 ← the user's space (12-bit tag)
<the kennel's /28>               ← per-kennel (16 addresses)
host 1 within the /28            ← kennel's primary address; proxy listens here
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

**Configuration requires privilege.** Adding addresses to `lo` (or a per-kennel dummy interface) requires `CAP_NET_ADMIN`. Project Kennel uses a privileged helper (setuid or with file capability `CAP_NET_ADMIN=ep`) invoked at kennel start. The helper is approximately 100 lines, accepts requests only from Project Kennel's UID, and operates only on Project Kennel's reserved address space.

For users unwilling to grant `CAP_NET_ADMIN` to any helper: IPv4 still works fully (`127/8` is pre-configured by the kernel). IPv6 falls back to "deny all IPv6 binds, force IPv6 traffic through the proxy". Document both modes; default to privileged setup if available, degrade gracefully otherwise.

**Isolation properties.** With a kennel bound to `127.42.7.1` and `fd...:4207::1`:

- Other kennels on the same host cannot reach it. Their cgroup BPF rules deny connect() to addresses outside their own private subnet and their proxy.
- The user's normal shell (default context) can reach it — the default context has no `connect()` restrictions. This is correct: the user is in control.
- Other users on the system cannot reach it. Loopback is per-namespace and address-routed locally.
- Same-uid processes outside the kennel can reach it. This is the limitation worth being honest about: IP-level isolation is between *kennels*, not between *processes within a uid*.

The cleaner story for same-uid isolation: cgroup-aware connect-side policy. A connection from outside the kennel to `127.42.7.1:3000` fires a cgroup BPF hook on the *connecting* side; Project Kennel's policy decides "the default context may always reach kennels' loopback" (typical), or "only the kennel that spawned this one may reach it" (stricter), or "no other kennel may reach it" (strictest, breaks browser-tab-to-dev-server workflows).

## 7.3.7 Bind semantics

A kennel legitimately needs to `bind()`: AI agent runs `npm run dev` spinning up a webpack dev server, build tool starts a local service for testing, language server opens a socket for the editor.

What we don't want:

- Context binds to `0.0.0.0:8080` and its dev server is reachable from the LAN.
- Context binds to `127.0.0.1:5432` and conflicts with the user's real Postgres, or worse, makes itself silently substitutable.
- Context binds to a port and same-uid processes outside the kennel reach it inadvertently.
- Context binds to a privileged port.
- Context binds to a non-loopback address it shouldn't have access to (VPN interface, Tailscale, Docker bridge).

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

**Port allocation.** Two kennels can both bind `:3000` without conflict — they're really binding `127.42.7.1:3000` and `127.42.11.1:3000`. Tools that hardcode `localhost:3000` for status checks within the kennel work, because the kennel's `/etc/hosts` shadows `localhost` → `127.42.<ctx>.1`.

## 7.3.8 Threats addressed

Against the threats in `THREATS.md`:

- **T1 (credential reconnaissance):** kennel cannot exfiltrate code to `attacker.example.com` because the proxy refuses. Cannot reach the user's other dev services on loopback. Cannot bypass via raw socket. Audit log records every destination attempted.
- **T2 (malicious post-install script):** with `net.mode = "none"`, the script can't reach anything. With `constrained` to the registry only, can't exfiltrate stolen data.
- **T9 (supply chain in legitimately-allowed dependency):** the audit log surfaces unexpected destinations the dependency tries to reach.
- **T7 (DNS exfiltration):** structurally impossible — kennel cannot make raw DNS queries.
- **T6 (lateral movement to local services):** if dockerd socket denied, no escape. Postgres on host loopback unreachable unless explicitly granted.

## 7.3.9 Residuals

- **TLS exfiltration via allowed destinations (T8).** Kennel can reach `api.openai.com`, so it can exfiltrate by putting data in API requests. Proxy can't see inside TLS without MITM. Optional TLS inspection layer mitigates if user accepts CA management; otherwise this is a known residual.
- **Covert channels.** Timing, DNS query patterns to allowed resolvers, TLS SNI to allowed hosts can carry exfiltration bandwidth. Out of scope for a non-paranoid threat model.
- **Pre-existing trust.** If the user pasted `OPENAI_API_KEY` into the kennel's env, the kennel can use it. Limiting which env vars cross the boundary (§7.7) is the mitigation, not the proxy.

## 7.3.10 Failure modes

| Situation | Behaviour |
|---|---|
| Proxy daemon crashes | All outbound traffic blocked (cgroup BPF is independent). Framework detects, optionally restarts. |
| Proxy denies a connection | Client gets SOCKS5 reply 0x02. Audit logs the deny. |
| Cgroup BPF unavailable | Refuse to start kennel if `net.mode != "open"`. No silent degradation. |
| Privileged helper unavailable | IPv6 disabled, IPv4 still works. Warn at startup. |
| Context tries raw socket | `inet_sock_create` BPF denies, returns EPERM. |
| Client doesn't honour `*_PROXY` env | Direct `connect()` fails at kernel level. Audit logs the BPF-level deny. |
| Proxy resolver upstream fails | Per `on_resolve_change`: deny (don't fall back to direct), warn, or cache extension. |

## 7.3.11 Test plan additions

For each invariant, a regression test in `tests/net/`:

1. Context with `mode=none` attempts any `connect()`; expect EPERM.
2. Context with constrained mode and `api.openai.com` allowlisted connects there; expect success via proxy.
3. Context attempts direct `connect()` to `1.1.1.1:443`; expect EPERM at cgroup BPF level.
4. Context attempts UDP/53 to external resolver; expect EPERM.
5. Context binds `127.0.0.1:3000` with `allow_host_loopback_v4=false`; expect EACCES.
6. Context binds `0.0.0.0:3000` with `inaddr_any_policy=rewrite`; expect success, `getsockname` returns `127.42.<ctx>.1:3000`.
7. Two kennels both bind `:3000`; expect both succeed on their respective private_addr.
8. From default context, connect to kennel's `127.42.<ctx>.1:3000`; expect success.
9. From sibling kennel, connect to first kennel's address; expect ECONNREFUSED or EACCES.
10. Context attempts `setsockopt(IPV6_V6ONLY, 0)`; expect denied or rewritten to 1.
11. Context binds `[::1]:3000` with `allow_host_loopback_v6=false`; expect EACCES.
12. Kennel connects to `[fc00::1]:80` (other ULA outside framework's prefix); expect EACCES.
13. Kennel connects to `[fe80::1]:80` (link-local); expect EACCES.
14. tcpdump on host external interface during kennel operation; expect zero DNS queries originating from the kennel's cgroup.
15. Context attempts `AF_NETLINK` socket creation; expect EACCES.
16. Context exceeds `bytes_per_second` rate limit; expect proxy throttles.
17. Context attempts to bind privileged port (`80`); expect EACCES (min_port).
18. DNS rebinding test: resolver returns a different IP on second query with `on_resolve_change=deny`; expect connection refused.

The full network test corpus is approximately 50 cases. The list above is the core invariants.
