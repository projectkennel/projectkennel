# net-fetch (spawn target)

A single-leg **SPAWN target** (`docs/archive/design/07-12-dynamic-spawn.md` §7.12): **reach without
code** — fetch from the network and stream the bytes back over the spawn channel.

- **Leg:** network. `net.mode = "constrained"` (frozen — the proxy is the egress gate); no
  `fs.write` grant; the fixed entrypoint runs no agent-supplied code.
- **Mutable surface:** `net.proxy.allow` under a **pattern** constraint. The agent supplies
  concrete destinations not enumerated at sign time, admitted only if they match a signed shape
  (subdomain `*.suffix:port`, exact `host:port`). This governs the egress **proxy** filter only —
  `[net.bpf]` is a separate mechanism, never touched. Residual: T3.9 R1, bounded by the shapes.
- **Spawn-eligibility (§7.12.8):** depth-1, a 10-minute self-reaping TTL, memory/pids/CPU ceilings.

The default shapes cover the common public package/source hosts; tighten or widen in a derived
template. The entrypoint (`/usr/libexec/kennel/mcp-fetch`) is a constructed-view path the spawned
image provides.
