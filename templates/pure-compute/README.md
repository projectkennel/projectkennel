# pure-compute (spawn target)

A single-leg **SPAWN target** (`docs/design/07-12-dynamic-spawn.md` §7.12): run untrusted
code that **reaches nothing**.

- **Leg:** execution only. `net.mode = "none"` (no egress), no `fs.write` grant, ephemeral root.
- **Mutable surface:** none — the most-fenced target. An agent spawns it exactly as signed, so
  the delegated-spawn residual (T3.9 R1) does not attach.
- **Spawn-eligibility (§7.12.8):** no `[spawn]` of its own (depth-1), a 10-minute self-reaping
  TTL, and explicit memory/pids/CPU ceilings.

The entrypoint (`/usr/libexec/kennel/mcp-compute`) is a constructed-view path the spawned image
provides; this template governs the policy, not the binary.
