# scratch-fs (spawn target)

A single-leg **SPAWN target** (`docs/design/07-12-dynamic-spawn.md` §7.12): **data shuffling
without reach** — move and transform data on the filesystem, with no path to the network.

- **Leg:** filesystem. `net.mode = "none"` (no egress), no persistence; the one leg is a writable
  scratch area.
- **Mutable surface:** `fs.write` under a **oneof** constraint — the agent selects its working
  directory from a fixed, signed set (zero free text; T3.9 R1 does not attach). The roadmap's
  free-form *predicate-bound* workspace path (a `relpath` constraint resolved `RESOLVE_IN_ROOT`
  under a workspace root) lands once the applicator wires the predicate `under` root; until then
  this closed set is the fully-enforced form.
- **Spawn-eligibility (§7.12.8):** depth-1, a 10-minute self-reaping TTL, memory/pids/CPU ceilings.

The entrypoint (`/usr/libexec/kennel/mcp-scratch`) is a constructed-view path the spawned image
provides.
