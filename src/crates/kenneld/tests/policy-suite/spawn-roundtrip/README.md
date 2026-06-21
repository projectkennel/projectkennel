# spawn-roundtrip — dynamic spawn, end to end (§7.12)

The first policy-suite case that exercises a **real SPAWN**. It proves the whole dynamic-spawn
path with the kennel's exit code as the verdict.

## What it proves

A confined requester (this kennel) holds a `[spawn]` grant for the signed `echo-tool@v1` template
but **no network and no second capability of its own**. Its workload is `facade-spawn-probe` — the
in-kennel SPAWN client — which:

1. opens node 0 and transacts `verb::SPAWN` for `echo-tool@v1` (no fds out, `TF_ACCEPT_FDS` set);
2. receives the two channel ends `kenneld` mints (`Reply::DataAndFds`: the socketpair local end +
   the stderr pipe read end), decoded by `Connection::transact_with_fds`;
3. writes a probe to the socketpair and reads it back — the spawned sibling (`echo-tool` = `/bin/cat`)
   echoes its stdin to its stdout over that same end.

Exit 0 ⇒ the requester instantiated a real, scoped sibling kennel and the kernel-to-kernel channel
reached it. Along the way `kenneld` validated the grant, re-verified `echo-tool`'s content-pin
(the settled artefact's ed25519 signature), re-ran spawn-eligibility, atomically claimed a
`max_instances` slot, minted the channel, and constructed the sibling — no compiler, no JSON in the
daemon; fds flow out of node 0 only.

## Moving parts

- `policy.toml` — the requester: `[spawn]` allows `echo-tool@v1`, workload = the probe.
- `templates/echo-tool/` — the spawn target's **source**; `setup.sh` compiles + **signs** it to its
  settled form (`echo-tool.settled.toml`) with the suite key the daemon trusts, since a spawn target
  is the complete signed *settled* policy the daemon load-verifies and instantiates as-is.
- `facade-spawn-probe` — the requester workload (installed in libexec with the other in-kennel bins).

Run: `src/tools/policy-e2e.sh spawn-roundtrip` (needs the installed `kenneld.service`).
