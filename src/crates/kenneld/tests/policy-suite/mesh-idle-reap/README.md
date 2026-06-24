# mesh-idle-reap — ondemand idle-reaping, end to end (§7.13.6, W6)

The full activate → idle → reap → pending → re-activate cycle on real kennels. A
self-driving case (`run.sh`): the mesh needs a **provider** and a **consumer** plus
enablement, so the hook owns the flow.

- **provider.toml** — an ondemand service that `[[provides]]` `test.mesh.idle`
  (af-unix) with a short `[lifecycle].ttl`. For an ondemand provider that TTL is its
  **idle grace**: kenneld re-arms it while a consumer kennel runs and reaps it when
  none does, riding the existing §9.7 TTL custodian — not a parallel reaper.
- **consumer.toml** — `[[consumes]]` `test.mesh.idle` at an `at` socket; its workload
  connects and exits 0 iff it reads `pong` back.
- **run.sh** — enables the provider ondemand, `daemon-reload`s, then: (1) runs the
  consumer to socket-activate the cold provider; (2) idles past the TTL and asserts
  the provider is `pending` **and not running** in `kennel list` — a reap, not a
  crash-restart (a restart would bounce back to ready+running); (3) runs the consumer
  again to prove the reaped provider re-activates from cold.

Proves: an idle reap is distinguishable from a crash — the supervisor returns the
provider to declared-but-pending and stops supervising, and the activation dedup
clears, so the next consume re-activates it. The verdict is the hook's exit code.
