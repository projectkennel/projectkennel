# mesh-roundtrip — cross-kennel provide/consume, end to end (§7.13.4)

The mesh's whole loop on real kennels. A self-driving case (`run.sh`): `kennel run`
constructs one kennel, but the mesh needs a **provider** and a **consumer** plus
enablement, so the hook owns the flow.

- **provider.toml** — an ondemand service that `[[provides]]` `test.mesh.echo`
  (af-unix) and serves a ping→pong echo at its endpoint.
- **consumer.toml** — `[[consumes]]` `test.mesh.echo` at an `at` socket; its workload
  connects and exits 0 iff it reads `pong` back.
- **run.sh** — compiles + signs the provider, enables it ondemand, `daemon-reload`s
  the catalogue, then runs the consumer. The consumer's exit is the verdict.

Proves: `at` materialisation → the af-unix facade → kenneld's CONNECT_AFUNIX dispatch
to the broker → catalogue resolve → ondemand socket-activation (W6) → reach the
provider's endpoint through `/proc/<pid>/root` → splice. The workload is
`facade-mesh-probe` (staged via `--with-test-bins`; never shipped in a release).
