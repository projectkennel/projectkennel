# containerised-service

A long-lived containerised dev service (Postgres, Redis, a broker): reachable
from your workstation but **not the LAN**, data confined to one path, and no
container escape-hatch flags.

> **Design-level — not yet enforced.** Project Kennel has no container-runtime
> integration today, so the `[container]` section is the design contract, not a
> working path (`templates/README.md`, `architecture/08-as-built-notes.md` §8.2).
> The inherited `fs`/`net`/`cap` confinement is enforced; the container
> orchestration is not. This template is here to pin the intended shape and to
> complete the executive-summary set.

## What the user adds (intended)

```toml
template = "containerised-service@v1"
name = "dev-postgres"

[container.override]
image_digest = "sha256:..."   # pin the exact image
reason = "reproducible Postgres image"

[[fs.write.add]]
path = "~/data/dev-postgres/**"
reason = "Postgres data directory"
```

The password and other secrets come from the user's secret store at run time —
never in the policy file.

## Defends / residuals

- **Defends:** T21 (LAN exposure — published ports bind only to the kennel's
  loopback, never `0.0.0.0`), T22, T1 (partial — the container sees only its data
  volume). `--privileged` / `--pid=host` / `--network=host` are template
  invariants the leaf cannot remove.
- **Residuals:** T20 (container escape via a runtime/kernel CVE — beyond any
  userspace framework). T23 (the container's root is uid 0 on the host on the
  volume mount) — mitigated only if Docker runs with `userns-remap`; documented
  here, not enforceable from the policy.

## Adds over base-confined

The `[container]` orchestration (pinned image, loopback-only published ports, a
single data volume, the no-escape-flags invariants) and the data-dir write grant.
