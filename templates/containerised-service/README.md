# containerised-service

A long-lived local dev service (Postgres, Redis, a broker, an internal API):
reachable from your workstation but **not the LAN**, with its data confined to a
single persistent path.

> **The kennel is the container.** There is no Docker/Podman in the trust path.
> The service runs directly under Project Kennel's user/mount/PID/IPC namespaces,
> the constructed view + Landlock, the cgroup-BPF egress filter, and the loopback
> bind-rewrite — the same isolation a container would give, enforced by the
> framework itself. Every section in this template is **enforced today**.

## What the user adds

```toml
template_base = "containerised-service@v1"
name = "dev-postgres"

[exec]
allow = ["/usr/lib/postgresql/17/bin/postgres"]   # the service binary you run

[[fs.write.add]]
path = "~/data/dev-postgres/**"
reason = "Postgres data directory"
```

The server binary is the one thing the template cannot know — execution is
deny-by-default, so you name it in the leaf and the compiler resolves its library
closure. The password and other secrets come from your secret store at run time,
never from the policy file.

## How the shape is enforced

- **Reachable from the workstation, not the LAN (T3.3).** base-confined rewrites a
  wildcard bind (`0.0.0.0` / `::`) to the kennel's own private loopback address
  (computed from `<tag>`/`<ctx>`), so the service answers within the kennel's
  address space and is invisible to the LAN. Binding the host's `0.0.0.0` is
  refused; privileged ports are refused.
- **Data confined to one path (T1.1).** The leaf grants a single writable `~/`
  directory, which binds the real host inode read-write beneath the constructed
  `$HOME` so the data persists across runs. Everything else in the view is
  ephemeral (`$HOME` tmpfs, private `/tmp`) or simply absent.
- **No outbound egress by default.** `net.mode = "constrained"` — the cgroup BPF
  denies direct connect (fail-closed). A service that must reach a registry or a
  dependency adds exactly that `[[net.allow]]` in its leaf.

## Defends / residuals

- **Defends:** T3.3 (LAN exposure — the loopback bind-rewrite), T1.1 (the service
  sees only its data path plus the read baseline).
- **Residuals:** secrets management is the operator's (use a run-time secret
  store, not the policy file); a kernel/Landlock CVE is beyond any userspace
  framework.

## Adds over base-confined

The data-dir write grant (persistent, per-kennel), the read baseline re-listed for
a dynamically-linked server, sensible `nofile`/`nproc` limits for a long-lived
service, and the long-lived lifecycle posture.
