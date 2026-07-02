# Policy test suite

Each subdirectory here is **one self-checking policy**: a source `policy.toml` whose
`[workload]` is a `/bin/sh -c` chain that inspects the constructed kennel **from the
inside** and exits `0` iff the slice of behaviour it proves holds. The workload's exit
code *is* the verdict — there is no Rust assertion harness. The daemon builds each
kennel from the signed policy exactly as it does in production (`docs/archive/design/07-2`,
`docs/archive/architecture/08-enforcement-architecture.md` §8.2).

This is the self-hosting principle (`e2e-must-be-self-hosting`): drive the real
`kennel run` against a live `kenneld`, not a hand-built `Spec`/`BinderPrep` replica that
can drift from the real wiring.

## Running

```sh
src/tools/policy-e2e.sh              # every case
src/tools/policy-e2e.sh net-none     # one (or several) by name
```

The runner does the one-time host setup the unprivileged spawn path needs (factory caps
on the privhelper, an `/etc/kennel/subkennel` allocation at tag 42, a root-owned
`kennel-bin-init`, an `/etc/kennel/system.toml` pointing the daemon at the build-tree
helpers, an AppArmor `userns` grant, a delegated cgroup), stages the fixtures a policy
cannot carry, then runs every case as the ordinary operator. A skip is never a pass: a
missing prerequisite aborts with the precise cause.

## Cases

| case | mode | proves |
|---|---|---|
| `masked-identity` | none | `$HOME`/`$USER`/passwd/group are the synthetic `kennel` persona; supplementary groups dropped |
| `fs-view`         | none | granted `~` subdir readable; non-granted sibling ENOENT; home tmpfs writable; `/etc/shadow` absent |
| `exec-deny`       | none | execution is deny-by-default — an allowlisted binary runs, a non-listed one is refused at execve |
| `net-none`        | none | total isolation: own empty netns, connect to loopback **and** a public address both fail |
| `net-constrained` | constrained | own netns loopback is up + bindable; the in-ns SOCKS endpoint listens at `<addr>:1080` |
| `net-isolated`    | constrained | the kennel is in its OWN netns: it reaches its own in-ns loopback but CANNOT reach a host `127.0.0.1` listener (proves two distinct namespaces, not a filtered one). Setup binds a host-side listener. |
| `ssh-egress`      | constrained | the full SSH re-origination cascade: workload `ssh` → facade-ssh → binder → netproxy → bastion → akc-vended forced command → `ssh` to a destination sshd, marker round-trips. No agent. |
| `full-vertical`   | constrained | the whole constructed view in one workload: fs + masked id + net-ns + AF_UNIX facade + dev passthrough |

The kennel's own loopback address is never hardcoded in the net cases — the workload
reads it from the synthetic `/etc/hosts` (`<v4>\tlocalhost <name>`), so a case is
independent of which ctx the daemon allocates.

## Fixtures the runner provides

A policy cannot carry a live host resource, so the runner stages:

- `~/kennel-e2e/granted/file` (content `OK`) and a non-granted `~/kennel-e2e/secret/file`;
- a host `AF_UNIX` echo listener at `/run/kennel-e2e/echo.sock` (`ping` → `pong`) that the
  `full-vertical` case's facade brokers into the kennel;
- a root-owned `kennel-akc` (the SSH bastion's `AuthorizedKeysCommand` must be root-owned).

## Per-case setup hooks

A case that needs host fixtures it cannot carry ships an executable `setup.sh` (and an
optional `teardown.sh`). The runner runs `setup.sh <case-dir> <scratch-dir>`; the hook
stages its fixtures and prints, on its **last stdout line**, the policy path to actually
run (usually a generated copy with host-specific values filled in). `ssh-egress` uses this
to stand up a destination sshd, mint the operator's real key + a host-key pin, and rewrite
its `policy.toml` (`__DEST_PORT__`, `__REAL_KEY__`, …) before the run.

## Adding a case

Create `<name>/policy.toml` deriving `base-confined`, set the `[net].mode` and the
grants the slice needs, and put the proof in `[workload].argv`. Keep it to one concern.
Validate it compiles with `kennel policy validate <name>/policy.toml --template-dir templates`,
then it is picked up automatically by the runner.
