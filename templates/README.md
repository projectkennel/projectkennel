# Project Kennel templates

Operators do not write policy from scratch. They derive from the **templates**
here: signed, versioned, threat-tagged baselines for recognisable workflows. A
user's leaf policy is a short delta from a template (typically 5–15 lines with a
`reason` on every addition). The template system is specified in
`docs/05-templates.md`; the fully-annotated reference is
`TEMPLATE-ai-coding-strict.md` at the repo root.

## The set (this directory)

| Template | For | Defends (THREATS.md) | Notable residuals |
|---|---|---|---|
| [`base-confined`](base-confined/) | The factored root of every confined template. Not used directly. | T19, baseline T1/T6/T12 | No fs/exec scope of its own |
| [`ai-coding-strict`](ai-coding-strict/) | An AI coding agent on a single project. | T1, T2, T3, T6, T12, T14, T25 | T8 (exfil via the LLM API); T13 |
| [`package-install`](package-install/) | Installing from a specific registry, time-bounded. | T2, T9 (partial) | TTL is the main T10 defence |
| [`untrusted-build`](untrusted-build/) | Building from untrusted source, network-off. | T2, T5 (strong) | Needs offline mirrors for real deps |
| [`inspect-only`](inspect-only/) | Read-only inspection of a directory; no build. | T2, T4, T5 (strong) | Cannot build/run/test |
| [`containerised-service`](containerised-service/) | A long-lived containerised service (Postgres, …). | T21, T22, T1 (partial) | T20 (container escape); T23 needs userns-remap |

Each template directory carries `policy.toml` (the template's policy), `meta.toml`
(identity + signing reference), and `README.md` (the threat-model summary).

## Implementation status — read this before assuming enforcement

> These templates are **source policies**: the design contract and the input the
> policy compiler will consume. They are intentionally ahead of the runtime. Two
> things are not yet built (`architecture/08-as-built-notes.md` §8.2):
>
> 1. **The compiler.** `kennel compile` — which resolves the template/include
>    chain, applies deltas, verifies signatures, and emits a signed *settled*
>    policy — is **not implemented**. The runtime today consumes a hand-produced,
>    signed `SettledPolicy` (the flat artefact in `kennel-policy::settled`; see the
>    kenneld e2e for a worked instance). So the inheritance, `[[*.add]]`/`[[*.remove]]`
>    deltas, `*.invariant` markings, `include`, signing, and `kennel.lock` described
>    here describe the *design*, not a working `kennel run <template>` path yet.
>
> 2. **Some resource classes.** The settled schema the runtime enforces covers
>    **`net`, `fs`, `exec`, `proc`, `cap`, `seccomp`, `lifecycle`**. The other
>    sections used below are source-policy design that the compiler will fold in;
>    today they are enforced as noted:

| Section | Enforced today? |
|---|---|
| `fs.read`/`write`/`deny`, `fs.home` (constructed `$HOME` view), `fs.tmp`, `fs.dev`, `fs.proc` | **Yes** — `pivot_root` view + Landlock + private `/tmp` + constructed `/dev` + `hidepid` (§7.2, §8.1). |
| `net.mode`, `net.allow` (by-CIDR → BPF+proxy; by-name → proxy), `net.deny.invariant` | **Yes** — cgroup BPF (deny-first, fail-closed) + per-kennel `kennel-netproxy` (dual-stack). |
| `exec.allow`, `exec.deny_setuid`/`setgid`/`setcap`/`deny_writable` | **Yes** — Landlock `EXECUTE` allowlist + the BPF/settled invariants + seccomp. |
| `proc`, `cap.no_new_privs`, `seccomp` | **Yes**. |
| `unix.abstract = "deny"`, signal isolation | **Yes, natively** — Landlock ABI-6 scoping (§8.1; supersedes the AppArmor/seccomp fallback in `docs/07-4`/`07-7`). |
| `fs.dev` `ioctl` on granted nodes | **Yes** — `IOCTL_DEV` (§8.1). |
| `lifecycle.ttl` | Schema-carried; the TTL *timer/reaping* enforcement is owed. |
| `unix.allow` path sockets (per-kennel ssh-agent), `[dbus]`, `[x11]`, `[env]` curation, `[ptrace]`, `fs.home.sanitise`, `fs.scrub` per-file overlay | **Not yet** — design-level; the spawn builds a synthetic `/etc` + essential binds rather than arbitrary-file sanitise, and hides non-granted *names* (ENOENT) rather than per-pattern scrubbing inside granted dirs. |
| `[net.dns]`, `tls.required`/`tls.pin_sha256` | **Dropped / not built.** DNS is resolved by the proxy via the OS resolver and the answers vetted by policy (no configurable resolver; §8.1). TLS inspection is an enterprise/future layer. These do **not** appear in the templates. |
| `[container]` (`containerised-service`) | **Not built** — no container-runtime integration; that template is design-level. |

## Conventions

- `policy.toml` references its parent as `template_base = "<name>@v<version>"` and
  carries `template_name`/`template_version` (§5.2/§5.10).
- Substitution variables (`<kennel>`, `<uid>`, `<user>`, `<home>`, `<tag>`,
  `<ctx>`, `<gid>`) are expanded at spawn time (§5.4); a leftover variable is a
  hard error.
- Every grant carries a `reason`; capability-granting rules carry
  `threats.exposed` (§5.6).
- `[[<section>.deny.invariant]]` marks a rule no downstream delta may remove (§5.5).

## Owed

Per-template `tests/allow.sh` + `tests/deny.sh` (and the `kennel test-template`
harness that runs them against a live kernel) are not written here — they need
the compiler and a privileged test runner. They are the next deliverable once
`kennel compile` lands.
