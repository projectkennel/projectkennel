# Project Kennel templates

Operators do not write policy from scratch. They derive from the **templates**
here: signed, versioned, threat-tagged baselines for recognisable workflows. A
user's leaf policy is a short delta from a template (typically 5–15 lines with a
`reason` on every addition). The template system is specified in
`docs/design/05-templates.md`; the fully-annotated reference is
`TEMPLATE-ai-coding-strict.md` at the repo root.

## The set (this directory)

| Template | For | Defends (THREATS.md) | Notable residuals |
|---|---|---|---|
| [`base-confined`](base-confined/) | The factored root of every confined template. Not used directly. | T3.1, baseline T1.1/T1.6/T2.1 | No fs/exec scope of its own |
| [`ai-coding-strict`](ai-coding-strict/) | An AI coding agent on a single project. | T1.1, T1.2, T1.3, T1.6, T2.1, T2.3, T3.7 | T1.8 (exfil via the LLM API); T2.2 |
| [`package-install`](package-install/) | Installing from a specific registry, time-bounded. | T1.2, T1.9 (partial) | TTL is the main T1.10 defence |
| [`untrusted-build`](untrusted-build/) | Building from untrusted source, network-off. | T1.2, T1.5 (strong) | Needs offline mirrors for real deps |
| [`inspect-only`](inspect-only/) | Read-only inspection of a directory; no build. | T1.2, T1.4, T1.5 (strong) | Cannot build/run/test |
| [`containerised-service`](containerised-service/) | A long-lived local service (Postgres, …) confined directly by the kennel. | T3.3, T1.1 (partial) | Secrets via a run-time store; kernel/Landlock CVEs |

Each template directory carries `policy.toml` (the template's policy), `meta.toml`
(identity + signing reference), and `README.md` (the threat-model summary).

## Enforcement status

> Templates are **source policies**: `kennel compile` resolves the template/include
> chain, applies the `[[*.add]]`/`[[*.remove]]` deltas and `*.invariant` markings,
> verifies signatures, and emits a signed *settled* policy plus `kennel.lock`, which
> the runtime enforces. The settled schema covers **`net`, `fs`, `exec`, `proc`,
> `cap`, `seccomp`, `lifecycle`**; the remaining policy sections are source-policy
> concerns the compiler folds in. What each section enforces today:

| Section | Enforced today? |
|---|---|
| `fs.read`/`write`/`deny`, `fs.home` (constructed `$HOME` view), `fs.tmp`, `fs.dev`, `fs.proc` | **Yes** — `pivot_root` view + Landlock + private `/tmp` + constructed `/dev` + `hidepid` (§7.2). |
| `net.mode`, `net.allow` (by-CIDR → BPF+proxy; by-name → proxy), `net.deny.invariant` | **Yes** — cgroup BPF (deny-first, fail-closed) + per-kennel `kennel-netproxy` (dual-stack). |
| `exec.allow`, `exec.deny_setuid`/`setgid`/`setcap`/`deny_writable` | **Yes** — Landlock `EXECUTE` allowlist + the BPF/settled invariants + seccomp. |
| `proc`, `cap.no_new_privs`, `seccomp` | **Yes**. |
| `unix.abstract = "deny"`, signal isolation | **Yes, natively** — Landlock ABI-6 scoping (supersedes the AppArmor/seccomp fallback; design §7.4/§7.7). |
| `fs.dev` `ioctl` on granted nodes | **Yes** — `IOCTL_DEV`. |
| `lifecycle.ttl` | Schema-carried; the TTL *timer/reaping* enforcement is owed. |
| `unix.allow` path sockets (per-kennel ssh-agent), `[dbus]`, `[x11]`, `[env]` curation, `[ptrace]`, `fs.home.sanitise`, `fs.scrub` per-file overlay | **Not yet** — design-level; the spawn builds a synthetic `/etc` + essential binds rather than arbitrary-file sanitise, and hides non-granted *names* (ENOENT) rather than per-pattern scrubbing inside granted dirs. |
| `[net.dns]`, `tls.required`/`tls.pin_sha256` | **Dropped / not built.** DNS is resolved by the proxy via the OS resolver and the answers vetted by policy (no configurable resolver). TLS inspection is an enterprise/future layer. These do **not** appear in the templates. |
| `[container]` | **Not built** — design-level language only (parse + compile-warn), in the same family as `[dbus]`/`[x11]`/`[ptrace]`. No shipped template uses it: `containerised-service` runs the service directly under the kennel (the kennel *is* the container). |

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
harness that runs them against a live kernel) are not written here — they need a
privileged test runner. They are the next deliverable for the template set.
