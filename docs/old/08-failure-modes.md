# §8 Failure modes and degraded operation

A confinement framework's failure modes are themselves part of the threat model. The wrong response to "Landlock unavailable" is not "run the context unconfined and hope". This chapter catalogues the ways the framework can fail and the response in each case.

## 8.1 Failure taxonomy

Failures fall into categories:

- **Missing kernel feature.** The kernel doesn't support what the policy requires.
- **Policy error.** The policy is invalid, conflicts with invariants, or references unknown templates.
- **Resource error.** Daemons fail to launch, addresses fail to bind, sockets fail to create.
- **Runtime error.** Mid-context, something the framework set up stops working.
- **Adversary enumeration.** The confined process probes for weaknesses.

Each category has a defined response.

## 8.2 Missing kernel features

The framework checks kernel feature availability at policy-load time, against the requirements derived from the policy. If a required feature is missing, the framework refuses to start the context.

| Missing feature | Policy implication | Behaviour |
|---|---|---|
| Landlock filesystem | Any `fs.*` rule | Refuse to start; report kernel ≥5.13 needed |
| Landlock FS_EXECUTE | Any `exec.*` rule | Refuse to start; report kernel ≥6.10 needed for full semantics |
| cgroup BPF (connect hooks) | Any `net.allow` or `net.deny` | Refuse to start; report kernel ≥4.10 needed |
| cgroup BPF (bind hook) | Any `net.bind.inaddr_any_policy = "rewrite"` | Refuse to start; report kernel ≥5.7 needed |
| Mount namespace | Any shim-using rule (essentially all confined policies) | Refuse to start; report kernel unsupported (essentially impossible on modern Linux) |
| AppArmor | `unix.abstract = "deny"` policy | Warn; fall back to seccomp-TRAP for abstract-socket denial; functionality reduced |
| `legacy_tiocsti` sysctl | `tty.require_tiocsti_disabled = true` and kernel ≥6.2 | If sysctl is enabled, refuse to start; report how to disable |

The principle is "refuse to start rather than silently weaken the confinement". A policy that claims to defend against T13 (lateral movement to local services) and runs without cgroup BPF is not defending against T13; the user must be told.

For users on older kernels who genuinely cannot upgrade: the framework supports a `--unsafe-degrade` flag that turns refusals into warnings. The flag is loud, logged, and visible in audit. Templates can also declare which features they tolerate degradation on; `inspect-only` may permit running without cgroup BPF (it has `net.mode = "none"` anyway), while `ai-coding-strict` may not.

## 8.3 Policy errors

Errors detected at policy load:

| Error | Behaviour |
|---|---|
| Syntactically invalid TOML | Refuse; report parse error with line number |
| Schema violation (unknown field, wrong type) | Refuse; report the field |
| Reference to unknown template | Refuse; report missing template and suggest similar names |
| Framework invariant violated | Refuse; report which invariant and why it exists |
| Template invariant violated by user delta | Refuse; report template, invariant, user delta location |
| `reason` missing on a delta | Refuse; require reasons on all deltas |
| Template version mismatch | Warn (not refuse); suggest `agent-run upgrade` |
| DNS resolution failure for a `net.allow` name | Refuse if `dns.required = true`; otherwise warn and disable that rule |

The pattern: anything that would result in a context running under a different policy than the user authored is an error.

## 8.4 Resource errors

Failures during context setup:

| Failure | Behaviour |
|---|---|
| Cannot allocate context's loopback IPv4 (conflict, full range) | Refuse; report conflict; suggest changing tag |
| Cannot allocate IPv6 ULA (no privileged helper) | Disable IPv6 for context, warn; continue with IPv4 |
| Cannot launch SOCKS5 proxy | Refuse; report why (port conflict, bin missing) |
| Cannot launch dbus-proxy | If dbus policy is non-empty: refuse; else: continue without |
| Cannot launch Xwayland/Xephyr | Refuse if X11 isolation needed; otherwise continue |
| Cannot create mount namespace | Refuse (essentially impossible on modern Linux) |
| Privileged helper unavailable | Refuse if helper is needed (IPv6, cgroup creation on non-delegated systems); otherwise continue |
| BPF program load fails (kernel reports error) | Refuse; report BPF error (this indicates a framework bug, file it) |

## 8.5 Runtime failures

Mid-context failures:

| Failure | Behaviour |
|---|---|
| SOCKS5 proxy crashes | All outbound traffic blocked (BPF rules still in place). Supervisor restarts proxy. Context's connections to the proxy fail with ECONNREFUSED during the gap. |
| dbus-proxy crashes | Bus calls fail. Supervisor restarts. Active D-Bus connections are dropped; clients reconnect. |
| Xwayland/Xephyr crashes | X11 apps inside die. Supervisor restarts the server; user's open applications are lost. |
| Per-context ssh-agent crashes | Ssh operations fail (no agent socket). Supervisor restarts; keys must be re-added unless agent persists state. |
| Audit log writer fails | Audit events queued in memory; if queue fills, framework chooses: drop new events (logged loudly) or block context (configurable per template). |
| Real D-Bus daemon restarts on host | dbus-proxy reconnects; context's bus connections briefly stall. |
| Real Wayland compositor restarts | Xwayland in context loses its connection; Xwayland exits; supervisor restarts. User's X apps in context are lost. |
| Kernel evicts BPF program (rare) | Framework should detect; behaviour TBD (possibly: refuse to continue context, kill its processes). |

The supervisor's restart policy is configurable. Defaults are conservative: restart on crash, with exponential backoff, give up after some number of failures.

## 8.6 Adversary enumeration

A confined adversary may probe for misconfigurations. Probes the framework should detect and respond to:

- **Ptrace attempts.** Any `ptrace(PTRACE_ATTACH)` from a confined context is logged as a forensic signal regardless of policy. AppArmor denies; the framework records.
- **Unusual syscalls.** `userfaultfd`, `bpf`, `kexec_load`, etc. Seccomp denies; the framework records.
- **Repeated denied connects.** A context making many `connect()` attempts to denied destinations is suspicious. The framework logs each; downstream monitoring can alert on patterns.
- **Abstract-namespace connection probes.** Each is logged.
- **Filesystem path enumeration.** A context that `stat()`s many denied paths in sequence (probing for what's accessible) is suspicious. Landlock denies; the framework records.
- **Capability probing.** A context that calls `capget()` is observing the dropped capability set. Allowed but noted.

The framework does not actively respond to probes (no automatic context termination, no escalation). Detection and logging is the framework's role; response is the user's decision. Templates may set thresholds in monitoring config that, when exceeded, trigger user-facing alerts via the audit log shipping mechanism (§7.10).

## 8.7 The user as failure mode

The user can:

- Disable the framework entirely.
- Run `agent-run --context none` for any command.
- Edit policies to weaken them.
- Override warnings.

The framework's response: make these visible but do not prevent them. The user is the trust root (§2.6); the framework's role is to make the right choice easier than the wrong one, not to make the wrong choice impossible.

Specifically:

- `agent-run --context none` is supported but produces a clear message ("running without confinement").
- Editing a policy to weaken it produces visible diffs.
- Overriding warnings requires explicit flags (`--unsafe-degrade`, `--ignore-version-mismatch`, `--unsigned-template`); the flags appear in audit logs and process arguments.

This means the framework cannot enforce a corporate policy on a user who can edit their own files. Corporate enforcement (mandatory baselines, server-side policy checks) is a layer above what the framework provides; the framework's tools (signed templates, validation in CI) support that layer.

## 8.8 What happens when the framework itself is broken

Bugs in the framework's own code. Some are worse than others:

- **The schema validator misses an invariant violation.** A policy that should be rejected loads. Context runs under a weaker policy than intended. Mitigation: extensive test corpus; user-visible audit log surfaces the actual policy in effect.
- **The BPF program is buggy.** Denials happen when they shouldn't, or allows happen when they shouldn't. Mitigation: BPF programs are small, well-tested, version-pinned to the framework version. Failures are detectable in the audit log (unexpected denies show up; unexpected allows are harder).
- **The SOCKS5 proxy has a parse bug.** A malformed request crashes the proxy. Mitigation: supervisor restarts; the context's traffic was denied during the gap (BPF still blocks direct connects).
- **The privileged helper has a vulnerability.** An attacker could potentially escalate to `CAP_NET_ADMIN`. Mitigation: the helper is small, narrowly scoped, fuzzed; it accepts requests only from the framework's UID via a 0600 socket; it operates only within reserved address space.

Like any security tool, the framework's correctness is itself part of its trust model. The framework's threat model (§2) acknowledged that compromise of the framework's own dependencies is out of scope (X7, X8). Compromise of the framework itself is not formally out of scope, but is mitigated by code-quality discipline rather than architectural defence.

The framework's own dogfooding requirement: the framework's CI runs every template's test suite on every kernel version supported. If a template stops enforcing its claimed defences, CI fails. This catches the largest class of "framework code regression" issues.

## 8.9 Communicating failures to the user

The framework's user-facing error messages should:

- Identify what failed (which check, which rule, which mechanism).
- Identify why (kernel feature missing, policy field invalid, daemon failed to start).
- Suggest a fix (upgrade kernel to X, change field Y, restart daemon Z).
- Point at a reference (URL or section in this document).
- Not blame the user.

Example:

```
$ agent-run my-ai-coding bash
ERROR: cannot start context my-ai-coding.

  The policy requires Landlock FS_EXECUTE (for exec.* rules), but your
  kernel (5.15) does not support it. Full exec policy enforcement requires
  kernel 6.10 or later.

  Options:
    1. Upgrade to kernel 6.10+ (recommended)
    2. Use a template without exec rules (e.g. ai-coding-no-exec, which
       relies on no_new_privs and AppArmor instead)
    3. Force-start with degraded enforcement: --unsafe-degrade
       (logged loudly; not recommended for AI agents)

  See §8.2 in the framework documentation for the full kernel feature matrix.
```

The error message is the framework's primary documentation surface for failure modes. It needs to be deliberate and tested.
