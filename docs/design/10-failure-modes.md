# §10 Failure modes and degraded operation

A confinement framework's failure modes are themselves part of the threat model. The wrong response to "Landlock unavailable" is not "run the kennel unconfined and hope". This chapter catalogues the ways Project Kennel can fail and the response in each case.

## 10.1 Failure taxonomy

Failures fall into categories:

- **Missing kernel feature.** The kernel doesn't support what the policy requires.
- **Policy error.** The policy is invalid, conflicts with invariants, or references unknown templates.
- **Resource error.** Daemons fail to launch, addresses fail to bind, sockets fail to create.
- **Runtime error.** Mid-kennel, something Project Kennel set up stops working.
- **Adversary enumeration.** The confined process probes for weaknesses.

Each category has a defined response.

## 10.2 Missing kernel features

Project Kennel checks kernel feature availability at policy-load time, against the requirements derived from the policy. If a required feature is missing, Project Kennel refuses to start the kennel.

| Missing feature | Policy implication | Behaviour |
|---|---|---|
| Landlock filesystem | Any `fs.*` rule | Refuse to start; report kernel ≥5.13 needed |
| Landlock FS_EXECUTE | Any `exec.*` rule | Refuse to start; report kernel ≥6.10 needed for full semantics |
| cgroup BPF (connect hooks) | Any `net.allow` or `net.deny` | Refuse to start; report kernel ≥4.10 needed |
| cgroup BPF (bind hook) | Any `net.bind.inaddr_any_policy = "rewrite"` | Refuse to start; report kernel ≥5.7 needed |
| Mount namespace | Any shim-using rule (essentially all confined policies) | Refuse to start; report kernel unsupported (essentially impossible on modern Linux) |
| AppArmor | `unix.abstract = "deny"` policy | Warn; fall back to seccomp-TRAP for abstract-socket denial; functionality reduced |
| `legacy_tiocsti` sysctl | `tty.require_tiocsti_disabled = true` and kernel ≥6.2 | If sysctl is enabled, refuse to start; report how to disable |

The principle is "refuse to start rather than silently weaken the confinement". A policy that claims to defend against T2.2 (lateral movement to local services) and runs without cgroup BPF is not defending against T2.2; the user must be told.

For users on older kernels who genuinely cannot upgrade: Project Kennel supports a `--unsafe-degrade` flag that turns refusals into warnings. The flag is loud, logged, and visible in audit. Templates can also declare which features they tolerate degradation on; `inspect-only` may permit running without cgroup BPF (it has `net.mode = "none"` anyway), while `ai-coding-strict` may not.

## 10.3 Policy errors

Errors detected at policy load:

| Error | Behaviour |
|---|---|
| Syntactically invalid TOML | Refuse; report parse error with line number |
| Schema violation (unknown field, wrong type) | Refuse; report the field |
| Reference to unknown template | Refuse; report missing template and suggest similar names |
| Framework invariant violated | Refuse; report which invariant and why it exists |
| Template invariant violated by user delta | Refuse; report template, invariant, user delta location |
| `reason` missing on a delta | Refuse; require reasons on all deltas |
| Template version mismatch | Warn (not refuse); suggest `kennel policy upgrade` |
| DNS resolution failure for a `net.allow` name | Refuse if `dns.required = true`; otherwise warn and disable that rule |

The pattern: anything that would result in a kennel running under a different policy than the user authored is an error.

## 10.4 Resource errors

Failures during kennel setup:

| Failure | Behaviour |
|---|---|
| Cannot allocate kennel's loopback IPv4 (conflict, full range) | Refuse; report conflict; suggest changing tag |
| Cannot allocate IPv6 ULA (no privileged helper) | Disable IPv6 for kennel, warn; continue with IPv4 |
| Cannot launch SOCKS5 proxy | Refuse; report why (port conflict, bin missing) |
| Cannot launch dbus-proxy | If dbus policy is non-empty: refuse; else: continue without |
| Cannot launch Xwayland/Xephyr | Refuse if X11 isolation needed; otherwise continue |
| Cannot create mount namespace | Refuse (essentially impossible on modern Linux) |
| Privileged helper unavailable | Refuse if helper is needed (IPv6, cgroup creation on non-delegated systems); otherwise continue |
| BPF program load fails (kernel reports error) | Refuse; report BPF error (this indicates a Project Kennel bug, file it) |

## 10.5 Runtime failures

Mid-kennel failures:

| Failure | Behaviour |
|---|---|
| SOCKS5 proxy crashes | All outbound traffic blocked (BPF rules still in place). Supervisor restarts proxy. Kennel's connections to the proxy fail with ECONNREFUSED during the gap. |
| dbus-proxy crashes | Bus calls fail. Supervisor restarts. Active D-Bus connections are dropped; clients reconnect. |
| Xwayland/Xephyr crashes | X11 apps inside die. Supervisor restarts the server; user's open applications are lost. |
| SSH egress bastion (`kennel-sshd`) crashes | SSH from kennels fails (no route out — direct `:22` stays denied). `kenneld` restarts it and regenerates its key state from the live kennels; no keys to re-add (the bastion holds none — §7.10). |
| Audit log writer fails | Audit events queued in memory; if queue fills, Project Kennel chooses: drop new events (logged loudly) or block kennel (configurable per template). |
| Real D-Bus daemon restarts on host | dbus-proxy reconnects; kennel's bus connections briefly stall. |
| Real Wayland compositor restarts | Xwayland in the kennel loses its connection; Xwayland exits; supervisor restarts. User's X apps in the kennel are lost. |
| Kernel evicts BPF program (rare) | Project Kennel should detect; behaviour TBD (possibly: refuse to continue kennel, kill its processes). |

The supervisor's restart policy is configurable. Defaults are conservative: restart on crash, with exponential backoff, give up after some number of failures.

## 10.6 Adversary enumeration

A confined adversary may probe for misconfigurations. Probes Project Kennel should detect and respond to:

- **Ptrace attempts.** Any `ptrace(PTRACE_ATTACH)` from a kennel is logged as a forensic signal regardless of policy. AppArmor denies; Project Kennel records.
- **Unusual syscalls.** `userfaultfd`, `bpf`, `kexec_load`, etc. Seccomp denies; Project Kennel records.
- **Repeated denied connects.** A kennel making many `connect()` attempts to denied destinations is suspicious. Project Kennel logs each; downstream monitoring can alert on patterns.
- **Abstract-namespace connection probes.** Each is logged.
- **Filesystem path enumeration.** A kennel that `stat()`s many denied paths in sequence (probing for what's accessible) is suspicious. Landlock denies; Project Kennel records.
- **Capability probing.** A kennel that calls `capget()` is observing the dropped capability set. Allowed but noted.

Project Kennel does not actively respond to probes (no automatic kennel termination, no escalation). Detection and logging is Project Kennel's role; response is the user's decision. Templates may set thresholds in monitoring config that, when exceeded, trigger user-facing alerts via the audit log shipping mechanism (§9.11).

## 10.7 The user as failure mode

The user can:

- Disable Project Kennel entirely.
- Run `kennel run none` for any command.
- Edit policies to weaken them.
- Override warnings.

Project Kennel's response: make these visible but do not prevent them. The user is the trust root (§2.6); Project Kennel's role is to make the right choice easier than the wrong one, not to make the wrong choice impossible.

Specifically:

- `kennel run none` is supported but produces a clear message ("running without confinement").
- Editing a policy to weaken it produces visible diffs.
- Overriding warnings requires explicit flags (`--unsafe-degrade`, `--ignore-version-mismatch`, `--unsigned-template`); the flags appear in audit logs and process arguments.

This means Project Kennel cannot enforce a corporate policy on a user who can edit their own files. Corporate enforcement (mandatory baselines, server-side policy checks) is a layer above what Project Kennel provides; Project Kennel's tools (signed templates, validation in CI) support that layer.

## 10.8 Project Kennel itself broken

Bugs in Project Kennel's own code. Some are worse than others:

- **The schema validator misses an invariant violation.** A policy that should be rejected loads. Context runs under a weaker policy than intended. Mitigation: extensive test corpus; user-visible audit log surfaces the actual policy in effect.
- **The BPF program is buggy.** Denials happen when they shouldn't, or allows happen when they shouldn't. Mitigation: BPF programs are small, well-tested, version-pinned to Project Kennel version. Failures are detectable in the audit log (unexpected denies show up; unexpected allows are harder).
- **The SOCKS5 proxy has a parse bug.** A malformed request crashes the proxy. Mitigation: supervisor restarts; the kennel's traffic was denied during the gap (BPF still blocks direct connects).
- **The privileged helper has a vulnerability.** An attacker could potentially escalate to `CAP_NET_ADMIN`. Mitigation: the helper is small, narrowly scoped, fuzzed; it accepts requests only from Project Kennel's UID via a 0600 socket; it operates only within reserved address space.

Like any security tool, Project Kennel's correctness is itself part of its trust model. Project Kennel's threat model (§2) acknowledged that compromise of Project Kennel's own dependencies is out of scope (X7, X8). Compromise of Project Kennel itself is not formally out of scope, but is mitigated by code-quality discipline rather than architectural defence.

Project Kennel's own dogfooding requirement: Project Kennel's CI runs every template's test suite on every kernel version supported. If a template stops enforcing its claimed defences, CI fails. This catches the largest class of "Project Kennel code regression" issues.

## 10.9 Communicating failures to the user

Project Kennel's user-facing error messages should:

- Identify what failed (which check, which rule, which mechanism).
- Identify why (kernel feature missing, policy field invalid, daemon failed to start).
- Suggest a fix (upgrade kernel to X, change field Y, restart daemon Z).
- Point at a reference (URL or section in this document).
- Not blame the user.

Example:

```
$ kennel my-ai-coding bash
ERROR: cannot start kennel my-ai-coding.

  The policy requires Landlock FS_EXECUTE (for exec.* rules), but your
  kernel (5.15) does not support it. Full exec policy enforcement requires
  kernel 6.10 or later.

  Options:
    1. Upgrade to kernel 6.10+ (recommended)
    2. Use a template without exec rules (e.g. ai-coding-no-exec, which
       relies on no_new_privs and AppArmor instead)
    3. Force-start with degraded enforcement: --unsafe-degrade
       (logged loudly; not recommended for AI agents)

  See §10.2 in Project Kennel documentation for the full kernel feature matrix.
```

The error message is Project Kennel's primary documentation surface for failure modes. It needs to be deliberate and tested.
