# §7 Policy lifecycle

Policies are not write-once artefacts. They are authored, refined as workflows evolve, updated when templates advance, occasionally rolled back, and sometimes shared between users or within an organisation. The framework treats the policy lifecycle as a first-class concern: tools support each stage, and the audit infrastructure makes policy-change consequences visible.

## 7.1 Authoring

A new policy is born from a template (§5). The framework's `init` command produces a starting file:

```
$ agent-run init my-ai-coding --template ai-coding-strict
```

The resulting file contains the template reference, version pin, and an empty deltas section with comments pointing the user at the diff and validate commands. Users do not author policies from scratch; the experience is "pick a template, customise the deltas".

For users who genuinely need a new template (organisation-specific workflow, novel tool integration), the path is "fork a close template, modify, propose upstream or maintain internally". This is more work but produces a reusable artefact rather than a one-off policy.

Authoring discipline:

- Every delta needs a `reason`. The schema rejects deltas without one. Reasons accumulate institutional knowledge.
- `agent-run diff` is run before commit. The diff surfaces threat-impact changes.
- `agent-run validate` is run before commit. Schema and invariants are checked.
- For organisation-managed policies, both run in CI on the policy repo.

## 7.2 Refinement

Workflows change. A context that started as "AI agent on a single Python project" becomes "AI agent on Python, with occasional npm install, talking to an internal API". Each change is a delta:

```
# Initial:
template = "ai-coding-strict"
[fs.read.add]
- path = "~/projects/myapp/**"
  reason = "the project"

# Six weeks later:
[fs.read.add]
- path = "~/projects/myapp/**"
  reason = "the project"
- path = "~/projects/shared-lib/**"
  reason = "shared library we depend on"

[net.allow.add]
- name = "internal-api.corp.example"
  ports = [443]
  reason = "API the project consumes"
  threats.exposed = []

[exec.allow.add]
- path = "/usr/bin/node"
  reason = "needed for npm install of frontend deps"
- path = "/usr/bin/npm"
  reason = "frontend deps"
```

Each refinement is small. The diff between yesterday's policy and today's is reviewable. Audit logs from the previous configuration are still valid evidence about what the context did under the prior policy.

## 7.3 Reflexive refinement: deriving policy from observed behaviour

The framework's audit log can be used backwards: run a context under a permissive template, observe what it does, then tighten the policy to match.

```
$ agent-run --context permissive-discovery --template ai-coding-permissive bash
# ... run the workflow normally ...

$ agent-run derive permissive-discovery > suggested-policy.toml
```

`derive` reads the context's audit log and produces a tightened policy: the file system paths actually read, the network destinations actually contacted, the AF_UNIX sockets actually used. The user reviews the suggestion, edits the reasons (the framework cannot synthesise meaningful reasons), and commits as the new policy.

This is not automatic policy generation. The user is in the loop, the reasons are theirs, and the threat tags are assigned consciously. But it removes the "what do I even need" cold-start problem for novel workflows. A user with no a-priori knowledge of which paths and hosts a tool needs can discover them by running once and reading the audit.

Caveat: `derive` should be used on workflows the user already trusts to be safe. Running a confirmed-malicious tool through `derive` and then writing a policy that exactly accommodates it is missing the point. The discovered policy is the *minimum* needed for the observed behaviour; the policy author still has to decide whether the observed behaviour is what they want.

## 7.4 Template updates

When the upstream template advances (new version published), the framework warns the user. The user runs `agent-run upgrade <context>` to review changes (§5.9).

Three outcomes:

- **Clean upgrade.** No conflicts; the template's changes are accepted, policy version bumped.
- **Conflict.** The template's changes overlap with the user's deltas. The user reviews, decides per conflict, applies.
- **Decline.** The user pins to the old version. Acceptable but means missing future template-level mitigations; the framework reminds occasionally.

Template versions are append-only. A template never disappears; an old version remains available indefinitely so that users pinned to it continue to work. Deprecated templates are marked in metadata; the framework warns when a deprecated template is referenced and suggests the successor.

## 7.5 Rollback

A policy change that breaks workflow needs reverting. The framework's policy files are plain text; users typically version-control them in git, and `git revert` is the rollback mechanism.

For users not version-controlling policies, the framework optionally keeps the last N versions of each policy file under `~/.local/state/agent-run/policy-history/`. The `agent-run history <context>` command lists them; `agent-run revert <context> <version>` restores.

This is intentionally simple. Policy rollback should not need a sophisticated framework feature; git is the right primitive. The framework's history feature is for users who don't version-control.

## 7.6 Sharing policies

Policies are shareable artefacts. A user with a working AI-coding policy can share it with a colleague:

```
$ agent-run export my-ai-coding > my-ai-coding.policy
# colleague:
$ agent-run import my-ai-coding.policy --name colleagues-ai-coding
```

The exported file is the policy plus its template reference. The colleague's framework resolves the template from the same repository (if both have the same templates available) or warns if the template is unknown.

For organisations:

- **Template repository.** Internal templates published to a git repo. Users clone or syncher locally.
- **Policy review.** User policies committed to a per-user repo; CI runs `agent-run validate` and `agent-run diff` against the previous version; security-reviewer approves merges.
- **Mandated baseline.** Organisation publishes a template (say, `corp-confined`) that all employee policies must derive from. The schema validator can be configured to require a specific template root.

The framework supports this without prescribing it. The mechanisms are policy import/export, template repositories, and the standard validation tooling. The policy-management workflow is the organisation's concern.

## 7.7 Time-bounded contexts

Some contexts should not be long-lived. An ad-hoc "inspect this repo" or "install this one tool" context should expire automatically. Policy supports a TTL:

```toml
[lifecycle]
ttl = "2h"           # context auto-exits after this duration
ttl_action = "exit"  # "exit" | "warn" | "renew"
```

Reaches the TTL, the framework either:

- `exit`: terminates the context cleanly (SIGTERM, then SIGKILL after grace).
- `warn`: logs a warning, asks the user to renew, continues.
- `renew`: prompts the user via the user's session (notification or terminal) for confirmation to extend.

Default is `exit` for templates that don't override.

Time-bounded contexts address T8 (long-lived tool creep). A `package-install` context with a 30-minute TTL cannot accumulate capability over months because it cannot exist for months. Users who need long-lived contexts use templates without TTLs (`ai-coding-strict` has none); the explicit non-TTL is itself a documented choice.

## 7.8 Periodic re-consent

A related mechanism for long-lived contexts: periodic prompt-for-re-consent.

```toml
[lifecycle]
reconsent_interval = "7d"
```

Every 7 days of context activity, the framework reminds the user that the context is still active and asks them to confirm continued operation. The user's response is recorded in the audit log; declining tears down the context.

This is a behavioural rather than a technical defence. The threat is the user *forgetting* that a context exists and continues to run. Re-consent makes the context visible at regular intervals.

## 7.9 Policy as code

For users with the inclination, policies can be programmatically generated. A common case: a developer with N similar projects wants a policy per project, each scoped to the right path. A small script generates N policies from a template:

```python
for project in projects:
    write_policy(
        path=f"~/.config/agent-run/contexts/{project}.toml",
        template="ai-coding-strict",
        fs_paths=[f"~/projects/{project}/**"],
        net_hosts=PROJECT_HOSTS[project],
    )
```

The framework does not provide an SDK for this; the policy file format is straightforward TOML and any language can produce it. The validate and diff commands operate on the produced files identically to hand-written ones.

This is also how organisations can centrally manage policies: a CI job in the org's policy repo generates per-developer per-project policies from a template plus a manifest of projects, signs them, and pushes them to developer workstations.

## 7.10 What the audit log enables

The structured audit log per context (§6.6) supports several downstream uses beyond debugging:

- **Forensics.** If a context did something unexpected, the log records every resource access. The user can answer "what did the AI agent read between 14:00 and 15:00?".
- **Compliance.** Organisations may need to demonstrate that confined contexts didn't access prohibited resources. The audit log is the evidence.
- **Policy refinement.** As above (§7.3), the audit log feeds back into policy authoring.
- **Anomaly detection.** A monitoring layer (external to the framework) can watch logs and alert on patterns: new destinations, unusual file access, repeated denies. The framework provides the log; the monitoring layer is downstream.

The log format is stable across framework versions (schema_version field). Tools that parse it can rely on the structure.

## 7.11 Compliance and regulatory considerations

For regulated industries (finance, healthcare, government), the framework's audit infrastructure can support compliance demonstrations:

- **Evidence of confinement.** The audit log shows that a context did not access protected resources, because the kernel denied each attempt.
- **Policy review trail.** Version-controlled policies plus the diff output document what was approved and when.
- **Centralised audit.** Audit logs can be shipped to a central collector (the framework writes to files; standard log-shipping tools handle the rest).
- **Tamper resistance.** Audit logs are write-once-append-only from the framework's perspective. Stronger tamper-evidence (signed log segments, transparency logs) is a downstream concern.

The framework does not claim regulatory certification. It provides the infrastructure that makes certification-relevant claims demonstrable.
