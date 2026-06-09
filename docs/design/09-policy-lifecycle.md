# §9 Policy lifecycle

Policies are not write-once artefacts. They are authored, refined as workflows evolve, updated when templates advance, occasionally rolled back, and sometimes shared between users or within an organisation. Project Kennel treats the policy lifecycle as a first-class concern: tools support each stage, and the audit infrastructure makes policy-change consequences visible.

## 9.1 Authoring

A new policy is born from a template (§5). Project Kennel's `init` command produces a starting file:

```
$ kennel init my-ai-coding --template ai-coding-strict
```

The resulting file contains the template reference, version pin, and an empty deltas section with comments pointing the user at the diff and validate commands. Users do not author policies from scratch; the experience is "pick a template, customise the deltas".

For users who genuinely need a new template (organisation-specific workflow, novel tool integration), the path is "fork a close template, modify, propose upstream or maintain internally". This is more work but produces a reusable artefact rather than a one-off policy.

Authoring discipline:

- Every delta needs a `reason`. The schema rejects deltas without one. Reasons accumulate institutional knowledge.
- `kennel diff` is run before commit. The diff surfaces threat-impact changes.
- `kennel validate` is run before commit. Schema and invariants are checked.
- For organisation-managed policies, both run in CI on the policy repo.

## 9.2 Refinement

Workflows change. A kennel that started as "AI agent on a single Python project" becomes "AI agent on Python, with occasional npm install, talking to an internal API". Each change is a delta:

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

Each refinement is small. The diff between yesterday's policy and today's is reviewable. Audit logs from the previous configuration are still valid evidence about what the kennel did under the prior policy.

## 9.3 Reflexive refinement

Project Kennel's audit log can be used backwards: run a kennel under a permissive template, observe what it does, then tighten the policy to match.

```
$ kennel run permissive-discovery --template ai-coding-permissive bash
# ... run the workflow normally ...

$ kennel derive permissive-discovery > suggested-policy.toml
```

`derive` reads the kennel's audit log and produces a tightened policy: the file system paths actually read, the network destinations actually contacted, the AF_UNIX sockets actually used. The user reviews the suggestion, edits the reasons (Project Kennel cannot synthesise meaningful reasons), and commits as the new policy.

This is not automatic policy generation. The user is in the loop, the reasons are theirs, and the threat tags are assigned consciously. But it removes the "what do I even need" cold-start problem for novel workflows. A user with no a-priori knowledge of which paths and hosts a tool needs can discover them by running once and reading the audit.

Caveat: `derive` should be used on workflows the user already trusts to be safe. Running a confirmed-malicious tool through `derive` and then writing a policy that exactly accommodates it is missing the point. The discovered policy is the *minimum* needed for the observed behaviour; the policy author still has to decide whether the observed behaviour is what they want.

## 9.4 Template updates

When the upstream template advances (new version published), Project Kennel warns the user. The user runs `kennel upgrade <kennel>` to review changes (§5.11).

Three outcomes:

- **Clean upgrade.** No conflicts; the template's changes are accepted, policy version bumped.
- **Conflict.** The template's changes overlap with the user's deltas. The user reviews, decides per conflict, applies.
- **Decline.** The user pins to the old version. Acceptable but means missing future template-level mitigations; Project Kennel reminds occasionally.

Template versions are append-only. A template never disappears; an old version remains available indefinitely so that users pinned to it continue to work. Deprecated templates are marked in metadata; Project Kennel warns when a deprecated template is referenced and suggests the successor.

## 9.5 Rollback

A policy change that breaks workflow needs reverting. Project Kennel's policy files are plain text; users typically version-control them in git, and `git revert` is the rollback mechanism.

For users not version-controlling policies, Project Kennel optionally keeps the last N versions of each policy file under `~/.local/state/kennel/policy-history/`. The `kennel history <kennel>` command lists them; `kennel revert <kennel> <version>` restores.

This is intentionally simple. Policy rollback should not need a sophisticated framework feature; git is the right primitive. Project Kennel's history feature is for users who don't version-control.

## 9.6 Sharing policies

Policies are shareable artefacts. A user with a working AI-coding policy can share it with a colleague:

```
$ kennel export my-ai-coding > my-ai-coding.policy
# colleague:
$ kennel import my-ai-coding.policy --name colleagues-ai-coding
```

The exported file is the policy plus its template reference. The colleague's Project Kennel installation resolves the template from the same repository (if both have the same templates available) or warns if the template is unknown.

For organisations:

- **Template repository.** Internal templates published to a git repo. Users clone or syncher locally.
- **Policy review.** User policies committed to a per-user repo; CI runs `kennel validate` and `kennel diff` against the previous version; security-reviewer approves merges.
- **Mandated baseline.** Organisation publishes a template (say, `corp-confined`) that all employee policies must derive from. The schema validator can be configured to require a specific template root.

Project Kennel supports this without prescribing it. The mechanisms are policy import/export, template repositories, and the standard validation tooling. The policy-management workflow is the organisation's concern.

## 9.7 Time-bounded kennels

Some kennels should not be long-lived. An ad-hoc "inspect this repo" or "install this one tool" kennel should expire automatically. Policy supports a TTL:

```toml
[lifecycle]
ttl = "2h"           # kennel auto-exits after this duration
ttl_action = "exit"  # "exit" | "warn" | "renew"
```

The deadline is held **inside** the kennel — `kennel-init` (PID 1) runs the timer — and enforced with the **cgroup v2 freezer**, not an external polling reaper. At expiry `kennel-init` makes a single blocking call out to the daemon, which owns the kennel's cgroup; the daemon **atomically freezes** the whole kennel (so nothing runs past the deadline — there is no "acts during the grace window" race) and then, per `ttl_action`:

- `exit`: terminate the frozen kennel. The freeze is atomic and the kill reaches frozen tasks, so termination is immediate and race-free — and it is the *daemon's* kill, which a compromised in-kennel PID 1 cannot refuse.
- `warn`: a momentary atomic pause, an audit event, then **resume** — the workload keeps running. The same blocking call returns and the kennel picks up exactly where it was suspended.
- `renew`: freeze and request renewal via the user's session (the interactive prompt is the remaining piece; until it is wired this behaves as a louder `warn` — freeze, audit, resume).

Default is `exit` for templates that don't override. The freezer makes "suspend, decide, resume" a first-class operation: a kennel can be paused at its deadline and continued, not just killed.

Time-bounded kennels address T1.10 (long-lived workload capability creep). A `package-install` kennel with a 30-minute TTL cannot accumulate capability over months because it cannot exist for months. Users who need long-lived kennels use templates without TTLs (`ai-coding-strict` has none); the explicit non-TTL is itself a documented choice.

## 9.8 Periodic re-consent

A related mechanism for long-lived kennels: periodic prompt-for-re-consent.

```toml
[lifecycle]
reconsent_interval = "7d"
```

Every 7 days of kennel activity, Project Kennel reminds the user that the kennel is still active and asks them to confirm continued operation. The user's response is recorded in the audit log; declining tears down the kennel.

This is a behavioural rather than a technical defence. The threat is the user *forgetting* that a kennel exists and continues to run. Re-consent makes the kennel visible at regular intervals.

## 9.9 Policy as code

For users with the inclination, policies can be programmatically generated. A common case: a developer with N similar projects wants a policy per project, each scoped to the right path. A small script generates N policies from a template:

```python
for project in projects:
    write_policy(
        path=f"~/.config/kennel/kennels/{project}.toml",
        template="ai-coding-strict",
        fs_paths=[f"~/projects/{project}/**"],
        net_hosts=PROJECT_HOSTS[project],
    )
```

Project Kennel does not provide an SDK for this; the policy file format is straightforward TOML and any language can produce it. The validate and diff commands operate on the produced files identically to hand-written ones.

This is also how organisations can centrally manage policies: a CI job in the org's policy repo generates per-developer per-project policies from a template plus a manifest of projects, signs them, and pushes them to developer workstations.

## 9.10 Compilation and the settled policy

Everything described so far — template inheritance, includes, deltas, signature verification, lockfile byte-pinning, invariant checks, variable substitution — is *resolution* work. A naive implementation does all of it every time a kennel starts: parse the leaf policy, walk the inheritance chain, verify each template's and fragment's signature, check the lockfile, merge includes, apply deltas, validate invariants, substitute variables, and only then have an effective policy to enforce. That is a great deal of complex code (TOML parsing of arbitrary templates, chain-walking, glob handling, include conflict resolution, cryptographic verification) running on the hot path of every `kennel run`.

Project Kennel does not work this way. It compiles.

The systems Project Kennel is measured against already do this. AppArmor authors a text profile and `apparmor_parser` compiles it into a binary policy loaded into the kernel; the text is never consulted at enforcement time. SELinux compiles a monolithic binary policy from source modules. The authored artefact and the enforced artefact are different things, and the compile step is where the expensive, fallible, security-critical work happens — once, deliberately — rather than on every enforcement.

### The settled policy

`kennel compile` takes a leaf policy and produces a **settled policy**: a flat, fully-resolved document in which the inheritance chain has been folded, includes have been merged, deltas have been applied, and every source signature and lockfile pin has been verified. The settled policy contains no `template_base`, no `include`, no delta operators — only the final effective rules. It is signed as a unit by the compiling authority.

The division of labour:

**Compile time (`kennel compile`, run once per policy revision):**

- Parse the leaf policy and resolve the full inheritance chain.
- Resolve and merge all includes; detect and reject conflicts.
- Apply all deltas.
- Verify the signature of every source template and fragment against the trust store.
- Check every resolved artefact's signature against the lockfile pin.
- Validate framework and template invariants.
- Validate threat tags against the catalogue.
- Substitute the *installation-constant* variables (`<tag>`, `<gid>`).
- Emit the settled policy and sign it.

**Run time (`kennel run`, every spawn):**

- Verify *one* signature, over the settled policy, against the trust store.
- Re-assert framework invariants (see below).
- Substitute the *per-instance* variables (`<ctx>`, `<uid>`, `<kennel>`, `<home>`).
- Build the kernel objects (Landlock ruleset, BPF maps, mount plan) and spawn.

The spawn path links none of the template machinery. It does not parse templates, walk chains, resolve includes, or apply deltas. The complex code runs at compile time, in a context where the operator can review the output; the runtime consumes a settled artefact whose shape is fixed and simple.

### What stays deferred

Not every variable can be baked in at compile time. Some are intrinsically per-kennel-instance:

- `<ctx>` is assigned by kenneld when the kennel starts, and differs between concurrent kennels deriving from the same settled policy.
- `<uid>`, `<home>` are per-user; a settled policy distributed to a fleet is the same for every recipient.
- `<kennel>` for ad-hoc kennels is generated at start.

These are recorded in the settled policy as an explicit `deferred_substitutions` list. The runtime substitutes exactly those, and refuses to spawn if any *other* unsubstituted placeholder remains — a settled policy that somehow carries an un-deferred, un-substituted variable is a compile bug, caught at spawn rather than enforced wrong.

### Framework invariants are re-asserted at runtime

A valid signature on a settled policy means a trusted key vouched for it. It does not, on its own, mean the policy upholds Project Kennel's structural guarantees — those guarantees are Project Kennel's, not the signer's. So the runtime re-asserts the framework invariants (§5.5) on the settled policy as a final gate: `no_new_privs`, the setuid/setgid/setcap denials, the mandatory `$HOME` shim, the cloud-metadata denies, the PID namespace, the SOCKS5-proxy-only egress. These checks are cheap (a handful of structural assertions) and they hold regardless of who signed the artefact or how it arrived. A validly-signed settled policy that violates a framework invariant is refused.

This is the one place runtime deliberately repeats compile-time work. It is worth it: it means no policy — however it was produced, whatever key signed it, whether it arrived by compile or by fleet push — can disable the protections that define what a kennel *is*.

### Two operating modes

**Local development.** A developer iterating on a policy does not want a manual compile step in the edit-run loop. `kennel run` of a source policy auto-compiles in memory when no fresh settled artefact exists, signs the result (and records the lockfile pins), marks it a development build, and runs it. Staleness is detected by comparing the settled policy's provenance (the recorded inputs) against the current source; a changed input triggers recompilation. The loop stays tight; the developer rarely types `kennel compile` explicitly.

**Fleet / attested deployment.** An organisation compiles policies centrally — in CI, on infrastructure that holds the templates, the fragments, the lockfiles, and the signing key — and pushes *only the signed settled policies* to developer workstations. The workstation need not have the templates, the lockfile, or even the resolution code paths exercised. `kennel run` verifies the organisation's signature on the settled policy, re-asserts framework invariants, and spawns. The runtime trust surface on the workstation is reduced to a single signature verification against a pinned key.

This is the foundation for the attestation capability described in the executive summary: a workstation can demonstrate that it is running an approved, signed policy revision, because the settled policy it enforces is exactly the artefact the organisation signed — its ed25519 signature is the identity — with no live resolution that could diverge.

### Provenance

The settled policy carries a provenance block recording every input that produced it: the leaf policy, each resolved template and fragment (by `name@version` and signature, lifted from the lockfile), the schema version, the invariant set, the threat-catalogue version, the installation constants baked in, and the compiler version. The settled policy is therefore self-describing — anyone can read exactly which signed source artefacts, at which versions and bytes, were composed to produce it, without needing those sources present. `kennel diff` can diff two settled policies directly, and can show the provenance delta between revisions.

## 9.11 Audit log uses

The structured audit log per kennel (§8.6) supports several downstream uses beyond debugging:

- **Forensics.** If a kennel did something unexpected, the log records every resource access. The user can answer "what did the AI agent read between 14:00 and 15:00?".
- **Compliance.** Organisations may need to demonstrate that kennels didn't access prohibited resources. The audit log is the evidence.
- **Policy refinement.** As above (§9.3), the audit log feeds back into policy authoring.
- **Anomaly detection.** A monitoring layer (external to Project Kennel) can watch logs and alert on patterns: new destinations, unusual file access, repeated denies. Project Kennel provides the log; the monitoring layer is downstream.

The log format is stable across Project Kennel versions (schema_version field). Tools that parse it can rely on the structure.

## 9.12 Compliance and regulatory considerations

For regulated industries (finance, healthcare, government), Project Kennel's audit infrastructure can support compliance demonstrations:

- **Evidence of confinement.** The audit log shows that a kennel did not access protected resources, because the kernel denied each attempt.
- **Policy review trail.** Version-controlled policies plus the diff output document what was approved and when.
- **Centralised audit.** Audit logs can be shipped to a central collector (Project Kennel writes to files; standard log-shipping tools handle the rest).
- **Tamper resistance.** Audit logs are write-once-append-only from Project Kennel's perspective. Stronger tamper-evidence (signed log segments, transparency logs) is a downstream concern.

Project Kennel does not claim regulatory certification. It provides the infrastructure that makes certification-relevant claims demonstrable.
