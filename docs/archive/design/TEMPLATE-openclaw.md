# Worked example: confining `openclaw`

**A complete, annotated, validated leaf policy for running an untrusted autonomous coding agent on one project.**

This is the canonical Project Kennel tenant, and it is the honest one. The earlier worked template ([`TEMPLATE-ai-coding-strict.md`](TEMPLATE-ai-coding-strict.md)) describes the *template* — the reusable security posture for "an AI coding agent on one project." This document is the other half: the **leaf policy** a real user writes on top of that template, for a real, hostile-by-assumption workload.

The workload is `openclaw`: an open-source, autonomous coding agent that reads code, writes code, runs tests, pulls dependencies, and calls a remote model API — all on its own initiative, with a prompt-injectable instruction channel and an arbitrary dependency tree. It is not a hypothetical. `openclaw` appears by name in the threat catalogue ([THREATS.md](THREATS.md) §T1.2): the Cline supply-chain incident (February 2026) delivered `openclaw` globally via an npm `postinstall` script. So this document treats the agent as **adversarial** throughout — not because openclaw's authors are malicious, but because an autonomous agent that executes arbitrary code and follows instructions from untrusted inputs *is* an attacker surface, whoever wrote it.

The leaf is reproduced in full, it is ~25 lines of which ~6 are policy, and **it is validated**: every TOML fragment in this document parses and validates against the real policy parser (`kennel_lib_policy::parse_leaf` + `LeafPolicy::validate`), proven by the oracle at `src/crates/kennel-lib-policy/examples/validate-policy.rs`. Run it yourself:

```
cargo run -p kennel-lib-policy --example validate-policy -- leaf templates/examples/openclaw-myproj.toml
```

For the meaning of every field — types, defaults, validation rules — see the schema reference in [`docs/archive/architecture/02-2-config-schema.md`](../architecture/02-2-config-schema.md). This document explains the *security reasoning*, not the field catalogue.

---

## 1 — The whole policy

`~/.config/kennel/kennels/openclaw-myproj.toml` (the in-tree copy lives at [`templates/examples/openclaw-myproj.toml`](../../templates/examples/openclaw-myproj.toml)):

```toml
template_base = "ai-coding-strict@v1"
name = "openclaw-myproj"

[[fs.write.add]]
path = "~/projects/myproj/**"
reason = "openclaw edits the project in place (read implied)"

[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "the model API openclaw calls"
threats.exposed = ["T1.8"]
```

That is the entire user-authored policy. Everything else — the constructed `$HOME`, the credential locations *absent* from the view, the per-kennel network namespace, the exec allowlist, the seccomp filter, the registry/git-host egress, the 8-hour TTL — is inherited from `ai-coding-strict@v1` and, beneath it, `base-confined@v1`.

---

## 2 — How to read it

**A leaf names its parent and itself, nothing more structural.** `template_base = "ai-coding-strict@v1"` is a single versioned reference: the name and the version travel together, and the lockfile pins the exact fragment hash at compile time so the parent cannot be swapped under you. There is no separate `template_version` field on a leaf (a common mistake — the version is part of the reference). `name` identifies this kennel.

**Every grant is a delta, and every delta carries a `reason`.** `[[fs.read.add]]` is a TOML array-of-tables: each entry is *appended* (`+=`) to the effective read-list the template chain produced. The policy **refuses to compile** if any delta entry omits `reason`, so a capability is never granted silently — the audit trail starts in the policy file itself. Scalars override; lists add (`.add`) or remove (`.remove`). That is the whole composition model: the template sets the posture, the leaf names the specifics.

---

## 3 — What each grant admits, and what it costs

### The project tree (`fs.write.add`)

openclaw gets read+write on **exactly** `~/projects/myproj/**` and nothing else under `$HOME` — from a single `fs.write.add`, because a writable path is implied-readable (the settled policy gets the read grant too, visible in `kennel diff`). This is the constructed-view model (§7.4): the kennel's `$HOME` is a fresh tmpfs into which only the granted paths are bound. The credential locations are not *denied* — they are **absent**. `~/.ssh`, `~/.aws`, `~/.config/gh`, your shell history, your other projects: the agent cannot read them, cannot enumerate them, cannot tell they exist. This is the structural answer to **T1.1** (credential and configuration reconnaissance): there is nothing to reconnoitre.

**The irreducible cost, stated plainly:** a secret that lives *inside* the granted tree — a committed `.env`, a stray `id_rsa`, a `.git/config` with a token — is readable by the agent, because you granted the tree. The sandbox cannot distinguish your code from your secrets once both sit under a granted path. Keep secrets out of project trees. This is not a gap in the design; it is the boundary of what a path-granting sandbox can do.

### The model endpoint (`net.allow.add`)

This is the one destination openclaw may reach beyond the registries and git hosts the template already allows. The mechanism matters for the threat story:

- The kennel lives in its **own network namespace** with no route off its loopback. It cannot `connect()` to anything directly, and it cannot resolve names — there is no resolver reachable from inside (§7.5). Its only egress path is the binder gateway to kenneld.
- On a request to `api.anthropic.com`, **kenneld** resolves the name (in the host namespace), re-checks the resolved address against the invariant deny list (cloud metadata, link-local, host loopback), pins it, and dials it through the host-side delegate. A poisoned or rebinding DNS answer is caught *before* the dial, because the kennel never holds an address — only a name kenneld vets.

So a leaf that grants `api.anthropic.com` cannot be turned, by DNS trickery or a raw-IP `connect()`, into a path to `169.254.169.254` or the user's local Postgres (**T1.6** — lateral movement to local services — is closed by the namespace boundary, not merely by a rule).

**The irreducible cost — T1.8 (exfiltration via an allowed destination):** openclaw can put anything it can read into a request to the endpoint it is allowed to reach. The allowlist bounds *where* bytes may go, not *what* goes there. This is unavoidable for any agent that legitimately talks to a model API. The mitigations are external and are named in the policy (`threats.exposed = ["T1.8"]`): grant no tree with high-value secrets, rely on the per-connection audit record, and add the optional TLS-inspection layer if your threat model requires payload inspection. The policy does not pretend this is solved.

---

## 4 — What the template already denied (so the leaf didn't have to)

The leaf is short because the template is strict. openclaw, running under this policy, **cannot**:

- **Spawn off-allowlist binaries** (`sudo`, a downloaded payload, a shell openclaw wrote to disk): the exec allowlist is the closure of the template's named interpreters and tools, enforced by Landlock `FS_EXECUTE` on `execve` (§7.3). A `postinstall` script that drops a binary and runs it (**T1.2**) gets `EACCES` on the exec.
- **Reach the user's ssh-agent or gpg keyring** (**T1.6**): SSH egress goes through the re-origination bastion, bound to specific destinations, never an exposed agent socket. `~/.gnupg` is absent from the view; commit signing is host-side (the human signs on review before push, §11.2).
- **See the user's other processes** (**T1.1**): a private PID namespace and a fresh `/proc`.
- **Degrade host security config** or escalate: `no_new_privs`, an empty capability bounding set, a seccomp filter, and an unprivileged user namespace mean there is no root to become and no privileged syscall to call.
- **Outlast its session unbounded**: an 8-hour TTL (warn, not kill — a workday-length coding session) bounds a quietly-persistent agent.

Each of these is inherited, auditable, and — per the project's ethos — a *warning* surface, not a forbidden one: a user who genuinely needs to loosen a constraint writes a delta and says why, rather than the framework pretending the loosening is impossible.

---

## 5 — Residuals (the honest list)

A worked example that claimed no residuals would be lying. For this policy:

- **T1.8 — exfiltration via the model API.** Covered above. Irreducible for an agent that talks to a remote model. External mitigations only.
- **T1.9 — supply-chain compromise in a fetched dependency.** Every registry grant in the template (`npmjs.org`, `pypi.org`, `crates.io`, …) is a path by which a poisoned package enters the project tree. The sandbox confines what that package can *do* (exec allowlist, net namespace, no credential access), which is exactly the mitigation — but it does not vet the package. A malicious dependency that limits itself to corrupting the project's own output (**T2.2**, semantic regressions) is within the granted surface.
- **Secrets inside the granted tree.** Covered in §3. Policy cannot fix project hygiene.

These are written into the policy itself (`threats.exposed`) so they travel with it and surface in the audit, rather than living only in a design document a reader might not consult.

---

## 6 — Switching agents, switching models

The policy describes constraints on *what any process in the kennel may do*, not on openclaw specifically. To run a different agent, or point openclaw at a different model, the only change is the `net.allow.add` destination — `api.openai.com`, a self-hosted endpoint, whatever. The project tree, the credential isolation, the exec allowlist, the namespace boundary: unchanged. That is what "agent-agnostic, model-agnostic policy" means in practice, and it is why the canonical tenant being *hostile* costs the user ~6 lines rather than a bespoke sandbox.
