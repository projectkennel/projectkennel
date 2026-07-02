# ai-coding-strict

Strict confinement for an AI coding agent (Claude Code, Codex, Cursor, Aider, …)
working against **one project**. The canonical case Project Kennel was designed
for. The fully-annotated reference — every rule mapped to its kernel mechanism,
with worked denials — is [`TEMPLATE-ai-coding-strict.md`](../../docs/archive/design/TEMPLATE-ai-coding-strict.md)
at the repo root.

## What the user adds

The template intentionally omits the two things that vary per use: the project
path and the LLM API endpoint. A leaf policy is ~10 lines:

```toml
template = "ai-coding-strict"
name = "myproj-ai"

[[fs.read.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

[[fs.write.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

[[net.allow.add]]
name = "api.anthropic.com"   # or api.openai.com, generativelanguage.googleapis.com, …
ports = [443]
reason = "the LLM API for the agent I use"
threats.exposed = ["T1.8"]
```

Switching agents is a one-line change (the API host). Everything else — the
credential denylist, the constructed `$HOME`, proxy-only egress, the seccomp
filter, the ssh-agent — is inherited.

## Defends / residuals

- **Defends:** T1.1 (credential recon), T1.2 (post-install scripts), T1.3 (compromised
  extension/MCP), T1.6 (lateral movement), T2.1 (host-control deactivation), T2.3
  (secrets in unintended locations), T3.7 (prompt injection blast-radius).
- **Residuals:** **T1.8** — the agent legitimately reaches the LLM API and can put
  exfiltrated data in API requests (mitigate externally: keep secrets out of the
  project; optional TLS-inspection layer). **T2.2** — semantic security
  regressions in produced code (output-review tooling, not this template).

## Adds over base-confined

The agent toolchain (interpreters, build tools, package managers, git, ssh), the
common package registries + git hosts (by name, proxy-enforced), a per-kennel
ssh-agent, `.env`-style scrubbing in the project tree, and an 8-hour `warn` TTL.

See `templates/README.md` for which sections are runtime-enforced today.
