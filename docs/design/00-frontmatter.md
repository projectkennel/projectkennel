# Project Kennel

**Kernel-enforced confinement for unsigned workloads on Linux developer workstations.**

Status: working draft
Version: 0.1
Last updated: 2026-05-16

---

## Executive summary

The user level of a modern developer workstation has become a complete software runtime — package managers, container engines, AI agents, MCP servers, build tools, language tooling — but it inherited none of the enforcement vocabulary that makes the host level defensible.

AI coding agents are the most acute current instance. Agents are trained on task completion; training on completion produces behaviour that minimises friction between the agent and finishing the task. Most of an organisation's security posture is friction. Agents trained to complete tasks therefore systematically degrade security posture as a side effect of doing their work — and the behaviour becomes more pronounced as agents become more capable.

The same threat shape applies to other unsigned workloads. Malicious npm post-install scripts execute as the user with full filesystem and network access during `npm install`. Container images from public registries run with whatever capabilities `docker run` granted. Scripts piped from `curl | sh` run with the developer's full credentials. The AI agent case is dramatic because the agent reasons its way through controls; the other cases are quieter, but the threat model is the same.

The defence that scales correctly is capability-based constraint at a level the workload cannot influence — kernel-enforced, workload-agnostic, with policy expressed in a vocabulary durable across vendors and workload types. Project Kennel is that vocabulary: signed templates, threat-tagged audit, kernel-enforced confinement applied at user-level workload granularity.

Project Kennel does not ask the workload to be trustworthy. It assumes the workload will optimise for completion (in the AI agent case) or that the developer will route around friction (in every other case), and constrains what either is permitted to look like.

---

## Audiences

This document has three audiences. Read the chapters that match yours.

**Security buyers (CISO, security architect, compliance officer):** §1 (the user-level runtime), §2 (adversary model), §5 (templates), §6 (worked examples), §11 (open questions). The security case, the operational layer, the honest limitations. The §7 mechanism reference and §8 enforcement architecture chapters can be skipped unless you want to audit implementation claims yourself.

**Developers using Project Kennel:** §1 skim, §6 (worked examples), §5 (templates). §2 is worth reading once.

**Template authors and framework contributors:** read everything, in order. The mechanism chapters (§7, §8) are reference material organised by resource class.

---

## Table of contents

| § | Title |
|---|---|
| 0 | Front matter (this file) |
| 1 | The user-level runtime |
| 2 | Adversary model |
| 3 | Same-uid as trust boundary |
| 4 | Trust boundaries and constructed views |
| 5 | Template system |
| 6 | Worked examples |
| 7.1 | Policy surface: binary execution |
| 7.2 | Policy surface: filesystem |
| 7.3 | Policy surface: network |
| 7.4 | Policy surface: AF_UNIX sockets and the shim model |
| 7.5 | Policy surface: D-Bus (proxied) |
| 7.6 | Policy surface: X11 (isolated only) |
| 7.7 | Policy surface: process introspection, env, capabilities, misc |
| 8 | Enforcement architecture |
| 9 | Policy lifecycle |
| 10 | Failure modes and degraded operation |
| 11 | Open questions and out-of-scope topics |
| 12 | Glossary and references |

The threat catalogue `THREATS.md` is a standalone companion artefact. The worked template `TEMPLATE-ai-coding-strict.md` is the complete annotated AI-agent template. The 2-page summary `EXEC-SUMMARY.md` is for circulation.

---

## File layout

Each chapter is a separate file (`NN-chapter-name.md` or `NN-N-chapter-name.md` for §7 subsections) so chapters can be revised in parallel without merge conflicts. Numbering is stable; new chapters added later take a non-integer suffix rather than renumbering downstream.

Cross-references use chapter number, e.g. "see §7.3". Within-chapter references use subsection numbers.

Code blocks in policy examples use TOML for the policy language and shell/C for implementation sketches. Policy examples are illustrative; the canonical schema lives in `schema/policy.toml.schema` in the Project Kennel repository.

---

## Conventions

- **Project Kennel** is this framework as a whole — the design, the runtime, the threat catalogue, the templates, the maintenance commitment.
- **`kennel`** is the command-line tool the developer invokes.
- **A kennel** is a confined execution context: the unit of confinement, the space a workload runs in, the thing a policy describes.
- **Workload** is the generic term for code being confined inside a kennel. AI agent, container image, package install script, MCP server, downloaded tool — all are workloads.
- **Default context** is the user's normal shell environment, unconstrained by Project Kennel. The trust root.
- **Threat IDs** are family-prefixed `T<family>.<index>` (T1.1, T1.2, …, T2.1, …, T3.7): the integer before the dot is the threat family, so each family carries its own sequence. They cross-link `THREATS.md`, this document, templates, and the audit log. The catalogue is at v0.3 (the family-prefix scheme landed in 0.3, replacing the former consecutive T1–T26).
- **Out-of-scope IDs** (X1, X2, ...) identify explicit non-goals.
- **Resource classes** in §7 follow a consistent naming convention: `exec.*`, `fs.*`, `net.*`, `unix.*`, `dbus.*`, `x11.*`, `proc.*`, `env.*`, `cap.*`.

This is v0.1. Pre-release iteration may renumber threats, restructure chapters, or rename interfaces. Stability commitments apply at v1.0.
