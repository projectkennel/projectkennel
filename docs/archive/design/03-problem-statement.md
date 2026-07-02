# §3 Same-uid as trust boundary

## 3.1 The Unix model assumes user agency

The Unix permission model treats the user account as the unit of trust. Every process running as user `u` has every capability of user `u`: read every file, connect to every network endpoint, talk to every local service, execute every binary, sign with every credential. The model assumes the user is in close control of which processes run on their behalf.

That assumption broke years ago. A modern developer routinely invokes processes that nominally serve the user but operate semi-autonomously, with goals and instructions the user did not personally vet:

- AI coding agents that read source, write code, run tests, and call external services.
- Build tools that execute `postinstall` scripts from arbitrary npm/pypi/cargo packages.
- Container images pulled from public registries, running with whatever capabilities `docker run` granted.
- IDE extensions and language servers that scan repositories and phone home.
- MCP servers that mediate agent access to user resources, themselves running in the user's session.
- Installers fetched via `curl ... | sh` from URLs that may or may not be what the user typed.
- Long-lived development daemons that accumulate capability over months without re-consent.

Each runs as the user's uid. Each has, by default, full access to the user's SSH keys, GPG keys, browser cookies, password manager database, cloud credentials, source repositories, and every other piece of state the user has accumulated. None of them needs that access for the task the user asked them to perform.

The user did not consent to this capability grant. The user consented to "help me refactor this function" or "install this package" or "let me try this Postgres image". The system granted "everything you, the human, can do".

## 3.2 What changed

The threat is not new in principle. Same-uid malware has existed as long as multi-user systems. What is new is the *normalisation* of high-capability, semi-autonomous processes in the developer's daily workflow. The base rate of "untrusted code running as me on my workstation" has gone from "occasionally, when I make a mistake" to "constantly, by design".

Two shifts produced this.

**Frequency.** Five years ago, the typical developer might invoke a `curl | sh` installer once a month and pull a Docker image once a week. Today, the typical developer running AI coding agents has the agent invoke dozens of subprocesses per hour, each inheriting the user's uid and full capability. `npm install` of a project's dependencies executes hundreds of postinstall scripts. A development workflow that involves a database, a queue, and a search index runs three or four container images simultaneously, each from a public registry.

**Optimisation pressure.** Untrusted code on the user's workstation used to be untrusted *in spite of* its intent — a malicious npm package, an attacker-controlled installer. Increasingly it is untrusted *because of* its intent: an AI agent optimising for task completion via friction removal (§1.2), a developer reaching for `-v $HOME:/home --network host` to make a container's connection problems go away (§1.5). Even benign code degrades security posture as a side effect of doing its job.

The mitigation infrastructure has not kept pace. The available primitives — Linux capabilities, namespaces, Landlock, AppArmor, SELinux, seccomp, cgroup BPF — exist and work, but they are spread across kernel subsystems, lack a common policy language, and require expertise to apply correctly. The desktop-application sandbox story (Flatpak, snap) is mature; the command-line and developer-workflow story is essentially absent.

Developers have no usable mechanism for saying "this process gets a narrow slice of my account's capabilities" while continuing to work normally. The choice is between "give the workload everything" and "don't use the workload". Most developers pick the first, because the second is incompatible with their job.

## 3.3 Per-tool sandboxes

Per-tool sandbox solutions exist. Claude Code ships with a built-in sandbox (Linux: bubblewrap + a network proxy; macOS: Seatbelt). OpenAI Codex CLI uses Landlock + seccomp natively, with sandboxing on by default. Gemini CLI supports Docker/Podman as opt-in. ai-jail, compartment, and jail-ai wrap individual agents with bubblewrap-equivalent isolation. Containers themselves provide a partial isolation model for container-shaped workloads.

None of these constitutes an organisational security posture, for three reasons elaborated in §1.5 and §1.6:

- **Per-tool lifecycle.** Each tool's sandbox is tied to its release cadence, threat model, and configuration format. A corporate policy implemented in Claude Code's sandbox config is not portable to Codex, Cursor, or a container running as a development service. Developers swap tools on monthly timescales; security policy needs quarterly-to-yearly stability.
- **Vendor incentive misalignment.** Each tool's sandbox is optimised first for product metrics — task completion rate, developer satisfaction — and only secondarily for the user's security posture. A sandbox that breaks workflows is rolled back. The vendor's incentive is permissive defaults.
- **Application-layer enforcement.** Several per-agent sandboxes enforce policy in the same process that runs the agent. CVE-2025-59536, CVE-2026-21852, and CVE-2026-25725 each demonstrated the same architectural concern: malicious project files cause shell command execution before any consent dialog. Containers have an analogous problem with daemon-side enforcement (the Docker daemon's API trusts whoever has access to its socket).

Project Kennel enforces at the kernel layer, with policy expressed in a vocabulary independent of any specific tool. The mechanism is the same whether the workload is Claude Code, Codex, a container, an npm install, or an MCP server. The policy is the same. The audit log is the same. The tool is interchangeable; the security posture is durable.

Enforcement at the kernel layer also means the enforcement boundary cannot live in the same process as the workload it confines. A kennel is built inside its own namespaces and reaches anything outside them through exactly one kernel-mediated channel: a per-kennel binder bus whose context manager is the Project Kennel daemon, not the workload. That single mediated boundary is load-bearing — it is how the kennel is constructed and supervised, and how every grant the policy permits (a connected socket, a filtered D-Bus call, an inter-kennel service) is delivered, per call, with kernel-stamped caller identity the workload cannot forge. The application-layer-enforcement failure of per-tool sandboxes — policy in the process that the project files can already drive (CVE-2025-59536 and kin) — has no analogue here, because the deciding party is on the other side of a boundary the workload cannot cross from inside.

## 3.4 Scope

In scope:

- A Linux user-space framework.
- Same-uid threat model: one human user; some workloads trusted, others not.
- Interactive developer workflows: shells, AI agents, builds, repository inspection, containers, MCP servers.
- Composable confinement: kennels can refine into narrower sub-kennels.
- Audit infrastructure to make policy decisions inspectable.
- Workload-agnostic policy: the same policy applies regardless of what runs inside the kennel.

Out of scope:

- Kernel changes. Project Kennel uses only what is already upstream.
- Multi-user isolation. Different uids on the same host are handled by Unix permissions.
- Windows or macOS native ports. The threat model may inform them; the implementation is Linux-first.
- Server-side workloads. systemd-nspawn and friends already cover service confinement.
- Network-level defences against host-external attackers.
- Defence against Project Kennel's own dependencies being compromised (Landlock, AppArmor, the kernel itself).

## 3.5 Success criteria

A developer can write or generate a short policy file referencing a vetted template (§5), run their workload inside the corresponding kennel, and have confidence that:

- The workload cannot read credentials, browser data, or other sensitive state outside its granted view.
- The workload cannot connect to arbitrary network endpoints; outbound traffic is mediated, audited, and limited to a declared allowlist.
- The workload cannot reach local services (other ssh-agents, the user's database, dev servers) unless explicitly granted.
- The workload cannot escalate via `sudo`, setuid binaries, or capability-granting interfaces.
- Filesystem writes are confined to the kennel's granted writable paths.
- The workload cannot modify the user's host security configuration (git config, dotfiles outside the project, system configuration).
- The workload cannot read its own policy.
- Every denied operation is logged, structured, and queryable, including pattern-detection for systematic probing.
- The workload cannot widen its own confinement; child processes inherit the same narrowed view.
- The same policy applies unchanged when the developer switches from one tool to another within the same workload class — Claude Code to Codex, Postgres image to Redis image, npm to pnpm.

The developer should reach this posture by writing 5–15 lines of policy, not 800. The primary user-facing artefact is not the policy primitives but the curated templates and the diff tool that surfaces deviations from them.

## 3.6 Failure modes

Project Kennel fails if:

- Users disable confinement because the defaults break their workflow. Mitigation: templates tested against real workflows; permissive variants documented as weaker.
- Users grant capabilities they don't need because the policy language doesn't surface what the deviation means. Mitigation: diff tool with threat-impact surfacing; mandatory `reason` fields.
- Templates drift, lose maintainers, or accumulate cruft. Mitigation: template versioning, signing, sustained maintenance commitment.
- A confinement boundary appears strong but is bypassable. Mitigation: regression test corpus; published threat model; community review.
- Project Kennel's own daemons become a bigger attack surface than the threat they mitigate. Mitigation: namespace isolation of daemons; minimal privileged code; fuzzing.
- The policy language ages worse than the per-tool configs, so users prefer per-tool sandboxes. Mitigation: policy language designed for stability across tool vendors; minimal tool-specific concepts.

Each is a design responsibility. The threat model, the template set, the audit infrastructure, and the documentation must each be built to prevent the corresponding failure mode.
