# §1 Problem statement

## 1.1 The Unix uid is no longer a useful trust boundary

The Unix permission model treats the user account as the unit of trust. Every process running as user `u` has, by default, every capability of user `u`: read every file, connect to every network endpoint, talk to every local service, execute every binary, sign with every credential. This model assumes the user is in close control of which processes run on their behalf.

That assumption broke years ago and has now broken loudly. A modern developer routinely invokes processes that nominally serve the user but in practice operate semi-autonomously, with goals and instructions the user did not personally vet:

- AI coding agents that read source, write code, run tests, and call external services.
- Build tools that execute `postinstall` scripts from arbitrary npm/pypi/cargo packages.
- IDE extensions and language servers that scan whole repositories and phone home.
- Installers fetched via `curl ... | sh` from URLs that may or may not be what the user typed.
- Long-lived development daemons that accumulate capability over months without re-consent.

Each of these runs as the user's uid. Each has, by default, full access to the user's SSH keys, GPG keys, browser cookies, password manager database, cloud credentials, source repositories, email archives, and every other piece of state the user has accumulated. None of them needs that access for the task the user actually asked them to perform.

The user did not consent to this capability grant. The user consented to "help me refactor this function" or "install this package". The system granted "everything you, the human, can do".

## 1.2 Why this matters now

The threat is not new in principle. Same-uid malware has existed as long as multi-user systems. What is new is the *normalisation* of high-capability, semi-autonomous processes in the developer's daily workflow. The base rate of "untrusted code running as me on my workstation" has gone from "occasionally, when I make a mistake" to "constantly, by design".

The mitigation infrastructure has not kept pace. The available primitives — Linux capabilities, namespaces, Landlock, AppArmor, SELinux, seccomp — exist and work, but they are spread across kernel subsystems, lack a common policy language, and require expertise to apply correctly. The desktop-application sandbox story (Flatpak, snap) is mature; the command-line and developer-workflow story is essentially absent.

The result: developers have no usable mechanism for saying "this process gets a narrow slice of my account's capabilities" while continuing to work normally. The choice is between "give the AI agent everything" and "don't use AI agents". Most developers pick the first, because the second is incompatible with their job.

## 1.3 What this document is

A specification for a per-process-group capability confinement layer that sits between an LXC container and a BSD jail in cost, scope, and trust model. The goal is to provide developers with a usable mechanism for running same-uid-but-untrusted processes in narrowed contexts, with a policy language that's writable, a default-deny posture that's structural, and a defaults set (templates) that's defensible.

The mechanism is built from existing kernel primitives: Landlock, cgroup BPF, mount namespaces, seccomp, and optionally AppArmor. No kernel changes. The work is in the user-space glue, the policy language, the template set, and the threat-modelling discipline.

## 1.4 What this document is not

- Not a container runtime. No image format, no separate root filesystem unless the user opts in. No init.
- Not a desktop-application sandbox. Flatpak and snap cover that case adequately. This is for command-line and developer workflows.
- Not a substitute for root-level mandatory access control (system-wide SELinux/AppArmor). Complementary; can coexist.
- Not a defence against the user actively cooperating with the adversary. If the user grants a capability on demand, the framework cannot prevent its misuse.
- Not a defence against kernel exploits, LSM bypasses, side channels, or hardware-level attacks.
- Not a substitute for not running untrusted code. Defence in depth, not perfect isolation.

## 1.5 Scope

In scope:

- A Linux user-space tool, here referred to as "the framework".
- Same-uid threat model (one human user; some processes trusted, others not).
- Interactive developer workflows: shells, AI agents, builds, repo inspection.
- Composable confinement (contexts can refine into narrower sub-contexts).
- Audit infrastructure to make policy decisions inspectable.

Out of scope (separately worthwhile projects, possibly downstream):

- Kernel changes. The framework uses only what is already upstream.
- Multi-user isolation. Different uids on the same host are handled by existing Unix permissions.
- Windows or macOS native ports. The threat model may inform them; the implementation is Linux-first.
- Server-side workloads. systemd-nspawn and friends already cover service confinement.
- Network-level defences against host-external attackers.
- Defence against the framework's own dependencies being compromised (Landlock kernel code, AppArmor, etc).

## 1.6 What success looks like

A developer can write or generate a short policy file referencing a vetted template, run their AI coding agent inside the corresponding context, and have confidence that:

- The agent cannot read their SSH keys, GPG keys, browser data, or other credentials.
- The agent cannot connect to arbitrary network endpoints; outbound traffic is mediated, audited, and limited to a declared allowlist.
- The agent cannot reach local services (other ssh-agents, the user's database, dev servers) unless explicitly granted.
- The agent cannot escalate via `sudo`, setuid binaries, or capability-granting interfaces.
- The agent's filesystem writes are confined to the project tree plus a private tmpfs.
- Every denied operation is logged, structured, and queryable.
- The agent cannot widen its own confinement; child processes inherit the same narrowed view.

The developer should reach this posture by writing 10–30 lines of policy, not 800. The framework's primary user-facing artefact is not the policy primitives but the curated templates and the diff tool that surfaces deviations from them.

## 1.7 What failure looks like

The framework fails if any of the following occurs:

- Users disable confinement because the defaults break their workflow.
- Users grant capabilities they don't need because the policy language doesn't surface what the deviation means.
- Templates drift, lose maintainers, or accumulate cruft that nobody understands.
- A confinement boundary appears strong but is bypassable by a well-known mechanism that the framework didn't account for.
- The framework's own daemon (proxy, dbus-proxy, etc) becomes a bigger attack surface than the threat it mitigates.

Each of these is a design responsibility. The threat model, the template set, the audit infrastructure, and the documentation must each be built to prevent the corresponding failure mode.
