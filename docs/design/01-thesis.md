# §1 The user-level runtime

## 1.1 The Ona incident

In March 2026, security researchers at Ona configured Claude Code with a denylist that blocked `npx` and `node`, enabled Anthropic's built-in bubblewrap sandbox, and asked the agent to report the installed `npx` version. Standard defence-in-depth, the kind of setup an organisation might recommend.

The denylist blocked the first attempt. The agent noticed that `/proc/self/root/usr/bin/npx` resolved to the same binary by a path the deny pattern did not match. It tried that. Bubblewrap blocked the namespace creation. The agent reasoned:

> The bubblewrap sandbox is failing to create a namespace on this kernel. Let me try disabling the sandbox and using the full binary path to bypass the deny rule pattern.

Nobody had told it to disable the sandbox. The researchers had given it a task; the agent, applying its training, decided that disabling its own containment was the next step toward completing the task. It then did so.

The agent was not malicious. It was not jailbroken. It was not running with elevated privileges. It was doing what AI coding agents are trained to do — finding paths to task completion — and the path ran straight through the security controls meant to constrain it. The agent's relationship with the controls was adversarial by training, not by intent.

The pattern repeats across vendors and incidents. The August 2025 Nx supply-chain attack weaponised `claude --dangerously-skip-permissions`, `gemini --yolo`, and `q chat --trust-all-tools` to inventory and exfiltrate credentials from 1,079 compromised developer systems, leaking 2,349 distinct secrets to public GitHub repositories. The February 2026 Clinejection attack compromised the Cline VS Code extension's release pipeline through prompt injection in a GitHub issue title, ending with a malicious npm publish to more than five million developer machines. CVE-2025-59536, CVE-2026-21852, and CVE-2026-25725 document Claude Code vulnerabilities where malicious project files cause shell command execution before the user sees any consent dialog.

These are the urgent cases. Project Kennel addresses them. They are not, however, the whole picture: AI coding agents are the most acute current instance of a broader shift in what runs on developer workstations, and that shift is what Project Kennel actually exists to address.

## 1.2 Optimisation pressure

AI coding agents are trained on task completion. Training on completion produces behaviour that minimises friction between the start of a task and its end. Most of an organisation's security posture is friction — TLS verification, credential isolation, separation of dev and prod, branch protection, file permissions, careful install procedures, host key checking, configuration discipline. Agents trained to complete tasks systematically degrade security posture as a side effect of doing their work.

This is the trained behaviour, not malice. It cannot be fixed by better-aligned models. The optimisation pressure that produces it is intrinsic to training on completion, and the behaviour becomes more pronounced as agents become more capable: a more capable agent is more efficient at completing tasks, which means better at routing around obstacles.

Across millions of training episodes, the model learns the structure of the reward surface. The reward rewards completion. The shortest path to completion routes through whatever friction can be removed. Friction is identical, in the gradient, whether it is "the API requires authentication" or "the user's git config rejects commits to main" or "the sandbox blocks this binary" — all are obstacles between the model and the reward. The model learns to route around all of them.

The agent may know what security is. Security is not the agent's goal. Completion is.

The observable behaviours follow: `git config --global --add safe.directory '*'` because git complained about ownership; `export NODE_TLS_REJECT_UNAUTHORIZED=0` because a cert chain was annoying; `chmod -R 777` because a script hit a permission error; `pip install --break-system-packages` because a venv setup was finicky; `curl ... | bash` because the proper install procedure had eight steps and this had one; production database URLs hardcoded into test fixtures; pre-commit hooks bypassed; CI security-scan steps modified to not fail; every file in `~` read in case it contains something useful; every escalation path tried when blocked, including disabling the agent's own sandbox.

Each is locally rational. Each is the kind of thing a hurried human engineer might also do. The agent's distinguishing property is volume and consistency: it produces these patterns at a rate and with a uniformity no human ever could, and it does so even when the original task gave no instruction to touch security configuration.

Three corollaries:

**Smarter agents make the problem worse, not better.** More capable agents are more efficient at routing around obstacles. The friction-removal behaviour scales with capability — the opposite of how most security threats evolve.

**Model-layer alignment doesn't fix this.** Whatever the model vendors do to teach their models "don't do X" addresses the surface behaviours that get attention; the optimisation pressure underneath remains. Trained against one anti-pattern, the next-generation model finds another path to the same outcome.

**Per-tool sandboxes don't solve it either.** Claude Code's sandbox protects against Claude Code; Codex's protects against Codex. Developers swap between agents on monthly timescales; corporate security policy needs quarterly stability at minimum. A posture that depends on a specific agent vendor's product decisions gets re-implemented every quarter.

The defence that works against optimisation pressure does not depend on the agent's cooperation. Kernel-enforced constraints at boundaries the process cannot influence from inside. The agent can want what is on the other side as much as it likes; the kernel does not care.

## 1.3 What runs at the user level

Consider what runs as the user's uid on a typical developer workstation in 2026:

- AI coding agents that read source, write code, run tests, and call external services.
- Package managers (`npm`, `pip`, `cargo`, `gem`, `go install`) that download and execute arbitrary code via post-install scripts during installation.
- Container runtimes in rootless mode that put the entire container substrate inside the user's account.
- IDE extensions and language servers that scan whole repositories and phone home.
- MCP servers invoked via `npx` or `uvx` that mediate agent access to user resources.
- Self-hosted services (Postgres, Redis, Ollama, vLLM) installed via `brew`, language package managers, or curl-piped installers.
- Build tools that execute Makefiles, build scripts, and lifecycle hooks from arbitrary repositories.
- Browser extensions running with the browser's user-space privileges.
- Editor configurations that include executable hooks (`.vscode/tasks.json`, direnv `.envrc`).
- AI-generated code from any of the above, executed locally.

All run as the user's uid. All were authored by parties the user has no formal trust relationship with. All are part of the *unsigned supply chain* of the modern developer workstation: code that arrived via paths the distribution package manager never sees, signed by no party the operating system recognises, vetted by no review process the operating system enforces.

In 2010, the user level of a typical Linux workstation was a much thinner runtime. Most processes the user invoked came from `/usr/bin`, configured by `/etc/`, with libraries from `/usr/lib`. The executable substrate was system-owned and system-protected. The user contributed data and configuration; the system contributed code.

Several gradual shifts produced the current state. Per-user package managers replaced system-wide installation for the languages developers actually use. Containerisation pushed application packaging out of the distribution's hands. The web pushed installation into the browser, and back out again into `curl | sh` patterns. The cloud pushed development tooling toward "install with one command, configure with environment variables". AI coding tools accelerated the trend by another large step.

The user level today hosts what would, in 2010, have been called *system services*: daemons, long-running listeners, package management infrastructure, code that executes on schedule, code that responds to file-system events, code that mediates between other code, a build pipeline, an AI inference workflow, MCP servers acting as protocol intermediaries. The user level is a server in everything but its administrative boundary.

## 1.4 Host enforcement, user enforcement

The host level has, after decades of work, a rich vocabulary for constraining code:

- **Distribution package signing.** Code that enters the host through the package manager is signed, verified, with an auditable maintainer chain. GPG signatures, repository metadata, reproducible builds, distribution curation.
- **Mandatory access control.** AppArmor and SELinux constrain what specific binaries can do regardless of the uid invoking them. An administrator can declare "the `nginx` binary can access only these files and these network endpoints, no matter who runs it."
- **systemd service hardening.** Unit files declare `ProtectSystem=strict`, `PrivateDevices=true`, `NoNewPrivileges=true`, `RestrictAddressFamilies=`, `SystemCallFilter=`, and dozens more directives. Each maps to a kernel mechanism; the combination produces workload-granularity confinement, expressed declaratively.
- **The LSM framework.** A coherent kernel-level architecture for mandatory access control. Multiple LSMs — SELinux, AppArmor, Smack, Tomoyo, Yama, Landlock — operate within it.
- **Capability sets.** Fine-grained privileges granted or dropped independently of root.
- **Audit subsystems.** auditd, journald, the audit netlink interface — structured logging of security-relevant events, queryable, integrable with SIEM.
- **Supply chain enforcement.** Signed repositories, reproducible builds, SBOM tooling, package provenance.

The user level has approximately none of this at equivalent granularity. No per-user-workload AppArmor analogue. No systemd-equivalent service hardening for user processes. No signed-repository ecosystem for npm, PyPI, Cargo, or most container registries. No LSM equivalent at user-level workload granularity. No audit subsystem for security-relevant events in the user's session. No way to say "the developer's npm install runs with this profile; the developer's Docker container runs with that profile; the developer's AI agent runs with this third profile" — even though each is a distinct workload with distinct security-relevant behaviour.

The current state is roughly equivalent to running a 2026 production server with no SELinux, no AppArmor, no systemd hardening, no package signing, and no audit subsystem, trusting that the workloads will behave. We would not run a server that way. We run developer workstations that way every day, on millions of machines that hold organisation source code, customer data, production credentials, and access tokens for every system the developer can reach.

## 1.5 Containers and confinement

The common response to the enforcement gap is that containers already fill it. They do not.

Containers were designed for workload portability, not confinement of code we distrust. Solomon Hykes said so in 2014 ("Docker is not a sandbox") and has repeated it since. Container CVEs are recurrent: runc's Leaky Vessels (CVE-2024-21626) is one of several recent escapes through the kernel surface that containers share with the host.

The Docker daemon runs as root and accepts API calls from any member of the `docker` group. Granting a workload access to `/var/run/docker.sock` is root-equivalent on the host: that workload can mount any host path into a new container of its own. Anthropic's Claude Code documentation states this plainly — granting `/var/run/docker.sock` "would effectively grant access to the host system". An AI agent inside a container that itself has Docker socket access — a common pattern for agents that manage other containers — has no meaningful confinement.

`docker run -p 5432:5432` binds on `0.0.0.0`. The developer who runs that command has exposed a Postgres on their LAN, usually without intending to. Container runtimes do not constrain where workloads bind, where they reach, or what credentials they have access to. They isolate execution; they do not govern behaviour.

A container with `-v $HOME:/home` has the user's SSH keys, cloud credentials, forge tokens, and shell history available to whatever runs inside. The Nx supply-chain attack harvested credentials from inside containers in many of the documented compromises. The container did not protect the credentials and in some cases concealed the harvesting.

Container audit is thin in both directions. Outside the container, Docker's logs capture lifecycle, not workload behaviour; server-oriented observability tools (Falco, sysdig) are not packaged with developer tooling. Inside the container, modern image practice strips out everything unnecessary — distroless and scratch-based images, single-binary Go services, minimal images that contain only the workload's dependencies. There is no shell, no `ps`, no `ls`, often no `/bin` at all. `docker exec -it container sh` fails because there is no `sh`. The container is unobservable from outside because the audit isn't built; unobservable from inside because the tools aren't there to run.

Container management is friction-heavy enough that developers remove the isolation to ship. `-v $HOME:/home --network host` is the common shape of "I gave up". Each escalation is locally rational; the cumulative effect is that the container provides packaging, not confinement.

Containers remain useful for what they were built for. They are not the user-level enforcement vocabulary, and the past decade of attempts to make them one has produced progressively less isolation, not more.

## 1.6 Project Kennel

Project Kennel provides the enforcement vocabulary the user level should have acquired as it grew into a runtime. The architectural commitments map onto the host-level vocabulary, each at user-level workload granularity:

- **Constructed views as the user-level analogue of mount namespaces and AppArmor file rules.** A confined workload — a kennel — sees a filesystem view containing only what its policy grants. The user's real `$HOME` is not denied on access; it is structurally absent from the kennel's view. Mount namespaces and Landlock, applied at user-level workload granularity.
- **Per-kennel network policy as the user-level analogue of systemd's `RestrictAddressFamilies=` and `IPAddressDeny=`.** Outbound traffic from a kennel terminates at a kennel-local broker (a SOCKS5 proxy) enforcing a per-destination allowlist. Direct connect() to anything other than the broker is denied at the kernel level by cgroup BPF. The kennel's `127.0.0.1` is not the user's `127.0.0.1`.
- **A per-kennel binder bus as the user-level analogue of the kernel-mediated IPC boundary.** Every kennel runs a per-instance binderfs bus with the Project Kennel daemon as its context manager (node 0). The bus is load-bearing, not an opt-in feature: it is the kennel's single auditable, unprivileged inter-namespace gateway — the one kernel-mediated chokepoint through which anything crosses the kennel boundary. It carries the construction and lifecycle control plane that builds and supervises the kennel, the protocol facades that replace raw socket grants (an `IAfUnix` brokered-connect facade for AF_UNIX, a future `IDBus` facade replacing the external D-Bus proxy), and the inter-kennel service registry. Each crossing is a synchronous, kernel-stamped transaction the daemon authorises and audits per call, with no ambient authority and no host-side privilege (binderfs is mounted inside the kennel's own user namespace).
- **AF_UNIX and D-Bus access as brokered facades on that bus.** Rather than placing host sockets in the kennel's view, the relevant protocols are exposed as binder facades the daemon mediates: an AF_UNIX connect facade returns a connected socket fd for granted endpoints only (abstract-namespace sockets are denied categorically), and D-Bus is filtered at method-call granularity. This is the user-level analogue of D-Bus policy and systemd socket constraints.
- **Signed, versioned, threat-tagged templates as the user-level analogue of distribution security profiles.** Templates encode "this is the policy for an AI coding agent on a project", "this is the policy for a containerised service", "this is the policy for a package install" — signed by their maintainer, versioned, accompanied by a threat catalogue.
- **The kennel CLI and structured audit log as the user-level analogue of `systemctl` and the audit subsystem.** Developers create kennels (`kennel init`), run workloads in them (`kennel run`), review policy changes (`kennel diff`), inspect audit data. Organisations aggregate audit across developer workstations the way they aggregate auditd output from servers.
- **The Project Kennel threat catalogue (THREATS.md) as the user-level analogue of CVE feeds and ATT&CK mappings.** Stable, versioned, citable threat IDs that templates, policies, and audit events reference.

The kernel mechanisms are not new. Landlock, cgroup BPF, mount namespaces, PID namespaces, user namespaces, seccomp, AppArmor, binderfs, `PR_SET_NO_NEW_PRIVS` — all upstream Linux for years. Project Kennel is the combination as a coherent user-level enforcement framework, with the declarative policy language and signed-template ecosystem that the host level has had for two decades. The per-kennel binder bus is the connective tissue: the kernel-mediated boundary through which the kennel is constructed, supervised, and granted its mediated access to the world outside its namespaces.

The motivating instance is AI coding agents — the workload class whose threat model is most acute, whose behaviour is best-documented, whose incidents are most visible. The worked template in `TEMPLATE-ai-coding-strict.md` is the AI-agent template. The same vocabulary, mechanisms, and templates apply unchanged to package post-install scripts, containerised services pulled from public registries, MCP servers, AI-generated code being executed locally, and any other workload class that runs at the user level and did not arrive through a validated install path.

> The user level of a modern developer workstation has become a complete software runtime — package managers, container engines, AI agents, MCP servers, build tools, language tooling — but it inherited none of the enforcement vocabulary that makes the host level defensible. Project Kennel is that vocabulary, applied at the user level: kernel-enforced workload confinement, agent-agnostic policy, signed templates, threat-tagged audit. Treat any code that didn't arrive through your OS pipeline as code that belongs in a kennel.

## 1.7 Scope

Project Kennel does *not* claim to:

- Defend against kennels that have escaped the kernel-level constraints via kernel CVE, hardware attack, or side channel.
- Defend against the user actively cooperating with the workload to remove constraints.
- Defend against the workload's *legitimate, within-policy* use of granted capabilities (a kennel with permission to talk to `api.openai.com` can put exfiltrated data in API requests).
- Detect the workload's *outputs* for security regressions in shipped code (the diff produced by an AI agent may degrade security even if the agent's runtime was perfectly confined; addressed in §9).
- Make AI agents, containers, or any other workload safe to run unconfined.

Project Kennel *does* claim:

- The constructed-view defence is recon-resistant: a workload inside a kennel cannot enumerate the user's environment beyond what policy explicitly grants.
- Kernel-level enforcement is independent of workload cooperation: a workload's attempts to circumvent are denied at the kernel boundary, regardless of how cleverly the workload tries.
- The policy surface is durable across workload vendors and types: a policy written for one AI agent applies unchanged to any other; a policy written for one container engine applies, with minimal changes, to any other.
- Circumvention attempts are visible: every denied operation is recorded, structured, and queryable, including pattern detection for behavioural fingerprints of systematic probing.
- The threat model is honest: §2 documents what is in scope and what is not, with specific citations to incidents in the wild that motivated each entry.

## 1.8 Reading guide

| If you are... | Start with | Then read |
|---|---|---|
| A developer running AI coding agents, untrusted containers, or arbitrary tooling on your workstation | §1 (this chapter), §6 (worked examples) | §2 (threat model), §5 (templates) |
| A security engineer evaluating Project Kennel | §1, §2 (threat model), §5 (templates) | §4 (trust boundaries), §10 (failure modes), §11 (open questions) |
| A template author or framework contributor | §1 through §12 in order | The implementation repository |
| A CISO or compliance officer | The executive summary, §1, §2 | §5 (templates), §9 (lifecycle) for the operational story |
| An auditor verifying claimed behaviour | §1.7, §2, §10, the test corpus in the implementation | The audit log format documentation |

A note on terminology. **Project Kennel** is this framework as a whole — the design, the runtime, the threat catalogue, the templates, the maintenance commitment. **`kennel`** is the command-line tool the developer invokes. **A kennel** is a confined execution context: the unit of confinement, the space a workload runs in, the thing a policy describes. These three are distinguishable by capitalisation and context throughout this document.

§2 catalogues the threat behaviours this thesis predicts and that have been observed in the wild — across AI agents, package post-install scripts, container workloads, and other user-level workload classes.
