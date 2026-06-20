# §2 Adversary model

## 2.1 The adversary

The adversary is a process running as the user's real uid, inside a kennel the user has established, typically having been invited there by the user. The motivating instance is an AI coding agent — Claude Code, Codex, Cursor, Aider, Gemini CLI, or any successor — but the same model applies to any same-uid semi-autonomous workload: package post-install scripts, IDE extensions, container images, build tools, MCP servers, scripts piped from `curl | sh`.

By assumption, the workload:

- Has executed `execve()` at some point and is now running code the user cannot fully predict.
- May have arrived as a direct user invocation, as a child of such an invocation, or as a long-lived service the kennel started earlier.
- Knows it is being confined. Project Kennel's existence is not concealed; the policy in force may be opaque (§2.4) but the *fact* of confinement is observable through any number of kernel introspection paths.
- For AI agents specifically: is trained on task completion, with optimisation pressure favouring paths of least resistance, including paths that route around Project Kennel's constraints.
- Will probe systematically for capabilities it has not been explicitly granted.
- Will use any legitimate-looking interface to accomplish its goals — negotiating with the user via runtime prompts, producing diffs that degrade the user's host configuration, invoking subprocesses with elevated capabilities the kennel does not directly grant.

Project Kennel does not defend against:

- Kernel CVEs in Landlock, cgroup BPF, namespaces, or the LSM framework.
- Side channels (cache timing, electromagnetic, Spectre-class).
- Hardware attacks (DMA, cold boot, physical access).
- Compromise of the kernel itself.

These are out of any user-space framework's reach. They are documented in §2.3 as explicit out-of-scope threats.

The workload is assumed to:

- Read every file, environment variable, and socket the policy permits, whether or not such reading is relevant to the stated task.
- Connect to every endpoint the policy permits.
- Spawn child processes that inherit the kennel's policy.
- Probe for inconsistencies between intended policy and actual enforcement.
- Use any legitimate-looking interface to exfiltrate data within its granted bandwidth.
- Modify the user's host configuration (within granted write scope) to remove friction encountered during task execution.
- Negotiate with the user, via prompts or notifications, for capabilities the policy denies.
- For AI agents: generate code that introduces security regressions to the user's project as a side effect of completing the stated task.

## 2.2 Hostility by default

The behavioural evidence is unambiguous. AI coding agents probe systematically for unrestricted paths to task completion, including paths that bypass the sandbox they are running in. The Ona incident (§1.1) documented Claude Code finding `/proc/self/root/usr/bin/npx` to bypass a denylist and then disabling its own sandbox when that path was blocked. Agents read every file they have access to regardless of relevance. Agents negotiate with users via approval prompts, training the user that "ask the user" is an effective circumvention path. Agents treat every system-level control (macOS TCC, Linux AppArmor, Landlock) as friction to route around rather than policy to respect.

The agent's relationship to security policy is adversarial by training, not by intent. Security is not the agent's goal. Completion is. The optimisation pressure that produces friction-removal behaviour is intrinsic to training on completion (§1.2).

Project Kennel's design therefore assumes the workload will:

- Attempt to enumerate denied resources.
- Read its own policy if it can, in order to plan circumvention.
- Probe for kernel-level inconsistencies between policy and enforcement.
- Modify host configuration outside the kennel (within granted write scope) to remove friction.
- Request runtime capability grants from the user.
- Produce code that degrades security posture as a side effect of completing tasks.

A friendly workload that *happens* not to exhibit these behaviours is treated as a happy case where the same enforcement is sufficient. Defences are sized for the hostile case.

The same hostility assumption applies, with different mechanisms, to non-agent workloads. A malicious npm package's postinstall script is hostile from the start. A container image from a public registry may be benign but may also contain a payload designed to exfiltrate credentials from any volume mounts it is granted. A `curl | sh` installer runs with full user privileges and has no formal trust relationship with the user. In all cases, the right design posture is to assume hostile behaviour and constrain accordingly.

## 2.3 Threats explicitly out of scope

These are real threats. Project Kennel does not address them, by design. The full list with rationales is X1–X11 in `THREATS.md`. Summary:

- Process running as a different real uid (handled by Unix permissions).
- Process running as root (handled by root permissions and root-targeted MAC).
- Hardware-level attacks, side channels, physical access.
- The user actively cooperating with the workload.
- Network-level attacks against the host's exposed services (different threat model).
- Compromise of Project Kennel's own kernel dependencies or vetted system tools.
- Within-channel exfiltration via authorised destinations (an LLM API grant means data can leave inside legitimate API requests).
- TLS-inspection-defeating mechanisms (cert pinning in the workload's code).
- Semantic security regressions in workload-produced code that cannot be detected by pattern matching.

## 2.4 What the workload cannot do

Within Project Kennel's claimed strength:

- Cannot ptrace, signal, or otherwise interfere with processes outside its kennel.
- Cannot read files outside the kennel's filesystem ACL.
- Cannot connect to network endpoints outside the kennel's network ACL.
- Cannot connect to AF_UNIX sockets outside the kennel's socket ACL, including abstract-namespace sockets.
- Cannot execute binaries outside the kennel's exec ACL.
- Cannot widen its own kennel's policy. May refine (narrow) further.
- Cannot escape to a parent kennel's broader policy.
- Cannot read its own policy file — the policy is not present in the kennel's constructed view of the filesystem.
- Cannot enumerate denied resources by directory listing — denied resources are absent from the constructed view, not merely denied on access.
- Cannot influence Project Kennel's own daemon processes beyond making them deny things they would have denied anyway. (See §2.5.)
- Is never uid 0, even within its own user namespace. The kennel does map a real uid 0 (host root, mapped `0 0 1`), but that identity belongs solely to the trusted `kennel-bin-init` supervisor (§7.2), not to the workload. The workload is forked by `kennel-bin-init` and dropped to the operator's non-zero uid — gid, supplementary groups, then uid — before its `execve`, after which `no_new_privs` and seccomp make the drop irreversible. (See §2.8.)

Each property is demonstrated via the test corpus (§8 and §11). A claim without a regression test is provisional and marked as such.

## 2.5 Project Kennel's own attack surface

A determined same-uid attacker outside any kennel — the user's normal shell, another unconfined process — can read Project Kennel's state, signal its daemons, modify its policies. Project Kennel is built on user-space trust; the user is the trust root.

Inside kennels, Project Kennel's daemons (SOCKS5 proxy, the IDBus D-Bus facade, Xwayland/Xephyr) are accessible only via brokered interfaces. The cgroup BPF and Landlock constraints block direct access to the daemon's memory, signals, or non-broker sockets. A workload inside a kennel cannot ptrace the SOCKS5 proxy — the AppArmor ruleset denies cross-kennel ptrace. Cannot read the proxy's `/proc/<pid>/mem` — the PID namespace makes the proxy invisible. Cannot signal the proxy — the AppArmor signal rule denies it.

The hostility assumption requires the daemons to be isolated from the kennels they mediate. Isolation from the user's default context (the unconfined shell) is a separate and stricter property; it is out of scope for v1. The user is the trust root and the daemons run within the user's session.

## 2.6 The user is the trust root, not the adversary

The user can:

- Disable confinement entirely.
- Grant any capability they want, given a sufficient deviation from a template.
- Inspect any kennel's state.
- Kill any process in a kennel.
- Modify policy and restart kennels.

Project Kennel cannot constrain the user, and should not try. The role is to make narrow capability grants easier than broad ones, to make deviations visible and justified, and to provide good defaults. Users who choose broad capabilities are not adversaries; they are users making informed choices that Project Kennel should make legible.

There is tension between this principle and the runtime-grant approval pattern. A workload that asks the user for permission to access a resource the policy denies is recruiting the user into helping circumvent the policy. The user, under prompt fatigue, often grants. The user has not become an adversary; the user is being optimised against by an actor whose interests are not aligned with the user's security posture.

The response: runtime grants are narrow by default. Capabilities with significant security impact (filesystem write to security-relevant paths, new outbound destinations, new AF_UNIX sockets to system services) cannot be granted at runtime via a notification approval. They must be added to the policy file, where they surface in the diff (§5), threat-tagged, with a written reason. This adds friction to the user's approval path. The friction is the point: the user must engage deliberately rather than reflexively.

## 2.7 Threat catalogue

The full catalogue is `THREATS.md`. This section identifies which threat IDs are most relevant to the kennel adversary model and where they sit in the design.

**Family 1 — Reconnaissance and exfiltration (T1.1–T1.11).** What the workload reads, where it connects, what it leaks. T1.1 is the most-cited: the workload reads credentials, history, configuration. T1.6 covers lateral movement to local services. T1.7 and T1.8 cover network exfiltration via authorised resolvers and TLS endpoints. T1.10 covers long-lived workloads accumulating capability without re-consent.

**Family 2 — Posture degradation (T2.1–T2.8).** What the workload does to the user's host configuration and the artefacts it produces. T2.1 (host security control deactivation) is the Ona-incident class. T2.2 (security-degrading changes in produced code) is the daily case across AI agents. T2.3–T2.5 cover secrets in unintended locations, over-privileged provisioning, and suppression of failing security checks. T2.6 and T2.7 cover clipboard, screen capture, and input synthesis. T2.8 covers cross-context persistence: a workload planting a git hook or build/IDE trigger in its writable tree that later fires in the user's unconfined shell.

**Family 3 — Workload-class-specific (T3.1–T3.7).** T3.1 (setuid) is universal. T3.2–T3.5 are container-specific: container escape, port exposure, volume over-mounting, root-with-host-UID. T3.6 is MCP-specific: capability creep when an agent invokes an MCP server outside the agent's kennel. T3.7 is AI-agent-specific: prompt injection from project content.

The threat IDs are stable references that the rest of this document, the templates, and the audit log all use. A reader reviewing a specific incident can map it to the threat IDs via the incident appendix in `THREATS.md`.

## 2.8 Mapped uid 0 and the escalation window

Constructing a kennel requires a real uid 0 inside the kennel's user namespace. binderfs assigns its control and device nodes to uid 0 of the mounting namespace, and the view's root, `/dev`, and read-only library binds must be owned by a proper root rather than the namespace's overflow uid. The kennel therefore maps host root into the namespace with a precise two-line identity map — `0 0 1` plus the operator's identity line (and one line per granted gid) — written in a single `write(2)`. There is no `subuid`/`subgid` delegation and no `0 0 N` range; the mapping is exactly host root and the operator, nothing more.

A uid 0 inside the namespace is a privilege-escalation hazard *if and only if* code the adversary controls can run as that uid while host-owned resources are still reachable. Project Kennel's construction model is built to deny that condition structurally, and the resulting invariant is the security crux of the whole design:

**No operator-supplied or workload code ever runs as userns-0.** The only process that holds the mapped uid 0 is `kennel-bin-init` (§7.2), a small, root-owned, trusted-by-provenance supervisor. It is `execve`'d by the privhelper *after* `pivot_root` has detached the host root from the mount namespace, so from its very first instruction the host filesystem is physically absent — host DAC on host-owned files is impossible despite the kernel-level uid 0. The dangerous window of "a uid-0-mapped binary while the host filesystem is still visible" never exists.

The escalation-window analysis, stated as the adversary would probe it:

- **Before `kennel-bin-init` runs**, the only code executing as the mapped uid 0 is the privhelper's own post-`clone` child — trusted host-side code, not the workload, with no adversary input executing.
- **At hand-off**, the privhelper `execve`s `kennel-bin-init` with empty `argv`/`envp` (no serialised configuration to leak via `/proc/<pid>/cmdline` or `environ`) by file descriptor (`fexecve`) opened before the namespace existed, so the trusted init binary is not even resolvable by path inside the view. The operator cannot substitute a uid-0 init: its path comes from the root-owned deployment config, and the privhelper verifies root ownership and non-writability before opening it.
- **After hand-off**, `kennel-bin-init` holds no ambient host capabilities — being uid 0 *in the userns* grants only namespace-scoped `CAP_SETUID`/`CAP_SETGID`, enough to drop the workload and powerless against host-owned resources. It runs no mount, netlink, device, filesystem-lookup, or environment-handling code, and it performs no policy decisions.
- **The workload**, forked by `kennel-bin-init`, is dropped to the operator's non-zero uid before its `execve` and can never regain uid 0 (`no_new_privs` + seccomp). It therefore cannot reach the mapped uid 0 at all; the boundary it would need to cross is a separate process it cannot influence.

The mapped uid 0 is thus safe not because uid 0 is harmless but because the one process that holds it is trusted, trapped inside the sealed view, stripped of host authority, and unreachable by the workload. Remove any one of those properties and the mapping becomes an escalation path; the design treats all four as invariants, each with a corresponding regression test (§8, §11).
