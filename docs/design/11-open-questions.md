# §11 Open questions and out-of-scope topics

## 11.1 Open questions for v2

**Wayland clipboard.** Even on Wayland, a kennel's window can read and write the user's clipboard via standard Wayland protocols. Some compositors offer per-client clipboard policies; support is uneven. Project Kennel does not currently enforce clipboard policy at the Wayland layer. Open question: what is the minimum viable cross-compositor mechanism for clipboard isolation, and is it worth depending on?

**GPU access nuances.** The current GPU grant (§7.9.9) is binary: either the kennel has `/dev/nvidia*` etc. or it doesn't. Real workflows want finer control: "this kennel can compute on the GPU but cannot read the framebuffer of other GPU users". The kernel's GPU drivers offer some primitives (GEM handles, DRM lease) that could plumb into a finer policy. Open question: what does a useful "GPU compute only" policy look like, and is it expressible without driver-specific code?

**TPM and FIDO access policy.** Currently Project Kennel grants device-level access (`/dev/tpmrm0`, `/dev/hidraw*`) and trusts the userspace stack to enforce per-key or per-credential policy. Open question: should Project Kennel interpose at a higher level (the PKCS#11 socket, the FIDO HID protocol) to enforce per-key per-kennel bindings? This is significant engineering for marginal benefit, but the use case (per-kennel FIDO unlock for per-kennel ssh-agents) is exactly the motivating workflow.

**Syscall filtering as primary mechanism.** Some confinement frameworks (Firejail, Bubblewrap) use seccomp as their primary mechanism. Project Kennel treats seccomp as defence-in-depth (§7.9.6). Open question: should an "extra-strict" template family use comprehensive seccomp filters as a primary defence, accepting the brittleness and compatibility cost?

**Stricter daemon isolation from the default context.** A kennel reaches the services Project Kennel runs on its behalf only through the binder gateway, and lives in its own user, mount, PID, and IPC namespaces — so a kennel cannot `ptrace`, signal, or `/proc`-inspect those host-side components. They remain reachable, however, by same-uid processes in the *default context* (the user's normal shell), which is the user's own trust root. A stricter mode that isolates the daemons even from the default context is open for users who want stronger protection against same-uid attacks they might inadvertently introduce.

**Server vs per-kennel mediators.** Each kennel has its own egress proxy and other per-kennel mediators. For users with many kennels, this is many processes. An alternative: shared mediators with per-kennel credentials and policy lookup. Pros: fewer processes, lower memory. Cons: a shared mediator is a shared attack surface; its compromise affects all kennels. Open question: at what number of kennels does sharing make sense, and what is the right abstraction?

**Compositor-level Wayland mediation.** A future direction: Project Kennel's per-kennel grant for Wayland goes through a compositor-aware proxy that filters Wayland protocol messages. Mature proposals exist (e.g. the security-context-v1 protocol). Open question: when does compositor support reach "good enough" to depend on, and what does Project Kennel's policy surface look like for compositor-mediated access?

**Post-run inspection of persistent writes.** This is the intended primary control for T2.8 (cross-context persistence via workspace triggers, THREATS.md), and it is deliberately not in the first release. A workload with legitimate write access to its project tree can plant a git hook, redirect `core.hooksPath` into the writable tree, or add a build/IDE task that later fires in the user's *unconfined* shell; filesystem policy closes this only partially, because the build and IDE files that carry triggers must stay writable for the agent to function. The capability: at kennel teardown, diff everything the workload wrote to the persistent writable binds against the pre-run state and flag newly-introduced *execution triggers* — hook files, `core.hooksPath` changes, `Makefile`/`package.json` script entries, `.vscode`/`.idea` task definitions — for operator review before the user next acts on the tree. This is broader than the commit-time `kennel review` of T2.2 / design §9: persistence can be planted without ever passing through a git commit, so the inspection must run on the raw written file set, not the git diff. Open questions: the canonical set of "execution trigger" patterns to flag and how to keep it current as toolchains evolve; how to scope the diff cheaply for large trees (writable binds resolve to persistent host inodes, so a naive full re-scan is the fallback); whether inspection blocks at teardown or produces a reviewable report the user must acknowledge; and how it composes with the commit-time review so the two are one coherent `kennel review` surface rather than two tools.

## 11.2 Explicitly out of scope

The following are not in scope for any planned version of Project Kennel:

**Kernel-level CVE defence.** Project Kennel assumes kernel correctness for the features it relies on. A Landlock bypass via a kernel CVE defeats Project Kennel's filesystem confinement. Mitigation is at the kernel-update level, not Project Kennel level.

**Side-channel defence.** Cache timing, electromagnetic emanation, Spectre-class attacks, microarchitectural side channels. Project Kennel offers no defence; these are out of any user-space tool's reach.

**Hardware attacks.** Cold boot, DMA, peripheral compromise, firmware-level attacks. Out of any user-space tool's reach.

**Physical access.** The user's threat model does not include "an attacker has physical access to the workstation". Mitigations for that case are at the disk-encryption, boot-security, and physical-security layers.

**Network-level inbound attacks.** Project Kennel defends *what the kennel can do outbound*. Inbound attacks against host-exposed services (the host running an exposed SSH or web service) are a different threat model with different mitigations (firewalls, fail2ban, host hardening).

**Multi-user isolation.** Different uids on the same host are isolated by existing Unix permissions. Project Kennel adds nothing.

**Same-uid attacks against Project Kennel itself, from the default context.** A process in the user's default context (the unconfined shell) can read Project Kennel's state, signal its daemons, modify its policies. Project Kennel is built on user-space trust; the user is the trust root. Cross-kennel isolation of daemons (so kennels cannot attack Project Kennel's daemons) is built in; isolation from the user's default context remains a stricter-mode open question per §11.1.

**Anti-AI-agent measures.** Project Kennel treats AI agents as one class of workload subject to the catalogue's threats. It does not specifically detect or counter agent-like behaviour (LLM API patterns, agent-typical syscall sequences). The mechanism is the same whether the workload is an AI agent, a container, or a script; the threat model is mechanism-based, not actor-based.

**Defence against compromised vetted dependencies.** If `xdg-dbus-proxy`, `Xephyr`, the kernel's Landlock implementation, or other building blocks are themselves compromised, Project Kennel's guarantees are compromised. Project Kennel assumes its building blocks are sound (THREATS.md X7, X8).

**Cross-host enforcement.** A kennel on host A and a kennel on host B are not aware of each other. Project Kennel is per-host.

**Encryption of audit logs.** Project Kennel writes audit logs as plain JSONL. At-rest encryption is the user's responsibility (full-disk encryption, encrypted home directory). Project Kennel does not encrypt its own logs.

**Mandatory enforcement.** Project Kennel cannot prevent a user with full access to their own files from editing policies, disabling enforcement, or bypassing Project Kennel entirely. Mandatory enforcement is at a different administrative layer.

## 11.3 In scope, despite appearances

**Multi-kennel coordination.** Kennels can be configured to share specific resources (a filesystem path, a unix socket). This is in scope because Project Kennel explicitly defines the constructed views, and a shared path is a view that overlaps between two kennels. Not all "communication" is therefore out of scope; deliberate, policy-declared communication is supported.

**User-mediated capability grants.** Templates allow capabilities granted via portal dialogs (file picker, screenshot). The user mediates each grant. This is in scope and is the recommended pattern for capabilities that need human-in-the-loop.

**Long-lived background kennels.** A kennel need not be tied to an interactive command. Background services (a watcher, a periodic build) can run in a kennel indefinitely (subject to TTL and re-consent policies). In scope.

**Composition with container runtimes.** Containers (Docker, Podman) inside a kennel are supported with caveats. The container daemon socket grant is a significant capability (T3.2); the container itself is unconstrained by Project Kennel beyond the kennel's policy. Documented in the `containerised-service` and `containerised-tool` templates.

## 11.4 Roadmap caveats

These open questions are tracked, not scheduled. Project Kennel's actual roadmap depends on:

- User feedback (which templates need expansion, which residuals matter in practice).
- Kernel evolution (new Landlock features, new BPF hooks).
- Adversary evolution (how AI agents and supply-chain attacks shift over time).
- Maintainer capacity.

None of these open questions has a committed delivery date in v1. v2 will pick a small number to address; the rest carry forward.
