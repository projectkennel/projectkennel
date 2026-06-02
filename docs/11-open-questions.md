# §11 Open questions and out-of-scope topics

## 11.1 Open questions for v2

**Wayland clipboard.** Even on Wayland, a kennel's window can read and write the user's clipboard via standard Wayland protocols. Some compositors offer per-client clipboard policies; support is uneven. Project Kennel does not currently enforce clipboard policy at the Wayland layer. Open question: what is the minimum viable cross-compositor mechanism for clipboard isolation, and is it worth depending on?

**GPU access nuances.** The current GPU grant (§7.7.9) is binary: either the kennel has `/dev/nvidia*` etc. or it doesn't. Real workflows want finer control: "this kennel can compute on the GPU but cannot read the framebuffer of other GPU users". The kernel's GPU drivers offer some primitives (GEM handles, DRM lease) that could plumb into a finer policy. Open question: what does a useful "GPU compute only" policy look like, and is it expressible without driver-specific code?

**TPM and FIDO access policy.** Currently Project Kennel grants device-level access (`/dev/tpmrm0`, `/dev/hidraw*`) and trusts the userspace stack to enforce per-key or per-credential policy. Open question: should Project Kennel interpose at a higher level (the PKCS#11 socket, the FIDO HID protocol) to enforce per-key per-kennel bindings? This is significant engineering for marginal benefit, but the use case (per-kennel FIDO unlock for per-kennel ssh-agents) is exactly the motivating workflow.

**Syscall filtering as primary mechanism.** Some confinement frameworks (Firejail, Bubblewrap) use seccomp as their primary mechanism. Project Kennel treats seccomp as defence-in-depth (§7.7.6). Open question: should an "extra-strict" template family use comprehensive seccomp filters as a primary defence, accepting the brittleness and compatibility cost?

**Stricter daemon isolation from the default context.** Project Kennel's daemons (SOCKS5 proxy, xdg-dbus-proxy, per-kennel ssh-agent, Xwayland/Xephyr) are isolated from the kennels they mediate via PID namespace and AppArmor rules denying cross-kennel ptrace, signal, and `/proc/<pid>` access. They remain accessible to same-uid processes in the default context (the user's normal shell). A stricter mode that isolates daemons even from the default context is open for users who want stronger protection against same-uid attacks they themselves might inadvertently introduce.

**Per-kennel user IDs via subuid/subgid.** The current design keeps everything as the user's real uid. An alternative: allocate each kennel its own uid from the `/etc/subuid` range, run the kennel's processes as that uid. This gives kernel-level uid-based isolation as well as Project Kennel's policy-level isolation.

The trade-offs are significant. Pros:
- Filesystem ACLs become an additional layer (the kennel's uid cannot access the user's uid-owned files by virtue of uid permission alone).
- Some kernel APIs (signal delivery, ptrace) become naturally restricted.
- Resource accounting per kennel becomes precise.

Cons:
- File ownership becomes complicated. Writes from the kennel land in `~/projects/foo/` owned by a different uid; the user's normal shell sees files it can read but not write without permission gymnastics.
- The user's process management (kill, ps, etc) no longer "just works" across kennels.
- The mental model becomes more complex; Project Kennel's centre of gravity shifts from "narrowed view of user's uid" to "running as a different user".
- Setup requires `/etc/subuid` configuration, which is a different administrator concern.

This is the most significant open question in scope expansion. v1 explicitly does not do this. v2 might, behind an opt-in flag, for users who want stronger isolation and can accept the complexity. The threat model's "same-uid is no longer the trust boundary" claim is honoured by v1's mechanism-based isolation; subuid would be additional defence in depth.

**Server vs per-kennel proxies.** Currently each kennel has its own SOCKS5 proxy and dbus-proxy. For users with many kennels, this is many daemons. An alternative: shared proxies with per-kennel credentials and policy lookup. Pros: fewer processes, lower memory. Cons: shared proxy is shared attack surface; compromise of the proxy affects all kennels. Open question: at what number of kennels does shared make sense, and what's the right abstraction?

**TLS inspection as a first-class feature.** Project Kennel's SOCKS5 proxy could optionally MITM TLS connections, install a per-kennel CA in the kennel's trust store, and log full request contents. Pros: addresses T8 (exfil via allowed API) directly. Cons: significant complexity, breaks any TLS-pinning client, CA management is non-trivial, half the modern internet doesn't accept arbitrary CAs anyway. Open question: is there a useful subset of TLS inspection (logging SNI and connection metadata, but not contents) that is cheap and useful?

**Compositor-level Wayland mediation.** A future direction: Project Kennel's per-kennel grant for Wayland goes through a compositor-aware proxy that filters Wayland protocol messages. Mature proposals exist (e.g. the security-context-v1 protocol). Open question: when does compositor support reach "good enough" to depend on, and what does Project Kennel's policy surface look like for compositor-mediated access?

**Post-run inspection of persistent writes.** This is the intended primary control for T26 (cross-context persistence via workspace triggers, THREATS.md), and it is deliberately not in the first release. A workload with legitimate write access to its project tree can plant a git hook, redirect `core.hooksPath` into the writable tree, or add a build/IDE task that later fires in the user's *unconfined* shell; filesystem policy closes this only partially, because the build and IDE files that carry triggers must stay writable for the agent to function. The capability: at kennel teardown, diff everything the workload wrote to the persistent writable binds against the pre-run state and flag newly-introduced *execution triggers* — hook files, `core.hooksPath` changes, `Makefile`/`package.json` script entries, `.vscode`/`.idea` task definitions — for operator review before the user next acts on the tree. This is broader than the commit-time `kennel review` of T13 / design §9: persistence can be planted without ever passing through a git commit, so the inspection must run on the raw written file set, not the git diff. Open questions: the canonical set of "execution trigger" patterns to flag and how to keep it current as toolchains evolve; how to scope the diff cheaply for large trees (writable binds resolve to persistent host inodes, so a naive full re-scan is the fallback); whether inspection blocks at teardown or produces a reviewable report the user must acknowledge; and how it composes with the commit-time review so the two are one coherent `kennel review` surface rather than two tools.

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

**Composition with container runtimes.** Containers (Docker, Podman) inside a kennel are supported with caveats. The container daemon socket grant is a significant capability (T20); the container itself is unconstrained by Project Kennel beyond the kennel's policy. Documented in the `containerised-service` and `containerised-tool` templates.

## 11.4 Roadmap caveats

These open questions are tracked, not scheduled. Project Kennel's actual roadmap depends on:

- User feedback (which templates need expansion, which residuals matter in practice).
- Kernel evolution (new Landlock features, new BPF hooks).
- Adversary evolution (how AI agents and supply-chain attacks shift over time).
- Maintainer capacity.

None of these open questions has a committed delivery date in v1. v2 will pick a small number to address; the rest carry forward.
