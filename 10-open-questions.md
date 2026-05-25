# §10 Open questions and out-of-scope topics

The deliberate gaps in the framework's v1 scope, the open questions whose answers will shape v2, and the explicit non-goals.

## 10.1 Open questions for v2

**Wayland clipboard.** Even on Wayland, a confined context's window can read and write the user's clipboard via standard Wayland protocols. Some compositors offer per-client clipboard policies; support is uneven. The framework does not currently enforce clipboard policy at the Wayland layer. Open question: what is the minimum viable cross-compositor mechanism for clipboard isolation, and is it worth depending on?

**GPU access nuances.** The current GPU grant (§4.7.9) is binary: either the context has `/dev/nvidia*` etc. or it doesn't. Real workflows want finer control: "this context can compute on the GPU but cannot read the framebuffer of other GPU users". The kernel's GPU drivers offer some primitives (GEM handles, DRM lease) that could plumb into a finer policy. Open question: what does a useful "GPU compute only" policy look like, and is it expressible without driver-specific code?

**TPM and FIDO access policy.** Currently the framework grants device-level access (`/dev/tpmrm0`, `/dev/hidraw*`) and trusts the userspace stack to enforce per-key or per-credential policy. Open question: should the framework interpose at a higher level (the PKCS#11 socket, the FIDO HID protocol) to enforce per-key context bindings? This is significant engineering for marginal benefit, but the use case (per-context FIDO unlock for per-context ssh-agents) is exactly the motivating workflow.

**Syscall filtering as primary mechanism.** Some confinement frameworks (Firejail, Bubblewrap) use seccomp as their primary mechanism. The framework treats seccomp as defence-in-depth (§4.7.6). Open question: should an "extra-strict" template family use comprehensive seccomp filters as a primary defence, accepting the brittleness and compatibility cost?

**Namespace isolation of the framework's own daemons.** A determined same-uid attacker outside any context can read the framework's SOCKS5 proxy memory, signal its dbus-proxy, etc. v1 accepts this; the threat model documents it. Open question: a v2 mode where the framework's daemons run in their own PID/mount namespace, with stronger isolation from the rest of the user's session. Significant engineering; the threat is real but rare; the trade-off is open.

**Per-context user IDs via subuid/subgid.** The current design keeps everything as the user's real uid. An alternative: allocate each context its own uid from the `/etc/subuid` range, run the context's processes as that uid. This gives kernel-level uid-based isolation as well as the framework's policy-level isolation.

The trade-offs are significant. Pros:
- Filesystem ACLs become an additional layer (the context's uid cannot access the user's uid-owned files by virtue of uid permission alone).
- Some kernel APIs (signal delivery, ptrace) become naturally restricted.
- Resource accounting per context becomes precise.

Cons:
- File ownership becomes complicated. Writes from the context land in `~/projects/foo/` owned by a different uid; the user's normal shell sees files it can read but not write without permission gymnastics.
- The user's process management (kill, ps, etc) no longer "just works" across contexts.
- The mental model becomes more complex; the framework's centre of gravity shifts from "narrowed view of user's uid" to "running as a different user".
- Setup requires `/etc/subuid` configuration, which is a different administrator concern.

This is the most significant open question in scope expansion. v1 explicitly does not do this. v2 might, behind an opt-in flag, for users who want stronger isolation and can accept the complexity. The threat model's "same-uid is no longer the trust boundary" claim is honoured by v1's mechanism-based isolation; subuid would be additional defence in depth.

**Server vs per-context proxies.** Currently each context has its own SOCKS5 proxy and dbus-proxy. For users with many contexts, this is many daemons. An alternative: shared proxies with per-context credentials and policy lookup. Pros: fewer processes, lower memory. Cons: shared proxy is shared attack surface; compromise of the proxy affects all contexts. Open question: at what number of contexts does shared make sense, and what's the right abstraction?

**TLS inspection as a first-class feature.** The framework's SOCKS5 proxy could optionally MITM TLS connections, install a per-context CA in the context's trust store, and log full request contents. Pros: addresses T11 (exfil via allowed API) directly. Cons: significant complexity, breaks any TLS-pinning client, CA management is non-trivial, half the modern internet doesn't accept arbitrary CAs anyway. Open question: is there a useful subset of TLS inspection (logging SNI and connection metadata, but not contents) that is cheap and useful?

**Compositor-level Wayland mediation.** A future direction: the framework's per-context grant for Wayland goes through a compositor-aware proxy that filters Wayland protocol messages. Mature proposals exist (e.g. the security-context-v1 protocol). Open question: when does compositor support reach "good enough" to depend on, and what does the framework's policy surface look like for compositor-mediated access?

## 10.2 Explicitly out of scope

The following are not in scope for any planned version of the framework:

**Kernel-level CVE defence.** The framework assumes kernel correctness for the features it relies on. A Landlock bypass via a kernel CVE defeats the framework's filesystem confinement. Mitigation is at the kernel-update level, not the framework level.

**Side-channel defence.** Cache timing, electromagnetic emanation, Spectre-class attacks, microarchitectural side channels. The framework offers no defence; these are out of any user-space tool's reach.

**Hardware attacks.** Cold boot, DMA, peripheral compromise, firmware-level attacks. Out of any user-space tool's reach.

**Physical access.** The user's threat model does not include "an attacker has physical access to the workstation". Mitigations for that case are at the disk-encryption, boot-security, and physical-security layers.

**Network-level inbound attacks.** The framework defends *what the context can do outbound*. Inbound attacks against host-exposed services (the host running an exposed SSH or web service) are a different threat model with different mitigations (firewalls, fail2ban, host hardening).

**Multi-user isolation.** Different uids on the same host are isolated by existing Unix permissions. The framework adds nothing.

**Same-uid attacks against the framework itself.** A process in the user's default context can read the framework's state, signal its daemons, modify its policies. The framework is built on user-space trust; the user is the trust root. Stronger isolation of the framework from same-uid attackers is the open question above (10.1), not a v1 commitment.

**Anti-AI-agent measures.** The framework treats AI agents as a class of T1 adversary but does not specifically detect or counter agent-like behaviour (LLM API patterns, agent-typical syscall sequences). The threat model is mechanism-based, not actor-based.

**Defence against compromised vetted dependencies.** If `xdg-dbus-proxy`, `Xephyr`, the kernel's Landlock implementation, or other building blocks are themselves compromised, the framework's guarantees are compromised. The framework assumes its building blocks are sound (per §2.4, X7, X8).

**Cross-host enforcement.** A context on host A and a context on host B are not aware of each other. The framework is per-host.

**Encryption of audit logs.** The framework writes audit logs as plain JSONL. At-rest encryption is the user's responsibility (full-disk encryption, encrypted home directory). The framework does not encrypt its own logs.

**Mandatory enforcement.** The framework cannot prevent a user with full access to their own files from editing policies, disabling enforcement, or bypassing the framework entirely. Mandatory enforcement is at a different administrative layer.

## 10.3 Things that might look out of scope but aren't

**Multi-context coordination.** Contexts can be configured to share specific resources (a filesystem path, a unix socket). This is in scope because the framework explicitly defines the constructed views, and a shared path is a view that overlaps between two contexts. Not all "communication" is therefore out of scope; deliberate, policy-declared communication is supported.

**User-mediated capability grants.** Templates allow capabilities granted via portal dialogs (file picker, screenshot). The user mediates each grant. This is in scope and is the recommended pattern for capabilities that need human-in-the-loop.

**Long-lived background contexts.** A context need not be tied to an interactive command. Background services (a watcher, a periodic build) can run in a context indefinitely (subject to TTL and re-consent policies). In scope.

**Composition with container runtimes.** Containers (Docker, Podman) inside a framework context are supported with caveats (the container daemon socket grant is a significant capability, and the container itself is unconstrained by the framework). Documented in the `containerised-dev` template.

## 10.4 What this chapter is not

This chapter is not a roadmap. The framework's actual roadmap depends on:

- User feedback (which templates need expansion, which residuals matter in practice).
- Kernel evolution (new Landlock features, new BPF hooks).
- Adversary evolution (how AI agents and supply-chain attacks shift over time).
- Maintainer capacity.

The open questions here are real and tracked. None has a committed delivery date in v1. v2 will pick a small number to address; the rest carry forward.
