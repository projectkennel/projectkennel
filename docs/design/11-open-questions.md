# §11 Open questions and out-of-scope topics

## 11.1 Open questions for v2

**Wayland clipboard.** Even on Wayland, a kennel's window can read and write the user's clipboard via standard Wayland protocols. Some compositors offer per-client clipboard policies; support is uneven. Project Kennel does not currently enforce clipboard policy at the Wayland layer. Open question: what is the minimum viable cross-compositor mechanism for clipboard isolation, and is it worth depending on?

**GPU access nuances.** The current GPU grant (§7.9.9) is binary: either the kennel has `/dev/nvidia*` etc. or it doesn't. Real workflows want finer control: "this kennel can compute on the GPU but cannot read the framebuffer of other GPU users". The kernel's GPU drivers offer some primitives (GEM handles, DRM lease) that could plumb into a finer policy. Open question: what does a useful "GPU compute only" policy look like, and is it expressible without driver-specific code?

**TPM and FIDO access policy.** Currently Project Kennel grants device-level access (`/dev/tpmrm0`, `/dev/hidraw*`) and trusts the userspace stack to enforce per-key or per-credential policy. Open question: should Project Kennel interpose at a higher level (the PKCS#11 socket, the FIDO HID protocol) to enforce per-key per-kennel bindings? This is significant engineering for marginal benefit, but the use case (per-kennel FIDO unlock for the SSH bastion's keys) is exactly the motivating workflow.

**Syscall filtering as primary mechanism.** Some confinement frameworks (Firejail, Bubblewrap) use seccomp as their primary mechanism. Project Kennel treats seccomp as defence-in-depth (§7.9.6). Open question: should an "extra-strict" template family use comprehensive seccomp filters as a primary defence, accepting the brittleness and compatibility cost?

**Compositor-level Wayland mediation.** A future direction: Project Kennel's per-kennel grant for Wayland goes through a compositor-aware proxy that filters Wayland protocol messages. Mature proposals exist (e.g. the security-context-v1 protocol). Open question: when does compositor support reach "good enough" to depend on, and what does Project Kennel's policy surface look like for compositor-mediated access?

**Post-run inspection of persistent writes.** This is the intended primary control for T2.8 (cross-context persistence via workspace triggers, THREATS.md), and it is deliberately not in the first release. A workload with legitimate write access to its project tree can plant a git hook, redirect `core.hooksPath` into the writable tree, or add a build/IDE task that later fires in the user's *unconfined* shell; filesystem policy closes this only partially, because the build and IDE files that carry triggers must stay writable for the agent to function. The capability: at kennel teardown, diff everything the workload wrote to the persistent writable binds against the pre-run state and flag newly-introduced *execution triggers* — hook files, `core.hooksPath` changes, `Makefile`/`package.json` script entries, `.vscode`/`.idea` task definitions — for operator review before the user next acts on the tree. This is broader than the commit-time `kennel review` of T2.2 / design §9: persistence can be planted without ever passing through a git commit, so the inspection must run on the raw written file set, not the git diff. Open questions: the canonical set of "execution trigger" patterns to flag and how to keep it current as toolchains evolve; how to scope the diff cheaply for large trees (writable binds resolve to persistent host inodes, so a naive full re-scan is the fallback); whether inspection blocks at teardown or produces a reviewable report the user must acknowledge; and how it composes with the commit-time review so the two are one coherent `kennel review` surface rather than two tools.

## 11.2 Explicitly out of scope

Only the boundaries the framework's own claims might invite the reader to assume are stated here. The universal limits of any user-space tool — side channels, hardware and physical attacks, and bugs in the kernel or in the vetted building blocks it relies on (Landlock, Xephyr) — are assumptions of the threat model, catalogued in [`THREATS.md`](THREATS.md) (X7–X8), not re-listed here.

**The user is the trust root.** Project Kennel is built on user-space trust: a process in the user's default context (the unconfined shell) can read Project Kennel's state, signal its components, and edit its policies. Cross-kennel isolation of the mediating components is structural — a kennel reaches them only through the binder gateway and cannot see host pids — but isolating them from the user's *own* default context is not a goal, because that context is the trust root itself. By the same token Project Kennel cannot stop a user from editing policies, disabling enforcement, or bypassing the framework entirely; **mandatory** enforcement against the user is a different administrative layer.

**Workloads are confined by mechanism, not identified by type.** Project Kennel treats an AI agent as one class of workload subject to the catalogue's threats; it does not detect or counter agent-like behaviour (LLM API patterns, agent-typical syscall sequences). The confinement is the same whether the workload is an AI agent, a container, or a script.

**The workload never signs on the operator's behalf.** A kennel is built *around code the operator does not trust*; it follows by definition that the workload must never be able to produce a cryptographic *attestation* as the operator. This rests on the distinction between authentication and attestation:

- **Authentication** (e.g. SSH) grants a *constrained capability* — "I authorise the entity in this cage to reach this one destination." What is delegated (the destination) is bounded and host-verifiable, so it *can* be mediated: the §7.10 bastion re-originates the connection from the host, binds the `(host, key)` edge, and the workload never holds the key.
- **Attestation** (commit / artefact / release signing) is the operator *vouching* for the data — "I certify this is mine and trustworthy." Delegating that to an untrusted workload is an architectural contradiction: **you cannot automate trust for an untrusted entity.** Unlike a destination, there is nothing for the host to verify — "this code is trustworthy" is exactly the judgement the human is being asked to make.

So *the workload generates the work; the human verifies and signs it.* Any feature that blurs that line is rejected on definition, not on cost — which is why the technical "bridges" all fail and must not be re-attempted: the SSH re-origination trick does not carry over (a commit hash incorporates its own signature, so host-side re-signing rewrites the tree); an out-of-TCB commit parser buys nothing (a valid commit's tree can *be* the payload); path-bounding re-opens T2.8 (an in-`src/` build script or hook is a signed execution trigger); and per-commit `pinentry` degrades to "approve all" or "cannot commit" under agent cadence. Concretely: commit signing is left unset inside the kennel (the operator signs on the host before push), and a `[unix]` `gpg-agent`/`ssh-agent` grant is the destination-blind signing oracle — permitted only as a loudly-warned footgun (§7.6, [`THREATS.md`](THREATS.md) T1.6 residual), never sanctioned. The only admissible host-side signer is one where a human approves each signature (e.g. `ssh-keygen -Y sign`, key never in the kennel) — there the *human* attests and the kennel merely relays; the kennel still never signs on the operator's behalf.

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
