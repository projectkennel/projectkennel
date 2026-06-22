# Project Kennel — the design corpus

**Kernel-enforced confinement for unsigned workloads on Linux developer workstations.**

The user level of a modern developer workstation is a full software runtime — package
managers, container engines, AI coding agents, MCP servers, build tooling — all running as
the user, none arriving through the operating system's validated install path, and none
covered by the host-level enforcement vocabulary (AppArmor, SELinux, capabilities, audit)
that makes the system level defensible. Project Kennel is the enforcement vocabulary the
user level should have acquired as it grew into a runtime: signed policy describing
*kernel-level constraints* (which files, which network destinations, which sockets), applied
at user-level workload granularity, enforced by mechanisms the workload's userspace cannot
reach — Landlock, cgroup BPF, user/mount/PID/IPC namespaces, seccomp, `no_new_privs`.

It is **built, not proposed**, and it runs **without privilege**: `kenneld` is an ordinary
user process; the sandbox is assembled inside an identity-mapped user namespace (the
bubblewrap mechanism), with a single small file-capabilities helper for the three
host-global operations a user namespace cannot reach.

This directory is the **design corpus** — the *why* and the *what*, vendor- and
implementation-independent. The as-built *how* lives under
[`../architecture/`](../architecture/); the reference runtime is the rest of the repository.

## Start here

- **[The thesis](01-thesis.md)** — the full case: why the user level needs its own enforcement
  layer, why the existing mechanisms fail, why self-sandboxing misses the point, and where an
  organisation's own policy attaches. Start here.
- **[The threat catalogue](THREATS.md)** — the adversary model as a numbered, tagged catalogue
  (T1.x exfiltration/lateral, T2.x posture degradation, T3.x workload-class, …). The settled
  reference for what Kennel does and does not defend.
- **[Front matter](00-frontmatter.md)** — the terminology, the threat-ID scheme, and the
  notation the chapters assume. Skim once; refer back as needed.
- The two-page version for circulation is **[EXEC-SUMMARY.md](EXEC-SUMMARY.md)**.

## Reading guide by audience

- **Security buyers (CISO, security architect, compliance):** §1 (the case), §2 (adversary
  model), §4 (trust boundaries), §5 (templates), §6 (worked examples), §11 (open questions) —
  the security argument, the operational layer, the honest limitations. The §7 mechanism
  reference and §8 enforcement architecture can be skipped unless you want to audit the claims.
- **Developers using Kennel:** §1 skim, §6 (worked examples), §5 (templates); §2 once.
- **Template authors and framework contributors:** everything, in order. §7 and §8 are
  reference material organised by resource class.

## The chapters

| # | Chapter | Subject |
|---|---|---|
| 01 | [Thesis](01-thesis.md) | The argument: why user-level confinement, why kernel-enforced |
| 02 | [Adversary model](02-adversary-model.md) | What the workload is assumed to do |
| 03 | [Problem statement](03-problem-statement.md) | The gap the project closes |
| 04 | [Trust boundaries](04-trust-boundaries.md) | Who trusts whom, and where the lines are |
| 05 | [Templates](05-templates.md) | Signed, inheritable policy; the composition model |
| 06 | [Worked examples](06-worked-examples.md) | Real policies, annotated |
| 07.1 | [Binder](07-1-binder.md) | The in-kennel IPC gateway |
| 07.2 | [kennel-bin-init](07-2-kennel-init.md) | The trusted PID-1 construction model |
| 07.3 | [Exec](07-3-exec.md) | The `execve` allowlist and the library closure |
| 07.4 | [Filesystem](07-4-filesystem.md) | The constructed `$HOME` view, Landlock, the masked manifest |
| 07.5 | [Network](07-5-network.md) | The egress proxy, the net-ns boundary, the inbound mirror |
| 07.6 | [AF_UNIX](07-6-afunix.md) | The socket shim |
| 07.7 | [D-Bus](07-7-dbus.md) | Session-bus mediation (roadmap) |
| 07.8 | [X11](07-8-x11.md) | Out of scope — X11 cannot be granted |
| 07.9 | [Other](07-9-other.md) | Procfs, env, capabilities, seccomp, the tty (escape filter, controlling pty) |
| 07.10 | [SSH](07-10-ssh.md) | The double-blind re-origination bastion |
| 07.11 | [OCI substrate](07-11-oci-substrate.md) | Booting a vendor OCI image as a confined kennel root |
| 07.12 | [Dynamic spawn](07-12-dynamic-spawn.md) | Delegated ephemeral sibling kennels; MCP-over-stdio transport |
| 08 | [Enforcement architecture](08-enforcement-architecture.md) | How the kernel mechanisms compose |
| 09 | [Policy lifecycle](09-policy-lifecycle.md) | Author → compile → sign → run |
| 10 | [Failure modes](10-failure-modes.md) | What happens when each step fails |
| 11 | [Open questions](11-open-questions.md) | Unsettled design questions |
| 12 | [Glossary & references](12-glossary-references.md) | Terms and prior art |

Supporting: [BUILD-ENV.md](BUILD-ENV.md) (the kernel/toolchain floor), [EXEC-SUMMARY.md](EXEC-SUMMARY.md).

## Doc layering

The design corpus carries no build status — only what is *possible* or *impossible* by the
design. The [architecture chapters](../architecture/) carry the *as-built* truth; where code
and design diverge, the divergence is owed to the code and bubbles up to the design only when
the design is proven wrong or impossible. So a chapter here describing a mechanism does not
assert it is implemented — consult [`../architecture/08-as-built-notes.md`](../architecture/08-as-built-notes.md)
§8.1 for what remains roadmap.
