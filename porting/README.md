# Porting assessments

This directory holds **compatibility-mapping assessments** for porting Project
Kennel's Linux reference design to other kernels. They are *scoping documents*, not
implementations: the reference runtime under [`crates/`](../crates/) is Linux-only
(Landlock, cgroup BPF, namespaces, seccomp), and nothing here is built or shipped.

## The grading lens

Each assessment grades every Linux control against its closest equivalent on the
target kernel, using the project's test — **a control counts only if it is
kernel-enforced and keyed to process (or jail) identity such that the confined
workload cannot forge or bypass it.** A rule the workload sidesteps by changing its
source address, environment, or file-open path is a speed bump, not a control.

Grades: **Equivalent** · **Superior** (exceeds Linux) · **Partial** (coarser than
Linux) · **Inferior** (cannot match the Linux property; a residual threat is
recorded) · **Conditional / unsupported-API** (depends on a build option, code
change, or an undocumented interface).

## Port-specific residual threats

Where a port cannot match a Linux property, the assessment names a residual threat
as a `[T-NEW: <PORT>-<NAME>]` candidate — the `[T-NEW]` issue tag from
[CODING-STANDARDS.md](../CODING-STANDARDS.md) §13.5, for a suspected threat class not
yet in [THREATS.md](../THREATS.md). These are candidates pending catalogue
assignment if and when a port is undertaken; they are deliberately kept out of the
main catalogue (which describes the Linux reference) until then.

## Documents

| Document | Target | Headline |
|---|---|---|
| [DARWIN-COMPAT.md](DARWIN-COMPAT.md) | macOS / Darwin | Seatbelt (SBPL) is the only viable layer — undocumented and version-volatile; recon-resistance and same-UID loopback isolation are **Inferior** to Linux. |
| [FREEBSD-COMPAT.md](FREEBSD-COMPAT.md) | FreeBSD | Jails + VNET + Capsicum grade **Equivalent or Superior** on most controls, but VNET's private stack makes the egress proxy a new trusted path that must be plumbed deliberately. |

Both are honest about where the target falls short; a port that graded "Equal"
across the board would be hiding exactly the residuals §13.5 exists to surface.
