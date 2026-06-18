# Project Kennel — Front matter

**Kernel-enforced confinement for unsigned workloads on Linux developer workstations.**

Status: 0.1.0 (first versioned release)
Kernel floor: Linux 6.10 or newer (Landlock `FS_EXECUTE`)
Last updated: 2026-06-18

---

This is the front matter for the Project Kennel design corpus. It fixes the notation and terminology the chapters assume, and points to the documents that carry the argument and the navigation. It deliberately holds neither of those itself: each has a single home, so there is no second copy to drift against.

- **The case** — why the user level needs its own enforcement layer, and why unsigned workloads are the threat — opens `README.md` and is developed in full in §1.
- **The chapter index and the reading guide by audience** are in `README.md`.
- **The two-page summary** for circulation is `EXEC-SUMMARY.md`.
- **The threat catalogue** is `THREATS.md`, a standalone companion the chapters cross-link by threat ID.

If you are opening the corpus for the first time, start at `README.md`.

---

## Conventions

**Terminology.**

- **Project Kennel** is the framework as a whole — the design, the runtime, the threat catalogue, the templates, the maintenance commitment.
- **`kennel`** is the command-line tool the developer invokes.
- **A kennel** is a confined execution context: the unit of confinement, the space a workload runs in, the thing a policy describes.
- **Workload** is the generic term for code being confined inside a kennel — AI agent, container image, package install script, MCP server, downloaded tool.
- **Default context** is the user's normal shell environment, unconstrained by Project Kennel. The trust root.

These are distinguishable by capitalisation and context throughout. The full glossary is §12.

**Threat IDs** are family-prefixed `T<family>.<index>` (T1.1, T1.2, …, T2.1, …): the integer before the dot is the threat family, so each family carries its own sequence. They cross-link `THREATS.md`, the chapters, the templates, and the audit log. The catalogue is at v0.3 (the family-prefix scheme landed in 0.3, replacing the former consecutive T1–T26). **Out-of-scope IDs** (X1, X2, …) identify explicit non-goals.

**Resource classes** in §7 follow a consistent prefix convention: `exec.*`, `fs.*`, `net.*`, `unix.*`, `dbus.*`, `x11.*`, `proc.*`, `env.*`, `cap.*`.

**Cross-references** use the chapter number — "see §7.5" — and subsection numbers within a chapter. Each chapter is a separate file (`NN-chapter-name.md`, or `NN-N-` for §7 subsections) so chapters revise in parallel without merge conflicts. Numbering is stable; chapters added later take a suffix rather than renumbering downstream.

---

This is a pre-1.0 corpus. Iteration may renumber threats, restructure chapters, or rename interfaces; stability commitments apply at v1.0.