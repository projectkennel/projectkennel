# Project Kennel templates

Templates are signed starting policies for common workloads. A leaf policy inherits one template, adds the access its task needs, and is compiled into the settled policy that `kennel run` accepts. The template sets the floor; the leaf names the particular project, command, or destination.

Use `kennel template list` to see installed templates and `kennel template show <name>` to inspect the policy a leaf would inherit. [HOWTO.md](../../HOWTO.md) covers generating, compiling, and running a leaf policy. [The design](../../docs/archive/design/05-templates.md) explains inheritance and signature rules.

## Templates for users

| Template | Start here when you need to… |
| --- | --- |
| [`ai-coding-strict`](ai-coding-strict/) | Run an AI coding agent against one project. The leaf supplies the project path and model API destination. |
| [`interactive`](interactive/) | Run an interactive shell with a selected toolset. |
| [`inspect-only`](inspect-only/) | Read a directory without building or changing it. |
| [`package-install`](package-install/) | Install packages from selected registries for a bounded task. |
| [`untrusted-build`](untrusted-build/) | Build source with network access disabled. |
| [`containerised-service`](containerised-service/) | Run a local service under Kennel's confinement. |

`base-confined` is the shared foundation for these templates. It defines the default boundary but has no useful workload or project access by itself. Templates may also include signed [fragments](../fragments/) for toolsets and other additive grants.

For example, to start a policy for one coding project:

```sh
kennel policy generate myproject --from ai-coding-strict
# Edit the generated policy to grant the project and required destinations.
kennel policy validate myproject
kennel policy compile myproject
kennel run myproject
```

`kennel run` loads a compiled, signed policy by name. It does not compile source policies at launch. See [HOWTO.md](../../HOWTO.md) for key setup and the complete authoring flow.

## Templates used by the runtime

Some templates are installed to support Kennel's own workflows rather than as general starting points for a leaf policy:

| Group | Templates | Purpose |
| --- | --- | --- |
| Delegated tasks | [`pure-compute`](pure-compute/), [`net-fetch`](net-fetch/), [`scratch-fs`](scratch-fs/) | Bounded sibling kennels an agent can request through `[spawn]`. Each limits the access and fields a caller may supply. |
| GUI | `gui-interactive`, `gui-session`, `gui-broker` | Confined Wayland sessions and their brokered connection to the host display. |
| Network and services | `tun-broker`, `dbus-broker`, `oci-fetch` | Brokered network, D-Bus, and image-fetch workflows. |
| Tool and test fixtures | `argv-tool`, `echo-tool`, `true-tool`, `pyhello-tool` | Narrow workloads used by runtime and policy tests. |
| Substrate bases | `base-bwrap`, `base-flatpak` | Baselines for those integration paths. |

The three delegated-task templates separate execution, network access, and writable storage into different signed targets. A spawn request may fill only the fields its selected target marks mutable. Spawn eligibility and mutable fields are checked in [`spawn_templates.rs`](../../src/crates/kennel-lib-compile/tests/spawn_templates.rs).

## Files and policy rules

Each template directory contains `policy.toml` and `meta.toml`. Some also have a README with workload-specific guidance. `policy.toml` declares grants and, for derived templates, a `template_base`; `meta.toml` carries template identity and signing information. Included fragments are signed separately.

The compiler verifies the signed inheritance chain and included fragments, applies the leaf's grants, and emits a settled policy. It rejects changes that violate a template invariant. A new access grant should state its reason and identify the threats it exposes. For the resolved result, use `kennel template show <name>` before deriving and `kennel policy show <name>` for a leaf.

The canonical threat IDs and residual risks are in [THREATS.md](../../docs/reference/THREATS.md). A grant can still be misused within its allowed scope: for example, code allowed to read a project and call an API can send project data to that API. Review the effective policy for the task you are running.
