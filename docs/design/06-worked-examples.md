# §6 Worked examples

Each example gives the policy, explains what the user is signing up for, and surfaces the residuals.

Every leaf policy below derives from a vetted template by a small set of **deltas** — `[[fs.write.add]]`, `[[net.allow.add]]`, … — each of which carries a required `reason`. The template names a parent via a single versioned reference (`template_base = "<name>@v<ver>"`); the field-by-field schema is the reference in [`docs/architecture/02-2-config-schema.md`](../architecture/02-2-config-schema.md). A few grants are **implied** so you write the intent once (see §Implied rules in the schema reference): a writable path is readable, so a project tree is one `fs.write.add` (not a read+write pair); an `[[ssh.keys]]` host implies egress to it on :22. **Every TOML block in this chapter parses and validates against the real policy parser** (`kennel_lib_policy::parse_leaf` + `validate`), checked with the oracle at `src/crates/kennel-lib-policy/examples/validate-policy.rs`; what a leaf cannot express (egress `mode`, bind ports, the invariant denylist — all template-level) is called out where it arises. For an end-to-end annotated leaf on an adversarial workload, see [`TEMPLATE-openclaw.md`](TEMPLATE-openclaw.md).

## 6.1 AI coding agent on a project

The motivating use case. The user runs an AI agent (Claude Code, Cursor, Aider, similar) against a single project. The agent reads code, writes code, runs tests, calls a remote LLM API.

**Policy** (`~/.config/kennel/kennels/myproj-ai.toml`):

```toml
template_base = "ai-coding-strict@v1"
name = "myproj-ai"

[[fs.write.add]]
path = "~/projects/myproj/**"
reason = "the project (read implied)"

[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T1.8"]
```

Total user content: ~10 lines. Everything else is inherited from the template.

**What's enforced.** The agent can:
- Read and write `~/projects/myproj/**`.
- Read `/usr/**`, `/lib/**`, `/etc/**` (baseline).
- Talk to `api.anthropic.com:443`.
- Use a per-kennel ssh-agent (if the template grants one).
- Pop notifications (`org.freedesktop.Notifications` from template baseline).

The agent cannot:
- Read `~/.ssh/`, `~/.aws/`, `~/.config/gh/`, or any other credential location.
- Connect to anything other than the Anthropic API.
- Reach the user's local services (Postgres, Docker daemon).
- Spawn `sudo`, `curl`, or other binaries outside the template's exec allowlist.
- See the user's other processes via `/proc`.
- Manipulate clipboard or read the user's other windows.

**Residuals.**
- **T1.8 (exfiltration via allowed API).** The agent talks to api.anthropic.com; nothing stops it from putting stolen data in API requests. Mitigations are external: don't put high-value secrets in `myproj`, monitor API usage patterns, use the optional TLS-inspection layer if the threat model demands it.
- **Within-project compromise.** The agent has full read/write on the project. If the project itself contains credentials (`.env`, etc), the agent has them. The threat model says: keep secrets out of project trees.

**Startup.** Cold: ~1.5s. Warm (re-entering existing kennel): ~150ms.

## 6.2 `npm install` of an unfamiliar package

The user wants to try a new npm package. Post-install scripts (T1.2) are the threat.

**Policy** (`~/.config/kennel/kennels/npm-try.toml`):

```toml
template_base = "package-install@v1"
name = "npm-try"

# The template defaults to net.mode = "constrained" with the registry
# allowed. User adds the project where to install.

[[fs.write.add]]
path = "~/scratch/npm-try/**"
reason = "scratch dir for trial install"

# Override the template's TTL action: a trial install should be ephemeral, so
# stop (not warn) at the TTL. A leaf overrides scalars via `[lifecycle.override]`.
[lifecycle.override]
ttl = "1h"
ttl_action = "stop"
```

**What's enforced.** The post-install script can:
- Read `/usr/**`, `/lib/**`.
- Write to `~/scratch/npm-try/**`.
- Talk to `registry.npmjs.org:443` only.
- Run `node`, `npm`, basic shell utilities.

It cannot:
- Read anything else under `~/`.
- Connect anywhere else (no exfiltration, no command-and-control).
- Persist beyond 1 hour (the TTL kills the kennel).
- Spawn `curl`, `wget`, `bash -c '...nasty...'` (template restricts exec).

**Residuals.**
- **Supply-chain compromise of npmjs.org itself.** If the registry is poisoned, the malicious package arrives via legitimate channels. Out of scope.
- **In-band exfiltration to npm registry.** A package could conceivably exfiltrate via metadata in subsequent requests to the registry. Theoretical, low realism.

**Startup.** Cold: ~1s.

## 6.3 Inspecting a repository before deciding whether to trust it

The user has cloned a repository and wants to read it (`grep`, `cat`, `tree`) without giving the build system any opportunity to run.

**Policy** (`~/.config/kennel/kennels/inspect.toml`):

```toml
template_base = "inspect-only@v1"
name = "inspect-repo"

[[fs.read.add]]
path = "~/clones/<repo>/**"
reason = "the repo to inspect"
```

The `inspect-only` template provides:

```toml
# Template baseline (the relevant sections; the full template carries identity
# + signature). exec.allow is a TOML array of strings under [exec], not a list.
[net]
mode = "none"

[exec]
allow = [
    "/usr/bin/cat",
    "/usr/bin/grep",
    "/usr/bin/find",
    "/usr/bin/tree",
    "/usr/bin/less",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/file",
    "/usr/bin/strings",
    "/usr/bin/wc",
    "/usr/bin/sort",
    "/usr/bin/uniq",
    # Notably absent: any compiler, interpreter, build tool
]
```

**What's enforced.** The user can read the repo. Nothing in the kennel can execute build scripts, fetch dependencies, run tests, or do anything beyond text inspection.

**Residuals.**
- **The inspection tools themselves.** `grep` and `cat` are unlikely vectors, but if a CVE existed in `less` for processing crafted input, this kennel would expose it. Out of scope (assumes vetted system tools).

**Startup.** Cold: ~800ms (no daemons; just shim + Landlock).

## 6.4 Dev server with access to local Postgres

The user is developing a web application that needs the local Postgres instance. They want the dev server confined but able to reach Postgres on host loopback.

**Policy** (`~/.config/kennel/kennels/webapp-dev.toml`):

```toml
template_base = "ai-coding-strict@v1"
name = "webapp-dev"

[[fs.write.add]]
path = "~/projects/webapp/**"
reason = "the project (read implied)"

[[net.allow.add]]
name = "registry.npmjs.org"
ports = [443]
reason = "deps"

[[net.allow.add]]
name = "github.com"
ports = [443]
reason = "git fetches"

# Reach the host's local Postgres over loopback. There is no [net.loopback]
# section in a leaf; loopback reachability is an ordinary by-CIDR egress grant —
# kenneld dials 127.0.0.1:5432 on the kennel's behalf (a sanctioned host service).
[[net.allow.add]]
cidr = "127.0.0.1/32"
ports = [5432]
reason = "local development Postgres instance"
threats.exposed = ["T1.6"]
```

**What's enforced.** The dev server can:
- Reach `127.0.0.1:5432` (the host's Postgres), dialled by kenneld as a sanctioned host service — there is no direct loopback path out of the kennel's net-ns.
- Reach npmjs.org and github.com via the egress gateway.
- Be reached at its own loopback address from the user's default context (its bound port appears on the host `lo` at the kennel's `127.<tag>.<ctx>.1`).

It cannot:
- Reach other host loopback services (e.g. another Postgres on `:5433`, or an ssh-agent socket) — only the `127.0.0.1:5432` literal it was granted.
- Reach other kennels' dev servers (sibling kennels sit in distinct net namespaces with distinct loopback addresses).
- Exfiltrate beyond the npmjs+github allowlist.

> **Bind ports.** Rewriting a `0.0.0.0` listener to the kennel's own loopback and allowing specific bind ports (`net.bind.allowed_ports`, the Vite/HMR case) is a **template-level** setting, not a leaf delta — a leaf has no `[net.bind]` field. A dev-server template carries it; the leaf above only adds the project, the registries, and the Postgres reach.

**Residuals.**
- **The Postgres grant is broad.** Granting `127.0.0.1:5432` grants access to whatever that Postgres instance holds — including other databases on it. The mitigation is at the Postgres role level (the kennel's connection string uses a role scoped to the relevant database).

**Startup.** Cold: ~1.5s.

## 6.5 Build needing open internet (Rust project with many crates)

A Rust build that downloads dozens of crates from crates.io and a few from git repos. The user accepts open internet but wants everything audited.

**Policy** (`~/.config/kennel/kennels/rust-build.toml`):

```toml
# The open-net posture is carried by the template (net.mode is a template-level
# scalar, not a leaf delta). ai-coding-permissive would set mode = "open"; here
# the leaf adds the project + cargo cache and turns egress audit up to full.
template_base = "ai-coding-strict@v1"
name = "rust-build"

[[fs.write.add]]
path = "~/projects/myrustapp/**"
reason = "the project (read implied)"

[[fs.write.add]]
path = "~/.cargo/registry/**"
reason = "cargo's downloaded crate cache"

# A leaf tunes per-kennel egress audit via [net.audit.override] (level / log_path).
[net.audit.override]
level = "full"
```

**What's enforced.** With an open-net template the build can reach the open internet, but every connection is logged (`net.audit.override` raises it to `full`). The filesystem stays scoped to the project and the cargo cache regardless of net mode.

**Residuals.**
- **Open net mode is weak.** A compromised crate can exfiltrate freely. The audit log catches the destinations after the fact; the proxy adds nothing per-destination beyond logging.
- **`~/.cargo/registry/` is shared between kennels.** A poisoned crate cached by one kennel affects another.

The audit log review is the operational mitigation. After a build, the user can run:

```
$ kennel audit rust-build --since 1h --resource net --novel-only
```

To see destinations contacted that weren't part of the user's expected set.

**Startup.** Cold: ~1.5s.

## 6.6 Containerised service: Postgres for development

The developer needs a Postgres instance for local development. They want it exposed on their workstation but not on the LAN, and they want the credentials and data confined to a specific path.

**Policy** (`~/.config/kennel/kennels/dev-postgres.toml`):

```toml
template_base = "containerised-service@v1"
name = "dev-postgres"

[[fs.write.add]]
path = "~/data/dev-postgres/**"
reason = "Postgres data directory"
```

The `containerised-service` template runs the service as the kennel itself: the service binary and its invariants live in the template, its published port is a `[net.bind]` entry, and its data and config are `[fs]` grants. The leaf adds only the data directory.

**What's enforced.** The Postgres kennel:
- Listens only on its own per-kennel loopback address (`127.<tag>.<ctx>.1:5432`), which appears on the host `lo` at that same address — the user's default context can connect; the LAN cannot.
- Has access only to `~/data/dev-postgres/` plus the template's baseline read paths; no other host paths.
- Runs under the same unprivileged user namespace + seccomp + Landlock as any kennel.

**Residuals.**
- **The Postgres binary and its libraries are trusted.** The template grants exec on the system Postgres; a compromise of that package is a supply-chain residual (T1.9), mitigated only by the same confinement applied to everything else.
- **Secrets in the data directory.** The granted `~/data/dev-postgres/**` tree holds whatever the service writes there, readable by the kennel — keep unrelated secrets out of it.

**Startup.** Cold: ~1.5s (no container runtime to pull or start).

## 6.7 Corp-toolchain delta

The user works at a company that requires specific tools from a non-standard path and a VPN-mediated network. They derive from `ai-coding-strict`:

**Policy** (`~/.config/kennel/kennels/corp-ai.toml`):

```toml
template_base = "ai-coding-strict@v1"
name = "corp-ai"

[[fs.write.add]]
path = "~/projects/work/**"
reason = "work project (read implied)"

# Read-only: the corp toolchain is consumed, never modified — so this stays fs.read.
[[fs.read.add]]
path = "/opt/corp-toolchain/**"
reason = "company-installed dev tools"
threats.exposed = ["T1.4"]

[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"

[[net.allow.add]]
name = "git.corp.example"
ports = [443, 22]
reason = "corp git host (HTTPS + SSH)"

[[net.allow.add]]
name = "registry.corp.example"
ports = [443]
reason = "corp package registry"

[[net.allow.add]]
name = "artifacts.corp.example"
ports = [443]
reason = "corp artifact store"

[[unix.allow.add]]
name = "corp-vpn-agent"
real = "/run/corp/vpn-agent.sock"
shim = "/run/corp/vpn-agent.sock"
reason = "corp VPN agent for cert-based auth to internal services"
threats.exposed = ["T1.6"]
```

**Diff output** (when running `kennel diff corp-ai`):

```
+ fs.read: /opt/corp-toolchain/**
    reason: company-installed dev tools
    threats.exposed: T1.4 (corp-toolchain integrity)
    impact: read access to a non-user-controlled directory.
            Acceptable if /opt/corp-toolchain is managed by IT;
            consider if the toolchain itself is in scope of your trust model.

+ unix.allow: /run/corp/vpn-agent.sock
    reason: corp-vpn-agent
    threats.exposed: T1.6 (privileged service surface)
    impact: WARNING — granting access to a privileged service socket.
            This service has capability X, Y, Z.
            Consider whether the kennel truly needs this.

+ 3 additional net.allow entries (corp.example domains)
    threats.exposed: none catalogued; outbound to internal services.
```

The diff is the artefact that goes to the user's security reviewer in CI.

## 6.8 Workflow needing X11 (legacy app)

The user has to run a legacy GUI tool (some Java Swing app from 2008). It only works on X11.

**Policy** (`~/.config/kennel/kennels/legacy-gui.toml`):

```toml
# The X11 isolation (Xwayland/Xephyr) and the no-network posture are template
# work — an x11-isolated template carries net.mode = "none" and the X server
# wiring. A leaf has no [net].mode field. The leaf adds the data + the tool.
template_base = "ai-coding-strict@v1"
name = "legacy-gui"

[[fs.read.add]]
path = "~/legacy-data/**"
reason = "input data for the legacy tool"

[[fs.write.add]]
path = "~/legacy-data/output/**"
reason = "tool's output"

[[exec.allow.add]]
path = "/usr/bin/java"
reason = "the legacy tool's JVM runtime"

[[exec.allow.add]]
path = "/opt/legacy-tool/bin/legacy-tool"
reason = "the legacy tool"
```

**What's enforced.** With an X11-isolated template the tool runs in a dedicated Xwayland (Wayland host) or Xephyr (X11 host) instance and gets no network. The leaf adds read on the input data, write on the output dir, and exec on the JVM + the tool binary. The user sees the tool's window in their normal session; the tool sees only itself in its X server.

**Residuals.**
- **No copy-paste between host and tool.** The user accepts this in exchange for the isolation. Copy-paste within the tool works normally.
- **Performance.** Xephyr is software-rendered; if the legacy tool is graphics-heavy, may be slow.

**Startup.** Cold: ~2s (Xephyr launch takes ~500ms).

## 6.9 Common shape

Each example is 10–30 lines of user-authored policy. Each is composed against a vetted template. Each surfaces its residuals and threat exposures explicitly. Each is reviewable in a 30-second skim.

Confinement that is actually used, because authoring is cheap. The hard work is the template set (§5) and the threat catalogue (THREATS.md). The user-facing surface is small enough to actually engage with.
