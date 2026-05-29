# §9 Worked examples

The point of this chapter: show what the framework looks like for a handful of real workflows. Each example gives the policy, explains what the user is signing up for, and surfaces the residuals.

## 9.1 AI coding agent on a project

The motivating use case. The user runs an AI agent (Claude Code, Cursor, Aider, similar) against a single project. The agent reads code, writes code, runs tests, calls a remote LLM API.

**Policy** (`~/.config/agent-run/contexts/myproj-ai.toml`):

```toml
template = "ai-coding-strict"
template_version = "3"
name = "myproj-ai"

[fs.read.add]
- path = "~/projects/myproj/**"
  reason = "the project"

[fs.write.add]
- path = "~/projects/myproj/**"
  reason = "the project"

[net.allow.add]
- name = "api.anthropic.com"
  ports = [443]
  reason = "Claude API"
  threats.exposed = ["T11"]
```

Total user content: ~10 lines. Everything else is inherited from the template.

**What's enforced.** The agent can:
- Read and write `~/projects/myproj/**`.
- Read `/usr/**`, `/lib/**`, `/etc/**` (baseline).
- Talk to `api.anthropic.com:443`.
- Use a per-context ssh-agent (if the template grants one).
- Pop notifications (`org.freedesktop.Notifications` from template baseline).

The agent cannot:
- Read `~/.ssh/`, `~/.aws/`, `~/.config/gh/`, or any other credential location.
- Connect to anything other than the Anthropic API.
- Reach the user's local services (Postgres, Docker daemon).
- Spawn `sudo`, `curl`, or other binaries outside the template's exec allowlist.
- See the user's other processes via `/proc`.
- Manipulate clipboard or read the user's other windows.

**Residuals.**
- **T11 (exfiltration via allowed API).** The agent talks to api.anthropic.com; nothing stops it from putting stolen data in API requests. Mitigations are external: don't put high-value secrets in `myproj`, monitor API usage patterns, use the optional TLS-inspection layer if the threat model demands it.
- **Within-project compromise.** The agent has full read/write on the project. If the project itself contains credentials (`.env`, etc), the agent has them. The threat model says: keep secrets out of project trees.

**Startup.** Cold: ~1.5s. Warm (re-entering existing context): ~150ms.

## 9.2 `npm install` of an unfamiliar package

The user wants to try a new npm package. Post-install scripts (T2) are the threat.

**Policy** (`~/.config/agent-run/contexts/npm-try.toml`):

```toml
template = "package-install"
template_version = "2"
name = "npm-try"

# The template defaults to net.mode = "constrained" with the registry
# allowed. User adds the project where to install.

[fs.write.add]
- path = "~/scratch/npm-try/**"
  reason = "scratch dir for trial install"

[lifecycle]
ttl = "1h"
reason = "trial install; should be ephemeral"
```

**What's enforced.** The post-install script can:
- Read `/usr/**`, `/lib/**`.
- Write to `~/scratch/npm-try/**`.
- Talk to `registry.npmjs.org:443` only.
- Run `node`, `npm`, basic shell utilities.

It cannot:
- Read anything else under `~/`.
- Connect anywhere else (no exfiltration, no command-and-control).
- Persist beyond 1 hour (the TTL kills the context).
- Spawn `curl`, `wget`, `bash -c '...nasty...'` (template restricts exec).

**Residuals.**
- **Supply-chain compromise of npmjs.org itself.** If the registry is poisoned, the malicious package arrives via legitimate channels. Out of scope.
- **In-band exfiltration to npm registry.** A package could conceivably exfiltrate via metadata in subsequent requests to the registry. Theoretical, low realism.

**Startup.** Cold: ~1s.

## 9.3 Inspecting a repository before deciding whether to trust it

The user has cloned a repository and wants to read it (`grep`, `cat`, `tree`) without giving the build system any opportunity to run.

**Policy** (`~/.config/agent-run/contexts/inspect.toml`):

```toml
template = "inspect-only"
template_version = "1"
name = "inspect-repo"

[fs.read.add]
- path = "~/clones/<repo>/**"
  reason = "the repo to inspect"
```

The `inspect-only` template provides:

```toml
# Template baseline:
[net]
mode = "none"

[fs.write]
# Only the framework's audit log path

[exec.allow]
- /usr/bin/cat
- /usr/bin/grep
- /usr/bin/find
- /usr/bin/tree
- /usr/bin/less
- /usr/bin/head
- /usr/bin/tail
- /usr/bin/file
- /usr/bin/strings
- /usr/bin/wc
- /usr/bin/sort
- /usr/bin/uniq
# Notably absent: any compiler, interpreter, build tool
```

**What's enforced.** The user can read the repo. Nothing in the context can execute build scripts, fetch dependencies, run tests, or do anything beyond text inspection.

**Residuals.**
- **The inspection tools themselves.** `grep` and `cat` are unlikely vectors, but if a CVE existed in `less` for processing crafted input, this context would expose it. Out of scope (assumes vetted system tools).

**Startup.** Cold: ~800ms (no daemons; just shim + Landlock).

## 9.4 Dev server with access to local Postgres

The user is developing a web application that needs the local Postgres instance. They want the dev server confined but able to reach Postgres on host loopback.

**Policy** (`~/.config/agent-run/contexts/webapp-dev.toml`):

```toml
template = "dev-server"
template_version = "2"
name = "webapp-dev"

[fs.read.add]
- path = "~/projects/webapp/**"
  reason = "the project"

[fs.write.add]
- path = "~/projects/webapp/**"
  reason = "the project"

[net.allow.add]
- name = "registry.npmjs.org"
  ports = [443]
  reason = "deps"
- name = "github.com"
  ports = [443]
  reason = "git fetches"

[[net.loopback.host_services]]
name = "postgres"
addr_v4 = "127.0.0.1:5432"
proxy.required = false
reason = "local development Postgres instance"
threats.exposed = ["T13:local-service-via-explicit-grant"]

[net.bind.allowed_ports]
add = [3000, 3001]
reason = "Vite dev server and HMR socket"
```

**What's enforced.** The dev server can:
- Bind `127.42.<ctx>.1:3000` and `:3001` (rewritten from `0.0.0.0`).
- Reach `127.0.0.1:5432` directly (the host's Postgres).
- Reach npmjs.org and github.com via proxy.
- Be reached at its dev address from the user's browser (default context can connect to confined-context loopback).

It cannot:
- Reach other host loopback services (e.g. the user's other dev Postgres on `:5433`, or an ssh-agent on `~/.ssh/agent`).
- Reach other contexts' dev servers (sibling contexts have different loopback addresses).
- Exfiltrate beyond the npmjs+github allowlist.

**Residuals.**
- **The Postgres grant is broad.** Granting `127.0.0.1:5432` is granting access to whatever Postgres has — including other databases the user has on that instance. The mitigation is at the Postgres role level (the context's connection string uses a role with access only to the relevant database).

**Startup.** Cold: ~1.5s.

## 9.5 Build needing open internet (Rust project with many crates)

A Rust build that downloads dozens of crates from crates.io and a few from git repos. The user accepts open internet but wants everything audited.

**Policy** (`~/.config/agent-run/contexts/rust-build.toml`):

```toml
template = "ai-coding-permissive"
template_version = "1"
name = "rust-build"

[fs.read.add]
- path = "~/projects/myrustapp/**"
  reason = "the project"

[fs.write.add]
- path = "~/projects/myrustapp/**"
  reason = "the project"
- path = "~/.cargo/registry/**"
  reason = "cargo's downloaded crate cache"

[net]
mode = "open"
reason = "Rust builds fetch from crates.io and arbitrary git repos"

[net.audit.override]
level = "full"
reason = "open internet; log every destination for review"
```

**What's enforced.** The build can reach the open internet, but every connection is logged. Filesystem is still scoped to the project and cargo cache.

**Residuals.**
- **Open net mode is weak.** A compromised crate can exfiltrate freely. The audit log catches the destinations after the fact; the proxy adds nothing per-destination beyond logging.
- **`~/.cargo/registry/` is shared between contexts.** A poisoned crate cached by one context affects another.

The audit log review is the operational mitigation. After a build, the user can run:

```
$ agent-run audit rust-build --since 1h --resource net --novel-only
```

To see destinations contacted that weren't part of the user's expected set.

**Startup.** Cold: ~1.5s.

## 9.6 Corp-toolchain delta

The user works at a company that requires specific tools from a non-standard path and a VPN-mediated network. They derive from `ai-coding-strict`:

**Policy** (`~/.config/agent-run/contexts/corp-ai.toml`):

```toml
template = "ai-coding-strict"
template_version = "3"
name = "corp-ai"

[fs.read.add]
- path = "~/projects/work/**"
  reason = "work project"
- path = "/opt/corp-toolchain/**"
  reason = "company-installed dev tools"
  threats.exposed = ["T4:corp-toolchain-integrity"]

[fs.write.add]
- path = "~/projects/work/**"
  reason = "work project"

[net.allow.add]
- name = "api.anthropic.com"
  ports = [443]
- name = "git.corp.example"
  ports = [443, 22]
- name = "registry.corp.example"
  ports = [443]
- name = "artifacts.corp.example"
  ports = [443]

[unix.allow.add]
- name = "corp-vpn-agent"
  real = "/run/corp/vpn-agent.sock"
  shim = "/run/corp/vpn-agent.sock"
  reason = "corp VPN agent for cert-based auth to internal services"
  threats.exposed = ["T8:privileged-service-surface"]
```

**Diff output** (when running `agent-run diff corp-ai`):

```
+ fs.read: /opt/corp-toolchain/**
    reason: company-installed dev tools
    threats.exposed: T4 (corp-toolchain integrity)
    impact: read access to a non-user-controlled directory.
            Acceptable if /opt/corp-toolchain is managed by IT;
            consider if the toolchain itself is in scope of your trust model.

+ unix.allow: /run/corp/vpn-agent.sock
    reason: corp-vpn-agent
    threats.exposed: T8 (privileged service surface)
    impact: WARNING — granting access to a privileged service socket.
            This service has capability X, Y, Z.
            Consider whether the context truly needs this.

+ 3 additional net.allow entries (corp.example domains)
    threats.exposed: none catalogued; outbound to internal services.
```

The diff is the artefact that goes to the user's security reviewer in CI.

## 9.7 Workflow needing X11 (legacy app)

The user has to run a legacy GUI tool (some Java Swing app from 2008). It only works on X11.

**Policy** (`~/.config/agent-run/contexts/legacy-gui.toml`):

```toml
template = "x11-isolated-dev"
template_version = "1"
name = "legacy-gui"

[fs.read.add]
- path = "~/legacy-data/**"
  reason = "input data for the legacy tool"

[fs.write.add]
- path = "~/legacy-data/output/**"
  reason = "tool's output"

[exec.allow.add]
- path = "/usr/bin/java"
- path = "/opt/legacy-tool/bin/legacy-tool"
  reason = "the legacy tool"

# Template handles xwayland_isolated/xephyr_isolated based on host.
# Clipboard bridging deliberately off.

[net]
mode = "none"
reason = "the legacy tool has no business on the internet"
```

**What's enforced.** The tool runs in a dedicated Xwayland (Wayland host) or Xephyr (X11 host) instance. The tool can read input data, write output data, no network, no other capabilities. The user sees the tool's window in their normal session; the tool sees only itself in its X server.

**Residuals.**
- **No copy-paste between host and tool.** The user accepts this in exchange for the isolation. Copy-paste within the tool works normally.
- **Performance.** Xephyr is software-rendered; if the legacy tool is graphics-heavy, may be slow.

**Startup.** Cold: ~2s (Xephyr launch takes ~500ms).

## 9.8 What these examples illustrate

Each example is 10–30 lines of user-authored policy. Each is composed against a vetted template. Each surfaces its residuals and threat exposures explicitly. Each is reviewable in a 30-second skim.

This is the framework's user-facing claim: confinement that is actually used, because authoring is cheap. The hard work is the template set (§5) and the threat catalogue (§2). The user-facing surface is small enough to actually engage with.
