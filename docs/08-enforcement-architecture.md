# §8 Enforcement architecture

## 8.1 Mechanism map

Each resource class maps to one or more kernel mechanisms. Project Kennel uses these in combination; no single mechanism is sufficient.

| Resource class | Primary mechanism | Fallback / gap |
|---|---|---|
| Exec (§7.1) | Landlock `FS_EXECUTE` + `PR_SET_NO_NEW_PRIVS` | AppArmor for transition semantics |
| Filesystem (§7.2) | Landlock filesystem ACL | Mount namespace for constructed view |
| Network port (§7.3) | Landlock network (kernel 6.7+) | cgroup BPF for broader coverage |
| Network address (§7.3) | cgroup BPF (inet*_connect hooks) | None — required |
| Loopback isolation (§7.3) | cgroup BPF (rewrite/filter) | Netns for stronger isolation (optional) |
| AF_UNIX path (§7.4) | Landlock (filesystem perms) | Mount namespace for shim view |
| AF_UNIX abstract (§7.4) | AppArmor `unix` rules | BPF LSM, or seccomp on `connect()` |
| Proc visibility (§7.7) | Mount namespace + `hidepid` | PID namespace for stronger |
| Ptrace (§7.7) | AppArmor `ptrace` | Yama (coarse) |
| Signals (§7.7) | AppArmor `signal` | PID namespace |
| Env (§7.7) | User-space wrapper | None — wrapper-only |
| Capabilities (§7.7) | `prctl`/`capset` in wrapper | None — wrapper-only |
| Mount visibility (§7.7) | Mount namespace + Landlock | None — required |
| TIOCSTI (§7.7) | Sysctl check at policy load + seccomp | Refuse to start if unsupported |
| Seccomp (§7.7) | seccomp filter | None — straightforward |

## 8.2 Kernel feature requirements

Project Kennel requires the following kernel features, with version requirements:

| Feature | Minimum kernel | Notes |
|---|---|---|
| Landlock filesystem | 5.13 | Read/write/exec; the foundation |
| Landlock network | 6.7 | Port-level restrictions |
| Landlock FS_EXECUTE | 6.10 | Proper exec semantics |
| cgroup v2 | 4.5 | Universal on modern systems |
| cgroup BPF (inet*_connect) | 4.10 | Universal |
| cgroup BPF (bind, sock_create) | 5.7 | Common |
| Mount namespace | 2.6.x | Universal |
| PID namespace | 3.8 | Universal |
| Network namespace | 2.6.x | Universal (used optionally) |
| User namespace | 3.8 | Used for some advanced configurations |
| `PR_SET_NO_NEW_PRIVS` | 3.5 | Universal |
| AppArmor | Distribution-dependent | Optional but recommended |
| `legacy_tiocsti` sysctl | 6.2 | Defaults safe on newer kernels |

Recommended minimum: kernel 6.10. Project Kennel refuses to apply policies that require unavailable features and reports clearly which features are missing.

## 8.3 The spawn flow

Starting a kennel with `kennel run ai-coding bash`:

```
1. Load policy file, validate against schema
   - Check template inheritance, resolve to flat effective policy
   - Verify Project Kennel invariants
   - Check kernel feature availability against required features

2. Resolve DNS names in net.* allowlist; pin to IPs

3. Allocate kennel resources:
   - Kennel ID (small integer, derived from policy name hash)
   - Loopback IPv4 subnet (127.<tag>.<ctx>.0/24)
   - Loopback IPv6 ULA /64
   - Cgroup path (/sys/fs/cgroup/kennel/<ctx>/)
   - Shim directory (/run/kennel/<ctx>/)

4. Privileged-helper steps (if helper available):
   - Add IPv4 address to loopback (or to per-kennel dummy interface)
   - Add IPv6 ULA address
   - Create cgroup if not exists

5. Launch supporting daemons (if not already running for this kennel):
   - SOCKS5 proxy listening on kennel's loopback address
   - xdg-dbus-proxy for session bus (if dbus.session.enabled)
   - xdg-dbus-proxy for system bus (if dbus.system.enabled)
   - Per-kennel ssh-agent (if templates reference one)
   - Xwayland or Xephyr (if X11 isolation enabled)

6. Compile and attach BPF programs to cgroup:
   - inet4_connect, inet6_connect: address allowlist
   - inet_sock_create: family allowlist
   - bind4, bind6: loopback rewrite + denylist
   - setsockopt: force IPV6_V6ONLY=1

7. (Optional) Load AppArmor profile fragment if policy uses unix-abstract,
   ptrace, signal rules

8. Fork:
   parent: wait, manage lifecycle, audit
   child:
     a. Enter cgroup (write own pid to cgroup.procs)
     b. unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC)
        (network namespace optional, depending on policy)
     c. mount --make-rslave / (detach from host propagation)
     d. Construct shim view: bind-mount granted paths
     e. Bind-mount shim over real $HOME and $XDG_RUNTIME_DIR
     f. Mount private tmpfs at /tmp
     g. Mount /proc with hidepid=2
     h. Curate environment per env.* policy
     i. Set PR_SET_NO_NEW_PRIVS
     j. Drop capabilities per cap.* policy
     k. Apply seccomp filter
     l. Apply Landlock ruleset (final step before exec; ruleset is sealed)
     m. execve(command)

9. Parent process supervises the kennel:
   - Reaps zombies
   - Logs lifecycle events to audit log
   - Restarts crashed supporting daemons if policy specifies
   - On kennel exit: cleans up shim directory, removes loopback addresses,
     stops supporting daemons that have no other kennels using them
```

Step ordering is significant. Landlock is applied last because once applied, the ruleset is sealed and cannot be widened. Several setup steps (especially mount manipulation and seccomp) need broader access than the final ruleset allows.

## 8.4 Inheritance

Children of confined processes are automatically in the same cgroup (cgroup membership inherits across `fork()` by kernel design). The Landlock ruleset is sealed for the lifetime of the process and is inherited by children via `execve()`. The seccomp filter inherits similarly.

Refinement (narrowing the policy further in a child) is achieved by:

- The child calling `landlock_create_ruleset()` itself with a stricter policy.
- The child re-entering `kennel` with a refined kennel name (`kennel run ai-coding/npm cmd`), which sets up an additional Landlock ruleset on top of the existing one.

Widening is not possible. A child cannot escape its parent's confinement, by kernel design.

## 8.5 Project Kennel's privileged components

Project Kennel runs primarily as the user's uid. Two components have elevated privilege:

**The network-configuration helper.** Adds IPv4/IPv6 addresses to loopback or per-kennel dummy interfaces. Requires `CAP_NET_ADMIN`. Installed setuid root or with file capability `CAP_NET_ADMIN=ep`.

Trust boundary: this helper accepts requests only via a Unix socket owned by Project Kennel's UID with mode 0600. It validates that every requested operation falls within Project Kennel's reserved address space (e.g., the configured ULA `/48`, the `127.<tag>.0.0/16` subnet). It refuses any request outside that space.

The helper is approximately 100 lines and is Project Kennel's primary attack surface for privilege escalation. It is reviewed carefully, fuzzed, and kept narrow. A future revision could replace it with a long-running daemon owning `CAP_NET_ADMIN`, accessed via a privileged socket; this trades fewer setuid invocations for a continuously-privileged daemon.

**The cgroup-creation helper** (optional). On systems where cgroup v2 delegation is not pre-configured, a privileged helper creates Project Kennel's cgroup hierarchy at install time. After that, the user's cgroups can be manipulated unprivileged within the delegated subtree.

Most modern distributions pre-configure cgroup v2 delegation via systemd, so this helper is rarely needed at runtime. It is documented for completeness.

## 8.6 Auditing

Every connection attempt, every denied syscall, every policy decision is tagged with kennel ID and written to a structured log per kennel.

Format: JSONL, one event per line, schema versioned.

```jsonl
{"ts":"2026-05-16T12:34:56.789Z","ctx":"ai-coding","pid":12345,"event":"deny","resource":"net.connect","detail":{"addr":"169.254.169.254","port":80}}
{"ts":"2026-05-16T12:34:57.123Z","ctx":"ai-coding","pid":12345,"event":"allow","resource":"fs.read","detail":{"path":"/home/u/projects/foo/src/main.rs"}}
{"ts":"2026-05-16T12:34:58.456Z","ctx":"ai-coding","pid":12346,"event":"deny","resource":"unix.connect","detail":{"path":"/var/run/docker.sock","reason":"deny-list"}}
```

Sources of audit events:

- **Kernel** via LSM hooks (Landlock, AppArmor). Captured by an audit daemon reading from `audit(7)` or netlink.
- **cgroup BPF programs.** BPF maps store per-event records; user-space reader drains them.
- **Project Kennel's daemons** (SOCKS5 proxy, dbus-proxy). Each writes its own audit events directly.
- **The spawn wrapper.** Lifecycle events (kennel start, exit, daemon launches).

Logging philosophy:

- **Deny events: always logged.** They are security events. The user needs to be able to answer "what did the kennel try to do that I forbade?"
- **Allow events: selectively logged.** Default `level = "summary"` records the first occurrence of each (resource, target) pair per kennel lifetime. `level = "full"` records every allow event (verbose; for debugging). `level = "off"` records only denies.
- **Per-kennel log files.** Each kennel has its own log under `~/.local/state/kennel/<kennel>/`. Easier to inspect, easier to retain selectively, easier to ship.

The audit log is the primary debugging tool. A user puzzled by "why won't my AI agent reach X" reads the relevant `network.jsonl` and gets a structured answer:

```
{"ts":"...","event":"deny","resource":"net.connect","detail":{"name":"api.example.com","reason":"not in net.allow"}}
```

Project Kennel also provides `kennel audit <kennel> [--since 1h] [--resource net]` for ad-hoc queries.

## 8.7 Lifecycle of the supporting daemons

Per-kennel daemons (SOCKS5 proxy, dbus-proxy, ssh-agent, Xwayland/Xephyr) are managed by Project Kennel's supervisor:

**Launch.** When a kennel starts and a daemon is needed, the supervisor launches it. The daemon's socket is placed at a framework-known path (`/run/kennel/<ctx>/<daemon>.sock`).

**Reuse.** If a kennel restarts (`kennel` invoked again with the same kennel name), existing daemons are reused if their config hash matches the current policy. If the policy has changed, daemons are restarted.

**Shutdown.** When the last process in a kennel exits, the supervisor reaps the daemons after a configurable grace period (default 30 seconds — allows quick kennel restart without re-paying daemon startup cost). After the grace period, daemons are terminated and resources cleaned up.

**Crash recovery.** If a daemon crashes while a kennel is active, the supervisor restarts it. The kennel's traffic to that daemon will briefly fail (connections to a missing proxy fail with ECONNREFUSED until the proxy is back). Audit log records the crash and restart.

**Health checks.** The supervisor periodically probes each daemon (TCP connect for proxies, D-Bus call for dbus-proxy, X11 query for X servers). Failed health checks trigger a restart.

## 8.8 Inter-kennel isolation

Two kennels running concurrently are isolated by:

- **Different cgroups.** BPF programs attached to one don't affect the other.
- **Different mount namespaces.** Constructed views are disjoint.
- **Different PID namespaces.** Process visibility is disjoint.
- **Different loopback addresses.** Network reachability is disjoint.
- **Different supporting daemons.** Each kennel has its own proxy, dbus-proxy, etc.
- **Different shim directories.** AF_UNIX socket views are disjoint.

What is *not* isolated: the user's uid is shared. A determined same-uid attacker outside both kennels can read Project Kennel's state for either kennel, signal its processes (if not in a PID namespace from the host's perspective), or read its audit logs. A stricter mode that isolates Project Kennel's daemons from the unconfined default context is a v2 question (§11.1).

## 8.9 Performance

Kennel startup cost on a modern Linux system, rough order of magnitude:

| Step | Time |
|---|---|
| Policy parse and validation | 5–10 ms |
| DNS pre-resolution | 50–500 ms (one round-trip per name) |
| Cgroup setup | 1–5 ms |
| BPF program load and attach | 10–50 ms |
| Privileged helper (network config) | 5–20 ms |
| Daemon launches (cold) | 200–1000 ms per daemon |
| Mount namespace + bind mounts | 5–20 ms |
| Landlock + seccomp apply | 1–5 ms |
| `execve()` of user command | 1–10 ms |

Cold start: 1–2 seconds is typical. Warm restart (daemons already running): 100–200 ms. Both are acceptable for interactive use.

Runtime overhead:

- BPF programs add a small per-syscall cost (low microseconds). Imperceptible.
- Landlock adds a small per-syscall cost. Imperceptible.
- Mount namespace adds zero runtime cost after setup.
- The SOCKS5 proxy adds latency to every network operation (one extra round-trip locally, name resolution). Typically <1 ms per connection.
- The dbus-proxy adds latency to every method call (one extra hop). Typically <500 μs per call.

For interactive workflows and developer-tool workloads, the overhead is negligible. For high-throughput workloads (mass DNS queries, thousands of small HTTP requests), the proxy bottleneck may become noticeable; documented as a known limitation.

## 8.10 Composition with other security tools

- **systemd.** `kennel` and `systemd-run --user` should coexist. A long-running user service can wrap itself in a kennel.
- **Flatpak.** Orthogonal. Flatpak handles packaged desktop apps; this handles command-line and developer workflows.
- **Docker / Podman.** A kennel can grant or deny the container daemon socket. Containers running inside a kennel are bounded by that kennel's policy (volume mounts must be within `fs.read`/`fs.write`, published ports go via per-kennel loopback). The `containerised-service` and `containerised-tool` templates encode the conventions. T20–T23 in `THREATS.md` document the container-specific threats and their residuals.
- **System-wide AppArmor.** Project Kennel's optional AppArmor fragments compose with system policies; Project Kennel's fragments are loaded as additional profiles, not replacements.
- **System-wide SELinux.** Compatible; Project Kennel's enforcement is independent of SELinux labels. On SELinux systems, Project Kennel runs within the user's domain and adds layered constraints.
- **Firejail, bubblewrap.** Project Kennel uses bubblewrap-equivalent mechanisms (mount namespaces, etc) directly. Running firejail-wrapped commands inside a kennel is permissible but generally redundant.

## 8.11 What Project Kennel refuses to start

Project Kennel refuses to start a kennel if:

- A required kernel feature is missing (e.g. cgroup BPF unavailable but `net.mode != "open"` and `net.allow` is non-empty).
- The policy fails schema validation.
- A Project Kennel invariant would be violated.
- The privileged helper is required (e.g. IPv6 enabled) but unavailable.
- A supporting daemon required by the policy fails to launch.
- The kernel's `legacy_tiocsti` is enabled but the policy requires it disabled.

Each refusal produces a clear, actionable error message identifying the missing feature, the failed check, or the misconfiguration. No silent degradation.
