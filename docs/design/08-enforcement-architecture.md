# §8 Enforcement architecture

§4 set out what Project Kennel is: a reference monitor for the user level, built in user space — a mediator every access passes through, that the workload it confines cannot bypass or tamper with, and that is small enough to audit. This chapter is how the kernel mechanisms realise that monitor, and the three reference-monitor properties organise it.

- Complete mediation is the mechanism map (§8.1) and the spawn flow (§8.3): each kennel is assembled so that every resource is either absent from its view or reachable only through a transaction the monitor authorises, and §8.8 holds that line between kennels as well as around them.
- Tamperproof is §8.5: which components hold privilege, for how long, and why nothing the workload runs can reach them.
- Verifiable is the discipline the rest of the chapter answers to — the performance characteristics (§8.9), which follow from mediating control rather than data, and the refuse-to-start checks (§8.11) that decline to run when a required mechanism is missing rather than degrade silently.

The two limbs of §4 — construction, where a resource is simply absent from the kennel's view, and interposition, where it is reachable only through a transaction the monitor authorises — are what these mechanisms implement, resource class by resource class. The map below shows which mechanism carries which limb for each class.

## 8.1 Mechanism map

Each resource class maps to one or more kernel mechanisms. Project Kennel uses these in combination; no single mechanism is sufficient.

| Resource class | Primary mechanism | Fallback / gap |
|---|---|---|
| Exec (§7.3) | Landlock `FS_EXECUTE` + `PR_SET_NO_NEW_PRIVS` | — |
| Filesystem (§7.4) | Landlock filesystem ACL | Mount namespace for constructed view |
| Network port (§7.5) | Landlock network (kernel 6.7+) | cgroup BPF for broader coverage |
| Network address (§7.5) | cgroup BPF (inet*_connect hooks) | None — required |
| Loopback isolation (§7.5) | cgroup BPF (rewrite/filter) | Netns for stronger isolation (optional) |
| AF_UNIX path (§7.6) | Landlock (filesystem perms) | Mount namespace for shim view |
| AF_UNIX abstract (§7.6) | Landlock scoping (`SCOPE_ABSTRACT_UNIX_SOCKET`, ABI 6 / kernel 6.12+) | seccomp `connect()` filter or AppArmor `unix` rules below ABI 6 |
| Proc visibility (§7.9) | Mount namespace + `hidepid` | PID namespace for stronger |
| Ptrace (§7.9) | PID namespace + seccomp (`SYS_ptrace`) | Yama (coarse) |
| Signals (§7.9) | Landlock scoping (`SCOPE_SIGNAL`, ABI 6 / kernel 6.12+) + PID namespace | AppArmor `signal` below ABI 6 |
| Env (§7.9) | User-space wrapper | None — wrapper-only |
| Capabilities (§7.9) | `prctl`/`capset` in wrapper | None — wrapper-only |
| Mount visibility (§7.9) | Mount namespace + Landlock | None — required |
| TIOCSTI (§7.9) | Sysctl check at policy load + seccomp | Refuse to start if unsupported |
| Seccomp (§7.9) | seccomp filter | None — straightforward |

## 8.2 Kernel feature requirements

Project Kennel requires the following kernel features, with version requirements:

| Feature | Minimum kernel | Notes |
|---|---|---|
| Landlock filesystem | 5.13 | Read/write/exec; the foundation |
| Landlock network | 6.7 | Port-level restrictions |
| Landlock FS_EXECUTE | 6.10 | Proper exec semantics |
| Landlock scoping (ABI 6) | 6.12 | Abstract-AF_UNIX + signal isolation, default-on where present |
| cgroup v2 | 4.5 | Universal on modern systems |
| cgroup BPF (inet*_connect) | 4.10 | Universal |
| cgroup BPF (bind, sock_create) | 5.7 | Common |
| Mount namespace | 2.6.x | Universal |
| PID namespace | 3.8 | Universal |
| Network namespace | 2.6.x | Universal (used optionally) |
| User namespace | 3.8 | **The spawn foundation.** Created by the privhelper factory (§7.2) as the operator, so the userns is operator-owned. Its maps are precise identity lines — host root `0 0 1` + the operator `<op> <op> 1` (+ one per granted gid), no subuid — giving the kennel a real uid 0 and `CAP_SYS_ADMIN` *inside the namespace* to `mount`/`pivot_root` (the bubblewrap-equivalent mechanism). The `0 0 1` line needs `CAP_SETUID`, so construction is privileged; the privhelper's post-`clone` child does it, then `fexecve`s the trusted `kennel-bin-init` as PID 1 / uid 0. |
| PID namespace (via userns) | 3.8 | `CLONE_NEWPID` is in the factory's single `clone`, so the privhelper child is PID 1 of the fresh PID namespace directly — no double-fork (a later `unshare(CLONE_NEWPID)` would leave the caller in the parent namespace and force one; the clone does not). Being PID 1 is what lets it mount a fresh `/proc`. `kennel-bin-init` inherits this as PID 1 and forks the operator-uid workload beneath it. |
| `PR_SET_NO_NEW_PRIVS` | 3.5 | Universal |
| AppArmor | Distribution-dependent | Below-ABI-6 abstract-AF_UNIX/signal fallback. **Also a deploy prerequisite** where the distro restricts unprivileged user namespaces (next paragraph). |
| `legacy_tiocsti` sysctl | 6.2 | Defaults safe on newer kernels |

Recommended minimum: kernel 6.10 (Landlock ABI 5, the project floor). On 6.12+ (ABI 6) Landlock scoping comes into play and abstract-AF_UNIX/signal isolation is enforced natively rather than via the seccomp/AppArmor fallback; the development and CI box runs 6.17 (ABI 7). Project Kennel refuses to apply policies that require unavailable features and reports clearly which features are missing.

**Unprivileged user namespaces must be permitted.** The spawn rests on an unprivileged user namespace (above). Some hardened distributions restrict this by default: Ubuntu 23.10+/24.04 ship `kernel.apparmor_restrict_unprivileged_userns=1`, under which `unshare(CLONE_NEWUSER)` *succeeds* but the process holds **no capabilities** in the new namespace — the first `/proc/self/setgroups`/uid_map/gid_map write returns `EACCES` and the sandbox cannot be built. The remedy, and the supported deployment posture, is an AppArmor profile granting `userns` to the kenneld binary (`dist/apparmor/kenneld`, attached to `/usr/libexec/kennel/kenneld`); it restores the capability for kenneld alone without relaxing the host-wide restriction. This is the AppArmor counterpart of the privhelper's file capabilities (`07-paths.md`) — a one-time install step, not a runtime concern. Where the sysctl is `0` or absent, no profile is needed. kenneld surfaces a clear diagnostic (naming the sysctl and the profile) rather than failing obscurely if the capability is absent.

The profile is `flags=(unconfined)`: it *grants* `userns` and confines nothing else. An enforcing profile cannot confine kenneld here, because the kenneld binary's forked spawn child must be permitted `userns`/`mount`/`pivot_root`/`capability sys_admin` to build the sandbox, then sets `PR_SET_NO_NEW_PRIVS` (seccomp requires it) and execs the *arbitrary* workload. Under no-new-privs the kernel forbids AppArmor from changing the profile at exec — *every* transition is denied, both `Ux` (to unconfined) and even `Cx`/`Px` to a stricter child profile. An enforcing profile would therefore leave only `ix` (inherit) for the workload, handing it kenneld's own `mount`/`userns`/`sys_admin` — broader than unconfined. With `flags=(unconfined)` the workload exec proceeds with no transition, its confinement left to Landlock + seccomp + the namespaces. Confining the workload *via AppArmor* would require runtime `aa_change_onexec` integration in the spawn — a v2 question (§11.1), outside the project's "AppArmor is not relied on for the workload on ABI 6+" stance.

## 8.3 The spawn flow

Starting a kennel with `kennel run ai-coding bash`:

The flow consumes a *settled policy* — the flat, signed artefact produced by the compile step (§9.10), not a source policy. Resolution (template inheritance, includes, deltas, source-signature verification, lockfile checks) happened earlier, at compile time. In local development the compile may run implicitly just before this flow when the source has changed; in attested deployments the settled policy was compiled and signed centrally and pushed to the workstation. Either way, by the time the spawn flow runs, the policy is settled.

```
1. Load the settled policy
   - Verify its single signature against the trust store
   - Re-assert Project Kennel framework invariants (cheap; structural)
   - Substitute per-instance variables (<ctx>, <uid>, <kennel>, <home>)
   - Check kernel feature availability against the features the policy requires

2. Resolve DNS names in net.* allowlist; pin to IPs

3. Allocate kennel resources:
   - Kennel ID (small integer, derived from policy name hash)
   - Loopback IPv4 subnet (/28: `127 | tag(12) | ctx(8) | host(4)`)
   - Loopback IPv6 ULA /64
   - Cgroup path (/sys/fs/cgroup/kennel/<ctx>/)
   - Shim directory (/run/kennel/<ctx>/)

4. Privileged-helper steps:
   - Add IPv4 address to loopback (or to per-kennel dummy interface)
   - Add IPv6 ULA address
   - Create cgroup if not exists
   - (Roadmap, §7.5) `AddLoopbackAlias`: for `constrained`/`unconstrained`
     net-ns modes, bring the kennel's `/28`+`/64` up on the host `lo` so the
     host-side BIND leg can mirror inbound listeners at the kennel's own IP

5. Launch supporting daemons (if not already running for this kennel):
   - the egress proxy — on the kennel's loopback address, or, under the
     network-namespace model (§7.5), in the host net-ns as a CONNECT delegate
     behind a kenneld↔delegate socketpair rather than a TCP loopback listener
   - the `IDBus` facade (§7.7) for the session bus (if dbus.session.enabled)
   - the `IDBus` facade (§7.7) for the system bus (if dbus.system.enabled)

6. Compile and attach BPF programs to cgroup:
   - inet4_connect, inet6_connect: address allowlist
   - inet_sock_create: family allowlist
   - bind4, bind6: loopback rewrite + denylist
   - setsockopt: force IPV6_V6ONLY=1

7. (Below Landlock ABI 6 only) Load the fallback for abstract-AF_UNIX/signal
   isolation: a seccomp connect() filter, or an AppArmor profile fragment.
   On ABI 6+ kernels this is unnecessary — the scoping bits added to the
   Landlock ruleset (step 8l) cover it natively.

8. Construct (the privhelper is the factory — §7.2). The privhelper, running as
   the operator with file caps (`CAP_SETUID`/`CAP_SETGID`/`CAP_SETFCAP`, plus
   `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`), does all privileged construction in its own
   post-`clone` child before handing off across one irreversible boundary. The
   operator drives this by sending the construction-half Plan (§7.2.3) over a
   `SOCK_SEQPACKET` socketpair (`ConstructKennel`); the construction-half is parsed
   host-side, where there is no sandbox to manipulate it.

   parent (kenneld / operator): hold the full Plan; wait, manage lifecycle, audit;
     write nothing into the namespace except — escalating only for this — the maps
   privhelper (host root): opens the trusted root-owned `kennel-bin-init` binary
     (provenance-verified: root-owned, not group/other-writable) and holds the fd;
     `clone(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC [| CLONE_NEWNET])`
     → child C is PID 1 of the new PID namespace directly (no double-fork). Because
     the operator's privhelper creates the userns, the userns is **operator-owned**,
     which is what lets kenneld later open the binder device.
   child C (still privhelper code, full caps in the new userns):
     a. Write the precise identity maps in one `write(2)` each:
        uid_map / gid_map `0 0 1` + `<operator> <operator> 1` (+ one line per
        granted gid). The `0 0 1` line gives the kennel a real uid 0 (host root
        mapped), needed because binderfs (and the view/`/dev`/library binds) assign
        nodes to uid 0 of the mounting userns. No subuid/subgid. setgroups handling
        and supplementary groups are written here too, fully, in this one pass.
     b. Join the kennel cgroup; for the network-namespace modes (§7.5) bring up
        `lo` inside the net-ns with the kennel's assigned `/28`+`/64`.
     c. Self-escalate to the kennel's uid 0 and build the root-owned surfaces:
        mount --make-rprivate /; the constructed view (fresh tmpfs root; bind-mount
        granted paths beneath the shim $HOME); synthetic /etc; constructed /dev;
        private tmpfs at /tmp; /proc with hidepid=2 (permitted — C is PID 1 of its
        ns). Mount binderfs at the view's `/dev/binderfs/`, allocate the standard
        `binder` device, and **chown `/dev/binderfs/binder` to the operator** so the
        operator-uid facades and workload can open it.
     d. `pivot_root` into the view and detach the old host root — the structural
        sever. After this the host path to `kennel-bin-init` is gone from the mount
        namespace.
     e. `fexecve` the trusted `kennel-bin-init` by the fd opened pre-`clone`, with
        **empty argv/envp** (nothing for `/proc/<pid>/cmdline`/`environ` to leak).
        `fexecve` also keeps the init binary out of the view. This eliminates the
        window where a uid-0 binary runs while the host fs is still visible.
   ─────────────────────────────────────── trust boundary (host root gone) ───
   kennel-bin-init (PID 1, uid 0, trapped in the pivoted view):
     f. Open `/dev/binderfs/binder`; `GET_SANDBOX_PLAN` to node 0, retrying until
        kenneld has claimed node 0. kenneld acquires node 0 by opening
        `/proc/<init-host-pid>/root/dev/binderfs/binder` (the operator-owned userns
        makes the open succeed; SCM_RIGHTS fd-passing is rejected — binder fds are
        per-opener) and replies with the supervision-half Plan as a flat
        serialized buffer (binder copies it — no shared-memory hazard), the pty
        return socket riding as a passed file descriptor. kenneld identifies the
        kennel by the binderfs *instance* the txn arrived on.
     g. Under the network-namespace model (§7.5), once `INet` is registered, fork
        the in-kennel SOCKS5 facade as a sibling of the workload inside the net-ns
        and view; it serves SOCKS5 at
        `$KENNEL_SOCKS_PROXY` and relays `CONNECT`/`BIND` over binder. The
        host-side BIND leg mirrors allowed binds onto the host alias; both legs are
        kenneld↔delegate socketpairs, not binder participants.
     h. Fork the facades, each dropped to the operator (`set_gid` → groups →
        `set_uid`); fork the workload and drop it to the operator the same way.
        Only `kennel-bin-init` stays uid 0; the workload is never uid 0.
   workload child (where the seal completes and the workload runs):
     i. Curate environment per env.* policy
     j. Set PR_SET_NO_NEW_PRIVS
     k. Apply seccomp filter
     l. Apply Landlock ruleset, including ABI-6 scoping
        (SCOPE_ABSTRACT_UNIX_SOCKET + SCOPE_SIGNAL) where the kernel
        supports it (final step before exec; ruleset is sealed). Landlock and
        seccomp apply to the **workload child only** — not `kennel-bin-init` or the
        facades, which must stay free to fork, `waitpid`, and reach the bus.
     m. execve(command)

   Exit status rides the process chain (`kennel-bin-init` `_exit` → privhelper →
   kenneld), not binder, which may already be torn down; binder carries in-life
   telemetry only.

   Supplementary groups: the maps written in step (a) include one line per granted
   gid, so device-passthrough/identity grants (§7.4.8) land in the same single
   privileged write — no separate handshake. Groups not granted collapse to the
   overflow gid (`nogroup`).

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

Trust boundary: this helper accepts requests only via a Unix socket owned by Project Kennel's UID with mode 0600. It validates that every requested operation falls within the caller's reserved address space — the per-user IPv6 ULA `/48` and, within `127.0.0.0/8`, the kennel's `/28` (`127 | tag(12) | ctx(8) | host(4)`) — reconstructing the embedded `tag`/`gid`/`ctx` and comparing to the caller's scope. It refuses any request outside that space.

The helper is a few hundred lines and is Project Kennel's primary attack surface for privilege escalation. It is reviewed carefully, fuzzed, and kept narrow. A future revision could replace it with a long-running daemon owning `CAP_NET_ADMIN`, accessed via a privileged socket; this trades fewer setuid invocations for a continuously-privileged daemon.

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

- **Kernel** via LSM hooks (Landlock; AppArmor only on the below-ABI-6 fallback path). Captured by an audit daemon reading from `audit(7)` or netlink.
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

Per-kennel daemons (SOCKS5 proxy, the D-Bus facade) are managed by Project Kennel's supervisor:

**Launch.** When a kennel starts and a daemon is needed, the supervisor launches it. The daemon's socket is placed at a framework-known path (`/run/kennel/<ctx>/<daemon>.sock`).

**Reuse.** If a kennel restarts (`kennel` invoked again with the same kennel name), existing daemons are reused if their config hash matches the current policy. If the policy has changed, daemons are restarted.

**Shutdown.** When the last process in a kennel exits, the supervisor reaps the daemons after a configurable grace period (default 30 seconds — allows quick kennel restart without re-paying daemon startup cost). After the grace period, daemons are terminated and resources cleaned up.

**Crash recovery.** If a daemon crashes while a kennel is active, the supervisor restarts it. The kennel's traffic to that daemon will briefly fail (connections to a missing proxy fail with ECONNREFUSED until the proxy is back). Audit log records the crash and restart.

**Health checks.** The supervisor periodically probes each daemon (TCP connect for proxies, D-Bus call for dbus-proxy). Failed health checks trigger a restart.

## 8.8 Inter-kennel isolation

Two kennels running concurrently are isolated by:

- **Different cgroups.** BPF programs attached to one don't affect the other.
- **Different mount namespaces.** Constructed views are disjoint.
- **Different PID namespaces.** Process visibility is disjoint.
- **Different loopback addresses.** Network reachability is disjoint.
- **Different supporting daemons.** Each kennel has its own proxy, dbus-proxy, etc.
- **Different shim directories.** AF_UNIX socket views are disjoint.
- **Different binderfs instances.** Each kennel mounts its own binderfs inside its
  own user+mount namespace; two instances share no nodes (§7.1.2). A binder node
  reference is an opaque kernel object that does not transfer between instances.

The one designed exception is the **binder cross-instance relay** (§7.1.6):
two kennels may communicate over the binder bus, but only by an explicit *bilateral*
declaration — the consuming kennel declares `[[binder.consume]]` naming the service and
the providing kennel, and the providing kennel declares `[[binder.provide]]` naming the
service and accepting the consuming kennel in `accept_from`. A unilateral declaration on
either side yields a `getService` denial. kenneld is the sole relay; it copies a flat
payload between instances (no shared memory — `BINDER_TYPE_FD`/`BINDER_TYPE_PTR` are
rejected cross-instance) and audits every crossing as `binder.cross`. Kennels with no
`[binder]` section have no IPC surface at all and remain fully isolated. This is the only
sanctioned escape from the default; the workload still cannot reach any kennel it was not
explicitly granted.

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
- **Docker / Podman.** A kennel can grant or deny the container daemon socket. Containers running inside a kennel are bounded by that kennel's policy (volume mounts must be within `fs.read`/`fs.write`, published ports go via per-kennel loopback). The `containerised-service` and `containerised-tool` templates encode the conventions. T3.2–T3.5 in `THREATS.md` document the container-specific threats and their residuals.
- **System-wide AppArmor.** On the below-ABI-6 fallback path, Project Kennel's AppArmor fragments compose with system policies; they are loaded as additional profiles, not replacements. On ABI 6+ kernels Project Kennel does not rely on AppArmor at all.
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
