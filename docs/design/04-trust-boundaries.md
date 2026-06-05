# §4 Trust boundaries and constructed views

Project Kennel's central technical move is the *constructed-view* pattern. Rather than enumerating what a kennel is denied against the host's real state, Project Kennel presents the kennel with a positively-constructed view of each resource class, containing only what the policy grants. What is not in the view is not present, not deniable, not enumerable, not negotiable.

The pattern is not novel in isolation. Flatpak's per-app filesystem views, container runtimes' mount namespaces, even chroot all share the structure. The novelty here is applying the pattern uniformly across every resource class — filesystem, network, AF_UNIX sockets, D-Bus, environment, process visibility — as the structural answer to optimisation-pressure-driven reconnaissance (§1.2). A workload that cannot enumerate its environment cannot probe for what to remove.

## 4.1 Constructed views versus denylists

The naive design is a denylist: enumerate the resources the kennel should not access, configure the kernel to deny them. This works against threats that fail closed: a process that hits a denial gets an error and stops.

It fails against threats that optimise. An agent given `find ~ -name '.env'` against a real `$HOME` with read denies on credential paths still sees the *existence* of `~/.ssh/`, `~/.aws/`, `~/.gnupg/` as directory entries — the number of files in each, their names, their sizes, their modification times. The fact that some files are deniable and others are not, which itself signals importance. The shape of the user's environment, from which the agent can plan circumvention.

The agent does not need to *read* `~/.ssh/id_ed25519` to know it exists. Knowing it exists is enough to plan: ask the user for SSH access, look for the private key elsewhere, search the user's history for past commands that used it, generate code that requires SSH and prompt the user to grant access.

Denylists leak structural information. The agent can enumerate them by trying things and observing which fail. The agent can plan against them by knowing what the user has chosen to deny — itself a signal of what is sensitive.

The constructed-view alternative: the kennel's view of `$HOME` is a fresh tmpfs containing only the directories explicitly bind-mounted in from the policy's grants. `~/.ssh/` is not present, not as "exists but denied" but as "does not exist". `find ~ -name '.env'` returns nothing because the `~` the kennel sees does not contain those files. The workload cannot enumerate what is not there.

The same logic applies to every resource class:

- The kennel's network view consists of one address (Project Kennel's SOCKS5 proxy). The host's real network is not deniable from inside the kennel — it is not present in the network namespace, not reachable via any route, not discoverable via `ip route show`. The user's loopback services do not exist in the kennel's `127.0.0.1`.
- The kennel's AF_UNIX socket view consists of the shimmed sockets the policy grants, present in the standard paths. The host's other sockets (`/var/run/docker.sock`, `~/.gnupg/S.gpg-agent`, `$XDG_RUNTIME_DIR/bus`) do not exist in the kennel's filesystem view.
- The kennel's D-Bus view consists of the methods on the bus names that the proxy permits. The full session bus is not deniable; it is not connected to.
- The kennel's process view (under PID namespace) consists of its own descendants. The user's shell, browser, IDE, password manager are not deniable; they are not visible.

Project Kennel's job is to *construct* what the workload sees rather than redact from what would otherwise be visible. Denial is structural. The workload's probing has no surface to act against.

## 4.2 The trust hierarchy

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         USER ACCOUNT (real uid)                          │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────┐     │
│   │             DEFAULT CONTEXT (the user's normal shell)          │     │
│   │   Full capabilities of the uid. Trusted by construction.       │     │
│   │                                                                │     │
│   │   ┌─────────────────────────────────────────────────────┐      │     │
│   │   │       KENNEL: ai-coding                             │      │     │
│   │   │   Constructed view of every resource class.         │      │     │
│   │   │   Talks outbound only via kennel-local proxy.       │      │     │
│   │   │   Talks D-Bus only via kennel-local dbus-proxy.     │      │     │
│   │   │                                                     │      │     │
│   │   │   ┌──────────────────────────────────────┐          │      │     │
│   │   │   │   REFINED KENNEL: ai-coding/npm      │          │      │     │
│   │   │   │   Further narrowing only.            │          │      │     │
│   │   │   │   net.mode=none during install.      │          │      │     │
│   │   │   └──────────────────────────────────────┘          │      │     │
│   │   └─────────────────────────────────────────────────────┘      │     │
│   │                                                                │     │
│   │   ┌─────────────────────────────────────────────────────┐      │     │
│   │   │       KENNEL: untrusted-build                       │      │     │
│   │   │   Independent narrowing. Cannot see ai-coding.      │      │     │
│   │   └─────────────────────────────────────────────────────┘      │     │
│   └────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

The boundaries that must not weaken:

- **Default context ↔ kennel.** A kennel cannot influence default-context processes, files (outside grants), sockets, or environment. The default context can inspect, signal, and kill its confined children (it owns them).
- **Sibling kennels.** Two kennels of the same parent cannot see or affect each other unless explicitly granted. Their loopback subnets are disjoint, their AF_UNIX views are disjoint, their PID visibility is disjoint.
- **Kennel ↔ host services.** Every syscall to the kernel passes through the kennel's policy. There is no bypass via "I'm still uid 1000". Same-uid is no longer the trust boundary; cgroup membership, mount namespace, and Landlock ruleset are.
- **Refined kennel ↔ parent kennel.** A refined kennel's policy is the intersection of its own declarations and its parent's. It may narrow further; it may not widen.

## 4.3 Project Kennel's own trust position

Project Kennel runs primarily as the user's uid, with one narrow exception: a privileged helper for network-interface setup (per-kennel loopback subnet allocation). Project Kennel's trust position:

- **Higher than kennels.** Owns the policy decisions, the proxy daemons, the audit log, the cgroup hierarchy.
- **Equal to the default context.** Cannot do anything the user couldn't do in their normal shell.
- **Bounded by the user's consent.** The user installs it, configures it, can disable it. Project Kennel does not survive a user who actively works against it.

Project Kennel's daemons (SOCKS5 proxy, xdg-dbus-proxy, per-kennel ssh-agent) are accessible to same-uid processes outside Project Kennel's kennels. A determined adversary in the default context can read Project Kennel's state directly. This is acceptable: the default context is the trust root — anyone there is, by assumption, the user.

The daemons are protected from the *kennels* they mediate (by the policy they enforce, and by PID-namespace isolation) but not from the user's normal shell or anything that user runs unconfined. The threat model is about confining same-uid processes the user has decided to confine; it is not about protecting the user from themselves.

## 4.4 Resource classes

The same architectural pattern appears in every resource class. Project Kennel presents the kennel with a constructed view of each, containing exactly what the policy grants:

| Resource class | Real host state | Constructed view inside kennel |
|---|---|---|
| Filesystem (§7.2) | Full `$HOME`, `/usr`, `/etc`, `/tmp`, `/mnt`, etc. | Shim `$HOME` containing only granted paths, bind-mounted from real locations; private `/tmp` tmpfs |
| Network (§7.3) | Real loopback `127.0.0.1` and `::1`; full routing | Per-kennel IPv4 `/28` (`127 \| tag(12) \| ctx(8) \| host(4)`) and IPv6 `/64` (`0xfd \| gid(40) \| ctx(16) \| host(64)`); outbound only via proxy |
| AF_UNIX sockets (§7.4) | All sockets in `$HOME` and `$XDG_RUNTIME_DIR` | Shim view: only granted sockets present; per-kennel service instances bind-mounted to standard paths |
| D-Bus (§7.5) | User's session bus, system bus | Per-kennel xdg-dbus-proxy filtering every method call |
| Process visibility (§7.7) | Full system processes | PID namespace: only the kennel's own descendants |
| Environment (§7.7) | Full inherited env from default shell | Curated subset; sensitive vars stripped, framework vars forced |

X11 (§7.6) is a special case. It is not directly grantable. For workflows that need X11, Project Kennel constructs an entirely separate X server per kennel (Xwayland-isolated on Wayland hosts, Xephyr-isolated on X11 hosts). The kennel's X server is unrelated to the host's; X11 clients inside the kennel can interact with each other but cannot reach the host display.

The unifying property: **what isn't constructed isn't there**. A kennel cannot accidentally reach something the policy author forgot to deny, because the view doesn't include it. Default-deny is structural, not the result of an exhaustive deny-list.

Consequences:

- **Inspection is easy.** The user can ask "what does the kennel see for X?" and the answer is "exactly what's in the constructed view for X". There is no "everything not denied"; there is just the view.
- **Policy edits are positive.** A user adding a capability writes "add this to the view", not "remove this from the deny list". Cognitive load is one direction.
- **The view is the security boundary.** Bugs in policy authoring are bugs in *what's included*, which is more visible than bugs in *what's excluded*.
- **Project Kennel must construct each view.** Non-trivial code in each subsystem: mount namespace setup for fs, cgroup BPF for network, bind mounts for unix sockets, proxy launches for dbus. Project Kennel is implementing the constructed-view pattern, not just enforcing rules.

## 4.5 Brokers

A complementary pattern: where direct access to a resource cannot be filtered at the kernel level with sufficient expressiveness, Project Kennel interposes a userspace broker that does the filtering on its behalf.

| Resource | Why a broker is needed | Broker |
|---|---|---|
| Outbound network | cgroup BPF allows per-address allow/deny, but DNS resolution, audit, and per-method policy are user-space concerns | SOCKS5 proxy (one per kennel) |
| D-Bus | Method-level filtering requires parsing the protocol | xdg-dbus-proxy (one per session bus, optionally one per system bus, per kennel) |
| X11 | No filtering exists at the X11 protocol level for security purposes | Xwayland-isolated or Xephyr-isolated (one X server per kennel) |
| ssh-agent (when used) | The agent's policy is per-key, not per-caller | Per-kennel ssh-agent instance, optionally with destination constraints |

Kernel-level enforcement is simple ("you can only talk to your broker"); policy expressiveness lives in user-space code Project Kennel controls. The brokers are vetted system tools where possible (xdg-dbus-proxy, Xephyr) and small purpose-built daemons otherwise (the SOCKS5 proxy, per-kennel ssh-agent).

Brokers add latency, code complexity, and an additional process per kennel per protocol. For the threat model this is acceptable; protocol-level filtering is the property we need and there is no way to get it at the kernel level alone.

## 4.6 What crosses each trust boundary

**Default context → kennel:**

- Project Kennel's invocation parameters (`kennel run <kennel-name> cmd`).
- The curated environment (per env policy).
- The constructed filesystem view (read-only by default for most paths).
- Standard input/output (the controlling terminal, possibly).
- Initial working directory (constrained to be inside the granted fs).

**Kennel → default context:**

- Exit status and signals to the parent.
- Standard output and stderr.
- Audit log events (via Project Kennel's log writer, not directly).
- Files written to granted writable paths (which the default context can read normally).

Nothing else. In particular:

- No D-Bus signals back to the user's session bus (the dbus-proxy is one-directional in practice; the bus filters incoming as strictly as outgoing).
- No notifications to the user's desktop unless explicitly granted (granting notifications is a meaningful capability — see §7.5).
- No clipboard access (the X11/Wayland clipboard does not bridge unless explicitly bridged).
- No keystroke or input events delivered to other windows.
- No `kill()` to processes outside the kennel.

**Kennel ↔ sibling kennel:** nothing, by default. Two kennels of the same parent are mutually invisible. Explicit grants (a shared filesystem path, a shared loopback service) are possible but require deliberate policy on both sides.

## 4.7 Required kernel features

Each resource class requires specific kernel mechanisms to construct the view safely:

| Resource class | Required mechanism | Minimum kernel |
|---|---|---|
| Filesystem view | Mount namespace + Landlock | 5.13 (Landlock) |
| Network view | Network namespace + cgroup BPF | 4.10 (cgroup BPF connect hooks) |
| AF_UNIX view | Mount namespace + AppArmor (for abstract sockets) | 2.6+ (mount ns); AppArmor distribution-dependent |
| D-Bus view | xdg-dbus-proxy + AF_UNIX view above | Userspace |
| Environment view | User-space spawn wrapper | None |
| Process view | PID namespace + procfs hidepid | 3.8 (PID ns) |

The full kernel feature matrix appears in §8. Most modern Linux systems have everything needed; Project Kennel refuses to start on kernels lacking required features rather than degrade silently.
