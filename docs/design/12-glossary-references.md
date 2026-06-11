# §12 Glossary and references

## 12.1 Glossary

**Abstract namespace socket.** A Linux AF_UNIX socket whose path begins with a null byte. Lives in a kernel-managed namespace rather than the filesystem. Not covered by filesystem ACLs (Landlock); requires AppArmor, seccomp, or BPF LSM to constrain.

**AppArmor.** A Linux Security Module (LSM) providing mandatory access control via per-profile rules. Used in Project Kennel for unix abstract-socket, ptrace, and signal rules where Landlock has gaps.

**Audit log.** Project Kennel's structured (JSONL) record of every policy decision made for each kennel. Source of forensic evidence and policy-refinement input.

**BPF / eBPF.** Berkeley Packet Filter, generalised to "extended BPF". A kernel mechanism for safely executing user-supplied programs at well-defined hook points. Used here for cgroup-attached network and bind enforcement.

**BPF LSM.** A subsystem allowing eBPF programs to act as LSM hooks. Available since kernel 5.7. The cleanest path for AF_UNIX abstract-namespace policy in future kernels.

**Bubblewrap (bwrap).** A lower-level sandboxing tool that uses Linux namespaces. Project Kennel uses similar primitives directly; bubblewrap-style isolation is a building block.

**Capsicum.** FreeBSD's capability-mode sandboxing mechanism. Referenced as a precedent for capability-based confinement; not used directly (Linux equivalent is Landlock + cgroup BPF).

**cgroup (v2).** Control group, version 2. Linux's hierarchical process grouping mechanism, used here as the unit of policy attachment (BPF programs attach to cgroups, processes are placed in cgroups).

**cgroup BPF.** eBPF programs attached to cgroup hooks (connect, bind, sendmsg, etc). The kernel mechanism by which Project Kennel enforces network policy.

**Kennel.** A scoped execution environment with a specific policy in force. Project Kennel's primary unit of policy. See §4.

**Constructed view.** Project Kennel's design pattern of presenting a kennel with a positively-constructed view of each resource class (filesystem, network, sockets, etc), containing only what policy grants. See §4.1.

**Default context.** The user's normal shell environment, unconstrained by Project Kennel. The trust root.

**Delta.** A change relative to a template. User policies are expressed as deltas; Project Kennel's diff tool surfaces the threat impact of each delta. See §5.3.

**DNS rebinding.** An attack where a name initially resolves to an allowed IP, then re-resolves to a forbidden IP, exploiting cache TTL behaviour. Project Kennel's `on_resolve_change` policy mitigates. See §7.5.5.

**Framework invariant.** A property Project Kennel enforces unconditionally; no template or user policy can change. See §5.5.

**INADDR_ANY rewriting.** Project Kennel's cgroup BPF mechanism for rewriting `bind(0.0.0.0)` to `bind(<kennel's private loopback>)`, transparently to the application. See §7.5.7.

**IPv4-mapped IPv6 address.** An IPv6 address of form `::ffff:a.b.c.d`, representing an IPv4 address. Treated by the kernel as IPv4 for some purposes. Project Kennel forces `IPV6_V6ONLY=1` to disambiguate.

**Landlock.** A Linux LSM available since kernel 5.13, providing unprivileged sandboxing of filesystem access. Network port restrictions since 6.7. Project Kennel's primary filesystem mechanism.

**Loopback subnet, per-kennel.** The IPv4 `/28` laid out `127 | tag(12) | ctx(8) | host(4)` and the IPv6 `/64` laid out `0xfd | gid(40) | ctx(16) | host(64)` assigned to a kennel for its private loopback traffic. `tag`/`gid` are the user's per-user values (from `/etc/kennel/subkennel`); `ctx` is the kennel's context. See §7.5.6.

**LSM.** Linux Security Module. The kernel framework that AppArmor, SELinux, Landlock, BPF LSM, and others plug into.

**Mount namespace.** A Linux namespace isolating the set of mounts visible to processes. Project Kennel uses mount namespaces to construct per-kennel filesystem views.

**no_new_privs.** A `prctl()` flag preventing a process from gaining privileges via setuid binaries or LSM transitions. Set unconditionally in every kennel. See §7.3.8.

**PID namespace.** A Linux namespace isolating process IDs. Processes in the namespace see only descendants; processes outside see all (subject to other constraints). Project Kennel uses PID namespaces for process isolation between kennels.

**pledge / unveil.** OpenBSD's process self-restriction mechanisms. Referenced as a precedent for declarative capability narrowing; not used directly.

**Portal (XDG portal).** A pattern, originated by Flatpak, where a sandboxed application accesses user resources via user-mediated dialogs hosted in the user's session. Method calls go via D-Bus; Project Kennel allows the portal family by default in templates that need user-mediated grants.

**SOCKS5 proxy.** A protocol for proxying TCP connections (and optionally UDP). Project Kennel's per-kennel SOCKS5 proxy is where outbound network policy is enforced. See §7.5.

**seccomp.** A Linux mechanism for filtering system calls per-process. Used here as defence-in-depth and for a few specific mechanisms (TIOCSTI on older kernels, AF_UNIX abstract-namespace deny as fallback).

**SELinux.** A Linux Security Module providing comprehensive label-based access control. Compatible with Project Kennel but not used as a primary mechanism (assumes user-space framework, not system-wide policy).

**Shim view.** See "constructed view". Used interchangeably for the filesystem and AF_UNIX cases.

**Sibling kennel.** Two kennels with the same parent (typically both children of the user's default context). Isolated from each other by default.

**Template.** A signed, versioned, threat-tagged policy artefact that users compose deltas against. See §5.

**Threat tag.** A reference from a policy rule to an entry in the threat catalogue (`THREATS.md`). Format: `<T-number>:<tag-slug>`.

**ULA (Unique Local Address, IPv6).** An IPv6 address range (`fc00::/7`) reserved for private use. Project Kennel allocates a `/48` at install time and per-kennel `/64`s for loopback isolation. See RFC 4193.

**Wayland.** A display server protocol replacing X11. Per-client capability model is stricter than X11's; Project Kennel supports Xwayland-isolated as the X11 path on Wayland hosts.

**xdg-dbus-proxy.** A small daemon for filtering D-Bus traffic at the method-call level. Used here as the per-kennel D-Bus broker. See §7.7.

**Xephyr.** A nested X server (X-server-inside-X-server) used for the X11-isolated path on X11 hosts. See §7.8.4.

**Xwayland.** An X server running as a Wayland client. Used for the X11-isolated path on Wayland hosts. See §7.8.3.

**Yama.** A Linux LSM providing coarse-grained `ptrace` restrictions. Less expressive than AppArmor's per-profile ptrace rules but easier to deploy system-wide.

## 12.2 References

### Linux kernel documentation

- Landlock: <https://www.kernel.org/doc/html/latest/userspace-api/landlock.html>
- BPF and cgroup BPF: <https://docs.kernel.org/bpf/index.html>
- Cgroup v2: <https://www.kernel.org/doc/Documentation/admin-guide/cgroup-v2.rst>
- Mount namespaces: <https://man7.org/linux/man-pages/man7/mount_namespaces.7.html>
- PID namespaces: <https://man7.org/linux/man-pages/man7/pid_namespaces.7.html>
- seccomp: <https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html>
- prctl(2), capabilities(7), unix(7), ip(7), ipv6(7): standard man pages

### RFCs

- RFC 4193: Unique Local IPv6 Unicast Addresses
- RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
- RFC 6890: Special-Purpose IP Address Registries
- RFC 1928: SOCKS Protocol Version 5
- RFC 3493: Basic Socket Interface Extensions for IPv6 (re: IPV6_V6ONLY)

### Related projects

- Flatpak: <https://flatpak.org/> — desktop application sandboxing; the portal model and xdg-dbus-proxy come from here.
- Bubblewrap: <https://github.com/containers/bubblewrap> — low-level sandboxing primitives.
- Firejail: <https://firejail.wordpress.com/> — broader sandboxing tool; alternative philosophy (seccomp-primary).
- systemd-nspawn: a different point in the design space (full container, separate root).
- LXC / LXD: full system containers.
- runj / FreeBSD jails: capability-confined Unix process groups in BSD.
- Capsicum: <https://www.cl.cam.ac.uk/research/security/capsicum/> — FreeBSD capability mode.
- OpenBSD pledge(2) and unveil(2): manual pages; declarative process-level confinement.

### Threat-modelling references

- MITRE ATT&CK: <https://attack.mitre.org/>
- npm supply-chain incident catalogue (various): a useful corpus of T1.2-class incidents.
- LWN.net articles on Landlock, BPF, sandboxing (search engine the canonical source).

### Adjacent reading

- "The Confused Deputy Problem" (Hardy 1988): foundational paper on why uid-based access control fails for delegated programs.
- "Operating System Security" (Trent Jaeger): textbook treatment of LSM-style access control.
- "Capability-based Computer Systems" (Henry Levy): historical treatment of capability systems, useful context for why "narrow capability" thinking matters.

## 12.3 Versioning of this document

The document is versioned with Project Kennel. Each chapter file's first line carries an implicit version tag via the document's overall version (in `00-frontmatter.md`). Section numbers (§7.5.5 etc) are stable within a published version; major-version revisions may restructure.

T-numbers are stable within a published version of `THREATS.md`. Pre-release iteration may renumber as the catalogue is refined. Stability commitments apply at v1.0; until then, threat IDs are subject to change.

The document's authoritative location is Project Kennel's git repository; this rendered version is a snapshot.
