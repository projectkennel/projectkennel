# §3 Trust boundaries and constructed views

## 3.1 The trust hierarchy

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         USER ACCOUNT (real uid)                          │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────┐     │
│   │             DEFAULT CONTEXT (the user's normal shell)          │     │
│   │   Full capabilities of the uid. Trusted by construction.       │     │
│   │                                                                │     │
│   │   ┌─────────────────────────────────────────────────────┐      │     │
│   │   │       CONFINED CONTEXT: ai-coding                   │      │     │
│   │   │   Narrowed exec, fs, net, unix-sock, proc, env.     │      │     │
│   │   │   Talks outbound only via context-local proxy.      │      │     │
│   │   │   Talks D-Bus only via context-local dbus-proxy.    │      │     │
│   │   │                                                     │      │     │
│   │   │   ┌──────────────────────────────────────┐          │      │     │
│   │   │   │   REFINED CONTEXT: ai-coding/npm     │          │      │     │
│   │   │   │   Further narrowing only.            │          │      │     │
│   │   │   │   net.mode=none during install.      │          │      │     │
│   │   │   └──────────────────────────────────────┘          │      │     │
│   │   └─────────────────────────────────────────────────────┘      │     │
│   │                                                                │     │
│   │   ┌─────────────────────────────────────────────────────┐      │     │
│   │   │       CONFINED CONTEXT: untrusted-build             │      │     │
│   │   │   Independent narrowing. Cannot see ai-coding.      │      │     │
│   │   └─────────────────────────────────────────────────────┘      │     │
│   └────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

The boundaries that must not weaken:

- **Default context ↔ confined context**: a confined context cannot influence default-context processes, files (outside grants), sockets, or environment. The default context can inspect, signal, and kill its confined children (it owns them).
- **Sibling confined contexts**: two contexts of the same parent cannot see or affect each other unless explicitly granted. Their loopback subnets are disjoint, their AF_UNIX views are disjoint, their PID visibility is disjoint.
- **Confined context ↔ host services**: every syscall to the kernel passes through the context's policy. There is no bypass via "I'm still uid 1000". Same-uid is no longer the trust boundary; cgroup membership and Landlock ruleset are.
- **Refined context ↔ parent context**: a refined context's policy is the intersection of its own declarations and its parent's. It may narrow further; it may not widen.

## 3.2 The framework's own trust position

The framework itself runs as the user's uid (with the exception of one narrow privileged helper for network-interface setup — see §6). Its trust position is:

- **Higher than confined contexts**: it owns the policy decisions, the proxy daemons, the audit log, the cgroup hierarchy.
- **Equal to the default context**: it cannot do anything the user couldn't do in their normal shell.
- **Bounded by the user's consent**: the user installs it, the user configures it, the user can disable it. The framework does not survive a user who actively works against it.

This means the framework's daemons (SOCKS5 proxy, xdg-dbus-proxy, per-context ssh-agent, etc) are accessible to same-uid processes outside the framework's confined contexts. A determined adversary in the *default* context can read the framework's state directly. This is acceptable because the default context is the trust root — anyone there is, by assumption, the user.

The interesting consequence: the framework's daemons are protected from the *confined* contexts they mediate (by the policy they enforce) but not from the user's normal shell or anything that user runs unconfined. If the user wants stronger protection against same-uid attacks on the framework itself, they need namespace isolation of the daemons (§10 open question).

## 3.3 Constructed views: the cross-cutting design theme

The same architectural pattern appears in every resource class. Rather than enumerating "what the context is denied" against the host's real state, the framework presents the context with a *constructed view* of each resource class that contains exactly what the policy grants and nothing else.

Five major constructed views, one per resource class:

| Resource class | Real host state | Constructed view inside context |
|---|---|---|
| Filesystem (§4.2) | Full `$HOME`, `/usr`, `/etc`, `/tmp`, `/mnt`, etc | Shim `$HOME` containing only granted paths, bind-mounted from real locations; private `/tmp` tmpfs |
| Network (§4.3) | Real loopback `127.0.0.1` and `::1`; full routing | Per-context `127.x.y.z/24` and `fd<gid>:<tag>:<ctx>::/64`; outbound only via proxy |
| AF_UNIX sockets (§4.4) | All sockets in `$HOME` and `$XDG_RUNTIME_DIR` | Shim view: only granted sockets present; per-context service instances bind-mounted to standard paths |
| D-Bus (§4.5) | User's session bus, system bus | Per-context xdg-dbus-proxy filtering every method call |
| Environment (§4.7) | Full inherited env from default shell | Curated subset; sensitive vars stripped, framework vars forced |

The unifying property: **what isn't constructed isn't there**. A context cannot accidentally reach something the policy author forgot to deny, because the view doesn't include it. Default-deny is structural, not the result of an exhaustive deny-list.

This pattern has consequences worth surfacing:

- **Inspection is easy.** The user can ask "what does the context see for X?" and the answer is "exactly what's in the constructed view for X". There is no "everything not denied"; there is just the view.
- **Policy edits are positive.** A user adding a capability writes "add this to the view", not "remove this from the deny list". The cognitive load is one direction.
- **The view is the security boundary.** Bugs in policy authoring are bugs in *what's included*, which is more visible than bugs in *what's excluded*.
- **The framework must construct each view.** This is non-trivial code in each subsystem (mount namespace setup for fs, cgroup BPF for network, bind mounts for unix sockets, proxy launches for dbus). The framework is implementing the constructed-view pattern, not just enforcing rules.

## 3.4 The framework as broker

A second cross-cutting theme: where direct access to a resource cannot be filtered safely, the framework interposes a userspace broker that does the filtering on its behalf.

| Resource | Direct access | Broker |
|---|---|---|
| Outbound network | cgroup BPF could allow/deny per address, but DNS resolution, audit, and per-method policy are user-space concerns | SOCKS5 proxy (one per context) |
| D-Bus | Method-level filtering requires parsing the protocol | xdg-dbus-proxy (one per session bus, optionally one per system bus, per context) |
| X11 | No filtering exists at the X11 protocol level for security purposes | Xwayland-isolated or Xephyr-isolated (one X server per context) |
| ssh-agent (when used) | The agent's policy is per-key, not per-caller | Per-context ssh-agent instance, possibly with destination constraints |

The broker pattern means the kernel-level enforcement is simple ("you can only talk to your broker") and the policy expressiveness lives in user-space code the framework controls. The brokers are themselves vetted system tools where possible (xdg-dbus-proxy, Xephyr) and small purpose-built daemons otherwise (the SOCKS5 proxy, per-context ssh-agent).

The trade-off: brokers add latency, code complexity, and an additional process per context per protocol. For the threat model this is acceptable; the protocol-level filtering is the property we need and there is no way to get it at the kernel level alone.

## 3.5 Threat domains and what crosses between them

It is worth being explicit about what crosses each trust boundary, in both directions:

**Default context → confined context:**

- The framework's invocation parameters (`agent-run --context X cmd`).
- The curated environment (per env policy).
- The constructed filesystem view (read-only by default for most paths).
- Standard input/output (the controlling terminal, possibly).
- Initial working directory (constrained to be inside the granted fs).

**Confined context → default context:**

- Exit status and signals to the parent.
- Standard output and stderr.
- Audit log events (via the framework's log writer, not directly).
- Files written to granted writable paths (which the default context can read normally).

Nothing else. In particular:

- No D-Bus signals back to the user's session bus (the dbus-proxy is one-directional in practice; the bus filters incoming as strictly as outgoing).
- No notifications to the user's desktop unless explicitly granted (and granting notifications is a meaningful capability — see §4.5).
- No clipboard access (the X11/Wayland clipboard does not bridge unless explicitly bridged).
- No keystroke or input events delivered to other windows.
- No `kill()` to processes outside the context.

**Confined context ↔ confined sibling context:** nothing, by default. Two contexts of the same parent are mutually invisible. Explicit grants (a shared filesystem path, a shared loopback service) are possible but require deliberate policy on both sides.

## 3.6 Reading this document with the constructed-view lens

§4 (the policy surface) is organised by resource class, and each subsection describes how the constructed view for that class is built. The reader should approach each §4.x subsection asking: "what does the context see, where does it come from, and what's the policy that determines the view's contents?" This is more useful than asking "what's denied?", because the second question rarely has a tractable answer (the universe of things to deny is open-ended) and the first question always does.
