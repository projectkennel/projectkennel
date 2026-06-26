# §7.6 Policy surface: AF_UNIX sockets and the brokered-connect facade

> **The model is the brokered-connect facade, not a socket path in the view.** AF_UNIX
> access is mediated by the `org.projectkennel.IAfUnix/default` service on the kennel's
> binder bus (the inter-namespace gateway, §7.1): the workload issues a binder transaction
> naming the socket it wants, kenneld validates the request against `[[unix.allow]]`,
> performs the `connect()` on the host side, and returns the **connected fd** to the
> workload via `BINDER_TYPE_FD`. No host AF_UNIX socket path is present in the kennel's
> view, so there is nothing to enumerate, probe, or connect to out of band; every
> connection is authorized and audited at the call. The legacy bind-mount **shim model**
> below (a constructed view of `$HOME`/`$XDG_RUNTIME_DIR` holding exactly the granted
> sockets) is **superseded** by the facade and retained here only to motivate it — the
> facade subsumes its default-deny and per-kennel-renaming properties without ever placing
> a path in the view. The migration direction is shim → facade; new grants are facade
> grants. Abstract-namespace connections remain denied by Landlock scoping (§7.6.3),
> which applies regardless of model.

A kennel reaches the AF_UNIX sockets its policy grants through the `org.projectkennel.IAfUnix/default` facade: it asks for a socket by its policy name, kenneld connects on its behalf, and the workload receives a ready-to-use connected fd. Sockets the policy does not name cannot be reached; abstract-namespace connections are denied by default. Per-kennel service instances (gpg-agent, D-Bus) — see the dedicated facades in §7.7 and §7.1.5 — give strong isolation without breaking application defaults: the application asks for its service the usual way and Project Kennel brokers the right endpoint.

## 7.6.1 What we gate

Every `connect()` to an AF_UNIX socket, whether path-based or abstract-namespace. Some examples of high-trust sockets on a typical workstation:

```
~/.ssh/unique_keys/agents/*.sock         signs SSH challenges
~/.gnupg/S.gpg-agent                     signs PGP, decrypts secrets
$SSH_AUTH_SOCK                           whichever ssh-agent
$XDG_RUNTIME_DIR/bus                     user session D-Bus
$XDG_RUNTIME_DIR/wayland-0               screen, input, clipboard
$XDG_RUNTIME_DIR/pulse/native            audio (microphone)
$XDG_RUNTIME_DIR/pipewire-0              audio and video (camera)
$XDG_RUNTIME_DIR/gnupg/S.gpg-agent       gnupg variant
$XDG_RUNTIME_DIR/keyring/*.socket        gnome-keyring
$XDG_RUNTIME_DIR/p11-kit/pkcs11          PKCS#11 relay
/tmp/.X11-unix/X*                        X server (screen, input, clipboard)
/run/user/<uid>/systemd/private          user systemd control
/var/run/docker.sock                     root-equivalent
/run/containerd/containerd.sock          same
/var/run/libvirt/libvirt-sock            VM control
/tmp/tmux-<uid>/default                  run commands in user's tmux
/tmp/.s.PGSQL.5432                       local Postgres
+ abstract-namespace sockets (D-Bus, X11, various apps)
```

Each is a capability the AI agent should not silently have. Half are unauthenticated: if you can connect, you have full access. Socket file permissions are the ACL.

## 7.6.2 Why a chokepoint, not a path

The naive approach — "Landlock deny on the real paths, allowlist specific files" — is fragile:

- Paths are scattered. A complete policy must enumerate every socket the user might have.
- Variable expansion (`$XDG_RUNTIME_DIR`, `~`) means policy authoring requires care.
- Some sockets appear and disappear (gpg-agent on demand, ssh-agent per session). Landlock rulesets are sealed at apply time.
- Abstract-namespace sockets bypass filesystem ACLs entirely.

The **superseded shim model** answered this by giving the kennel a *constructed view* of `$HOME` and `$XDG_RUNTIME_DIR` where only the policy-granted sockets were present, bind-mounted from their real locations. That removed the enumeration and expansion hazards, but it still placed real socket *paths* in the view: the workload could see which sockets it had been granted, audit was only at connect time, and a path that appeared (even mistakenly) was a path that could be connected to.

The **brokered-connect facade** closes that gap. Instead of placing a socket in the view, the kennel asks the `org.projectkennel.IAfUnix/default` node on its binder bus to connect on its behalf; kenneld is the policy decision point for every `connect()` and returns only the resulting fd (§7.1.5). The facade keeps the shim's two structural properties — default-deny (a socket not granted simply cannot be asked for) and per-kennel renaming (the policy name decouples from any host path) — while removing the path from the view entirely. Enforcement and audit move from the connection level to the call level, which is what the resource class needs.

> **SSH is the exception.** ssh-agent is used below as the worked example of the *general* AF_UNIX mediation mechanism (which still serves gpg-agent, keyring, and the display/audio sockets, now through the facade), but per-kennel SSH is **not** exposed as an agent socket — an exposed agent is a destination-blind signing oracle. SSH is routed through the re-origination bastion of §7.10 instead. Read the ssh-agent worked example here as illustrating the mechanism, not as the SSH design.

The picture below shows the **superseded shim view** — the constructed `$HOME`/`$XDG_RUNTIME_DIR` the old model exposed. Under the facade no such paths appear in the view at all; the diagram is retained to show what the facade replaces, not what the kennel now sees.

```
Real layout (host view):
  ~/.ssh/unique_keys/agents/ai-coding.sock   real socket file
  ~/.gnupg/S.gpg-agent                       real socket file
  $XDG_RUNTIME_DIR/wayland-0                 real socket file
  $XDG_RUNTIME_DIR/bus                       real socket file
  ... (and 30 others)

Kennel's view of $HOME (shim layout):
  ~/.ssh/agent.sock                          ← bind-mounted from per-kennel socket
  ~/.config/...                              ← shadowed; empty or scoped
  ~/projects/foo/                            ← bind-mounted real path (work tree)
  (nothing else from ~ is visible)

Kennel's view of $XDG_RUNTIME_DIR:
  $XDG_RUNTIME_DIR/wayland-0                 ← present iff policy grants it
  (nothing else)
```

In the shim model the kennel saw a directory tree containing exactly the sockets it was permitted to use, named the way applications expect. The facade preserves the same three structural benefits while removing the path from the view:

1. **Default-deny is structural.** Under the shim, what wasn't bind-mounted in wasn't there; under the facade, a socket the policy does not grant simply cannot be named in an `IAfUnix` request. No "policy forgot to deny `$XDG_RUNTIME_DIR/pipewire-0`" failure mode either way.
2. **The construction is inspectable.** `kennel --kennel X --dry-run` enumerates the granted sockets and their policy names — the policy → reality mapping is visible without exposing any host path to the workload.
3. **Per-kennel socket renaming is trivial.** A kennel's gpg-agent on the host can live at `~/.gnupg/kennels/<kennel>/S.gpg-agent`; the policy name decouples it from any path the application would otherwise hard-code. The application doesn't know it's running in a kennel — and under the facade it never sees a host path at all.

## 7.6.3 Mechanism

### Facade path (the model)

The workload reaches a host AF_UNIX socket by transaction, not by path:

```
1. Workload looks up org.projectkennel.IAfUnix/default on node 0 (getService).
   The node is present iff the policy has a non-empty [unix] section.
2. Workload sends a binder transaction to that node, payload = the requested
   socket's policy name (a flat string; bounded, no host path supplied by the
   workload).
3. kenneld resolves the name against [[unix.allow]], maps it to the host
   socket's real path, and validates the grant. A name not in the allowlist is
   refused with BR_FAILED_REPLY; the attempt is audited.
4. kenneld performs the connect() host-side and returns the connected fd to the
   workload as a BINDER_TYPE_FD in the reply.
5. The workload uses the connected fd directly. It never holds, and cannot
   derive, a path into the host AF_UNIX namespace.
```

There is no per-grant bind mount, no socket path placed in the view, and no constructed `$HOME`/`$XDG_RUNTIME_DIR` socket overlay. Audit is at the call (`connect()`), not inferred from the view. The transaction decoder for the `IAfUnix` request is bounded and fuzzed alongside the other binder facades (§7.1).

Abstract-namespace denial below is **model-independent** — it is a Landlock property of the workload's domain and applies whether or not any path is in the view.

### Superseded shim path

The old shim model required a mount namespace and one bind mount per granted socket: a constructed `/run/kennel/<ctx>/` overlay populated from `[[unix.allow]]` and bind-mounted over the real `$HOME`/`$XDG_RUNTIME_DIR`, then Landlock-denied outside the overlay. That mechanism is superseded by the facade and is not the design going forward; it carried the per-grant bind-mount cost and still exposed socket paths in the view. The abstract-namespace scoping it relied on is retained verbatim by the facade model:

Linux's AF_UNIX has two namespaces: filesystem-path sockets (covered by Landlock's path rules) and abstract-namespace sockets (starting with `\0`, addressed by no path ACL). Project Kennel denies the abstract namespace with **Landlock scoping**, the kernel-native mechanism.

**Landlock scoping (ABI 6, kernel 6.12+) is the primary mechanism.** `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` makes a Landlock domain deny `connect()` to any abstract-namespace socket bound *outside* the sandbox — no `sun_path` inspection, no userspace-memory dereference, no AppArmor dependency. This is the kernel-native form of `unix.abstract = "deny"`. The companion `LANDLOCK_SCOPE_SIGNAL` isolates the kennel's signal-delivery domain the same way (a confined process cannot signal a process outside its domain), the native replacement for a PID-namespace + AppArmor signal story. Project Kennel queries the Landlock ABI and enables both scopes by default wherever the kernel reports ABI ≥ 6. The runtime floor is 6.10 (ABI 5).

**Fallback below ABI 6.** Where the kernel predates the scope bits, abstract-socket denial falls back to a seccomp `connect()` filter that reads the first byte of `sun_path` and denies on `\0`, or to AppArmor `unix` rules where a system policy is available:

- **`SECCOMP_RET_TRAP`** to a userspace handler that inspects `sun_path` (it lives in userspace memory most kernels can't safely dereference inline). Slow, complex, works.
- **AppArmor `unix` rules** for the kennel (requires root or system policy). Cleaner where AppArmor is present.

The fallback is the documented path below ABI 6 only; on a supported kernel the native scoping supersedes it entirely.

**`abstract = "allow"` escape hatch.** The default denial can be opted out of with `abstract = "allow"` in the `[unix]` section, but only when the kennel owns its `CLONE_NEWNET` (`net.mode` = `none` / `constrained` / `unconstrained`). In that configuration the per-kennel network namespace is the structural control: the kennel's abstract-socket namespace is empty by construction (no host daemon binds there). The combination `abstract = "allow"` + `net.mode = "host"` is a **hard compile error** — host mode shares `CLONE_NEWNET` with the host, so abstract sockets reach the host namespace directly (T1.13). Landlock ABI-6 abstract scoping is defence-in-depth on top of the net-ns boundary, never a substitute.

## 7.6.4 Policy primitives

A non-empty `[unix]` section is what causes kenneld to register the
`org.projectkennel.IAfUnix/default` facade node on the kennel's binder instance; an empty or
absent section means the node is not present and `getService` for it is refused (§7.1.4).
Each `[[unix.allow]]` entry names a host socket the facade will connect to on the workload's
behalf — the workload requests it by `name`, never by host path.

```toml
[unix]
default = "deny"                # "deny" | "allow" (rarely); the resolved default may not be "allow"
abstract = "deny"               # "deny" | "allow" — abstract-namespace socket disposition

# Explicit grants. Each [[unix.allow]] maps a logical `name` to the host socket the facade
# connects to (`real`) and the path the socket is bound at inside the kennel view (`shim`); an
# optional `env` var is set to the shim path. The workload asks IAfUnix for `name` (and finds the
# socket at `shim`/`$env`); the host `real` path is never disclosed to the workload.
#
# NB: SSH is NOT granted here. ssh-agent over the facade is a destination-blind signing oracle;
# per-kennel SSH goes through the re-origination bastion and the [ssh] section instead (§7.10).
# [[unix.allow]] is for the other agent-shaped services (gpg-agent, keyring) and display/audio
# sockets.

[[unix.allow]]
name = "wayland"
real = "$XDG_RUNTIME_DIR/wayland-0"     # the host socket the facade connects to
shim = "~/.kennel/wayland-0"            # where it appears inside the kennel view
env  = "WAYLAND_DISPLAY"                # optional: set this env var to the shim path
reason = "compositor"
# WARNING: granting Wayland gives clipboard access, screen-capture portal access
# (compositor-dependent), input synthesis (compositor-dependent). Document loudly.

[[unix.allow]]
name = "pipewire"
real = "$XDG_RUNTIME_DIR/pipewire-0"
shim = "~/.kennel/pipewire-0"
reason = "audio via PipeWire"
# WARNING: grants audio+video device access via portal.

# Per-kennel service instances
[[unix.allow]]
name = "gpg-agent"
real = "~/.gnupg/kennels/<kennel>/S.gpg-agent"   # a separately-managed per-kennel gpg-agent
shim = "~/.gnupg/S.gpg-agent"                     # the path gpg looks for inside the kennel
reason = "per-kennel gpg-agent"
# Pairs with a separately-managed per-kennel gpg-agent. Granting access to the user's real
# ~/.gnupg/ is virtually never correct.
```

There is no `[[unix.deny]]` table and no `[[unix.allow_abstract]]` table: a socket not named in `[[unix.allow]]` is denied by the `default = "deny"` floor, and abstract-namespace access is the single `abstract = "deny" | "allow"` toggle on `[unix]` (it is not per-socket). Sockets you would "explicitly deny" — session D-Bus (`$XDG_RUNTIME_DIR/bus`), `docker.sock`, `containerd.sock`, the systemd private socket, the X11 sockets — are simply never added to `[[unix.allow]]`; the deny is the default, not a list.

The `name` field is the handle the workload requests and the one that appears in audit logs and `--dry-run` output; `real` is the host socket kenneld connects to and is never disclosed to the workload; `shim` (and the optional `env`) is what the workload sees in its view.

## 7.6.5 The dry-run output

For an `ai-coding` kennel:

```
$ kennel inspect ai-coding --unix

Context: ai-coding (id 7)
AF_UNIX facade: org.projectkennel.IAfUnix/default (registered; [unix] non-empty)
Brokered grants (name → host socket kenneld connects to):
  wayland   → /run/user/1000/wayland-0           access rw
  (workload requests by name; no path appears in its view)

Filesystem grants (Landlock):
  read+exec: /usr, /lib, /etc
  read+write: /home/u/projects/foo, /tmp
  deny: everything else under /home/u

AF_UNIX rules:
  abstract namespace: DENY (Landlock scope)
  path connect from the view: none (no socket paths in the view)
  brokered names: <list of granted [[unix.allow]] names>

Environment overrides:
  XDG_RUNTIME_DIR = /run/user/1000  (real, but no host sockets visible)
  DISPLAY = (unset; no X11 access)
  WAYLAND_DISPLAY = wayland-0
```

The user reads this and reasons about whether the policy is what they meant — the name → host-socket mapping is visible to the operator inspecting from the host side, while the workload sees only the names it may request. The `--dry-run`/`inspect` flag is a standard tool Project Kennel ships with, alongside `kennel validate <file>`.

## 7.6.6 State placement

The facade places **no socket overlay** in the view, so the shim's "where do the bind-mounted sockets live" question is moot — there is no `/run/kennel/<ctx>/` socket overlay and no per-grant bind mount over `$HOME`/`$XDG_RUNTIME_DIR`. (In the superseded shim model the overlay lived in `/run/kennel/<ctx>/`, ephemeral, bind-mounted over the real paths; that machinery is gone with the model.)

What remains is the kennel's *persistent state* — the `~/.cache/`, `~/.config/` it legitimately needs to write — which lives in `~/.local/share/kennel/<ctx>/state/`, surfaced into the kennel's view as the appropriate subdirectories. It is clearly separated from real `~` and inspectable from the host side. Socket access is brokered by the facade; only durable state needs a home on disk.

## 7.6.7 Per-kennel services

The facade makes per-kennel *service instances* viable for agent-shaped services. Project Kennel owns launching them: policy names "kennel X gets service Y"; Project Kennel ensures Y is running before X starts, brokers X's connection to Y's socket through the facade (the workload asks for the service by name and receives a connected fd), and tears Y down when no kennels reference it. The application's configuration does not change — it asks for its service the usual way and reaches the right instance.

- **gpg-agent per kennel**: `~/.gnupg/kennels/<ctx>/` with its own keyring, the agent socket reached through the facade. (gpg-agent is a blind signing oracle in the same way ssh-agent is; the `org.projectkennel.IGpgAgent/default` facade (§7.1.5) narrows it to key grip + purpose, closing that residual — a strictly stronger position than a raw socket grant.)
- **Keyring per kennel**: an isolated `gnome-keyring-daemon` instance.
- **D-Bus per kennel**: mediated by the `org.projectkennel.IDBus/default` facade, not raw — see §7.7.

**SSH is the exception.** SSH is *not* exposed as a per-kennel agent socket — an exposed agent is a destination-blind signing oracle. Per-kennel SSH goes through the re-origination bastion of §7.10, reached over the egress proxy rather than the AF_UNIX facade.

## 7.6.8 Residuals

**X11.** `/tmp/.X11-unix/X0` cannot be safely brokered to — the X protocol has no confinement vocabulary, so even a facade in front of it would forward full screen/input/clipboard authority — see §7.8. Granting it is denying Project Kennel's claim of confinement.

**Wayland clipboard.** Even on Wayland, a kennel's window can read and write the user's clipboard through standard Wayland protocols. The `org.projectkennel.IWayland/default` facade (§7.1.5) gates `wl_data_device` and screencopy structurally; absent that facade, compositor-side mitigations exist but support varies. Documented as a known residual until the facade lands.

**Abstract namespace and library defaults.** Some libraries default to abstract sockets without obvious configuration. The facade does not broker the abstract namespace; such a `connect()` hits the always-on Landlock scope. Audit log should make this loud: "kennel tried connect() to abstract socket '@gnome-shell-mutter', denied" tells the user what to investigate.

**Cleanup on crash.** With the facade there are no per-grant bind mounts to reap; the connected fds are owned by the workload and close with it, and the facade node disappears with the kennel's binder instance. Framework state (which kennels running, which agents to keep alive) in `/run/` is cleared on reboot; periodic reconciliation handles orphans.

## 7.6.9 Test plan additions

The invariants the model must hold, each a regression test in `tests/unix/` (and, for the
facade transactions, `tests/facades/`):

1. Context with `[unix]` empty: `getService` for `org.projectkennel.IAfUnix/default` returns `BR_FAILED_REPLY` — the node is absent, the capability was never granted.
2. Context with a `gpg-agent` grant requests it by name through the facade and receives a connected fd that round-trips a byte to the host listener.
3. Context with `unix.abstract = "deny"` connects to ` /org/freedesktop/DBus`; expect EPERM from the Landlock abstract-unix scope (EACCES from the seccomp/AppArmor fallback below ABI 6).
4. Context lists `$XDG_RUNTIME_DIR`; expect to see no host sockets — the facade places no socket paths in the view.
5. Context requests a name not in `[[unix.allow]]`: the facade refuses with `BR_FAILED_REPLY`; the attempt is audited.
6. Two kennels with different `gpg-agent` grants each reach only their own instance through their own facade node; neither can request the other's name.
7. Context attempts to read `~/.gnupg/private-keys-v1.d/`; expect ENOENT (no host path in the view).
8. Context requests `/var/run/docker.sock` (an un-granted name — not in `[[unix.allow]]`, so denied by the `default = "deny"` floor): the facade refuses; no path is present to connect to directly.
9. Context attempts to connect to abstract ` /var/run/docker.sock`; expect EPERM from the Landlock abstract-unix scope.
10. Kennel's `--dry-run`/`inspect --unix` output enumerates the granted name → host-socket mappings; verify against policy.

The full test corpus is approximately 25 cases. (Per-kennel SSH has its own tests in §7.10.9.) The `IAfUnix` request decoder is fuzzed alongside the other binder facades (§7.1.11).
