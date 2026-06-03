# §7.4 Policy surface: AF_UNIX sockets and the shim model

A kennel sees a constructed view of `$HOME` and `$XDG_RUNTIME_DIR` containing only the sockets the policy grants. Sockets named in the policy are bind-mounted from their real locations (or from per-kennel service instances) into the shim view at the paths applications expect. Sockets not named are not present. AF_UNIX abstract-namespace connections are denied by default. Per-kennel service instances (ssh-agent, gpg-agent, D-Bus) allow strong isolation without breaking application defaults: the application looks for its socket at the standard path; Project Kennel arranges for the right socket to be there.

## 7.4.1 What we gate

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

## 7.4.2 Why the shim model

The naive approach — "Landlock deny on the real paths, allowlist specific files" — is fragile:

- Paths are scattered. A complete policy must enumerate every socket the user might have.
- Variable expansion (`$XDG_RUNTIME_DIR`, `~`) means policy authoring requires care.
- Some sockets appear and disappear (gpg-agent on demand, ssh-agent per session). Landlock rulesets are sealed at apply time.
- Abstract-namespace sockets bypass filesystem ACLs entirely.

The shim model: the kennel sees a *constructed view* of `$HOME` and `$XDG_RUNTIME_DIR` where only the sockets the policy explicitly grants are present, by bind-mounting from real locations.

> **SSH is the exception.** ssh-agent is used below as the worked example of the *general* socket-shim mechanism (which still serves gpg-agent, keyring, and the display/audio sockets), but per-kennel SSH is **not** shimmed as an agent socket — an exposed agent is a destination-blind signing oracle. SSH is routed through the re-origination bastion of §7.8 instead. Read the ssh-agent worked example here as illustrating the mechanism, not as the SSH design.

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

The kennel sees a directory tree containing exactly the sockets it's permitted to use, named the way applications expect. Applications use their default paths and find sockets — but the sockets they find are the ones policy bound in.

Three benefits over allowlist-in-place:

1. **Default-deny is structural.** What isn't bind-mounted in isn't there. No "policy forgot to deny `$XDG_RUNTIME_DIR/pipewire-0`" failure mode.
2. **The construction is inspectable.** Run `kennel --kennel X --dry-run` to see exactly which sockets are in the shimmed view. The policy → reality mapping is visible.
3. **Per-kennel socket renaming is trivial.** Kennel's ssh-agent on the host is `~/.ssh/unique_keys/agents/ai-coding.sock`. Inside the kennel it's bind-mounted to `~/.ssh/agent.sock`. The application doesn't know it's running in a kennel.

## 7.4.3 Mechanism

Required: mount namespace + bind mounts. The cost is real (more setup, slightly more startup latency, can't trivially mount-share with host) but the benefit is structural isolation independent of per-path Landlock rules being exhaustive.

Setup flow:

```
1. unshare(CLONE_NEWNS)              in child after fork
2. mount --make-rslave /             detach from host mount propagation
3. Construct shim directories:
     mkdir -p /run/kennel/<ctx>/home
     mkdir -p /run/kennel/<ctx>/xdg
4. Populate shim from policy:
     for each unix.allow entry:
       touch /run/kennel/<ctx>/<shim_path>
       mount --bind <real_path> /run/kennel/<ctx>/<shim_path>
5. Bind-mount shim over real locations:
     mount --bind /run/kennel/<ctx>/home  $REAL_HOME
     mount --bind /run/kennel/<ctx>/xdg   $XDG_RUNTIME_DIR
6. Apply Landlock (defence in depth):
     Deny AF_UNIX path access outside /run/kennel/<ctx>/
     Enable LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (+ SCOPE_SIGNAL)
7. execve
```

Linux's AF_UNIX has two namespaces: filesystem-path sockets (covered by Landlock's path rules) and abstract-namespace sockets (starting with `\0`, addressed by no path ACL). Project Kennel denies the abstract namespace with **Landlock scoping**, the kernel-native mechanism.

**Landlock scoping (ABI 6, kernel 6.12+) is the primary mechanism.** `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` makes a Landlock domain deny `connect()` to any abstract-namespace socket bound *outside* the sandbox — no `sun_path` inspection, no userspace-memory dereference, no AppArmor dependency. This is the kernel-native form of `unix.abstract = "deny"`. The companion `LANDLOCK_SCOPE_SIGNAL` isolates the kennel's signal-delivery domain the same way (a confined process cannot signal a process outside its domain), the native replacement for a PID-namespace + AppArmor signal story. Project Kennel queries the Landlock ABI and enables both scopes by default wherever the kernel reports ABI ≥ 6. Implemented in `kennel-syscall::landlock` (`Scope::ABSTRACT_UNIX_SOCKET`, `Scope::SIGNAL`, set in `Ruleset::new`). The runtime floor is 6.10 (ABI 5); the reference dev/CI box runs 6.17 (ABI 7), where both scopes apply.

**Fallback below ABI 6.** Where the kernel predates the scope bits, abstract-socket denial falls back to a seccomp `connect()` filter that reads the first byte of `sun_path` and denies on `\0`, or to AppArmor `unix` rules where a system policy is available:

- **`SECCOMP_RET_TRAP`** to a userspace handler that inspects `sun_path` (it lives in userspace memory most kernels can't safely dereference inline). Slow, complex, works.
- **AppArmor `unix` rules** for the kennel (requires root or system policy). Cleaner where AppArmor is present.

The fallback is the documented path below ABI 6 only; on a supported kernel the native scoping supersedes it entirely.

## 7.4.4 Policy primitives

```toml
[unix]
default = "deny"                # "deny" | "allow" (rarely)
abstract = "deny"               # "deny" | "allow"
shim_root = "/run/kennel/<ctx>"  # auto-set

# Explicit grants: real socket path → location in kennel's view
# Real socket is bind-mounted to shim location.
#
# NB: SSH is NOT granted here. ssh-agent over the shim is a destination-blind
# signing oracle; per-kennel SSH goes through the re-origination bastion and the
# [ssh] section instead (§7.8). [[unix.allow]] is for the other agent-shaped
# services (gpg-agent, keyring) and display/audio sockets.

[[unix.allow]]
name = "wayland"
real = "$XDG_RUNTIME_DIR/wayland-0"
shim = "$XDG_RUNTIME_DIR/wayland-0"
# WARNING: granting Wayland gives clipboard access, screen-capture portal
# access (compositor-dependent), input synthesis (compositor-dependent).
# Document loudly.

[[unix.allow]]
name = "pipewire"
real = "$XDG_RUNTIME_DIR/pipewire-0"
shim = "$XDG_RUNTIME_DIR/pipewire-0"
# WARNING: grants audio+video device access via portal.

# Per-kennel service instances
[[unix.allow]]
name = "kennel-local-gpg"
real = "~/.gnupg/kennels/<kennel>/S.gpg-agent"
shim = "~/.gnupg/S.gpg-agent"
# Pairs with a separately-managed per-kennel gpg-agent.
# Granting access to the user's real ~/.gnupg/ is virtually never correct.

# Explicit denials (belt and braces over category defaults)
[[unix.deny]]
real = "$XDG_RUNTIME_DIR/bus"           # never grant session D-Bus directly
[[unix.deny]]
real = "/var/run/docker.sock"
[[unix.deny]]
real = "/run/containerd/containerd.sock"
[[unix.deny]]
real = "/run/user/$UID/systemd/private"
[[unix.deny]]
real = "/tmp/.X11-unix/X*"              # X11 is screen+input+clipboard

# Abstract-namespace exceptions (rarely correct)
[[unix.allow_abstract]]
name = "\\0org.freedesktop.systemd1"
note = "Required for systemctl --user; opens significant attack surface"
```

The `name` field is informative — it appears in audit logs and `--dry-run` output.

## 7.4.5 The dry-run output

For an `ai-coding` kennel:

```
$ kennel inspect ai-coding --shim

Context: ai-coding (id 7)
Mount shim: /run/kennel/ai-coding/
Bind mounts:
  /home/u/.ssh/unique_keys/agents/ai-coding.sock
    → /run/kennel/ai-coding/home/.ssh/agent.sock
    (env SSH_AUTH_SOCK=/home/u/.ssh/agent.sock)
  /run/user/1000/wayland-0
    → /run/kennel/ai-coding/xdg/wayland-0

Filesystem grants (Landlock):
  read+exec: /usr, /lib, /etc
  read+write: /home/u/projects/foo, /tmp
  read: /run/kennel/ai-coding (the shim itself)
  deny: everything else under /home/u

AF_UNIX rules:
  abstract namespace: DENY (Landlock scope)
  default for paths: DENY (Landlock)
  allow connect: <list of shim paths>

Environment overrides:
  SSH_AUTH_SOCK = /home/u/.ssh/agent.sock
  XDG_RUNTIME_DIR = /run/user/1000  (real, but only shimmed contents visible)
  DISPLAY = (unset; no X11 access)
  WAYLAND_DISPLAY = wayland-0
```

The user reads this and reasons about whether the policy is what they meant. The `--dry-run` flag is a standard tool Project Kennel ships with, alongside `kennel validate <file>`.

## 7.4.6 Where the shim lives

Two viable placements:

**Option 1: shim outside `~`, bind-mounted over.**

Shim files live in `/run/kennel/<ctx>/`. Bind mounts overlay the real `$HOME` paths. Pros: clean separation of Project Kennel state from user files. Easy to clean up. Cons: more bind mounts per grant.

**Option 2: shim inside `~`, exposed as a subdirectory.**

Shim lives in `~/.cache/kennel/<ctx>/home/`. Kennel's `$HOME` points at the subdirectory. Pros: persistent kennel state has a natural location. Cons: shim is inside real `$HOME`; confused write that escapes the chroot-like view could touch real `~`.

**Recommendation: hybrid.**

- Shim *view* (`$HOME` and `$XDG_RUNTIME_DIR` overlays) lives in `/run/kennel/<ctx>/`, set up via bind mounts, ephemeral.
- Kennel's *persistent state* (`~/.cache/`, `~/.config/` it legitimately needs to write) lives in `~/.local/share/kennel/<ctx>/state/`, bind-mounted into the kennel's view as appropriate subdirectories.

Ephemeral shim plus persistent state, both clearly separated from real `~`, both inspectable from the host side.

## 7.4.7 Per-kennel services

The shim makes per-kennel *service instances* viable for agent-shaped services. Project Kennel owns launching them: policy names "kennel X gets service Y"; Project Kennel ensures Y is running before X starts, that Y's socket appears at the shim path inside X, and that Y is torn down when no kennels reference it. The application's configuration does not change — it looks for its socket at the standard path and the right socket is there.

- **gpg-agent per kennel**: `~/.gnupg/kennels/<ctx>/` with its own keyring, gpg-agent socket bound in as `~/.gnupg/`. (gpg-agent is a blind signing oracle in the same way ssh-agent is; constraining it to recipients/destinations is an open residual.)
- **Keyring per kennel**: an isolated `gnome-keyring-daemon` instance.
- **D-Bus per kennel**: proxied, not raw — see §7.5.

**SSH is the exception.** SSH is *not* exposed as a per-kennel agent socket — an exposed agent is a destination-blind signing oracle. Per-kennel SSH goes through the re-origination bastion of §7.8, reached over the egress proxy rather than the AF_UNIX shim.

## 7.4.8 Residuals

**X11.** `/tmp/.X11-unix/X0` cannot be safely shimmed — see §7.6. Granting it is denying Project Kennel's claim of confinement.

**Wayland clipboard.** Even on Wayland, a kennel's window can read and write the user's clipboard through standard Wayland protocols. Compositor-side mitigations exist but support varies. Documented as a known residual.

**Abstract namespace and library defaults.** Some libraries default to abstract sockets without obvious configuration. Audit log should make this loud: "kennel tried connect() to abstract socket '@gnome-shell-mutter', denied" tells the user what to investigate.

**Performance.** A kennel with 20 bind mounts in its mount namespace has slightly heavier `fork()` and cleanup. Not significant on modern Linux but worth measuring.

**Cleanup on crash.** Bind mounts in a mount namespace are cleaned up when the last process exits. Framework state (which kennels running, which agents to keep alive) in `/run/` is cleared on reboot; periodic reconciliation handles orphans.

## 7.4.9 Test plan additions

For each invariant, a regression test in `tests/unix/`:

1. Context with `unix.allow = []` attempts `connect()` to `$XDG_RUNTIME_DIR/bus`; expect ENOENT (the shim is empty — the name is absent, not merely denied).
2. Context with a `gpg-agent` shim grant finds the socket at `~/.gnupg/S.gpg-agent` and can use it.
3. Context with `unix.abstract = "deny"` connects to ` /org/freedesktop/DBus`; expect EPERM from the Landlock abstract-unix scope (EACCES from the seccomp/AppArmor fallback below ABI 6).
4. Context lists `$XDG_RUNTIME_DIR`; expect to see only granted entries.
5. Context attempts to read a non-granted socket path; expect ENOENT — un-granted names are absent from the constructed view, not present-but-denied.
6. Two kennels with different `gpg-agent` grants each see only their own instance's socket.
7. Context attempts to read `~/.gnupg/private-keys-v1.d/`; expect ENOENT.
8. Context attempts to connect to `/var/run/docker.sock`; expect ENOENT.
9. Context attempts to connect to abstract ` /var/run/docker.sock`; expect EPERM from the Landlock abstract-unix scope.
10. Kennel's `--dry-run` output enumerates all bind mounts; verify against policy.

The full test corpus is approximately 25 cases. (Per-kennel SSH has its own tests in §7.8.9.)
