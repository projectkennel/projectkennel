# §7.7 Policy surface: process introspection, environment, capabilities, mounts, tty

The remaining resource classes, grouped because each is smaller than the major classes (exec, fs, net, unix, dbus, x11) but each is essential to the threat model.

## 7.7.1 Process introspection: ptrace, signals, /proc visibility

**Why it matters.** An AI agent that can `ptrace` the user's shell can extract anything in memory: passwords, decrypted keys, browser session tokens, in-progress edits. An agent that can read `/proc/<other-pid>/environ` can lift secrets passed via env vars to other processes. An agent that can signal arbitrary processes can disrupt the user's workflow or kill protective daemons.

**Mechanism map.**

| Capability | Primary mechanism | Notes |
|---|---|---|
| `/proc` visibility | PID namespace + `hidepid=2` mount option | PID ns is the strong isolation |
| ptrace targets | AppArmor `ptrace` rule | Yama is coarse (global), AppArmor is per-profile |
| ptrace inbound | AppArmor `ptrace` rule (deny inbound from outside) | Defends against a trusted kennel being ptraced by a different kennel |
| Signal delivery | Landlock `SCOPE_SIGNAL` (ABI 6) / AppArmor `signal` rule + PID ns | PID ns blocks signals to processes not visible |
| Capability set | `cap.bounding_set` via capset() | Drop all bounding caps |

**Landlock signal scoping (ABI 6, kernel 6.12+).** `LANDLOCK_SCOPE_SIGNAL` denies sending a signal to any process *outside* the sandbox domain, natively and without an AppArmor dependency. It complements the PID namespace (which already hides non-member processes, so signals can't name them) by also covering the case where a target is reachable by PID. Project Kennel enables it by default wherever the kernel reports Landlock ABI ≥ 6; below that the AppArmor `signal` rule + PID ns remain the mechanism.

**Policy primitives.**

```toml
[proc]
visibility = "self"         # "self" | "ancestors" | "all"
                            # "self": only own process tree visible
                            # "ancestors": own + parents (rare)
                            # "all": full /proc (almost never correct)
hidepid = true              # mount /proc with hidepid=2

[ptrace]
allow_targets = []          # kennels/processes this kennel may ptrace
                            # default: empty (cannot ptrace anything outside)
allow_from = []             # kennels that may ptrace this kennel
                            # default: empty (cannot be ptraced from outside)

[signal]
allow_targets = ["self"]    # whom we may signal
                            # "self" = own process tree
                            # specific cgroup paths possible but rarely useful
allow_from = []             # who may signal us
                            # parent default kennel can always signal children;
                            # this rule covers cross-kennel signalling
```

**Test plan.** A kennel attempts `ptrace(PTRACE_ATTACH, <host shell pid>)`; expect EPERM. A kennel reads `/proc/<other-pid>/environ`; expect ENOENT (PID ns) or EACCES (hidepid). A kennel attempts `kill(<host pid>, SIGTERM)`; expect ESRCH (PID ns) or EPERM (AppArmor).

## 7.7.2 Environment variables

**Why it matters.** The parent kennel (the user's shell) typically has high-trust env vars in its environment: `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, custom credentials. Without curation, all of these flow into the kennel.

**Mechanism.** Not a kernel mechanism. The spawn tool **synthesises** the workload's environment from policy and `execve`s with that built-from-scratch `envp`. It does **not** inherit the parent's environment and filter it down. The default environment is **empty**; every variable present is there because policy put it there.

This is the deliberate inversion of the obvious approach. "Take the user's environment and curate the dangerous bits out" is the wrong model for the same reason a denylist is the wrong model anywhere: the parent's environment *is* the high-trust surface we are trying not to touch, and an allowlist that misses one variable leaks it. Synthesis from policy is closed by construction — a secret that policy never names cannot appear in the kennel, no matter what the parent's environment held. The user's environment is not a source of truth the spawn consults at all.

**Policy primitives.**

```toml
[env]
# Optional: a file of KEY=value defaults to seed the environment from. Resolved
# at compile time and its contents pinned into the settled policy (so the env is
# signature-bound and reproducible, not read from disk at spawn). The shared,
# reusable base — a team's standard locale/tooling vars — lives here; per-kennel
# deviations go in `set`.
template = "env/base.env"

# Forced values, layered over the template. PATH (from [exec].path, §7.1.6),
# HOME (the shim home), USER (the masked account), and SHELL ([exec].shell) are
# synthesised by the spawn and need not be repeated here.
set = {
    LANG = "C.UTF-8",
    TZ = "UTC",
    TMPDIR = "/tmp",        # private tmpfs from §7.2
}
```

There is **no `pass`-from-parent list** — the environment is built, not inherited, so there is correspondingly nothing to `deny`. The rare workload that genuinely needs a *value* carried from the invoking environment (never a secret — something dynamic like `TERM`) uses an explicit, single-variable opt-in that surfaces in the policy diff exactly as any other grant does; it is discouraged, it is per-variable, and it is never the default path.

**Test plan.** A kennel whose parent shell has `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `SSH_AUTH_SOCK`, and a dozen other vars set: the kennel's `env` shows **only** the synthesised set (`PATH`/`HOME`/`USER`/`SHELL` + the template + `[env].set`), none of the parent's. Editing `[env].set` changes the kennel environment; editing the parent's environment never does.

## 7.7.2a The run environment: PATH, shell, and shell-init files

Once the environment is synthesised, three further pieces determine what a *shell* inside the kennel actually does. They are grouped here because together they are the workload's "run context"; individually they touch exec (§7.1) and the filesystem view (§7.2). All three follow the same principle as the environment: **synthesised from policy, reconstructed each spawn, persistent only where the policy explicitly says so.**

**`$PATH`.** Set from `[exec].path`, not inherited (§7.1.6). The spawn writes it into the synthesised environment; it is the one env var the exec policy owns rather than `[env]`, because it is meaningless without the `exec.allow` allowlist it indexes into.

**The login shell.** The kennel's synthetic `/etc/passwd` names a shell for the workload's uid (what `getpwuid()->pw_shell` and a bare interactive shell resolve to). It is policy-selectable:

```toml
[exec]
# The kennel's login shell. Default "/bin/sh". Must also appear in exec.allow
# (and on $PATH if invoked by name); the policy refuses a shell it would then
# deny the right to execute.
shell = "/bin/bash"
```

The selected shell sets both the `passwd` `pw_shell` field and `$SHELL`. It lives in `[exec]` (not `[env]`) because it must be an *executable the exec policy already permits* — selecting a shell that is not in `exec.allow` is a policy error caught at compile time, not a runtime surprise. The default `/bin/sh` is unchanged from today. The workload's own command still runs by direct `execve(argv)`; the shell matters only when a tool consults `pw_shell`/`$SHELL` or the workload spawns an interactive shell (an AI agent running shell commands is the common case).

**Shell-init files (rc).** A shell reads init files at two levels; the kennel **synthesises both from policy** rather than copying the host's, and both are **reconstructed every spawn** unless the policy explicitly opts a path into persistence.

- **System-level** (`/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/*`, `/etc/shells`): part of the **synthetic `/etc`** (§7.2.x), constructed minimal and **read-only**, reconstructed every spawn. They set a sane prompt, source the kennel `$PATH`, and otherwise do nothing. The workload cannot edit them (they are masked exactly like `passwd`/`group`), and nothing survives a run. Never a persistence surface.
- **User-level** (`~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc`, `~/.config/…`): **synthesised into the kennel's `$HOME` each spawn** from built-in minimal defaults and, optionally, a policy-referenced home/dotfile template (resolved and pinned at compile time, like the `[env]` template). The home belongs to the kennel — it is **not** the host user's real home, which is never exposed. By default this home is **reconstructed every spawn and not persistent**: a workload may edit its dotfiles within a run, but the edits are gone at teardown, so there is no self-poisoning surface.

```toml
[fs.home]
# Seed the kennel home's dotfiles from this template (compile-time, pinned).
template = "home/dev-skeleton"

# Persistence is OFF by default: the home is reconstructed each spawn. Opt a
# path (or the whole home) into a persistent writable bind only here. THIS is
# where the self-persistence trade-off is accepted, per policy, in the diff.
persist = ["projects", ".cache"]    # survives runs; ~/.bashrc et al. do NOT
```

**Persistence is opt-in, by policy, per path.** The default — synthesise and reconstruct — is the safe one: a persistent, workload-writable `~/.bashrc` *is* a self-persistence / re-execution vector (it runs on every future interactive shell in the kennel), so it is never the default. A policy that wants durable state names exactly which paths persist in `[fs.home].persist`; that list is the visible, diff-reviewed place the trade-off is taken. Persisting a *working* directory (`projects/`, a cache) is the common, low-risk case; persisting the *shell-init* path is possible but is a deliberate, named choice with the re-execution risk understood. Everything not named is reconstructed each run. The blast radius of any persisted dotfile is still bounded — this kennel's own future runs only, re-running as the already-confined workload under the exec allowlist + `no_new_privs` (§7.1), the synthesised environment (§7.7.2), Landlock (§7.2), and the egress allowlist (§7.3) — and an operator resets it by clearing the kennel's persistent store.

**Test plan.** (1) `[exec].shell = "/bin/bash"` with `bash` in `exec.allow`: `getent passwd "$USER"` shows `/bin/bash`, `$SHELL` is `/bin/bash`. (2) `[exec].shell` naming a binary absent from `exec.allow` is a compile error. (3) `/etc/profile` exists, is read-only, and is byte-identical across two spawns. (4) With **no** `[fs.home].persist`, a workload's edit to `~/.bashrc` is **gone** on the next spawn (reconstructed). (5) With `~/.bashrc` (or its dir) named in `[fs.home].persist`, the edit **survives** — and is still absent from a different kennel's home and from the host user's real `~/.bashrc`. (6) The synthesised env and dotfiles are byte-identical for two policies that differ only in their parent shell's environment (synthesis ignores the parent).

## 7.7.3 Linux capabilities

**Why it matters.** Linux capabilities partition root privilege into smaller units. Most are irrelevant to a uid-1000 workload (they only apply to root or to setuid binaries). A few matter even for non-root: `CAP_NET_RAW` (raw sockets), `CAP_NET_BIND_SERVICE` (bind low ports). For kennels, the answer is always "drop everything".

**Mechanism.** `prctl(PR_CAPBSET_DROP, ...)` for the bounding set; `capset()` for the permitted/effective sets. `PR_SET_NO_NEW_PRIVS` (from §7.1) prevents gaining caps via setuid.

**Policy primitives.**

```toml
[cap]
bounding_set = []           # drop all bounding capabilities
no_new_privs = true         # non-negotiable; Project Kennel forces this
```

The `bounding_set` is typed as a list for forward compatibility, but the only defensible value for a kennel is empty. The schema validator warns if a kennel lists any capability, on the grounds that needing a cap in a confined uid-1000 kennel is almost always a sign of bad design.

`no_new_privs = false` is rejected by the schema regardless of context. This is a Project Kennel invariant; see §7.1.

## 7.7.4 Mount visibility

**Why it matters.** A kennel with visibility into all the user's mounts can see what removable media is plugged in, what cloud-sync mounts are present, what loop-mounted images exist. Some of these (e.g., `/mnt/usb-drive`) are sensitive.

**Mechanism.** Mount namespace (already required for the constructed-view pattern in §4.1). Project Kennel's mount-ns construction includes only the mounts the kennel needs; the user's other mounts are invisible.

**Policy primitives.**

```toml
[mount]
visible = [
    "/",                    # rootfs (read-only by default per fs policy)
    "/usr",
    "/lib", "/lib64",
    "/etc",
    "/home/<user>/projects/foo",
    "/tmp",
    "/run/kennel/<ctx>", # the shim itself
]
# Everything else: invisible.

# Optional: mount-point flags applied to bind mounts
default_flags = ["MS_NODEV", "MS_NOSUID"]
```

Project Kennel automatically derives `visible` from `fs.read` and `fs.write` lists; users rarely override.

**Test plan.** Context sees only listed mounts in `/proc/mounts`. Context attempts `mount()`; expect EPERM (no `CAP_SYS_ADMIN`).

## 7.7.5 Tty and TIOCSTI

**Why it matters.** The TIOCSTI ioctl ("type into the controlling tty as if I were the user") is a notorious sandbox escape. A confined process running in a terminal can inject keystrokes that appear to come from the user, executing commands in the user's shell after the kennel exits.

**Mechanism.** Recent kernels gate TIOCSTI behind the sysctl `dev.tty.legacy_tiocsti` (default off in kernels 6.2+). On older kernels, seccomp filtering of `ioctl()` is the fallback.

**Policy primitives.**

```toml
[tty]
# Check at policy load: refuse to apply this policy if TIOCSTI is enabled
# and the kernel is recent enough that it should be disabled.
require_tiocsti_disabled = true
```

If `require_tiocsti_disabled = true` and `dev.tty.legacy_tiocsti = 1`, Project Kennel refuses to start the kennel with a clear error message instructing the user to set the sysctl. This is preferable to attempting to work around a sysctl-disabled-by-policy via seccomp.

On older kernels where the sysctl doesn't exist, Project Kennel applies a seccomp filter denying `ioctl(*, TIOCSTI, *)`. This is best-effort; seccomp can't always inspect the arguments safely, see §7.4 for the same caveat.

**Other tty concerns.** Scrollback control and clipboard via terminal escape sequences (some terminals support OSC 52 for clipboard set, which is its own exfiltration channel) are out of scope for v1; future revisions may add `tty.osc52 = "deny"` style controls. The current mitigation is "run kennels in a terminal you trust, with OSC 52 disabled in terminal config".

## 7.7.5a Interactive controlling terminal

**Why it matters.** An interactive `kennel run` (a human at the keyboard, e.g. `kennel run interactive -- /bin/bash`) needs a real controlling terminal so the workload's shell has job control (`^Z`/`fg`/`bg`), full-screen editors and pagers work, and `isatty`/`ttyname` answer truthfully. Simply forwarding the operator's own terminal fds would hand the confined workload the *operator's* controlling tty — the TIOCSTI/`/dev/tty` surface §7.7.5 exists to keep away from it.

**Mechanism — the pty lives inside the kennel.** The controlling pty is allocated by the spawn seal from the kennel's **own** `devpts`, after `pivot_root` (§7.2): the kennel's `/dev/pts` is a freshly-mounted, isolated `devpts` instance (`newinstance`), so the workload's terminal is a node in *its* view, not a host node. The seal `setsid`s, claims the slave as the controlling terminal (`TIOCSCTTY`), `dup2`s it onto the workload's stdio, and hands the master back to the `kennel` CLI over a socketpair (`SCM_RIGHTS`). The CLI puts the operator's real terminal into raw mode, proxies bytes both ways, relays `SIGWINCH`, and restores the terminal on exit.

This is the docker-`-it`/`ssh` model, and the isolation is the point: because the slave is a node in the kennel's own `devpts`, `ttyname(3)` (the `tty` command) resolves it and the operator's controlling tty is never exposed to the confined process. A non-interactive (piped/redirected) run skips all of this — its three stdio fds are passed straight through, no pty is allocated.

## 7.7.6 Seccomp (optional system call filter)

**Why and when.** Seccomp filters individual system calls. Most confinement at Project Kennel's intended level is better expressed as resource ACLs (fs, net, etc) than as syscall filters. But there are a few cases where seccomp is genuinely useful:

- Denying AF_UNIX abstract-namespace connect() (the awkward gap in Landlock, see §7.4).
- Denying TIOCSTI on older kernels (above).
- Denying `userfaultfd()` and other syscalls historically used in exploit chains (defence-in-depth against kernel CVEs, even though kernel CVEs are out of scope).
- Denying esoteric socket families (AF_PACKET, AF_NETLINK) — though cgroup BPF can do this too.

**Policy primitives.**

```toml
[seccomp]
profile = "default"          # "default" | "strict" | "permissive"
                             # default: reasonable denylist
                             # strict: small allowlist
                             # permissive: only the must-deny set

# Explicit additions to the always-deny list
deny = [
    "userfaultfd",
    "perf_event_open",
    "bpf",                   # cannot install eBPF programs
    "ptrace",                # belt and braces over AppArmor
    "process_vm_readv",
    "process_vm_writev",
    "kexec_load",
    "mount", "umount", "umount2",
    "pivot_root",
    "swapon", "swapoff",
    "reboot",
]
```

The default profile denies syscalls that have no legitimate use in kennels and have historical CVE involvement.

**Test plan.** Context attempts `userfaultfd()`; expect EPERM. Context attempts `process_vm_readv(<host pid>, ...)`; expect EPERM regardless of policy (uid + ptrace policy already covers this, seccomp is the additional layer).

## 7.7.7 cgroup membership

**Why it matters.** A kennel that can modify its own cgroup membership can escape the BPF filters attached to that cgroup. A kennel that can read cgroup state can map Project Kennel's process tree.

**Mechanism.** Cgroup v2 with delegation. Project Kennel's cgroup hierarchy is owned by Project Kennel's UID; the kennel is placed in a sub-cgroup it cannot move out of. Write access to `/sys/fs/cgroup/.../cgroup.procs` is denied by the fs policy.

**Policy primitives.**

```toml
[cgroup]
# These are Project Kennel invariants, not user-settable.
# Documented here for completeness.
modify_self = false         # cannot move out of own cgroup
read_other = false          # cannot read other kennels' cgroup state
```

The user does not write these; they are properties of Project Kennel's setup.

## 7.7.8 Time and clock

**Why it matters.** Adversarial timing analysis benefits from precise time. A kennel with access to high-resolution clocks and `CAP_SYS_TIME` (which it shouldn't have) could attempt timing attacks against other processes. This is generally out of scope (covered by side-channel exclusion in §2) but worth noting.

**Mechanism.** None specific. `CAP_SYS_TIME` is denied by `cap.bounding_set = []`. `clock_gettime` is universally accessible and Project Kennel does not attempt to fuzz time.

## 7.7.9 GPU and accelerator access

**Why it matters.** `/dev/nvidia*`, `/dev/dri/*` (Mesa/Intel/AMD), `/dev/kfd` (AMD ROCm), and similar device files grant direct GPU access. The GPU is a memory-mapped peripheral with its own driver attack surface; granting access is a significant capability expansion.

**Default.** Denied (per §7.2 device list).

**For ML workloads.** Templates like `ml-coding` explicitly grant the relevant device files and document the capability. The grant is recorded in the diff and threat-tagged.

```toml
[gpu]
enabled = true
backend = "nvidia"           # "nvidia" | "amd" | "intel"
# Framework grants the appropriate /dev nodes and library paths
# based on backend.
```

Templates that enable GPU access also typically need broader `exec.allow` (CUDA tools, drivers' user-space components) and may need broader `fs.read` (driver caches in `/var/lib/...`).

## 7.7.10 Hardware tokens (FIDO, TPM, smart cards)

**Why it matters.** Some workflows need YubiKey, TPM, or smart-card access from inside the kennel (ssh signing, age decryption, certificate operations). These require `/dev/hidraw*`, `/dev/tpm*`, or `pcscd` socket access.

**Default.** Denied (per §7.2 device list and §7.4 socket list).

**For workflows that need them.** Explicit grants per template, with clear threat-impact annotation:

```toml
[hardware]
fido_token = true            # grants /dev/hidraw* matching FIDO devices
                             # and the appropriate udev permissions
tpm = false                  # grants /dev/tpmrm0
smartcard = false            # grants pcscd socket access
```

The FIDO case is interesting because hardware-token presence is *itself* a defence against AI-agent exfiltration: an agent that needs the user's FIDO touch to sign cannot proceed without it.

**For SSH specifically, do not grant `fido_token` to reach a touch key.** Per-kennel SSH goes through the re-origination bastion (§7.8): the key — hardware or otherwise — is used **host-side**, so a touch happens at the host, outside the kennel. Binding `/dev/hidraw*` into the kennel would *defeat* the touch defence, because FIDO over USB-HID is an unprivileged userspace protocol — a workload holding the device fd can drive the authenticator (CTAP) directly, with no agent and no `ssh-sk-helper` in the path, and either harvest a touch for its own challenge or register its own resident credential. So `fido_token` is reserved for genuine *in-kennel, non-SSH* token use (age decryption, certificate operations) and is its own loud, explicitly-justified grant; SSH never needs it.

## 7.7.11 Summary

The minor policy classes (the present chapter) collectively contribute most of Project Kennel's "remove obvious footguns" value:

- Process introspection denial prevents the most common escape paths (ptrace).
- Env curation closes the most common credential leak.
- `no_new_privs` and capability dropping prevent privilege gain.
- Mount namespace + procfs handling close the most common information-leak channels.
- TIOCSTI handling closes a well-known terminal escape.
- Seccomp adds defence-in-depth against kernel CVE chains.
- GPU and hardware-token handling are explicit, documented, threat-tagged.

Each is individually small. Each is necessary. None alone is sufficient.
