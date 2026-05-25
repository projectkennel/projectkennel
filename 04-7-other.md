# §4.7 Policy surface: process introspection, environment, capabilities, mounts, tty

The remaining resource classes, grouped because each is smaller than the major classes (exec, fs, net, unix, dbus, x11) but each is essential to the threat model.

## 4.7.1 Process introspection: ptrace, signals, /proc visibility

**Why it matters.** An AI agent that can `ptrace` the user's shell can extract anything in memory: passwords, decrypted keys, browser session tokens, in-progress edits. An agent that can read `/proc/<other-pid>/environ` can lift secrets passed via env vars to other processes. An agent that can signal arbitrary processes can disrupt the user's workflow or kill protective daemons.

**Mechanism map.**

| Capability | Primary mechanism | Notes |
|---|---|---|
| `/proc` visibility | PID namespace + `hidepid=2` mount option | PID ns is the strong isolation |
| ptrace targets | AppArmor `ptrace` rule | Yama is coarse (global), AppArmor is per-profile |
| ptrace inbound | AppArmor `ptrace` rule (deny inbound from outside) | Defends against trusted context being ptraced by a different context |
| Signal delivery | AppArmor `signal` rule + PID ns | PID ns blocks signals to processes not visible |
| Capability set | `cap.bounding_set` via capset() | Drop all bounding caps |

**Policy primitives.**

```toml
[proc]
visibility = "self"         # "self" | "ancestors" | "all"
                            # "self": only own process tree visible
                            # "ancestors": own + parents (rare)
                            # "all": full /proc (almost never correct)
hidepid = true              # mount /proc with hidepid=2

[ptrace]
allow_targets = []          # contexts/processes this context may ptrace
                            # default: empty (cannot ptrace anything outside)
allow_from = []             # contexts that may ptrace this context
                            # default: empty (cannot be ptraced from outside)

[signal]
allow_targets = ["self"]    # whom we may signal
                            # "self" = own process tree
                            # specific cgroup paths possible but rarely useful
allow_from = []             # who may signal us
                            # parent default context can always signal children;
                            # this rule covers cross-context signalling
```

**Test plan.** A context attempts `ptrace(PTRACE_ATTACH, <host shell pid>)`; expect EPERM. A context reads `/proc/<other-pid>/environ`; expect ENOENT (PID ns) or EACCES (hidepid). A context attempts `kill(<host pid>, SIGTERM)`; expect ESRCH (PID ns) or EPERM (AppArmor).

## 4.7.2 Environment variables

**Why it matters.** The parent context (the user's shell) typically has high-trust env vars in its environment: `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, custom credentials. Without curation, all of these flow into the confined context.

**Mechanism.** Not a kernel mechanism. The spawn tool curates the environment before `execve()` based on policy.

**Policy primitives.**

```toml
[env]
# Whitelist of env vars to pass through. Everything else is dropped.
pass = [
    "PATH",
    "HOME",          # framework overrides this anyway (to shim $HOME)
    "USER",
    "LANG",
    "LC_*",
    "TERM",
    "TZ",
    "COLORTERM",
]

# Forced values, overriding anything inherited.
set = {
    PATH = "/usr/bin:/bin",
    TMPDIR = "/tmp",       # private tmpfs from §4.2
    XDG_RUNTIME_DIR = "/run/user/<uid>",   # real, but shimmed contents per §4.4
    SSH_AUTH_SOCK = "/home/u/.ssh/agent.sock",   # per-context ssh-agent
}

# Categorical drops, even if in pass.
deny = [
    "SSH_AUTH_SOCK",         # use per-context agent, not user's
    "GPG_AGENT_INFO",
    "AWS_*",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "*_TOKEN",
    "*_SECRET",
    "*_PASSWORD",
    "*_API_KEY",
]
```

The deny list uses glob patterns and is intentionally aggressive about anything matching `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`. Users who need specific tokens passed into the context add them explicitly to `pass`, which makes the grant visible in the policy diff.

**Test plan.** Context inherits a shell with `OPENAI_API_KEY` set; context sees `OPENAI_API_KEY` unset. Context inherits `PATH` and `LANG`; both are present (per `pass`). Context sees `TMPDIR=/tmp` regardless of parent's setting.

## 4.7.3 Linux capabilities

**Why it matters.** Linux capabilities partition root privilege into smaller units. Most are irrelevant to a uid-1000 context (they only apply to root or to setuid binaries). A few matter even for non-root: `CAP_NET_RAW` (raw sockets), `CAP_NET_BIND_SERVICE` (bind low ports). For confined contexts, the answer is always "drop everything".

**Mechanism.** `prctl(PR_CAPBSET_DROP, ...)` for the bounding set; `capset()` for the permitted/effective sets. `PR_SET_NO_NEW_PRIVS` (from §4.1) prevents gaining caps via setuid.

**Policy primitives.**

```toml
[cap]
bounding_set = []           # drop all bounding capabilities
no_new_privs = true         # non-negotiable; framework forces this
```

The `bounding_set` is typed as a list for forward compatibility, but the only defensible value for a confined context is empty. The schema validator warns if a context lists any capability, on the grounds that needing a cap in a confined uid-1000 context is almost always a sign of bad design.

`no_new_privs = false` is rejected by the schema regardless of context. This is a framework invariant; see §4.1.

## 4.7.4 Mount visibility

**Why it matters.** A context with visibility into all the user's mounts can see what removable media is plugged in, what cloud-sync mounts are present, what loop-mounted images exist. Some of these (e.g., `/mnt/usb-drive`) are sensitive.

**Mechanism.** Mount namespace (already required for the constructed-view pattern in §3.3). The framework's mount-ns construction includes only the mounts the context needs; the user's other mounts are invisible.

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
    "/run/agent-run/<ctx>", # the shim itself
]
# Everything else: invisible.

# Optional: mount-point flags applied to bind mounts
default_flags = ["MS_NODEV", "MS_NOSUID"]
```

The framework automatically derives `visible` from `fs.read` and `fs.write` lists; users rarely override.

**Test plan.** Context sees only listed mounts in `/proc/mounts`. Context attempts `mount()`; expect EPERM (no `CAP_SYS_ADMIN`).

## 4.7.5 Tty and TIOCSTI

**Why it matters.** The TIOCSTI ioctl ("type into the controlling tty as if I were the user") is a notorious sandbox escape. A confined process running in a terminal can inject keystrokes that appear to come from the user, executing commands in the user's shell after the context exits.

**Mechanism.** Recent kernels gate TIOCSTI behind the sysctl `dev.tty.legacy_tiocsti` (default off in kernels 6.2+). On older kernels, seccomp filtering of `ioctl()` is the fallback.

**Policy primitives.**

```toml
[tty]
# Check at policy load: refuse to apply this policy if TIOCSTI is enabled
# and the kernel is recent enough that it should be disabled.
require_tiocsti_disabled = true
```

If `require_tiocsti_disabled = true` and `dev.tty.legacy_tiocsti = 1`, the framework refuses to start the context with a clear error message instructing the user to set the sysctl. This is preferable to attempting to work around a sysctl-disabled-by-policy via seccomp.

On older kernels where the sysctl doesn't exist, the framework applies a seccomp filter denying `ioctl(*, TIOCSTI, *)`. This is best-effort; seccomp can't always inspect the arguments safely, see §4.4 for the same caveat.

**Other tty concerns.** Pty allocation, scrollback control, clipboard via terminal escape sequences (some terminals support OSC 52 for clipboard set, which is its own exfiltration channel). These are out of scope for v1; future revisions may add `tty.osc52 = "deny"` style controls. The current mitigation is "run confined contexts in a terminal you trust, with OSC 52 disabled in terminal config".

## 4.7.6 Seccomp (optional system call filter)

**Why and when.** Seccomp filters individual system calls. Most confinement at the framework's intended level is better expressed as resource ACLs (fs, net, etc) than as syscall filters. But there are a few cases where seccomp is genuinely useful:

- Denying AF_UNIX abstract-namespace connect() (the awkward gap in Landlock, see §4.4).
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

The default profile denies syscalls that have no legitimate use in confined contexts and have historical CVE involvement.

**Test plan.** Context attempts `userfaultfd()`; expect EPERM. Context attempts `process_vm_readv(<host pid>, ...)`; expect EPERM regardless of policy (uid + ptrace policy already covers this, seccomp is the additional layer).

## 4.7.7 cgroup membership

**Why it matters.** A context that can modify its own cgroup membership can escape the BPF filters attached to that cgroup. A context that can read cgroup state can map the framework's process tree.

**Mechanism.** Cgroup v2 with delegation. The framework's cgroup hierarchy is owned by the framework's UID; the context is placed in a sub-cgroup it cannot move out of. Write access to `/sys/fs/cgroup/.../cgroup.procs` is denied by the fs policy.

**Policy primitives.**

```toml
[cgroup]
# These are framework invariants, not user-settable.
# Documented here for completeness.
modify_self = false         # cannot move out of own cgroup
read_other = false          # cannot read other contexts' cgroup state
```

The user does not write these; they are properties of the framework's setup.

## 4.7.8 Time and clock

**Why it matters.** Adversarial timing analysis benefits from precise time. A context with access to high-resolution clocks and `CAP_SYS_TIME` (which it shouldn't have) could attempt timing attacks against other processes. This is generally out of scope (covered by side-channel exclusion in §2) but worth noting.

**Mechanism.** None specific. `CAP_SYS_TIME` is denied by `cap.bounding_set = []`. `clock_gettime` is universally accessible and the framework does not attempt to fuzz time.

## 4.7.9 GPU and accelerator access

**Why it matters.** `/dev/nvidia*`, `/dev/dri/*` (Mesa/Intel/AMD), `/dev/kfd` (AMD ROCm), and similar device files grant direct GPU access. The GPU is a memory-mapped peripheral with its own driver attack surface; granting access is a significant capability expansion.

**Default.** Denied (per §4.2 device list).

**For ML workloads.** Templates like `ml-coding` explicitly grant the relevant device files and document the capability. The grant is recorded in the diff and threat-tagged.

```toml
[gpu]
enabled = true
backend = "nvidia"           # "nvidia" | "amd" | "intel"
# Framework grants the appropriate /dev nodes and library paths
# based on backend.
```

Templates that enable GPU access also typically need broader `exec.allow` (CUDA tools, drivers' user-space components) and may need broader `fs.read` (driver caches in `/var/lib/...`).

## 4.7.10 Hardware tokens (FIDO, TPM, smart cards)

**Why it matters.** Some workflows need YubiKey, TPM, or smart-card access from inside the context (ssh signing, age decryption, certificate operations). These require `/dev/hidraw*`, `/dev/tpm*`, or `pcscd` socket access.

**Default.** Denied (per §4.2 device list and §4.4 socket list).

**For workflows that need them.** Explicit grants per template, with clear threat-impact annotation:

```toml
[hardware]
fido_token = true            # grants /dev/hidraw* matching FIDO devices
                             # and the appropriate udev permissions
tpm = false                  # grants /dev/tpmrm0
smartcard = false            # grants pcscd socket access
```

The FIDO case is interesting because hardware-token presence is *itself* a defence against AI-agent exfiltration: an agent that needs the user's FIDO touch to sign cannot proceed without it. Templates for ssh-agent contexts (see the ssh-unique-key conversation that motivated this document) explicitly grant FIDO token access for this reason.

## 4.7.11 Summary

The minor policy classes (the present chapter) collectively contribute most of the framework's "remove obvious footguns" value:

- Process introspection denial prevents the most common escape paths (ptrace).
- Env curation closes the most common credential leak.
- `no_new_privs` and capability dropping prevent privilege gain.
- Mount namespace + procfs handling close the most common information-leak channels.
- TIOCSTI handling closes a well-known terminal escape.
- Seccomp adds defence-in-depth against kernel CVE chains.
- GPU and hardware-token handling are explicit, documented, threat-tagged.

Each is individually small. Each is necessary. None alone is sufficient.
