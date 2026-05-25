# §4.2 Policy surface: filesystem

## 4.2.1 What we gate

Every filesystem read, write, create, delete, rename, link, and listing performed by processes in the context. This is the largest and most-exercised resource class because almost every operation a process performs touches the filesystem at some level (libraries, configs, logs, working files, the program's own binary).

## 4.2.2 Why it matters

The default-uid threat model assumes the entire user account is reachable. The filesystem is where the user's secrets, history, configuration, and ongoing work live:

```
~/.ssh/                      private keys, known_hosts, config
~/.gnupg/                    private keys, encrypted secrets
~/.aws/                      cloud credentials
~/.config/gh/                GitHub auth tokens
~/.config/gcloud/            GCP credentials
~/.netrc                     legacy auth tokens
~/.password-store/           pass database
~/.mozilla/, ~/.config/google-chrome/   browser sessions, cookies, history
~/.bash_history, ~/.zsh_history          shell history (often includes secrets)
~/.cache/                    application caches (often include auth artefacts)
~/Documents/                 the user's documents
~/Mail/, ~/.thunderbird/     email
~/Downloads/                 whatever the user has downloaded
```

A confined context should see exactly what it needs and nothing else. Granting read on `~/` is granting read on every credential, cookie, and document the user has accumulated.

## 4.2.3 Mechanism

Primary: Landlock filesystem ACL. Mature, well-covered, fine-grained.

The framework also constructs the filesystem *view* (§3.3) via mount namespace and bind mounts, so that what the context sees in `$HOME` and `$XDG_RUNTIME_DIR` is not the host's real directory contents but a shim containing only what's granted. The Landlock ACL is defence in depth: even if the context somehow constructs a path that points outside its view, the Landlock rules deny it.

The combination of constructed view (mount namespace) and Landlock (filesystem ACL) is deliberate. Either alone has gaps:

- Mount namespace alone: a context could `readlink` its way into a real path that was bind-mounted in, and Landlock isn't there to stop it.
- Landlock alone: a context's `readdir` on `$HOME` would show every directory entry, including the ones it can't actually open, which is information leakage and is confusing for the user. Constructed views make `readdir` return only granted entries.

## 4.2.4 Policy primitives

```toml
[fs]
# Read access: paths the context may open for reading and list directory entries.
# Glob patterns supported. Hidden files inside listed directories are included.
read = [
    "/usr/**",
    "/lib/**",
    "/lib64/**",
    "/etc/**",
    "/proc/self/**",
    "~/projects/foo/**",
    "~/.cache/<context>/**",          # context-private cache
]

# Write access: paths the context may open for writing, modify, create, delete.
write = [
    "~/projects/foo/**",
    "/tmp/<context>/**",              # see fs.tmp below
    "~/.local/share/agent-run/<context>/state/**",
]

# Create access: paths where the context may create new files/directories.
# By default, inherits from write. Override to allow writing existing files
# but not creating new ones.
create = []                            # default: same as write

# Execute access: paths from which binaries may be executed.
# Interacts with exec.* policy in §4.1.
exec_allowed_from = [
    "/usr/**",
    "/lib/**",
]

# Categorical denials. Evaluated before any allow.
# These are typical defaults in templates; users rarely override.
deny = [
    "~/.ssh/**",
    "~/.gnupg/**",
    "~/.aws/**",
    "~/.config/gcloud/**",
    "~/.config/gh/**",
    "~/.password-store/**",
    "~/.netrc",
    "~/.mozilla/**",
    "~/.config/google-chrome/**",
    "~/.config/chromium/**",
    "~/.config/Slack/**",
    "~/.local/share/keyrings/**",
    "/etc/shadow",
    "/etc/sudoers*",
    "/etc/ssh/ssh_host_*",
    "/proc/sys/kernel/**",
    "/sys/kernel/**",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
]

# Private tmpfs at /tmp inside the context.
# Without this, the context sees the host's /tmp with whatever's in it.
[fs.tmp]
private = true
size = "512M"                          # cap on the tmpfs size
mode = "0700"

# Shadow $HOME: present the context with a synthetic home directory
# rooted elsewhere, with only granted paths visible.
[fs.home]
shadow = true                          # default in confined templates
shim_root = "/run/agent-run/<context>/home"
# When shadow=true, the context's $HOME points to shim_root.
# Paths listed in fs.read/fs.write under ~/ are bind-mounted from real $HOME
# into shim_root.

# Procfs handling
[fs.proc]
visibility = "self"                    # "self" | "ancestors" | "all"
                                       # "self": only own process visible
                                       # "ancestors": own + parents in context
                                       # "all": full /proc (rarely correct)
hidepid = true                         # use hidepid=2 mount option

# Devfs: which device files are accessible
[fs.dev]
allow = [
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",                        # the context's controlling terminal
    "/dev/pts/**",                     # for spawning ttys
]
# Notable defaults-denied: /dev/mem, /dev/kmem, /dev/port,
# /dev/nvidia*, /dev/dri/*, /dev/snd/*, /dev/video*, /dev/input/*
```

## 4.2.5 The constructed `$HOME`

The most important transformation in the filesystem policy: the context does not see the real `$HOME`. The framework constructs a shim directory and bind-mounts the policy-granted paths from the real `$HOME` into it.

For a context with:

```toml
[fs]
read = ["~/projects/foo/**", "~/.config/git/**"]
write = ["~/projects/foo/**"]
```

The shim at `/run/agent-run/<ctx>/home/` is constructed as:

```
/run/agent-run/<ctx>/home/
├── projects/
│   └── foo/                  ← bind-mounted from real ~/projects/foo (rw)
├── .config/
│   └── git/                  ← bind-mounted from real ~/.config/git (ro)
└── .cache/
    └── <context>/            ← bind-mounted from ~/.cache/<context> (rw)
```

The context's environment has `HOME=/run/agent-run/<ctx>/home`. Inside the context, `ls ~/` shows exactly these entries. `ls ~/.ssh/` returns `ENOENT` because the directory does not exist in the shim. The Landlock ruleset additionally denies access to the real `~/.ssh/`, so even constructed paths cannot reach it.

This solves the problem that motivated the entire framework: the context cannot enumerate, cannot discover, cannot accidentally reach the credentials and state in the user's real `$HOME`.

## 4.2.6 The private `/tmp`

A confined context gets its own tmpfs mounted at `/tmp`. The host's `/tmp` is invisible. This:

- Prevents the context from leaving artefacts in the host `/tmp` that other processes (in other contexts or in the user's main session) might read.
- Prevents the context from reading whatever happens to be in the host `/tmp` (other processes' temp files, X11's socket directory, downloaded files).
- Survives context exit by being unmounted with the namespace, with no cleanup of host paths.

`$TMPDIR` is set to `/tmp` in the context's environment (already the default, but the framework sets it explicitly to be sure).

For contexts that need to share `/tmp` with the host (rare, usually a sign that the context is wrong), `fs.tmp.private = false` falls back to bind-mounting the real `/tmp`. Templates do not enable this.

## 4.2.7 Procfs visibility

`/proc` is a leakage channel by default: any process can see every other process's `/proc/<pid>/cmdline`, `/proc/<pid>/environ` (which often contains secrets), `/proc/<pid>/status` (containing UIDs, capabilities, etc).

The framework mitigates this with two mechanisms:

- **PID namespace**: the context sees only PIDs that exist inside its own namespace. The user's other processes are invisible. This is the strong isolation.
- **`hidepid=2` mount option** on `/proc`: even within the namespace, `/proc/<pid>` directories are accessible only to the owner of the process. This is belt-and-braces for cases where PID namespacing is unavailable or where the policy allows seeing ancestors.

A PID namespace requires unsharing it during context setup (`CLONE_NEWPID` in `unshare()`). The first process in the new namespace becomes PID 1 within it, with the responsibilities and constraints that implies (reaping zombies, signal handling). The framework's spawn flow handles this; the user's command doesn't see the wrinkle.

## 4.2.8 Device files

Most device files are denied by default. The framework's baseline allows the trivial ones (`/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/pts/*`) and templates extend cautiously.

Significant device categories and their treatment:

| Device | Default | Why |
|---|---|---|
| `/dev/null`, `/dev/zero` | Allow | Harmless; everything assumes them |
| `/dev/random`, `/dev/urandom` | Allow | Essential for cryptographic operations |
| `/dev/tty`, `/dev/pts/*` | Allow | The context's terminal |
| `/dev/nvidia*`, `/dev/dri/*` | Deny | GPU access is significant capability; opt-in for ML workloads |
| `/dev/snd/*` | Deny | Audio device direct access; opt-in for audio workflows |
| `/dev/video*` | Deny | Webcam access; opt-in for video workflows |
| `/dev/input/*` | Deny | Raw input device access (keyloggers); never granted |
| `/dev/mem`, `/dev/kmem`, `/dev/port` | Deny (and uid-blocked) | Direct memory access; only root would have it anyway, redundant |
| `/dev/uinput` | Deny | Input device creation (synthetic keystrokes) |
| `/dev/tpm0`, `/dev/tpmrm0` | Deny | TPM access; opt-in for HSM-rooted workflows |
| `/dev/hidraw*` | Deny | Raw HID; opt-in for hardware token (FIDO/U2F) workflows |
| `/dev/loop*` | Deny | Loopback block devices; rarely needed in contexts |
| `/dev/fuse` | Deny | FUSE mounts; rarely needed |

Templates may enable specific device categories. The `ml-coding` template allows `/dev/nvidia*` and documents the capability expansion. The `audio-recording` template allows `/dev/snd/*`. Each grant comes with a `threats.exposed` annotation surfacing the implication (see §5).

## 4.2.9 Sysfs and other pseudo-filesystems

`/sys/` is mostly read-only and mostly informational, but contains some attack surface:

- `/sys/kernel/security/` — write here can modify LSM state.
- `/sys/fs/cgroup/` — write here can manipulate cgroup membership.
- `/sys/class/net/*/address` — read leaks MAC addresses.
- `/sys/devices/virtual/dmi/id/` — read leaks hardware fingerprinting info.

The framework's default is read-only access to `/sys` excluding `/sys/kernel/security` and `/sys/fs/cgroup`, with write denied across the board. Templates may further deny `/sys` reads for paranoid contexts.

`/proc/sys/` (sysctl) is similar: deny write across the board, allow read for the unprivileged majority of sysctls.

## 4.2.10 Symlink and bind-mount escapes

A historical class of sandbox escape: the context creates a symlink to a forbidden path, then follows it through an allowed entry point. Landlock handles this correctly by resolving symlinks at the kernel level and applying the ruleset to the resolved path; the framework relies on this.

Bind-mount escapes are the symmetric concern: a context with the ability to manipulate mounts could remount a forbidden path into an allowed one. The framework prevents this by:

- Not granting `CAP_SYS_ADMIN` (required for mount operations) — default for unprivileged uids anyway.
- Setting `MS_NODEV`, `MS_NOSUID`, `MS_NOEXEC` (where appropriate) on the constructed view's mount points.
- Marking the context's mount namespace `MS_SLAVE` from the host, so the context cannot propagate mounts back up.

## 4.2.11 Test plan

Each is a regression test in `tests/fs/`:

1. Context with `fs.read = ["~/projects/foo/**"]` reads `~/projects/foo/src/main.rs`; expect success.
2. Same context reads `~/.ssh/id_ed25519`; expect ENOENT (shim doesn't include it) or EACCES (Landlock denies).
3. Context lists `$HOME`; expect to see only entries corresponding to `fs.read`/`fs.write`.
4. Context writes to `~/projects/foo/new-file`; expect success.
5. Context writes to `~/projects/bar/`; expect EACCES.
6. Context creates `/tmp/test`; expect success in the private tmpfs.
7. Different context creates `/tmp/test`; both succeed (each has its own tmpfs).
8. Context reads `/etc/shadow`; expect EACCES.
9. Context follows a symlink from an allowed path to a denied path; expect EACCES on the deref.
10. Context attempts `mount()`; expect EPERM (uid-level) regardless of policy.
11. Context lists `/proc`; expect to see only its own descendants (PID namespace working).
12. Context reads another process's `/proc/<pid>/environ`; expect ENOENT (not in PID namespace) or EACCES (hidepid).
13. Context with no `/dev/nvidia*` grant attempts to open it; expect EACCES.
14. Context with `fs.deny_writable = true` (exec interaction) writes a binary then attempts to execute it; expect EACCES on the execve.
15. Context attempts to write `/sys/kernel/security/...`; expect EACCES.

Roughly 30 tests total in the full corpus; the list above captures the most important invariants.
