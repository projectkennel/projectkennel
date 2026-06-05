# §7.2 Policy surface: filesystem

## 7.2.1 What we gate

Every filesystem read, write, create, delete, rename, link, and listing performed by processes in the kennel. This is the largest and most-exercised resource class because almost every operation a process performs touches the filesystem at some level (libraries, configs, logs, working files, the program's own binary).

## 7.2.2 Threats addressed

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

A kennel should see exactly what it needs and nothing else. Granting read on `~/` is granting read on every credential, cookie, and document the user has accumulated.

## 7.2.3 Mechanism

Primary: Landlock filesystem ACL. Mature, well-covered, fine-grained.

Project Kennel also constructs the filesystem *view* (§4.1) via mount namespace and bind mounts, so that what the kennel sees in `$HOME` and `$XDG_RUNTIME_DIR` is not the host's real directory contents but a shim containing only what's granted. The Landlock ACL is defence in depth: even if the kennel somehow constructs a path that points outside its view, the Landlock rules deny it.

The combination of constructed view (mount namespace) and Landlock (filesystem ACL) is deliberate. Either alone has gaps:

- Mount namespace alone: a kennel could `readlink` its way into a real path that was bind-mounted in, and Landlock isn't there to stop it.
- Landlock alone: a kennel's `readdir` on `$HOME` would show every directory entry, including the ones it can't actually open, which is information leakage and is confusing for the user. Constructed views make `readdir` return only granted entries.

## 7.2.4 Policy primitives

```toml
[fs]
# Read access: paths the kennel may open for reading and list directory entries.
# Glob patterns supported. Hidden files inside listed directories are included.
read = [
    "/usr/**",
    "/lib/**",
    "/lib64/**",
    "/etc/**",
    "/proc/self/**",
    "~/projects/foo/**",
    "~/.cache/<kennel>/**",          # kennel-private cache
]

# Write access: paths the kennel may open for writing, modify, create, delete.
write = [
    "~/projects/foo/**",
    "/tmp/<kennel>/**",              # see fs.tmp below
    "~/.local/share/kennel/<kennel>/state/**",
]

# Create access: paths where the kennel may create new files/directories.
# By default, inherits from write. Override to allow writing existing files
# but not creating new ones.
create = []                            # default: same as write

# Execute access: paths from which binaries may be executed.
# Interacts with exec.* policy in §7.1.
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

# Private tmpfs at /tmp inside the kennel.
# Without this, the kennel sees the host's /tmp with whatever's in it.
[fs.tmp]
private = true
size = "512M"                          # cap on the tmpfs size
mode = "0700"

# Shadow $HOME: present the kennel with a synthetic home directory
# rooted elsewhere, with only granted paths visible.
[fs.home]
shadow = true                          # default in confined templates
shim_root = "/run/kennel/<kennel>/home"
# When shadow=true, the kennel's $HOME points to shim_root.
# Paths listed in fs.read/fs.write under ~/ are bind-mounted from real $HOME
# into shim_root.

# Procfs handling
[fs.proc]
visibility = "self"                    # "self" | "ancestors" | "all"
                                       # "self": only own process visible
                                       # "ancestors": own + parents in kennel
                                       # "all": full /proc (rarely correct)
hidepid = true                         # use hidepid=2 mount option

# Devfs: which device files are accessible
[fs.dev]
allow = [
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",                        # the kennel's controlling terminal
    "/dev/pts/**",                     # for spawning ttys
]
# Notable defaults-denied: /dev/mem, /dev/kmem, /dev/port,
# /dev/nvidia*, /dev/dri/*, /dev/snd/*, /dev/video*, /dev/input/*
```

## 7.2.5 The constructed `$HOME`

> The constructed `$HOME` view is built by
> `kennel-spawn`'s `build_view_and_pivot`, which mounts a fresh tmpfs new root, binds the
> granted system paths in place and the granted `~/…` paths remapped beneath
> `shim_root` (read-only unless the grant is writable), constructs `/dev` from
> `fs.dev.allow` (nodes bind-mounted and Landlock-granted read/write/`IOCTL_DEV`),
> mounts a fresh `/proc` with `hidepid=2` and a private `/tmp` (`fs.tmp` size/mode),
> then `pivot_root`s in. The synthetic `/etc` is **constructed, never the host
> `/etc` bound in**: `kenneld::etc` writes the libc/NSS files (passwd/group/hosts/
> resolv.conf/…) scrubbed of host specifics, plus read-only binds of the vanilla
> TLS/linker subtrees (`/etc/ssl`,`/etc/pki`,`/etc/ld.so.*`). **Identity is masked:**
> the synthetic `passwd`/`group` name the workload's uid and gid `kennel` (never the
> operator's login name), with the in-kennel shim `$HOME` as the home — so `id`,
> `whoami`, and `getpwuid` reveal no host identity. The uid/gid *numbers* are
> unchanged (they must match the host inodes of bind-mounted files). **Supplementary
> groups are policy-defined** (`[identity].groups`, §7.2.8): the privileged seal
> `setgroups` to exactly the granted set — by default *none*, dropping every inherited
> host group — and each granted group is named in the synthetic `/etc/group`, so `id`
> shows names, not the operator's full group memberships as bare numbers. Two invariants worth
> repeating: **writable binds resolve to persistent host inodes** (work survives
> teardown — the tmpfs holds only scaffolding), and the Landlock ruleset is built
> **after** `pivot_root` so its rules key on the view's inodes. kenneld sets
> `HOME=shim_root` and provides the new-root staging dir at bring-up.

The most important transformation in the filesystem policy: the kennel does not see the real `$HOME`. Project Kennel constructs a shim directory and bind-mounts the policy-granted paths from the real `$HOME` into it.

For a kennel with:

```toml
[fs]
read = ["~/projects/foo/**", "~/.config/git/**"]
write = ["~/projects/foo/**"]
```

The shim at `/run/kennel/<ctx>/home/` is constructed as:

```
/run/kennel/<ctx>/home/
├── projects/
│   └── foo/                  ← bind-mounted from real ~/projects/foo (rw)
├── .config/
│   └── git/                  ← bind-mounted from real ~/.config/git (ro)
└── .cache/
    └── <kennel>/            ← bind-mounted from ~/.cache/<kennel> (rw)
```

The kennel's environment has `HOME=/run/kennel/<ctx>/home`. Inside the kennel, `ls ~/` shows exactly these entries. `ls ~/.ssh/` returns `ENOENT` because the directory does not exist in the shim. The Landlock ruleset additionally denies access to the real `~/.ssh/`, so even constructed paths cannot reach it.

This solves the problem that motivated Project Kennel: the kennel cannot enumerate, cannot discover, cannot accidentally reach the credentials and state in the user's real `$HOME`.

### Template-level constructs built on the constructed-`$HOME` mechanism

Two template-level features extend the constructed-`$HOME` pattern. They are not separate policy primitives — both compose the underlying mount-namespace + bind-mount machinery — but they are common enough that templates declare them with dedicated syntax. The semantics live here in §7.2; the template-author-facing description lives in §5.9.

**`fs.home.sanitise`** constructs a sanitised copy of a host configuration file at kennel-spawn time and bind-mounts the sanitised copy into the shim at the path the agent expects. Useful for `~/.gitconfig`, `~/.npmrc`, and similar config files where the agent needs the file to operate but specific keys (credential helpers, embedded tokens, URL rewrites) must not be visible. Project Kennel reads the real file, applies the `strip` patterns to remove matching keys, writes the result to a tmpfs location under `/run/kennel/<kennel>/sanitised/`, and bind-mounts that location into the shim.

**`fs.scrub`** overlays a tmpfs over files within otherwise-granted directories that match a glob pattern. The canonical use case is hiding `.env`, `.env.*`, `terraform.tfstate`, `*.pem`, `*.key`, and similar credential-shaped files within the project tree. The agent can read the file but sees either an empty file (`mode = "empty"`, the default) or ENOENT (`mode = "enoent"`, stricter but breaks tools that test for file existence). Project Kennel iterates the granted directories at shim construction time, finds files matching the patterns, and overlays a per-file tmpfs at each match.

Both constructs are best-effort against direct reads, not against semantic-level recovery. An agent that can run `git show HEAD:.env` on a scrubbed file can recover the original contents from git's object store; an agent that can execute the build system can recover sanitised config via the build's normal credential-handling paths. Project Kennel does not claim these constructs prevent determined recovery; they prevent the casual reconnaissance pattern catalogued as T1.1 and the secret-introduction pattern catalogued as T3.1.

## 7.2.6 The private `/tmp`

A kennel gets its own tmpfs mounted at `/tmp`. The host's `/tmp` is invisible. This:

- Prevents the kennel from leaving artefacts in the host `/tmp` that other processes (in other kennels or in the user's main session) might read.
- Prevents the kennel from reading whatever happens to be in the host `/tmp` (other processes' temp files, X11's socket directory, downloaded files).
- Survives kennel exit by being unmounted with the namespace, with no cleanup of host paths.

`$TMPDIR` is set to `/tmp` in the kennel's environment (already the default, but Project Kennel sets it explicitly to be sure).

For kennels that need to share `/tmp` with the host (rare, usually a sign that the kennel is wrong), `fs.tmp.private = false` falls back to bind-mounting the real `/tmp`. Templates do not enable this.

## 7.2.7 Procfs visibility

`/proc` is a leakage channel by default: any process can see every other process's `/proc/<pid>/cmdline`, `/proc/<pid>/environ` (which often contains secrets), `/proc/<pid>/status` (containing UIDs, capabilities, etc).

Project Kennel mitigates this with two mechanisms:

- **PID namespace**: the kennel sees only PIDs that exist inside its own namespace. The user's other processes are invisible. This is the strong isolation.
- **`hidepid=2` mount option** on `/proc`: even within the namespace, `/proc/<pid>` directories are accessible only to the owner of the process. This is belt-and-braces for cases where PID namespacing is unavailable or where the policy allows seeing ancestors.

A PID namespace requires unsharing it during kennel setup (`CLONE_NEWPID` in `unshare()`). The first process in the new namespace becomes PID 1 within it, with the responsibilities and constraints that implies (reaping zombies, signal handling). Project Kennel's spawn flow handles this; the user's command doesn't see the wrinkle.

## 7.2.8 Device files

Most device files are denied by default. Project Kennel's baseline allows the trivial ones (`/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/pts/*`) and templates extend cautiously.

Significant device categories and their treatment:

| Device | Default | Why |
|---|---|---|
| `/dev/null`, `/dev/zero` | Allow | Harmless; everything assumes them |
| `/dev/random`, `/dev/urandom` | Allow | Essential for cryptographic operations |
| `/dev/tty`, `/dev/pts/*` | Allow | The kennel's terminal |
| `/dev/nvidia*`, `/dev/dri/*` | Deny | GPU access is significant capability; opt-in for ML workloads |
| `/dev/snd/*` | Deny | Audio device direct access; opt-in for audio workflows |
| `/dev/video*` | Deny | Webcam access; opt-in for video workflows |
| `/dev/input/*` | Deny | Raw input device access (keyloggers); never granted |
| `/dev/mem`, `/dev/kmem`, `/dev/port` | Deny (and uid-blocked) | Direct memory access; only root would have it anyway, redundant |
| `/dev/uinput` | Deny | Input device creation (synthetic keystrokes) |
| `/dev/tpm0`, `/dev/tpmrm0` | Deny | TPM access; opt-in for HSM-rooted workflows |
| `/dev/hidraw*` | Deny | Raw HID; opt-in for hardware token (FIDO/U2F) workflows |
| `/dev/loop*` | Deny | Loopback block devices; rarely needed in kennels |
| `/dev/fuse` | Deny | FUSE mounts; rarely needed |
| `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyS*` | Deny | Serial consoles; opt-in via `[[fs.dev.passthrough]]` (group `dialout`/`uucp`) |
| `/dev/net/tun` | Deny | Userspace tunnels; opt-in via `[[fs.dev.passthrough]]` (persistent, group-owned) |
| `/dev/ppp` | Deny | PPP; opt-in via `[[fs.dev.passthrough]]` (group `dip`) |

Templates may enable specific device categories. The `ml-coding` template allows `/dev/nvidia*` and documents the capability expansion. The `audio-recording` template allows `/dev/snd/*`. Each grant comes with a `threats.exposed` annotation surfacing the implication (see §5).

### Passing through a specific host device

The baseline `fs.dev.allow` list above is the *trivial* pseudo-device set — bare paths, no documentation needed. A workload that must talk to a **specific real host device** — a serial console (`/dev/ttyUSB0`, `/dev/ttyACM0`, `/dev/ttyS0`), `/dev/ppp`, `/dev/net/tun` — declares it as a **passthrough**, which is loud: a documented `reason` and an `exposed` threat tag are both required.

```toml
[[fs.dev.passthrough]]
path   = "/dev/ttyUSB0"
group  = "dialout"                # the owning group that gates access (below)
reason = "flash firmware to the board on the bench"
threats.exposed = ["T2.x"]        # passing a device through widens the kernel attack surface

[[fs.dev.passthrough]]
path   = "/dev/net/tun"
group  = "netdev"
reason = "establish a userspace WireGuard tunnel"
threats.exposed = ["T2.x"]
```

A passthrough is authored where the rest of a kennel's grants are — a leaf adds its own device with `[[fs.dev.passthrough.add]]`, folded up the template chain like `[[net.allow.add]]`. Validation (compile time, on the resolved policy): the `path` is absolute under `/dev` with no `..`, a `reason` is present, and an `exposed` threat tag is carried (`kennel-policy::dev`). A passthrough that shims an SSH agent has no special case — SSH is the §7.8 concern, not a device.

**Mechanism.** A passthrough binds exactly like an `fs.dev.allow` entry: the host node is bind-mounted into the kennel's constructed `/dev` at the same path (its parent created for a subdirectory node like `/dev/net/tun`), preserving the device's owner/group/mode, and granted Landlock `read`/`write`/`ioctl` (`IOCTL_DEV`). Nothing else is in the constructed `/dev`, so a non-granted device is structurally absent (ENOENT). The reason/threats/group are compile-time documentation and are not carried into the settled artefact.

**Access is GID, not capability.** These devices are gated by their DAC group — `dialout`/`uucp` for serial, `dip`/`modem` for `/dev/ppp`, `netdev` (or `0666`) for `/dev/net/tun` — not by a Linux capability. The kennel reaches a passed-through device only if the device's owning group is in the kennel's group set, and the user must already be a member of that group (the framework never grants a group the user lacks — that would be privilege escalation). `/dev/net/tun` and `/dev/ppp` are used the **unprivileged** way: a persistent device pre-created and owned by the user's group (the standard `tunctl`/`pppd` pattern), *not* by handing the workload `CAP_NET_ADMIN` to create fresh interfaces — which the kennel does not do, and which in the host network namespace would risk bypassing the egress proxy (§7.3).

The kennel carries **only the groups policy grants**: the privileged spawn seal `setgroups` to exactly the set named by `[identity].groups` plus every passthrough `group` (default: none — all inherited host groups are dropped), and `kenneld` refuses any group the operator is not a member of (the root seal could otherwise over-grant). So a passthrough's `group` both unlocks the device's DAC *and* is the group carried into the kennel; it is named in the synthetic `/etc/group`, so `id` resolves it by name. The standalone form, for non-device group access (e.g. group-owned files) or to be explicit:

```toml
# Supplementary groups the kennel retains (resolved to GIDs, membership-checked).
# A [[fs.dev.passthrough]].group is added automatically.
[identity]
groups = ["dialout", "plugdev"]
```

## 7.2.9 Sysfs and other pseudo-filesystems

`/sys/` is mostly read-only and mostly informational, but contains some attack surface:

- `/sys/kernel/security/` — write here can modify LSM state.
- `/sys/fs/cgroup/` — write here can manipulate cgroup membership.
- `/sys/class/net/*/address` — read leaks MAC addresses.
- `/sys/devices/virtual/dmi/id/` — read leaks hardware fingerprinting info.

Project Kennel's default is read-only access to `/sys` excluding `/sys/kernel/security` and `/sys/fs/cgroup`, with write denied across the board. Templates may further deny `/sys` reads for paranoid kennels.

`/proc/sys/` (sysctl) is similar: deny write across the board, allow read for the unprivileged majority of sysctls.

## 7.2.10 Symlink and bind-mount escapes

A historical class of sandbox escape: the kennel creates a symlink to a forbidden path, then follows it through an allowed entry point. Landlock handles this correctly by resolving symlinks at the kernel level and applying the ruleset to the resolved path; Project Kennel relies on this.

Bind-mount escapes are the symmetric concern: a kennel with the ability to manipulate mounts could remount a forbidden path into an allowed one. Project Kennel prevents this by:

- Not granting `CAP_SYS_ADMIN` (required for mount operations) — default for unprivileged uids anyway.
- Setting `MS_NODEV`, `MS_NOSUID`, `MS_NOEXEC` (where appropriate) on the constructed view's mount points.
- Marking the kennel's mount namespace `MS_SLAVE` from the host, so the kennel cannot propagate mounts back up.

## 7.2.11 Test plan

Each is a regression test in `tests/fs/`:

1. Context with `fs.read = ["~/projects/foo/**"]` reads `~/projects/foo/src/main.rs`; expect success.
2. Same kennel reads `~/.ssh/id_ed25519`; expect ENOENT (shim doesn't include it) or EACCES (Landlock denies).
3. Context lists `$HOME`; expect to see only entries corresponding to `fs.read`/`fs.write`.
4. Context writes to `~/projects/foo/new-file`; expect success.
5. Context writes to `~/projects/bar/`; expect EACCES.
6. Context creates `/tmp/test`; expect success in the private tmpfs.
7. Different kennel creates `/tmp/test`; both succeed (each has its own tmpfs).
8. Context reads `/etc/shadow`; expect EACCES.
9. Context follows a symlink from an allowed path to a denied path; expect EACCES on the deref.
10. Context attempts `mount()`; expect EPERM (uid-level) regardless of policy.
11. Context lists `/proc`; expect to see only its own descendants (PID namespace working).
12. Context reads another process's `/proc/<pid>/environ`; expect ENOENT (not in PID namespace) or EACCES (hidepid).
13. Context with no `/dev/nvidia*` grant attempts to open it; expect EACCES.
14. Context with `fs.deny_writable = true` (exec interaction) writes a binary then attempts to execute it; expect EACCES on the execve.
15. Context attempts to write `/sys/kernel/security/...`; expect EACCES.

Roughly 30 tests total in the full corpus; the list above captures the most important invariants.
