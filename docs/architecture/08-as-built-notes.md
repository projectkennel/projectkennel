# §8 Implementation notes: roadmap, lessons, and gotchas

The design and architecture chapters describe the system as built. This chapter
collects what does not belong in a surface description: the pieces that are
designed but not yet implemented (roadmap), the implementation lessons that
should shape the rest of the build, and the build/test gotchas that bite.

## 8.1 Roadmap — designed, not yet built

Real design intent, not dead ideas; simply not implemented yet. The chapters that
describe these read as roadmap.

- **The unified audit writer + sinks** (`02-3-audit-schema.md`) — **BUILT** (it
  graduated from this roadmap; kept here for the remnants still owed). The
  `kennel-audit` crate (`#![forbid(unsafe_code)]`) is the seam: the canonical
  `AuditEvent` envelope, one `kennel-text` sanitisation pass, per-class audit-level
  filtering (incl. `summary` first-allow dedup), and a `Sink` trait with fan-out
  and drop-reporting. All four sinks exist — file (per-class JSONL, append-atomic,
  rotation+retention), stdout, hand-rolled RFC 5424 syslog, and a feature-gated
  journald sink (`sd_journal_sendv` FFI in `kennel-syscall`, feature
  `audit-journald`). The `[audit]` policy section is parsed, folded, validated, and
  carried in the signed settled policy as `AuditRuntime` (omitted from the canonical
  form when empty, so existing policies sign unchanged). kenneld builds the writer
  from it and emits the `lifecycle.*` events (`kennel-spawn`'s spawn lifecycle).
  Still owed: routing the netproxy's egress records and the BPF/privhelper events
  *through* the unified writer (today the netproxy formats its own
  `network.jsonl` — schema-forward-compatible per `02-3`, and the BPF events still
  drain `kennel-bpf/src/ringbuf.rs` directly); kernel-LSM (Landlock/AppArmor) deny
  capture; the journald `MESSAGE_ID` registry; file-sink gzip compression
  (`compress_after_seconds`); the installation-wide `/etc/kennel/audit.toml`; and
  the per-sink emit timeout.
- **`kennel-checksum-verify`** (the Rust verifier of `03-crate-decomposition.md`
  / §5.5): the shell witness (`src/tools/verify-checksums.sh`, system `sha256sum`)
  is what runs today; the Rust twin lands once `sha2` is itself vendored (§5.5.1).

- **`kennel-sshd` — the per-kennel SSH egress bastion** (design `07-8-ssh.md` §7.8) — **BUILT** (it graduated from this roadmap; kept here for its build
  notes and the findings that shaped it). A per-user managed instance of stock
  OpenSSH `sshd`, sibling to `kenneld`, that re-originates a kennel's SSH to
  policy-granted destinations with the user's real key (held host-side) so the
  workload never holds a key or an agent socket. The mechanism is **validated end
  to end against stock OpenSSH 9.6** (see the proof note below) — forced-command
  re-origination carries `git`-shape commands and interactive ptys; the destination
  is fixed in `command=` (keyed to the authenticated synthetic key) so the workload
  cannot redirect it; a non-synthetic key is refused; `$SSH_USER_AUTH`
  (`ExposeAuthInfo`) exposes which synthetic key authenticated. Three findings
  shaped the build:
  1. The forced-command bindings **are** the access policy, so where they are stored
     is load-bearing. A static `AuthorizedKeysFile` owned by the bastion user is a
     decision the user could rewrite without `kenneld` ever seeing it — a mutable
     surface that bypasses the trusted daemon entirely. The **production** source is
     therefore a **root-owned `AuthorizedKeysCommand`** (`kennel-akc`): OpenSSH's
     safe-path check accepts a root-owned helper, the user cannot replace it, and it
     answers each auth by querying the **running `kenneld`** — the same trusted process
     that builds and seals every kennel — for the line bound to the offered key
     (`kenneld::control::Request::AuthorizedKeys`). The bindings live only in the
     daemon's verified, in-memory edge state; **no file is written**. Trusting the
     running daemon here is the matching posture, not a gap: if user-cred code could
     subvert `kenneld`, the confinement itself is already lost, so a second on-disk
     check would buy nothing. The static `AuthorizedKeysFile` (`AuthSource::File`)
     remains as the prototype/e2e fallback, on a `0700` safe-owned path.
  2. `restrict,pty` is the per-key option set (denies forwarding/X11/agent/
     user-rc, keeps a tty); combined with the `Match` block (`AllowTcpForwarding
     no`, `Subsystem sftp /bin/false`) this makes SFTP/scp/port-forwarding
     out-of-scope-by-construction for the first cut.
  3. Every sshd-checked path (runtime dir, host key, AKC) must be on a
     safe-owned path — never world-writable `/tmp`.

  **Built so far** (the pure, host-independent layers, fully unit-tested):
  - The **`[ssh]` source schema** — `SshSection`/`SshKey`/`SshKnownHost` in
    `kennel-policy::source`, `fold_ssh` in `resolve.rs` (bare-set lists like
    `[unix]`), `SshLeaf` add/remove deltas in `leaf.rs`, dropped in `translate.rs`
    (source-only), with the §7.8.8 compile-time validators in `kennel-policy::ssh`
    wired into `compile`/`compile_leaf`: every `fingerprint` well-formed
    (`SHA256:<43-char base64>`), every `hosts` entry `⊆ net.allow` on port 22, and
    `allow_headless = true` must carry a threat tag.
  - The **synthetic `~/.ssh` generator** — `kenneld::ssh` (a sibling of `etc.rs`):
    renders the generated read-only `config` (one bastion-routed stanza per granted
    host, `HostKeyAlias kennel-bastion`, `IdentitiesOnly`, `StrictHostKeyChecking`)
    and the bastion-only `known_hosts`, and `materialize`s them with `0700`/`0600`
    modes alongside the pre-minted synthetic keys.
  - **`kennel-ssh-reorigin`** — the unprivileged forced-command router (its own
    std-only crate). The security-load-bearing core is pure and tested: strict
    `--dest`/`--key` parsing (option-injection-proof), the hostname and
    `SHA256:` grammars, `$SSH_USER_AUTH` publickey confirmation (fail-closed),
    exact fingerprint→agent-identity selection, and outbound-`ssh` argv
    construction (`IdentitiesOnly`, `StrictHostKeyChecking`, `--`-terminated so
    `$SSH_ORIGINAL_COMMAND` can never be read as a flag). `main` is the thin IO
    tail (`ssh-add` enumeration, identity-file write, `execvp ssh`). The host-side
    config seam is two `kenneld`-owned env knobs the workload cannot influence:
    `KENNEL_SSH_KNOWN_HOSTS` (the bastion's `known_hosts` for the real
    destinations) and `KENNEL_SSH_CONFIG` (an `ssh -F` config for per-destination
    `HostName`/`Port`/`ProxyJump`).
  - **The bastion key-state manager** — `kenneld::bastion`: `kenneld` owns one
    per-user `kennel-sshd` for the session and tracks the granted
    `(synthetic-key → dest, real-key)` edges across all the user's kennels. It
    renders the bastion's `authorized_keys` from the edge set (one
    `restrict,pty,command=…` line each), mints the disposable synthetic key per edge
    (`kenneld::ssh::mint_synthetic_key`, stock `ssh-keygen`), lazily starts the
    daemon on the first edge and stops it when the last kennel deregisters, and tags
    edges by owning kennel so a teardown drops exactly its grants. (Edge-bookkeeping
    and `authorized_keys` rendering are unit-tested; the live start/stop reuses the
    proven `sshd` spawn.)
  - **The bastion config + launch** — `kenneld::sshd`: the hardened `sshd_config`
    generator (`ExposeAuthInfo`, publickey-only, `AllowTcpForwarding no`/`PermitOpen
    none`/`Subsystem sftp /bin/false`, the `SetEnv SSH_AUTH_SOCK=…` that hands the
    forced command the host-side agent), the `restrict,pty,command=…`
    `authorized_keys` line builder, host-key generation via stock `ssh-keygen`, and
    `spawn`/reap of the managed `sshd` (mirrors `proxy.rs`). It emits whichever auth
    source `Bastion` is configured with: the production root-owned
    `AuthorizedKeysCommand … %t %k` (no file) or the prototype `AuthorizedKeysFile`.
  - **The root-owned key command** — `kennel-akc` (a `kenneld` bin) is the production
    `AuthorizedKeysCommand`. sshd hands it the offered key (`%t %k`); it queries the
    running `kenneld` over the control socket
    (`Request::AuthorizedKeys` → `Bastion::authorized_keys_for`, matching the offered
    key's `(type, base64)` against the live edges, comment-ignored) and prints the
    forced-command line(s). Fail-closed: no daemon, bad args, or any non-matching key
    prints nothing and exits non-zero, so sshd authorises nothing. Installed
    root-owned (safe-path), it runs as the bastion user to reach the per-user control
    socket. Unit- and integration-tested (`tests/akc.rs` drives the real binary
    against a stand-in control server, including the no-daemon and empty-argv
    fail-closed paths), and proven **end to end against stock OpenSSH under root**
    (`tests/akc_openssh.rs`, gated `root-tests`): a real bastion `sshd` configured with
    the root-owned AKC authorises exactly the synthetic key bound to a live edge — it
    runs `kennel-akc`, which queries `Bastion::authorized_keys_for` over the control
    socket — and refuses an unregistered key. (The one privileged step is chowning the
    AKC to root, which is precisely the privilege Project Kennel installs with.)
  - **The egress reach** — `kennel-socks-connect` (its own std-only crate): a
    kennel can `connect()` only to its egress proxy (§7.3.2) and `ssh` has no
    built-in SOCKS client, so each synthetic `~/.ssh` `config` stanza names this
    binary as its `ProxyCommand`; it SOCKS5s through the proxy (`$KENNEL_SOCKS_PROXY`)
    to the bastion (reached as a host-loopback service, §7.3). The synthetic config
    generator emits the `ProxyCommand` line. *Design decision:* the bastion is
    reached via the existing `[[net.loopback.host_services]]` allow, and a shipped
    SOCKS connector (not a dependency on `nc`) bridges `ssh` to the proxy.
  - **End-to-end proof** — `src/tools/ssh-bastion-e2e.sh` stands up a real topology
    with stock OpenSSH 9.6 (a bastion `sshd` + a destination `sshd` + an agent) and
    drives the **built** binaries through it, asserting §7.8.9's load-bearing
    properties: re-origination forwards `$SSH_ORIGINAL_COMMAND` to the policy-fixed
    destination; an injection-laden command cannot redirect it or execute on the
    bastion; a non-synthetic key is refused; a port-forward channel is denied; and
    the **full egress chain** — `ssh` → `kennel-socks-connect` → the real
    `kennel-netproxy` (SOCKS5) → bastion → re-origination — reaches the destination.
    All five pass.

  - **The source-only→runtime bridge** — the resolved `[ssh]` grants are carried
    into the signed settled policy (`SettledPolicy.ssh: SshRuntime`, populated by
    `translate`, kept out of the enforcement `EffectivePolicy` and omitted from the
    canonical form when empty so existing signatures are unaffected), and surfaced to
    `kenneld` via `Loaded.ssh`. This is the path the still-unbuilt `[unix]` runtime
    will reuse.

  - **`kennel-netproxy` host-loopback services** — *built*. The proxy now reads
    `[[net.host_services]]` (a list of exact `addr:port` literals) and reaches them
    despite the host-loopback invariant deny, via an allow-exception checked ahead of
    the deny-before-allow ruleset (`Proxy::with_host_services`); the match is on the
    literal destination address only (never a resolved name), so there is no
    rebinding surface. Unit-tested: a host service connects through a loopback deny,
    a non-host-service loopback port stays denied, and the config parses.

  - **The spawn-path assembly** — *built and proven in a real kennel*. When a kennel's
    `Loaded.ssh` is non-empty, `kenneld` (`server.rs::register_ssh` →
    `lib.rs::bring_up`): mints a synthetic key per grant, registers each edge with the
    per-user `Bastion` (lazily starting `kennel-sshd`), materialises the synthetic
    `~/.ssh` into the constructed-view `$HOME` (laid in like the synthetic `/etc`,
    with a Landlock read grant on the `~/.ssh` dir), binds `kennel-socks-connect` into
    the view with a Landlock execute grant, sets `$KENNEL_SOCKS_PROXY` to the kennel's
    proxy address, and adds the bastion as a `[[net.host_services]]` entry in the
    proxy config; teardown (and any bring-up failure) deregisters the kennel's edges.
    The per-user `Bastion` lives in `Shared`, configured from `Identity` (bastion
    loopback addr + tag-derived port + `$SSH_AUTH_SOCK`). The kenneld root e2e
    (`tests/e2e.rs`) brings a confined kennel up with an `[ssh]` grant and the
    workload verifies — inside the sandbox (namespaces, pivot_root view, BPF,
    Landlock) — that its synthetic `~/.ssh` (connector `ProxyCommand`, bastion-pinned
    `known_hosts`, the synthetic key), the bound connector, and `$KENNEL_SOCKS_PROXY`
    are all present.

  **The key source is the root-owned `AuthorizedKeysCommand`.** Production vends keys
  through `kennel-akc` (root-owned, querying the running `kenneld`), not a file. The
  bindings are the access policy; keeping them only in the trusted daemon's verified
  in-memory state — never on a disk a user-cred process could rewrite behind
  `kenneld`'s back — is the matching security posture, and the root-owned helper is
  what OpenSSH's safe-path check requires. The static `AuthorizedKeysFile`
  (`AuthSource::File`, rewritten live by `Bastion`) survives only as the prototype/e2e
  fallback on a `0700` safe-owned path.

  (Phase numbering follows §7.8's original plan; the per-kennel SSH egress is now
  built end to end and proven by both `src/tools/ssh-bastion-e2e.sh` — the bastion
  re-origination + full egress chain against stock OpenSSH 9.6, driving the real
  `kennel-ssh-reorigin`, `kennel-socks-connect`, and `kennel-netproxy` binaries — and
  the kenneld root e2e — the spawn-path assembly inside a confined kennel.)

- **`[unix]` — the AF_UNIX socket shim** (design `07-4-afunix.md` §7.4) — **core
  shim BUILT** (graduated from this roadmap; kept here for the build notes). A
  kennel sees a constructed view in which only the sockets policy grants are
  present, bound from their real host locations at the paths applications expect;
  what is not bound in is structurally absent (default-deny), and abstract-namespace
  connections are denied unconditionally by the always-on Landlock scope (ABI 6+,
  §7.4.3). What is built:
  - The **policy bridge**, mirroring `[ssh]`: the `[unix]` source schema, folding,
    and leaf deltas already existed; added are the `kennel-policy::unix` validators
    (on the resolved policy: refuse `default = "allow"`, `abstract = "allow"` — it
    cannot be honoured under the always-on scope, a `[[unix.allow]]` missing
    `real`/`shim`, and — load-bearing — any entry that shims an **SSH agent**
    (`name = ssh-agent` / `env = SSH_AUTH_SOCK`): an exposed agent is a
    destination-blind oracle (§7.8.1), so SSH goes through the `[ssh]` bastion, never
    AF_UNIX), `translate_unix` → `SettledPolicy.unix: UnixRuntime` (signed,
    per-instance-substituted, omitted from the canonical form when empty), and the
    compile wiring.
  - The **realization** in `kenneld`: `Loaded.unix` → `Shared::prepare_unix` resolves
    each socket's real host path and in-view shim path (filling
    `<kennel>`/`<uid>`/`<home>`, expanding `~`/`$HOME`/`$XDG_RUNTIME_DIR`) → the
    bring-up's `apply_unix_shims` binds each host socket into `view.binds` at its shim
    path. The **key difference from the `~/.ssh` shim**: a socket cannot be *copied*
    (the `file_binds` path copies, which works for the SSH config/keys but not a
    socket node), so it rides a real **bind mount** in the constructed view; Landlock
    grants the shim path + parent so the workload can reach and connect.
  - **Proven end to end** in the kenneld root e2e: a confined kennel granted a host
    socket finds it present at its shim path, **connects through the bind** and
    round-trips a byte to the host listener, and a non-granted socket name is absent
    (ENOENT) — §7.4.9 items 1/5/8.
  - **Deferred** (still roadmap): per-kennel **service launching** (§7.4.7 — kenneld
    spawning gpg-agent/keyring instances; today the shim binds whatever is at `real`,
    skip-missing), the `abstract = "allow"` / `[[unix.allow_abstract]]` escape hatch
    (an ABI-gated future; the scope is all-or-nothing), and the `--dry-run`/`inspect`
    shim output (§7.4.5). The `ai-coding-strict` template's stale per-kennel
    *ssh-agent* shim was removed (SSH is the §7.8 bastion now) and replaced with a
    per-kennel gpg-agent example.

- **`[[fs.dev.passthrough]]` — specific host devices** (design `07-2-filesystem.md`
  §7.2.8) — **BUILT**. A first-class, loud way to expose a specific real host device
  (a serial console, `/dev/ppp`, `/dev/net/tun`) to a kennel, distinct from the
  trivial `fs.dev.allow` pseudo-device baseline. The constructed `/dev` already bound
  arbitrary allowlisted nodes (preserving owner/group/mode, Landlock `rw`+`ioctl`,
  parent dirs created for a subdir node); what was added is the policy surface
  (`kennel-policy`), mirroring `[unix]`/`[ssh]`:
  - `[[fs.dev.passthrough]]` source entries (`path`, `group`, `reason`, `threats`),
    folded bare-set, with a `[[fs.dev.passthrough.add]]` leaf delta; `kennel-policy::dev`
    validators (resolved policy: `path` absolute under `/dev`, no `..`; an `exposed`
    threat tag required) plus the `reason` check; `translate` **merges** passthrough
    paths into `DevPolicy.allow` (both bind identically at spawn — no runtime change),
    dropping `reason`/`threats`/`group` as compile-time-only.
  - **Access is GID, not capability** (the key design point): the device is gated by
    its DAC group (`dialout`/`dip`/`netdev`), and the kennel reaches it only if that
    group is in its group set; the user must already be a member. `/dev/net/tun` and
    `/dev/ppp` are used the unprivileged way (a persistent, group-owned device), never
    by granting `CAP_NET_ADMIN` (which in the host netns would risk egress bypass).
  - The `group` is carried into the kennel's group set via the `[identity]` mechanism
    below (it is added automatically), and named in the synthetic `/etc/group`.
    **Proven** in the kenneld root e2e: a confined kennel granted `/dev/net/tun` (a
    subdir device) finds it present + openable, and a non-granted device (`/dev/mem`)
    is absent.

- **`[identity].groups` — supplementary-group isolation** (design `07-2-filesystem.md`
  §7.2) — **BUILT**. The kennel carries only the supplementary Unix groups policy
  grants; by default **none** — every inherited host group is dropped — closing the
  leak the identity masking left (where `id` showed the operator's group memberships
  as bare numbers).
  - **Mechanism.** On the unprivileged userns path the default drop-all is free: an
    unprivileged user namespace maps only the primary gid (an unprivileged `gid_map` is
    limited to the single effective gid), so every inherited supplementary group collapses
    to the overflow gid (`nogroup`) inside the kennel — no `setgroups` call (which the
    kernel denies once the userns is established). The no-userns path instead drops to the
    granted set with an explicit `setgroups` in the seal (`Plan.supplementary_groups`,
    exercised by the root tests). **Re-granting a specific group** (the §7.2.8
    device-passthrough case) cannot be done unprivileged;
    it needs the narrow **privhelper `set-gid-map` operation** (the privhelper holds
    `CAP_SETGID` in the init userns and writes the workload's `gid_map`) — **BUILT**. The
    spawn-time handshake is **design (a), kenneld-side**: child A establishes the userns
    with the `gid_map` *deferred* (`namespace::establish_userns_defer_gid_map` — unshare
    USER, `setgroups=deny`, `uid_map`, but **not** `gid_map`), signals its pid down a
    pipe, and blocks; because `Command::spawn` blocks the calling thread until A execs, a
    scoped servicer thread inside `kennel_spawn::spawn_with_gid_map` reads the pid, calls
    the privhelper, and acks — only then does A fork the PID-1 grandchild and exec. The
    servicer polls the pipe with a cancel flag (the parent keeps a copy of the write end
    alive in `Command`'s stored `pre_exec` closure, so EOF cannot be relied on). `kenneld`
    drives it from `bring_up`/`spawn_workload`, mapping `dedupe(real_gid + granted gids)`.
    See the spawn flow in design §8.3 and the user-namespace prerequisite in §8.2.
  - **Policy + resolution**: `[identity].groups` (names) → `SettledPolicy.identity:
    IdentityRuntime`, mirroring `ssh`/`unix`; `translate_identity` unions the explicit
    list with every `[[fs.dev.passthrough]].group`. `kennel-policy::dev`-style
    validation rejects names with `:`/whitespace/control chars (synthetic-`/etc/group`
    injection). `kenneld` resolves each name to a GID and **membership-checks** it —
    refusing any group the operator is not in (the root seal could otherwise
    over-grant: escalation) — sets `plan.supplementary_groups`, and names the granted
    groups in `/etc/group` so `id` shows names.
  - **Proven** in the kenneld **unprivileged** e2e (`tests/e2e.rs`, run off sudo via
    `src/tools/unprivileged-e2e.sh`): a real supplementary group the operator holds is
    re-granted through the `set-gid-map` handshake and is present inside (`id -G` shows
    its gid, `id -Gn` shows `kennelgrp` via the synthetic `/etc/group`), while every
    other supplementary gid folds to the overflow gid (`nogroup`/65534) — the
    userns-correct isolation invariant (every gid is the primary, the overflow, or the
    granted one). The no-userns path's `setgroups`-to-exactly-the-granted-set is covered
    by the privileged unit/root tests; the production proof is the unprivileged vertical.

## 8.2 Implementation lessons (apply these to the rest)

- **A read-only bind remount must preserve the source's locked flags inside a userns.**
  `mount(MS_BIND|MS_REMOUNT|MS_RDONLY)` that *clears* a flag locked on the source
  superblock (`nosuid`/`nodev`/`noexec`) is `EPERM` in an unprivileged user namespace —
  the kernel permits clearing locked flags only with real privilege. So
  `mount::remount_readonly` `statvfs`es the target and carries the locked flags into the
  remount (this matters when binding a file from a `nosuid,nodev` mount — e.g. the
  `AF_UNIX` socket on the `$XDG_RUNTIME_DIR` tmpfs). It is also strictly more restrictive
  (a read-only grant never wants `suid`/`dev`), and a source without those flags (the root
  fs under `/usr`) is unaffected, so an executable bind stays executable. The lesson
  generalises: under a userns, a remount may only *add* restrictions.
- **The kenneld `AppArmor` profile is `flags=(unconfined)`; its only job is to grant
  `userns`.** An enforcing profile cannot confine kenneld here: the forked spawn child
  shares the profile and needs `userns`/`mount`/`pivot_root`/`sys_admin` to build the
  sandbox, then sets `PR_SET_NO_NEW_PRIVS` (seccomp requires it) and execs the arbitrary
  workload — and under no-new-privs the kernel denies *every* AppArmor exec transition
  (`Ux`→unconfined and even `Cx`/`Px`→stricter both give `apparmor="DENIED" …
  info="no new privs"`). That leaves only `ix` for the workload, which would inherit
  kenneld's `mount`/`userns`/`sys_admin` — worse than unconfined. The workload is confined
  by Landlock + seccomp + namespaces, not AppArmor; confining it via AppArmor would need
  runtime `aa_change_onexec` (a v2 question). See `dist/apparmor/kenneld`.
- **Userns-dependent proofs must report their precise skip cause, and be confirmed with
  `--nocapture`.** `cargo test` captures a passing test's output, so a test that skips
  (e.g. where the host lacks the `AppArmor` `userns` grant) still reads as a green `ok`
  unless its skip cause is surfaced. The spawn proofs `eprintln!` the exact reason; the
  production proof is the off-sudo runner `src/tools/unprivileged-e2e.sh`, which loads the
  `userns` profile. Relaxing the host sysctl is not the remedy (security-weakening).
- **The Landlock ruleset must be built *after* `pivot_root`, in the child.** A rule
  opens an `O_PATH` fd at build time and is keyed to that inode. Bind mounts preserve
  inodes (so system/home/dev rules match a parent-built ruleset), but the constructed
  `/etc` has fresh tmpfs inodes a host-opened fd would never match — libc would be
  denied `/etc`. So the seal builds the ruleset post-pivot with a *skip-missing* pass
  (a grant for a path the view doesn't contain is vacuous). See `kennel-spawn::spawn`.
- **The process is ephemeral; the work is not.** The new root is a throwaway tmpfs,
  but every *writable* bind resolves to a persistent host inode (the agent's real
  project tree), so work survives teardown. Any new writable surface must keep this
  property — never let something the workload means to keep live only on the tmpfs.
- **Fail closed, and prove it adversarially.** Every BPF decision path defaults to
  `KENNEL_DENY`; every new scope/right ships with a test that shows the *denied*
  case actually denies on the running kernel (the IPv4-mapped-IPv6 connect, the
  abstract-socket scope, the device ioctl). A test that only shows the allow path
  is half a test.
- **Landlock denial errnos differ by class.** Filesystem/network rules deny with
  `EACCES`; scoping (`SCOPE_*`) denies with `EPERM`. Accept both when asserting "the
  scope bit fired".

## 8.3 Build and test gotchas

- **Rebuild the BPF privhelper before root tests.** A workspace `cargo test` /
  `cargo clippy --all-targets` rebuilds `kennel-privhelper` with default features,
  clobbering the `--features bpf-egress` binary; the `kenneld` e2e then fails with
  `ENOSYS`. Always `cargo build -p kennel-privhelper --features bpf-egress` (and
  `kennel-netproxy`) immediately before running the gated binaries.
- **Run the gated test *binaries* directly under sudo**, not `sudo cargo` (which
  leaves root-owned files in `target/`). Compile with `--features root-tests
  --no-run`, then `sudo ./target/debug/deps/<name>-<hash>`. Use `pkill -x kenneld`,
  never `pkill -f` (which matches the harness wrapper and kills the shell).
- **Stage shim / `/etc` / new-root dirs outside `/tmp`.** The seal mounts a fresh
  tmpfs over `/tmp` before the shadow binds; a `/tmp`-staged source vanishes.
  Production stages under `$XDG_RUNTIME_DIR`; tests under `/run`.
- **Do not run `cargo fmt`.** There is no `rustfmt.toml` and the installed rustfmt
  reflows the maintainer's wider-line hand-formatting across the whole corpus. New
  code matches the surrounding style by hand.
- **A required new settled-schema field touches every fixture.** Adding a
  non-defaulted field to a policy struct forces every `FsPolicy`/`Plan` literal
  across crates into the same commit.
