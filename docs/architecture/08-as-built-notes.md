# §8 Implementation notes: roadmap, lessons, and gotchas

The design and architecture chapters describe the system as built. This chapter
collects what does not belong in a surface description: the pieces that are
designed but not yet implemented (roadmap), the implementation lessons that
should shape the rest of the build, and the build/test gotchas that bite.

## 8.1 Roadmap — designed, not yet built

Real design intent, not dead ideas; simply not implemented yet. The chapters that
describe these read as roadmap.

- **The unified audit writer + sinks** (`02-3-audit-schema.md`): the
  journald/syslog/stdout sinks, the `[audit]` policy section / `audit.toml`, the
  per-sink timeout, and a centralised `kennel-audit` writer. Today: BPF events
  drain a lock-free ring buffer that drops on full (`kennel-bpf/src/ringbuf.rs`,
  `bpf/kennel.bpf.h`); the netproxy formats one JSONL record per request
  (`kennel-netproxy/src/audit.rs`) and owns its sink; kenneld wires a per-kennel
  file sink (`~/.local/state/kennel/<kennel>/network.jsonl`, §7.3.4). The
  journald/syslog sinks, the `[audit]` section, and a single writer are owed.
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

## 8.2 Implementation lessons (apply these to the rest)

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
