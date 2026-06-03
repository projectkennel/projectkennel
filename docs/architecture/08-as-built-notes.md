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

- **`kennel-sshd` — the per-kennel SSH egress bastion** (design `07-8-ssh.md` §7.8). A per-user managed instance of stock OpenSSH `sshd`, sibling to
  `kenneld`, that re-originates a kennel's SSH to policy-granted destinations
  with the user's real key (held host-side) so the workload never holds a key or
  an agent socket. The mechanism is **prototype-validated against stock OpenSSH
  9.6** — forced-command re-origination carries `git`-shape commands and
  interactive ptys; the destination is fixed in `command=` (keyed to the
  authenticated synthetic key) so the workload cannot redirect it; a
  non-synthetic key is refused; `$SSH_USER_AUTH` (`ExposeAuthInfo`) exposes which
  synthetic key authenticated. Three findings constrain the build:
  1. The `AuthorizedKeysCommand` helper must be **root-owned** (OpenSSH's
     safe-path check rejects an AKC owned by the unprivileged sshd-running user),
     so `install.sh` ships it root-owned in the prefix and it queries `kenneld`
     over the control socket; the rootless `kennel-sshd` only invokes it.
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
    `spawn`/reap of the managed `sshd` (mirrors `proxy.rs`). Both the static
    `AuthorizedKeysFile` and the root-owned `AuthorizedKeysCommand` sources are
    expressible.
  - **End-to-end proof** — `src/tools/ssh-bastion-e2e.sh` stands up a real
    two-hop topology with stock OpenSSH 9.6 (a bastion `sshd` + a destination
    `sshd` + an agent) and drives the **built** `kennel-ssh-reorigin` through it,
    asserting §7.8.9's load-bearing properties: re-origination forwards
    `$SSH_ORIGINAL_COMMAND` to the policy-fixed destination; an injection-laden
    command cannot redirect it or execute on the bastion; a non-synthetic key is
    refused; a port-forward channel is denied. All four pass.

  **Still owed** (the integration into a *live kennel* — needs the kennel spawn
  path + root to validate as a whole): the supervision lifecycle wired into
  `kenneld`'s per-kennel orchestration (start/track/reap the managed `sshd`
  alongside the netproxy, regenerate state on restart) — sharing the sibling-service
  prerequisite with the still-unbuilt `[unix]` socket path; synthetic-key minting
  per `(real-key, host)` edge wired to the synthetic `~/.ssh` of a live kennel; the
  root-owned AKC helper that vends the forced-command bindings for live kennels over
  the control socket and deregisters on teardown; the bridge carrying the resolved
  `[ssh]` grants from the policy into the kennel's spawn params (the
  source-only-section→runtime path, also still-unbuilt for `[unix]`); and reaching
  the bastion over the egress proxy (one allowlisted loopback port). (The phase
  numbering follows §7.8's original plan; 2/4/5 and the bastion config + e2e are
  done.)

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
